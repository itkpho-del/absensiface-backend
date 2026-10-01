require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');

const app = express();

// ==========================================
// 🛡️ TRUSTED PROXY (WAJIB KALAU DI DEPAN ADA NGINX/APACHE)
// ==========================================
// Di server live, backend Express tidak diakses langsung oleh browser, melainkan
// lewat reverse proxy (nginx/Apache) di host yang sama. Akibatnya
// req.socket.remoteAddress SELALU berisi IP proxy itu sendiri (mis. 172.17.0.87),
// bukan IP WireGuard komputer.
// Forwarded-For yang disetel oleh proxy-lah yang memuat IP asli, jadi kita izinkan
// Express membacanya — TAPI hanya untuk request yang datang dari proxy
// terdaftar di bawah. Header dari klien biasa (yang bukan proxy) tetap diabaikan
// sehingga IP tidak bisa dipalsukan dengan crafting header.
//
// Daftar IP proxy, pisahkan koma. HAPUS dari daftar ini kalau nama mesin/alamat
// proxy berubah, karena kalau tidak cocok maka IP klien kembali terbaca sebagai
// IP proxy dan absensi akan ditolak.
const daftarProxyTepercaya = (process.env.TRUST_PROXY_IPS || 'loopback,172.17.0.87')
  .split(',')
  .map((ip) => ip.trim())
  .filter(Boolean);

app.set('trust proxy', daftarProxyTepercaya);
console.log('Trusted proxy (boleh menyetor X-Forwarded-For):', daftarProxyTepercaya.join(', '));

// 📥 Terjemahkan nama rentang (loopback) menjadi alamat konkret, karena
// pengecekan peer di bawah memakai perbandingan biasa, bukan proxy-addr.
// Contoh: 'loopback' -> 127.0.0.1 + ::1
const PETA_NAMA_RENTANG = {
  loopback: ['127.0.0.1', '::1'],
  linklocal: ['169.254.0.0/16', 'fe80::/10'],
};

function alamatProxyTerpercaya() {
  const hasil = [];
  for (const item of daftarProxyTepercaya) {
    const kunci = item.toLowerCase();
    if (PETA_NAMA_RENTANG[kunci]) {
      hasil.push(...PETA_NAMA_RENTANG[kunci]);
    } else {
      hasil.push(item);
    }
  }
  return hasil;
}

function ipv4KeAngka(ip) {
  const bagian = String(ip).split('.');
  if (bagian.length !== 4) return null;
  let nilai = 0;
  for (const oktet of bagian) {
    const angka = Number(oktet);
    if (!Number.isInteger(angka) || angka < 0 || angka > 255) return null;
    nilai = nilai * 256 + angka;
  }
  return nilai;
}

// 📦 Pencocokan alamat IP: IP persis (172.17.0.87), prefiks (172.17.0.),
// atau CIDR (172.17.0.0/16).
function ipDalamRentang(ip, rentang) {
  if (rentang.includes('/')) {
    const [jaringan, bits] = rentang.split('/');
    const ipNum = ipv4KeAngka(ip);
    const jaringNum = ipv4KeAngka(jaringan);
    if (ipNum === null || jaringNum === null) return false;
    const geser = 32 - Number(bits);
    if (!Number.isInteger(geser) || geser < 0) return false;
    return Math.floor(ipNum / 2 ** geser) === Math.floor(jaringNum / 2 ** geser);
  }
  if (rentang.endsWith('.')) {
    return ip.startsWith(rentang);
  }
  return ip === rentang;
}

// 🟢 1. CORS WAJIB DI TARUH DI SINI (PALING ATAS!)
app.use(cors({
  origin: '*', 
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// 🟢 2. BARU PASANG LIMIT JSON DI BAWAH CORS
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Koneksi ke Database menggunakan Pool
const db = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'password', // sesuaikan dengan password db anda
  database: process.env.DB_NAME || 'absensi',
  waitForConnections: true,
  connectionLimit: 20,
  queueLimit: 0
});

// ✅ Kueri dasar untuk memastikan pool database berfungsi saat startup
db.query('SELECT 1', (err) => {
  if (err) {
    console.error('Koneksi DB Gagal saat inisialisasi awal:', err.message);
  } else {
    console.log('Database Connection Pool siap digunakan!');
  }
});

// 🛡️ BANTUAN: Ambil IP klien yang SEBENARNYA, baik lewat proxy maupun langsung.
function normalisasiIp(ip) {
  let bersih = (ip || '').trim();
  if (bersih.startsWith('::ffff:')) {
    bersih = bersih.slice('::ffff:'.length);
  }
  if (bersih === '::1') {
    bersih = '127.0.0.1';
  }
  return bersih;
}

// Daftar alamat loopback. Proxy lokal (nginx/Apache) di mesin yang sama selalu
// terlihat sebagai 127.0.0.1 atau ::1, apa pun nama host/IP yang dipakainya.
const ALAMAT_LOOPBACK = ['127.0.0.1', '::1', '0.0.0.0'];

// Apakah request ini datang dari proxy yang kita percaya? Kalau ya, header
// proxy layak dibaca. Kalau tidak, header diabaikan sepenuhnya supaya IP tidak
// bisa dipalsukan oleh klien mana pun.
function peerAdalahProxyTerpercaya(req) {
  const peer = normalisasiIp(req.socket?.remoteAddress);
  return alamatProxyTerpercaya().some((rentang) => ipDalamRentang(peer, rentang));
}

function ambilIpKoneksi(req) {
  const peer = normalisasiIp(req.socket?.remoteAddress);

  // Tanpa proxy: peer TCP sudah pasti IP komputer_asli.
  if (!peerAdalahProxyTerpercaya(req)) {
    return peer;
  }

  // Lewat proxy. req.ip = hasil resolusi X-Forwarded-For oleh Express/proxy-addr:
  // membaca dari kanan dan melewati HANYA alamat proxy, jadi entri XFF yang
  // dipalsukan klien (bagian paling kiri) otomatis dibuang.
  const dariXff = normalisasiIp(req.ip);
  if (dariXff && dariXff !== peer) {
    return dariXff;
  }

  // Sebagian config nginx hanya mengirim X-Real-IP (tanpa X-Forwarded-For),
  // jadi dipakai sebagai cadangan selama peer-nya proxy terdaftar.
  const dariXReal = normalisasiIp(req.headers['x-real-ip']);
  if (dariXReal) {
    return dariXReal;
  }

  return peer;
}

// 🩺 Bantu diagnosis saat IP ditolak: catat semua jejak IP supaya jelas masalahnya
// di proxy (header tidak diteruskan) atau di database (IP tidak terdaftar).
function catatDitolak(req, clientIp, middleware) {
  console.warn(`[IP-DITOLAK:${middleware}] ip_terbaca=${clientIp} peer_tcp=${normalisasiIp(req.socket?.remoteAddress)} proxy_terpercaya=${peerAdalahProxyTerpercaya(req)} xff=${req.headers['x-forwarded-for'] || '-'} xreal=${req.headers['x-real-ip'] || '-'} host=${req.headers.host || '-'} path=${req.originalUrl}`);
  if (peerAdalahProxyTerpercaya(req) && !req.headers['x-forwarded-for'] && !req.headers['x-real-ip']) {
    console.warn('[IP-DITOLAK] Request datang dari proxy tapi TIDAK ADA header X-Forwarded-For maupun X-Real-IP -> IP asli tidak bisa diketahui. Perbaiki proxy_set_header di config nginx.');
  }
}

// Kueri umum: cocokkan IP dengan kode pabrik/store
async function cariPabrikDariIP(clientIp) {
  const query = `SELECT pab_kode, pab_nama FROM hrd2.tpabrik WHERE pab_status=1 AND pab_face='Y' AND pab_ip = ? LIMIT 1`;
  const [rows] = await db.promise().query(query, [clientIp]);
  return rows && rows.length > 0
    ? { pab_kode: rows[0].pab_kode, pab_nama: rows[0].pab_nama, clientIp, isLocal: false }
    : null;
}

// ==========================================
// ⚠️⚠️ MODE LEMBIR SEMENTARA (WASPADA) ⚠️⚠️
// ==========================================
// Aktif HANYA kalau IP benar-benar belum terdaftar atau proxy belum dikonfigurasi,
// supaya absensi tetap bisa jalan. TIDAK untuk pemakaian rutin / produksi.
// Cara pakai: set BYPASS_IP_CHECK=true di .env lalu restart backend.
// MATIKAN lagi (hapus baris itu / set false) setelah jaringan beres.
//
// Kalau aktif, kode toko memakai LOCAL_STORE sebagai gantinya.
const BYPASS_IP_CHECK = ['1', 'true', 'yes', 'on'].includes(
  String(process.env.BYPASS_IP_CHECK || '').trim().toLowerCase()
);
const KODE_STORE_FALLBACK = (process.env.LOCAL_STORE || '').trim();

if (BYPASS_IP_CHECK) {
  console.warn('='.repeat(70));
  console.warn('PERINGATAN: MODE LEMBIR AKTIF — verifikasi IP NONAKTIF!');
  console.warn('Semua komputer bebas absen. Jangan dipakai di produksi.');
  console.warn(`Kode toko fallback: ${KODE_STORE_FALLBACK || '(belum diisi di .env)'}`);
  console.warn('='.repeat(70));
}

// 🔓 Cari identitas toko yang dipakai saat mode bypass aktif.
async function tokoSaatBypass(clientIp) {
  if (KODE_STORE_FALLBACK) {
    const [rows] = await db.promise().query(
      `SELECT pab_kode, pab_nama FROM hrd2.tpabrik WHERE pab_kode = ? LIMIT 1`,
      [KODE_STORE_FALLBACK]
    );
    if (rows && rows.length > 0) {
      return { pab_kode: rows[0].pab_kode, pab_nama: rows[0].pab_nama, clientIp, isLocal: true };
    }
    console.warn(`[BYPASS] Kode toko "${KODE_STORE_FALLBACK}" tidak ada di tpabrik, ambil daftar pertama.`);
  }

  // Tidak diisi / tidak ketemu: pakai toko pertama yang aktif supaya absensi
  // tetap bisa jalan (data wajah & log IP tetap tercatat seperti biasa).
  const [rows] = await db.promise().query(
    `SELECT pab_kode, pab_nama FROM hrd2.tpabrik WHERE pab_status=1 AND pab_face='Y' ORDER BY pab_kode LIMIT 1`
  );
  if (rows && rows.length > 0) {
    return { pab_kode: rows[0].pab_kode, pab_nama: rows[0].pab_nama, clientIp, isLocal: true };
  }
  throw new Error('Tidak ada satu pun toko aktif di hrd2.tpabrik');
}

// 🛡️ MIDDLEWARE VERIFIKASI IP & IDENTIFIKASI KODE PABRIK/STORE CLIENT
// Dipakai untuk semua endpoint terproteksi. Identitas klien = IP WireGuard
// (peer TCP asli) dan WAJIB terdaftar di hrd2.tpabrik — TIDAK ADA bypass localhost.
const verifikasiIPWireGuard = async (req, res, next) => {
  const clientIp = ambilIpKoneksi(req);

  try {
    const pabrik = await cariPabrikDariIP(clientIp);
    if (pabrik) {
      req.pabrikClient = pabrik;
      return next(); // IP Ditemukan! Izinkan akses ke controller.
    }
    if (BYPASS_IP_CHECK) {
      req.pabrikClient = await tokoSaatBypass(clientIp);
      return next(); // ⚠️ Mode bypass aktif: izinkan tanpa IP terdaftar.
    }
    catatDitolak(req, clientIp, 'umum');
    return res.status(403).json({ 
      success: false, 
      message: `Akses Ditolak! Komputer Anda (${clientIp}) tidak terdaftar dalam jaringan absensi cabang resmi mana pun.` 
    });
  } catch (error) {
    console.error("Error validasi IP dari MySQL:", error);
    return res.status(500).json({
      success: false,
      message: "Terjadi kesalahan sistem saat memverifikasi IP komputer Anda."
    });
  }
};

// 🛡️ STRICT KHUSUS ABSENSI — identik dengan di atas (tanpa bypass localhost),
// pesan khusus agar jelas bahwa absensi hanya boleh dari IP terdaftar di tpabrik.
const verifikasiIPAbsensi = async (req, res, next) => {
  const clientIp = ambilIpKoneksi(req);

  try {
    const pabrik = await cariPabrikDariIP(clientIp);
    if (pabrik) {
      req.pabrikClient = pabrik;
      return next();
    }
    if (BYPASS_IP_CHECK) {
      req.pabrikClient = await tokoSaatBypass(clientIp);
      return next(); // ⚠️ Mode bypass aktif: izinkan tanpa IP terdaftar.
    }
    catatDitolak(req, clientIp, 'absensi');
    return res.status(403).json({
      success: false,
      message: `Absensi Ditolak! IP (${clientIp}) tidak terdaftar di tabel tpabrik.`
    });
  } catch (error) {
    console.error("Error validasi IP Absensi dari MySQL:", error);
    return res.status(500).json({
      success: false,
      message: "Terjadi kesalahan sistem saat memverifikasi IP komputer Anda."
    });
  }
};

// ==========================================
// ENDPOINT SERVER TIME
// ==========================================
app.get('/api/server-time', (req, res) => {
  res.json({ serverTime: new Date().getTime() });
});

// ==========================================
// 🌟 ENDPOINT BARU: AMBIL USERS HANYA SESUAI KODE STORE CLIENT (IP)
// ==========================================
// Dipanggil oleh Frontend Vue.js saat inisialisasi Face-api.js agar
// pencocokan biometrik HANYA memuat wajah karyawan di toko tersebut.
app.get('/api/users-by-store', verifikasiIPWireGuard, async (req, res) => {
  const infoPabrikClient = req.pabrikClient;

  try {
    let query = '';
    let params = [];

    if (infoPabrikClient.isLocal) {
      // Jalur localhost (testing internal).
      // - Jika env LOCAL_STORE diisi → tetap difilter per toko (simulasi komputer toko tsb).
      // - Jika kosong → muat semua wajah agar testing lintas cabang tetap bisa.
      const lokalStoreOverride = process.env.LOCAL_STORE;

      if (lokalStoreOverride) {
        infoPabrikClient.pab_kode = lokalStoreOverride;
        infoPabrikClient.pab_nama = `Simulasi Toko ${lokalStoreOverride}`;
        query = `
          SELECT tf.nik, tf.nama, tf.face_vektor 
          FROM absensi.tfacevector tf
          INNER JOIN hrd2.tkaryawan k ON k.kar_nik = tf.nik
          WHERE k.kar_status_aktif = 1 
            AND k.kar_pab_kode = ?
        `;
        params = [lokalStoreOverride];
      } else {
        query = `
          SELECT tf.nik, tf.nama, tf.face_vektor 
          FROM absensi.tfacevector tf
        `;
      }
    } else {
      // Hanya muat data biometrik yang terdaftar di store lokasi komputer ini
      // DAN pastikan status karyawan di master HRD masih AKTIF di store tersebut
      query = `
        SELECT tf.nik, tf.nama, tf.face_vektor 
        FROM absensi.tfacevector tf
        INNER JOIN hrd2.tkaryawan k ON k.kar_nik = tf.nik
        WHERE k.kar_status_aktif = 1 
          AND k.kar_pab_kode = ?
      `;
      params = [infoPabrikClient.pab_kode];
    }

    const [results] = await db.promise().query(query, params);
    
    return res.json({
      success: true,
      store: infoPabrikClient.pab_kode,
      nama_store: infoPabrikClient.pab_nama,
      total_wajah: results.length,
      data: results
    });

  } catch (error) {
    console.error("Error Get Users By Store:", error);
    return res.status(500).json({ 
      success: false, 
      message: "Gagal memuat data biometrik toko" 
    });
  }
});

// ==========================================
// ENDPOINT REGISTRASI WAJAH (VALIDASI KODE STORE & IP)
// ==========================================
app.post('/api/register', verifikasiIPWireGuard, async (req, res) => {
  const { nik, face_vektor, kode_pabrik } = req.body;
  const infoPabrikClient = req.pabrikClient;

  if (!nik || !face_vektor || !kode_pabrik) {
    return res.status(400).json({ message: "NIK, Vektor Wajah, atau Kode Pabrik tidak boleh kosong!" });
  }

  // 🛡️ VALIDASI: Kode store tempat registrasi harus cocok dengan IP lokasi komputer
  if (!infoPabrikClient.isLocal && kode_pabrik !== infoPabrikClient.pab_kode) {
    return res.status(403).json({
      success: false,
      message: `Registrasi Ditolak! Anda mencoba mendaftarkan cabang [${kode_pabrik}], tetapi komputer ini terdeteksi berada di cabang [${infoPabrikClient.pab_nama} / ${infoPabrikClient.pab_kode}].`
    });
  }

  try {
    // Skema tfacevector bisa berbeda antara lokal & produksi (produksi tanpa
    // kolom kode_store) → deteksi otomatis agar INSERT tetap aman.
    const kolomTface = await kolomTfacevector();
    const punyaKodeStore = kolomTface.includes('kode_store');

    // Ambil nama dan kar_pab_kode (sebagai kode_store) dari master karyawan
    const checkKaryawanSql = `
      SELECT kar_nama AS nama, kar_pab_kode AS kode_store 
      FROM hrd2.tkaryawan 
      WHERE kar_status_aktif = 1 
        AND kar_nik = ? 
        AND kar_pab_kode = ? 
        AND kar_pab_kode IN (SELECT pab_kode FROM hrd2.tpabrik WHERE pab_face = 'Y') 
      LIMIT 1
    `;

    const [rowsKaryawan] = await db.promise().query(checkKaryawanSql, [nik, kode_pabrik]);

    if (rowsKaryawan.length === 0) {
      return res.status(404).json({ 
        message: `Gagal Registrasi! NIK ${nik} tidak terdaftar aktif di Cabang/Store ${kode_pabrik}.` 
      });
    }

    const namaResmiKaryawan = rowsKaryawan[0].nama;
    const kodeStore = rowsKaryawan[0].kode_store;

    // Simpan NIK, Nama, Face Vektor (+ Kode Store hanya bila kolomnya tersedia)
    const insertUserSql = punyaKodeStore
      ? `INSERT INTO tfacevector (nik, nama, face_vektor, kode_store) VALUES (?, ?, ?, ?)`
      : `INSERT INTO tfacevector (nik, nama, face_vektor) VALUES (?, ?, ?)`;
    const insertParams = punyaKodeStore
      ? [nik, namaResmiKaryawan, JSON.stringify(face_vektor), kodeStore]
      : [nik, namaResmiKaryawan, JSON.stringify(face_vektor)];

    await db.promise().query(insertUserSql, insertParams);

    return res.status(200).json({ 
      success: true,
      message: `Profile biometrik wajah berhasil didaftarkan secara resmi!`,
      detail: { 
        nik, 
        nama: namaResmiKaryawan, 
        kode_pabrik, 
        kode_store: kodeStore,
        registered_from_ip: infoPabrikClient.clientIp 
      }
    });

  } catch (error) {
    console.error("Error Registrasi Profile Biometric:", error);
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ message: `NIK ${nik} sudah merekam wajah sebelumnya!` });
    }
    return res.status(500).json({ message: "Gagal menyimpan profile biometrik wajah" });
  }
});

// ==========================================
// ENDPOINT ABSENSI (MENYIMPAN ALAMAT IP & PESAN ERROR PRESISI)
// ==========================================
app.post('/api/absensi', verifikasiIPAbsensi, (req, res) => {
  const { nik, checktype } = req.body;

  if (!nik || !checktype) {
    return res.status(400).json({ message: "Data tidak lengkap (NIK dan Checktype wajib diisi)" });
  }

  // 1. Ambil data karyawan dari database master
  const selectKaryawanSql = `
    SELECT kar_nama AS nama, kar_pab_kode AS kode_pabrik 
    FROM hrd2.tkaryawan 
    WHERE kar_status_aktif = 1 
      AND kar_nik = ? 
    LIMIT 1
  `;

  db.query(selectKaryawanSql, [nik], (errKaryawan, rowsKaryawan) => {
    if (errKaryawan) {
      console.error("Error Query Karyawan:", errKaryawan);
      return res.status(500).json({ message: "Gagal memproses validasi database karyawan" });
    }

    const infoPabrikClient = req.pabrikClient;

    // 🛡️ JIKA NIK TIDAK DITEMUKAN ATAU KARYAWAN BERADA DI STORE LAIN
    if (rowsKaryawan.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: "NIK tidak terdaftar atau status karyawan tidak aktif!" 
      });
    }

    const namaResmiKaryawan = rowsKaryawan[0].nama;
    const kodePabrikKaryawan = rowsKaryawan[0].kode_pabrik;

    // 🛡️ VALIDASI STRICT: PESAN BILA DILUAR TOKO
    if (!infoPabrikClient.isLocal && kodePabrikKaryawan !== infoPabrikClient.pab_kode) {
      return res.status(403).json({
        success: false,
        message: "NIK tidak terdaftar di toko ini!"
      });
    }

    // 🛡️ KONDISI A: JIKA CHECK-IN (I)
    if (checktype === 'I') {
      const cekWaktuLamaSql = `
        SELECT TIME_FORMAT(checktime, '%H:%i:%s') as jam_terakhir 
        FROM tcheckinout 
        WHERE nik = ? AND checktype = 'I' AND tanggal = CURDATE()
        ORDER BY checktime DESC LIMIT 1
      `;

      db.query(cekWaktuLamaSql, [nik], (errWaktu, rowsWaktu) => {
        if (errWaktu) return res.status(500).json({ message: "Gagal memeriksa riwayat absensi" });

        if (rowsWaktu.length > 0) {
          const jamTerakhirDiDB = rowsWaktu[0].jam_terakhir;
          
          db.query(`SELECT CURTIME() as jam_sekarang`, (errSkrg, rowsSkrg) => {
            if (errSkrg || rowsSkrg.length === 0) return res.status(500).json({ message: "Gagal mengambil waktu" });

            const jamSekarangServer = rowsSkrg[0].jam_sekarang;

            if (jamSekarangServer > jamTerakhirDiDB) {
              return res.status(422).json({ 
                message: `Anda sudah melakukan Check-In pada pukul ${jamTerakhirDiDB}` 
              });
            } else {
              eksekusiInsertAbsen(nik, namaResmiKaryawan, checktype, kodePabrikKaryawan, infoPabrikClient, res);
            }
          });
        } else {
          eksekusiInsertAbsen(nik, namaResmiKaryawan, checktype, kodePabrikKaryawan, infoPabrikClient, res);
        }
      });

    // 🔄 KONDISI B: JIKA CHECK-OUT (O)
    } else if (checktype === 'O') {
      const cekOutLamaSql = `
        SELECT id FROM tcheckinout 
        WHERE nik = ? AND checktype = 'O' AND tanggal = CURDATE() 
        LIMIT 1
      `;

      db.query(cekOutLamaSql, [nik], (errCekOut, rowsOut) => {
        if (errCekOut) return res.status(500).json({ message: "Gagal memvalidasi log checkout" });

        if (rowsOut.length > 0) {
          const idLogLama = rowsOut[0].id;

          ambilKolomIP().then((kolom) => {
            const updateSql = kolom
              ? `UPDATE tcheckinout SET checktime = CURTIME(), ${kolom} = ? WHERE id = ?`
              : `UPDATE tcheckinout SET checktime = CURTIME() WHERE id = ?`;
            const updateParams = kolom ? [infoPabrikClient.clientIp, idLogLama] : [idLogLama];

            db.query(updateSql, updateParams, (updateErr) => {
              if (updateErr) return res.status(500).json({ message: "Gagal memperbarui waktu Check-Out" });

              db.query(`SELECT TIME_FORMAT(checktime, '%H:%i:%s') as jam_baru FROM tcheckinout WHERE id = ?`, [idLogLama], (errJam, rowsJam) => {
                const jamFix = (!errJam && rowsJam.length > 0) ? rowsJam[0].jam_baru : "00:00:00";
                return res.status(200).json({ 
                  success: true,
                  message: "Check-Out Diperbarui (Jam Terbaru)!", 
                  detail: { 
                    nik, 
                    nama: namaResmiKaryawan, 
                    checktype, 
                    kode_pabrik: kodePabrikKaryawan, 
                    kode_store_ip: infoPabrikClient.pab_kode,
                    nama_store_ip: infoPabrikClient.pab_nama,
                    ip_address: infoPabrikClient.clientIp,
                    jam: jamFix 
                  }
                });
              });
            });
          });

        } else {
          eksekusiInsertAbsen(nik, namaResmiKaryawan, checktype, kodePabrikKaryawan, infoPabrikClient, res);
        }
      });
    }
  });
});

// 🌐 Deteksi otomatis nama kolom IP pada tabel tcheckinout
// (ip_absen untuk skema lokal, ip_address untuk skema lama/produksi,
//  atau tidak ada -> IP di-skip agar insert/update tetap aman)
let kolomIPAbsen = null;
let promiseKolomIP = null;

// 📦 Deteksi kolom absensi.tfacevector (skema lokal vs produksi bisa beda:
// produksi TIDAK punya kolom kode_store → query SELECT/INSERT dibuat dinamis)
let daftarKolomTface = null;
let promiseKolomTface = null;

function kolomTfacevector() {
  if (!promiseKolomTface) {
    const cekSql = `
      SELECT COLUMN_NAME FROM information_schema.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tfacevector'
    `;

    promiseKolomTface = new Promise((resolve) => {
      db.query(cekSql, (err, rows) => {
        daftarKolomTface = (err || !rows) ? [] : rows.map((r) => r.COLUMN_NAME);
        console.log('Kolom tfacevector terdeteksi:', daftarKolomTface.join(', ') || '(kosong)');
        resolve(daftarKolomTface);
      });
    });
  }
  return promiseKolomTface;
}

function ambilKolomIP() {
  if (!promiseKolomIP) {
    const cekSql = `
      SELECT COLUMN_NAME FROM information_schema.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tcheckinout' 
        AND COLUMN_NAME IN ('ip_absen','ip_address')
    `;

    promiseKolomIP = new Promise((resolve) => {
      db.query(cekSql, (err, rows) => {
        if (err || !rows || rows.length === 0) {
          kolomIPAbsen = null;
        } else {
          kolomIPAbsen = rows.some((r) => r.COLUMN_NAME === 'ip_absen') ? 'ip_absen' : 'ip_address';
        }
        console.log('Kolom IP tcheckinout terdeteksi:', kolomIPAbsen || '(tidak ada, IP di-skip)');
        resolve(kolomIPAbsen);
      });
    });
  }
  return promiseKolomIP;
}

// 📦 Fungsi Bantuan untuk Melakukan Insert ke Database Absensi (Lengkap dengan IP)
function eksekusiInsertAbsen(nik, nama, checktype, kode_pabrik, infoPabrikClient, res) {
  ambilKolomIP().then((kolom) => {
    const realInsertSql = kolom
      ? `INSERT INTO tcheckinout (nik, nama, tanggal, checktime, checktype, ${kolom}) 
         VALUES (?, ?, CURDATE(), CURTIME(), ?, ?)`
      : `INSERT INTO tcheckinout (nik, nama, tanggal, checktime, checktype) 
         VALUES (?, ?, CURDATE(), CURTIME(), ?)`;

    const insertParams = kolom ? [nik, nama, checktype, infoPabrikClient.clientIp] : [nik, nama, checktype];

    db.query(realInsertSql, insertParams, (insertErr) => {
      if (insertErr) {
        console.error("Error Insert Absensi:", insertErr);
        return res.status(500).json({ message: "Gagal menyimpan log absensi ke database" });
      }

    const selectWaktuSql = `
      SELECT TIME_FORMAT(checktime, '%H:%i:%s') as jam_server 
      FROM tcheckinout 
      WHERE id = LAST_INSERT_ID()
    `;

    db.query(selectWaktuSql, (selectErr, rowsWaktu) => {
      const jamFix = (!selectErr && rowsWaktu.length > 0) ? rowsWaktu[0].jam_server : "00:00:00";

      return res.status(200).json({ 
        success: true,
        message: "Absensi Berhasil!", 
        detail: { 
          nik, 
          nama, 
          checktype, 
          kode_pabrik, 
          kode_store_ip: infoPabrikClient.pab_kode,
          nama_store_ip: infoPabrikClient.pab_nama,
          ip_address: infoPabrikClient.clientIp,
          jam: jamFix 
        }
});
    });
    });
    });
}

// ==========================================
// ENDPOINT VALIDASI PASSWORD MODAL ADMIN
// ==========================================
app.post('/api/admin/verify-password', verifikasiIPWireGuard, (req, res) => {
  const { password } = req.body;
  // 🌟 Ganti lewat environment variable ADMIN_PASS, fallback ke default lama
  const PASSWORD_ADMIN_VALID = process.env.ADMIN_PASS || "Face#01"; 

  if (!password) {
    return res.status(400).json({ auth: false, message: "Password tidak boleh kosong" });
  }

  if (password === PASSWORD_ADMIN_VALID) {
    return res.status(200).json({ auth: true, message: "Akses diberikan" });
  } else {
    return res.status(401).json({ auth: false, message: "Password Salah!" });
  }
});

// ==========================================
// ENDPOINT AMBIL DAFTAR KARYAWAN AKTIF (UNTUK LOV)
// ==========================================
app.get('/api/karyawan', async (req, res) => {
  try {
    const [rows] = await db.promise().query(
      'SELECT kar_nik nik, kar_nama nama, kar_pab_kode pabrik FROM hrd2.tkaryawan WHERE kar_status_aktif = 1 AND kar_pab_kode IN (SELECT pab_kode FROM hrd2.tpabrik WHERE pab_face="Y") ORDER BY kar_nama ASC'
    );
    res.json(rows);
  } catch (error) {
    console.error('Error Query Karyawan:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Gagal mengambil data master karyawan dari database' 
    });
  }
});

// ==========================================
// ENDPOINT AMBIL DAFTAR WAJAH TERDAFTAR
// ==========================================
app.get('/api/facekaryawan', async (req, res) => {
  try {
    const [rows] = await db.promise().query(
      `SELECT tf.nik, tf.nama, ifnull(kar_pab_kode,'') kode_store, kar_pab_kode lokasi, if(kar_status_aktif=1,'Aktif','Nonaktif') status FROM absensi.tfacevector tf LEFT JOIN hrd2.tkaryawan ON kar_nik=tf.nik order by tf.nama`
    );
    res.json(rows);
  } catch (error) {
    console.error('Error Query Karyawan:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Gagal mengambil data karyawan terdaftar' 
    });
  }
});

// ==========================================
// DELETE WAJAH TERDAFTAR
// ==========================================
app.delete('/api/facekaryawan/:nik', verifikasiIPWireGuard, async (req, res) => {
  const { nik } = req.params;

  if (!nik) {
    return res.status(400).json({ 
      success: false, 
      message: 'Parameter NIK tidak boleh kosong' 
    });
  }

  try {
    const [result] = await db.promise().query(
      'DELETE FROM absensi.tfacevector WHERE nik = ?', 
      [nik]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: `Data biometrik dengan NIK ${nik} tidak ditemukan`
      });
    }

    res.json({
      success: true,
      message: `Profil biometrik wajah NIK ${nik} berhasil dihapus dari sistem`
    });

  } catch (error) {
    console.error('Error saat menghapus wajah:', error);
    res.status(500).json({
      success: false,
      message: 'Gagal menghapus data biometrik di server'
    });
  }
});

// ==========================================
// ENDPOINT TRANSFER DATA ABSENSI
// ==========================================
app.post('/api/absensi/transfer', async (req, res) => {
  const { tanggalMulai, tanggalSelesai, cabang } = req.body;

  if (!tanggalMulai || !tanggalSelesai || !cabang || !Array.isArray(cabang) || cabang.length === 0) {
    return res.status(400).json({ 
      success: false, 
      message: 'Tanggal mulai, tanggal selesai, dan minimal satu cabang harus dipilih!' 
    });
  }

  try {
    const placeholdersCabang = cabang.map(() => '?').join(',');
    
    const selectQuery = `
      SELECT k.kar_kode_absensi nik, c.nama, c.tanggal, 
      min(if(checktype='I',c.checktime,null)) scan1,
      max(if(checktype='O',c.checktime,null)) scan2
      FROM absensi.tcheckinout c  
      INNER JOIN hrd2.tkaryawan k ON c.nik = k.kar_nik
      WHERE c.tanggal BETWEEN ? AND ?      
      AND k.kar_pab_kode IN (${placeholdersCabang})
      GROUP BY 1,2,3
    `;

    const queryParams = [tanggalMulai, tanggalSelesai, ...cabang];
    const [rowsToTransfer] = await db.promise().query(selectQuery, queryParams);

    if (rowsToTransfer.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Tidak ada data absensi yang ditemukan pada tanggal dan cabang terpilih.'
      });
    }

    const insertQuery = `
      INSERT INTO hrd2.tabsensi (nik, tanggal, scan1, scan2) 
      VALUES ? 
      ON DUPLICATE KEY UPDATE 
        scan1 = IF(
        VALUES(scan1) IS NOT NULL AND (hrd2.tabsensi.scan1 IS NULL OR hrd2.tabsensi.scan1='00:00:00' OR VALUES(scan1) < hrd2.tabsensi.scan1), 
        VALUES(scan1), 
        hrd2.tabsensi.scan1
      ),
        scan2 = IFNULL(VALUES(scan2), scan2)
    `;

    const valuesToInsert = rowsToTransfer.map(row => [
      row.nik,
      row.tanggal,
      row.scan1,
      row.scan2
    ]);

    const [insertResult] = await db.promise().query(insertQuery, [valuesToInsert]);
    
    res.json({
      success: true,
      message: `Berhasil mentransfer ${insertResult.affectedRows} log absensi ke tabel master absensi.`
    });

  } catch (error) {
    console.error('Error saat transfer data absensi:', error);
    res.status(500).json({
      success: false,
      message: 'Gagal melakukan sinkronisasi/transfer data absensi di server.'
    });
  }
});

// ==========================================
// ENDPOINT AMBIL DAFTAR CABANG
// ==========================================
app.get('/api/cabang', async (req, res) => {
  try {
    const [rows] = await db.promise().query(
      `SELECT DISTINCT kar_pab_kode as kode_cabang, pab_nama 
       FROM hrd2.tkaryawan 
       LEFT JOIN hrd2.tpabrik ON (pab_kode=kar_pab_kode)
       WHERE kar_Status_aktif=1 
         AND kar_pab_kode IS NOT NULL 
         AND kar_pab_kode IN (SELECT pab_kode FROM hrd2.tpabrik WHERE pab_face='Y')
       ORDER BY kar_pab_kode ASC`
    );
    res.json(rows);
  } catch (error) {
    console.error('Error Get Cabang:', error);
    res.status(500).json({ success: false, message: 'Gagal memuat master daftar cabang' });
  }
});

const PORT = Number(process.env.PORT || 8081);
const HOST = process.env.HOST || '0.0.0.0';

app.listen(PORT, HOST, () => {
  console.log(`Server Kencana berjalan aktif!`);
  console.log(`- Akses Lokal: http://localhost:${PORT}`);
  console.log(`- Akses Server Jaringan: http://${process.env.SERVER_IP || '172.17.0.87'}:${PORT}`);
  console.log(`- Endpoint terlindungi (butuh IP terdaftar di hrd2.tpabrik): /api/absensi, /api/register, /api/users-by-store`);
});