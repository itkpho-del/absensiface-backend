require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');

const app = express();

// 🌟 CATATAN: identitas IP diambil dari peer TCP asli (req.socket.remoteAddress),
// bukan dari header X-Forwarded-For, agar selalu IP WireGuard klien yang tersimpan.

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

// 🛡️ BANTUAN: Ambil IP peer TCP yang SEBENARNYA (req.socket.remoteAddress).
// Di jaringan WireGuard ini persis IP WireGuard klien (mis. 172.17.x.x), bukan
// alamat fisik LAN, dan tidak bisa dipalsukan lewat header.
// Header X-Forwarded-For sengaja DIABAIKAN agar IP yang tercatat di
// tcheckinout / tfacevector / log registrasi selalu IP WireGuard asli.
function ambilIpKoneksi(req) {
  let clientIp = req.socket.remoteAddress || req.connection.remoteAddress || '';
  if (clientIp.includes('::ffff:')) {
    clientIp = clientIp.split('::ffff:')[1];
  }
  return clientIp;
}

// Kueri umum: cocokkan IP dengan kode pabrik/store
async function cariPabrikDariIP(clientIp) {
  const query = `SELECT pab_kode, pab_nama FROM hrd2.tpabrik WHERE pab_status=1 AND pab_face='Y' AND pab_ip = ? LIMIT 1`;
  const [rows] = await db.promise().query(query, [clientIp]);
  return rows && rows.length > 0
    ? { pab_kode: rows[0].pab_kode, pab_nama: rows[0].pab_nama, clientIp, isLocal: false }
    : null;
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
          SELECT tf.nik, tf.nama, tf.face_vektor, tf.kode_store 
          FROM absensi.tfacevector tf
          INNER JOIN hrd2.tkaryawan k ON k.kar_nik = tf.nik
          WHERE k.kar_status_aktif = 1 
            AND k.kar_pab_kode = ?
        `;
        params = [lokalStoreOverride];
      } else {
        query = `
          SELECT tf.nik, tf.nama, tf.face_vektor, tf.kode_store 
          FROM absensi.tfacevector tf
        `;
      }
    } else {
      // Hanya muat data biometrik yang terdaftar di store lokasi komputer ini
      // DAN pastikan status karyawan di master HRD masih AKTIF di store tersebut
      query = `
        SELECT tf.nik, tf.nama, tf.face_vektor, tf.kode_store 
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
app.post('/api/register', verifikasiIPWireGuard, (req, res) => {
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

  db.query(checkKaryawanSql, [nik, kode_pabrik], (errCheck, rowsKaryawan) => {
    if (errCheck) {
      console.error("Error Check Karyawan:", errCheck);
      return res.status(500).json({ message: "Gagal memeriksa data master karyawan" });
    }

    if (rowsKaryawan.length === 0) {
      return res.status(404).json({ 
        message: `Gagal Registrasi! NIK ${nik} tidak terdaftar aktif di Cabang/Store ${kode_pabrik}.` 
      });
    }

    const namaResmiKaryawan = rowsKaryawan[0].nama;
    const kodeStore = rowsKaryawan[0].kode_store;

    // Simpan NIK, Nama, Face Vektor, dan Kode Store ke tfacevector
    const insertUserSql = `INSERT INTO tfacevector (nik, nama, face_vektor, kode_store) VALUES (?, ?, ?, ?)`;

    db.query(insertUserSql, [nik, namaResmiKaryawan, JSON.stringify(face_vektor), kodeStore], (insertErr) => {
      if (insertErr) {
        console.error("Error Insert Biometric:", insertErr);
        if (insertErr.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ message: `NIK ${nik} sudah merekam wajah sebelumnya!` });
        }
        return res.status(500).json({ message: "Gagal menyimpan profile biometrik wajah" });
      }

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
    });
  });
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
      `SELECT tf.nik, tf.nama, tf.kode_store, kar_pab_kode lokasi, if(kar_status_aktif=1,'Aktif','Nonaktif') status FROM absensi.tfacevector tf LEFT JOIN hrd2.tkaryawan ON kar_nik=tf.nik order by tf.nama`
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

const PORT = 8081;
const HOST = '0.0.0.0';

app.listen(PORT, HOST, () => {
  console.log(`Server Kencana berjalan aktif!`);
  console.log(`- Akses Lokal: http://localhost:${PORT}`);
  console.log(`- Akses Server Jaringan: http://172.17.0.87:${PORT}`);
});