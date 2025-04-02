/*
 * Copyright 2016 - 2022 Anton Tananaev (anton.tananaev@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
@file:Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")

package com.tananaev.passportreader

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.graphics.Bitmap
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.AsyncTask
import android.os.Bundle
import android.preference.PreferenceManager
import android.text.Editable
import android.text.TextWatcher
import android.util.Base64
import android.util.Log
import android.view.View
import android.view.WindowManager
import android.widget.EditText
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.snackbar.Snackbar
import com.tananaev.passportreader.ImageUtil.decodeImage
import com.wdullaer.materialdatetimepicker.date.DatePickerDialog
import net.sf.scuba.smartcards.CardService
import net.sf.scuba.util.Hex
import org.apache.commons.io.IOUtils
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.x509.Certificate
import org.jmrtd.BACKey
import org.jmrtd.BACKeySpec
import org.jmrtd.PassportService
import org.jmrtd.Util
import org.jmrtd.lds.CardAccessFile
import org.jmrtd.lds.ChipAuthenticationPublicKeyInfo
import org.jmrtd.lds.PACEInfo
import org.jmrtd.lds.SODFile
import org.jmrtd.lds.SecurityInfo
import org.jmrtd.lds.icao.DG14File
import org.jmrtd.lds.icao.DG15File
import org.jmrtd.lds.icao.DG1File
import org.jmrtd.lds.icao.DG2File
import org.jmrtd.lds.iso19794.FaceImageInfo
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.InputStream
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.X509Certificate
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.text.ParseException
import java.text.SimpleDateFormat
import java.util.*
import javax.crypto.Cipher

abstract class MainActivity : AppCompatActivity() {

    private lateinit var passportNumberView: EditText
    private lateinit var expirationDateView: EditText
    private lateinit var birthDateView: EditText
    private var passportNumberFromIntent = false
    private var encodePhotoToBase64 = false
    private lateinit var mainLayout: View
    private lateinit var loadingLayout: View

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val preferences = PreferenceManager.getDefaultSharedPreferences(this)
        val dateOfBirth = intent.getStringExtra("dateOfBirth")
        val dateOfExpiry = intent.getStringExtra("dateOfExpiry")
        val passportNumber = intent.getStringExtra("passportNumber")
        encodePhotoToBase64 = intent.getBooleanExtra("photoAsBase64", false)
        if (dateOfBirth != null) {
            PreferenceManager.getDefaultSharedPreferences(this)
                .edit().putString(KEY_BIRTH_DATE, dateOfBirth).apply()
        }
        if (dateOfExpiry != null) {
            PreferenceManager.getDefaultSharedPreferences(this)
                .edit().putString(KEY_EXPIRATION_DATE, dateOfExpiry).apply()
        }
        if (passportNumber != null) {
            PreferenceManager.getDefaultSharedPreferences(this)
                .edit().putString(KEY_PASSPORT_NUMBER, passportNumber).apply()
            passportNumberFromIntent = true
        }

        passportNumberView = findViewById(R.id.input_passport_number)
        expirationDateView = findViewById(R.id.input_expiration_date)
        birthDateView = findViewById(R.id.input_date_of_birth)
        mainLayout = findViewById(R.id.main_layout)
        loadingLayout = findViewById(R.id.loading_layout)

        passportNumberView.setText(preferences.getString(KEY_PASSPORT_NUMBER, null))
        expirationDateView.setText(preferences.getString(KEY_EXPIRATION_DATE, null))
        birthDateView.setText(preferences.getString(KEY_BIRTH_DATE, null))

        passportNumberView.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable) {
                PreferenceManager.getDefaultSharedPreferences(this@MainActivity)
                    .edit().putString(KEY_PASSPORT_NUMBER, s.toString()).apply()
            }
        })

        expirationDateView.setOnClickListener {
            val c = loadDate(expirationDateView)
            val dialog = DatePickerDialog.newInstance(
                { _, year, monthOfYear, dayOfMonth ->
                    saveDate(
                        expirationDateView,
                        year,
                        monthOfYear,
                        dayOfMonth,
                        KEY_EXPIRATION_DATE,
                    )
                },
                c[Calendar.YEAR],
                c[Calendar.MONTH],
                c[Calendar.DAY_OF_MONTH],
            )
            dialog.showYearPickerFirst(true)
            fragmentManager.beginTransaction().add(dialog, null).commit()
        }

        birthDateView.setOnClickListener {
            val c = loadDate(birthDateView)
            val dialog = DatePickerDialog.newInstance(
                { _, year, monthOfYear, dayOfMonth ->
                    saveDate(birthDateView, year, monthOfYear, dayOfMonth, KEY_BIRTH_DATE)
                },
                c[Calendar.YEAR],
                c[Calendar.MONTH],
                c[Calendar.DAY_OF_MONTH],
            )
            dialog.showYearPickerFirst(true)
            fragmentManager.beginTransaction().add(dialog, null).commit()
        }
    }

    override fun onResume() {
        super.onResume()
        val adapter = NfcAdapter.getDefaultAdapter(this)
        if (adapter != null) {
            val intent = Intent(applicationContext, this.javaClass)
            intent.flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
            val pendingIntent = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_MUTABLE)
            val filter = arrayOf(arrayOf("android.nfc.tech.IsoDep"))
            adapter.enableForegroundDispatch(this, pendingIntent, null, filter)
        }
        if (passportNumberFromIntent) {
            // When the passport number field is populated from the caller, we hide the
            // soft keyboard as otherwise it can obscure the 'Reading data' progress indicator.
            window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_HIDDEN)
        }
    }

    override fun onPause() {
        super.onPause()
        val adapter = NfcAdapter.getDefaultAdapter(this)
        adapter?.disableForegroundDispatch(this)
    }

    public override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (NfcAdapter.ACTION_TECH_DISCOVERED == intent.action) {
            val tag: Tag? = intent.extras?.getParcelable(NfcAdapter.EXTRA_TAG)
            if (tag?.techList?.contains("android.nfc.tech.IsoDep") == true) {
                val preferences = PreferenceManager.getDefaultSharedPreferences(this)
                val passportNumber = preferences.getString(KEY_PASSPORT_NUMBER, null)
                val expirationDate = convertDate(preferences.getString(KEY_EXPIRATION_DATE, null))
                val birthDate = convertDate(preferences.getString(KEY_BIRTH_DATE, null))
                if (!passportNumber.isNullOrEmpty() && !expirationDate.isNullOrEmpty() && !birthDate.isNullOrEmpty()) {
                    val bacKey: BACKeySpec = BACKey(passportNumber, birthDate, expirationDate)
                    ReadTask(IsoDep.get(tag), bacKey).execute()
                    mainLayout.visibility = View.GONE
                    loadingLayout.visibility = View.VISIBLE
                } else {
                    Snackbar.make(passportNumberView, R.string.error_input, Snackbar.LENGTH_SHORT).show()
                }
            }
        }
    }

    @SuppressLint("StaticFieldLeak")
    private inner class ReadTask(private val isoDep: IsoDep, private val bacKey: BACKeySpec) : AsyncTask<Void?, Void?, Exception?>() {

        private lateinit var dg1File: DG1File
        private lateinit var dg2File: DG2File
        private lateinit var dg14File: DG14File
        private lateinit var dg15File: DG15File
        private lateinit var sodFile: SODFile
        private var imageBase64: String? = null
        private var bitmap: Bitmap? = null
        private var chipAuthSucceeded = false
        private var passiveAuthSuccess = false
        private var activeAuthSuccess = false
        private lateinit var dg14Encoded: ByteArray
        private lateinit var dg15Encoded: ByteArray

        override fun doInBackground(vararg params: Void?): Exception? {
            try {
                isoDep.timeout = 10000
                val cardService = CardService.getInstance(isoDep)
                cardService.open()
                val service = PassportService(
                    cardService,
                    PassportService.NORMAL_MAX_TRANCEIVE_LENGTH,
                    PassportService.DEFAULT_MAX_BLOCKSIZE,
                    false,
                    false,
                )
                service.open()
                var paceSucceeded = false
                try {
                    val cardAccessFile = CardAccessFile(service.getInputStream(PassportService.EF_CARD_ACCESS))
                    val securityInfoCollection = cardAccessFile.securityInfos
                    for (securityInfo: SecurityInfo in securityInfoCollection) {
                        if (securityInfo is PACEInfo) {
                            service.doPACE(
                                bacKey,
                                securityInfo.objectIdentifier,
                                PACEInfo.toParameterSpec(securityInfo.parameterId),
                                null,
                            )
                            paceSucceeded = true
                        }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, e)
                }
                service.sendSelectApplet(paceSucceeded)
                if (!paceSucceeded) {
                    try {
                        service.getInputStream(PassportService.EF_COM).read()
                    } catch (e: Exception) {
                        service.doBAC(bacKey)
                    }
                }
                val dg1In = service.getInputStream(PassportService.EF_DG1)
                dg1File = DG1File(dg1In)
                val dg2In = service.getInputStream(PassportService.EF_DG2)
                dg2File = DG2File(dg2In)
                val sodIn = service.getInputStream(PassportService.EF_SOD)
                sodFile = SODFile(sodIn)

                doChipAuth(service)
                doActiveAuth(service)
                doPassiveAuth()

                val allFaceImageInfo: MutableList<FaceImageInfo> = ArrayList()
                dg2File.faceInfos.forEach {
                    allFaceImageInfo.addAll(it.faceImageInfos)
                }
                if (allFaceImageInfo.isNotEmpty()) {
                    val faceImageInfo = allFaceImageInfo.first()
                    val imageLength = faceImageInfo.imageLength
                    val dataInputStream = DataInputStream(faceImageInfo.imageInputStream)
                    val buffer = ByteArray(imageLength)
                    dataInputStream.readFully(buffer, 0, imageLength)
                    val inputStream: InputStream = ByteArrayInputStream(buffer, 0, imageLength)
                    bitmap = decodeImage(this@MainActivity, faceImageInfo.mimeType, inputStream)
                    imageBase64 = Base64.encodeToString(buffer, Base64.DEFAULT)
                }
            } catch (e: Exception) {
                return e
            }
            return null
        }

        private fun doChipAuth(service: PassportService) {
            try {
                val dg14In = service.getInputStream(PassportService.EF_DG14)
                dg14Encoded = IOUtils.toByteArray(dg14In)
                val dg14InByte = ByteArrayInputStream(dg14Encoded)
                dg14File = DG14File(dg14InByte)
                val dg14FileSecurityInfo = dg14File.securityInfos
                for (securityInfo: SecurityInfo in dg14FileSecurityInfo) {
                    if (securityInfo is ChipAuthenticationPublicKeyInfo) {
                        service.doEACCA(
                            securityInfo.keyId,
                            ChipAuthenticationPublicKeyInfo.ID_CA_ECDH_AES_CBC_CMAC_256,
                            securityInfo.objectIdentifier,
                            securityInfo.subjectPublicKey,
                        )
                        chipAuthSucceeded = true
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, e)
            }
        }

        private fun doActiveAuth(service: PassportService) {
            try {
                val dg15In = service.getInputStream(PassportService.EF_DG15)
                dg15Encoded = IOUtils.toByteArray(dg15In)
                val dg15InByte = ByteArrayInputStream(dg15Encoded)
                dg15File = DG15File(dg15InByte)
                val random = SecureRandom()
                val rndIFD = ByteArray(8)
                random.nextBytes(rndIFD)
                // see https://sourceforge.net/p/jmrtd/discussion/580232/thread/2aa0c04b4d/?limit=25#36ff
                // JMRTD did not implement AA verify yet
                val resp = service.doAA(null, null, null, rndIFD)
                val rsa = Cipher.getInstance("RSA")
                rsa.init(Cipher.DECRYPT_MODE, dg15File.publicKey)
                val decrypted = rsa.doFinal(resp.response)

                val md: MessageDigest
                val trailerLen: Int
                if ((decrypted.last().toInt() and 0xFF) == 0xBC) {
                    // Option 1: SHA-1
                    md = Util.getMessageDigest("SHA-1")
                    trailerLen = 1
                } else if ((decrypted.last().toInt() and 0xFF) == 0xCC) {
                    // Option 2: SHA-224/256/384/512
                    trailerLen = 2
                    md = when (decrypted[decrypted.size - 2].toInt()) {
                        0x38 -> Util.getMessageDigest("SHA-224")
                        0x34 -> Util.getMessageDigest("SHA-256")
                        0x36 -> Util.getMessageDigest("SHA-384")
                        0x35 -> Util.getMessageDigest("SHA-512")
                        else -> throw IllegalArgumentException()
                    }
                } else {
                    throw IllegalArgumentException()
                }
                val m1 = Util.recoverMessage(md.digestLength, decrypted)
                val m = m1 + rndIFD
                val expected = md.digest(m)
                val received = decrypted.slice(decrypted.size - md.digestLength - trailerLen..<decrypted.size - trailerLen).toByteArray()
                if (!received.contentEquals(expected)) {
                    Log.w(TAG, "hash mismatch, expected: " + Hex.bytesToHexString(expected) + ", actual: " + Hex.bytesToHexString(received))
                    return
                }
                activeAuthSuccess = true
            } catch (e: Exception) {
                Log.w(TAG, e)
            }
        }

        private fun doPassiveAuth() {
            try {
                val digest = MessageDigest.getInstance(sodFile.digestAlgorithm)
                val dataHashes = sodFile.dataGroupHashes
                val dg14Hash = if (chipAuthSucceeded) digest.digest(dg14Encoded) else ByteArray(0)
                val dg1Hash = digest.digest(dg1File.encoded)
                val dg2Hash = digest.digest(dg2File.encoded)

                if (Arrays.equals(dg1Hash, dataHashes[1]) && Arrays.equals(dg2Hash, dataHashes[2])
                    && (!chipAuthSucceeded || Arrays.equals(dg14Hash, dataHashes[14]))) {

                    val asn1InputStream = ASN1InputStream(assets.open("masterList"))
                    val keystore = KeyStore.getInstance(KeyStore.getDefaultType())
                    keystore.load(null, null)
                    val cf = CertificateFactory.getInstance("X.509")

                    var p: ASN1Primitive?
                    while (asn1InputStream.readObject().also { p = it } != null) {
                        val asn1 = ASN1Sequence.getInstance(p)
                        if (asn1 == null || asn1.size() == 0) {
                            throw IllegalArgumentException("Null or empty sequence passed.")
                        }
                        if (asn1.size() != 2) {
                            throw IllegalArgumentException("Incorrect sequence size: " + asn1.size())
                        }
                        val certSet = ASN1Set.getInstance(asn1.getObjectAt(1))
                        for (i in 0 until certSet.size()) {
                            val certificate = Certificate.getInstance(certSet.getObjectAt(i))
                            val pemCertificate = certificate.encoded
                            val javaCertificate = cf.generateCertificate(ByteArrayInputStream(pemCertificate))
                            keystore.setCertificateEntry(i.toString(), javaCertificate)
                        }
                    }

                    val docSigningCertificates = sodFile.docSigningCertificates
                    for (docSigningCertificate: X509Certificate in docSigningCertificates) {
                        docSigningCertificate.checkValidity()
                    }

                    val cp = cf.generateCertPath(docSigningCertificates)
                    val pkixParameters = PKIXParameters(keystore)
                    pkixParameters.isRevocationEnabled = false
                    val cpv = CertPathValidator.getInstance(CertPathValidator.getDefaultType())
                    cpv.validate(cp, pkixParameters)
                    var sodDigestEncryptionAlgorithm = sodFile.docSigningCertificate.sigAlgName
                    var isSSA = false
                    if ((sodDigestEncryptionAlgorithm == "SSAwithRSA/PSS")) {
                        sodDigestEncryptionAlgorithm = "SHA256withRSA/PSS"
                        isSSA = true
                    }
                    val sign = Signature.getInstance(sodDigestEncryptionAlgorithm)
                    if (isSSA) {
                        sign.setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))
                    }
                    sign.initVerify(sodFile.docSigningCertificate)
                    sign.update(sodFile.eContent)
                    passiveAuthSuccess = sign.verify(sodFile.encryptedDigest)
                }
            } catch (e: Exception) {
                Log.w(TAG, e)
            }
        }

        override fun onPostExecute(result: Exception?) {
            mainLayout.visibility = View.VISIBLE
            loadingLayout.visibility = View.GONE
            if (result == null) {
                val intent = if (callingActivity != null) {
                    Intent()
                } else {
                    Intent(this@MainActivity, ResultActivity::class.java)
                }
                val mrzInfo = dg1File.mrzInfo
                intent.putExtra(ResultActivity.KEY_FIRST_NAME, mrzInfo.secondaryIdentifier.replace("<", " "))
                intent.putExtra(ResultActivity.KEY_LAST_NAME, mrzInfo.primaryIdentifier.replace("<", " "))
                intent.putExtra(ResultActivity.KEY_GENDER, mrzInfo.gender.toString())
                intent.putExtra(ResultActivity.KEY_STATE, mrzInfo.issuingState)
                intent.putExtra(ResultActivity.KEY_NATIONALITY, mrzInfo.nationality)
                val passiveAuthStr = if (passiveAuthSuccess) {
                    getString(R.string.pass)
                } else {
                    getString(R.string.failed)
                }
                val chipAuthStr = if (chipAuthSucceeded) {
                    getString(R.string.pass)
                } else {
                    getString(R.string.failed)
                }
                val activeAuthStr = if (activeAuthSuccess) {
                    getString(R.string.pass)
                } else {
                    getString(R.string.failed)
                }
                intent.putExtra(ResultActivity.KEY_PASSIVE_AUTH, passiveAuthStr)
                intent.putExtra(ResultActivity.KEY_CHIP_AUTH, chipAuthStr)
                intent.putExtra(ResultActivity.KEY_ACTIVE_AUTH, activeAuthStr)
                bitmap?.let { bitmap ->
                    if (encodePhotoToBase64) {
                        intent.putExtra(ResultActivity.KEY_PHOTO_BASE64, imageBase64)
                    } else {
                        val ratio = 320.0 / bitmap.height
                        val targetHeight = (bitmap.height * ratio).toInt()
                        val targetWidth = (bitmap.width * ratio).toInt()
                        intent.putExtra(
                            ResultActivity.KEY_PHOTO,
                            Bitmap.createScaledBitmap(bitmap, targetWidth, targetHeight, false)
                        )
                    }
                }
                if (callingActivity != null) {
                    setResult(RESULT_OK, intent)
                    finish()
                } else {
                    startActivity(intent)
                }
            } else {
                Snackbar.make(passportNumberView, result.toString(), Snackbar.LENGTH_LONG).show()
            }
        }
    }

    private fun convertDate(input: String?): String? {
        if (input == null) {
            return null
        }
        return try {
            SimpleDateFormat("yyMMdd", Locale.US).format(SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(input)!!)
        } catch (e: ParseException) {
            Log.w(MainActivity::class.java.simpleName, e)
            null
        }
    }

    private fun loadDate(editText: EditText): Calendar {
        val calendar = Calendar.getInstance()
        if (editText.text.isNotEmpty()) {
            try {
                calendar.timeInMillis = SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(editText.text.toString())!!.time
            } catch (e: ParseException) {
                Log.w(MainActivity::class.java.simpleName, e)
            }
        }
        return calendar
    }

    private fun saveDate(editText: EditText, year: Int, monthOfYear: Int, dayOfMonth: Int, preferenceKey: String) {
        val value = String.format(Locale.US, "%d-%02d-%02d", year, monthOfYear + 1, dayOfMonth)
        PreferenceManager.getDefaultSharedPreferences(this)
            .edit().putString(preferenceKey, value).apply()
        editText.setText(value)
    }

    companion object {
        private val TAG = MainActivity::class.java.simpleName
        private const val KEY_PASSPORT_NUMBER = "passportNumber"
        private const val KEY_EXPIRATION_DATE = "expirationDate"
        private const val KEY_BIRTH_DATE = "birthDate"
    }
}
