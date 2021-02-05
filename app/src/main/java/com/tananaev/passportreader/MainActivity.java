/*
 * Copyright 2016 - 2020 Anton Tananaev (anton.tananaev@gmail.com)
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
package com.tananaev.passportreader;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.AsyncTask;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.view.WindowManager;
import android.widget.EditText;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.snackbar.Snackbar;
import com.wdullaer.materialdatetimepicker.date.DatePickerDialog;

import net.sf.scuba.smartcards.CardFileInputStream;
import net.sf.scuba.smartcards.CardService;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.x509.Certificate;
import org.jmrtd.BACKey;
import org.jmrtd.BACKeySpec;
import org.jmrtd.PassportService;
import org.jmrtd.lds.ChipAuthenticationPublicKeyInfo;
import org.jmrtd.lds.SODFile;
import org.jmrtd.lds.CardAccessFile;
import org.jmrtd.lds.SecurityInfo;
import org.jmrtd.lds.icao.DG14File;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.DG2File;
import org.jmrtd.lds.icao.MRZInfo;
import org.jmrtd.lds.iso19794.FaceImageInfo;
import org.jmrtd.lds.iso19794.FaceInfo;

import org.jmrtd.lds.PACEInfo;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.jmrtd.PassportService.DEFAULT_MAX_BLOCKSIZE;
import static org.jmrtd.PassportService.NORMAL_MAX_TRANCEIVE_LENGTH;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = MainActivity.class.getSimpleName();

    private final static String KEY_PASSPORT_NUMBER = "passportNumber";
    private final static String KEY_EXPIRATION_DATE = "expirationDate";
    private final static String KEY_BIRTH_DATE = "birthDate";

    private Calendar loadDate(EditText editText) {
        Calendar calendar = Calendar.getInstance();
        if (!editText.getText().toString().isEmpty()) {
            try {
                calendar.setTimeInMillis(new SimpleDateFormat("yyyy-MM-dd", Locale.US)
                        .parse(editText.getText().toString()).getTime());
            } catch (ParseException e) {
                Log.w(MainActivity.class.getSimpleName(), e);
            }
        }
        return calendar;
    }

    private void saveDate(EditText editText, int year, int monthOfYear, int dayOfMonth, String preferenceKey) {
        String value = String.format(Locale.US, "%d-%02d-%02d", year, monthOfYear + 1, dayOfMonth);
        PreferenceManager.getDefaultSharedPreferences(this)
                .edit().putString(preferenceKey, value).apply();
        editText.setText(value);
    }

    private EditText passportNumberView;
    private EditText expirationDateView;
    private EditText birthDateView;
    private boolean passportNumberFromIntent = false;
    private boolean encodePhotoToBase64 = false;
    private View mainLayout;
    private View loadingLayout;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(this);

        String dateOfBirth = getIntent().getStringExtra("dateOfBirth");
        String dateOfExpiry = getIntent().getStringExtra("dateOfExpiry");
        String passportNumber = getIntent().getStringExtra("passportNumber");
        encodePhotoToBase64 = getIntent().getBooleanExtra("photoAsBase64", false);

        if (dateOfBirth != null) {
            PreferenceManager.getDefaultSharedPreferences(this)
                .edit().putString(KEY_BIRTH_DATE, dateOfBirth).apply();
        }
        if (dateOfExpiry != null) {
            PreferenceManager.getDefaultSharedPreferences(this)
                    .edit().putString(KEY_EXPIRATION_DATE, dateOfExpiry).apply();
        }
        if (passportNumber != null) {
            PreferenceManager.getDefaultSharedPreferences(this)
                    .edit().putString(KEY_PASSPORT_NUMBER, passportNumber).apply();
            passportNumberFromIntent = true;
        }

        passportNumberView = findViewById(R.id.input_passport_number);
        expirationDateView = findViewById(R.id.input_expiration_date);
        birthDateView = findViewById(R.id.input_date_of_birth);

        mainLayout = findViewById(R.id.main_layout);
        loadingLayout = findViewById(R.id.loading_layout);

        passportNumberView.setText(preferences.getString(KEY_PASSPORT_NUMBER, null));
        expirationDateView.setText(preferences.getString(KEY_EXPIRATION_DATE, null));
        birthDateView.setText(preferences.getString(KEY_BIRTH_DATE, null));

        passportNumberView.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override
            public void afterTextChanged(Editable s) {
                PreferenceManager.getDefaultSharedPreferences(MainActivity.this)
                        .edit().putString(KEY_PASSPORT_NUMBER, s.toString()).apply();
            }
        });

        expirationDateView.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Calendar c = loadDate(expirationDateView);
                DatePickerDialog dialog = DatePickerDialog.newInstance(new DatePickerDialog.OnDateSetListener() {
                    @Override
                    public void onDateSet(DatePickerDialog view, int year, int monthOfYear, int dayOfMonth) {
                        saveDate(expirationDateView, year, monthOfYear, dayOfMonth, KEY_EXPIRATION_DATE);
                    }
                }, c.get(Calendar.YEAR), c.get(Calendar.MONTH), c.get(Calendar.DAY_OF_MONTH));
                dialog.showYearPickerFirst(true);
                getFragmentManager().beginTransaction().add(dialog, null).commit();
            }
        });

        birthDateView.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Calendar c = loadDate(birthDateView);
                DatePickerDialog dialog = DatePickerDialog.newInstance(new DatePickerDialog.OnDateSetListener() {
                    @Override
                    public void onDateSet(DatePickerDialog view, int year, int monthOfYear, int dayOfMonth) {
                        saveDate(birthDateView, year, monthOfYear, dayOfMonth, KEY_BIRTH_DATE);
                    }
                }, c.get(Calendar.YEAR), c.get(Calendar.MONTH), c.get(Calendar.DAY_OF_MONTH));
                dialog.showYearPickerFirst(true);
                getFragmentManager().beginTransaction().add(dialog, null).commit();
            }
        });
    }

    @Override
    protected void onResume() {
        super.onResume();

        NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
        if (adapter != null) {
            Intent intent = new Intent(getApplicationContext(), this.getClass());
            intent.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
            PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT);
            String[][] filter = new String[][]{new String[]{"android.nfc.tech.IsoDep"}};
            adapter.enableForegroundDispatch(this, pendingIntent, null, filter);
        }

        if (passportNumberFromIntent) {
            // When the passport number field is populated from the caller, we hide the
            // soft keyboard as otherwise it can obscure the 'Reading data' progress indicator.
            getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_HIDDEN);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();

        NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
        if (adapter != null) {
            adapter.disableForegroundDispatch(this);
        }
    }

    private static String convertDate(String input) {
        if (input == null) {
            return null;
        }
        try {
            return new SimpleDateFormat("yyMMdd", Locale.US)
                    .format(new SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(input));
        } catch (ParseException e) {
            Log.w(MainActivity.class.getSimpleName(), e);
            return null;
        }
    }

    @Override
    public void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        if (NfcAdapter.ACTION_TECH_DISCOVERED.equals(intent.getAction())) {
            Tag tag = intent.getExtras().getParcelable(NfcAdapter.EXTRA_TAG);
            if (Arrays.asList(tag.getTechList()).contains("android.nfc.tech.IsoDep")) {
                SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(this);
                String passportNumber = preferences.getString(KEY_PASSPORT_NUMBER, null);
                String expirationDate = convertDate(preferences.getString(KEY_EXPIRATION_DATE, null));
                String birthDate = convertDate(preferences.getString(KEY_BIRTH_DATE, null));
                if (passportNumber != null && !passportNumber.isEmpty()
                        && expirationDate != null && !expirationDate.isEmpty()
                        && birthDate != null && !birthDate.isEmpty()) {
                    BACKeySpec bacKey = new BACKey(passportNumber, birthDate, expirationDate);
                    new ReadTask(IsoDep.get(tag), bacKey).execute();
                    mainLayout.setVisibility(View.GONE);
                    loadingLayout.setVisibility(View.VISIBLE);
                } else {
                    Snackbar.make(passportNumberView, R.string.error_input, Snackbar.LENGTH_SHORT).show();
                }
            }
        }
    }

    private static String exceptionStack(Throwable exception) {
        StringBuilder s = new StringBuilder();
        String exceptionMsg = exception.getMessage();
        if (exceptionMsg != null) {
            s.append(exceptionMsg);
            s.append(" - ");
        }
        s.append(exception.getClass().getSimpleName());
        StackTraceElement[] stack = exception.getStackTrace();

        if (stack.length > 0) {
            int count = 3;
            boolean first = true;
            boolean skip = false;
            String file = "";
            s.append(" (");
            for (StackTraceElement element : stack) {
                if (count > 0 && element.getClassName().startsWith("com.tananaev")) {
                    if (!first) {
                        s.append(" < ");
                    } else {
                        first = false;
                    }

                    if (skip) {
                        s.append("... < ");
                        skip = false;
                    }

                    if (file.equals(element.getFileName())) {
                        s.append("*");
                    } else {
                        file = element.getFileName();
                        s.append(file.substring(0, file.length() - 5)); // remove ".java"
                        count -= 1;
                    }
                    s.append(":").append(element.getLineNumber());
                } else {
                    skip = true;
                }
            }
            if (skip) {
                if (!first) {
                    s.append(" < ");
                }
                s.append("...");
            }
            s.append(")");
        }
        return s.toString();
    }

    private class ReadTask extends AsyncTask<Void, Void, Exception> {

        private IsoDep isoDep;
        private BACKeySpec bacKey;

        private ReadTask(IsoDep isoDep, BACKeySpec bacKey) {
            this.isoDep = isoDep;
            this.bacKey = bacKey;
        }

        private DG1File dg1File;
        private DG2File dg2File;
        private DG14File dg14File;
        private SODFile sodFile;
        private String imageBase64;
        private Bitmap bitmap;
        private boolean chipAuthSucceeded = false;
        private boolean passiveAuthSuccess = false;

        private byte[] dg14Encoded = new byte[0];

        private void doChipAuth(PassportService service) {
            try {
                CardFileInputStream dg14In = service.getInputStream(PassportService.EF_DG14);
                dg14Encoded = IOUtils.toByteArray(dg14In);
                ByteArrayInputStream dg14InByte = new ByteArrayInputStream(dg14Encoded);
                dg14File = new DG14File(dg14InByte);

                Collection<SecurityInfo> dg14FileSecurityInfos = dg14File.getSecurityInfos();
                for (SecurityInfo securityInfo : dg14FileSecurityInfos) {
                    if (securityInfo instanceof ChipAuthenticationPublicKeyInfo) {
                        ChipAuthenticationPublicKeyInfo publicKeyInfo = (ChipAuthenticationPublicKeyInfo) securityInfo;
                        BigInteger keyId = publicKeyInfo.getKeyId();
                        PublicKey publicKey = publicKeyInfo.getSubjectPublicKey();
                        String oid = publicKeyInfo.getObjectIdentifier();
                        service.doEACCA(keyId, ChipAuthenticationPublicKeyInfo.ID_CA_ECDH_AES_CBC_CMAC_256, oid, publicKey);
                        chipAuthSucceeded = true;
                    }
                }
            }
            catch (Exception e) {
                Log.w(TAG, e);
            }
        }

        private void doPassiveAuth() {
            try {
                MessageDigest digest = MessageDigest.getInstance(sodFile.getDigestAlgorithm());

                Map<Integer,byte[]> dataHashes = sodFile.getDataGroupHashes();

                byte[] dg14Hash = new byte[0];
                if(chipAuthSucceeded) {
                    dg14Hash = digest.digest(dg14Encoded);
                }
                byte[] dg1Hash = digest.digest(dg1File.getEncoded());
                byte[] dg2Hash = digest.digest(dg2File.getEncoded());

                if(Arrays.equals(dg1Hash, dataHashes.get(1)) && Arrays.equals(dg2Hash, dataHashes.get(2)) && (!chipAuthSucceeded || Arrays.equals(dg14Hash, dataHashes.get(14)))) {
                    // We retrieve the CSCA from the german master list
                    ASN1InputStream asn1InputStream = new ASN1InputStream(getAssets().open("masterList"));
                    ASN1Primitive p;
                    KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
                    keystore.load(null, null);
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    while((p = asn1InputStream.readObject()) != null) {
                        ASN1Sequence asn1 = ASN1Sequence.getInstance(p);
                        if (asn1 == null || asn1.size() == 0) {
                            throw new IllegalArgumentException("null or empty sequence passed.");
                        }
                        if (asn1.size() != 2) {
                            throw new IllegalArgumentException("Incorrect sequence size: " + asn1.size());
                        }
                        ASN1Set certSet = ASN1Set.getInstance(asn1.getObjectAt(1));

                        for (int i = 0; i < certSet.size(); i++) {
                            Certificate certificate = Certificate.getInstance(certSet.getObjectAt(i));

                            byte[] pemCertificate = certificate.getEncoded();

                            java.security.cert.Certificate javaCertificate = cf.generateCertificate(new ByteArrayInputStream(pemCertificate));
                            keystore.setCertificateEntry(String.valueOf(i), javaCertificate);
                        }
                    }
                    List<X509Certificate> docSigningCertificates = sodFile.getDocSigningCertificates();
                    for (X509Certificate docSigningCertificate : docSigningCertificates) {
                        docSigningCertificate.checkValidity();
                    }

                    // We check if the certificate is signed by a trusted CSCA
                    // TODO: verify if certificate is revoked
                    CertPath cp = cf.generateCertPath(docSigningCertificates);
                    PKIXParameters pkixParameters = new PKIXParameters(keystore);
                    pkixParameters.setRevocationEnabled(false);
                    CertPathValidator cpv = CertPathValidator.getInstance(CertPathValidator.getDefaultType());
                    cpv.validate(cp, pkixParameters);

                    String sodDigestEncryptionAlgorithm = sodFile.getDigestEncryptionAlgorithm();

                    boolean isSSA = false;
                    if (sodDigestEncryptionAlgorithm.equals("SSAwithRSA/PSS")) {
                        sodDigestEncryptionAlgorithm = "SHA256withRSA/PSS";
                        isSSA = true;
                    }

                    Signature sign = Signature.getInstance(sodDigestEncryptionAlgorithm);
                    if (isSSA) {
                        sign.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
                    }

                    sign.initVerify(sodFile.getDocSigningCertificate());
                    sign.update(sodFile.getEContent());
                    passiveAuthSuccess = sign.verify(sodFile.getEncryptedDigest());
                }
            }
            catch (Exception e) {
                Log.w(TAG, e);
            }
        }

        @Override
        protected Exception doInBackground(Void... params) {
            try {
                CardService cardService = CardService.getInstance(isoDep);
                cardService.open();

                PassportService service = new PassportService(cardService, NORMAL_MAX_TRANCEIVE_LENGTH, DEFAULT_MAX_BLOCKSIZE, false, false);
                service.open();

                boolean paceSucceeded = false;
                try {
                    CardAccessFile cardAccessFile = new CardAccessFile(service.getInputStream(PassportService.EF_CARD_ACCESS));
                    Collection<SecurityInfo> securityInfoCollection = cardAccessFile.getSecurityInfos();
                    for (SecurityInfo securityInfo : securityInfoCollection) {
                        if (securityInfo instanceof PACEInfo) {
                            PACEInfo paceInfo = (PACEInfo) securityInfo;
                            service.doPACE(bacKey, paceInfo.getObjectIdentifier(), PACEInfo.toParameterSpec(paceInfo.getParameterId()), null);
                            paceSucceeded = true;
                        }
                    }
                } catch (Exception e) {
                    Log.w(TAG, e);
                }

                service.sendSelectApplet(paceSucceeded);

                if (!paceSucceeded) {
                    try {
                        service.getInputStream(PassportService.EF_COM).read();
                    } catch (Exception e) {
                        service.doBAC(bacKey);
                    }
                }

                CardFileInputStream dg1In = service.getInputStream(PassportService.EF_DG1);
                dg1File = new DG1File(dg1In);

                CardFileInputStream dg2In = service.getInputStream(PassportService.EF_DG2);
                dg2File = new DG2File(dg2In);

                CardFileInputStream sodIn = service.getInputStream(PassportService.EF_SOD);
                sodFile = new SODFile(sodIn);

                // We perform Chip Authentication using Data Group 14
                doChipAuth(service);

                // Then Passive Authentication using SODFile
                doPassiveAuth();

                List<FaceImageInfo> allFaceImageInfos = new ArrayList<>();
                List<FaceInfo> faceInfos = dg2File.getFaceInfos();
                for (FaceInfo faceInfo : faceInfos) {
                    allFaceImageInfos.addAll(faceInfo.getFaceImageInfos());
                }

                if (!allFaceImageInfos.isEmpty()) {
                    FaceImageInfo faceImageInfo = allFaceImageInfos.iterator().next();

                    int imageLength = faceImageInfo.getImageLength();
                    DataInputStream dataInputStream = new DataInputStream(faceImageInfo.getImageInputStream());
                    byte[] buffer = new byte[imageLength];
                    dataInputStream.readFully(buffer, 0, imageLength);
                    InputStream inputStream = new ByteArrayInputStream(buffer, 0, imageLength);

                    bitmap = ImageUtil.decodeImage(
                            MainActivity.this, faceImageInfo.getMimeType(), inputStream);
                    imageBase64 = Base64.encodeToString(buffer, Base64.DEFAULT);
                }

            } catch (Exception e) {
                return e;
            }
            return null;
        }

        @Override
        protected void onPostExecute(Exception result) {
            mainLayout.setVisibility(View.VISIBLE);
            loadingLayout.setVisibility(View.GONE);

            if (result == null) {

                Intent intent;
                if (getCallingActivity() != null) {
                    intent = new Intent();
                } else {
                    intent = new Intent(MainActivity.this, ResultActivity.class);
                }

                MRZInfo mrzInfo = dg1File.getMRZInfo();

                intent.putExtra(ResultActivity.KEY_FIRST_NAME, mrzInfo.getSecondaryIdentifier().replace("<", " "));
                intent.putExtra(ResultActivity.KEY_LAST_NAME, mrzInfo.getPrimaryIdentifier().replace("<", " "));
                intent.putExtra(ResultActivity.KEY_GENDER, mrzInfo.getGender().toString());
                intent.putExtra(ResultActivity.KEY_STATE, mrzInfo.getIssuingState());
                intent.putExtra(ResultActivity.KEY_NATIONALITY, mrzInfo.getNationality());

                String passiveAuthStr = "";
                if(passiveAuthSuccess) {
                    passiveAuthStr = getString(R.string.pass);
                } else {
                    passiveAuthStr = getString(R.string.failed);
                }

                String chipAuthStr = "";
                if (chipAuthSucceeded) {
                    chipAuthStr = getString(R.string.pass);
                } else {
                    chipAuthStr = getString(R.string.failed);
                }
                intent.putExtra(ResultActivity.KEY_PASSIVE_AUTH, passiveAuthStr);
                intent.putExtra(ResultActivity.KEY_CHIP_AUTH, chipAuthStr);

                if (bitmap != null) {
                    if (encodePhotoToBase64) {
                        intent.putExtra(ResultActivity.KEY_PHOTO_BASE64, imageBase64);
                    } else {
                        double ratio = 320.0 / bitmap.getHeight();
                        int targetHeight = (int) (bitmap.getHeight() * ratio);
                        int targetWidth = (int) (bitmap.getWidth() * ratio);

                        intent.putExtra(ResultActivity.KEY_PHOTO,
                            Bitmap.createScaledBitmap(bitmap, targetWidth, targetHeight, false));
                    }
                }

                if (getCallingActivity() != null) {
                    setResult(Activity.RESULT_OK, intent);
                    finish();
                } else {
                    startActivity(intent);
                }

            } else {
                Snackbar.make(passportNumberView, exceptionStack(result), Snackbar.LENGTH_LONG).show();
            }
        }

    }

}
