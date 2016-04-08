package com.tananaev.passportreader;

import android.app.DatePickerDialog;
import android.app.Dialog;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.preference.PreferenceFragment;
import android.preference.PreferenceManager;
import android.support.v4.app.DialogFragment;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Log;
import android.view.View;
import android.widget.DatePicker;
import android.widget.EditText;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Locale;

public class MainActivity extends AppCompatActivity {

    private final static String KEY_PASSPORT_NUMBER = "passportNumber";
    private final static String KEY_EXPIRATION_DATE = "expirationDate";
    private final static String KEY_BIRTH_DATE = "birthDate";

    public static class DatePickerFragment extends DialogFragment implements DatePickerDialog.OnDateSetListener {

        private final static String KEY_VIEW_ID = "viewId";
        private final static String KEY_PREFERENCE = "preferenceKey";

        public static DatePickerFragment createInstance(int viewId, String preferenceKey) {
            DatePickerFragment fragment = new DatePickerFragment();
            Bundle bundle = new Bundle();
            bundle.putInt(KEY_VIEW_ID, viewId);
            bundle.putString(KEY_PREFERENCE, preferenceKey);
            fragment.setArguments(bundle);
            return fragment;
        }

        EditText editText;

        @Override
        public Dialog onCreateDialog(Bundle savedInstanceState) {
            editText = (EditText) getActivity().findViewById(getArguments().getInt(KEY_VIEW_ID));

            Calendar c = Calendar.getInstance();
            if (!editText.getText().toString().isEmpty()) {
                try {
                    c.setTimeInMillis(new SimpleDateFormat("yyyy-MM-dd", Locale.US)
                            .parse(editText.getText().toString()).getTime());
                } catch (ParseException e) {
                    Log.w(MainActivity.class.getSimpleName(), e);
                }
            }

            return new DatePickerDialog(getActivity(), this,
                    c.get(Calendar.YEAR), c.get(Calendar.MONTH), c.get(Calendar.DAY_OF_MONTH));
        }

        @Override
        public void onDateSet(DatePicker view, int year, int monthOfYear, int dayOfMonth) {
            String value = String.format("%d-%02d-%02d", year, monthOfYear + 1, dayOfMonth);
            PreferenceManager.getDefaultSharedPreferences(getActivity())
                    .edit().putString(getArguments().getString(KEY_PREFERENCE), value).apply();
            editText.setText(value);
        }

        @Override
        public void onDismiss(DialogInterface dialog) {
            editText.clearFocus();
        }

    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(this);

        EditText passportNumberView = (EditText) findViewById(R.id.input_passport_number);
        EditText expirationDateView = (EditText) findViewById(R.id.input_expiration_date);
        EditText birthDateView = (EditText) findViewById(R.id.input_date_of_birth);

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

        expirationDateView.setOnFocusChangeListener(new View.OnFocusChangeListener() {
            @Override
            public void onFocusChange(View v, boolean hasFocus) {
                if (hasFocus) {
                    getSupportFragmentManager().beginTransaction().add(
                            DatePickerFragment.createInstance(R.id.input_expiration_date, KEY_EXPIRATION_DATE), null).commit();
                }
            }
        });

        birthDateView.setOnFocusChangeListener(new View.OnFocusChangeListener() {
            @Override
            public void onFocusChange(View v, boolean hasFocus) {
                if (hasFocus) {
                    getSupportFragmentManager().beginTransaction().add(
                            DatePickerFragment.createInstance(R.id.input_date_of_birth, KEY_BIRTH_DATE), null).commit();
                }
            }
        });
    }

}
