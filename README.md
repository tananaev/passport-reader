# e-Passport Reader

[![](https://play.google.com/intl/en_us/badges/images/badge_new.png)](https://play.google.com/store/apps/details?id=com.tananaev.passportreader)

Android app that uses the NFC chip to communicate with an electronic passport.

Third party apps can use custom intent action to use this app to retrieve passport data.

Custom action id:
- `com.tananaev.passportreader.REQUEST`

Available data keys:
- `firstName` - String
- `lastName` - String
- `gender` - String
- `state` - String
- `nationality` - String
- `photo` - Bitmap

Usage example:

```java
public class LoginActivity extends AppCompatActivity {

    ...

    private void requestPassportData() {
        Intent intent = new Intent();
        intent.setAction("com.tananaev.passportreader.REQUEST");
        startActivityForResult(intent, 0);
    }

    ...

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (resultCode == RESULT_OK) {
            String name = data.getStringExtra("firstName") + " " + data.getStringExtra("lastName");
            ...
        }
    }

    ...

}

```

For full usage example see "sample" module in the repository.

## Contacts

Author - Anton Tananaev ([anton.tananaev@gmail.com](mailto:anton.tananaev@gmail.com))

## License

    Apache License, Version 2.0

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
