/*
 * Copyright 2016 Anton Tananaev (anton.tananaev@gmail.com)
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

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;

import com.gemalto.jp2.JP2Decoder;

import org.jnbis.WsqDecoder;

import java.io.IOException;
import java.io.InputStream;

public class ImageUtil {

    public static Bitmap decodeImage(Context context, String mimeType, InputStream inputStream) throws IOException {

        if (mimeType.equalsIgnoreCase("image/jp2") || mimeType.equalsIgnoreCase("image/jpeg2000")) {

            return new JP2Decoder(inputStream).decode();

        } else if (mimeType.equalsIgnoreCase("image/x-wsq")) {

            WsqDecoder wsqDecoder = new WsqDecoder();
            org.jnbis.Bitmap bitmap = wsqDecoder.decode(inputStream);
            byte[] byteData = bitmap.getPixels();
            int[] intData = new int[byteData.length];
            for (int j = 0; j < byteData.length; j++) {
                intData[j] = 0xFF000000 | ((byteData[j] & 0xFF) << 16) | ((byteData[j] & 0xFF) << 8) | (byteData[j] & 0xFF);
            }
            return Bitmap.createBitmap(intData, 0, bitmap.getWidth(), bitmap.getWidth(), bitmap.getHeight(), Bitmap.Config.ARGB_8888);

        } else {

            return BitmapFactory.decodeStream(inputStream);

        }

    }

}
