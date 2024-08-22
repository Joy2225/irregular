---
title: Injured Android 
published: 2024-04-05
description: "My writeups for the Injured Android series"
image: "./Injured.jpeg"
tags: ["Android", "Reverse Engineering", "CTF", "Frida", "Java"]
category: Writeups
draft: false
---


# <u>Solution</u>
Get the app [here](https://github.com/B3nac/InjuredAndroid).


First decompile the apk file using jadx-gui. Inside decompile all the classes under tools. Keep the AndroidManifest.xml file under Resources always open as it contains the activities that executes and is created.

**Challenge 1**

Inside AndroidManifest.xml search for `FlagOneLoginActivity` as it is the activity that will be launched when you open the challenge.
![](./Images/image.png)

Double click on that activity name and it will take you to the java code of `FlagOneLoginActivity`

You can observe this part where the hints have been written, which you can see on pressing the emergency looking button in the app.
![](./Images/image1.png)

Now we check the `submitFlag` function
```java
 public final void submitFlag(View view) {
        EditText editText = (EditText) findViewById(R.id.editText2);
        d.s.d.g.d(editText, "editText2");
        if (d.s.d.g.a(editText.getText().toString(), "F1ag_0n3")) // Here is the flag
        {
            Intent intent = new Intent(this, FlagOneSuccess.class);
            new FlagsOverview().J(true);
            new j().b(this, "flagOneButtonColor", true);
            startActivity(intent);
        }
 }

```

From the hints it can be clearly made out that the flag is right infront of us. And we can clearly see the flag.

Flag:- `F1ag_0n3`

**Challenge 2**

Exported Activities are activities that can be launched from outside of an app.

By looking at the code of `FlagTwoActivity` nothing is found there. So how do we proceed?? In the hints they asked to find for keywords '`exported` and `activity`. So we will go to `AndroidManifest.xml` and find the required activity.

On searching we find a line that looks interesting:
```xml
<activity android:name="b3nac.injuredandroid.b25lActivity" android:exported="true"/>
```
Here the activity name is `b3nac.injuredandroid.b25lActivity`.

Now to run this activity we will make use of `adb`

The command has a syntax:
`adb shell am start -n <package_name>/<activity_name>`
The package name can be easily got from the 1st line in `AndroidManifest.xml`.

Hence run this command on your terminal:
`adb shell am start -n b3nac.injuredandroid/b3nac.injuredandroid.b25lActivity`

It will give an output on the terminal as:
`Starting: Intent { cmp=b3nac.injuredandroid/.b25lActivity }`

Now on checking the injuredandroid app we find the flag on the screen. Hence an activity was launched from outside the app.
![](./Images/image_3.png)

Flag: `S3c0nd_F1ag`

**Challenge 3**

In the `submitFlag` file for this challenge, we see that our input is being compared with some value.
```java
public final void submitFlag(View view) {  
        EditText editText = (EditText) findViewById(R.id.editText2);  
        d.s.d.g.d(editText, "editText2");  
        if (d.s.d.g.a(editText.getText().toString(), getString(R.string.cmVzb3VyY2VzX3lv))) // Here
        {  
            Intent intent = new Intent(this, FlagOneSuccess.class);  
            new FlagsOverview().L(true);  
            new j().b(this, "flagThreeButtonColor", true);  
            startActivity(intent);  
        } 
    }
```

Now when we double click and go to the mentioned file and check the value, it shows an integer value in hexadecimal format.
```java
public static final int cmVzb3VyY2VzX3lv = 0x7f0f002f;
```

Doesn't really look like a flag.

So now what?? There is another folder named `resources.arsc`. Under that go to `res/values/strings.xml`. Here we search for the same variable and we get the flag.

```xml
<string name="cmVzb3VyY2VzX3lv">F1ag_thr33</string>
```

Flag: `F1ag_thr33`

`strings.xml` is a very lucrative place to look for vulnerabilities. Usernames and passwords might just be there in poorly secure apps.

**Challenge 4**

As usual we 1st look into the Activity file for this challenge.

In the `submitFlag` function we see that `a2` array is getting its data from some external function of another class.
```java
public final void submitFlag(View view) {  
        EditText editText = (EditText) findViewById(R.id.editText2);  
        d.s.d.g.d(editText, "editText2");  
        String obj = editText.getText().toString();  
        byte[] a2 = new g().a();  // Here
        d.s.d.g.d(a2, "decoder.getData()");
        if (d.s.d.g.a(obj, new String(a2, d.w.c.f2418a))) {  
            Intent intent = new Intent(this, FlagOneSuccess.class);  
            new FlagsOverview().I(true);  
            new j().b(this, "flagFourButtonColor", true);  
            startActivity(intent);
        }  
    }
```

We go to the location by double clicking on it.

```java
package b3nac.injuredandroid; 
import android.util.Base64;  
/* loaded from: classes.dex */ 
public class g {  
    /* renamed from: a  reason: collision with root package name */  
    private byte[] f1468a = Base64.decode("NF9vdmVyZG9uZV9vbWVsZXRz", 0);  
    public byte[] a() {  
        return this.f1468a;  
    }  
}
```

It is clearly seen that `Base64.decode("NF9vdmVyZG9uZV9vbWVsZXRz")` is returned to `a2` array.
Use an online decoder for the given string and we get the flag.

Flag: `4_overdone_omelets`

**Challenge 5**

In the `onCreate` function we see that `FlagFiveReceiver` class is called.
```java
new ComponentName(this, FlagFiveReceiver.class);
```

So we go to the following class and see the code there.
```java
package b3nac.injuredandroid;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;
import android.widget.Toast;
  
/* loaded from: classes.dex */
public final class FlagFiveReceiver extends BroadcastReceiver {
    /* renamed from: a  reason: collision with root package name */
    private static int f1454a;
    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        String str;
        int i;
        String e;
        String e2;
        d.s.d.g.e(context, "context");
        d.s.d.g.e(intent, "intent");
        j.j.a(context);
        int i2 = f1454a;
        if (i2 == 0) {
            StringBuilder sb = new StringBuilder();
            e = d.w.h.e("\n    Action: " + intent.getAction() + "\n\n    ");
            sb.append(e);
            e2 = d.w.h.e("\n    URI: " + intent.toUri(1) + "\n\n    ");
            sb.append(e2);
            str = sb.toString();
            d.s.d.g.d(str, "sb.toString()");
            Log.d("DUDE!:", str);
        } else {
            str = "Keep trying!";
            if (i2 != 1) {
                if (i2 != 2) {
                    Toast.makeText(context, "Keep trying!", 1).show();
                    return;
                }
				new FlagsOverview().H(true);
				new j().b(context, "flagFiveButtonColor", true);
				Toast.makeText(context, "You are a winner " + k.a("Zkdlt0WwtLQ="), 1).show();
                i = 0;
                f1454a = i;
            }
        }
        Toast.makeText(context, str, 1).show();
        i = f1454a + 1;
        f1454a = i;
    } 
}
```
On analyzing this code it can be concluded that by clicking on the challenge 3 times, the decoded flag will be displayed on the screen.
![](./Images/Flag_5.png)
Flag: {F1v3!}

**Challenge 6**

We first check the `submitFlag` function in the `FlagSixLoginActivity` 
```java
 public final void submitFlag(View view) {
        EditText editText = (EditText) findViewById(R.id.editText3);
        d.s.d.g.d(editText, "editText3");
        if (d.s.d.g.a(editText.getText().toString(), k.a("k3FElEG9lnoWbOateGhj5pX6QsXRNJKh///8Jxi8KXW7iDpk2xRxhQ=="))) { 
            Intent intent = new Intent(this, FlagOneSuccess.class);
            FlagsOverview.G = true;
            new j().b(this, "flagSixButtonColor", true);
            startActivity(intent);
        }
  }
```
We see that `k3FElEG9lnoWbOateGhj5pX6QsXRNJKh///8Jxi8KXW7iDpk2xRxhQ==` is being passes to function `a` of class `k`. 

We can click and see what the function does 
```java
 public static String a(String str) {
        if (c(str)) {
            try {
                SecretKey generateSecret = SecretKeyFactory.getInstance("DES").generateSecret(new DESKeySpec(f1472a));
                byte[] decode = Base64.decode(str, 0);
                Cipher cipher = Cipher.getInstance("DES");
                cipher.init(2, generateSecret);
                return new String(cipher.doFinal(decode));
            } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Not a string!");
        }
        return str;
    }
```
It takes a value from some other java file and does some decryption on the string provided.

Now you can write a custom java program to pass the string to this function and output the value. But this can be done if the function is this small and simple. A better way to do this to write a `frida script` for this.

You can see the full js script in [lvl_6.js](https://github.com/Joy2225/Rev_treasure/blob/main/Android/Injured_android/lvl_6.js) 
```js
Java.perform(function(){
    let a=Java.use("b3nac.injuredandroid.k"); // Class name k inside the package 
    var flag=a.a("k3FElEG9lnoWbOateGhj5pX6QsXRNJKh///8Jxi8KXW7iDpk2xRxhQ=="); //Calling the function a inside the class represented by a and storing and printing the flag
    console.log(flag);
})
```
First we are storing the class name inside package `b3nac.injuredandroid.k` and referring it to as `a`. Then we call the function `a` inside the class and pass the encoded string `k3FElEG9lnoWbOateGhj5pX6QsXRNJKh///8Jxi8KXW7iDpk2xRxhQ==` and store the result in `flag` and print the `flag`.

**Running the Frida script**
Firstly, run the `Frida-server`. If you don't know how to run it check out [Frida setup](https://github.com/Joy2225/Rev_treasure/blob/main/Android/Setup%20Frida.md)
Now open another terminal and go to the directory where you have the `js file` and type the following command:
```
frida -U -f b3nac.injuredandroid -l lvl_6.js
```

`b3nac.injuredandroid` is the package name and `lvl_6.js` is the `js script`
We get the output something like this
![flag 6](./Images/flag_6.png)

We get out flag.
Flag: `{This_Isn't_Where_I_Parked_My_Car}`


**Challenge 7**

We see the `onCreate`  and `onDestroy` functions.
```java
public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_flag_seven_sqlite);
        C((Toolbar) findViewById(R.id.toolbar));
        j.j.a(this);
        H();
        ((FloatingActionButton) findViewById(R.id.fab)).setOnClickListener(new a());
        SQLiteDatabase writableDatabase = this.x.getWritableDatabase();
        ContentValues contentValues = new ContentValues();
        contentValues.put("title", Base64.decode("VGhlIGZsYWcgaGFzaCE=", 0));
        contentValues.put("subtitle", Base64.decode("MmFiOTYzOTBjN2RiZTM0MzlkZTc0ZDBjOWIwYjE3Njc=", 0));
        writableDatabase.insert("Thisisatest", null, contentValues);
        contentValues.put("title", Base64.decode("VGhlIGZsYWcgaXMgYWxzbyBhIHBhc3N3b3JkIQ==", 0));
        contentValues.put("subtitle", h.c());
        writableDatabase.insert("Thisisatest", null, contentValues);
    }  
```

```java

    @Override // androidx.appcompat.app.c, androidx.fragment.app.d, android.app.Activity
    public void onDestroy() {
        this.x.close();
        deleteDatabase("Thisisatest.db");
        l lVar = this.H;
        if (lVar != null) {
            com.google.firebase.database.d dVar = this.F;
            d.s.d.g.c(lVar);
            dVar.f(lVar);
        }
        l lVar2 = this.I;
        if (lVar2 != null) {
            com.google.firebase.database.d dVar2 = this.G;
            d.s.d.g.c(lVar2);
            dVar2.f(lVar2);
        }
        super.onDestroy();
    }
```

On analyzing we see that in `onCreate` a database is being created and some values are pushed to a database.

In the `onDestroy` function, we see that a database named `Thisisatest.db` is getting deleted.

Now you can decode the data written in the database or access the contents of the database.
To achieve that you need to access the database of the app while the level 7 activity is loaded. Also you need to do it in root mode. 

Write the following commands to see the data in the `Thisisatest.db` database.
```
adb shell
cd data/data/b3nac.injuredandroid/
cd databases
```

At this point if you `ls`, you will see the `Thisisatest.db` database. To access that you need to write the following commands.
```
sqlite3 Thisisatest.db
//Now you will be in the sqlite command line. Now type
.tables  // It shows what tables are there in the database
select * from Thisisatest; // It will show the data in the table
```

The data which will appear is
```
1|The flag hash!|2ab96390c7dbe3439de74d0c9b0b1767
2|The flag is also a password!|9EEADi^^:?;FC652?5C@:5]7:C632D6:@]4@>^DB=:E6];D@?
```
Now use an online hash cracker to get the password.
The flag hash: `hunter2`
The second one is a ROT 47 cipher(I understood it as it wasn't any hash and not even a normal cipher as it involved special characters. Hence ROT 47). Use an online tool to decipher that and it gives us a link: https://injuredandroid.firebaseio.com/sqlite.json
There you will see the flag: `S3V3N_11`

Put these two and click `submit`.

