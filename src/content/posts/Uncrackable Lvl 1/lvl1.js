Java.perform(function(){
    let c = Java.use("sg.vantagepoint.a.c");
    c["a"].implementation = function () {
        console.log(`c.a is called`);
        let result=false;
        return result;
    };

    c["b"].implementation = function () {
        console.log(`c.b is called`);
        let result=false;
        return result;
    };

    c["c"].implementation = function () {
        console.log(`c.c is called`);
        let result=false;
        return result;
    };

    let android=Java.use("android.util.Base64");
    let ab=Java.use("sg.vantagepoint.uncrackable1.a");
    var key=ab.b("8d127684cbc37c17616d806cf50473cc");
    var secret=android.decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=", 0);
    let final=Java.use("sg.vantagepoint.a.a");
    var ans=final.a(key,secret);
    var result=""
    for(var i=0;i<ans.length;i++){
        result+=String.fromCharCode(ans[i]);
    }
    console.log(result)

})