Return-Path: <kasan-dev+bncBCC5HZGYUYIRBRXJ2WAQMGQEXWCMMUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id E30E832334F
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 22:33:59 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id t25sf3131otp.22
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 13:33:59 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:in-reply-to:references:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UrcDKHZ6sAKbCJEj8pnbRzSiloIBEnlXEoivpDbWcjc=;
        b=MUX5InpQ8nNKbU6SubVBbGRcMdgh1nk48Un3jJClP1E9M4RnlotMKnXigHBbLS+tZ4
         ui0oBG6Sk90HkDpG+zRgUGH9/YMCx/n0z4V+2uvTxovMFZoOZipPym75G1RRbGFTyH7o
         nJdJsqudt6Y+6fnX3YnULzGO7kxnUus+We8eDu0Pp0HsRvQ7TgMxQ2SFGsnMoW1Uhm1a
         iZyptR25/LkH/1arQN3ybA/EHSxVi/CwLO1iKjU46G54e30MX8i2TEZ43gR4MqVYZPHb
         lszdXE5P86OQXyTkP2uqNARctSroXTF8e4yvEohSRjjO9QfIdSk4OmU0X/M948x5KsWr
         Rzaw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:in-reply-to:references:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UrcDKHZ6sAKbCJEj8pnbRzSiloIBEnlXEoivpDbWcjc=;
        b=F6Rtrx0jKK+h1Khd8BfRlXsTlgesqg+hCAeOSovn3WKtPxlqaAcpk0RSvxOlHY533n
         8edehZ2HiqzADn3ccuCIZU3L7JNj8CBpGeifxPjLtyHrXdRUUTm53MYnpmQO7ZK73tnX
         v3/ch1RNaB//zkUvn/ggTkL2GFpBEl/G9k2sT7xeehH1mSmEZXyznIrx5ehihW2Nh8ha
         3mgu5V22nYhIjuxm741AszVFFY6SRwPdoZUcX9vYsL1Ke/ri61aqPWhtR42kNgRG5P9Z
         urGQaZnbAXNTOix2MMoA290gHIDipbRq2YwPLQaDVcwuVGbbwoTKWv3/VrQQ48cu9T1b
         y9ig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:in-reply-to
         :references:subject:mime-version:x-original-sender:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UrcDKHZ6sAKbCJEj8pnbRzSiloIBEnlXEoivpDbWcjc=;
        b=hStlBWFyBT5HSbY0F+fyL00qBYvHwCvD70jEtan8Zp24zTnEysUfQ8d+0enX7EZfoE
         dPNL29syf71slhLLkRKbtRNRpMuc74G04wQfW6CSoCFoO6gjd9DvX+RGZohxSEdSarSu
         ARXcKMGSp/dEIJ9TX2w3UUAQUijRO7AUEjm3CVp2y5KEHG0NK2ekpiJpi9B2uxDCA+ea
         g5fj8966MFbNUIOFw3vBJ+Z98lodS18WH4Xh0uFMMz+DCv/w2IApdbMbZAISyB9gxZfs
         w35ZTbGiZuaBR07iA75cac/4HRNgtFiU7yjNO44lIpkCu4q6Sfo3XrhULvtyEaWxlLBz
         mJLw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5306/qVF93tgPjyzQnHqrrkUR7uAYig3Uc9oh3vMyWtHhy78Dj+d
	46GnoVKQ7bwLApfud1l4yQY=
X-Google-Smtp-Source: ABdhPJw3H+6Bi1NgGVrL20nNkN9JqCdm7+CeGYhTwzFEo0rRkZ2SUJbOCZiQErl9cDUSLjKbMKs/7g==
X-Received: by 2002:a05:6830:22fa:: with SMTP id t26mr3663112otc.143.1614116038707;
        Tue, 23 Feb 2021 13:33:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:923:: with SMTP id v35ls31603ott.0.gmail; Tue, 23
 Feb 2021 13:33:58 -0800 (PST)
X-Received: by 2002:a9d:6c6:: with SMTP id 64mr13606909otx.78.1614116038127;
        Tue, 23 Feb 2021 13:33:58 -0800 (PST)
Date: Tue, 23 Feb 2021 13:33:57 -0800 (PST)
From: Shahbaz Ali <shbaz.ali@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <4e60f843-ab24-4277-b213-8d4b523c6fc9n@googlegroups.com>
In-Reply-To: <589d9334-7d65-4679-9c4d-2feea648d092n@googlegroups.com>
References: <745fe86a-17de-4597-8af3-baa306b6dd0cn@googlegroups.com>
 <CAAeHK+z1k3Y3qQWwYWa5ZuZdYtR+sqF9CSauoeLfGqR=qcdyDw@mail.gmail.com>
 <3ab303b3-1488-4c47-91db-248138ab5541n@googlegroups.com>
 <CAAeHK+z2FS0tZxPs73oJBX80mRkLWKyguT72bv2XZ9Db57NCrg@mail.gmail.com>
 <c8763b30-cc09-40c1-ac50-774c99ee1712n@googlegroups.com>
 <589d9334-7d65-4679-9c4d-2feea648d092n@googlegroups.com>
Subject: Re: __asan_register_globals with out-of-tree modules
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_296_812329996.1614116037574"
X-Original-Sender: shbaz.ali@gmail.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

------=_Part_296_812329996.1614116037574
Content-Type: multipart/alternative; 
	boundary="----=_Part_297_864980608.1614116037574"

------=_Part_297_864980608.1614116037574
Content-Type: text/plain; charset="UTF-8"

Hi,

Issue resolved.

Turned out that the gcc version used for the kernel was different to the 
one used for out-of-tree modules.

Shahbaz

On Monday, February 22, 2021 at 11:41:32 AM UTC Shahbaz Ali wrote:

> Hi,
>
> Managed to successfully port this to my 4.9 kernel.  However, I'm still 
> having the same issue with my out-of-tree modules:
>
> [   13.657676] KASAN got bad input address: 0000000000000190; (converted 
> to:dfff200000000032)
> [   13.669442] KASAN got bad input address: 0000000000000350; (converted 
> to:dfff20000000006a)
> [   13.680547] KASAN got bad input address: 00000000000001c0; (converted 
> to:dfff200000000038)
> [   13.691172] KASAN got bad input address: fffe4000016a3b48; (converted 
> to:fffee800002d4769)
> [   13.701755] KASAN got bad input address:           (null); (converted 
> to:dfff200000000000)
> [   13.712600] KASAN got bad input address: fffe4000016a66c0; (converted 
> to:fffee800002d4cd8)
> [   13.723101] KASAN got bad input address: 0000000000000050; (converted 
> to:dfff20000000000a)
> [   13.733607] KASAN got bad input address: 00000000000000d0; (converted 
> to:dfff20000000001a)
> [   13.744125] KASAN got bad input address: 0000000000000040; (converted 
> to:dfff200000000008)
> [   13.754642] KASAN got bad input address: fffe4000016a3c20; (converted 
> to:fffee800002d4784)
> [   13.765136] KASAN got bad input address:           (null); (converted 
> to:dfff200000000000)
> [   13.775619] KASAN got bad input address: fffe4000016a6880; (converted 
> to:fffee800002d4d10)
> [   13.786107] KASAN got bad input address: 0000000000000020; (converted 
> to:dfff200000000004)
> [   13.796587] KASAN got bad input address: 0000000000000060; (converted 
> to:dfff20000000000c)
>
> If I understand correctly, the __asan_register_globals is being 
> instrumented into the out-of-tree module code during compile time; and 
> during loading of the module,
> this exported function is called with the kasan_global struct data 
> (including memory address of the global)?
>
> If that's the case, how is the address / kasan_global data determined for 
> the call?  Is this hardcoded in by GCC during compile-time (in which case 
> it might be a toolchain issue), or is it probing the kernel for that data 
> during module load?
>
> Basically, I'm just trying to track down why those global->beg addresses 
> are wrong, whose fault it is, and why.  Any further help would be greately 
> appreciated!
>
> Thanks,
> Shahbaz
> On Tuesday, February 16, 2021 at 4:37:24 PM UTC Shahbaz Ali wrote:
>
>> Thanks, I will take anything I can get!
>>
>> Shahbaz
>>
>> On Tuesday, February 16, 2021 at 4:16:13 PM UTC andre...@google.com 
>> wrote:
>>
>>> On Tue, Feb 16, 2021 at 5:02 PM Shahbaz Ali <shba...@gmail.com> wrote: 
>>> > 
>>> > Thanks Andre, 
>>> > 
>>> > Unfortunately, due to the nature of the system, I do not have an easy 
>>> option to update it other than apply the 4.9 LTS patches (which I have done 
>>> already). 
>>> > 
>>> > Do you think it'd be possible for me to backport KASAN from the 
>>> current version? 
>>>
>>> You can try backporting KASAN patches that mention changing global 
>>> variables handling, maybe that would help. 
>>>
>>> Backporting all KASAN patches is possible, but that's a lot of work. I 
>>> backported KASAN to the 4.9 Android common kernel two years ago, the 
>>> patches are here: 
>>>
>>> https://github.com/xairy/kernel-sanitizers/tree/android-4.9-kasan 
>>>
>>> But there have been a number of changes since then. 
>>>
>>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4e60f843-ab24-4277-b213-8d4b523c6fc9n%40googlegroups.com.

------=_Part_297_864980608.1614116037574
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hi,<div><br></div><div>Issue resolved.</div><div><br></div><div>Turned out =
that the gcc version used for the kernel was different to the one used for =
out-of-tree modules.</div><div><br></div><div>Shahbaz<br><br></div><div cla=
ss=3D"gmail_quote"><div dir=3D"auto" class=3D"gmail_attr">On Monday, Februa=
ry 22, 2021 at 11:41:32 AM UTC Shahbaz Ali wrote:<br/></div><blockquote cla=
ss=3D"gmail_quote" style=3D"margin: 0 0 0 0.8ex; border-left: 1px solid rgb=
(204, 204, 204); padding-left: 1ex;">Hi,<div><br></div><div>Managed to succ=
essfully port this to my 4.9 kernel.=C2=A0 However, I&#39;m still having th=
e same issue with my out-of-tree modules:</div><div><br></div><div><div>[=
=C2=A0 =C2=A013.657676] KASAN got bad input address: 0000000000000190; (con=
verted to:dfff200000000032)</div><div>[=C2=A0 =C2=A013.669442] KASAN got ba=
d input address: 0000000000000350; (converted to:dfff20000000006a)</div><di=
v>[=C2=A0 =C2=A013.680547] KASAN got bad input address: 00000000000001c0; (=
converted to:dfff200000000038)</div><div>[=C2=A0 =C2=A013.691172] KASAN got=
 bad input address: fffe4000016a3b48; (converted to:fffee800002d4769)</div>=
<div>[=C2=A0 =C2=A013.701755] KASAN got bad input address:=C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0(null); (converted to:dfff200000000000)</div><div>[=
=C2=A0 =C2=A013.712600] KASAN got bad input address: fffe4000016a66c0; (con=
verted to:fffee800002d4cd8)</div><div>[=C2=A0 =C2=A013.723101] KASAN got ba=
d input address: 0000000000000050; (converted to:dfff20000000000a)</div><di=
v>[=C2=A0 =C2=A013.733607] KASAN got bad input address: 00000000000000d0; (=
converted to:dfff20000000001a)</div><div>[=C2=A0 =C2=A013.744125] KASAN got=
 bad input address: 0000000000000040; (converted to:dfff200000000008)</div>=
<div>[=C2=A0 =C2=A013.754642] KASAN got bad input address: fffe4000016a3c20=
; (converted to:fffee800002d4784)</div><div>[=C2=A0 =C2=A013.765136] KASAN =
got bad input address:=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0(null); (con=
verted to:dfff200000000000)</div><div>[=C2=A0 =C2=A013.775619] KASAN got ba=
d input address: fffe4000016a6880; (converted to:fffee800002d4d10)</div><di=
v>[=C2=A0 =C2=A013.786107] KASAN got bad input address: 0000000000000020; (=
converted to:dfff200000000004)</div><div>[=C2=A0 =C2=A013.796587] KASAN got=
 bad input address: 0000000000000060; (converted to:dfff20000000000c)</div>=
</div><div><br></div><div>If I understand correctly, the __asan_register_gl=
obals is being instrumented into the out-of-tree module code during compile=
 time; and during loading of the module,</div><div>this exported function i=
s called with the kasan_global struct data (including memory address of the=
 global)?</div><div><br></div><div>If that&#39;s the case, how is the addre=
ss / kasan_global data determined for the call?=C2=A0 Is this hardcoded in =
by GCC during compile-time (in which case it might be a toolchain issue), o=
r is it probing the kernel for that data during module load?<br><br></div><=
div>Basically, I&#39;m just trying to track down why those global-&gt;beg a=
ddresses are wrong, whose fault it is, and why.=C2=A0 Any further help woul=
d be greately appreciated!</div><div><br></div><div>Thanks,</div><div>Shahb=
az</div><div class=3D"gmail_quote"><div dir=3D"auto" class=3D"gmail_attr">O=
n Tuesday, February 16, 2021 at 4:37:24 PM UTC Shahbaz Ali wrote:<br></div>=
<blockquote class=3D"gmail_quote" style=3D"margin:0 0 0 0.8ex;border-left:1=
px solid rgb(204,204,204);padding-left:1ex">Thanks, I will take anything I =
can get!<div><br></div><div>Shahbaz<br><br></div><div class=3D"gmail_quote"=
><div dir=3D"auto" class=3D"gmail_attr">On Tuesday, February 16, 2021 at 4:=
16:13 PM UTC <a rel=3D"nofollow">andre...@google.com</a> wrote:<br></div><b=
lockquote class=3D"gmail_quote" style=3D"margin:0 0 0 0.8ex;border-left:1px=
 solid rgb(204,204,204);padding-left:1ex">On Tue, Feb 16, 2021 at 5:02 PM S=
hahbaz Ali &lt;<a rel=3D"nofollow">shba...@gmail.com</a>&gt; wrote:
<br>&gt;
<br>&gt; Thanks Andre,
<br>&gt;
<br>&gt; Unfortunately, due to the nature of the system, I do not have an e=
asy option to update it other than apply the 4.9 LTS patches (which I have =
done already).
<br>&gt;
<br>&gt; Do you think it&#39;d be possible for me to backport KASAN from th=
e current version?
<br>
<br>You can try backporting KASAN patches that mention changing global
<br>variables handling, maybe that would help.
<br>
<br>Backporting all KASAN patches is possible, but that&#39;s a lot of work=
. I
<br>backported KASAN to the 4.9 Android common kernel two years ago, the
<br>patches are here:
<br>
<br><a href=3D"https://github.com/xairy/kernel-sanitizers/tree/android-4.9-=
kasan" rel=3D"nofollow" target=3D"_blank" data-saferedirecturl=3D"https://w=
ww.google.com/url?hl=3Den&amp;q=3Dhttps://github.com/xairy/kernel-sanitizer=
s/tree/android-4.9-kasan&amp;source=3Dgmail&amp;ust=3D1614202358912000&amp;=
usg=3DAFQjCNHtsp9f2dZcSdK4ta7_5-piXLdwrA">https://github.com/xairy/kernel-s=
anitizers/tree/android-4.9-kasan</a>
<br>
<br>But there have been a number of changes since then.
<br></blockquote></div></blockquote></div></blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/4e60f843-ab24-4277-b213-8d4b523c6fc9n%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/4e60f843-ab24-4277-b213-8d4b523c6fc9n%40googlegroups.com</a>.<b=
r />

------=_Part_297_864980608.1614116037574--

------=_Part_296_812329996.1614116037574--
