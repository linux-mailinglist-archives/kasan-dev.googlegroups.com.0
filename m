Return-Path: <kasan-dev+bncBC63BL75QIBRBHEAVLXQKGQEFR2J5FA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 75EF4115509
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Dec 2019 17:21:50 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id t11sf4037897pgm.2
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Dec 2019 08:21:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575649309; cv=pass;
        d=google.com; s=arc-20160816;
        b=A3Q2mWwSFjPfoOj/SpODVqgpNYk9/MQx7wb5tQc/27gDGiyh3D5kUMADNabf38HWKy
         0Em3WMF27jkI4pDZwGyPGWz6hnMPybgdbAdousm45Gd4ye83TpHt/d5sDvA8H4IKOzyo
         2ra2iClyRG8HRmfRueYym7gvxYSNrOMxLNjmbyPTDxKawwToCt1bunVNeL8EBsOyO2Zw
         r471ycMjwgspP9Vdex3iCfP0AwJKY/Gxe+BGn1HeTI4hKYDWWgX/9LyYD7Nf6Rp7Bzfi
         Wi3CbDHxQPDAX8zduEvnJBrGVIOlaUFFxrmmBoxvRk9mJpnaZSRYVrZPjhmbOobDGO2J
         bpyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=R9/9+30zv5FeCYLWgCHq4v2mUhDvw7OSHL4tVVrt88c=;
        b=owUUz0ou3baiQARgyc96WKkNS4Yb7uKzGjMvusykc1pMdVYPc5w1q1cfKLK6QhnOZE
         V1h+T65RPJIiZfTRmNVUXkIHRfvp+CobzllegkFNFd68YMaRnDUi55W8FRX5Zn8aaJUO
         00VpRQHsiBWH8KvJp1AekWds93Rt086cVAPrLBA+G0ivPVighwIS0tCk45vrqDRbVNln
         V1oWAgxh0ysioERYoy5lUONzDKdaGhPEOCvMKIzVq5yuG7unzA5aDfsWL5R6D2uwkVfH
         rYZ8T5O5vEx18KOAugPxkZxuVPA2CO9ADfPLPSFkfNkbTuvnGGbnaeS4vczYgAGMcStT
         qJtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=kK9OimSa;
       spf=pass (google.com: domain of vermasachin09@gmail.com designates 2607:f8b0:4864:20::136 as permitted sender) smtp.mailfrom=vermasachin09@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R9/9+30zv5FeCYLWgCHq4v2mUhDvw7OSHL4tVVrt88c=;
        b=ZYgwTKdmyY826BF+cSG3F9AKI2KSGlq4Px0WDscrD9dBzJzsYrczSqs/fHKqpNoqm9
         R6kKAeMWgGVc2UczEJBvask1kGuox6nclHVjlujmDJnZnJi/F8hnaus14AuChSjgkmkA
         CfdiQN7ta2IiqBmrj2kTcc/6RgWYPxPjXsJPxCvg6+hK8piTi9EMO7g3zuR+F6l0jig6
         aYW28we0JK4KtJ5cWlC8pTYFJNH23SX6bF7rGYGBSBHE+oEcKcZ8RYHO1SUnkbDsjLHt
         xmUA4HeXJcqz5BkuN/+js+wxwfvOeDjkhNaxzsnmx28EywpdcOc8Q2cDCpYITcO7qUIv
         p71A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=R9/9+30zv5FeCYLWgCHq4v2mUhDvw7OSHL4tVVrt88c=;
        b=WoNLCLf6btEfloeB4pyWcKo+zdxp05cntCihnWh/+efTLbAWPERVkyF/gnSjvFUcbT
         n/en4BagyZQg15VEZ6sj1AyNsdcMx6mFeVo0Nn3IO4vPY5jtZvLsCdKYqbcxeWpsxitj
         Bc7AqQQ4MY1mVZS2KRyfalLFg/GYkLErLQFf3EmVDovWTEVEsKrfsm/2OTAqUAzZJ4FN
         7CbAN9PHjTIflWVtjNDmlB6odfdoXvOIrF/OPCSZ62DcYPd5eZBZFoviB+cH+ILDKeZW
         sgEBTQAYYDveXUgjOR/9RkmK2qHe9kjdDx4aLzKCj4cqUnZo09jtyGpZ1y0xG4P7nq53
         ypOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=R9/9+30zv5FeCYLWgCHq4v2mUhDvw7OSHL4tVVrt88c=;
        b=aFYRGMyCL1udi1p9S5Q+XFUj7tBrLo6cdzduhqm5ruK6J1rCv6vPKZuuEC7X2/7DnA
         /mEVbKAkDlcM52C+MSMTkhdF9lARphWJ1uTJ0EF497XQdvkx4DU+DOzZFqBiozXE7kRk
         DiZvtKJ+q7W5+OG05soekwMnwTmtVyAZXtVEtJkBFJUAMlXBHiFh5oRfPkI0L5c7EnaY
         RbZ507bT3YF/n6+F7+q6U09QbqSXgYrNkx928eZ41gOwBNNTFD8ZZNwOvaSo+ipPqi7C
         yTnS3yELMDp283hEbiQQ7RHY6y502BcGSojaD0Vu8AysUh2FKpAV0345hrMRrHFZIaOQ
         8yxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXUKCCNjfYlnwG57raj4kA0arWHJOCNbVkTQFNCSqLY4brGWiUO
	C5jWra77KcA9965aLmRjKXk=
X-Google-Smtp-Source: APXvYqzl1QU1AqgcaxrnpnSOOezBSdwFe5o49Ktwz46mfx6oEQlRg5k9ukU0xwHQBOoOA8zIAXz84A==
X-Received: by 2002:a62:e914:: with SMTP id j20mr15538469pfh.245.1575649308592;
        Fri, 06 Dec 2019 08:21:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:3b42:: with SMTP id t2ls1805494pjf.2.gmail; Fri, 06
 Dec 2019 08:21:48 -0800 (PST)
X-Received: by 2002:a17:90a:3aaf:: with SMTP id b44mr16940967pjc.9.1575649308213;
        Fri, 06 Dec 2019 08:21:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575649308; cv=none;
        d=google.com; s=arc-20160816;
        b=qliYG/2OZXOic4NM9+JrL/RvEoY1r0n6GyoyyYRKW0ggL+zamycUeEtmyNiwbYsZCU
         +uBoWwNY1BTlIPgNH3GoG2Gc1gG2rIU5pLxbTds11WxgLC3RwT6u3VhVmQXQB0cADwQ1
         eT8SOWH5wzWWr4Quh72QrCtb7rfMWabpRGCCJFuhepXojEhnH2yPXTb4sugNvCxI4Pbw
         WYNOu+WMSpfT4CgsasgkZd/Vh1az1X2m3KB9rsbnZlNqc+7UAT++05XFL3hQh/7MZsOt
         nXETZMA/M7w4apESK31Plp+3uPFSU97bEHcrqbvDvD8bA1eooXLWqIlB3rRvA+qZt++d
         MeXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=Ff7cEEUlORqgwaoTuF7lBsqX9NejKmYzFGOm1lP3aT0=;
        b=E10a4L1z1d2N2kqBYPqJ6qvPIdkvw2jZ//USiJOwy2CWmfmXZg06d8Znj0Vc4Di2dZ
         dsbz/0IUA9VE506YKsQbiKJY1lvuImOpPSZdU/VcqoNTA3j/CjwgqVpk7X/XomPk/qTE
         yLuflKLVs/ceLmqJwLfKbi7TIelBRmLgrLENhBNtNwGhdkPKyJJy1GGmzfYibgTY1tny
         NG+1oILkn9ypIJ4xgChHYF0U9ExYkyusvok+/T8F9T5JCXp2Sb35BX7JukcHzUaVVpEU
         0BkMpM+25aSDgCF7jiwn3wFkJtb2HbMgBTZJ0uWXZspU7GOWEor5TaDVe/rtYyrckMKJ
         40pQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=kK9OimSa;
       spf=pass (google.com: domain of vermasachin09@gmail.com designates 2607:f8b0:4864:20::136 as permitted sender) smtp.mailfrom=vermasachin09@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x136.google.com (mail-il1-x136.google.com. [2607:f8b0:4864:20::136])
        by gmr-mx.google.com with ESMTPS id i131si710847pfe.3.2019.12.06.08.21.48
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Dec 2019 08:21:48 -0800 (PST)
Received-SPF: pass (google.com: domain of vermasachin09@gmail.com designates 2607:f8b0:4864:20::136 as permitted sender) client-ip=2607:f8b0:4864:20::136;
Received: by mail-il1-x136.google.com with SMTP id u17so6736283ilq.5;
        Fri, 06 Dec 2019 08:21:48 -0800 (PST)
X-Received: by 2002:a92:3602:: with SMTP id d2mr14855994ila.7.1575649307325;
 Fri, 06 Dec 2019 08:21:47 -0800 (PST)
MIME-Version: 1.0
From: sachin verma <vermasachin09@gmail.com>
Date: Fri, 6 Dec 2019 21:51:36 +0530
Message-ID: <CA+YOsKJ-ejSNp8htq3+r2kmdW=9Q7UAsb0fLugyX_1VbzmaRfA@mail.gmail.com>
Subject: Flashed Kernel for Pixel2 but changes not appears
To: kasan-dev@googlegroups.com, linux-kbuild@vger.kernel.org, 
	linux-ntb@googlegroups.com, android-building@googlegroups.com
Content-Type: multipart/alternative; boundary="00000000000040faea05990b71d8"
X-Original-Sender: vermasachin09@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=kK9OimSa;       spf=pass
 (google.com: domain of vermasachin09@gmail.com designates 2607:f8b0:4864:20::136
 as permitted sender) smtp.mailfrom=vermasachin09@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--00000000000040faea05990b71d8
Content-Type: text/plain; charset="UTF-8"

Hi,
I have flashed android10 kernel for Pixel 2 with some changes(additional
logs) but the logs are not appearing in kmsg or dmesg, *Even I have append
the existing log(the logs which are printing on original build) but could
not get modified logs only original's one printing.* It Seems modified code
(modified logs) not flashing in the system.


*Here are the steps I am doing:*

Downloaded AOSP10 and build for aosp_walleye-userdebug
Downloaded the kernel code from *repo branch android-msm-wahoo-4.4-*
*android10-qpr1*.
Compile the kernel by *build/build.sh *from kernel root directory.
Copy the Image.lz4-dtb file generated with build/build.sh to the AOSP
kernel folder of my device i.e /device/google/wahoo-kernel, substituting
the existing one.
run m bootimage to generate boot.img
adb reboot bootloader
fastboot flashall -w to flash the build
Now I can see the kernel build which shows the latest date of kernel build
in device Settings, means kernel flash is successful. But my changes are
not appearing means modified logs are not appearing.


Here are the files I have added/modified the logs
drivers/staging/qca-wifi-host-cmn/wmi/src/wmi_unified_tlv.c
drivers/staging/qcacld-3.0/Kbuild
drivers/staging/qcacld-3.0/core/hdd/src/wlan_hdd_cfg80211.c
drivers/staging/qcacld-3.0/core/hdd/src/wlan_hdd_main.c
drivers/staging/qcacld-3.0/core/wma/src/wma_dev_if.c
drivers/staging/qcacld-3.0/core/wma/src/wma_mgmt.c


*One example of my changes(append msg in existing log):*
-       hdd_info("Disabling queues, adapter device mode:
%s(%d)",hdd_device_mode_to_string(adapter->device_mode),
                 adapter->device_mode);   *---->*
+       hdd_info("*Modified* ...Disabling queues, adapter device mode:
%s(%d)",hdd_device_mode_to_string(adapter->device_mode),
                 adapter->device_mode);
So I am not getting modified versions. while I have checked in kernel
source there's no other place for this log.

Please let me know if any prebuilt binary are there in kernel source for
*staging* module or If I am missing some configuration during compilation.

Thanks,
Sachin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BYOsKJ-ejSNp8htq3%2Br2kmdW%3D9Q7UAsb0fLugyX_1VbzmaRfA%40mail.gmail.com.

--00000000000040faea05990b71d8
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div>Hi,</div><div>I have flashed android10 kernel for Pix=
el 2 with some changes(additional logs) but the logs are not appearing in k=
msg or dmesg, <b>Even I have append the existing log(the logs which are pri=
nting on original build) but could not get modified logs only original&#39;=
s one printing.</b> It Seems modified code (modified logs) not flashing in =
the system.</div><div><b><br></b></div><div><b><br></b></div><div><b>Here a=
re the steps I am doing:</b></div><div><b><br></b></div><div>Downloaded AOS=
P10 and build for aosp_walleye-userdebug</div><div>Downloaded the kernel co=
de from <b>repo branch android-msm-wahoo-4.4-</b><b>android10-qpr1</b>.</di=
v><div>Compile the kernel by <b>build/build.sh </b>from kernel root directo=
ry.<b><br></b></div><div>Copy the Image.lz4-dtb file generated with build/b=
uild.sh to the
AOSP kernel folder of my device i.e /device/google/wahoo-kernel, substituti=
ng the existing one.</div><div>run m bootimage to generate boot.img <br></d=
iv><div>adb reboot bootloader</div><div>fastboot flashall -w to flash the b=
uild</div><div>Now I can see the kernel build which shows the latest date o=
f kernel build in device Settings, means kernel flash is successful. But my=
 changes are not appearing means modified logs are not appearing.</div><div=
><br></div><div><br></div><div>Here are the files I have added/modified the=
 logs</div><div>	drivers/staging/qca-wifi-host-cmn/wmi/src/wmi_unified_tlv.=
c<br>	drivers/staging/qcacld-3.0/Kbuild<br>drivers/staging/qcacld-3.0/core/=
hdd/src/wlan_hdd_cfg80211.c<br>drivers/staging/qcacld-3.0/core/hdd/src/wlan=
_hdd_main.c<br>	drivers/staging/qcacld-3.0/core/wma/src/wma_dev_if.c<br>	dr=
ivers/staging/qcacld-3.0/core/wma/src/wma_mgmt.c</div><div><br></div><div><=
br></div><div><b>One example of my changes(append msg in existing log):</b>=
<br></div><div>- =C2=A0 =C2=A0 =C2=A0 hdd_info(&quot;Disabling queues, adap=
ter device mode: %s(%d)&quot;,hdd_device_mode_to_string(adapter-&gt;device_=
mode),<br>=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0ada=
pter-&gt;device_mode);=C2=A0=C2=A0 <b>----&gt;</b><br>+ =C2=A0 =C2=A0 =C2=
=A0 hdd_info(&quot;<b>Modified</b> ...Disabling queues, adapter device mode=
: %s(%d)&quot;,hdd_device_mode_to_string(adapter-&gt;device_mode),<br>=C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0adapter-&gt;devi=
ce_mode);</div><div>So I am not getting modified versions. while I have che=
cked in kernel source there&#39;s no other place for this log.</div><div><b=
r></div><div>Please let me know if any prebuilt binary are there in kernel =
source for <b>staging</b> module or If I am missing some configuration duri=
ng compilation.</div><div><br></div><div>Thanks,</div><div>Sachin<br></div>=
<div> <br></div><div><br></div><br>=C2=A0<br></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CA%2BYOsKJ-ejSNp8htq3%2Br2kmdW%3D9Q7UAsb0fLugyX_1Vbzma=
RfA%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups=
.google.com/d/msgid/kasan-dev/CA%2BYOsKJ-ejSNp8htq3%2Br2kmdW%3D9Q7UAsb0fLug=
yX_1VbzmaRfA%40mail.gmail.com</a>.<br />

--00000000000040faea05990b71d8--
