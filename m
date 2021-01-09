Return-Path: <kasan-dev+bncBDKYJ4OFZQIRB3PV4T7QKGQELJH5BXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id B5F7B2EFDDC
	for <lists+kasan-dev@lfdr.de>; Sat,  9 Jan 2021 06:11:10 +0100 (CET)
Received: by mail-vk1-xa38.google.com with SMTP id a204sf6414001vka.21
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Jan 2021 21:11:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610169069; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rs6mmaIotoTFWCOTW3mgJkzdI+RNhXtLLanzgcdGzZsdq0BGBguD6nImc+pQ1kwtlU
         IFjb2eI0FYKXJhcNycka4YjicHXppWhzCFOkt9jT27L+1myUVyhY34cLt89bckZJaVZ8
         k6TzTWl8jlCWd6Kjv+VdJ1YU6VD6aHCpEsfhE+HRLlKh/IfAgwYICArdX+AWap0YwsxJ
         Dpybj1DzZZIRKhh3VAOkN1aZBW7oHgtlkI29LSjEedMr9RJEuHlXYUOeda2O077c+5qT
         HgDuOgBil/ntKMtwhXtEPNuAmee9wjFBtMnmLBb1aPbI+pzA5X14bG9sRVeMuEWdOi+x
         1igw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=8ZL5u/RCX2Tuuh5KpvSYSsQTF41Icq8n+qwfUXgFQls=;
        b=SWN5exktZnnnxTWc8YgLoEWTe/lou8SjoLToiyd/afCR1FRhAXw73YyAgKHJTHhy3j
         liuTwx0Chm1jOTkKOIx2eh/f8zHRNUuToyN55iClIAaiCkz2kZDZK5qeH6hmCzadDitz
         x5lQXQ0/diRhHHCSL4HUFOgRecGFFZ3ZA4s1nns45LurcktFuvTPdgy3oiePBh/7ugv8
         T/+W4X3qZ5URFWc2QQtSD300kOpWqsSN7+fZO74Wnjyf7XJsrbFYnYseiIpp/qmUO6It
         Kq5GQqilq9aEXEJP1F9wp0RkjN2XzbL11UjKiHIH18aTFExEM2tzEClV/YxBtIoAGa4J
         wptQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=ISJfnFac;
       spf=pass (google.com: domain of andy.jinhuang@gmail.com designates 2607:f8b0:4864:20::a2a as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8ZL5u/RCX2Tuuh5KpvSYSsQTF41Icq8n+qwfUXgFQls=;
        b=B7kGZBNHIodS6YgwmYz2sFL7Yw4Mv7mqnNRyQZNoALqIQwKGUwmWjrIT8NuEk8z+xD
         vyAUr1jQW7ILJssiwgDKaVQfMofniJkioqb/Dw1hgplQEYO12y9WnM2CUvOWk66iBc3A
         sXgE1gKy+MPej7oVOwyr8i6OSMteIgaHhSvlOsRPbT8tqsWdOqIeM5jxlCfWwqUS2yEF
         N/HFsX9jKMRrpHPueWo3A/4g5qgoC8JgDgcAu33/E0B5xHNoz87jG9NtUGiZag/xF9aq
         2OuUB8Au1BS5ntUdjHmR3uFfmt+C/wzH2qyJ8JGFaw6JF8Z+yt/NfYHpRy7V8qglGHNT
         W15g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8ZL5u/RCX2Tuuh5KpvSYSsQTF41Icq8n+qwfUXgFQls=;
        b=UiCwEq3+2+2KO4SafymHmxmYRxtATcwX4tFoBKslC7IpENUCcQRCHIf1JWGlVHYE7h
         x3RHJXvbUsyrQSg2CJkIYziwasIIQMRzCYOLQhrC3TQFb7rKGUvAW/WSf4MdcmByr27j
         b+jJCXy9Cr28K0FEpUmLWcOQGxoislv3Y60y2VWiBQBv9zvwsABqV6dQCRynUE851kNu
         uw6Dnw1nwbBdBzrldHoB6+EKZtQjPWRpR040EGkOTHsTSAlvtzPJTxAbYeiSXM5WxF05
         TTs3w9963ZsJ9MIXLa9MIyLfNF0uPXoHLELxFQH/NOkWBBhW6/YbwRn1/vfGIfIx1hcG
         xX/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8ZL5u/RCX2Tuuh5KpvSYSsQTF41Icq8n+qwfUXgFQls=;
        b=ae7oNQW7/DqrXKzABbSrQ5MdOWa0uwq9MotRPL9N/zCdcZDasYlkYJOmc7MbA3eD8e
         QGHGFvedDcacopj8Mb57z7ffoP2MSDnmBRPAn1+VkCZ6UJT/PNFNKVHn9DXIjYlqaf+r
         vW6S/AFEDt1Dqw92aAeU66wR1Y+zRFfx9kHqSJpieQSHR9CqqOdoa8pkGS4e6VIcmST6
         9a6dlcMyetPLxOz2D66tpVahOiMlMm3GVGkHLKZ1Nrsm2/uKTxrWn2G/49QVQZWOvdRx
         s2YT7WL44RiZ/7JUNXZV9km2765uvDkspvjDWyqO8u7nL8tSiF6/CQssh3qL7kiPy+kn
         aHJg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Ev+8W7KXpPV8ERtZX/UVkl+J1WMFSdkLRGAkvJ8mFcmajcXbL
	2InPrAg/3dzKH83u7313y/4=
X-Google-Smtp-Source: ABdhPJyu/mklAfEjRzr8IX7iJKOfgQt6UDlvDvtoqymGMc3iOfuZt09RIukHBJ76rh8KTIWbYI8WaQ==
X-Received: by 2002:a67:be17:: with SMTP id x23mr5981670vsq.59.1610169069448;
        Fri, 08 Jan 2021 21:11:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:ea12:: with SMTP id g18ls1761413vso.9.gmail; Fri, 08 Jan
 2021 21:11:09 -0800 (PST)
X-Received: by 2002:a67:cfc9:: with SMTP id h9mr5684553vsm.23.1610169068995;
        Fri, 08 Jan 2021 21:11:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610169068; cv=none;
        d=google.com; s=arc-20160816;
        b=eNZgOgihZLC27i1gas+JDKyVnPp7/g6Kq347vFU6PdrM+XIpn+YEjOLdXIMVeMg5RE
         Phhp4CA1JzIKgmL/Vbsqub7AWIZQLroFvlDnpAoGHXIqJXori3oQeE9igmBdjsk7gBQ0
         590K+8SLLAcCbwXblN4L/HJJ9ycAic/75vhDo3E3KmJNUvg9NRfzYSG61SF8866jxxea
         lMEYWTzm3adsQ/SwCP5daCtOAuiiBctT54fgU/IscldPX3x+uu4MCvP991QPC70wkO5R
         yojdpAbe7U/SCiy4ZcUBzvvLNLfA1Luwf019eEb6/RirS/dW3nw1Hq5zO3ylgUhNJjux
         kC0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=/eeHygNEcrW8czXE3a6KF69yjIHX1BInbBCMgwRX5cU=;
        b=wcDXXsz+KVTsafiDrZ8qeUtfhVFo3jrYvWy2ylmAgwMeXCw7BM7wYQe4TAte0TiGJv
         aEkc7QKH8r3ROmKQiEMcD5Oh9vXe1EAsjoF9fZ5UzoHGi9rmTB+cpEc2YJwLhCQja89E
         cXylD9ZIk+5dJU+xrTZQp1qM0OkkGjb4ssOIzx8ql6MPnYxVdWfQbjLeabPlUMuZmBiG
         7t9uwVHYFmstiZ2LAIcl2KkIK1xDLDqN7XaQkAQtT9Eq+1yiAgKJBs/BQjTTbEysoPP3
         Y5Q2StJ0tRoEc6/IRa+KC+JoV9Jn5zFu+O3TnDrSiFw4MfxOBHRA+MXNAW/yFyeRNbgb
         5l8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=ISJfnFac;
       spf=pass (google.com: domain of andy.jinhuang@gmail.com designates 2607:f8b0:4864:20::a2a as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-vk1-xa2a.google.com (mail-vk1-xa2a.google.com. [2607:f8b0:4864:20::a2a])
        by gmr-mx.google.com with ESMTPS id g17si323006vso.1.2021.01.08.21.11.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Jan 2021 21:11:08 -0800 (PST)
Received-SPF: pass (google.com: domain of andy.jinhuang@gmail.com designates 2607:f8b0:4864:20::a2a as permitted sender) client-ip=2607:f8b0:4864:20::a2a;
Received: by mail-vk1-xa2a.google.com with SMTP id t16so3006515vkl.10
        for <kasan-dev@googlegroups.com>; Fri, 08 Jan 2021 21:11:08 -0800 (PST)
X-Received: by 2002:a1f:9fce:: with SMTP id i197mr6027121vke.18.1610169068399;
 Fri, 08 Jan 2021 21:11:08 -0800 (PST)
MIME-Version: 1.0
From: Jin Huang <andy.jinhuang@gmail.com>
Date: Sat, 9 Jan 2021 00:10:57 -0500
Message-ID: <CACV+narOjL5_o_in_WtOo9kjhcKFD4S4ozctPtdj6JR0+b8adg@mail.gmail.com>
Subject: KCSAN how to use
To: kasan-dev@googlegroups.com, paulmck@kernel.org
Content-Type: multipart/alternative; boundary="00000000000059afd205b870b34e"
X-Original-Sender: andy.jinhuang@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=ISJfnFac;       spf=pass
 (google.com: domain of andy.jinhuang@gmail.com designates 2607:f8b0:4864:20::a2a
 as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;       dmarc=pass
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

--00000000000059afd205b870b34e
Content-Type: text/plain; charset="UTF-8"

Hi,
My name is Jin Huang, a graduate student at TAMU. I am interested in KCSAN.
I want to ask is there any hands-on instructions/introductions about how to
run KCSAN on Linux Kernel?
According to the official document, I compiled the 5.10.5 kernel with
Clang11 and CONFIG_KCSAN=y, but after I runned it on QEMU, I did not see
any information about KCSAN in the dmesg info.
Is it the correct way to try KCSAN on Linux Kernel, or any instructions?

Thank You
Best
Jin Huang

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACV%2BnarOjL5_o_in_WtOo9kjhcKFD4S4ozctPtdj6JR0%2Bb8adg%40mail.gmail.com.

--00000000000059afd205b870b34e
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Hi,<div>My name is Jin Huang, a graduate student at TAMU. =
I am interested in KCSAN.<br><div>I want to ask is there any hands-on instr=
uctions/introductions about how to run KCSAN on Linux Kernel?</div><div>Acc=
ording to the official document, I compiled the 5.10.5 kernel with=C2=A0 Cl=
ang11 and CONFIG_KCSAN=3Dy, but after I runned it on QEMU, I did not see an=
y information about KCSAN in the dmesg info.</div><div>Is it the correct wa=
y to try KCSAN=C2=A0on Linux Kernel, or any instructions?<br clear=3D"all">=
<div><div dir=3D"ltr" class=3D"gmail_signature" data-smartmail=3D"gmail_sig=
nature"><div dir=3D"ltr"><div><br></div><div>Thank You</div>Best<div>Jin Hu=
ang</div></div></div></div></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CACV%2BnarOjL5_o_in_WtOo9kjhcKFD4S4ozctPtdj6JR0%2Bb8ad=
g%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CACV%2BnarOjL5_o_in_WtOo9kjhcKFD4S4ozctPtdj6JR0=
%2Bb8adg%40mail.gmail.com</a>.<br />

--00000000000059afd205b870b34e--
