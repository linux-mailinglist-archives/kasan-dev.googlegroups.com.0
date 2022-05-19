Return-Path: <kasan-dev+bncBD427JUBYAARBN5US6KAMGQEJNLLSAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A57152CBA1
	for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 07:48:40 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id o12-20020a4aa80c000000b0035ea8bd060asf2140796oom.3
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 22:48:40 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:message-id:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GHSdBFqSNVY28RrfbJcIC4HCvbbXR7KcCz6y4++PZKk=;
        b=lrZtFAITOSEOaWQybUi2hBQujGJrZi7R4kW5MrxOX0PL6+H3cJZUAMFpWAJAezJk/n
         3q85Jo6ohwHuM+hKXKudhXsEqpXHuyGrs+kERd55M0+sSMCv1EJxkrTZfsMgdAlkKNPI
         gPTNU8SYjdA86wHnO8n0GjMd5fecse+TDsNUSnTj/rEnJY3EpIdarC3TKD9X88QYbZ9U
         msD9tNkJkM4Qv4ebH3DzkNeX3tSDZaZ/MuUicB4bIBBF1493qI7awfgiWUzhEvwJTQ8O
         A1rmMrq+8g3ueUrHEUmEnv47gKw26eTsLKwwZJ9MGEctEiyYFlmOmHQsVFC4ajPydLso
         S4Ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:message-id:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GHSdBFqSNVY28RrfbJcIC4HCvbbXR7KcCz6y4++PZKk=;
        b=ya1td4M4mQbaCmANycgOBqe3kuF8TfkzMuUxoz76u16GjdoKXmWBtcoBRFzewqY65X
         meeX6w4Q8Jbzdz5mBjQ87mHB8v9vIRqG7DknS+VKjgp0Sq4U3uLjcMLH4tLm3xwXssSP
         6RQS0n+z+Ve7SasWbmYtbUB2tUDa302vQqMTcqVERaPEPTfeez8WJPCKfMY4f6L8/kF8
         Dy9cnnLVBmOy+OHWQAj7fo5FoCYehInGcUHf8CvVMzAUnL/I+5OhbrgenMSWYQPGmqbw
         dikmGFUwudQZEiKGXHkYGgsDEu+r2jSDkTKy393Pp9Rnxm7AZshO34lgC+oAwCSa4zv5
         5/cg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532qPHBujCXSmHcI/YiBDN/nn7oKX8t3PicbFmKZLVxWi5WoYisz
	Gkha5Mq9wpBPDJ7/MmNEey8=
X-Google-Smtp-Source: ABdhPJxjrr4RjFasQqakVhwXuqDRWwVzv2BrWD6chLTGolhwnKq2+atRTZcoTAXBiUJa0r5qAnNKmQ==
X-Received: by 2002:a05:6808:2389:b0:32a:e3d7:56dc with SMTP id bp9-20020a056808238900b0032ae3d756dcmr1388484oib.57.1652939319408;
        Wed, 18 May 2022 22:48:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:13cd:b0:de:c1c1:ac0e with SMTP id
 13-20020a05687013cd00b000dec1c1ac0els765135oat.8.gmail; Wed, 18 May 2022
 22:48:39 -0700 (PDT)
X-Received: by 2002:a05:6870:204c:b0:ee:1742:1be3 with SMTP id l12-20020a056870204c00b000ee17421be3mr1742322oad.170.1652939319005;
        Wed, 18 May 2022 22:48:39 -0700 (PDT)
Date: Wed, 18 May 2022 22:48:38 -0700 (PDT)
From: "youyo...@126.com" <youyou8075@126.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <266bea64-68dd-4ebf-84ae-040b2c9b364en@googlegroups.com>
Subject: enable kasan config on android,  but it can not boot up
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_208_1740872457.1652939318451"
X-Original-Sender: youyou8075@126.com
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

------=_Part_208_1740872457.1652939318451
Content-Type: multipart/alternative; 
	boundary="----=_Part_209_1762751607.1652939318452"

------=_Part_209_1762751607.1652939318452
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hi All,

I want to enable KASAN function on Android12, after try many times , I can=
=20
successfully build boot.img, when I flash boot.img to the device , it does=
=20
not work=EF=BC=8C it means the system can not boot up.

so compare the size of vmlinux , I found strange Phenomenon,  like the=20
below, according to=20
https://source.android.com/devices/tech/debug/kasan-kcov#troubleshooting,=
=20
the image size should be become larger when enable KASAN, but I found the=
=20
size is samller when enable KASAN.

351910528 May 18 22:53 vmlinux  enable KASAN

694713016 May 18 22:40 vmlinux  disable KASAN

I have done some searching, but could not find the answer.
Could someone help me with this? Thanks in advance!

BR.
McKay.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/266bea64-68dd-4ebf-84ae-040b2c9b364en%40googlegroups.com.

------=_Part_209_1762751607.1652939318452
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hi All,<div><br></div><div>I want to enable KASAN function on Android12, af=
ter try many times , I can successfully build boot.img, when I flash boot.i=
mg to the device , it does not work=EF=BC=8C it means the system can not bo=
ot up.<br><br>so compare the size of vmlinux , I found strange Phenomenon, =
&nbsp;like the below, according to https://source.android.com/devices/tech/=
debug/kasan-kcov#troubleshooting, the image size should be become larger wh=
en enable KASAN, but I found the size is samller when enable KASAN.<br><br>=
351910528 May 18 22:53 vmlinux &nbsp;enable KASAN<br><br>694713016 May 18 2=
2:40 vmlinux &nbsp;disable KASAN<br><br>I have done some searching, but cou=
ld not find the answer.<br>Could someone help me with this? Thanks in advan=
ce!<br></div><div><br></div><div>BR.</div><div>McKay.</div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/266bea64-68dd-4ebf-84ae-040b2c9b364en%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/266bea64-68dd-4ebf-84ae-040b2c9b364en%40googlegroups.com</a>.<b=
r />

------=_Part_209_1762751607.1652939318452--

------=_Part_208_1740872457.1652939318451--
