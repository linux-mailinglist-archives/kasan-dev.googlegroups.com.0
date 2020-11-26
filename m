Return-Path: <kasan-dev+bncBC6Z3ANQSIPBBOGZ736QKGQEBOGWFDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-f188.google.com (mail-pl1-f188.google.com [209.85.214.188])
	by mail.lfdr.de (Postfix) with ESMTPS id 32D6E2C552E
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Nov 2020 14:25:14 +0100 (CET)
Received: by mail-pl1-f188.google.com with SMTP id w1sf1513525plz.14
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Nov 2020 05:25:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606397112; cv=pass;
        d=google.com; s=arc-20160816;
        b=JA6jnBcw7WdSLZ/KP+/sEF1RIcepGy9iJNo1gja8T61oQHYoeUHfDDA2OxTb9NXT/i
         khG+wKClt2fGw3LBGWQcFNQ+WpcfwaVBQATI+7vqUUtwAal4GvkfXUp6v1tQJ7FjbBFb
         BBBOtxoUrdgwsFWr/NhntIaixf6U/LHKb/AFoSL+JMhM4O0sT7VaAOb2ivMW/+iDsu70
         h0C0oTOF7nItax565onDyVom0Ig+bFzUQgHCqwfATX9GxRRkZ4fVbJwT7Qmfu16hqYWd
         GISjZirndxmHoT09d3tQgusvY/Wm68cOwLDw0pjV0wA1V635ymTRyszeMt1RpF07CUpy
         q+Vg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date
         :content-transfer-encoding:mime-version:subject:cc:to:from:sender;
        bh=CbCKY7ymHoNODQxQ+NDHrWcSWiq6jTbEdr43aAHsWEo=;
        b=oL43HLg1xl/s0MG39OYMAjGsv8a0RWohbMAXWbB1CCqYSTawk6pI4oBVaA9NXc7ovm
         RGLtrogUs+mBSwTLyCb4xBX8F3uRViHxVoHniZXlBHURc3mq14UsNxf611jVCDqbRDca
         iMSP2+13skVhPu42Cq+OYScEkZHv6H6q50uANvEVH+ioBGDR47RD+WePrbbYJ2Ic7NEw
         Xen87j/Ont/95n9O3NHun1gnFfJB5yF7XCv0KTr0wM7aPCxjutyKHfbEnPJ7nnyHx/Kp
         //r9uSKy3gLl4KlrwGpK7AOdPUKbgZFTQFzzJQZaWbEBmCh2blzp/zIjalixQltCZrBG
         M0yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@vt-edu.20150623.gappssmtp.com header.s=20150623 header.b="NAQ/wmKB";
       spf=pass (google.com: domain of valdis@vt.edu designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=valdis@vt.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=vt.edu
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:from:to:cc:subject:mime-version
         :content-transfer-encoding:date:message-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CbCKY7ymHoNODQxQ+NDHrWcSWiq6jTbEdr43aAHsWEo=;
        b=aY5QSm2JfngAdXwn1mCNoW6IOJ0vPuZH3fCT5xmVMqliXcqrSZdN3QhB2SKwANUtkV
         acTU1qqsSSvx6dtoZt8mv4ggMj3oS7FcmP61xfjU/uwH1I1jc2/ZDB73XyMG5PqLuDfU
         AmnjWQo9kT2OrKvPccwMiNX1CPl+iOFB3aAT2Wnh5MlTBPFeI0IaEf+NU1PJ7zxsRC1I
         YZn/mqKj1BHwBferTE0svslIVOKSqb0Y7UAPe10NYA55IV3LnDbUwh3COHXyvn0IiXxJ
         xHnVt2WPCP+dg5fXI4ID+K+feNGl6Q4nCHm81KujNldwbGl852hrpoB15qnFXHJsTKJl
         k5dQ==
X-Gm-Message-State: AOAM532yc4fmUWdoDhW2Xno1hI7LhJFt0AjZSEP54ufzl8L/s5142CD6
	Ao3CzwBAAQZreJbcbxkGEUo=
X-Google-Smtp-Source: ABdhPJzEM85raY8KFPW9UJhMOq45xgR4oz7L+xd9XYoN5zh3BxjzgXrFtPgHvLONrpbeWF7n29BQDg==
X-Received: by 2002:a17:90a:af88:: with SMTP id w8mr3495682pjq.152.1606397112685;
        Thu, 26 Nov 2020 05:25:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ec06:: with SMTP id l6ls1055363pld.8.gmail; Thu, 26
 Nov 2020 05:25:12 -0800 (PST)
X-Received: by 2002:a17:90a:e646:: with SMTP id ep6mr3736485pjb.218.1606397111876;
        Thu, 26 Nov 2020 05:25:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606397111; cv=none;
        d=google.com; s=arc-20160816;
        b=BdUkb8gc8uLIQsxpQx0zrbgNzo2WUXXDbaoVs0TvhTmzbRZKcdydQTS+V+u8Y4RHGE
         QRqbFnRGueWn/QU6bL1o1po9o3en+FP03wQBqM5P2vKnf4vQDT5VykN8Ak5DzX4K8qRq
         j5y2jCUoX9aGPomUIhQ0xVA4ahCwhxh1m2j8DeJCOgT/ET4tmD3d3I6wC7cxbPTrf85Q
         qlp6xods+x8vXufyRs6tA3N+taIJWm9ZJU7RjacLut08U7JSslkcLDF462L/H/HtRJKB
         jONjmyEqaUBhvXPdMyL7Ggt75AoJUzvx7Hz9RwhuF7VcAInP1JpvyrsAufh9EKTwJsso
         wyJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:content-transfer-encoding:mime-version:subject:cc
         :to:from:sender:dkim-signature;
        bh=MNcQv1d1aoirYTMBX9DjnG1i0iErg2wQNhH4EnUPrCs=;
        b=j9YNBPw9Nr6PPoGnqfI1eI9AYTZEd6xmrQXRXyzuegOrZrHUrAMG6RQmOlUxF4ylQS
         ozrz7X1GTv2+b35I7pnHGuIRELoCZ37stdeLIegTbE398Cv76l2BJbVIMobz1htaOc7B
         CiZAHh/1I/DSwz2GWL7+g2oxYDiJqsLgPYptZCuJs/sFZ0j/F46dqOMpQSW+1SMCL5cS
         gOSEugjFJoMwQ9BRXTWV29PuLyGvcJsLSs34eX3ZuuxLvu1vSGYdY8ovKDci06YsLHP2
         eGvjkf5GfjiDGP60D72W2q8yaJ2p7vpm7LNktX+5xkS2sraZFYjbb1pLcJ0qLPuZDcwp
         1t2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@vt-edu.20150623.gappssmtp.com header.s=20150623 header.b="NAQ/wmKB";
       spf=pass (google.com: domain of valdis@vt.edu designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=valdis@vt.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=vt.edu
Received: from mail-qv1-xf34.google.com (mail-qv1-xf34.google.com. [2607:f8b0:4864:20::f34])
        by gmr-mx.google.com with ESMTPS id l23si178255pjt.1.2020.11.26.05.25.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Nov 2020 05:25:11 -0800 (PST)
Received-SPF: pass (google.com: domain of valdis@vt.edu designates 2607:f8b0:4864:20::f34 as permitted sender) client-ip=2607:f8b0:4864:20::f34;
Received: by mail-qv1-xf34.google.com with SMTP id x13so892736qvk.8
        for <kasan-dev@googlegroups.com>; Thu, 26 Nov 2020 05:25:11 -0800 (PST)
X-Received: by 2002:ad4:4743:: with SMTP id c3mr3126157qvx.31.1606397105649;
        Thu, 26 Nov 2020 05:25:05 -0800 (PST)
Received: from turing-police ([2601:5c0:c380:d61::359])
        by smtp.gmail.com with ESMTPSA id t133sm2418736qke.82.2020.11.26.05.25.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Nov 2020 05:25:03 -0800 (PST)
Sender: Valdis Kletnieks <valdis@vt.edu>
From: "Valdis =?utf-8?Q?Kl=c4=93tnieks?=" <valdis.kletnieks@vt.edu>
X-Mailer: exmh version 2.9.0 11/07/2018 with nmh-1.7+dev
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
    linux-kernel@vger.kernel.org
Subject: linux-next 20201126 - build error on arm allmodconfig
Mime-Version: 1.0
Content-Type: multipart/signed; boundary="==_Exmh_1606397102_2385P";
	 micalg=pgp-sha1; protocol="application/pgp-signature"
Content-Transfer-Encoding: 7bit
Date: Thu, 26 Nov 2020 08:25:02 -0500
Message-ID: <24105.1606397102@turing-police>
X-Original-Sender: valdis.kletnieks@vt.edu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@vt-edu.20150623.gappssmtp.com header.s=20150623 header.b="NAQ/wmKB";
       spf=pass (google.com: domain of valdis@vt.edu designates
 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=valdis@vt.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=vt.edu
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

--==_Exmh_1606397102_2385P
Content-Type: text/plain; charset="UTF-8"

Seems something is giving it indigestion regarding asmlinkage...

  CC      arch/arm/mm/kasan_init.o
In file included from ./include/linux/kasan.h:15,
                 from arch/arm/mm/kasan_init.c:11:
./arch/arm/include/asm/kasan.h:26:11: error: expected ';' before 'void'
 asmlinkage void kasan_early_init(void);
           ^~~~~
           ;
make[2]: *** [scripts/Makefile.build:283: arch/arm/mm/kasan_init.o] Error 1
make[1]: *** [scripts/Makefile.build:500: arch/arm/mm] Error 2
make: *** [Makefile:1803: arch/arm] Error 2

Git bisect points at:

commit 2df573d2ca4c1ce6ea33cb7849222f771e759211
Author: Andrey Konovalov <andreyknvl@google.com>
Date:   Tue Nov 24 16:45:08 2020 +1100

    kasan: shadow declarations only for software modes

Looks like it's this chunk:

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 59538e795df4..26f2ab92e7ca 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -11,7 +11,6 @@ struct task_struct;

 #ifdef CONFIG_KASAN

-#include <linux/pgtable.h>
 #include <asm/kasan.h>

Testing shows putting that #include back in makes it compile correctly,
but it's not obvious why putting that back makes 'asmlinkage' recognized.

"You are in a twisty little maze of #includes, all different"... :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/24105.1606397102%40turing-police.

--==_Exmh_1606397102_2385P
Content-Type: application/pgp-signature

-----BEGIN PGP SIGNATURE-----
Comment: Exmh version 2.9.0 11/07/2018

iQIVAwUBX7+srgdmEQWDXROgAQJW4Q/9GFUDqf7hgecXDcL2yFy34oKrqxn9gXoZ
V1dpisivWhfbQiLZwIhhIkrs52LoWt58FgtTQ0RuCIcn1S2yKyg94MVylREcjK8X
iw9jMuWZW86ZdjSO3n7fLJBVWQG2pSuQWlV/5DpimEeheFCpYA0mee3V6uNjoJzV
3LRU/DDY6wP9tA15WlYIf3AlincoI3jt4n9MgWudCNqWr5veKnlpM7dOfB/2VAIU
KJ2QeUBhDk41QNFLR1siHH0BQ3gY1eSubv0Na1Rs6hfAGlbcV2CkidKkVq8YBb4m
gQKbpT55dH7xyYXiM/FFR6APCPj9NRHgpVby2/FzZMS8tZHC6kp0Mjq+EKF9Cx1p
IZbZJe4BQJynvj8uXR5ua04gLHBsRrDMsDN5ArzJkBW5C9twSOyCQVRDKZbdgQQO
S3V4NUI3SU/nG/hYA/c91hLtV4+B7PqvV994atnd5m9VTqLfI+pcgbUcNtahln9b
18TZH6/dBsCuWi4ecvqB9WIyNBNV8JxhtCZVp32aww/0D4VJSzjFPDesAAoc6bf7
8R6oA3klD3CUb1CEBB5i0jcFiNrz+vesXNs77JCe5twlTuD4zLr9Y0xccmMbWLJh
P1825oVnWJG/cJQfSxuvYvmNyC/isqk7DGTgNi0Lpd6q2uo/w9kqXCtauSmx0ggH
yJPa5fxc3DU=
=edQj
-----END PGP SIGNATURE-----

--==_Exmh_1606397102_2385P--
