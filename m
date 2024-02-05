Return-Path: <kasan-dev+bncBAABBG7XQGXAMGQEK7TAW4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id C801D8493B0
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Feb 2024 07:09:33 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-296a6b84448sf254067a91.0
        for <lists+kasan-dev@lfdr.de>; Sun, 04 Feb 2024 22:09:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707113372; cv=pass;
        d=google.com; s=arc-20160816;
        b=JjM5exFzuyP6PZvIRF2fzPNCW3lRvUNn9etp+xNrcOUF2x0CzE3QPPSYCOY3ZV/QN7
         Dq7WJIa1/zaWYnxEjz1I8J4Fbu3HzNh60aJT9w0KssslyFEXzcXwXee7Q5H1HC1GkQxH
         9M3TOHtfF70zDiIOXhu6pc0KnQzBOczQdL+L+rni99YGAEIGEfhDM2yAfDthOU3coTKT
         6l1fA+7E94NnICOzVggzHc3o5BpwMGtTiYzWIN+m2TX0ScbNAyV4UXu2uCSjXtvBWVSd
         gW78dpTnBZu38kkqAj1JShUaZG6SJWF00ZK6ei8eLdat4ycchV/mT8tYTJiak884Lwjx
         0+yQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature;
        bh=XQRYhU3UUc/FxbXygNpLSIglxlSofSoAwP6M1KEHl28=;
        fh=0KRQjzbHBaKQUWW2QN6sdkLPD8j+RSKb6Fp4CX9F69Y=;
        b=Ok+JwfbMbr+myiDTOJiG0Hw/93OaUkTXYvhhDglkpWY0sE24fDpvGeqY1us7V5RE78
         liJeKS64WP/hoyCgEjVR0D8HvUkH/4ZcxpSR+qLrb9hqTmCQGJNUVcoaHRu+37LflRjt
         oAawaEs4jbEXGikdB5ccT3dbvXdky9ok7PIx+8nmZEgRYKpdDfkSRG6NMPa9Iiaxtmxq
         Ce3gky1PdkYtVrSPCy2tEstimVoYNsl4Ju4CwRljKw/ZxfIbe6fN5gvcpZputXV9e9RH
         8Lj4RO7ESYMo/xu9xDh0ZJBmcOxGhfCDHNi8FxDFOywZ0n1V3jTRqpTbPjgljrkVqPZz
         34Lw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707113372; x=1707718172; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XQRYhU3UUc/FxbXygNpLSIglxlSofSoAwP6M1KEHl28=;
        b=DRUAahjucV53uWNlsAl47soUU9SHBmsuD+S5JqTtLm3vuuAbwiHhlzZ515eKmeGPQb
         Uyh916mU/zj5k7yA4PLY31ff2eKhjN15Vcvx9HJgEZy6/bP9q/8ZpGvSCAkU7L70I4zZ
         UkUm+n2sTCWMA6iFgih/Sb1kWv0IYfbKlZTjPrXZaMgwLts69E3F3JgCfIEJ9INr5uZb
         RjLk+yYnoBBCLwvHncYK7JvtO56qqX0V7415ecYlVvDtbEZcyoY88YoEV1YGQiZ4Pk7D
         fBXLyd3SRsTTPsIFfDgdT6PIV92IQ2e5tLKSik4Qy02YXgPcQ4B2KiZMGvibUBHw9J6G
         gsbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707113372; x=1707718172;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=XQRYhU3UUc/FxbXygNpLSIglxlSofSoAwP6M1KEHl28=;
        b=rmmmCMG/HUnf0EmUPt+0CtSfyezIDliNoZVc8Nv/NCF4R/xLtPX97vRZY3zTT2yEOS
         OIxgVILko6m3ZWUhnz9PaWvkXGJeJ/KkELalNzTaXmtkykt/njwKD4TnD1/L7H3GHUfD
         suzRswTSk/6VZBS2S2zcgxAEs3T52z/X5H4YRtiPNgNV8RIx/nX4vzOVGD3ibYf59590
         Y9/JXoA4k3Ov2MLF3U0g2f60CfC4zj13STu4hgVWjKePcsyYdSWOJ9NNhueV+W4d7394
         pn/Cw6RE9xD/PI6KZfcc3gl8vgKFcJI2DTkU5iCSf+i4M3NJpuJGh6MPBwdVgZXdoWBF
         gK+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YySOM+Ezrrkbh6+hdmJuou8BzUuj8gFtOwKF0djFbXX1B/3rrf0
	C51kxLtCzSYxo4bxKg096aEe/VWsEqrhT8t/q+qZCJTkPugfpNEP
X-Google-Smtp-Source: AGHT+IFaYL9FwHCFSagO2Ki1VYAZHNpL7JaZfn84jI3SG7nxxI3xe7yWUNK4YBosKZdDz7cwAfHQ5g==
X-Received: by 2002:a17:90a:2f01:b0:296:545f:8544 with SMTP id s1-20020a17090a2f0100b00296545f8544mr7780244pjd.28.1707113372069;
        Sun, 04 Feb 2024 22:09:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:eb11:b0:1d8:ec21:8c69 with SMTP id
 l17-20020a170902eb1100b001d8ec218c69ls2638710plb.2.-pod-prod-06-us; Sun, 04
 Feb 2024 22:09:31 -0800 (PST)
X-Received: by 2002:a17:903:32d2:b0:1d8:e079:ce16 with SMTP id i18-20020a17090332d200b001d8e079ce16mr10618409plr.1.1707113371055;
        Sun, 04 Feb 2024 22:09:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707113371; cv=none;
        d=google.com; s=arc-20160816;
        b=SuPoFAAX9djp4zACbNl2ORWUqbVUqKI8gFeDA0uQABgsXuNL/aEbEdeqEc1EzL1qFW
         N9crAfkCAvAGtSnmx5SO5o9YAcNGJePBll8WjIB5lWPI/Yy+30q2ZgEbA3u5P8Og9j64
         rSHfSruis9HV+qECB0arqV2qSIc9kcpSLsk8yHc6zuubhVAqrBledWTiRg80XnHX5zEu
         qos9XKbFJ0911+pafbXU5cibECUR1fuFsuaCKSmIADfG2k+MupCAwXH3QkKjxFl6XGfM
         gubFRHR/tRun6mkvkov9zcyldLeJsrkL+YxWF9xpLdx3awb1pcSvBmFFednVG6BfdOxo
         3Oww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=i8v1pIn3U09Lj+/SpL7EHyIk18f/vUZc/EOmsup7vbs=;
        fh=0KRQjzbHBaKQUWW2QN6sdkLPD8j+RSKb6Fp4CX9F69Y=;
        b=vk1F0CAtQs6/r1va9D70rw2H+z/JsHLeB1y3WpoGe/aKPtX0rhFLuurhkGSpdKAWMr
         DW4AJkDJ5Gs3H/u/wt2Tr9oM8WePmdUwlVOrJ/WRLggB2p7gKl87vBmHLEbSHD6aSgH0
         yWd2VaKeFiijUriN7HjJOegqyxIdK+CCMKkVL07ZWnagKdyMJlY+KngHHagwRfdpVnTo
         liuZt91gpHlDW1e6ICW2H/23XBAqZgQIYOOWpyj9nm+nbARiAwh1sy9QLFpjOZnEPqa3
         eIlf3Y/aigAdv6rx9x2/HoWBCjhx5baxMz+G/LN/6U/jaTzZfFlEGP6S/+G55SGTF2gF
         3IHA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id r17-20020a170903015100b001d8f9b6e31bsi480687plc.10.2024.02.04.22.09.30
        for <kasan-dev@googlegroups.com>;
        Sun, 04 Feb 2024 22:09:30 -0800 (PST)
Received-SPF: pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [113.200.148.30])
	by gateway (Coremail) with SMTP id _____8DxK+mXe8Bl68kKAA--.11791S3;
	Mon, 05 Feb 2024 14:09:27 +0800 (CST)
Received: from linux.localdomain (unknown [113.200.148.30])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8AxHs+Ve8BluusvAA--.49177S3;
	Mon, 05 Feb 2024 14:09:26 +0800 (CST)
From: Tiezhu Yang <yangtiezhu@loongson.cn>
To: Andrew Morton <akpm@linux-foundation.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>
Cc: kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH 1/2] kasan: docs: Update descriptions about test file and module
Date: Mon,  5 Feb 2024 14:09:21 +0800
Message-ID: <20240205060925.15594-2-yangtiezhu@loongson.cn>
X-Mailer: git-send-email 2.42.0
In-Reply-To: <20240205060925.15594-1-yangtiezhu@loongson.cn>
References: <20240205060925.15594-1-yangtiezhu@loongson.cn>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: AQAAf8AxHs+Ve8BluusvAA--.49177S3
X-CM-SenderInfo: p1dqw3xlh2x3gn0dqz5rrqw2lrqou0/
X-Coremail-Antispam: 1Uk129KBj93XoWxKryUuF15ZF1Uuw4fJr1xtFc_yoWDJF1xpF
	ZFgryxtFn8ArWkur4jyF1jyr10yFs7ur17K3Zaqwn3XrZ8Kw10yFsFkr4jgFyxWr4rZFyU
	Z3WktFyDGw4UGabCm3ZEXasCq-sJn29KB7ZKAUJUUUU8529EdanIXcx71UUUUU7KY7ZEXa
	sCq-sGcSsGvfJ3Ic02F40EFcxC0VAKzVAqx4xG6I80ebIjqfuFe4nvWSU5nxnvy29KBjDU
	0xBIdaVrnRJUUUkYb4IE77IF4wAFF20E14v26r1j6r4UM7CY07I20VC2zVCF04k26cxKx2
	IYs7xG6rWj6s0DM7CIcVAFz4kK6r106r15M28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48v
	e4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Gr0_Xr1l84ACjcxK6xIIjxv20xvEc7CjxVAFwI
	0_Gr0_Cr1l84ACjcxK6I8E87Iv67AKxVWxJVW8Jr1l84ACjcxK6I8E87Iv6xkF7I0E14v2
	6r4UJVWxJr1le2I262IYc4CY6c8Ij28IcVAaY2xG8wAqjxCEc2xF0cIa020Ex4CE44I27w
	Aqx4xG64xvF2IEw4CE5I8CrVC2j2WlYx0E2Ix0cI8IcVAFwI0_JF0_Jw1lYx0Ex4A2jsIE
	14v26r1j6r4UMcvjeVCFs4IE7xkEbVWUJVW8JwACjcxG0xvY0x0EwIxGrwCF04k20xvY0x
	0EwIxGrwCFx2IqxVCFs4IE7xkEbVWUJVW8JwC20s026c02F40E14v26r1j6r18MI8I3I0E
	7480Y4vE14v26r106r1rMI8E67AF67kF1VAFwI0_Jw0_GFylIxkGc2Ij64vIr41lIxAIcV
	C0I7IYx2IY67AKxVWUCVW8JwCI42IY6xIIjxv20xvEc7CjxVAFwI0_Jr0_Gr1lIxAIcVCF
	04k26cxKx2IYs7xG6r1j6r1xMIIF0xvEx4A2jsIE14v26r1j6r4UMIIF0xvEx4A2jsIEc7
	CjxVAFwI0_Jr0_GrUvcSsGvfC2KfnxnUUI43ZEXa7IU8wNVDUUUUU==
X-Original-Sender: yangtiezhu@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
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

After commit f7e01ab828fd ("kasan: move tests to mm/kasan/"), the test
file is renamed to mm/kasan/kasan_test.c and the test module is renamed
to kasan_test.ko, so update the descriptions in the document.

While at it, update the line number and testcase number when the tests
kmalloc_large_oob_right and kmalloc_double_kzfree failed to sync with
the current code in mm/kasan/kasan_test.c.

Signed-off-by: Tiezhu Yang <yangtiezhu@loongson.cn>
---
 Documentation/dev-tools/kasan.rst             | 20 +++++++++----------
 .../translations/zh_CN/dev-tools/kasan.rst    | 20 +++++++++----------
 .../translations/zh_TW/dev-tools/kasan.rst    | 20 +++++++++----------
 3 files changed, 30 insertions(+), 30 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/ka=
san.rst
index 858c77fe7dc4..a5a6dbe9029f 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -169,7 +169,7 @@ Error reports
 A typical KASAN report looks like this::
=20
     =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
-    BUG: KASAN: slab-out-of-bounds in kmalloc_oob_right+0xa8/0xbc [test_ka=
san]
+    BUG: KASAN: slab-out-of-bounds in kmalloc_oob_right+0xa8/0xbc [kasan_t=
est]
     Write of size 1 at addr ffff8801f44ec37b by task insmod/2760
=20
     CPU: 1 PID: 2760 Comm: insmod Not tainted 4.19.0-rc3+ #698
@@ -179,8 +179,8 @@ A typical KASAN report looks like this::
      print_address_description+0x73/0x280
      kasan_report+0x144/0x187
      __asan_report_store1_noabort+0x17/0x20
-     kmalloc_oob_right+0xa8/0xbc [test_kasan]
-     kmalloc_tests_init+0x16/0x700 [test_kasan]
+     kmalloc_oob_right+0xa8/0xbc [kasan_test]
+     kmalloc_tests_init+0x16/0x700 [kasan_test]
      do_one_initcall+0xa5/0x3ae
      do_init_module+0x1b6/0x547
      load_module+0x75df/0x8070
@@ -200,8 +200,8 @@ A typical KASAN report looks like this::
      save_stack+0x43/0xd0
      kasan_kmalloc+0xa7/0xd0
      kmem_cache_alloc_trace+0xe1/0x1b0
-     kmalloc_oob_right+0x56/0xbc [test_kasan]
-     kmalloc_tests_init+0x16/0x700 [test_kasan]
+     kmalloc_oob_right+0x56/0xbc [kasan_test]
+     kmalloc_tests_init+0x16/0x700 [kasan_test]
      do_one_initcall+0xa5/0x3ae
      do_init_module+0x1b6/0x547
      load_module+0x75df/0x8070
@@ -510,15 +510,15 @@ When a test passes::
=20
 When a test fails due to a failed ``kmalloc``::
=20
-        # kmalloc_large_oob_right: ASSERTION FAILED at lib/test_kasan.c:16=
3
+        # kmalloc_large_oob_right: ASSERTION FAILED at mm/kasan/kasan_test=
.c:245
         Expected ptr is not null, but is
-        not ok 4 - kmalloc_large_oob_right
+        not ok 5 - kmalloc_large_oob_right
=20
 When a test fails due to a missing KASAN report::
=20
-        # kmalloc_double_kzfree: EXPECTATION FAILED at lib/test_kasan.c:97=
4
+        # kmalloc_double_kzfree: EXPECTATION FAILED at mm/kasan/kasan_test=
.c:709
         KASAN failure expected in "kfree_sensitive(ptr)", but none occurre=
d
-        not ok 44 - kmalloc_double_kzfree
+        not ok 28 - kmalloc_double_kzfree
=20
=20
 At the end the cumulative status of all KASAN tests is printed. On success=
::
@@ -534,7 +534,7 @@ There are a few ways to run KUnit-compatible KASAN test=
s.
 1. Loadable module
=20
    With ``CONFIG_KUNIT`` enabled, KASAN-KUnit tests can be built as a load=
able
-   module and run by loading ``test_kasan.ko`` with ``insmod`` or ``modpro=
be``.
+   module and run by loading ``kasan_test.ko`` with ``insmod`` or ``modpro=
be``.
=20
 2. Built-In
=20
diff --git a/Documentation/translations/zh_CN/dev-tools/kasan.rst b/Documen=
tation/translations/zh_CN/dev-tools/kasan.rst
index 8fdb20c9665b..2b1e8f74904b 100644
--- a/Documentation/translations/zh_CN/dev-tools/kasan.rst
+++ b/Documentation/translations/zh_CN/dev-tools/kasan.rst
@@ -137,7 +137,7 @@ KASAN=E5=8F=97=E5=88=B0=E9=80=9A=E7=94=A8 ``panic_on_wa=
rn`` =E5=91=BD=E4=BB=A4=E8=A1=8C=E5=8F=82=E6=95=B0=E7=9A=84=E5=BD=B1=E5=93=
=8D=E3=80=82=E5=BD=93=E5=AE=83=E8=A2=AB=E5=90=AF=E7=94=A8
 =E5=85=B8=E5=9E=8B=E7=9A=84KASAN=E6=8A=A5=E5=91=8A=E5=A6=82=E4=B8=8B=E6=89=
=80=E7=A4=BA::
=20
     =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
-    BUG: KASAN: slab-out-of-bounds in kmalloc_oob_right+0xa8/0xbc [test_ka=
san]
+    BUG: KASAN: slab-out-of-bounds in kmalloc_oob_right+0xa8/0xbc [kasan_t=
est]
     Write of size 1 at addr ffff8801f44ec37b by task insmod/2760
=20
     CPU: 1 PID: 2760 Comm: insmod Not tainted 4.19.0-rc3+ #698
@@ -147,8 +147,8 @@ KASAN=E5=8F=97=E5=88=B0=E9=80=9A=E7=94=A8 ``panic_on_wa=
rn`` =E5=91=BD=E4=BB=A4=E8=A1=8C=E5=8F=82=E6=95=B0=E7=9A=84=E5=BD=B1=E5=93=
=8D=E3=80=82=E5=BD=93=E5=AE=83=E8=A2=AB=E5=90=AF=E7=94=A8
      print_address_description+0x73/0x280
      kasan_report+0x144/0x187
      __asan_report_store1_noabort+0x17/0x20
-     kmalloc_oob_right+0xa8/0xbc [test_kasan]
-     kmalloc_tests_init+0x16/0x700 [test_kasan]
+     kmalloc_oob_right+0xa8/0xbc [kasan_test]
+     kmalloc_tests_init+0x16/0x700 [kasan_test]
      do_one_initcall+0xa5/0x3ae
      do_init_module+0x1b6/0x547
      load_module+0x75df/0x8070
@@ -168,8 +168,8 @@ KASAN=E5=8F=97=E5=88=B0=E9=80=9A=E7=94=A8 ``panic_on_wa=
rn`` =E5=91=BD=E4=BB=A4=E8=A1=8C=E5=8F=82=E6=95=B0=E7=9A=84=E5=BD=B1=E5=93=
=8D=E3=80=82=E5=BD=93=E5=AE=83=E8=A2=AB=E5=90=AF=E7=94=A8
      save_stack+0x43/0xd0
      kasan_kmalloc+0xa7/0xd0
      kmem_cache_alloc_trace+0xe1/0x1b0
-     kmalloc_oob_right+0x56/0xbc [test_kasan]
-     kmalloc_tests_init+0x16/0x700 [test_kasan]
+     kmalloc_oob_right+0x56/0xbc [kasan_test]
+     kmalloc_tests_init+0x16/0x700 [kasan_test]
      do_one_initcall+0xa5/0x3ae
      do_init_module+0x1b6/0x547
      load_module+0x75df/0x8070
@@ -421,15 +421,15 @@ KASAN=E8=BF=9E=E6=8E=A5=E5=88=B0vmap=E5=9F=BA=E7=A1=
=80=E6=9E=B6=E6=9E=84=E4=BB=A5=E6=87=92=E6=B8=85=E7=90=86=E6=9C=AA=E4=BD=BF=
=E7=94=A8=E7=9A=84=E5=BD=B1=E5=AD=90=E5=86=85=E5=AD=98=E3=80=82
=20
 =E5=BD=93=E7=94=B1=E4=BA=8E ``kmalloc`` =E5=A4=B1=E8=B4=A5=E8=80=8C=E5=AF=
=BC=E8=87=B4=E6=B5=8B=E8=AF=95=E5=A4=B1=E8=B4=A5=E6=97=B6::
=20
-        # kmalloc_large_oob_right: ASSERTION FAILED at lib/test_kasan.c:16=
3
+        # kmalloc_large_oob_right: ASSERTION FAILED at mm/kasan/kasan_test=
.c:245
         Expected ptr is not null, but is
-        not ok 4 - kmalloc_large_oob_right
+        not ok 5 - kmalloc_large_oob_right
=20
 =E5=BD=93=E7=94=B1=E4=BA=8E=E7=BC=BA=E5=B0=91KASAN=E6=8A=A5=E5=91=8A=E8=80=
=8C=E5=AF=BC=E8=87=B4=E6=B5=8B=E8=AF=95=E5=A4=B1=E8=B4=A5=E6=97=B6::
=20
-        # kmalloc_double_kzfree: EXPECTATION FAILED at lib/test_kasan.c:97=
4
+        # kmalloc_double_kzfree: EXPECTATION FAILED at mm/kasan/kasan_test=
.c:709
         KASAN failure expected in "kfree_sensitive(ptr)", but none occurre=
d
-        not ok 44 - kmalloc_double_kzfree
+        not ok 28 - kmalloc_double_kzfree
=20
=20
 =E6=9C=80=E5=90=8E=E6=89=93=E5=8D=B0=E6=89=80=E6=9C=89KASAN=E6=B5=8B=E8=AF=
=95=E7=9A=84=E7=B4=AF=E7=A7=AF=E7=8A=B6=E6=80=81=E3=80=82=E6=88=90=E5=8A=9F=
::
@@ -445,7 +445,7 @@ KASAN=E8=BF=9E=E6=8E=A5=E5=88=B0vmap=E5=9F=BA=E7=A1=80=
=E6=9E=B6=E6=9E=84=E4=BB=A5=E6=87=92=E6=B8=85=E7=90=86=E6=9C=AA=E4=BD=BF=E7=
=94=A8=E7=9A=84=E5=BD=B1=E5=AD=90=E5=86=85=E5=AD=98=E3=80=82
 1. =E5=8F=AF=E5=8A=A0=E8=BD=BD=E6=A8=A1=E5=9D=97
=20
    =E5=90=AF=E7=94=A8 ``CONFIG_KUNIT`` =E5=90=8E=EF=BC=8CKASAN-KUnit=E6=B5=
=8B=E8=AF=95=E5=8F=AF=E4=BB=A5=E6=9E=84=E5=BB=BA=E4=B8=BA=E5=8F=AF=E5=8A=A0=
=E8=BD=BD=E6=A8=A1=E5=9D=97=EF=BC=8C=E5=B9=B6=E9=80=9A=E8=BF=87=E4=BD=BF=E7=
=94=A8
-   ``insmod`` =E6=88=96 ``modprobe`` =E5=8A=A0=E8=BD=BD ``test_kasan.ko`` =
=E6=9D=A5=E8=BF=90=E8=A1=8C=E3=80=82
+   ``insmod`` =E6=88=96 ``modprobe`` =E5=8A=A0=E8=BD=BD ``kasan_test.ko`` =
=E6=9D=A5=E8=BF=90=E8=A1=8C=E3=80=82
=20
 2. =E5=86=85=E7=BD=AE
=20
diff --git a/Documentation/translations/zh_TW/dev-tools/kasan.rst b/Documen=
tation/translations/zh_TW/dev-tools/kasan.rst
index 979eb84bc58f..ed342e67d8ed 100644
--- a/Documentation/translations/zh_TW/dev-tools/kasan.rst
+++ b/Documentation/translations/zh_TW/dev-tools/kasan.rst
@@ -137,7 +137,7 @@ KASAN=E5=8F=97=E5=88=B0=E9=80=9A=E7=94=A8 ``panic_on_wa=
rn`` =E5=91=BD=E4=BB=A4=E8=A1=8C=E5=8F=83=E6=95=B8=E7=9A=84=E5=BD=B1=E9=9F=
=BF=E3=80=82=E7=95=B6=E5=AE=83=E8=A2=AB=E5=95=93=E7=94=A8
 =E5=85=B8=E5=9E=8B=E7=9A=84KASAN=E5=A0=B1=E5=91=8A=E5=A6=82=E4=B8=8B=E6=89=
=80=E7=A4=BA::
=20
     =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
-    BUG: KASAN: slab-out-of-bounds in kmalloc_oob_right+0xa8/0xbc [test_ka=
san]
+    BUG: KASAN: slab-out-of-bounds in kmalloc_oob_right+0xa8/0xbc [kasan_t=
est]
     Write of size 1 at addr ffff8801f44ec37b by task insmod/2760
=20
     CPU: 1 PID: 2760 Comm: insmod Not tainted 4.19.0-rc3+ #698
@@ -147,8 +147,8 @@ KASAN=E5=8F=97=E5=88=B0=E9=80=9A=E7=94=A8 ``panic_on_wa=
rn`` =E5=91=BD=E4=BB=A4=E8=A1=8C=E5=8F=83=E6=95=B8=E7=9A=84=E5=BD=B1=E9=9F=
=BF=E3=80=82=E7=95=B6=E5=AE=83=E8=A2=AB=E5=95=93=E7=94=A8
      print_address_description+0x73/0x280
      kasan_report+0x144/0x187
      __asan_report_store1_noabort+0x17/0x20
-     kmalloc_oob_right+0xa8/0xbc [test_kasan]
-     kmalloc_tests_init+0x16/0x700 [test_kasan]
+     kmalloc_oob_right+0xa8/0xbc [kasan_test]
+     kmalloc_tests_init+0x16/0x700 [kasan_test]
      do_one_initcall+0xa5/0x3ae
      do_init_module+0x1b6/0x547
      load_module+0x75df/0x8070
@@ -168,8 +168,8 @@ KASAN=E5=8F=97=E5=88=B0=E9=80=9A=E7=94=A8 ``panic_on_wa=
rn`` =E5=91=BD=E4=BB=A4=E8=A1=8C=E5=8F=83=E6=95=B8=E7=9A=84=E5=BD=B1=E9=9F=
=BF=E3=80=82=E7=95=B6=E5=AE=83=E8=A2=AB=E5=95=93=E7=94=A8
      save_stack+0x43/0xd0
      kasan_kmalloc+0xa7/0xd0
      kmem_cache_alloc_trace+0xe1/0x1b0
-     kmalloc_oob_right+0x56/0xbc [test_kasan]
-     kmalloc_tests_init+0x16/0x700 [test_kasan]
+     kmalloc_oob_right+0x56/0xbc [kasan_test]
+     kmalloc_tests_init+0x16/0x700 [kasan_test]
      do_one_initcall+0xa5/0x3ae
      do_init_module+0x1b6/0x547
      load_module+0x75df/0x8070
@@ -421,15 +421,15 @@ KASAN=E9=80=A3=E6=8E=A5=E5=88=B0vmap=E5=9F=BA=E7=A4=
=8E=E6=9E=B6=E6=A7=8B=E4=BB=A5=E6=87=B6=E6=B8=85=E7=90=86=E6=9C=AA=E4=BD=BF=
=E7=94=A8=E7=9A=84=E5=BD=B1=E5=AD=90=E5=85=A7=E5=AD=98=E3=80=82
=20
 =E7=95=B6=E7=94=B1=E6=96=BC ``kmalloc`` =E5=A4=B1=E6=95=97=E8=80=8C=E5=B0=
=8E=E8=87=B4=E6=B8=AC=E8=A9=A6=E5=A4=B1=E6=95=97=E6=99=82::
=20
-        # kmalloc_large_oob_right: ASSERTION FAILED at lib/test_kasan.c:16=
3
+        # kmalloc_large_oob_right: ASSERTION FAILED at mm/kasan/kasan_test=
.c:245
         Expected ptr is not null, but is
-        not ok 4 - kmalloc_large_oob_right
+        not ok 5 - kmalloc_large_oob_right
=20
 =E7=95=B6=E7=94=B1=E6=96=BC=E7=BC=BA=E5=B0=91KASAN=E5=A0=B1=E5=91=8A=E8=80=
=8C=E5=B0=8E=E8=87=B4=E6=B8=AC=E8=A9=A6=E5=A4=B1=E6=95=97=E6=99=82::
=20
-        # kmalloc_double_kzfree: EXPECTATION FAILED at lib/test_kasan.c:97=
4
+        # kmalloc_double_kzfree: EXPECTATION FAILED at mm/kasan/kasan_test=
.c:709
         KASAN failure expected in "kfree_sensitive(ptr)", but none occurre=
d
-        not ok 44 - kmalloc_double_kzfree
+        not ok 28 - kmalloc_double_kzfree
=20
=20
 =E6=9C=80=E5=BE=8C=E6=89=93=E5=8D=B0=E6=89=80=E6=9C=89KASAN=E6=B8=AC=E8=A9=
=A6=E7=9A=84=E7=B4=AF=E7=A9=8D=E7=8B=80=E6=85=8B=E3=80=82=E6=88=90=E5=8A=9F=
::
@@ -445,7 +445,7 @@ KASAN=E9=80=A3=E6=8E=A5=E5=88=B0vmap=E5=9F=BA=E7=A4=8E=
=E6=9E=B6=E6=A7=8B=E4=BB=A5=E6=87=B6=E6=B8=85=E7=90=86=E6=9C=AA=E4=BD=BF=E7=
=94=A8=E7=9A=84=E5=BD=B1=E5=AD=90=E5=85=A7=E5=AD=98=E3=80=82
 1. =E5=8F=AF=E5=8A=A0=E8=BC=89=E6=A8=A1=E5=A1=8A
=20
    =E5=95=93=E7=94=A8 ``CONFIG_KUNIT`` =E5=BE=8C=EF=BC=8CKASAN-KUnit=E6=B8=
=AC=E8=A9=A6=E5=8F=AF=E4=BB=A5=E6=A7=8B=E5=BB=BA=E7=88=B2=E5=8F=AF=E5=8A=A0=
=E8=BC=89=E6=A8=A1=E5=A1=8A=EF=BC=8C=E4=B8=A6=E9=80=9A=E9=81=8E=E4=BD=BF=E7=
=94=A8
-   ``insmod`` =E6=88=96 ``modprobe`` =E5=8A=A0=E8=BC=89 ``test_kasan.ko`` =
=E4=BE=86=E9=81=8B=E8=A1=8C=E3=80=82
+   ``insmod`` =E6=88=96 ``modprobe`` =E5=8A=A0=E8=BC=89 ``kasan_test.ko`` =
=E4=BE=86=E9=81=8B=E8=A1=8C=E3=80=82
=20
 2. =E5=85=A7=E7=BD=AE
=20
--=20
2.42.0

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240205060925.15594-2-yangtiezhu%40loongson.cn.
