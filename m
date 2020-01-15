Return-Path: <kasan-dev+bncBDQ27FVWWUFRBMHG7LYAKGQEJLRM2BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc39.google.com (mail-yw1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id F00F413B9C9
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 07:37:37 +0100 (CET)
Received: by mail-yw1-xc39.google.com with SMTP id q130sf18830539ywh.11
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2020 22:37:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579070257; cv=pass;
        d=google.com; s=arc-20160816;
        b=ta4EO9NweV7XMWNkRlLddEGlFHVwFqwuKWeyiT1CrUtygfqVfN+xNW18akq11h8LjD
         V8G7rFjEsN1wWsqCIU+RqImyrY6XmPsEgPztlmYi9XtL6Q9vasC7NzwkDHcP4DcemDZU
         31NspZQyEC3VPD5CNuiSG6CvWDbz94Omk/zF4To1lJvWdy4QwIbrzIbOQc18EH/ZtUG8
         RdjCgaATk+9S3H29MII8Ou2Gn6aDX9zzZjs4aRHTTBJMRRoj8rngHgjhRt/djh8vcefo
         Vk8juko+fDVNe8M6H/uRvgYWZARUFgrJqnPk9DbPlR8zcxEJHIW4+HmpKhgzRKDyv5xZ
         DbBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature;
        bh=/eL1akvry/f9zjUF29I5NPHcTvwFd0Um7MyH6278ico=;
        b=jFaiIBzimL65/wxZhlN6KEs5ETMFpoUs/Qq733UZIKHx8wn29B4D5s/YV85D6h+7Vt
         QnUFPMRuJccUQ+JpOqffsl4knAj346uydcskiV9HrT60p9LISWico/CykjepGMSkwEDv
         36T1L2piVadWu7vSvTSOfmRYGc3VuUzBoPRU0LjObw/Gd0yopt6Ep3M3gCINCixip278
         Yw+Fu2B/2aa7fDRbVni+AwQOer025GwsM2ewrgKjNQECtTtuMJ2ViKvLm4Iqpvr12s9S
         AwUbQeKBkhyAUxCtYiIk3m9PKw/44iauPUD2UM2hCrJqL3SQaxPTgS7F50IqDSdgVpzA
         QxKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=hZt2zcSk;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/eL1akvry/f9zjUF29I5NPHcTvwFd0Um7MyH6278ico=;
        b=Jo2wFs2oMj77IS48nITm8RUANbqZrlfBIP2v0D5ojXaEqR/490ATmqY3TvKvHJYJ/t
         LG0PXxB3syWQ2bi/LSkW0XxJAQLJtzIRe45AZVjaJYAQOB2ArFSgeCjwcijb+WXnyRvl
         lYytfVfS8+ehzwNWYnljNaJ7ROmisq8Hm6MvYpCDE4jLolwjM6pdkHPTk1cs5H61Gh4B
         Hnsh+NaHoczJiDANOsuXTtT4A3tpQ6F4Jvn9j4FUsT10IXfzRny+BfH91n0MZOg+HOSe
         gE7ZOqz1e/s1p3QxJgNLufoEwOkAjxTBekoH0AR6q4deoSTZzw48mgwV8r3uLONbyrMU
         ypgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/eL1akvry/f9zjUF29I5NPHcTvwFd0Um7MyH6278ico=;
        b=G1st61jzg3x8wHoieLFyJL1VOSaEOoYzWq8PkLyu81IaAXnjyJw93WyZvJp6XKpQJY
         Nb5iCFrQht2W/smBXGYSffE/6I/1bESyZWMWi/0T+l3rf48arlkE44BoGvPCA1hkHMoA
         HDflyMTdRzdfgDo6k/0yqYMhvu17kdANbQT3gWqQVa11J12rOFbtlOomrQQMb6VRefdp
         oms9s8VBiY0vftaaESWHy48wrLvap4rCaZSxCyf24VPYrYSxvM87OWM05zLica+C2lHa
         OjkbkgZVlp1v0sJWiu+7cbg1ecAHs+bvhq3VAn4S5VBlwxHACff5VLD5XTtqIxMam5Fb
         l8UQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX3J9sBBxRSGqhzAAg+AzWUKy65lLH94+9vuK0oUn0JKT/gJlnn
	+eb4rN4MORhlEZRUnY7NuaA=
X-Google-Smtp-Source: APXvYqxbzK7EL3dD0pPYbYVtwama75Alb5t3QhIrNdPvH5Gznq4SjH4WmyekW46zQ2GkoDTm1iZ14g==
X-Received: by 2002:a81:7841:: with SMTP id t62mr21018333ywc.140.1579070256840;
        Tue, 14 Jan 2020 22:37:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:aa54:: with SMTP id s78ls1561367ybi.9.gmail; Tue, 14 Jan
 2020 22:37:36 -0800 (PST)
X-Received: by 2002:a25:7cc1:: with SMTP id x184mr20925836ybc.69.1579070256546;
        Tue, 14 Jan 2020 22:37:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579070256; cv=none;
        d=google.com; s=arc-20160816;
        b=pPAVgeJ50H03mExIEt89L4JedmZYx//PGCN9SiIaBGG2F/EK2oOmRcE3s/3cj0XorC
         gr2WXvkbOE/dJqZ7jzH1cO5Sg3BYhSuTpVWwesboWeleNM1clrCqPe6F6D9UTGK9xnAp
         d9WxuQqdZ0JKCbqoWKX/OGATZvsP341NhQZhl2YA2OTrFoS3yhj32Swb9PHAOKnoiFg8
         ZVoGcFEGgNZlDD61t+fGDXxrzLLoAQCx3OrUuQAkEI3lQLwYBHTyBs1AMhB+NwRxYkAY
         Xn47uhGRSicfg1lNqgIrh7s3DORU6nckHYHHRjKrcXc5wIvh/N93Ao05QQstf4mHQcOs
         ji/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=r5/dhMWxJZ8SOba/KcCWGM9GPzNc+Jy36C4OySceHUs=;
        b=EdIO1/O+NpFFdR/KjzOntAHKkQeNM3ozVguWBMb6sIgql4IqDf6ssiQVWEIxeom4a8
         SrtoNTJp3aOQsy4lI0TNx9pfSjybVTwB8koXgnfNCVIaoxSsHIGebd6NsC5Wkqj6rZ4W
         Nui+kNbnHu5Vfoo4zPxzKT6rvedwoLOtpXh/2Hh61XhH/XF8A6DwZMd0M3OsknhH4pxI
         cSEi6TseocRKFt2OMLzjCGefPeehJYk0B5QPa/sHf8DS4cyXRcWDNMk4YaJL4tWS6r16
         JwH+kleMzkjqQ9bYwx1soWwNd4Mx/OWfa3bcwjT5oLYy/MPCAGUsQ9BeXYNeAftcwFSQ
         cpdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=hZt2zcSk;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x1044.google.com (mail-pj1-x1044.google.com. [2607:f8b0:4864:20::1044])
        by gmr-mx.google.com with ESMTPS id j7si802184ywc.2.2020.01.14.22.37.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Jan 2020 22:37:36 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1044 as permitted sender) client-ip=2607:f8b0:4864:20::1044;
Received: by mail-pj1-x1044.google.com with SMTP id u63so1717819pjb.0
        for <kasan-dev@googlegroups.com>; Tue, 14 Jan 2020 22:37:36 -0800 (PST)
X-Received: by 2002:a17:90a:6:: with SMTP id 6mr34950202pja.71.1579070255741;
        Tue, 14 Jan 2020 22:37:35 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-8d73-bc9d-5592-cfd7.static.ipv6.internode.on.net. [2001:44b8:1113:6700:8d73:bc9d:5592:cfd7])
        by smtp.gmail.com with ESMTPSA id c15sm20438468pja.30.2020.01.14.22.37.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Jan 2020 22:37:35 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com
Cc: linuxppc-dev@lists.ozlabs.org,
	linux-arm-kernel@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-xtensa@linux-xtensa.org,
	x86@kernel.org,
	Daniel Axtens <dja@axtens.net>,
	Daniel Micay <danielmicay@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>
Subject: [PATCH 1/2] kasan: stop tests being eliminated as dead code with FORTIFY_SOURCE
Date: Wed, 15 Jan 2020 17:37:09 +1100
Message-Id: <20200115063710.15796-2-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200115063710.15796-1-dja@axtens.net>
References: <20200115063710.15796-1-dja@axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=hZt2zcSk;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1044 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

3 KASAN self-tests fail on a kernel with both KASAN and FORTIFY_SOURCE:
memchr, memcmp and strlen.

When FORTIFY_SOURCE is on, a number of functions are replaced with
fortified versions, which attempt to check the sizes of the operands.
However, these functions often directly invoke __builtin_foo() once they
have performed the fortify check. The compiler can detect that the results
of these functions are not used, and knows that they have no other side
effects, and so can eliminate them as dead code.

Why are only memchr, memcmp and strlen affected?
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D

Of string and string-like functions, kasan_test tests:

 * strchr  ->  not affected, no fortified version
 * strrchr ->  likewise
 * strcmp  ->  likewise
 * strncmp ->  likewise

 * strnlen ->  not affected, the fortify source implementation calls the
               underlying strnlen implementation which is instrumented, not
               a builtin

 * strlen  ->  affected, the fortify souce implementation calls a __builtin
               version which the compiler can determine is dead.

 * memchr  ->  likewise
 * memcmp  ->  likewise

 * memset ->   not affected, the compiler knows that memset writes to its
	       first argument and therefore is not dead.

Why does this not affect the functions normally?
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D

In string.h, these functions are not marked as __pure, so the compiler
cannot know that they do not have side effects. If relevant functions are
marked as __pure in string.h, we see the following warnings and the
functions are elided:

lib/test_kasan.c: In function =E2=80=98kasan_memchr=E2=80=99:
lib/test_kasan.c:606:2: warning: statement with no effect [-Wunused-value]
  memchr(ptr, '1', size + 1);
  ^~~~~~~~~~~~~~~~~~~~~~~~~~
lib/test_kasan.c: In function =E2=80=98kasan_memcmp=E2=80=99:
lib/test_kasan.c:622:2: warning: statement with no effect [-Wunused-value]
  memcmp(ptr, arr, size+1);
  ^~~~~~~~~~~~~~~~~~~~~~~~
lib/test_kasan.c: In function =E2=80=98kasan_strings=E2=80=99:
lib/test_kasan.c:645:2: warning: statement with no effect [-Wunused-value]
  strchr(ptr, '1');
  ^~~~~~~~~~~~~~~~
...

This annotation would make sense to add and could be added at any point, so
the behaviour of test_kasan.c should change.

The fix
=3D=3D=3D=3D=3D=3D=3D

Make all the functions that are pure write their results to a global,
which makes them live. The strlen and memchr tests now pass.

The memcmp test still fails to trigger, which is addressed in the next
patch.

Cc: Daniel Micay <danielmicay@gmail.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Fixes: 0c96350a2d2f ("lib/test_kasan.c: add tests for several string/memory=
 API functions")
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 lib/test_kasan.c | 30 +++++++++++++++++++-----------
 1 file changed, 19 insertions(+), 11 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 328d33beae36..58a8cef0d7a2 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -23,6 +23,14 @@
=20
 #include <asm/page.h>
=20
+/*
+ * We assign some test results to these globals to make sure the tests
+ * are not eliminated as dead code.
+ */
+
+int int_result;
+void *ptr_result;
+
 /*
  * Note: test functions are marked noinline so that their names appear in
  * reports.
@@ -603,7 +611,7 @@ static noinline void __init kasan_memchr(void)
 	if (!ptr)
 		return;
=20
-	memchr(ptr, '1', size + 1);
+	ptr_result =3D memchr(ptr, '1', size + 1);
 	kfree(ptr);
 }
=20
@@ -618,8 +626,7 @@ static noinline void __init kasan_memcmp(void)
 	if (!ptr)
 		return;
=20
-	memset(arr, 0, sizeof(arr));
-	memcmp(ptr, arr, size+1);
+	int_result =3D memcmp(ptr, arr, size + 1);
 	kfree(ptr);
 }
=20
@@ -642,22 +649,22 @@ static noinline void __init kasan_strings(void)
 	 * will likely point to zeroed byte.
 	 */
 	ptr +=3D 16;
-	strchr(ptr, '1');
+	ptr_result =3D strchr(ptr, '1');
=20
 	pr_info("use-after-free in strrchr\n");
-	strrchr(ptr, '1');
+	ptr_result =3D strrchr(ptr, '1');
=20
 	pr_info("use-after-free in strcmp\n");
-	strcmp(ptr, "2");
+	int_result =3D strcmp(ptr, "2");
=20
 	pr_info("use-after-free in strncmp\n");
-	strncmp(ptr, "2", 1);
+	int_result =3D strncmp(ptr, "2", 1);
=20
 	pr_info("use-after-free in strlen\n");
-	strlen(ptr);
+	int_result =3D strlen(ptr);
=20
 	pr_info("use-after-free in strnlen\n");
-	strnlen(ptr, 1);
+	int_result =3D strnlen(ptr, 1);
 }
=20
 static noinline void __init kasan_bitops(void)
@@ -724,11 +731,12 @@ static noinline void __init kasan_bitops(void)
 	__test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
=20
 	pr_info("out-of-bounds in test_bit\n");
-	(void)test_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
+	int_result =3D test_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
=20
 #if defined(clear_bit_unlock_is_negative_byte)
 	pr_info("out-of-bounds in clear_bit_unlock_is_negative_byte\n");
-	clear_bit_unlock_is_negative_byte(BITS_PER_LONG + BITS_PER_BYTE, bits);
+	int_result =3D clear_bit_unlock_is_negative_byte(BITS_PER_LONG +
+		BITS_PER_BYTE, bits);
 #endif
 	kfree(bits);
 }
--=20
2.20.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200115063710.15796-2-dja%40axtens.net.
