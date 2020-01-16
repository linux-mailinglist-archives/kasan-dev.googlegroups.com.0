Return-Path: <kasan-dev+bncBDQ27FVWWUFRBHEEQDYQKGQEPM5WY2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F3AC13D447
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 07:26:37 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id 62sf3985987ybt.9
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 22:26:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579155996; cv=pass;
        d=google.com; s=arc-20160816;
        b=WCe+w84xaQQveMi0ZBxt59FLq4x0O49pLXdVer85SZJ4Mcb4RZLRpB+C0ebeHQAzoo
         BP7XzYYMPOQYff+3B2L7DZPJXbFD+uDuNV5i8wMMTOyBwokafAO8/mEhOYh20lpY4e9p
         H6hIiTEB+Xtk5guVEJg4109na8v6Qh4Zg2Yk2I6An4bQpaWvoUHSxSpEWn6JLgm2i2uR
         EFI/r9WJURBbtl1tfz4ogSq4ah/ma14DSEkQLa9/i1ZUDm8hsss3en324qW4Atc7coS8
         MVlfYEQMlsGFU+z8ie2VGQVGOo4zMlbHbmU74NKWBCzmf17NMeUXlCEqJTmT0c/6xW9m
         0Wjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature;
        bh=Ty9YycZ8BP5KKmDyTNILPYmSrCE5elTOX0WbokKxMtM=;
        b=jX8topBbU+QqnFrHa82/AiqtnzMICuKtED4SR8kMceMZ/w0fA3lcBkzqOt7j+dp9yp
         kEPPwdwmUDhIi8n3woNiOy1fkEM7fB9mqWoCeMfM6FbyNsJcMCJxOxkoN1Hdj+9VO2an
         SMwTF3ZI5zytb9GopM9EDYKIqpvk68mdJTuD6T9CryMPLvQzG+qwguwTAAfDAcXuqRto
         mW7VxJcGSCLMjRewK7FqozJbzXYOhV0LbhOs+RnU7XurU54x78eoTiRqO3e11msVKK/h
         drOviXWbEqF4VTJOiMNcxTYnZSxZ3Uc6WGVW74ylP6GOCXIe2M4fPjL/s/1iICsRF6Vj
         WIoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="C+UNMN/n";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Ty9YycZ8BP5KKmDyTNILPYmSrCE5elTOX0WbokKxMtM=;
        b=kKhYzd4rMpkrdqvAdjoaC+qjxNsvUHJplKdW/HPrRUrNGX3Kqz3l6iO6gMTHQ+UWDw
         Q6f82CW6JQhP6oo1OBUroJ+Op+u0QhCues0LYmNzkGdTgLm0cr4MQCFTjK56JAs4hVW5
         Unh7WmOva/VZ73UuuFhSr4IdHamIq27Ah1tg/RuIO4gdVTyp4RTmA73z+MsSzxSVCRXV
         72vrx8Rjz1yNpH71fEvHXx03H83hSFIY/nahItWpb6mt8M7Qlh4MjLckFnsHreVHBDwW
         48o2H2olLJUnaeks3+wZ/xuqpZGYSZyDgVSDFvkuaaCm0YJWQWI9Z5lo2+01pTRrDJrC
         GhDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Ty9YycZ8BP5KKmDyTNILPYmSrCE5elTOX0WbokKxMtM=;
        b=XpXYng/D+VNCBtIkNLQD0WVYbcUdYXHgjK9yvmLAyrGe5kohoHdAm+u+G8lNP7VhOw
         GIq+1u7fB0VemXcJKtj3Zz1ZKDNdAzY6GOaFLXwQxhpTcH3jzZKJlDdUg+ySO1ny6YGl
         H2VYqbTrisq1wkMxgzB+VoLj3LfpowGzeAQ6YkvN4HtmqOju8fy/aCxMjCyaJuRhy+2H
         +h3N9nJd3OLERARZ6Wan4wxwopZhGFEzMTfyK3UGznX2zKlkr5uqeVV9uwOFAI2L7kNM
         tXSjApBex07LOSET3JMUOE3FBsbBL+TW31fiBh9FE6D8DDrvoMxtZBMaU7thqLXT/YD5
         uOnQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAULsq1LlfYxzZyq7v2bE/+QWTqIFbbVeAnXFxq16Vg+QFLciefg
	pwQF21sFCUox0T9hFP43Agg=
X-Google-Smtp-Source: APXvYqxCzX+vXO1WVgke0QTCVzyObrieExJAQsgImKJdw98roKsKv8lofTARLA8kEycpw8/iG7208g==
X-Received: by 2002:a81:d251:: with SMTP id m17mr19994011ywl.330.1579155996331;
        Wed, 15 Jan 2020 22:26:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5b:845:: with SMTP id v5ls2220806ybq.13.gmail; Wed, 15 Jan
 2020 22:26:36 -0800 (PST)
X-Received: by 2002:a25:6b02:: with SMTP id g2mr25275470ybc.74.1579155996018;
        Wed, 15 Jan 2020 22:26:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579155996; cv=none;
        d=google.com; s=arc-20160816;
        b=VZpyVlmrT4NTbi3U2mtzFi1iVGrvKYzcbuS6tmjTT6qkWGMGcZggJV/YQaAv3f8sNi
         tAd4XuCwx6PV2UIlskqU9U1BQD0gI4DZlqSk/9G/ufU1d4XdgyNJABXrHUC27mOpnHSE
         08uytibBZYBuivu3PPhA9aU98SEuOuIjh66o2eo0JsdeycfNewdkpLmKDdF6aiG5niEd
         ly9F+fm7EYCf8kvuxt5XQBoTK8SiMUCqiyi1puoT9w781ZTJ+NqUWpzE5IQ/e5apeXPa
         LORNpZrvb/bjD1LP/iMPos8Xx0iL9syDWbzKbLfzuAEXWLZu0k6ipZrTQN25CnRgiDbS
         twGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pcisanTgJm2Q3K0/rpShD/S/gMp/LV+S7q0SnsZ5eZA=;
        b=eRU54DUfjpGf2UTbNn1mSSR9mmRe+SEupKTtXK6bMUL29VeX+h0JCakj8Jj+Nioe5u
         MeBgEXPouHSiolx3zcvUua3/My+8GY/t/bUZHWSJsFghJBAK4hH8g3Hmst57TsueH1F9
         n5AQGpiMDJbsJnJUi7k8AZuHqZ47FxFmXcNv+9QAWEtjrjudVu9Od0vlzW8AkC+RZYc8
         WyJFmZCifuvNaD9oWbHcWwcG737aq5PKh0NYPikpBgTLGvU4LxEszgXqeAFq9J0BMHrm
         kUYTg/zDIx6jwaQxT0RK5HbdtNGcwS39FWm8jSOuiXNkMbyF8sKfmLcpnC8KemsudnOJ
         iboA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="C+UNMN/n";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id p187si971191ywe.1.2020.01.15.22.26.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2020 22:26:35 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id x8so9369762pgk.8
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 22:26:35 -0800 (PST)
X-Received: by 2002:a63:220b:: with SMTP id i11mr36948573pgi.50.1579155995165;
        Wed, 15 Jan 2020 22:26:35 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-097c-7eed-afd4-cd15.static.ipv6.internode.on.net. [2001:44b8:1113:6700:97c:7eed:afd4:cd15])
        by smtp.gmail.com with ESMTPSA id c68sm24184359pfc.156.2020.01.15.22.26.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Jan 2020 22:26:34 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com
Cc: linuxppc-dev@lists.ozlabs.org,
	linux-arm-kernel@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-xtensa@linux-xtensa.org,
	x86@kernel.org,
	dvyukov@google.com,
	christophe.leroy@c-s.fr,
	Daniel Axtens <dja@axtens.net>,
	Daniel Micay <danielmicay@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>
Subject: [PATCH v2 1/3] kasan: stop tests being eliminated as dead code with FORTIFY_SOURCE
Date: Thu, 16 Jan 2020 17:26:23 +1100
Message-Id: <20200116062625.32692-2-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200116062625.32692-1-dja@axtens.net>
References: <20200116062625.32692-1-dja@axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b="C+UNMN/n";       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as
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
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>

---

v2: rename variables to have kasan_ prefixes
---
 lib/test_kasan.c | 30 +++++++++++++++++++-----------
 1 file changed, 19 insertions(+), 11 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 328d33beae36..a130d75b9385 100644
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
+int kasan_int_result;
+void *kasan_ptr_result;
+
 /*
  * Note: test functions are marked noinline so that their names appear in
  * reports.
@@ -603,7 +611,7 @@ static noinline void __init kasan_memchr(void)
 	if (!ptr)
 		return;
=20
-	memchr(ptr, '1', size + 1);
+	kasan_ptr_result =3D memchr(ptr, '1', size + 1);
 	kfree(ptr);
 }
=20
@@ -618,8 +626,7 @@ static noinline void __init kasan_memcmp(void)
 	if (!ptr)
 		return;
=20
-	memset(arr, 0, sizeof(arr));
-	memcmp(ptr, arr, size+1);
+	kasan_int_result =3D memcmp(ptr, arr, size + 1);
 	kfree(ptr);
 }
=20
@@ -642,22 +649,22 @@ static noinline void __init kasan_strings(void)
 	 * will likely point to zeroed byte.
 	 */
 	ptr +=3D 16;
-	strchr(ptr, '1');
+	kasan_ptr_result =3D strchr(ptr, '1');
=20
 	pr_info("use-after-free in strrchr\n");
-	strrchr(ptr, '1');
+	kasan_ptr_result =3D strrchr(ptr, '1');
=20
 	pr_info("use-after-free in strcmp\n");
-	strcmp(ptr, "2");
+	kasan_int_result =3D strcmp(ptr, "2");
=20
 	pr_info("use-after-free in strncmp\n");
-	strncmp(ptr, "2", 1);
+	kasan_int_result =3D strncmp(ptr, "2", 1);
=20
 	pr_info("use-after-free in strlen\n");
-	strlen(ptr);
+	kasan_int_result =3D strlen(ptr);
=20
 	pr_info("use-after-free in strnlen\n");
-	strnlen(ptr, 1);
+	kasan_int_result =3D strnlen(ptr, 1);
 }
=20
 static noinline void __init kasan_bitops(void)
@@ -724,11 +731,12 @@ static noinline void __init kasan_bitops(void)
 	__test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
=20
 	pr_info("out-of-bounds in test_bit\n");
-	(void)test_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
+	kasan_int_result =3D test_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
=20
 #if defined(clear_bit_unlock_is_negative_byte)
 	pr_info("out-of-bounds in clear_bit_unlock_is_negative_byte\n");
-	clear_bit_unlock_is_negative_byte(BITS_PER_LONG + BITS_PER_BYTE, bits);
+	kasan_int_result =3D clear_bit_unlock_is_negative_byte(BITS_PER_LONG +
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
kasan-dev/20200116062625.32692-2-dja%40axtens.net.
