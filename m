Return-Path: <kasan-dev+bncBDQ27FVWWUFRBC7QQ32QKGQEYG63DSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 72CA21B5FC9
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 17:45:16 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id u5sf6471823qvt.12
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 08:45:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587656715; cv=pass;
        d=google.com; s=arc-20160816;
        b=TzrAXvTKapFJqAIBLoRT/NS+CDfgFWgvMA1TfUGr5bORZwI3ZHxxQDYYZf4uw1rNZ5
         +6n3wNhqv1EtSIYTT1fENABC0cpBPuOIhEVRjimm1v0zmmF3moAKCthKjigA372fm8DN
         hCE3Khy9QVwSAG2hIG/lr6er+GHpCoPsWZPPMXcYQsBkJNE7YE8Sx848rCi+UJthhIkc
         fpGSrG8O3w0qU4jFe1/eY98CAHXvuiZ+I1eO8iL3w4CrC7lU2iTuXsrEOqZRFvGUYAbl
         21kBxq3+TJoYZ4e8KZiKQLjNxOCbjw2+vCQPs5y7k+mKiAY/td26qgW+TZV/t1FgzMNm
         08OA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature;
        bh=BDZBAYS6VRR075q8Qkb2MR9R5clgasqT4MI7S1KoMhU=;
        b=CZbG2iQICyiLC9Ke4zESHdFGWFOUAJmafG3d5V4in/KZykyaohdydmRqoeoNSavHVF
         cPK0zLKPv2xBqtMh9Ajk2lkwVneyy2NAp+HJGv1xKa32e3/n9lOcwHc0f96Dn2NvRVZ4
         l6RvxeDokUqWZ6EuCRkjohpt5BQsQy8xLFAUEOmG529jiUsMWtBgnrnmYMHmcKz10fg2
         o8+zx+kYhJAhCK1teIsEc70qZaYdEMxTFwjRe5jHYUyHchY/XKd71AhCnNIvJ18UhMCh
         Yywthb2pqtgtTazau76jXfgUxWqxoLtwAH0mIrnRki2jcvG+RxPK1IeApD5r6fEj9YPD
         fJ1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=jPvZSIVR;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BDZBAYS6VRR075q8Qkb2MR9R5clgasqT4MI7S1KoMhU=;
        b=HzZJA4fzR0XxEz+aE6ZaXwYrNuzuKIVVIorFmzxQ33gxOW8bzHIZeLla/c+ECt+8Zw
         5SaoYVcSrKZ/Z8esaF3I61WsR4tJpJvdkObBDMls/O5lTeKXTgGn+qHyGzcsvIS1RLoU
         nNwxiFTWy1h9DiZ9uTEJOa7X4rTzqQnJMhYz+r5WiCudSz3DQvQlQU2M1+oj4eMtWbVm
         CuaZO4jJSik/RDho85b6fVONQZB8MuimnKB+GNKQogBe+nduvmilwlBtdIIxaROQHFeF
         u2sdHKtgk7VhCBX2xf6htUkFcMmUco8TNZhzabbg52LYpzuXDQ1wJoD9OhI4gMPAI6YF
         f9bA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BDZBAYS6VRR075q8Qkb2MR9R5clgasqT4MI7S1KoMhU=;
        b=as8tElYTLVQgRnsYafkOdyQC6BUeMNQDxzh+Jl9Iq6A126JRzJuwMXk59m65YeH4sJ
         efD7DGdJyZ63CPbAh73kiBGZ9ltU5fAhyuw5VW8xeJvNGGFlkS2RnxL3cD+9OHmflel5
         d8rWHQrxIJVt0MLAxraQ1LYU+gn073gRMvnqiypv0eVisqrl8b2aNdiXQo7cZBlFmvo9
         +bmMYQlFND/mIsBolH+8udbubsEOiT5LF2rVrENVgZKkMObt7GzE2Y4yS79R3hAxHlej
         LVqdnMp7Z+pbL6LREwo9bi+uDMPUumcu0JijJbSYIO7q4jr1F7X8KrUVYabi+wRnwEJZ
         AxIA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuY3OwJkJfDby7dJKYVA9RBM9Ncyzt344DtzWDgOcrvsIyTav+mZ
	1cPCreGjN/geTi4Zyim2rYs=
X-Google-Smtp-Source: APiQypKG/p1GUKMuuM0JzQg/Rzs/CFDTru0oWitRhnmtojqJU0mhfgnFXxxJtPs7ej3HUzBwMemc7Q==
X-Received: by 2002:a05:6214:1812:: with SMTP id o18mr4890865qvw.64.1587656715265;
        Thu, 23 Apr 2020 08:45:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:994:: with SMTP id dt20ls1759739qvb.7.gmail; Thu,
 23 Apr 2020 08:45:14 -0700 (PDT)
X-Received: by 2002:a05:6214:1248:: with SMTP id q8mr4838237qvv.66.1587656714678;
        Thu, 23 Apr 2020 08:45:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587656714; cv=none;
        d=google.com; s=arc-20160816;
        b=vbu81uJQOiHz7kuAIDjcOsJGCVwsr8cb9bya+TzFeEcSfqG5OIiN/5orL5IIVKG7Jv
         W/Gpf5dDQ/c033xouaEcNLjB+GYyjgFhygoePfGsH0PA7QcSz7BNkjPxklCVl00hNviO
         aN0/LFAys2MZX1mRonOzaKeM0BzQhjBUDZjMkVqd51uCBq2eCnLeBghhy/Hyihhu10xG
         JSvKTBsWymQaijwa3Na79QIS5DFN1k5H4ngpVKh8mhqRK1tiAnixistpX7+I0U/6FvKH
         a2UU77cqSfma600TTTMs7vEMeqpmHh+miWsE9dFg5wPv057ZTh6p1NpyEAZSQChD86vq
         HSvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Rm9KJcgesHnxEUAmWee/mQjOLa+QTtuSP9X5sIq0tgA=;
        b=tospoCADPWR0tuEAAp/1IpKmAVgl98sTq2aYMO/xfDaQy8AeyOeSwo+FNTzEdfsezO
         r8fFgyvaXZnQwbsowr5xJQ+DyuItQNAY99mGpdHyoQJt+b2noSpZe6LXo5Rn0fYHk87Z
         q0vdioOFQgiibX9U8bkO3dSL0UQatKMYVTdba4fE0XWwyyk9iOVzOrmbJkNQVLOU88/1
         pOEECVuhaRtxV7qGkwfBmKkVTIB6EQlrcS3VJzG07BYjDgCOfNVStSdCpQwnZDiQujX0
         qnGd46xaVypfh0Dv2STI0xcdi+psljvNTloVnMS3yVrA1zSLDw2CINjQe/EGnSxU2ld1
         2Zjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=jPvZSIVR;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id l23si147504qkl.0.2020.04.23.08.45.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Apr 2020 08:45:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id p25so3127332pfn.11
        for <kasan-dev@googlegroups.com>; Thu, 23 Apr 2020 08:45:14 -0700 (PDT)
X-Received: by 2002:a62:1d48:: with SMTP id d69mr4369984pfd.102.1587656714044;
        Thu, 23 Apr 2020 08:45:14 -0700 (PDT)
Received: from localhost (2001-44b8-111e-5c00-7979-720a-9390-aec6.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:7979:720a:9390:aec6])
        by smtp.gmail.com with ESMTPSA id w125sm2435466pgw.22.2020.04.23.08.45.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Apr 2020 08:45:13 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com
Cc: dvyukov@google.com,
	christophe.leroy@c-s.fr,
	Daniel Axtens <dja@axtens.net>,
	Daniel Micay <danielmicay@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>
Subject: [PATCH v3 1/3] kasan: stop tests being eliminated as dead code with FORTIFY_SOURCE
Date: Fri, 24 Apr 2020 01:45:01 +1000
Message-Id: <20200423154503.5103-2-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200423154503.5103-1-dja@axtens.net>
References: <20200423154503.5103-1-dja@axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=jPvZSIVR;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as
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
 lib/test_kasan.c | 30 +++++++++++++++++++-----------
 1 file changed, 19 insertions(+), 11 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index e3087d90e00d..939f395a5392 100644
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
@@ -622,7 +630,7 @@ static noinline void __init kasan_memchr(void)
 	if (!ptr)
 		return;
=20
-	memchr(ptr, '1', size + 1);
+	kasan_ptr_result =3D memchr(ptr, '1', size + 1);
 	kfree(ptr);
 }
=20
@@ -637,8 +645,7 @@ static noinline void __init kasan_memcmp(void)
 	if (!ptr)
 		return;
=20
-	memset(arr, 0, sizeof(arr));
-	memcmp(ptr, arr, size+1);
+	kasan_int_result =3D memcmp(ptr, arr, size + 1);
 	kfree(ptr);
 }
=20
@@ -661,22 +668,22 @@ static noinline void __init kasan_strings(void)
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
@@ -743,11 +750,12 @@ static noinline void __init kasan_bitops(void)
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
kasan-dev/20200423154503.5103-2-dja%40axtens.net.
