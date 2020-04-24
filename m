Return-Path: <kasan-dev+bncBDQ27FVWWUFRBZP3RP2QKGQEXYIQ4GQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BA5C1B789C
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 16:55:34 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id a11sf7094163otc.17
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 07:55:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587740133; cv=pass;
        d=google.com; s=arc-20160816;
        b=bf+Ps+6nLQJC6AiKgjzpUO7PXCYvWsX+ovtSMkZE25IH0MKc17UEzPZ3WSfsdc6UAt
         kx66Sc/NrCGfoVMBNmHCPqf0QO0wujCm3+oEzJ4q9ZsTKb+yELyKt/cXCM9m5naxLiXk
         qMBWvY1JBZVF5TS6SajFUSOVOfio2HEvNYhT2vGfyEeCyVJUvjXti7oinvLhKNGUiSyy
         rZ9FWWlrwG/+vPIl6KxcyFQkD65D+W4v0dAbDaH8OTfotp8dbaxAOBUj/Awq06CmaeBl
         wjqsnH+CYRbXD49qYIIT3UAeL+fTmndK/6r6HX9YZe8toIQdpMpEu//tWN4Z3iiP/Q/X
         OzIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature;
        bh=ml5KGugaCz12RqyH08E92G9E0nDIuDYLa5BssLImEVk=;
        b=PLRQ3wPdNt+886nJC7N69rbJqGxb9i2Kcrueq66KzC5lc27LpH7UiAg9xWhIiz2l9X
         Z+MW6j7YbIjrGvB0eRgzxqgUs0vBY2KhVggiIw/uKVHH18BV10ZoC7VWkictILw526QV
         2QJ8ry6CNIBaKqS3qq+x1tP/U6gpNR9WzpY51uMd4cW+1Lhg82I7SEVFM+2jllw4HBTt
         fO+DoGa3FxZzWPbsZkzQxfKsBrqgZuliRBtP4ijNqHnfHaB4ejkm8LX3xRnARGG4wKZG
         ba+aGVH3/VjvboojeyuBgNgeKoD8ZBqP+f9x7hyGu128wvwMmOWtU8AUE5SaaKJeBRyb
         kuZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=f9J3gTCI;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ml5KGugaCz12RqyH08E92G9E0nDIuDYLa5BssLImEVk=;
        b=RN861CroNAlANqhVU3KkJm+CCK01Of6Sf1VQsttO1lnJQTIjs3JzuiaMYLXgYoHZCS
         T5gtyqxNvxeSytRJD33uOUM9+QNcBlztp4rm4wwu3L0fwiN8QMfP/LlDay2aWzalUOQo
         4TSacNiuYKG1lmS7ZJrz8nzHZZsrEQa14mKMtzQ7GFYCJ4vcQqlpZMgzroS/BvpdO79k
         bM1X5JuCt5PaDAXZLo4Y/Ot5F+tFsyb6RzWDh4stpSd1MEvthoKSyawlhVu5OtdVKnUL
         IDyJ00fAbk/1L2N9yLRa7bcp2C5qJ4CxnuMNSH6kPFwnCZTSp1+cbQ9Pjz3883Uea9wM
         nv2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ml5KGugaCz12RqyH08E92G9E0nDIuDYLa5BssLImEVk=;
        b=uSg/NGWC7+f3SpDpuZ2NKE6vvsImaltnz2vYm8rwiVZ5ZomMOD7frK/ko4PWnhX5PL
         YuB+wAzUuqyVuxjzcMTfFfQPffwUhJXREv7IiyuWY22hivgclwBHS07KlOhy7dK8ZdN3
         0EUBKNEO1Oln5dW+9wzwWHWR+KzGk4udYsPftbMe0vxc2BMTbwPCXb0tOorIm1Z4vpBo
         43a1AoKEuRVwTZgMiqj1xV+D1tk7Np2uvY7sTedaptbzwc/b/QV1MaxgR5jQSIu/s0PE
         n6ssZk+0EOzS9/I2Pxzt3PDRk3vyxdgCiPx4KrJTIvu02JTI0yTkPTWjrnRxYO+pjZR7
         24yw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYkqTcghtmy20JHTWQtTiIB0lgGQH1Qgf6I3rNH7sDG2xVcYRBL
	LyjF0KswzmX+V9NSsaT8gww=
X-Google-Smtp-Source: APiQypLR84tNa+4Pds8UISMuZs9EcS7piz2lnlCA85rSdkgwcubDS2jU2/qbrGOZxWEVpE9WFbQGVw==
X-Received: by 2002:aca:88d:: with SMTP id 135mr7130219oii.10.1587740133076;
        Fri, 24 Apr 2020 07:55:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d485:: with SMTP id l127ls1673309oig.9.gmail; Fri, 24
 Apr 2020 07:55:32 -0700 (PDT)
X-Received: by 2002:a05:6808:24f:: with SMTP id m15mr7736154oie.152.1587740132654;
        Fri, 24 Apr 2020 07:55:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587740132; cv=none;
        d=google.com; s=arc-20160816;
        b=phTeBF2GUxrGy0o5Ble/pnrg+lGxNEReqKe80+IuuEsRqGzVt6na1lR/PImpyFe21q
         gl+nUs7wrtI2OouveLx+3iEC/m018/s053xQ80wgsDcfBVZf+9o3803YwYIlF9XbbVqU
         RJUWpm4WMjZzdfkRI9OE3zpKhhkH8DQxhTb8J4Y7Vm0iTFJI6rT4abhZDkTA6iwcp3ob
         wTh8SBidru+vRAI92x6TPecU84nfEuHzWC3DQpwgrU0EN20dEAHmLsa4pn10ccHb+dGr
         jJMvPOiFURXTFjhgNw8ABfTyUqQ12x+RfeWisElDN4LoFcuLFJ41sccPbAcxtVgDbm7S
         qnLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=qPgC2WAJzXEPrhZgAELaUlSrwS704anaXCh4Y7pEazI=;
        b=VuNj8UTcd3FiTF3Io9i3IncP5YOX/Wk7uvpmGcvqYb/WcumeGxLZUGExytEIjdNtnW
         WQX6OhPFxyN/Rprgx2K8/Q70TsynRibL2ukVMXIpadxJzH4/j9wxNOjlYSYRhFAkS82X
         j7IotiUNtnY5oLZ15ytY6WRXvOEVbLeS6VXdIzl6yVDfmJeYhCFKr00l+36ebfDTuyxP
         J0Qdfhhxj4X72Hv63vzYO8F772yfwWAjCeUotSll7X2Irc07Tu1C0OxdGJq/eKXNchIZ
         K5Q7TDvna07veEcH/pKnp9DD6evy/1lsFGhb2o4Gwk1XSjv/paEBm2CeNPhxVC1M+nIt
         6lww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=f9J3gTCI;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id l22si473858oos.2.2020.04.24.07.55.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Apr 2020 07:55:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id t16so3819716plo.7
        for <kasan-dev@googlegroups.com>; Fri, 24 Apr 2020 07:55:32 -0700 (PDT)
X-Received: by 2002:a17:90a:246e:: with SMTP id h101mr6793515pje.83.1587740131771;
        Fri, 24 Apr 2020 07:55:31 -0700 (PDT)
Received: from localhost (2001-44b8-1113-6700-fd06-aa7b-7508-4b8b.static.ipv6.internode.on.net. [2001:44b8:1113:6700:fd06:aa7b:7508:4b8b])
        by smtp.gmail.com with ESMTPSA id o11sm5123020pgd.58.2020.04.24.07.55.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 24 Apr 2020 07:55:30 -0700 (PDT)
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
	Alexander Potapenko <glider@google.com>,
	David Gow <davidgow@google.com>
Subject: [PATCH v4 1/2] kasan: stop tests being eliminated as dead code with FORTIFY_SOURCE
Date: Sat, 25 Apr 2020 00:55:20 +1000
Message-Id: <20200424145521.8203-2-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200424145521.8203-1-dja@axtens.net>
References: <20200424145521.8203-1-dja@axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=f9J3gTCI;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as
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
Tested-by: David Gow <davidgow@google.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>

---

v4: I accidentally dropped a memset from kasan_memcmp and then 'fixed' it i=
n patch 3.
    Just don't drop it.

---
 lib/test_kasan.c | 29 +++++++++++++++++++----------
 1 file changed, 19 insertions(+), 10 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index e3087d90e00d..dc2c6a51d11a 100644
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
@@ -638,7 +646,7 @@ static noinline void __init kasan_memcmp(void)
 		return;
=20
 	memset(arr, 0, sizeof(arr));
-	memcmp(ptr, arr, size+1);
+	kasan_int_result =3D memcmp(ptr, arr, size + 1);
 	kfree(ptr);
 }
=20
@@ -661,22 +669,22 @@ static noinline void __init kasan_strings(void)
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
@@ -743,11 +751,12 @@ static noinline void __init kasan_bitops(void)
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
kasan-dev/20200424145521.8203-2-dja%40axtens.net.
