Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBHOS3YQKGQESCO7FSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AF48142D0B
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 15:19:49 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id b1sf13611164ybk.21
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 06:19:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579529988; cv=pass;
        d=google.com; s=arc-20160816;
        b=HYpZKlWjZjDo5hfDFXZdVTkaZtPmV0tQPf/ds+eXXn86zLadlZXC6fEgrNKEwXMmNx
         IpycsjT2nFdFavmjULyiO69mx4g7UYa6cDBh7t6S53K9aeQZqWVGf7wKAlK8jHGwFerB
         E16J4ZdFlxEkbHWyux4Hb+h/ThzDJql5PrRKJgwPSOYgoSZQxek5cXx9jdv9I5o7LWKE
         XkWZAXF/Gvw2Hrlt3WmKzSxHvEdEs1pLCiSloJaNmhwvQemsB3GFEVfYF9LuxNXpoqva
         QL7/d9F+dISjhjiYYGxMGK64JzWW4MS7N5qGNb60mRnneuCKFZq4GMBYvKv4ovMb2Qlj
         DvBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=89F6rKm5MEjxsqXt7JHY2sChbDqcRZCa8rAYYAfh3pg=;
        b=yOpWiAH172q14+rxydHM8gYRLNuIE7nWYveuX6rbRHofPDu1h7Oi8Wixn9r+WMmuX4
         fsuvHcrRxbtkHT2EhpbX6J6BjGFBejYEyZNZpR4RTGFU1AiZV1ciMLuVHx261BtzsEIL
         l/Z4gsN4gh2oWKz7yeW8QcxLHbK9CPn+kpPSJI6DWYqnY+GtYMlVHG0L9Gxss9tfzj4m
         zatpW9uyK/J7mpKwdpok1a0yCbC5i67usSn0nJ/NRdXMorvPFna+RSBBFWBnfYojzIji
         eh/9vXE417rkAzLmZ+I9grfPOj9T/EtqnkoVFqGFU7VbGP2a407UmxDp2lkxAV7Vu7cF
         hvkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=b2jwDAsC;
       spf=pass (google.com: domain of 3a7clxgukcf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a49 as permitted sender) smtp.mailfrom=3A7clXgUKCf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=89F6rKm5MEjxsqXt7JHY2sChbDqcRZCa8rAYYAfh3pg=;
        b=J85uHkj0ln3I577dAT81Hj6pXqKZTFRpi6tJwX6fMbwTeiZbeoCqirwFM4F3gjrHIm
         YojqYRfME8vfEimCIFvVqNTrGMuqhx+QT029gXTDRY2H7f6yUcmtkr5GBbDn5P5a31r4
         FKxLPRFUBTyh/z530oogFQUPFArAT5OQpHfo8K6L2UAT3+JuHlScUTkBBHqHrh4kEEfB
         Q98s16hsKM722tJJzBUwiHc+J2Ooio6ULraotuuAmsJKdXXJCZGWA5RkkUx3JJqoOLA8
         uklR4HrRD6X1oNYRrxSSvFQukuyDQFjBi89azh10qXgyM6JTfQmJu/u3D5x89gg6Fpmk
         psLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=89F6rKm5MEjxsqXt7JHY2sChbDqcRZCa8rAYYAfh3pg=;
        b=T+wtEyssbqoF2fOUI6KwscME8RDgvnQvCXFshWsAPDwbHAIlYsIxsgvDJeM6l95U55
         PPJPzpFY6QoksAKWj9Wl3LVWz6uz8x+h0sIKSYP05K8IrgT2DjjciaEu3VG9Jgr343kq
         0hBZKe+JTh7plvrAbzYuLCUOgHZjlteSc6B2QjevCTjtxTyjGRJeUTWm1OJ1/LwRONm7
         gXHEos54Pc7Ax6vy4yzHnwfjQ+itNd4VcL2pjQyJ+kPP8JUCYL0klqaBxPmHONxHM4lz
         som9sVQdZj77rXPWZd6xOR4N8GOTHh2VzYVkd02TcCo+acq55DY7U5R/rY53DyUbwkgH
         ToZw==
X-Gm-Message-State: APjAAAU79L/ma6OTbaaxkuCwDKcHsyT70iHLZyZl1laEqmPkhlNH8By4
	9E9DGU8gfWXWYLoTA+CzpHw=
X-Google-Smtp-Source: APXvYqyUkEL86dxijriF8VNDrNUl7BrHp9w8OZReiy+Bsk/3MzZuNsv4nRzrJCnz1Ty0BEHmzublxg==
X-Received: by 2002:a81:7016:: with SMTP id l22mr39375516ywc.69.1579529988394;
        Mon, 20 Jan 2020 06:19:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7184:: with SMTP id m126ls2014913ybc.12.gmail; Mon, 20
 Jan 2020 06:19:48 -0800 (PST)
X-Received: by 2002:a25:8601:: with SMTP id y1mr17580246ybk.193.1579529987957;
        Mon, 20 Jan 2020 06:19:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579529987; cv=none;
        d=google.com; s=arc-20160816;
        b=gUOHeRwduu7VQ7Zxg/i/sK6bxT3w5eU6mIgk7E7ROPAb8YBCcm/UnlWDJfULRJROut
         fB7lP0QdN8f5mBWY22BqQD9S307i+Fj7db9OA4xZpisZnu65b5n81qcZX+DiTgm9nB6Z
         I5uzZTgeopuM0uFSW3M/PDqmuI/pkk9OdWoW0yPrD7gOMCca+HkSG2QwHk/gfI4u+Fe8
         zFdnJMVzpoA7tkHZLkueTks75kR9baxBT1WOCnXN9TdCm3ypKDKSB3HBULadRIFaAU7U
         nOTHCK30kSzlO8jf9uaXp1SEegXZ45jJtOBG3YVPICZLcJzFFiiLm5pFm8FETbAYD2/r
         xVog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=1yb9KPpW163F2PxwvPiqbffL92UYcGBzOHlCQNKTfHs=;
        b=nE69e/aj/YuDbyP32XOmrFN2PfON4LVt91xA8RoHTc/PqPh+aDHttbMO1yhO3gn4P+
         2O1hTwx3LZJd1jZIT1/hwRTG6JFaKO0RbTtbwYkBZo81pBmnMTv1H5x18IvnaTt0ylmB
         deIybmvYXOKfO5T6ubco5zNGnTmI/YnX30HUW1MhnL3EzMhtjmXIKoMdn3bOf3cxwV4V
         LCmvaxTMEbrUVyP9OiyZ5tjv25N0ZvmhcXFjDpHLi33qsOJgvb5zp8gooyI+USMcSTSR
         EWSu6pm7L8sLExITTyaKbPwmgiSY1OEZ0Zr2MT1kzt9a67mfdfcBofKKdiXCtKHRa9b+
         ATww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=b2jwDAsC;
       spf=pass (google.com: domain of 3a7clxgukcf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a49 as permitted sender) smtp.mailfrom=3A7clXgUKCf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa49.google.com (mail-vk1-xa49.google.com. [2607:f8b0:4864:20::a49])
        by gmr-mx.google.com with ESMTPS id v72si1289522ybe.1.2020.01.20.06.19.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jan 2020 06:19:47 -0800 (PST)
Received-SPF: pass (google.com: domain of 3a7clxgukcf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a49 as permitted sender) client-ip=2607:f8b0:4864:20::a49;
Received: by mail-vk1-xa49.google.com with SMTP id t126so12936217vkg.6
        for <kasan-dev@googlegroups.com>; Mon, 20 Jan 2020 06:19:47 -0800 (PST)
X-Received: by 2002:ab0:2ea8:: with SMTP id y8mr10878454uay.23.1579529987496;
 Mon, 20 Jan 2020 06:19:47 -0800 (PST)
Date: Mon, 20 Jan 2020 15:19:25 +0100
In-Reply-To: <20200120141927.114373-1-elver@google.com>
Message-Id: <20200120141927.114373-3-elver@google.com>
Mime-Version: 1.0
References: <20200120141927.114373-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH 3/5] asm-generic, kcsan: Add KCSAN instrumentation for bitops
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	mark.rutland@arm.com, will@kernel.org, peterz@infradead.org, 
	boqun.feng@gmail.com, arnd@arndb.de, viro@zeniv.linux.org.uk, 
	christophe.leroy@c-s.fr, dja@axtens.net, mpe@ellerman.id.au, 
	rostedt@goodmis.org, mhiramat@kernel.org, mingo@kernel.org, 
	christian.brauner@ubuntu.com, daniel@iogearbox.net, cyphar@cyphar.com, 
	keescook@chromium.org, linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=b2jwDAsC;       spf=pass
 (google.com: domain of 3a7clxgukcf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::a49 as permitted sender) smtp.mailfrom=3A7clXgUKCf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Add explicit KCSAN checks for bitops.

Note that test_bit() is an atomic bitop, and we instrument it as such,
although it is in the non-atomic header. Currently it cannot be moved:
 http://lkml.kernel.org/r/87pnh5dlmn.fsf@dja-thinkpad.axtens.net

Signed-off-by: Marco Elver <elver@google.com>
---
 include/asm-generic/bitops/instrumented-atomic.h | 14 +++++++-------
 include/asm-generic/bitops/instrumented-lock.h   | 10 +++++-----
 .../asm-generic/bitops/instrumented-non-atomic.h | 16 ++++++++--------
 3 files changed, 20 insertions(+), 20 deletions(-)

diff --git a/include/asm-generic/bitops/instrumented-atomic.h b/include/asm-generic/bitops/instrumented-atomic.h
index 18ce3c9e8eec..fb2cb33a4013 100644
--- a/include/asm-generic/bitops/instrumented-atomic.h
+++ b/include/asm-generic/bitops/instrumented-atomic.h
@@ -11,7 +11,7 @@
 #ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_ATOMIC_H
 #define _ASM_GENERIC_BITOPS_INSTRUMENTED_ATOMIC_H
 
-#include <linux/kasan-checks.h>
+#include <linux/instrumented.h>
 
 /**
  * set_bit - Atomically set a bit in memory
@@ -25,7 +25,7 @@
  */
 static inline void set_bit(long nr, volatile unsigned long *addr)
 {
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	arch_set_bit(nr, addr);
 }
 
@@ -38,7 +38,7 @@ static inline void set_bit(long nr, volatile unsigned long *addr)
  */
 static inline void clear_bit(long nr, volatile unsigned long *addr)
 {
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	arch_clear_bit(nr, addr);
 }
 
@@ -54,7 +54,7 @@ static inline void clear_bit(long nr, volatile unsigned long *addr)
  */
 static inline void change_bit(long nr, volatile unsigned long *addr)
 {
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	arch_change_bit(nr, addr);
 }
 
@@ -67,7 +67,7 @@ static inline void change_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
 {
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_set_bit(nr, addr);
 }
 
@@ -80,7 +80,7 @@ static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
 {
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_clear_bit(nr, addr);
 }
 
@@ -93,7 +93,7 @@ static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
 {
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_change_bit(nr, addr);
 }
 
diff --git a/include/asm-generic/bitops/instrumented-lock.h b/include/asm-generic/bitops/instrumented-lock.h
index ec53fdeea9ec..b9bec468ae03 100644
--- a/include/asm-generic/bitops/instrumented-lock.h
+++ b/include/asm-generic/bitops/instrumented-lock.h
@@ -11,7 +11,7 @@
 #ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_LOCK_H
 #define _ASM_GENERIC_BITOPS_INSTRUMENTED_LOCK_H
 
-#include <linux/kasan-checks.h>
+#include <linux/instrumented.h>
 
 /**
  * clear_bit_unlock - Clear a bit in memory, for unlock
@@ -22,7 +22,7 @@
  */
 static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
 {
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	arch_clear_bit_unlock(nr, addr);
 }
 
@@ -37,7 +37,7 @@ static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
  */
 static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
 {
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_write(addr + BIT_WORD(nr), sizeof(long));
 	arch___clear_bit_unlock(nr, addr);
 }
 
@@ -52,7 +52,7 @@ static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
  */
 static inline bool test_and_set_bit_lock(long nr, volatile unsigned long *addr)
 {
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_set_bit_lock(nr, addr);
 }
 
@@ -71,7 +71,7 @@ static inline bool test_and_set_bit_lock(long nr, volatile unsigned long *addr)
 static inline bool
 clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
 {
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_clear_bit_unlock_is_negative_byte(nr, addr);
 }
 /* Let everybody know we have it. */
diff --git a/include/asm-generic/bitops/instrumented-non-atomic.h b/include/asm-generic/bitops/instrumented-non-atomic.h
index 95ff28d128a1..20f788a25ef9 100644
--- a/include/asm-generic/bitops/instrumented-non-atomic.h
+++ b/include/asm-generic/bitops/instrumented-non-atomic.h
@@ -11,7 +11,7 @@
 #ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H
 #define _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H
 
-#include <linux/kasan-checks.h>
+#include <linux/instrumented.h>
 
 /**
  * __set_bit - Set a bit in memory
@@ -24,7 +24,7 @@
  */
 static inline void __set_bit(long nr, volatile unsigned long *addr)
 {
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_write(addr + BIT_WORD(nr), sizeof(long));
 	arch___set_bit(nr, addr);
 }
 
@@ -39,7 +39,7 @@ static inline void __set_bit(long nr, volatile unsigned long *addr)
  */
 static inline void __clear_bit(long nr, volatile unsigned long *addr)
 {
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_write(addr + BIT_WORD(nr), sizeof(long));
 	arch___clear_bit(nr, addr);
 }
 
@@ -54,7 +54,7 @@ static inline void __clear_bit(long nr, volatile unsigned long *addr)
  */
 static inline void __change_bit(long nr, volatile unsigned long *addr)
 {
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_write(addr + BIT_WORD(nr), sizeof(long));
 	arch___change_bit(nr, addr);
 }
 
@@ -68,7 +68,7 @@ static inline void __change_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
 {
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch___test_and_set_bit(nr, addr);
 }
 
@@ -82,7 +82,7 @@ static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
 {
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch___test_and_clear_bit(nr, addr);
 }
 
@@ -96,7 +96,7 @@ static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
 {
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch___test_and_change_bit(nr, addr);
 }
 
@@ -107,7 +107,7 @@ static inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool test_bit(long nr, const volatile unsigned long *addr)
 {
-	kasan_check_read(addr + BIT_WORD(nr), sizeof(long));
+	instrument_atomic_read(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_bit(nr, addr);
 }
 
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200120141927.114373-3-elver%40google.com.
