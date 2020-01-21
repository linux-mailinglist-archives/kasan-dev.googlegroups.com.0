Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTWCTTYQKGQELCOQTCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DD4E144188
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 17:05:34 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id a21sf1010735lfg.4
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 08:05:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579622734; cv=pass;
        d=google.com; s=arc-20160816;
        b=b6GjJOnysnQo3/E7rCzxY9Xe4lCCgc8rMDH2TTmasluXPnG3nRzxU4mMgCDX6o/W77
         s71Gizchd9pJ2vbR622TMD6iSCnPM4RLIqqLmXKbWzxV/gumHQ/ysJl9woCYBOgIKdL4
         6N8oV72Qg8rZ138C9t2PbXB5MTPaqvEXTOJCaf8iV23I4n6R9F/2JkQ0PZoNGgxFNfos
         Y79oaE4KQdAFZO6LHQx0dI8nTyGiKdW7+/EnmNJlGclSqta1lz1gJQZTT4DM46pVPpdF
         7D9c1IyGtfz0B/zKZLFyJyTJK3Ug96dlZMnu0cr7k87D5nXFACbEVmkSAzaIWDjt00lk
         Ls/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=e0gyzFHPkx9sxCCb9eC4kCLO6ZuEafO6iTkmJ2CbZUk=;
        b=imYCDewn3SHchUzO9HAJ9nVm04xL5v2Fpvc8E01noERerRtY6MrlOjEapy+6Gvxdbz
         6XFA+aoZusePNa8oLyRf0euxBwBceIgNhboeLA2FTKJVtasvJyFaUkb5jnPc+WTexZN7
         I0ECp4beXE51vt+dkpHpcShKlw3zjyT+Mc0oEDQ4ZYmLBi/2xmeUqjJ13vkdYPQbamZY
         6doAm47gkX25qDFZ8uF3+DqdPABrCSNXpS96yQ9sraLOmBP5wBKRPIYFZNI8NmTwg2xv
         IhFiRZRpHHHQci9actyS8QHY/0KOjSTCzuRHrQvj7UeqRdcqScZRredkNx8lwQJxHfIn
         w+bA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OiZZ2Nb9;
       spf=pass (google.com: domain of 3tcenxgukcsmdkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3TCEnXgUKCSMDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e0gyzFHPkx9sxCCb9eC4kCLO6ZuEafO6iTkmJ2CbZUk=;
        b=kGZjGohknFAj/gTzOaCdWLrli71orst/WM6ddsLl6YTmpYZFKyQWKPTJtWcKwDkXQ/
         7xsegI5wOkmigt+sOgY0LEihmYulXdqBvHR9V2AF64U3rmYcz9MvntiVZSEUDy1i694/
         PqZO4jssvaIZylWKnuTCxqM7+fVlZhaa7cYtNAYkwViRNKyJxGi/yOWU7zVDYhf19zdn
         XBSLqcAs9dTt/F9MA59dDM3CaT/LKdyVkJBocCV4NvXlqp/KfgaaAf9LSh4YEDcpJV2F
         q8FYVeUMiPXO0JneBS8zc75/eDeLfg22Dh5Y+nWfMOPW9S81cLlip8stClY0KtnQh0vO
         Lk5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e0gyzFHPkx9sxCCb9eC4kCLO6ZuEafO6iTkmJ2CbZUk=;
        b=TxjXZ9GTlZClwe8GgtNZAV/0ynpmXIk2vfzgzwM/RgaLMImJIS7kvsTSOex29D8r7D
         jcwboA8EbFFQTbb0qJ8o+ZmMwVOs0gW4emOGa2+8XcgiBSBx+ySC/m7N/N/P6qYq1zh6
         UPvceeSm/dkVtSgLxWbP9ifj6RaEbDXi9y58f46x6xX9HJtV4G+jFf/GhPweZFe/SDm9
         s4gaoIDESVCS1+hLySgdCfSev+cZQnDFXnwvZxBw+OqUNunOieDqc+kV7xdx4b1GG1nA
         5IlfZ6RQsUNdeZwlMMWNO741098ShrW50PnEByPJAt2r9HztekWZSaiKR3JAH0++rMaX
         Brfg==
X-Gm-Message-State: APjAAAUFBLQgo8SNgkb01qk1PEQydnj24wAz8iH7wcPzE4Dw3mxVZoos
	ulOYMjDMT7v+wuS4UxUovk8=
X-Google-Smtp-Source: APXvYqxMxLWyeORPO90u3vmZ0xZjaq9zLlPOY9hgtxRhLUN/MdcQjRtWsjbmpWmQ/cGu4JC1GMO4mw==
X-Received: by 2002:a2e:9cca:: with SMTP id g10mr16636100ljj.258.1579622734059;
        Tue, 21 Jan 2020 08:05:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:ec09:: with SMTP id b9ls858751lfa.6.gmail; Tue, 21 Jan
 2020 08:05:33 -0800 (PST)
X-Received: by 2002:ac2:485c:: with SMTP id 28mr3028701lfy.118.1579622733303;
        Tue, 21 Jan 2020 08:05:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579622733; cv=none;
        d=google.com; s=arc-20160816;
        b=xpoZ3A/wxA3yrM18+jzPiSh3AjnmNxeMs7ShsTh4nplijknQKqale6Dh+RXOauHjY9
         3uHxlXYo2/Odkszw0Hsf31xz6FKozD1gYBGaJZRYs3DJ1c3tEbu/71MkNecMBYIUnLA2
         yEfuc3wTsPjs6oWe+Ody71CYIihtsg9z1AoiOlPdx3VxVE/1aCITjJUzszBLQ/28zNM2
         cjhuuwsJu4krrrSQLaS68dklj1eptSCIx6CmVue4iJgUnZsPN5zl/+zgov1PYQ2KSPui
         +ApETr4LTsX+P3Rrm4bO026y4gjuPAVWrHChVk9MY3+m2FdmN8FGjx5cdIcrxG4Q3p3/
         +jFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=XsOEVIH7jX8NSYZHOvo5XGjY3g9CTXyDnOv/v4uZ/Bk=;
        b=l0Y9Z0fyYAFLidGqP+KV87vWL/Iyq53cqBMyf3NcTzi43iIB/oMOjA1eBaW8wz7YYk
         K5e8zeh+vy+UwhQg5h9zBSgY7BsmcMHIj2XB955669DZ/vYkxwrX0v8UutUaW4FTGxwp
         IXnLWE9CcffNMeuIPYpFvNol4cadeUyexW02Tatoa2mUFkROuLtvxo3oUKz4Ff85QqB9
         RvJc0VHUqEPN6jD3W6dysh6zQnYNUrCIhkKWJJJKRMoM7uJdtN5ElpOjqW4P9TN7hx55
         TdAM79R/+9hzgnKvNIfItIJRbrJv7bAHSVf2EHVvwwZLjyKSAQxjRndd6nRGsPDPTcL2
         FJGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OiZZ2Nb9;
       spf=pass (google.com: domain of 3tcenxgukcsmdkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3TCEnXgUKCSMDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id a4si875316lfg.1.2020.01.21.08.05.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jan 2020 08:05:33 -0800 (PST)
Received-SPF: pass (google.com: domain of 3tcenxgukcsmdkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id w6so1502528wrm.16
        for <kasan-dev@googlegroups.com>; Tue, 21 Jan 2020 08:05:33 -0800 (PST)
X-Received: by 2002:adf:b60f:: with SMTP id f15mr6190858wre.372.1579622732563;
 Tue, 21 Jan 2020 08:05:32 -0800 (PST)
Date: Tue, 21 Jan 2020 17:05:10 +0100
In-Reply-To: <20200121160512.70887-1-elver@google.com>
Message-Id: <20200121160512.70887-3-elver@google.com>
Mime-Version: 1.0
References: <20200121160512.70887-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH v2 3/5] asm-generic, kcsan: Add KCSAN instrumentation for bitops
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	mark.rutland@arm.com, will@kernel.org, peterz@infradead.org, 
	boqun.feng@gmail.com, arnd@arndb.de, viro@zeniv.linux.org.uk, dja@axtens.net, 
	christophe.leroy@c-s.fr, mpe@ellerman.id.au, mhiramat@kernel.org, 
	rostedt@goodmis.org, mingo@kernel.org, christian.brauner@ubuntu.com, 
	daniel@iogearbox.net, keescook@chromium.org, cyphar@cyphar.com, 
	linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OiZZ2Nb9;       spf=pass
 (google.com: domain of 3tcenxgukcsmdkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3TCEnXgUKCSMDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
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

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Arnd Bergmann <arnd@arndb.de>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200121160512.70887-3-elver%40google.com.
