Return-Path: <kasan-dev+bncBAABBONGTLZQKGQEYXPJ26A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D29117E7CB
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:26 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id c3sf7429182ilm.4
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780665; cv=pass;
        d=google.com; s=arc-20160816;
        b=ftu+/QzN4qKi9E+pvDHYDzeuReY455jaGoS2st8reohtRcOIL8qVfV6KDDVMm02P+h
         lBG150qgjmE2mV9d1a7bQgukIWffdAloYucVSUOGYi419lv20zQzBmOyAD60yaWK1KLl
         PSmPxyI+K1C7Bqb7HXw+8LTW1gp6xbohenuIslynteWWVNSDrfGDNAeYKBQj5Si3AMxR
         MeikUXJFiZvR10MM3IxeaCXgU3nEueVcV8kLkehZvdLh4zuuMoSZWWyH5VZ0nXvnIYdo
         /PI/q6I+M+CFj2W90EWJn094qdCQ0e8cxI1yDXw/t/91d2ufqrSAn0FrmW3d6um1vays
         h2Ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=sYEoRvnX+rO8r3Z4hztuhkFQWrcHW4oBg53ulMM+mG4=;
        b=HhpI+J8X3drSacu82YHcLRzdwjOWu/cNsz0IT6+5ZhrYIcQ0rVeRpMsHjTum4fRZLO
         QcYixpiXcEHtaDC2mIdu7Fp5EznVJnn+peUCqE8qQVX5oQ09lhU/4SCio+qkcvBj4Xgh
         QRY8jhYD5H+3ri+zF5me7uRmD38ATtk04uzQXaE0b7/J2g/08+yx4Cwy8ONvWWsT6dps
         FEUm75bjtEZsiG0oMzDW8rrkrFA0ZnDyzjJVYpdp3gbGrcL6i3/W/VSDXv9lFsutcc33
         9XF4k4PkXg+HGUBcOQjz7H7mHsK32U9XidIHnSPDaEg1Gmb59jY1ZATCQaHXtJb7RFI+
         C9oA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="rV93/R6q";
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sYEoRvnX+rO8r3Z4hztuhkFQWrcHW4oBg53ulMM+mG4=;
        b=AxIDlRLBGFNlI7Q99Q7BwXDtiz+n/0D8KgLNhK26MKBsAKTJLsNSVm/XoBB8CxEBtO
         +mWOn/PzsoI4p1ANNfx58YbHy7I2eNZFyFJXHbnuY30ZswKQWqkzY67se+P2Vvcrc+D5
         /UrNIZZogNtMjljmFHAGdjqbEnqXAw7wx7iOan5N0g8e2dajnQpNEr+UcoR47uuWX6g/
         pcRkDuTsqviUanDRamUqlTzYXc9K7vd8TdZ4j2DF2HqZg5+pu0aCI4eUgzDSYsHejDEp
         /K9/VhHZQOi+Lue6P1fXlzfFcCXpiWim40ioYk04r6qNO01uPO4wAuibVb9+p94e7CGI
         5cUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sYEoRvnX+rO8r3Z4hztuhkFQWrcHW4oBg53ulMM+mG4=;
        b=COjxG857IIlX2JzUWGZUinCet8QqMLnLtnWVqJfaVN0SExMSLEsClF+kbKxDEpyJRS
         T2ClkM7+dUAo7frd5oe9k+jzCkgEKERwZq87RvgNbyJ5TmjWNHgGPcLbeBprb2dZr7ty
         19p7DbHlzTisx07egabZb8z2T0hD7W48LhpBIn0TMGBP0lcX1bTb4x99Gn/4SIdmzuUy
         HJOrXUp/Gfcw88sgVp4v7FLEwF1zAwYtoQGqYAWP941RkecH5gSTc8Rm8WjcK6NNyV5i
         nJfrmFHlDpkUFaYc03S4yf7zfEIExa7byZHJfNWgTsF/QLQexL64iVaSyMjRDHkQ6cm+
         VfLg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ0lTLUIsJQIf7J9NFzDLIEAIEbqLUWOOSIFyfUObxqXlv1aDjDt
	lT4FKrlnuLGgbweGORG1qdE=
X-Google-Smtp-Source: ADFU+vtb3MGui/QmZpBoYGonNMlWR4DxQlS0BYqxNFiO+DNX/lTTlX+Tgkw/0zhtgqN1TYBVeyLhmg==
X-Received: by 2002:a92:8b8b:: with SMTP id i133mr12386293ild.307.1583780665201;
        Mon, 09 Mar 2020 12:04:25 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9057:: with SMTP id v23ls1550411ioq.5.gmail; Mon, 09 Mar
 2020 12:04:24 -0700 (PDT)
X-Received: by 2002:a6b:e70e:: with SMTP id b14mr1965378ioh.1.1583780664847;
        Mon, 09 Mar 2020 12:04:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780664; cv=none;
        d=google.com; s=arc-20160816;
        b=RCXGFSrpuE1tC6SMDE//6GNOC5xfbLRdwcZ+b/Lpisjh55YuPBYRnTvphpU/aphQLX
         7KEk1AOl1us77YOU1NWNwoiTmteyzJR8XtPFwGMJj84MMrf2TgXxcQuvfLhf3pQT6O1h
         BskcnaxMQMOeYxVbJxDDKIucOj0CpM+j/J3RzjkROFMYrpoBiadcDk/JKTuQhXlC0fJ9
         SSk5QDsPXRRM4oASqsuUJXdBr6JVbamzby+FM74hR9EOs7cv293Hylasn+P7VcCeeuVS
         RSW2/pDythlfbO3YFJZKWD8PpNxzX7drZJfd0Gzxl+c22X+HnPORi13gsuvgPH1Lgw5G
         OO8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=+hkaLOIVc7xUSiPNDSPRb3iPWfaWnj1AuhUwWo4MHuc=;
        b=jAfUOukxmoDAj8EkT8xJ422Yr8rAs6gRgZuPf9hDG21wonwCcEworWfj0/X71M0+5H
         Baot5LaxbRxmQeVDNL8l6kDhbnvGF5Hw2htKLYG79GnUnwDA3kWlcnlcB6pE+4/Qs7c9
         m/r6Dzg12q0Z4PymjaGN+2kEVM4PCGIxvEckBJIOh7OtiVXQvsratXrZn536prMsGN3z
         42rslrugDJ1ajPCrrv3VPngB3UD/IN0LeAx7m0ZgEW0/akZhS3fNaerfCyP+KV+Z85IW
         c4zh907r3hwbH+MqGDUHTyMVuYWuh57T8qQYVVM5ryr1iVGvcHnNK1ytzPsalLcsMQ6T
         v4JQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="rV93/R6q";
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s201si243602ilc.0.2020.03.09.12.04.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 138AD22522;
	Mon,  9 Mar 2020 19:04:24 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 08/32] asm-generic, kcsan: Add KCSAN instrumentation for bitops
Date: Mon,  9 Mar 2020 12:03:56 -0700
Message-Id: <20200309190420.6100-8-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="rV93/R6q";       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
Content-Type: text/plain; charset="UTF-8"
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

From: Marco Elver <elver@google.com>

Add explicit KCSAN checks for bitops.

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Arnd Bergmann <arnd@arndb.de>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 include/asm-generic/bitops/instrumented-atomic.h     | 14 +++++++-------
 include/asm-generic/bitops/instrumented-lock.h       | 10 +++++-----
 include/asm-generic/bitops/instrumented-non-atomic.h | 16 ++++++++--------
 3 files changed, 20 insertions(+), 20 deletions(-)

diff --git a/include/asm-generic/bitops/instrumented-atomic.h b/include/asm-generic/bitops/instrumented-atomic.h
index 18ce3c9..fb2cb33 100644
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
index ec53fde..b9bec46 100644
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
index 95ff28d..20f788a 100644
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
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-8-paulmck%40kernel.org.
