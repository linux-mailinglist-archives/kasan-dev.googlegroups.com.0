Return-Path: <kasan-dev+bncBCYPXT7N6MFRBU7V5GJAMGQE6UYLLTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id B0DD950351A
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Apr 2022 10:14:12 +0200 (CEST)
Received: by mail-ua1-x938.google.com with SMTP id m23-20020ab073d7000000b0035d2f93e362sf4388512uaq.8
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Apr 2022 01:14:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650096851; cv=pass;
        d=google.com; s=arc-20160816;
        b=HwK5efXTuObpoDp4plZAXZrPfv0aghDgHb3C+pN8BHGEoZwK6XBbGqCbdcviucIeQM
         PBOciQFx+Wgo36YCfUW9xl2zU/0cHprsyIxDdM+2O2mwHogTaTwuZCZoyX2bVwrDaYva
         GuOPM9C5zN/Hk2kzjPPcFuTaH50oAOgLpC/tN6STOJ3xDATdtZAgJ6bP6KoStOHffisN
         wnIjFRo+0fHLW3mAsyTm1dGEdeII3Ds1ozGzp/uxFEJ2oyrc3RgDQa+WOLiqpbNj3eQx
         Qp0dknh+rdMhmmxfigkBXKPbF3HLQ8fGBRD0+M8nqmRy6G+85PiVmXTfmpXW6fcPmawI
         HzFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=CvD0oIYBha60S9Af3XW6p4YnfINPQJQe9y6k4v2Yw1A=;
        b=ktnHnq3QmKU7H7mnEO/9Rnals/RlWremYVisB+uG1NAKk995TS101h/m0EZfR0UbjJ
         PYdicOc5eNPfndsB3bSO4NRnKHbFFrb1dumX5D2JrTYqGfikNaLpdnHc+3VIzNqMkR6n
         MKPzunS1RYFL6yp8Yac0MjhEGoe9+cQrdEzAJ8aSvxWZCWOV9mJGlQil8WLJYk6y/rLS
         NMDfWmpjy2+xJBMmISa7K6QmCMJw1AoI/tLuroMrBnQH8RD6PI40vWxhM9ZiuTGzJi84
         SUXDSfp9hvhE6wjd1eSdBbuvWI+CRDBFOaFKGO6+9iJr6aCkt308xFSB7WDOO/ar64tv
         iuZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Rlap9suI;
       spf=pass (google.com: domain of jcmvbkbc@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=jcmvbkbc@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CvD0oIYBha60S9Af3XW6p4YnfINPQJQe9y6k4v2Yw1A=;
        b=bjv8iM6sEVKmnxFuR00B/LIVJqYMd5pFGhHC+CxEo5SPeScmfsjWsd1Kexk7JWeUCk
         fMpVP5Wszb0l/uFsDa2RiweP0U0WbD8pq4LE3XruzE0L1aSBmcFWI/GhQlVgFrQRhN+G
         x5jyLuA1csjBYr4RoLQ7tOm95L2WLZZzHEe9QR3stLBg0m6XiRB2PGGBlepEZ4iiM6DV
         lQVm9MVBd/FuvrPXrGaiq/BQfb+sG6rsUa5hKx4AGxFpJdeUuS23fqFKyIiYw7mkR2UC
         /o4Late3q2Bmc7nLnT/rZr8ZnEBOZrLHrg9vtJT+cZKzqmpJhi36s4/nQgs+HV2zRqJ4
         5Iqw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CvD0oIYBha60S9Af3XW6p4YnfINPQJQe9y6k4v2Yw1A=;
        b=ToPJ64mwkU+uMRzTQHxwSFAnwWv6ghgll6+8dgXE5aKoqbqg//ETgpiVwe6fYnUeO1
         MoQ9eIacLjnoqhartk0kv84arc7Oi7bOKFLcW8ViQ8/ff36yxNoIRxhL4i/M6qWuLwpj
         qH2mOLD6WosYthk378tfS9xusL7Lu5eM2jF+sIqNaNvacLlpbMYi6YA1Nu7WqXrrmuW9
         yMuV+aZu6n779ngLpJ0nuMhq9Dd2V059WgZsVO9xpq3at1yWyQRcZejs3VzMt0s2A2QX
         JOZolcGPL4guVRcb/StmbXZG+ACRMBS4IIWESXLZm1AiA2orlh0/UMrFli6TQCeEpdkd
         EIYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CvD0oIYBha60S9Af3XW6p4YnfINPQJQe9y6k4v2Yw1A=;
        b=rxqG1GsdjuVbchrmLfuFSPGZBokxCg13xtuC8NHvM2XbK6pPeBdJUI5ouCJ2rAVMQ5
         Nzchm22eWq87TPgIn+GL5R/XdFO8baiIICsKASPXG0133w77PN9tYS3lo+UyvAwUwtrZ
         XRwYuu/YaNWoYlMje8s8MylhwA20geF4C+U53GDuHFz7s2EoPbCyOW7PQb9JiwZEZvKH
         MSa0JGutZfzVqmaXLP5lK+/NO3MGhCjYcbM/3hg2w65Wam2FbhqvaDaQ4Up+uNaQERPD
         HZVFV+A6MulGbJ3nVLCEhYChyQQ1q/C4aEUyntYh+tXr4e9LxRC8LDUsuhp/NdtnA7ST
         G0tw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530LJKD15dUkT/ren2sa1nYC6MA7SPim2QA6LCwfI4PmXkCjylSc
	QAPO7z34VJKg50rMwG9pdz0=
X-Google-Smtp-Source: ABdhPJxb0P3YI68LnWYDg8vQLtc8SyWc6+vaDMPKDCtU1FmiFygU6SNwuSFjrj3LpPbGnEBPeyw5Ow==
X-Received: by 2002:a67:f842:0:b0:32a:492e:332e with SMTP id b2-20020a67f842000000b0032a492e332emr212308vsp.47.1650096851413;
        Sat, 16 Apr 2022 01:14:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:244:b0:32a:4a4b:4eb3 with SMTP id
 a4-20020a056102024400b0032a4a4b4eb3ls124991vsq.1.gmail; Sat, 16 Apr 2022
 01:14:11 -0700 (PDT)
X-Received: by 2002:a67:fd0b:0:b0:31b:e36d:31b1 with SMTP id f11-20020a67fd0b000000b0031be36d31b1mr775886vsr.44.1650096850961;
        Sat, 16 Apr 2022 01:14:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650096850; cv=none;
        d=google.com; s=arc-20160816;
        b=BuUv88ipQxR5JEDDFzWzZS20xu2jQfTYZwoa7dRqS9Gif7nk9HQhKOAjYJOHWSMr7v
         a8AdnSJOL7wvJeDTmTR4Ui0uP9K9bcJEvieep+JqG3+3aKofaNk3VqoC5jPTE3EwDV1o
         PSpTtTP6BM02TUmapGi5LP8qAnkEr9f+MiOyzvn23lwyH1jB3dkvSYu2HyysuJTU5bmc
         uTx0TkWrzsJJgNhsJwyv55TWVlL78BGOH3hvJStKYb3OEvA2L2eZXMrG6YTsKrYClGvT
         ubPybuA/iz+us1vVEqOjgKuDw428NA+FwHxuc1ggAG8WVymfyD2/k9s4lxfSZMjcp030
         l8kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Q0bDlxsxRT7vU+fHQb3K3oqWDHlvOU9rQoKkjc4MdmI=;
        b=bPY1Yk2Jx7p3z/eMcNMroaPxoJxvHo5xk/8ki1KtSWE+ZZBGubTuJLB8nQa6tcbFmP
         C/5bWGWbo6dij9Aac3n2knXRwz1iqi6f23MUe982GUqOn53tWO4PTRdyi/5i3G+wlOzX
         27wJGonhViDVnpRfQ3vTPWc8hzT9xrBxdwG4/w5waSxfdN7NY6kSKtoMnspsPF8vs6NO
         AttereZDbUneJbOqVJQNwiFabMEnHFnt0ytmZONYOUeD7MCQdNSRPKYbcLTM4FCYoCZM
         9uVExy5gEi760WIj+Lj+1RYGK8/KvclfbzHScihdXb/c2AWlboVnifG4vW91oDQgppW7
         xmSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Rlap9suI;
       spf=pass (google.com: domain of jcmvbkbc@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=jcmvbkbc@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1035.google.com (mail-pj1-x1035.google.com. [2607:f8b0:4864:20::1035])
        by gmr-mx.google.com with ESMTPS id y16-20020ac5cf10000000b003490e9e14c9si345300vke.2.2022.04.16.01.14.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 16 Apr 2022 01:14:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of jcmvbkbc@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) client-ip=2607:f8b0:4864:20::1035;
Received: by mail-pj1-x1035.google.com with SMTP id mp16-20020a17090b191000b001cb5efbcab6so13370116pjb.4
        for <kasan-dev@googlegroups.com>; Sat, 16 Apr 2022 01:14:10 -0700 (PDT)
X-Received: by 2002:a17:90a:1c08:b0:1cd:474a:a4f8 with SMTP id s8-20020a17090a1c0800b001cd474aa4f8mr2810056pjs.82.1650096850114;
        Sat, 16 Apr 2022 01:14:10 -0700 (PDT)
Received: from octofox.hsd1.ca.comcast.net ([2601:641:401:1d20:9b6:6aad:72f6:6e16])
        by smtp.gmail.com with ESMTPSA id oa16-20020a17090b1bd000b001c72b632222sm11527623pjb.32.2022.04.16.01.14.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 16 Apr 2022 01:14:09 -0700 (PDT)
From: Max Filippov <jcmvbkbc@gmail.com>
To: linux-xtensa@linux-xtensa.org
Cc: Chris Zankel <chris@zankel.net>,
	linux-kernel@vger.kernel.org,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	Max Filippov <jcmvbkbc@gmail.com>
Subject: [PATCH] xtensa: enable KCSAN
Date: Sat, 16 Apr 2022 01:13:55 -0700
Message-Id: <20220416081355.2155050-1-jcmvbkbc@gmail.com>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
X-Original-Sender: jcmvbkbc@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Rlap9suI;       spf=pass
 (google.com: domain of jcmvbkbc@gmail.com designates 2607:f8b0:4864:20::1035
 as permitted sender) smtp.mailfrom=jcmvbkbc@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Prefix arch-specific barrier macros with '__' to make use of instrumented
generic macros.
Prefix arch-specific bitops with 'arch_' to make use of instrumented
generic functions.
Provide stubs for 64-bit atomics when building with KCSAN.
Disable KCSAN instrumentation in arch/xtensa/boot.

Signed-off-by: Max Filippov <jcmvbkbc@gmail.com>
---
 arch/xtensa/Kconfig               |  1 +
 arch/xtensa/boot/lib/Makefile     |  1 +
 arch/xtensa/include/asm/barrier.h |  6 ++--
 arch/xtensa/include/asm/bitops.h  | 10 +++---
 arch/xtensa/lib/Makefile          |  2 ++
 arch/xtensa/lib/kcsan-stubs.c     | 54 +++++++++++++++++++++++++++++++
 6 files changed, 67 insertions(+), 7 deletions(-)
 create mode 100644 arch/xtensa/lib/kcsan-stubs.c

diff --git a/arch/xtensa/Kconfig b/arch/xtensa/Kconfig
index 797355c142b3..c87f5ab493d9 100644
--- a/arch/xtensa/Kconfig
+++ b/arch/xtensa/Kconfig
@@ -29,6 +29,7 @@ config XTENSA
 	select HAVE_ARCH_AUDITSYSCALL
 	select HAVE_ARCH_JUMP_LABEL if !XIP_KERNEL
 	select HAVE_ARCH_KASAN if MMU && !XIP_KERNEL
+	select HAVE_ARCH_KCSAN
 	select HAVE_ARCH_SECCOMP_FILTER
 	select HAVE_ARCH_TRACEHOOK
 	select HAVE_CONTEXT_TRACKING
diff --git a/arch/xtensa/boot/lib/Makefile b/arch/xtensa/boot/lib/Makefile
index e3d717c7bfa1..162d10af36f3 100644
--- a/arch/xtensa/boot/lib/Makefile
+++ b/arch/xtensa/boot/lib/Makefile
@@ -16,6 +16,7 @@ CFLAGS_REMOVE_inffast.o = -pg
 endif
 
 KASAN_SANITIZE := n
+KCSAN_SANITIZE := n
 
 CFLAGS_REMOVE_inflate.o += -fstack-protector -fstack-protector-strong
 CFLAGS_REMOVE_zmem.o += -fstack-protector -fstack-protector-strong
diff --git a/arch/xtensa/include/asm/barrier.h b/arch/xtensa/include/asm/barrier.h
index d6f8d4ddc2bc..a22d4bb08159 100644
--- a/arch/xtensa/include/asm/barrier.h
+++ b/arch/xtensa/include/asm/barrier.h
@@ -11,9 +11,9 @@
 
 #include <asm/core.h>
 
-#define mb()  ({ __asm__ __volatile__("memw" : : : "memory"); })
-#define rmb() barrier()
-#define wmb() mb()
+#define __mb()  ({ __asm__ __volatile__("memw" : : : "memory"); })
+#define __rmb() barrier()
+#define __wmb() mb()
 
 #if XCHAL_HAVE_S32C1I
 #define __smp_mb__before_atomic()		barrier()
diff --git a/arch/xtensa/include/asm/bitops.h b/arch/xtensa/include/asm/bitops.h
index cd225896c40f..e02ec5833389 100644
--- a/arch/xtensa/include/asm/bitops.h
+++ b/arch/xtensa/include/asm/bitops.h
@@ -99,7 +99,7 @@ static inline unsigned long __fls(unsigned long word)
 #if XCHAL_HAVE_EXCLUSIVE
 
 #define BIT_OP(op, insn, inv)						\
-static inline void op##_bit(unsigned int bit, volatile unsigned long *p)\
+static inline void arch_##op##_bit(unsigned int bit, volatile unsigned long *p)\
 {									\
 	unsigned long tmp;						\
 	unsigned long mask = 1UL << (bit & 31);				\
@@ -119,7 +119,7 @@ static inline void op##_bit(unsigned int bit, volatile unsigned long *p)\
 
 #define TEST_AND_BIT_OP(op, insn, inv)					\
 static inline int							\
-test_and_##op##_bit(unsigned int bit, volatile unsigned long *p)	\
+arch_test_and_##op##_bit(unsigned int bit, volatile unsigned long *p)	\
 {									\
 	unsigned long tmp, value;					\
 	unsigned long mask = 1UL << (bit & 31);				\
@@ -142,7 +142,7 @@ test_and_##op##_bit(unsigned int bit, volatile unsigned long *p)	\
 #elif XCHAL_HAVE_S32C1I
 
 #define BIT_OP(op, insn, inv)						\
-static inline void op##_bit(unsigned int bit, volatile unsigned long *p)\
+static inline void arch_##op##_bit(unsigned int bit, volatile unsigned long *p)\
 {									\
 	unsigned long tmp, value;					\
 	unsigned long mask = 1UL << (bit & 31);				\
@@ -163,7 +163,7 @@ static inline void op##_bit(unsigned int bit, volatile unsigned long *p)\
 
 #define TEST_AND_BIT_OP(op, insn, inv)					\
 static inline int							\
-test_and_##op##_bit(unsigned int bit, volatile unsigned long *p)	\
+arch_test_and_##op##_bit(unsigned int bit, volatile unsigned long *p)	\
 {									\
 	unsigned long tmp, value;					\
 	unsigned long mask = 1UL << (bit & 31);				\
@@ -205,6 +205,8 @@ BIT_OPS(change, "xor", )
 #undef BIT_OP
 #undef TEST_AND_BIT_OP
 
+#include <asm-generic/bitops/instrumented-atomic.h>
+
 #include <asm-generic/bitops/le.h>
 
 #include <asm-generic/bitops/ext2-atomic-setbit.h>
diff --git a/arch/xtensa/lib/Makefile b/arch/xtensa/lib/Makefile
index 5848c133f7ea..d4e9c397e3fd 100644
--- a/arch/xtensa/lib/Makefile
+++ b/arch/xtensa/lib/Makefile
@@ -8,3 +8,5 @@ lib-y	+= memcopy.o memset.o checksum.o \
 	   divsi3.o udivsi3.o modsi3.o umodsi3.o mulsi3.o \
 	   usercopy.o strncpy_user.o strnlen_user.o
 lib-$(CONFIG_PCI) += pci-auto.o
+lib-$(CONFIG_KCSAN) += kcsan-stubs.o
+KCSAN_SANITIZE_kcsan-stubs.o := n
diff --git a/arch/xtensa/lib/kcsan-stubs.c b/arch/xtensa/lib/kcsan-stubs.c
new file mode 100644
index 000000000000..2b08faa62b86
--- /dev/null
+++ b/arch/xtensa/lib/kcsan-stubs.c
@@ -0,0 +1,54 @@
+// SPDX-License-Identifier: GPL-2.0
+
+#include <linux/bug.h>
+#include <linux/types.h>
+
+void __atomic_store_8(volatile void *p, u64 v, int i)
+{
+	BUG();
+}
+
+u64 __atomic_load_8(const volatile void *p, int i)
+{
+	BUG();
+}
+
+u64 __atomic_exchange_8(volatile void *p, u64 v, int i)
+{
+	BUG();
+}
+
+bool __atomic_compare_exchange_8(volatile void *p1, void *p2, u64 v, bool b, int i1, int i2)
+{
+	BUG();
+}
+
+u64 __atomic_fetch_add_8(volatile void *p, u64 v, int i)
+{
+	BUG();
+}
+
+u64 __atomic_fetch_sub_8(volatile void *p, u64 v, int i)
+{
+	BUG();
+}
+
+u64 __atomic_fetch_and_8(volatile void *p, u64 v, int i)
+{
+	BUG();
+}
+
+u64 __atomic_fetch_or_8(volatile void *p, u64 v, int i)
+{
+	BUG();
+}
+
+u64 __atomic_fetch_xor_8(volatile void *p, u64 v, int i)
+{
+	BUG();
+}
+
+u64 __atomic_fetch_nand_8(volatile void *p, u64 v, int i)
+{
+	BUG();
+}
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220416081355.2155050-1-jcmvbkbc%40gmail.com.
