Return-Path: <kasan-dev+bncBCYPXT7N6MFRBJNUQGJQMGQEG3UUFCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D5B0508FFD
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Apr 2022 21:08:23 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id o188-20020a2541c5000000b0064334935847sf2284854yba.16
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Apr 2022 12:08:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650481702; cv=pass;
        d=google.com; s=arc-20160816;
        b=LYJ95+JibShf9JSjnQGBj1WCvE92g69S/RFtoNtoO5LYIhWxnwm00C7ULtAHuoRzqj
         c0PPA2F7JKGQyLsO+8W4ekgAkuM9Vy5o9+PhRC6WSYiNKRMO/dGG0FagU18ccZaxtEM3
         mr7ZISbzzzN1PKFFE6blc+xbXtexE0kuIjYgWPOvRUCh6VY4VlCTOpOnLTi3/7VJbn3C
         8rciG4GWZSYoVhDI+Vw3mIPMbggzWZPRZcbGxgc4wNcKTYNxonc2AuuNm5Pk3gzqSz79
         0I9I5pXSAJlYL1PQuaLVOM8AkC3Coz9NJiXMS+TJMf8ONJWml9RdFm8YKliLHwZ2Bzy3
         UAAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=NaebiQpb7v4TCqnW3ihscfJPZ3+RvsooOG/GOWGDN7Q=;
        b=usHv/nkTppigB84Gb19zFHICvRYVDR5q+6z8nf9QVIPRdlgpG+gv17mqeQMuD2p5Uz
         d+EFw5Xh/nE1XhAng2GgFjdHn+EhEf4sXpj6GiLpC1jW0Uq/TWJ4+qojtU7qGZzYPJBj
         AfAkqgxtR3Ll2MxLyp63NuZG926/icvY7htSgGJSVf7jqs97HTxvS0ndmMRa9B+0Kwg7
         hzuZMvdZem1aPHte8ZHu9xPWPxJxJVTM6qvamSreGhV24kKP0pBD+iDF3hDq9eeUCeA8
         cb+VdLpm5iNtlZRwT5HQqI5Y0xZ+G/uiolEHqkH/aBLpztkmRL3TXaznYr02YC8+GtH5
         enZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=IDkxaISV;
       spf=pass (google.com: domain of jcmvbkbc@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=jcmvbkbc@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NaebiQpb7v4TCqnW3ihscfJPZ3+RvsooOG/GOWGDN7Q=;
        b=aqMyosIotWf46lbK2pDFTAJO+A/PD0iKsOds6LE0iLNew6OpPxKKlsxfMCyuI6itMV
         aOeaj//gTbT5dGnwdymuQpNiVjrHYzPgpIlFdQxSoy/nQHm/ODc9WV8LRIRm2hCYeIxt
         Mo7FZzDwNaenrLLE3qFUEISN37xbkwlecgYHvALxhkg1J9Cwmaj4O4tHufzgmJtJPG+h
         eiQ/xucDDI4Iz9IGO+QYGb1GcjfvO0Ploxa9BUUyh4tiBB/j/ebGQqYbXJWBOC2bHsm6
         /yGMmFfy1O9WM+uepZqc09CouTddqYgDGPWtZtnKJI+WLhSF+6X153w/iizkJeTowxA9
         GLwA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NaebiQpb7v4TCqnW3ihscfJPZ3+RvsooOG/GOWGDN7Q=;
        b=cPT2+A+YLXCbPE/J+gL58CqWp9288BCmWFAKArPX3xAE5ZNLxE5NqEanlCowkq1Tkg
         WL2au+IaHnsRKlabj3KF/16kJTS5BABi7rX5fBWdcffKJAN2Jat+Qm/twZz5+lnrWJDv
         DAVOxywDFTOwiFCNq6UDmQZe6a55ppPsO8CmivGq20d2NJlRA83CRIZr59GiBqmCLvKE
         ONfXt6goOiLwR8wzPWUKEtEzU7b6/6Dv8RzCKviU18CpJEgSlX26n5A4xbHqb2fz8PlD
         jfnfYOpfOVtD9S+6UM0fLaujX18W9ZRMOTTRB5sUB6nqs1Tto7CJKgQnqoprMS95TbQ1
         J6iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NaebiQpb7v4TCqnW3ihscfJPZ3+RvsooOG/GOWGDN7Q=;
        b=Z9fiXuC3mynrllA9dl5xWTYw/20iDaBCwXDFbahG/qwpbI+tGS/8H1P9MVy4apATFs
         sQJjpmbkSQANr68t4CUDjTCWXBXrmesGto0hokZiO7x4DlDMX/kSwyG6dUAeebaWEd8q
         fvwtGFNPhbOAc08r8JH6SCE0ZStts2B2ITqWB38sO/BA6RJ3sEi/nPfadpnTE8Z3O/ly
         sht41/DY65FzRoMMGGk38EKuEJwQ5Eoh+r7HEOTXv4PyR/1P870IwiMoykDNUD59iRf/
         7kRW6ABhj0Q68XSseIxgJXPdQfJSq4NPT2CYs2smUTWmbff5OxtZPTK5U7FOLqP4w7By
         r4/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533jPNYINcYFLtU0nRBx4fcStVjvpEbviH79bSJ0q61IA9Fnz1hi
	vrYiHuaGLKnb1NYqQsZoy70=
X-Google-Smtp-Source: ABdhPJyCjDfmbADW0wSDAS3iedUAQqLD+sOGe6+k7p59+SBM201qA5bzevBGv/ulbzBWB6OOUvkCBA==
X-Received: by 2002:a25:8a0e:0:b0:633:63de:4118 with SMTP id g14-20020a258a0e000000b0063363de4118mr20520785ybl.409.1650481702064;
        Wed, 20 Apr 2022 12:08:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:5683:0:b0:63e:7eb8:1a0d with SMTP id k125-20020a255683000000b0063e7eb81a0dls2497587ybb.7.gmail;
 Wed, 20 Apr 2022 12:08:21 -0700 (PDT)
X-Received: by 2002:a5b:8cf:0:b0:641:385d:7719 with SMTP id w15-20020a5b08cf000000b00641385d7719mr22717136ybq.444.1650481701483;
        Wed, 20 Apr 2022 12:08:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650481701; cv=none;
        d=google.com; s=arc-20160816;
        b=oOWui0m0keIZIs9WR3+Wmdv7zPWx8reuftHv3bdiNZpcbFppuApVpyEPIpx9/YXBou
         9gCCCXsdBTcug+DxBRZqwyx1FtOAWES9H06SuIIT7EYTfORabKP1oFkKIur1u+8cyuqZ
         Y8Y98Upy+pSj0NZ6uglbL/SaQjiBbXHNVAWGdiV8ORFmO9MDe6HhZO5T1gkCOSZo4Ct1
         Yr/LJZa8QQIP/1V3X9NegG/25x/vAPcTL3f9pvt/64teRZGzmGuE4JHPXf07Nq06eyjE
         /zRdy+/EusZbDkxSgWUXG5pmJz6DzD5l6U+qJ3gthnPitGqzqu+9XYHyfs4SOYRi+wKV
         hoXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=RadBw9TnGKHb+r+fDSXV2TygRfs0ByPhIe2F4r3TF0c=;
        b=ODIyrKzebMQKx1y1MKDmTa1+QXtnirKUhn395fin2P0fCGJGqiM5ixDjy2JGrF2f56
         ZlvZVjkRxCNEdaveLXgl1YtymfEXo2IT8/wvnlZEDt8LmKhpxFRcpL0lzv64pMENNn4S
         uqokHbzV4mW5JK+PA1SUk+NSxOXpn1jZCgWlzc2CHUORdsYn2XfcfToDCgdaXU6UHcdN
         49Lrpdie3P5yAz9apzO6qzehb1CraO9YHBZps2zsv7u0g0YAY/MFHSl44dGbDAugx/WZ
         8mxddy1tnxJ4mn5shwPe6HY7haUH001XLL3WC1L5y4+iFBgzXZljhUrjAHWeLknLTDEq
         01+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=IDkxaISV;
       spf=pass (google.com: domain of jcmvbkbc@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=jcmvbkbc@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x52b.google.com (mail-pg1-x52b.google.com. [2607:f8b0:4864:20::52b])
        by gmr-mx.google.com with ESMTPS id w189-20020a2549c6000000b00641ea7c6ddasi105719yba.1.2022.04.20.12.08.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Apr 2022 12:08:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of jcmvbkbc@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) client-ip=2607:f8b0:4864:20::52b;
Received: by mail-pg1-x52b.google.com with SMTP id t4so2508217pgc.1
        for <kasan-dev@googlegroups.com>; Wed, 20 Apr 2022 12:08:21 -0700 (PDT)
X-Received: by 2002:a63:8bc7:0:b0:3aa:7a8b:cf67 with SMTP id j190-20020a638bc7000000b003aa7a8bcf67mr2185090pge.402.1650481700643;
        Wed, 20 Apr 2022 12:08:20 -0700 (PDT)
Received: from octofox.hsd1.ca.comcast.net ([2601:641:401:1d20:daec:60d:88f6:798a])
        by smtp.gmail.com with ESMTPSA id u8-20020a62ed08000000b0050a90fd59d5sm8263004pfh.50.2022.04.20.12.08.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 20 Apr 2022 12:08:20 -0700 (PDT)
From: Max Filippov <jcmvbkbc@gmail.com>
To: linux-xtensa@linux-xtensa.org
Cc: Chris Zankel <chris@zankel.net>,
	linux-kernel@vger.kernel.org,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	Max Filippov <jcmvbkbc@gmail.com>
Subject: [PATCH v2] xtensa: enable KCSAN
Date: Wed, 20 Apr 2022 12:08:05 -0700
Message-Id: <20220420190805.152533-1-jcmvbkbc@gmail.com>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
X-Original-Sender: jcmvbkbc@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=IDkxaISV;       spf=pass
 (google.com: domain of jcmvbkbc@gmail.com designates 2607:f8b0:4864:20::52b
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
Changes v1->v2:

- fix __wmb definition to use __mb instead of mb
- provide __smp_{,r,w}mb definitions because definitions from the
  asm-generic use mb/rmb/wmb instead of __mb/__rmb/__wmb, thus
  doubling KCSAN instrumentation.

  Both changes fix a few failures in the KCSAN testsuite.

 arch/xtensa/Kconfig               |  1 +
 arch/xtensa/boot/lib/Makefile     |  1 +
 arch/xtensa/include/asm/barrier.h | 12 +++++--
 arch/xtensa/include/asm/bitops.h  | 10 +++---
 arch/xtensa/lib/Makefile          |  2 ++
 arch/xtensa/lib/kcsan-stubs.c     | 54 +++++++++++++++++++++++++++++++
 6 files changed, 73 insertions(+), 7 deletions(-)
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
index d6f8d4ddc2bc..898ea397e9bc 100644
--- a/arch/xtensa/include/asm/barrier.h
+++ b/arch/xtensa/include/asm/barrier.h
@@ -11,9 +11,15 @@
 
 #include <asm/core.h>
 
-#define mb()  ({ __asm__ __volatile__("memw" : : : "memory"); })
-#define rmb() barrier()
-#define wmb() mb()
+#define __mb()  ({ __asm__ __volatile__("memw" : : : "memory"); })
+#define __rmb() barrier()
+#define __wmb() __mb()
+
+#ifdef CONFIG_SMP
+#define __smp_mb() __mb()
+#define __smp_rmb() __rmb()
+#define __smp_wmb() __wmb()
+#endif
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220420190805.152533-1-jcmvbkbc%40gmail.com.
