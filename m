Return-Path: <kasan-dev+bncBD52JJ7JXILRBH4TQ6JQMGQEVBSJZFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id E317450AA9D
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 23:16:16 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id k25-20020a544699000000b002fa69ba89b6sf2728609oic.19
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 14:16:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650575775; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zn2WQ+w0yKt2jwyJEvmc3UvnM50G+vd7BypEZrHAPnm/NWq567P1CCp7x6Uumn7oDf
         QM63+LTK4pbXVgBH9iT8BM27ShUlGoQmgTvMa3W2z3Nyq3cWODT07U8ksUhrc1qlNTqt
         62uD8gsHfODKf1TSgVBLkDLQfGF70YesBY8XnW1rBoTAPDkg0QkIdX7AKZSW8W8F5m9F
         8bJYAktWLZ0fpPFvz72V0Z5TGp6jrdE/pASyNDEAdeLY87quFy1U9q+bEBkD2/85Pfl+
         tBhS6OGih22NuW0RQjM7uNlg9brAIp86u0cUtnrkah5e0AYif0lyk5cr7yUkyicnH3Ol
         k6Ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=MZugZIzmpYAistOjQHO653MRCpETYS6a8C5Kob0HgwY=;
        b=StIX15DNX/icv/yGYAsy11W5dwIIWSENGmnjkRhpB6BEdSeg44nwrEFmtXMFlirGGC
         waec4KOfx4W+SWGV6ESs1KS228f7YUrNJytN2kJQ4HH+2gCLhdZSUg3K2OMVqA+/qjZF
         wTwwuS1SUCA68NenGhVNBG572dyarjweVEDOMQF8+7ROMhgKXN0Lp2D69Mt0DsHAmDbm
         JqOR4EjdikevvliCYFnY6bsWi0tSPBrnOa8mDbSDy3KWOMbO+mZ1UNW0qmND58j++VZF
         IcZV4lTFSHZjEQCXd8Z5DnXPeSCpfyZ8I4IJ36rIcODNLGWTTPaZOAh6xeDE/nnaKY3H
         27nw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LBvXnMLK;
       spf=pass (google.com: domain of 3nslhygmkcdeczz3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3nslhYgMKCdECzz3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=MZugZIzmpYAistOjQHO653MRCpETYS6a8C5Kob0HgwY=;
        b=JHMpiJpGwIXUU6kl4gCPkDlJoGnhVTgtH7qrq+B++osU8su+NCFGKaXBSjq+j7dLTT
         iX9Lq5J8DbeehxQ/M2RMOAAzQrxMW8vOQ9o4NiJqt9nohwox1HfBoSfab4SDxaDnRL16
         f/cEddMDFz7DaB7+E2P1VfXbcbXt/OP+xvo1t6xisIj45b10bg3vkur5wxbCaKBlBOpH
         lpK4NGYr2BXWUwHS3QqP/l1jwUKjIgZIjM7ZvBdXDQXjqO8EPknDGRaG1+kaGCY7QgCK
         ths9VBf6GE234cWR3n3iO/BrLYpbHzSi483sUgNyzTiKZoSemhiVZ858kowNfVYRaTJu
         MaNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MZugZIzmpYAistOjQHO653MRCpETYS6a8C5Kob0HgwY=;
        b=DktkIg75Ru/iJDRLTIM0NsHZdYPkd4IKUByE6oiTXjV0o19O59Q3jMjx3Vn377AGfp
         /WUa7rtBWNULko0FlW8cgoRCegAlXdcRe9gSymnJR1RMmsjRgmHcqbUWn8VrNpI+iMaw
         ciAMOy1qXX6SJfTyPUdKG8lVBViLxz3Qmrh57OxTaigzJnywkGC/Ii+yEeNKslI81vhO
         SjLaRRVeDOYDRzWKYjGGw4HBukbBn0aelHnTrZ1mi9kqphdLnRfW2yJDM3LfG3dowdkV
         oJRSvHUmhmfGBKn7qTNC9plq1HcgWqA4foxyWu1UTvzz9qnZ9xw1CKhzTJjopW3TvcMJ
         sk2w==
X-Gm-Message-State: AOAM533Z1lOjO7sdPBtYI6bodpvwnzpBhJ4Q/jFlSkSJGZhTWMQrBfWo
	zQ6IZzzipn7ru91mR0O4KUE=
X-Google-Smtp-Source: ABdhPJzD730vwp76v3bd+jrWhUgVnFhV9n/iATn7ieqzjIiykP1R201eVFB/CA4EsIobIp2+h+wnSQ==
X-Received: by 2002:a05:6870:eaa0:b0:e6:358f:1fc5 with SMTP id s32-20020a056870eaa000b000e6358f1fc5mr4853669oap.110.1650575775346;
        Thu, 21 Apr 2022 14:16:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:8:b0:322:b0b1:bb with SMTP id u8-20020a056808000800b00322b0b100bbls3574761oic.1.gmail;
 Thu, 21 Apr 2022 14:16:15 -0700 (PDT)
X-Received: by 2002:a05:6808:1992:b0:322:ca0b:cce3 with SMTP id bj18-20020a056808199200b00322ca0bcce3mr779221oib.168.1650575774974;
        Thu, 21 Apr 2022 14:16:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650575774; cv=none;
        d=google.com; s=arc-20160816;
        b=VyO+cvg3K4YBTOAj0Xr3QctQUEVooC2msXq17m/v3DRP/Uh7CVxIMLHxZhi1x9OozE
         9aEDnXBv60uqKH2WJ9UKNqSMkamY2XbQ2cwarERdeLuQ819tHUBauGc+r8bVkFzxmC4v
         p7RxuQpX8ww86beRIJNBkaTL7/kvcjw5qOMINt8hFiUI+PbB9pIeE15q7DE98/2qMJA/
         ziuFv/RoW2O2cWWqHOML9ig5E7+FJWtyw+9OevJ7iWmksreJWdCCrhhTEK5LBl99t0qN
         7rl1QP52jchlCNTjBILEX/beYn3RXVp2kolAmchwAO6uSimXonvsGkv0HPWZ2WU3oKeo
         sVEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=03Z+idmGJ7XYtJB1gQOW/umO4Zo4sumIH09aShWkJ9I=;
        b=Id8Z812pk6JFjCy663Iq6PUbE8rSjr8ckoahcTR8+WZmzxgHKVvJjiT92UJ1FPKz+T
         6tmfrG8lZY1An4M+ka8cspIjTxlfSqDvIM544jeUg0Mgq27XlhYbCR3pnB9t4vrrf6EK
         eAINywdJ0kC9IwwLNB/UYowCNSkMzGFl7NkEiEoOStn96r3Ln8HBl77s64fzvazNzVtH
         sH7V324MM2v0FfB1ZyZBPEeYMra8B1WJ/q/elB3dn1VEvMQvRhEPU9HRFYZP0XkxMrZ2
         LoMe8nzEDqNmwTLGYJFy5is6VPBKzdm3feHOZh0RB7NMV1/jDNBFNRqczNAuytyr/j/d
         Kp+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LBvXnMLK;
       spf=pass (google.com: domain of 3nslhygmkcdeczz3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3nslhYgMKCdECzz3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id c3-20020a056871034300b000ddbc266799si521901oag.2.2022.04.21.14.16.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Apr 2022 14:16:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3nslhygmkcdeczz3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-2f4e28ae604so10783887b3.8
        for <kasan-dev@googlegroups.com>; Thu, 21 Apr 2022 14:16:14 -0700 (PDT)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2ce:200:38c6:db53:1479:afb0])
 (user=pcc job=sendgmr) by 2002:a81:650:0:b0:2f4:cc5b:c510 with SMTP id
 77-20020a810650000000b002f4cc5bc510mr1747612ywg.113.1650575774393; Thu, 21
 Apr 2022 14:16:14 -0700 (PDT)
Date: Thu, 21 Apr 2022 14:15:48 -0700
Message-Id: <20220421211549.3884453-1-pcc@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v2] mm: make minimum slab alignment a runtime property
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@gmail.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>
Cc: Peter Collingbourne <pcc@google.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, vbabka@suse.cz, penberg@kernel.org, 
	roman.gushchin@linux.dev, iamjoonsoo.kim@lge.com, rientjes@google.com, 
	Herbert Xu <herbert@gondor.apana.org.au>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Eric Biederman <ebiederm@xmission.com>, 
	Kees Cook <keescook@chromium.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=LBvXnMLK;       spf=pass
 (google.com: domain of 3nslhygmkcdeczz3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3nslhYgMKCdECzz3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

When CONFIG_KASAN_HW_TAGS is enabled we currently increase the minimum
slab alignment to 16. This happens even if MTE is not supported in
hardware or disabled via kasan=off, which creates an unnecessary
memory overhead in those cases. Eliminate this overhead by making
the minimum slab alignment a runtime property and only aligning to
16 if KASAN is enabled at runtime.

On a DragonBoard 845c (non-MTE hardware) with a kernel built with
CONFIG_KASAN_HW_TAGS, waiting for quiescence after a full Android
boot I see the following Slab measurements in /proc/meminfo (median
of 3 reboots):

Before: 169020 kB
After:  167304 kB

Link: https://linux-review.googlesource.com/id/I752e725179b43b144153f4b6f584ceb646473ead
Signed-off-by: Peter Collingbourne <pcc@google.com>
---
v2:
- use max instead of max_t in flat_stack_align()

 arch/arc/include/asm/cache.h        |  4 ++--
 arch/arm/include/asm/cache.h        |  2 +-
 arch/arm64/include/asm/cache.h      | 19 +++++++++++++------
 arch/microblaze/include/asm/page.h  |  2 +-
 arch/riscv/include/asm/cache.h      |  2 +-
 arch/sparc/include/asm/cache.h      |  2 +-
 arch/xtensa/include/asm/processor.h |  2 +-
 fs/binfmt_flat.c                    |  9 ++++++---
 include/crypto/hash.h               |  2 +-
 include/linux/slab.h                | 22 +++++++++++++++++-----
 mm/slab.c                           |  7 +++----
 mm/slab_common.c                    |  3 +--
 mm/slob.c                           |  6 +++---
 13 files changed, 51 insertions(+), 31 deletions(-)

diff --git a/arch/arc/include/asm/cache.h b/arch/arc/include/asm/cache.h
index f0f1fc5d62b6..b6a7763fd5d6 100644
--- a/arch/arc/include/asm/cache.h
+++ b/arch/arc/include/asm/cache.h
@@ -55,11 +55,11 @@
  * Make sure slab-allocated buffers are 64-bit aligned when atomic64_t uses
  * ARCv2 64-bit atomics (LLOCKD/SCONDD). This guarantess runtime 64-bit
  * alignment for any atomic64_t embedded in buffer.
- * Default ARCH_SLAB_MINALIGN is __alignof__(long long) which has a relaxed
+ * Default ARCH_SLAB_MIN_MINALIGN is __alignof__(long long) which has a relaxed
  * value of 4 (and not 8) in ARC ABI.
  */
 #if defined(CONFIG_ARC_HAS_LL64) && defined(CONFIG_ARC_HAS_LLSC)
-#define ARCH_SLAB_MINALIGN	8
+#define ARCH_SLAB_MIN_MINALIGN	8
 #endif
 
 extern int ioc_enable;
diff --git a/arch/arm/include/asm/cache.h b/arch/arm/include/asm/cache.h
index e3ea34558ada..3e1018bb9805 100644
--- a/arch/arm/include/asm/cache.h
+++ b/arch/arm/include/asm/cache.h
@@ -21,7 +21,7 @@
  * With EABI on ARMv5 and above we must have 64-bit aligned slab pointers.
  */
 #if defined(CONFIG_AEABI) && (__LINUX_ARM_ARCH__ >= 5)
-#define ARCH_SLAB_MINALIGN 8
+#define ARCH_SLAB_MIN_MINALIGN 8
 #endif
 
 #define __read_mostly __section(".data..read_mostly")
diff --git a/arch/arm64/include/asm/cache.h b/arch/arm64/include/asm/cache.h
index a074459f8f2f..38f171591c3f 100644
--- a/arch/arm64/include/asm/cache.h
+++ b/arch/arm64/include/asm/cache.h
@@ -6,6 +6,7 @@
 #define __ASM_CACHE_H
 
 #include <asm/cputype.h>
+#include <asm/mte-def.h>
 
 #define CTR_L1IP_SHIFT		14
 #define CTR_L1IP_MASK		3
@@ -49,15 +50,21 @@
  */
 #define ARCH_DMA_MINALIGN	(128)
 
-#ifdef CONFIG_KASAN_SW_TAGS
-#define ARCH_SLAB_MINALIGN	(1ULL << KASAN_SHADOW_SCALE_SHIFT)
-#elif defined(CONFIG_KASAN_HW_TAGS)
-#define ARCH_SLAB_MINALIGN	MTE_GRANULE_SIZE
-#endif
-
 #ifndef __ASSEMBLY__
 
 #include <linux/bitops.h>
+#include <linux/kasan-enabled.h>
+
+#ifdef CONFIG_KASAN_SW_TAGS
+#define ARCH_SLAB_MIN_MINALIGN	(1ULL << KASAN_SHADOW_SCALE_SHIFT)
+#elif defined(CONFIG_KASAN_HW_TAGS)
+static inline size_t arch_slab_minalign(void)
+{
+	return kasan_hw_tags_enabled() ? MTE_GRANULE_SIZE :
+					 __alignof__(unsigned long long);
+}
+#define arch_slab_minalign() arch_slab_minalign()
+#endif
 
 #define ICACHEF_ALIASING	0
 #define ICACHEF_VPIPT		1
diff --git a/arch/microblaze/include/asm/page.h b/arch/microblaze/include/asm/page.h
index 4b8b2fa78fc5..ccdbc1da3c3e 100644
--- a/arch/microblaze/include/asm/page.h
+++ b/arch/microblaze/include/asm/page.h
@@ -33,7 +33,7 @@
 /* MS be sure that SLAB allocates aligned objects */
 #define ARCH_DMA_MINALIGN	L1_CACHE_BYTES
 
-#define ARCH_SLAB_MINALIGN	L1_CACHE_BYTES
+#define ARCH_SLAB_MIN_MINALIGN	L1_CACHE_BYTES
 
 /*
  * PAGE_OFFSET -- the first address of the first page of memory. With MMU
diff --git a/arch/riscv/include/asm/cache.h b/arch/riscv/include/asm/cache.h
index 9b58b104559e..7beb3b5d27c7 100644
--- a/arch/riscv/include/asm/cache.h
+++ b/arch/riscv/include/asm/cache.h
@@ -16,7 +16,7 @@
  * the flat loader aligns it accordingly.
  */
 #ifndef CONFIG_MMU
-#define ARCH_SLAB_MINALIGN	16
+#define ARCH_SLAB_MIN_MINALIGN	16
 #endif
 
 #endif /* _ASM_RISCV_CACHE_H */
diff --git a/arch/sparc/include/asm/cache.h b/arch/sparc/include/asm/cache.h
index e62fd0e72606..9d8cb4687b7e 100644
--- a/arch/sparc/include/asm/cache.h
+++ b/arch/sparc/include/asm/cache.h
@@ -8,7 +8,7 @@
 #ifndef _SPARC_CACHE_H
 #define _SPARC_CACHE_H
 
-#define ARCH_SLAB_MINALIGN	__alignof__(unsigned long long)
+#define ARCH_SLAB_MIN_MINALIGN	__alignof__(unsigned long long)
 
 #define L1_CACHE_SHIFT 5
 #define L1_CACHE_BYTES 32
diff --git a/arch/xtensa/include/asm/processor.h b/arch/xtensa/include/asm/processor.h
index 4489a27d527a..e3ea278e3fcf 100644
--- a/arch/xtensa/include/asm/processor.h
+++ b/arch/xtensa/include/asm/processor.h
@@ -18,7 +18,7 @@
 #include <asm/types.h>
 #include <asm/regs.h>
 
-#define ARCH_SLAB_MINALIGN XTENSA_STACK_ALIGNMENT
+#define ARCH_SLAB_MIN_MINALIGN XTENSA_STACK_ALIGNMENT
 
 /*
  * User space process size: 1 GB.
diff --git a/fs/binfmt_flat.c b/fs/binfmt_flat.c
index 626898150011..23ce3439eafa 100644
--- a/fs/binfmt_flat.c
+++ b/fs/binfmt_flat.c
@@ -64,7 +64,10 @@
  * Here we can be a bit looser than the data sections since this
  * needs to only meet arch ABI requirements.
  */
-#define FLAT_STACK_ALIGN	max_t(unsigned long, sizeof(void *), ARCH_SLAB_MINALIGN)
+static size_t flat_stack_align(void)
+{
+	return max(sizeof(void *), arch_slab_minalign());
+}
 
 #define RELOC_FAILED 0xff00ff01		/* Relocation incorrect somewhere */
 #define UNLOADED_LIB 0x7ff000ff		/* Placeholder for unused library */
@@ -148,7 +151,7 @@ static int create_flat_tables(struct linux_binprm *bprm, unsigned long arg_start
 		sp -= 2; /* argvp + envp */
 	sp -= 1;  /* &argc */
 
-	current->mm->start_stack = (unsigned long)sp & -FLAT_STACK_ALIGN;
+	current->mm->start_stack = (unsigned long)sp & -flat_stack_align();
 	sp = (unsigned long __user *)current->mm->start_stack;
 
 	if (put_user(bprm->argc, sp++))
@@ -966,7 +969,7 @@ static int load_flat_binary(struct linux_binprm *bprm)
 #endif
 	stack_len += (bprm->argc + 1) * sizeof(char *);   /* the argv array */
 	stack_len += (bprm->envc + 1) * sizeof(char *);   /* the envp array */
-	stack_len = ALIGN(stack_len, FLAT_STACK_ALIGN);
+	stack_len = ALIGN(stack_len, flat_stack_align());
 
 	res = load_flat_file(bprm, &libinfo, 0, &stack_len);
 	if (res < 0)
diff --git a/include/crypto/hash.h b/include/crypto/hash.h
index f140e4643949..442c290f458c 100644
--- a/include/crypto/hash.h
+++ b/include/crypto/hash.h
@@ -149,7 +149,7 @@ struct ahash_alg {
 
 struct shash_desc {
 	struct crypto_shash *tfm;
-	void *__ctx[] __aligned(ARCH_SLAB_MINALIGN);
+	void *__ctx[] __aligned(ARCH_SLAB_MIN_MINALIGN);
 };
 
 #define HASH_MAX_DIGESTSIZE	 64
diff --git a/include/linux/slab.h b/include/linux/slab.h
index 373b3ef99f4e..80e517593372 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -201,21 +201,33 @@ void kmem_dump_obj(void *object);
 #endif
 
 /*
- * Setting ARCH_SLAB_MINALIGN in arch headers allows a different alignment.
+ * Setting ARCH_SLAB_MIN_MINALIGN in arch headers allows a different alignment.
  * Intended for arches that get misalignment faults even for 64 bit integer
  * aligned buffers.
  */
-#ifndef ARCH_SLAB_MINALIGN
-#define ARCH_SLAB_MINALIGN __alignof__(unsigned long long)
+#ifndef ARCH_SLAB_MIN_MINALIGN
+#define ARCH_SLAB_MIN_MINALIGN __alignof__(unsigned long long)
+#endif
+
+/*
+ * Arches can define this function if they want to decide the minimum slab
+ * alignment at runtime. The value returned by the function must be
+ * >= ARCH_SLAB_MIN_MINALIGN.
+ */
+#ifndef arch_slab_minalign
+static inline size_t arch_slab_minalign(void)
+{
+	return ARCH_SLAB_MIN_MINALIGN;
+}
 #endif
 
 /*
  * kmalloc and friends return ARCH_KMALLOC_MINALIGN aligned
- * pointers. kmem_cache_alloc and friends return ARCH_SLAB_MINALIGN
+ * pointers. kmem_cache_alloc and friends return ARCH_SLAB_MIN_MINALIGN
  * aligned pointers.
  */
 #define __assume_kmalloc_alignment __assume_aligned(ARCH_KMALLOC_MINALIGN)
-#define __assume_slab_alignment __assume_aligned(ARCH_SLAB_MINALIGN)
+#define __assume_slab_alignment __assume_aligned(ARCH_SLAB_MIN_MINALIGN)
 #define __assume_page_alignment __assume_aligned(PAGE_SIZE)
 
 /*
diff --git a/mm/slab.c b/mm/slab.c
index 0edb474edef1..97b756976c8b 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -3009,10 +3009,9 @@ static void *cache_alloc_debugcheck_after(struct kmem_cache *cachep,
 	objp += obj_offset(cachep);
 	if (cachep->ctor && cachep->flags & SLAB_POISON)
 		cachep->ctor(objp);
-	if (ARCH_SLAB_MINALIGN &&
-	    ((unsigned long)objp & (ARCH_SLAB_MINALIGN-1))) {
-		pr_err("0x%px: not aligned to ARCH_SLAB_MINALIGN=%d\n",
-		       objp, (int)ARCH_SLAB_MINALIGN);
+	if ((unsigned long)objp & (arch_slab_minalign() - 1)) {
+		pr_err("0x%px: not aligned to arch_slab_minalign()=%d\n", objp,
+		       (int)arch_slab_minalign());
 	}
 	return objp;
 }
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 2b3206a2c3b5..33cc49810a54 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -154,8 +154,7 @@ static unsigned int calculate_alignment(slab_flags_t flags,
 		align = max(align, ralign);
 	}
 
-	if (align < ARCH_SLAB_MINALIGN)
-		align = ARCH_SLAB_MINALIGN;
+	align = max_t(size_t, align, arch_slab_minalign());
 
 	return ALIGN(align, sizeof(void *));
 }
diff --git a/mm/slob.c b/mm/slob.c
index 40ea6e2d4ccd..3bd2669bd690 100644
--- a/mm/slob.c
+++ b/mm/slob.c
@@ -478,7 +478,7 @@ static __always_inline void *
 __do_kmalloc_node(size_t size, gfp_t gfp, int node, unsigned long caller)
 {
 	unsigned int *m;
-	int minalign = max_t(size_t, ARCH_KMALLOC_MINALIGN, ARCH_SLAB_MINALIGN);
+	int minalign = max_t(size_t, ARCH_KMALLOC_MINALIGN, arch_slab_minalign());
 	void *ret;
 
 	gfp &= gfp_allowed_mask;
@@ -555,7 +555,7 @@ void kfree(const void *block)
 
 	sp = virt_to_folio(block);
 	if (folio_test_slab(sp)) {
-		int align = max_t(size_t, ARCH_KMALLOC_MINALIGN, ARCH_SLAB_MINALIGN);
+		int align = max_t(size_t, ARCH_KMALLOC_MINALIGN, arch_slab_minalign());
 		unsigned int *m = (unsigned int *)(block - align);
 		slob_free(m, *m + align);
 	} else {
@@ -584,7 +584,7 @@ size_t __ksize(const void *block)
 	if (unlikely(!folio_test_slab(folio)))
 		return folio_size(folio);
 
-	align = max_t(size_t, ARCH_KMALLOC_MINALIGN, ARCH_SLAB_MINALIGN);
+	align = max_t(size_t, ARCH_KMALLOC_MINALIGN, arch_slab_minalign());
 	m = (unsigned int *)(block - align);
 	return SLOB_UNITS(*m) * SLOB_UNIT;
 }
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220421211549.3884453-1-pcc%40google.com.
