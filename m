Return-Path: <kasan-dev+bncBC6OLHHDVUOBBMNDXOKAMGQE2MMXG3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 254C55347C0
	for <lists+kasan-dev@lfdr.de>; Thu, 26 May 2022 03:02:44 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id nv16-20020a17090b1b5000b001df2567933esf2211116pjb.4
        for <lists+kasan-dev@lfdr.de>; Wed, 25 May 2022 18:02:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653526962; cv=pass;
        d=google.com; s=arc-20160816;
        b=dhCJtYeTuaHjEN3ERKa00u5R7coUckNx1EqeMVXlIOkBnFN2IvMyFqLVKrcAdDEtkV
         QSF4YsFDR1fprL6GHScLS8NZ4alLzg7h6SQVpW53tueoK+vka74dSwsRP6JDNVgwJwKK
         MXw17A0NymdxCeVZU3z9UgNwQ3Lla7/abvwTWg+Cx/P8vLyehJsp1M10LFFofJNk9RGB
         nl+QxJzwECBVeFVmusyz0R9U5xBiiluMUa23ugzRSiPKq3MCk5GJWyQmdBRSPPZ3VQFe
         ZWSPYp3u3j5abtCb5ZhFpuShJYggHs4Bn/YpqDEpFXl9cKnT5Yg/O+d2/4BBrDLeRn4N
         mG9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=h8Ft3hyZ3uzrWCE9GDKDtC7z3Gwzn/Rb3x0wTJPpaEA=;
        b=bLEFstLU1UNFiiw63POIqca6UP1SfryLx5awrVl4hqn8k6vudvWyhM5JxRVQ6u8Fnq
         h/HX5OfFRcOgmi83sp8uA2WcWVfMzsAxhVlff0mKJ2QAlpAJS+uRF0fHFCdnAktfABDe
         73AF37Pj6IGIcX7Vl8d+4UGt/HfePBxO3ORv2yR/mFxbc/wP/6jusnm8rVm/uM0T4djE
         XuAEqVTD20QfEGn2s8NeTj/ONHArltViTfXEuX0G2cAHJM/5EQK1knnEurrgYIjmy24e
         5l+PsCen4z6I1uVyk/ePJTmA/TFouj2KwSmeTmFo6aF5BwQlpDcXE9h/4nJlHHskufr6
         /IIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=D4OFEhQ+;
       spf=pass (google.com: domain of 3sngoyggkcakmjermpxfpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3sNGOYggKCakMJeRMPXfPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h8Ft3hyZ3uzrWCE9GDKDtC7z3Gwzn/Rb3x0wTJPpaEA=;
        b=knMPFvSpmWyeLYrKARd8a6w2E4N0cg/X3r8o0euOu8/9O3TBPJXfDYSc7DMmR2YRVs
         mwuZ41anmKQrnnWvbmOeJxgCzmsCpfVq2nJOvtUK3HV9/uXSaXkYBS9OHtgbqXoTzyex
         6WMRVmFA01a/G/U06peHcH25KUvuUe9dqFcxdZEIr/hYVjfOYCVQD5zkP6r532IrZkiu
         CKYg49uheZlXDQBpFRunkSup3gubrviSBzNmKgbC4d1Tg8l9n/jH9THqZDq+SKI/jjjn
         FG3TwGvpDO/KKQtqrrOVQW/Gl0b7/kqJhc3SrFA2T8spdIVDjBvuV4FgrjPC95C8sCPW
         X9bQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h8Ft3hyZ3uzrWCE9GDKDtC7z3Gwzn/Rb3x0wTJPpaEA=;
        b=ALag7bDHgFsdnBnz4a7ubNGKtpSPCL87BwhxJduVvzxJ+EB70UzEEwy+Z89xg8MWtR
         Wc5ctbgVnFgp/XjBqxypfAbpuhzd4O3XpPYBT6Vlf3E1Y3dQNlbzZb9tm4QSzV88q7X2
         +ccl+YS+bR6sVtHZTTQbBufECI9DfZorbhrSNnxMrJ6YUNiRPh7+mpjo3ezZI8wmziG/
         9b0KpN8qNGW0NYbN5X99AsBs81TZqRsITl39C0psh49RyWMVpFWq9qyuWlZpBmIfcGUs
         NWQhjJaPITHXJWb7CidMGalcegRJP0nlXg/a0MJOfBf9Vu6YrCdsZ8l8NlOnmp9i9EU2
         OjRQ==
X-Gm-Message-State: AOAM530ZjzR06OgcIcnNnH3Zk7uVlzgBww2cml9pwXgQSjrm24fvdsFE
	gVT/5oAvZRZGVDX5geYZP04=
X-Google-Smtp-Source: ABdhPJwnn0oAT2FDzsLUtFqXStqsKrcxwiKr9goC1qFv4+PWcJ0JiD78hjk9rf2KslBtcHIIj203DQ==
X-Received: by 2002:a17:903:124a:b0:154:c7a4:9374 with SMTP id u10-20020a170903124a00b00154c7a49374mr35775919plh.68.1653526962088;
        Wed, 25 May 2022 18:02:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:d414:0:b0:3fa:e8ff:849b with SMTP id a20-20020a63d414000000b003fae8ff849bls1122840pgh.5.gmail;
 Wed, 25 May 2022 18:02:41 -0700 (PDT)
X-Received: by 2002:a05:6a00:ad0:b0:4e1:2d96:2ab0 with SMTP id c16-20020a056a000ad000b004e12d962ab0mr36267490pfl.3.1653526961072;
        Wed, 25 May 2022 18:02:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653526961; cv=none;
        d=google.com; s=arc-20160816;
        b=k/5jo2m719gC8emuK+SHM6tFCKSLuFdpmA8nuyowC3AkhTUFtDaYjvntOCdno6ss4e
         ynw8Re2O8qZvGhrGIh2H0Mmj3ycz+6B/rUqoUKIb6BHhlga5Mj5WvFT1nqsasEbHULpg
         RPm0U9cDKvU8TzOHiUcZkC8AIagWdViBT3ZqcGiYhKXfTCsy2q7zeG3JK+NI6j9Xr8bx
         hhVTFiy4p1xek6XxQEXstH19gzKWvOA2YjUK/WNA/uFcDzfrPGBUKfVOioFk9+o7a81i
         dciCY0GaOHF8lQz1SPEcRmRYoj58KMBF/i1lKb3lOhj2dABGeKfkXzDjc6NmyaTXqeyt
         LtHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=EEiYE3N4C+FiTTiGz2/4DMmfamDqDEZrPCXEkusGckA=;
        b=Etk9v6uLvfY9c4umgu0sEbQm1N3ZeK7aBtIoIflgzTgO6ML2hwUDDzHyRxnhI2LWBM
         5jdf8/SbH7I4gKYYtpb1/Dg1sxjcixxGGdSJQH1YWRDgKi3pBr3x98eoWhJDt9wN3xgY
         R9XOekbXQNWyrm+WFYvH0PKZ3jfWZ+IMdsL29XKnDrzvP9FndI6mlwtCcLh/2PO0fvRG
         oSo2ZBzUpVaj9DSVPQNDd7TLm0SSJZznl30HYvnO0T4zUn89m9ujvBZ0SlIvqpQAVoMi
         g2l4y9dWdfD3qtrfhL3tNf28Iyv3CUw5rtzThmHdk5hrqIKX0G5FLL7QywprQ6yYOgbv
         +DwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=D4OFEhQ+;
       spf=pass (google.com: domain of 3sngoyggkcakmjermpxfpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3sNGOYggKCakMJeRMPXfPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id rt9-20020a17090b508900b001df76e9c039si346087pjb.3.2022.05.25.18.02.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 May 2022 18:02:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3sngoyggkcakmjermpxfpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id g7-20020a5b0707000000b0064f39e75da4so280695ybq.17
        for <kasan-dev@googlegroups.com>; Wed, 25 May 2022 18:02:41 -0700 (PDT)
X-Received: from spirogrip.svl.corp.google.com ([2620:15c:2cb:201:cd2b:6bc3:8646:2eaa])
 (user=davidgow job=sendgmr) by 2002:a25:cb89:0:b0:652:964e:909d with SMTP id
 b131-20020a25cb89000000b00652964e909dmr9872550ybg.241.1653526960292; Wed, 25
 May 2022 18:02:40 -0700 (PDT)
Date: Wed, 25 May 2022 18:01:11 -0700
In-Reply-To: <20220525111756.GA15955@axis.com>
Message-Id: <20220526010111.755166-1-davidgow@google.com>
Mime-Version: 1.0
References: <20220525111756.GA15955@axis.com>
X-Mailer: git-send-email 2.36.1.124.g0e6072fb45-goog
Subject: [RFC PATCH v3] UML: add support for KASAN under x86_64
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vincent Whitchurch <vincent.whitchurch@axis.com>, Johannes Berg <johannes@sipsolutions.net>, 
	Patricia Alfonso <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, 
	Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Dmitry Vyukov <dvyukov@google.com>, Brendan Higgins <brendanhiggins@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, linux-um@lists.infradead.org, 
	LKML <linux-kernel@vger.kernel.org>, Daniel Latypov <dlatypov@google.com>, 
	David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=D4OFEhQ+;       spf=pass
 (google.com: domain of 3sngoyggkcakmjermpxfpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3sNGOYggKCakMJeRMPXfPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

From: Patricia Alfonso <trishalfonso@google.com>

Make KASAN run on User Mode Linux on x86_64.

The UML-specific KASAN initializer uses mmap to map the roughly 2.25TB
of shadow memory to the location defined by KASAN_SHADOW_OFFSET.
kasan_init() utilizes constructors to initialize KASAN before main().

The location of the KASAN shadow memory, starting at
KASAN_SHADOW_OFFSET, can be configured using the KASAN_SHADOW_OFFSET
option. UML uses roughly 18TB of address space, and KASAN requires 1/8th
of this. The default location of this offset is 0x100000000000, which
keeps it out-of-the-way even on UML setups with more "physical" memory.

For low-memory setups, 0x7fff8000 can be used instead, which fits in an
immediate and is therefore faster, as suggested by Dmitry Vyukov. There
is usually enough free space at this location; however, it is a config
option so that it can be easily changed if needed.

Note that, unlike KASAN on other architectures, vmalloc allocations
still use the shadow memory allocated upfront, rather than allocating
and free-ing it per-vmalloc allocation.

Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
Co-developed-by: Vincent Whitchurch <vincent.whitchurch@axis.com>
Signed-off-by: Vincent Whitchurch <vincent.whitchurch@axis.com>
Signed-off-by: David Gow <davidgow@google.com>
---

This is a new RFC for the KASAN/UML port, based on the patch v1:
https://lore.kernel.org/all/20200226004608.8128-1-trishalfonso@google.com/

With several fixes by Vincent Whitchurch:
https://lore.kernel.org/all/20220525111756.GA15955@axis.com/

That thread describes the differences from the v1 (and hence the
previous RFCs better than I can here), but the gist of it is:
- Support for KASAN_VMALLOC, by changing the way
  kasan_{populate,release}_vmalloc work to update existing shadow
  memory, rather than allocating anything new.
- A similar fix for modules' shadow memory.
- Support for KASAN_STACK
  - This requires the bugfix here:
https://lore.kernel.org/lkml/20220523140403.2361040-1-vincent.whitchurch@axis.com/
  - Plus a couple of files excluded from KASAN.
- Revert the default shadow offset to 0x100000000000
  - This was breaking when mem=1G for me, at least.
- A few minor fixes to linker sections and scripts.
  - I've added one to dyn.lds.S on top of the ones Vincent added.

There are still a few things to be sorted out before this is ready to go
upstream, in particular:
- We've got a bunch of checks for CONFIG_UML, where a more specific
  config option might be better. For example: CONFIG_KASAN_NO_SHADOW_ALLOC.
- Alternatively, the vmalloc (and module) shadow memory allocators could
  support per-architecture replacements.
- Do we want to the alignment before or after the __memset() in
  kasan_populate_vmalloc()?
- This doesn't seem to work when CONFIG_STATIC_LINK is enabled (because
  libc crt0 code calls memory functions, which expect the shadow memory
  to already exist, due to multiple symbols being resolved.
  - I think we should just make this depend on dynamic UML.
  - For that matter, I think static UML is actually broken at the
    moment. I'll send a patch out tomorrow.
- And there's a checkpatch complaint about a long __memset() line.

Thanks again to everyone who's contributed and looked at these patches!
Note that I removed the Reviewed-by tags, as I think this version has
enough changes to warrant a re-review.

-- David

---
 arch/um/Kconfig                  | 15 +++++++++++++++
 arch/um/Makefile                 |  6 ++++++
 arch/um/include/asm/common.lds.S |  2 ++
 arch/um/kernel/Makefile          |  3 +++
 arch/um/kernel/dyn.lds.S         |  6 +++++-
 arch/um/kernel/mem.c             | 18 ++++++++++++++++++
 arch/um/os-Linux/mem.c           | 22 ++++++++++++++++++++++
 arch/um/os-Linux/user_syms.c     |  4 ++--
 arch/x86/um/Makefile             |  3 ++-
 arch/x86/um/vdso/Makefile        |  3 +++
 mm/kasan/shadow.c                | 20 +++++++++++++++++++-
 11 files changed, 97 insertions(+), 5 deletions(-)

diff --git a/arch/um/Kconfig b/arch/um/Kconfig
index 4d398b80aea8..c28ea5c89381 100644
--- a/arch/um/Kconfig
+++ b/arch/um/Kconfig
@@ -11,6 +11,8 @@ config UML
 	select ARCH_HAS_STRNLEN_USER
 	select ARCH_NO_PREEMPT
 	select HAVE_ARCH_AUDITSYSCALL
+	select HAVE_ARCH_KASAN if X86_64
+	select HAVE_ARCH_KASAN_VMALLOC if HAVE_ARCH_KASAN
 	select HAVE_ARCH_SECCOMP_FILTER
 	select HAVE_ASM_MODVERSIONS
 	select HAVE_UID16
@@ -219,6 +221,19 @@ config UML_TIME_TRAVEL_SUPPORT
 
 	  It is safe to say Y, but you probably don't need this.
 
+config KASAN_SHADOW_OFFSET
+	hex
+	depends on KASAN
+	default 0x100000000000
+	help
+	  This is the offset at which the ~2.25TB of shadow memory is
+	  mapped and used by KASAN for memory debugging. This can be any
+	  address that has at least KASAN_SHADOW_SIZE(total address space divided
+	  by 8) amount of space so that the KASAN shadow memory does not conflict
+	  with anything. The default is 0x100000000000, which works even if mem is
+	  set to a large value. On low-memory systems, try 0x7fff8000, as it fits
+	  into the immediate of most instructions, improving performance.
+
 endmenu
 
 source "arch/um/drivers/Kconfig"
diff --git a/arch/um/Makefile b/arch/um/Makefile
index f2fe63bfd819..a98405f4ecb8 100644
--- a/arch/um/Makefile
+++ b/arch/um/Makefile
@@ -75,6 +75,12 @@ USER_CFLAGS = $(patsubst $(KERNEL_DEFINES),,$(patsubst -I%,,$(KBUILD_CFLAGS))) \
 		-D_FILE_OFFSET_BITS=64 -idirafter $(srctree)/include \
 		-idirafter $(objtree)/include -D__KERNEL__ -D__UM_HOST__
 
+# Kernel config options are not included in USER_CFLAGS, but the option for KASAN
+# should be included if the KASAN config option was set.
+ifdef CONFIG_KASAN
+	USER_CFLAGS+=-DCONFIG_KASAN=y
+endif
+
 #This will adjust *FLAGS accordingly to the platform.
 include $(srctree)/$(ARCH_DIR)/Makefile-os-$(OS)
 
diff --git a/arch/um/include/asm/common.lds.S b/arch/um/include/asm/common.lds.S
index eca6c452a41b..fd481ac371de 100644
--- a/arch/um/include/asm/common.lds.S
+++ b/arch/um/include/asm/common.lds.S
@@ -83,6 +83,8 @@
   }
   .init_array : {
 	__init_array_start = .;
+	*(.kasan_init)
+	*(.init_array.*)
 	*(.init_array)
 	__init_array_end = .;
   }
diff --git a/arch/um/kernel/Makefile b/arch/um/kernel/Makefile
index 1c2d4b29a3d4..a089217e2f0e 100644
--- a/arch/um/kernel/Makefile
+++ b/arch/um/kernel/Makefile
@@ -27,6 +27,9 @@ obj-$(CONFIG_EARLY_PRINTK) += early_printk.o
 obj-$(CONFIG_STACKTRACE) += stacktrace.o
 obj-$(CONFIG_GENERIC_PCI_IOMAP) += ioport.o
 
+KASAN_SANITIZE_stacktrace.o := n
+KASAN_SANITIZE_sysrq.o := n
+
 USER_OBJS := config.o
 
 include arch/um/scripts/Makefile.rules
diff --git a/arch/um/kernel/dyn.lds.S b/arch/um/kernel/dyn.lds.S
index 2f2a8ce92f1e..2b7fc5b54164 100644
--- a/arch/um/kernel/dyn.lds.S
+++ b/arch/um/kernel/dyn.lds.S
@@ -109,7 +109,11 @@ SECTIONS
      be empty, which isn't pretty.  */
   . = ALIGN(32 / 8);
   .preinit_array     : { *(.preinit_array) }
-  .init_array     : { *(.init_array) }
+  .init_array     : {
+    *(.kasan_init)
+    *(.init_array.*)
+    *(.init_array)
+  }
   .fini_array     : { *(.fini_array) }
   .data           : {
     INIT_TASK_DATA(KERNEL_STACK_SIZE)
diff --git a/arch/um/kernel/mem.c b/arch/um/kernel/mem.c
index 15295c3237a0..a32cfce53efb 100644
--- a/arch/um/kernel/mem.c
+++ b/arch/um/kernel/mem.c
@@ -18,6 +18,24 @@
 #include <kern_util.h>
 #include <mem_user.h>
 #include <os.h>
+#include <linux/sched/task.h>
+
+#ifdef CONFIG_KASAN
+void kasan_init(void)
+{
+	/*
+	 * kasan_map_memory will map all of the required address space and
+	 * the host machine will allocate physical memory as necessary.
+	 */
+	kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
+	init_task.kasan_depth = 0;
+	os_info("KernelAddressSanitizer initialized\n");
+}
+
+static void (*kasan_init_ptr)(void)
+__section(".kasan_init") __used
+= kasan_init;
+#endif
 
 /* allocated in paging_init, zeroed in mem_init, and unchanged thereafter */
 unsigned long *empty_zero_page = NULL;
diff --git a/arch/um/os-Linux/mem.c b/arch/um/os-Linux/mem.c
index 3c1b77474d2d..8530b2e08604 100644
--- a/arch/um/os-Linux/mem.c
+++ b/arch/um/os-Linux/mem.c
@@ -17,6 +17,28 @@
 #include <init.h>
 #include <os.h>
 
+/*
+ * kasan_map_memory - maps memory from @start with a size of @len.
+ * The allocated memory is filled with zeroes upon success.
+ * @start: the start address of the memory to be mapped
+ * @len: the length of the memory to be mapped
+ *
+ * This function is used to map shadow memory for KASAN in uml
+ */
+void kasan_map_memory(void *start, size_t len)
+{
+	if (mmap(start,
+		 len,
+		 PROT_READ|PROT_WRITE,
+		 MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE|MAP_NORESERVE,
+		 -1,
+		 0) == MAP_FAILED) {
+		os_info("Couldn't allocate shadow memory: %s\n.",
+			strerror(errno));
+		exit(1);
+	}
+}
+
 /* Set by make_tempfile() during early boot. */
 static char *tempdir = NULL;
 
diff --git a/arch/um/os-Linux/user_syms.c b/arch/um/os-Linux/user_syms.c
index 715594fe5719..cb667c9225ab 100644
--- a/arch/um/os-Linux/user_syms.c
+++ b/arch/um/os-Linux/user_syms.c
@@ -27,10 +27,10 @@ EXPORT_SYMBOL(strstr);
 #ifndef __x86_64__
 extern void *memcpy(void *, const void *, size_t);
 EXPORT_SYMBOL(memcpy);
-#endif
-
 EXPORT_SYMBOL(memmove);
 EXPORT_SYMBOL(memset);
+#endif
+
 EXPORT_SYMBOL(printf);
 
 /* Here, instead, I can provide a fake prototype. Yes, someone cares: genksyms.
diff --git a/arch/x86/um/Makefile b/arch/x86/um/Makefile
index ba5789c35809..f778e37494ba 100644
--- a/arch/x86/um/Makefile
+++ b/arch/x86/um/Makefile
@@ -28,7 +28,8 @@ else
 
 obj-y += syscalls_64.o vdso/
 
-subarch-y = ../lib/csum-partial_64.o ../lib/memcpy_64.o ../entry/thunk_64.o
+subarch-y = ../lib/csum-partial_64.o ../lib/memcpy_64.o ../entry/thunk_64.o \
+	../lib/memmove_64.o ../lib/memset_64.o
 
 endif
 
diff --git a/arch/x86/um/vdso/Makefile b/arch/x86/um/vdso/Makefile
index 5943387e3f35..8c0396fd0e6f 100644
--- a/arch/x86/um/vdso/Makefile
+++ b/arch/x86/um/vdso/Makefile
@@ -3,6 +3,9 @@
 # Building vDSO images for x86.
 #
 
+# do not instrument on vdso because KASAN is not compatible with user mode
+KASAN_SANITIZE			:= n
+
 # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
 KCOV_INSTRUMENT                := n
 
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index a4f07de21771..d8c518bd0e7d 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -295,8 +295,14 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 		return 0;
 
 	shadow_start = (unsigned long)kasan_mem_to_shadow((void *)addr);
-	shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
 	shadow_end = (unsigned long)kasan_mem_to_shadow((void *)addr + size);
+
+	if (IS_ENABLED(CONFIG_UML)) {
+		__memset(kasan_mem_to_shadow((void *)addr), KASAN_VMALLOC_INVALID, shadow_end - shadow_start);
+		return 0;
+	}
+
+	shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
 	shadow_end = ALIGN(shadow_end, PAGE_SIZE);
 
 	ret = apply_to_page_range(&init_mm, shadow_start,
@@ -466,6 +472,10 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 
 	if (shadow_end > shadow_start) {
 		size = shadow_end - shadow_start;
+		if (IS_ENABLED(CONFIG_UML)) {
+			__memset(shadow_start, KASAN_SHADOW_INIT, shadow_end - shadow_start);
+			return;
+		}
 		apply_to_existing_page_range(&init_mm,
 					     (unsigned long)shadow_start,
 					     size, kasan_depopulate_vmalloc_pte,
@@ -531,6 +541,11 @@ int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
 	if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
 		return -EINVAL;
 
+	if (IS_ENABLED(CONFIG_UML)) {
+		__memset((void *)shadow_start, KASAN_SHADOW_INIT, shadow_size);
+		return 0;
+	}
+
 	ret = __vmalloc_node_range(shadow_size, 1, shadow_start,
 			shadow_start + shadow_size,
 			GFP_KERNEL,
@@ -554,6 +569,9 @@ int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
 
 void kasan_free_module_shadow(const struct vm_struct *vm)
 {
+	if (IS_ENABLED(CONFIG_UML))
+		return;
+
 	if (vm->flags & VM_KASAN)
 		vfree(kasan_mem_to_shadow(vm->addr));
 }
-- 
2.36.1.124.g0e6072fb45-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220526010111.755166-1-davidgow%40google.com.
