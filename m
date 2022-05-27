Return-Path: <kasan-dev+bncBC6OLHHDVUOBBSV5YSKAMGQEKVOIYUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 9FEA453673C
	for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 20:56:11 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id 129-20020a6b0187000000b00660cf61c6e8sf3263028iob.4
        for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 11:56:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653677770; cv=pass;
        d=google.com; s=arc-20160816;
        b=DtpIV2REYvcCoOQSBN+Oz/tgk684C18h6IrCASTKD5drNUMrMenvphHoL+7vySFvxd
         Guy+R95klOi57n2KSxBGjxei/lBFg14lzXg9jf+AXzoHzDZTxRepQCjPsv0psYsPxjs6
         ZyHeIbasxXyn15b9XpNnFu6N170lpOLIxBhc5E/VB0l39k7Mprrvhua+FEVobh+U1SK1
         BV/LNkRuqEQGVjyeeb3o5WJbCBG3JuUzTKzQtRGjeJWHQUBhG7glBJNrcQQOphHZc6Nk
         h41XLPblciiKrF6H1aXoDUc7rLiyLWiCVZjnIgp01AaVsix1Cx56rvLmCLYooBr1YvG1
         UXhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=56fpqGVaOpkSwj2mi1b0MLgqxdqWNXsiXa+5reS3cAA=;
        b=gGFttltYmt8jTPIfOwp/SdNdSvIEVkFXIclMg0dU8rEs9+ade8du+USLHRaJR3n45p
         VbWJD1k7FmQb9DYY016VgT7PSfb+5iYRf9ImCV031a7mWXo2fZBq3R0QMDBCEa8j7JhG
         hyHYT2GBaGuO5jmCoAXFmErCBmgFUvKS1SBpivSW/V1fwXFao6gEToKxXXENi7FWhlNk
         PsNpycbZa5PV6dtDXYdeykBfgNR/qWu/KY+7FnC6eEHYPECDd2pH36OJqnOHa6QG5T4A
         6oRm8fdMJCq0vuPlTEMLNq3h3fYkBgeWUce7MEScki9Xp+macH+T9D5UpMYnrzQ8Tlvd
         ZL6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fVzu+fZu;
       spf=pass (google.com: domain of 3yr6ryggkcwyhezmhksaksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3yR6RYggKCWYHEZMHKSaKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=56fpqGVaOpkSwj2mi1b0MLgqxdqWNXsiXa+5reS3cAA=;
        b=RGJckrTNlCJ30+EoW6/grivRBN+xr42BrWdn/Qk0rs5N4IIGnho3fXUURebo+OHke7
         ERyoJ2il6MWjzkuetL1T0Vnx6GG17m1AC2+JHXxrHR8BYsADGReUeW9ZkLyc6/oaYVfv
         /sY+MHZdc1iBOZUCiyDbBEoPZP2Zga+3FK3XaOSMlJCwNzjLHFp0OUyePFk2jkbMT3GY
         cX91AR8jTwrYSEqfhmnSZFowZ3DBD+rPbr4aqItb31t4Ym0eYzN3YZKDl3NisuSPqR6C
         uTDvbwJ62cjSmOSia3b+z2P/WfVWJj5IwQqc6sH8sEBO1kbizoW4Up9rZW72ldRKZ8pb
         npEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=56fpqGVaOpkSwj2mi1b0MLgqxdqWNXsiXa+5reS3cAA=;
        b=dVI326qmb52kNtL+4ECPQirlZiXOWcjPewOr287yBcVCIo0/qygAF+sjle5PpSJM0h
         i+HaTgfB4hvjsDiGbNKUGh5/Kjtlij1/db4OGCHrDnMZUtqlmAXZ+epG1QLB0rmpJBLe
         tN6pZAOwFTkvc48UhVHxDFtjNamapTki/tN/lsCzQP6VPL5oysUkGekrnT31gRkSIw0D
         vPHwuT308BQROMSHEM7JP/4Kaq78mcBjnmp6GOJkKW7mBX1kQorBMtQezI5Mm1TMdrvW
         1Rwhb2nDAVh3NinaTWDoOiIeO0GMlL4CIYS84Bu0sKsa9LHuIIOuZJlrz35D+ioww6jQ
         gNvQ==
X-Gm-Message-State: AOAM532dqxc90RhF+wwvf/yIUxhwfUS7DAvGg8iRARNqEuMgRa0z1Tm/
	tinUdAUG6fAwkkX4HjMpybg=
X-Google-Smtp-Source: ABdhPJymgmhobXYj91LTv2NiImG7mzn/vTTtu6ayDefyw55QNBdMdJOA+rEsxmaZVVtwsK79nXovPA==
X-Received: by 2002:a05:6602:2c4c:b0:64f:a897:80cb with SMTP id x12-20020a0566022c4c00b0064fa89780cbmr20136970iov.139.1653677770421;
        Fri, 27 May 2022 11:56:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:329b:b0:330:eb95:f830 with SMTP id
 f27-20020a056638329b00b00330eb95f830ls699106jav.9.gmail; Fri, 27 May 2022
 11:56:10 -0700 (PDT)
X-Received: by 2002:a05:6638:2582:b0:330:fd2d:9c01 with SMTP id s2-20020a056638258200b00330fd2d9c01mr1569128jat.16.1653677769906;
        Fri, 27 May 2022 11:56:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653677769; cv=none;
        d=google.com; s=arc-20160816;
        b=ZtYlKDS63VK4/JibaVkK+CElENQZFPc51QzFRRcynQyU/7oyXq+u4cBKBocCub/0VV
         70ugNdUJKZuwXn7QnWTbXoT6ROXJUQZrKvYyWw8jl3mDrEH9mL4TApp7YyToM1NPucHS
         3an4ku3SNMw1hTuFETLqgRvsOOc2anTFPwNf9rZFtph5tlRrzyGGwWIYL67tCbqup+Df
         cd/a0bFSAef/4Jr2+BC5MHgVDGfdwPGst4T9Ka3CmfURZVfsIcIcbDwih0t8NXGdAKFM
         UBYz/kJmcWAfYAhwrVGrjGudRbhfUKbJcOB0Yov4XvdQqii9ofEj8vTajULt8QQ78jIO
         sDWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=QA4cO/cwsaurmRGD7CxGk+K83Ifx5si4sh5tEesvWqg=;
        b=poygs8Ovvx69G7TLnecN7PBHK8gvK+LWcPRLfOyI28bFVRTIbtmZeFexDAY4bSnB07
         N/HOZ0X8yO0GtiqHzW0VhokdiX3M2fJZaa642sEV1sAy/RZEZwrDaQ3FTjtKmcIyW5lE
         zuig7RsrJSECvyH9bXieTPaxlz4lU/chtPvfsp7tsSPk0X6j4vaB458MeoiJWkvhl/Zu
         DOT5dV6fR/kMIJt1dY4bxMHVPB3ynpgfJtFcXQYYCEqi5uq4UpZxOsi2GQyReHg0SOfX
         dIjhZP9KF229mq9NhO/VF06ywCBZopQBXUmDhDELSbD/rqoAfyJcRnMONsenH/1IJ60r
         RqaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fVzu+fZu;
       spf=pass (google.com: domain of 3yr6ryggkcwyhezmhksaksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3yR6RYggKCWYHEZMHKSaKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id j5-20020a92c205000000b002ca3e929b6csi287260ilo.2.2022.05.27.11.56.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 May 2022 11:56:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yr6ryggkcwyhezmhksaksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-30026cf9af8so46152157b3.3
        for <kasan-dev@googlegroups.com>; Fri, 27 May 2022 11:56:09 -0700 (PDT)
X-Received: from spirogrip.svl.corp.google.com ([2620:15c:2cb:201:122e:1813:2b92:fe8e])
 (user=davidgow job=sendgmr) by 2002:a05:6902:534:b0:655:d6a1:891b with SMTP
 id y20-20020a056902053400b00655d6a1891bmr5671303ybs.108.1653677769431; Fri,
 27 May 2022 11:56:09 -0700 (PDT)
Date: Fri, 27 May 2022 11:56:00 -0700
In-Reply-To: <20220527185600.1236769-1-davidgow@google.com>
Message-Id: <20220527185600.1236769-2-davidgow@google.com>
Mime-Version: 1.0
References: <20220527185600.1236769-1-davidgow@google.com>
X-Mailer: git-send-email 2.36.1.124.g0e6072fb45-goog
Subject: [PATCH v2 2/2] UML: add support for KASAN under x86_64
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vincent Whitchurch <vincent.whitchurch@axis.com>, Johannes Berg <johannes@sipsolutions.net>, 
	Patricia Alfonso <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, 
	Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Dmitry Vyukov <dvyukov@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, linux-um@lists.infradead.org, 
	LKML <linux-kernel@vger.kernel.org>, Daniel Latypov <dlatypov@google.com>, linux-mm@kvack.org, 
	David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=fVzu+fZu;       spf=pass
 (google.com: domain of 3yr6ryggkcwyhezmhksaksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3yR6RYggKCWYHEZMHKSaKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--davidgow.bounces.google.com;
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

Also note that, while UML supports both KASAN in inline mode
(CONFIG_KASAN_INLINE) and static linking (CONFIG_STATIC_LINK), it does
not support both at the same time.

Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
Co-developed-by: Vincent Whitchurch <vincent.whitchurch@axis.com>
Signed-off-by: Vincent Whitchurch <vincent.whitchurch@axis.com>
Signed-off-by: David Gow <davidgow@google.com>
---

This is v2 of the KASAN/UML port. It should be ready to go.

It does benefit significantly from the following patches:
- Bugfix for memory corruption, needed for KASAN_STACK support:
https://lore.kernel.org/lkml/20220523140403.2361040-1-vincent.whitchurch@axis.com/
- Fix CONFIG_CONSTRUCTORS on static linked kernels:
https://lore.kernel.org/all/20220526185402.955870-1-davidgow@google.com/
- Improve callstack reporting for Tiny RCU:
https://lore.kernel.org/all/20220527170743.04c21d235467.I1f79da0f90fb9b557ec34932136c656bc64b8fbf@changeid/

Changes since RFC v3:
https://lore.kernel.org/all/20220526010111.755166-1-davidgow@google.com/
- No longer print "KernelAddressSanitizer initialized" (Johannes)
- Document the reason for the CONFIG_UML checks in shadow.c (Dmitry)
- Support static builds via kasan_arch_is_ready() (Dmitry)
- Get rid of a redundant call to kasam_mem_to_shadow() (Dmitry)
- Use PAGE_ALIGN and the new PAGE_ALIGN_DOWN macros (Dmitry)
- Reinstate missing arch/um/include/asm/kasan.h file (Johannes)

Changes since v1:
https://lore.kernel.org/all/20200226004608.8128-1-trishalfonso@google.com/
- Include several fixes from Vincent Whitchurch:
https://lore.kernel.org/all/20220525111756.GA15955@axis.com/
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


---
 arch/um/Kconfig                  | 15 +++++++++++++
 arch/um/Makefile                 |  6 ++++++
 arch/um/include/asm/common.lds.S |  2 ++
 arch/um/include/asm/kasan.h      | 37 ++++++++++++++++++++++++++++++++
 arch/um/kernel/Makefile          |  3 +++
 arch/um/kernel/dyn.lds.S         |  6 +++++-
 arch/um/kernel/mem.c             | 19 ++++++++++++++++
 arch/um/os-Linux/mem.c           | 22 +++++++++++++++++++
 arch/um/os-Linux/user_syms.c     |  4 ++--
 arch/x86/um/Makefile             |  3 ++-
 arch/x86/um/vdso/Makefile        |  3 +++
 mm/kasan/shadow.c                | 36 +++++++++++++++++++++++++++++--
 12 files changed, 150 insertions(+), 6 deletions(-)
 create mode 100644 arch/um/include/asm/kasan.h

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
diff --git a/arch/um/include/asm/kasan.h b/arch/um/include/asm/kasan.h
new file mode 100644
index 000000000000..0d6547f4ec85
--- /dev/null
+++ b/arch/um/include/asm/kasan.h
@@ -0,0 +1,37 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef __ASM_UM_KASAN_H
+#define __ASM_UM_KASAN_H
+
+#include <linux/init.h>
+#include <linux/const.h>
+
+#define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
+
+/* used in kasan_mem_to_shadow to divide by 8 */
+#define KASAN_SHADOW_SCALE_SHIFT 3
+
+#ifdef CONFIG_X86_64
+#define KASAN_HOST_USER_SPACE_END_ADDR 0x00007fffffffffffUL
+/* KASAN_SHADOW_SIZE is the size of total address space divided by 8 */
+#define KASAN_SHADOW_SIZE ((KASAN_HOST_USER_SPACE_END_ADDR + 1) >> \
+			KASAN_SHADOW_SCALE_SHIFT)
+#else
+#error "KASAN_SHADOW_SIZE is not defined for this sub-architecture"
+#endif /* CONFIG_X86_64 */
+
+#define KASAN_SHADOW_START (KASAN_SHADOW_OFFSET)
+#define KASAN_SHADOW_END (KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
+
+#ifdef CONFIG_KASAN
+void kasan_init(void);
+void kasan_map_memory(void *start, unsigned long len);
+extern int kasan_um_is_ready;
+
+#ifdef CONFIG_STATIC_LINK
+#define kasan_arch_is_ready() (kasan_um_is_ready)
+#endif
+#else
+static inline void kasan_init(void) { }
+#endif /* CONFIG_KASAN */
+
+#endif /* __ASM_UM_KASAN_H */
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
index 15295c3237a0..276a1f0b91f1 100644
--- a/arch/um/kernel/mem.c
+++ b/arch/um/kernel/mem.c
@@ -18,6 +18,25 @@
 #include <kern_util.h>
 #include <mem_user.h>
 #include <os.h>
+#include <linux/sched/task.h>
+
+#ifdef CONFIG_KASAN
+int kasan_um_is_ready;
+void kasan_init(void)
+{
+	/*
+	 * kasan_map_memory will map all of the required address space and
+	 * the host machine will allocate physical memory as necessary.
+	 */
+	kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
+	init_task.kasan_depth = 0;
+	kasan_um_is_ready = true;
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
index a4f07de21771..c993d99116f2 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -295,9 +295,29 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 		return 0;
 
 	shadow_start = (unsigned long)kasan_mem_to_shadow((void *)addr);
-	shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
 	shadow_end = (unsigned long)kasan_mem_to_shadow((void *)addr + size);
-	shadow_end = ALIGN(shadow_end, PAGE_SIZE);
+
+	/*
+	 * User Mode Linux maps enough shadow memory for all of physical memory
+	 * at boot, so doesn't need to allocate more on vmalloc, just clear it.
+	 *
+	 * If another architecture chooses to go down the same path, we should
+	 * replace this check for CONFIG_UML with something more generic, such
+	 * as:
+	 * - A CONFIG_KASAN_NO_SHADOW_ALLOC option, which architectures could set
+	 * - or, a way of having architecture-specific versions of these vmalloc
+	 *   and module shadow memory allocation options.
+	 *
+	 * For the time being, though, this check works. The remaining CONFIG_UML
+	 * checks in this file exist for the same reason.
+	 */
+	if (IS_ENABLED(CONFIG_UML)) {
+		__memset((void *)shadow_start, KASAN_VMALLOC_INVALID, shadow_end - shadow_start);
+		return 0;
+	}
+
+	shadow_start = PAGE_ALIGN_DOWN(shadow_start);
+	shadow_end = PAGE_ALIGN(shadow_end);
 
 	ret = apply_to_page_range(&init_mm, shadow_start,
 				  shadow_end - shadow_start,
@@ -466,6 +486,10 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 
 	if (shadow_end > shadow_start) {
 		size = shadow_end - shadow_start;
+		if (IS_ENABLED(CONFIG_UML)) {
+			__memset(shadow_start, KASAN_SHADOW_INIT, shadow_end - shadow_start);
+			return;
+		}
 		apply_to_existing_page_range(&init_mm,
 					     (unsigned long)shadow_start,
 					     size, kasan_depopulate_vmalloc_pte,
@@ -531,6 +555,11 @@ int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
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
@@ -554,6 +583,9 @@ int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220527185600.1236769-2-davidgow%40google.com.
