Return-Path: <kasan-dev+bncBD653A6W2MGBBNXJWKKAMGQESAWJE7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D09E5327B0
	for <lists+kasan-dev@lfdr.de>; Tue, 24 May 2022 12:34:31 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id s9-20020aa7d789000000b0042ab9d77febsf12451017edq.16
        for <lists+kasan-dev@lfdr.de>; Tue, 24 May 2022 03:34:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653388471; cv=pass;
        d=google.com; s=arc-20160816;
        b=LJVl8+QkHqnedIu7i3LvAG3FZ2yZE3CjROmAnaM9LFPoT3kbYxCYKbxU6w0mITDgEN
         h05CrlV86HhSS4lZvKPvIQp5RVfuqCrNnCdRPx5KWPYObGulTc7rD08ibJs97THJjb/z
         iiH/T5R2shUe6ZmYtgWc+ciSI8irGlnsXsMLV7CDMm+VxNURjSpotsj4CO9pfPRcelYE
         BuvhtHdgSQM6+sLPJmp8Knu3bHdTVQtNHulpcMBkRSnd1mntGK1UYnGsAXGICRNLgKBa
         p4gAAkQTc/rREVcMVGh5Q3SpxFSCmHFCzemEVk2KyAL1XuQMi/IDf8eXlZwxWVBdER0U
         /w3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=cly7LQ01LZorseKwQtjZ2X3WlQe09OLgRWGGHh1Dbuo=;
        b=kRENyVo9/mCDmDRwySBxaGI0ci5ETqptVXKjLg9kmGtcUGUHzawvXPL23SCLmT0AG0
         5c8RFOhUjDWIVJlqsWBmPh2vurnI4l8hsukynsXNP91KKd72p0MhDkuSPtPmT3JAnmCK
         rCBpEW4N9k/FcRkX+9sJfrIW3d//Wy4rt3Oj22kl8FQ+JZE6oKUQyTJzbjKPLRP+l7pP
         FdyRvtaS+l+gJk3DM+Gkxj5aIXETSzKbNO4lOSsGnqueIhMUgZaxcQGF/bHD+Cfsvq73
         lGO0INOn1bzTIWO7RIJm2lo4QcxbZTZkU6qdCUfsekz1/bA+cfiy0G7ch8XPvfLsf3U8
         1Y1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@axis.com header.s=axis-central1 header.b=EXfzNGfz;
       spf=pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.17 as permitted sender) smtp.mailfrom=Vincent.Whitchurch@axis.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=axis.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cly7LQ01LZorseKwQtjZ2X3WlQe09OLgRWGGHh1Dbuo=;
        b=afIFrj5O+OYihcwX+jJaG+B6BiXMw+YyKLhBtcRaYKX/bAkw93Rh6QPGOhsR0ESjBi
         vNg5+P5PODCMMiZTN6hkmQna1aXkpMHdpDBW8Oby41lpjUyIGUwf1IBjaYvP3aVA/w6R
         GUYyxUfCRvnjy/z3sttJIi3jbnvANZYHF3sc5rfdjsEROm5g604qm+x8+nlBJvDQg3Jy
         g8oAlABgnWWV+fuW3/gsb5gJWq1IAkyNTF3mfZHSCv1Tt1UJDVI4iy4UywfhHNeTEuxT
         426OVA9BvtT2wTbhNiPOplnh170qJb1mziAB/pBdPZk9cjvlkJWgulGz9YODbHC374vh
         kC5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cly7LQ01LZorseKwQtjZ2X3WlQe09OLgRWGGHh1Dbuo=;
        b=E3JUQSmiIbeeNIm7IgCBoO4I/Bf+Ef9I7vIPG7aw7CAkV3ecnqSAetcVaZHhFsWLgg
         Yi81ZsJkLIFNQzU2/NyKLJ+BIOe+cGyz3Fse6ODjiRmziFXClH6w2XtEuB2uB40nAH+K
         SKBPGeiKRedBw0lW5G/m0HJVPr8jIfEhmFMFHCD/zgbyKQAjsLgWSlnz0s7bNpykGL3P
         0HF8BgzolrTfU0oqcRA2qCeI7ZNcV3ZTb4DiHUIryb0HQiWSv88EHlM55q/WzB/ejMvk
         EjlKvGmhm2Lg+AiligH0b/x1u2jf06F/SJZBIgHjAI71Rqu03BJgIreBvaCDRuRLcKCx
         8r7A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530TuC6k8/0oSlygl8V56fV9IOWKUGIldZX0jIAS5Ghe2Q9aw8iN
	ZELS+6otvz3ROzIRr3uVWJE=
X-Google-Smtp-Source: ABdhPJzn/u0i5x/3bgzGA7ZyDLCkNPTAGUiP/tx5BAlgrvkAcopLWEopzAxBfNXbpnLJl7J30Nz2bw==
X-Received: by 2002:a17:907:72c4:b0:6ff:59f:640f with SMTP id du4-20020a17090772c400b006ff059f640fmr2003215ejc.532.1653388470764;
        Tue, 24 May 2022 03:34:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:9910:b0:6fe:c0cb:366b with SMTP id
 zl16-20020a170906991000b006fec0cb366bls4072587ejb.11.gmail; Tue, 24 May 2022
 03:34:29 -0700 (PDT)
X-Received: by 2002:a17:907:6ea4:b0:6f9:b218:8cd with SMTP id sh36-20020a1709076ea400b006f9b21808cdmr23078056ejc.376.1653388469672;
        Tue, 24 May 2022 03:34:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653388469; cv=none;
        d=google.com; s=arc-20160816;
        b=z7jI3tM2KttlpBAcffAL9ikvIFdOoGM7R1j84ju6GpROnIrkD4/mX99/w4YjXqT7l9
         JmM3zkgse4CVjEMKHQ0P2nzhwxyisNbToKiUcZRc2neDb4NGDHLTS8j6f+8e0IS9d0ex
         oXuHwwVDZ5QBgHzZXpZmcbhyeWsNaB6qlZbEVZQGtLHzvH1jvXUlUBjd6IYz7wmo/tCX
         V+Yb8ZVB16UYVPIa/4Nl4lRFBK2xe6/zGm6YvmDPotx22HJueS6qKmlSjo2ac4lRbKN8
         Qat5pJN+a3JLyoeX630EcAawwPCivwC5gV3luBmdBl17QP7JpNAW/owuqLJoUoJdTRSi
         6q5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=tTO9KlSLvwJ5fB+7S3O+zA2j/+7fp0U+77neSmOoPwU=;
        b=CCM8uvzauzpZN5uOaUwfNmeX391LUY5c6lNp/LsBVNfTTsFyZUVEJFqngHAA1RIBhf
         0S/AdW0s9fLEnWIYS2a/IHdYyRI5Wsvl55ECBqUvUE8djsrIoH06sijwsE0M4oyg8eHT
         ab6ZTW981izF6dAUkWz1KIXbtFqV2cqWNlFhgGJPjtOHzzhiaQDF0vD1bfFDc9W1OOwp
         3c0K0CM0qP/6Gdxm3JdUp4V689Hz5O7xO+LuB/pXx7pOLyQw1QQpudHXXcRX4H1J3Pmy
         I8KENPad33WUC31ojGVj6Cce1h0cY+Tx5WyrgdkyzC9+maJiSqwZAm9/JusIvw9TFWLF
         ekjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@axis.com header.s=axis-central1 header.b=EXfzNGfz;
       spf=pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.17 as permitted sender) smtp.mailfrom=Vincent.Whitchurch@axis.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=axis.com
Received: from smtp1.axis.com (smtp1.axis.com. [195.60.68.17])
        by gmr-mx.google.com with ESMTPS id e22-20020a170906845600b006feb6644b51si391713ejy.2.2022.05.24.03.34.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 24 May 2022 03:34:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.17 as permitted sender) client-ip=195.60.68.17;
Date: Tue, 24 May 2022 12:34:28 +0200
From: Vincent Whitchurch <vincent.whitchurch@axis.com>
To: Johannes Berg <johannes@sipsolutions.net>
CC: Patricia Alfonso <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>,
	Richard Weinberger <richard@nod.at>, <anton.ivanov@cambridgegreys.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov
	<dvyukov@google.com>, Brendan Higgins <brendanhiggins@google.com>, David Gow
	<davidgow@google.com>, kasan-dev <kasan-dev@googlegroups.com>, LKML
	<linux-kernel@vger.kernel.org>, <linux-um@lists.infradead.org>
Subject: Re: [PATCH] UML: add support for KASAN under x86_64
Message-ID: <20220524103423.GA13239@axis.com>
References: <20200226004608.8128-1-trishalfonso@google.com>
 <CAKFsvULd7w21T_nEn8QiofQGMovFBmi94dq2W_-DOjxf5oD-=w@mail.gmail.com>
 <4b8c1696f658b4c6c393956734d580593b55c4c0.camel@sipsolutions.net>
 <CAKFsvULGSQRx3hL8HgbYbEt_8GOorZj96CoMVhx6sw=xWEwSwA@mail.gmail.com>
 <1fb57ec2a830deba664379f3e0f480e08e6dec2f.camel@sipsolutions.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1fb57ec2a830deba664379f3e0f480e08e6dec2f.camel@sipsolutions.net>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: vincent.whitchurch@axis.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@axis.com header.s=axis-central1 header.b=EXfzNGfz;
       spf=pass (google.com: domain of vincent.whitchurch@axis.com designates
 195.60.68.17 as permitted sender) smtp.mailfrom=Vincent.Whitchurch@axis.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=axis.com
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

On Wed, Mar 11, 2020 at 11:44:37PM +0100, Johannes Berg wrote:
> On Wed, 2020-03-11 at 15:32 -0700, Patricia Alfonso wrote:
> > I'll need some time to investigate these all myself. Having just
> > gotten my first module to run about an hour ago, any more information
> > about how you got these errors would be helpful so I can try to
> > reproduce them on my own.
> 
> See the other emails, I was basically just loading random modules. In my
> case cfg80211, mac80211, mac80211-hwsim - those are definitely available
> without any (virtio) hardware requirements, so you could use them.
> 
> Note that doing a bunch of vmalloc would likely result in similar
> issues, since the module and vmalloc space is the same on UML.

Old thread, but I had a look at this the other day and I think I got it
working.  Since the entire shadow area is mapped at init, we don't need
to do any mappings later.

It works both with and without KASAN_VMALLOC.  KASAN_STACK works too
after I disabled sanitization of the stacktrace code.  All kasan kunit
tests pass and the test_kasan.ko module works too.

Delta patch against Patricia's is below.  The CONFIG_UML checks need to
be replaced with something more appropriate (new config? __weak
functions?) and the free functions should probably be hooked up to
madvise(MADV_DONTNEED) so we discard unused pages in the shadow mapping.

Note that there's a KASAN stack-out-of-bounds splat on startup when just
booting UML.  That looks like a real (17-year-old) bug, I've posted a
fix for that:

 https://lore.kernel.org/lkml/20220523140403.2361040-1-vincent.whitchurch@axis.com/

8<-----------
diff --git a/arch/um/Kconfig b/arch/um/Kconfig
index a1bd8c07ce14..5f3a4d25d57e 100644
--- a/arch/um/Kconfig
+++ b/arch/um/Kconfig
@@ -12,6 +12,7 @@ config UML
 	select ARCH_NO_PREEMPT
 	select HAVE_ARCH_AUDITSYSCALL
 	select HAVE_ARCH_KASAN if X86_64
+	select HAVE_ARCH_KASAN_VMALLOC if HAVE_ARCH_KASAN
 	select HAVE_ARCH_SECCOMP_FILTER
 	select HAVE_ASM_MODVERSIONS
 	select HAVE_UID16
@@ -223,7 +224,7 @@ config UML_TIME_TRAVEL_SUPPORT
 config KASAN_SHADOW_OFFSET
 	hex
 	depends on KASAN
-	default 0x7fff8000
+	default 0x100000000000
 	help
 	  This is the offset at which the ~2.25TB of shadow memory is
 	  mapped and used by KASAN for memory debugging. This can be any
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
diff --git a/arch/um/kernel/mem.c b/arch/um/kernel/mem.c
index 7c3196c297f7..a32cfce53efb 100644
--- a/arch/um/kernel/mem.c
+++ b/arch/um/kernel/mem.c
@@ -33,7 +33,7 @@ void kasan_init(void)
 }
 
 static void (*kasan_init_ptr)(void)
-__section(.kasan_init) __used
+__section(".kasan_init") __used
 = kasan_init;
 #endif
 
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 1113cf5fea25..1f3e620188a2 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -152,7 +152,7 @@ config KASAN_STACK
 	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
 	depends on KASAN_GENERIC || KASAN_SW_TAGS
 	depends on !ARCH_DISABLE_KASAN_INLINE
-	default y if CC_IS_GCC && !UML
+	default y if CC_IS_GCC
 	help
 	  The LLVM stack address sanitizer has a know problem that
 	  causes excessive stack usage in a lot of functions, see
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
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220524103423.GA13239%40axis.com.
