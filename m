Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTGX4D6AKGQE2IKGCQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id DC7DB29B01E
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 15:16:45 +0100 (CET)
Received: by mail-oi1-x238.google.com with SMTP id i13sf735026oik.12
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 07:16:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603808205; cv=pass;
        d=google.com; s=arc-20160816;
        b=RN/38smadrauhpLfeWtJl+VbT6lP4mgAlpT2qQJkhQMNc+BaT9ewdXKJ2VLnmKTnMz
         CsfWTEmyKMyrj/eG3t4qQ5qIHl++ECxIL+SphSiAJPeRp7Jd5RLBNDDxGCUy+NN0tkK+
         rTFgQlO6wnA46FTOJ0VPt4+qK3ihpiADIyK2Tg0S0XYQOReRld5+B3lJmJYmqOxAzecf
         zFjXMWBHYKNHRWWyuP/ea5b+M5tnfhrjwtzblFGx86/jX4BENNavTZNhaCHxIAqP78TS
         PYB+AK3GfRv0IEJMm/mq2gcZZbDDrg97eqiCb0CsmIiOXDQNaXZXyDsXRORD7UqjN9WP
         8IyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=YUq63wmvYoPRHXV7XY0R1se8GIHLT9zFN3dT+u4MjlQ=;
        b=Px9XexeJX6Uq0joIMd1GXeQffB6HrmTowX4NimG6ExEIJuofvFFzqculAdbGMIvl1L
         CANgKLoB8xu+nbQs0r098zy9YHoB/BEreCcx7grVcXiSSj19v/udXjLedFGlg33tqFma
         aqfarYkH3tFLUUAkgGJ4lQkEho48oo7VBNqpldDNdQNcYvZ2YJ+vwmFqICxWg6QdFDo1
         C206gyxg4Lnxg8as7EXRCJTh2VD5kOZ2XtAiIDKI/sP2tAIhI3SSXUvf5TIv9WfC1zDN
         KJli0Sk+aPKLSm93/2PJt6Tp1PTW6VnSACS14vYN4eKrjd9ibuOGd9AHmpN/8WDiGIOb
         jAWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=J7MAP7wf;
       spf=pass (google.com: domain of 3yyuyxwukcyyov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3yyuYXwUKCYYov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YUq63wmvYoPRHXV7XY0R1se8GIHLT9zFN3dT+u4MjlQ=;
        b=PXc7y54N7tldo/QL819RqS6xYH3jPg6qgQRhdxzewId17vpF0Nd7nhhfgQe1gCAumm
         N5OF/2gmS2exHsG4kFPkeMfVivZaWI6w2hAQj9UlodxWBYeFmceD68EVLjw9RtqIL0lM
         rolSaJwvQhs1Gw2ukhdC0WiHIXJa1YjLdsiJAV/GvMZf2uSAa9z0T5IplUvao3axGkzz
         ItFdhUdG4t05AGQiNbVVBV+W3AI/v5e+vDdrU5K5XmqKD2z6BVfvN7r04LZ2YdvBFtS6
         KJ9DmKfdflqrvmQfh4e1gWFr0g6xrj+O3bKT7k+CkEiWFoM59qC3t4VAJoJj9sa8j3kb
         RVaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YUq63wmvYoPRHXV7XY0R1se8GIHLT9zFN3dT+u4MjlQ=;
        b=KTrG0p+p902HIgd40Ec++wHHrY6s/lO/FhU5eKN4/iDWMsTK8bKs1CHX/J9daxR29o
         yNG1sqEso6N9efVyLYZ+ytudXgIxvzMBe5KMme7P6kdvranSJTEIN7f0oy0H+G+c+aLj
         4sb1hdjik54AvJtaiR1vh4MTHLQLn3QKKaTEmfwBB3sd2137cnEyxb+WWpm70AHGVw60
         hCpfKhQgQ1mAHJSJyIk/zsonGyglHu6EGgXm1K2w2gIZSC7mreNNd48h5OvuAHZXuPjA
         91xTziNczZ8mezi+2yKvmnY+1j33UZO2IN/WCWl9JHl6yp7GF6RD3Tiy1gqLMJq9PK18
         ootQ==
X-Gm-Message-State: AOAM531bKfuoWie9ccqILy6TkUDRQNyXagE7XUd+lvTXmkk8wctalD+p
	Jp8ntC0yT4x31YGcTHGuryc=
X-Google-Smtp-Source: ABdhPJwkfAWZxOJytxV6v56/2D6nbHivHs0dcRDBWUxB98mOKCEUsFsNlQ73pN0Qhv+NhA8i2oiG1g==
X-Received: by 2002:aca:4854:: with SMTP id v81mr467893oia.43.1603808204728;
        Tue, 27 Oct 2020 07:16:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cf15:: with SMTP id f21ls457996oig.8.gmail; Tue, 27 Oct
 2020 07:16:44 -0700 (PDT)
X-Received: by 2002:a54:4194:: with SMTP id 20mr1653751oiy.137.1603808204306;
        Tue, 27 Oct 2020 07:16:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603808204; cv=none;
        d=google.com; s=arc-20160816;
        b=bktgrx46O3jlIq93er3Jx4TT+eHtyKbB3JffJkp9hlORKnKt2JZ7N2k0gXBilESuJs
         1hymXRuzuHeQ8cDqVr5ssF+0VoyTycrACP4MkDKRA6KTAZUxA8Ihh4fh+PTQjjVWHcWw
         DG+zuyTON1NWXt7atMKja9hlFK40BnqEduOUihDhsH02PyTdRexFawpdn/kobSfGnZIv
         z5y+qZQp5DPlLka3FQF/A+1EAYmB1+5S0wDBgOGurLuISoocwmQOp+9qQPhKZW+H59o8
         31pGl9VinmyUXopeyV0JX7Ck5chEUgQqMYivWULHn52jCvYzZFF2V/Jwo58Uk9+lCENW
         Wz5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=R5deNKQtKH9EZ+lgyHLcLWPCg/4T3AT3F5cjxg8+c98=;
        b=0x7MEagt01ucgqs4+O/5v5uQEiw0RZt308ykVH86GckUOp7sogxLeZpuJ9UotdlFOD
         2nhzuASEoWEhvdcERxeHoU8Ho/ItQwx4mI1IsN/tGTUT16R9fMY9t1wNUPdsWZzTfhsY
         tsv5d0/jAeHfgkI/qW2OOplcTAxWt3BYuG5TjsSSNAgu97YmoTtBuZ5iVBEDssX3AMNV
         dz9QtYQo00AWkJLohscBl1iOPl2MaoGe/6L4Yn92YHBkgY2nELWko6+Fq1IHmp6uEs9W
         8pPRb2sSvIh9vj1XLb4HURr+3GkBDGGxdw0pGmJZOEnRDxQ0yGVbY4GAO/DsHppaZUdM
         8N4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=J7MAP7wf;
       spf=pass (google.com: domain of 3yyuyxwukcyyov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3yyuYXwUKCYYov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id b15si111242otj.3.2020.10.27.07.16.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Oct 2020 07:16:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yyuyxwukcyyov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id s14so847793qke.1
        for <kasan-dev@googlegroups.com>; Tue, 27 Oct 2020 07:16:44 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:ad4:54e9:: with SMTP id k9mr2692160qvx.60.1603808203591;
 Tue, 27 Oct 2020 07:16:43 -0700 (PDT)
Date: Tue, 27 Oct 2020 15:16:00 +0100
In-Reply-To: <20201027141606.426816-1-elver@google.com>
Message-Id: <20201027141606.426816-4-elver@google.com>
Mime-Version: 1.0
References: <20201027141606.426816-1-elver@google.com>
X-Mailer: git-send-email 2.29.0.rc2.309.g374f81d7ae-goog
Subject: [PATCH v5 3/9] arm64, kfence: enable KFENCE for ARM64
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, hdanton@sina.com, mingo@redhat.com, 
	jannh@google.com, Jonathan.Cameron@huawei.com, corbet@lwn.net, 
	iamjoonsoo.kim@lge.com, joern@purestorage.com, keescook@chromium.org, 
	mark.rutland@arm.com, penberg@kernel.org, peterz@infradead.org, 
	sjpark@amazon.com, tglx@linutronix.de, vbabka@suse.cz, will@kernel.org, 
	x86@kernel.org, linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=J7MAP7wf;       spf=pass
 (google.com: domain of 3yyuyxwukcyyov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3yyuYXwUKCYYov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
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

Add architecture specific implementation details for KFENCE and enable
KFENCE for the arm64 architecture. In particular, this implements the
required interface in <asm/kfence.h>.

KFENCE requires that attributes for pages from its memory pool can
individually be set. Therefore, force the entire linear map to be mapped
at page granularity. Doing so may result in extra memory allocated for
page tables in case rodata=full is not set; however, currently
CONFIG_RODATA_FULL_DEFAULT_ENABLED=y is the default, and the common case
is therefore not affected by this change.

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Co-developed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
v5:
* Move generic page allocation code to core.c [suggested by Jann Horn].
* Remove comment about HAVE_ARCH_KFENCE_STATIC_POOL, since we no longer
  support static pools.
* Force page granularity for the linear map [suggested by Mark Rutland].
---
 arch/arm64/Kconfig              |  1 +
 arch/arm64/include/asm/kfence.h | 19 +++++++++++++++++++
 arch/arm64/mm/fault.c           |  4 ++++
 arch/arm64/mm/mmu.c             |  7 ++++++-
 4 files changed, 30 insertions(+), 1 deletion(-)
 create mode 100644 arch/arm64/include/asm/kfence.h

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index f858c352f72a..2f8b32dddd8b 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -135,6 +135,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
 	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
+	select HAVE_ARCH_KFENCE if (!ARM64_16K_PAGES && !ARM64_64K_PAGES)
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
new file mode 100644
index 000000000000..5ac0f599cc9a
--- /dev/null
+++ b/arch/arm64/include/asm/kfence.h
@@ -0,0 +1,19 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+#ifndef __ASM_KFENCE_H
+#define __ASM_KFENCE_H
+
+#include <asm/cacheflush.h>
+
+#define KFENCE_SKIP_ARCH_FAULT_HANDLER "el1_sync"
+
+static inline bool arch_kfence_init_pool(void) { return true; }
+
+static inline bool kfence_protect_page(unsigned long addr, bool protect)
+{
+	set_memory_valid(addr, 1, !protect);
+
+	return true;
+}
+
+#endif /* __ASM_KFENCE_H */
diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index 94c99c1c19e3..ec8ed2943484 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -10,6 +10,7 @@
 #include <linux/acpi.h>
 #include <linux/bitfield.h>
 #include <linux/extable.h>
+#include <linux/kfence.h>
 #include <linux/signal.h>
 #include <linux/mm.h>
 #include <linux/hardirq.h>
@@ -312,6 +313,9 @@ static void __do_kernel_fault(unsigned long addr, unsigned int esr,
 	    "Ignoring spurious kernel translation fault at virtual address %016lx\n", addr))
 		return;
 
+	if (kfence_handle_page_fault(addr))
+		return;
+
 	if (is_el1_permission_fault(addr, esr, regs)) {
 		if (esr & ESR_ELx_WNR)
 			msg = "write to read-only memory";
diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
index 1c0f3e02f731..86be6d1a78ab 100644
--- a/arch/arm64/mm/mmu.c
+++ b/arch/arm64/mm/mmu.c
@@ -1449,7 +1449,12 @@ int arch_add_memory(int nid, u64 start, u64 size,
 {
 	int ret, flags = 0;
 
-	if (rodata_full || debug_pagealloc_enabled())
+	/*
+	 * KFENCE requires linear map to be mapped at page granularity, so that
+	 * it is possible to protect/unprotect single pages in the KFENCE pool.
+	 */
+	if (rodata_full || debug_pagealloc_enabled() ||
+	    IS_ENABLED(CONFIG_KFENCE))
 		flags = NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
 
 	__create_pgd_mapping(swapper_pg_dir, start, __phys_to_virt(start),
-- 
2.29.0.rc2.309.g374f81d7ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201027141606.426816-4-elver%40google.com.
