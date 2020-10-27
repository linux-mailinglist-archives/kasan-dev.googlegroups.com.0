Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSWX4D6AKGQEHJ26J7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 867E129B01D
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 15:16:43 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id a4sf905695ljb.1
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 07:16:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603808203; cv=pass;
        d=google.com; s=arc-20160816;
        b=XGBJHOWNXWqW8xZp92otYp8dGoeINyVMhzmdIdivx9VZx2IOW+mS5w6ta35/Usa+7o
         mk9huBKLkj4gq7vJ0k2VN1AJEAyDq1NeWy7BApGWZ4T2myshl7IjBz88wKfKp/O1Ay7B
         3ExAlgAFC/jjvJpVM0WgGyWHX+/dDsJ3gVyxixdmmh/d7mHNdn4A3JQl3sWmYb0rOExX
         16L/E5jlwlTJyOGKrDJIs2TwnqfznQVSunnETgPUvJbn2UNDs3cL5+HW9oYEI7lvBxZO
         CyRXxVjgfEvyCPWtTQaQ3pF+2xHIvmEmm6+MntZwPNMCxOBISe9sGLmMidhl7Kjd417c
         PZUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=9EnX/JlNjx7zVEnGcqpSL76ip3A2ZSr8Ytf5HYEXDMk=;
        b=gSfOwwtt/AW0r2LZs7fl4MT/X54w0redakWRjE48rlkYAPdw9Q3KiIGJG2+dfcZPU6
         EjVO52KJ/qUG+MHBe+G89YpZfz8jk8h6RiReVhZ+1Q2aTAXfoK92ecGFAxiDyoK8+nNV
         lqFNydp2ceBLbFaM5ARnLToMoZYVYSfFLOQBAZ28HdAoz4HZUIn82kLuFrUE09ahCFaN
         J7LmiYmyhg6e0bDSIhHMekjfHhvpu2tRnPIU0wYmwNd6GjIXe0+QHiZUgsUYjVvVti1Q
         jQ96P4FBaejYsgtVI5ymNPU76KDghG2kN5HfoTs6/BnC3EAcwPcBOLW3ZyV5ncFFZqSm
         iccQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lqYJFavI;
       spf=pass (google.com: domain of 3ysuyxwukcyqmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ySuYXwUKCYQmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9EnX/JlNjx7zVEnGcqpSL76ip3A2ZSr8Ytf5HYEXDMk=;
        b=HqkVqQVrlOmc6zAzpMELhAxn+zND4wjHXMeZLcSw45qRau5qlx7HT4cPKTvEj5Dpp+
         5lIj1QrUWUEfuxnCNi6nTsgzUoFZLZUxcSdhOcrx22w9vAyQW+SX4HMeIPnxM1Oz/D5s
         gCIkEjbyi/O1ptMBFgGCtmeHoGnBN5/dVSh0zuYN11msvBzNVltBQioJgK+wDk4QfAda
         5R/bKAcTIMNbs0xgoDih92+2Fn3sGbB4GAz6skG0BtSphh6x+lCoL+dVSC62yeR4ctzL
         Sh9TbaXlxIhELZxQiCIdpN0J8dh/Y+fZ8M6XGdNNdQDH/kzFUb1sKrEIURvNZfuYVU36
         Z4rg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9EnX/JlNjx7zVEnGcqpSL76ip3A2ZSr8Ytf5HYEXDMk=;
        b=Rl3XTQ40EWYes3VJR9gln/IXd+gJ4SFC9nJlvBNAyYQaYOKPXWP+vIqCn5Vr9M72Op
         OX90JwtI4gSOxfLFZzBkGCHPVzLZNYHS6Vo5gez0H6NYovXrvZLK5DwSLqM9jz0PYlxr
         98aoH5uKtZTKfaAvqzJT8QQIp96XQIRkyjpkfEsLGfOK67HfonLfGRh+FORc2IqnafeV
         tiQMOGSEUxqHl+t1Wh3N/6BxlrDjlxTJbmk+jcnrli1GMncX34b4KRbOWzi7TNuks+Cz
         hrWv3IbrZSuLkAMcIcmcxJlYhKuZkvV0actvwqKO0WxZ/gUf0thkh3vMaQEXhAEahw85
         bNpA==
X-Gm-Message-State: AOAM530z6efF+HGTq5Kp4KaKl156GMIZ6aZfskaRIXVxkAvctueLfYm1
	HGEJAE7b9NmS5uyfauSGJto=
X-Google-Smtp-Source: ABdhPJyY1x+W550A9p8JZ+RdyFU8t98sfs9fPhJJHaHh2f6Mp2E1FjTIZjLm8Dko60X55MJ9fhKsYA==
X-Received: by 2002:a19:58d:: with SMTP id 135mr968421lff.139.1603808203004;
        Tue, 27 Oct 2020 07:16:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7a0e:: with SMTP id v14ls362984ljc.7.gmail; Tue, 27 Oct
 2020 07:16:41 -0700 (PDT)
X-Received: by 2002:a2e:8985:: with SMTP id c5mr1316135lji.406.1603808201796;
        Tue, 27 Oct 2020 07:16:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603808201; cv=none;
        d=google.com; s=arc-20160816;
        b=0VL1DEOG/bdybw84cnasuYIdIjnvLW4YXXE971CdsLYG1VfbPDiWYDEDyQze1QGjHj
         a33rLMT6SPT6FC5AApuTC7zYxpxj9enpDhiKDSKKTrUoTyCowncNME3MfIIY/X/G3c0X
         sGMoIV3VNiMYKCaig350V089Ib1IvAnvSMWtKCXl3wUJ5CLYYwD8llkNt34gS4Zr/pnt
         xaY4T3+5FlcofxUujJe00teOM/t/vGCADANBPxZe9Tl5ks6vqYwnQ5EFh3BCJaY7MKOI
         jUWU3hq5iZ1/vrws1W5mW3TIsyrZ1NxYV9iQhb81mkUkGr6y6M5YoWO7alitCDfdGS8o
         PQIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=amWdP6FV7IwvIOgrtWK6Wa5LLRx0C6kQ2UzTi3lX/Ww=;
        b=hP/CzFEkvA77y9/hFqW2QS7T2SIjYl+qTaVXu2+Ph2T72ZptLHdTCdoL8FXK+O52vm
         3YjHe+4aMAaHuRuCx67tnXIEhZCGUuKy+236eCcNvWHpi4AnbanfXTz81ED7LhiGmIZQ
         +DknpPg1/cugq3XKuQOmjY4vyyMZFQhf3pr8yA+h3p25ya3bY7nbpoY6l66a9Jteti80
         TQIcYsPaBF3GOxg4n+L3XMnWg7FxbFy4yUq3UObTkbtq7eUrWS8zpsWqcXsn1+wcNT67
         0ludqYmcsYyjmZ1tyqmi8aQXmDJ1NwWHEutZpbRl+TYQDbr2Kfe0CGI2pZbXxBg3NDcU
         umKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lqYJFavI;
       spf=pass (google.com: domain of 3ysuyxwukcyqmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ySuYXwUKCYQmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id h4si53420ljl.1.2020.10.27.07.16.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Oct 2020 07:16:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ysuyxwukcyqmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id c204so641794wmd.5
        for <kasan-dev@googlegroups.com>; Tue, 27 Oct 2020 07:16:41 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:adf:eac6:: with SMTP id o6mr3348520wrn.117.1603808201007;
 Tue, 27 Oct 2020 07:16:41 -0700 (PDT)
Date: Tue, 27 Oct 2020 15:15:59 +0100
In-Reply-To: <20201027141606.426816-1-elver@google.com>
Message-Id: <20201027141606.426816-3-elver@google.com>
Mime-Version: 1.0
References: <20201027141606.426816-1-elver@google.com>
X-Mailer: git-send-email 2.29.0.rc2.309.g374f81d7ae-goog
Subject: [PATCH v5 2/9] x86, kfence: enable KFENCE for x86
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
 header.i=@google.com header.s=20161025 header.b=lqYJFavI;       spf=pass
 (google.com: domain of 3ysuyxwukcyqmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ySuYXwUKCYQmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
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

From: Alexander Potapenko <glider@google.com>

Add architecture specific implementation details for KFENCE and enable
KFENCE for the x86 architecture. In particular, this implements the
required interface in <asm/kfence.h> for setting up the pool and
providing helper functions for protecting and unprotecting pages.

For x86, we need to ensure that the pool uses 4K pages, which is done
using the set_memory_4k() helper function.

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Co-developed-by: Marco Elver <elver@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
v5:
* MAJOR CHANGE: Switch to the memblock_alloc'd pool. Running benchmarks
  with the newly optimized is_kfence_address(), no difference between
  baseline and KFENCE is observed.
* Suggested by Jann Horn:
  * Move x86 kfence_handle_page_fault before oops handling.
  * WARN_ON in kfence_protect_page if non-4K pages.
  * Better comments for x86 kfence_protect_page.

v4:
* Define __kfence_pool_attrs.
---
 arch/x86/Kconfig              |  1 +
 arch/x86/include/asm/kfence.h | 65 +++++++++++++++++++++++++++++++++++
 arch/x86/mm/fault.c           |  4 +++
 3 files changed, 70 insertions(+)
 create mode 100644 arch/x86/include/asm/kfence.h

diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index f6946b81f74a..c9ec6b5ba358 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -144,6 +144,7 @@ config X86
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN			if X86_64
 	select HAVE_ARCH_KASAN_VMALLOC		if X86_64
+	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS		if MMU
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS	if MMU && COMPAT
diff --git a/arch/x86/include/asm/kfence.h b/arch/x86/include/asm/kfence.h
new file mode 100644
index 000000000000..beeac105dae7
--- /dev/null
+++ b/arch/x86/include/asm/kfence.h
@@ -0,0 +1,65 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+#ifndef _ASM_X86_KFENCE_H
+#define _ASM_X86_KFENCE_H
+
+#include <linux/bug.h>
+#include <linux/kfence.h>
+
+#include <asm/pgalloc.h>
+#include <asm/pgtable.h>
+#include <asm/set_memory.h>
+#include <asm/tlbflush.h>
+
+/*
+ * The page fault handler entry function, up to which the stack trace is
+ * truncated in reports.
+ */
+#define KFENCE_SKIP_ARCH_FAULT_HANDLER "asm_exc_page_fault"
+
+/* Force 4K pages for __kfence_pool. */
+static inline bool arch_kfence_init_pool(void)
+{
+	unsigned long addr;
+
+	for (addr = (unsigned long)__kfence_pool; is_kfence_address((void *)addr);
+	     addr += PAGE_SIZE) {
+		unsigned int level;
+
+		if (!lookup_address(addr, &level))
+			return false;
+
+		if (level != PG_LEVEL_4K)
+			set_memory_4k(addr, 1);
+	}
+
+	return true;
+}
+
+/* Protect the given page and flush TLB. */
+static inline bool kfence_protect_page(unsigned long addr, bool protect)
+{
+	unsigned int level;
+	pte_t *pte = lookup_address(addr, &level);
+
+	if (WARN_ON(!pte || level != PG_LEVEL_4K))
+		return false;
+
+	/*
+	 * We need to avoid IPIs, as we may get KFENCE allocations or faults
+	 * with interrupts disabled. Therefore, the below is best-effort, and
+	 * does not flush TLBs on all CPUs. We can tolerate some inaccuracy;
+	 * lazy fault handling takes care of faults after the page is PRESENT.
+	 */
+
+	if (protect)
+		set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
+	else
+		set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
+
+	/* Flush this CPU's TLB. */
+	flush_tlb_one_kernel(addr);
+	return true;
+}
+
+#endif /* _ASM_X86_KFENCE_H */
diff --git a/arch/x86/mm/fault.c b/arch/x86/mm/fault.c
index 82bf37a5c9ec..380638745f42 100644
--- a/arch/x86/mm/fault.c
+++ b/arch/x86/mm/fault.c
@@ -9,6 +9,7 @@
 #include <linux/kdebug.h>		/* oops_begin/end, ...		*/
 #include <linux/extable.h>		/* search_exception_tables	*/
 #include <linux/memblock.h>		/* max_low_pfn			*/
+#include <linux/kfence.h>		/* kfence_handle_page_fault	*/
 #include <linux/kprobes.h>		/* NOKPROBE_SYMBOL, ...		*/
 #include <linux/mmiotrace.h>		/* kmmio_handler, ...		*/
 #include <linux/perf_event.h>		/* perf_sw_event		*/
@@ -725,6 +726,9 @@ no_context(struct pt_regs *regs, unsigned long error_code,
 	if (IS_ENABLED(CONFIG_EFI))
 		efi_recover_from_page_fault(address);
 
+	if (kfence_handle_page_fault(address))
+		return;
+
 oops:
 	/*
 	 * Oops. The kernel tried to access some bad page. We'll have to
-- 
2.29.0.rc2.309.g374f81d7ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201027141606.426816-3-elver%40google.com.
