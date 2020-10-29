Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUMB5P6AKGQE54RIKBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 27B0B29EC9C
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 14:17:06 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id k6sf415751lfg.1
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 06:17:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603977425; cv=pass;
        d=google.com; s=arc-20160816;
        b=b26OZE1uWIJOz3V8sxcRxbW1OO9ok/QHhpHEuLzdBvpj8+Uj1moPwqZIlrCzVypkGp
         8zTCiZm9D5kUKyXyAWI+LXs95YZ7Z77PVBNOkqrqczSIhsdwA0qZ6agx1Q4vwqoiZ1Zx
         ClVOrZRFoW90qk+TeAaqzuCAA77yQGl25lXxqbNwau8Jwy+wfT+RBFehf00diQwAfdhU
         fdHXfZux47uMWz+Wq4qh62R0obYli9Y2Wm2pTUDTwioMBlhepAHr6b3x1lRo+D/nTF7X
         /ffQ+NC9gHMFddXDpsRgpIOODFXk4TVxgSqeehcWiM6S4jkqDHAodeURp9K48KoAB3lF
         TfIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ZZA0MAIO9hdkwtdEg5F9uHxx84oLwrXcfMoPy96Plpg=;
        b=dLpcGxjsbxdNgbGQZoywRIUcMH9HZ8JkYOsZl+t3q1s8jHJ5ZeFEkCFHvWBRlgDzkQ
         fg0PS/XSqBUglK+1KRevKAwGS2E6U2HitRQM7qPGqpc345t7PAz2ihKFI2QNiVrSsA8g
         hFOmEAZu21beT7FjP+f7/1JrtiNe4hFHZ2PwoEl1h5GAt9XVCf0du5yx1k9+czcfjr8e
         r6qatC963YRGruPgr5r9JTKYeFfl9oRo1If6iArjglkxooY7WnYYZIRwRtKfP1Lgg8Bo
         EfkCzTTlvNdKiA3HJYWkFDwWveTODY3FLL3RX+Ys+8E8CxIpjM98qpZKoI+TUEIyUMhd
         JzZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XtCQzmxA;
       spf=pass (google.com: domain of 3z8caxwukcb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3z8CaXwUKCb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZZA0MAIO9hdkwtdEg5F9uHxx84oLwrXcfMoPy96Plpg=;
        b=UTd40gIhMM1KmM9mzy7PioPLChzKW/114jkQhguyfVC+1s44ma5/PGKeFSq6Ov3k02
         0xQ0cU2GHI/n7kDJLzcCepWEfzYUDy+Yg5vWfH3Nu5aalQCrdFcgl5QHY2rZmJ3y7MiG
         67u3aSVzF63WsWWGWblDPgtYH9nfax9z0ABG56fqeVEklZLNXMiK6NFChGLz2zYO/d/s
         VXsnWQm/rk7Ttj5BWxwjBJUVYHu7jqBQ3HAe5M7o2ZJhXIV73yZrMqHyA7kKkSB+xWUz
         TfC/6X/2UPqUzAfFDGF68znlZy6CgaehV1GVdArddwKNwpE7NWzaSy74PEs1v2c8f1y4
         Ll6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZZA0MAIO9hdkwtdEg5F9uHxx84oLwrXcfMoPy96Plpg=;
        b=c5PboFzZcBSBfH0LwyZR0HmRFU/fRDcn4CskMFmYurjcsUTdbi7RUeDkN5342bjEqu
         QNFYU6SwfjwkQNud3PcUJLLKZIZplM7P9ACesBIBjlTov6GeR0HNf1+SRo2koYaGCkhz
         HyC3UQmrxMkM70hXri34K3kWWVRaQsULWGytJ1mFU/IBE6csHXTlASc3Xa8J76czAvuW
         mJ+3hlTdvUMep58qgxlacJAtr5MVdQWDZazQKhFu6tkZsbFhYY+FKn48nHkusuNlmFO+
         0Eqx6ZsFwpu8mbI/VDSW2Hv4S1fHlUGvW2KtsPeA99EirNWwNlc18Monf4xc0ulcL7al
         CNzA==
X-Gm-Message-State: AOAM533U41c02QZ0d2vVbXI3V/3YFYP48yzmJIpP5lGyMMVdm/f19Cgx
	0N9CKyJ+4tXU0y3oKwYvwqc=
X-Google-Smtp-Source: ABdhPJw1m9Dq7TaW8wYBsHKdsBnG4tvjr/OmPVZ7DM5SvWlFxumTSHwg8YP2qA+j+BGxz9Lba0TFnw==
X-Received: by 2002:a2e:6816:: with SMTP id c22mr2023249lja.200.1603977425686;
        Thu, 29 Oct 2020 06:17:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:84c1:: with SMTP id g184ls1621878lfd.3.gmail; Thu, 29
 Oct 2020 06:17:04 -0700 (PDT)
X-Received: by 2002:ac2:55a5:: with SMTP id y5mr1784822lfg.473.1603977424309;
        Thu, 29 Oct 2020 06:17:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603977424; cv=none;
        d=google.com; s=arc-20160816;
        b=NTnqvi0r9Kt6OGrykzZ4E5MbOx++iT3B3wAVcZoBN6JtLOE7oZF4Q6q8f6LzosriHy
         5yhvGSsHNvOlOs3h6vI7hVJ/l6xYajBxTceYqQe3PDBqdBt3qaR89w2VICmz8iAUAMey
         bBDdQRxuMsWspONBOnPzIjBvjoK/hutA/Yv+ngCb65wxpyfmHaNrO4+gz6ieDrTIlEF2
         pH6fn3S05FU0qlBA3TU0bRUwb33xPN4kFmYhPH/z4B5k15RpLKYBbRgw/KI4vvI+iHYe
         WdxQdmUC75iX5QFgAWF6gH9ih2igGRXlL+1BPUS9bkhwW3TtahbEIQVbmvPops+D8H2+
         ZUjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=aekwiuoH1QcAWJM1a9jRrxi/2azRZLfvm2QlRD7DdRg=;
        b=nJ5myZz1PbD6GyBrSUsaqZfAEuKsL94bpDcfc/Kc0mvbi7jv9PJRg7MJGCtumKa9Cd
         WDn1rOdKTlLMYhIbFbaddzks63TV5WpLkF4vFr26hG7yuu0uGSqW5gGAf70bl5jXwVu2
         e1o5POjR4eqBFm2jDVnPcv9VMhXml6FtZPHb3oiIYeuhYCiXmlVoUk6S3K0xuwUnVlJU
         W8JPzhSohLfLreGgvgsEHfDkpbfSYAWJmfkNMLgbFZUCt7Xl7KfKB9afXc0XjlSj2pTG
         JrfOTS/OzH1FJMUyICG1woq7OvpcUufBtMRK86W95vdJGjxuWwySWrNz3KSbEdlGYbwS
         p6Gg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XtCQzmxA;
       spf=pass (google.com: domain of 3z8caxwukcb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3z8CaXwUKCb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id a17si89111ljj.6.2020.10.29.06.17.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 06:17:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3z8caxwukcb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id c204so1100850wmd.5
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 06:17:04 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a1c:f20d:: with SMTP id s13mr4625315wmc.156.1603977423631;
 Thu, 29 Oct 2020 06:17:03 -0700 (PDT)
Date: Thu, 29 Oct 2020 14:16:42 +0100
In-Reply-To: <20201029131649.182037-1-elver@google.com>
Message-Id: <20201029131649.182037-3-elver@google.com>
Mime-Version: 1.0
References: <20201029131649.182037-1-elver@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 2/9] x86, kfence: enable KFENCE for x86
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
 header.i=@google.com header.s=20161025 header.b=XtCQzmxA;       spf=pass
 (google.com: domain of 3z8caxwukcb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3z8CaXwUKCb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201029131649.182037-3-elver%40google.com.
