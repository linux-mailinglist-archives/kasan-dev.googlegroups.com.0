Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZNUQ36QKGQEATKKOZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D49D2A4DA3
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Nov 2020 18:59:02 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id v5sf8147418wrr.0
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Nov 2020 09:59:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604426342; cv=pass;
        d=google.com; s=arc-20160816;
        b=v99JaMfErXKbfmcaQ6UVXPQB8ae/f7PmNM7jBOhVP0JWHD14oNIZl7k1VSAlHi97j0
         FCGDpsGhSvyUXutfpMyCK8I5fffJIUN0dKpCW/dS+DPNYuWlocm9VDNS1awpHvE84ZSN
         YCCLj0gL1Blj6bvzEtZqIng1moz5vYfRQy1tet36+x3xrYnjezuhbDP23pLFh3XIyhnK
         k/UE8e100xIMGPQTvKU+CRelC+MlGpMrLp9L5YFUliBm0T33k4usbPDAOG6009dLgXMC
         ZtlnBbAFFG+ql+n8RyIF6VtitxDcvvltF3nMrYhu2USc/YwBpRY1763OWD75Bo7xaO6+
         sb0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Jf/p8LUPsVgDfiiqMohxSIUPwifYA7cUTF0KIkq7ThE=;
        b=Fcei3/4sMzwgjpYjkH/+PHEIHzjNa9HA4di7hbdbEIIXg7Ti2ruKDPx5pirBv+l/lA
         ZB3vFDz/NLq9BdFgxxXlVANYzhbvVQVRz9js6KVcWk8BLX0N0csKyzBv+yPSfXuZp63S
         FJy0m/0NDWZGCfXPy4tK8gRuSWqRYdgZWVxU/M5ypHpPOe0lcWSUNGskaGP7mzIc7XVR
         1gZBe011ha9Ut/bKA9L9yITV1bWk5yLSGcQkWrncXLjWQwr3/kkMy+tFPWWNBgtX/k5r
         gWtykvl6/+gEzs/idxWflAa86TF4qzipdD8E/co7vSN9MbMZlBN/UkRELW5fFQx1S6+K
         zt4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rAGTbC3O;
       spf=pass (google.com: domain of 3zjqhxwukcsmdkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3ZJqhXwUKCSMDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Jf/p8LUPsVgDfiiqMohxSIUPwifYA7cUTF0KIkq7ThE=;
        b=m4v65Oz412ieqnBqtNN4QDhvCCgp9CNpcA/4yNaz3/U6GMNgIvetLjRp5UWtexgRQE
         /X408TeyFiGdNqNDJnhiRHKyeB1CIAwac/wRmZOR8zMHfK2TlR9oQsFTOQMEePhaRlbN
         b64v44Mpa8TUJsLrvEqEP50jj5X5eqJ/L5PiWoyrtbcST/oGE7y94ktaaoCzf7/6aZuw
         kK+UbZdFHur8Hplg/eSsqpsD9ZVDXb9mHWuDwn8ZBCtT+LxIFSwJrrjQIoN9mhbUdfTz
         EbfSrosA/wVuAg91VrZO9I3+3/Mx1S3B58g5Im+KdNY0XQPnamgxbsUVGRX9Bleo0SWk
         9/MA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Jf/p8LUPsVgDfiiqMohxSIUPwifYA7cUTF0KIkq7ThE=;
        b=oe2DBuwZfY1gWK154xmhcUiBA8xc7Sfo0Md1FetLYh2MIq0q4QdWvpJ07V5qyvVlF3
         n02PPhe4WdBSWT2C1n7t/FLgblMhdA9lb+LwMqXA4+2mq92bYsEheyZLwqP4bLTDEYSF
         X+vi1KJmQsQGoaf9UR1SRA+O9REoulKN/atT0vu4KiKgto4IcDpv3z42CQHvCmle8VBy
         /u12PSE4JwS3IlN0ntP0jdw25sK68K4IbOzxhOh5RGlR+OLh0ngshW4NxHkWNxPuwIh3
         FexRYqUGjsVWwNO/XLteLKzJc1H/8HyZ4RI/aYDDAV5DegIRFtvBEqEzrBdnKLsvMunc
         IeEg==
X-Gm-Message-State: AOAM533CB6ZGlipxwkKBGkIa0EGyuHpsT9JyJkp93b1iUxXycYQYh/Z+
	uC9rzYsFkPK0byygXKr6jfI=
X-Google-Smtp-Source: ABdhPJwX4sXKFGt9EF9g/dJVLNypBFLuGCmcpDwRb5g3MMHaJ/Jw0PLKlNegSba00pNlv1TRPGupmg==
X-Received: by 2002:a1c:2cc2:: with SMTP id s185mr335092wms.77.1604426341887;
        Tue, 03 Nov 2020 09:59:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:a981:: with SMTP id s123ls1430169wme.3.canary-gmail;
 Tue, 03 Nov 2020 09:59:00 -0800 (PST)
X-Received: by 2002:a05:600c:2048:: with SMTP id p8mr316778wmg.165.1604426340899;
        Tue, 03 Nov 2020 09:59:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604426340; cv=none;
        d=google.com; s=arc-20160816;
        b=FFa7qou7+XbzIPVEPQqfOJy4pRpT24rg3dJ02lHdmz7jFLz1PGSXqRPLXeeW8Wm0U4
         Fnd9efoAQFKr+iHgfkJdf2fi0ZJdTK+lJo/XsdQsjXabrXbE57pXLPQRGKBpoZ+rLHvf
         I2nzBcgtDT2AHBjBqJ5UZ4Wfr9A4t0pydORawGj2loc8CSq/EmrwxyDxo9coJnhii44w
         LqFz7bE4WzNTm7l1gAb0GLu6+6EdsoHym7EXJUQ1lDt4tfbJorQkIVYG8Hie0c1QIXni
         W2hX7NqypB9P7Bums2Vtr5rmyVTMtHvUz32lUs7wMr2wWDG7xFp+/tPYjUjw7Cbx2vNG
         yHIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=CjOul1VqaRkscFJ+dD4H59GaMNHUJMUL0L/eCnbi6QE=;
        b=Vrg9DSO7u7sjh5hUyCGamoEkPrFtgvIzDV9EUg1KlrWrnCQ8FitpIsE0Q0X2+dgiyT
         1vHX1jYBX+KTwEW+6/EJXbfwpHToW/xc2qcezT2BXVW8au9z9w1gdtjp2Au4gbsYoSHx
         FM+ToP40C0zDH7yhEv9SzQxPxWBAGDZ+C7kbZV6hU4MADCSAZI8ZGEIwaHrLuzZNbouY
         Tfp7fIPafL459yDO7JQNQb/q/KW/jrFKvTL4/QqpBTPtQJ02D5xcACYnIzZLR3BHBrrc
         M8GcohOMLUgRhp5OYI+cGnYgw792x/sBHQI5kJjnIcZ5Rz4QXq4f7OoJy3y6xYioiVT/
         uVxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rAGTbC3O;
       spf=pass (google.com: domain of 3zjqhxwukcsmdkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3ZJqhXwUKCSMDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id w62si86959wma.1.2020.11.03.09.59.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Nov 2020 09:59:00 -0800 (PST)
Received-SPF: pass (google.com: domain of 3zjqhxwukcsmdkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id p18so5716153ejl.14
        for <kasan-dev@googlegroups.com>; Tue, 03 Nov 2020 09:59:00 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a05:6402:b6e:: with SMTP id
 cb14mr9832146edb.308.1604426340371; Tue, 03 Nov 2020 09:59:00 -0800 (PST)
Date: Tue,  3 Nov 2020 18:58:34 +0100
In-Reply-To: <20201103175841.3495947-1-elver@google.com>
Message-Id: <20201103175841.3495947-3-elver@google.com>
Mime-Version: 1.0
References: <20201103175841.3495947-1-elver@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 2/9] x86, kfence: enable KFENCE for x86
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
 header.i=@google.com header.s=20161025 header.b=rAGTbC3O;       spf=pass
 (google.com: domain of 3zjqhxwukcsmdkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3ZJqhXwUKCSMDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
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
v7:
* Only not-present faults should be handled by kfence [reported by Jann Horn].

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
 arch/x86/mm/fault.c           |  5 +++
 3 files changed, 71 insertions(+)
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
index 82bf37a5c9ec..e42db2836438 100644
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
@@ -725,6 +726,10 @@ no_context(struct pt_regs *regs, unsigned long error_code,
 	if (IS_ENABLED(CONFIG_EFI))
 		efi_recover_from_page_fault(address);
 
+	/* Only not-present faults should be handled by KFENCE. */
+	if (!(error_code & X86_PF_PROT) && kfence_handle_page_fault(address))
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201103175841.3495947-3-elver%40google.com.
