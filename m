Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJUIR76QKGQEU2LJZ3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 159F12A7A58
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 10:21:43 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id d6sf464826ooi.7
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 01:21:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604568102; cv=pass;
        d=google.com; s=arc-20160816;
        b=joMWNb5JIZpJJJHkmv3DfElvuD5zQUKDJ1rQke5RNJFK413Sv0v0rUf6f/9+sgs2b8
         EQK6GCuhFj+vQRSM0ZXItRl3UQGzhm+bREcVfcnBbbYO3tXnbfMoMpGUD3af4em8yKbd
         onvmBCGoLBxsQiRKbri2+Nft1uaIXDeedpN1VcJxHOHKcitF5y1HydLUCObdpAIJKVyS
         u11d3oGjxrmz7WMJM/78DFGoodZLhMc4DSuZmuvUTX758vq8UqlnIhtb13jdg9MZNMTK
         3GUDzg58Cnrq6jxMXOAIAV6fiBo3tiYLGY6WtpSBDAZe9Xu4oFxwMlWdOaClVaqoLMTN
         rJPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=PsSZHfnn/OuZhgfh9/pXUjMNkZBCAO44MIYX9oq84VE=;
        b=0ugRQ+W8DS4Jayx1+rHfzRwv/uClORwbsFNLtkuQvyMoDYEV9DrPjcVoZQlz0vRVBd
         tC6sD1gvG7sc1CtLHaewo4j7598mOrgM/1443GN5XiDCME1Rt3hZuz3/JBg4KM2RIWg8
         6BDzLao9U8y1uoA4eLbp45v+9AbdwJLXD4ZCyPhJAQyVM1cU3IM8H28uDBUYihP4TLPY
         ADPE4ExJHGCkyXMKzA+USrKaBmhRBXmPzdvwYtvbBLlwYtPrQQvBJLLwzctFZA6w2hp8
         gqSVzHWpojmvExOO6xXcEBqU/3OGfeqBV3GM+621AcLlPyuttyosXi++BvqYN9TvhXgX
         Jc1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=t80j7HIk;
       spf=pass (google.com: domain of 3jcsjxwukcuagnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3JcSjXwUKCUAgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PsSZHfnn/OuZhgfh9/pXUjMNkZBCAO44MIYX9oq84VE=;
        b=HlQa18q8rhQwlBRNr9F8Jn5QYbZKKXzqtdpRQZgwEke5Q7UhsnfB40UF+rZHe81ItD
         dMOZvs5sAeJtiWH1LH2dwSbpFWNJDPcdDDMZZNNuvT0HcxGexDPtvKwFQwkDa4sQ5TkA
         XZglSIzN1iltxJhcyfnix7ywAzRV54U6jYa3+JVRDmEjAlTawC0FeEGDG8F6w0tW/axQ
         4ibbOiepE5zrkCYh0cT7vw+OYw1wDMA4fTemrycdEe7JkbbDEoHw2z09IzQKo978MVOx
         BgtL4j9wa20oVse4q9PhPPQpf/ceoPPpLpsR0bno2Nwy+Jw6XSjDDbvaXPlilUopIuBY
         nJPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PsSZHfnn/OuZhgfh9/pXUjMNkZBCAO44MIYX9oq84VE=;
        b=XiQi95j4Yrt4gHabBZK4oau+jL2kPthCVvAD4iDxPUnVTsgIKqDoQNUzY7Jl+53dBQ
         A7yZP7pFJKac8MC7xauAWhuf+z6QxsaYlWDXgDUTlP+iSQolbxgE6FQf/321WFBDQPo4
         rZoAuS93E7N8K/GrxU1S2Zwhka9U4ekUkrKzV2DJrzhubpTaQlXN8NoJLbL7UZ6hzjoj
         4ei5fQPwSyFdRvtI6+vTxQOpwanP38zhYDT3D5jqG+a4taPqPTKRZpgbZkmY/iEEiIi2
         sI+6sbR7wU40QqDilOjTia0b77lJyzqn1gvnvhfCAT0dCPQoTQvprK7N9Md8AjIhC4XO
         u6Hw==
X-Gm-Message-State: AOAM533HUcNS6aY8T0oS0b2egKgtxdsRkG78JZsH7jPAKrhZ5x+/jmhq
	N1dtPb411JYjAi6JbZJA24k=
X-Google-Smtp-Source: ABdhPJzl7KR0M+lmxXJaHOMcd6nWR/qgRB9e8PILRfqw46NyS4JpSgWvf315HzbZUmDZC/i8WSSnKg==
X-Received: by 2002:aca:5113:: with SMTP id f19mr919427oib.41.1604568102103;
        Thu, 05 Nov 2020 01:21:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:14a:: with SMTP id h10ls238915oie.11.gmail; Thu, 05
 Nov 2020 01:21:41 -0800 (PST)
X-Received: by 2002:aca:35d6:: with SMTP id c205mr1018639oia.115.1604568101693;
        Thu, 05 Nov 2020 01:21:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604568101; cv=none;
        d=google.com; s=arc-20160816;
        b=BNNTIEF0sR4kh3VlWbER/HmhffxMwqTjDjb4KnW7lDisPlJg7jIK01avOMV6kJ0ULl
         Zmw1BNZklHVNfbd5IQJIHwiqQP99rV2sIXywzePuxJXKtglGl0aZRk+L84NcVXaUz/2r
         wa+GGhRnuxKMhz66ioc9exYgbZoeFZQY7/8cx5Hk7zz60ovpCnZv/Oy7if19mpuPZKc0
         UMiq6GNgMeFQ0aWn1Sb7jxbOeMSbV9whYIuInP6V5ABw6JFewPpWjRgtSAjdGC+gqb0Q
         4ajjKwKOr5d2zJ6umxTDb8WLnJzVfkcJVOYQpatB722bh6gBHpgW5IwpZuHXMr6l7omU
         /FYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=bFemS5lF24Ay3Ly62yBwjbW4q0e7c3wKlLqU+bgvo/I=;
        b=hazPkssny239nfDAQr3O8XRwom2uD/vkkGfowP6LgVphOg4HsJDshog6ABuhbwWf3U
         Z9etcr3RxevKdX1+jKh79c5jPL99s6cnBdDPfbtNmvHaa7jnHjLOeEvK3q6/h3Cr4uIT
         GDkfVlhzdRm3JUdUgoSRkdGt3/1/5e9GM0t0uUCphv1Rmi/fHV5CWLEBfaxIXpkpwGKD
         WluDJsrjwIe4rnBg59VJiEizb3vJDK8UFpSB2A7u7V3v28ewO5icyVuJHpeZrn1a+rXQ
         5+f6vMOiGfKBId4NiLqEq3HQk55Y+reBb5hbT9OB0PbZZd6owkPscMt7ivQJX/UWS6VU
         +OTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=t80j7HIk;
       spf=pass (google.com: domain of 3jcsjxwukcuagnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3JcSjXwUKCUAgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id p17si73729oot.0.2020.11.05.01.21.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Nov 2020 01:21:41 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jcsjxwukcuagnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id s9so497334qvt.13
        for <kasan-dev@googlegroups.com>; Thu, 05 Nov 2020 01:21:41 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a0c:b44a:: with SMTP id e10mr1321540qvf.4.1604568101175;
 Thu, 05 Nov 2020 01:21:41 -0800 (PST)
Date: Thu,  5 Nov 2020 10:21:33 +0100
Message-Id: <20201105092133.2075331-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH] kfence: Use pt_regs to generate stack trace on faults
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, jannh@google.com, 
	mark.rutland@arm.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, x86@kernel.org, 
	linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=t80j7HIk;       spf=pass
 (google.com: domain of 3jcsjxwukcuagnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3JcSjXwUKCUAgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
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

Instead of removing the fault handling portion of the stack trace based
on the fault handler's name, just use struct pt_regs directly.

Change kfence_handle_page_fault() to take a struct pt_regs, and plumb it
through to kfence_report_error() for out-of-bounds, use-after-free, or
invalid access errors, where pt_regs is used to generate the stack
trace.

If the kernel is a DEBUG_KERNEL, also show registers for more
information.

Suggested-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 arch/arm64/include/asm/kfence.h |  2 --
 arch/arm64/mm/fault.c           |  2 +-
 arch/x86/include/asm/kfence.h   |  6 ----
 arch/x86/mm/fault.c             |  2 +-
 include/linux/kfence.h          |  5 +--
 mm/kfence/core.c                | 10 +++---
 mm/kfence/kfence.h              |  4 +--
 mm/kfence/report.c              | 63 +++++++++++++++++++--------------
 8 files changed, 48 insertions(+), 46 deletions(-)

diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
index 5ac0f599cc9a..6c0afeeab635 100644
--- a/arch/arm64/include/asm/kfence.h
+++ b/arch/arm64/include/asm/kfence.h
@@ -5,8 +5,6 @@
 
 #include <asm/cacheflush.h>
 
-#define KFENCE_SKIP_ARCH_FAULT_HANDLER "el1_sync"
-
 static inline bool arch_kfence_init_pool(void) { return true; }
 
 static inline bool kfence_protect_page(unsigned long addr, bool protect)
diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index 2d60204b4ed2..183d1e6dd9e0 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -323,7 +323,7 @@ static void __do_kernel_fault(unsigned long addr, unsigned int esr,
 	} else if (addr < PAGE_SIZE) {
 		msg = "NULL pointer dereference";
 	} else {
-		if (kfence_handle_page_fault(addr))
+		if (kfence_handle_page_fault(addr, regs))
 			return;
 
 		msg = "paging request";
diff --git a/arch/x86/include/asm/kfence.h b/arch/x86/include/asm/kfence.h
index beeac105dae7..2f3f877a7a5c 100644
--- a/arch/x86/include/asm/kfence.h
+++ b/arch/x86/include/asm/kfence.h
@@ -11,12 +11,6 @@
 #include <asm/set_memory.h>
 #include <asm/tlbflush.h>
 
-/*
- * The page fault handler entry function, up to which the stack trace is
- * truncated in reports.
- */
-#define KFENCE_SKIP_ARCH_FAULT_HANDLER "asm_exc_page_fault"
-
 /* Force 4K pages for __kfence_pool. */
 static inline bool arch_kfence_init_pool(void)
 {
diff --git a/arch/x86/mm/fault.c b/arch/x86/mm/fault.c
index e42db2836438..53d732161b4f 100644
--- a/arch/x86/mm/fault.c
+++ b/arch/x86/mm/fault.c
@@ -727,7 +727,7 @@ no_context(struct pt_regs *regs, unsigned long error_code,
 		efi_recover_from_page_fault(address);
 
 	/* Only not-present faults should be handled by KFENCE. */
-	if (!(error_code & X86_PF_PROT) && kfence_handle_page_fault(address))
+	if (!(error_code & X86_PF_PROT) && kfence_handle_page_fault(address, regs))
 		return;
 
 oops:
diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index ed2d48acdafe..98a97f9d43cd 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -171,6 +171,7 @@ static __always_inline __must_check bool kfence_free(void *addr)
 /**
  * kfence_handle_page_fault() - perform page fault handling for KFENCE pages
  * @addr: faulting address
+ * @regs: current struct pt_regs (can be NULL, but shows full stack trace)
  *
  * Return:
  * * false - address outside KFENCE pool,
@@ -181,7 +182,7 @@ static __always_inline __must_check bool kfence_free(void *addr)
  * cases KFENCE prints an error message and marks the offending page as
  * present, so that the kernel can proceed.
  */
-bool __must_check kfence_handle_page_fault(unsigned long addr);
+bool __must_check kfence_handle_page_fault(unsigned long addr, struct pt_regs *regs);
 
 #else /* CONFIG_KFENCE */
 
@@ -194,7 +195,7 @@ static inline size_t kfence_ksize(const void *addr) { return 0; }
 static inline void *kfence_object_start(const void *addr) { return NULL; }
 static inline void __kfence_free(void *addr) { }
 static inline bool __must_check kfence_free(void *addr) { return false; }
-static inline bool __must_check kfence_handle_page_fault(unsigned long addr) { return false; }
+static inline bool __must_check kfence_handle_page_fault(unsigned long addr, struct pt_regs *regs) { return false; }
 
 #endif
 
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 9d597013cd5d..9358f42a9a9e 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -212,7 +212,7 @@ static inline bool check_canary_byte(u8 *addr)
 		return true;
 
 	atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
-	kfence_report_error((unsigned long)addr, addr_to_metadata((unsigned long)addr),
+	kfence_report_error((unsigned long)addr, NULL, addr_to_metadata((unsigned long)addr),
 			    KFENCE_ERROR_CORRUPTION);
 	return false;
 }
@@ -351,7 +351,7 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
 	if (meta->state != KFENCE_OBJECT_ALLOCATED || meta->addr != (unsigned long)addr) {
 		/* Invalid or double-free, bail out. */
 		atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
-		kfence_report_error((unsigned long)addr, meta, KFENCE_ERROR_INVALID_FREE);
+		kfence_report_error((unsigned long)addr, NULL, meta, KFENCE_ERROR_INVALID_FREE);
 		raw_spin_unlock_irqrestore(&meta->lock, flags);
 		return;
 	}
@@ -752,7 +752,7 @@ void __kfence_free(void *addr)
 		kfence_guarded_free(addr, meta, false);
 }
 
-bool kfence_handle_page_fault(unsigned long addr)
+bool kfence_handle_page_fault(unsigned long addr, struct pt_regs *regs)
 {
 	const int page_index = (addr - (unsigned long)__kfence_pool) / PAGE_SIZE;
 	struct kfence_metadata *to_report = NULL;
@@ -815,11 +815,11 @@ bool kfence_handle_page_fault(unsigned long addr)
 
 out:
 	if (to_report) {
-		kfence_report_error(addr, to_report, error_type);
+		kfence_report_error(addr, regs, to_report, error_type);
 		raw_spin_unlock_irqrestore(&to_report->lock, flags);
 	} else {
 		/* This may be a UAF or OOB access, but we can't be sure. */
-		kfence_report_error(addr, NULL, KFENCE_ERROR_INVALID);
+		kfence_report_error(addr, regs, NULL, KFENCE_ERROR_INVALID);
 	}
 
 	return kfence_unprotect(addr); /* Unprotect and let access proceed. */
diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
index f115aabc2052..fa3579d03089 100644
--- a/mm/kfence/kfence.h
+++ b/mm/kfence/kfence.h
@@ -99,8 +99,8 @@ enum kfence_error_type {
 	KFENCE_ERROR_INVALID_FREE,	/* Invalid free. */
 };
 
-void kfence_report_error(unsigned long address, const struct kfence_metadata *meta,
-			 enum kfence_error_type type);
+void kfence_report_error(unsigned long address, struct pt_regs *regs,
+			 const struct kfence_metadata *meta, enum kfence_error_type type);
 
 void kfence_print_object(struct seq_file *seq, const struct kfence_metadata *meta);
 
diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index 0fdaa3ddf1b4..4dedc2ff8f28 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -5,6 +5,7 @@
 #include <linux/kernel.h>
 #include <linux/lockdep.h>
 #include <linux/printk.h>
+#include <linux/sched/debug.h>
 #include <linux/seq_file.h>
 #include <linux/stacktrace.h>
 #include <linux/string.h>
@@ -36,7 +37,6 @@ static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries
 {
 	char buf[64];
 	int skipnr, fallback = 0;
-	bool is_access_fault = false;
 
 	if (type) {
 		/* Depending on error type, find different stack entries. */
@@ -44,8 +44,12 @@ static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries
 		case KFENCE_ERROR_UAF:
 		case KFENCE_ERROR_OOB:
 		case KFENCE_ERROR_INVALID:
-			is_access_fault = true;
-			break;
+			/*
+			 * kfence_handle_page_fault() may be called with pt_regs
+			 * set to NULL; in that case we'll simply show the full
+			 * stack trace.
+			 */
+			return 0;
 		case KFENCE_ERROR_CORRUPTION:
 		case KFENCE_ERROR_INVALID_FREE:
 			break;
@@ -55,26 +59,21 @@ static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries
 	for (skipnr = 0; skipnr < num_entries; skipnr++) {
 		int len = scnprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[skipnr]);
 
-		if (is_access_fault) {
-			if (!strncmp(buf, KFENCE_SKIP_ARCH_FAULT_HANDLER, len))
-				goto found;
-		} else {
-			if (str_has_prefix(buf, "kfence_") || str_has_prefix(buf, "__kfence_") ||
-			    !strncmp(buf, "__slab_free", len)) {
-				/*
-				 * In case of tail calls from any of the below
-				 * to any of the above.
-				 */
-				fallback = skipnr + 1;
-			}
-
-			/* Also the *_bulk() variants by only checking prefixes. */
-			if (str_has_prefix(buf, "kfree") ||
-			    str_has_prefix(buf, "kmem_cache_free") ||
-			    str_has_prefix(buf, "__kmalloc") ||
-			    str_has_prefix(buf, "kmem_cache_alloc"))
-				goto found;
+		if (str_has_prefix(buf, "kfence_") || str_has_prefix(buf, "__kfence_") ||
+		    !strncmp(buf, "__slab_free", len)) {
+			/*
+			 * In case of tail calls from any of the below
+			 * to any of the above.
+			 */
+			fallback = skipnr + 1;
 		}
+
+		/* Also the *_bulk() variants by only checking prefixes. */
+		if (str_has_prefix(buf, "kfree") ||
+		    str_has_prefix(buf, "kmem_cache_free") ||
+		    str_has_prefix(buf, "__kmalloc") ||
+		    str_has_prefix(buf, "kmem_cache_alloc"))
+			goto found;
 	}
 	if (fallback < num_entries)
 		return fallback;
@@ -152,13 +151,20 @@ static void print_diff_canary(unsigned long address, size_t bytes_to_show,
 	pr_cont(" ]");
 }
 
-void kfence_report_error(unsigned long address, const struct kfence_metadata *meta,
-			 enum kfence_error_type type)
+void kfence_report_error(unsigned long address, struct pt_regs *regs,
+			 const struct kfence_metadata *meta, enum kfence_error_type type)
 {
 	unsigned long stack_entries[KFENCE_STACK_DEPTH] = { 0 };
-	int num_stack_entries = stack_trace_save(stack_entries, KFENCE_STACK_DEPTH, 1);
-	int skipnr = get_stack_skipnr(stack_entries, num_stack_entries, &type);
 	const ptrdiff_t object_index = meta ? meta - kfence_metadata : -1;
+	int num_stack_entries;
+	int skipnr = 0;
+
+	if (regs) {
+		num_stack_entries = stack_trace_save_regs(regs, stack_entries, KFENCE_STACK_DEPTH, 0);
+	} else {
+		num_stack_entries = stack_trace_save(stack_entries, KFENCE_STACK_DEPTH, 1);
+		skipnr = get_stack_skipnr(stack_entries, num_stack_entries, &type);
+	}
 
 	/* Require non-NULL meta, except if KFENCE_ERROR_INVALID. */
 	if (WARN_ON(type != KFENCE_ERROR_INVALID && !meta))
@@ -222,7 +228,10 @@ void kfence_report_error(unsigned long address, const struct kfence_metadata *me
 
 	/* Print report footer. */
 	pr_err("\n");
-	dump_stack_print_info(KERN_ERR);
+	if (IS_ENABLED(CONFIG_DEBUG_KERNEL) && regs)
+		show_regs(regs);
+	else
+		dump_stack_print_info(KERN_ERR);
 	pr_err("==================================================================\n");
 
 	lockdep_on();
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201105092133.2075331-1-elver%40google.com.
