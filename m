Return-Path: <kasan-dev+bncBDX4HWEMTEBRBNGE3H5QKGQECMNUVSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id CD725280B14
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:11:49 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id k13sf79442pfh.4
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:11:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593908; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xny+EAIQ+TjI/MG/jXCpthF+yDL47oXl+UT0SoP956hNfv1SfQnsYAuRaBvKv78qBx
         N8H82NrOMpvRjhXJ39IMx0EyBUflxdMUS5LMeCyAgA9dx5011qv6yoH+dPAYR+UEVcJP
         TO3fOPdrw+COKFhgbBo0OiLXp9U6br8Pr9qvhncUCYeIbQRcyMOVeNICGvbgPsmQqvsl
         2i/lSgxQBbB1iTb1NkU31rFkDy6wei2B1T9uIenMV/9XznL2r3bbJyTLf45UnH2WGGms
         IEC2xXUEW1Q1qJF0bKWSRP0Lq2Jf+ns8L0JBaKvgfCMTQ20jXM/P6QK770X/aTs6I9qd
         HkCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=4WZeZkg2afgNsrhdy+sDKxfNJleyPUeEf35JeG+zTaI=;
        b=h6pZwGiC5L8ux6Q5LaTbFW9RBp36NZmEZFVkmtgnwLAl9wSYCXgo7n1j9jk3+mXDZ5
         VoxdbXeMBdO7Q0dLzJ2PT9cFzZ1WWMKNnZ8nTvxYxVbLiw1KL6rcS+2ly5Nh+hyXGjKM
         qQEfsuCS8eNe4sVJQU22DdFqe+bBdPAqZUjCxzO5MUA9SFz19BxDLolCWgWAZLbIGDYh
         aOsCnemNqJ8FuUdQqo+atuHSHljhae/pqI2s/iluh7ffQo1fWNCnr986STSwRcnd97EK
         1PBB7dKTf53ngXSDbkLwRKSVz0+70AQqASm+zSLK0/dVHS/gJ5KlgLIyKIopv7y+R2LG
         isQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oXpZiZjC;
       spf=pass (google.com: domain of 3m2j2xwokcdiyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3M2J2XwoKCdIyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4WZeZkg2afgNsrhdy+sDKxfNJleyPUeEf35JeG+zTaI=;
        b=ie8dJIYpAXJSElMjc4e9i/11NqFw2qJSGPW5NwzDZfN0wPrwLFoMEczICrGxaC/b11
         9OJRWm05mldgO385EC8Oxn4JhmU1oDH8KqMiXg92xBXiYSjMmQaHvGwp/uyC4zbniyIo
         gme/8w0bfWzNinYSIwYTzXkRJlGlWXV0AwL1tsjWu+apyRc2RSP+lt9K9G0BJ6jM8N1K
         qQ7MGcGRBAZFzV6sX0uWyHNMrAitBtRN8HQ5MomvU9V96/LhcwD7uhOFhCUnP/f/BWJx
         itv3dlYRaEJHmDhrdLOckuc/vSTM3kTWZXa7sNZbq5bk5vdstVTCpNMjFUhVXK6lV5Ir
         QIIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4WZeZkg2afgNsrhdy+sDKxfNJleyPUeEf35JeG+zTaI=;
        b=LhMADzPWlp6om8JnEFqvFExcc9Mw2ZNKK1/h/9hkmmO++WTfQ0e3SGY0JxVmoKKCEz
         Y7tH/ILZNnk1T55fuRzjdABIN31/KqfwSnvAQWjImbfslVQFNAotveBabIZhJmr0pn1T
         qSKYoE/M5Z3CA5ALRHJS6U6YmaceNZqAXIthNNSHuH891uQvCZ5aRWEwUu/vnRSmD3vc
         hFnONU/bmJtYOWyhWdC0l+5fvxzr6FUR2m5lsFAlEfhjozyDBCDjKVYNBHnlZfWxUs7U
         fGjXPfGhIK/r7z1FQ0GXTUwGrKSdgxfm5osTe+BvPzClv6EZFfDzIT9YFWZOyUErMLU3
         0HTw==
X-Gm-Message-State: AOAM533SJZnR4YXCYcubVTKpT8dKB6CkjwNaWBEjAFcnVTmZG7Q584mW
	vH7QFv0YrV6ll7tfoUnWeJE=
X-Google-Smtp-Source: ABdhPJx+dkfysq4BNCVvj+J/QO2oq0w9v2L/YSUDA45r+7BT1ILF3PQRI4O4bFFfYkhaFnBLEsUzkQ==
X-Received: by 2002:aa7:99c2:0:b029:142:440b:fa28 with SMTP id v2-20020aa799c20000b0290142440bfa28mr10107292pfi.30.1601593908526;
        Thu, 01 Oct 2020 16:11:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:96cd:: with SMTP id h13ls2816981pfq.0.gmail; Thu, 01 Oct
 2020 16:11:48 -0700 (PDT)
X-Received: by 2002:aa7:85d4:0:b029:142:4339:42ca with SMTP id z20-20020aa785d40000b0290142433942camr9278863pfn.5.1601593907939;
        Thu, 01 Oct 2020 16:11:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593907; cv=none;
        d=google.com; s=arc-20160816;
        b=veZThWk/1O51HUW7nAjxlwRvB9SCWvlnQl0D2cNCPyqn0rqwO55yNGs/Nui1ufovb0
         UjZYmN5eSNcdGcfV3QODX5+LcbfAIZJfchFhGRwXxJz30LkjficeChYlQoB2j9e1dmGd
         4Fyc3jk7xhyhqGqhEuBH/DYGher8W9EPJkBXDiQifpVXd1iGkQq11HltmqIrjO8SGOkG
         7KTqBHoxwhgqQ2TjpuDTdXnolOMdJc6JWi1UZ2R1TFa/yYJdCk6FRw776+KtXU2vWiuj
         6wfLgBb/t6Ux6zrwXtoztIASogcYpHAZskRdBBngmATk9Me53ZZgVCgCw36cpbtI8+vq
         OXTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Xi5PXBDKSbfXQXlBbsevZkyVwMa3nBoVlbAwrLjnULM=;
        b=tcD0VxDQT1v/j/UBWHPI/6f44pZqMMTjfQu1bNSdsqNLzCY6Xzi0T260Woxf+wzrVs
         dkjHDcHSbvPzP5By2KxzCpPUB4peQWyS56435G6NxCODn1Xa7oVTvFOX+ZOxFgaJ1ln9
         Ju5LLkMcHE+fmoNaBaqizXcj1eltrSNEiAjSPKvFr9U/Um4Uj/jvf6UP20FouoVOibwN
         6ZpQJLOARULYvSH/7HdQphspXgUoh1i03Kvnwx1gWnsPtuEqXp8s8lBoqxoveSHwQBvQ
         2GxuSlqOV/GDd3A1BmrgsC/j0qZEt76+8+XIfoUocf/utc+ffthZQj2aPQ5oM27wI9jo
         dMsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oXpZiZjC;
       spf=pass (google.com: domain of 3m2j2xwokcdiyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3M2J2XwoKCdIyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id f6si393866pgk.3.2020.10.01.16.11.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:11:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3m2j2xwokcdiyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id p20so252809qvl.4
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:11:47 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:57cc:: with SMTP id
 y12mr10157699qvx.48.1601593907080; Thu, 01 Oct 2020 16:11:47 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:27 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <1466ded7cb14ef17258b12a17129d2ca62f81911.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 26/39] arm64: mte: Add in-kernel tag fault handler
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=oXpZiZjC;       spf=pass
 (google.com: domain of 3m2j2xwokcdiyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3M2J2XwoKCdIyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

From: Vincenzo Frascino <vincenzo.frascino@arm.com>

Add the implementation of the in-kernel fault handler.

When a tag fault happens on a kernel address:
* MTE is disabled on the current CPU,
* the execution continues.

When a tag fault happens on a user address:
* the kernel executes do_bad_area() and panics.

The tag fault handler for kernel addresses is currently empty and will be
filled in by a future commit.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I9b8aa79567f7c45f4d6a1290efcf34567e620717
---
 arch/arm64/include/asm/uaccess.h | 23 +++++++++++++++++++
 arch/arm64/mm/fault.c            | 38 +++++++++++++++++++++++++++++++-
 2 files changed, 60 insertions(+), 1 deletion(-)

diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
index 991dd5f031e4..c7fff8daf2a7 100644
--- a/arch/arm64/include/asm/uaccess.h
+++ b/arch/arm64/include/asm/uaccess.h
@@ -200,13 +200,36 @@ do {									\
 				CONFIG_ARM64_PAN));			\
 } while (0)
 
+/*
+ * The Tag Check Flag (TCF) mode for MTE is per EL, hence TCF0
+ * affects EL0 and TCF affects EL1 irrespective of which TTBR is
+ * used.
+ * The kernel accesses TTBR0 usually with LDTR/STTR instructions
+ * when UAO is available, so these would act as EL0 accesses using
+ * TCF0.
+ * However futex.h code uses exclusives which would be executed as
+ * EL1, this can potentially cause a tag check fault even if the
+ * user disables TCF0.
+ *
+ * To address the problem we set the PSTATE.TCO bit in uaccess_enable()
+ * and reset it in uaccess_disable().
+ *
+ * The Tag check override (TCO) bit disables temporarily the tag checking
+ * preventing the issue.
+ */
 static inline void uaccess_disable(void)
 {
+	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(0),
+				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
+
 	__uaccess_disable(ARM64_HAS_PAN);
 }
 
 static inline void uaccess_enable(void)
 {
+	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(1),
+				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
+
 	__uaccess_enable(ARM64_HAS_PAN);
 }
 
diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index a3bd189602df..d110f382dacf 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -33,6 +33,7 @@
 #include <asm/debug-monitors.h>
 #include <asm/esr.h>
 #include <asm/kprobes.h>
+#include <asm/mte.h>
 #include <asm/processor.h>
 #include <asm/sysreg.h>
 #include <asm/system_misc.h>
@@ -294,6 +295,11 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
 	do_exit(SIGKILL);
 }
 
+static void report_tag_fault(unsigned long addr, unsigned int esr,
+			     struct pt_regs *regs)
+{
+}
+
 static void __do_kernel_fault(unsigned long addr, unsigned int esr,
 			      struct pt_regs *regs)
 {
@@ -641,10 +647,40 @@ static int do_sea(unsigned long addr, unsigned int esr, struct pt_regs *regs)
 	return 0;
 }
 
+static void do_tag_recovery(unsigned long addr, unsigned int esr,
+			   struct pt_regs *regs)
+{
+	static bool reported = false;
+
+	if (!READ_ONCE(reported)) {
+		report_tag_fault(addr, esr, regs);
+		WRITE_ONCE(reported, true);
+	}
+
+	/*
+	 * Disable MTE Tag Checking on the local CPU for the current EL.
+	 * It will be done lazily on the other CPUs when they will hit a
+	 * tag fault.
+	 */
+	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_NONE);
+	isb();
+}
+
+
 static int do_tag_check_fault(unsigned long addr, unsigned int esr,
 			      struct pt_regs *regs)
 {
-	do_bad_area(addr, esr, regs);
+	/*
+	 * The tag check fault (TCF) is per EL, hence TCF0 affects
+	 * EL0 and TCF affects EL1.
+	 * TTBR0 address belong by convention to EL0 hence to correctly
+	 * discriminate we use the is_ttbr0_addr() macro.
+	 */
+	if (is_ttbr0_addr(addr))
+		do_bad_area(addr, esr, regs);
+	else
+		do_tag_recovery(addr, esr, regs);
+
 	return 0;
 }
 
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1466ded7cb14ef17258b12a17129d2ca62f81911.1601593784.git.andreyknvl%40google.com.
