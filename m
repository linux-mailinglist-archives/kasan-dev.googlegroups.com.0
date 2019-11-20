Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBQVO2TXAKGQE2TIIDBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id BD87A1037AF
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 11:36:52 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id h2sf18989329pfr.20
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 02:36:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574246211; cv=pass;
        d=google.com; s=arc-20160816;
        b=F3dpcATYp68FQ+w9Lx4AxsFcsqRiUCxzeitcQp6ErftOgzMgqvIEvJkkNvsJ2Zg6mJ
         AskIhBsczIfImGe6xlCYFeYHIUGhZv+sUt/80znCrpWBTvddX5H5KOtqUHWRH8TV0tT9
         K71YVi6IO9WZGmgjI/wLxsYf/awqp7Sc0Hg/e23Yd9JopsZpT/y2q16Q8nuqJgJvUL5f
         VBGOiJujE/FNbkP49ThxUjdn80eiXOV59EFaa0/eVAlf2/Q66R//qDO40kUmedeZe2N1
         bAIuOdC/DaWPqI4UcqcQUWr3Pjfjfzj9HuRmUd+bHSVflaijNha8992W2e0AcUZcd3aE
         jobw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=s8cSN08UPfSCPjgbu46zy6wHV3lGmdsnMwSuyk5M2Ao=;
        b=oH+KXWc0BF2C/nnd9fRne08blp3l1Bmj/nFE10LG1dMavXOI9jKcCaIfdwk5fEBByl
         jRg3ZIS4a878xtkdClV9hPlBVcBG0CgU/o1Hs8GSlLgOTgcv951Q5QpoQmgTaQMmhZQV
         m6m1cneVggdhZLMe/8Q4m/nzBrBS/shvnEbwaUC3H+IazNAkmvyqiuc6+KePmg9UeT8e
         BU3PNkIxhQjmNIkdDkE5XoULoDjWWJfoUqnwHTCeqV4mtvFbkTOTDtZ63GzKfD33KqoD
         cxb9XfHRDGw5VtCWwDJNqlbG0LrtUtgoRGbHAIiARTt68IAP5C1RpFwQzj1o2NOQvfm2
         o4WA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JdTANbiV;
       spf=pass (google.com: domain of 3qrfvxqukcbghyllfemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3QRfVXQUKCbghYllfemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s8cSN08UPfSCPjgbu46zy6wHV3lGmdsnMwSuyk5M2Ao=;
        b=DbNEI1NAzSOw8rf38RrdHLZfzX7qCTTBT3YxhYpDSSMbvoapjesIOd6x5dY25b958j
         D5WpZtYMHh1RJPpE4POKMzN/7sllh3zsIVkqoAqDuG8qgW7TcRvweyXIkXCqDIZIa135
         Og/beXgtMdeU+IpmnHNXu44ag+FYrf3I2VcGydUA28Mvz+OawieKmy3S5i1sUS6WyiR/
         atX0tSnESP3NzH8TAdLLVnqfIcgUBQXA8GLr4e5ZWy5xRf+0qMZZEybcgzQpl+EWblk4
         bFpDNc43EvffFsqkxQ2x/EgDm5CLI9fl8ZLsxPGPIbnhYPnBmjA/PnBWWk2WeGojpkm+
         PiFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s8cSN08UPfSCPjgbu46zy6wHV3lGmdsnMwSuyk5M2Ao=;
        b=QvnLHQpSVQBtvg8ekDOwucf+eQ1qNDWT8IHtlEN7KF/q7Ly3LqiyLPAxo3WjGiq1VJ
         001VwdfiKGpTBAkyI11L48Wgs8eGbWxkx7qrxpW2vlv0GwfrQRV8kxvj8LfDov8bJiSZ
         gbBLYyotKAZtdly2bulDHHAYj7PLaVpUnlWHxV1GFSOZBhTDj0U4W94GVKwd8+6msTxg
         H0Lllt5XMnDbO+pJVBiVJeugbD4uWOhF4v/bqn1WCCZGMcxc0N88/IvcPfwZ4rUt0B4u
         t2uE4XxYRr9QgDxI2jk+FSBEUvhzv9bwKhW1jRr5YHpLPXSVKsb6f3EhfUbE0t1MhS4W
         Sthw==
X-Gm-Message-State: APjAAAVlsuyGXLvR21FLJoT3zEFZxB9MAcVC65PaUcKW3P7vJbKY/8nn
	q6Zr2VEEjQpJAV6YlAvQqhw=
X-Google-Smtp-Source: APXvYqyFmXPG0F+VBIqHTmeAQLuHERPXV7z9v3ty/A9y289slQFaHJ9jBaoKKbtDAuTZSnr2/60Unw==
X-Received: by 2002:a17:902:9a05:: with SMTP id v5mr2256690plp.212.1574246210822;
        Wed, 20 Nov 2019 02:36:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:216c:: with SMTP id a99ls443861pje.5.gmail; Wed, 20
 Nov 2019 02:36:50 -0800 (PST)
X-Received: by 2002:a17:90a:326b:: with SMTP id k98mr3232732pjb.50.1574246210460;
        Wed, 20 Nov 2019 02:36:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574246210; cv=none;
        d=google.com; s=arc-20160816;
        b=0Gar/WRDlRnFT8PR9ukAQ3gEwZoAmKVgov4WiRWF9+vTDB5K2lUUA13uKAIdYBpb09
         j1E1+JEaZLC+JelEs01B1//zUkHPYCxoXIyo/v1DpuVqrP8aMwScfrqChRUnW/bxzOvU
         yvDQuf4OGJgm8EMEJcEB3UIMUx72lHPFHHnccbjos5+8tBvNmUXVmYModKJlDLNmQwL7
         NZeHiSz7JyJrmA3rjq/35IKhTIzVh7lYv3MUVxnSdf7FRknAZgHF6cmNZt6wI+lc8gMP
         GWN/9/R+TxyK7G0pXhnwj15cgK4RZb0+4wtYtaH6hXGWDvaVTdId353l9qkuDm/9aVBp
         yUjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=XXv7Sasr5KrifXcHDhUghU+ar6AdS1iTu/G2m38gf3g=;
        b=TajGy+2Tgr9jE4UYNdDVnrIFmuDRZJYmcmqMpVDDSD4yykR5Ix1h1PzX4EHXFgoMUe
         ppWOTh3ay6KSvMBDesZr5EBi/k6PHSCb1dLx7NF6ot5EZWQsxsEEdLXcTVnpB0eux2Mr
         Eg02AHd9roKDesbOI8vtyxhtO0vi0nRxFAkw3lxLJwLSb9tQ97M9mxtTbFnpMBLC4unJ
         Xvofw7c9YMaFHmZCTfhs8teDQZXzXa9y9RDqvlUimFQLNeB9WhPOu/+Bw+/ePpDlTEiK
         D9FkjQYUgCWQ8M/7vVWq9qIR/IS0zxeHGCkYQbgHs26aS6r/iAhTFrp5HS8aA2reSwQT
         KYbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JdTANbiV;
       spf=pass (google.com: domain of 3qrfvxqukcbghyllfemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3QRfVXQUKCbghYllfemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id j19si864031pff.4.2019.11.20.02.36.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Nov 2019 02:36:50 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qrfvxqukcbghyllfemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id a186so15536346qkb.18
        for <kasan-dev@googlegroups.com>; Wed, 20 Nov 2019 02:36:50 -0800 (PST)
X-Received: by 2002:ae9:dd47:: with SMTP id r68mr1686874qkf.7.1574246209435;
 Wed, 20 Nov 2019 02:36:49 -0800 (PST)
Date: Wed, 20 Nov 2019 11:36:13 +0100
In-Reply-To: <20191120103613.63563-1-jannh@google.com>
Message-Id: <20191120103613.63563-4-jannh@google.com>
Mime-Version: 1.0
References: <20191120103613.63563-1-jannh@google.com>
X-Mailer: git-send-email 2.24.0.432.g9d3f5f5b63-goog
Subject: [PATCH v3 4/4] x86/kasan: Print original address on #GP
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
To: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, x86@kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	jannh@google.com
Cc: linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Sean Christopherson <sean.j.christopherson@intel.com>, 
	Andi Kleen <ak@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JdTANbiV;       spf=pass
 (google.com: domain of 3qrfvxqukcbghyllfemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--jannh.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3QRfVXQUKCbghYllfemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

Make #GP exceptions caused by out-of-bounds KASAN shadow accesses easier
to understand by computing the address of the original access and
printing that. More details are in the comments in the patch.

This turns an error like this:

    kasan: CONFIG_KASAN_INLINE enabled
    kasan: GPF could be caused by NULL-ptr deref or user memory access
    general protection fault probably for non-canonical address
        0xe017577ddf75b7dd: 0000 [#1] PREEMPT SMP KASAN PTI

into this:

    general protection fault probably for non-canonical address
        0xe017577ddf75b7dd: 0000 [#1] PREEMPT SMP KASAN PTI
    KASAN: maybe wild-memory-access in range
        [0x00badbeefbadbee8-0x00badbeefbadbeef]

The hook is placed in architecture-independent code, but is currently
only wired up to the X86 exception handler because I'm not sufficiently
familiar with the address space layout and exception handling mechanisms
on other architectures.

Signed-off-by: Jann Horn <jannh@google.com>
---

Notes:
    v2:
     - move to mm/kasan/report.c (Dmitry)
     - change hook name to be more generic
     - use TASK_SIZE instead of TASK_SIZE_MAX for compiling on non-x86
     - don't open-code KASAN_SHADOW_MASK (Dmitry)
     - add "KASAN: " prefix, but not "BUG: " (Andrey, Dmitry)
     - use same naming scheme as get_wild_bug_type (Andrey)
     - this version was "Reviewed-by: Dmitry Vyukov <dvyukov@google.com>"
    v3:
     - adjusted example output in commit message based on
       changes in preceding patch
     - ensure that KASAN output happens after bust_spinlocks(1)
     - moved hook in arch/x86/kernel/traps.c such that output
       appears after the first line of KASAN-independent error report

 arch/x86/kernel/traps.c     | 11 ++++++++++
 arch/x86/mm/kasan_init_64.c | 21 -------------------
 include/linux/kasan.h       |  6 ++++++
 mm/kasan/report.c           | 40 +++++++++++++++++++++++++++++++++++++
 4 files changed, 57 insertions(+), 21 deletions(-)

diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index 19afedcd6f4e..b5baf1114d44 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -37,6 +37,7 @@
 #include <linux/mm.h>
 #include <linux/smp.h>
 #include <linux/io.h>
+#include <linux/kasan.h>
 #include <asm/stacktrace.h>
 #include <asm/processor.h>
 #include <asm/debugreg.h>
@@ -568,6 +569,8 @@ do_general_protection(struct pt_regs *regs, long error_code)
 	tsk = current;
 	if (!user_mode(regs)) {
 		unsigned long non_canonical_addr = 0;
+		unsigned long flags;
+		int sig;
 
 		if (fixup_exception(regs, X86_TRAP_GP, error_code, 0))
 			return;
@@ -598,6 +601,14 @@ do_general_protection(struct pt_regs *regs, long error_code)
 			    GPFSTR " probably for non-canonical address 0x%lx",
 			    non_canonical_addr);
 
+		flags = oops_begin();
+		sig = SIGSEGV;
+		__die_header(desc, regs, error_code);
+		if (non_canonical_addr)
+			kasan_non_canonical_hook(non_canonical_addr);
+		if (__die_body(desc, regs, error_code))
+			sig = 0;
+		oops_end(flags, regs, sig);
 		die(desc, regs, error_code);
 		return;
 	}
diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 296da58f3013..69c437fb21cc 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -245,23 +245,6 @@ static void __init kasan_map_early_shadow(pgd_t *pgd)
 	} while (pgd++, addr = next, addr != end);
 }
 
-#ifdef CONFIG_KASAN_INLINE
-static int kasan_die_handler(struct notifier_block *self,
-			     unsigned long val,
-			     void *data)
-{
-	if (val == DIE_GPF) {
-		pr_emerg("CONFIG_KASAN_INLINE enabled\n");
-		pr_emerg("GPF could be caused by NULL-ptr deref or user memory access\n");
-	}
-	return NOTIFY_OK;
-}
-
-static struct notifier_block kasan_die_notifier = {
-	.notifier_call = kasan_die_handler,
-};
-#endif
-
 void __init kasan_early_init(void)
 {
 	int i;
@@ -298,10 +281,6 @@ void __init kasan_init(void)
 	int i;
 	void *shadow_cpu_entry_begin, *shadow_cpu_entry_end;
 
-#ifdef CONFIG_KASAN_INLINE
-	register_die_notifier(&kasan_die_notifier);
-#endif
-
 	memcpy(early_top_pgt, init_top_pgt, sizeof(early_top_pgt));
 
 	/*
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index cc8a03cc9674..7305024b44e3 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -194,4 +194,10 @@ static inline void *kasan_reset_tag(const void *addr)
 
 #endif /* CONFIG_KASAN_SW_TAGS */
 
+#ifdef CONFIG_KASAN_INLINE
+void kasan_non_canonical_hook(unsigned long addr);
+#else /* CONFIG_KASAN_INLINE */
+static inline void kasan_non_canonical_hook(unsigned long addr) { }
+#endif /* CONFIG_KASAN_INLINE */
+
 #endif /* LINUX_KASAN_H */
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 621782100eaa..5ef9f24f566b 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -512,3 +512,43 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
 
 	end_report(&flags);
 }
+
+#ifdef CONFIG_KASAN_INLINE
+/*
+ * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
+ * canonical half of the address space) cause out-of-bounds shadow memory reads
+ * before the actual access. For addresses in the low canonical half of the
+ * address space, as well as most non-canonical addresses, that out-of-bounds
+ * shadow memory access lands in the non-canonical part of the address space.
+ * Help the user figure out what the original bogus pointer was.
+ */
+void kasan_non_canonical_hook(unsigned long addr)
+{
+	unsigned long orig_addr;
+	const char *bug_type;
+
+	if (addr < KASAN_SHADOW_OFFSET)
+		return;
+
+	orig_addr = (addr - KASAN_SHADOW_OFFSET) << KASAN_SHADOW_SCALE_SHIFT;
+	/*
+	 * For faults near the shadow address for NULL, we can be fairly certain
+	 * that this is a KASAN shadow memory access.
+	 * For faults that correspond to shadow for low canonical addresses, we
+	 * can still be pretty sure - that shadow region is a fairly narrow
+	 * chunk of the non-canonical address space.
+	 * But faults that look like shadow for non-canonical addresses are a
+	 * really large chunk of the address space. In that case, we still
+	 * print the decoded address, but make it clear that this is not
+	 * necessarily what's actually going on.
+	 */
+	if (orig_addr < PAGE_SIZE)
+		bug_type = "null-ptr-deref";
+	else if (orig_addr < TASK_SIZE)
+		bug_type = "probably user-memory-access";
+	else
+		bug_type = "maybe wild-memory-access";
+	pr_alert("KASAN: %s in range [0x%016lx-0x%016lx]\n", bug_type,
+		 orig_addr, orig_addr + KASAN_SHADOW_MASK);
+}
+#endif
-- 
2.24.0.432.g9d3f5f5b63-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120103613.63563-4-jannh%40google.com.
