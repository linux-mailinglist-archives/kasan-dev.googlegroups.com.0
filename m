Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBTMX7TXAKGQEHZDUJPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id A832F10C0D1
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Nov 2019 00:50:37 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id s17sf3336794edy.12
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Nov 2019 15:50:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574898637; cv=pass;
        d=google.com; s=arc-20160816;
        b=wlgCypJyQlxNLmfMQ5rnD1gcmtzV96pkNP4q76fUBjusfjHpSS6aEyLbzZ07+KLV8l
         /dQIPbyLY+XEUEpDGUgVXB97OBuvH8FeELTbWaYpCUEpsq4P2wbSt0hU1k0Dx6YxSYaG
         iVeIBk/Hi51cngNjxgZbT4PB4MOQ+NuUlC1n2D0vNlb7MpjzY07cqEflTK+ShpGQq3JQ
         UpUogI1t8wLVcH5zmrRtyiMh8+NeyhTOspKWmbwKp0Q9RAd83/FY04SvRKkt9BMSuHx4
         pAbYbE3AxgR6Nz7g1dM3D0ZzPlUxa+iwQdX5hK1ZUCJXodtBKt5QPMu8kL45gjFDVyGG
         36tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=TP0SBC0l8+4qbXm9dpfGI3txP2Qo813yLHuyd67Omzk=;
        b=ofyMJMi8xJ//QzYf7+5+ED21RDLd9rgxuPtBt8Vah62fvCHYsYLzYY8owNkQ1cyPVk
         ZSdR2l2tjcZCJy5vcH8/LQigJf1BSVQ+dQUxl7ewPBbnsW46NEtlQQEtFAigJYZ/z6w7
         0CLzcImOjQ/xNIZfLLVK+yhbuwCkxk01YhFPRh3QU+BEw9fvs8VnElGRk7BKYg3O1tah
         gBxtosg6MHmfb18/XHovMiYgYMaVJ9xZtr7pJKOhTd7MCNdCJgPxgJiMdOxzlA03OuR0
         xRheWyaMZ1wYIcMsDw6JD8i62fMo64gCH2pA1xL+uq76l8FGK1ZFJKboXYU6W5v2SZQZ
         8sFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W5y6tSeM;
       spf=pass (google.com: domain of 3zavfxqukcvu6xaa43bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3zAvfXQUKCVU6xAA43BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TP0SBC0l8+4qbXm9dpfGI3txP2Qo813yLHuyd67Omzk=;
        b=MXacNGbsdy/o5VN5PJzKpFhsUvyG7eA0/ZJd3PSmgYHAzzq/GhUDzpCyJhyhzxAe19
         N4K10bX6wi84K5zjOstRCj/vQzq74odlk8NzdlmDDuy7nVT2DLj9iAZEJ0E0p8QbswQM
         jTgA/8/X2cHzYKjW5S0oYpI51PvH5f7IbnY/jqubUHhospoBGF4gyhtCsHgkJIYfPouj
         nnC3pvgy7WkV09TSjESI3DjvAnFRwh45CBmZjuwLPIcYjmMFnWQfl4eJKJgm/KNAa4KQ
         eoc+w2Nq9adJC2YHILKWBJgrFQiBQ34GolxQrCT5deGf7NA3rzygXyS80H+qRFHn7cxv
         qJIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TP0SBC0l8+4qbXm9dpfGI3txP2Qo813yLHuyd67Omzk=;
        b=jotvop0OkoEZuxRirszALDGfCFqTU3erOqSPkqhsnnXxJwsJxvdVwvmAQ8rCfcxLZZ
         vX6eb3gqy/17NlbiH+Dcti0ZXYVsJV1PzMlfxKUBLk//B94/Cf2g8tvHGCkC3sWdsu12
         KreLoo4yDb4keEcUbs66LNelzDfze/YPymcDkxb/T7dT2v4Ne3G+9yvaiJk3GGWWX1x1
         kIc8ZmwPCm5C7WYrwBfhwEjctsbZiduH5Dqb2IhS3L7qSsUpUoND5PRYqjAUZ9bQ5LOV
         bPLAW35YK0m2FSuzLj2oE53vaSzfLUZ0/E0S/vgRgihi62IYC4iqTzG1ZhKqclBnHa4T
         IlMA==
X-Gm-Message-State: APjAAAUaIMyXGKW2Lrp+2Mdo/ekMH2fu4hrBVbdQTOxwy+0QUDpHVBZw
	ZrhsYoxK2wMS9w/F8VMsgRI=
X-Google-Smtp-Source: APXvYqxS8z6Q0FPlW/c+3ekxwpoLCIfRnbnF1Q1/Jle7i5qVIQ0pFaMHB319cgS4J+LwZj8Le/5GYw==
X-Received: by 2002:a17:906:4c8c:: with SMTP id q12mr52628472eju.256.1574898637316;
        Wed, 27 Nov 2019 15:50:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:b245:: with SMTP id ce5ls7753924ejb.13.gmail; Wed,
 27 Nov 2019 15:50:36 -0800 (PST)
X-Received: by 2002:a17:906:3418:: with SMTP id c24mr52310673ejb.121.1574898636814;
        Wed, 27 Nov 2019 15:50:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574898636; cv=none;
        d=google.com; s=arc-20160816;
        b=EI2IUVsk7DZyWlX4XkljdmWzRJ454PbPhThna41Y1EMaNtsmuW2qvd3zAj2eld0k0I
         U+flqh7dFzs6lR1cvfkVMJgDyz/b2DzUzv2+xgnZ7sNw0N4qSGGimyfsASPVSginiGln
         3uRh8RrZciKcILzNWPTZ8/KcGJbmhAugo9OSxqv69jQiQKu0qi5I1g6qSf1rpUsY7XEn
         L0r8jYPKTdmanFCjFV/J53Bx1YbLmeRoq17+1OKDe8FO1kAmNCKdkt7ERjAmo6dhQSkw
         zLiFP/ylfydxbtpmdv8NQXc4CQv4k8gRBq/RFQYZ6vd2S6w7KcgPUIiPAADa/QRUx+V4
         XBvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=+1lx5ocSVx6un1v0Cw2ClVXDDkVMc3TsX0GOf0k847E=;
        b=yERDRSWBrYeeX2WHqoUacS4oDbTi8Z1eE2NDgUtDfWotiUyWNaw2IP9CvNfxKidi+k
         vHeqQl0uKdL0lRn+6sFDbyGAnse7iNwOj3JbWDXgqkHK3NOUNXgcs2eY4QC5mHxVDYV7
         c8JtjNNxzCsdKvtfMXL8k16RVajz2mgwOfBIDpH8/BaDl7ZljeFgEas3LktdIxP1pYj+
         WhVrOZiUbScatcEhkDDB1pCfyTnDEcy4tDR06tltJqFc5kvd8GK1v/Leuco8d4TXH8dG
         azdNMUz0rjZj+dQWxP3cdom51JH38yvnJIreTrVV3C+ySkct1HKFb4HriKbtC2WWwKUZ
         43yA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W5y6tSeM;
       spf=pass (google.com: domain of 3zavfxqukcvu6xaa43bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3zAvfXQUKCVU6xAA43BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id b2si196795edq.2.2019.11.27.15.50.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Nov 2019 15:50:36 -0800 (PST)
Received-SPF: pass (google.com: domain of 3zavfxqukcvu6xaa43bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id t3so193059wrm.23
        for <kasan-dev@googlegroups.com>; Wed, 27 Nov 2019 15:50:36 -0800 (PST)
X-Received: by 2002:adf:e944:: with SMTP id m4mr10084533wrn.49.1574898636363;
 Wed, 27 Nov 2019 15:50:36 -0800 (PST)
Date: Thu, 28 Nov 2019 00:49:16 +0100
In-Reply-To: <20191127234916.31175-1-jannh@google.com>
Message-Id: <20191127234916.31175-4-jannh@google.com>
Mime-Version: 1.0
References: <20191127234916.31175-1-jannh@google.com>
X-Mailer: git-send-email 2.24.0.432.g9d3f5f5b63-goog
Subject: [PATCH v5 4/4] x86/kasan: Print original address on #GP
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
To: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, x86@kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	jannh@google.com
Cc: linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Sean Christopherson <sean.j.christopherson@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=W5y6tSeM;       spf=pass
 (google.com: domain of 3zavfxqukcvu6xaa43bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--jannh.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3zAvfXQUKCVU6xAA43BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--jannh.bounces.google.com;
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
    v4:
     - adjust patch to changes in x86/traps patch
    v5:
     - adjust patch to changes in x86/traps patch
     - fix bug introduced in v3: remove die() call after oops_end()

 arch/x86/kernel/traps.c     | 12 ++++++++++-
 arch/x86/mm/kasan_init_64.c | 21 -------------------
 include/linux/kasan.h       |  6 ++++++
 mm/kasan/report.c           | 40 +++++++++++++++++++++++++++++++++++++
 4 files changed, 57 insertions(+), 22 deletions(-)

diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index 9b6e4d04112a..a7dade19783a 100644
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
@@ -589,6 +590,8 @@ do_general_protection(struct pt_regs *regs, long error_code)
 	if (!user_mode(regs)) {
 		enum kernel_gp_hint hint = GP_NO_HINT;
 		unsigned long gp_addr;
+		unsigned long flags;
+		int sig;
 
 		if (fixup_exception(regs, X86_TRAP_GP, error_code, 0))
 			return;
@@ -621,7 +624,14 @@ do_general_protection(struct pt_regs *regs, long error_code)
 				 "maybe for address",
 				 gp_addr);
 
-		die(desc, regs, error_code);
+		flags = oops_begin();
+		sig = SIGSEGV;
+		__die_header(desc, regs, error_code);
+		if (hint == GP_NON_CANONICAL)
+			kasan_non_canonical_hook(gp_addr);
+		if (__die_body(desc, regs, error_code))
+			sig = 0;
+		oops_end(flags, regs, sig);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191127234916.31175-4-jannh%40google.com.
