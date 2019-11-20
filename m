Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBJ7D2XXAKGQENTCW7SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id B45E41041AA
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 18:02:32 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id p8sf266468pgm.9
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 09:02:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574269351; cv=pass;
        d=google.com; s=arc-20160816;
        b=wsZeOmRNQbVT6iUPOgmjSgRxRQWy6E9L3X7/sT4HcMPxejK2BrWnHTcs+cu7BkC34W
         3apWr/AuW4AKXOeePR2si/5HzEDAr6ySAw82XNoQ1/VsMsgeoVFs76Wk5XjRz2ZRsfOf
         50Tgazn8+g1ZzAmHkSwOd5kWCKAQm/KqMsAQDZ9zp3SYYVcUGaP8FiSxbrxR/X96Adzg
         Un95zCJq7OFencRu1nzj1FVABZOLs9rDWnoD6irQ5fe1ENFhUs8K/dsRzT6R0rNT0QcL
         ewbB5S/Y3X/HoESJE9HqpZUhCHmRdKBC8lJljdNdTUx+DlDEIF3J8ci2/fyEELa8Z1xk
         Zpkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=eRaaZhqYEQI6Yy9YVHk9K4UwsnBKwwqh7UE3+ob5a0A=;
        b=lKNgv9/EzPUfBX5UGOeF9i8wyuGzjvjntOCXOGSoXaOVWsGTXmq7Yxrak/oIzDMy5I
         axELIiRXCsTPplLg+GceIignHCPVxs+Zb7f7nq0Ys7v8ytzzAdQKBKw9kQ2IoeWG3+W8
         CnZTdlXF57pqEbPu/jtX17qLGv5x2TBQLE2xCAs2JYG/gsM10xjpf6dAtSKG73pC4mLk
         IVkYpsdMCKHCfpYIXPrkEzPwR4f+0nuS+SGFxZ2SCtPvHtfEmlnfWN165Ae6PVvRi8Ff
         GTPXY0OYZDv949NXUJOAj+TJhrVW6bWk1CZIkM99X+TPmNQqQ0czlvnOVj3greEPaxPY
         Pl+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r1azWtR8;
       spf=pass (google.com: domain of 3pxhvxqukcdi7ybb54cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=3pXHVXQUKCdI7yBB54CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eRaaZhqYEQI6Yy9YVHk9K4UwsnBKwwqh7UE3+ob5a0A=;
        b=CLCIahRRigf/qbLJGEQZmnN21IN5YUz9xjR1/nJWgDu6St/9w/ImhAHyfO/JW9SRVa
         jHRIF849N+uNT0zkBDeMsL7Nj2ucj86MPTmcMoUvI7UM07syFH7PXT3MzA90kYTlRFRT
         A07NvM7/DZkbZg8KzZ4Lnvv8FqfwvcW5cdCfBjgKKVjuPB6/TTrKMCi+8BH/2BFNAGqt
         hPDJt04QF85u401jiQ8cmb1YghMhUqjbkU7EH4LmQmh18rjtQUoCyvBC8eSVU+0+jGMe
         6puIGnRjUCGsqJbhT6z9SWxwdViOZTq8xp/+Guo8p06sQd0HGd6ttS7h2Q+QLx8IC7hc
         qgCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eRaaZhqYEQI6Yy9YVHk9K4UwsnBKwwqh7UE3+ob5a0A=;
        b=YJn+Z22V8bg05w6x6IPIfRpLcXPgeAW054t1HQDKgrChBQH+pIeaWp+yDaM5Wu5Nlm
         cL6Ox5OCX5s3r881eT976LZZMVir/xtWZLxMjDrKJXA/uOBNXjLwF1LsE5J15naAQFBC
         r3nfS5KjNaqOc3AKZxH3s/eSkAvwCMJJzHibNfg+YillGpJ+BvNc7w2zZWRt7BKpSMbC
         ZZ8mGYwroNpffDUgDDOfjfB26GoOvFqHk/Ew26BMQktRq5FpJQ7S8Jq5YXepBU3APGqN
         U4TmgdF/HJAPSz92SL2wTo99BpXajPH4MplY+SRohxEMj+vfUI6zXFyl/kEvRIy1M0w8
         4qGw==
X-Gm-Message-State: APjAAAXD6leimk+TQOo0VwqGqWQucBaljKhvzSXWcgLYhupqHxKvPvlT
	COeko1c3i3qzwlEpbhBV6FU=
X-Google-Smtp-Source: APXvYqyQWCst9LfNdry9DBkcrWLY1t1wtsCGIWi1574qwfFOZm7kCfl7iqHdd2aJZiv+nbEqREcd5Q==
X-Received: by 2002:aa7:9aa9:: with SMTP id x9mr5308267pfi.207.1574269351113;
        Wed, 20 Nov 2019 09:02:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:7904:: with SMTP id u4ls180147pgc.0.gmail; Wed, 20 Nov
 2019 09:02:30 -0800 (PST)
X-Received: by 2002:aa7:9d8b:: with SMTP id f11mr5277446pfq.20.1574269350627;
        Wed, 20 Nov 2019 09:02:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574269350; cv=none;
        d=google.com; s=arc-20160816;
        b=V9757cPNAHT7iPNd/4L4VoWFiPpXFo6mUZFdbO3Ox3F9MZCCwu2kkHJKBMC4i0hx/W
         rLEwf9W8nEgV+KfqpVAsjajSfHVza1R3xXlwwXWE/EjwgNGKt6UBaz12I0cW+/Oga8kI
         bsf+I2otKCVCjxyhdsGm2q2zk30L4RKkOGQ5h2kzlXYW64cM8KLmNdRXAiKwKzmw0FPo
         bQ97G4EmPwqB04WbJpzAkdDA0WcxkcE6C22m7IgvhIccEzZyM94m3Y3lVmNl7vNud1AT
         +ulxDSn9zhKvnPiRKVEyhTr5qOrm2ZFdhpY8YBL311BIQdcReHKK4wlNiboCLh26PJEH
         xzDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=gxBL3CBm1h/tbDLIWI6DpF6/W5QiOnWrINNtvzXl3CY=;
        b=rWhFlt2vhQt53WR90qOwdqI1XKNBzlQaBcZSuU43VL7I890HxIE9jEr8RozP6Bxhvf
         TZj12Y1ibf09DfpGGs1TBJzJawxRdjx3dY1ODtv12ctrtTiT+HTIdBFqWYF+4R5nJVJJ
         d+wrQdUmMAu7v1ehGNf9RWHEjQz39WY7QwpNt4O04IN2/8nrlX58YQmKQjeNHdNlWW2G
         z9ahlQKavcF63iYArmGMno62hNXZyr6V2ALppNfT0PoWQoKZOY7rU5XNVhbTonJgSzdl
         2eP63iZYVboAZn1EF1i6bAJPyv79vhwStCMRjRYxNqxprOoZTVvgZmZPpwe9jBxFJbhg
         7XvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r1azWtR8;
       spf=pass (google.com: domain of 3pxhvxqukcdi7ybb54cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=3pXHVXQUKCdI7yBB54CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe4a.google.com (mail-vs1-xe4a.google.com. [2607:f8b0:4864:20::e4a])
        by gmr-mx.google.com with ESMTPS id k6si267808pjp.2.2019.11.20.09.02.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Nov 2019 09:02:30 -0800 (PST)
Received-SPF: pass (google.com: domain of 3pxhvxqukcdi7ybb54cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) client-ip=2607:f8b0:4864:20::e4a;
Received: by mail-vs1-xe4a.google.com with SMTP id b12so111699vsh.10
        for <kasan-dev@googlegroups.com>; Wed, 20 Nov 2019 09:02:30 -0800 (PST)
X-Received: by 2002:a1f:944a:: with SMTP id w71mr2219271vkd.60.1574269349528;
 Wed, 20 Nov 2019 09:02:29 -0800 (PST)
Date: Wed, 20 Nov 2019 18:02:08 +0100
In-Reply-To: <20191120170208.211997-1-jannh@google.com>
Message-Id: <20191120170208.211997-4-jannh@google.com>
Mime-Version: 1.0
References: <20191120170208.211997-1-jannh@google.com>
X-Mailer: git-send-email 2.24.0.432.g9d3f5f5b63-goog
Subject: [PATCH v4 4/4] x86/kasan: Print original address on #GP
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
 header.i=@google.com header.s=20161025 header.b=r1azWtR8;       spf=pass
 (google.com: domain of 3pxhvxqukcdi7ybb54cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--jannh.bounces.google.com
 designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=3pXHVXQUKCdI7yBB54CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--jannh.bounces.google.com;
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

 arch/x86/kernel/traps.c     | 11 ++++++++++
 arch/x86/mm/kasan_init_64.c | 21 -------------------
 include/linux/kasan.h       |  6 ++++++
 mm/kasan/report.c           | 40 +++++++++++++++++++++++++++++++++++++
 4 files changed, 57 insertions(+), 21 deletions(-)

diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index b90635f29b9f..342cee50bf7b 100644
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
@@ -574,7 +575,9 @@ do_general_protection(struct pt_regs *regs, long error_code)
 	if (!user_mode(regs)) {
 		bool addr_resolved = false;
 		unsigned long gp_addr;
+		unsigned long flags;
 		bool non_canonical;
+		int sig;
 
 		if (fixup_exception(regs, X86_TRAP_GP, error_code, 0))
 			return;
@@ -606,6 +609,14 @@ do_general_protection(struct pt_regs *regs, long error_code)
 			    GPFSTR " probably for %saddress 0x%lx",
 			    non_canonical ? "non-canonical " : "", gp_addr);
 
+		flags = oops_begin();
+		sig = SIGSEGV;
+		__die_header(desc, regs, error_code);
+		if (addr_resolved && non_canonical)
+			kasan_non_canonical_hook(gp_addr);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120170208.211997-4-jannh%40google.com.
