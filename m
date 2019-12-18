Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBVHE5LXQKGQEYAMVRAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 0525612577B
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Dec 2019 00:12:21 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id c2sf1656934edx.19
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2019 15:12:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576710740; cv=pass;
        d=google.com; s=arc-20160816;
        b=UtJqaXvgEucBTSBt5/9ntnNkR15FjQTurNyaqXGEB00Z08aaXQApoK8pLLeYY7DBbC
         yZFnJkjlc9nIibvQ3l2WDtL+u0HKtBTTn+pot2REEcH2NpMsUD/990vhg65/KlZKU7kU
         IOVvKUAehq28iTn564AtuZHU9QA7VegWXpOx+F4UgI5QVox8l9CCkXXV5Birw4gXRKWl
         Ywzxx5yLlJ72W2nCwgeTepuLO61qpr6RLxGvr+VrcrIufnKCCuOxPfb/pu7F6ayl5mP4
         wi2kJpGSCLlv0OGxmEdS+4ZovJFzw1SooDE7cpy8k/J8JA62frwYJEAGbjTS0VknBrAN
         PGEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=cetix4zvr2FxAICwuJJ+5p3NPpNzO46tFSs/6zHPEaQ=;
        b=Wlxo2lArgjxlxHW1a5/47DzuR/wkdUFkNqRSpecCIcFt9mAh+dCNGj++gXy6jCBu5T
         i0BKAb8MIfHEYqCfqfPhMjGo05iv1OkvspS4PAkxwCKk1NQ1iv50yQvQG7eyOhp/Fl2k
         qqLCOSC1CAGxKxvUk81aNYK8GptZa9B+duNCri1+TdhRxIzN5x3QtU1vw2YJpqx0L2tz
         7yTApl9e6i782QdPbUOXWSiYCUIIk4kgWNKsax+MRSRt79Y119az7pPjcnFM9wnhpT4V
         Y69zoVGFErJlsTy2cKEQ3goulFc3myBmAZi8g8s8RcAvSgVmf1lBZhH3gXt+TVyjFQZJ
         bcPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YejG3w1m;
       spf=pass (google.com: domain of 3u7l6xqukczgb2ff98gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3U7L6XQUKCZgB2FF98GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cetix4zvr2FxAICwuJJ+5p3NPpNzO46tFSs/6zHPEaQ=;
        b=sejdq3GtrDvyRdqYIshKBFObFp8/S6khPKd/Irt7uAirLoVvx/yM+1mcOLn3CEwy5y
         DYXGw8NinwQYRIhGLGcImB3DFEdwlXPRNcxJ3e8BLkGVUzhMJHYEN0L/l1W4tt8buoqG
         Q+o1mrhTN8SER0XLvZIxgcrUj82BfHjvzEsCX7Gzaxum0iCX9kfe3/2pq3oEDQJrRGKL
         R6KQaQ+ubXzbNIE6PVWX1i8VrkM+ZSra5i0xZwefk/nEbUI9lh153h1xAucaJH2uVq2p
         az7/j3Snoahb+JJ+kGprS6srxqWaouEbxl4tGYw6J8j08C2I9cTAESI4rsFXMSZYoNxR
         OzwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cetix4zvr2FxAICwuJJ+5p3NPpNzO46tFSs/6zHPEaQ=;
        b=LC+ledyuNKjhfg8FbeGKnJeZiLqspejuC9kY+tlsflkzLpwkw3sJSK4ZRWdPJU2oY1
         yoHXEgQ2G5UgfqEb4rmWkzGMKqzEr1HhKNiWq1bqji4rxyccb09qNco+LJFWfAIxlyCc
         NjbE9cGWgqWlOBKdX+eTpN/3sXvYBS3MDxXbpxJt0AigQ1feRzG4nuMYgYK5F7lxF/QO
         4RM+G5KUSMhvRJuEtXvUGL/ZscXi+lz8AySYoaS71GJL69on/HMlHJT0zxEW8oUBKTcB
         EL3yIpucuZ5JQTFFTpmt8zs72biy6ST873eX08W1FJJ86cY8s+HKOyvvWMWv8nl4mVvi
         yQww==
X-Gm-Message-State: APjAAAXIDpGL/3mpPwfKZqp4gnA6UR/xl1CgWrs0o6AWjGpQlohX+z8w
	hnRJ2LzxTSqj8WrXPWF05Xc=
X-Google-Smtp-Source: APXvYqyaLN2NRGHAJP0Z+EJ4sOa/NSGdbNq3PuTScXZ1VgGXBSfjMsUNG22MjjCvZx8RmZjU5oVEfw==
X-Received: by 2002:a17:906:3299:: with SMTP id 25mr5828385ejw.118.1576710740526;
        Wed, 18 Dec 2019 15:12:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:b82f:: with SMTP id j44ls843308ede.8.gmail; Wed, 18 Dec
 2019 15:12:20 -0800 (PST)
X-Received: by 2002:aa7:c2da:: with SMTP id m26mr5583701edp.244.1576710740026;
        Wed, 18 Dec 2019 15:12:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576710740; cv=none;
        d=google.com; s=arc-20160816;
        b=NoCf6B1NZQE9ZweXf4zN3lwZGxoI5gIk/sSOg1tEjzMR5sexpLFMiRVFGbcuqeO6lL
         9KPivazgl+zKYwb049+JmGsn2Wr17LXODi8IL5Qgxrx70qlSNAIrCsdrRIM0/62TR6Fl
         Yf1hfer+dPHnA7z+fhH7ZG+giiuntCe0GZx5McgvtBQTVIOb0c7tIKQ6WNHijEBeDWXh
         WkXDI0kLeEEU9d21bgvxNiKyO1NeCr8wuyO5gA/ZfkWNiHdydDscVhI7ZiEMhK+nq7aR
         X1ROCCr1EnSc+S9Z5x/LCDF0GTQgejxKeuCYfiVdSrCatNbDdjLhXL/zi1OAaaU2xcSx
         x3nQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=QJVxB1VCfI6KusMgyUKoVn9ra2wF9uGUlqzP8fySzgI=;
        b=W/Xl34EB4lz9ccqcY4ntWlwawkMHxMoN4kzZj0b9af11cy4dbLPaBO+QJBknmc6bn4
         cpDNh1oKznSGbruXtB9SqVQod/ZTw+pjeJNk401gkRcqnXCn4lkBMCnJlaMZFbFk/rPU
         ZQrUuAPT0DEgeKULSC0fKPUMnn0jb3IRgXJ6Zw/8zrvPS9T+Oujy9XCA+0b8WIMCprSV
         I3PqQbbhp5+FgRsoHXHn3hHiftJYDyQn+ttDO6hHN3H+b3fNjcBEZuFDazI5FG7a79b/
         DxscutblQuZXW1RgLDu5Xyex2z7H4RPV4wHh4M//1sGuYKSc9KjlWFl9PlhhKos0u+ck
         pZng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YejG3w1m;
       spf=pass (google.com: domain of 3u7l6xqukczgb2ff98gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3U7L6XQUKCZgB2FF98GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id cc24si132653edb.5.2019.12.18.15.12.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Dec 2019 15:12:20 -0800 (PST)
Received-SPF: pass (google.com: domain of 3u7l6xqukczgb2ff98gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id h30so1511123wrh.5
        for <kasan-dev@googlegroups.com>; Wed, 18 Dec 2019 15:12:20 -0800 (PST)
X-Received: by 2002:adf:f448:: with SMTP id f8mr5828298wrp.263.1576710739585;
 Wed, 18 Dec 2019 15:12:19 -0800 (PST)
Date: Thu, 19 Dec 2019 00:11:50 +0100
In-Reply-To: <20191218231150.12139-1-jannh@google.com>
Message-Id: <20191218231150.12139-4-jannh@google.com>
Mime-Version: 1.0
References: <20191218231150.12139-1-jannh@google.com>
X-Mailer: git-send-email 2.24.1.735.g03f4e72817-goog
Subject: [PATCH v7 4/4] x86/kasan: Print original address on #GP
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
 header.i=@google.com header.s=20161025 header.b=YejG3w1m;       spf=pass
 (google.com: domain of 3u7l6xqukczgb2ff98gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--jannh.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3U7L6XQUKCZgB2FF98GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--jannh.bounces.google.com;
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
    general protection fault, probably for non-canonical address
        0xe017577ddf75b7dd: 0000 [#1] PREEMPT SMP KASAN PTI

into this:

    general protection fault, probably for non-canonical address
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
    v6:
     - adjust sample output in commit message
    v7:
     - instead of open-coding __die_header()+__die_body() in traps.c,
       insert a hook call into die_body(), introduced in patch 3/4
       (Borislav)

 arch/x86/kernel/dumpstack.c |  2 ++
 arch/x86/mm/kasan_init_64.c | 21 -------------------
 include/linux/kasan.h       |  6 ++++++
 mm/kasan/report.c           | 40 +++++++++++++++++++++++++++++++++++++
 4 files changed, 48 insertions(+), 21 deletions(-)

diff --git a/arch/x86/kernel/dumpstack.c b/arch/x86/kernel/dumpstack.c
index 8995bf10c97c..ae64ec7f752f 100644
--- a/arch/x86/kernel/dumpstack.c
+++ b/arch/x86/kernel/dumpstack.c
@@ -427,6 +427,8 @@ void die_addr(const char *str, struct pt_regs *regs, long err, long gp_addr)
 	int sig = SIGSEGV;
 
 	__die_header(str, regs, err);
+	if (gp_addr)
+		kasan_non_canonical_hook(gp_addr);
 	if (__die_body(str, regs, err))
 		sig = 0;
 	oops_end(flags, regs, sig);
diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index cf5bc37c90ac..763e71abc0fe 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -288,23 +288,6 @@ static void __init kasan_shallow_populate_pgds(void *start, void *end)
 	} while (pgd++, addr = next, addr != (unsigned long)end);
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
@@ -341,10 +324,6 @@ void __init kasan_init(void)
 	int i;
 	void *shadow_cpu_entry_begin, *shadow_cpu_entry_end;
 
-#ifdef CONFIG_KASAN_INLINE
-	register_die_notifier(&kasan_die_notifier);
-#endif
-
 	memcpy(early_top_pgt, init_top_pgt, sizeof(early_top_pgt));
 
 	/*
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 4f404c565db1..e0238af0388f 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -225,4 +225,10 @@ static inline void kasan_release_vmalloc(unsigned long start,
 					 unsigned long free_region_end) {}
 #endif
 
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
2.24.1.735.g03f4e72817-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191218231150.12139-4-jannh%40google.com.
