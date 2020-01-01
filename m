Return-Path: <kasan-dev+bncBAABBVO6WHYAKGQEP3OULHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-f60.google.com (mail-wr1-f60.google.com [209.85.221.60])
	by mail.lfdr.de (Postfix) with ESMTPS id CA63112DE6E
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Jan 2020 11:07:17 +0100 (CET)
Received: by mail-wr1-f60.google.com with SMTP id k18sf19173261wrw.9
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Jan 2020 02:07:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1577873237; cv=pass;
        d=google.com; s=arc-20160816;
        b=y3/jnGha7iXgJYQPh+9uWMv6Nv0N1FYrWSb39Ypg4ejshTL5vdma4ARMt3lPQLGIrx
         8cpDfiO7/1883ISer+uciNKUA5WlrAxaYhYvjsRMi8ZAk6q/AiwVrGeOarqMS5Lc1Y5a
         rq/Kx1zgCP8LcjHjkCcWZos5O8q7jKp0LD656TZf+hpaiDKTKA+LLzbUaZDwu+bfh1hD
         ft5eWGF4wyzzSzmTz+lola2GdB410VvMO6gBjvhRqgyuQKYfuQFCo7QsHvcMktyUiAf2
         vTdEcUbkzh7WzBXibn0ZvKRwTPYgZOSWgJPIHb9bzeR+7ouXL1l9EAuo1lAaFOnsngw7
         yqjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:robot-unsubscribe:robot-id
         :message-id:mime-version:references:in-reply-to:cc:subject:to
         :reply-to:sender:from:date;
        bh=laTBLL0mxJVFmvWpxed/Zk7lDAQmWGhAkfMLGIa7G04=;
        b=NfYwGjkUhYjms4Bj5H+w2ohdRvLjk0sPlQZXpT+sP0Ilf0rtIhA8uMFVUE8BNQKI5K
         ht7mNVd3xrlQSYyGNK2uckbC90Kpef/GyL++N11dks2IOL3ziF9ebku15xXvgv0O0lAc
         iNtqcL6YoHWrQhms+BQuCpLXRHY5BV6FX+6Zre0gTBU01yAuoB6+crP8M/a/3QsNSKzw
         lmN5DmRpV3V/VDoexB0xJNFv5m6sE5OquunPfmsTYd8lpAOlCLzGlTJWqWDs8fKJBwg2
         2V4J6uX7F/TAfRZrAGQQVwmdKMT1/usLwVhml6PHTYsUImt9fJmgr39sQDQES+32ApgV
         32eg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of tip-bot2@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tip-bot2@linutronix.de
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:sender:reply-to:to:subject:cc
         :in-reply-to:references:mime-version:message-id:robot-id
         :robot-unsubscribe:precedence:x-original-sender
         :x-original-authentication-results:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=laTBLL0mxJVFmvWpxed/Zk7lDAQmWGhAkfMLGIa7G04=;
        b=DynmR/2ZYw99aOQX1QBCJiBWKno7LF+PziZUwTRGK20vPXmcT/5/+Y2Gb0ZASO4R44
         uneYst+XSLW+xDIYZv/8Fc9LcnGfqnF+spqJVTLPmtnoEFqB/pAnaU8PkJSAgCPqrSnQ
         hZ4uwJeX45tylzX9RFWHMQXABp2tdJfSGH3O5HToF+oH4v8jaIqS4UKro7YIryXJj8Yx
         IuVM24xonSQco2fpbXmqCYF0iGeGl8qHiHpY61c626HTWlKGejY6stocvBeSpkhnfkXi
         o+QZdLauPvs7PuzkgHdlB5+sCqfDL0mJu5YCStdvM+GtCqbnyNbp9kk6FEEm0NVivBoG
         0i0A==
X-Gm-Message-State: APjAAAUBWjeiNe9UkNKA0/q/WOT3JE/RoC8eLRDJaMFk4/TXkqo4B/Ok
	8lLcf6M9aon3wsfaenL7oFs=
X-Google-Smtp-Source: APXvYqw+Wgz9AsFPsEDW6wOU7i28WfFZVV33o3uTwGRBLrrvXPfIqL+2Mrev5iKVKyZQ5zqmbMR/DA==
X-Received: by 2002:a05:600c:30a:: with SMTP id q10mr8480985wmd.84.1577873237456;
        Wed, 01 Jan 2020 02:07:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cb55:: with SMTP id v21ls1205632wmj.4.canary-gmail; Wed,
 01 Jan 2020 02:07:17 -0800 (PST)
X-Received: by 2002:a7b:c342:: with SMTP id l2mr9272974wmj.159.1577873237007;
        Wed, 01 Jan 2020 02:07:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1577873237; cv=none;
        d=google.com; s=arc-20160816;
        b=uIz6TKTfivK5GdGDIImbgcyg9koFMvWZHn4j9/3J3304ryYCRKk00iVk8VzL5DISVS
         qg8OThMXHgvNlnBesL2GwQaXsj4sHNcpII/fjgPGvazR/98zwCqMDz6LJSpLnKCmfLlC
         NSMy0wiQh8nxLVkq2d5RMa0BV3vNTo0W3CFfb6kmJ9n+xTjTlLfa4XToUNAp3qzD3S31
         cjdv+IiKk6/st9NOQmLjdW4wsMAq8+60VkgiebXNVAnWZA6YxZ3i6BSLfM8NqjoFbhbM
         DCFVzGcupvIxjruQcyCTTnFp5Uxis1KRUCA6Fv4dQfTwLd0+QFFk/qn+XS7rWM6pvnDa
         F/Lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:precedence:robot-unsubscribe:robot-id
         :message-id:mime-version:references:in-reply-to:cc:subject:to
         :reply-to:sender:from:date;
        bh=7x6ZxTeX/T9IRYDy8G4cz8njUXnLYigPjIJD7YHmwec=;
        b=XgoIfwDxF54SHLCZC/trr6SnKqyFEzSrc/mWesLSWPJgDxVSS2kXhB6BINPJ8nMYwv
         DTi7cEc7sOIKgWhDmupDtYWBLVI2cZG4DlWb0RNax1Vee53HItN4tPNlNsJD6EIY+J0B
         X5pjcOMN+1jmCcwPJeJjxGUR20WijKMINT7HI18CNu1gz4IB/9akuiN3npfocRiSoTs+
         Zxs/z7rErX8HuDK2gx3RGIuzACcGwjjLakXe+ZfAbbqDM85Srn+K+UmC0OS7gdCo0TwQ
         ufn9gxiyuYewhHdXzBF9r1THBmjj13PWWciNM2NQsfA2beXY/L00kIWJhEh5QmicSpF8
         Napg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of tip-bot2@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tip-bot2@linutronix.de
Received: from Galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id o139si221187wme.1.2020.01.01.02.07.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=AES128-SHA bits=128/128);
        Wed, 01 Jan 2020 02:07:16 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of tip-bot2@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Received: from [5.158.153.53] (helo=tip-bot2.lab.linutronix.de)
	by Galois.linutronix.de with esmtpsa (TLS1.2:DHE_RSA_AES_256_CBC_SHA256:256)
	(Exim 4.80)
	(envelope-from <tip-bot2@linutronix.de>)
	id 1imauH-0004P0-MQ; Wed, 01 Jan 2020 11:07:14 +0100
Received: from [127.0.1.1] (localhost [IPv6:::1])
	by tip-bot2.lab.linutronix.de (Postfix) with ESMTP id 169A81C2BFF;
	Wed,  1 Jan 2020 11:07:13 +0100 (CET)
Date: Wed, 01 Jan 2020 10:07:12 -0000
From: "tip-bot2 for Jann Horn" <tip-bot2@linutronix.de>
Sender: tip-bot2@linutronix.de
Reply-to: linux-kernel@vger.kernel.org
To: linux-tip-commits@vger.kernel.org
Subject: [tip: x86/core] x86/kasan: Print original address on #GP
Cc: Jann Horn <jannh@google.com>, Borislav Petkov <bp@suse.de>,
 Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Andrey Konovalov <andreyknvl@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Andy Lutomirski <luto@kernel.org>,
 Dave Hansen <dave.hansen@linux.intel.com>, "H. Peter Anvin" <hpa@zytor.com>,
 Ingo Molnar <mingo@redhat.com>, kasan-dev@googlegroups.com,
 "linux-mm" <linux-mm@kvack.org>, Peter Zijlstra <peterz@infradead.org>,
 Sean Christopherson <sean.j.christopherson@intel.com>,
 Thomas Gleixner <tglx@linutronix.de>, "x86-ml" <x86@kernel.org>,
 LKML <linux-kernel@vger.kernel.org>
In-Reply-To: <20191218231150.12139-4-jannh@google.com>
References: <20191218231150.12139-4-jannh@google.com>
MIME-Version: 1.0
Message-ID: <157787323296.30329.6279558999926427913.tip-bot2@tip-bot2>
X-Mailer: tip-git-log-daemon
Robot-ID: <tip-bot2.linutronix.de>
Robot-Unsubscribe: Contact <mailto:tglx@linutronix.de> to get blacklisted from these emails
Precedence: list
Content-Type: text/plain; charset="UTF-8"
X-Linutronix-Spam-Score: -1.0
X-Linutronix-Spam-Level: -
X-Linutronix-Spam-Status: No , -1.0 points, 5.0 required,  ALL_TRUSTED=-1,SHORTCIRCUIT=-0.0001
X-Original-Sender: tip-bot2@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of tip-bot2@linutronix.de
 designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tip-bot2@linutronix.de
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

The following commit has been merged into the x86/core branch of tip:

Commit-ID:     2f004eea0fc8f86b45dfc2007add2d4986de8d02
Gitweb:        https://git.kernel.org/tip/2f004eea0fc8f86b45dfc2007add2d4986de8d02
Author:        Jann Horn <jannh@google.com>
AuthorDate:    Thu, 19 Dec 2019 00:11:50 +01:00
Committer:     Borislav Petkov <bp@suse.de>
CommitterDate: Tue, 31 Dec 2019 13:15:38 +01:00

x86/kasan: Print original address on #GP

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
Signed-off-by: Borislav Petkov <bp@suse.de>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Andy Lutomirski <luto@kernel.org>
Cc: Dave Hansen <dave.hansen@linux.intel.com>
Cc: "H. Peter Anvin" <hpa@zytor.com>
Cc: Ingo Molnar <mingo@redhat.com>
Cc: kasan-dev@googlegroups.com
Cc: linux-mm <linux-mm@kvack.org>
Cc: Peter Zijlstra <peterz@infradead.org>
Cc: Sean Christopherson <sean.j.christopherson@intel.com>
Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: x86-ml <x86@kernel.org>
Link: https://lkml.kernel.org/r/20191218231150.12139-4-jannh@google.com
---
 arch/x86/kernel/dumpstack.c |  2 ++-
 arch/x86/mm/kasan_init_64.c | 21 +-------------------
 include/linux/kasan.h       |  6 +++++-
 mm/kasan/report.c           | 40 ++++++++++++++++++++++++++++++++++++-
 4 files changed, 48 insertions(+), 21 deletions(-)

diff --git a/arch/x86/kernel/dumpstack.c b/arch/x86/kernel/dumpstack.c
index 8995bf1..ae64ec7 100644
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
index cf5bc37..763e71a 100644
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
index e18fe54..5cde9e7 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -228,4 +228,10 @@ static inline void kasan_release_vmalloc(unsigned long start,
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
index 6217821..5ef9f24 100644
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
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/157787323296.30329.6279558999926427913.tip-bot2%40tip-bot2.
