Return-Path: <kasan-dev+bncBCZP5TXROEILJ45TXADBUBCXFMTAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 46D4599C7DE
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 13:00:07 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-71e5a7bd897sf1184762b3a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 04:00:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728903605; cv=pass;
        d=google.com; s=arc-20240605;
        b=dfU3gTO998fJszOQmiMhH2bt+6RPvxGCwWDEK7RZa5UxSikpMzfIJXIpvWyZGfyJyd
         j7JRP6kVRx14cs5RgwjrJ1hn13VuMVALRkpF/h0vzr3U3U5wluIeI1rgaEmKhL0mBScd
         fuRwZmgChekB3vMOaX1Qb3x31SUWcp4inT2I1II/2y8Y8jlhVWW+Qa9wEtGiI48WalA4
         pDlBmaCZ341QlgaNBMM4CzNq7WGXKk7TlZc+ynIGjGwlyuelv4bhP0MgEQu4K6rxFbWK
         jsTJgCawQkAFlhm2mZE6tO0+D9yddrecB/MIeK1jn8eAKYTPZMTX14240ecOKcB+Q9Wu
         XDqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=vwl/5o5XpbKAqiMNEkTA5aJCqNPimPl7mGTXrdqnzSE=;
        fh=eDnTmwAz+9+QTi4uOfBFX6l9AXvb9mFPlSMOw0PdQac=;
        b=Zpphyt7D4+NwcTWXMKvRPD51w11R+TNHlDPioPT9ZxGTme+7kQ4UMR5fXlxbf6R6jo
         tmWKOhUxmQ1ftv5QXQ9ED+Wem7COjhiyDF+eqpXBeOOovRMbgUaK4a2bc/pEWOmFH9dj
         N7afUVVlvsY8f3M2PWTKHdtraX100+bw5ddAgNI0k6V8jUdWcIYT2X4LNaGz2xRTsimu
         czLqdPMX2+rYcvXt+cM89cTQeTODRJEcADopDx3AjXawL3Qun8bKQOtTekt8POzp+Z4S
         TgBl7M1j6ZZZO5vl96AW1Ot2VVaa+CTMunDhFQiwLsjwgDsGBjmSUoR6ygL6gg+A6x/3
         Wbdw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728903605; x=1729508405; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vwl/5o5XpbKAqiMNEkTA5aJCqNPimPl7mGTXrdqnzSE=;
        b=PquEOtunWD1UqUTMO2gzfQp1/3qTd7/+AgeS4TrDaWqjBbEe50AQUleGMksE8qfkJ+
         q/lp61XfPAF+Ennaa+kl8RdlyJdafGgrnzgjQtA869Xb14IOEhf1pepC3HY3y1SwFlaD
         FoHRnlCMUB8GGhUE2zE03JXiWA5ooAiFhL4yqsbHc7jEHa2xmfdBO+IJON/muj1Y2pk2
         JyLodBbN4UzleqTYDobl7qYM2r8/S/c6cc/DNnBrxQ3bmsxxr0WNHjyaG8mdviHqs9ug
         1L1EZXUt6whKIW/LfypySBHqHytlVPmeQIMW/INlJXhocYa4Wn/k5srk7s1kIhB5fd9B
         d4rw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728903605; x=1729508405;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vwl/5o5XpbKAqiMNEkTA5aJCqNPimPl7mGTXrdqnzSE=;
        b=V0MnA6CJnWDHZuocDWBCzqoC61j0NNgEUedLahg8rr9a1d4K9ZtVmhPgKPy14fHyk+
         iS4Sj+W0Yot7J/ewtzGbd3YOxzudC5xAaRVMIoT8eoOvTM68BwGUH3kTz7bDwH/41ItO
         5Ag0RWLeb9WwLGXHpY14VncFfFcY/nT3gyfvlnWN/1MGU/34VEHsvz1NUf4Se01ltCG5
         ooRXcLdlyFs4YFkg6fQkUdBNgT+o0u7kCrp5W7Pr9N75yYL7YKL1N1kbS6NGqDiGtyr/
         Ydmx/gb1vuO31MroBy6e4K3+ZO03VpWj6ejUDAMlpOpgMa/biDYEFQ17UBzPd2EAMcKT
         ZB1A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWL/W3qe7J/a7Hwso5HkozIwRwD0a5hJiLrPoF8jW9Kykjf4CY5b7euN2OldyNoz/yGdnN0NA==@lfdr.de
X-Gm-Message-State: AOJu0Yx1kDtcTxukwyCI4/BT8L2tUJoEBzNJGzzo+IouibxLyPjAI+vL
	F16anheNpSZVcjZtNSkjh4Yj2DsQsdUAfbAf8UAXiaQPdCKR3BFE
X-Google-Smtp-Source: AGHT+IHZV5EcQdvgdiJ9776F1/rxU1ZdHeuOlSoCbNJCWVsOMUZViDGRDIelsYe0IyhtpYr8JZZ4rw==
X-Received: by 2002:a05:6a00:8d3:b0:71e:5a6a:94ca with SMTP id d2e1a72fcca58-71e5a6a9589mr8168129b3a.19.1728903605143;
        Mon, 14 Oct 2024 04:00:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:855:b0:71e:1d00:d753 with SMTP id
 d2e1a72fcca58-71e2704efa1ls3903577b3a.1.-pod-prod-02-us; Mon, 14 Oct 2024
 04:00:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUPI9nnu+wPm4QjFSO47gCrxSUQ+HsBwlFPxxffVNdarx7SCXnpaJmGiP0NwcxCW/D9byQd2IQUly8=@googlegroups.com
X-Received: by 2002:a05:6a21:e591:b0:1d3:9cd:e737 with SMTP id adf61e73a8af0-1d8bcf55280mr16207453637.28.1728903603677;
        Mon, 14 Oct 2024 04:00:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728903603; cv=none;
        d=google.com; s=arc-20240605;
        b=F860ObMH+btRSC/94IVv8KmqPU/5Q2uXr/fsmBo3Z64BHe2kkER+tlrPAwotfSaZSG
         Va/eX3iakI1wpcTRwJnQbaCR9Usbi0y8vLBDVvlERtwvq6Z/chEBYmxP4vAcJk+WT3TW
         f95IWXDTtb4IBV9U22zp1kZTrFZ11+YnhY6JQlmduQe2cj0oVEgp2wn8R0AwDUj/xrZ8
         6AnLgVoRBuWh0fyXj61Ajq/ujISRfuMl5THeX/c8xMGUW8B3kNvyFAuIkQadJ+bXPEoQ
         Gw/amO9r7RjcmqKvQ8HsAjiR4yf8oALk+KDjQdFvpNMclRB1XldWGd8sicIr4ll7nAOU
         DYJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=B2YC/X3UwnXWGexJl2uM83krn8GDdx7g25hAIge8UU4=;
        fh=fvyV0qyRdEL9b8DWnqLz5/SQGtW3AyuNuwJzIOu6DiU=;
        b=IYLNk4v0ILS8PK2ksuLRcvQ8SkQKuLavYEcfmiQ1Fo4xNQyvfh6+12AGfCDSkD9FNV
         WiGE9iuTfDfnWjr9eY3LPhpSEYMuc76VVqgCQ1iNjsbB9dh/hcukuTWyEHcngD10P9Kk
         8i/mf0uaZW2T/F/fO+zUD55eVP2hT9T8g0Yz9h+1/ORzLxUsfa774sxW+twvc7bArFiW
         B2uCm9DSW7wk9TbfGBfcxC1ZGH/GNB+GPgnqD2bIru1U0chHRKxiED+So2q7P+ljQNWH
         XAbC35nt809/bHOCSARLm/f00H2k6xGaFfTfRloUstIZflOX17nMHw1fTZEBrW5FLx0T
         mgdQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 98e67ed59e1d1-2e2cc1d9c1bsi679019a91.0.2024.10.14.04.00.03
        for <kasan-dev@googlegroups.com>;
        Mon, 14 Oct 2024 04:00:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id E3B391424;
	Mon, 14 Oct 2024 04:00:31 -0700 (PDT)
Received: from e125769.cambridge.arm.com (e125769.cambridge.arm.com [10.1.196.27])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E14783F51B;
	Mon, 14 Oct 2024 03:59:58 -0700 (PDT)
From: Ryan Roberts <ryan.roberts@arm.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Anshuman Khandual <anshuman.khandual@arm.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	David Hildenbrand <david@redhat.com>,
	Greg Marsden <greg.marsden@oracle.com>,
	Ingo Molnar <mingo@redhat.com>,
	Ivan Ivanov <ivan.ivanov@suse.com>,
	Juri Lelli <juri.lelli@redhat.com>,
	Kalesh Singh <kaleshsingh@google.com>,
	Marc Zyngier <maz@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Matthias Brugger <mbrugger@suse.com>,
	Miroslav Benes <mbenes@suse.cz>,
	Peter Zijlstra <peterz@infradead.org>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Will Deacon <will@kernel.org>
Cc: Ryan Roberts <ryan.roberts@arm.com>,
	kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org
Subject: [RFC PATCH v1 11/57] fork: Permit boot-time THREAD_SIZE determination
Date: Mon, 14 Oct 2024 11:58:18 +0100
Message-ID: <20241014105912.3207374-11-ryan.roberts@arm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20241014105912.3207374-1-ryan.roberts@arm.com>
References: <20241014105514.3206191-1-ryan.roberts@arm.com>
 <20241014105912.3207374-1-ryan.roberts@arm.com>
MIME-Version: 1.0
X-Original-Sender: ryan.roberts@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=ryan.roberts@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
Content-Type: text/plain; charset="UTF-8"
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

THREAD_SIZE defines the size of a kernel thread stack. To date, it has
been set at compile-time. However, when using vmap stacks, the size must
be a multiple of PAGE_SIZE, and given we are in the process of
supporting boot-time page size, we must also do the same for
THREAD_SIZE.

The alternative would be to define THREAD_SIZE for the largest supported
page size, but this would waste memory when using a smaller page size.
For example, arm64 requires THREAD_SIZE to be 16K, but when using 64K
pages and a vmap stack, we must increase the size to 64K. If we required
64K when 4K or 16K page size was in use, we would waste 48K per kernel
thread.

So let's refactor to allow THREAD_SIZE to not be a compile-time
constant. THREAD_SIZE_MAX (and THREAD_ALIGN_MAX) are introduced to
manage the limits, as is done for PAGE_SIZE.

When THREAD_SIZE is a compile-time constant, behaviour and code size
should be equivalent.

Signed-off-by: Ryan Roberts <ryan.roberts@arm.com>
---

***NOTE***
Any confused maintainers may want to read the cover note here for context:
https://lore.kernel.org/all/20241014105514.3206191-1-ryan.roberts@arm.com/

 include/asm-generic/vmlinux.lds.h |  6 ++-
 include/linux/sched.h             |  4 +-
 include/linux/thread_info.h       | 10 ++++-
 init/main.c                       |  2 +-
 kernel/fork.c                     | 67 +++++++++++--------------------
 mm/kasan/report.c                 |  3 +-
 6 files changed, 42 insertions(+), 50 deletions(-)

diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
index 5727f883001bb..f19bab7a2e8f9 100644
--- a/include/asm-generic/vmlinux.lds.h
+++ b/include/asm-generic/vmlinux.lds.h
@@ -56,6 +56,10 @@
 #define LOAD_OFFSET 0
 #endif
 
+#ifndef THREAD_SIZE_MAX
+#define THREAD_SIZE_MAX		THREAD_SIZE
+#endif
+
 /*
  * Only some architectures want to have the .notes segment visible in
  * a separate PT_NOTE ELF Program Header. When this happens, it needs
@@ -398,7 +402,7 @@
 	init_stack = .;							\
 	KEEP(*(.data..init_task))					\
 	KEEP(*(.data..init_thread_info))				\
-	. = __start_init_stack + THREAD_SIZE;				\
+	. = __start_init_stack + THREAD_SIZE_MAX;			\
 	__end_init_stack = .;
 
 #define JUMP_TABLE_DATA							\
diff --git a/include/linux/sched.h b/include/linux/sched.h
index f8d150343d42d..3de4f655ee492 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1863,14 +1863,14 @@ union thread_union {
 #ifndef CONFIG_THREAD_INFO_IN_TASK
 	struct thread_info thread_info;
 #endif
-	unsigned long stack[THREAD_SIZE/sizeof(long)];
+	unsigned long stack[THREAD_SIZE_MAX/sizeof(long)];
 };
 
 #ifndef CONFIG_THREAD_INFO_IN_TASK
 extern struct thread_info init_thread_info;
 #endif
 
-extern unsigned long init_stack[THREAD_SIZE / sizeof(unsigned long)];
+extern unsigned long init_stack[THREAD_SIZE_MAX / sizeof(unsigned long)];
 
 #ifdef CONFIG_THREAD_INFO_IN_TASK
 # define task_thread_info(task)	(&(task)->thread_info)
diff --git a/include/linux/thread_info.h b/include/linux/thread_info.h
index 9ea0b28068f49..a7ccc448cd298 100644
--- a/include/linux/thread_info.h
+++ b/include/linux/thread_info.h
@@ -74,7 +74,15 @@ static inline long set_restart_fn(struct restart_block *restart,
 }
 
 #ifndef THREAD_ALIGN
-#define THREAD_ALIGN	THREAD_SIZE
+#define THREAD_ALIGN		THREAD_SIZE
+#endif
+
+#ifndef THREAD_SIZE_MAX
+#define THREAD_SIZE_MAX		THREAD_SIZE
+#endif
+
+#ifndef THREAD_ALIGN_MAX
+#define THREAD_ALIGN_MAX	max(THREAD_ALIGN, THREAD_SIZE_MAX)
 #endif
 
 #define THREADINFO_GFP		(GFP_KERNEL_ACCOUNT | __GFP_ZERO)
diff --git a/init/main.c b/init/main.c
index ba1515eb20b9d..4dc28115fdf57 100644
--- a/init/main.c
+++ b/init/main.c
@@ -797,7 +797,7 @@ void __init __weak smp_prepare_boot_cpu(void)
 {
 }
 
-# if THREAD_SIZE >= PAGE_SIZE
+#ifdef CONFIG_VMAP_STACK
 void __init __weak thread_stack_cache_init(void)
 {
 }
diff --git a/kernel/fork.c b/kernel/fork.c
index ea472566d4fcc..cbc3e73f9b501 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -184,13 +184,7 @@ static inline void free_task_struct(struct task_struct *tsk)
 	kmem_cache_free(task_struct_cachep, tsk);
 }
 
-/*
- * Allocate pages if THREAD_SIZE is >= PAGE_SIZE, otherwise use a
- * kmemcache based allocator.
- */
-# if THREAD_SIZE >= PAGE_SIZE || defined(CONFIG_VMAP_STACK)
-
-#  ifdef CONFIG_VMAP_STACK
+#ifdef CONFIG_VMAP_STACK
 /*
  * vmalloc() is a bit slow, and calling vfree() enough times will force a TLB
  * flush.  Try to minimize the number of calls by caching stacks.
@@ -343,46 +337,21 @@ static void free_thread_stack(struct task_struct *tsk)
 	tsk->stack_vm_area = NULL;
 }
 
-#  else /* !CONFIG_VMAP_STACK */
+#else /* !CONFIG_VMAP_STACK */
 
-static void thread_stack_free_rcu(struct rcu_head *rh)
-{
-	__free_pages(virt_to_page(rh), THREAD_SIZE_ORDER);
-}
-
-static void thread_stack_delayed_free(struct task_struct *tsk)
-{
-	struct rcu_head *rh = tsk->stack;
-
-	call_rcu(rh, thread_stack_free_rcu);
-}
-
-static int alloc_thread_stack_node(struct task_struct *tsk, int node)
-{
-	struct page *page = alloc_pages_node(node, THREADINFO_GFP,
-					     THREAD_SIZE_ORDER);
-
-	if (likely(page)) {
-		tsk->stack = kasan_reset_tag(page_address(page));
-		return 0;
-	}
-	return -ENOMEM;
-}
-
-static void free_thread_stack(struct task_struct *tsk)
-{
-	thread_stack_delayed_free(tsk);
-	tsk->stack = NULL;
-}
-
-#  endif /* CONFIG_VMAP_STACK */
-# else /* !(THREAD_SIZE >= PAGE_SIZE || defined(CONFIG_VMAP_STACK)) */
+/*
+ * Allocate pages if THREAD_SIZE is >= PAGE_SIZE, otherwise use a
+ * kmemcache based allocator.
+ */
 
 static struct kmem_cache *thread_stack_cache;
 
 static void thread_stack_free_rcu(struct rcu_head *rh)
 {
-	kmem_cache_free(thread_stack_cache, rh);
+	if (THREAD_SIZE >= PAGE_SIZE)
+		__free_pages(virt_to_page(rh), THREAD_SIZE_ORDER);
+	else
+		kmem_cache_free(thread_stack_cache, rh);
 }
 
 static void thread_stack_delayed_free(struct task_struct *tsk)
@@ -395,7 +364,16 @@ static void thread_stack_delayed_free(struct task_struct *tsk)
 static int alloc_thread_stack_node(struct task_struct *tsk, int node)
 {
 	unsigned long *stack;
-	stack = kmem_cache_alloc_node(thread_stack_cache, THREADINFO_GFP, node);
+	struct page *page;
+
+	if (THREAD_SIZE >= PAGE_SIZE) {
+		page = alloc_pages_node(node, THREADINFO_GFP, THREAD_SIZE_ORDER);
+		stack = likely(page) ? page_address(page) : NULL;
+	} else {
+		stack = kmem_cache_alloc_node(thread_stack_cache,
+					      THREADINFO_GFP, node);
+	}
+
 	stack = kasan_reset_tag(stack);
 	tsk->stack = stack;
 	return stack ? 0 : -ENOMEM;
@@ -409,13 +387,16 @@ static void free_thread_stack(struct task_struct *tsk)
 
 void thread_stack_cache_init(void)
 {
+	if (THREAD_SIZE >= PAGE_SIZE)
+		return;
+
 	thread_stack_cache = kmem_cache_create_usercopy("thread_stack",
 					THREAD_SIZE, THREAD_SIZE, 0, 0,
 					THREAD_SIZE, NULL);
 	BUG_ON(thread_stack_cache == NULL);
 }
 
-# endif /* THREAD_SIZE >= PAGE_SIZE || defined(CONFIG_VMAP_STACK) */
+#endif /* CONFIG_VMAP_STACK */
 
 /* SLAB cache for signal_struct structures (tsk->signal) */
 static struct kmem_cache *signal_cachep;
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index b48c768acc84d..57c877852dbc6 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -365,8 +365,7 @@ static inline bool kernel_or_module_addr(const void *addr)
 static inline bool init_task_stack_addr(const void *addr)
 {
 	return addr >= (void *)&init_thread_union.stack &&
-		(addr <= (void *)&init_thread_union.stack +
-			sizeof(init_thread_union.stack));
+		(addr <= (void *)&init_thread_union.stack + THREAD_SIZE);
 }
 
 static void print_address_description(void *addr, u8 tag,
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241014105912.3207374-11-ryan.roberts%40arm.com.
