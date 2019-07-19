Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBELY7UQKGQECTWNHHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 741DF6E65A
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Jul 2019 15:28:38 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id u1sf18713830pgr.13
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Jul 2019 06:28:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1563542916; cv=pass;
        d=google.com; s=arc-20160816;
        b=hG3+XDcOsU3sdXpqCuw8++tG5TRCbFqVX2Ok83w/I3XA+0jAvgEXBUCH6h6v0zabCl
         iRm1Hl0efKsZaLaybclog2l52BJvjB2GGYPedGtC9huNy+oGeTvQhsdgWgZJWVd9yA6t
         1Oivr37TR0yyCAIIDE/TTZTUeQos07Zg/B3jwfWcFvCSQaiw4Ar+sxU0ObbVErwxR1j5
         YOZre6TUKyGrOKou1XmKFB9L8LGPshO4Kh2gd1l8DyxcR5q83SJAlYS6torcsQ6dfybn
         fVI/pw9qqIZbgCAEhzWU/vWYPUFfuZtEHjP3ukNMol8SlthHEaNSq/LVWnLUSBGlqoHZ
         4utA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=MKbCF4sh3a/mlHLxVFBm+1/rs8EaZF7p8Thw7E86XCY=;
        b=BPqZVvZw5EQ+y347z8F7ZMRB7uhaLoZosE997V5hbXJoC8IxDTuwTfhTb5Ft3flpyP
         yN/QZSqpnBNbT2AyGzCFOy4JL38XAKWOlEZX0pqCOTEHM7RY8bocdpRfxVIFSOpcOWXg
         WJKKnqSiE7tgRVFVxv19SYv6TwD7iEa245grMKPxqo+IG1W89T4fnPZGlPmvvC0N8+1s
         PUj1xYKCw7bdFeM7NIAFoj7Nomgh7XPz0mdV0ph4jnOM2dpEGLrs71v+DMpryTy5pzem
         i+MRTVomgIL1eViCkghkFXXrnZppAmMYIgRIZQ1J+KNIMwzIMOYFFPbLGC45Deovn1mN
         5F1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qlZ5YXsQ;
       spf=pass (google.com: domain of 3g8uxxqukccqov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::64a as permitted sender) smtp.mailfrom=3g8UxXQUKCcQov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=MKbCF4sh3a/mlHLxVFBm+1/rs8EaZF7p8Thw7E86XCY=;
        b=ccVwnLOpqxG4M8BYF3wOs4rEgaSC5ltCzNonSjAsl5FmlbTktHq8GIkqERqwq7oP4j
         9D02J5tD9Tb/gjNAM0HASXj69mQzYluS8dc3IkmXM+cTECQwvv0P2VwoEDSXifcI7tFd
         vvtKmEkyvD0J5Ty9DZCfMxUBKExR9OL7Zf8BibLZz3AGUAsifISFJUtjtysoGdA81X6t
         ZUyA075x/VqsO4LiwiQOXnNpXUSMWMmtQazFqS2wV5orsbm/u/Yasmb9XTFei2Q0p/xV
         fTTNVPrgkvazCQ/XP+BGwAOoSL/FGhvvBAmVV+KmJtQvPXpxzl0xWn1PuCnuP3I41pFW
         t+BA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MKbCF4sh3a/mlHLxVFBm+1/rs8EaZF7p8Thw7E86XCY=;
        b=AMtpEAbPn/4MZU0g5I4E0OP12YvqPPo7ONPQ5TQFAULANnc98cpi0VAEj33fIh79Gc
         y1eEnHI2ZpwQQxPkc2SSEnpKMaYHmDBSc7C1tP9f/HxphLEXxG+djWgU6Coa43hxB0AW
         qBxBbk0QxREmV4t7Pl3/g/KN/1pQ3RyIiy4kDr01sBstxKN/5BDqw05MR5vN/xCWHmkr
         u8sLOKKia12Lk3na2qLizh3pES15//INPnKnICrgTsZULv7+4dVdtdBZ0Q+n5ZcxuKbX
         OyFpoSp43Y4OVjldYrXhhi8GNDxzfIitrGYmuLCW4IQoDn23flUDiGNF2e+ujCCa6TUI
         CVDA==
X-Gm-Message-State: APjAAAVP9JfSEi1KwR9UJeEkjymxiquOwcBQvG7BircMSi3BMRDSGaDI
	6eWhI5GQXlwXaLwortxDxeQ=
X-Google-Smtp-Source: APXvYqzN6RdaNm6VI6AqhA8CmPf7XRdaiIsdpxYBakq4r5aaqFodFQokrKQGXbvc9iO9eKZcNPxnqQ==
X-Received: by 2002:a17:902:2862:: with SMTP id e89mr57328789plb.258.1563542916559;
        Fri, 19 Jul 2019 06:28:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:6b81:: with SMTP id p1ls7315258plk.6.gmail; Fri, 19
 Jul 2019 06:28:36 -0700 (PDT)
X-Received: by 2002:a17:902:bd94:: with SMTP id q20mr46214924pls.307.1563542916088;
        Fri, 19 Jul 2019 06:28:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1563542916; cv=none;
        d=google.com; s=arc-20160816;
        b=l84AqQN8cbn4bV2raNsamdGAWRaVtD4Fkb7xbEBZq/ERkGXNh7EhIustvdL99d5cxG
         TJn2L+jiVv0C8dJTga2uHFnxYBz3NC7ANUdYPynEkBe4+sWc+u0kUSj8W6ZLYOeZMKZQ
         JyddvAHmTZrc8T87aQNu+3t4QlPfrjikRzwMBLdkS9K93yvsXj0YTNn1Ugi6JiDJlr82
         oMslnOlSPIuyu5M4nFW34EVlNdIXlG//sNc7o/2Rx9fxIlbE+pAJIxYhNBVwoVzsBZie
         INlevnPQ5eZtiYLSUTIZgwJoVhtYid2jHLpqnsmOpJpTY4tIjhaVOJOi9OBQgyRxLONc
         S2Uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=iYL0YLGspAoacIEhwiD/4Rcr5rrGFUrtzpWbGW+PP1M=;
        b=Pc4xNHSH+wPbsE6HeofxOvYmSAmZzpkTxVmEy49PK64jNZXJANJwYwouppy/JNgFot
         GtuatL1dI4MawvkkdS9n3wVJNfIjsARhcJUaFLTyDO5McMMmODKtP/OreHsF4Qbh53v3
         uDfePjCOd0Zy5bGaYQVxtQonxVug9/Qbmq4lcdqr6qkGYUPd/WgXzr3bUfO8SAEz9CnJ
         Co5LyDVvBzE/gFlE9myd63adoBdcidP+qcNmrTUFyvcOOBqH03FpbkMMzlVlcBpIgsZ+
         zxvhdDNfIls8cD4tN80nl24awMk/cUQ2CWcklsb4+uJKsy9UEnBTu3qOhNHwQYoP+k6u
         KiEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qlZ5YXsQ;
       spf=pass (google.com: domain of 3g8uxxqukccqov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::64a as permitted sender) smtp.mailfrom=3g8UxXQUKCcQov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x64a.google.com (mail-pl1-x64a.google.com. [2607:f8b0:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id m93si1378657pje.2.2019.07.19.06.28.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Fri, 19 Jul 2019 06:28:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3g8uxxqukccqov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::64a as permitted sender) client-ip=2607:f8b0:4864:20::64a;
Received: by mail-pl1-x64a.google.com with SMTP id u10so15858033plq.21
        for <kasan-dev@googlegroups.com>; Fri, 19 Jul 2019 06:28:36 -0700 (PDT)
X-Received: by 2002:a63:ef4b:: with SMTP id c11mr51427206pgk.129.1563542915386;
 Fri, 19 Jul 2019 06:28:35 -0700 (PDT)
Date: Fri, 19 Jul 2019 15:28:17 +0200
Message-Id: <20190719132818.40258-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.22.0.657.g960e92d24f-goog
Subject: [PATCH 1/2] kernel/fork: Add support for stack-end guard page
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: linux-kernel@vger.kernel.org, Thomas Gleixner <tglx@linutronix.de>, 
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, "H. Peter Anvin" <hpa@zytor.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, x86@kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qlZ5YXsQ;       spf=pass
 (google.com: domain of 3g8uxxqukccqov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::64a as permitted sender) smtp.mailfrom=3g8UxXQUKCcQov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
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

Enabling STACK_GUARD_PAGE helps catching kernel stack overflows immediately
rather than causing difficult-to-diagnose corruption. Note that, unlike
virtually-mapped kernel stacks, this will effectively waste an entire page of
memory; however, this feature may provide extra protection in cases that cannot
use virtually-mapped kernel stacks, at the cost of a page.

The motivation for this patch is that KASAN cannot use virtually-mapped kernel
stacks to detect stack overflows. An alternative would be implementing support
for vmapped stacks in KASAN, but would add significant extra complexity. While
the stack-end guard page approach here wastes a page, it is significantly
simpler than the alternative.  We assume that the extra cost of a page can be
justified in the cases where STACK_GUARD_PAGE would be enabled.

Note that in an earlier prototype of this patch, we used
'set_memory_{ro,rw}' functions, which flush the TLBs. This, however,
turned out to be unacceptably expensive, especially when run with
fuzzers such as Syzkaller, as the kernel would encounter frequent RCU
timeouts. The current approach of not flushing the TLB is therefore
best-effort, but works in the test cases considered -- any comments on
better alternatives or improvements are welcome.

Signed-off-by: Marco Elver <elver@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: Ingo Molnar <mingo@redhat.com>
Cc: Borislav Petkov <bp@alien8.de>
Cc: "H. Peter Anvin" <hpa@zytor.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: Peter Zijlstra <peterz@infradead.org>
Cc: x86@kernel.org
Cc: linux-kernel@vger.kernel.org
Cc: kasan-dev@googlegroups.com
---
 arch/Kconfig                         | 15 +++++++++++++++
 arch/x86/include/asm/page_64_types.h |  8 +++++++-
 include/linux/sched/task_stack.h     | 11 +++++++++--
 kernel/fork.c                        | 22 +++++++++++++++++++++-
 4 files changed, 52 insertions(+), 4 deletions(-)

diff --git a/arch/Kconfig b/arch/Kconfig
index e8d19c3cb91f..cca3258fff1f 100644
--- a/arch/Kconfig
+++ b/arch/Kconfig
@@ -935,6 +935,21 @@ config LOCK_EVENT_COUNTS
 	  the chance of application behavior change because of timing
 	  differences. The counts are reported via debugfs.
 
+config STACK_GUARD_PAGE
+	default n
+	bool "Use stack-end page as guard page"
+	depends on !VMAP_STACK && ARCH_HAS_SET_DIRECT_MAP && THREAD_INFO_IN_TASK && !STACK_GROWSUP
+	help
+	  Enable this if you want to use the stack-end page as a guard page.
+	  This causes kernel stack overflows to be caught immediately rather
+	  than causing difficult-to-diagnose corruption. Note that, unlike
+	  virtually-mapped kernel stacks, this will effectively waste an entire
+	  page of memory; however, this feature may provide extra protection in
+	  cases that cannot use virtually-mapped kernel stacks, at the cost of
+	  a page. Note that, this option does not implicitly increase the
+	  default stack size. The main use-case is for KASAN to avoid reporting
+	  misleading bugs due to stack overflow.
+
 source "kernel/gcov/Kconfig"
 
 source "scripts/gcc-plugins/Kconfig"
diff --git a/arch/x86/include/asm/page_64_types.h b/arch/x86/include/asm/page_64_types.h
index 288b065955b7..b218b5713c02 100644
--- a/arch/x86/include/asm/page_64_types.h
+++ b/arch/x86/include/asm/page_64_types.h
@@ -12,8 +12,14 @@
 #define KASAN_STACK_ORDER 0
 #endif
 
+#ifdef CONFIG_STACK_GUARD_PAGE
+#define STACK_GUARD_SIZE PAGE_SIZE
+#else
+#define STACK_GUARD_SIZE 0
+#endif
+
 #define THREAD_SIZE_ORDER	(2 + KASAN_STACK_ORDER)
-#define THREAD_SIZE  (PAGE_SIZE << THREAD_SIZE_ORDER)
+#define THREAD_SIZE  ((PAGE_SIZE << THREAD_SIZE_ORDER) - STACK_GUARD_SIZE)
 
 #define EXCEPTION_STACK_ORDER (0 + KASAN_STACK_ORDER)
 #define EXCEPTION_STKSZ (PAGE_SIZE << EXCEPTION_STACK_ORDER)
diff --git a/include/linux/sched/task_stack.h b/include/linux/sched/task_stack.h
index 2413427e439c..7ee86ad0a282 100644
--- a/include/linux/sched/task_stack.h
+++ b/include/linux/sched/task_stack.h
@@ -11,6 +11,13 @@
 
 #ifdef CONFIG_THREAD_INFO_IN_TASK
 
+#ifndef STACK_GUARD_SIZE
+#ifdef CONFIG_STACK_GUARD_PAGE
+#error "Architecture not compatible with STACK_GUARD_PAGE"
+#endif
+#define STACK_GUARD_SIZE 0
+#endif
+
 /*
  * When accessing the stack of a non-current task that might exit, use
  * try_get_task_stack() instead.  task_stack_page will return a pointer
@@ -18,14 +25,14 @@
  */
 static inline void *task_stack_page(const struct task_struct *task)
 {
-	return task->stack;
+	return task->stack + STACK_GUARD_SIZE;
 }
 
 #define setup_thread_stack(new,old)	do { } while(0)
 
 static inline unsigned long *end_of_stack(const struct task_struct *task)
 {
-	return task->stack;
+	return task->stack + STACK_GUARD_SIZE;
 }
 
 #elif !defined(__HAVE_THREAD_FUNCTIONS)
diff --git a/kernel/fork.c b/kernel/fork.c
index d8ae0f1b4148..22033b03f7da 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -94,6 +94,7 @@
 #include <linux/livepatch.h>
 #include <linux/thread_info.h>
 #include <linux/stackleak.h>
+#include <linux/set_memory.h>
 
 #include <asm/pgtable.h>
 #include <asm/pgalloc.h>
@@ -249,6 +250,14 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
 					     THREAD_SIZE_ORDER);
 
 	if (likely(page)) {
+		if (IS_ENABLED(CONFIG_STACK_GUARD_PAGE)) {
+			/*
+			 * Best effort: do not flush TLB to avoid the overhead
+			 * of flushing all TLBs.
+			 */
+			set_direct_map_invalid_noflush(page);
+		}
+
 		tsk->stack = page_address(page);
 		return tsk->stack;
 	}
@@ -258,6 +267,7 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
 
 static inline void free_thread_stack(struct task_struct *tsk)
 {
+	struct page* stack_page;
 #ifdef CONFIG_VMAP_STACK
 	struct vm_struct *vm = task_stack_vm_area(tsk);
 
@@ -285,7 +295,17 @@ static inline void free_thread_stack(struct task_struct *tsk)
 	}
 #endif
 
-	__free_pages(virt_to_page(tsk->stack), THREAD_SIZE_ORDER);
+	stack_page = virt_to_page(tsk->stack);
+
+	if (IS_ENABLED(CONFIG_STACK_GUARD_PAGE)) {
+		/*
+		 * Avoid flushing TLBs, and instead rely on spurious fault
+		 * detection of stale TLBs.
+		 */
+		set_direct_map_default_noflush(stack_page);
+	}
+
+	__free_pages(stack_page, THREAD_SIZE_ORDER);
 }
 # else
 static struct kmem_cache *thread_stack_cache;
-- 
2.22.0.657.g960e92d24f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190719132818.40258-1-elver%40google.com.
