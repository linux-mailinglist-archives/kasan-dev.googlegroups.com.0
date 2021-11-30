Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSM5TCGQMGQEMQKSCPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D89E4632C2
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 12:45:14 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id h40-20020a0565123ca800b00402514d959fsf7803247lfv.7
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 03:45:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638272714; cv=pass;
        d=google.com; s=arc-20160816;
        b=pAUp5iKB+1/7empMR9AN9Bujo94OwJUWJ/sZYwaKNH6yFNX1o2w0dPtDgxsvbXFkWD
         XgiyAEzQZIK7QQ06sZBk20uwLw7ZUVQSMld7+Z/yCOAIkgJgGcKGCUsAf0RRSpDytq/E
         JZUiYVzwmZj9HjRpAddROmoFFfjmUbHcmxWrVCCavWaiU/izbdE4g3s8zrQsI/ruRW3m
         BOp2YtXk9ZpofheNPEixR15VGwcnzsZKfMUedaG/F+FJicglGceO0HEeF9Kx5Q2r22Zr
         5aEc2eG3AoExL6L1PIxh6P/kXU725AplGgNignUpU6Bu26/zoS1hpazRI/Gc1Sa081KN
         JqvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=QTOT7sc0vdjXxTheyy1GAmxeBjmjbcprwfXHXiX6VuI=;
        b=Y/3J/dsgBcWT30r9IglgPZRFAnkLh1iXUlIwnXqL337RCf6XQHpqG5uh7t4OZSBr/c
         3FuzL2FNPCbpOFf+AFky1cT6/7v2DRd51NyqP5Qxs0sMpeXxeqjy3KEVYMcWAeP47EIM
         JWqlMQjNkq8Id3T7nLWbvbl0OVw9b1ydp/RJt4FDuX/n8HOMLchb5LPU+lA8nAlTX8r9
         UAPkgHALO1LPu7IzpxVlJlUeL+jbNxlsbdUd3uu4tDGxz83Sj/oxvhdVPcbO2cH/KO3Z
         dYwWl+C3LxxEVoizMqFG0MaDeirPU640oGCEW3lMAXgQpxN0PE4k1Z1/yfkAqhq2cHi1
         uG+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sCXEXO2T;
       spf=pass (google.com: domain of 3ya6myqukczez6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3yA6mYQUKCZEz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QTOT7sc0vdjXxTheyy1GAmxeBjmjbcprwfXHXiX6VuI=;
        b=kshE2RkEbYLpS+qZEzZSLYRvzSTNbeAmS/3XlezQKim1p5IQbZqyWZBtMJW7bfg5Z6
         WWPN3fEYpM9uZu2dAIezLVVhicFqw902TSqIjyMB/QMaYtWGwNnafwkCyb8Nbwk2Us/Z
         Lw3quffp1M7oR3UstbSLzOCsq2pYHH8WYzn8iZbcjlc9qV3dF2R58VU5y1TZ6jzAsypj
         RAYvrriQC2I3xlA+UwdPijF8TYVO/xC6gObOszvCGW/K9JGB5yWDFmPa/D2e+M7V8m6G
         rz/PtcbMG48h0ypMj5fHvlikMtV58AiBMdmd0B/t5MTJ51swa5pB2U+my4E/Ghcxvknt
         sMWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QTOT7sc0vdjXxTheyy1GAmxeBjmjbcprwfXHXiX6VuI=;
        b=WAb5U97l6+2BpaoVuIcXekgk3YorNpNZ4z5+ZnnCC4P6iU6CjdzUINnDKQj1/JDrY6
         zNQ15uzgZL+OgI/o7pxDVVap1B1DOgNGYsMZkXu1y4Ty5Zbom4eFVuvoCRRhmH5Q+FXY
         hDm6YRKpNPq2z0gnTDDlMGk3NaQvSkKaYCjBAdkYNf7VxXnHt6FYmc3WfTk4RUVqoRmR
         91ucxBmQRXBkz7cnmAdKQPXXB2e/4N/CLrSoqx7MaU1W87JgU4+ygsHA/l4LKGWHRWzY
         WWJ7i2yfgxsL/6iB+4KMNftfar4xAjmU+njB9rEU1pKaHD+3L6Zuy+WWOFK2NVAftaEW
         k5gQ==
X-Gm-Message-State: AOAM531P13NRL8VVt3/9ujvIH0bJwR9AHowiA8umdXQ+dRNsx359+cJc
	06GpPUMKrZ+wUYzEeGXUAZA=
X-Google-Smtp-Source: ABdhPJxpVygC1nWt3Erli+BDM91Hu85gMHW8pZ7Jm/htnoEv+zfkUsZgSXoIA767Licj70cKem0j4Q==
X-Received: by 2002:ac2:4e70:: with SMTP id y16mr50333188lfs.436.1638272713963;
        Tue, 30 Nov 2021 03:45:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a4c2:: with SMTP id p2ls2450422ljm.4.gmail; Tue, 30 Nov
 2021 03:45:13 -0800 (PST)
X-Received: by 2002:a2e:a176:: with SMTP id u22mr55764447ljl.116.1638272712991;
        Tue, 30 Nov 2021 03:45:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638272712; cv=none;
        d=google.com; s=arc-20160816;
        b=BZLcD91d42flxOUDsjg3nwlR4k0H5s8ROukwjypYvkKMfnzMHrAc3X4KlB9iwm1lni
         7YI4b5CmXwYq8u2qpa7y1r44r1Kq2xhnfgZYtNnraxwPMM/1nDBZeP3cw4PF20/ZUnyi
         89ZnqId5lTSLg5aYQE5CovVFxgllmTTfBQ1pH/KaSQAJ7/Ms2LLsfxa1WZabInXEEWby
         HF694XWVbcPGPy91SUWvWH6H9pcH2eile/JASPKaIeW4KMKH8+QSG8wMvb3ApmkYHQ2v
         j8PavUJjee3FR+vAxBlXuuTr9Mw4lN1rIbc1G6WEzX/rCiGrh3ZrH6Z5U8L2AdvyQuVv
         rz6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=j0T1gtE+z4XQoB9A6TUQpKsLEr+NfbiB6RG+Afi5nLo=;
        b=OGkPghxv0NedD5StlIQlz65xrdWiRjFtt96Z4aqQEsDfUSFWmksYfaCPgiwn2cqPaM
         KzoVhstpiV/LrwPAugjuQVKyBMlA+wmrslYVWlc9OBzRj8hcU3W4+wChpHrQ53+/dCAm
         d0ah5TsNb17DV0eo1IWUuHWo4fb/coGxwR0nErGJkAAwUFT+9GxH6wbG8OOMu9G19rd1
         dSgY/FDQJqS6sMu+p+i/SwYI4eDgY8x6a0I+LdYqK7Zq7xqNKoePm9DJ1mr6+uug7kuh
         /uAqQ7ggfrzzhUQZEM8IKhgEP7HWFf4gdc4YxnM0wkhho/tAx0+XF2oPiH0sBII8YnVh
         MjWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sCXEXO2T;
       spf=pass (google.com: domain of 3ya6myqukczez6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3yA6mYQUKCZEz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id c12si1371168ljf.4.2021.11.30.03.45.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 03:45:12 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ya6myqukczez6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id v62-20020a1cac41000000b0033719a1a714so10282431wme.6
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 03:45:12 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:86b7:11e9:7797:99f0])
 (user=elver job=sendgmr) by 2002:a05:600c:4e4a:: with SMTP id
 e10mr4187194wmq.176.1638272712718; Tue, 30 Nov 2021 03:45:12 -0800 (PST)
Date: Tue, 30 Nov 2021 12:44:12 +0100
In-Reply-To: <20211130114433.2580590-1-elver@google.com>
Message-Id: <20211130114433.2580590-5-elver@google.com>
Mime-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v3 04/25] kcsan: Add core support for a subset of weak memory modeling
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=sCXEXO2T;       spf=pass
 (google.com: domain of 3ya6myqukczez6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3yA6mYQUKCZEz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
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

Add support for modeling a subset of weak memory, which will enable
detection of a subset of data races due to missing memory barriers.

KCSAN's approach to detecting missing memory barriers is based on
modeling access reordering, and enabled if `CONFIG_KCSAN_WEAK_MEMORY=y`,
which depends on `CONFIG_KCSAN_STRICT=y`. The feature can be enabled or
disabled at boot and runtime via the `kcsan.weak_memory` boot parameter.

Each memory access for which a watchpoint is set up, is also selected
for simulated reordering within the scope of its function (at most 1
in-flight access).

We are limited to modeling the effects of "buffering" (delaying the
access), since the runtime cannot "prefetch" accesses (therefore no
acquire modeling). Once an access has been selected for reordering, it
is checked along every other access until the end of the function scope.
If an appropriate memory barrier is encountered, the access will no
longer be considered for reordering.

When the result of a memory operation should be ordered by a barrier,
KCSAN can then detect data races where the conflict only occurs as a
result of a missing barrier due to reordering accesses.

Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* Remove kcsan_noinstr hackery, since we now try to avoid adding any
  instrumentation to .noinstr.text in the first place.
* Restrict config WEAK_MEMORY to only be enabled with tooling where
  we actually remove instrumentation from noinstr.
* Don't define kcsan_weak_memory bool if !KCSAN_WEAK_MEMORY.

v2:
* Define kcsan_noinstr as noinline if we rely on objtool nop'ing out
  calls, to avoid things like LTO inlining it.
---
 include/linux/kcsan-checks.h |  10 +-
 include/linux/kcsan.h        |  10 +-
 include/linux/sched.h        |   3 +
 kernel/kcsan/core.c          | 209 ++++++++++++++++++++++++++++++++---
 lib/Kconfig.kcsan            |  20 ++++
 scripts/Makefile.kcsan       |   9 +-
 6 files changed, 242 insertions(+), 19 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index 5f5965246877..a1c6a89fde71 100644
--- a/include/linux/kcsan-checks.h
+++ b/include/linux/kcsan-checks.h
@@ -99,7 +99,15 @@ void kcsan_set_access_mask(unsigned long mask);
 
 /* Scoped access information. */
 struct kcsan_scoped_access {
-	struct list_head list;
+	union {
+		struct list_head list; /* scoped_accesses list */
+		/*
+		 * Not an entry in scoped_accesses list; stack depth from where
+		 * the access was initialized.
+		 */
+		int stack_depth;
+	};
+
 	/* Access information. */
 	const volatile void *ptr;
 	size_t size;
diff --git a/include/linux/kcsan.h b/include/linux/kcsan.h
index 13cef3458fed..c07c71f5ba4f 100644
--- a/include/linux/kcsan.h
+++ b/include/linux/kcsan.h
@@ -49,8 +49,16 @@ struct kcsan_ctx {
 	 */
 	unsigned long access_mask;
 
-	/* List of scoped accesses. */
+	/* List of scoped accesses; likely to be empty. */
 	struct list_head scoped_accesses;
+
+#ifdef CONFIG_KCSAN_WEAK_MEMORY
+	/*
+	 * Scoped access for modeling access reordering to detect missing memory
+	 * barriers; only keep 1 to keep fast-path complexity manageable.
+	 */
+	struct kcsan_scoped_access reorder_access;
+#endif
 };
 
 /**
diff --git a/include/linux/sched.h b/include/linux/sched.h
index 78c351e35fec..0cd40b010487 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1339,6 +1339,9 @@ struct task_struct {
 #ifdef CONFIG_TRACE_IRQFLAGS
 	struct irqtrace_events		kcsan_save_irqtrace;
 #endif
+#ifdef CONFIG_KCSAN_WEAK_MEMORY
+	int				kcsan_stack_depth;
+#endif
 #endif
 
 #if IS_ENABLED(CONFIG_KUNIT)
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index bd359f8ee63a..36a75e79a0bd 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -12,6 +12,7 @@
 #include <linux/delay.h>
 #include <linux/export.h>
 #include <linux/init.h>
+#include <linux/instrumentation.h>
 #include <linux/kernel.h>
 #include <linux/list.h>
 #include <linux/moduleparam.h>
@@ -20,6 +21,8 @@
 #include <linux/sched.h>
 #include <linux/uaccess.h>
 
+#include <asm/sections.h>
+
 #include "encoding.h"
 #include "kcsan.h"
 #include "permissive.h"
@@ -40,6 +43,13 @@ module_param_named(udelay_interrupt, kcsan_udelay_interrupt, uint, 0644);
 module_param_named(skip_watch, kcsan_skip_watch, long, 0644);
 module_param_named(interrupt_watcher, kcsan_interrupt_watcher, bool, 0444);
 
+#ifdef CONFIG_KCSAN_WEAK_MEMORY
+static bool kcsan_weak_memory = true;
+module_param_named(weak_memory, kcsan_weak_memory, bool, 0644);
+#else
+#define kcsan_weak_memory false
+#endif
+
 bool kcsan_enabled;
 
 /* Per-CPU kcsan_ctx for interrupts */
@@ -351,6 +361,67 @@ void kcsan_restore_irqtrace(struct task_struct *task)
 #endif
 }
 
+static __always_inline int get_kcsan_stack_depth(void)
+{
+#ifdef CONFIG_KCSAN_WEAK_MEMORY
+	return current->kcsan_stack_depth;
+#else
+	BUILD_BUG();
+	return 0;
+#endif
+}
+
+static __always_inline void add_kcsan_stack_depth(int val)
+{
+#ifdef CONFIG_KCSAN_WEAK_MEMORY
+	current->kcsan_stack_depth += val;
+#else
+	BUILD_BUG();
+#endif
+}
+
+static __always_inline struct kcsan_scoped_access *get_reorder_access(struct kcsan_ctx *ctx)
+{
+#ifdef CONFIG_KCSAN_WEAK_MEMORY
+	return ctx->disable_scoped ? NULL : &ctx->reorder_access;
+#else
+	return NULL;
+#endif
+}
+
+static __always_inline bool
+find_reorder_access(struct kcsan_ctx *ctx, const volatile void *ptr, size_t size,
+		    int type, unsigned long ip)
+{
+	struct kcsan_scoped_access *reorder_access = get_reorder_access(ctx);
+
+	if (!reorder_access)
+		return false;
+
+	/*
+	 * Note: If accesses are repeated while reorder_access is identical,
+	 * never matches the new access, because !(type & KCSAN_ACCESS_SCOPED).
+	 */
+	return reorder_access->ptr == ptr && reorder_access->size == size &&
+	       reorder_access->type == type && reorder_access->ip == ip;
+}
+
+static inline void
+set_reorder_access(struct kcsan_ctx *ctx, const volatile void *ptr, size_t size,
+		   int type, unsigned long ip)
+{
+	struct kcsan_scoped_access *reorder_access = get_reorder_access(ctx);
+
+	if (!reorder_access || !kcsan_weak_memory)
+		return;
+
+	reorder_access->ptr		= ptr;
+	reorder_access->size		= size;
+	reorder_access->type		= type | KCSAN_ACCESS_SCOPED;
+	reorder_access->ip		= ip;
+	reorder_access->stack_depth	= get_kcsan_stack_depth();
+}
+
 /*
  * Pull everything together: check_access() below contains the performance
  * critical operations; the fast-path (including check_access) functions should
@@ -389,8 +460,10 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
 	 * The access_mask check relies on value-change comparison. To avoid
 	 * reporting a race where e.g. the writer set up the watchpoint, but the
 	 * reader has access_mask!=0, we have to ignore the found watchpoint.
+	 *
+	 * reorder_access is never created from an access with access_mask set.
 	 */
-	if (ctx->access_mask)
+	if (ctx->access_mask && !find_reorder_access(ctx, ptr, size, type, ip))
 		return;
 
 	/*
@@ -440,11 +513,13 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
 	const bool is_assert = (type & KCSAN_ACCESS_ASSERT) != 0;
 	atomic_long_t *watchpoint;
 	u64 old, new, diff;
-	unsigned long access_mask;
 	enum kcsan_value_change value_change = KCSAN_VALUE_CHANGE_MAYBE;
+	bool interrupt_watcher = kcsan_interrupt_watcher;
 	unsigned long ua_flags = user_access_save();
 	struct kcsan_ctx *ctx = get_ctx();
+	unsigned long access_mask = ctx->access_mask;
 	unsigned long irq_flags = 0;
+	bool is_reorder_access;
 
 	/*
 	 * Always reset kcsan_skip counter in slow-path to avoid underflow; see
@@ -467,6 +542,17 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
 		goto out;
 	}
 
+	/*
+	 * The local CPU cannot observe reordering of its own accesses, and
+	 * therefore we need to take care of 2 cases to avoid false positives:
+	 *
+	 *	1. Races of the reordered access with interrupts. To avoid, if
+	 *	   the current access is reorder_access, disable interrupts.
+	 *	2. Avoid races of scoped accesses from nested interrupts (below).
+	 */
+	is_reorder_access = find_reorder_access(ctx, ptr, size, type, ip);
+	if (is_reorder_access)
+		interrupt_watcher = false;
 	/*
 	 * Avoid races of scoped accesses from nested interrupts (or scheduler).
 	 * Assume setting up a watchpoint for a non-scoped (normal) access that
@@ -482,7 +568,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
 	 * information is lost if dirtied by KCSAN.
 	 */
 	kcsan_save_irqtrace(current);
-	if (!kcsan_interrupt_watcher)
+	if (!interrupt_watcher)
 		local_irq_save(irq_flags);
 
 	watchpoint = insert_watchpoint((unsigned long)ptr, size, is_write);
@@ -503,7 +589,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
 	 * Read the current value, to later check and infer a race if the data
 	 * was modified via a non-instrumented access, e.g. from a device.
 	 */
-	old = read_instrumented_memory(ptr, size);
+	old = is_reorder_access ? 0 : read_instrumented_memory(ptr, size);
 
 	/*
 	 * Delay this thread, to increase probability of observing a racy
@@ -515,8 +601,17 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
 	 * Re-read value, and check if it is as expected; if not, we infer a
 	 * racy access.
 	 */
-	access_mask = ctx->access_mask;
-	new = read_instrumented_memory(ptr, size);
+	if (!is_reorder_access) {
+		new = read_instrumented_memory(ptr, size);
+	} else {
+		/*
+		 * Reordered accesses cannot be used for value change detection,
+		 * because the memory location may no longer be accessible and
+		 * could result in a fault.
+		 */
+		new = 0;
+		access_mask = 0;
+	}
 
 	diff = old ^ new;
 	if (access_mask)
@@ -585,11 +680,20 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
 	 */
 	remove_watchpoint(watchpoint);
 	atomic_long_dec(&kcsan_counters[KCSAN_COUNTER_USED_WATCHPOINTS]);
+
 out_unlock:
-	if (!kcsan_interrupt_watcher)
+	if (!interrupt_watcher)
 		local_irq_restore(irq_flags);
 	kcsan_restore_irqtrace(current);
 	ctx->disable_scoped--;
+
+	/*
+	 * Reordered accesses cannot be used for value change detection,
+	 * therefore never consider for reordering if access_mask is set.
+	 * ASSERT_EXCLUSIVE are not real accesses, ignore them as well.
+	 */
+	if (!access_mask && !is_assert)
+		set_reorder_access(ctx, ptr, size, type, ip);
 out:
 	user_access_restore(ua_flags);
 }
@@ -597,7 +701,6 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
 static __always_inline void
 check_access(const volatile void *ptr, size_t size, int type, unsigned long ip)
 {
-	const bool is_write = (type & KCSAN_ACCESS_WRITE) != 0;
 	atomic_long_t *watchpoint;
 	long encoded_watchpoint;
 
@@ -608,12 +711,14 @@ check_access(const volatile void *ptr, size_t size, int type, unsigned long ip)
 	if (unlikely(size == 0))
 		return;
 
+again:
 	/*
 	 * Avoid user_access_save in fast-path: find_watchpoint is safe without
 	 * user_access_save, as the address that ptr points to is only used to
 	 * check if a watchpoint exists; ptr is never dereferenced.
 	 */
-	watchpoint = find_watchpoint((unsigned long)ptr, size, !is_write,
+	watchpoint = find_watchpoint((unsigned long)ptr, size,
+				     !(type & KCSAN_ACCESS_WRITE),
 				     &encoded_watchpoint);
 	/*
 	 * It is safe to check kcsan_is_enabled() after find_watchpoint in the
@@ -627,9 +732,42 @@ check_access(const volatile void *ptr, size_t size, int type, unsigned long ip)
 	else {
 		struct kcsan_ctx *ctx = get_ctx(); /* Call only once in fast-path. */
 
-		if (unlikely(should_watch(ctx, ptr, size, type)))
+		if (unlikely(should_watch(ctx, ptr, size, type))) {
 			kcsan_setup_watchpoint(ptr, size, type, ip);
-		else if (unlikely(ctx->scoped_accesses.prev))
+			return;
+		}
+
+		if (!(type & KCSAN_ACCESS_SCOPED)) {
+			struct kcsan_scoped_access *reorder_access = get_reorder_access(ctx);
+
+			if (reorder_access) {
+				/*
+				 * reorder_access check: simulates reordering of
+				 * the access after subsequent operations.
+				 */
+				ptr = reorder_access->ptr;
+				type = reorder_access->type;
+				ip = reorder_access->ip;
+				/*
+				 * Upon a nested interrupt, this context's
+				 * reorder_access can be modified (shared ctx).
+				 * We know that upon return, reorder_access is
+				 * always invalidated by setting size to 0 via
+				 * __tsan_func_exit(). Therefore we must read
+				 * and check size after the other fields.
+				 */
+				barrier();
+				size = READ_ONCE(reorder_access->size);
+				if (size)
+					goto again;
+			}
+		}
+
+		/*
+		 * Always checked last, right before returning from runtime;
+		 * if reorder_access is valid, checked after it was checked.
+		 */
+		if (unlikely(ctx->scoped_accesses.prev))
 			kcsan_check_scoped_accesses();
 	}
 }
@@ -916,19 +1054,60 @@ DEFINE_TSAN_VOLATILE_READ_WRITE(8);
 DEFINE_TSAN_VOLATILE_READ_WRITE(16);
 
 /*
- * The below are not required by KCSAN, but can still be emitted by the
- * compiler.
+ * Function entry and exit are used to determine the validty of reorder_access.
+ * Reordering of the access ends at the end of the function scope where the
+ * access happened. This is done for two reasons:
+ *
+ *	1. Artificially limits the scope where missing barriers are detected.
+ *	   This minimizes false positives due to uninstrumented functions that
+ *	   contain the required barriers but were missed.
+ *
+ *	2. Simplifies generating the stack trace of the access.
  */
 void __tsan_func_entry(void *call_pc);
-void __tsan_func_entry(void *call_pc)
+noinline void __tsan_func_entry(void *call_pc)
 {
+	if (!IS_ENABLED(CONFIG_KCSAN_WEAK_MEMORY))
+		return;
+
+	instrumentation_begin();
+	add_kcsan_stack_depth(1);
+	instrumentation_end();
 }
 EXPORT_SYMBOL(__tsan_func_entry);
+
 void __tsan_func_exit(void);
-void __tsan_func_exit(void)
+noinline void __tsan_func_exit(void)
 {
+	struct kcsan_scoped_access *reorder_access;
+
+	if (!IS_ENABLED(CONFIG_KCSAN_WEAK_MEMORY))
+		return;
+
+	instrumentation_begin();
+	reorder_access = get_reorder_access(get_ctx());
+	if (!reorder_access)
+		goto out;
+
+	if (get_kcsan_stack_depth() <= reorder_access->stack_depth) {
+		/*
+		 * Access check to catch cases where write without a barrier
+		 * (supposed release) was last access in function: because
+		 * instrumentation is inserted before the real access, a data
+		 * race due to the write giving up a c-s would only be caught if
+		 * we do the conflicting access after.
+		 */
+		check_access(reorder_access->ptr, reorder_access->size,
+			     reorder_access->type, reorder_access->ip);
+		reorder_access->size = 0;
+		reorder_access->stack_depth = INT_MIN;
+	}
+out:
+	add_kcsan_stack_depth(-1);
+	instrumentation_end();
 }
 EXPORT_SYMBOL(__tsan_func_exit);
+
 void __tsan_init(void);
 void __tsan_init(void)
 {
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index e0a93ffdef30..e4394ea8068b 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -191,6 +191,26 @@ config KCSAN_STRICT
 	  closely aligns with the rules defined by the Linux-kernel memory
 	  consistency model (LKMM).
 
+config KCSAN_WEAK_MEMORY
+	bool "Enable weak memory modeling to detect missing memory barriers"
+	default y
+	depends on KCSAN_STRICT
+	# We can either let objtool nop __tsan_func_{entry,exit}() and builtin
+	# atomics instrumentation in .noinstr.text, or use a compiler that can
+	# implement __no_kcsan to really remove all instrumentation.
+	depends on STACK_VALIDATION || CC_IS_GCC
+	help
+	  Enable support for modeling a subset of weak memory, which allows
+	  detecting a subset of data races due to missing memory barriers.
+
+	  Depends on KCSAN_STRICT, because the options strenghtening certain
+	  plain accesses by default (depending on !KCSAN_STRICT) reduce the
+	  ability to detect any data races invoving reordered accesses, in
+	  particular reordered writes.
+
+	  Weak memory modeling relies on additional instrumentation and may
+	  affect performance.
+
 config KCSAN_REPORT_VALUE_CHANGE_ONLY
 	bool "Only report races where watcher observed a data value change"
 	default y
diff --git a/scripts/Makefile.kcsan b/scripts/Makefile.kcsan
index 37cb504c77e1..4c7f0d282e42 100644
--- a/scripts/Makefile.kcsan
+++ b/scripts/Makefile.kcsan
@@ -9,7 +9,12 @@ endif
 
 # Keep most options here optional, to allow enabling more compilers if absence
 # of some options does not break KCSAN nor causes false positive reports.
-export CFLAGS_KCSAN := -fsanitize=thread \
-	$(call cc-option,$(call cc-param,tsan-instrument-func-entry-exit=0) -fno-optimize-sibling-calls) \
+kcsan-cflags := -fsanitize=thread -fno-optimize-sibling-calls \
 	$(call cc-option,$(call cc-param,tsan-compound-read-before-write=1),$(call cc-option,$(call cc-param,tsan-instrument-read-before-write=1))) \
 	$(call cc-param,tsan-distinguish-volatile=1)
+
+ifndef CONFIG_KCSAN_WEAK_MEMORY
+kcsan-cflags += $(call cc-option,$(call cc-param,tsan-instrument-func-entry-exit=0))
+endif
+
+export CFLAGS_KCSAN := $(kcsan-cflags)
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211130114433.2580590-5-elver%40google.com.
