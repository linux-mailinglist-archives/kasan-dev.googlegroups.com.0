Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAP2SO6QMGQEUXHFMMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 443BDA2B064
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:18:43 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-436723db6c4sf10349385e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:18:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738865923; cv=pass;
        d=google.com; s=arc-20240605;
        b=gcR6Jy0nQAe78AtN9yKnzkABPl7emtMpENkqfXQexfJdCn19wEPlMQkTgPi2OjZ0Xs
         KMGwIisM4C/g2Z+VEk5pezaAuUVVIPyiwwlb4GlsQn8g+m7j3+1wyi07uRmf8a8Cf5vV
         5d8OWJYBzfTxMFYxTacf8OBfhkM4dxm59bCGrLPMeIyfDbkyV3L4aGEt75OZJYsZU3Io
         HMj8VcADOw0KsFI/49gdBahRWxgeqrlZYo7tLGqPV9oedKB6oHYbx24YJnHZzwPrhpO/
         mXqjlI986LDCEgegPfrbXjp5ByiJ9nJ2ubQJMUz2noxZ0jzkSg1rcfXIuK9NJYMQ1Hhz
         88kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=k9qnZsZHFh/wRQJpUy73wDitiBAsECFkIuc6VJlPcbM=;
        fh=Lkl9FRqYGM1gqu7CJQKy+Nc5tZqwTesqiRtuuh/i7Qk=;
        b=crqbFIDiW1KYaBnJsEXDcMzuOjHbMsoHyJDn4s1SLSQNZSYLPqejV5LV55UBUBUbZ0
         p3mLrrZoBa9ToZzZ2aBzU2m3Be6/wbanFI4KCyDA3GuSS1PdHArIPWtmCnkk7LTaXKR7
         cAlmPeBd16XCLomV35RR4EniYbZIB8n2Cc8K8eDfH3l7Ou5rWLzkRhtSlgkU3iekm9Vo
         3xjiAxEIdpSYtc1Y8RSwQ8AOPDetV8jSrIoZS+RfS9fPnGZxrHSbFNqKibQ3g/pV2ptB
         ++04A0wSESf4Ikjd0LKi9DOFP9aMEYmkfl/vCY4R8s6RIEKlbKCB34axlOIopjrtnqMH
         u+ig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tR5At4+D;
       spf=pass (google.com: domain of 3__ykzwukcda07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3__ykZwUKCdA07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738865923; x=1739470723; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=k9qnZsZHFh/wRQJpUy73wDitiBAsECFkIuc6VJlPcbM=;
        b=k/6bMAoUDEuBryjCZVs97fTIdtkpho1ovoRAC0NyBTqoLjaMuwjKt0AhufiSAoShKU
         RDVZY5PPSyhvLaYsSkGZU0B2o+MRz1nl+I+XpNHTtz7HK/KC/F+rJ30XqI2gUo2Esd28
         Ohlg6ySDbfdLmVHDfIZ3ZVkZx3ixe3GudduyuD18NDSOdkZ9lNk2tGgoM8JE+mn0pqPw
         JVOUbqeeSGEted35VSBjv1HaX1pfyvl68CNv1h9bftEq2fq2Dx5x5n0FllCLm1gBMevX
         /1fhhkY5Ym8ruEjHSKfs9iBKxAQoC0th6cgodFoiNVMqZYcmj98+YQkNk7DSL9NBb1Io
         /sNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738865923; x=1739470723;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=k9qnZsZHFh/wRQJpUy73wDitiBAsECFkIuc6VJlPcbM=;
        b=pMZUSCjtHZyGb9oUX/UZ6Rl3Tcrqmlbw9t56DV9P4y5n77sJciReRDqsUFO6Ac71wG
         TfbW9tn4PKbqSZ+MWhLXQpsmW0S1lxN9o9HSdu5CmY9QtNYFf736apVz7rh7D3EvC+Fj
         iQ1ccKQkGdprC1B1ezVWp9A7vaugqkVfSFVCDTVZn+jlGC4g+0IazpQ/Rkly83QZfdml
         m9Dkvd5i7J62jzGMIphQKbh2STEPahDBreMHkrm7aJCArigAOv79oFeEwUdyMM7EI9MK
         B9at3HKb9Y86CGcR5IFdgfAwZLcJs29rFVnKJUyYwhAUVMBGnv1aPpKMG5Bd0bCLHm1Q
         +9iA==
X-Forwarded-Encrypted: i=2; AJvYcCUtHeKQU83hdgUjJjFx4TlYQGqjOoVPLdEOLPfIAcfPL8XGoUNz0akDeIav7i9xrS8XuJp8LQ==@lfdr.de
X-Gm-Message-State: AOJu0Yzir/RBX/E4X4pF8Fvo2TDpQizaSkU7gE0d0SINCMOJ6gvr7kja
	ELbPdj4glHBRHaHL3CDYrSpYwpJFZfEOtYjsAVZ8zKQYODvxeljp
X-Google-Smtp-Source: AGHT+IFhiYSzFQARvsXxNyO24SAxr1oRtC/sjy7jKzgYC53wM646NyMdlS780+/VyZ/P1CXeh2TpEg==
X-Received: by 2002:a05:600c:4f47:b0:434:fff1:1ade with SMTP id 5b1f17b1804b1-43924991dfdmr4278385e9.13.1738865921976;
        Thu, 06 Feb 2025 10:18:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:9bc8:0:b0:374:c0b6:44c0 with SMTP id ffacd0b85a97d-38dc6f0070els149406f8f.0.-pod-prod-09-eu;
 Thu, 06 Feb 2025 10:18:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWCAmNSLiDrchifI89Sd+/aZCMXzH2qHRENiOCdZY1NYGFEjdOCcZ9+vmcUR6amnBShJAfOCzQKWzQ=@googlegroups.com
X-Received: by 2002:a05:600c:4687:b0:434:fa61:fdfb with SMTP id 5b1f17b1804b1-43924991398mr4348605e9.18.1738865919453;
        Thu, 06 Feb 2025 10:18:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738865919; cv=none;
        d=google.com; s=arc-20240605;
        b=T9LtrQD7L1WyM0+QWdvzOLlyasGZNX9XcMyu6SKFSIrBGVOxU2Or+9ZRsI2RvyASez
         vVPn8fMHNa52IFXyjtXJTMk+KXgW64bGsfX7tBApWyh7Mas7y6qCDt8UTG9j7g6hNn7W
         XTSQq5U6hGI6v5n20r7e8XSFg4vaevnoVIKzqUmL0s+aX0DkQI0Wc2I0QUS7exUiRJ2L
         XaxCw582FU48tmKrqvXa6id4X0rSzVYZXCjmMDHBdAfgAhjOw410F3z4KLWqw6kZRPlo
         OdtFGGbbTTjbJAX4OCpiK9Hy15+SZmC9cyrYaXxK+oT1rDQxxlp2L2JL6FBs3mYgB89R
         T7iA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=/Q/r6EDjEaKBVCObAXq5d4B0c7MeKIT3YrYe1pikBVY=;
        fh=tk4Tj1of0JEOniAM/2k198+B9UVPWJ/dXHK1GSTaj2c=;
        b=NcZyCoE1KyaAYISPTHa/ky3J0h7fvqZE8v19z69EpbMapwk7kdkLcVP/XpFlh7N+wt
         8JxOrws3uQnljyl/R6Myo5BdC9b240xNGWFxZbiXzmv+5dpn29K27P4NXSuGdJCGKg0d
         d8IMBZ+MAMZTaTrdQ8OfZbeQ42g/mqy0FSFDIhboSjvNQYcHR3T0NRlLmbgwxZ3SbCiP
         BHl8fEyT/ix3ZeZIZ2T7Db1WIcxs+je/K2LwbHwwphNu5fla5LpU00KOkslm3aPc9mSK
         TqQrUR79uWjKIP+nLUM59Fvf5TRgjeAcbtyGGpegGIr68cl1e1R+oSthGeFP0AiEckXF
         znOA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tR5At4+D;
       spf=pass (google.com: domain of 3__ykzwukcda07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3__ykZwUKCdA07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-38dbde4c5e1si42891f8f.8.2025.02.06.10.18.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:18:39 -0800 (PST)
Received-SPF: pass (google.com: domain of 3__ykzwukcda07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id 4fb4d7f45d1cf-5dc5b397109so1443938a12.2
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:18:39 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXwVW/bk7i+Es3/rfVZasg1/A+uFPCoq3QjILI6NBr2xgrwSMHBr6W83BzhjFsDQdQSGVNwod31xPs=@googlegroups.com
X-Received: from edag6.prod.google.com ([2002:a05:6402:3206:b0:5de:3ce0:a49b])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:3583:b0:5da:9d3:bc23
 with SMTP id 4fb4d7f45d1cf-5de4508a0b9mr436219a12.24.1738865919115; Thu, 06
 Feb 2025 10:18:39 -0800 (PST)
Date: Thu,  6 Feb 2025 19:10:15 +0100
In-Reply-To: <20250206181711.1902989-1-elver@google.com>
Mime-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.502.g6dc24dfdaf-goog
Message-ID: <20250206181711.1902989-22-elver@google.com>
Subject: [PATCH RFC 21/24] kfence: Enable capability analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Frederic Weisbecker <frederic@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=tR5At4+D;       spf=pass
 (google.com: domain of 3__ykzwukcda07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3__ykZwUKCdA07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

Enable capability analysis for the KFENCE subsystem.

Notable, kfence_handle_page_fault() required minor restructure, which
also fixed a subtle race; arguably that function is more readable now.

Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kfence/Makefile      |  2 ++
 mm/kfence/core.c        | 24 +++++++++++++++++-------
 mm/kfence/kfence.h      | 18 ++++++++++++------
 mm/kfence/kfence_test.c |  4 ++++
 mm/kfence/report.c      |  8 ++++++--
 5 files changed, 41 insertions(+), 15 deletions(-)

diff --git a/mm/kfence/Makefile b/mm/kfence/Makefile
index 2de2a58d11a1..b3640bdc3c69 100644
--- a/mm/kfence/Makefile
+++ b/mm/kfence/Makefile
@@ -1,5 +1,7 @@
 # SPDX-License-Identifier: GPL-2.0
 
+CAPABILITY_ANALYSIS := y
+
 obj-y := core.o report.o
 
 CFLAGS_kfence_test.o := -fno-omit-frame-pointer -fno-optimize-sibling-calls
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 102048821c22..c2d1ffd20a1f 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -7,6 +7,8 @@
 
 #define pr_fmt(fmt) "kfence: " fmt
 
+disable_capability_analysis();
+
 #include <linux/atomic.h>
 #include <linux/bug.h>
 #include <linux/debugfs.h>
@@ -34,6 +36,8 @@
 
 #include <asm/kfence.h>
 
+enable_capability_analysis();
+
 #include "kfence.h"
 
 /* Disables KFENCE on the first warning assuming an irrecoverable error. */
@@ -132,8 +136,8 @@ struct kfence_metadata *kfence_metadata __read_mostly;
 static struct kfence_metadata *kfence_metadata_init __read_mostly;
 
 /* Freelist with available objects. */
-static struct list_head kfence_freelist = LIST_HEAD_INIT(kfence_freelist);
-static DEFINE_RAW_SPINLOCK(kfence_freelist_lock); /* Lock protecting freelist. */
+DEFINE_RAW_SPINLOCK(kfence_freelist_lock); /* Lock protecting freelist. */
+static struct list_head kfence_freelist __var_guarded_by(&kfence_freelist_lock) = LIST_HEAD_INIT(kfence_freelist);
 
 /*
  * The static key to set up a KFENCE allocation; or if static keys are not used
@@ -253,6 +257,7 @@ static bool kfence_unprotect(unsigned long addr)
 }
 
 static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *meta)
+	__must_hold(&meta->lock)
 {
 	unsigned long offset = (meta - kfence_metadata + 1) * PAGE_SIZE * 2;
 	unsigned long pageaddr = (unsigned long)&__kfence_pool[offset];
@@ -288,6 +293,7 @@ static inline bool kfence_obj_allocated(const struct kfence_metadata *meta)
 static noinline void
 metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state next,
 		      unsigned long *stack_entries, size_t num_stack_entries)
+	__must_hold(&meta->lock)
 {
 	struct kfence_track *track =
 		next == KFENCE_OBJECT_ALLOCATED ? &meta->alloc_track : &meta->free_track;
@@ -485,7 +491,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 	alloc_covered_add(alloc_stack_hash, 1);
 
 	/* Set required slab fields. */
-	slab = virt_to_slab((void *)meta->addr);
+	slab = virt_to_slab(addr);
 	slab->slab_cache = cache;
 	slab->objects = 1;
 
@@ -514,6 +520,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool zombie)
 {
 	struct kcsan_scoped_access assert_page_exclusive;
+	u32 alloc_stack_hash;
 	unsigned long flags;
 	bool init;
 
@@ -546,9 +553,10 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
 	/* Mark the object as freed. */
 	metadata_update_state(meta, KFENCE_OBJECT_FREED, NULL, 0);
 	init = slab_want_init_on_free(meta->cache);
+	alloc_stack_hash = meta->alloc_stack_hash;
 	raw_spin_unlock_irqrestore(&meta->lock, flags);
 
-	alloc_covered_add(meta->alloc_stack_hash, -1);
+	alloc_covered_add(alloc_stack_hash, -1);
 
 	/* Check canary bytes for memory corruption. */
 	check_canary(meta);
@@ -593,6 +601,7 @@ static void rcu_guarded_free(struct rcu_head *h)
  * which partial initialization succeeded.
  */
 static unsigned long kfence_init_pool(void)
+	__no_capability_analysis
 {
 	unsigned long addr;
 	struct page *pages;
@@ -1192,6 +1201,7 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
 {
 	const int page_index = (addr - (unsigned long)__kfence_pool) / PAGE_SIZE;
 	struct kfence_metadata *to_report = NULL;
+	unsigned long unprotected_page = 0;
 	enum kfence_error_type error_type;
 	unsigned long flags;
 
@@ -1225,9 +1235,8 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
 		if (!to_report)
 			goto out;
 
-		raw_spin_lock_irqsave(&to_report->lock, flags);
-		to_report->unprotected_page = addr;
 		error_type = KFENCE_ERROR_OOB;
+		unprotected_page = addr;
 
 		/*
 		 * If the object was freed before we took the look we can still
@@ -1239,7 +1248,6 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
 		if (!to_report)
 			goto out;
 
-		raw_spin_lock_irqsave(&to_report->lock, flags);
 		error_type = KFENCE_ERROR_UAF;
 		/*
 		 * We may race with __kfence_alloc(), and it is possible that a
@@ -1251,6 +1259,8 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
 
 out:
 	if (to_report) {
+		raw_spin_lock_irqsave(&to_report->lock, flags);
+		to_report->unprotected_page = unprotected_page;
 		kfence_report_error(addr, is_write, regs, to_report, error_type);
 		raw_spin_unlock_irqrestore(&to_report->lock, flags);
 	} else {
diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
index dfba5ea06b01..27829d70baf6 100644
--- a/mm/kfence/kfence.h
+++ b/mm/kfence/kfence.h
@@ -9,6 +9,8 @@
 #ifndef MM_KFENCE_KFENCE_H
 #define MM_KFENCE_KFENCE_H
 
+disable_capability_analysis();
+
 #include <linux/mm.h>
 #include <linux/slab.h>
 #include <linux/spinlock.h>
@@ -16,6 +18,8 @@
 
 #include "../slab.h" /* for struct kmem_cache */
 
+enable_capability_analysis();
+
 /*
  * Get the canary byte pattern for @addr. Use a pattern that varies based on the
  * lower 3 bits of the address, to detect memory corruptions with higher
@@ -34,6 +38,8 @@
 /* Maximum stack depth for reports. */
 #define KFENCE_STACK_DEPTH 64
 
+extern raw_spinlock_t kfence_freelist_lock;
+
 /* KFENCE object states. */
 enum kfence_object_state {
 	KFENCE_OBJECT_UNUSED,		/* Object is unused. */
@@ -53,7 +59,7 @@ struct kfence_track {
 
 /* KFENCE metadata per guarded allocation. */
 struct kfence_metadata {
-	struct list_head list;		/* Freelist node; access under kfence_freelist_lock. */
+	struct list_head list __var_guarded_by(&kfence_freelist_lock);	/* Freelist node. */
 	struct rcu_head rcu_head;	/* For delayed freeing. */
 
 	/*
@@ -91,13 +97,13 @@ struct kfence_metadata {
 	 * In case of an invalid access, the page that was unprotected; we
 	 * optimistically only store one address.
 	 */
-	unsigned long unprotected_page;
+	unsigned long unprotected_page __var_guarded_by(&lock);
 
 	/* Allocation and free stack information. */
-	struct kfence_track alloc_track;
-	struct kfence_track free_track;
+	struct kfence_track alloc_track __var_guarded_by(&lock);
+	struct kfence_track free_track __var_guarded_by(&lock);
 	/* For updating alloc_covered on frees. */
-	u32 alloc_stack_hash;
+	u32 alloc_stack_hash __var_guarded_by(&lock);
 #ifdef CONFIG_MEMCG
 	struct slabobj_ext obj_exts;
 #endif
@@ -141,6 +147,6 @@ enum kfence_error_type {
 void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *regs,
 			 const struct kfence_metadata *meta, enum kfence_error_type type);
 
-void kfence_print_object(struct seq_file *seq, const struct kfence_metadata *meta);
+void kfence_print_object(struct seq_file *seq, const struct kfence_metadata *meta) __must_hold(&meta->lock);
 
 #endif /* MM_KFENCE_KFENCE_H */
diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index 00034e37bc9f..67eca6e9a8de 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -11,6 +11,8 @@
  *         Marco Elver <elver@google.com>
  */
 
+disable_capability_analysis();
+
 #include <kunit/test.h>
 #include <linux/jiffies.h>
 #include <linux/kernel.h>
@@ -26,6 +28,8 @@
 
 #include <asm/kfence.h>
 
+enable_capability_analysis();
+
 #include "kfence.h"
 
 /* May be overridden by <asm/kfence.h>. */
diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index 10e6802a2edf..bbee90d0034d 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -5,6 +5,8 @@
  * Copyright (C) 2020, Google LLC.
  */
 
+disable_capability_analysis();
+
 #include <linux/stdarg.h>
 
 #include <linux/kernel.h>
@@ -22,6 +24,8 @@
 
 #include <asm/kfence.h>
 
+enable_capability_analysis();
+
 #include "kfence.h"
 
 /* May be overridden by <asm/kfence.h>. */
@@ -106,6 +110,7 @@ static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries
 
 static void kfence_print_stack(struct seq_file *seq, const struct kfence_metadata *meta,
 			       bool show_alloc)
+	__must_hold(&meta->lock)
 {
 	const struct kfence_track *track = show_alloc ? &meta->alloc_track : &meta->free_track;
 	u64 ts_sec = track->ts_nsec;
@@ -207,8 +212,6 @@ void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *r
 	if (WARN_ON(type != KFENCE_ERROR_INVALID && !meta))
 		return;
 
-	if (meta)
-		lockdep_assert_held(&meta->lock);
 	/*
 	 * Because we may generate reports in printk-unfriendly parts of the
 	 * kernel, such as scheduler code, the use of printk() could deadlock.
@@ -263,6 +266,7 @@ void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *r
 	stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr, 0);
 
 	if (meta) {
+		lockdep_assert_held(&meta->lock);
 		pr_err("\n");
 		kfence_print_object(NULL, meta);
 	}
-- 
2.48.1.502.g6dc24dfdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250206181711.1902989-22-elver%40google.com.
