Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPUOTO7AMGQEJWVMREQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id D0604A4D81F
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:26:23 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-5d9e4d33f04sf5781075a12.0
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:26:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080383; cv=pass;
        d=google.com; s=arc-20240605;
        b=EdeI4DByqTT8Bfzawl1/NvohZlj3Kh7gXFD8wL/X48m7FUOXN33ajkPR32mIYA5ieE
         8fCx03KT0yg9EhW7c4isXzrWDom/HgtpXgXcF+Qw/GCIVIxK5d/ALQw5iqMjEq1blDzk
         ni69DRdxWLD92zF3jerI9ngE8GeY8Be6FmnI69frY6qGmqVEkFzb9akQ+wp6ur2VA5mP
         jeAIf2fSya68Gr97xZlVbpmGpXtkwH0mg7soCsnAXey7e05AmEFTebnu6do5SpbhOzsW
         r8noZoXt4I+vru60vQiIWtMturzAipmpd9WgS11/tIh6XEvc7kyZjhXnRiaUC84UzuXd
         SMAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=lIdbT5MUIKBicEcQ4rht9j13O1r0E4iv/SxmMdH/J0Q=;
        fh=pNm4PMoSrXSSMztsII1pZAP1A64aHQ+SUiMJwY8BkYs=;
        b=HIZSqJBphF/2ZH3abQP7L+2TpzUXmMRe3vJSx/4TpszgMANlOLffwbzW9AnB42l6rn
         v5uRFlh1fG3nOOjZxXO8R1RtUEg+eO/RMQktfpXw+EY/W2LtNoxjpP1UehS1Kh0rie1I
         H2/FIr2fqWVwzHm9hM/n6zeeok/ae3xdT6wkG4u2/ZZn/NQ7pH7TT8Qeh+TTrGpBpnfJ
         Dt+pIOhqatBzGTikaxAG6IhdxXWi2V3psU6r3d3e7+xUBsdW7hiaBzPq86oZKQdP/uca
         XMjPLSQU7HlUpvV1DgQ3hC0fhe078xmweWenCg9U0zjpj8ouGrg2sw2HJNKWCmlpqpZP
         nDEQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hihUWngR;
       spf=pass (google.com: domain of 3o8fgzwukcsokrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3O8fGZwUKCSoKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080383; x=1741685183; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=lIdbT5MUIKBicEcQ4rht9j13O1r0E4iv/SxmMdH/J0Q=;
        b=g0Imy1WnMeGs6WKJ0PDxKIxu9aXXnagzCXZIeMppMUdf03d6orRlRtl+R6VYYcmKTT
         Zi20eJ6dOHzY/pYAgipMj/zoQyYAYrvXDpACNnJfzbCC7LYHrVI0AVLL3W1NtSAw4cVF
         Q14/NqRZZqHi8kc8woAiageNnPW1SOkDcIz4mdi8wB+h+ry2i+JzcKv9QaNab+LNDzfs
         eqEvRLboeNDGMtwNMtl2uDz6Ktf9f8f9A+kubkB9qHQLSjRz8C0jKffWeVZ7UnVnlW2X
         e1toXw6rHL5MCe4xhhDLVn6CuGRgnTYmX1Yiv9zF+KbDE3NnfsaMBk4zFlwF9i7n+6Wz
         zNfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080383; x=1741685183;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lIdbT5MUIKBicEcQ4rht9j13O1r0E4iv/SxmMdH/J0Q=;
        b=osqnvYSwdBeKbLMMCdV3VBHHHaUFYQh2XjU/iAlZ/QTUBaQ9EVdRUyQ6VnAEB6S0zu
         K4nwWTGfc5zNTSb6YJDdYrIssN7uQEefwUz4I4QJMCK6pBD/dvu9cLhZP52Ndba64pGR
         hzskl0ydBB7HKIJkds7zWjrJ4qWe33F8BvZnkqOKltyUYHMQZlg1Lo+X2JaWvUb8Evup
         666m0jaLOAHzLgUxs87AZiZrRInsKM11GR4uhj6Pd2RZYuttzaCWgmfGNPhosdX57NTa
         6/MRbERhRjAN4CEh2KgfNe+iO4dRb3c0tlWe6vlkbZoidmr4yQnyvn+HIzL7WDJWKlyv
         Q1ew==
X-Forwarded-Encrypted: i=2; AJvYcCWgcpnH7WGUBst8YpGxSd/9Xl5VT2bGPvAl+Nsukx8wnXl6Q6IW/c4WuthW1WErf1FDwbkYeA==@lfdr.de
X-Gm-Message-State: AOJu0YxK/gRX0s65Z+JPMY3aw9fr6DtV35SEvHtQF27bBRUX+XtlK0ae
	iXiqdeZ+j//vB/p6XUKobbHNX2pvZJtnFtdfZOlElJOLyA8nS+9/
X-Google-Smtp-Source: AGHT+IGdv5WW8RjLyognXJqe/uld+fAvL9iLCVX/bzXV1lpc2Dz88I0dNaTn0C4SgdEVb3Dfmev9TQ==
X-Received: by 2002:a05:6402:5193:b0:5e0:82a0:50d7 with SMTP id 4fb4d7f45d1cf-5e4d6ae7ffdmr13932444a12.8.1741080382636;
        Tue, 04 Mar 2025 01:26:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGfkcgkC5hnwFNg/XybuqAl6V3IbrS2IilFl4iwJJJ2Nw==
Received: by 2002:a50:9b18:0:b0:5e0:a894:5f93 with SMTP id 4fb4d7f45d1cf-5e591921e35ls364202a12.0.-pod-prod-02-eu;
 Tue, 04 Mar 2025 01:26:20 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUKa5Ka/WSDsl4wZvYpFZopvE7lHV9INyVGNRrpARgnkWH5pAYEfvhXFi6HgmgBwZ93J8TwyWOLt44=@googlegroups.com
X-Received: by 2002:a17:907:781:b0:abb:83b9:4dbe with SMTP id a640c23a62f3a-abf2687f8a2mr2004879766b.47.1741080380074;
        Tue, 04 Mar 2025 01:26:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080380; cv=none;
        d=google.com; s=arc-20240605;
        b=ffMTnUU2HzNZqWR9waQKCxSKdfC/HKIzs28CgJGUDLB6VeYc8FStBjWs+/qxOG7qe5
         dIYtZdZSvFohdBxDJ4870fwgrRGhQR5E6SB6eNpOMPqBHCBoqup6A/idEjfSm6tm1wLk
         NEl8TWDjAQtKuNe8NCnge8mw2TcUCE1qyIJkN8PuPeFYc7UCKJ5hyvw52xK+K0YXAWsZ
         W1JUoERmoqyNirBGTboQg0dLhBysKVNgrgoAtdNcdIjVkyBEw+uMe9wbf3+A+hOUwB4+
         mweVbuF2fEeqmGvMYb4YFrK2Z0DkFSercwGp44r5+aOxlxcJLJssAPZrUGcE55umUB01
         wwlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=3v8nr6j5ymgBv8KDTOp6L+lQpjYSKF+JE+VajMZf96I=;
        fh=kCfWdc/DCVpAw1dbh8hAn9TR7SO6yk9m/lC8CKko3f4=;
        b=POLJ87N/asASpANjnUA8NS/knb3oG9wQIidghaxydXP8XBwWAWWmnxpMJNi4ew9Uuk
         sWuTiOLyHPbM4ICdHSEqABQbMTzFGwaHhZdfMgC5h9mM4tvWHP9SFuEj8FosLVER1I03
         d8rjmvFBl3ef8PGCFvvCtNyHuXAJArusSeaA7qB/hu78TyO803PI7F1CMtHvBQVoBqcC
         MceZDJ8QEtkVE+pGp3rCRUWo8D4Tpi/OApHCjzOIOhiZLNAxPyJV2I1Fwump9od+Sxkz
         s9KcTxgWLaBJA2mcsavfx0qoCkNJWzhoisbEHez13Inr9JUYkuOOOoOHIhxNiU1U2+xg
         ZY8Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hihUWngR;
       spf=pass (google.com: domain of 3o8fgzwukcsokrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3O8fGZwUKCSoKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-abf0c0dd5a8si46882166b.1.2025.03.04.01.26.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:26:20 -0800 (PST)
Received-SPF: pass (google.com: domain of 3o8fgzwukcsokrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id a640c23a62f3a-abf68178603so277089666b.0
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:26:20 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWAe3kYSQrbygkQnZVtQ3cqSBDyFaBP/Cr1qmdBUkL2c77yHaGfGdkOl3Di7E1e2oWcO/Xa2l3BDC4=@googlegroups.com
X-Received: from ejctb24.prod.google.com ([2002:a17:907:8b98:b0:ac1:4149:808d])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:1ca2:b0:abf:5d9b:8076
 with SMTP id a640c23a62f3a-abf5d9b8a4fmr1339937166b.33.1741080379689; Tue, 04
 Mar 2025 01:26:19 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:25 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-27-elver@google.com>
Subject: [PATCH v2 26/34] kfence: Enable capability analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Jiri Slaby <jirislaby@kernel.org>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org, 
	linux-serial@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=hihUWngR;       spf=pass
 (google.com: domain of 3o8fgzwukcsokrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3O8fGZwUKCSoKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
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
v2:
* Remove disable/enable_capability_analysis() around headers.
* Use __capability_unsafe() instead of __no_capability_analysis.
---
 mm/kfence/Makefile |  2 ++
 mm/kfence/core.c   | 20 +++++++++++++-------
 mm/kfence/kfence.h | 14 ++++++++------
 mm/kfence/report.c |  4 ++--
 4 files changed, 25 insertions(+), 15 deletions(-)

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
index 102048821c22..f75c3c11c0be 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -132,8 +132,8 @@ struct kfence_metadata *kfence_metadata __read_mostly;
 static struct kfence_metadata *kfence_metadata_init __read_mostly;
 
 /* Freelist with available objects. */
-static struct list_head kfence_freelist = LIST_HEAD_INIT(kfence_freelist);
-static DEFINE_RAW_SPINLOCK(kfence_freelist_lock); /* Lock protecting freelist. */
+DEFINE_RAW_SPINLOCK(kfence_freelist_lock); /* Lock protecting freelist. */
+static struct list_head kfence_freelist __guarded_by(&kfence_freelist_lock) = LIST_HEAD_INIT(kfence_freelist);
 
 /*
  * The static key to set up a KFENCE allocation; or if static keys are not used
@@ -253,6 +253,7 @@ static bool kfence_unprotect(unsigned long addr)
 }
 
 static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *meta)
+	__must_hold(&meta->lock)
 {
 	unsigned long offset = (meta - kfence_metadata + 1) * PAGE_SIZE * 2;
 	unsigned long pageaddr = (unsigned long)&__kfence_pool[offset];
@@ -288,6 +289,7 @@ static inline bool kfence_obj_allocated(const struct kfence_metadata *meta)
 static noinline void
 metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state next,
 		      unsigned long *stack_entries, size_t num_stack_entries)
+	__must_hold(&meta->lock)
 {
 	struct kfence_track *track =
 		next == KFENCE_OBJECT_ALLOCATED ? &meta->alloc_track : &meta->free_track;
@@ -485,7 +487,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 	alloc_covered_add(alloc_stack_hash, 1);
 
 	/* Set required slab fields. */
-	slab = virt_to_slab((void *)meta->addr);
+	slab = virt_to_slab(addr);
 	slab->slab_cache = cache;
 	slab->objects = 1;
 
@@ -514,6 +516,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool zombie)
 {
 	struct kcsan_scoped_access assert_page_exclusive;
+	u32 alloc_stack_hash;
 	unsigned long flags;
 	bool init;
 
@@ -546,9 +549,10 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
 	/* Mark the object as freed. */
 	metadata_update_state(meta, KFENCE_OBJECT_FREED, NULL, 0);
 	init = slab_want_init_on_free(meta->cache);
+	alloc_stack_hash = meta->alloc_stack_hash;
 	raw_spin_unlock_irqrestore(&meta->lock, flags);
 
-	alloc_covered_add(meta->alloc_stack_hash, -1);
+	alloc_covered_add(alloc_stack_hash, -1);
 
 	/* Check canary bytes for memory corruption. */
 	check_canary(meta);
@@ -593,6 +597,7 @@ static void rcu_guarded_free(struct rcu_head *h)
  * which partial initialization succeeded.
  */
 static unsigned long kfence_init_pool(void)
+	__capability_unsafe(/* constructor */)
 {
 	unsigned long addr;
 	struct page *pages;
@@ -1192,6 +1197,7 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
 {
 	const int page_index = (addr - (unsigned long)__kfence_pool) / PAGE_SIZE;
 	struct kfence_metadata *to_report = NULL;
+	unsigned long unprotected_page = 0;
 	enum kfence_error_type error_type;
 	unsigned long flags;
 
@@ -1225,9 +1231,8 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
 		if (!to_report)
 			goto out;
 
-		raw_spin_lock_irqsave(&to_report->lock, flags);
-		to_report->unprotected_page = addr;
 		error_type = KFENCE_ERROR_OOB;
+		unprotected_page = addr;
 
 		/*
 		 * If the object was freed before we took the look we can still
@@ -1239,7 +1244,6 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
 		if (!to_report)
 			goto out;
 
-		raw_spin_lock_irqsave(&to_report->lock, flags);
 		error_type = KFENCE_ERROR_UAF;
 		/*
 		 * We may race with __kfence_alloc(), and it is possible that a
@@ -1251,6 +1255,8 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
 
 out:
 	if (to_report) {
+		raw_spin_lock_irqsave(&to_report->lock, flags);
+		to_report->unprotected_page = unprotected_page;
 		kfence_report_error(addr, is_write, regs, to_report, error_type);
 		raw_spin_unlock_irqrestore(&to_report->lock, flags);
 	} else {
diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
index dfba5ea06b01..f9caea007246 100644
--- a/mm/kfence/kfence.h
+++ b/mm/kfence/kfence.h
@@ -34,6 +34,8 @@
 /* Maximum stack depth for reports. */
 #define KFENCE_STACK_DEPTH 64
 
+extern raw_spinlock_t kfence_freelist_lock;
+
 /* KFENCE object states. */
 enum kfence_object_state {
 	KFENCE_OBJECT_UNUSED,		/* Object is unused. */
@@ -53,7 +55,7 @@ struct kfence_track {
 
 /* KFENCE metadata per guarded allocation. */
 struct kfence_metadata {
-	struct list_head list;		/* Freelist node; access under kfence_freelist_lock. */
+	struct list_head list __guarded_by(&kfence_freelist_lock);	/* Freelist node. */
 	struct rcu_head rcu_head;	/* For delayed freeing. */
 
 	/*
@@ -91,13 +93,13 @@ struct kfence_metadata {
 	 * In case of an invalid access, the page that was unprotected; we
 	 * optimistically only store one address.
 	 */
-	unsigned long unprotected_page;
+	unsigned long unprotected_page __guarded_by(&lock);
 
 	/* Allocation and free stack information. */
-	struct kfence_track alloc_track;
-	struct kfence_track free_track;
+	struct kfence_track alloc_track __guarded_by(&lock);
+	struct kfence_track free_track __guarded_by(&lock);
 	/* For updating alloc_covered on frees. */
-	u32 alloc_stack_hash;
+	u32 alloc_stack_hash __guarded_by(&lock);
 #ifdef CONFIG_MEMCG
 	struct slabobj_ext obj_exts;
 #endif
@@ -141,6 +143,6 @@ enum kfence_error_type {
 void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *regs,
 			 const struct kfence_metadata *meta, enum kfence_error_type type);
 
-void kfence_print_object(struct seq_file *seq, const struct kfence_metadata *meta);
+void kfence_print_object(struct seq_file *seq, const struct kfence_metadata *meta) __must_hold(&meta->lock);
 
 #endif /* MM_KFENCE_KFENCE_H */
diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index 10e6802a2edf..787e87c26926 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -106,6 +106,7 @@ static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries
 
 static void kfence_print_stack(struct seq_file *seq, const struct kfence_metadata *meta,
 			       bool show_alloc)
+	__must_hold(&meta->lock)
 {
 	const struct kfence_track *track = show_alloc ? &meta->alloc_track : &meta->free_track;
 	u64 ts_sec = track->ts_nsec;
@@ -207,8 +208,6 @@ void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *r
 	if (WARN_ON(type != KFENCE_ERROR_INVALID && !meta))
 		return;
 
-	if (meta)
-		lockdep_assert_held(&meta->lock);
 	/*
 	 * Because we may generate reports in printk-unfriendly parts of the
 	 * kernel, such as scheduler code, the use of printk() could deadlock.
@@ -263,6 +262,7 @@ void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *r
 	stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr, 0);
 
 	if (meta) {
+		lockdep_assert_held(&meta->lock);
 		pr_err("\n");
 		kfence_print_object(NULL, meta);
 	}
-- 
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-27-elver%40google.com.
