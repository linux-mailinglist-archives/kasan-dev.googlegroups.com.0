Return-Path: <kasan-dev+bncBC7OBJGL2MHBBI7A7TEAMGQECMVK2LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C190C74C90
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:13:40 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-477563a0c75sf5575995e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:13:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763651620; cv=pass;
        d=google.com; s=arc-20240605;
        b=Uw9Aal11QYnX6gcm0chfMFwSTMMlfmZACnet5d8eMCItJZDJ8cyx11hTLo9EG6ljic
         IaY1yD0IIE48Pinh3Y6rJ4cK62Mxna43QKBosqcq4WZ8DZNjyz+em7xFeV1Jq37EA6EE
         tXV7lygygXZ4J6dkivOBbMVm/TBJJMXWo/zL+TyATqPDo+fogDFobx4zZ1rxaTmG+961
         5ISeL7RYlm/KbqZGuVj/yK7VhTn04aguQP9HOw4J6Wc1stjGLoGoRtBt3cvy38fevEJs
         YWAubLjMQcoJGt+XzbOYNhzgo21E/KdUH1YoVTGV1GCu6PAKkhrglp/m0K7GU2u+lBFg
         NmsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=wIqvrpptNe1O94wumnetsVlpTVNZmgmjof84eTXzh2s=;
        fh=UpWSE3wi6IlkMYC+w3na+Hu+0EIkVYLa8Y0WJIjxCC4=;
        b=XHp55Xpbb8WvELpVTf6caZmr8wRB0Zu34I1aG9rLjVDITDsBDVrUbmOa/dteWgdLqe
         Gy4yeLeXn66GnYfjLoh6mvR2To4BZdxipmISCek7P4xlGN1G/4YyDH0Vx8/n5jJmbhkY
         n+jfIsCOqnn+CDThuMTFPd5TkuZowR3ZNd50Kd80brB8EQzIKdxijZ4RiOgny4G/Sz1y
         SRYKfczn72RpG8G16nEOK+iVn8Y67xkHiiMYJctN2d4bWr0m883zVYdB/buZvHBzbOWR
         eZ7BNJBU2eP3KyEUq8voqTD2aaMNTHdTVsOu+umdW2dgPAzGnabAiScy4EC1oK6JjFZQ
         NRQQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=drdD7pN8;
       spf=pass (google.com: domain of 3idafaqukcu0t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3IDAfaQUKCU0t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763651620; x=1764256420; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=wIqvrpptNe1O94wumnetsVlpTVNZmgmjof84eTXzh2s=;
        b=L1jORRteAxkSTLAXnxjRvVivBELDXRFO2VK9yZGTPwDzo2y8DGSTMLlwUG0BQY9ttc
         dggqPlDl5RMVHTaqpk8+aHWejLqy6eVpepLhrE2stM/pOKLZ3kgI3u5jjaCtIPxyR5Mn
         Ea9DcHDM7qMKgX448rD4ap1yx9QbbzbrE/2a7878RwKEFUrzU/rmU2wPahoOktVHCgPq
         1M2dKS30BfiastzGs6vsOQBOMHBqwHki1z1J/3YGXJc5i9woPJYOCElQ3QChjCii20Vf
         /IY41BWoxGpQczKp3H7YU7MVytTdetiS9dH/l07CAMQjrtzntmkAisef7eg6GEIqLRK1
         Ne3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763651620; x=1764256420;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wIqvrpptNe1O94wumnetsVlpTVNZmgmjof84eTXzh2s=;
        b=BUt0m3AKP672CTF41AXc0DiJuiCIOJ6TRr/89MJ3lS0xZ11T0sJJazCKTj/ONZ8OCw
         KX/hvoKtiND9/9NL9igJyaLeglqa0m+tdpO+aJc2fnPo4teUfALfsObIO89BLa8T45IC
         KtVC40pVtlglwY4DS92DEbtkbje4b1j5FrdD1gYyEuLUUoX93LlpuCp9AJCwpo8c1yNu
         5P2Uscyn8bxdwStsbmGAvSxlqtt+ld6HOkh3j37rhsNkJ8xafQzYiw/7HSHWfEnSdeE1
         zy9Pyzfha/kg09MVBjplQtW7QUY5X4ujO8rjsGaxkJZo5Rvh8O0Y18s91UZJM9+jiBOK
         O+pA==
X-Forwarded-Encrypted: i=2; AJvYcCUC9uukqer0qlbfEZLxGex2bRE8y2AGPgnxgarZfzOcnEk38TGLZY4B5g/miRKdudZHprHCAA==@lfdr.de
X-Gm-Message-State: AOJu0YyvdsNCEphCmtao6e3T7DWZILBiOCuBDFdJ6wD29mktpVEWmp7g
	2mDqAAFGRlrVjUdivKlTXX6GAdCwsAWzaC2tDDOJi5dEpZe3AZx+zadL
X-Google-Smtp-Source: AGHT+IGb4DGY6vYgOXWas7rBYZiVsSvZ8PtmoqxsLKt1Rbc/VxTtlHbGA9xL08r6U0sCdcK9wCi6Gw==
X-Received: by 2002:a05:600c:474a:b0:46e:5100:326e with SMTP id 5b1f17b1804b1-477b8a98a93mr38382295e9.23.1763651619941;
        Thu, 20 Nov 2025 07:13:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YojY9V9Y8x8YDgZgJ1GGyGDh0CrLBo4OlT4g3yKYeGzg=="
Received: by 2002:a05:600c:8188:b0:477:5c4c:acc2 with SMTP id
 5b1f17b1804b1-477b8e1bc46ls4045895e9.1.-pod-prod-08-eu; Thu, 20 Nov 2025
 07:13:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVAwwrTgdJE51b8EjtnXMDTBNmBeXLgL0j1nnzTIBT7FmUrx9UdggoPo/AsrqW212kRMXPI963t0+U=@googlegroups.com
X-Received: by 2002:a05:600c:314f:b0:471:d2f:7987 with SMTP id 5b1f17b1804b1-477b8a98c6dmr33428805e9.26.1763651616986;
        Thu, 20 Nov 2025 07:13:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763651616; cv=none;
        d=google.com; s=arc-20240605;
        b=LIjhOHavx/ByHgF1YoRXWEdFPAaFURFr8FInbQakhkMmTCSuL2NP2lDKwLNaRmbZLW
         KqGZGZpIm28ye5xR11iv7qYRty8oBa4ieLal0KmQFQcxVYL5LE8YZkPxp5NS2x5pIiSB
         t0qcPDHFFi0l6f8sgPxFcgcghBPkdvC4hE6jQgk+FQ14lRiACUWifWEJ8j2Koc86fIgU
         dDwVbkJutXxeuDEHxpf0nDKqkxiMECl/T/vCOPTu8khQwD4f2EugDsqhDyQC4E1BAYOD
         UJef+1YWvjJ3CVP4Mff6l7WGKzkpXSOD0glpEe2vvb88cSajVqLqkeZInlNHgzpLIkd1
         1btA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=mqBL95K9iMIYpMB+0uabPzgdi4RlMsfaN5hL0tFWKIQ=;
        fh=kW3+GCJUrccrNVqyXo1QSRkNmrYca9ei5Vun5ecAyZk=;
        b=Yv8N0T9DHEEzzRPYqxj28E3nQYZoPDpZfqFzXd9ANfjjCkjnKaD74U95z5N2w++CWv
         r7eyqqMtu4y6R6upA2Lt8kxbzFY/07+SiVeeEsUkdqsu3IzAUx3bzRQwWuCP+RmwPDCK
         zoqfwCiDsbw9M24yOFYGcHTdM96TbjwarOeu8caH6Be4TGMbPOFV284ePES9nTswE9fn
         VTXnl7QnychsyvAVseMOXz9AtIhAwFlq/jN10QyavjCafmBUlwUfbSn3ifWnprw3te7X
         ltlxImyd4r6YP+OEry0UfELNjf4zs2X/AaeUHPBURCj1X+Z9VRxAQ3SOxGuu+u5TtJI8
         qaNw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=drdD7pN8;
       spf=pass (google.com: domain of 3idafaqukcu0t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3IDAfaQUKCU0t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-477a9d20159si1330435e9.1.2025.11.20.07.13.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:13:36 -0800 (PST)
Received-SPF: pass (google.com: domain of 3idafaqukcu0t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-42b2ad2a58cso546279f8f.0
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:13:36 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWswnS0UhkE5B47tymciBAXIqafdtXWczHd6QoTKOYLKa1Vclp32hd+QcGwepgl+vvCwj5NCJZjZrA=@googlegroups.com
X-Received: from wruc15.prod.google.com ([2002:a5d:4f0f:0:b0:42b:2fcc:57d1])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:240b:b0:429:b2ad:f31e
 with SMTP id ffacd0b85a97d-42cb9a3f384mr3224742f8f.35.1763651616390; Thu, 20
 Nov 2025 07:13:36 -0800 (PST)
Date: Thu, 20 Nov 2025 16:09:52 +0100
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120151033.3840508-28-elver@google.com>
Subject: [PATCH v4 27/35] kfence: Enable context analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>, 
	Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland <mark.rutland@arm.com>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Miguel Ojeda <ojeda@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=drdD7pN8;       spf=pass
 (google.com: domain of 3idafaqukcu0t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3IDAfaQUKCU0t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
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

Enable context analysis for the KFENCE subsystem.

Notable, kfence_handle_page_fault() required minor restructure, which
also fixed a subtle race; arguably that function is more readable now.

Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Rename capability -> context analysis.

v2:
* Remove disable/enable_context_analysis() around headers.
* Use __context_unsafe() instead of __no_context_analysis.
---
 mm/kfence/Makefile |  2 ++
 mm/kfence/core.c   | 20 +++++++++++++-------
 mm/kfence/kfence.h | 14 ++++++++------
 mm/kfence/report.c |  4 ++--
 4 files changed, 25 insertions(+), 15 deletions(-)

diff --git a/mm/kfence/Makefile b/mm/kfence/Makefile
index 2de2a58d11a1..a503e83e74d9 100644
--- a/mm/kfence/Makefile
+++ b/mm/kfence/Makefile
@@ -1,5 +1,7 @@
 # SPDX-License-Identifier: GPL-2.0
 
+CONTEXT_ANALYSIS := y
+
 obj-y := core.o report.o
 
 CFLAGS_kfence_test.o := -fno-omit-frame-pointer -fno-optimize-sibling-calls
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 727c20c94ac5..9cf1eb9ff140 100644
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
+	__context_unsafe(/* constructor */)
 {
 	unsigned long addr, start_pfn;
 	int i;
@@ -1194,6 +1199,7 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
 {
 	const int page_index = (addr - (unsigned long)__kfence_pool) / PAGE_SIZE;
 	struct kfence_metadata *to_report = NULL;
+	unsigned long unprotected_page = 0;
 	enum kfence_error_type error_type;
 	unsigned long flags;
 
@@ -1227,9 +1233,8 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
 		if (!to_report)
 			goto out;
 
-		raw_spin_lock_irqsave(&to_report->lock, flags);
-		to_report->unprotected_page = addr;
 		error_type = KFENCE_ERROR_OOB;
+		unprotected_page = addr;
 
 		/*
 		 * If the object was freed before we took the look we can still
@@ -1241,7 +1246,6 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
 		if (!to_report)
 			goto out;
 
-		raw_spin_lock_irqsave(&to_report->lock, flags);
 		error_type = KFENCE_ERROR_UAF;
 		/*
 		 * We may race with __kfence_alloc(), and it is possible that a
@@ -1253,6 +1257,8 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
 
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
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120151033.3840508-28-elver%40google.com.
