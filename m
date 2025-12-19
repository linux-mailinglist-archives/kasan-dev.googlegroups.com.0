Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCHHSXFAMGQED6XKEYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 11D65CD09BC
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:47:22 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-596adff8004sf2279662e87.3
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:47:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159241; cv=pass;
        d=google.com; s=arc-20240605;
        b=VIrZLQOvLwGAH8z7q87SbTDyNuEzNMneIXcqlN944BJFUNXW1GOyJB1ezzUwB41NA5
         g8pdNQ8ROiUJSSQhO7HrI22ID0NdkHZBBBxs1YTbgq0W6yg/cbJwZkCWbhZyPDVKv2M/
         o/upd77UElX9fwI9OrvK6a423E/SMgKhv49CnZM+4rbKU9QCkCL4SXlW5oJwP4Bnwcy0
         a9OJJx0rE8pE+eamCW/lkRaQ70an/x7maeBe90HWUxW/s//d1TWwTb4HSA6eAmiYbCBM
         lMnhCSTVqfYHdIHE04SCTrgfxcAUsILx4gX8xYKDuPJzSi4yTkg3+UPawmYlVEg0Oj1u
         Nn+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=tlYhznwMRxHTeLCzZN1AIafV2KG210vhxdB1XW8uKw4=;
        fh=uWYqjglhOG7zncRQJMzicI+x9U6O/6TLAHWVHWWSfEM=;
        b=N5ogcQWn4zJ0yVHt3Z0IdAGsJ82RPerRp6MuaqkhB75i409JH+n+iKoyMmLqBYz0pd
         JWiOVmonB6mEW3IJFnnRp5pKp1Frexb3CJXcFCnjJ3TrJXGNFOMg6q68pBWchoNNyS/c
         x06bZlW+NRG2AH7F2mOEhQIY/DKnygJm+GBd5bxiD9RHyY4QGGSd9biqPgl8ZoOWXi7z
         3N+imTbEyrbvfyRZZFCJlaEar7KhGwi18wBedHxxSghtaxuz7rqioDaQRhQKsFDkXaGW
         43WMuPsZMErR8qnovOJL+e1uTW/W0n0IslEb/BVxnkFzuNcsDF4iptyiWDM0ZQ7aw2nf
         9nGA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pZNrJKZP;
       spf=pass (google.com: domain of 3hxnfaqukcdi29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3hXNFaQUKCdI29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159241; x=1766764041; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=tlYhznwMRxHTeLCzZN1AIafV2KG210vhxdB1XW8uKw4=;
        b=DgE6Wc0BmffcCvGrAASXcJNS6KrELTQe7vwTzcMKkDHtTxcG3gNvkyi/xNfPM6ns4G
         upW/TY3bNWWq/GOPsc8nTPLKVeBKoEuVk7PQgWUe3BqozwHUzGFB0pz/aQT1Ml7Qw9nj
         JpSHsYJUQlAkI0WNDKb3cSZqYhxeA0O5OadbOgCV5mnZr3aaAj338kMNZ15E+rPQrNBJ
         CjiHfTI2bE14HUfeRUXCo6E6/sPxmy7jaqGk0iXyrfziGhKsxl0Mg96+Onj4pLWAwX8H
         7bTadkiFeVl/9gtdScQwSTAFfLZ6F+5Rws07gqe0zUt7gFfz5NOZD8DKxeYJokywqzEN
         PLYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159241; x=1766764041;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tlYhznwMRxHTeLCzZN1AIafV2KG210vhxdB1XW8uKw4=;
        b=NQCJNs1Q1ypQAEwA3eehBrZ89fCTX61DtVXcMeP0tRQ64x/M8eWOo2KHxno39HR6sq
         ThpkzZW7SvKFSZxhCjSAXFu685wtjLIhrbPedwiriKIyu6arub424OCHOZ29W79jIuHX
         fqVI7FCkQ2Pgq0ZUwtai5XSbENRGBLIV8Tyqnb5S/lKdxPO/NHMVTWnONsCtGSc50LLp
         vHIAwPZ/MDOCIvGbwbZLCMV7KOyBUdRZRoMhUwkXY78jTikw1w5+Up8ZCDfQOuV+dEGy
         0liiWhJJ3Vp58ilDXMdAsLA9FdFoAySikV8Bpc3uhu35nk5ggX+EeILIxK8fqD1wTtnz
         q1vQ==
X-Forwarded-Encrypted: i=2; AJvYcCUVoyxt/CyLPQpFu3a1E0PNn/JW7vYPHaN15TrH1OfNnql680E7PBCm7o/ssUUCbgY48itFlQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw0kq/P49L+aYwTMoM4+YoFpXaAglTftq/qaaBuP/1r5HCFesEe
	mp6kbU4ezGkFmdY8E48IMcl/1LmyooXjn7kXHYrVQFv1F24jKcswMMxn
X-Google-Smtp-Source: AGHT+IEClLM81t/6kHJzGqBzhgIsJO1y0XEk0vwGsSJh+rJ75C2fnrxYA73t910gPi3GgvYFtOVgAg==
X-Received: by 2002:a05:6512:3d07:b0:599:fe3:77d with SMTP id 2adb3069b0e04-59a17d5f153mr1258732e87.45.1766159241310;
        Fri, 19 Dec 2025 07:47:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbUGYRyKdKgHgw/ummvhMO6kWlY61nioUHQCSGR0boO0w=="
Received: by 2002:a05:6512:202c:b0:599:36b:f693 with SMTP id
 2adb3069b0e04-599036bf765ls1540231e87.1.-pod-prod-05-eu; Fri, 19 Dec 2025
 07:47:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXpc7PKmh3JHVugSy8T2II04jUveIQztrIVbvgjQ6OP4iI23jZjCt2/zSfXn4DWhw4B1yVRMOFoi1E=@googlegroups.com
X-Received: by 2002:a05:6512:3e19:b0:598:efe3:42d9 with SMTP id 2adb3069b0e04-59a17cff4cemr1216059e87.5.1766159238523;
        Fri, 19 Dec 2025 07:47:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159238; cv=none;
        d=google.com; s=arc-20240605;
        b=NWQObSHVGNpGWSFGT8QpgAaGmfqhY2iz9Hnx5NC7murwU6+4u5TYvA1K1+VO7G2gDd
         5ChcA7GwX9om2424P/z1CUduop9qfLtlrw1X/5yHUU4iEv85TzGICAPfis/8uplxDAqg
         r4qzczVpNf19XxKverc3Zv6ZZwBlREhuk6so+CG1aZ7Ych7nCaiVHtKg/2Ry9e8NodUJ
         DoZoEXwfg8XwgUCLwxeVe7TAN7NoTtbJIiV5vyS8IPiCMUZBb8NxyvRiUdowx03fZz+K
         W/rrtfaXeyJMJnvsrSz3LLqG8ByqZ7sCKfuIN4ChdqwTcK1LaU4oDOV84HmbD4hUxChw
         4qpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=in59w/Ham4YrnosvYw1tGLvejZ0fwtDhCl3ORoOSt58=;
        fh=BW/gRS4lopC8UbI6QVfvRFq1dNMNSGjeO/au8t87FLA=;
        b=EBThgScDDzrpBoS7OWmpLwFx3bEh/7S56c8cUySI/+dIgi+KPiarqNhNtYSRx7fIGc
         iTAXly8EAU9Dl72K93vupdspaxUPFFs1mnwhVUVGAsmzQ0bO7Dx1sb5cyx1kzdMpvNLX
         Vgp/EL/oo85/JJVw6x7/SocPRPXBBpvqdRspWj3jYfDwgWXDtYl46oFnChEHpVpq6EWT
         FoXg9reUzqeza13dKVNno8n0MpBKnU0BRwQpMyRSCiHRvjcgoQwr9Eall8tioOctjH1i
         J5vy8xTP8dfBGXWx7U5Rfazuqii3rBtfUvXDbV5s8ydtXYyKvG3WwFKZb2CKs7qV4DI0
         oMqg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pZNrJKZP;
       spf=pass (google.com: domain of 3hxnfaqukcdi29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3hXNFaQUKCdI29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59a185d65e2si61292e87.2.2025.12.19.07.47.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:47:18 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hxnfaqukcdi29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-4779b432aecso9871215e9.0
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:47:18 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWNT0nOvfP684BeH6Cz6a3brtvvKbh+o8RSvXPgdMq8SCe5Q14Rpo1n3QK29/k7hQJptEzqYromMl0=@googlegroups.com
X-Received: from wmsm16.prod.google.com ([2002:a05:600c:3b10:b0:479:3624:3472])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:4e8e:b0:477:b0b8:4dd0
 with SMTP id 5b1f17b1804b1-47d1957b120mr31632645e9.17.1766159237625; Fri, 19
 Dec 2025 07:47:17 -0800 (PST)
Date: Fri, 19 Dec 2025 16:40:17 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-29-elver@google.com>
Subject: [PATCH v5 28/36] kfence: Enable context analysis
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
 header.i=@google.com header.s=20230601 header.b=pZNrJKZP;       spf=pass
 (google.com: domain of 3hxnfaqukcdi29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3hXNFaQUKCdI29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
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
index 577a1699c553..ebf442fb2c2b 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -133,8 +133,8 @@ struct kfence_metadata *kfence_metadata __read_mostly;
 static struct kfence_metadata *kfence_metadata_init __read_mostly;
 
 /* Freelist with available objects. */
-static struct list_head kfence_freelist = LIST_HEAD_INIT(kfence_freelist);
-static DEFINE_RAW_SPINLOCK(kfence_freelist_lock); /* Lock protecting freelist. */
+DEFINE_RAW_SPINLOCK(kfence_freelist_lock); /* Lock protecting freelist. */
+static struct list_head kfence_freelist __guarded_by(&kfence_freelist_lock) = LIST_HEAD_INIT(kfence_freelist);
 
 /*
  * The static key to set up a KFENCE allocation; or if static keys are not used
@@ -254,6 +254,7 @@ static bool kfence_unprotect(unsigned long addr)
 }
 
 static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *meta)
+	__must_hold(&meta->lock)
 {
 	unsigned long offset = (meta - kfence_metadata + 1) * PAGE_SIZE * 2;
 	unsigned long pageaddr = (unsigned long)&__kfence_pool[offset];
@@ -289,6 +290,7 @@ static inline bool kfence_obj_allocated(const struct kfence_metadata *meta)
 static noinline void
 metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state next,
 		      unsigned long *stack_entries, size_t num_stack_entries)
+	__must_hold(&meta->lock)
 {
 	struct kfence_track *track =
 		next == KFENCE_OBJECT_ALLOCATED ? &meta->alloc_track : &meta->free_track;
@@ -486,7 +488,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 	alloc_covered_add(alloc_stack_hash, 1);
 
 	/* Set required slab fields. */
-	slab = virt_to_slab((void *)meta->addr);
+	slab = virt_to_slab(addr);
 	slab->slab_cache = cache;
 	slab->objects = 1;
 
@@ -515,6 +517,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool zombie)
 {
 	struct kcsan_scoped_access assert_page_exclusive;
+	u32 alloc_stack_hash;
 	unsigned long flags;
 	bool init;
 
@@ -547,9 +550,10 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
 	/* Mark the object as freed. */
 	metadata_update_state(meta, KFENCE_OBJECT_FREED, NULL, 0);
 	init = slab_want_init_on_free(meta->cache);
+	alloc_stack_hash = meta->alloc_stack_hash;
 	raw_spin_unlock_irqrestore(&meta->lock, flags);
 
-	alloc_covered_add(meta->alloc_stack_hash, -1);
+	alloc_covered_add(alloc_stack_hash, -1);
 
 	/* Check canary bytes for memory corruption. */
 	check_canary(meta);
@@ -594,6 +598,7 @@ static void rcu_guarded_free(struct rcu_head *h)
  * which partial initialization succeeded.
  */
 static unsigned long kfence_init_pool(void)
+	__context_unsafe(/* constructor */)
 {
 	unsigned long addr, start_pfn;
 	int i;
@@ -1220,6 +1225,7 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
 {
 	const int page_index = (addr - (unsigned long)__kfence_pool) / PAGE_SIZE;
 	struct kfence_metadata *to_report = NULL;
+	unsigned long unprotected_page = 0;
 	enum kfence_error_type error_type;
 	unsigned long flags;
 
@@ -1253,9 +1259,8 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
 		if (!to_report)
 			goto out;
 
-		raw_spin_lock_irqsave(&to_report->lock, flags);
-		to_report->unprotected_page = addr;
 		error_type = KFENCE_ERROR_OOB;
+		unprotected_page = addr;
 
 		/*
 		 * If the object was freed before we took the look we can still
@@ -1267,7 +1272,6 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
 		if (!to_report)
 			goto out;
 
-		raw_spin_lock_irqsave(&to_report->lock, flags);
 		error_type = KFENCE_ERROR_UAF;
 		/*
 		 * We may race with __kfence_alloc(), and it is possible that a
@@ -1279,6 +1283,8 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
 
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
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-29-elver%40google.com.
