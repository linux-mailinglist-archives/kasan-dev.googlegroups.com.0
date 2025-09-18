Return-Path: <kasan-dev+bncBC7OBJGL2MHBB45DWDDAMGQEEPCPUFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id A5D21B84FE8
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:06:44 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-55f70a5c9e3sf730152e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:06:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204404; cv=pass;
        d=google.com; s=arc-20240605;
        b=k1rfp0iDEafA33XRLDxbDESS5vCoyam/icuu/QiSYWjRfvI6Xp5tP5OH96U8Xi+D4Z
         mTKsyZJQOst7wuBb4pqY+BWSI2tdA3xpQOMXRkCwVoeQsMnz93CBasPYvDcBBmHqIXqX
         XQxkddMp00mfekM0BYATTUPk9wRqT4cFTu+Y3PCP4/EMkz4rpF37K4mGnxdlojqRDlBv
         SNfaMTawOpGsb2avNmJleRERhTO2m2a6Hd9G8z8tJHnRP2oB9HN8vzUjEhjjkqEZYZ9h
         U1XUbFGSCqzdexp24qyG0V7yCD1+Pl+QzaiOSFovzBWbd0bY5J9cFCnZtZuUSXbwl5eT
         QJAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=UvfPIKEB3rKaSFEAYg8pTjrzKJI5UL6bfNMwAx+vsGA=;
        fh=53StgpFYpnoiuV9zPmfzhDW+mHlM3g+NXQXprMwrjKk=;
        b=A75XINYMJ06cMZ7FI7GYIF56ULYUchgqmEriFvjfkOMfJzYNhoG5PFu03j/d00EPRB
         x0/WpQ7hbq5Bf97TvkwsXAw/3+RoXRT3n8txdKV/Znw5elg07ftsSg9NdnHJXbC72pKg
         0o4IN6i38FxksobmEN2nCszM2Sd85sAZIX2mRVWf+tvxeKTD/+Cld+N5jOYU73hFYlKF
         H5MPbl9SHkZB061y9Y6if/Hv4cyxqumwe3GSVs4GdToeAIHmS0DXxkJWIjWR8Ew5lNln
         ylqvR4zD5ejmcSCj6xvGGv7uq9TbqAugeoE9n20ic1Ukgm6CCY20wm0pno9RycY7QW8g
         RATQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TRk1I9MB;
       spf=pass (google.com: domain of 38bhmaaukczez6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2a00:1450:4864:20::14a as permitted sender) smtp.mailfrom=38BHMaAUKCZEz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204404; x=1758809204; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=UvfPIKEB3rKaSFEAYg8pTjrzKJI5UL6bfNMwAx+vsGA=;
        b=w4LUY7Ypm5iLNqQQmQ5Yz4l7PTRRb+GF3i9khce/lFG1Hc+yO6GDdpVRzSzRQK7h5G
         PrgBX3CuPESvOJW//tqbyjB+tAamCOoSVHQhImphfnfR2bnZq4I5X7WU4W0AWwCbxsct
         f9iKA7td5kzD3e7P3l377d73ErppUxivVL2FfIygtgv+icRIt/nVPMSVr0NRunYOqoNB
         aSlh38Ir4n94a6TwTpfkqgnt1YhPXnQMhCwaTzvhmSpREGsbtIcySLQus5gzOtvRNcpy
         MTG7x0VQLGD5fRGCZGFUB3KcjnCG9qgQMJvJHw0r5tew74IS5riJzhHk64zrF4wu2bk4
         nilg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204404; x=1758809204;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UvfPIKEB3rKaSFEAYg8pTjrzKJI5UL6bfNMwAx+vsGA=;
        b=bdONqeTZYgMaWudfYYF08Om+vzeIqB9fhR82sx6l857zflGMg8TzsSkBLk3c69HJsS
         K4bOn86f6doO/+RJVCS1vhcJpLaEdyirROBSbymF4e/ThWFYbH3UgvEl12Su9RW8DlFr
         1bEodI14i1OG24mRmgWCXyV3aaFIFr1GY7T1Dkv7i8tklnhg+lxSTtLybeIZ4GpRt1M6
         qBukWwmJDxNZXP6dpkTi/3Tg/5AWIkGjb4nTHUy13Vp5FoaUIcn+G0HV+Yr7mJ5W3Lwl
         C+s5ACwi6rLu2se6se+GGd9v7MYHC7+T9XU92zHJGtIES8tWl0FLIWCcfodfSOAzU1Rj
         A9qw==
X-Forwarded-Encrypted: i=2; AJvYcCX91BcPs22KtJDd2po1hJbur4d6n0lX9a4mPPajuw4V7NWDYfLnkaphmOjN2tSW49lUQ+laiQ==@lfdr.de
X-Gm-Message-State: AOJu0YwcE3t74cKoR17IiEP5pVhQFA8q+fWaezmKilGi/47nW56aMU+l
	pihJG0rzxKQTVfzlwVemumxDVumt1eSshc4DZ3jG5MHusycABYZ3MFKP
X-Google-Smtp-Source: AGHT+IHU7/u/MzPOUOjtvvd0gPZosd5lr+qOMcSZ6Loy3mK8uWT/kyQ/AeCF4ZFmn+2TMI1ozyVFGw==
X-Received: by 2002:a05:6512:1553:20b0:578:ed03:7b5f with SMTP id 2adb3069b0e04-578ed037e06mr732262e87.26.1758204403543;
        Thu, 18 Sep 2025 07:06:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7CfSChKDrSVtP/cWnXjUdOlgLBlT2olOUCsldF9csaRA==
Received: by 2002:a05:6512:1051:b0:55f:457c:89b2 with SMTP id
 2adb3069b0e04-578ca7e37f2ls379278e87.2.-pod-prod-02-eu; Thu, 18 Sep 2025
 07:06:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVRD8a3OHG/Qv0voi9r9/pYmeMRL4w22YI43xH5p06XC9X7B/jdVtcGu0wqcwJ6UeB+IbD/b5/XAcY=@googlegroups.com
X-Received: by 2002:a05:6512:3b8e:b0:574:927f:8c31 with SMTP id 2adb3069b0e04-57796f3e262mr2221224e87.19.1758204400521;
        Thu, 18 Sep 2025 07:06:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204400; cv=none;
        d=google.com; s=arc-20240605;
        b=i6fGs1IjD0S/Gcf+pd9gVdPF0fsa6JiYFiygmBCXQTxpnV44NEpQN2y35RPTyJgEJW
         zsG//qzYXyRIG4KFw5ZhcUnS29lb8OuHkc8AFKOYyKZIpVr08TIogybRdgAxvtfDXeJS
         nz0onKOOCihPsOQmlcXFBbe7brR75nLSHh9uBCoLze8bbxu5bJXJ1kzDE5LNu66IfLpB
         1YubIsQBOflrX5LTma40g+v5rBNIVUFv7iRQioQxuB2+bBrpQlNI1eH0UTzo66iyRJ9W
         L3II1GC0GCsaoNdfmJJxfdBzM/ExA7MfFB8IaNG7VN/79cUazzQ5+cV7Matp8vXRWA8q
         gBJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=AbpPVjMmuER0ts34LQajNdvnhoooPemuy99n7ga7GVE=;
        fh=dD3Fvk0bg7AidOGVJlN/Do79ym/71NrQfFhyUrHgS/w=;
        b=Slr911VXNBFDCw38D5Zf8SuQA4HTdJYAfsl2XaoPVpgp9z3X/VZdYyWTdGbXDqKyLQ
         mz/Sej+oejmUeeRPBDLG1uTyAhKC57i6AXpDDWATSiEu31J4OFmgEAioaFKAhHyRWXR/
         fR0J2uNhxG6Ev69Sn3loEsp/nGlCybbAs9mFGir0xxRYNPWBqiaO7hXyrFMVEDEujKVu
         lWZjphQKc9XEL24p9/rM/gyUrcpyeljVULinJhr29G1lWUjKjmguDzjG/bDlPJGDutaA
         6ycyW2vLWhkq0VQ/lKIXSIPlSyQGRlHt/lJvcIzWRmu+4tDDPvtvVUmhoFTx64kCGsFA
         4EEg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TRk1I9MB;
       spf=pass (google.com: domain of 38bhmaaukczez6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2a00:1450:4864:20::14a as permitted sender) smtp.mailfrom=38BHMaAUKCZEz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x14a.google.com (mail-lf1-x14a.google.com. [2a00:1450:4864:20::14a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-578a3896346si50190e87.0.2025.09.18.07.06.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:06:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38bhmaaukczez6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2a00:1450:4864:20::14a as permitted sender) client-ip=2a00:1450:4864:20::14a;
Received: by mail-lf1-x14a.google.com with SMTP id 2adb3069b0e04-55f6f4dea68so679091e87.0
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:06:40 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXBmP4/eyJAQFMiy4TzWvaZsAbXIatYP2uAl7BEb2xSyofNzsgXm2LnL0yAo7AEUkqxPQBNBMPErgw=@googlegroups.com
X-Received: from lfby21.prod.google.com ([2002:a19:6415:0:b0:577:abf1:7dcc])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6512:4041:b0:579:c485:8704
 with SMTP id 2adb3069b0e04-579c4858934mr81687e87.42.1758204400078; Thu, 18
 Sep 2025 07:06:40 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:38 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-28-elver@google.com>
Subject: [PATCH v3 27/35] kfence: Enable capability analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Christoph Hellwig <hch@lst.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Kentaro Takeda <takedakn@nttdata.co.jp>, Lukas Bulwahn <lukas.bulwahn@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=TRk1I9MB;       spf=pass
 (google.com: domain of 38bhmaaukczez6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::14a as permitted sender) smtp.mailfrom=38BHMaAUKCZEz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
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
index 0ed3be100963..53b81eb5f31a 100644
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
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-28-elver%40google.com.
