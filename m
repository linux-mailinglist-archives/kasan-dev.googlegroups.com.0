Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE7HSXFAMGQET6PIHUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id D26D8CD09C5
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:47:32 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-430f57cd2casf1623848f8f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:47:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159252; cv=pass;
        d=google.com; s=arc-20240605;
        b=FLQZumrjCc1canWdAd+zXhBLmqo0qjF9c7X1zTMHR851AyJFKOyFAnqQo25psIpm8/
         iONmpoT+cQAOorRjH6xPzpCjjE9xlrCTymjdOe6l1hcZ1fLciMbEJFwW2nkVmMtDFG0+
         ReuNOT4wyrfm5mqXlBNR1wbJcExBFrA6BPFaKd/PsqWY8SZV4Oc5RuL0UUmwLBpSoRYz
         Zfl2ZJW1/nQnsFJYSwZtqV30Y3DwYIXPtFuQT+6L6/bIgTnGdWlSNXbqfJdvZWLX4zHH
         CSTvmeJpN2KF8BN/sRCim1/aUrijyCli5jGqkqMhI5O2JJAsXWjpWYpcM+RC31QoP1fC
         Mngw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Njl4W8MUisE0oBHsqLIhEfOb3ddWj2iZN3EzcFnQyIk=;
        fh=X1m+VyeqO+vq0EtLxG8hmfLQQA7buaj9DDh/PpASxfA=;
        b=GcLLlDAeLt/fgtCSjuU1wIVc3MFBhAi9KjYIY+9Jv6oekV5ErkLrjEIJTfUhaoeXNw
         PUjtW2sM4DA0eJWahLxo9sgrhopFaB24J8LSdfdsuOXU6KluOtPmbfIZnDMq/7Ly3dQJ
         +p2z637pm6YcwXalV2K6+5wEnG4G9Jqfq8hokvZCzEKebudGW6HtUQ7VtiKt0B8z6+m4
         73vsD0jQsQKeOuDdJsyt/2p8C3Zpl7qS0s0x30EhF7nFo01X80EtBIG9sLlUE9KuRoeN
         +H58N3/FsVZUnQlM8kTAvOgxJxEA5cKBmD3mJ7vumMTuhvxZRiDZ9/cy8bYUOE2jaOZH
         hEvw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=s3EXoqzM;
       spf=pass (google.com: domain of 3kxnfaqukcd4elvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3kXNFaQUKCd4ELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159252; x=1766764052; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Njl4W8MUisE0oBHsqLIhEfOb3ddWj2iZN3EzcFnQyIk=;
        b=ZiKN75UGi8hHAu1Ddk4Et4KEcueWprDXqh9L5sn7d+8dRLoZSnGZKptA9yM68OCT4s
         q0+JS9q9dw8wCiaPC8Nt9mbAnyUsk33J5Vi2tQD4xF07zbCs9VySlio1wXGWTI1sOeQG
         FpF7lZA9GITx5KDLXHnIQAhtd6fkKytdGRYq0V9XENvSW34+QZqZZxANJaoJOpKcWVX+
         NXHL5WreUeZ8hUDg0Y8bwaqRPBxyVsrS2ow+xaegcANEekLJV3UiNiX7zOLsxjg/qjoI
         me/fcjTrtAOppICLH8xsT31bouWZnNgXPxlP4VT71O9BRT1anW217ELE0Hxk/ajDdFvx
         +reQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159252; x=1766764052;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Njl4W8MUisE0oBHsqLIhEfOb3ddWj2iZN3EzcFnQyIk=;
        b=slRresJh2BQV4EdIK3Vk3porpcqYnaOAt7dq7iqmpifft8yz5e5XUN0zMve+eNbn/d
         QNBs1sc9K6qM6hmP0ZMfLB/wgToWrT9YtBkBnSoXcagSvpM8KuUD1xP8uwHUSn2VbxAr
         XsTO5MUr17+KXx5vzELzguK6wsqSwFLRKu8zbbbvpp0cowsXgQMHFGRP4VtCd1xy1Lpn
         sh6fvDB5AqgqO/bmZQ037AkqMCDAXnTdqGLthgAypVCzrtxXvYWSRhMEoNMZPmBu31rb
         JDQSDYUZrBKl1eJpULVV9EiZzCat1hBOsV74ssAh9EWRZ+AWoO+///LkeqL3jpWONxVI
         tpVQ==
X-Forwarded-Encrypted: i=2; AJvYcCWY7yBt2F836nfruZ7hoo9LdHbNlJbUOA0XS3DoYkkEQ3Hu3BbmoK8yyqa2W9HI1Y2c9soMnw==@lfdr.de
X-Gm-Message-State: AOJu0YzeBTRFVyv8nNV/kHNaWeSFpfcypJAMfKkzvuof76ECXV6yFnUm
	nLGuBrqYHpeV3NmpQRvW0EKIQDp86XJhsTwian7+nzo9u0DT5hBCRSUY
X-Google-Smtp-Source: AGHT+IEHrk54JfxQpXBEe70B/1nBiDucwaTypYg3iJOyDWh6wzkkGHzQ/kwMRny3FtUI90aJGKgjJw==
X-Received: by 2002:a05:6000:1845:b0:430:f5ed:83e3 with SMTP id ffacd0b85a97d-4324e4c737bmr2926286f8f.6.1766159252180;
        Fri, 19 Dec 2025 07:47:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYywu7kYQaewrIwWk1k1Cwsx9WQq5KTDd72hKNPAEAXoQ=="
Received: by 2002:a5d:5f89:0:b0:426:fc42:689f with SMTP id ffacd0b85a97d-42fb2d890aels4475514f8f.2.-pod-prod-05-eu;
 Fri, 19 Dec 2025 07:47:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXBnoIE8d1Mo9Mq5g/DzzY3ai2sTV5P/GdS4lHhVPAPM2PnA/vD+lRec5fHwo9mT/PmTNpgAzbTIOs=@googlegroups.com
X-Received: by 2002:a05:6000:178c:b0:430:f41f:bd5a with SMTP id ffacd0b85a97d-4324e709017mr3918649f8f.57.1766159249858;
        Fri, 19 Dec 2025 07:47:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159249; cv=none;
        d=google.com; s=arc-20240605;
        b=T+OFmLz7zIO99XH2q4YRYM8ySZjeANZ7aPeK5Jw8H3Mje/MJAgTA7QrfC17Ib81lq3
         qmuzgU0trAtFlOifMK0MrGL39Q5X8DMUXuWHRIyqo+s1Hqk/2qd8xNEhj4BDQ6JbLbLG
         m8MCMz7CnKZIHYBkrxWxQ5hPyKcF5J1Pc/1xIbyRDOIPziEssLN/bRan2iveghSdaJIj
         uacNuE2pSc85QH2svxSdCel5MjpT0xlIr5VCbS4BLTPzF6YG92dk4dyh9rROK5M6cSDZ
         38gufZwFfgxN98c0RCWbeB/WK6gVYu1sdj3MSymorkxg1P9dfxJh3stVJogyG1THgrHn
         bJlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=4XK3qzntTZnJieCCKu4A/HzWNSoArWneMhDpC7gb9Kg=;
        fh=mgH788xisfz5HbQ2aYcXbMfXTpT0VV90ZObYor2rzoQ=;
        b=lpxMXVk1mJ2W0dtcVb4ai3IFx6zqGl5qXvp95nho8mL/STtT8WfXztu5T0NZtY/kW3
         LvNsqN776DpuES5Gnw6EaQvriIjOQM6U/yaJ/jy+d3ItSIIaUdnRdh/vLm1KnhOhVE4t
         /bbeIQuzH5nT4/zrbhLrZ8yleWkD1wdUFJC88Ybwou72LnKqP7habmEjarYBS37pMVi1
         qOicdcOEDB6fGiPvxAcEIbjBi5+vvQWI4O5marDbI2Q1Gd5pbYwFUsM92CtR1as5jcI3
         UeZ+0rj8NStzw3dc+bKcrr6Og2/8aQRNEqd0SeaEkiLQQd6QRgxhW5rTb6q3Ps8zCrCC
         6Xmw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=s3EXoqzM;
       spf=pass (google.com: domain of 3kxnfaqukcd4elvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3kXNFaQUKCd4ELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-4324ea794desi40085f8f.6.2025.12.19.07.47.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:47:29 -0800 (PST)
Received-SPF: pass (google.com: domain of 3kxnfaqukcd4elvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-64b9ccc9661so764700a12.1
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:47:29 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXe/PE3UHCO4W40sMZueHzcSNPforxZkCDFt4FrQafXqxZ+ZBcYwzkQ6waf/YXBJtf6HZB6o64aZBc=@googlegroups.com
X-Received: from edpr3.prod.google.com ([2002:aa7:c143:0:b0:64b:9f62:a079])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:d62:b0:64b:993f:ce06
 with SMTP id 4fb4d7f45d1cf-64b993fd097mr1762424a12.32.1766159249192; Fri, 19
 Dec 2025 07:47:29 -0800 (PST)
Date: Fri, 19 Dec 2025 16:40:20 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-32-elver@google.com>
Subject: [PATCH v5 31/36] stackdepot: Enable context analysis
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
 header.i=@google.com header.s=20230601 header.b=s3EXoqzM;       spf=pass
 (google.com: domain of 3kxnfaqukcd4elvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3kXNFaQUKCd4ELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
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

Enable context analysis for stackdepot.

Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Rename capability -> context analysis.

v2:
* Remove disable/enable_context_analysis() around headers.
---
 lib/Makefile     |  1 +
 lib/stackdepot.c | 20 ++++++++++++++------
 2 files changed, 15 insertions(+), 6 deletions(-)

diff --git a/lib/Makefile b/lib/Makefile
index 89defefbf6c0..e755eee4e76f 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -250,6 +250,7 @@ obj-$(CONFIG_POLYNOMIAL) += polynomial.o
 # Prevent the compiler from calling builtins like memcmp() or bcmp() from this
 # file.
 CFLAGS_stackdepot.o += -fno-builtin
+CONTEXT_ANALYSIS_stackdepot.o := y
 obj-$(CONFIG_STACKDEPOT) += stackdepot.o
 KASAN_SANITIZE_stackdepot.o := n
 # In particular, instrumenting stackdepot.c with KMSAN will result in infinite
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index de0b0025af2b..166f50ad8391 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -61,18 +61,18 @@ static unsigned int stack_bucket_number_order;
 /* Hash mask for indexing the table. */
 static unsigned int stack_hash_mask;
 
+/* The lock must be held when performing pool or freelist modifications. */
+static DEFINE_RAW_SPINLOCK(pool_lock);
 /* Array of memory regions that store stack records. */
-static void **stack_pools;
+static void **stack_pools __pt_guarded_by(&pool_lock);
 /* Newly allocated pool that is not yet added to stack_pools. */
 static void *new_pool;
 /* Number of pools in stack_pools. */
 static int pools_num;
 /* Offset to the unused space in the currently used pool. */
-static size_t pool_offset = DEPOT_POOL_SIZE;
+static size_t pool_offset __guarded_by(&pool_lock) = DEPOT_POOL_SIZE;
 /* Freelist of stack records within stack_pools. */
-static LIST_HEAD(free_stacks);
-/* The lock must be held when performing pool or freelist modifications. */
-static DEFINE_RAW_SPINLOCK(pool_lock);
+static __guarded_by(&pool_lock) LIST_HEAD(free_stacks);
 
 /* Statistics counters for debugfs. */
 enum depot_counter_id {
@@ -291,6 +291,7 @@ EXPORT_SYMBOL_GPL(stack_depot_init);
  * Initializes new stack pool, and updates the list of pools.
  */
 static bool depot_init_pool(void **prealloc)
+	__must_hold(&pool_lock)
 {
 	lockdep_assert_held(&pool_lock);
 
@@ -338,6 +339,7 @@ static bool depot_init_pool(void **prealloc)
 
 /* Keeps the preallocated memory to be used for a new stack depot pool. */
 static void depot_keep_new_pool(void **prealloc)
+	__must_hold(&pool_lock)
 {
 	lockdep_assert_held(&pool_lock);
 
@@ -357,6 +359,7 @@ static void depot_keep_new_pool(void **prealloc)
  * the current pre-allocation.
  */
 static struct stack_record *depot_pop_free_pool(void **prealloc, size_t size)
+	__must_hold(&pool_lock)
 {
 	struct stack_record *stack;
 	void *current_pool;
@@ -391,6 +394,7 @@ static struct stack_record *depot_pop_free_pool(void **prealloc, size_t size)
 
 /* Try to find next free usable entry from the freelist. */
 static struct stack_record *depot_pop_free(void)
+	__must_hold(&pool_lock)
 {
 	struct stack_record *stack;
 
@@ -428,6 +432,7 @@ static inline size_t depot_stack_record_size(struct stack_record *s, unsigned in
 /* Allocates a new stack in a stack depot pool. */
 static struct stack_record *
 depot_alloc_stack(unsigned long *entries, unsigned int nr_entries, u32 hash, depot_flags_t flags, void **prealloc)
+	__must_hold(&pool_lock)
 {
 	struct stack_record *stack = NULL;
 	size_t record_size;
@@ -486,6 +491,7 @@ depot_alloc_stack(unsigned long *entries, unsigned int nr_entries, u32 hash, dep
 }
 
 static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
+	__must_not_hold(&pool_lock)
 {
 	const int pools_num_cached = READ_ONCE(pools_num);
 	union handle_parts parts = { .handle = handle };
@@ -502,7 +508,8 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 		return NULL;
 	}
 
-	pool = stack_pools[pool_index];
+	/* @pool_index either valid, or user passed in corrupted value. */
+	pool = context_unsafe(stack_pools[pool_index]);
 	if (WARN_ON(!pool))
 		return NULL;
 
@@ -515,6 +522,7 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 
 /* Links stack into the freelist. */
 static void depot_free_stack(struct stack_record *stack)
+	__must_not_hold(&pool_lock)
 {
 	unsigned long flags;
 
-- 
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-32-elver%40google.com.
