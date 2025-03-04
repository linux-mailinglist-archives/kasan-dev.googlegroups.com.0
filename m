Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQ4OTO7AMGQE3MTM6CQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id CEBADA4D824
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:26:29 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-390f729efacsf1223990f8f.0
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:26:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080389; cv=pass;
        d=google.com; s=arc-20240605;
        b=MbjsZrDfGYo/hHNnKGRhNzb2zukKm1doGAtzNfN2lxoibJ1dXGRdaFaZjJQo6cTByQ
         MT6w3wCvZkyGo0vvM9xM6uAqGfL8CSQAWed1P/aRCYv3NgA+dLgnyWR/DBYbuMwR2C7d
         JvcYloDZpWiZEPJMivW+dgv50xkfSv/bhEbFy80kmiW3dipc7aFivVixLSt64AwS/D8I
         29G8eOUL/gJyfLuf3KUvx+GIKAXeA/yQFC8sH6BoTQD4cMYncL19aWJ73eMlbD5Vq71D
         X3HUpihntvXXsbUp1I7Rtoud4Rdn9M725jPQVdyFTppMLLMcO4+H+PFvLY3eiZoXwsrs
         TRTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=nfpplB3A6KEO6oOzRT4rwb0v6dshx1G2PoNEReqUm/U=;
        fh=OXdndPSoYD16fQfg9v83yTvIDyWdu3HU9/GNCLOpmTo=;
        b=ISeu20VI8mV2KpF4WLYW6RgahYaVCeWMRhyuACh9LfXVvll4mQEHSGWiBeBf5WjRfW
         OsZUUpggRN5YETqk8xO9q7uKVAWZRPGpn/3HL4IegTOCQJo7u8/NCawH3XOjT0MFHTED
         PfGaQJ1HY1/gP6Ap28gVL7GDuiWPeuCzQnbccJZuwbBAWXJHrHvJ7OlTGvmU8l3wVz4j
         TnBbGmIGzg2RQUkesaL1o2exaUGy8X0+mrZX6qDJU27Eo+NFHux5gw723+Cg7/b6Jtwr
         cpf4q8fqVVlFxjsIYOhn04mzMGxcTmTWw6FV26U0z0J0mEprF+lm8/TTgI1S3w+mbtkR
         sCYA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Rts2iYuI;
       spf=pass (google.com: domain of 3qcfgzwukctaqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3QcfGZwUKCTAQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080389; x=1741685189; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=nfpplB3A6KEO6oOzRT4rwb0v6dshx1G2PoNEReqUm/U=;
        b=GwuATPris83Geq6v4lTZjcZ+65awPf7KSmx8Thy0wAZFSqK0mCdkwigkmg0DKyv2C3
         b83C7aWkI+zb6wWMXcjtXhhiR5JiTPvaZyvnhlhGwd6ATDv5eesJYR4gOoSYU0p9jxsr
         ycC8TefLEE1b1pfh9kyAVddRplSUqSdenQ/BDOayFmPORhNjMwNxBywR8uE+t4qszFvz
         /U0j7Xf3lFSUBwplIFsoBGCiyMwUPVSTuy1nXpA7Q4SlhoWiOudvSYKW+C0cpjeJTLnB
         neFdnDGqKkSUZkw2YpJFuJOvve7N6o2QFugzJ3lIshELBiYa9VM3Kle6YpRf6XH+O823
         Zwzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080389; x=1741685189;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nfpplB3A6KEO6oOzRT4rwb0v6dshx1G2PoNEReqUm/U=;
        b=aw2UgfodhNBykwp3u94iQ4R9VLK06j3asmI5sU3TsfXVUNhjc1ZXm0v32ODKXNsMT7
         gzx6rF8n815Wwn+G5gwIFPya1B40MBhwrc3FZ2fMAA2MpJCbAw4nZlvmwgDXNrsWavLz
         RVOTQ9/wIYY2wd2ZA0C7WlojwW91X3B58ZvnvaOtEhHHhHkCWOQy3wbYgsZwapH7wtwj
         essjd5GJXdauUoHXmJfUZigVgtpiqYKTzmk0Vx/mVJISVxAka3vOr1WM6eO40KwZh76i
         vYX5DJ9HqsQItbCjf/yi43SWHZIMepAq8kDPHrK4lOqqaRLiBLi0nb6RhdQwEYxpR7Jd
         BBrw==
X-Forwarded-Encrypted: i=2; AJvYcCXWvXPXZ8iu3Gkci6m3PRxppfotvVZxChV6tYwLs7FV8wb00WBnomKVJZKGE26JmWyrsWVHeQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywjkd1Dn1qLsNbU8PnhkjZHCd3nlphjfcAbu94s2yDYSZ7+D91e
	Tg2iWD5JbqfR6h8q4H2jxsgIpy324lyARWQOjDyzye+8DoUzd3g+
X-Google-Smtp-Source: AGHT+IFE4CPy74Jl+6gNOsvSCFD3rCrHfH4NQjRA9A7soRMejyG4UJN4oFC8LK17wXeb4/5j1k5TdA==
X-Received: by 2002:a05:6000:178b:b0:38d:d7a4:d447 with SMTP id ffacd0b85a97d-390eca34fafmr13817305f8f.34.1741080387965;
        Tue, 04 Mar 2025 01:26:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFmzTV8OKZsbIfxA5uLpXjO2YAi9C7b+QhR5/ypcXZPJw==
Received: by 2002:a05:600c:28e:b0:439:9891:79df with SMTP id
 5b1f17b1804b1-43aed4c8fe6ls23591775e9.0.-pod-prod-06-eu; Tue, 04 Mar 2025
 01:26:25 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUtPodFl6LbI/iL8xRFroZgco3R2aQXvs7q/nfo2g9OzFQ3plEEcBNq3sjxwSLP5zNA0kgSnow7mOE=@googlegroups.com
X-Received: by 2002:a05:600c:4f14:b0:43b:c034:57b1 with SMTP id 5b1f17b1804b1-43bc0345ceamr52275835e9.20.1741080385357;
        Tue, 04 Mar 2025 01:26:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080385; cv=none;
        d=google.com; s=arc-20240605;
        b=gkRMNV9cfchyLToJ4HBospTQL1oq7ILpCSECory+IQbrpLLi5gg/B6oBWRBZaBaoAr
         TngoViL2OyCoBO6JG8ZR9G/zgKxFSfShle8YYq4RKTu5yBU5aK5FGwEYyhvFb7vCX7h+
         mJn68b0ERyF0E7VV4mCSLhdJoFzEKfQtZ0emVHM0pjTACDYWdjw1ciAKisqyggXCyhcb
         pAqFJtaWkucUOAtncYZK3dcHuMzkxiLDgOVKxmG5F3a6kkOhfPdW0E5RRn6jjlJ+GJsW
         /y41PEyX4ar8hnCt7zPzbYucgl5BFgkU2uJiVEl8B4HkGdu6jg2ubvfYL/ED5rMtAR+1
         /fTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=OCbQJguuxExNh/1WWVSwShtOCrr3VVCLOHRvUq00gbI=;
        fh=zA6hL8B0QbEWEOF8OjUdMnhcYzDbm9CtLN3cj+7yoVE=;
        b=UtgFvS+17pdMy1sfxNX60XnNwFq1QiAnj22+7S31L3W4DN7Dxdq+gvI8318HUkZhCU
         ADVuFAmIjAAqNL6xDvjGPARi8K678kxswPl2qQFGI4gWz/K3lhJm1JcllrobgEvnDhmL
         Qzjw6nuAm2SZD6jVUdTXVYobW64t15b5MqzrMyU3fmppr3SgC6N4hjnXoKLsey/Mmps+
         k7GyP0oKr8rI4G0KDqC6bYBLiSIQqtpgXlRfEOESDpKhDWjiUaNmwyILot2T7pECKIrT
         i0n8sEAClMe3UfxKBsjYWgMTzmrRlZR/t9ra1SbJksfrlmVamksydYQ81QrE47dRq6+n
         ksFA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Rts2iYuI;
       spf=pass (google.com: domain of 3qcfgzwukctaqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3QcfGZwUKCTAQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43bcc139b49si809095e9.1.2025.03.04.01.26.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:26:25 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qcfgzwukctaqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id a640c23a62f3a-ac1e442740cso150119566b.1
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:26:25 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXQOdivjFo5ag56zXEOomR04jBlfS4EqcI+QcfohhNZGOa3ZKmT+UFOtR5auU8AMn5w4TLu69aCngI=@googlegroups.com
X-Received: from ejcwb15.prod.google.com ([2002:a17:907:d50f:b0:abf:740d:69f5])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:1b26:b0:abb:c647:a4bf
 with SMTP id a640c23a62f3a-abf25faa163mr1968124666b.23.1741080385011; Tue, 04
 Mar 2025 01:26:25 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:27 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-29-elver@google.com>
Subject: [PATCH v2 28/34] stackdepot: Enable capability analysis
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
 header.i=@google.com header.s=20230601 header.b=Rts2iYuI;       spf=pass
 (google.com: domain of 3qcfgzwukctaqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3QcfGZwUKCTAQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
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

Enable capability analysis for stackdepot.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Remove disable/enable_capability_analysis() around headers.
---
 lib/Makefile     |  1 +
 lib/stackdepot.c | 20 ++++++++++++++------
 2 files changed, 15 insertions(+), 6 deletions(-)

diff --git a/lib/Makefile b/lib/Makefile
index 1dbb59175eb0..f40ba93c9a94 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -270,6 +270,7 @@ obj-$(CONFIG_POLYNOMIAL) += polynomial.o
 # Prevent the compiler from calling builtins like memcmp() or bcmp() from this
 # file.
 CFLAGS_stackdepot.o += -fno-builtin
+CAPABILITY_ANALYSIS_stackdepot.o := y
 obj-$(CONFIG_STACKDEPOT) += stackdepot.o
 KASAN_SANITIZE_stackdepot.o := n
 # In particular, instrumenting stackdepot.c with KMSAN will result in infinite
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 245d5b416699..a8b6a49c9058 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -61,18 +61,18 @@ static unsigned int stack_bucket_number_order;
 /* Hash mask for indexing the table. */
 static unsigned int stack_hash_mask;
 
+/* The lock must be held when performing pool or freelist modifications. */
+static DEFINE_RAW_SPINLOCK(pool_lock);
 /* Array of memory regions that store stack records. */
-static void *stack_pools[DEPOT_MAX_POOLS];
+static void *stack_pools[DEPOT_MAX_POOLS] __guarded_by(&pool_lock);
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
@@ -242,6 +242,7 @@ EXPORT_SYMBOL_GPL(stack_depot_init);
  * Initializes new stack pool, and updates the list of pools.
  */
 static bool depot_init_pool(void **prealloc)
+	__must_hold(&pool_lock)
 {
 	lockdep_assert_held(&pool_lock);
 
@@ -289,6 +290,7 @@ static bool depot_init_pool(void **prealloc)
 
 /* Keeps the preallocated memory to be used for a new stack depot pool. */
 static void depot_keep_new_pool(void **prealloc)
+	__must_hold(&pool_lock)
 {
 	lockdep_assert_held(&pool_lock);
 
@@ -308,6 +310,7 @@ static void depot_keep_new_pool(void **prealloc)
  * the current pre-allocation.
  */
 static struct stack_record *depot_pop_free_pool(void **prealloc, size_t size)
+	__must_hold(&pool_lock)
 {
 	struct stack_record *stack;
 	void *current_pool;
@@ -342,6 +345,7 @@ static struct stack_record *depot_pop_free_pool(void **prealloc, size_t size)
 
 /* Try to find next free usable entry from the freelist. */
 static struct stack_record *depot_pop_free(void)
+	__must_hold(&pool_lock)
 {
 	struct stack_record *stack;
 
@@ -379,6 +383,7 @@ static inline size_t depot_stack_record_size(struct stack_record *s, unsigned in
 /* Allocates a new stack in a stack depot pool. */
 static struct stack_record *
 depot_alloc_stack(unsigned long *entries, unsigned int nr_entries, u32 hash, depot_flags_t flags, void **prealloc)
+	__must_hold(&pool_lock)
 {
 	struct stack_record *stack = NULL;
 	size_t record_size;
@@ -437,6 +442,7 @@ depot_alloc_stack(unsigned long *entries, unsigned int nr_entries, u32 hash, dep
 }
 
 static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
+	__must_not_hold(&pool_lock)
 {
 	const int pools_num_cached = READ_ONCE(pools_num);
 	union handle_parts parts = { .handle = handle };
@@ -453,7 +459,8 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 		return NULL;
 	}
 
-	pool = stack_pools[pool_index];
+	/* @pool_index either valid, or user passed in corrupted value. */
+	pool = capability_unsafe(stack_pools[pool_index]);
 	if (WARN_ON(!pool))
 		return NULL;
 
@@ -466,6 +473,7 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 
 /* Links stack into the freelist. */
 static void depot_free_stack(struct stack_record *stack)
+	__must_not_hold(&pool_lock)
 {
 	unsigned long flags;
 
-- 
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-29-elver%40google.com.
