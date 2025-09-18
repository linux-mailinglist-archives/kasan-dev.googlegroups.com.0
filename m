Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6VDWDDAMGQEIVQ3ICY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 065F8B84FF7
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:06:52 +0200 (CEST)
Received: by mail-ej1-x638.google.com with SMTP id a640c23a62f3a-b04206e3d7esf292249166b.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:06:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204411; cv=pass;
        d=google.com; s=arc-20240605;
        b=gPlwR+wOBBpiyuhwJhkw3ctiiXjt3bz2czOKTgRnlJ9A8lYRyi5CS0Aiuz7v38SAeO
         xfVgCcMy/2xv/7TLj8sWEvTAQrB76dM02LDcNT8QMZnmHxKlrvrxE+H234PhtcLr13wm
         qMgybYz5Iy4j8TrtpsHMasc0Zm70LQidL+9MnxrDEFGDYX9Uo+C7mpEk5cN2ncwE8+p9
         QNLpbVUHZGgCh0ygrqbdYOkiCFibaUQTexcOS+kACXThXnGiIcyygTLauiMB9Tjij8rz
         ubZcfCSnHxEFiuIRSZNJ/LXvRLB6gFkvho1OnBamsNZ30MyuJFL362JQf3zqEozNrMsC
         gRyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=SuL96o7bJMpxpO+PodKctsnWR+mWIG2zumQ6CiSzer8=;
        fh=q0uhEjLFFzjzUoDY7VcNFkQw87+kkzpbybzSOXsf4Wo=;
        b=Abq/RIVQqZKtCr4Y4AlTIufkwBKUMrfa/POTINOs36nlDuVVwU22cugwPDYzFuF8Lc
         AWcGw11FlIY44Z/sG9hGZfjPAE4gBFuhFH62TfIfCg0UkxDocic3vxMy7Pg1PHuqLcZQ
         kzMKDyso7vj2VyyGj0Ib2XccEktphjevPEN8K3aIgTSg7KJKLhMD/+FSvykibbCq8lLz
         uqO/essLK5FMmwVizW2VslbTc1/8KKngHty0vU+AALM/VCOOM+SqBf+2rRC+OqZ3v7jt
         zXAq18PfPFzdgeWvZRnrVp0j9Fhjkni6DMO1hHB39wh44Xh96pJOp6bxUvYm45OedWg5
         3Rdw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="O/aVMrki";
       spf=pass (google.com: domain of 39xhmaaukczg6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=39xHMaAUKCZg6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204411; x=1758809211; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=SuL96o7bJMpxpO+PodKctsnWR+mWIG2zumQ6CiSzer8=;
        b=Hmhue6omQpHoXvXcC+VOJDo7HbWpvE3W+uhFspt2VHnLMsG92UH37YTY9GR6Xktccl
         J0yXrdBGTK9lEutEq3vExcLRs1lXmI7RFnYsiMzz4a65jdzOALOahjMmMYz4Rsw5fbQg
         13MHvPi6+uRd3eWDB/wPnhzA8EJHiN/ytPdeeZm7OIAxydL8lGACrmrEGrKBLgUlPm3F
         tguiEFQGo0WF0I6k1LaBCMNWaHWhgKC6utBoExLAn8d5hKZpX72aN8FAKxQR1lqJMNRz
         vgz1hE+Kt4uVvPLW04s+ui96m3RqsXeaDNEZvUKhVrrlMA3IgZ0qlYRKhqgOtYhYIB8S
         BdzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204411; x=1758809211;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SuL96o7bJMpxpO+PodKctsnWR+mWIG2zumQ6CiSzer8=;
        b=CBOO+Ejdl2o83rkFegF5tqj++E6fPMXs+EuV1ba5tdPjvk7AcdmJqx65sUdD4Grd99
         qHoqEDXUA2nmCxaj1+/X5f+Gzt5+6Gxy/btAP8UKz7UA95P9trhjcTQ4l9brGRGyfTcR
         OQFaklq1AzH9iTxyrrRJMKTIoZqbRpFuiiSoh5PJcp/N/lJDSCnocc575m/rSfnfXlPq
         +DDQXgU9MHMLpQPtO0L6ehvuNHe2jCoMO5bBnnyhXbmATfNmlZdrVNlOgO6iq0RYDMpM
         yoVT6BOHVPYr9NC8D7zNLWwsnqtGuGycXYRvdHSKycQ+XUjaZ4g7rxg+990BBa8KbwsT
         RieQ==
X-Forwarded-Encrypted: i=2; AJvYcCXRNVUQ3QFpaqFJYJUG9UtRZitcHERwsLOftJ5mIkdLME42LoZhDVz6s/eNsT2UVUBtOKYokw==@lfdr.de
X-Gm-Message-State: AOJu0YwVLFgVOx/p619Eh4GF4ZR35GQi/7egWmj6KW7V+znbmOvUrJhR
	jEZ02VI84JQPfq2SaZf/Rh6jh1uuyKqMrtFVLIb69I8xeBx9NgyWP6Nd
X-Google-Smtp-Source: AGHT+IF4TdQSNEwSnAsUV1AycI7HYPG/KCQs5KE2AtuOYHRcTPdWK7laYTREPVDMm3LdrPItvNT+3Q==
X-Received: by 2002:a05:6402:52d5:b0:62e:ebb4:e6e0 with SMTP id 4fb4d7f45d1cf-62fa2e5d420mr3466044a12.1.1758204411362;
        Thu, 18 Sep 2025 07:06:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5NrxWYG9fTEH6oX0yrrGVCzPg5Ow/zJQxSwScb7WD6oQ==
Received: by 2002:a05:6402:22a5:b0:61c:386c:2d51 with SMTP id
 4fb4d7f45d1cf-62fa754e081ls518801a12.0.-pod-prod-00-eu; Thu, 18 Sep 2025
 07:06:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCULVvs4Ub4RiWDTMkSkZOaM4r8/vZm4LdWfboBF7033ClnQgXwdyjPRmFFgGTDd8qrdEE6hRfMWx2Y=@googlegroups.com
X-Received: by 2002:a05:6402:528b:b0:62f:8bad:76e5 with SMTP id 4fb4d7f45d1cf-62fa215a480mr2702274a12.5.1758204408385;
        Thu, 18 Sep 2025 07:06:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204408; cv=none;
        d=google.com; s=arc-20240605;
        b=XAWKovtKoML1KJztfnwJ71WIvTVZJXBdA5rP0bhWI6jinW3Kuo7INhWhm5QAK0+51+
         J3UC1408+1hd02RSKD4KbX9D7Wnkhc0u7A7vQOEiqyEBZAHVqyNUKQNZeAjEHMVS/QHM
         WkOPSM8tIGW/2MiTbVB3tUnpOar/P4hekP1dOxSpaanvEMAn3mzPspgn3A4zdfJkTr9f
         pcjeVObXnGWz3qkSUuZuSls2ibj/ezQca+vkmsiX+p0jzXXFw+urXlEZljNrA7v4AB6U
         ptjftTO8/xwiezE5k3lCusiq8910MULj1x/HSumtjp3E7kcOCmLsJcgeGdp8Hyv0UQ9K
         VdSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=YhhK0C9j76pn7jOOIS0RXV1c5LB6TEMUuvpPm0VX42A=;
        fh=oFfMMEb/eYJKDFN1ZKRsS744b3zMg6FERf9wRYhPXe0=;
        b=AXwglKh6Yo7EvOCsB6NtZwqDm7IcXZxkOMD7qCNP/h0bwZ0IHQkj46ddjcsxbh57E1
         vAR3iCfu9QGGp0W06f94hCLsz200lu3Hs75mGFKMPm5+3aZn0XI6W04+HAQjJg7Nj1Mm
         LBVEc1R9TEA71kXXuuYiPs0WkLz2Ti+x19VTCMMRhe3bq53GJTBr3lwSvWfpXm3Kkx1b
         MZs2bs6MHsDn2sXbMeSDcYEG4SQLDD+pEDmmw3ro3bouWKp1+p7hQTv+UcrXmJbfUVgv
         nFtknDrK3kC/09G5/+xApcVjb5+veZeeEK3K04568hbauu703J/BxXY3ViTsVjCMwgfw
         O2Eg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="O/aVMrki";
       spf=pass (google.com: domain of 39xhmaaukczg6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=39xHMaAUKCZg6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-62fa5285903si35223a12.0.2025.09.18.07.06.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:06:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39xhmaaukczg6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-45b9a856d58so7211375e9.0
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:06:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXObneQSLOuvv71PLtsPMTJOODccH1wrqrM/2QNDssRqsp8iivXPuHtccNxHCGI+Iap0e6umFbImGE=@googlegroups.com
X-Received: from wmpl42.prod.google.com ([2002:a05:600c:8aa:b0:45d:e45e:96aa])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:444c:b0:45b:47e1:ef69
 with SMTP id 5b1f17b1804b1-46207897e75mr58816305e9.36.1758204407846; Thu, 18
 Sep 2025 07:06:47 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:41 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-31-elver@google.com>
Subject: [PATCH v3 30/35] stackdepot: Enable capability analysis
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
 header.i=@google.com header.s=20230601 header.b="O/aVMrki";       spf=pass
 (google.com: domain of 39xhmaaukczg6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=39xHMaAUKCZg6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
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
index e677cb5cc777..43b965046c2c 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -251,6 +251,7 @@ obj-$(CONFIG_POLYNOMIAL) += polynomial.o
 # Prevent the compiler from calling builtins like memcmp() or bcmp() from this
 # file.
 CFLAGS_stackdepot.o += -fno-builtin
+CAPABILITY_ANALYSIS_stackdepot.o := y
 obj-$(CONFIG_STACKDEPOT) += stackdepot.o
 KASAN_SANITIZE_stackdepot.o := n
 # In particular, instrumenting stackdepot.c with KMSAN will result in infinite
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index de0b0025af2b..43122294f128 100644
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
+	pool = capability_unsafe(stack_pools[pool_index]);
 	if (WARN_ON(!pool))
 		return NULL;
 
@@ -515,6 +522,7 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 
 /* Links stack into the freelist. */
 static void depot_free_stack(struct stack_record *stack)
+	__must_not_hold(&pool_lock)
 {
 	unsigned long flags;
 
-- 
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-31-elver%40google.com.
