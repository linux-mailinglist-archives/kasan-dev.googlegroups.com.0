Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBX2SO6QMGQEDK6K7JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 00BE4A2B067
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:18:48 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-5dc6714f3e8sf1736428a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:18:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738865928; cv=pass;
        d=google.com; s=arc-20240605;
        b=KNfnsflrpC38u09c/mZgrhbQyxhyb40odMk1B/YVLA6IdLm/LXjTecPPK26xmQZ/hN
         Gm9hmjns4SN3jQHlstPFM9TNeOTu0NriAxmHv65s9grv+T9y+vouiJoFXDASaSa15sSq
         hWoF6g090vvyqDuFh6sc4JeRmSVg/XsNFf2IzGJl+YL3QwYN/h4wPoubmh0dSCJIvpzL
         1x52Xm7puj+T32rTacDrya/iv2eCjXiQHFHJ7k/vhSq53lCQbqsaxpne/rLzEBuMb9m5
         wU6Wz7VMHQ8b4SBoB45dEOUlai9zeh8kawFXovfLNkT9D3wojgRNv2+LHn61NTtlwfSJ
         vaAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=D/sTkLlppmea16/L03gZ6uN277kJ0wuCymc01f//5n8=;
        fh=BjA0kw2havMjw/C1HjAvjAs/4P3543qHd6wduylQlxA=;
        b=Q66bO/tCGLhwTOml7eLJM6a2WDAky8XqZlNAuE/nLkQhFSh7Sgc2PI+7KCLxr7LrGK
         G6czI4OhSCKq4LQV6TAWAB8gccLw8qphaYz9t7pcQXTMzn8Bj0lSgqgYi+UEYlG1DLPN
         LzMAojrf6JaevitA2crqV6Xu2Kv8NGjMEbqNPZbb3E7H8dJ2fbaz3EY0EzR9DSYDMX5y
         izbkGiAZNH97obxBN08hZ7/U219W3iZtuKhBZGf565V5EAVqwYIobfsoUFSNtLL6CkkA
         yK82T/q/Ngn2iQDj9S+YtQx6FoTWt/kmN/PqeiNjjivY6ww0OlgFKKwbv+F6UO4yesSd
         /Prw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XtjRtYJh;
       spf=pass (google.com: domain of 3bp2kzwukcdu5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3BP2kZwUKCdU5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738865928; x=1739470728; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=D/sTkLlppmea16/L03gZ6uN277kJ0wuCymc01f//5n8=;
        b=EOTxeRvjfEo3EriAXVWJ/ItmwTGYAinEBt9s4Vg90LD4hZaOMPRWzOjJTeTIIZKdWC
         +LEPLSAymPIJQ/Fqh0ntP6KMGBnfJNnFLN/6bnZlpyfDAA73cP6dIDN9H3C6x6k3OJ8Q
         52rBFkqfBFLx8+urdT9Xq1KDbn0R4X4EfEQLy6OjXC9Oqpg49XkizukqtsXzoIZ/OvxU
         seasI35lNyvruOyIQP1OGULnuVRACp6+SZ/8MOfpSElYPkVdLuCnOBRPX1sHTnM6VyVI
         zTtllNngcwLY33ggFIRYvqM/L3Q5jxouThYnZYNNFpZ/S/7ugjuPh4dMzmZ+/NC6cH4s
         DK5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738865928; x=1739470728;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=D/sTkLlppmea16/L03gZ6uN277kJ0wuCymc01f//5n8=;
        b=ofUWZGjBzy+Y8DZeyv+SPTsQqojcooJ1YnT2hXiRip4dFliYSkNFTp9lnFy76ZxqCZ
         Pg8k2+AUCT1HqdynAbAeaNFleAZhSXKwzDsKHs4/FuLkFosBwPwNmb+1IHoUcy7mOO65
         eIvCg3vO0Q+2kbJHrkhshu2mw2pBuBprTOfk9VRdmce9JtL76RRbcuuRbatSBTNNMFQG
         FNOt8yg3exFc2jdt6ctpJSPWBJpvF1IVfob3WDTZAzMSP9nlpJ11ceMKHXYe/siD5rjl
         oJwuSyDUqd0V+dV5OUl8iQxUlCnxeakE0SInM3fASlLF1voshabyd0RrZ2zaSa5mAcey
         VeMw==
X-Forwarded-Encrypted: i=2; AJvYcCWlMMwBVVshDzh979hQG9o3krbs/DCRGor6lpl6RdFXUX/V7Kms1M2i3n75DN/O3RGUPWC9FQ==@lfdr.de
X-Gm-Message-State: AOJu0YyUP2kQWb49czoyVUIIY+Jffwr82O+0CwZMg/lcadDPBSGv4KOF
	f4FaNeuhQHOhZ0uB2bdEzwLrC2uBJrdH/I2E0bk2+z21hyFPzLfS
X-Google-Smtp-Source: AGHT+IGlQWOJc2CW8JX/9CHMfQ3Ty+UfIj6fnhJjuWvz2e8sd0it3v7uoo3V0PfQZoNbCtXSNu+kPw==
X-Received: by 2002:a05:6402:35cb:b0:5dc:7b59:445b with SMTP id 4fb4d7f45d1cf-5de4509abfbmr430587a12.28.1738865927137;
        Thu, 06 Feb 2025 10:18:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:ca4b:0:b0:5dc:8ead:6a00 with SMTP id 4fb4d7f45d1cf-5de45eb67e8ls20489a12.2.-pod-prod-06-eu;
 Thu, 06 Feb 2025 10:18:44 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUR/J8YSzxKNnd+pNv5faSDmSb9Kqo0gdOIVemuSLaEQ7AVi7TuA764VVCmGgsABBQmSr9vmmkrZW0=@googlegroups.com
X-Received: by 2002:a05:6402:e8a:b0:5dc:a44f:6ec4 with SMTP id 4fb4d7f45d1cf-5de45018934mr541300a12.13.1738865924559;
        Thu, 06 Feb 2025 10:18:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738865924; cv=none;
        d=google.com; s=arc-20240605;
        b=TPC57zVJHp1ju6R7dXNv7lGBc4U/Fn/HQmXNxGeIQqI8TLIKLqNXQLbh+r2y7PPHB7
         NwBAxF2zb3aeT15X60biUzDW6UbPor7COoXLrsQOUuNVz0kqr+dS+nOuTLVRXZqg4pYZ
         NbuRZ9Jw2nKl32A5/5yU2ZPrILn6cHQnRfep7ijBFo8K+hIT7OCCRR21m5U3SQK6v1ow
         sWnqjetbBNHqm86CnsTCOSN0ju5AtmauYhPOJdtkEM1xzFxNqEOhpLkqJRhMZ15LnVuV
         YCBQNliD+9HqZkJ8f/CLtqulsKHZNxV+3YREPlr/0hw8RH3RLB7rfrt94OauW13jf75B
         ngFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=cTAbjs+ZIolkWTfm9mQklQQ/rgalTGxg3MlfIrb1brs=;
        fh=ga0w2th1Xf2uQtDFKOd6O2ZWp524Xhcg6kmyEIlA6ug=;
        b=H7HKrxYINk8+AoZBTtZtvyBpCAqrJOjcxtlFYqyUgoeRNyZBOMZrnTOLtAC93dLbUx
         jHUKc6MjIQVrU6fj6eha+hQPuGs1bH/DyiI2PA/rReJzlVzRCmHh2WtfVZuTBkTIsw8q
         EUvOGEAm+7f/JqD7PCXGExzE7y0EBRSaPburg12zWiw8ea4GB4A7HmxZLx/9RtOTyaNW
         T1IwuSh/RkyUL+sUgdUGHmMNxMp+iuD+fbxLavoE2g7Tfi4j6TImAZHVmrsqjdKPIA1j
         Zhrwm5iIEiOlekZKh34jZrEFWqRWi1/RIi4vByBISswIdHyN06nuajTja92ouoBPHaTL
         ElrA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XtjRtYJh;
       spf=pass (google.com: domain of 3bp2kzwukcdu5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3BP2kZwUKCdU5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5dcf9f6fb76si42031a12.5.2025.02.06.10.18.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:18:44 -0800 (PST)
Received-SPF: pass (google.com: domain of 3bp2kzwukcdu5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-ab77dd2c243so101701966b.0
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:18:44 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVhyRKa4SNba0ImjKOMLeHeP4emnqZXYINe4RVwLlPgR78+maz4iTliLWtx0+LAortTFYnNd2YymrU=@googlegroups.com
X-Received: from edbfj20.prod.google.com ([2002:a05:6402:2b94:b0:5dc:4848:561d])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:9724:b0:aae:869f:c4ad
 with SMTP id a640c23a62f3a-ab75e212f41mr882204166b.7.1738865924120; Thu, 06
 Feb 2025 10:18:44 -0800 (PST)
Date: Thu,  6 Feb 2025 19:10:17 +0100
In-Reply-To: <20250206181711.1902989-1-elver@google.com>
Mime-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.502.g6dc24dfdaf-goog
Message-ID: <20250206181711.1902989-24-elver@google.com>
Subject: [PATCH RFC 23/24] stackdepot: Enable capability analysis
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
 header.i=@google.com header.s=20230601 header.b=XtjRtYJh;       spf=pass
 (google.com: domain of 3bp2kzwukcdu5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3BP2kZwUKCdU5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
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
 lib/Makefile     |  1 +
 lib/stackdepot.c | 24 ++++++++++++++++++------
 2 files changed, 19 insertions(+), 6 deletions(-)

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
index 245d5b416699..6664146d1f31 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -14,6 +14,8 @@
 
 #define pr_fmt(fmt) "stackdepot: " fmt
 
+disable_capability_analysis();
+
 #include <linux/debugfs.h>
 #include <linux/gfp.h>
 #include <linux/jhash.h>
@@ -36,6 +38,8 @@
 #include <linux/memblock.h>
 #include <linux/kasan-enabled.h>
 
+enable_capability_analysis();
+
 #define DEPOT_POOLS_CAP 8192
 /* The pool_index is offset by 1 so the first record does not have a 0 handle. */
 #define DEPOT_MAX_POOLS \
@@ -61,18 +65,18 @@ static unsigned int stack_bucket_number_order;
 /* Hash mask for indexing the table. */
 static unsigned int stack_hash_mask;
 
+/* The lock must be held when performing pool or freelist modifications. */
+static DEFINE_RAW_SPINLOCK(pool_lock);
 /* Array of memory regions that store stack records. */
-static void *stack_pools[DEPOT_MAX_POOLS];
+static void *stack_pools[DEPOT_MAX_POOLS] __var_guarded_by(&pool_lock);
 /* Newly allocated pool that is not yet added to stack_pools. */
 static void *new_pool;
 /* Number of pools in stack_pools. */
 static int pools_num;
 /* Offset to the unused space in the currently used pool. */
-static size_t pool_offset = DEPOT_POOL_SIZE;
+static size_t pool_offset __var_guarded_by(&pool_lock) = DEPOT_POOL_SIZE;
 /* Freelist of stack records within stack_pools. */
-static LIST_HEAD(free_stacks);
-/* The lock must be held when performing pool or freelist modifications. */
-static DEFINE_RAW_SPINLOCK(pool_lock);
+static __var_guarded_by(&pool_lock) LIST_HEAD(free_stacks);
 
 /* Statistics counters for debugfs. */
 enum depot_counter_id {
@@ -242,6 +246,7 @@ EXPORT_SYMBOL_GPL(stack_depot_init);
  * Initializes new stack pool, and updates the list of pools.
  */
 static bool depot_init_pool(void **prealloc)
+	__must_hold(&pool_lock)
 {
 	lockdep_assert_held(&pool_lock);
 
@@ -289,6 +294,7 @@ static bool depot_init_pool(void **prealloc)
 
 /* Keeps the preallocated memory to be used for a new stack depot pool. */
 static void depot_keep_new_pool(void **prealloc)
+	__must_hold(&pool_lock)
 {
 	lockdep_assert_held(&pool_lock);
 
@@ -308,6 +314,7 @@ static void depot_keep_new_pool(void **prealloc)
  * the current pre-allocation.
  */
 static struct stack_record *depot_pop_free_pool(void **prealloc, size_t size)
+	__must_hold(&pool_lock)
 {
 	struct stack_record *stack;
 	void *current_pool;
@@ -342,6 +349,7 @@ static struct stack_record *depot_pop_free_pool(void **prealloc, size_t size)
 
 /* Try to find next free usable entry from the freelist. */
 static struct stack_record *depot_pop_free(void)
+	__must_hold(&pool_lock)
 {
 	struct stack_record *stack;
 
@@ -379,6 +387,7 @@ static inline size_t depot_stack_record_size(struct stack_record *s, unsigned in
 /* Allocates a new stack in a stack depot pool. */
 static struct stack_record *
 depot_alloc_stack(unsigned long *entries, unsigned int nr_entries, u32 hash, depot_flags_t flags, void **prealloc)
+	__must_hold(&pool_lock)
 {
 	struct stack_record *stack = NULL;
 	size_t record_size;
@@ -437,6 +446,7 @@ depot_alloc_stack(unsigned long *entries, unsigned int nr_entries, u32 hash, dep
 }
 
 static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
+	__must_not_hold(&pool_lock)
 {
 	const int pools_num_cached = READ_ONCE(pools_num);
 	union handle_parts parts = { .handle = handle };
@@ -453,7 +463,8 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 		return NULL;
 	}
 
-	pool = stack_pools[pool_index];
+	/* @pool_index either valid, or user passed in corrupted value. */
+	pool = capability_unsafe(stack_pools[pool_index]);
 	if (WARN_ON(!pool))
 		return NULL;
 
@@ -466,6 +477,7 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 
 /* Links stack into the freelist. */
 static void depot_free_stack(struct stack_record *stack)
+	__must_not_hold(&pool_lock)
 {
 	unsigned long flags;
 
-- 
2.48.1.502.g6dc24dfdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250206181711.1902989-24-elver%40google.com.
