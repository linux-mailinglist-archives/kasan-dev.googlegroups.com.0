Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCP2SO6QMGQEYQIRKPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 31459A2B069
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:18:51 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-542a77b4a4csf834886e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:18:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738865930; cv=pass;
        d=google.com; s=arc-20240605;
        b=JLqt6h5sWfNhVfB0ri+oQO8tUpq2ISaNEgRPy2JXEqehaqYSwbVuzA/j9Vq9Otz2be
         8sshQrtiCmD8PKdTzi2/AMshELKAyVn/BkI7xjnYtZtR/v2lCj6LFwJ8KQ2zsWk1f2kV
         tivMGpPSi+KkKh2WU1mQlmym/0v0XMjpQ9tVVpx3/4bUeiqv2cR9C5hqo1qgSCJqwwdx
         w3Cr8FH5LkjN7ZUJyIG4Sia9cN6kqZtD69m6ej1FQSk6S6cGOVCPWOZhArA4hxfzcngM
         5c1r1gKfQ6dxXZQc07U778/ILVE9MSoukkiNn2hmz964+Qkm7QPrTURvZ47iBqZJCt8i
         Ueng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=N8XGtB5ZcMyCZPotTOD0S4kD6zXAvYa/zbs5UwCcWkE=;
        fh=FS7iNjs7xWTUhmTFdO2fB+1DG0LSHVMdeC9OX/mKDyE=;
        b=Z6GGgCpmv/Dq9DXnxw5Ego3eqRF5bgR60Yn4YfEo4NtokJQNuwkRwFfTzg5kG2hOHq
         dKL/w7dv1Aibc0P4CddpuOIAUDNrNlkZSsSYHylO4eJKwmafQeJuYWVtspgOirshSvzT
         fAzIMH80jUGhmNUb/MaV12ijUcopYamTpapxakYqLPFrbpRsP50ZsQlPrLh0eODrMWgE
         6U8s+cO8Mt2uFzu132ymJXzJ+l2glt/ZXEcHgko5paIt7FuukPXAs02kEpMf4i96y8Ww
         7TH5ElE+mQobImyEjRt+6UHTaTmSsr09yFCKOLoUat7qYj1PNwEkkYCHhEi8MhgQehs2
         1MIg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=AotQ4IxX;
       spf=pass (google.com: domain of 3bv2kzwukcdc7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3Bv2kZwUKCdc7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738865930; x=1739470730; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=N8XGtB5ZcMyCZPotTOD0S4kD6zXAvYa/zbs5UwCcWkE=;
        b=KTOj1PqKUyFcuYZxt+SuNq8+Tq7F+DBN+OHD18ZNrayPDTekcnt4B67BqnUrK/8n5a
         qgrEe17qFiYT+qligWUCA2/XawH6bHnc+cE48ERPiCY0inr1uMcsgqASmgza1k/xo75R
         lLOYGwxRZpJNqoY5h2erRR57R9w5CGa1WeWK5BZwexC7ZyqnrNs4/z5Trp+UGj3LvbEJ
         VhuunwNqvk3QqC/PUpELSzPwwl4m9ttTeO0uxucIMyruRSWsPcoTav+z0lW5PjBmxZrx
         doEm2GC1/Mcsow6+QSCQIvAMxoEoDcrD8t3rx4ijZslBRMy1oJTXn4ttZ+d9Kmf6G9LN
         viOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738865930; x=1739470730;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=N8XGtB5ZcMyCZPotTOD0S4kD6zXAvYa/zbs5UwCcWkE=;
        b=ZSOW6T2cwocpQPB0rzqNwh1SdgIfvZqi2tBF4QTsCjqavFMPpgGK/sQd/5Ty2+8Y7f
         2bBCqjv4X9sMsk1GJNg/5a/7umBgE7wL5vdu0MCnjeAoDUyeZ88GGcIwrhGBGmSG/HM5
         WF3jD4ao0naP3eSj7pXJ0LQ3iSMjL9eARbFzLqlny5AGwlnNiZgfA6iMjtWWm0fFBYE5
         2Af8t4+vNfZGJaKgShTYNWxGH+kP+m+cDcwheZzJ1Wk9rhdtXbyreXzmyTEpt1p0wB6w
         0yd/TpERqQHY38zKqOyThKrVaIo+BaSAHVKvz3vNGpv8rez5hkVF8E25da+0e4DVOu+N
         sMUg==
X-Forwarded-Encrypted: i=2; AJvYcCUSOyQ5qF+HiL/r/eSjiXnh+F6pAu7WcSgKqPUx4HTseeVWygBXJ+N9LSg+8IdQHfAPYpI+qg==@lfdr.de
X-Gm-Message-State: AOJu0YzI8lAl3LWbFKOpjidoq+hISPGTYdjmLcWSBqILoyc7n8Nt/9zy
	icQ4E1T1Sk+oKwJNsQ6lu8oc0MVxP4uMivahV1B6TDZ6wXZtRJNN
X-Google-Smtp-Source: AGHT+IFJ3ffALyapMPrGzHHS3VNGrIrLhOtlD8eIr8DSQkuSrc6aEQbaj8hPs+MmMl8nbxfbC9d0YQ==
X-Received: by 2002:a05:6512:118e:b0:544:1093:ee3a with SMTP id 2adb3069b0e04-5441093ef00mr1166956e87.24.1738865930048;
        Thu, 06 Feb 2025 10:18:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5628:0:b0:540:1bb1:7828 with SMTP id 2adb3069b0e04-54413c748fbls43917e87.1.-pod-prod-07-eu;
 Thu, 06 Feb 2025 10:18:47 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWyCS2uAy8WhBCLqBjlJZJsDLiJuRL7Fj0nWLnROnKVzWB4nqNCdQMtA1ICtmuuhPfJLJI5o87CUc0=@googlegroups.com
X-Received: by 2002:a05:6512:2022:b0:544:1262:4c21 with SMTP id 2adb3069b0e04-5441262502bmr731199e87.12.1738865927259;
        Thu, 06 Feb 2025 10:18:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738865927; cv=none;
        d=google.com; s=arc-20240605;
        b=eyl+9HPTP8dvkq7PizDsdnPs67C9Lx0X3jcRTb9cp6RsFPnxKLk/+vP3ZC9zjL0muc
         GQVlVxGTqw6w8s6Zrk4z9VO934anRXFN8HIqlnzJIe544oEz29w4YxN8VCaQgw6h6SuU
         yDyqYuHEakdOoTzbQJokmDNgZ0E4iNH59n6tPFpZXNt5KaK6+YT9SQGMbF0WwkuNqEyb
         gjXyh3cnPZdP9F8GokNTwmPLWBse0gj/1CNsqWK4PKvmOkYnK7YjnG3o1K6ZXK0zvxDo
         /+GElZVZtIIDuLhyfgx1WlRnztepiiZIpoVkPGVDNlJQbLQ+YOY8c+M3oqiD1eo7n7rc
         1IZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=M3npqKmcD7idosYB3Rql5Qlei3J/L1gfZsrIz0sfHUY=;
        fh=2wzsGS1l53xupuesMDtUHd57e7qQfqMTGe3OoVT+Fuc=;
        b=FU73hqkWIGfiykC6c+wXoH+fb8/nxANP8UEFbXalKD79L0iuTGbj9CGUrleAb/MDo4
         MJLNf+yBzKSGFm6JcjmoeQujlIH4FjWNHimNVuYM80jJG8yDBHLcZCREcSEE0qyCjYS9
         0kt6DdDSSH5T+bEbALumpdlMLVQvlkBYWaCB/yLWMIMifaHOUN9rYGdUHw7jPDx3C2cB
         Fj5clZQKgcylu6dEn0WF3AQvOvWDAnh6Mge4M4Y04KwY3O+nzFyi2tKQkAP0BJVNzene
         MdvQmvyifU5rBbKCU1z5yHPIjNBuGjaTvPGGsxDdx9F8ZhyEfOcmyJ2+J70TzEcvL2fG
         YiNg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=AotQ4IxX;
       spf=pass (google.com: domain of 3bv2kzwukcdc7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3Bv2kZwUKCdc7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-544106267d1si67004e87.11.2025.02.06.10.18.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:18:47 -0800 (PST)
Received-SPF: pass (google.com: domain of 3bv2kzwukcdc7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-ab7044083e5so161439866b.2
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:18:47 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWR093w4qSQ9l3xMcIEgEs9iU+NfrHBNDSVq9GI+a2EtTAQ4zlsROqiroU3NpKA6j36GWwUU4NX3A8=@googlegroups.com
X-Received: from edben5.prod.google.com ([2002:a05:6402:5285:b0:5dc:c943:7c1])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:906:dc8d:b0:aac:622:8f6
 with SMTP id a640c23a62f3a-ab75e26558fmr633944866b.17.1738865926699; Thu, 06
 Feb 2025 10:18:46 -0800 (PST)
Date: Thu,  6 Feb 2025 19:10:18 +0100
In-Reply-To: <20250206181711.1902989-1-elver@google.com>
Mime-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.502.g6dc24dfdaf-goog
Message-ID: <20250206181711.1902989-25-elver@google.com>
Subject: [PATCH RFC 24/24] rhashtable: Enable capability analysis
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
 header.i=@google.com header.s=20230601 header.b=AotQ4IxX;       spf=pass
 (google.com: domain of 3bv2kzwukcdc7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3Bv2kZwUKCdc7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
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

Enable capability analysis for rhashtable, which was used as an initial
test as it contains a combination of RCU, mutex, and bit_spinlock usage.

Users of rhashtable now also benefit from annotations on the API, which
will now warn if the RCU read lock is not held where required.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/rhashtable.h | 14 +++++++++++---
 lib/Makefile               |  2 ++
 lib/rhashtable.c           | 12 +++++++++---
 3 files changed, 22 insertions(+), 6 deletions(-)

diff --git a/include/linux/rhashtable.h b/include/linux/rhashtable.h
index 8463a128e2f4..c6374691ccc7 100644
--- a/include/linux/rhashtable.h
+++ b/include/linux/rhashtable.h
@@ -245,16 +245,17 @@ void *rhashtable_insert_slow(struct rhashtable *ht, const void *key,
 void rhashtable_walk_enter(struct rhashtable *ht,
 			   struct rhashtable_iter *iter);
 void rhashtable_walk_exit(struct rhashtable_iter *iter);
-int rhashtable_walk_start_check(struct rhashtable_iter *iter) __acquires(RCU);
+int rhashtable_walk_start_check(struct rhashtable_iter *iter) __acquires_shared(RCU);
 
 static inline void rhashtable_walk_start(struct rhashtable_iter *iter)
+	__acquires_shared(RCU)
 {
 	(void)rhashtable_walk_start_check(iter);
 }
 
 void *rhashtable_walk_next(struct rhashtable_iter *iter);
 void *rhashtable_walk_peek(struct rhashtable_iter *iter);
-void rhashtable_walk_stop(struct rhashtable_iter *iter) __releases(RCU);
+void rhashtable_walk_stop(struct rhashtable_iter *iter) __releases_shared(RCU);
 
 void rhashtable_free_and_destroy(struct rhashtable *ht,
 				 void (*free_fn)(void *ptr, void *arg),
@@ -325,6 +326,7 @@ static inline struct rhash_lock_head __rcu **rht_bucket_insert(
 
 static inline unsigned long rht_lock(struct bucket_table *tbl,
 				     struct rhash_lock_head __rcu **bkt)
+	__acquires(__bitlock(0, bkt))
 {
 	unsigned long flags;
 
@@ -337,6 +339,7 @@ static inline unsigned long rht_lock(struct bucket_table *tbl,
 static inline unsigned long rht_lock_nested(struct bucket_table *tbl,
 					struct rhash_lock_head __rcu **bucket,
 					unsigned int subclass)
+	__acquires(__bitlock(0, bucket))
 {
 	unsigned long flags;
 
@@ -349,6 +352,7 @@ static inline unsigned long rht_lock_nested(struct bucket_table *tbl,
 static inline void rht_unlock(struct bucket_table *tbl,
 			      struct rhash_lock_head __rcu **bkt,
 			      unsigned long flags)
+	__releases(__bitlock(0, bkt))
 {
 	lock_map_release(&tbl->dep_map);
 	bit_spin_unlock(0, (unsigned long *)bkt);
@@ -402,13 +406,14 @@ static inline void rht_assign_unlock(struct bucket_table *tbl,
 				     struct rhash_lock_head __rcu **bkt,
 				     struct rhash_head *obj,
 				     unsigned long flags)
+	__releases(__bitlock(0, bkt))
 {
 	if (rht_is_a_nulls(obj))
 		obj = NULL;
 	lock_map_release(&tbl->dep_map);
 	rcu_assign_pointer(*bkt, (void *)obj);
 	preempt_enable();
-	__release(bitlock);
+	__release(__bitlock(0, bkt));
 	local_irq_restore(flags);
 }
 
@@ -589,6 +594,7 @@ static inline int rhashtable_compare(struct rhashtable_compare_arg *arg,
 static inline struct rhash_head *__rhashtable_lookup(
 	struct rhashtable *ht, const void *key,
 	const struct rhashtable_params params)
+	__must_hold_shared(RCU)
 {
 	struct rhashtable_compare_arg arg = {
 		.ht = ht,
@@ -642,6 +648,7 @@ static inline struct rhash_head *__rhashtable_lookup(
 static inline void *rhashtable_lookup(
 	struct rhashtable *ht, const void *key,
 	const struct rhashtable_params params)
+	__must_hold_shared(RCU)
 {
 	struct rhash_head *he = __rhashtable_lookup(ht, key, params);
 
@@ -692,6 +699,7 @@ static inline void *rhashtable_lookup_fast(
 static inline struct rhlist_head *rhltable_lookup(
 	struct rhltable *hlt, const void *key,
 	const struct rhashtable_params params)
+	__must_hold_shared(RCU)
 {
 	struct rhash_head *he = __rhashtable_lookup(&hlt->ht, key, params);
 
diff --git a/lib/Makefile b/lib/Makefile
index f40ba93c9a94..c7004270ad5f 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -45,6 +45,8 @@ lib-$(CONFIG_MIN_HEAP) += min_heap.o
 lib-y	+= kobject.o klist.o
 obj-y	+= lockref.o
 
+CAPABILITY_ANALYSIS_rhashtable.o := y
+
 obj-y += bcd.o sort.o parser.o debug_locks.o random32.o \
 	 bust_spinlocks.o kasprintf.o bitmap.o scatterlist.o \
 	 list_sort.o uuid.o iov_iter.o clz_ctz.o \
diff --git a/lib/rhashtable.c b/lib/rhashtable.c
index 3e555d012ed6..47a61e214621 100644
--- a/lib/rhashtable.c
+++ b/lib/rhashtable.c
@@ -11,6 +11,10 @@
  * pointer as suggested by Josh Triplett
  */
 
+#include <linux/rhashtable.h>
+
+disable_capability_analysis();
+
 #include <linux/atomic.h>
 #include <linux/kernel.h>
 #include <linux/init.h>
@@ -22,10 +26,11 @@
 #include <linux/mm.h>
 #include <linux/jhash.h>
 #include <linux/random.h>
-#include <linux/rhashtable.h>
 #include <linux/err.h>
 #include <linux/export.h>
 
+enable_capability_analysis();
+
 #define HASH_DEFAULT_SIZE	64UL
 #define HASH_MIN_SIZE		4U
 
@@ -358,6 +363,7 @@ static int rhashtable_rehash_table(struct rhashtable *ht)
 static int rhashtable_rehash_alloc(struct rhashtable *ht,
 				   struct bucket_table *old_tbl,
 				   unsigned int size)
+	__must_hold(&ht->mutex)
 {
 	struct bucket_table *new_tbl;
 	int err;
@@ -392,6 +398,7 @@ static int rhashtable_rehash_alloc(struct rhashtable *ht,
  * bucket locks or concurrent RCU protected lookups and traversals.
  */
 static int rhashtable_shrink(struct rhashtable *ht)
+	__must_hold(&ht->mutex)
 {
 	struct bucket_table *old_tbl = rht_dereference(ht->tbl, ht);
 	unsigned int nelems = atomic_read(&ht->nelems);
@@ -724,7 +731,7 @@ EXPORT_SYMBOL_GPL(rhashtable_walk_exit);
  * resize events and always continue.
  */
 int rhashtable_walk_start_check(struct rhashtable_iter *iter)
-	__acquires(RCU)
+	__acquires_shared(RCU)
 {
 	struct rhashtable *ht = iter->ht;
 	bool rhlist = ht->rhlist;
@@ -940,7 +947,6 @@ EXPORT_SYMBOL_GPL(rhashtable_walk_peek);
  * hash table.
  */
 void rhashtable_walk_stop(struct rhashtable_iter *iter)
-	__releases(RCU)
 {
 	struct rhashtable *ht;
 	struct bucket_table *tbl = iter->walker.tbl;
-- 
2.48.1.502.g6dc24dfdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250206181711.1902989-25-elver%40google.com.
