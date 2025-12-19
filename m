Return-Path: <kasan-dev+bncBC7OBJGL2MHBBW7GSXFAMGQEDLHVEGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id D0666CD0977
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:46:36 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-64b45d9bb11sf1944230a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:46:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159196; cv=pass;
        d=google.com; s=arc-20240605;
        b=aEG1pMfVrkoJdAVHQerhaTXUu1i9BEAzukmp2zEj2k0rEoy6X5H64n1/sntOo6ajwd
         W0yiTW7Ba0vIOKgm6W19+v/MN1k9LxGAZdyh9EIhv3QdRnDGtXrhV9K2qTvQtQwWvAHt
         n3eG5Y5dJ8/9ZVK4h6xaGpQjjDuAxVAloO8apDM6zvShZnITdZrQwOQt9Z7stH856LQA
         rpIvCEnE/OImlQcXUl0RVpT/vR4snueUJc1pqM18gXdlUb+uQBl4dKHpDyk7YUHAreoz
         nIK+ZMicAOkZMFo7wKnqVVt85uPkJARLPRB0C5pQE9Nyl031567xt61kt28MUaNPoFBH
         WSMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ipuRmLZBL0Hv9nnzGLG+0R+sqejBWNwObPYgwU/6RHs=;
        fh=HuJUhXviZEaj8m4wLXZrFM3N6QxUENXTyBOYsjljMcg=;
        b=ZJzltsP/EYl9HhOhAbb/5tUjBwwnxFevt9lv6qR8GA9dsYQ7o1i6qoDWbjhudI5wOM
         nDfHJYIMeL6IvQ9RvLsynVpQ/2CSOBGy3lKUQoiZ0g8I68biyyc6NaUaZlCmJZlAXqcN
         fLIL1D6N6LDkMwOE54g4/bTT5apyxk+956YKuVQ3Ab7HK4yMRdHmQqfPydDbIxgezab3
         HOwCT5wH0cCu2hzmfcL3wxxF3bpzDeDfWauwYq0DTX8ZDf8YdkMY5YgVGcta6yqj11Vg
         2phO7AyVRSPKRERNQ0h4C0UWNOOagKLoW3w2QxNA1rX9ZH+LyTfQRCDVVPE24DWphbEp
         XEZQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MCRIDgrb;
       spf=pass (google.com: domain of 3whnfaqukcaujqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3WHNFaQUKCaUJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159196; x=1766763996; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ipuRmLZBL0Hv9nnzGLG+0R+sqejBWNwObPYgwU/6RHs=;
        b=jF6oTkafKTPsflCHZizc7UuF1E/6lLplU3UpRQFpDcSXEKUw4LOh9/VANE4tODje4x
         ykd8/xGSt3z2K0w/u4dFDVnYt8SBeF+Rm4kJXAFRVBsVAQ0dNb2Ysnd5icOQTA8iX4Fl
         ux3gvZcnjyB9tJEVbCQz/kWc4U4rRGW33T4pXl5A+xpEqP8Nzyp2wCM/ADoACvh+woXe
         uWrfh+qERPDi8asjeg+I3hm9NIaqCirZIpmSr6S8qRo9mTzpfiXXfTDnxCvTblhTU21Z
         GScG3kUGXuBL7hTKl+0vBxIxgaE/gL/EZlDqhggbYY0L7hK5EeEtTOLWpP7gZGhBNW+e
         zNWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159196; x=1766763996;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ipuRmLZBL0Hv9nnzGLG+0R+sqejBWNwObPYgwU/6RHs=;
        b=ClrQChDfqPpOSxZsDjHvN/4fNfCpKXUTgcJgfSJRyfx4MD4AdS8+R7+WDrmIMlaNUI
         ArOj6M9AC2KbcuLYDQWeQ8jnZgM3Ym4zJ2bh4jKvu9VvbLupxqTRHgBnZWe2agASioaX
         conO8pqs432VfkzVX4vKpc6s2S+KoORn0WE6FKhsI1UCjbYcCXYHh+ZilZaoMGKIckbO
         u08DeWT1UFcGbAg46w94Sy8IeemOll8fAK2QQC+ViaCEDuY85OB7plwoB3t7Jt4aUd+M
         TWO0rs6O1H2ax9dwTpYqrEWTcx/z2tKSbidF6LrjB+pHfq4dsxJLwROgmDfbRGphruj9
         lpDA==
X-Forwarded-Encrypted: i=2; AJvYcCWASkZSg5h2L3l1TAutf69zEh/LMVlDH50yVoBqZsUH4PqJoyswxNMf7I/rYI071CirDgTbfg==@lfdr.de
X-Gm-Message-State: AOJu0YxXQ7mBQ3a+/zQpOHdRaksLatnGnTqvEiqYEPs/SRdGCNfZ+hMM
	1EYS+gP8PaPtRmpSFa8tva84W+2eNkM8uTy+KZD4EnpucUO4lki0A7MK
X-Google-Smtp-Source: AGHT+IFSg+cI/6UYVXs3QD+ZzHXLibxJ0aATfsYr215bz/+DgvXwOfOQDpzou9EWv92tqZ535YSx6A==
X-Received: by 2002:a05:6402:1449:b0:640:ebe3:dd55 with SMTP id 4fb4d7f45d1cf-64b8e9454bemr3033597a12.6.1766159196055;
        Fri, 19 Dec 2025 07:46:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZ5rXXOqUr/L4G7aRN8mGJsQAPPSXnhbKJBC83BQRAEqg=="
Received: by 2002:aa7:d418:0:b0:64b:a8b0:ba67 with SMTP id 4fb4d7f45d1cf-64ba8b0bab2ls579663a12.0.-pod-prod-07-eu;
 Fri, 19 Dec 2025 07:46:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWFylSec14D4xt812yE52SoQoqKii/7vl2Rvq4V1FglEZBUbp20ld191LMqupPRqaALBoXTTPva/tc=@googlegroups.com
X-Received: by 2002:a17:907:2da5:b0:b77:2269:8de6 with SMTP id a640c23a62f3a-b8036f86bb4mr314242666b.19.1766159193479;
        Fri, 19 Dec 2025 07:46:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159193; cv=none;
        d=google.com; s=arc-20240605;
        b=MfAQGFnYT9yIUJJkN+PxM+dm8A/7s7Ixzvxil+eulamPzR3NpE69TotR/ZYEfQAn9m
         p9p/2EW15YK5gfQSxPo60zQLlA83blqcZV5OBZYzBfBHYATija27WerVubDMF5Egr3kj
         MSg7Qbfu85AFeb8rUrGEFc7KWl5UCpYq4HnTlNyzkS5W9nOlDHGLevuuYktvY48HoxPa
         WEmb1K6FNVa53SAn0MOEzZRdJpShCH9Li70NRMGdPXBcLak//J8Ed/X0cP1+L62mLBRJ
         WhlvppB7VqbjmGsQYXCSVSmkh8F1p94+xzNEcOn7W4GxH1VO9uofRxXNEFpJHk44q7rf
         PeKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=91/M6Wc5goo40nrJkJ1ulkL+/DliPVncC/51mYdmaQ4=;
        fh=E1AM+y1LBPsTtnxpTDU70CiEMg3D6Rfe2EaLcMi4YQ8=;
        b=XdbKTdgJQQtuKQGksduNxZY9AQnommOoij6/Lfa6quy5r25avDaiRRJComs0iWqGTZ
         pdzgJECIh3aoyvgfaQFNkrwck46jnzsFrzTITc0trc1smhUGAnQ/Hg1Umps5A03Pf1I0
         GhlUPAIMY9AYkjEyxI6QOhBYKbRzjCzA6Ycp5wk/CwOyZpSIULcfP/f2NjFKNiDs2e3C
         FWCXrs2hr386s3rZQfenRr5/+CiKF5lXTw9kxr2e30B5g8EKoOSqxObbM3foTLXekkjY
         94aEl/PydM4lDHXOFY+0Sfdiba9apTum3P01J03FUKfcWwiOjCtvtbyMXoozGFqelbOR
         LRZw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MCRIDgrb;
       spf=pass (google.com: domain of 3whnfaqukcaujqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3WHNFaQUKCaUJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-64b9158a9f2si61692a12.7.2025.12.19.07.46.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:46:33 -0800 (PST)
Received-SPF: pass (google.com: domain of 3whnfaqukcaujqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-47799717212so18621765e9.3
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:46:33 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXbzDUXlmUAa6ASkCL3mR38v05hm9w/XN1/qfYVfxytD7ga+QrXasdAUx5bOe3iFVjLgXwSwWBnN2c=@googlegroups.com
X-Received: from wmxb4-n2.prod.google.com ([2002:a05:600d:8444:20b0:477:5a4b:d57f])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:1c28:b0:45d:dc85:c009
 with SMTP id 5b1f17b1804b1-47d1954586amr32388785e9.10.1766159192865; Fri, 19
 Dec 2025 07:46:32 -0800 (PST)
Date: Fri, 19 Dec 2025 16:40:06 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-18-elver@google.com>
Subject: [PATCH v5 17/36] locking/rwsem: Support Clang's context analysis
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
 header.i=@google.com header.s=20230601 header.b=MCRIDgrb;       spf=pass
 (google.com: domain of 3whnfaqukcaujqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3WHNFaQUKCaUJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
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

Add support for Clang's context analysis for rw_semaphore.

Signed-off-by: Marco Elver <elver@google.com>
---
v5:
* Rename "context guard" -> "context lock".
* Use new cleanup.h helpers to properly support scoped lock guards.

v4:
* Rename capability -> context analysis.

v3:
* Switch to DECLARE_LOCK_GUARD_1_ATTRS() (suggested by Peter)
* __assert -> __assume rename
---
 Documentation/dev-tools/context-analysis.rst |  2 +-
 include/linux/rwsem.h                        | 76 +++++++++++++-------
 lib/test_context-analysis.c                  | 64 +++++++++++++++++
 3 files changed, 114 insertions(+), 28 deletions(-)

diff --git a/Documentation/dev-tools/context-analysis.rst b/Documentation/dev-tools/context-analysis.rst
index f7736f1c0767..7b660c3003a0 100644
--- a/Documentation/dev-tools/context-analysis.rst
+++ b/Documentation/dev-tools/context-analysis.rst
@@ -80,7 +80,7 @@ Supported Kernel Primitives
 
 Currently the following synchronization primitives are supported:
 `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
-`bit_spinlock`, RCU, SRCU (`srcu_struct`).
+`bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`.
 
 For context locks with an initialization function (e.g., `spin_lock_init()`),
 calling this function before initializing any guarded members or globals
diff --git a/include/linux/rwsem.h b/include/linux/rwsem.h
index f1aaf676a874..8da14a08a4e1 100644
--- a/include/linux/rwsem.h
+++ b/include/linux/rwsem.h
@@ -45,7 +45,7 @@
  * reduce the chance that they will share the same cacheline causing
  * cacheline bouncing problem.
  */
-struct rw_semaphore {
+context_lock_struct(rw_semaphore) {
 	atomic_long_t count;
 	/*
 	 * Write owner or one of the read owners as well flags regarding
@@ -76,11 +76,13 @@ static inline int rwsem_is_locked(struct rw_semaphore *sem)
 }
 
 static inline void rwsem_assert_held_nolockdep(const struct rw_semaphore *sem)
+	__assumes_ctx_lock(sem)
 {
 	WARN_ON(atomic_long_read(&sem->count) == RWSEM_UNLOCKED_VALUE);
 }
 
 static inline void rwsem_assert_held_write_nolockdep(const struct rw_semaphore *sem)
+	__assumes_ctx_lock(sem)
 {
 	WARN_ON(!(atomic_long_read(&sem->count) & RWSEM_WRITER_LOCKED));
 }
@@ -119,6 +121,7 @@ do {								\
 	static struct lock_class_key __key;			\
 								\
 	__init_rwsem((sem), #sem, &__key);			\
+	__assume_ctx_lock(sem);					\
 } while (0)
 
 /*
@@ -148,7 +151,7 @@ extern bool is_rwsem_reader_owned(struct rw_semaphore *sem);
 
 #include <linux/rwbase_rt.h>
 
-struct rw_semaphore {
+context_lock_struct(rw_semaphore) {
 	struct rwbase_rt	rwbase;
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 	struct lockdep_map	dep_map;
@@ -172,6 +175,7 @@ do {								\
 	static struct lock_class_key __key;			\
 								\
 	__init_rwsem((sem), #sem, &__key);			\
+	__assume_ctx_lock(sem);					\
 } while (0)
 
 static __always_inline int rwsem_is_locked(const struct rw_semaphore *sem)
@@ -180,11 +184,13 @@ static __always_inline int rwsem_is_locked(const struct rw_semaphore *sem)
 }
 
 static __always_inline void rwsem_assert_held_nolockdep(const struct rw_semaphore *sem)
+	__assumes_ctx_lock(sem)
 {
 	WARN_ON(!rwsem_is_locked(sem));
 }
 
 static __always_inline void rwsem_assert_held_write_nolockdep(const struct rw_semaphore *sem)
+	__assumes_ctx_lock(sem)
 {
 	WARN_ON(!rw_base_is_write_locked(&sem->rwbase));
 }
@@ -202,6 +208,7 @@ static __always_inline int rwsem_is_contended(struct rw_semaphore *sem)
  */
 
 static inline void rwsem_assert_held(const struct rw_semaphore *sem)
+	__assumes_ctx_lock(sem)
 {
 	if (IS_ENABLED(CONFIG_LOCKDEP))
 		lockdep_assert_held(sem);
@@ -210,6 +217,7 @@ static inline void rwsem_assert_held(const struct rw_semaphore *sem)
 }
 
 static inline void rwsem_assert_held_write(const struct rw_semaphore *sem)
+	__assumes_ctx_lock(sem)
 {
 	if (IS_ENABLED(CONFIG_LOCKDEP))
 		lockdep_assert_held_write(sem);
@@ -220,48 +228,62 @@ static inline void rwsem_assert_held_write(const struct rw_semaphore *sem)
 /*
  * lock for reading
  */
-extern void down_read(struct rw_semaphore *sem);
-extern int __must_check down_read_interruptible(struct rw_semaphore *sem);
-extern int __must_check down_read_killable(struct rw_semaphore *sem);
+extern void down_read(struct rw_semaphore *sem) __acquires_shared(sem);
+extern int __must_check down_read_interruptible(struct rw_semaphore *sem) __cond_acquires_shared(0, sem);
+extern int __must_check down_read_killable(struct rw_semaphore *sem) __cond_acquires_shared(0, sem);
 
 /*
  * trylock for reading -- returns 1 if successful, 0 if contention
  */
-extern int down_read_trylock(struct rw_semaphore *sem);
+extern int down_read_trylock(struct rw_semaphore *sem) __cond_acquires_shared(true, sem);
 
 /*
  * lock for writing
  */
-extern void down_write(struct rw_semaphore *sem);
-extern int __must_check down_write_killable(struct rw_semaphore *sem);
+extern void down_write(struct rw_semaphore *sem) __acquires(sem);
+extern int __must_check down_write_killable(struct rw_semaphore *sem) __cond_acquires(0, sem);
 
 /*
  * trylock for writing -- returns 1 if successful, 0 if contention
  */
-extern int down_write_trylock(struct rw_semaphore *sem);
+extern int down_write_trylock(struct rw_semaphore *sem) __cond_acquires(true, sem);
 
 /*
  * release a read lock
  */
-extern void up_read(struct rw_semaphore *sem);
+extern void up_read(struct rw_semaphore *sem) __releases_shared(sem);
 
 /*
  * release a write lock
  */
-extern void up_write(struct rw_semaphore *sem);
-
-DEFINE_GUARD(rwsem_read, struct rw_semaphore *, down_read(_T), up_read(_T))
-DEFINE_GUARD_COND(rwsem_read, _try, down_read_trylock(_T))
-DEFINE_GUARD_COND(rwsem_read, _intr, down_read_interruptible(_T), _RET == 0)
-
-DEFINE_GUARD(rwsem_write, struct rw_semaphore *, down_write(_T), up_write(_T))
-DEFINE_GUARD_COND(rwsem_write, _try, down_write_trylock(_T))
-DEFINE_GUARD_COND(rwsem_write, _kill, down_write_killable(_T), _RET == 0)
+extern void up_write(struct rw_semaphore *sem) __releases(sem);
+
+DEFINE_LOCK_GUARD_1(rwsem_read, struct rw_semaphore, down_read(_T->lock), up_read(_T->lock))
+DEFINE_LOCK_GUARD_1_COND(rwsem_read, _try, down_read_trylock(_T->lock))
+DEFINE_LOCK_GUARD_1_COND(rwsem_read, _intr, down_read_interruptible(_T->lock), _RET == 0)
+
+DECLARE_LOCK_GUARD_1_ATTRS(rwsem_read, __acquires_shared(_T), __releases_shared(*(struct rw_semaphore **)_T))
+#define class_rwsem_read_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(rwsem_read, _T)
+DECLARE_LOCK_GUARD_1_ATTRS(rwsem_read_try, __acquires_shared(_T), __releases_shared(*(struct rw_semaphore **)_T))
+#define class_rwsem_read_try_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(rwsem_read_try, _T)
+DECLARE_LOCK_GUARD_1_ATTRS(rwsem_read_intr, __acquires_shared(_T), __releases_shared(*(struct rw_semaphore **)_T))
+#define class_rwsem_read_intr_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(rwsem_read_intr, _T)
+
+DEFINE_LOCK_GUARD_1(rwsem_write, struct rw_semaphore, down_write(_T->lock), up_write(_T->lock))
+DEFINE_LOCK_GUARD_1_COND(rwsem_write, _try, down_write_trylock(_T->lock))
+DEFINE_LOCK_GUARD_1_COND(rwsem_write, _kill, down_write_killable(_T->lock), _RET == 0)
+
+DECLARE_LOCK_GUARD_1_ATTRS(rwsem_write, __acquires(_T), __releases(*(struct rw_semaphore **)_T))
+#define class_rwsem_write_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(rwsem_write, _T)
+DECLARE_LOCK_GUARD_1_ATTRS(rwsem_write_try, __acquires(_T), __releases(*(struct rw_semaphore **)_T))
+#define class_rwsem_write_try_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(rwsem_write_try, _T)
+DECLARE_LOCK_GUARD_1_ATTRS(rwsem_write_kill, __acquires(_T), __releases(*(struct rw_semaphore **)_T))
+#define class_rwsem_write_kill_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(rwsem_write_kill, _T)
 
 /*
  * downgrade write lock to read lock
  */
-extern void downgrade_write(struct rw_semaphore *sem);
+extern void downgrade_write(struct rw_semaphore *sem) __releases(sem) __acquires_shared(sem);
 
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 /*
@@ -277,11 +299,11 @@ extern void downgrade_write(struct rw_semaphore *sem);
  * lockdep_set_class() at lock initialization time.
  * See Documentation/locking/lockdep-design.rst for more details.)
  */
-extern void down_read_nested(struct rw_semaphore *sem, int subclass);
-extern int __must_check down_read_killable_nested(struct rw_semaphore *sem, int subclass);
-extern void down_write_nested(struct rw_semaphore *sem, int subclass);
-extern int down_write_killable_nested(struct rw_semaphore *sem, int subclass);
-extern void _down_write_nest_lock(struct rw_semaphore *sem, struct lockdep_map *nest_lock);
+extern void down_read_nested(struct rw_semaphore *sem, int subclass) __acquires_shared(sem);
+extern int __must_check down_read_killable_nested(struct rw_semaphore *sem, int subclass) __cond_acquires_shared(0, sem);
+extern void down_write_nested(struct rw_semaphore *sem, int subclass) __acquires(sem);
+extern int down_write_killable_nested(struct rw_semaphore *sem, int subclass) __cond_acquires(0, sem);
+extern void _down_write_nest_lock(struct rw_semaphore *sem, struct lockdep_map *nest_lock) __acquires(sem);
 
 # define down_write_nest_lock(sem, nest_lock)			\
 do {								\
@@ -295,8 +317,8 @@ do {								\
  * [ This API should be avoided as much as possible - the
  *   proper abstraction for this case is completions. ]
  */
-extern void down_read_non_owner(struct rw_semaphore *sem);
-extern void up_read_non_owner(struct rw_semaphore *sem);
+extern void down_read_non_owner(struct rw_semaphore *sem) __acquires_shared(sem);
+extern void up_read_non_owner(struct rw_semaphore *sem) __releases_shared(sem);
 #else
 # define down_read_nested(sem, subclass)		down_read(sem)
 # define down_read_killable_nested(sem, subclass)	down_read_killable(sem)
diff --git a/lib/test_context-analysis.c b/lib/test_context-analysis.c
index 39e03790c0f6..1c96c56cf873 100644
--- a/lib/test_context-analysis.c
+++ b/lib/test_context-analysis.c
@@ -8,6 +8,7 @@
 #include <linux/build_bug.h>
 #include <linux/mutex.h>
 #include <linux/rcupdate.h>
+#include <linux/rwsem.h>
 #include <linux/seqlock.h>
 #include <linux/spinlock.h>
 #include <linux/srcu.h>
@@ -262,6 +263,69 @@ static void __used test_seqlock_scoped(struct test_seqlock_data *d)
 	}
 }
 
+struct test_rwsem_data {
+	struct rw_semaphore sem;
+	int counter __guarded_by(&sem);
+};
+
+static void __used test_rwsem_init(struct test_rwsem_data *d)
+{
+	init_rwsem(&d->sem);
+	d->counter = 0;
+}
+
+static void __used test_rwsem_reader(struct test_rwsem_data *d)
+{
+	down_read(&d->sem);
+	(void)d->counter;
+	up_read(&d->sem);
+
+	if (down_read_trylock(&d->sem)) {
+		(void)d->counter;
+		up_read(&d->sem);
+	}
+}
+
+static void __used test_rwsem_writer(struct test_rwsem_data *d)
+{
+	down_write(&d->sem);
+	d->counter++;
+	up_write(&d->sem);
+
+	down_write(&d->sem);
+	d->counter++;
+	downgrade_write(&d->sem);
+	(void)d->counter;
+	up_read(&d->sem);
+
+	if (down_write_trylock(&d->sem)) {
+		d->counter++;
+		up_write(&d->sem);
+	}
+}
+
+static void __used test_rwsem_assert(struct test_rwsem_data *d)
+{
+	rwsem_assert_held_nolockdep(&d->sem);
+	d->counter++;
+}
+
+static void __used test_rwsem_guard(struct test_rwsem_data *d)
+{
+	{ guard(rwsem_read)(&d->sem); (void)d->counter; }
+	{ guard(rwsem_write)(&d->sem); d->counter++; }
+}
+
+static void __used test_rwsem_cond_guard(struct test_rwsem_data *d)
+{
+	scoped_cond_guard(rwsem_read_try, return, &d->sem) {
+		(void)d->counter;
+	}
+	scoped_cond_guard(rwsem_write_try, return, &d->sem) {
+		d->counter++;
+	}
+}
+
 struct test_bit_spinlock_data {
 	unsigned long bits;
 	int counter __guarded_by(__bitlock(3, &bits));
-- 
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-18-elver%40google.com.
