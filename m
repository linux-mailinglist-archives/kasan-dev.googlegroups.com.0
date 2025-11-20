Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVG77TEAMGQEXHXFU2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 70AB8C74C27
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:12:22 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-5943838a6d1sf861673e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:12:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763651542; cv=pass;
        d=google.com; s=arc-20240605;
        b=gFxJxGlCJHNIWXqXQS/s8ddxnwEvvJilovwYsCtMjVv+EwqObMVtVtd/F6hITF4eCp
         +J/5gqhdLWpCuDkDQlGW+n24xi2WeMdvtw0a1czIrpbmFBBDOI6gYOva0CvTJDJFZu2e
         NiVeKlGZAOe4mlheGNZKHzyo9Zdu5yx1Cr8EPYFShWrHyZBVbu3hX1+pVAT54x5ueEjX
         R5AF/i2MQ99dXMjWrb6ox6N8eVmODr30Sd8/OqaMi/Gxk56bVSmGg2DS/grEDJ6BJS41
         HQ5AtIy4dd0ffA75CCmTSZVP/L+GI2Qy7Hz00/o3UyHRnl5OPX0XzKZYV0FYblTNX6wj
         ny6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=fg6HanMrADK01o6cxzc39rOKf7X7WujDGqMWp5oTtoA=;
        fh=0SToYG5oUoWo0ruw96Atb5ZbY0m7eTXeODmHu6gZGvA=;
        b=UloFJFk3nKeTStAchA/rQz4UkgMP0T1I2AmOBEefjGomvzu8lVsnTSnbVuvKS9sWDL
         srFjKa7dx3qJZpn0vF0hDTxPj32xchxq0B6XRjWsEYaCDZycxFVdwcAsQuut3HX5i0u8
         dlBx07lBhL6tgLH+McgQtHTH3iJA7tmODpozTLR/F1mucCagH5WrTNNM6QKeQNY4CfpW
         rfHfRhFn00B+WB6nTDWO1oI3uALjR0VOzgdO9w5Is+m47o8rn6FIbDygCnIrwyH3e8Hv
         +XP9m6Pkh5hj6AJIf6Zq9Ln6gTHZjUBTuiIwqsHSwFSu/zZlYyUcUSnPTbxL3h6bPL76
         apMw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="R/oZIGjb";
       spf=pass (google.com: domain of 30s8faqukcfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=30S8faQUKCfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763651542; x=1764256342; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=fg6HanMrADK01o6cxzc39rOKf7X7WujDGqMWp5oTtoA=;
        b=t/Y4uLSGlCTVKYDeCrciEDrfvQxN4un988rPNCqUobHXpkW/dZMsc5gfr/n+sZfuF2
         5hjwgD9E+lVYdzdcUzn1dkSQ483f2hjamoCNixYyKQQcLePkqzvPuiBsHoUrOzliSgx7
         xHoDBXHfwVSzmHWIR7AgT9tE+qE1nfYb7A1UxDkLTBAIiR+4i1yNRPpf3bjfhu/AMQlk
         6wYbC8nDGGnoDryevopjVqG0uR+XzhDgQzuINwhNi23yJigDKNjYhP01hqQVxU4q2SdC
         TJC8qMFJVZ35CZEygl7pxfja+8gMYNKRkd1kUvolTeKjEoaUZB87+MdjNZrUDLLuYWZV
         DL3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763651542; x=1764256342;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fg6HanMrADK01o6cxzc39rOKf7X7WujDGqMWp5oTtoA=;
        b=Rlp7dPE1BOCnNjSGZ2R0l4l+96t1TILFF6TkoyLKvece4euwEmxo7NKF+5u12SCGOV
         5JD4YVIcDKj2u9cOxyxeHQYMwll2pJ3twxEZqKvUFr8FiDkcKMLeTZwtMTrXMWJq8h+a
         aXVvNTlheGd3PutRHTuH3jealSFtwbgSapW30DDH1xFuy3s5qKDcTrU7EONsynBuGSoF
         ubYgzCtwihLwKBN42sUq9sJMQTjLi2GMvYf5cFc7fEoM6z5cZ1ayj2qJ+slsONISo5Kb
         2OKp6pLEMwstHVbxzd974jLjnISiwiv8w1nq4ye5Agl2MbKdLDPgmSUDCfaG2U3Ai4ck
         yzmQ==
X-Forwarded-Encrypted: i=2; AJvYcCVxao4mpsb/++QEk+/ulUFlwAKg9wgRPyDCrqLfn2sQcAwkP3JPOtMiu4s/CKm8vTqhbT4V0w==@lfdr.de
X-Gm-Message-State: AOJu0YyR3kypIid6kR1AyBlZBT6ANi4Mg4GUjgk+qMjodODDC8rm+h+j
	DV3LDEPpG4581XnLtqaETObQnWmnQ2qPVoVIxvuBUcRwuq2V+uPnSpCa
X-Google-Smtp-Source: AGHT+IEvvXr9So0f8m9O2XhVGzJwCu69JOLKDNo1SGW9K1uFNnrmWRC1UvCuPFOYILTXHpuRV/2hrA==
X-Received: by 2002:a05:6512:3e15:b0:594:4d7b:9030 with SMTP id 2adb3069b0e04-5969e30d102mr1124554e87.35.1763651541586;
        Thu, 20 Nov 2025 07:12:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+b2WBYpoo9S5r9CUJ6VLsJahaX93U5TfsCe7hrZ8R2uTg=="
Received: by 2002:ac2:5688:0:b0:595:9914:b7e9 with SMTP id 2adb3069b0e04-5969dc049dbls333112e87.0.-pod-prod-05-eu;
 Thu, 20 Nov 2025 07:12:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUZxhIST7TfPaE3sk58CxUqod4h+Oc3PnT2DVfF9/aPZotdCtYHDkmNBTiSqTOz4R5wDA4sFvtWHM4=@googlegroups.com
X-Received: by 2002:a05:6512:3d08:b0:594:25e6:8a3a with SMTP id 2adb3069b0e04-5969e2e74d7mr1243679e87.20.1763651538423;
        Thu, 20 Nov 2025 07:12:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763651538; cv=none;
        d=google.com; s=arc-20240605;
        b=S9D0qLlKIztDg5wV89uBHhunlQucTVLnHNP1uxP2S5uve9j5uLcX78OHztcfMKn1dO
         venTbOgOixg+w3VCFgCos9h5GyDpFUG+jGa3xfAWkpsDo8+sM1IECHzGdDI9rd4iSMk0
         n2M0SggBZvZhp7GPWzHBo36PTJ4dJd0JWjHnQFUp1VFmw5PyNdD7zo2wHEQVJykqGBM7
         RA5b+xus8D1TtRC+tlYrXKRiLAzSxp9JTBR4ZCwj3CN0J4M71JEz39nv7FlkrArcAs52
         UUAQWsQFzfodHweym+BE2r/rGZpiyplKpqAdzG9X/vVhgz94frOqK1P0yYj72AiVL7CR
         Lu9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=hosCU2YAM4wmLhG6gCEf4XqbMRgXsIjIUxIgZVPv95A=;
        fh=Wz3rUix0Fa/bEvA4KJYiEzYr/8AOBUbB0zOJgwbcSK0=;
        b=Ni8A1QGWc7j8xz3jdlPgRCI48I5ZQO0GsDH4tUOw1bQDeDzp08+y34qYyntGXkc27y
         NK1HKGVCLmpefE5/y0GtNjz3gBiYY000QT1/c8+GnFEZZxWbWRM4Ogz5pFZiDhLgKt2P
         wsZXVCxtSTHjvUZ/ygmeYLNX/I8u7N5MbX6Btgrp1FnZcqXJjKqE8WRPQTu1SUVAQqGz
         MILyhmb33sASJwNnbRZjEM83wtrJu1fQBIjDqLBRt9bdyyv0pmGd9X6YODRRAu6HsKe3
         1XRsWOT1o0pZ73LGL5lfuUjvduznWWXKL5DCFDKAcmcKwjzU8TyJUL+uRNWEmO7Mai4E
         ox8Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="R/oZIGjb";
       spf=pass (google.com: domain of 30s8faqukcfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=30S8faQUKCfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5969dba0852si45591e87.4.2025.11.20.07.12.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:12:18 -0800 (PST)
Received-SPF: pass (google.com: domain of 30s8faqukcfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-429c95fdba8so504544f8f.0
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:12:18 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW0KynUGi6zQK8SXQUsyMFLMToFGIxsnItFdgdGCpFKhUSds7Q828h/RBLxD+Q0ugd/F3wGFwOVu4U=@googlegroups.com
X-Received: from wraj7.prod.google.com ([2002:a5d:4527:0:b0:42b:2aa2:e459])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:2505:b0:42b:3ed2:c08b
 with SMTP id ffacd0b85a97d-42cbb2b1a6emr2638286f8f.51.1763651537400; Thu, 20
 Nov 2025 07:12:17 -0800 (PST)
Date: Thu, 20 Nov 2025 16:09:36 +0100
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120151033.3840508-12-elver@google.com>
Subject: [PATCH v4 11/35] locking/seqlock: Support Clang's context analysis
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
 header.i=@google.com header.s=20230601 header.b="R/oZIGjb";       spf=pass
 (google.com: domain of 30s8faqukcfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=30S8faQUKCfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
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

Add support for Clang's context analysis for seqlock_t.

Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* __assert -> __assume rename
---
 Documentation/dev-tools/context-analysis.rst |  2 +-
 include/linux/seqlock.h                      | 24 +++++++++++
 include/linux/seqlock_types.h                |  5 ++-
 lib/test_context-analysis.c                  | 43 ++++++++++++++++++++
 4 files changed, 71 insertions(+), 3 deletions(-)

diff --git a/Documentation/dev-tools/context-analysis.rst b/Documentation/dev-tools/context-analysis.rst
index 1f5d7c758219..598962f6cb40 100644
--- a/Documentation/dev-tools/context-analysis.rst
+++ b/Documentation/dev-tools/context-analysis.rst
@@ -80,7 +80,7 @@ Supported Kernel Primitives
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~
 
 Currently the following synchronization primitives are supported:
-`raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`.
+`raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`.
 
 For context guards with an initialization function (e.g., `spin_lock_init()`),
 calling this function before initializing any guarded members or globals
diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
index 5ce48eab7a2a..c79210d369ef 100644
--- a/include/linux/seqlock.h
+++ b/include/linux/seqlock.h
@@ -816,6 +816,7 @@ static __always_inline void write_seqcount_latch_end(seqcount_latch_t *s)
 	do {								\
 		spin_lock_init(&(sl)->lock);				\
 		seqcount_spinlock_init(&(sl)->seqcount, &(sl)->lock);	\
+		__assume_ctx_guard(sl);					\
 	} while (0)
 
 /**
@@ -832,6 +833,7 @@ static __always_inline void write_seqcount_latch_end(seqcount_latch_t *s)
  * Return: count, to be passed to read_seqretry()
  */
 static inline unsigned read_seqbegin(const seqlock_t *sl)
+	__acquires_shared(sl) __no_context_analysis
 {
 	return read_seqcount_begin(&sl->seqcount);
 }
@@ -848,6 +850,7 @@ static inline unsigned read_seqbegin(const seqlock_t *sl)
  * Return: true if a read section retry is required, else false
  */
 static inline unsigned read_seqretry(const seqlock_t *sl, unsigned start)
+	__releases_shared(sl) __no_context_analysis
 {
 	return read_seqcount_retry(&sl->seqcount, start);
 }
@@ -872,6 +875,7 @@ static inline unsigned read_seqretry(const seqlock_t *sl, unsigned start)
  * _irqsave or _bh variants of this function instead.
  */
 static inline void write_seqlock(seqlock_t *sl)
+	__acquires(sl) __no_context_analysis
 {
 	spin_lock(&sl->lock);
 	do_write_seqcount_begin(&sl->seqcount.seqcount);
@@ -885,6 +889,7 @@ static inline void write_seqlock(seqlock_t *sl)
  * critical section of given seqlock_t.
  */
 static inline void write_sequnlock(seqlock_t *sl)
+	__releases(sl) __no_context_analysis
 {
 	do_write_seqcount_end(&sl->seqcount.seqcount);
 	spin_unlock(&sl->lock);
@@ -898,6 +903,7 @@ static inline void write_sequnlock(seqlock_t *sl)
  * other write side sections, can be invoked from softirq contexts.
  */
 static inline void write_seqlock_bh(seqlock_t *sl)
+	__acquires(sl) __no_context_analysis
 {
 	spin_lock_bh(&sl->lock);
 	do_write_seqcount_begin(&sl->seqcount.seqcount);
@@ -912,6 +918,7 @@ static inline void write_seqlock_bh(seqlock_t *sl)
  * write_seqlock_bh().
  */
 static inline void write_sequnlock_bh(seqlock_t *sl)
+	__releases(sl) __no_context_analysis
 {
 	do_write_seqcount_end(&sl->seqcount.seqcount);
 	spin_unlock_bh(&sl->lock);
@@ -925,6 +932,7 @@ static inline void write_sequnlock_bh(seqlock_t *sl)
  * other write sections, can be invoked from hardirq contexts.
  */
 static inline void write_seqlock_irq(seqlock_t *sl)
+	__acquires(sl) __no_context_analysis
 {
 	spin_lock_irq(&sl->lock);
 	do_write_seqcount_begin(&sl->seqcount.seqcount);
@@ -938,12 +946,14 @@ static inline void write_seqlock_irq(seqlock_t *sl)
  * seqlock_t write side section opened with write_seqlock_irq().
  */
 static inline void write_sequnlock_irq(seqlock_t *sl)
+	__releases(sl) __no_context_analysis
 {
 	do_write_seqcount_end(&sl->seqcount.seqcount);
 	spin_unlock_irq(&sl->lock);
 }
 
 static inline unsigned long __write_seqlock_irqsave(seqlock_t *sl)
+	__acquires(sl) __no_context_analysis
 {
 	unsigned long flags;
 
@@ -976,6 +986,7 @@ static inline unsigned long __write_seqlock_irqsave(seqlock_t *sl)
  */
 static inline void
 write_sequnlock_irqrestore(seqlock_t *sl, unsigned long flags)
+	__releases(sl) __no_context_analysis
 {
 	do_write_seqcount_end(&sl->seqcount.seqcount);
 	spin_unlock_irqrestore(&sl->lock, flags);
@@ -998,6 +1009,7 @@ write_sequnlock_irqrestore(seqlock_t *sl, unsigned long flags)
  * The opened read section must be closed with read_sequnlock_excl().
  */
 static inline void read_seqlock_excl(seqlock_t *sl)
+	__acquires_shared(sl) __no_context_analysis
 {
 	spin_lock(&sl->lock);
 }
@@ -1007,6 +1019,7 @@ static inline void read_seqlock_excl(seqlock_t *sl)
  * @sl: Pointer to seqlock_t
  */
 static inline void read_sequnlock_excl(seqlock_t *sl)
+	__releases_shared(sl) __no_context_analysis
 {
 	spin_unlock(&sl->lock);
 }
@@ -1021,6 +1034,7 @@ static inline void read_sequnlock_excl(seqlock_t *sl)
  * from softirq contexts.
  */
 static inline void read_seqlock_excl_bh(seqlock_t *sl)
+	__acquires_shared(sl) __no_context_analysis
 {
 	spin_lock_bh(&sl->lock);
 }
@@ -1031,6 +1045,7 @@ static inline void read_seqlock_excl_bh(seqlock_t *sl)
  * @sl: Pointer to seqlock_t
  */
 static inline void read_sequnlock_excl_bh(seqlock_t *sl)
+	__releases_shared(sl) __no_context_analysis
 {
 	spin_unlock_bh(&sl->lock);
 }
@@ -1045,6 +1060,7 @@ static inline void read_sequnlock_excl_bh(seqlock_t *sl)
  * hardirq context.
  */
 static inline void read_seqlock_excl_irq(seqlock_t *sl)
+	__acquires_shared(sl) __no_context_analysis
 {
 	spin_lock_irq(&sl->lock);
 }
@@ -1055,11 +1071,13 @@ static inline void read_seqlock_excl_irq(seqlock_t *sl)
  * @sl: Pointer to seqlock_t
  */
 static inline void read_sequnlock_excl_irq(seqlock_t *sl)
+	__releases_shared(sl) __no_context_analysis
 {
 	spin_unlock_irq(&sl->lock);
 }
 
 static inline unsigned long __read_seqlock_excl_irqsave(seqlock_t *sl)
+	__acquires_shared(sl) __no_context_analysis
 {
 	unsigned long flags;
 
@@ -1089,6 +1107,7 @@ static inline unsigned long __read_seqlock_excl_irqsave(seqlock_t *sl)
  */
 static inline void
 read_sequnlock_excl_irqrestore(seqlock_t *sl, unsigned long flags)
+	__releases_shared(sl) __no_context_analysis
 {
 	spin_unlock_irqrestore(&sl->lock, flags);
 }
@@ -1125,6 +1144,7 @@ read_sequnlock_excl_irqrestore(seqlock_t *sl, unsigned long flags)
  * parameter of the next read_seqbegin_or_lock() iteration.
  */
 static inline void read_seqbegin_or_lock(seqlock_t *lock, int *seq)
+	__acquires_shared(lock) __no_context_analysis
 {
 	if (!(*seq & 1))	/* Even */
 		*seq = read_seqbegin(lock);
@@ -1140,6 +1160,7 @@ static inline void read_seqbegin_or_lock(seqlock_t *lock, int *seq)
  * Return: true if a read section retry is required, false otherwise
  */
 static inline int need_seqretry(seqlock_t *lock, int seq)
+	__releases_shared(lock) __no_context_analysis
 {
 	return !(seq & 1) && read_seqretry(lock, seq);
 }
@@ -1153,6 +1174,7 @@ static inline int need_seqretry(seqlock_t *lock, int seq)
  * with read_seqbegin_or_lock() and validated by need_seqretry().
  */
 static inline void done_seqretry(seqlock_t *lock, int seq)
+	__no_context_analysis
 {
 	if (seq & 1)
 		read_sequnlock_excl(lock);
@@ -1180,6 +1202,7 @@ static inline void done_seqretry(seqlock_t *lock, int seq)
  */
 static inline unsigned long
 read_seqbegin_or_lock_irqsave(seqlock_t *lock, int *seq)
+	__acquires_shared(lock) __no_context_analysis
 {
 	unsigned long flags = 0;
 
@@ -1205,6 +1228,7 @@ read_seqbegin_or_lock_irqsave(seqlock_t *lock, int *seq)
  */
 static inline void
 done_seqretry_irqrestore(seqlock_t *lock, int seq, unsigned long flags)
+	__no_context_analysis
 {
 	if (seq & 1)
 		read_sequnlock_excl_irqrestore(lock, flags);
diff --git a/include/linux/seqlock_types.h b/include/linux/seqlock_types.h
index dfdf43e3fa3d..7b195368e654 100644
--- a/include/linux/seqlock_types.h
+++ b/include/linux/seqlock_types.h
@@ -81,13 +81,14 @@ SEQCOUNT_LOCKNAME(mutex,        struct mutex,    true,     mutex)
  *    - Comments on top of seqcount_t
  *    - Documentation/locking/seqlock.rst
  */
-typedef struct {
+context_guard_struct(seqlock) {
 	/*
 	 * Make sure that readers don't starve writers on PREEMPT_RT: use
 	 * seqcount_spinlock_t instead of seqcount_t. Check __SEQ_LOCK().
 	 */
 	seqcount_spinlock_t seqcount;
 	spinlock_t lock;
-} seqlock_t;
+};
+typedef struct seqlock seqlock_t;
 
 #endif /* __LINUX_SEQLOCK_TYPES_H */
diff --git a/lib/test_context-analysis.c b/lib/test_context-analysis.c
index 2b28d20c5f51..59c6642c582e 100644
--- a/lib/test_context-analysis.c
+++ b/lib/test_context-analysis.c
@@ -6,6 +6,7 @@
 
 #include <linux/build_bug.h>
 #include <linux/mutex.h>
+#include <linux/seqlock.h>
 #include <linux/spinlock.h>
 
 /*
@@ -208,3 +209,45 @@ static void __used test_mutex_cond_guard(struct test_mutex_data *d)
 		d->counter++;
 	}
 }
+
+struct test_seqlock_data {
+	seqlock_t sl;
+	int counter __guarded_by(&sl);
+};
+
+static void __used test_seqlock_init(struct test_seqlock_data *d)
+{
+	seqlock_init(&d->sl);
+	d->counter = 0;
+}
+
+static void __used test_seqlock_reader(struct test_seqlock_data *d)
+{
+	unsigned int seq;
+
+	do {
+		seq = read_seqbegin(&d->sl);
+		(void)d->counter;
+	} while (read_seqretry(&d->sl, seq));
+}
+
+static void __used test_seqlock_writer(struct test_seqlock_data *d)
+{
+	unsigned long flags;
+
+	write_seqlock(&d->sl);
+	d->counter++;
+	write_sequnlock(&d->sl);
+
+	write_seqlock_irq(&d->sl);
+	d->counter++;
+	write_sequnlock_irq(&d->sl);
+
+	write_seqlock_bh(&d->sl);
+	d->counter++;
+	write_sequnlock_bh(&d->sl);
+
+	write_seqlock_irqsave(&d->sl, flags);
+	d->counter++;
+	write_sequnlock_irqrestore(&d->sl, flags);
+}
-- 
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120151033.3840508-12-elver%40google.com.
