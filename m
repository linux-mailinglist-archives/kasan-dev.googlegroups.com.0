Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2XZSO6QMGQELMZXDPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 56F39A2B058
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:18:21 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-4361ecebc5bsf7035045e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:18:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738865901; cv=pass;
        d=google.com; s=arc-20240605;
        b=HmrrL8nwgGA3r9PLFiOIdHkFCAdIlhOzzjU7HssdvEIivWF6tJBwDkPOJgm0SHBlQq
         AD/PSDuz0YauPzbtDiWsJGlocovrVaflsiZznZZcXleUF2oLaTEWtnHM2VHJsxC6WZ9u
         eYvjRIx1mBguODOHe3RUCeF8y8ad6akwejuDpU/UtmtrNX+pWjasW3m9sqnPmbghyM2I
         ogRRtp6I5oMUbrHKe6fSUBivhejNyPJWxCo3nsjqxZXoEZaeTpMqglpxEnAiFfr6od1e
         cJgXWCWCoOezrC2imR8JgTEEZZSjOxwT6uhJh2ogsncFMNWW8sv9sQkn7FcyHhoBi40G
         QHbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=MBALXu0yc3TGx0O6FU+92zO2RXLdKaXhZmFk+vkYnMY=;
        fh=ObMolpbMrrjbA5Pw27Wl5a2al8mALiofzEsv7kE1isQ=;
        b=T8XsL4NCSa1c9VDBsUwJYuRqoZZ1qBHVNwGtxq1xdx2vtYntZaTQy6MV74+63BbTyj
         mHe+AGYH1ifLWWRc81pOTDLM3mp35FvVeWEf0xlJ4nOSqpICkk9Anef4o8fuIaD57kZy
         QwDtdsZ3+TqxAxvmm3gICPpWYguqH15rFNJQSkctqAT2tJbfUeZVtUy01qLVvZvl3vCi
         g2YFLOVq/o0jqXrDCE5q0CPdgZ21FYboGgL6vRrVw6vVxVKvvcKQh4Gk0MuDXj0N9fqC
         t9dl07L9bQDC075D0H0ikAVML23sqW+MR6Aofz+ENd9/eWq1w8CXmPb77KH+ycmH7bs6
         NeCA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Ub0hdLxO;
       spf=pass (google.com: domain of 36pykzwukcbkdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=36PykZwUKCbkdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738865900; x=1739470700; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=MBALXu0yc3TGx0O6FU+92zO2RXLdKaXhZmFk+vkYnMY=;
        b=CuuuJOWmEbVewm0o/q9cXBvwWjFPKutCBLpYbTbRD/zUVuo2UrjnC0MV2tweEf0Sfd
         EHDDjHbzq7IlA4gOu6wRZM5Mv7iaEmQJjGALFTE8DRCOlpLgqMgT2Mki+NGAYW59cxOZ
         MOFviWmejvzAY4t0hT+2k9EqzRtqrBTTVvLH3QvYu6F3LJE1nS+sypkBtSeEcFA294y+
         OSgNt7xE+mUtRXfK5aJxgi/7nlfnM+h2uZo7muftuun8gDXxmRpoJnpkyZFTjL71X5Az
         YDRJThEGQ5Hf0pStiaQ5lU9B0Kl3u+jbQ52lpwWvxcFrGzejJLEYSBIHMbhm/RBMOhtO
         NBhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738865901; x=1739470701;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MBALXu0yc3TGx0O6FU+92zO2RXLdKaXhZmFk+vkYnMY=;
        b=n2c+VLagxgT+HPmzJfgb9KAQPv0lI2VWW7VrblMC3ITC1y0YNQ/7bVesS05qjXN5dU
         8p0Sh1+Wn+fK+1AIL22ogirWMl83afS57ZuAdNbLr9glzL06orlpNmOIDQYXakyDXDP8
         pc3BYL4idLilI8VFVVLXcfRAa8ivslaXbw7TXd3zaITLJ3b57C36iWIOcFrYLuM8XG0A
         5C7acnY3BQpB9KC59F/xNrP3WfubdUr/Euj9EaPdpVbJm3HOd1N3kSqWtWhv+rW1f5PJ
         KUmyG9KR0ZKSTT2giYNAFurgzZOT1WOzaGzRRb43FXi/wY24pPIIdBy2AWO11pgOHLAP
         conA==
X-Forwarded-Encrypted: i=2; AJvYcCUqqE6kxSGECX0+yA7YA4rqrtYQjLNB70COHCVpJq4GwOgUvuApAXI447Qb8A62HV2UO9ehlw==@lfdr.de
X-Gm-Message-State: AOJu0YyDII9JMDB1v+YUtUzices8rbLotSYcQbWvWN+R+WMhldob+4CT
	WfAq3NpS4QT9rB/R8irnMm1MXP7/clO5k6NWDDSTqqV962pLryfH
X-Google-Smtp-Source: AGHT+IHwitEA+7E3sEYX2GtM9kzUgphkSIXUmZUrS1Ni8TIpTvhKDfEWP4K6vSzouvR5ZjYz69a4Qg==
X-Received: by 2002:a05:600c:b87:b0:436:1c04:aa8e with SMTP id 5b1f17b1804b1-43924991e23mr4565225e9.16.1738865899297;
        Thu, 06 Feb 2025 10:18:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=AT6nireMD4T+Pw4OlBgqeRH+knlmYJ0d+fU0NN+OmFD5fXfTdg==
Received: by 2002:a05:600c:285:b0:434:9332:de65 with SMTP id
 5b1f17b1804b1-43924c3e068ls248635e9.0.-pod-prod-06-eu; Thu, 06 Feb 2025
 10:18:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUc4xTmhuUuSZtTBnSADLjWRba0U93C1uDdouCPihqpBbpTZ/unIND5F809vw7YyzVt4F9oRW08Ngg=@googlegroups.com
X-Received: by 2002:a05:600c:1c1c:b0:434:a4fe:cd71 with SMTP id 5b1f17b1804b1-4392498a9a0mr4402635e9.12.1738865896595;
        Thu, 06 Feb 2025 10:18:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738865896; cv=none;
        d=google.com; s=arc-20240605;
        b=XxvZWb2drCnRvogJPShwtvj15pBcRqn1q5hx9XlSJho/nOugpq5LzQf4XDDuoFc17p
         39MQjU9SeSrCAjmn2oNLXpcAmdvXomiaJOgPWLBadqFJAh7nqVSHjvTkEYA/9mBy5B/v
         oIO1y70N+thyx1ZlqAVwOUSbrhe3D70BrgEnGU5mSkrHmGNJfxCvY79oghis1tfPJ4Ju
         kPeinkscNhvZ7Q/EoImSZsqniAbuBM7cO6NjOwj4TU1rPWqrpLiGBFwjb3gIphXsjxU1
         4oHxxomN8pEHaZ5ny5nAtc/2q2jOQKKxdc5nmbwQM9yvIpGY3o6sU4Nz74ebUg7kGJEz
         EgfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=H4q+9WLE15qKddw85vlrIejrThq+pT1MCiLGjI1MaOU=;
        fh=DvPvtUpYKPAsU7Duszcmnb2mDE30lWb7k9xLNJJDZhM=;
        b=NN8rqP/i+yKiprAchQMCg8xphPKQvObP/XT6pHLxoYkaxsb1pfHvD5Gm7KJjBqb2Ps
         h23Ga7dkcjHZ7Sn1r5kvvgB+3TACDsJz7T41KtSD7+ko8DJ/NNnrUWqkmJwWBOLFPcPc
         D7OLGY46piFf369WEfPrho8w6LLVsvI2jA9M6uR49dDiciJSAeJ0EJJTXg5TEqWplso5
         A788PwgQ9ESaBYTNkwvH9akEcy/5GnCyGJRwaKYbFaB1YPlCykLWcjGnUAnZ9lRu2lqw
         82uMfK/AvccQQVUgbMcQOYtVxGERXASeZFR7s7e2bQaBKFQg9MIanQj6yiF5rKz4ulkp
         clhA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Ub0hdLxO;
       spf=pass (google.com: domain of 36pykzwukcbkdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=36PykZwUKCbkdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4390692a173si5665735e9.0.2025.02.06.10.18.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:18:16 -0800 (PST)
Received-SPF: pass (google.com: domain of 36pykzwukcbkdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id 4fb4d7f45d1cf-5d9fb24f87bso1474329a12.0
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:18:16 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXHDAaeUEWEUac7Lu1t0GS4mFDlsIUzjZvcrq1Lvpo/Lbk6C0GOmffhqPrftEdwKEhaol7DMHoXyCI=@googlegroups.com
X-Received: from edbin10.prod.google.com ([2002:a05:6402:208a:b0:5de:35d9:f60c])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:194b:b0:5db:f423:19c5
 with SMTP id 4fb4d7f45d1cf-5de44fea647mr545992a12.5.1738865896253; Thu, 06
 Feb 2025 10:18:16 -0800 (PST)
Date: Thu,  6 Feb 2025 19:10:06 +0100
In-Reply-To: <20250206181711.1902989-1-elver@google.com>
Mime-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.502.g6dc24dfdaf-goog
Message-ID: <20250206181711.1902989-13-elver@google.com>
Subject: [PATCH RFC 12/24] locking/seqlock: Support Clang's capability analysis
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
 header.i=@google.com header.s=20230601 header.b=Ub0hdLxO;       spf=pass
 (google.com: domain of 36pykzwukcbkdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=36PykZwUKCbkdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
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

Add support for Clang's capability analysis for seqlock_t.

Signed-off-by: Marco Elver <elver@google.com>
---
 .../dev-tools/capability-analysis.rst         |  2 +-
 include/linux/seqlock.h                       | 24 +++++++++++
 include/linux/seqlock_types.h                 |  5 ++-
 lib/test_capability-analysis.c                | 43 +++++++++++++++++++
 4 files changed, 71 insertions(+), 3 deletions(-)

diff --git a/Documentation/dev-tools/capability-analysis.rst b/Documentation/dev-tools/capability-analysis.rst
index 31f76e877be5..8d9336e91ce2 100644
--- a/Documentation/dev-tools/capability-analysis.rst
+++ b/Documentation/dev-tools/capability-analysis.rst
@@ -85,7 +85,7 @@ Supported Kernel Primitives
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~
 
 Currently the following synchronization primitives are supported:
-`raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`.
+`raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`.
 
 For capabilities with an initialization function (e.g., `spin_lock_init()`),
 calling this function on the capability instance before initializing any
diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
index 5ce48eab7a2a..c914eb9714e9 100644
--- a/include/linux/seqlock.h
+++ b/include/linux/seqlock.h
@@ -816,6 +816,7 @@ static __always_inline void write_seqcount_latch_end(seqcount_latch_t *s)
 	do {								\
 		spin_lock_init(&(sl)->lock);				\
 		seqcount_spinlock_init(&(sl)->seqcount, &(sl)->lock);	\
+		__assert_cap(sl);					\
 	} while (0)
 
 /**
@@ -832,6 +833,7 @@ static __always_inline void write_seqcount_latch_end(seqcount_latch_t *s)
  * Return: count, to be passed to read_seqretry()
  */
 static inline unsigned read_seqbegin(const seqlock_t *sl)
+	__acquires_shared(sl) __no_capability_analysis
 {
 	return read_seqcount_begin(&sl->seqcount);
 }
@@ -848,6 +850,7 @@ static inline unsigned read_seqbegin(const seqlock_t *sl)
  * Return: true if a read section retry is required, else false
  */
 static inline unsigned read_seqretry(const seqlock_t *sl, unsigned start)
+	__releases_shared(sl) __no_capability_analysis
 {
 	return read_seqcount_retry(&sl->seqcount, start);
 }
@@ -872,6 +875,7 @@ static inline unsigned read_seqretry(const seqlock_t *sl, unsigned start)
  * _irqsave or _bh variants of this function instead.
  */
 static inline void write_seqlock(seqlock_t *sl)
+	__acquires(sl) __no_capability_analysis
 {
 	spin_lock(&sl->lock);
 	do_write_seqcount_begin(&sl->seqcount.seqcount);
@@ -885,6 +889,7 @@ static inline void write_seqlock(seqlock_t *sl)
  * critical section of given seqlock_t.
  */
 static inline void write_sequnlock(seqlock_t *sl)
+	__releases(sl) __no_capability_analysis
 {
 	do_write_seqcount_end(&sl->seqcount.seqcount);
 	spin_unlock(&sl->lock);
@@ -898,6 +903,7 @@ static inline void write_sequnlock(seqlock_t *sl)
  * other write side sections, can be invoked from softirq contexts.
  */
 static inline void write_seqlock_bh(seqlock_t *sl)
+	__acquires(sl) __no_capability_analysis
 {
 	spin_lock_bh(&sl->lock);
 	do_write_seqcount_begin(&sl->seqcount.seqcount);
@@ -912,6 +918,7 @@ static inline void write_seqlock_bh(seqlock_t *sl)
  * write_seqlock_bh().
  */
 static inline void write_sequnlock_bh(seqlock_t *sl)
+	__releases(sl) __no_capability_analysis
 {
 	do_write_seqcount_end(&sl->seqcount.seqcount);
 	spin_unlock_bh(&sl->lock);
@@ -925,6 +932,7 @@ static inline void write_sequnlock_bh(seqlock_t *sl)
  * other write sections, can be invoked from hardirq contexts.
  */
 static inline void write_seqlock_irq(seqlock_t *sl)
+	__acquires(sl) __no_capability_analysis
 {
 	spin_lock_irq(&sl->lock);
 	do_write_seqcount_begin(&sl->seqcount.seqcount);
@@ -938,12 +946,14 @@ static inline void write_seqlock_irq(seqlock_t *sl)
  * seqlock_t write side section opened with write_seqlock_irq().
  */
 static inline void write_sequnlock_irq(seqlock_t *sl)
+	__releases(sl) __no_capability_analysis
 {
 	do_write_seqcount_end(&sl->seqcount.seqcount);
 	spin_unlock_irq(&sl->lock);
 }
 
 static inline unsigned long __write_seqlock_irqsave(seqlock_t *sl)
+	__acquires(sl) __no_capability_analysis
 {
 	unsigned long flags;
 
@@ -976,6 +986,7 @@ static inline unsigned long __write_seqlock_irqsave(seqlock_t *sl)
  */
 static inline void
 write_sequnlock_irqrestore(seqlock_t *sl, unsigned long flags)
+	__releases(sl) __no_capability_analysis
 {
 	do_write_seqcount_end(&sl->seqcount.seqcount);
 	spin_unlock_irqrestore(&sl->lock, flags);
@@ -998,6 +1009,7 @@ write_sequnlock_irqrestore(seqlock_t *sl, unsigned long flags)
  * The opened read section must be closed with read_sequnlock_excl().
  */
 static inline void read_seqlock_excl(seqlock_t *sl)
+	__acquires_shared(sl) __no_capability_analysis
 {
 	spin_lock(&sl->lock);
 }
@@ -1007,6 +1019,7 @@ static inline void read_seqlock_excl(seqlock_t *sl)
  * @sl: Pointer to seqlock_t
  */
 static inline void read_sequnlock_excl(seqlock_t *sl)
+	__releases_shared(sl) __no_capability_analysis
 {
 	spin_unlock(&sl->lock);
 }
@@ -1021,6 +1034,7 @@ static inline void read_sequnlock_excl(seqlock_t *sl)
  * from softirq contexts.
  */
 static inline void read_seqlock_excl_bh(seqlock_t *sl)
+	__acquires_shared(sl) __no_capability_analysis
 {
 	spin_lock_bh(&sl->lock);
 }
@@ -1031,6 +1045,7 @@ static inline void read_seqlock_excl_bh(seqlock_t *sl)
  * @sl: Pointer to seqlock_t
  */
 static inline void read_sequnlock_excl_bh(seqlock_t *sl)
+	__releases_shared(sl) __no_capability_analysis
 {
 	spin_unlock_bh(&sl->lock);
 }
@@ -1045,6 +1060,7 @@ static inline void read_sequnlock_excl_bh(seqlock_t *sl)
  * hardirq context.
  */
 static inline void read_seqlock_excl_irq(seqlock_t *sl)
+	__acquires_shared(sl) __no_capability_analysis
 {
 	spin_lock_irq(&sl->lock);
 }
@@ -1055,11 +1071,13 @@ static inline void read_seqlock_excl_irq(seqlock_t *sl)
  * @sl: Pointer to seqlock_t
  */
 static inline void read_sequnlock_excl_irq(seqlock_t *sl)
+	__releases_shared(sl) __no_capability_analysis
 {
 	spin_unlock_irq(&sl->lock);
 }
 
 static inline unsigned long __read_seqlock_excl_irqsave(seqlock_t *sl)
+	__acquires_shared(sl) __no_capability_analysis
 {
 	unsigned long flags;
 
@@ -1089,6 +1107,7 @@ static inline unsigned long __read_seqlock_excl_irqsave(seqlock_t *sl)
  */
 static inline void
 read_sequnlock_excl_irqrestore(seqlock_t *sl, unsigned long flags)
+	__releases_shared(sl) __no_capability_analysis
 {
 	spin_unlock_irqrestore(&sl->lock, flags);
 }
@@ -1125,6 +1144,7 @@ read_sequnlock_excl_irqrestore(seqlock_t *sl, unsigned long flags)
  * parameter of the next read_seqbegin_or_lock() iteration.
  */
 static inline void read_seqbegin_or_lock(seqlock_t *lock, int *seq)
+	__acquires_shared(lock) __no_capability_analysis
 {
 	if (!(*seq & 1))	/* Even */
 		*seq = read_seqbegin(lock);
@@ -1140,6 +1160,7 @@ static inline void read_seqbegin_or_lock(seqlock_t *lock, int *seq)
  * Return: true if a read section retry is required, false otherwise
  */
 static inline int need_seqretry(seqlock_t *lock, int seq)
+	__releases_shared(lock) __no_capability_analysis
 {
 	return !(seq & 1) && read_seqretry(lock, seq);
 }
@@ -1153,6 +1174,7 @@ static inline int need_seqretry(seqlock_t *lock, int seq)
  * with read_seqbegin_or_lock() and validated by need_seqretry().
  */
 static inline void done_seqretry(seqlock_t *lock, int seq)
+	__no_capability_analysis
 {
 	if (seq & 1)
 		read_sequnlock_excl(lock);
@@ -1180,6 +1202,7 @@ static inline void done_seqretry(seqlock_t *lock, int seq)
  */
 static inline unsigned long
 read_seqbegin_or_lock_irqsave(seqlock_t *lock, int *seq)
+	__acquires_shared(lock) __no_capability_analysis
 {
 	unsigned long flags = 0;
 
@@ -1205,6 +1228,7 @@ read_seqbegin_or_lock_irqsave(seqlock_t *lock, int *seq)
  */
 static inline void
 done_seqretry_irqrestore(seqlock_t *lock, int seq, unsigned long flags)
+	__no_capability_analysis
 {
 	if (seq & 1)
 		read_sequnlock_excl_irqrestore(lock, flags);
diff --git a/include/linux/seqlock_types.h b/include/linux/seqlock_types.h
index dfdf43e3fa3d..9775d6f1a234 100644
--- a/include/linux/seqlock_types.h
+++ b/include/linux/seqlock_types.h
@@ -81,13 +81,14 @@ SEQCOUNT_LOCKNAME(mutex,        struct mutex,    true,     mutex)
  *    - Comments on top of seqcount_t
  *    - Documentation/locking/seqlock.rst
  */
-typedef struct {
+struct_with_capability(seqlock) {
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
diff --git a/lib/test_capability-analysis.c b/lib/test_capability-analysis.c
index 3410c04c2b76..1e4b90f76420 100644
--- a/lib/test_capability-analysis.c
+++ b/lib/test_capability-analysis.c
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
+	int counter __var_guarded_by(&sl);
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
2.48.1.502.g6dc24dfdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250206181711.1902989-13-elver%40google.com.
