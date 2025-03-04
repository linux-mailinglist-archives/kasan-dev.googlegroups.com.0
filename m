Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFMOTO7AMGQEK47MCMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F187A4D803
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:25:43 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-5e4cc705909sf1863080a12.3
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:25:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080343; cv=pass;
        d=google.com; s=arc-20240605;
        b=X/eqAwqQKcYZdPsZ2BEagELY8LMHZtDpaccrcdBmiR0VgpbOVmvrNvjuKywMObKHax
         eb+0GD+RNOecAM02T4zfVE9wXySvvuhT75Ff9DckcllUUZGiAkWY17dtN5WEYkm+8WuE
         Y5YdHCQL9e1MPZ4rvLwHQEbFjURRi5ThwzcqjPSlYX+WaFXAAp31Nqp0Vi7GF0BmCR1L
         JZwzfLEICXuYHS3JEk+oJNNmO6Uj8oCKXhaN73V3JIVQHs9YCPyiRPvwmVn1weZOPDWc
         3Vba8lE9rs6hP3qOG4tiQDqLtSZr4kQcB6qWHyNXDtDBYB4uKsUZWFjmG8QEO5/goQ3Y
         Mc7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=cOeb9baedw9QXx9Tyi0OlvqHvE11QuOcu3iRkFYnpiM=;
        fh=1O6+XnqZ70vnuSn9ivOdFtVLNJZ8SZKrrxkBk3vcA/s=;
        b=lptMgrxG+lbuuoAFr6luUlwk8BnYiqg/vWSve+b4h3W9H5o17qR/rK9TNEYP3cdZ5W
         +LQE3f7DOdd/HCBhSe3vgfYSnUUBtXaQ/jps4CuXIXDtulWeZBf95HJs8jRM4Qy8fRY5
         5gdaZSf7bBI8nzYyBBorov8UWqwptHa8lj84TYsOK49qbmHUsTNcHviZjd5zhlAQZT36
         XUZ6kCQp45VZ482iJZD2lD3HgwULrdDbU3Is1DBRez9r0MMkqO3ZsOdDTjG36KC89/Z6
         nYWfiFSHkZIzZEIu58n8hVDc+WfFBJSRsrTbWMzAirmJbkAhadIjKi0yjwn8U1GugWWn
         Mv1w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RLF+qsmB;
       spf=pass (google.com: domain of 3esfgzwukcqefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3EsfGZwUKCQEfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080343; x=1741685143; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=cOeb9baedw9QXx9Tyi0OlvqHvE11QuOcu3iRkFYnpiM=;
        b=Pyb49gbefzjA+DZDHokd28IzrWqmIA+5cnpDvrn5NAkaYLkMqhA6El/H/vyqsOS4Ef
         S9Ba1ClJSuQVZnWUwBurbrO8KivbPvz/4mjztdbUHKmhPazoiFGdh+TBcbDEmjvfpKHB
         hDq4fYtRQ/z3TJRfk2ZWohg+3C95XtUstKhzNhQDhcPAQjeaIdlX3OUrjeaR0vO/KjGQ
         pTxU3eOoTZLgqw55W/rUpKc+jrZTo7f5zKhIfYfLJmalIKaGeubYljt/lBPqz57t+R6n
         5wC4qUiqt4m5Iw7AhHthqwefprLScztVLB3FrskcKT94ZdHjPrIPhaZQ4zFGoiGsGXHu
         ZVyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080343; x=1741685143;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cOeb9baedw9QXx9Tyi0OlvqHvE11QuOcu3iRkFYnpiM=;
        b=f5Jmrc0xljs3qOn5YEDbJFqSqKw0mDkPt9nII18Uq0nxJALss0ArZEUYcI8MuwhyUK
         hMmo0aKPTVA6BVADaVJMnXaO7ZroIU/vAEwJUAe+xN+HUOM1cGBIVlvMZzOYwlQtCZcK
         LKUkAgoJBzn5uFE8+12UlR5rp7heoJuo2uA1JtEjusLaD2KHM7UdVG1i/KrJ8/QEqZR7
         wztS0DS93p6bwFtNp9PGuRMX/AdUF47Vpdih12o391la408WZ80omSFlRpPr5HvZy/Qe
         lBBMmxuoleTYScHySIPS6tqt66LacutIkINdzNghqyhHZBCJwKSp2bf8cQb1WVTB0f9d
         +RaA==
X-Forwarded-Encrypted: i=2; AJvYcCWuGD3h959nkGTBASMYLizsT8p3qwbfDrlX1G5vyM7E79g1x/huJoV73qeoZnuBQo56tUXDww==@lfdr.de
X-Gm-Message-State: AOJu0YxeFYUVLdtFzM7h43aKdDAy9FYkz5wITcY2SUoGg3XxDTfSpyla
	y1NlTnT52+05joMabmn1esiDJyHabBUK/wkXms5sibvPPzlXh885
X-Google-Smtp-Source: AGHT+IFXw3zsRila5yoVdezTzEWTvtVvd8AWrzeZxJJlcKlLqPv+6i+RviU5taHr/vxdwObvfU6m/w==
X-Received: by 2002:a05:6402:274b:b0:5e4:cf2e:891c with SMTP id 4fb4d7f45d1cf-5e4d6ad8737mr20358184a12.12.1741080342068;
        Tue, 04 Mar 2025 01:25:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHxeOEpcNoTGVSGfJTa983IH8rCZKudPcWC6dQST0MszA==
Received: by 2002:a50:9f2b:0:b0:5de:3b3a:573a with SMTP id 4fb4d7f45d1cf-5e59388c467ls104282a12.0.-pod-prod-08-eu;
 Tue, 04 Mar 2025 01:25:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXgbwpryLvfxnwcvoLV/XlCANrHXIkiPzPN8LO+cSL/yhcYR5WYXk26TkfsnH+Zp4EWkJTU7uPMFEA=@googlegroups.com
X-Received: by 2002:a17:906:f5aa:b0:abf:70fb:7f05 with SMTP id a640c23a62f3a-abf70fb942bmr953987666b.50.1741080339297;
        Tue, 04 Mar 2025 01:25:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080339; cv=none;
        d=google.com; s=arc-20240605;
        b=QcsJ9QFVQ8qkK6vPD3wJJJwRvbV5DlRkx4J6kbQFDUtZXeZygYGSwiJiOL8mPGRIMi
         cG80Bdf0NBRKD7sLaceMR4dxz/akyHv8mPtw7X8nuVV4J8WuOVFDsEByFLB1lK6wiqvG
         kepXU3XZGtEtThU33GOGSqgsu60EgBJPtVa0ny70eHZPjIwt3kAtQgcQtrnjLF4y3eJS
         2rNch6aAdpO9iZlDVEMPAPuCgqDSy8TJVaiAXAvlI3bAc31X/MpHc4qfw4vPqVVKGCkb
         C41Flygo3nMOmohMsDhHp4ok/B5XiUfVemoU9Hh8M8P2fI6Rg3gr6fJRRlnHxxg4ECUW
         3RCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=8z4fgpkLlPzvclrtbcw45VHrfGlnBGLpcfc2M8hQ/8Q=;
        fh=N59Tb6na7M3A2u6+hVrJ2qWBzTAnFCf0eMTZ+mp0bJo=;
        b=U3fDmSO05Tq7dF88tq0Hcc9nSxikv9MOLwk6Q4wP+cyHurmN2QligUx663PdO/qeDn
         hSOk+BNS/pqbO2f8G6Opnj2GTzaYJoHigjSXND0UnSTAKCCZfmr1rPd30VJRoyWdZCZT
         K36Hay51RJa16/huX8/tcG2jQQTq6xkssNmnk35MUtLe2u5RZH2GDes4SkrPtOVGqJKQ
         UImyBzN6/x6hyDk9WtTTXNdabXI3oVINF5DUIyPu3AHPuv3HNrtRH1M32eGd0eJCbAad
         Dkqm7Ahqr1Mw0P2detQUrALHgcYywm/3NxibwnDTvCG+MbV4q9hIi9Qgae6JJN6vv/pJ
         hPJQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RLF+qsmB;
       spf=pass (google.com: domain of 3esfgzwukcqefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3EsfGZwUKCQEfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-abf0c0dd5a8si46875666b.1.2025.03.04.01.25.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:25:39 -0800 (PST)
Received-SPF: pass (google.com: domain of 3esfgzwukcqefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id a640c23a62f3a-abf48e1e70eso288315466b.2
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:25:39 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVX0tZ4JNfE8xfsRvgz07vjGiuj8glgoh2Cjkn2mD1QgM7xyqEMdD2qKqbRLtBZojf6w+Uq8F7krdE=@googlegroups.com
X-Received: from ejcvg12.prod.google.com ([2002:a17:907:d30c:b0:abf:7710:3f5])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:3fa6:b0:abf:65c8:70e5
 with SMTP id a640c23a62f3a-abf65c8922cmr1078595566b.25.1741080338878; Tue, 04
 Mar 2025 01:25:38 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:10 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-12-elver@google.com>
Subject: [PATCH v2 11/34] locking/seqlock: Support Clang's capability analysis
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
 header.i=@google.com header.s=20230601 header.b=RLF+qsmB;       spf=pass
 (google.com: domain of 3esfgzwukcqefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3EsfGZwUKCQEfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
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
index 0000214056c2..e4b333fffb4d 100644
--- a/Documentation/dev-tools/capability-analysis.rst
+++ b/Documentation/dev-tools/capability-analysis.rst
@@ -79,7 +79,7 @@ Supported Kernel Primitives
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
index 286723b47328..74d287740bb8 100644
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
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-12-elver%40google.com.
