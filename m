Return-Path: <kasan-dev+bncBDBK55H2UQKRBGFXRK4QMGQESXGGQOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 565D19B6E08
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2024 21:48:26 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-4315ad4938fsf1393975e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2024 13:48:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730321306; cv=pass;
        d=google.com; s=arc-20240605;
        b=VYmJjHz+Q69oeEEEF/GS4s8H2ngNC1lbeGwkDYei4aGj3+4lfNZm47Objrvb30UStc
         sZ36yZdOg8vOhLaNB1yxEA4bu6kB9boS7kHajKTKTPGzQuwLlzXXZ5/+dNjL+94vERMF
         jrjo8YbRMx2WbwxJWGYBX5TE68iA1jd3tegnujsapt4EelN7aOLWPwoAFxZQV8jn1ugn
         Gr/h+bFDx7nXPqqq7hJllUR4O4IjxaUpHhyt8sTDEqwgUqd2aeKRAGrW48Ss9mI0SHrZ
         sXe0MZFkoHjTnCw4Btd3p9svfQsM2YzirjVxYseEM5hc/jfMcSLUyaxtU5gl7RXTM5ko
         QOYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=FQqJhq+TeSeDbBLHHOr3FPcOGjqOyK9VjaAtQ7ZdaVA=;
        fh=1X/shhdY1Hc8eNUnIg8BetXH6lMQ1caVJkXmKtGlxDY=;
        b=bDa7TJgH1CP23NCKFl1QZeUoyyMYVyshG/qXkBP32Dbr/9xoKj/W4eE76v9lvgG0HN
         zu0R6ljL0ssBQsWBFSoSOX0tg1lDBEHD1WT9c82s4HXATL2nBGgeSVlonHqqP2LJGSA6
         hYThOd56yYO6WRjeqZN7Ubjviwfi5zB9Yu710svK/irk8goSoMN0NNu+BbPwSojro9DG
         kvRfVJK+sXiEDIOCJjjZCvnp7qLyHe4X/FgU8vxfJJYAK/zmtJLj2MdXUylPmAafXRPn
         VeZoSwdvxTWCVx1ryLzqmzx4ui7XrgePZVR373+s6F3X9FtMvENSTYmJJXJA/Dz5VBmf
         rrKQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=PI16AU47;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730321306; x=1730926106; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FQqJhq+TeSeDbBLHHOr3FPcOGjqOyK9VjaAtQ7ZdaVA=;
        b=tURYrssOT0zTu5maeiWYeYpFQSWIgY7fBgQvZMjUi+h7DW4WC70hY2w3hbOqDD51OG
         TV7VOOJx0LJwDhUc4jmm4DSZqEuidWTLmb4k07Jy0DKRCblrpBBQI17TJbOfv0jMN+2F
         f18RTkGK1vQ0f2yr5i+qkPS7pdZEEFNi1SKEDq+o2DYPxXCYbJY/TgglxTFZLSi8C3fG
         IW4lAj2szy6PjphtMvP2gblHmw8OhScnZ5zP0hep5ly5yYiSU6yz3Fw3WMgEy7a+Otng
         6cyrAxaDLx0UTaoYUE3jHU8+2DwnwFsKHHr7zo7M7sBsWLxpZcJp/E+5y/T9ZGppmOx0
         d8TQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730321306; x=1730926106;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FQqJhq+TeSeDbBLHHOr3FPcOGjqOyK9VjaAtQ7ZdaVA=;
        b=kNzKIsvnfoHF3A6bY9DgVATodhs14GMazeaSwZAV+zzRQ7liyKHXn548l9dA9fPB8b
         j3RFj6LD6miU2vyY2gRMKWSvU66N3ibKfvDeYyvXVX34kdmqUKJdgVGOWX9J+MXt/Q78
         n57reo8UzaWd1alCtisjsdzZyS8WHp0zCUfqGVrpzUk3v+sLAe6r+9dHdAqu+3HMUW/r
         EmpRrQo6T3i+85d/YhJAhMel6ypvWrOlGcSpE4V0qt86PBqZJcavaAEuicsmfnzuYWcP
         +UH20tFiTeWtbBO/WEgor2y7skYIogvDOdUQN9LDi6+wAK2w7uhKlQxX5gh5mDOZ5jMx
         8MTw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU/7HaTuS+4Y47FkxjLH0/tU6UD8awqDaWIw4dmS9RsM8Essl+Jtf1VaVLuudTeBWzhX6HwFQ==@lfdr.de
X-Gm-Message-State: AOJu0YyKWgbLe8VfVjmUbPYCyYLA/Ze/Sq8N+1x4bvd76OcNjvciWHto
	t8niI/PVg4agWS8ewomwv74bDHvks7npP38Q3ERaa5ksI10Kmxda
X-Google-Smtp-Source: AGHT+IFKaNGk2vctqZlq7GO307wITE1DGyd0+7Pcij0C7w3MFsfKyryD0BRPTdyi9GYCmfpZk7Rjjg==
X-Received: by 2002:a05:600c:2153:b0:431:5d4f:73b9 with SMTP id 5b1f17b1804b1-4319ad04f95mr176488325e9.26.1730321305053;
        Wed, 30 Oct 2024 13:48:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b92:b0:42c:b037:5fe4 with SMTP id
 5b1f17b1804b1-4327b81d5fdls1237745e9.2.-pod-prod-08-eu; Wed, 30 Oct 2024
 13:48:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW7hyzuToV54AExGCD4jhhH6rh3Oxdr1PIWXcZWrJS3hvOqp6nCk1nLhmzt+tpIanOLoSyBstNKnzM=@googlegroups.com
X-Received: by 2002:a5d:5705:0:b0:37d:2e59:68ca with SMTP id ffacd0b85a97d-380611633f3mr11746654f8f.28.1730321302490;
        Wed, 30 Oct 2024 13:48:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730321302; cv=none;
        d=google.com; s=arc-20240605;
        b=DEE93zNdXaGvbzOL6XndWRaVxtTUxqf8xoQR+Q12KR3to+oTTj7glBLG6nKAIpoZ47
         +sXQfeejUHo+XqTeWsnwkM4qDnWoma/c48DvpQI/XIS8VW0LmPPnpPnhHxyvhaZipKbh
         eiCh4AjNGCKwcnGn2UnzFGy9xzBjfvmYvovm8j7Hp4HEe5SLXTXZq6Fhl3kVXw5uJaoA
         n0p6p0z5NDm3LSGHUJ9v0M8hUlxXI2scEDIT3Odvjbh4+6FQqYPjaFdL4otxTR3V64lU
         HNC56HHizyzm5vBRXPK+pO+Yx/X1FGO/gFT1p52m+opzq1OOK6GYewZH1VikimzUEEkm
         r8Nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=99kTf82GzK1ndpXdfczRfvZOLKCNQTEUCVNieLNuiSs=;
        fh=rsYLeNn3EhqnY/ERv90DXt1NYQkHGuhFKomDG1eXtr4=;
        b=NzRAf+N8SnInR50b5pEJen4dcrkmCbxAphDeuLrwRVBY8VPtG0YIYK9cq3lzXcOrhH
         ariJvW2r34hV5d4RmyVr+nKCbgH6kEMN++rtt3r+li/O23/VknIB1Ad4X3HRAUnd0yyZ
         hYw+h8e+FYygH827NlZhJi9dQ9No75JCRw0BU2OLenmMLo4p9QxBEtyA/0VfffQCNMek
         8MaWyTJsK0soc0zKA5npTw0lnpcOpqqGTXV1xRmPxEquK48SAv6MPd1VOPxhXqg/Avjf
         HzrGleQvBYi4Zmx2e/xbui4epSyLglRj4dMYjU3NdmywDMVqt6osf7lBr2886j7//xn3
         aJjw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=PI16AU47;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-381c11629bdsi2634f8f.3.2024.10.30.13.48.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Oct 2024 13:48:22 -0700 (PDT)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98 #2 (Red Hat Linux))
	id 1t6Fc0-0000000ALFy-1gjc;
	Wed, 30 Oct 2024 20:48:18 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id B3B51300ABE; Wed, 30 Oct 2024 21:48:15 +0100 (CET)
Date: Wed, 30 Oct 2024 21:48:15 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>,
	Waiman Long <longman@redhat.com>, Boqun Feng <boqun.feng@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Mark Rutland <mark.rutland@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Alexander Potapenko <glider@google.com>
Subject: Re: [PATCH] kcsan, seqlock: Support seqcount_latch_t
Message-ID: <20241030204815.GQ14555@noisy.programming.kicks-ass.net>
References: <20241029083658.1096492-1-elver@google.com>
 <20241029114937.GT14555@noisy.programming.kicks-ass.net>
 <CANpmjNPyXGRTWHhycVuEXdDfe7MoN19MeztdQaSOJkzqhCD69Q@mail.gmail.com>
 <20241029134641.GR9767@noisy.programming.kicks-ass.net>
 <ZyFKUU1LpFfLrVXb@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZyFKUU1LpFfLrVXb@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=PI16AU47;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Tue, Oct 29, 2024 at 09:49:21PM +0100, Marco Elver wrote:

> Something like this?
> 
> ------ >8 ------
> 
> Author: Marco Elver <elver@google.com>
> Date:   Tue Oct 29 21:16:21 2024 +0100
> 
>     time/sched_clock: Swap update_clock_read_data() latch writes
>     
>     Swap the writes to the odd and even copies to make the writer critical
>     section look like all other seqcount_latch writers.
>     
>     With that, we can also add the raw_write_seqcount_latch_end() to clearly
>     denote the end of the writer section.
>     
>     Signed-off-by: Marco Elver <elver@google.com>
> 
> diff --git a/kernel/time/sched_clock.c b/kernel/time/sched_clock.c
> index 68d6c1190ac7..311c90a0e86e 100644
> --- a/kernel/time/sched_clock.c
> +++ b/kernel/time/sched_clock.c
> @@ -119,9 +119,6 @@ unsigned long long notrace sched_clock(void)
>   */
>  static void update_clock_read_data(struct clock_read_data *rd)
>  {
> -	/* update the backup (odd) copy with the new data */
> -	cd.read_data[1] = *rd;
> -
>  	/* steer readers towards the odd copy */
>  	raw_write_seqcount_latch(&cd.seq);
>  
> @@ -130,6 +127,11 @@ static void update_clock_read_data(struct clock_read_data *rd)
>  
>  	/* switch readers back to the even copy */
>  	raw_write_seqcount_latch(&cd.seq);
> +
> +	/* update the backup (odd) copy with the new data */
> +	cd.read_data[1] = *rd;
> +
> +	raw_write_seqcount_latch_end(&cd.seq);
>  }
>  
>  /*

That looks about right :-)

> ------ >8 ------
> 
> I also noticed your d16317de9b41 ("seqlock/latch: Provide
> raw_read_seqcount_latch_retry()") to get rid of explicit instrumentation
> in noinstr.
> 
> Not sure how to resolve that. We have that objtool support to erase
> calls in noinstr code (is_profiling_func), but that's x86 only.
> 
> I could also make kcsan_atomic_next(0) noinstr compatible by checking if
> the ret IP is in noinstr, and immediately return if it is.
> 
> Preferences?

Something like this perhaps?

---
 arch/x86/kernel/tsc.c        |  5 +++--
 include/linux/rbtree_latch.h | 14 ++++++++------
 include/linux/seqlock.h      | 31 ++++++++++++++++++++++++++++++-
 kernel/printk/printk.c       |  9 +++++----
 kernel/time/sched_clock.c    | 20 ++++++++++++--------
 kernel/time/timekeeping.c    | 10 ++++++----
 6 files changed, 64 insertions(+), 25 deletions(-)

diff --git a/arch/x86/kernel/tsc.c b/arch/x86/kernel/tsc.c
index dfe6847fd99e..67aeaba4ba9c 100644
--- a/arch/x86/kernel/tsc.c
+++ b/arch/x86/kernel/tsc.c
@@ -174,10 +174,11 @@ static void __set_cyc2ns_scale(unsigned long khz, int cpu, unsigned long long ts
 
 	c2n = per_cpu_ptr(&cyc2ns, cpu);
 
-	raw_write_seqcount_latch(&c2n->seq);
+	write_seqcount_latch_begin(&c2n->seq);
 	c2n->data[0] = data;
-	raw_write_seqcount_latch(&c2n->seq);
+	write_seqcount_latch(&c2n->seq);
 	c2n->data[1] = data;
+	write_seqcount_latch_end(&c2n->seq);
 }
 
 static void set_cyc2ns_scale(unsigned long khz, int cpu, unsigned long long tsc_now)
diff --git a/include/linux/rbtree_latch.h b/include/linux/rbtree_latch.h
index 6a0999c26c7c..bc992c61b7ce 100644
--- a/include/linux/rbtree_latch.h
+++ b/include/linux/rbtree_latch.h
@@ -145,10 +145,11 @@ latch_tree_insert(struct latch_tree_node *node,
 		  struct latch_tree_root *root,
 		  const struct latch_tree_ops *ops)
 {
-	raw_write_seqcount_latch(&root->seq);
+	write_seqcount_latch_begin(&root->seq);
 	__lt_insert(node, root, 0, ops->less);
-	raw_write_seqcount_latch(&root->seq);
+	write_seqcount_latch(&root->seq);
 	__lt_insert(node, root, 1, ops->less);
+	write_seqcount_latch_end(&root->seq);
 }
 
 /**
@@ -172,10 +173,11 @@ latch_tree_erase(struct latch_tree_node *node,
 		 struct latch_tree_root *root,
 		 const struct latch_tree_ops *ops)
 {
-	raw_write_seqcount_latch(&root->seq);
+	write_seqcount_latch_begin(&root->seq);
 	__lt_erase(node, root, 0);
-	raw_write_seqcount_latch(&root->seq);
+	write_seqcount_latch(&root->seq);
 	__lt_erase(node, root, 1);
+	write_seqcount_latch_end(&root->seq);
 }
 
 /**
@@ -204,9 +206,9 @@ latch_tree_find(void *key, struct latch_tree_root *root,
 	unsigned int seq;
 
 	do {
-		seq = raw_read_seqcount_latch(&root->seq);
+		seq = read_seqcount_latch(&root->seq);
 		node = __lt_find(key, root, seq & 1, ops->comp);
-	} while (raw_read_seqcount_latch_retry(&root->seq, seq));
+	} while (read_seqcount_latch_retry(&root->seq, seq));
 
 	return node;
 }
diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
index fffeb754880f..9c2751087185 100644
--- a/include/linux/seqlock.h
+++ b/include/linux/seqlock.h
@@ -621,6 +621,12 @@ static __always_inline unsigned raw_read_seqcount_latch(const seqcount_latch_t *
 	return READ_ONCE(s->seqcount.sequence);
 }
 
+static __always_inline unsigned read_seqcount_latch(const seqcount_latch_t *s)
+{
+	kcsan_atomic_next(KCSAN_SEQLOCK_REGION_MAX);
+	return raw_read_seqcount_latch(s);
+}
+
 /**
  * raw_read_seqcount_latch_retry() - end a seqcount_latch_t read section
  * @s:		Pointer to seqcount_latch_t
@@ -635,6 +641,13 @@ raw_read_seqcount_latch_retry(const seqcount_latch_t *s, unsigned start)
 	return unlikely(READ_ONCE(s->seqcount.sequence) != start);
 }
 
+static __always_inline int
+read_seqcount_latch_retry(const seqcount_latch_t *s, unsigned start)
+{
+	kcsan_atomic_next(0);
+	return raw_read_seqcount_latch_retry(s, start);
+}
+
 /**
  * raw_write_seqcount_latch() - redirect latch readers to even/odd copy
  * @s: Pointer to seqcount_latch_t
@@ -716,13 +729,29 @@ raw_read_seqcount_latch_retry(const seqcount_latch_t *s, unsigned start)
  *	When data is a dynamic data structure; one should use regular RCU
  *	patterns to manage the lifetimes of the objects within.
  */
-static inline void raw_write_seqcount_latch(seqcount_latch_t *s)
+static __always_inline void raw_write_seqcount_latch(seqcount_latch_t *s)
 {
 	smp_wmb();	/* prior stores before incrementing "sequence" */
 	s->seqcount.sequence++;
 	smp_wmb();      /* increment "sequence" before following stores */
 }
 
+static __always_inline void write_seqcount_latch_begin(seqcount_latch_t *s)
+{
+	kcsan_nestable_atomic_begin();
+	raw_write_seqcount_latch(s);
+}
+
+static __always_inline void write_seqcount_latch(seqcount_latch_t *s)
+{
+	raw_write_seqcount_latch(s);
+}
+
+static __always_inline void write_seqcount_latch_end(seqcount_latch_t *s)
+{
+	kcsan_nestable_atomic_end();
+}
+
 #define __SEQLOCK_UNLOCKED(lockname)					\
 	{								\
 		.seqcount = SEQCNT_SPINLOCK_ZERO(lockname, &(lockname).lock), \
diff --git a/kernel/printk/printk.c b/kernel/printk/printk.c
index beb808f4c367..19911c8fa7b6 100644
--- a/kernel/printk/printk.c
+++ b/kernel/printk/printk.c
@@ -560,10 +560,11 @@ bool printk_percpu_data_ready(void)
 /* Must be called under syslog_lock. */
 static void latched_seq_write(struct latched_seq *ls, u64 val)
 {
-	raw_write_seqcount_latch(&ls->latch);
+	write_seqcount_latch_begin(&ls->latch);
 	ls->val[0] = val;
-	raw_write_seqcount_latch(&ls->latch);
+	write_seqcount_latch(&ls->latch);
 	ls->val[1] = val;
+	write_seqcount_latch_end(&ls->latch);
 }
 
 /* Can be called from any context. */
@@ -574,10 +575,10 @@ static u64 latched_seq_read_nolock(struct latched_seq *ls)
 	u64 val;
 
 	do {
-		seq = raw_read_seqcount_latch(&ls->latch);
+		seq = read_seqcount_latch(&ls->latch);
 		idx = seq & 0x1;
 		val = ls->val[idx];
-	} while (raw_read_seqcount_latch_retry(&ls->latch, seq));
+	} while (read_seqcount_latch_retry(&ls->latch, seq));
 
 	return val;
 }
diff --git a/kernel/time/sched_clock.c b/kernel/time/sched_clock.c
index 68d6c1190ac7..4958b40ba6c9 100644
--- a/kernel/time/sched_clock.c
+++ b/kernel/time/sched_clock.c
@@ -71,13 +71,13 @@ static __always_inline u64 cyc_to_ns(u64 cyc, u32 mult, u32 shift)
 
 notrace struct clock_read_data *sched_clock_read_begin(unsigned int *seq)
 {
-	*seq = raw_read_seqcount_latch(&cd.seq);
+	*seq = read_seqcount_latch(&cd.seq);
 	return cd.read_data + (*seq & 1);
 }
 
 notrace int sched_clock_read_retry(unsigned int seq)
 {
-	return raw_read_seqcount_latch_retry(&cd.seq, seq);
+	return read_seqcount_latch_retry(&cd.seq, seq);
 }
 
 unsigned long long noinstr sched_clock_noinstr(void)
@@ -102,7 +102,9 @@ unsigned long long notrace sched_clock(void)
 {
 	unsigned long long ns;
 	preempt_disable_notrace();
+	kcsan_atomic_next(KCSAN_SEQLOCK_REGION_MAX);
 	ns = sched_clock_noinstr();
+	kcsan_atomic_next(0);
 	preempt_enable_notrace();
 	return ns;
 }
@@ -119,17 +121,19 @@ unsigned long long notrace sched_clock(void)
  */
 static void update_clock_read_data(struct clock_read_data *rd)
 {
-	/* update the backup (odd) copy with the new data */
-	cd.read_data[1] = *rd;
-
 	/* steer readers towards the odd copy */
-	raw_write_seqcount_latch(&cd.seq);
+	write_seqcount_latch_begin(&cd.seq);
 
 	/* now its safe for us to update the normal (even) copy */
 	cd.read_data[0] = *rd;
 
 	/* switch readers back to the even copy */
-	raw_write_seqcount_latch(&cd.seq);
+	write_seqcount_latch(&cd.seq);
+
+	/* update the backup (odd) copy with the new data */
+	cd.read_data[1] = *rd;
+
+	write_seqcount_latch_end(&cd.seq);
 }
 
 /*
@@ -267,7 +271,7 @@ void __init generic_sched_clock_init(void)
  */
 static u64 notrace suspended_sched_clock_read(void)
 {
-	unsigned int seq = raw_read_seqcount_latch(&cd.seq);
+	unsigned int seq = read_seqcount_latch(&cd.seq);
 
 	return cd.read_data[seq & 1].epoch_cyc;
 }
diff --git a/kernel/time/timekeeping.c b/kernel/time/timekeeping.c
index 7e6f409bf311..2ca26bfeb8f3 100644
--- a/kernel/time/timekeeping.c
+++ b/kernel/time/timekeeping.c
@@ -424,16 +424,18 @@ static void update_fast_timekeeper(const struct tk_read_base *tkr,
 	struct tk_read_base *base = tkf->base;
 
 	/* Force readers off to base[1] */
-	raw_write_seqcount_latch(&tkf->seq);
+	write_seqcount_latch_begin(&tkf->seq);
 
 	/* Update base[0] */
 	memcpy(base, tkr, sizeof(*base));
 
 	/* Force readers back to base[0] */
-	raw_write_seqcount_latch(&tkf->seq);
+	write_seqcount_latch(&tkf->seq);
 
 	/* Update base[1] */
 	memcpy(base + 1, base, sizeof(*base));
+
+	write_seqcount_latch_end(&tkf->seq);
 }
 
 static __always_inline u64 __ktime_get_fast_ns(struct tk_fast *tkf)
@@ -443,11 +445,11 @@ static __always_inline u64 __ktime_get_fast_ns(struct tk_fast *tkf)
 	u64 now;
 
 	do {
-		seq = raw_read_seqcount_latch(&tkf->seq);
+		seq = read_seqcount_latch(&tkf->seq);
 		tkr = tkf->base + (seq & 0x01);
 		now = ktime_to_ns(tkr->base);
 		now += __timekeeping_get_ns(tkr);
-	} while (raw_read_seqcount_latch_retry(&tkf->seq, seq));
+	} while (read_seqcount_latch_retry(&tkf->seq, seq));
 
 	return now;
 }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241030204815.GQ14555%40noisy.programming.kicks-ass.net.
