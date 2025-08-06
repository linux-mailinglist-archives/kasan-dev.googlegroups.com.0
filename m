Return-Path: <kasan-dev+bncBC7OBJGL2MHBBX5UZXCAMGQEMU72SEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 326FEB1C6DE
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Aug 2025 15:36:33 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-55b81da0daasf2845886e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Aug 2025 06:36:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754487392; cv=pass;
        d=google.com; s=arc-20240605;
        b=XjAipTd6A+1WcyYtHjmeQM8HySZ9biqFXNBGeZeA2UAPwk24dOrTHJJ1HkSoTCViXY
         +/kyOghgUPiFnhVrFhgbDCbDhtc1CZDCld926dQv1ihFgkK9ETpsyxR0Jhdle+bczPcR
         B8y4L2cnAkp1AP5iOzxuNvq0P9XO1DvTD/ZrFOpgGoU0+OIOkZL6ghmkCGtCIA/KeTq1
         W4K2iyXk2P6I+A+dHFJT7P14FbGnnIwb4ehJTqpDYpNKb6/EHp1y44tSGpIHXTyoUwX0
         W3/8k//OovyF4ALZxZeQIOk8JIslX6/+dzdHR0fOxV6ouOd4LARXWlP6tLk08Ogzbsvp
         qPFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=NLoNY7jmnLQP+mNQAaPrzk+vSUCPZKaCtWW/AcGvpIo=;
        fh=idPk5Vj7zG4MCDyeq+cmA5lhk/xC/msAII5GGfgGXuQ=;
        b=XEv/NAEISS9Fcq3675wYJPYgDABqwEje9CdFD9Y/MXh2MLnxH7Ec/hNa6gA3coYEE/
         MyDCyElGy/3pDs21/mXYFk2m8ZFxeYYOoKe19+0cCsZ1MP3U6xi4sVXymIZRShopr0VM
         /UrMAMHwOgBGw9hFO16q5gHxItmx1DFPx8nmAGbz9kC4HRxkc+CFl+pRGaw06sR6TNdd
         TbT2fQe6zmMGlLlQiZpeOLGDASu1U8pElEaQ7e9hLIRd4fIyfdr8xSiRCRcpH5A8DR6q
         rkI18aPo+j2uNrmBNhTnaIImn7R+drLbtNP7ZD8syJ1c7xY0K/OKpx//bheZztr1pFTY
         bSYQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=av54Eheu;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754487392; x=1755092192; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=NLoNY7jmnLQP+mNQAaPrzk+vSUCPZKaCtWW/AcGvpIo=;
        b=WeldzkqUqXHIR+cOx5uSJuecvtbV5oym5s0deV8wKqGodl7/3ZEKb3+NrcMRvICuX8
         VyTwfFzkG1rmRZJeyzEdjER3QYNN/0IvTfxc53l4tOikjP/up7qkV6qKzKvT8Jyqkpeh
         ipBs//QRaDFgVXGmuAyIHJ7zH0pYaLANPpvOWStVs/vElAKiMa0sMvCsrNdzWaNE48/K
         ifkO9mALHjGPjyMQ63V8jjhk+kzov6NHlgVMbzvExsQYd6TTrTlbzbjj4qWs5160mnZ5
         +ipXFs/fXAA2bsirFqJlEH7h0Gi7kRpZxXnD0NieEKvTWWe9g77Yt55ttOgXTisNfeSu
         uVdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754487392; x=1755092192;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NLoNY7jmnLQP+mNQAaPrzk+vSUCPZKaCtWW/AcGvpIo=;
        b=axNEDh8Fv8zG3Tr1kKPN1W8PgncePcgf0xdMtgMVDSXWX9htw9XyIBs1af+EzTWxpM
         J35oL1I2iJ4GUPGj5fJTrhBTm9Jj5IKwix5is6dLPjQN+cs5LPvG2IcMfLlLqyg8uYSt
         q5MYySxwvklrsQ2UI+KTUx9li4H2FfpYwANJhPRu5E8l1l0gBptmxpy9IFsH5VRCGTJ4
         x9JDpUodCFyBbvE9YoqaVIz60cAoetH7C24OGH0p2F7pz4BH2V5iGBYqpUrNE6hxI2YK
         CMkXHbfJDRkgwt1m4v4+cIajWMzJkqJlSRHhCYmFM3sY9MwDVlkECVZLzssKH2zffRi5
         J1ig==
X-Forwarded-Encrypted: i=2; AJvYcCUPRnbPAAZim4Zg9IzmjyMKs7hLc3+QYEE6nbCGayk7tMFn3ya8izgLFFtdXX0JmvfrxoaEiw==@lfdr.de
X-Gm-Message-State: AOJu0YzdsjtisHiKQxjVwK5OBYpdlPNcU/se85JMBAvuwFcCK9cfjlR2
	7Qajx/XryOfPK8yw+FZcMoM3QN62ZGt3ss2OQMEr5Hfy7/pxJj3bAL9R
X-Google-Smtp-Source: AGHT+IESZfqxpECUfJ+bhh8PfPO6uDtyaPqRSoQFS4qIsCjn1bwI6yyJDxtIZAYrZRbc6RvEBEUkZQ==
X-Received: by 2002:a05:6512:31cd:b0:55b:8f02:c9d0 with SMTP id 2adb3069b0e04-55caf1e8b6cmr912368e87.0.1754487391952;
        Wed, 06 Aug 2025 06:36:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdCkZDbgHtdhYh+YFGTYSE2maQEYPkfI5UOgCw5D4J49A==
Received: by 2002:ac2:58f7:0:b0:550:e048:74ff with SMTP id 2adb3069b0e04-55b87827697ls1252642e87.0.-pod-prod-06-eu;
 Wed, 06 Aug 2025 06:36:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVJEmcsynmU41SMngecZDedd7eTvc5TjKjZYLNZJjFKNYPb08RPiA9/Onm3udTaFzThrZLTicTHSak=@googlegroups.com
X-Received: by 2002:a05:6512:3402:b0:55b:8285:1eca with SMTP id 2adb3069b0e04-55caf2cdbe6mr946827e87.1.1754487388477;
        Wed, 06 Aug 2025 06:36:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754487388; cv=none;
        d=google.com; s=arc-20240605;
        b=ICPpQmxvPca29RvX6wSnzcvXzreYtbE5qYfF5ks0wiQBescfnAwT+RfbiqyE1iKSif
         FBxiquOtznrNHpeY/A2SzO+pzykTtbnpTUhmxWDjzur3oTUKVyKpXdg827065E9wLWTA
         OChPEaCqAQkutkhVLHToK3/AHRmKgH451MsgZ+r5sZRiyJBEkOAzxaPv3HFOm5YZIfMz
         E0JukBiRXkP9+9FXIwpP7atygxbY+RfJA31D0aE95zQ3VP7ft8Cg15KCDUcqqi/4YtU9
         DxeEOqs4d9j5gWbKFMO0MZoeDJ2SmfPxLgi2TwYv4B1T8H7csnLqXoBTSXHbFhS6bStz
         qBzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=0fLfQNanTpPrwYTh/p3ORoJw+sTRzGdPh+Aqm5jOtPI=;
        fh=nD/otvHxwNxHSqKA/GOHuQZeIcnxlTOMSNzoVOctxoE=;
        b=aDmc18KPONhgs/CXAWkOUtRZw4NXMpwWigAo7wSHRJD7DAyIHWgI2ypEwEOLm1go8y
         FVwycjjYsMLd8VOvuaTTUMinX1rJqw03u8o3GVZ+YJUA2rW5or/coXrsnqLfM54BA6Wj
         bIQoMUYk+9V7MOlBzuUCXMeA/3ICdLWULmhs6nG2jYdSPChy2WaCF4fqXKj1W09uHq+9
         TaAzRQCyxL6W/RINivFLxiyPaPTlBF+KyZYszcGQawsV9luq8WqlfT+VOiDwNhgZ8kfc
         EOKM1MtLyr2QmZ7VKh55C4zRF/UJ4AAMCn3hPXxCQFTmxbDvlYAnM6jEvSgnF1/Kvvrb
         j1Fg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=av54Eheu;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b9a222e4asi284339e87.5.2025.08.06.06.36.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Aug 2025 06:36:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id ffacd0b85a97d-3b8de193b60so2069930f8f.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Aug 2025 06:36:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUgJIoFKWulHNpYXnWwrO2XFWcH1afhvwkehaCze7RuRKPSMJcfCrkrivsBVNutvJFUS8eRNLq6k7g=@googlegroups.com
X-Gm-Gg: ASbGncvsQKNkEpghqc02Qi+Y204rLrWqv0n/MiYmJjzPYK4U5EB7/QjZpu+4VY/0iR3
	6xwDGQcasjWthn3EuJ3PUGU6wbGASi6cgZrcUx/pbtWbbBc2DquAG/pfNAkpZEGVI8bxeSmTOW/
	L2QY/3ppjTL8NwRJWfiww0UwMsTYPJUJBEBcdxFYI9POxfUS2NTQc8OPFTOxl4zjwGgWuKHeAuB
	msUCyzlI0vJ0re52+o9f13+PDutynS2pnlmoUsx4y3TKxPXWgSSRbklwW2Jdhitf/Pc/ddiOu/I
	vav4GmPVAKnC1Q5yKXwx72jcLXo9cSZNnROs++HqmJxUp5TAPhQfX7F9YJwzgNbJ1OQMdq1v6NV
	v2GKsW+7QRKpBUVCbTS7TT3B5bNKJWKESOwwtJ2gBqSCg/QF9rjTO1HDqbdI=
X-Received: by 2002:a05:6000:1a8f:b0:3b7:dd87:d730 with SMTP id ffacd0b85a97d-3b8f420f051mr2451935f8f.52.1754487387380;
        Wed, 06 Aug 2025 06:36:27 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:2834:9:5667:3708:660c:31f5])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-458953cfd10sm313688645e9.21.2025.08.06.06.36.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Aug 2025 06:36:26 -0700 (PDT)
Date: Wed, 6 Aug 2025 15:36:19 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: "David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>,
	Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ingo Molnar <mingo@kernel.org>, Jann Horn <jannh@google.com>,
	Jiri Slaby <jirislaby@kernel.org>,
	Joel Fernandes <joel@joelfernandes.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Kentaro Takeda <takedakn@nttdata.co.jp>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Thomas Gleixner <tglx@linutronix.de>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	Christoph Hellwig <hch@lst.de>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev,
	rcu@vger.kernel.org, linux-crypto@vger.kernel.org,
	linux-serial@vger.kernel.org
Subject: Re: [PATCH v2 00/34] Compiler-Based Capability- and Locking-Analysis
Message-ID: <aJNaUwoDjuGfplLm@elver.google.com>
References: <20250304092417.2873893-1-elver@google.com>
 <20250305112041.GA16878@noisy.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250305112041.GA16878@noisy.programming.kicks-ass.net>
User-Agent: Mutt/2.2.13 (2024-03-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=av54Eheu;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Mar 05, 2025 at 12:20PM +0100, Peter Zijlstra wrote:
> 
> Right, so since this is all awesome, I figured I should try and have it
> compile kernel/sched/, see how far I get.
> 
[...]

It's been a while, but teaching Clang new tricks for this analysis has
been taking its time (and I've only been looking into this on and off).

Anyway, Clang has already gained __attribute__((reentrant_capability).
Of course, that alone doesn't quite help that much.
But what we really wanted, I think, per this Clang discussion thread
[1], was some "simple" form of intra-procedural alias analysis.

[1] https://lore.kernel.org/all/CANpmjNPquO=W1JAh1FNQb8pMQjgeZAKCPQUAd7qUg=5pjJ6x=Q@mail.gmail.com/

Anyway, this evolving Clang PR probably gets us pretty close:
 https://github.com/llvm/llvm-project/pull/142955

With Clang from that PR, I can compile kernel/sched/{core.c, fair.c}
with modest changes (see below - work in progress) without warnings.
Notably, this can also deal with "capability acquired in returned
object" with some macro magic.

The full v3 series preview is here:
https://git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git/log/?h=cap-analysis/dev

The whole tree compiles cleanly, although I might have missed testing
some kernel configs.

If/when that Clang PR lands (~ETA another month probably), I would think
about sending the next version of this series.

Thanks,
-- Marco

------ >8 ------

From: Marco Elver <elver@google.com>
Date: Sun, 3 Aug 2025 20:21:39 +0200
Subject: [PATCH] sched: Enable capability analysis for core.c and fair.c

This demonstrates a larger conversion to use Clang's capability
analysis. The benefit is additional static checking of locking rules,
along with better documentation.

Arguably, kernel/sched is the "final boss" of Clang's capability
analysis, and application to core.c & fair.c demonstrates that the
latest Clang version has become powerful enough to start applying this
to more complex subsystems (with some modest annotations and changes).

Signed-off-by: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@redhat.com>
---
v3:
* New patch.
---
 include/linux/sched.h                       |   6 +-
 include/linux/sched/signal.h                |   4 +-
 include/linux/sched/task.h                  |   5 +-
 include/linux/sched/wake_q.h                |   3 +
 kernel/sched/Makefile                       |   3 +
 kernel/sched/core.c                         |  82 ++++++++++-----
 kernel/sched/fair.c                         |   6 +-
 kernel/sched/sched.h                        | 108 +++++++++++++-------
 scripts/capability-analysis-suppression.txt |   1 +
 9 files changed, 148 insertions(+), 70 deletions(-)

diff --git a/include/linux/sched.h b/include/linux/sched.h
index aa9c5be7a632..3ac9d2407773 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -2125,9 +2125,9 @@ static inline int _cond_resched(void)
 	_cond_resched();			\
 })
 
-extern int __cond_resched_lock(spinlock_t *lock);
-extern int __cond_resched_rwlock_read(rwlock_t *lock);
-extern int __cond_resched_rwlock_write(rwlock_t *lock);
+extern int __cond_resched_lock(spinlock_t *lock) __must_hold(lock);
+extern int __cond_resched_rwlock_read(rwlock_t *lock) __must_hold_shared(lock);
+extern int __cond_resched_rwlock_write(rwlock_t *lock) __must_hold(lock);
 
 #define MIGHT_RESCHED_RCU_SHIFT		8
 #define MIGHT_RESCHED_PREEMPT_MASK	((1U << MIGHT_RESCHED_RCU_SHIFT) - 1)
diff --git a/include/linux/sched/signal.h b/include/linux/sched/signal.h
index bc7f83b012fb..6f581a750e84 100644
--- a/include/linux/sched/signal.h
+++ b/include/linux/sched/signal.h
@@ -734,10 +734,12 @@ static inline int thread_group_empty(struct task_struct *p)
 		(thread_group_leader(p) && !thread_group_empty(p))
 
 extern struct sighand_struct *lock_task_sighand(struct task_struct *task,
-						unsigned long *flags);
+						unsigned long *flags)
+	__acquires(&task->sighand->siglock);
 
 static inline void unlock_task_sighand(struct task_struct *task,
 						unsigned long *flags)
+	__releases(&task->sighand->siglock)
 {
 	spin_unlock_irqrestore(&task->sighand->siglock, *flags);
 }
diff --git a/include/linux/sched/task.h b/include/linux/sched/task.h
index ca1db4b92c32..a4373fc687bd 100644
--- a/include/linux/sched/task.h
+++ b/include/linux/sched/task.h
@@ -226,15 +226,18 @@ static inline struct vm_struct *task_stack_vm_area(const struct task_struct *t)
  * neither inside nor outside.
  */
 static inline void task_lock(struct task_struct *p)
+	__acquires(&p->alloc_lock)
 {
 	spin_lock(&p->alloc_lock);
 }
 
 static inline void task_unlock(struct task_struct *p)
+	__releases(&p->alloc_lock)
 {
 	spin_unlock(&p->alloc_lock);
 }
 
-DEFINE_GUARD(task_lock, struct task_struct *, task_lock(_T), task_unlock(_T))
+DEFINE_LOCK_GUARD_1(task_lock, struct task_struct, task_lock(_T->lock), task_unlock(_T->lock))
+DECLARE_LOCK_GUARD_1_ATTRS(task_lock, __assumes_cap(_T->alloc_lock), /* */)
 
 #endif /* _LINUX_SCHED_TASK_H */
diff --git a/include/linux/sched/wake_q.h b/include/linux/sched/wake_q.h
index 0f28b4623ad4..765bbc3d54be 100644
--- a/include/linux/sched/wake_q.h
+++ b/include/linux/sched/wake_q.h
@@ -66,6 +66,7 @@ extern void wake_up_q(struct wake_q_head *head);
 /* Spin unlock helpers to unlock and call wake_up_q with preempt disabled */
 static inline
 void raw_spin_unlock_wake(raw_spinlock_t *lock, struct wake_q_head *wake_q)
+	__releases(lock)
 {
 	guard(preempt)();
 	raw_spin_unlock(lock);
@@ -77,6 +78,7 @@ void raw_spin_unlock_wake(raw_spinlock_t *lock, struct wake_q_head *wake_q)
 
 static inline
 void raw_spin_unlock_irq_wake(raw_spinlock_t *lock, struct wake_q_head *wake_q)
+	__releases(lock)
 {
 	guard(preempt)();
 	raw_spin_unlock_irq(lock);
@@ -89,6 +91,7 @@ void raw_spin_unlock_irq_wake(raw_spinlock_t *lock, struct wake_q_head *wake_q)
 static inline
 void raw_spin_unlock_irqrestore_wake(raw_spinlock_t *lock, unsigned long flags,
 				     struct wake_q_head *wake_q)
+	__releases(lock)
 {
 	guard(preempt)();
 	raw_spin_unlock_irqrestore(lock, flags);
diff --git a/kernel/sched/Makefile b/kernel/sched/Makefile
index 8ae86371ddcd..8603987ce4c1 100644
--- a/kernel/sched/Makefile
+++ b/kernel/sched/Makefile
@@ -1,5 +1,8 @@
 # SPDX-License-Identifier: GPL-2.0
 
+CAPABILITY_ANALYSIS_core.o := y
+CAPABILITY_ANALYSIS_fair.o := y
+
 # The compilers are complaining about unused variables inside an if(0) scope
 # block. This is daft, shut them up.
 ccflags-y += $(call cc-disable-warning, unused-but-set-variable)
diff --git a/kernel/sched/core.c b/kernel/sched/core.c
index 81c6df746df1..0182d0246f44 100644
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -664,16 +664,17 @@ void double_rq_lock(struct rq *rq1, struct rq *rq2)
 	raw_spin_rq_lock(rq1);
 	if (__rq_lockp(rq1) != __rq_lockp(rq2))
 		raw_spin_rq_lock_nested(rq2, SINGLE_DEPTH_NESTING);
+	else
+		__acquire_cap(__rq_lockp(rq2)); /* fake acquire */
 
 	double_rq_clock_clear_update(rq1, rq2);
 }
 #endif
 
 /*
- * __task_rq_lock - lock the rq @p resides on.
+ * ___task_rq_lock - lock the rq @p resides on.
  */
-struct rq *__task_rq_lock(struct task_struct *p, struct rq_flags *rf)
-	__acquires(rq->lock)
+struct rq *___task_rq_lock(struct task_struct *p, struct rq_flags *rf)
 {
 	struct rq *rq;
 
@@ -696,9 +697,7 @@ struct rq *__task_rq_lock(struct task_struct *p, struct rq_flags *rf)
 /*
  * task_rq_lock - lock p->pi_lock and lock the rq @p resides on.
  */
-struct rq *task_rq_lock(struct task_struct *p, struct rq_flags *rf)
-	__acquires(p->pi_lock)
-	__acquires(rq->lock)
+struct rq *_task_rq_lock(struct task_struct *p, struct rq_flags *rf)
 {
 	struct rq *rq;
 
@@ -2494,6 +2493,7 @@ static inline bool is_cpu_allowed(struct task_struct *p, int cpu)
  */
 static struct rq *move_queued_task(struct rq *rq, struct rq_flags *rf,
 				   struct task_struct *p, int new_cpu)
+	__must_hold(&rq->__lock)
 {
 	lockdep_assert_rq_held(rq);
 
@@ -2540,6 +2540,7 @@ struct set_affinity_pending {
  */
 static struct rq *__migrate_task(struct rq *rq, struct rq_flags *rf,
 				 struct task_struct *p, int dest_cpu)
+	__must_hold(&rq->__lock)
 {
 	/* Affinity changed (again). */
 	if (!is_cpu_allowed(p, dest_cpu))
@@ -2576,6 +2577,12 @@ static int migration_cpu_stop(void *data)
 	 */
 	flush_smp_call_function_queue();
 
+	/*
+	 * We may change the underlying rq, but the locks held will
+	 * appropriately be "transferred" when switching.
+	 */
+	capability_unsafe_alias(rq);
+
 	raw_spin_lock(&p->pi_lock);
 	rq_lock(rq, &rf);
 
@@ -2685,6 +2692,8 @@ int push_cpu_stop(void *arg)
 	if (!lowest_rq)
 		goto out_unlock;
 
+	lockdep_assert_rq_held(lowest_rq);
+
 	// XXX validate p is still the highest prio task
 	if (task_rq(p) == rq) {
 		move_queued_task_locked(rq, lowest_rq, p);
@@ -2930,8 +2939,7 @@ void release_user_cpus_ptr(struct task_struct *p)
  */
 static int affine_move_task(struct rq *rq, struct task_struct *p, struct rq_flags *rf,
 			    int dest_cpu, unsigned int flags)
-	__releases(rq->lock)
-	__releases(p->pi_lock)
+	__releases(&rq->__lock, &p->pi_lock)
 {
 	struct set_affinity_pending my_pending = { }, *pending = NULL;
 	bool stop_pending, complete = false;
@@ -3079,8 +3087,7 @@ static int __set_cpus_allowed_ptr_locked(struct task_struct *p,
 					 struct affinity_context *ctx,
 					 struct rq *rq,
 					 struct rq_flags *rf)
-	__releases(rq->lock)
-	__releases(p->pi_lock)
+	__releases(&rq->__lock, &p->pi_lock)
 {
 	const struct cpumask *cpu_allowed_mask = task_cpu_possible_mask(p);
 	const struct cpumask *cpu_valid_mask = cpu_active_mask;
@@ -4400,29 +4407,30 @@ static bool __task_needs_rq_lock(struct task_struct *p)
  */
 int task_call_func(struct task_struct *p, task_call_f func, void *arg)
 {
-	struct rq *rq = NULL;
 	struct rq_flags rf;
 	int ret;
 
 	raw_spin_lock_irqsave(&p->pi_lock, rf.flags);
 
-	if (__task_needs_rq_lock(p))
-		rq = __task_rq_lock(p, &rf);
+	if (__task_needs_rq_lock(p)) {
+		struct rq *rq = __task_rq_lock(p, &rf);
 
-	/*
-	 * At this point the task is pinned; either:
-	 *  - blocked and we're holding off wakeups	 (pi->lock)
-	 *  - woken, and we're holding off enqueue	 (rq->lock)
-	 *  - queued, and we're holding off schedule	 (rq->lock)
-	 *  - running, and we're holding off de-schedule (rq->lock)
-	 *
-	 * The called function (@func) can use: task_curr(), p->on_rq and
-	 * p->__state to differentiate between these states.
-	 */
-	ret = func(p, arg);
+		/*
+		 * At this point the task is pinned; either:
+		 *  - blocked and we're holding off wakeups	 (pi->lock)
+		 *  - woken, and we're holding off enqueue	 (rq->lock)
+		 *  - queued, and we're holding off schedule	 (rq->lock)
+		 *  - running, and we're holding off de-schedule (rq->lock)
+		 *
+		 * The called function (@func) can use: task_curr(), p->on_rq and
+		 * p->__state to differentiate between these states.
+		 */
+		ret = func(p, arg);
 
-	if (rq)
 		rq_unlock(rq, &rf);
+	} else {
+		ret = func(p, arg);
+	}
 
 	raw_spin_unlock_irqrestore(&p->pi_lock, rf.flags);
 	return ret;
@@ -5118,6 +5126,8 @@ static inline void __balance_callbacks(struct rq *rq)
 
 static inline void
 prepare_lock_switch(struct rq *rq, struct task_struct *next, struct rq_flags *rf)
+	__releases(__rq_lockp(rq))
+	__acquires(__rq_lockp(this_rq()))
 {
 	/*
 	 * Since the runqueue lock will be released by the next
@@ -5131,9 +5141,15 @@ prepare_lock_switch(struct rq *rq, struct task_struct *next, struct rq_flags *rf
 	/* this is a valid case when another task releases the spinlock */
 	rq_lockp(rq)->owner = next;
 #endif
+	/*
+	 * Model the rq reference switcheroo.
+	 */
+	__release(__rq_lockp(rq));
+	__acquire(__rq_lockp(this_rq()));
 }
 
 static inline void finish_lock_switch(struct rq *rq)
+	__releases(&rq->__lock)
 {
 	/*
 	 * If we are tracking spinlock dependencies then we have to
@@ -5189,6 +5205,7 @@ static inline void kmap_local_sched_in(void)
 static inline void
 prepare_task_switch(struct rq *rq, struct task_struct *prev,
 		    struct task_struct *next)
+	__must_hold(&rq->__lock)
 {
 	kcov_prepare_switch(prev);
 	sched_info_switch(rq, prev, next);
@@ -5220,7 +5237,7 @@ prepare_task_switch(struct rq *rq, struct task_struct *prev,
  * because prev may have moved to another CPU.
  */
 static struct rq *finish_task_switch(struct task_struct *prev)
-	__releases(rq->lock)
+	__releases(__rq_lockp(this_rq()))
 {
 	struct rq *rq = this_rq();
 	struct mm_struct *mm = rq->prev_mm;
@@ -5308,7 +5325,7 @@ static struct rq *finish_task_switch(struct task_struct *prev)
  * @prev: the thread we just switched away from.
  */
 asmlinkage __visible void schedule_tail(struct task_struct *prev)
-	__releases(rq->lock)
+	__releases(&this_rq()->__lock)
 {
 	/*
 	 * New tasks start with FORK_PREEMPT_COUNT, see there and
@@ -5340,6 +5357,7 @@ asmlinkage __visible void schedule_tail(struct task_struct *prev)
 static __always_inline struct rq *
 context_switch(struct rq *rq, struct task_struct *prev,
 	       struct task_struct *next, struct rq_flags *rf)
+	__releases(&rq->__lock)
 {
 	prepare_task_switch(rq, prev, next);
 
@@ -6026,6 +6044,7 @@ static void prev_balance(struct rq *rq, struct task_struct *prev,
  */
 static inline struct task_struct *
 __pick_next_task(struct rq *rq, struct task_struct *prev, struct rq_flags *rf)
+	__must_hold(__rq_lockp(rq))
 {
 	const struct sched_class *class;
 	struct task_struct *p;
@@ -6118,6 +6137,7 @@ static void queue_core_balance(struct rq *rq);
 
 static struct task_struct *
 pick_next_task(struct rq *rq, struct task_struct *prev, struct rq_flags *rf)
+	__must_hold(__rq_lockp(rq))
 {
 	struct task_struct *next, *p, *max = NULL;
 	const struct cpumask *smt_mask;
@@ -6562,6 +6582,7 @@ static inline void sched_core_cpu_dying(unsigned int cpu) {}
 
 static struct task_struct *
 pick_next_task(struct rq *rq, struct task_struct *prev, struct rq_flags *rf)
+	__must_hold(__rq_lockp(rq))
 {
 	return __pick_next_task(rq, prev, rf);
 }
@@ -8004,6 +8025,12 @@ static int __balance_push_cpu_stop(void *arg)
 	struct rq_flags rf;
 	int cpu;
 
+	/*
+	 * We may change the underlying rq, but the locks held will
+	 * appropriately be "transferred" when switching.
+	 */
+	capability_unsafe_alias(rq);
+
 	raw_spin_lock_irq(&p->pi_lock);
 	rq_lock(rq, &rf);
 
@@ -8031,6 +8058,7 @@ static DEFINE_PER_CPU(struct cpu_stop_work, push_work);
  * effective when the hotplug motion is down.
  */
 static void balance_push(struct rq *rq)
+	__must_hold(&rq->__lock)
 {
 	struct task_struct *push_task = rq->curr;
 
diff --git a/kernel/sched/fair.c b/kernel/sched/fair.c
index 7a14da5396fb..260158287ddb 100644
--- a/kernel/sched/fair.c
+++ b/kernel/sched/fair.c
@@ -4842,7 +4842,8 @@ static inline unsigned long cfs_rq_load_avg(struct cfs_rq *cfs_rq)
 	return cfs_rq->avg.load_avg;
 }
 
-static int sched_balance_newidle(struct rq *this_rq, struct rq_flags *rf);
+static int sched_balance_newidle(struct rq *this_rq, struct rq_flags *rf)
+	__must_hold(__rq_lockp(this_rq));
 
 static inline unsigned long task_util(struct task_struct *p)
 {
@@ -8737,6 +8738,7 @@ static void set_cpus_allowed_fair(struct task_struct *p, struct affinity_context
 
 static int
 balance_fair(struct rq *rq, struct task_struct *prev, struct rq_flags *rf)
+	__must_hold(__rq_lockp(rq))
 {
 	if (sched_fair_runnable(rq))
 		return 1;
@@ -8884,6 +8886,7 @@ static void set_next_task_fair(struct rq *rq, struct task_struct *p, bool first)
 
 struct task_struct *
 pick_next_task_fair(struct rq *rq, struct task_struct *prev, struct rq_flags *rf)
+	__must_hold(__rq_lockp(rq))
 {
 	struct sched_entity *se;
 	struct task_struct *p;
@@ -8970,6 +8973,7 @@ pick_next_task_fair(struct rq *rq, struct task_struct *prev, struct rq_flags *rf
 }
 
 static struct task_struct *__pick_next_task_fair(struct rq *rq, struct task_struct *prev)
+	__must_hold(__rq_lockp(rq))
 {
 	return pick_next_task_fair(rq, prev, NULL);
 }
diff --git a/kernel/sched/sched.h b/kernel/sched/sched.h
index 83e3aa917142..0da7c8b89030 100644
--- a/kernel/sched/sched.h
+++ b/kernel/sched/sched.h
@@ -1343,8 +1343,13 @@ static inline bool is_migration_disabled(struct task_struct *p)
 
 DECLARE_PER_CPU_SHARED_ALIGNED(struct rq, runqueues);
 
+static __always_inline struct rq *__this_rq(void)
+{
+	return this_cpu_ptr(&runqueues);
+}
+
 #define cpu_rq(cpu)		(&per_cpu(runqueues, (cpu)))
-#define this_rq()		this_cpu_ptr(&runqueues)
+#define this_rq()		__this_rq()
 #define task_rq(p)		cpu_rq(task_cpu(p))
 #define cpu_curr(cpu)		(cpu_rq(cpu)->curr)
 #define raw_rq()		raw_cpu_ptr(&runqueues)
@@ -1473,11 +1478,13 @@ static inline bool sched_core_disabled(void)
 }
 
 static inline raw_spinlock_t *rq_lockp(struct rq *rq)
+	__returns_cap(&rq->__lock)
 {
 	return &rq->__lock;
 }
 
 static inline raw_spinlock_t *__rq_lockp(struct rq *rq)
+	__returns_cap(&rq->__lock)
 {
 	return &rq->__lock;
 }
@@ -1519,32 +1526,42 @@ static inline bool rt_group_sched_enabled(void)
 #endif /* CONFIG_RT_GROUP_SCHED */
 
 static inline void lockdep_assert_rq_held(struct rq *rq)
+	__assumes_cap(__rq_lockp(rq))
 {
 	lockdep_assert_held(__rq_lockp(rq));
 }
 
-extern void raw_spin_rq_lock_nested(struct rq *rq, int subclass);
-extern bool raw_spin_rq_trylock(struct rq *rq);
-extern void raw_spin_rq_unlock(struct rq *rq);
+extern void raw_spin_rq_lock_nested(struct rq *rq, int subclass)
+	__acquires(&rq->__lock);
+
+extern bool raw_spin_rq_trylock(struct rq *rq)
+	__cond_acquires(true, &rq->__lock);
+
+extern void raw_spin_rq_unlock(struct rq *rq)
+	__releases(&rq->__lock);
 
 static inline void raw_spin_rq_lock(struct rq *rq)
+	__acquires(&rq->__lock)
 {
 	raw_spin_rq_lock_nested(rq, 0);
 }
 
 static inline void raw_spin_rq_lock_irq(struct rq *rq)
+	__acquires(&rq->__lock)
 {
 	local_irq_disable();
 	raw_spin_rq_lock(rq);
 }
 
 static inline void raw_spin_rq_unlock_irq(struct rq *rq)
+	__releases(&rq->__lock)
 {
 	raw_spin_rq_unlock(rq);
 	local_irq_enable();
 }
 
 static inline unsigned long _raw_spin_rq_lock_irqsave(struct rq *rq)
+	__acquires(&rq->__lock)
 {
 	unsigned long flags;
 
@@ -1555,6 +1572,7 @@ static inline unsigned long _raw_spin_rq_lock_irqsave(struct rq *rq)
 }
 
 static inline void raw_spin_rq_unlock_irqrestore(struct rq *rq, unsigned long flags)
+	__releases(&rq->__lock)
 {
 	raw_spin_rq_unlock(rq);
 	local_irq_restore(flags);
@@ -1805,17 +1823,15 @@ static inline void rq_repin_lock(struct rq *rq, struct rq_flags *rf)
 	rq->clock_update_flags |= rf->clock_update_flags;
 }
 
-extern
-struct rq *__task_rq_lock(struct task_struct *p, struct rq_flags *rf)
-	__acquires(rq->lock);
+#define __task_rq_lock(...) __acquire_ret(___task_rq_lock(__VA_ARGS__), &__ret->__lock)
+extern struct rq *___task_rq_lock(struct task_struct *p, struct rq_flags *rf) __acquires_ret;
 
-extern
-struct rq *task_rq_lock(struct task_struct *p, struct rq_flags *rf)
-	__acquires(p->pi_lock)
-	__acquires(rq->lock);
+#define task_rq_lock(...) __acquire_ret(_task_rq_lock(__VA_ARGS__), &__ret->__lock)
+extern struct rq *_task_rq_lock(struct task_struct *p, struct rq_flags *rf)
+	__acquires(&p->pi_lock) __acquires_ret;
 
 static inline void __task_rq_unlock(struct rq *rq, struct rq_flags *rf)
-	__releases(rq->lock)
+	__releases(&rq->__lock)
 {
 	rq_unpin_lock(rq, rf);
 	raw_spin_rq_unlock(rq);
@@ -1823,8 +1839,7 @@ static inline void __task_rq_unlock(struct rq *rq, struct rq_flags *rf)
 
 static inline void
 task_rq_unlock(struct rq *rq, struct task_struct *p, struct rq_flags *rf)
-	__releases(rq->lock)
-	__releases(p->pi_lock)
+	__releases(&rq->__lock, &p->pi_lock)
 {
 	rq_unpin_lock(rq, rf);
 	raw_spin_rq_unlock(rq);
@@ -1835,44 +1850,45 @@ DEFINE_LOCK_GUARD_1(task_rq_lock, struct task_struct,
 		    _T->rq = task_rq_lock(_T->lock, &_T->rf),
 		    task_rq_unlock(_T->rq, _T->lock, &_T->rf),
 		    struct rq *rq; struct rq_flags rf)
+DECLARE_LOCK_GUARD_1_ATTRS(task_rq_lock, __assumes_cap(_T->pi_lock), /* */)
 
 static inline void rq_lock_irqsave(struct rq *rq, struct rq_flags *rf)
-	__acquires(rq->lock)
+	__acquires(&rq->__lock)
 {
 	raw_spin_rq_lock_irqsave(rq, rf->flags);
 	rq_pin_lock(rq, rf);
 }
 
 static inline void rq_lock_irq(struct rq *rq, struct rq_flags *rf)
-	__acquires(rq->lock)
+	__acquires(&rq->__lock)
 {
 	raw_spin_rq_lock_irq(rq);
 	rq_pin_lock(rq, rf);
 }
 
 static inline void rq_lock(struct rq *rq, struct rq_flags *rf)
-	__acquires(rq->lock)
+	__acquires(&rq->__lock)
 {
 	raw_spin_rq_lock(rq);
 	rq_pin_lock(rq, rf);
 }
 
 static inline void rq_unlock_irqrestore(struct rq *rq, struct rq_flags *rf)
-	__releases(rq->lock)
+	__releases(&rq->__lock)
 {
 	rq_unpin_lock(rq, rf);
 	raw_spin_rq_unlock_irqrestore(rq, rf->flags);
 }
 
 static inline void rq_unlock_irq(struct rq *rq, struct rq_flags *rf)
-	__releases(rq->lock)
+	__releases(&rq->__lock)
 {
 	rq_unpin_lock(rq, rf);
 	raw_spin_rq_unlock_irq(rq);
 }
 
 static inline void rq_unlock(struct rq *rq, struct rq_flags *rf)
-	__releases(rq->lock)
+	__releases(&rq->__lock)
 {
 	rq_unpin_lock(rq, rf);
 	raw_spin_rq_unlock(rq);
@@ -1883,18 +1899,24 @@ DEFINE_LOCK_GUARD_1(rq_lock, struct rq,
 		    rq_unlock(_T->lock, &_T->rf),
 		    struct rq_flags rf)
 
+DECLARE_LOCK_GUARD_1_ATTRS(rq_lock, __assumes_cap(_T->__lock), /* */);
+
 DEFINE_LOCK_GUARD_1(rq_lock_irq, struct rq,
 		    rq_lock_irq(_T->lock, &_T->rf),
 		    rq_unlock_irq(_T->lock, &_T->rf),
 		    struct rq_flags rf)
 
+DECLARE_LOCK_GUARD_1_ATTRS(rq_lock_irq, __assumes_cap(_T->__lock), /* */);
+
 DEFINE_LOCK_GUARD_1(rq_lock_irqsave, struct rq,
 		    rq_lock_irqsave(_T->lock, &_T->rf),
 		    rq_unlock_irqrestore(_T->lock, &_T->rf),
 		    struct rq_flags rf)
 
-static inline struct rq *this_rq_lock_irq(struct rq_flags *rf)
-	__acquires(rq->lock)
+DECLARE_LOCK_GUARD_1_ATTRS(rq_lock_irqsave, __assumes_cap(_T->__lock), /* */);
+
+#define this_rq_lock_irq(...) __acquire_ret(_this_rq_lock_irq(__VA_ARGS__), &__ret->__lock)
+static inline struct rq *_this_rq_lock_irq(struct rq_flags *rf) __acquires_ret
 {
 	struct rq *rq;
 
@@ -2927,9 +2949,15 @@ static inline void double_rq_clock_clear_update(struct rq *rq1, struct rq *rq2)
 #define DEFINE_LOCK_GUARD_2(name, type, _lock, _unlock, ...)				\
 __DEFINE_UNLOCK_GUARD(name, type, _unlock, type *lock2; __VA_ARGS__)			\
 static inline class_##name##_t class_##name##_constructor(type *lock, type *lock2)	\
+	__no_capability_analysis							\
 { class_##name##_t _t = { .lock = lock, .lock2 = lock2 }, *_T = &_t;			\
   _lock; return _t; }
 
+#define DECLARE_LOCK_GUARD_2_ATTRS(_name, _lock, _unlock) \
+static inline class_##_name##_t class_##_name##_constructor(lock_##_name##_t *_T1, \
+							    lock_##_name##_t *_T2) _lock; \
+static inline void class_##_name##_destructor(class_##_name##_t *_T) _unlock
+
 #ifdef CONFIG_SMP
 
 static inline bool rq_order_less(struct rq *rq1, struct rq *rq2)
@@ -2958,7 +2986,8 @@ static inline bool rq_order_less(struct rq *rq1, struct rq *rq2)
 	return rq1->cpu < rq2->cpu;
 }
 
-extern void double_rq_lock(struct rq *rq1, struct rq *rq2);
+extern void double_rq_lock(struct rq *rq1, struct rq *rq2)
+	__acquires(&rq1->__lock, &rq2->__lock);
 
 #ifdef CONFIG_PREEMPTION
 
@@ -2971,9 +3000,8 @@ extern void double_rq_lock(struct rq *rq1, struct rq *rq2);
  * also adds more overhead and therefore may reduce throughput.
  */
 static inline int _double_lock_balance(struct rq *this_rq, struct rq *busiest)
-	__releases(this_rq->lock)
-	__acquires(busiest->lock)
-	__acquires(this_rq->lock)
+	__must_hold(&this_rq->__lock)
+	__acquires(&busiest->__lock)
 {
 	raw_spin_rq_unlock(this_rq);
 	double_rq_lock(this_rq, busiest);
@@ -2990,9 +3018,8 @@ static inline int _double_lock_balance(struct rq *this_rq, struct rq *busiest)
  * regardless of entry order into the function.
  */
 static inline int _double_lock_balance(struct rq *this_rq, struct rq *busiest)
-	__releases(this_rq->lock)
-	__acquires(busiest->lock)
-	__acquires(this_rq->lock)
+	__must_hold(&this_rq->__lock)
+	__acquires(&busiest->__lock)
 {
 	if (__rq_lockp(this_rq) == __rq_lockp(busiest) ||
 	    likely(raw_spin_rq_trylock(busiest))) {
@@ -3018,6 +3045,8 @@ static inline int _double_lock_balance(struct rq *this_rq, struct rq *busiest)
  * double_lock_balance - lock the busiest runqueue, this_rq is locked already.
  */
 static inline int double_lock_balance(struct rq *this_rq, struct rq *busiest)
+	__must_hold(&this_rq->__lock)
+	__acquires(&busiest->__lock)
 {
 	lockdep_assert_irqs_disabled();
 
@@ -3025,14 +3054,17 @@ static inline int double_lock_balance(struct rq *this_rq, struct rq *busiest)
 }
 
 static inline void double_unlock_balance(struct rq *this_rq, struct rq *busiest)
-	__releases(busiest->lock)
+	__releases(&busiest->__lock)
 {
 	if (__rq_lockp(this_rq) != __rq_lockp(busiest))
 		raw_spin_rq_unlock(busiest);
+	else
+		__release(__rq_lockp(busiest)); /* fake release */
 	lock_set_subclass(&__rq_lockp(this_rq)->dep_map, 0, _RET_IP_);
 }
 
 static inline void double_lock(spinlock_t *l1, spinlock_t *l2)
+	__acquires(l1, l2)
 {
 	if (l1 > l2)
 		swap(l1, l2);
@@ -3042,6 +3074,7 @@ static inline void double_lock(spinlock_t *l1, spinlock_t *l2)
 }
 
 static inline void double_lock_irq(spinlock_t *l1, spinlock_t *l2)
+	__acquires(l1, l2)
 {
 	if (l1 > l2)
 		swap(l1, l2);
@@ -3051,6 +3084,7 @@ static inline void double_lock_irq(spinlock_t *l1, spinlock_t *l2)
 }
 
 static inline void double_raw_lock(raw_spinlock_t *l1, raw_spinlock_t *l2)
+	__acquires(l1, l2)
 {
 	if (l1 > l2)
 		swap(l1, l2);
@@ -3060,6 +3094,7 @@ static inline void double_raw_lock(raw_spinlock_t *l1, raw_spinlock_t *l2)
 }
 
 static inline void double_raw_unlock(raw_spinlock_t *l1, raw_spinlock_t *l2)
+	__releases(l1, l2)
 {
 	raw_spin_unlock(l1);
 	raw_spin_unlock(l2);
@@ -3069,6 +3104,8 @@ DEFINE_LOCK_GUARD_2(double_raw_spinlock, raw_spinlock_t,
 		    double_raw_lock(_T->lock, _T->lock2),
 		    double_raw_unlock(_T->lock, _T->lock2))
 
+DECLARE_LOCK_GUARD_2_ATTRS(double_raw_spinlock, __assumes_cap(_T1) __assumes_cap(_T2), /* */);
+
 /*
  * double_rq_unlock - safely unlock two runqueues
  *
@@ -3076,13 +3113,12 @@ DEFINE_LOCK_GUARD_2(double_raw_spinlock, raw_spinlock_t,
  * you need to do so manually after calling.
  */
 static inline void double_rq_unlock(struct rq *rq1, struct rq *rq2)
-	__releases(rq1->lock)
-	__releases(rq2->lock)
+	__releases(&rq1->__lock, &rq2->__lock)
 {
 	if (__rq_lockp(rq1) != __rq_lockp(rq2))
 		raw_spin_rq_unlock(rq2);
 	else
-		__release(rq2->lock);
+		__release(&rq2->__lock); /* fake release */
 	raw_spin_rq_unlock(rq1);
 }
 
@@ -3100,8 +3136,7 @@ extern bool sched_smp_initialized;
  * you need to do so manually before calling.
  */
 static inline void double_rq_lock(struct rq *rq1, struct rq *rq2)
-	__acquires(rq1->lock)
-	__acquires(rq2->lock)
+	__acquires(&rq1->__lock, &rq2->__lock)
 {
 	WARN_ON_ONCE(!irqs_disabled());
 	WARN_ON_ONCE(rq1 != rq2);
@@ -3117,8 +3152,7 @@ static inline void double_rq_lock(struct rq *rq1, struct rq *rq2)
  * you need to do so manually after calling.
  */
 static inline void double_rq_unlock(struct rq *rq1, struct rq *rq2)
-	__releases(rq1->lock)
-	__releases(rq2->lock)
+	__releases(&rq1->__lock, &rq2->__lock)
 {
 	WARN_ON_ONCE(rq1 != rq2);
 	raw_spin_rq_unlock(rq1);
diff --git a/scripts/capability-analysis-suppression.txt b/scripts/capability-analysis-suppression.txt
index 95fb0b65a8e6..7ecd888ac522 100644
--- a/scripts/capability-analysis-suppression.txt
+++ b/scripts/capability-analysis-suppression.txt
@@ -26,6 +26,7 @@ src:*include/linux/refcount.h=emit
 src:*include/linux/rhashtable.h=emit
 src:*include/linux/rwlock*.h=emit
 src:*include/linux/rwsem.h=emit
+src:*include/linux/sched*=emit
 src:*include/linux/seqlock*.h=emit
 src:*include/linux/spinlock*.h=emit
 src:*include/linux/srcu*.h=emit
-- 
2.50.1.565.gc32cd1483b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJNaUwoDjuGfplLm%40elver.google.com.
