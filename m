Return-Path: <kasan-dev+bncBDBK55H2UQKRBCPSUG7AMGQE6XO3RAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id B6321A5045F
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Mar 2025 17:17:15 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-30babe2708asf21161211fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Mar 2025 08:17:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741191435; cv=pass;
        d=google.com; s=arc-20240605;
        b=SUiYTn52Cl0pUem+sJ+Y1jOf5khjueEUELNmLYFDKoDwbbY1iF4FAFxmwuvsbyisW4
         QzdI+B5txaTI2ayw2Fe7x/79powxeEUx+qHjmWKLx+jo/7H+kc4qozFfLU8PXzfUB65b
         /+OSaP9Hxp8okapDP1oMrE1hcMQO4DPuRcjCdmxGSiDBernkg71KqASgAjA5zr7b/1q3
         5jCE0xmgs06PynE6wnkwevKCRYXYUarP2JABQiJQe8kEFy0f7qKOvlaHzBJ1i+occZ5f
         gp6PW20UOG+67p+KSfOPi3Lm1wlwcXTjWAc1os79kwNfNUMgjy3mSnVI073YMPwEn1wP
         C7WA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=TWcKaA1EZpkRPwSE9nwgSC/Tkrwjm2eNb+SsMVbcjwg=;
        fh=ncjOKdF2nTx1GwFgmZXdTEy4X4aVcH0XdRSEnGPwRig=;
        b=KTqnC2kuhuzMgrJ3SvtNR5I5/Ppe1qvThPtCIvzEad/KoSL++ZWTQdAXugSI22ZtLF
         nf1VyfV7ITi4EHIoFwDzSSssQAgCPvrbb2ryfeuMY9nNQll3LrsKwsn2+BhN/wFPpHXh
         OpyaQBXn7eTGTAZ1u4/KRtDNZPCehx6Kgq9Sh3UZ/ACCaWe6MXQeDWIv+K+VuK4MyK0K
         tEPx2n17pUNb1vhPpbhOGmpoX5AnAl/sW0LpxKY0eWd7PUauYcVuiu7IWt/5CLzOqG/k
         O7F1YD+K6wIqGvY4ZhbGy63MtnDzX+KlN/tj0RJAC47/z9tUrjIOYOznvtbsbN2Cf8nv
         3R4g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=oK6Ax3Bf;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741191435; x=1741796235; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TWcKaA1EZpkRPwSE9nwgSC/Tkrwjm2eNb+SsMVbcjwg=;
        b=OBnm+dk5cyZpbaixXLaOElHxEI6NNPSb2kl+7+C9pVN0Rwb0K0hIqrIzdNikb93XOR
         aQxI8med20wdqZstqEo4uQKFVY4D6OvDEBNkL/+Mg2U2VcGRLDNYxIggVjlCQZf3zAPt
         Yx3lFV6+4sQhXThbsjRtP8fUDvbeUeA05/xauREQKbB4knhRPm5gjsaVEhjT0EM4upQD
         PyrZ3i4YVHMrhdRnEdD6rxQn2C1HgkVf4Nc1Ako1CQK5pw6FSsTeTSh0aKQDSWWxHMfN
         aYLpiAD71lwxKa7J+18jGg35b7nKYpWhrMH+uYruEKXhwRdHgAxdy/BgO91h6fyG2HrM
         ejjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741191435; x=1741796235;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TWcKaA1EZpkRPwSE9nwgSC/Tkrwjm2eNb+SsMVbcjwg=;
        b=trBOC+edbwDhIhJoJ9lZ2PeJtzCfseCfIMVj1fyMGm1W42ogm7Z/TjYuEgXYmiDltx
         lEvf+A0o5YTtuCYTAmEd3paI8K1YppNg/Yzp9vgSYlEugxBNKWqLLDyXMvInplih5uTK
         PYh55GWNIXS8sevXdSSenNPSM1rfC8BW/AFlrf7jWLiEUlkJ0IUtaQJsWhla9iBEQyA3
         9sIP+ysJcNFiyEozDfSI1AQjS5fTfLjSV3M7eBykcyvPfWtgdze/eBnIaq667Q4yGNru
         QsSB2jyhIB0dEWFN2vidfodCkZnNzMBLq2MBYgJ7HajfUdJ5cDb6bjTsOYefCTmjto24
         OHDw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXmX70vFHM1B3vnEphIqGT9DFe1fMyapfo/v2RoQm9ryhMV5VnNa4WmizUDINyqOtc5K+Ul3w==@lfdr.de
X-Gm-Message-State: AOJu0YxaX6Qd7O8bOlOyJVJAeiebX5z8r8yg1sWceixqFjR+KroiHlVj
	ecZSctmvy4RLof7wMHLOA0CyYGjy1ToqVf/laV52s8d+zqaJW3ov
X-Google-Smtp-Source: AGHT+IF/Yr3AFaBFHcQy3SUA42Y5HCBcf4sh+PFOSaz8DtclNKZ7O2emJBf9HaRex8xlj6fGmVCsXg==
X-Received: by 2002:a2e:96c3:0:b0:30b:be53:bdd4 with SMTP id 38308e7fff4ca-30bd7a5844emr13184091fa.20.1741191434318;
        Wed, 05 Mar 2025 08:17:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFqPxtBxRc1NxIaPqg9bBObHhAwV6cdQyv0jASZfNKobg==
Received: by 2002:a05:651c:50e:b0:30b:78cd:df7b with SMTP id
 38308e7fff4ca-30b846e38acls996871fa.0.-pod-prod-08-eu; Wed, 05 Mar 2025
 08:17:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXgMvSU/NQKnal6v6HuSyUNo3Uz+D2IsrX7+/7z7QxsqOJ+hzrXU/oXzJgjL4m1pgDFYcbG3oCMS8M=@googlegroups.com
X-Received: by 2002:a05:6512:3f12:b0:549:54f7:e54 with SMTP id 2adb3069b0e04-5497d38ba55mr1604681e87.50.1741191431203;
        Wed, 05 Mar 2025 08:17:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741191431; cv=none;
        d=google.com; s=arc-20240605;
        b=dIel81e8v81SG/CAwlWFBMOswYFsGlOGZKpjQ2u4iW8UJ22AwBzQuXxrq5K0N4Jm22
         6zoWrWKZ9VYkSoigGlkYxvY3ePR6vo69nXl+PhI4BlTUbEJqClM+zWvzJc3r/ygu0cPW
         sMZETZxU57idJiVlzLwjYiKZLm73UZVSUVs+b5A3esJ/FLaoOidP55wzmFZot0bk+3j9
         UzdAK4Q3NLM08cOwn+PaD0WfyJAcVPKyXAFWJ0S/NDpmS6SnQU9Opb6x8Qu7oHV1RMWE
         Zyqe1c4aD5Xf/Vsc5c7RgKgpZHcG7R2aFVoHC1V+SZEBGptrbJCsrpMW5sTVEMCi4dyD
         68Xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=3jN1+xJ/BcC8IjBdHqdwVy40EWJGNjtffvW7aUuKF40=;
        fh=S/v13xR+0DCaIb8zFeaZsBimGOQmGh83bRmiSJNQ8Bs=;
        b=aP6DEEsvDzmzEMRLrKA+IkIMRj4WI1Q7bFujNyYpdjuyeSIPV7CNSq91d9zuuXMgli
         ChdggSf8NEXWJnRPqKR5ZzBk+JsTPlx3GmyWDxRx/F1GblbmoyzQCShK/FktMrvc/RSc
         HR7HiVFWCfHsOuL/0rRmNaU7Sn6YDmpkywY90ZCO2v753oViuSKL7GVmgYqKqKZQ9NTU
         ks5H7W/BrNuZM8qKSjPbfxVSnkac43bFO/OuVqpxWKIkIFYgDGHc0qauyPmtYq2mOIC0
         UBMqqQ8xe42grppNVc14t5jgV6oEEfLrKc3MkfKGlDRohWRXyoqcWW8MJR/XJjs6uyPF
         5xyg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=oK6Ax3Bf;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-54954f95ee1si427023e87.4.2025.03.05.08.17.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Mar 2025 08:17:11 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98 #2 (Red Hat Linux))
	id 1tprQT-00000000coL-1dqW;
	Wed, 05 Mar 2025 16:16:53 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 79D7430031C; Wed,  5 Mar 2025 17:16:52 +0100 (CET)
Date: Wed, 5 Mar 2025 17:16:52 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Bart Van Assche <bvanassche@acm.org>
Cc: Marco Elver <elver@google.com>, "David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bill Wendling <morbo@google.com>,
	Boqun Feng <boqun.feng@gmail.com>,
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
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-serial@vger.kernel.org
Subject: Re: [PATCH v2 00/34] Compiler-Based Capability- and Locking-Analysis
Message-ID: <20250305161652.GA18280@noisy.programming.kicks-ass.net>
References: <20250304092417.2873893-1-elver@google.com>
 <20250305112041.GA16878@noisy.programming.kicks-ass.net>
 <76f8c8e1-5f32-4f31-a960-9285a15340e3@acm.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <76f8c8e1-5f32-4f31-a960-9285a15340e3@acm.org>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=oK6Ax3Bf;
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

On Wed, Mar 05, 2025 at 07:27:32AM -0800, Bart Van Assche wrote:
> On 3/5/25 3:20 AM, Peter Zijlstra wrote:
> > diff --git a/include/linux/blkdev.h b/include/linux/blkdev.h
> > index 248416ecd01c..d27607d9c2dc 100644
> > --- a/include/linux/blkdev.h
> > +++ b/include/linux/blkdev.h
> > @@ -945,6 +945,7 @@ static inline unsigned int blk_boundary_sectors_left(sector_t offset,
> >    */
> >   static inline struct queue_limits
> >   queue_limits_start_update(struct request_queue *q)
> > +	__acquires(q->limits_lock)
> >   {
> >   	mutex_lock(&q->limits_lock);
> >   	return q->limits;
> > @@ -965,6 +966,7 @@ int blk_validate_limits(struct queue_limits *lim);
> >    * starting update.
> >    */
> >   static inline void queue_limits_cancel_update(struct request_queue *q)
> > +	__releases(q->limits_lock)
> >   {
> >   	mutex_unlock(&q->limits_lock);
> >   }
> 
> The above is incomplete. Here is what I came up with myself:

Oh, I'm sure. I simply fixed whatever was topmost in the compile output
when trying to build kernel/sched/. After fixing these two, it stopped
complaining about blkdev.

I think it complains about these because they're inline, even though
they're otherwise unused.

> > diff --git a/include/linux/device.h b/include/linux/device.h
> > index 80a5b3268986..283fb85d96c8 100644
> > --- a/include/linux/device.h
> > +++ b/include/linux/device.h
> > @@ -1026,21 +1026,25 @@ static inline bool dev_pm_test_driver_flags(struct device *dev, u32 flags)
> >   }
> >   static inline void device_lock(struct device *dev)
> > +	__acquires(dev->mutex)
> >   {
> >   	mutex_lock(&dev->mutex);
> >   }
> >   static inline int device_lock_interruptible(struct device *dev)
> > +	__cond_acquires(0, dev->mutex)
> >   {
> >   	return mutex_lock_interruptible(&dev->mutex);
> >   }
> >   static inline int device_trylock(struct device *dev)
> > +	__cond_acquires(true, dev->mutex)
> >   {
> >   	return mutex_trylock(&dev->mutex);
> >   }
> >   static inline void device_unlock(struct device *dev)
> > +	__releases(dev->mutex)
> >   {
> >   	mutex_unlock(&dev->mutex);
> >   }
> 
> I propose to annotate these functions with __no_capability_analysis as a
> first step. Review of all callers of these functions in the entire
> kernel tree learned me that annotating these functions results in a
> significant number of false positives and not to the discovery of any
> bugs. The false positives are triggered by conditional locking. An
> example of code that triggers false positive thread-safety warnings:

Yeah, I've ran into this as well. The thing is entirely stupid when it
sees a branch. This is really unfortunate. But I disagree, I would
annotate those functions that have conditional locking with
__no_capability_analysis, or possibly:

#define __confused_by_conditionals __no_capability_analysis

I'm also not quite sure how to annotate things like pte_lockptr().


Anyway, this thing has some promise, however it is *really*, as in
*really* *REALLY* simple. Anything remotely interesting, where you
actually want the help, it falls over.

But you gotta start somewhere I suppose. I think the thing that is
important here is how receptive the clang folks are to working on this
-- because it definitely needs work.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250305161652.GA18280%40noisy.programming.kicks-ass.net.
