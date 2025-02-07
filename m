Return-Path: <kasan-dev+bncBDBK55H2UQKRBSNKS66QMGQEBIUPDQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 31E87A2BFA9
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Feb 2025 10:41:32 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-4359206e1e4sf15321655e9.2
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Feb 2025 01:41:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738921292; cv=pass;
        d=google.com; s=arc-20240605;
        b=klvPpnmMcIUDhswCQ1GGCSpoTSDkL+6xfUuSK0M2bsF+TsU1K4J4BufVaoGPniNv9i
         QYnQ+1oLSmOCkny4Xu87mvYnnYTtlZ6XGWhDZ1RRsYsB4+xR/PfWs0BxaIdiS3Z8bjqX
         QM+k3HKB8NOaZcBlEev1kKcHZX55lqG0hwctmMWJI0P3W5iHxmbBQ28oGthZaM8CRd0/
         AI1prOcNTrNexwWYrPmohayoJts2JFAv8skmh62hkL/U7KlxdDJ55DzJc8HvYj8R+x05
         93wE+vTd1H5bYmwlxwQY61vyyGsSwo3UdpYibsj7O8xoKroOk0mRAma1rdUr0e/Izu7X
         lDcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=mIabFUomBR/EqIvOAmnaiPoBxsnFDUID/ezGtW5MlGk=;
        fh=RbyNaMA9Zbn/8NuF1tKePfPfbtq9E4WHEO0tiR0OjyI=;
        b=Tf6p07gtnCADphEkz+4dn25HBFDtjQ+gauIQX2GXke7vCElKht8L7A/hgEr/jlsowZ
         /1puw8VIpRo7/2fn2C9nbfoGG0m5bMScE3KuXzUBNHUax4Wb+hdppsHLHiZgEGghWCi9
         /IDcHRZb40z2EBKQ7UOA4k/0zVqNuclazzjeNkQw7JygP9wfxwMjvaT6mNP0HvLI1gOp
         XxDCoX++nDS3KtZZWTWXqsy7plz///xXS13Ts8sKYyeDfM0frJ+mVAnA4Mo5BJWMoHRc
         zPw6yD2UTQY2GaNGwCn37DZjgPlhAXjKiTk7Y/PD3m53Pn5dRXYXahwKw3ahIKUyHyzY
         Ejbg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=W0PE77Qt;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738921292; x=1739526092; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mIabFUomBR/EqIvOAmnaiPoBxsnFDUID/ezGtW5MlGk=;
        b=ffYukW1jXWFTpJ89x+Pw8eeULwvGAvizJicbqRucaSdJwpRjn0Vg32QQ8+Vu4EPlEf
         rgYVFtoNyDzTMFp+p8PV3+fxQ42UPpVDWuaoQ8mkofRYg28mZBLSl90QHD3FdyjkM1IP
         ir2psfCi9ogWfLSg/r5tfmPQ1g5zvLV3O3EAT2dco87wDunkXFSOcAAwBipRR0wTHdBw
         MCTJqIv/noDCUwErJNTJ9IIKQSWnElMs1Y8obrLe/1GqO7Pbpxk1IKskNCSKWgohfe0x
         OgsWLOmoitf+YdkOlBsQAlH2FNWmBXc0OZwtOMoQVTHBzvL1IyKmzpGebw7CSPpCGk4A
         Ywbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738921292; x=1739526092;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mIabFUomBR/EqIvOAmnaiPoBxsnFDUID/ezGtW5MlGk=;
        b=B4ZluWXZ2g10Rir3cxCBVsBRzsVi87uixFDcyAePVYnD9J0UgCnm4Gp5hzkT9xMMk7
         SXoDJDRdjjPPaqYZepGuLJpIaMJPqfvX5QWKk67M2WnAzsxApUvFBE0yccMAcIr/Gatp
         ieM3BDGCP8fPJzsHbLrzGdRDlywgV1zWGvP8pQYjaqQhaQHq1RdLVK0juj1Bht5ZS0fe
         uFHMVaiDan9DJ6zJ+7wSvNDyCccHUqHO20GvMscsf2OgCcMpUSwsgG8FEKCCAwP1+DIq
         uHZiRzbYCyGXQaqmdUhFwqn21YiykvfnPuL/cej11YQwJzBV+ciK7LOcQHnoQBPYrIQS
         WMlA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWMWzyDN2C83bMSnzv9w2mziAVzHwfL4gG5KeYxRfpNTdpuyo9qatv3/FaKoreOspCj85uqCQ==@lfdr.de
X-Gm-Message-State: AOJu0YxwdnzWX50XQggcLqrHa8FjkfR9+m10/aJgTN/IAniOGbt4WElH
	8AmcWwoFfMGwLsdLMtevkyyRvPzNB1fyugNaBNpiSTdS1i1fLMp9
X-Google-Smtp-Source: AGHT+IGtTdZUd1IAv2ab9B1QC6f5Js9yztNhAICxM9zp66+x/mZEroJjk6Ip7tq6pk+evVG7Koaq+g==
X-Received: by 2002:a05:600c:3b1f:b0:434:f753:6012 with SMTP id 5b1f17b1804b1-43924991384mr22435245e9.17.1738921290376;
        Fri, 07 Feb 2025 01:41:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cd85:0:b0:436:9336:a5f9 with SMTP id 5b1f17b1804b1-43924c3fa80ls4108535e9.0.-pod-prod-05-eu;
 Fri, 07 Feb 2025 01:41:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWYZBAquoYooUh58urV9W8g+xZjs6rMno+xzr6uZAvTBCSgZ8TMinXgqR6TgCSiaFnJmmkf1+XOmNc=@googlegroups.com
X-Received: by 2002:a05:6000:1a8e:b0:385:fb34:d5a0 with SMTP id ffacd0b85a97d-38dc90f1b1emr1671742f8f.29.1738921287624;
        Fri, 07 Feb 2025 01:41:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738921287; cv=none;
        d=google.com; s=arc-20240605;
        b=Vdnqi6QUf/tIt254WXBbhTlpfkXqDMrJir2bhLIMKXizhgH5BhbQ8Dzms/usHcYQC+
         23+t91oKuSSgawbnvMTclRnovATt6WzfEkDBF8sk39sxNMT8+c54dxIYHX+RUW6CEFGw
         0dfvhmKl3mw1Ve78Ny/jVbXTdmSqIbI/5ORjy9tS0cK563i6/4mVRYwiJEvxnw+lz8jG
         AlbCGkJUrWqDr/cHUsYue4k542QqI0I1Emdv87zOjoA9dpMgg8Il2pDyUGXn3IGgZ3Zd
         I+V2wJYCDEL09GfaTNqTAey+LG2BMb0NLMnk7JXikyomIqtCeqgmIBn1OoJ2aRM1rcxC
         cX3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Y1gqRSqWYUoS/5b4bvazFO7Ddo/G+ehsqfGlUNrq33s=;
        fh=p9qVCSW3g/knQl1jy4WovKLdPkqy2lNlDCIoDQ06JPc=;
        b=Jhgf+Dww9Ay7jxynHykyxoJ0y9rEALOnuk+5yRPQdx8VLNL1+h9ieDuPrBo84XxxYP
         tNIgZEULjkGQnni/SSFGaTg3vqd6jaH3JgEVMF3c8xEnT8yKMYCAUTW/MuSaBcnYs8Lt
         zYS60WEpOnEa9s+S/N5M7Par6dghZP292mhMi2Cx2YTik/XTd08/g3vw7f3j24dipza1
         eWruwHB3AKwX344pFBKFSSjdpMq08+xfeTyZfz3aPCBjOUFDSXhC2g5cNiL0u/7SEPgI
         DWxSP9whWQ9cWTr/GBqIW8ohO/RJT4Sq4QUZ7uBUDxsBAiAbGuJ6NbwBfXV6K5ePRJg+
         iJYg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=W0PE77Qt;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-38dcb734033si18293f8f.7.2025.02.07.01.41.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Feb 2025 01:41:27 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98 #2 (Red Hat Linux))
	id 1tgKrR-0000000H9UC-0XlV;
	Fri, 07 Feb 2025 09:41:21 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 1A6313002F0; Fri,  7 Feb 2025 10:41:20 +0100 (CET)
Date: Fri, 7 Feb 2025 10:41:20 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Bart Van Assche <bvanassche@acm.org>,
	Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Ingo Molnar <mingo@kernel.org>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joel@joelfernandes.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org,
	linux-crypto@vger.kernel.org
Subject: Re: [PATCH RFC 02/24] compiler-capability-analysis: Rename
 __cond_lock() to __cond_acquire()
Message-ID: <20250207094120.GA7145@noisy.programming.kicks-ass.net>
References: <20250206181711.1902989-1-elver@google.com>
 <20250206181711.1902989-3-elver@google.com>
 <20250207082832.GU7145@noisy.programming.kicks-ass.net>
 <Z6XTKTo_LMj9KmbY@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Z6XTKTo_LMj9KmbY@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=W0PE77Qt;
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

On Fri, Feb 07, 2025 at 10:32:25AM +0100, Marco Elver wrote:
> On Fri, Feb 07, 2025 at 09:28AM +0100, Peter Zijlstra wrote:
> > On Thu, Feb 06, 2025 at 07:09:56PM +0100, Marco Elver wrote:
> > > Just like the pairing of attribute __acquires() with a matching
> > > function-like macro __acquire(), the attribute __cond_acquires() should
> > > have a matching function-like macro __cond_acquire().
> > > 
> > > To be consistent, rename __cond_lock() to __cond_acquire().
> > 
> > So I hate this __cond_lock() thing we have with a passion. I think it is
> > one of the very worst annotations possible since it makes a trainwreck
> > of the trylock code.
> > 
> > It is a major reason why mutex is not annotated with this nonsense.
> > 
> > Also, I think very dim of sparse in general -- I don't think I've ever
> > managed to get a useful warning from between all the noise it generates.
> 
> Happy to reduce the use of __cond_lock(). :-)
> Though one problem I found is it's still needed for those complex
> statement-expression *_trylock that spinlock.h/rwlock.h has, where we
> e.g. have (with my changes):
> 
> 	#define raw_spin_trylock_irqsave(lock, flags)		\
> 		__cond_acquire(lock, ({				\
> 			local_irq_save(flags);			\
> 			_raw_spin_trylock(lock) ?		\
> 			1 : ({ local_irq_restore(flags); 0; }); \
> 		}))
> 
> Because there's an inner condition using _raw_spin_trylock() and the
> result of _raw_spin_trylock() is no longer directly used in a branch
> that also does the unlock, Clang becomes unhappy and complains. I.e.
> annotating _raw_spin_trylock with __cond_acquires(1, lock) doesn't work
> for this case because it's in a complex statement-expression. The only
> way to make it work was to wrap it into a function that has attribute
> __cond_acquires(1, lock) which is what I made __cond_lock/acquire do.

Does something like:

static inline bool
_raw_spin_trylock_irqsave(raw_spinlock_t *lock, unsigned long *flags)
	__cond_acquire(1, lock)
{
	local_irq_save(*flags);
	if (_raw_spin_trylock(lock))
		return true;
	local_irq_restore(*flags);
	return false;
}

#define raw_spin_trylock_irqsave(lock, flags) \
	_raw_spin_trylock_irqsave((lock), &(flags))

work?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250207094120.GA7145%40noisy.programming.kicks-ass.net.
