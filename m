Return-Path: <kasan-dev+bncBC7OBJGL2MHBBM5GS66QMGQE2UMYCBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E737A2BF5E
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Feb 2025 10:32:36 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-438e4e9a53fsf14638115e9.1
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Feb 2025 01:32:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738920756; cv=pass;
        d=google.com; s=arc-20240605;
        b=Mfakf2hM6AQaUAajDkD/cdCBiaezOJ1YkTrqWoo9BMyieCnGqgGMF8BFR54hw0hVuU
         wuu0hgCPltK87o7tm3HYaDxb34pipdDIs1IgB9r6hJtu5CL4scUvPC4jLzv9MFK7Dz2Y
         s0yY/w5TcXnNp5atiKZpBUp3dkZW2mHKKmHqYFYAa5YHCSgyusTY4OFU/ZbSc+5Eiidr
         D4xX4ZUX0g/idR4j8yOAEd9MYvrpmGOuYw+Dq4/Q0oKxLRcgLi3Jy7kpJM6PM+UKK06A
         UL0b9OiqmeEHVSJYw84SloaDTidi0k/BwEEkAY3hPd50GTY/G3a3sjvJFRkCpGkrQGfg
         SXVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=HXXalXlXzTXm/cUarKWM8gwbDkHI56Q4qOM7yGr6PRs=;
        fh=dzHrYuSM5TRHCHpwfM/re3at6VQ5YFv/QUb3MtwBg2k=;
        b=TXubuY6R9G6BS5l82u/OwXZycbIbWvjPChgy6BSGVl43YX1qNhZ5gkxVNKnjwO+0DH
         EvpRBh8N74+l440dWnLljG2lxOFK/liehLcbGe1tNN7U6zIqv0gL7/0UtUeRfj/Y5Umv
         sxP7zhJX2Js4VgI1GSNvm7z7HbUQdb5dmL6M4E9XEmyitYHa2K7Hrmgw2ydHM5qHmTgR
         jfoeb5B/o/xUGW5kK3BL8iVQRx3ZJj4Y5Fa6/2QWuFt1kdEODVdCg+RBfWF8TWnSyhl/
         toFVzBumI0X5sCDHItiVRY99c+dYGhfTc4Vjyfw6o3gnh6UPQ8Cmha3gXlQsV4UU7HZ8
         sbqQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ORVK6ILE;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738920756; x=1739525556; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=HXXalXlXzTXm/cUarKWM8gwbDkHI56Q4qOM7yGr6PRs=;
        b=sBjTixLDroiShHx2W9firsQS4MtISpvAFT1xZJTyUJ2Ekhdr76lDyts8mKXGBJGMiE
         V6+ZOBebn1wla18cevlvgErZvyqauL66Hurb2dm6t+08QFnLofbtbGzUzQFpAr0BOEnz
         e45KRT0kf2GVrHt5RDm4lEKBapHEGXPDJO49ia1Rztx/Ga8tA9O21EwCPjKAw6cQRcj0
         IYacO0cQ1NPgcj5jDqCh6xttZlwNtmjhk7mflgY7Fa81cKeLDaMfDangCHTFrWdbDdgd
         5KMfT0EV3RTMfL6O6hy6V4pTpf/dMU3mSD9O5epku4j3rJt//t6lhB4U/IF9B2keHc3w
         0BOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738920756; x=1739525556;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HXXalXlXzTXm/cUarKWM8gwbDkHI56Q4qOM7yGr6PRs=;
        b=CIyCHDEh7aJKz4WWPTzld6+Ohzi8lJyF4dBncJjPet4+hammHD91FCAOT1PuD+bU0p
         TJfOKik76jtW+za264AlPxCNxd8sTa840bxzBRLCPldsNKD0C4m5s14s3nZC6ma0zJr2
         caFg/CeWWyGJl4KOtzSwQIXrYeBJsRgEZVFtPnx+Zhtxsh/FdpSSlnK12q4sp9GYbqES
         QO1g/XeRPC4D/YwJTyc02MEf3lJN9l3KF4/5yZkIviVJkI4hsj5MfoAVW/k7Ii6zoop6
         6M+VTE2oh+PAnN+6WMI1eit4RmnijsNU3kifWzWb2i7GLlY7s62bXi3L/xPNV39dz+ak
         h9Og==
X-Forwarded-Encrypted: i=2; AJvYcCXTDBQMvXmAn2paFeyCDNmMDYkkxCoo07EAmIBFfeewD0TNsuoM6JmuxoZKxmS8KiGUW8dpvQ==@lfdr.de
X-Gm-Message-State: AOJu0YzU5w0byhwaktvRUgAbZlGjAuZiNOgNNWkgL27HZ9GlYNgCYQba
	PYeOVsMDixx0Kft6oVn24OoXIuiyBSBE8T127Jn0ddem64Oes4Qa
X-Google-Smtp-Source: AGHT+IFF/e9JT7ozw53fRApaaQCtSJBOwwFwaBaZeFgOnB9wFd2EPmpWbwvvp5d5EoRkqL7hob3ISw==
X-Received: by 2002:a05:600c:3b9c:b0:436:ed33:1535 with SMTP id 5b1f17b1804b1-43924991f68mr22832695e9.12.1738920755380;
        Fri, 07 Feb 2025 01:32:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:b51:b0:436:5d0c:e9c6 with SMTP id
 5b1f17b1804b1-43924c40137ls822375e9.0.-pod-prod-02-eu; Fri, 07 Feb 2025
 01:32:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWMM0w3pI2nzVjuewjAoHoUXbm+gsgvR/hE3OTXksUBkfiPYHUL1p5UA5g72q9v75RFzA6jqUH9mCo=@googlegroups.com
X-Received: by 2002:a05:600c:3b9c:b0:436:ed33:1535 with SMTP id 5b1f17b1804b1-43924991f68mr22830965e9.12.1738920752861;
        Fri, 07 Feb 2025 01:32:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738920752; cv=none;
        d=google.com; s=arc-20240605;
        b=JOqNiwQy+3pLtfrW540QczeVbROu0vPhzsQYEmxM/Htl7mgMwJU6bDgA/YWlfB7E6Q
         P9xjnAzg8JfmCbH/Y88rglBgBbEiuyma8qJaNVZHU+vHTTfrgMvUp49+SIfKPDbz7UPu
         JPKVi15DVMoLpyIQG7F2A2Iz0330Rg/DRPWVRoJNNBnIdYjwJwPgHJJ+fMVOsZboMjoU
         xu4sayrDsBnJmgbu4D/TVmnPPS02GECQmGEGQJ//vapgG1NRUJiFtlG+d6v66R5WYKSH
         xqN0egQfc3flu3EgVJflIlLZNB2O0NnvXSZZ4mY/7NXm+lzKgrtwoeSJFC8rEAzUPnOA
         8JhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=w8aNJoNQ8/KZ3zGcS/1S9RhAv2oCaPXrYb2HHOjsrgw=;
        fh=auTZbVELAcnuTUm6/jsVe5QVQUHqmfL449MwO113iaI=;
        b=AGQS4d/08lhy7a+76RaSFfa6tN+JiONTTN+hpSp3vbXmVFL0+WPgSIYKkjI+hDVxQW
         bqSXSyWB7PHgo5PPkfo7Ck2RmN2Rf8GLWOwXjHgruKdOxcHdR/kNZgbD6osfo7cMjtZa
         E9oTUYYKwq2+X7oqfCahekGOF054rhbG8ngNzHqWuU+Z/iPW+aASRtCF4onffVxNErip
         AsJUJyUG85/rY4C8fkikSeDRvp3LH/O7uoD0R+CYaYOrmpmd3FXJfrwOUqwI9woAspGj
         M0CYHhxICj8pRSkukJnyzYoAf1yTbp9IGTeEbOpst2Qi3oMuNu4eOwLJaHbJYfpnHdHr
         PABA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ORVK6ILE;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4390692a173si6652675e9.0.2025.02.07.01.32.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Feb 2025 01:32:32 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id 5b1f17b1804b1-438a3216fc2so18304145e9.1
        for <kasan-dev@googlegroups.com>; Fri, 07 Feb 2025 01:32:32 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUmGJF5C/Risn7TZISLKFnOaPkKlh6kSLffFEt3pIsOL/w8NOpuhOu8ihdo6f1U9lMx/0RYzDYpZ3U=@googlegroups.com
X-Gm-Gg: ASbGnct8qgL7qeSasw/takQNP3M9kC4+Fl9Y+nt8N3LYhdgbjD7Gj9BRHM/AQtiX6OO
	vJradAtXYD0PuGM+dXmRdGGy+soPwZr8YNFX4e25tQ6KOAzpVzFbe+gZDAIBloAavyUHqpBrRSa
	l7gklVOAgVei7au2zhemKto11S4HpTxB5RRAej5ZYhlUDYEcJY0SfGGmv+xF3mpeXCLZDyJ3Cwa
	iz85yseOVw+Lw+k4GMAX9GVl/Be9XUeSE9XK4zx+RVQk066mJKGH/gmMMWoHej9Vg/rFo2V+kK0
	f3OFI9B+FE5WwETG
X-Received: by 2002:a05:600c:19c9:b0:434:a0bf:98ea with SMTP id 5b1f17b1804b1-4392498c08cmr20059475e9.9.1738920752144;
        Fri, 07 Feb 2025 01:32:32 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:9c:201:fad3:ca37:9540:5c99])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-4391dfdc1acsm48592775e9.40.2025.02.07.01.32.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Feb 2025 01:32:31 -0800 (PST)
Date: Fri, 7 Feb 2025 10:32:25 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
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
Message-ID: <Z6XTKTo_LMj9KmbY@elver.google.com>
References: <20250206181711.1902989-1-elver@google.com>
 <20250206181711.1902989-3-elver@google.com>
 <20250207082832.GU7145@noisy.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250207082832.GU7145@noisy.programming.kicks-ass.net>
User-Agent: Mutt/2.2.12 (2023-09-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ORVK6ILE;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as
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

On Fri, Feb 07, 2025 at 09:28AM +0100, Peter Zijlstra wrote:
> On Thu, Feb 06, 2025 at 07:09:56PM +0100, Marco Elver wrote:
> > Just like the pairing of attribute __acquires() with a matching
> > function-like macro __acquire(), the attribute __cond_acquires() should
> > have a matching function-like macro __cond_acquire().
> > 
> > To be consistent, rename __cond_lock() to __cond_acquire().
> 
> So I hate this __cond_lock() thing we have with a passion. I think it is
> one of the very worst annotations possible since it makes a trainwreck
> of the trylock code.
> 
> It is a major reason why mutex is not annotated with this nonsense.
> 
> Also, I think very dim of sparse in general -- I don't think I've ever
> managed to get a useful warning from between all the noise it generates.

Happy to reduce the use of __cond_lock(). :-)
Though one problem I found is it's still needed for those complex
statement-expression *_trylock that spinlock.h/rwlock.h has, where we
e.g. have (with my changes):

	#define raw_spin_trylock_irqsave(lock, flags)		\
		__cond_acquire(lock, ({				\
			local_irq_save(flags);			\
			_raw_spin_trylock(lock) ?		\
			1 : ({ local_irq_restore(flags); 0; }); \
		}))

Because there's an inner condition using _raw_spin_trylock() and the
result of _raw_spin_trylock() is no longer directly used in a branch
that also does the unlock, Clang becomes unhappy and complains. I.e.
annotating _raw_spin_trylock with __cond_acquires(1, lock) doesn't work
for this case because it's in a complex statement-expression. The only
way to make it work was to wrap it into a function that has attribute
__cond_acquires(1, lock) which is what I made __cond_lock/acquire do.

For some of the trivial uses, like e.g.

	#define raw_spin_trylock(lock)	__cond_acquire(lock, _raw_spin_trylock(lock))

it's easy enough to remove the outer __cond_lock/acquire if e.g. the
_raw_spin_trylock has the attribute __cond_acquires. I kept these around
for Sparse compatibility, but if we want to get rid of Sparse
compatibility, some of those can be simplified.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z6XTKTo_LMj9KmbY%40elver.google.com.
