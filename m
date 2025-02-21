Return-Path: <kasan-dev+bncBCS4VDMYRUNBBCEC4O6QMGQE7Q3LBTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AB93A3FE40
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 19:08:10 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-472001e9fe9sf52336811cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 10:08:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740161289; cv=pass;
        d=google.com; s=arc-20240605;
        b=lpCIuGJJ8ZWFbDIM2Wwbr0tL4J0cmlbXbq8QZ2fEr6Yyv9TywlBiLIQex39FNmXYB3
         8J9vYVpHQ4BYGtHinne8D1RENCjmqOoxpgwUXTjIEOmX4+O2aS+qxhpsQjdrIxV9vqaB
         r0EyG98Xnye3P/bNe1F0VJ8xNaXp8JKPdlEWWHG6kRind0zzRGRYMx1UbKdc+2TGnPVX
         yBFyvI8X5Cdgb+5qgjnHBxvos5PGXyN/fWshgxtyXrSH+Hk9ISuJ8FqzASG1WclLLgSg
         OsdvxmgasAJ4rzywuSTZ6CqkYb3g3g304SDlEMZdqbaOirl58nt7X0Ysa7mx0zZswtpC
         rWXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=/6Lk8md8WthVQXHwQYl587eMqN9VJk5ozT+prhvQFZE=;
        fh=t7e4BMJtHZDPCFiOy8U6YNZi706bMBE4Vj8wfXS/WKY=;
        b=jobb2GaqdPyl1gnbX1lgQJGjVbY0JLqcJ+cXtG9A+OrI+GlM28zmt4sYCUtQdU8DXd
         fIclxosGoEmdhN8jqdEarrVJGXrz4GiKUBn2AwS41TDsoAgUgJXmz4z3bVlFm46lLWN0
         fvr9CkgswApvtAsIczXPxfSRsZB40jFBi2KJRDSX7f4qFiwa27CAyvW5dfWV4LNaigX2
         kBZAO4EfCIIsqMpaA2t261PKmgpGZSR43Dy2GtUH/+qqjHwTM2IjAxeZfEmj9x7Stchr
         61dZBAQ6LscQMW4IqUiPxCT8UkPzECR/sb4C/agVVAGgByy4VczQrclF0KIUNWKIpCZR
         zg0A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=e9H5tiM+;
       spf=pass (google.com: domain of srs0=3afp=vm=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c04::f03c:95ff:fe5e:7468 as permitted sender) smtp.mailfrom="SRS0=3AFP=VM=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740161289; x=1740766089; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/6Lk8md8WthVQXHwQYl587eMqN9VJk5ozT+prhvQFZE=;
        b=FcvBDqGWCw2wHisf39BGtY7vCvkSEVmgYC3n7sVtuvHOrmgumw8DREGlfl3Fc9uQh4
         lk+s7OuZ/tHtonKtPlX43aNOplJX6Qj6BPDTwDNZreykMsTQpMP/atxxWXCDvwMAJP1A
         6TZOHhUl73y0V4MX88yKGBHv25Rj0N9rLIIG+U/JNELL7p1Loofs5/UxMy6t1NNb/yID
         tGT4bcyOxz0bMNXsxe+ovnZfgG3wFroOMCHiYplvf46D3Ih1/8lxKAL52/9vKs9T/dWO
         zmw8m52uVcVI0Gjkb0SHDqJZwdqLfoXdXinW4tGrG/YghI7hWzShIMGiMSL6xThB7uit
         nn2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740161289; x=1740766089;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/6Lk8md8WthVQXHwQYl587eMqN9VJk5ozT+prhvQFZE=;
        b=MdTMkEkmqZe5470zYgyV44aYp4mw5wgbE2Qf44vNP+/89s10WhfD5b9Nkc5QCDsQc8
         lAS4Qp8Ge9gCB+sj3OiSiEqT+Glfb0AgLgKosdLBIvzhIP6c4oy4xee+j4pQfNnNdSTv
         4eMinIRKv5oJmrj8SbCUeRJyWtu7gOMUkQB3UM13K0LteJYA1wQ0yqYGxv2hcok1Yr2z
         omPEodqYytNzUhaTLwaoBN3DkRcIBRhpsj4y2hxXeFA6KxKR778HvuEWJm4IO+9/Q1J/
         Lvis4PIZDIVjv/ffD2QaS0hFjk2/XgTlK488ox8T1LDnkvysxHOeMFZduuzEJzDhsf0K
         NZXA==
X-Forwarded-Encrypted: i=2; AJvYcCXL4EJsxMVAi9dymnYBlFt9l21ex8PoLO1ef2cQaFZp1Dva5lRUe8OOeYzT5nMR0gBWWVjjwg==@lfdr.de
X-Gm-Message-State: AOJu0Yw1ALNE9y7cMrnblvGapXtxfsSaXMl0YxAGArPdvv7zi1x0dHZ5
	vtI/2lafke2cnZRymCJiBO184KTUaA3fx7vpXqKOzkQctej3SrnH
X-Google-Smtp-Source: AGHT+IHw0v69gyKDDBwmYE/P0hZPhsqCPSkg9SZBDiXFLFJ5MIbHbLrzP/APB42V1foQrDKcSrNbFw==
X-Received: by 2002:a05:622a:11d3:b0:471:bcb7:7894 with SMTP id d75a77b69052e-472228b3b36mr58218621cf.8.1740161289131;
        Fri, 21 Feb 2025 10:08:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVG4S9F7yZ+wwh898mWjEGZUkAiickx4zgYe3Eyu0//zTQ==
Received: by 2002:ac8:750a:0:b0:472:731:a5a with SMTP id d75a77b69052e-47214fb55dals925301cf.2.-pod-prod-07-us;
 Fri, 21 Feb 2025 10:08:08 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX5tvEGm20j+waZkTXtMWOIYwcFlqGUTmJ5yaqLc6nEoZX5YIbZoHrUYdKxh2/hKvBgaqP6J5ZjTUc=@googlegroups.com
X-Received: by 2002:a05:6102:2ad0:b0:4bb:e5bf:9c7c with SMTP id ada2fe7eead31-4bfc023dfa9mr2933981137.20.1740161287979;
        Fri, 21 Feb 2025 10:08:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740161287; cv=none;
        d=google.com; s=arc-20240605;
        b=AfbakLieD9ldMhtxzcKtQcUrDYLb8hFijyCEe48qm/szm/uUzLTvz6+kf+w1kv+rCk
         sQPKtVSL4D/wnrwqUPiLPZqHLjfBKAr1DAiS7tARm5t7e5OaYZPHb2/297mCJel9Ar1z
         6xg4xTeaApq0RLkYuDdbsozVWnWqq2SBPwmg2lvGTc+gxgnZMloBHTuZ92CNnWH8R7SF
         efrKm6O/B/mEQVlqrruArpDSYfkYsGuXWxPm7XBCQSfZIwf3UM84jSpvwlmlmflUGrvd
         AJWqaEbTYBhrZSx1Fs51C3f6H28a328+J3FgQT4K99uEAn/A1VVz05RsOW46FW5rbk4N
         OBhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=0bFpjrtl0ZifJr6noG0TJauL7blZvWcOpQGSce2ON1s=;
        fh=6daLWNj2ng9AC7k6NsHppG+JXGUhij4U/k8Liihd2jM=;
        b=UVawgu1PeopFNuGxvLqtzxR6+EsNnOHKzwFm6w+J+pYLJYm0Ecz5kNGGvjepGNutSi
         Hw62L/ATU/FdmEcNZVvIi6OE/VsJpHe6/tk4Bo2ROckQVwARUDuh+PssePSHfKZGtViB
         GLvACgMMEG/suQbGJjfdr2FeqD9MVF0OdEcgjilMHxKG/SBu+D4xww4T/2P+6nO9W3wQ
         m/Ute5vjIq3UZRXARs/0kIy5rMgGAFnbDDATc+Px/1fFVu9wGEPeK+IbXl/P0vrco0q5
         zf7KbZqjjoNF+tCR4cmvUBdFsVYBd6Q3EMd7c/KICAUmNB+J3ibNBye9aPy6Nc/uGZPb
         q7ZA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=e9H5tiM+;
       spf=pass (google.com: domain of srs0=3afp=vm=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c04::f03c:95ff:fe5e:7468 as permitted sender) smtp.mailfrom="SRS0=3AFP=VM=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04::f03c:95ff:fe5e:7468])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-8692939dd7esi453231241.0.2025.02.21.10.08.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 21 Feb 2025 10:08:07 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=3afp=vm=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c04::f03c:95ff:fe5e:7468 as permitted sender) client-ip=2600:3c04::f03c:95ff:fe5e:7468;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id CD59E615D4;
	Fri, 21 Feb 2025 18:08:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id F2044C4CEE8;
	Fri, 21 Feb 2025 18:08:06 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 94967CE059C; Fri, 21 Feb 2025 10:08:06 -0800 (PST)
Date: Fri, 21 Feb 2025 10:08:06 -0800
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
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
	Peter Zijlstra <peterz@infradead.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org,
	linux-crypto@vger.kernel.org
Subject: Re: [PATCH RFC 15/24] rcu: Support Clang's capability analysis
Message-ID: <aa50d616-fdbb-4c68-86ff-82bb57aaa26a@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <20250206181711.1902989-1-elver@google.com>
 <20250206181711.1902989-16-elver@google.com>
 <a1483cb1-13a5-4d6e-87b0-fda5f66b0817@paulmck-laptop>
 <CANpmjNOPiZ=h69V207AfcvWOB=Q+6QWzBKoKk1qTPVdfKsDQDw@mail.gmail.com>
 <3f255ebb-80ca-4073-9d15-fa814d0d7528@paulmck-laptop>
 <CANpmjNNHTg+uLOe-LaT-5OFP+bHaNxnKUskXqVricTbAppm-Dw@mail.gmail.com>
 <772d8ec7-e743-4ea8-8d62-6acd80bdbc20@paulmck-laptop>
 <Z7izasDAOC_Vtaeh@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Z7izasDAOC_Vtaeh@elver.google.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=e9H5tiM+;       spf=pass
 (google.com: domain of srs0=3afp=vm=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2600:3c04::f03c:95ff:fe5e:7468 as permitted sender)
 smtp.mailfrom="SRS0=3AFP=VM=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "Paul E. McKenney" <paulmck@kernel.org>
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

On Fri, Feb 21, 2025 at 06:10:02PM +0100, Marco Elver wrote:
> On Thu, Feb 20, 2025 at 05:26PM -0800, Paul E. McKenney wrote:
> [...]
> > > That's what I've tried with this patch (rcu_read_lock_bh() also
> > > acquires "RCU", on top of "RCU_BH"). I need to add a re-entrancy test,
> > > and make sure it doesn't complain about that. At a later stage we
> > > might also want to add more general "BH" and "IRQ" capabilities to
> > > denote they're disabled when held, but that'd overcomplicate the first
> > > version of this series.
> > 
> > Fair enough!  Then would it work to just do "RCU" now, and ad the "BH"
> > and "IRQ" when those capabilities are added?
> 
> I tried if this kind of re-entrant locking works - a test like this:
> 
>  | --- a/lib/test_capability-analysis.c
>  | +++ b/lib/test_capability-analysis.c
>  | @@ -370,6 +370,15 @@ static void __used test_rcu_guarded_reader(struct test_rcu_data *d)
>  |  	rcu_read_unlock_sched();
>  |  }
>  |  
>  | +static void __used test_rcu_reentrancy(struct test_rcu_data *d)
>  | +{
>  | +	rcu_read_lock();
>  | +	rcu_read_lock_bh();
>  | +	(void)rcu_dereference(d->data);
>  | +	rcu_read_unlock_bh();
>  | +	rcu_read_unlock();
>  | +}
> 
> 
>  | $ make lib/test_capability-analysis.o
>  |   DESCEND objtool
>  |   CC      arch/x86/kernel/asm-offsets.s
>  |   INSTALL libsubcmd_headers
>  |   CALL    scripts/checksyscalls.sh
>  |   CC      lib/test_capability-analysis.o
>  | lib/test_capability-analysis.c:376:2: error: acquiring __capability_RCU 'RCU' that is already held [-Werror,-Wthread-safety-analysis]
>  |   376 |         rcu_read_lock_bh();
>  |       |         ^
>  | lib/test_capability-analysis.c:375:2: note: __capability_RCU acquired here
>  |   375 |         rcu_read_lock();
>  |       |         ^
>  | lib/test_capability-analysis.c:379:2: error: releasing __capability_RCU 'RCU' that was not held [-Werror,-Wthread-safety-analysis]
>  |   379 |         rcu_read_unlock();
>  |       |         ^
>  | lib/test_capability-analysis.c:378:2: note: __capability_RCU released here
>  |   378 |         rcu_read_unlock_bh();
>  |       |         ^
>  | 2 errors generated.
>  | make[3]: *** [scripts/Makefile.build:207: lib/test_capability-analysis.o] Error 1
>  | make[2]: *** [scripts/Makefile.build:465: lib] Error 2

I was hoping!  Ah well...  ;-)

> ... unfortunately even for shared locks, the compiler does not like
> re-entrancy yet. It's not yet supported, and to fix that I'd have to go
> and implement that in Clang first before coming back to this.

This would be needed for some types of reader-writer locks, and also for
reference counting, so here is hoping that such support is forthcoming
sooner rather than later.

> I see 2 options for now:
> 
>   a. Accepting the limitation that doing a rcu_read_lock() (and
>      variants) while the RCU read lock is already held in the same function
>      will result in a false positive warning (like above). Cases like that
>      will need to disable the analysis for that piece of code.
> 
>   b. Make the compiler not warn about unbalanced rcu_read_lock/unlock(),
>      but instead just help enforce a rcu_read_lock() was issued somewhere
>      in the function before an RCU-guarded access.
> 
> Option (b) is obviously weaker than (a), but avoids the false positives
> while accepting more false negatives.
> 
> For all the code that I have already tested this on I observed no false
> positives, so I'd go with (a), but I'm also fine with the weaker
> checking for now until the compiler gains re-entrancy support.
> 
> Preferences?

Whichever one provides the best checking without false positives.
Which sounds to me like (a) unless and until false positives crop up,
in which case (b).  Which looks to be where you were going anyway.  ;-)

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aa50d616-fdbb-4c68-86ff-82bb57aaa26a%40paulmck-laptop.
