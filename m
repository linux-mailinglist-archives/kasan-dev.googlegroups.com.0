Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5PG4K6QMGQEWWNB3MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 42F0EA3FCEF
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 18:10:17 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-38f39352f1dsf1004664f8f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 09:10:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740157815; cv=pass;
        d=google.com; s=arc-20240605;
        b=b7Av4Ca2kWdvfc5v/oDo50sb6pZE77C6D2jaw4/gD7tNCvVjdzQVGYK2oSFivhjU1s
         NkhrmN3QNtlF6aQnE0D6awDLysbKXN+JRinmzTNqiEMPQZhJN64Rnwqka4DazR/x5Hzy
         Sz/4CtpUpab5bXGmJf+WzZvARIlUFdFDop0wCjvUW1QCCTnAqd5q4gZcs8YiOdPNo7hV
         ORGbh1xMG0M2okhY6GKQwBSPWP5VtCL8zk0uGGPPCXxnhEvCSwOvK9fk2+9j4fxFLoLS
         PtjSgBRxLpeGWJDe0suuY2NCyu5bpoFb6UQdv6XriFCOKJ+oADntcE/py+8rDunxESVV
         nBoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=StzVk2o07DTEadkjuM9W3vNlltBJn1mkaUd1jywJOmY=;
        fh=iznsNNVA66i39RPXoHzdduYlnLSXQyHKekSdEc2mW7U=;
        b=VRJH5UoS45YX0SEqlXWS8VzJ26ccRZAq6kknHdgBX/DZaMyHgEqMiWQ9CeCPVZAhYj
         yDYgnMj1dMEjAEkMAVZ6phDcy6dg+JFD4lXBDcsMjiJp+yZ4Z+JJ8+x0WjmX3NxYwQu+
         BysYot67Z24LQMq7UIETh21RZs4GcBvtp5nVIuy5JZxOO4QwMjCOjid/2jjsOzjo9uHq
         Tkng8zUnysURJDt/gCE+ieM7brIpSg3Ib+gP4jFw66I3H1fT24DhNLjoG8NhnWeuN+q3
         iLpiw0xecFue9QXDHLBGBYTjhF1t3FzpYrtb+1JBb8w7WvcjCqcsoXsHd9ND77zuc5Tc
         xdrg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=t7daMEP3;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740157815; x=1740762615; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=StzVk2o07DTEadkjuM9W3vNlltBJn1mkaUd1jywJOmY=;
        b=wkkTFsBkZdxabFwxG75Y+TVJVrAh29X9DFJDMUlQKTKelsHc56N+eBckMv45ejqkKh
         wfj93rTyVXEzg54Q4Kw9NsqcWyIR0FwEdbij40DSEOtYcEWhPCVU6VH+tKH3UNGj+hLG
         oxVqbeVEYeCulKOhgNlBpgiNhinnBqJR5tRbG9Qyk9l0U9zBhGIj9ePgI/nsQiiFhOD6
         HWjlA2T778tDAljUgN/wGLgk7zi5S5Qm4UgMUMP/wg2bBvedXAwrnzEbxJWx1GUjSgh/
         xrnlbExJipjYR6Lpy/H+GkvOhMzI2BsxHoKIapiixut00nQWknXiWYu+q77FR7o6Qo00
         h5xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740157815; x=1740762615;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=StzVk2o07DTEadkjuM9W3vNlltBJn1mkaUd1jywJOmY=;
        b=Ve92L/ZLcZk42vshh2aWM6Ox50XLoHbRMD3SdwKL7gpAwEmvzRy2b6xVN0EUUKX5Ry
         NnBP+RwxuFWC3IicZuJOdHNaoN9j2imL0ACj/6CvTtB16Tm2e+NAJdh6pwMUAvdLpy+Q
         +U/wXwayJEm9X1gmWEJ/sZEKHzBwdxolLAdsPp1zzSUjrbNJyblf3F3t8Udz7SHrcvWo
         7eKZrf9+oQpLbqG46DKdtRk0LxRp9pjP8W0Y+fNlu+2MgUYK5Pz55NMEsUJNHewjU6cG
         1P42lAvntgA36eMsKspB7hpD3NtM/wDma8XxTYtPlUUmVb7yYo3Te9TyyZaUJdN7imGw
         o4rw==
X-Forwarded-Encrypted: i=2; AJvYcCXVlC3BFsJIYI6cgH6UCXTulvIHfctUX0r+V/C1tUg5144BMu2eKsUoJLUUprbqgpUvT3tpGg==@lfdr.de
X-Gm-Message-State: AOJu0YwiuQpaD9wnHtGg8vVeMxVMT4fbQyEsBXsMXNj0V9mSKrUcqjQz
	71jXsnyYtBTIKP72//q0LdpjVfofsfGlSGwVo0ok5QfKpYK80t/0
X-Google-Smtp-Source: AGHT+IEl0a78pirgU0qBQYSUV9x1hc+HTVaYjFNKmfMtVKHzh/k9ITNBVibaq9Z37rDTxvCkiSzRFw==
X-Received: by 2002:a05:6000:1789:b0:38f:3de0:d16 with SMTP id ffacd0b85a97d-38f7085dc1dmr2501428f8f.52.1740157814246;
        Fri, 21 Feb 2025 09:10:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFWL2EzXfFrwCVHZXKd4zdLg8rK//48pXnvRFOsywzXvg==
Received: by 2002:a5d:5f55:0:b0:38d:c1e5:15ce with SMTP id ffacd0b85a97d-38f6f859259ls603528f8f.2.-pod-prod-03-eu;
 Fri, 21 Feb 2025 09:10:12 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVii2lIRJXvm11NRmcWKwnvLnZtI69VhUulLgvpeSFJNxvwPvWjBq4ynVQ61MxaD7xOBHeLmyaK1jU=@googlegroups.com
X-Received: by 2002:a05:6000:188c:b0:38d:b113:eb8 with SMTP id ffacd0b85a97d-38f7078b9e6mr3331641f8f.20.1740157811883;
        Fri, 21 Feb 2025 09:10:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740157811; cv=none;
        d=google.com; s=arc-20240605;
        b=ej5UolLghZh/JShH8VCuoptIKSTwBxlLYdRE2+WvYyNDDiyis08Bbfnvh4eURI8lEw
         iEDpDSDyUmxw8wOvTkQrZp42hkd1TDw73x8TN6a85Z0/293lIuzOnFRLBtJNtbKZwAOq
         OTWnM2pf6duGStZ4d6E/fOwhgkvOazFk+2q39uI9SUZHCuVHMwLmWK9u0pUO1/d3DVC2
         as4f5PE2lWFvNeNXLbhMGtlW82CaFDFq34AihRMLicvU6Z81vTz9hZC3JiMoIb4IjcrB
         8LIMOjLhMuGwBOw5Mmr6O7wUMTxNUTSvIZsyZno+emErhKlP46riQckj+UumQPpVA5JF
         PoSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=9Ae5OH7jwtkminWKyF9PaRglXPc6x2IkfIyVHHThfxY=;
        fh=7jCD/IjCWp5yE7/MWovzseSZEoANmZM3OvNrLiJP+fU=;
        b=STyLjgZwrDd9HM4YQym4YSrEY0TP2zLaiuTnnSdSf8aiWwURJS4FwD+rYVZN1AQXdy
         Xo6tUKeJBdmT+asvX3LcXMEXw3l9K6wmGmd5Y/YB59juMWlVFZJIVScG9uAybLVRLMwz
         dglhDYTr+PCYFf8rDpDQHt3wNYN0u4Fs+o39Q0wMgy3cAjC/+gwAQnWaRsa2+sPNGFPo
         XwrSwy2eEKsgrt4jBJn6d7ULGRUn60u3axGMy9J8bAGsdaqW1egnSa1bvPSSk0sAIPHt
         2ULmsFgZN4xtCvMobRD9sqEGUmmqSOKYmYPlYQFgxklm0spmlfn5GlTTfY47LCu5JqX2
         oXDA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=t7daMEP3;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-38f2589a0e6si581151f8f.1.2025.02.21.09.10.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Feb 2025 09:10:11 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id ffacd0b85a97d-38f3ee8a119so1205276f8f.0
        for <kasan-dev@googlegroups.com>; Fri, 21 Feb 2025 09:10:11 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVqMGZCNLW+qjKqsDHmV/ioZQmnqJBqnScDvQu6qzd46kojmGcBqiTQcfKqpZIxKisG7opkK8LVYeY=@googlegroups.com
X-Gm-Gg: ASbGncujqdICwCoGDG1x6O1OAJHahSdqFH9xWmyg/hYDqiRbABvtW/DPcT9pXCNeyEX
	s/tFI046Msz4/bEwQigNmDJM6avggdY18zWt5nG1AbAwtAiwZPMeyOTqvV3ozCdfdLE2m0A/S0I
	aVopCMaYuFMBwh698th9/Db+RdsXnnRfm5YapKCOY9nG8qkvE4Y3uqISkpz1MKZy3LnYWQtDsUe
	6wXgsuRBMb7ajMrrdISV+gvw34b9wKYjsOVKbqIXHjylCbhAKVhnNOnryivfYtBkH4CvMwOvNra
	bfV9BM74dj6u2oB54y2TknNZTyc20pl76kIZSZ2rtT7WLnZpR+uzm+DZv9je
X-Received: by 2002:a05:6000:154a:b0:38d:e3da:8b50 with SMTP id ffacd0b85a97d-38f7082821bmr3755812f8f.39.1740157810923;
        Fri, 21 Feb 2025 09:10:10 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:2834:9:9d7a:cec:e5e:1ee2])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-38f561bee3esm9232017f8f.21.2025.02.21.09.10.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 21 Feb 2025 09:10:10 -0800 (PST)
Date: Fri, 21 Feb 2025 18:10:02 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Paul E. McKenney" <paulmck@kernel.org>
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
Message-ID: <Z7izasDAOC_Vtaeh@elver.google.com>
References: <20250206181711.1902989-1-elver@google.com>
 <20250206181711.1902989-16-elver@google.com>
 <a1483cb1-13a5-4d6e-87b0-fda5f66b0817@paulmck-laptop>
 <CANpmjNOPiZ=h69V207AfcvWOB=Q+6QWzBKoKk1qTPVdfKsDQDw@mail.gmail.com>
 <3f255ebb-80ca-4073-9d15-fa814d0d7528@paulmck-laptop>
 <CANpmjNNHTg+uLOe-LaT-5OFP+bHaNxnKUskXqVricTbAppm-Dw@mail.gmail.com>
 <772d8ec7-e743-4ea8-8d62-6acd80bdbc20@paulmck-laptop>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <772d8ec7-e743-4ea8-8d62-6acd80bdbc20@paulmck-laptop>
User-Agent: Mutt/2.2.13 (2024-03-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=t7daMEP3;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::436 as
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

On Thu, Feb 20, 2025 at 05:26PM -0800, Paul E. McKenney wrote:
[...]
> > That's what I've tried with this patch (rcu_read_lock_bh() also
> > acquires "RCU", on top of "RCU_BH"). I need to add a re-entrancy test,
> > and make sure it doesn't complain about that. At a later stage we
> > might also want to add more general "BH" and "IRQ" capabilities to
> > denote they're disabled when held, but that'd overcomplicate the first
> > version of this series.
> 
> Fair enough!  Then would it work to just do "RCU" now, and ad the "BH"
> and "IRQ" when those capabilities are added?

I tried if this kind of re-entrant locking works - a test like this:

 | --- a/lib/test_capability-analysis.c
 | +++ b/lib/test_capability-analysis.c
 | @@ -370,6 +370,15 @@ static void __used test_rcu_guarded_reader(struct test_rcu_data *d)
 |  	rcu_read_unlock_sched();
 |  }
 |  
 | +static void __used test_rcu_reentrancy(struct test_rcu_data *d)
 | +{
 | +	rcu_read_lock();
 | +	rcu_read_lock_bh();
 | +	(void)rcu_dereference(d->data);
 | +	rcu_read_unlock_bh();
 | +	rcu_read_unlock();
 | +}


 | $ make lib/test_capability-analysis.o
 |   DESCEND objtool
 |   CC      arch/x86/kernel/asm-offsets.s
 |   INSTALL libsubcmd_headers
 |   CALL    scripts/checksyscalls.sh
 |   CC      lib/test_capability-analysis.o
 | lib/test_capability-analysis.c:376:2: error: acquiring __capability_RCU 'RCU' that is already held [-Werror,-Wthread-safety-analysis]
 |   376 |         rcu_read_lock_bh();
 |       |         ^
 | lib/test_capability-analysis.c:375:2: note: __capability_RCU acquired here
 |   375 |         rcu_read_lock();
 |       |         ^
 | lib/test_capability-analysis.c:379:2: error: releasing __capability_RCU 'RCU' that was not held [-Werror,-Wthread-safety-analysis]
 |   379 |         rcu_read_unlock();
 |       |         ^
 | lib/test_capability-analysis.c:378:2: note: __capability_RCU released here
 |   378 |         rcu_read_unlock_bh();
 |       |         ^
 | 2 errors generated.
 | make[3]: *** [scripts/Makefile.build:207: lib/test_capability-analysis.o] Error 1
 | make[2]: *** [scripts/Makefile.build:465: lib] Error 2


... unfortunately even for shared locks, the compiler does not like
re-entrancy yet. It's not yet supported, and to fix that I'd have to go
and implement that in Clang first before coming back to this.

I see 2 options for now:

  a. Accepting the limitation that doing a rcu_read_lock() (and
     variants) while the RCU read lock is already held in the same function
     will result in a false positive warning (like above). Cases like that
     will need to disable the analysis for that piece of code.

  b. Make the compiler not warn about unbalanced rcu_read_lock/unlock(),
     but instead just help enforce a rcu_read_lock() was issued somewhere
     in the function before an RCU-guarded access.

Option (b) is obviously weaker than (a), but avoids the false positives
while accepting more false negatives.

For all the code that I have already tested this on I observed no false
positives, so I'd go with (a), but I'm also fine with the weaker
checking for now until the compiler gains re-entrancy support.

Preferences?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z7izasDAOC_Vtaeh%40elver.google.com.
