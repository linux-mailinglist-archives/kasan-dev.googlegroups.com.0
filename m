Return-Path: <kasan-dev+bncBDBK55H2UQKRBVNCQXFAMGQEQHHDQSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B182CC2C13
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 13:32:23 +0100 (CET)
Received: by mail-ej1-x63c.google.com with SMTP id a640c23a62f3a-b79ff60ed8esf747682366b.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 04:32:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765888342; cv=pass;
        d=google.com; s=arc-20240605;
        b=DtIp5SlvRLYc2sbwP+YYtNw/F8GxVN/OCSrGGMv4RVxRHuwEkUIk0Q9FL8O0J36PxJ
         bFvmC+DY8dhvepF6CdgNjhAU4ATKAYL0sOGIHtZcT9sAdFqUoOFHHUOMhKa1Ytr09ah5
         DrEQz4NBbijKdWVkW7b/G36sfAESr603dgMRhPx4S17ZGqt+kmU3OWSQw/vszFBiBnnT
         FCM2IFVprJ6Lk9gMGH1Zzgtl8BtpvckLwn6JfJzeVjz566KOrnJVjWrsWli8NwfEI5pf
         SgtqITW3wwUvabT+yIdI+IUe+W2rPEivRKvwVTzJDsnzbQsvSm/uK8NNcwas8jL6o1oM
         jY1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=hJ9f/ybWANzLJx+3XMwf5iBRhgqDgjXYmKUJDhOzmCo=;
        fh=X7/gc9fqV3nAKdeBCaYeb9YOuH1zFaDOGicFojeNPfk=;
        b=M+I2i4GWGOFgP67k/YTe6quSk3OOkTWTkdEndgJTrWNNu1GYiIFwFj0Ch9aE3VFxNP
         4rD2b1REbo15+FxvS+fq90n1yvimbJk306MdCzoz+rbw7uKHTQTdqqph3/xdlYk0nu/t
         l+uo5TVugMvwOdMNMwEelRKGnusLe3K/TXpkiEYmKCW6WZPm4b9cd3HkOGmXbCz92Xqs
         NQDyyPn7GBUKrV89wnBmw5fL4z3C7WV00QergXy3nNjQ9xKoNPjOcHc3JTdEmgw++CeN
         gwT4HWgOY6q8nAAHHGRrx98abtRdBdlYj13cHx4I7/z45TAGmCBe4A3b+3L4bbe+5VMA
         T61g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=aULM0WOR;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765888342; x=1766493142; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hJ9f/ybWANzLJx+3XMwf5iBRhgqDgjXYmKUJDhOzmCo=;
        b=GLqGJ6Y0pGOHrMhChkQ6tDUpE8HTs4fVxofCBwqb6qkslGJsi1gNMuV443uUinA2pl
         SoRqEvDhCMedATnxhHNJvh+WWWiPjB8u7r4Z3xRch+RKJV1/wBH2f9CcBktXrBQeImWL
         4sKgAP9ZDNxNh5S/VFOymyBQU+fhlpqSNKqbRerRBFWVY80m9NElFYtdFQesE5KlafTG
         zPBcowP1dOg22LbNHLGitikfDNkovL6a9nwNdYOutmTpIHtXDduggVoOMNRjg3FiMexY
         eO3Pz1OKVb6cdDC44JOx8ag6gmgGAAttWWbrjOut49qNxIA0UOT/WDxS7YIKGK9uqNn0
         mpLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765888342; x=1766493142;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hJ9f/ybWANzLJx+3XMwf5iBRhgqDgjXYmKUJDhOzmCo=;
        b=QCcu3VkDjvPpQqMezliU8nGnSiYjItLm2lWb91D/F5KbA9kaolTP03pOSLlsyKPzrs
         D6XP5to5BghWhohtKs77PJWH2rYGyn7qKgM4t++DNCGW5VFcjayUoYsjaPCx1lMaU74m
         QdAE2LHMylf+dsasb8Ab+mKXNjRvnpBPbLzqbcUyAN1D0biKSs08CMv+6dswuUMvU/iw
         HG/mpYjnOlxjm0EpnDLRwWj7mjzy0taysoSHk6abtxwLseNCGOTPqzzTlvbXfD0aOEoM
         FuOmXBOwZpgn8+tEz6AGu0DogqGYTQUtjtYg/XbfxR/P9dhG+5bV6Shpqz/bdFHM27Hy
         9c0w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU8lHpQLJUVnb6GJWvZcONN/MUHfSK+87Vgn41CexMNGR5Y8SDFK244CjQxPi9ACgiWLa9m4w==@lfdr.de
X-Gm-Message-State: AOJu0YyhoN2VMTrsK8Mp1WockuZ1nyWbn9mI1KjdS43QxhkSdQzJkyFR
	JensPyQyLlFXECqTso2J/S5GtUZBbnVdCdx9t/9PIi/Auj8Z34GLIazz
X-Google-Smtp-Source: AGHT+IFhLKoFCkKyI2BhNbwRYt6PxlO2eZ+reOuIjgpyHyYnddLEH1jS8Lz0zU1vCMOYbHybUJaGfA==
X-Received: by 2002:a17:906:c148:b0:b70:aa96:6023 with SMTP id a640c23a62f3a-b7d236e0348mr1428180166b.24.1765888342046;
        Tue, 16 Dec 2025 04:32:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZyZHPcb6RJDPEhDXN3Mzb5HKW+9OlC8XrNWJHO9bZ4KA=="
Received: by 2002:aa7:d5c3:0:b0:641:5a07:215b with SMTP id 4fb4d7f45d1cf-6499a47a9dfls4875531a12.2.-pod-prod-06-eu;
 Tue, 16 Dec 2025 04:32:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVJTHiVPGmTKkRMmyHven5V29GGA4d7ij+MK0TYnVmiYFomXid8+pYr6YRfrw1N8p9SwIQSyATJ/ZQ=@googlegroups.com
X-Received: by 2002:a17:907:da2:b0:b76:3599:649e with SMTP id a640c23a62f3a-b7d2362ae70mr1416119066b.11.1765888338631;
        Tue, 16 Dec 2025 04:32:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765888338; cv=none;
        d=google.com; s=arc-20240605;
        b=iS4ESh6NyBQJuy0IBBTsPEUsn770n4Xxb6RAkVFIsj25lAwMuiQsgeqdMGjTlTKmX3
         5WBQFLjsrv5uW9Ay09f0DzQHkWOP9wd/Q8dEobWu/qu0/IGYrksHKF7GUBAe4KNseu31
         DgpoJgotjm57NPYWyE1ThFYn1rF2hf0hmTm0StMTKwKs2uGQIKchSsPUGJXC6daN11J2
         HRf/B3byApr5I/sCx0PGtM6vKS7FzpVPC6naNPUo5h0FynpHnqrnmHJ2e8Bi7UppMFGQ
         3n+eNKeRfB/8EOBcNSVMgo+apucppYOQRhgqn9vDaTKH9+vVf45RZzBTQO6TjT+Fn/CM
         Q50Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=PT+1SSkmSVMS0Ka1JPI8XlGmFQ/04yBEbtnblqzrJZU=;
        fh=0851L0nspSnj7qhIjXjlHLoAWeF01NCU66B65AWv7JQ=;
        b=XBaZzKUrbK9Hj3zCZDJryuvEXX6QFtTFaTnDm4Apl9u0ZWnprQGeNNOWEsA1Ulffqe
         lHwSovVgF0UdLwgPHUd2pI+sGir65MTWVyhsXswqGAvxpxgrBok7z6I2U00NwuXhWOW6
         JWTD0CqelT7U7X82o53lvh0vJo5PQZIgiQfY3WV9GANjXya8Xm06T6DHuYdpP6PV4Za+
         tT6ZISgcm3OU/DMbz0yobAkRgOCajwl2HAspB3c8awXKKdtYEY5IylhA+QTlTVjbWquY
         NBEhMDZwIL6KaIHROvJGTTgvN8ykHxaY/BA7ktMIauPsfNgwdEIlUwYTB5NJ6Sh9c18F
         iV0A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=aULM0WOR;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b7fc026b778si8706566b.3.2025.12.16.04.32.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Dec 2025 04:32:18 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vVTMO-00000004iUO-3Ujr;
	Tue, 16 Dec 2025 11:36:56 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 9425D300220; Tue, 16 Dec 2025 13:32:11 +0100 (CET)
Date: Tue, 16 Dec 2025 13:32:11 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	Chris Li <sparse@chrisli.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>,
	Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joelagnelf@nvidia.com>,
	Johannes Berg <johannes.berg@intel.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Kentaro Takeda <takedakn@nttdata.co.jp>,
	Lukas Bulwahn <lukas.bulwahn@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, kasan-dev@googlegroups.com,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-security-module@vger.kernel.org,
	linux-sparse@vger.kernel.org, linux-wireless@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org
Subject: Re: [PATCH v4 06/35] cleanup: Basic compatibility with context
 analysis
Message-ID: <20251216123211.GT3707837@noisy.programming.kicks-ass.net>
References: <20251120145835.3833031-2-elver@google.com>
 <20251120151033.3840508-7-elver@google.com>
 <20251211121659.GH3911114@noisy.programming.kicks-ass.net>
 <CANpmjNOmAYFj518rH0FdPp=cqK8EeKEgh1ok_zFUwHU5Fu92=w@mail.gmail.com>
 <20251212094352.GL3911114@noisy.programming.kicks-ass.net>
 <CANpmjNP=s33L6LgYWHygEuLtWTq-s2n4yFDvvGcF3HjbGH+hqw@mail.gmail.com>
 <20251212110928.GP3911114@noisy.programming.kicks-ass.net>
 <aUAPbFJSv0alh_ix@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aUAPbFJSv0alh_ix@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=aULM0WOR;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=infradead.org
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

On Mon, Dec 15, 2025 at 02:38:52PM +0100, Marco Elver wrote:

> Working on rebasing this to v6.19-rc1 and saw this new scoped seqlock
> abstraction. For that one I was able to make it work like I thought we
> could (below). Some awkwardness is required to make it work in
> for-loops, which only let you define variables with the same type.

> 
> diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
> index b5563dc83aba..5162962b4b26 100644
> --- a/include/linux/seqlock.h
> +++ b/include/linux/seqlock.h
> @@ -1249,6 +1249,7 @@ struct ss_tmp {
>  };
>  
>  static __always_inline void __scoped_seqlock_cleanup(struct ss_tmp *sst)
> +	__no_context_analysis
>  {
>  	if (sst->lock)
>  		spin_unlock(sst->lock);
> @@ -1278,6 +1279,7 @@ extern void __scoped_seqlock_bug(void);
>  
>  static __always_inline void
>  __scoped_seqlock_next(struct ss_tmp *sst, seqlock_t *lock, enum ss_state target)
> +	__no_context_analysis
>  {
>  	switch (sst->state) {
>  	case ss_done:
> @@ -1320,9 +1322,18 @@ __scoped_seqlock_next(struct ss_tmp *sst, seqlock_t *lock, enum ss_state target)
>  	}
>  }
>  
> +/*
> + * Context analysis helper to release seqlock at the end of the for-scope; the
> + * alias analysis of the compiler will recognize that the pointer @s is is an
> + * alias to @_seqlock passed to read_seqbegin(_seqlock) below.
> + */
> +static __always_inline void __scoped_seqlock_cleanup_ctx(struct ss_tmp **s)
> +	__releases_shared(*((seqlock_t **)s)) __no_context_analysis {}
> +
>  #define __scoped_seqlock_read(_seqlock, _target, _s)			\
>  	for (struct ss_tmp _s __cleanup(__scoped_seqlock_cleanup) =	\
> -	     { .state = ss_lockless, .data = read_seqbegin(_seqlock) };	\
> +	     { .state = ss_lockless, .data = read_seqbegin(_seqlock) }, \
> +	     *__UNIQUE_ID(ctx) __cleanup(__scoped_seqlock_cleanup_ctx) = (struct ss_tmp *)_seqlock; \
>  	     _s.state != ss_done;					\
>  	     __scoped_seqlock_next(&_s, _seqlock, _target))
>  

I am ever so confused.. where is the __acquire_shared(), in read_seqbegin() ?

Also, why do we need this second variable with cleanup; can't the
existing __scoped_seqlock_cleanup() get the __releases_shared()
attribute?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251216123211.GT3707837%40noisy.programming.kicks-ass.net.
