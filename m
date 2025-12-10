Return-Path: <kasan-dev+bncBCS4VDMYRUNBBG7S47EQMGQEWMDWXFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A15ACB42A7
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Dec 2025 23:50:05 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4ee21a0d326sf5793411cf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Dec 2025 14:50:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765407004; cv=pass;
        d=google.com; s=arc-20240605;
        b=RaDeX6v28zFEGc87vEuMRt+yuYHNxLl6EhcMWzu8Kv8gIg+5s0rtscfVRB2nTncOul
         pyGS4UqivkXdRSTli/36rTaPiZs7zYYlG9CsVgLfbVTLOhzXAlp89UsKdxQMN82azki6
         0tj8PA4GevheFsgi6NSUlw+4CXnTgqCZ4jwffS7rqSliE1USKGfGkL1G+2XV05J2Ui0L
         UPz9GqWCmP1Etd5UkNfZIxy6kRKtuCCb4coSbjUMY2dszK5NIQxAnjUjR4hbHditwij1
         qSAU8UefED2MpWZ9CpcfiJ4or3g/zO3fUCrNdbUO979SwXI0J8G8ogMty2sYqvt5dpXq
         IIXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=QyRTAzlPWWeXvmk0IJIo/L4faQQ6CR65Pow+160aef4=;
        fh=3jHaPTCjNKbLzLw12hwB7KFZbsrWxjfXwAnUkraEBXc=;
        b=V8O9Q9cF4Orp3BZMhybWoOp+v9TeoDHvjJehaoZZVfCsQeCYcWCMk1/PCLS3m7gt6N
         b2lIz6fbdIEhA/wOwf5s/fw5H/fA8dgjgLlxJWrtcEDuUQHOh8fJLZFK3Cj/zRwetcva
         XkSLQ2ywo1hacA7ghz0tATJCXjB5fP9mb1FmYA4BpUHfLZ4mDkOJFYwdfIfNGHvYimsC
         2P2FWXmeTW11lD8HF7TxbemKUP7PYaiaBKFEzKIWBf6Cke2z1b8bidelXqZbxfEnOdob
         zy4EoGEL0wOaJePzDgoiuA0+UF6Q5xqTHZHJjW0IHjF+cK+rt+reorZsnpqChrdFiHZU
         jMew==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AO3exkGe;
       spf=pass (google.com: domain of srs0=0x6l=6q=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom="SRS0=0X6L=6Q=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765407004; x=1766011804; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QyRTAzlPWWeXvmk0IJIo/L4faQQ6CR65Pow+160aef4=;
        b=omo+1PMdq042ybMMqUhKP1uoqVt2Z6PwLdsNIcSrmty4AxwEM6krR5hpE30W/GTJlm
         ZLPhYETWJOrP1wglb5t+ktr8KmZg+gwlNfiMsOuMJf/26sQtcLDFxRSyptoND4j2mtzO
         j62FDUnjg1hWDk0Oku9bjdvln5mSwFhDl+FOePpFtskMOd30NdjVGawFM7eEdJ6dFHys
         6NBFa6FlOTyBtGkbGSFOayQr5wQYtU8yjZFvDMM+znOt2naOefrveBgVPbgfrRJ7HfHM
         gjZs9h7Cy38bdLDdXp/EsV5AWmdCc7PpJGZPR05fTrwpu4UQz8DYH/itAiPsnnWcv5e2
         OQRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765407004; x=1766011804;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QyRTAzlPWWeXvmk0IJIo/L4faQQ6CR65Pow+160aef4=;
        b=Sppl5sY4yaDDqBUpTwQ+Tio3ULzLlgHU4HpraTAEE7WdLYLztA0wk2qL67N8YeOVa6
         OC5fQ1anIvWQOF3Dkq6dHVIPW2krSNWMTjlepWfgS3tfGruojkWV+QVlvahbVLNnYMYD
         rjk6wiyGxl3qTUkY7b3pEmL8s/ZVGtFgDm36Ma+d9kXY65ODShaW3eF5dy3fFKX7Hufa
         CqVg+m1GMUEjzJToujThElrxKsaGslDZp01c7M6RT5+TfgE9pkbRiI+Q70zp3emtWU2m
         huAlRT7W/NmWWxNY70MZT/eheaqgqvJQUxCX1WgvxcWjDNJld9I9Hgc1dpjXz1QgW0yH
         KrGQ==
X-Forwarded-Encrypted: i=2; AJvYcCUYfLo/iGgP+cNLKRkrywwmHsWk62Ga08lhmTSZ3rs5ftH3Uxw6mtAwEjbRjVwCia5ViR/cMg==@lfdr.de
X-Gm-Message-State: AOJu0YzMjyvjePERFyJFyNIwptH17kuMgg7sPamlwplRdt+5wSb4PcKG
	YQgJYG7ZXl5NxzN39lufdrTuT30iCIa68w0NjvfU2YxXsEIj4LU5gnHa
X-Google-Smtp-Source: AGHT+IFPrW8BuyFImNZEe6i8SKujIPH0ly5FL0ftqVVnFLST7U7L3Ssv2aNtyQ0/O8Vhzl51QbJ4cA==
X-Received: by 2002:a05:622a:1a8a:b0:4ed:67bc:50de with SMTP id d75a77b69052e-4f1b1a69d29mr57584931cf.24.1765407003778;
        Wed, 10 Dec 2025 14:50:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWa0tS7PsMLlAplsHfpuKEFFURaaYXnAysgPyMCnKCvrtw=="
Received: by 2002:a05:622a:112:b0:4ed:e411:4bf5 with SMTP id
 d75a77b69052e-4f1bd8f40bfls3926761cf.1.-pod-prod-01-us; Wed, 10 Dec 2025
 14:50:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU3n/yoG4umewiu8aUc5WpAMODIh3ybx7ydsUPkZ4eqcR0vd8ZUYb/+IqbdGpwHAXT6PxFgRZMiuhk=@googlegroups.com
X-Received: by 2002:a05:622a:1487:b0:4e8:a442:d6b3 with SMTP id d75a77b69052e-4f1b1a937ecmr54816651cf.37.1765407002988;
        Wed, 10 Dec 2025 14:50:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765407002; cv=none;
        d=google.com; s=arc-20240605;
        b=gqwAFx8MMNgAxLrIgT70umJrHPNiL7y7GwWAPFyx+/XZlBq2kUl6Nsqv8iwHJG2KVH
         W/0JflB9eubtgB2F57uayOiqdmO7aT48ijMyyJUtxNR9/XkbiuTb8rcG4FBh/FqZnEMe
         n5O++msxAzmBF0mIfFRZjOGFXXCku+BGim1tMrSnjUBKg/wprIONbtV4KFEZRB7Yy1lb
         5Cbv2H4DL8LDDX89aExRqK4odZyciLmW4jeOBtvaxuG6BapWpgbJXQXWHUWY5cPbHDWD
         4ZVuYW8pvIxxoJG0+ptmas1o2ZkVHGFFXCTA6bjB2ZpWbSZX9nM57dzOpmFvXEXlhSFf
         TP6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=6FoZNt0nK3YYBtmZQJhBvmqydOQpluIdlIFzCbdFNYI=;
        fh=ydmDXTPQBUm8gYjTRTOr6oYMuSaewZBXZ+dcUdAtNU8=;
        b=awtyntUWP0JcjoTeiYyCbMFig4zTQfDkMMd8jI7ORQxAxYJZsiI3sRrodgtLfZH6tp
         8JG47HyeJSRe+ryBqBfIq2mWZn5EncsCPwqq/CfCZDBBmOejkt+fJx00E3sDldBgiyKF
         R2c+MJsqL7QthciF1/mOMiUJJnhW7rpV4omEDFPAPU/IRhodILLxFN8nX9u5a5cbTVKt
         GxOo+SZV1iwRp6fH0Tni5sqNvm8hTlVZVYGfWHyv6sufjzoRoga8u9JsKQgEITSMVq9y
         ne8B+zL2QepQwFAf7hDidYjsyow6TQQPPOBRnijPfY+GXhknRVioOWx4XapCgUvbky7y
         4pVg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AO3exkGe;
       spf=pass (google.com: domain of srs0=0x6l=6q=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom="SRS0=0X6L=6Q=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4f1bd590f7dsi357451cf.2.2025.12.10.14.50.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Dec 2025 14:50:02 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=0x6l=6q=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 113DC6011E;
	Wed, 10 Dec 2025 22:50:02 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8D001C4CEF1;
	Wed, 10 Dec 2025 22:50:01 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 31591CE0CA7; Wed, 10 Dec 2025 14:49:59 -0800 (PST)
Date: Wed, 10 Dec 2025 14:49:59 -0800
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	Chris Li <sparse@chrisli.org>,
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
Subject: Re: [PATCH v4 14/35] rcu: Support Clang's context analysis
Message-ID: <31a77eff-5295-48a9-96be-ecc7ff416317@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <20251120145835.3833031-2-elver@google.com>
 <20251120151033.3840508-7-elver@google.com>
 <20251120151033.3840508-15-elver@google.com>
 <98453e19-7df2-43cb-8f05-87632f360028@paulmck-laptop>
 <CANpmjNNsR_+Mx=H6+4zxJHwpRuM7vKUakS8X+edBD521=w4y_g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNsR_+Mx=H6+4zxJHwpRuM7vKUakS8X+edBD521=w4y_g@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=AO3exkGe;       spf=pass
 (google.com: domain of srs0=0x6l=6q=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender)
 smtp.mailfrom="SRS0=0X6L=6Q=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Wed, Dec 10, 2025 at 10:50:11PM +0100, Marco Elver wrote:
> On Wed, 10 Dec 2025 at 20:30, Paul E. McKenney <paulmck@kernel.org> wrote:
> > On Thu, Nov 20, 2025 at 04:09:39PM +0100, Marco Elver wrote:
> > > Improve the existing annotations to properly support Clang's context
> > > analysis.
> > >
> > > The old annotations distinguished between RCU, RCU_BH, and RCU_SCHED;
> > > however, to more easily be able to express that "hold the RCU read lock"
> > > without caring if the normal, _bh(), or _sched() variant was used we'd
> > > have to remove the distinction of the latter variants: change the _bh()
> > > and _sched() variants to also acquire "RCU".
> > >
> > > When (and if) we introduce context guards to denote more generally that
> > > "IRQ", "BH", "PREEMPT" contexts are disabled, it would make sense to
> > > acquire these instead of RCU_BH and RCU_SCHED respectively.
> 
>  ^

"I can't read!"  ;-)

> > > The above change also simplified introducing __guarded_by support, where
> > > only the "RCU" context guard needs to be held: introduce __rcu_guarded,
> > > where Clang's context analysis warns if a pointer is dereferenced
> > > without any of the RCU locks held, or updated without the appropriate
> > > helpers.
> > >
> > > The primitives rcu_assign_pointer() and friends are wrapped with
> > > context_unsafe(), which enforces using them to update RCU-protected
> > > pointers marked with __rcu_guarded.
> > >
> > > Signed-off-by: Marco Elver <elver@google.com>
> >
> > Good reminder!  I had lost track of this series.
> >
> > My big questions here are:
> >
> > o       What about RCU readers using (say) preempt_disable() instead
> >         of rcu_read_lock_sched()?
> 
> The infrastructure that is being built up in this series will be able
> to support this, it's "just" a matter of enhancing our various
> interfaces/macros to use the right annotations, and working out which
> kinds of contexts we want to support. There are the obvious
> candidates, which this series is being applied to, as a starting
> point, but longer-term there are other kinds of context rules that can
> be checked with this context analysis. However, I think we have to
> start somewhere.
> 
> > o       What about RCU readers using local_bh_disable() instead of
> >         rcu_read_lock_sched()?
> 
> Same as above; this requires adding the necessary annotations to the
> BH-disabling/enabling primitives.
> 
> > And keeping in mind that such readers might start in assembly language.
> 
> We can handle this by annotating the C functions invoked from assembly
> with attributes like  __must_hold_shared(RCU) or
> __releases_shared(RCU) (if the callee is expected to release the RCU
> read lock / re-enable preemption / etc.) or similar.
> 
> > One reasonable approach is to require such readers to use something like
> > rcu_dereference_all() or rcu_dereference_all_check(), which could then
> > have special dispensation to instead rely on run-time checks.
> 
> Agree. The current infrastructure encourages run-time checks where the
> static analysis cannot be helped sufficiently otherwise (see patch:
> "lockdep: Annotate lockdep assertions for context analysis").

OK, very good.

> > Another more powerful approach would be to make this facility also
> > track preemption, interrupt, NMI, and BH contexts.
> >
> > Either way could be a significant improvement over what we have now.
> >
> > Thoughts?
> 
> The current infrastructure is powerful enough to allow for tracking
> more contexts, such as interrupt, NMI, and BH contexts, and as I
> hinted above, would be nice to eventually get to!  But I think this is
> also a question of how much do we want to front-load for this to be
> useful, and what should incrementally be enhanced while the baseline
> infrastructure is already available.
> 
> I think the current series is the baseline required support to be
> useful to a large fraction of "normal" code in the kernel.

Makes sense to me!

> On a whole, my strategy was to get to a point where maintainers and
> developers can start using context analysis where appropriate, but at
> the same time build up and incrementally add more supported contexts
> in parallel. There's also a good chance that, once baseline support
> lands, more interested parties contribute and things progress faster
> (or so I'd hope :-)).

I know that feelling!  ;-)

OK, for this patch and the SRCU patch based on a quick once-over:

Acked-by: Paul E. McKenney <paulmck@kernel.org>

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/31a77eff-5295-48a9-96be-ecc7ff416317%40paulmck-laptop.
