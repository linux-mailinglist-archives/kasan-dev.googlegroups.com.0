Return-Path: <kasan-dev+bncBAABBNVST33QKGQE2XPGUCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B1A51F9C4E
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 17:52:23 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id e192sf21168752ybf.17
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 08:52:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592236342; cv=pass;
        d=google.com; s=arc-20160816;
        b=JAQMiL2M/1LIRPfYcCfC3hU/S+lw1+ZI+OP4zApayvs0Yq4rFvzM1nqd1SrxZ5U1DT
         haUuIn50Yqya+S2O1Ovf5ctNTBU7zww2CyGpMdmd7a6125zCgUmf6HKmzNze4i0AEDWq
         0BeUNaOEkzaedddHBDlbqBkgrKMmmfG5YbUxOcvnj5W6NJcHKoy9ZGRLA/CFrdc1JLc2
         exJ4TQ1MSgNskUQn/u6sapOdDIurVSAwY9qSMq65h/6EoWmbAZbTj1zSxo4Rwr1fg1fp
         CkMD50DwzuE7fxU7URCBGT+WYOMMVsdR0GQooI7o+7HonrsosY7ZGCnNCIomFoN2la+t
         HNDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=/SVnKGdEvMaeEWqF7sB2gwNq3c8vqXXnvO8ZyOq2USM=;
        b=iqRNjALJLo2WwStgL1v3aLMMxFrC1QQZhwMJ0Sgyef+xYzUQHNX5BIvaViDlYHgfr7
         +x+LGKjsDOe5zS/jdAT3XLkcUSGb3N5CRfvNrhBC4mBH3wzLbUKAxzUUzIjT8OtP7ciN
         X07e/ZLbesUjdMJrf3XqflZguKfx+OfLfSIkArNF4xJRR8d7kmhxe+GpPCwTvhxI/4z+
         q565LR1vHk2K3tOf37Jq5fF4JuL8GMyjRRMVNQjvKJWX2lUsww4YiSThoNQ5Jzx8gGTu
         id7v7Yi6OxNsFRfxJXU6dMoZvd/3yVKBH3kpMro5N+4D0OQYa4zrsR8M4oSXxzt82qsP
         H7PA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=AbWyZrgT;
       spf=pass (google.com: domain of srs0=xl4n=74=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=xl4N=74=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/SVnKGdEvMaeEWqF7sB2gwNq3c8vqXXnvO8ZyOq2USM=;
        b=mL3TJQt8ZtEBHTk03C2sYgDnCLKJX9NXcWBQLnurke+Y+3M5RZbdf8hhvQNKzcbdxu
         9AwFTPyxSnk+10r5UbgfNlUsS5Yf4yxcWHVvG7bADObpQLRzUnKFblxiZtZkZezaxk6V
         icH0RbcUvoS6TNgzXp0nUj9hgVl0FNhbk/fYd5g3fxv2Dlois25ANhydEZ9E6jy8EkBa
         /ILnpVdUTtiM67WT9VrUhjX7GToobrklRj0/vEFXxT+UnRwJnLCSxJCxxYHEqbkSH0TP
         eHau8Fi3TkzPQbWpNILUMDFpdRc6JMTVUF9fyoCq2cVDVx4/8Q2fVNIfR+nEq9A8dIiW
         uk8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/SVnKGdEvMaeEWqF7sB2gwNq3c8vqXXnvO8ZyOq2USM=;
        b=a6SUyjlZGWryfV5nhg5VaCD3RCfPz7J9E3dso5Q9+cfvO0m1oCAndssUQzhdDiQm6k
         d5Ug0l6bM9dzHBZSPfQPQBqrkMkrJ6i3gJS293gkgXzKpR5llaHCBMIJ69xCLU6r+j0Y
         6YFZlS+WaVbwHBKf8HkinuqmBlKOnwmcAC7jg1inT6+wsVxSxl6ZO6jInoMtPz8Q3+En
         5A0PsaF/w+ASokrfV+niQQwr8t8dfQHOM1I2yqc7N5wCY2JJeCzZd/2NmoNpBqF6ChtV
         dJsga4Tomv9rCZgazAIA36GKU7MYMj9/EfU0TOenbvMLGIhESc/M3L6frhqWtG/KHcSC
         P2cA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ld9lOWgcycediRZuc1iWXkl1/0Vd8n1SBFLLLidrAfjMPFdLw
	zdKXokon4hjri953NMNHyis=
X-Google-Smtp-Source: ABdhPJxORGTQFvY1inxTdEKP1a88Cnv6zW4Y3zmDwKGpdFrTQ+ikTwVgEuPR989a/8gLGBxbHSjl3g==
X-Received: by 2002:a5b:ec1:: with SMTP id a1mr44598174ybs.41.1592236342178;
        Mon, 15 Jun 2020 08:52:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6602:: with SMTP id a2ls6024904ybc.0.gmail; Mon, 15 Jun
 2020 08:52:21 -0700 (PDT)
X-Received: by 2002:a25:d90:: with SMTP id 138mr45423508ybn.19.1592236341855;
        Mon, 15 Jun 2020 08:52:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592236341; cv=none;
        d=google.com; s=arc-20160816;
        b=hTBmMyWQsQ1vBs4Qu6Is9GHCKMGxqB6SAGPcH93jBkLrb6K+y2Lcjen3sHzylOUbdS
         G6ILuVpaZHXk+Pxa4LKT/Puov9Cny1gkcZFKHucjaZ/2KIzzh5qNYVLwaqE7e3kDiHJy
         O6ak5ueK2D1fzA6sleRFvoupqYWJ+M29X7TQM4Hr6/dxNFU76zRcOB6BuqjEWivWjA9t
         RYA6oc8ZH7KTOZg5YV+2J5WN2Fr1I6kTV+Rh3aupeUrRwe8w/EDkMe/37TqR6ec6y66c
         aSTntwV0mR4LhXFFgehGhMYke1MyspfPfzFzz+WrWfdWcC05v8UfbAtS6vPvT7Bh8NCM
         3uHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=PWQAZd9i24tDAEQIsGv7qqBTIlRdxChM1cswRjsJquo=;
        b=iPMLedQBBR8rtMFNH79I3tLBkbD2ax2wIDXwRIyilBvor37kYXZ1+MIl5lQfs7BOY6
         CGskkpKZScPpn9JB5B+/orAwDEEsfwEMQ4ClWenBDxDjKLKtFP6bVCMUgFNHsUCKVTEA
         LUKBwC7lpSimBTzUOaxSe91EW8CZ7lWsSOlAqJMYuLTE7Or+AaEkN58zfshA7x8vlgHi
         F+PJjV5gYEPCcuMpOo5cT2VlpzkYGcJANMdk1Psazn+90UORl64ggsLf0dTAJvbneb3k
         Xa+G0fsdIeioOW3hXAWP4TApHgCrtkD9VphMPNnAnsC7Q9Iwrii5mUBC5WPU9kzW1QOW
         tHMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=AbWyZrgT;
       spf=pass (google.com: domain of srs0=xl4n=74=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=xl4N=74=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v16si1035488ybe.2.2020.06.15.08.52.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Jun 2020 08:52:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=xl4n=74=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id CEC67206DB;
	Mon, 15 Jun 2020 15:52:20 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id B3D063522EFD; Mon, 15 Jun 2020 08:52:20 -0700 (PDT)
Date: Mon, 15 Jun 2020 08:52:20 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: tglx@linutronix.de, x86@kernel.org, elver@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	will@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com
Subject: Re: [PATCH 2/9] rcu: Fixup noinstr warnings
Message-ID: <20200615155220.GE2723@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200603114014.152292216@infradead.org>
 <20200603114051.896465666@infradead.org>
 <20200603164600.GQ29598@paulmck-ThinkPad-P72>
 <20200615153052.GY2531@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200615153052.GY2531@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=AbWyZrgT;       spf=pass
 (google.com: domain of srs0=xl4n=74=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=xl4N=74=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, Jun 15, 2020 at 05:30:52PM +0200, Peter Zijlstra wrote:
> On Wed, Jun 03, 2020 at 09:46:00AM -0700, Paul E. McKenney wrote:
> 
> > >  	// RCU is now watching.  Better not be in an extended quiescent state!
> > >  	rcu_dynticks_task_trace_exit();  // After ->dynticks update!
> > >  	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) &&
> > >  		     !(seq & RCU_DYNTICK_CTRL_CTR));
> > >  	if (seq & RCU_DYNTICK_CTRL_MASK) {
> > > -		atomic_andnot(RCU_DYNTICK_CTRL_MASK, &rdp->dynticks);
> > > +		arch_atomic_andnot(RCU_DYNTICK_CTRL_MASK, &rdp->dynticks);
> > 
> > This one is gone in -rcu.
> 
> I'm still seeing that in mainline, was that removal scheduled for next
> round?

Yes.  Unlike the few commits following it, this commit seems to work
fine even with the recent changes in mainline.

> > >  		smp_mb__after_atomic(); /* _exit after clearing mask. */
> > >  	}
> > >  }
> 
> What shall we do with this patch?

I plan to submit it to the v5.9 merge window.  Do you need it to get
to mainline earlier?

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200615155220.GE2723%40paulmck-ThinkPad-P72.
