Return-Path: <kasan-dev+bncBAABBYOHTTYQKGQEFKAZS6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id EDE481441DA
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 17:16:34 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id l13sf1851524pgt.5
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 08:16:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579623393; cv=pass;
        d=google.com; s=arc-20160816;
        b=SMc19Ax5tR1vjvgS1+Fi9vV1iVbDwkwIhScfOsjBUiUc/yxVXnC5epbnQAAyR/4kwG
         ZZcUCwBOfYf3uQjBbE5XNctFQ0tYCCdw5Jic81bX/gqwE74+6IPoLnOEJHhyhJl0nWVa
         /sHH03OwjuNdBd1/so0g2mHhqa6lJcla0vFLIOtSw4V+kZUdjmJa7GU2py8WYMv+wdPi
         xZYz8+Jo69bF1zXJuMWVvwBKKyjdXbKvC4wVVYhKlhu/N7hGPCRA4EsKBvP0DgFoKuw2
         OhGlppiMboxzYdR5s5O3NfaVOTTDgb94mZoXzfn/RsTBYFivKT2vOqlMR0rLmT8r/vvk
         pI7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=K/eUzAUZgVk5rjsKQgqez7nxW9g1XfJ4HrF3yn7UMmE=;
        b=xETzzgQN033TWUFgxr4xxSMEL4tOE/DPRNQ2r6xmrdMIv/S/P2MKPATyAoBa0egp0c
         pwBdFPAZQ5jBYjJ5WY4pQvh+Q5lAdZhy56rV9ry/ZGxNSX3BLtfPeh4AyTGWqBd1DlNf
         GPlGUq3pQDX3dSG13mXYfzKGStDRU0B9WytBCj2xAnCGNWjT15A/YtbOl17OLUFUDzVd
         TgBhprZTIUZ0CdUdA5T+uXUj+DHwlKOA8hvVBCkYXc2E1MRIn8Dyk36I9fVdHXMP0fx/
         XNBL2M40qVuE+vj/1JbKUNHv/SDqyaF3LD/S6TcovIlJeLJQ6W9oXOd9aEj4qH5svsfv
         XjAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Il7G75GL;
       spf=pass (google.com: domain of srs0=adgr=3k=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ADgR=3K=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K/eUzAUZgVk5rjsKQgqez7nxW9g1XfJ4HrF3yn7UMmE=;
        b=d64CxH7OOM7ceHRF6M0CpchQWXtOTF2eorw0DI50nygmRxID1hE+7+2EPup6IERJ8b
         s88V4mgzc1AsB+PU9fntgD+RHQb9zfaeq1EnIPO5z18nGl3wZiDfQa6Nhd94Tb95WOIp
         UhBUq6mVjAgVM196QRC2wmKiJeuVS1PlcDAvYVyrMsHuMWmP3MxRNSowVIW+dPsYNhpQ
         PiM3VCq4OEJ04t6AAr+dRGaQPHaJWi3lPFfcHivpmHc5CSwlqFXvOHucMXY/K+th+TMm
         eXG/PP5QcJ4NFBdzd9nWpFTtBXXt7q6BCdaZ8P7GdE5UInxT/OmN7tHaN7NLGZKtlMle
         b8nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=K/eUzAUZgVk5rjsKQgqez7nxW9g1XfJ4HrF3yn7UMmE=;
        b=RwPILTAuvWIAim4xuN53SeXWlvFSTsbJ4YjFXiRZr//NPENvHVCcVoNqAS8imLwkdT
         KM58X3rTvdzYPzMmxX7l/2M8UMFhe6lc7SHXwurG58ce3yqvH21xnkpv51P+obL3uLeE
         2nkdiXGSfwK3TH1iIOWtNBIfw6A7jv2LUtRwIOauC7QNnNNWemsdIiVcijFcGSIEpX0p
         vMwi3lIaDxgirNZSugwP8LerUH4L245Dj89qcL1g5hX7lstO37RmRB84NhBi3m+riMgL
         YZserRF6FjdAW4xxPgea+2SpR8KV6VoLRuyBvG3e7A+mGkWdXFnxRGP9hZ4ryCykZ8E9
         IqMA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWQPaBGQKTGLR4yY7xJWeGEvDTUQnCxKqknZcEuWiQPr/uyw2vo
	V2AytQgdXRpbv5jev68juHs=
X-Google-Smtp-Source: APXvYqxMQJPVNqWffULn5z4Xd1XpWo9o9+e96nYtVsGBCoHdg+OS0AjDFIv7JIxzG269qnuXfuQXeg==
X-Received: by 2002:a65:578e:: with SMTP id b14mr6267404pgr.444.1579623393592;
        Tue, 21 Jan 2020 08:16:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:d007:: with SMTP id z7ls10966153pgf.9.gmail; Tue, 21 Jan
 2020 08:16:33 -0800 (PST)
X-Received: by 2002:a63:cd16:: with SMTP id i22mr6488369pgg.239.1579623393157;
        Tue, 21 Jan 2020 08:16:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579623393; cv=none;
        d=google.com; s=arc-20160816;
        b=1Ksqla6Ru0YPtiT9liUULzsOxXSG1NOlTdwDmNt5lBNCrk0yTxGv7zq8jvLALBdBuJ
         f5r1ffkaBpIeED+9X9cl+7PBOE/qv4gLluLFQkZM7rW4OTKC870wOC6M8cwBxgz1lnTu
         IHZXLGHBDywWZ6BfkTIPsNmo5MZZpPeOb97FpNpGzI0CxMXoHlJ+pgrhfLaMtZNVPP2B
         JWxST7R6M8NlXN209GZsP8y5lBfZj6CLVT4HMRypAo4t1FlTG0bfp+k+5oKvMUMC7mLm
         YfYC5C9JSXRQw57igg5R3wsitCpCuDDPqfAGsyMWLPrQml43y2zU1A/oVqTYWj0rlRi0
         1inw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=HwQDf2Hnv36KRq5wQ9NdwNzTgHjSiYTn6/ev9AQDDQA=;
        b=t+YJyECkV5o9CO4ENjKGXC/Zqe70FCfoac0Xh4FK9GFrsy0EZm1gcK4dyLPtR7QG9o
         mwkR5/6zQhU14ArUc62Ar+xiWwp7hG7ktEW+g0Bs7slsZxtjEcmkUl85olyZ6IZtme5V
         T0cuMclEXPaoGN++I1UdksgNwzZA4bZ9OaM7kS9ODy5AtjK3ATyskU6Ic3euC/9ePw7Y
         xJR3U/7J3dmi8a9KZ5ZYu8T+2D4zEjDfrJHkFy3mbzSKIJ8UNpADineyQNpSTEaivMSO
         qBv9iL2PitQ9N/2BMy0JKw1/BNlKAspZsfOSe7FovGBSThCfAwRckWnp3+Tc+PtIAxLJ
         ET6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Il7G75GL;
       spf=pass (google.com: domain of srs0=adgr=3k=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ADgR=3K=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h19si1774397pfn.1.2020.01.21.08.16.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Jan 2020 08:16:33 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=adgr=3k=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id CCD43217F4;
	Tue, 21 Jan 2020 16:16:32 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id A677E3520DC0; Tue, 21 Jan 2020 08:16:32 -0800 (PST)
Date: Tue, 21 Jan 2020 08:16:32 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Marco Elver <elver@google.com>, andreyknvl@google.com,
	glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, mark.rutland@arm.com, will@kernel.org,
	boqun.feng@gmail.com, arnd@arndb.de, viro@zeniv.linux.org.uk,
	christophe.leroy@c-s.fr, dja@axtens.net, mpe@ellerman.id.au,
	rostedt@goodmis.org, mhiramat@kernel.org, mingo@kernel.org,
	christian.brauner@ubuntu.com, daniel@iogearbox.net,
	cyphar@cyphar.com, keescook@chromium.org,
	linux-arch@vger.kernel.org
Subject: Re: [PATCH 3/5] asm-generic, kcsan: Add KCSAN instrumentation for
 bitops
Message-ID: <20200121161632.GV2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200120141927.114373-1-elver@google.com>
 <20200120141927.114373-3-elver@google.com>
 <20200120144048.GB14914@hirez.programming.kicks-ass.net>
 <20200120162725.GE2935@paulmck-ThinkPad-P72>
 <20200120165223.GC14914@hirez.programming.kicks-ass.net>
 <20200120202359.GF2935@paulmck-ThinkPad-P72>
 <20200121091501.GF14914@hirez.programming.kicks-ass.net>
 <20200121142109.GQ2935@paulmck-ThinkPad-P72>
 <20200121144716.GQ14879@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200121144716.GQ14879@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=Il7G75GL;       spf=pass
 (google.com: domain of srs0=adgr=3k=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ADgR=3K=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Tue, Jan 21, 2020 at 03:47:16PM +0100, Peter Zijlstra wrote:
> On Tue, Jan 21, 2020 at 06:21:09AM -0800, Paul E. McKenney wrote:
> > On Tue, Jan 21, 2020 at 10:15:01AM +0100, Peter Zijlstra wrote:
> > > On Mon, Jan 20, 2020 at 12:23:59PM -0800, Paul E. McKenney wrote:
> > > > We also don't have __atomic_read() and __atomic_set(), yet atomic_read()
> > > > and atomic_set() are considered to be non-racy, right?
> > > 
> > > What is racy? :-) You can make data races with atomic_{read,set}() just
> > > fine.
> > 
> > Like "fairness", lots of definitions of "racy".  ;-)
> > 
> > > Anyway, traditionally we call the read-modify-write stuff atomic, not
> > > the trivial load-store stuff. The only reason we care about the
> > > load-store stuff in the first place is because C compilers are shit.
> > > 
> > > atomic_read() / test_bit() are just a load, all we need is the C
> > > compiler not to be an ass and split it. Yes, we've invented the term
> > > single-copy atomicity for that, but that doesn't make it more or less of
> > > a load.
> > > 
> > > And exactly because it is just a load, there is no __test_bit(), which
> > > would be the exact same load.
> > 
> > Very good!  Shouldn't KCSAN then define test_bit() as non-racy just as
> > for atomic_read()?
> 
> Sure it does; but my comment was aimed at the gripe that test_bit()
> lives in the non-atomic bitops header. That is arguably entirely
> correct.

Fair enough!

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200121161632.GV2935%40paulmck-ThinkPad-P72.
