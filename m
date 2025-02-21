Return-Path: <kasan-dev+bncBDBK55H2UQKRB4MW4O6QMGQEDVDRG2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id D53EFA3FF13
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 19:52:34 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-38f2726c0fasf2506630f8f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 10:52:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740163954; cv=pass;
        d=google.com; s=arc-20240605;
        b=Zy2zD30GWnMZDOwMpIp/ICwFxZE6YdTLuAtoa0u9U2r5aqdLvVInLfORYsPY+wkMB2
         LK/82XCuoEtyX/CTQpuHSKAazMFUhtGm9aovsA74wY6QpFRoUCcmO5f6frtK0qGfzu/z
         goz0rXh+MocCqJRhYlR4YD/wt96zwxG1/j+/1I992eh2pku0LR8WjW60GZVzP2xWRXtD
         /KOLpr5gArfHTTgsgwzRA2G30WP6BsLR7e4BDA7HcCm+eaYg3Ayqzu50zVvy4wxAIdDg
         dbzpcxY41k8i2YiA4ttyg46VOWh2Xif+mcN2YfkTGcO3IdK/ZygC4XNdK694IMCnIx0N
         I1ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=hm8G6Isz330oyBW54t3IdfvT8UYoo3k7LXUGdK9FSKw=;
        fh=v1S8a0Q0lIxL8TqQ2Zl54XqBbCdd82XTd8Q+mBzskD4=;
        b=Uc4PNGoY7J/kdAfwQs2F6/gAhr1+n3aOmYSxSUmdXPl9adA+dCG0arBzLZ124GuPNU
         2ub2s5eSW2lXejbZGX/FQ+1kS8fiO7V8yTGx5y3BbA6Go9xPX7x5wyXHOyjPJLnqllkR
         vpGs+Be+BNTjv+J+8dKP9SbHm0Wqms0n5cTyPYyK+XLb0fLMvz7NvADQ3zQ7zT1aJuiy
         faKDOprxPQ05ex5xcSs3N9bZJytGevTSyBIjTHtpbhXfkUDdbhKq+5vmhmDW9ZVqnNxP
         qrXMWoxR6GHAkdUWlNmyTh5Rwvf29l5mR9mO2FWMT/YEWf2xnabu/0p1gnQuiIZ0/9RK
         1Zkg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=pL3PD508;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740163954; x=1740768754; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hm8G6Isz330oyBW54t3IdfvT8UYoo3k7LXUGdK9FSKw=;
        b=RAokoD1YbURPLg+KpclI5R01860a1htKs8plYjqSSY4XwhtM/ZfauFyxuQvO7CThcc
         8hAhGIlvfdVIHp/n31luFk1mAHTT/RDVkB38Ow0apzOJeypsdmBrYl9kLTXyq1Gu42fo
         N7puQ/OesB1L0Q++v9UwfHd1yZY1mV37RlDMEW0m6BEUTlhQaVcN2GX6/YrO2ogZOmej
         o6cPAh3H/0phE1ZNTbuRkZAQYL9vsJEA2jodschsG/cE09RpF/cm7CAK0h1zef/mBtUz
         R3g55xRPASL5fQpBPnSpP/011d4XHK5SnGC+Gv4VZclwYBet0oScmOp3lmoltSHze87w
         X+oA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740163954; x=1740768754;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hm8G6Isz330oyBW54t3IdfvT8UYoo3k7LXUGdK9FSKw=;
        b=fsSxfQZtnmvBnooVI62T+0sO3kHWAHkV2+uVIceJmbfJOh8Yeuu/Nn2iEOVSPl0ggT
         gjqqRNUR6SS7Wk7uGzI0CtmFv+o3ADLZCUFMkT3poWOlxZ8jPWKN9iq5zeFC/HhRLkgh
         606L9J8YvKHi8C5vS5fAxCvRQ0WprSTPj0AgsDLSti1ljYuN8Z07FrQqT6c6TI851vBS
         FQqh83tDWjHWml1+N78k45cdwO5Aeip6mr8zITg8YpKzigOdj0Jhs5G1gq4gTNtwrBi9
         PYZ/OAsViNGgAxs2G8V6CbMB6vpsYnDxKuo0PRSq6e6HhufXaZlbNSrPBhYKEjOAP+eS
         E+xw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXXr6i/g2NCWgK25OeSfQneSssRaCzXHuOBqqRHic30SiOgMazxOmLYLqZdWo52j4x+5cMu4w==@lfdr.de
X-Gm-Message-State: AOJu0Yz3d4Tqd3WJcAMz+2prOc6Uy02lgRR21SqYmj9VZXbVe1uku+Df
	pNI0ZJdExiwgC4QRROxr9N6zDxk8SqdC0SKOYbjCQQE6ob7fuR9Z
X-Google-Smtp-Source: AGHT+IEpM7II33sxMbXA5lwJJmx8FjFYV+pakqDMBoZyetFgj1AP7ORxUnbgR6aob45b8PEb6CXoBg==
X-Received: by 2002:a5d:64c3:0:b0:38d:d2ea:9579 with SMTP id ffacd0b85a97d-38f6f0bed6amr4335841f8f.46.1740163953769;
        Fri, 21 Feb 2025 10:52:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVG+1ljahqIOPCStHPref985RVRQVB3UEnd4tXGGk3xzyQ==
Received: by 2002:a5d:5f55:0:b0:38d:eaeb:19e2 with SMTP id ffacd0b85a97d-38f61476d3bls362459f8f.1.-pod-prod-05-eu;
 Fri, 21 Feb 2025 10:52:31 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWxeCWYdbzCF2yFlsJF1yxP3MWxzm0l901spoMR02w6STUsLQ6MnbU3vcFAZ96HrkRnWLuG4g5Rj6M=@googlegroups.com
X-Received: by 2002:a05:6000:4006:b0:38f:2856:7dc2 with SMTP id ffacd0b85a97d-38f6e95d596mr4615695f8f.18.1740163951117;
        Fri, 21 Feb 2025 10:52:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740163951; cv=none;
        d=google.com; s=arc-20240605;
        b=gXSJoSyxOQIXziZbh+YSH4bYZB8ak27csAPqKnvnhgHo4VlLWLp/ffAZ7yJVAah6D1
         Foy8wk9N2D9sJ4wfvdkOcpN5bhLwvO2iyLDWaM7zZEcaKUar009sScQWOA4Zxi1IkLRp
         y8A30sH0Kgp82F9g8v70zDNs0U8C6zuwUPGeWzYif2sPtCPN6XK5QL7miDU7xt8/QiEH
         SLYwOJqqoR6t+Ahp2XFcQvy3FeuKX5Du37g+TpOuM9nWCueX5XMyyOg6CHuFplLbgyPZ
         KwHzyXoBDPcPbyg628HFXlF0Ijb3pf+8DjLT2Jp8V8ViSb2GUyc1XfaVHU9oA57g3C1Y
         JOUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=7FduBSMLh/i0qPWqlE52G0TkoLVQsc7mFC68GyadH68=;
        fh=hz4EpMCtLMaEslMzklMPCQ1Y8AFISbggjWSj0KH2SyE=;
        b=l1w+KnTpnhjeNSqNuSX8x8PgF9LySsmnhxll/WS4aXhnzZzzhlAOQW7qr4Yvmrzv3Y
         xo1jFR4v3UUm9H4SASUS3FuWvb2AZdVTFafTrOhl5CNJXM4BYKBjUTqzNDnc8Uk1VGZo
         4cSssuNUpmm/tEbPMsTWtKNJ9bjsu65tyQpvZ/mB4yRtsBb2f91rV2DKaz6aty6itP2J
         HHJERB54MIhPOEVoV2+RR1iX5XU4XHoHEuXBMNAGeN2GDMCk95+IeNoEUJPfHvu4ipov
         e3qE8ZqHHF/nCkhv2lwtoIisWMxYwC49bAPyvPqhEHvrU/ftDKJ8VnI5LRsCxG5hbWf9
         hhdg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=pL3PD508;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-38f2589a0e6si586069f8f.1.2025.02.21.10.52.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 21 Feb 2025 10:52:31 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98 #2 (Red Hat Linux))
	id 1tlY8L-00000002iJq-36td;
	Fri, 21 Feb 2025 18:52:21 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id C6DDC30066A; Fri, 21 Feb 2025 19:52:20 +0100 (CET)
Date: Fri, 21 Feb 2025 19:52:20 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
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
Subject: Re: [PATCH RFC 15/24] rcu: Support Clang's capability analysis
Message-ID: <20250221185220.GA7373@noisy.programming.kicks-ass.net>
References: <20250206181711.1902989-1-elver@google.com>
 <20250206181711.1902989-16-elver@google.com>
 <a1483cb1-13a5-4d6e-87b0-fda5f66b0817@paulmck-laptop>
 <CANpmjNOPiZ=h69V207AfcvWOB=Q+6QWzBKoKk1qTPVdfKsDQDw@mail.gmail.com>
 <3f255ebb-80ca-4073-9d15-fa814d0d7528@paulmck-laptop>
 <CANpmjNNHTg+uLOe-LaT-5OFP+bHaNxnKUskXqVricTbAppm-Dw@mail.gmail.com>
 <772d8ec7-e743-4ea8-8d62-6acd80bdbc20@paulmck-laptop>
 <Z7izasDAOC_Vtaeh@elver.google.com>
 <aa50d616-fdbb-4c68-86ff-82bb57aaa26a@paulmck-laptop>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aa50d616-fdbb-4c68-86ff-82bb57aaa26a@paulmck-laptop>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=pL3PD508;
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

On Fri, Feb 21, 2025 at 10:08:06AM -0800, Paul E. McKenney wrote:

> > ... unfortunately even for shared locks, the compiler does not like
> > re-entrancy yet. It's not yet supported, and to fix that I'd have to go
> > and implement that in Clang first before coming back to this.
> 
> This would be needed for some types of reader-writer locks, and also for
> reference counting, so here is hoping that such support is forthcoming
> sooner rather than later.

Right, so I read the clang documentation for this feature the other day,
and my take away was that this was all really primitive and lots of work
will need to go into making this more capable before we can cover much
of the more interesting things we do in the kernel.

Notably the whole guarded_by member annotations, which are very cool in
concept, are very primitive in practise and will need much extensions.

To that effect, and because this is basically a static analysis pass
with no codegen implications, I would suggest that we keep the whole
feature limited to the very latest clang version for now and don't
bother supporting older versions at all.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250221185220.GA7373%40noisy.programming.kicks-ass.net.
