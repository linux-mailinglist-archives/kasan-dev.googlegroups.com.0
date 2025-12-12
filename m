Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2GW57EQMGQEEJFC2XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id D52ECCB898F
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Dec 2025 11:16:10 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-2958a134514sf15066925ad.2
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Dec 2025 02:16:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765534569; cv=pass;
        d=google.com; s=arc-20240605;
        b=PvbM5wcNKFpGDcyDeogUeT3WVIx/d8PCudiAVyIAeKHITK0dV668NLuNcCmUMac1St
         dYArohvIBvzU8SGcYtS6wl4b3ymCCotUb4MBGf4TLAtqlbVtEKv3EasRWZwcH9KeZ+4N
         lDISr16YSQJbJOkxFGEHl8/iF6yO8RVLPEmuhucZ7hQZOupLBpr2YQW636B1F0LKfApu
         wperV/9yejqMkSwKCX34PYRqfep6e7YaPpwSlG4zvIqm6HeeLm1syjr05Pa2WMzaRWJW
         obej5m00QWCKsL5Om1AlSFPp73vEO8OxbTKUqyNH7+/sizWRbdhyExoD00tsHIJSVrnW
         StKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ASH3gJlM5ZJicrvnr4I7oEoMVuoyulwlImDMmV/jQcU=;
        fh=Y2iA/tu7OWlhXO4PJFQpaAW0wixyZkWpO91jmejRMyQ=;
        b=gMvjgFMX854kpis3qJTC6/JAQ8hDwNjNeBXmE8MUdpJXwNr/3rTa8Kec1k4Khul/gW
         IhK727skOq3Mjd3/5JY0cs+DUnuvTArAf4N+CdFy10CW9Qogc0/0hXnOqvfFpb4zKADv
         lUwxxBItWqAOrJ4RwTMmaFy68EvJ+LLoScX2PwP0e4LmE4RKxaOTJ2mv6asZPBmisuer
         k6e8YYdXbxGEw0jOg9E8zf1Ej9BbpFmTo1zYbW5uif9D4UlT9lD0DBwXTisByCo3JNgW
         xO/54mOEtwY6Fk548ajb5+csW866nYH/II4E6g1dupmgbSdXvDrWaokXQeN5bk1BPR/y
         kBUQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=kZdGnV+q;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765534569; x=1766139369; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ASH3gJlM5ZJicrvnr4I7oEoMVuoyulwlImDMmV/jQcU=;
        b=m52N4sUkDFoVb2B6GMGm984OxgubMmALiuUw/H4lnwSdTERFldHH4Sh5JiHwqxHBuH
         I0rAOHDGNLZ6ZKKhaa64a1wdjEwY9HwChubzWjOms2gNc37Xq3ZvvHRvI3ZjJrs3pHH/
         d5AFoACwqiU1w5OnnSVzHin+a2YOHgAAWk1QEdRVT1jvsdjmX6f0iBCvD3aXnSwiQ2iR
         7624FxBzWDTUgS2UwaitGmHC05IM0zsn4RKwdTs88Omkt/4Tz5KSs2Jti99OjdUH2t0K
         n2tR5oF2cwyYlfvbjRRBV5OjPOipKuM+eKhFSkMK42Dae+Uq1rrCooKu8DNFQQhqtYsK
         DrKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765534569; x=1766139369;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ASH3gJlM5ZJicrvnr4I7oEoMVuoyulwlImDMmV/jQcU=;
        b=Lv3f/XmThIkbfgq6R8/RuK0Jlr4Z60vY1ACzcuSrvf0iF/2xFE7yFDWTh5HQG323M3
         ZSVArThYfDbWhaGDH5q9htdLiTgDgzHuAXbH9tuRc7pTy9EJC5HHLb89g8/kN52r4DDg
         q1kUsr2DyyMG0oMItovfSeP10o0MZIT7bGkO/c4EXWRXOTWqFi8oO++/a7F0H6cerPQu
         5axJEeHD06wHrp3RYjwyAGHjhrvu1V8mR07ywkN1Kl564KRqAuU8Aj1LwP2NSU4+ZITo
         /Nl9XXn/ipIw+CX4llK+F6RfIffHiVaz0kjC7REN4SquU1jT/dDtg6Xd8hr3wVUFywZ1
         B0zQ==
X-Forwarded-Encrypted: i=2; AJvYcCUZo5wXSDrAun1tNTML08FJJBD01VCwWUAAdQt8aQTI4LASXPzY0054uKo/HeoEYwNWaqu+Eg==@lfdr.de
X-Gm-Message-State: AOJu0Yz50iwYbe+YWKTrMitD8+npHqCmTT1+WmFxbpfO9TnOr/SLdoq5
	RhsckaQm7YNtF8+WfuV6gGeM5RWWFrGl0eP97IYJwoKeD3zZm5WUyUPV
X-Google-Smtp-Source: AGHT+IFDp/7Xxl5Ry/Kv6m9KFBkRy6kX/WUbBnryomV87tNoUOUdSYkV8qVV2fL8UnUfm2sijDq0qw==
X-Received: by 2002:a17:903:90c:b0:297:d6c1:26e with SMTP id d9443c01a7336-29f23b1e1e4mr21966455ad.6.1765534568913;
        Fri, 12 Dec 2025 02:16:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaXam8oalGYE7txNSPYvGgCloHOm53d1ho0jri8HMH/Aw=="
Received: by 2002:a17:903:200f:b0:298:e5:d986 with SMTP id d9443c01a7336-29f235ef49cls5720145ad.1.-pod-prod-09-us;
 Fri, 12 Dec 2025 02:16:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV005037wtivc6gaRGnL/kiUwnJ/LxM6M5k2T1MCEi3a6OdVNSGYXc7cPkRHinFvmnS6yCagECSWr8=@googlegroups.com
X-Received: by 2002:a17:902:ebca:b0:295:86a1:5008 with SMTP id d9443c01a7336-29f23c7c568mr15106155ad.38.1765534567348;
        Fri, 12 Dec 2025 02:16:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765534567; cv=none;
        d=google.com; s=arc-20240605;
        b=AiU9k8VCHnKm2xCtRNRpsrBSX365USsVbmMz9v2nscnHEZwX4zRjvhWk1Wdmk9+IXg
         MLwymMRfCG9uQJm7QGzWUhBtPbZ4lPLfRJxAK9HW//qJ2B+5Ou2SadT7KXla0hUch0RA
         Y0l72Pw+k9A8PI8DaRrCOqfBfEOXUAqBkeKZgyVa/Nso96G3lziLupi2mZdNtKqL81xa
         pY9HjVRIXwlmsTmoKq22BXwB6SlHFKGu6ZrNZGekNajNEQM0MlPro2ayxFNeYXYyeeye
         xnVtRoVLK7c0zxXlauXnRovN1Z7Ds7wydoFI8leaKx7HT4+6SUrO5UUAhp6YrTgUxsdS
         DDiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Yy8AVUr1WzoEhC0gwViTyIIecU1pDeO+TdO72jBT6kg=;
        fh=uZchOi4aWxYUc/0NUbleq7XcmljX98ZE/PWubQcfLNA=;
        b=Jh6v0qKkdfoQXMYlve03HrMwWftH8CcHuq6QxcG97aau8ZGikRCTgb1TUIQirL2sL8
         tebkEKtp/XggYbNMeQHiEou77y1E8DOJxG8sWaNtdnMKv4NtQlvsGmBHtfSXi8CtYWVK
         TRV6cUh+vkaFaNTWWU1shUNraUiYgWbOxtdG+scQR5tcKUUWEzoj1GdUWTBr39ic4b4a
         XiVo+CAT1iHMBSyKmohAPdbzq5AzZhWcj0q6QhPDWudeYJvh9TDfRRLnio8se1ORwn4c
         urq2WCutWD10W7Fc/Am43009anDgSWZEiv+lBkCAxXcsAFa1HA8tpFcUZiLjz0tIWil4
         oxUA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=kZdGnV+q;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52b.google.com (mail-pg1-x52b.google.com. [2607:f8b0:4864:20::52b])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-29ee9b17b82si2229395ad.1.2025.12.12.02.16.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Dec 2025 02:16:07 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52b as permitted sender) client-ip=2607:f8b0:4864:20::52b;
Received: by mail-pg1-x52b.google.com with SMTP id 41be03b00d2f7-bc0d7255434so698524a12.0
        for <kasan-dev@googlegroups.com>; Fri, 12 Dec 2025 02:16:07 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX1oLn7H6CUPx/qYDqW2LW7aaPjQws3WzHWXwUQq5ZBNmpA5Qwsmc4xIa6Oht8fnkgy9jGrU7NO26Q=@googlegroups.com
X-Gm-Gg: AY/fxX5vAUGKDQ5SyVOxYrxNlmM+73erIrIqcrBob8SAOCJHpsXPgyKUyD8vFmAORXr
	Q+NBFERLcpZcepRyYLR9RfDjg3VL+L2YJ02MkzRZyaal029RPJKxi5e4yor+LWAk2u2KN0ej7NW
	7olhejM6AVfHDEWMmIbto9wD5XGjdgCfAowoqw15i871AMOHByPr8C/QYrvmd6YHOKuJo1cyQlr
	Bn0eCkpYPnb6kAcnaVZTAxpfbT6aEY68ZtpBoFAD2Q2/WG+AJCqHsmd4Y3ozd8OzKvaaV+D31BT
	i3NjkGStn69mdTWgmLMjuLT8jykyR/XJEQ2r7g==
X-Received: by 2002:a05:7300:2aa5:b0:2ab:ca55:89b4 with SMTP id
 5a478bee46e88-2ac303f2fbcmr872533eec.43.1765534566419; Fri, 12 Dec 2025
 02:16:06 -0800 (PST)
MIME-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
 <20251211121659.GH3911114@noisy.programming.kicks-ass.net>
 <CANpmjNOmAYFj518rH0FdPp=cqK8EeKEgh1ok_zFUwHU5Fu92=w@mail.gmail.com> <20251212094352.GL3911114@noisy.programming.kicks-ass.net>
In-Reply-To: <20251212094352.GL3911114@noisy.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Dec 2025 11:15:29 +0100
X-Gm-Features: AQt7F2qb9ENq_mtkRfqCrKNBJnxHOwKNFDuSBIrcF4bjbeWckbG0712gmoUp-Ao
Message-ID: <CANpmjNP=s33L6LgYWHygEuLtWTq-s2n4yFDvvGcF3HjbGH+hqw@mail.gmail.com>
Subject: Re: [PATCH v4 06/35] cleanup: Basic compatibility with context analysis
To: Peter Zijlstra <peterz@infradead.org>
Cc: Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, 
	Will Deacon <will@kernel.org>, "David S. Miller" <davem@davemloft.net>, 
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, Chris Li <sparse@chrisli.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Frederic Weisbecker <frederic@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>, 
	Joel Fernandes <joelagnelf@nvidia.com>, Johannes Berg <johannes.berg@intel.com>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Kentaro Takeda <takedakn@nttdata.co.jp>, Lukas Bulwahn <lukas.bulwahn@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=kZdGnV+q;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52b as
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

On Fri, 12 Dec 2025 at 10:43, Peter Zijlstra <peterz@infradead.org> wrote:
[..]
> > Correct. We're trading false negatives over false positives at this
> > point, just to get things to compile cleanly.
>
> Right, and this all 'works' right up to the point someone sticks a
> must_not_hold somewhere.
>
> > > > Better support for Linux's scoped guard design could be added in
> > > > future if deemed critical.
> > >
> > > I would think so, per the above I don't think this is 'right'.
> >
> > It's not sound, but we'll avoid false positives for the time being.
> > Maybe we can wrangle the jigsaw of macros to let it correctly acquire
> > and then release (via a 2nd cleanup function), it might be as simple
> > as marking the 'constructor' with the right __acquires(..), and then
> > have a 2nd __attribute__((cleanup)) variable that just does a no-op
> > release via __release(..) so we get the already supported pattern
> > above.
>
> Right, like I mentioned in my previous email; it would be lovely if at
> the very least __always_inline would get a *very* early pass such that
> the above could be resolved without inter-procedural bits. I really
> don't consider an __always_inline as another procedure.
>
> Because as I already noted yesterday, cleanup is now all
> __always_inline, and as such *should* all end up in the one function.
>
> But yes, if we can get a magical mash-up of __cleanup and __release (let
> it be knows as __release_on_cleanup ?) that might also work I suppose.
> But I vastly prefer __always_inline actually 'working' ;-)

The truth is that __always_inline working in this way is currently
infeasible. Clang and LLVM's architecture simply disallow this today:
the semantic analysis that -Wthread-safety does happens over the AST,
whereas always_inline is processed by early passes in the middle-end
already within LLVM's pipeline, well after semantic analysis. There's
a complexity budget limit for semantic analysis (type checking,
warnings, assorted other errors), and path-sensitive &
intra-procedural analysis over the plain AST is outside that budget.
Which is why tools like clang-analyzer exist (symbolic execution),
where it's possible to afford that complexity since that's not
something that runs for a normal compile.

I think I've pushed the current version of Clang's -Wthread-safety
already far beyond what folks were thinking is possible (a variant of
alias analysis), but even my healthy disregard for the impossible
tells me that making path-sensitive intra-procedural analysis even if
just for __always_inline functions is quite possibly a fool's errand.

So either we get it to work with what we have, or give up.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP%3Ds33L6LgYWHygEuLtWTq-s2n4yFDvvGcF3HjbGH%2Bhqw%40mail.gmail.com.
