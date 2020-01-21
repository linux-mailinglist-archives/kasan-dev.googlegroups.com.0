Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWNHTTYQKGQEEJFQYUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id B1AB814402A
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 16:08:10 +0100 (CET)
Received: by mail-oi1-x23b.google.com with SMTP id x75sf1213029oix.3
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 07:08:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579619289; cv=pass;
        d=google.com; s=arc-20160816;
        b=a7OVKYfOwvKXNt2M/NdiKwVqdaD0RbSYhY3JRMDXCpS5pGXO963fGoulsSt5g69ZVb
         KWzk9BPzAF312qNeVxCv1W8lhBw/r1OtATAY+ppYtHFAZg9X9N0pnl/lh3teSaNfGsSZ
         2weL0n9H95yhAB0RJIv1vkggFp2Q9rDAwgAuOpq9R2jBBtEnK3iHWOjeFFHqYFVGOuiJ
         cEQ5UzR30K/eB+vXxjTyFjYT1g5uAbfWwwWtWCu2pgl9W4+ece62WNZrRtXhgLdMVbiV
         zUJ1Ed0tZW5j1QM/WyDpERODF3VTHkEjV1K5uq+dgSuLcATuCO1UPIYa5t4jL6mAmgyU
         1MmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5E4wbjAxNE4AqZhEA1zAGsSTFElpH4wpSQSHqUtN0J8=;
        b=cifwRguXaNDGAVpNWHGsJGLk2ZYLeQ0qnHc5JvO/hwCfhQI5Nr1zto5dpaOnQfbhUM
         TS4yOJCxVayVcm0gou26oRBclIgA0PwvlnshS9ZWb7xo2ZHhoBjxsuinHXfbYu+mWXCo
         8SawjLj+5O16ISgaCVA0pgArgk7WIF3hZcknxu+vV82rov6dYMz0bs+/m4Ew0+AFW8fo
         oGaQkCXropDjG/K0B9vzEuSsiS/7Y0ci33iCBArYZ37LkoR2AuP/JytAxdBdnW9MTdjI
         pVRCprO0gEqVNwm4ik+lTUVudtNVGlLnMaolbAqZJN4DetCgONHaZjb5ko5jR/1whCZQ
         5HXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uikBkA3X;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5E4wbjAxNE4AqZhEA1zAGsSTFElpH4wpSQSHqUtN0J8=;
        b=rBha1Qt8EZz+VJIvk1Ge6CSA6OfhWZ0AagZQpeF+xqg6MGo1prCH33DcfZwWwQYIZv
         m8tpAk+6rGJ5zqSGsam93EeHLGeLRCfyUWl4vjKlZWpKKrbIWaV4g4oEZt1JkcfsKUUE
         m74JIwIRhG3VYs4fBI7zVSL4g235ftMEQerLThkolVm9D71+l8tT6nGCfLq5V/E2pbKp
         eRYaSU+ZW8NBwpIgi2UKJtLUKS7AdKu+7KwT0/JQjXTX0UEFLoaDIGk/Yto4/C0ONivg
         VvrtyQMF99bGvZVjGOpVduaTvVqlTChxXOGcHVLj/bauFZf70+fDJxGdgQDPVL/Mt/JE
         h+xA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5E4wbjAxNE4AqZhEA1zAGsSTFElpH4wpSQSHqUtN0J8=;
        b=ZzTaBC+bKEEh9nkdtU0kPa8ar1Vo271OEymDiFR32RES397c8zIA1ztegmHjGMDHwJ
         +mNLnBtJSmibuEZIptS/85IOLZBiLHVrqPWa9qb4Z/Y5siQRscv+rnC3xYqRujDnqdKj
         QMaEV4wAPPuklI6XD3RGhwcRfHHr5TaeEe5ZBQnVShycwKCUlIgIDWRtZ+Z5YLvBRNVa
         9MvqD34KAYZbFBkY8wLQ4A+++p/5slnFv8U1fByuOBd9gwrHuYyL5Oq8DDek09qKos/J
         ckKN/8VMI3B7caEC7tsgyx+KZO7lwpQA8kHzIM4kKiy7wTojIXY2dI0gWySINR6p+bBz
         NgRQ==
X-Gm-Message-State: APjAAAXRq6w6TpdRwH1sXiONXp9eTyHZL3+YjBtBEsNSkkG+TN/JDZ7+
	hwfjguNryRnHeqsNf4pqtzE=
X-Google-Smtp-Source: APXvYqy/iywrTSQMDKBSnAw3WVsPP9/fuX3fR9H5DsE+SJwWnGkLuBAwODbb554ACja539S4T3BKRw==
X-Received: by 2002:a9d:7616:: with SMTP id k22mr3877066otl.364.1579619289270;
        Tue, 21 Jan 2020 07:08:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:649:: with SMTP id z9ls6339246oih.3.gmail; Tue, 21
 Jan 2020 07:08:08 -0800 (PST)
X-Received: by 2002:aca:d0c:: with SMTP id 12mr3388559oin.26.1579619288927;
        Tue, 21 Jan 2020 07:08:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579619288; cv=none;
        d=google.com; s=arc-20160816;
        b=l5BILC/w89wBbBd982ZzS5EKIZgdarLIsbF85Nd7a0qnUdkxbvJ9Rc8pR0UoCwPE7h
         OAFOwnA+nprmm7MQmrVKDklv7p81J6od1Ix4/aRxLRetQO1rIOiJ4S/4XIGMhVAtXTAr
         zezeheHQ3MMEZMKoQiMZbntjkorysTHoPzp8kY09060Fu8MAFwSlWy+9eX2WoE4t3w5i
         ubNjSw2DJ7UqScZPgWasKP12dM6k5HSZnUSOn4jlia9Zod/FC+wV+EdpeS9Mvv3IrkiJ
         fdUHPemLQQopnyxdp75Y6xLRdGDXmqLsifQXk0OujaAxBLUJn7ewOTxtmwJm1VRfF3do
         W2zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sORnSh7V9XjzjlniDOWj1Q+C/fnBMkuk2ZbJfbkUnZI=;
        b=tv5WjKj7RBCfYEv209Na05dAY26WfQ0c3CxNxQtMHXA7fKf9udqFTf1wG0gacdFlD1
         taZTd5UQTSIkmh76XRJTGqdAZBl3b1SWAjvem/JfHuHrgYi6Apa2COTAMu4iRquoZwXN
         FRKkR+lhvhJR6OiVdCigKF2semFO0ZPvb1ro3oOhJpGSbAP8pvUjMG8T+NXCm5EJGolj
         14E3f6DH87Ztk4TAJArpC11zPVjNLZaL+lcVG8Z7tsvOSp/iwRECKO14O0OfZLnT+zGq
         xCETmHlu4ttyrV2xdZCOPO0Cd3bcF2E8j/iDg8rQ6nZOtqNZNVdOAyiayvmlOO4qk1S4
         RohA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uikBkA3X;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id c23si1880721oto.4.2020.01.21.07.08.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jan 2020 07:08:08 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id n16so2792213oie.12
        for <kasan-dev@googlegroups.com>; Tue, 21 Jan 2020 07:08:08 -0800 (PST)
X-Received: by 2002:aca:2112:: with SMTP id 18mr3156833oiz.155.1579619288271;
 Tue, 21 Jan 2020 07:08:08 -0800 (PST)
MIME-Version: 1.0
References: <20200120141927.114373-1-elver@google.com> <20200120141927.114373-3-elver@google.com>
 <20200120144048.GB14914@hirez.programming.kicks-ass.net> <20200120162725.GE2935@paulmck-ThinkPad-P72>
 <20200120165223.GC14914@hirez.programming.kicks-ass.net> <20200120202359.GF2935@paulmck-ThinkPad-P72>
 <20200121091501.GF14914@hirez.programming.kicks-ass.net> <20200121142109.GQ2935@paulmck-ThinkPad-P72>
 <20200121144716.GQ14879@hirez.programming.kicks-ass.net>
In-Reply-To: <20200121144716.GQ14879@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Jan 2020 16:07:56 +0100
Message-ID: <CANpmjNNM_5=tBJhPdgGKbG6kaFpniyHZ1RyPypC-7qxEYBBkPA@mail.gmail.com>
Subject: Re: [PATCH 3/5] asm-generic, kcsan: Add KCSAN instrumentation for bitops
To: Peter Zijlstra <peterz@infradead.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Will Deacon <will@kernel.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Arnd Bergmann <arnd@arndb.de>, Al Viro <viro@zeniv.linux.org.uk>, 
	christophe leroy <christophe.leroy@c-s.fr>, Daniel Axtens <dja@axtens.net>, 
	Michael Ellerman <mpe@ellerman.id.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Ingo Molnar <mingo@kernel.org>, 
	Christian Brauner <christian.brauner@ubuntu.com>, Daniel Borkmann <daniel@iogearbox.net>, cyphar@cyphar.com, 
	Kees Cook <keescook@chromium.org>, linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uikBkA3X;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Tue, 21 Jan 2020 at 15:47, Peter Zijlstra <peterz@infradead.org> wrote:
>
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

I will also point out that test_bit() is listed in
Documentation/atomic_bitops.txt.  What I gather from
atomic_bitops.txt, is that the semantics of test_bit() is simply an
unordered atomic operation: the interface promises that the load will
be executed as one indivisible step, i.e. (single-copy) atomically
(after compiler optimizations etc.).

Although at this point probably not too important, I checked Alpha's
implementation of test_bit(), and there is no
smp_read_barrier_depends(). Is it safe to say that test_bit() should
then be weaker in terms of ordering than READ_ONCE()?

My assumption was that test_bit() is as strong as READ_ONCE().

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNM_5%3DtBJhPdgGKbG6kaFpniyHZ1RyPypC-7qxEYBBkPA%40mail.gmail.com.
