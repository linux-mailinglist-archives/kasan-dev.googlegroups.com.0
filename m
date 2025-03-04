Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6WOTO7AMGQEFZASTWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 31685A4DCD6
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 12:43:56 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-2fe98fad333sf11011204a91.2
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 03:43:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741088634; cv=pass;
        d=google.com; s=arc-20240605;
        b=du/5KJmoIR6I8fDuUJYosQdG/cBU0pULBwyWEtigPygTYB4HXWTki5PP9WsnwboB5Y
         DSIo/u1KJg2WMHv2qvhs8BUEJntdelRvN9VQ2rXQebuuPECAWpWlNosetIRnGxFH9VU1
         hiZRcSRlGV7cngEt12joIt80EtfBt4VVfhmlb6dC57mmDCeIA1+CIQa4DrYz69qqKB/l
         MgLRrbeHR9knKlFOQhh24xigxVzJkrIMqhiIs7b8wVfPk6okGVqd0bK8vgMhyAY3+vk0
         x1DmXx5XaXT4N0aJh/cBWDqlooBc4l2ofSECV5pNYThmufMcOiVHnXW1ZzAP3+6Mzcu0
         V7dA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=cNke5b+1gVCOVphbIxb/UNYyeSzUNN7arCIth7wK+iE=;
        fh=5eehrgFr2fyyFdWnaQol5Vbo1utDaFbHCDsdfxyyp+M=;
        b=g8/R0kcDLhqf7ajLPdxvsQAqyA+3OCkMHjaianxjgsKzddG67xy24B2svytfNXpeBS
         AsvMqr3JwvfY7f/fUOTIOy9Fa0j4t1EkgTWe2DPDVqV+SvEMH2WygeTUW1GKRwe+q/Nl
         e0QNaVrljC3xCT/LOFZFq3cO9+7t/XlyI+lEru54cnD95Y/+nPsCdl2s56JgRo9huquF
         qrmA4aymEfdoDfOfzYkEEX+xcsQiTcjQcrNlNZC1uQFIAjAKEY8+JmPzn5Cf+gHAYhX1
         RafdCF470qm4Q9vYc4YJdDIwG/NjduNc5EMIzBjm+HmyZ+lc0J+oh2biOUgm79O0Xx0y
         hJPA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=z4CJHvCi;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741088634; x=1741693434; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=cNke5b+1gVCOVphbIxb/UNYyeSzUNN7arCIth7wK+iE=;
        b=UHAjPADLAERLeLT1ntvH3a5bE0yPM8F9dQi7OsfHxcyq8hr3/sh10pShn3ErVEjKCq
         8ETCulslUylglnX9OQAv3/fQoK22IH+c7yTLh0MXwtf4q6Lt1YmmSQBJjnuYjJaugOgT
         TsLYwgs41lWuHzBgx9l4Wc71xIuRrhijoUSi4gsIVOz2bhRXb9gVzbzgUgWtUz7jpjAv
         xtk0A23sCOpcRbHAVhnUYtNRa6T3QSu1yCqN0zwv7xo6Z4we0nEE0FjzVX9nzXtsdfy5
         EIGvUWKOqH9nKtpm7ury0QT2GI//MSF7O4gkrzZA59uygmtGIvPFJ1UFVEOtbVWQAxSj
         e+dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741088634; x=1741693434;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cNke5b+1gVCOVphbIxb/UNYyeSzUNN7arCIth7wK+iE=;
        b=C031TxD4bDhLoeUuv5bATvDzeU7fWwAC5PlA3bqsameHphVql9PqkNeUe6mkhLHYte
         RkpEJBLq560MK37Ea9vpOZv2bH9v46jOQ7bz5WyL3f/DIN7uejLH2JHBYVds2zJCj5rw
         R4Gk87nxB82qZXBpx/TRkSZAufXjoivO7+x8CwC9+/Or9Q/ErVb5eh54hy5+73BuXEAe
         NbE66rV5xl7LtSCrBcF9y5KQGwY3NiPykHfIt+jNgEn9x4rWafywPO1+joJ4P5OnJIK+
         +hxsY2rnaChAI91ZSmUDS9be4j2dqlj0SRc7wLKjDkpIG//xt78NL5D6P49oqBMilv7P
         lzaQ==
X-Forwarded-Encrypted: i=2; AJvYcCXvJA1qBtDGGyJuvzFsS/xRwdwcStOHb2D0TgRVH3lgQxJnstKoCrxcAJUJDUV6ZM7d1gkvlA==@lfdr.de
X-Gm-Message-State: AOJu0YxSnNeJp7G8d69nrDAedXJEH1+JBE/sDrIxYFUvdmY2C2hnt5Q5
	sH9qnK42YPZHK1qqG5d9ftpqenhLE5FK8v76q8BTWNb0eWQ6zGUb
X-Google-Smtp-Source: AGHT+IErJY/bwWv4mBiYC7sa9UN5ajt4NGPhSz4FgEug2ddztGL3FkYe4TT7ZVjbxnnH+9pPUBr0PQ==
X-Received: by 2002:a17:90b:1ccb:b0:2fe:b470:dde4 with SMTP id 98e67ed59e1d1-2febab3c659mr31294677a91.12.1741088634421;
        Tue, 04 Mar 2025 03:43:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGvv71mLlawCp4+u3oHyy3DYU9k+MUhkoAQE0Y0PJSd4g==
Received: by 2002:a17:90b:1ccc:b0:2fe:8e16:8cec with SMTP id
 98e67ed59e1d1-2fe9ff67cb7ls1398343a91.2.-pod-prod-01-us; Tue, 04 Mar 2025
 03:43:53 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWm4F+sM95V9AleZnC8GplrH9QORBt3Oh6Fo84susoQdokmppLvls5WoBxecHMjWMKJ2D881wHU6+8=@googlegroups.com
X-Received: by 2002:a17:902:fc44:b0:217:9172:2ce1 with SMTP id d9443c01a7336-22368fa8f7bmr302147155ad.22.1741088633078;
        Tue, 04 Mar 2025 03:43:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741088633; cv=none;
        d=google.com; s=arc-20240605;
        b=LqdZYZlFs53LX5104MK+LD580wze6CaSYYcWGhblddlFrshcrC9cFfmJpk55pYC0NW
         mcbVOTOdbGblx1H711Vsu0TlEsSPJ/SmiKSZkFmgNX8PUQe0a+UFnKMwvjzszN04xRYF
         2BxYDY6csUIBn9x5If8suuDDK+6Pr50LNFlpaeTZXYNgC75+zqV3f+4cU3NXxm5SZDI5
         FCD9RcA2/hxqIB+b0nmyaTYsXmJFiUdhl3xGUfOqz+7WB2jnVu5OoVudyqlK2MNIszC8
         9aYVzf17hrNEPkFKaDCrQQ9IKcS+3/1Y6e1865ySaLp/PNZPPApemqO7J5wHEDwkfmq3
         dx6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QR5Fe2yNdtUQN8MYBySGOzmABqc40NGzK767K+eex7I=;
        fh=4B7nt1s9BrzbjGDb3j+krWE6fay1Q3fffcTGSz3994U=;
        b=gZQuEl1Y5lcQm+mEwqqIyqaTB9MAgzK44mSXUi45XQvL5jGUe2qzy54qZEgLAaSXXN
         1pVcRjuM19t1G7bB2aeItb553ozLTOYNwmVghYlux1pmRZG3Dz/TD1gt7g/NdXynOlXz
         /YEyePYMI2lufW8P3/smz46GnoQ9ATEGkpBb8378NztE08bENjlZKoflNw1+sRhyju87
         VHHlY3pKAWv+jw9s/FtimtXH/mUSeXo1SR48rydlaxfya+/cewp8hC6MLgcePPrXVcfh
         1bBmaoAQ8PwPcHzEIvUBmRfLrelGTGf/UFDHqrARULydupKzLC95dKHld81jlGn7GG+b
         7PCw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=z4CJHvCi;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-223501e5f6bsi5414575ad.3.2025.03.04.03.43.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 03:43:53 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id d9443c01a7336-22339936bbfso80116145ad.1
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 03:43:53 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXzS5M8jNIk1p90r9LxqQBNDUvyTW5s9NjaV5oX9cIeo+5nivCg+/yOwFXkVduVEYKw4PK8bZ+BS70=@googlegroups.com
X-Gm-Gg: ASbGnctnFV1qxXPI01iMVT/TgOKX4sR4LR4PrFKNSRGtnbCZ7xg04pdjr3hZy18Iq4O
	jIDiGgW1Od++0UYWxyvHAj5QoZhKSBHIQoF2OcG8LC7+T5YnCs7QeDzyT5QfGpuqQwkR5RQc8EI
	/94sfPGW7sC83IsJ+mlveIApAeL1ZvtMWnV4GppYDblDJffV/dNuWwkFkE
X-Received: by 2002:a17:903:17cf:b0:215:89a0:416f with SMTP id
 d9443c01a7336-22368fc97c4mr252442495ad.30.1741088632488; Tue, 04 Mar 2025
 03:43:52 -0800 (PST)
MIME-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com> <20250304112114.GE11590@noisy.programming.kicks-ass.net>
In-Reply-To: <20250304112114.GE11590@noisy.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 4 Mar 2025 12:43:15 +0100
X-Gm-Features: AQ5f1Jq8MTV2B3C5aow9x7Sg78yjoK0kjhHzTC3jNgyCezrqQgZfKxcyrD8i65c
Message-ID: <CANpmjNP6N0d0dnGjDUGLeH4FQ2-G5YAuWrSPp+bvDR==0hYykw@mail.gmail.com>
Subject: Re: [PATCH v2 00/34] Compiler-Based Capability- and Locking-Analysis
To: Peter Zijlstra <peterz@infradead.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Jiri Slaby <jirislaby@kernel.org>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org, 
	linux-serial@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=z4CJHvCi;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::634 as
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

On Tue, 4 Mar 2025 at 12:21, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Tue, Mar 04, 2025 at 10:20:59AM +0100, Marco Elver wrote:
>
> > === Initial Uses ===
> >
> > With this initial series, the following synchronization primitives are
> > supported: `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`,
> > `seqlock_t`, `bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`,
> > `local_lock_t`, `ww_mutex`.
>
> Wasn't there a limitation wrt recursion -- specifically RCU is very much
> a recursive lock and TS didn't really fancy that?

Yup, I mentioned that in the rcu patch. Make it more prominent in documentation?

> >   - Rename __var_guarded_by to simply __guarded_by. Initially the idea
> >     was to be explicit about if the variable itself or the pointed-to
> >     data is guarded, but in the long-term, making this shorter might be
> >     better.
> >
> >   - Likewise rename __ref_guarded_by to __pt_guarded_by.
>
> Shorter is better :-)
>
> Anyway; I think I would like to start talking about extensions for these
> asap.
>
> Notably I feel like we should have a means to annotate the rules for
> access/read vs modify/write to a variable.
>
> The obvious case is RCU; where holding RCU is sufficient to read, but
> modification requires a 'real' lock. This is not something that can be
> currently expressed.

It can. It distinguishes between holding shared/read locks and
exclusive/read-write locks.

RCU is is a bit special because we also have rcu_dereference() and
rcu_assign_pointer() and such, but in general if you only hold a
"shared capability" e.g. the RCU read lock only, it won't let you
write to __guarded_by variables. Again, the RCU case is special
because updating RCU-guarded can be done any number of ways, so I had
to make rcu_assign_pointer() a bit more relaxed.

But besides RCU, the distinction between holding a lock exclusively or
shared does what one would expect: holding the lock exclusively lets
you write, and holding it shared only lets you only read a
__guarded_by() member.

> The other is the lock pattern I touched upon the other day, where
> reading is permitted when holding one of two locks, while writing
> requires holding both locks.
>
> Being able to explicitly write that in the __guarded_by() annotations is
> the cleanest way I think.

Simpler forms of this are possible if you stack __guarded_by(): you
must hold both locks exclusively to write, otherwise you can only read
(but must still hold both locks "shared", or "shared"+"exclusive").

The special case regarding "hold lock A -OR- B to read" is problematic
of course - that can be solved by designing lock-wrappers that "fake
acquire" some lock, or we do design some extension. We can go off and
propose something to the Clang maintainers, but I fear that there are
only few cases where we need __guarded_by(A OR B). If you say we need
an extension, then we need a list of requirements that we can go and
design a clear and implementable extension.

In general, yes, the analysis imposes additional constraints, and not
all kernel locking patterns will be expressible (if ever). But a lot
of the "regular" code (drivers!) can be opted in today.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP6N0d0dnGjDUGLeH4FQ2-G5YAuWrSPp%2BbvDR%3D%3D0hYykw%40mail.gmail.com.
