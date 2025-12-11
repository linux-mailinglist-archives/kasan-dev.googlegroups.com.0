Return-Path: <kasan-dev+bncBC7OBJGL2MHBBW4G5PEQMGQEVOSXB3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id D40B3CB5FAA
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Dec 2025 14:13:01 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-298535ef0ccsf626045ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Dec 2025 05:13:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765458780; cv=pass;
        d=google.com; s=arc-20240605;
        b=Fkp6ayj9Muy9xp4oiHFhQSduE1MCREniLB6q7GwNlMmI2iECYbzEtjuc3NUfdBnQQh
         exGM8SYPLJxxnKigZRpZCNweZeFby1ytA98Lj7oDfBoTvCcYlySYyfj039Vv5zTqfcQs
         rJigq0KZvYNGmRUiBc8oW9ZW5IqdDUxUBN6pU0oWSZpKT10TL2avUBFEEq4PU7YcjQQU
         BOYEdWf+1PzP4vUruG0flDrloZNfXQzSi58M7o/4h6du8fqJRV3raFeJzF+wn+csJ9QO
         jOdxOt0avKEUWkA8pwSsn+FXtafUxXszAWKSuldv9c7ttN0zAFQha7G8/+m9yU940so9
         +Gfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=642z+xb2lYyGHXp2GOM0rYZD1QqqLMY5l3YEpP98lQg=;
        fh=yndfdaAq0lYub+jqe8wwILIsjeLA1qoxHhws8Jknpl0=;
        b=f+pPzCkAlGygcvFdTZMzbn9WFs27I4XAFRWmvnJ2QKB8JBvM6BLBAxsJH4ZsQRdogT
         VU6u/KvgKKPmVRMdPu53jq/vkvFjKYeJ+WB9QUFDJ5Ta7qN3vjeFAm4Vk5WsVlo0oT0B
         CGDmRRt3io1KgkSVt243G/xvfO9cBvB89x1xc1wiqj+TOvT5TDrbIGkMQ2ujdyRQWo0a
         y0JYbuOzz8q0BJhwE8j0LxwstpcnDBZlR2VwhS0RB/QqDVQ+NgTl/FgmWYKuxCAqjJkP
         e8SmEOlyGtmqGvBspw9Txj6IqJhD07EpfwPA3UjN6FvIkBTfGNj9j7BUZ/azU+Senu4f
         t8Cw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=IBS82K7A;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765458780; x=1766063580; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=642z+xb2lYyGHXp2GOM0rYZD1QqqLMY5l3YEpP98lQg=;
        b=UYV0LOROTI2PPxyNbNlrHohWYEdEbk8M0UwlQdTUppkxHDv0jlima9x+dpzJW8BVIi
         CsRfehuTSA9VqsBUtiLcBw2K7MlgdVRGVVVw9ghHiuHZyiNB6KPxv8eiUlnbBY5gOghF
         2nkuWk4gku5UnnZeboJeQmodUlw47WZm6lz4RF8UYl/UKr6wE3EtbrHooJrCFrsEq1s9
         JTDp/zsQm/9Qk2vYAinN5vmkA5ntiIvrXqAat1MKN1S79K3NkkBqhH+zCbCa03zZpWWX
         2uAw17QBKd4m/NLHxXVKeZmVvAN8BYmW3znIONYNx6BCPBu9owL1pgdlIybWj3tPi/93
         lQZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765458780; x=1766063580;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=642z+xb2lYyGHXp2GOM0rYZD1QqqLMY5l3YEpP98lQg=;
        b=GZ5QakarYm53GkWWYiRSNmHu62YRrW4CJk8GvM1dgN5g10pMyQiA5KL4sTm6lxiJur
         5/fSwfFucnFe475Zrb1nwSffq4AQxFG5OFa38XscSgZguooqv/U/IQ/rc0x+LTUz0YdA
         WByN79bkTOFFOdHnUIRIqp35BPUO0MvVER76X+dkXXXKq+my9BMB0E/nRbgxS03Y8sLO
         GSJN/vd2Rn7bDKCkLzbheo+i5rV5BD1vgI17PsFQa2ObO1vRMRfn27usXMvlCC0LGd13
         enUtB6RGL4mS6LSUAWaea/opA4pmcSzSPxtJtdU9jc1PXtIgObto4lRalchGVYS09GU0
         frfg==
X-Forwarded-Encrypted: i=2; AJvYcCWU5OEryQq1AMySFtL+ZVtwYbX8LuloSRdEevpikNvf0Ko9+/QM+vo98bKXc1PqGDKcE93YTQ==@lfdr.de
X-Gm-Message-State: AOJu0YxAr423mu5MlyqktmnKPf31kB3QKRKlVu0k4aBU8CI/k1Fn4xXr
	fLqnBkWZlI8lhmWyEwGxvjorNB0vvrfgVcX3G+HvzdozFVhcitTudP8c
X-Google-Smtp-Source: AGHT+IEKtdxQ+zN7GO/hRz3bxyzPdb2Fv+UGUfOntP3Lhb0iWRMyR3cwC6GxaWsL2JCtJe12zGR5pQ==
X-Received: by 2002:a17:902:db07:b0:29e:c283:39fb with SMTP id d9443c01a7336-29ec2833a77mr70490815ad.52.1765458779799;
        Thu, 11 Dec 2025 05:12:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaIqUL20X6tb3/Hi3Ok+4o/J/uLlRAoBmNfOfRxhzhHBg=="
Received: by 2002:a17:903:3da5:b0:295:3ebe:5b4b with SMTP id
 d9443c01a7336-29ee92076f9ls7455325ad.2.-pod-prod-09-us; Thu, 11 Dec 2025
 05:12:58 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWacVsdAAhW64mfDWCvzg4XCeFqYUGnvRODE8mMr9K8BEwRZG5N+jCPxYIjBAm2DDfYshRfNrfRaQc=@googlegroups.com
X-Received: by 2002:a17:902:f706:b0:295:56da:62a4 with SMTP id d9443c01a7336-29ec27bae00mr58228165ad.45.1765458777903;
        Thu, 11 Dec 2025 05:12:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765458777; cv=none;
        d=google.com; s=arc-20240605;
        b=NpuMIbpzq9cLnelu+OBB5dg1TVXfneH2OkX9y5IufrtVshB7HDIYpRYxYWw+IH7Jsq
         UyX8ycdDyrXKEGVXAZl5dfeSdX7TZV3xO/iemBXaCQDXjCO+iy3lZPEUJ5iyONJuGeid
         jGfuAopbtSVZ66eRMMJarqMnzr9l+MJiy8cG4k2uYQAIjz5CXnD6BdQ5B3GeXFl8FL/K
         sgKpWy7q5snlY/E+izFF4cJrq2t0hHuhECCFaryQMEf5sEQx/5ClV+HNPOz2YKdYqXle
         YGPkZl9+K250U0IZvGnfx8W3sKnn4LRdovHNMUE1sH41LjO2NnQCx0phF6r/ho48hFif
         3lwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aSAWeLhswH6DwjvXpmjx7xXAiszMCLjSPlHn40Ul7IQ=;
        fh=qfaKMuFfcBtEGo5kihsIqGabV4VBrasLD+5MZscbuyU=;
        b=QoIqEKYgxznrBIPNiO5DPk/n9+us6M+4dnXp0euKJORMO4en/Jc27bydpAaxkRz2T1
         +8uFGUL37RvMk+7C53Ii31v19lbJtUooo47mkcFbrbOOUMFX4NsMglQA4sEyNUgdJrei
         7xTUlf5ShBs9121w2uwEJffGob+njOyoOIbjyarTEPVKuJCxlcvaPGw5DIElxRj0p0ma
         3Yc0zwcRr4z+l3/O73SAFsIv1MgoEDuwHTqyYmfBoZmpPTOiIWrXc3afRvGffXJfGmCD
         yOZKbkBmbkFq6tIhiULekEMEp5ljUH5vzGMF2Agd0JdMlGkwe4SYRe0W/GKz39Ro1b/u
         3r3g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=IBS82K7A;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-29ee9fe4578si852665ad.8.2025.12.11.05.12.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Dec 2025 05:12:57 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id d2e1a72fcca58-7a9c64dfa8aso36599b3a.3
        for <kasan-dev@googlegroups.com>; Thu, 11 Dec 2025 05:12:57 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUPzjPx0EEl/xvK7zrKtWg2NGQ+hyiIothvk6GRBlnEGc+Sy9dkxHK8k3DY4+5GF6PJ6XWqyU6uD4Q=@googlegroups.com
X-Gm-Gg: AY/fxX7baTrWUsSxpXouNgy8Aj+6wYEcQGwl64O1hT+8ZQEUgDzb93Bm7CK+cp8BlIq
	0msflamPO0ynqqinuCZwBcvqSA+qNIVunuQ9PRRjPU8Rn/efHZmZkWZL9R2YXsn9t/Tw3cbGcYg
	Ao+wzUeQcACVtdtOZEYNhukdnF0fDnhlN9S521Z7juouJT7yhrzeHzWCe+fk2HxgvBgodvcjS68
	91kbVlQF3oRTvmrTXsI+dgrmtSB+YCx2oIjk98WKn7Oyi55C+Ub+/YggULR156XkYBfXOj37C63
	l3xjQV2p5yGKkg9gZ3CJfiIT
X-Received: by 2002:a05:7022:685:b0:11a:5065:8763 with SMTP id
 a92af1059eb24-11f2966a3c7mr5044765c88.5.1765458776836; Thu, 11 Dec 2025
 05:12:56 -0800 (PST)
MIME-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120145835.3833031-4-elver@google.com>
 <20251211120441.GG3911114@noisy.programming.kicks-ass.net>
In-Reply-To: <20251211120441.GG3911114@noisy.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Dec 2025 14:12:19 +0100
X-Gm-Features: AQt7F2ok29a5Gxu0w202jEvGPrWPxaH5LVi0EBv48F585MyX9KePj1tDpUehhNc
Message-ID: <CANpmjNOyDW7-G5Op5nw722ecPEv=Ys5TPbJnVBB1_WGiM2LeWQ@mail.gmail.com>
Subject: Re: [PATCH v4 02/35] compiler-context-analysis: Add infrastructure
 for Context Analysis with Clang
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
 header.i=@google.com header.s=20230601 header.b=IBS82K7A;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::430 as
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

On Thu, 11 Dec 2025 at 13:04, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Thu, Nov 20, 2025 at 03:49:04PM +0100, Marco Elver wrote:
>
> > +/**
> > + * context_guard_struct() - declare or define a context guard struct
> > + * @name: struct name
> > + *
> > + * Helper to declare or define a struct type that is also a context guard.
> > + *
> > + * .. code-block:: c
> > + *
> > + *   context_guard_struct(my_handle) {
> > + *           int foo;
> > + *           long bar;
> > + *   };
> > + *
> > + *   struct some_state {
> > + *           ...
> > + *   };
> > + *   // ... declared elsewhere ...
> > + *   context_guard_struct(some_state);
> > + *
> > + * Note: The implementation defines several helper functions that can acquire
> > + * and release the context guard.
> > + */
> > +# define context_guard_struct(name, ...)                                                             \
> > +     struct __ctx_guard_type(name) __VA_ARGS__ name;                                                 \
> > +     static __always_inline void __acquire_ctx_guard(const struct name *var)                         \
> > +             __attribute__((overloadable)) __no_context_analysis __acquires_ctx_guard(var) { }       \
> > +     static __always_inline void __acquire_shared_ctx_guard(const struct name *var)                  \
> > +             __attribute__((overloadable)) __no_context_analysis __acquires_shared_ctx_guard(var) { } \
> > +     static __always_inline bool __try_acquire_ctx_guard(const struct name *var, bool ret)           \
> > +             __attribute__((overloadable)) __no_context_analysis __try_acquires_ctx_guard(1, var)    \
> > +     { return ret; }                                                                                 \
> > +     static __always_inline bool __try_acquire_shared_ctx_guard(const struct name *var, bool ret)    \
> > +             __attribute__((overloadable)) __no_context_analysis __try_acquires_shared_ctx_guard(1, var) \
> > +     { return ret; }                                                                                 \
> > +     static __always_inline void __release_ctx_guard(const struct name *var)                         \
> > +             __attribute__((overloadable)) __no_context_analysis __releases_ctx_guard(var) { }       \
> > +     static __always_inline void __release_shared_ctx_guard(const struct name *var)                  \
> > +             __attribute__((overloadable)) __no_context_analysis __releases_shared_ctx_guard(var) { } \
> > +     static __always_inline void __assume_ctx_guard(const struct name *var)                          \
> > +             __attribute__((overloadable)) __assumes_ctx_guard(var) { }                              \
> > +     static __always_inline void __assume_shared_ctx_guard(const struct name *var)                   \
> > +             __attribute__((overloadable)) __assumes_shared_ctx_guard(var) { }                       \
> > +     struct name
>
> -typedef struct {
> +context_guard_struct(rwlock) {
>         struct rwbase_rt        rwbase;
>         atomic_t                readers;
>  #ifdef CONFIG_DEBUG_LOCK_ALLOC
>         struct lockdep_map      dep_map;
>  #endif
> -} rwlock_t;
> +};
> +typedef struct rwlock rwlock_t;
>
>
> I must say I find the 'guard' naming here somewhat confusing. This is
> not a guard, but an actual lock type.

The switch to "context analysis" required us coming up with a name for
the actual objects (previously: "capability") that "guard" those
contexts.

The reasoning was that these are guards for entering a particular
context. The lock guards the given context, but the context itself !=
lock. Clang's naming of "capability" was a lot clearer in isolation,
but the problem that Linus raised is that "capability" is already
overloaded in the kernel.

The fact it overlaps in naming with the other guard(..) infrastructure
is not entirely coincidental, but I see the confusion.

What's a better name?

context_lock_struct -> and call it "context lock" rather than "context
guard"; it might work also for things like RCU, PREEMPT, BH, etc. that
aren't normal "locks", but could claim they are "context locks".

context_handle_struct -> "context handle" ...

?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOyDW7-G5Op5nw722ecPEv%3DYs5TPbJnVBB1_WGiM2LeWQ%40mail.gmail.com.
