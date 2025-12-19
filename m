Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOOBS3FAMGQEERPXGAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id F040FCD1810
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 20:00:10 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-657474a3312sf47028eaf.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 11:00:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766170809; cv=pass;
        d=google.com; s=arc-20240605;
        b=M7ZABYkbiPX4T/U4F2sjR3I4CXubQQ5jql5JBb0DDmOr4Cqsg1nY5Ux1SYdmrpWXkB
         aZGbYnP2EEWjQxjDNHZJ5EyzWF8Whi2N2hBXNPbaPoYaozVk+1CZ5kS6OEsPcVNLaqyr
         Qn5Maplzh8NP8iF9mfI0LAtSIBvHbOQIRkFaoCAQnDxpxG61xq0LWFl+StEu+uBVwhHG
         pf+IZ6gsdWSvr0YHP84iglQhGKcHuEDruC1CU/OXmZ0GBE67znSAHerSErU6PnwhOfGl
         WZnzevOxG0WWr/kSTaRR5bsMuPqJ01Mf5f/AJkK5oYvwStzsj75j071xbVd0yCL9sAf6
         kVkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OTkcccV/SMA0HygcotIG8GgUgHGveG6Sy1FaHFoilh4=;
        fh=+7sZAxCIEiCbZVw3R8V60GkpPsUYIOtfsoGKJ7VPBZo=;
        b=aDCl6LYjzy/VROA7X6ABf5TKmrxR4hVEI6dB6s/nlb51rUCtHDzYpofCZA3cFVqq5w
         l6ulCz87gFGjpHUBIv1mOjiKMQFh7M+LI6VxMKdXJIhq/OsHSYTtY4EGWSMoNAyYz3eW
         rFD9yuowWob0rLK19fbcjSKgifXGiL6RKDrGaluQL3FDuSJ/vuFaXgyJa759iTm5vo/e
         wK6O3fjYEjyA2wotafXq4EFr+09ALQb0JZ63rZcU1gvNlhmr/o0H+RK7BLXhsxNEq6LX
         kPlN+GTMEu/kIdI49XY4kzlkzQlrOGgcOtI2UTIOeVseTJlrsPT7YCvakgASy63EHa8w
         fhzg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tM4cU+A6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1236 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766170809; x=1766775609; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OTkcccV/SMA0HygcotIG8GgUgHGveG6Sy1FaHFoilh4=;
        b=XumVPnxn56KzLpM8istdcO54or4s3CKzR5m83QYd+bOIZKrn2g0G2f54J4Q8WJXsxE
         ab6KAL6ICV10tYVtY5LiW1ZvR5SDs7SGzGipCftQipBX3dKVCgOeWjjHfUTPt5CvkrTE
         XBGiqfawOH0vLsp1ebJ533C3nwOeZ9wt89A46fZ/sFUk9oE4MguUUw9Pr4FHuk0K7zH+
         tbctLGREDPYF8Qn4Byi3MGSCb35d5Ev89Eaz1j+1cdsIjXJRfgQnBqQe80No/gzp8IVr
         CZED+UykmxiZboN6914K6MXmdUcuJ4K+goXi+nZjvFaU3v6TQxgaqB6rpQLe4P4bPFpt
         Zdtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766170809; x=1766775609;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OTkcccV/SMA0HygcotIG8GgUgHGveG6Sy1FaHFoilh4=;
        b=D5AqgpaJ0AKfZEk4KYFJLaX1GgDe9CAuFgLXmS8lGoWlEf2LJtGadg/vhhwl2l8B3l
         GtSh87Pxp2Y9W8RyZwBilMWhED7/Wm8eKBiU5fY0YaD4r0fEBTmVFzAbgOZqk783JHzv
         vAed+IYN2hO3Bvx98Iapz1NaSLKe9Pl7xwbsP0Ird4rsdzc9qtdhyOkMupTVyWgTo9HZ
         T7bNMUKlhCLypVREoSAdQ0MU6dBeA4LE2b4sPZOd1hzLOqzN48hv/q8eA+qxJ9I5b5LW
         T78SQhY4wIs7YOwW5lsTMYY0tI9B1RqrtE2XWeN6KNnouYE9xlhJrCt3YgyCD1hMwSLN
         ojpQ==
X-Forwarded-Encrypted: i=2; AJvYcCUWkjNPwdV8Q/vSB2PCjhttoNsRW8AWCSrmtASlcM5hrweokYombMdFO0z5bUiYxA03bBHmhw==@lfdr.de
X-Gm-Message-State: AOJu0YyTRGVrjfkSCm9o6wuQ8rgCHhspBIeZWdD41HCc6e12he+dbBLY
	Pfc85ukb1oxYvy2ejGCIiQNzuyo2tAdBsycAPBjbLmznMbZ6akrKaaFT
X-Google-Smtp-Source: AGHT+IFnnaIaiqN0wl9KZT3rRAOl3T+YSn0D+LZoCvIKv/N0oKtjFEuThtRvAwDocnVXjAzWrtmRrg==
X-Received: by 2002:a05:6870:f114:b0:3c9:88eb:39ba with SMTP id 586e51a60fabf-3fda561464bmr1494414fac.2.1766170809224;
        Fri, 19 Dec 2025 11:00:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZL/07evODpUrxs0rY6y1jtHkDzbwZwAygcx453nZ8BPQ=="
Received: by 2002:a05:6870:a11d:b0:3f9:f658:fe8 with SMTP id
 586e51a60fabf-3f9f6582e06ls1625735fac.1.-pod-prod-00-us; Fri, 19 Dec 2025
 11:00:08 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWROeFxARyxmGwCv/oOSb/7GRA/C+8bv1WBDhkSlILk6/34UM2T3bk+VNOpJR8F8Mp/+DH/GkWEsyU=@googlegroups.com
X-Received: by 2002:a05:6808:4fd0:b0:455:e057:982f with SMTP id 5614622812f47-457b20f54f1mr1947495b6e.1.1766170808011;
        Fri, 19 Dec 2025 11:00:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766170808; cv=none;
        d=google.com; s=arc-20240605;
        b=QnO0bl7L7XL9VgNAs7DUaRz9xlUXlsbAC2PyXLhcTB8CjtIG7Xk9fiECAqNjdzHDvt
         1/rS1qPbMbdg4GrL1h7TZjGWxyXVHsPOAmdRJN69LeuTWVYZ0sJAKKP2sL6sS1Z5iCGr
         PMgPFue1HFptNQWCwSvzF0SsaX4PAuokq6cEkoYQrttZ7fTKCTM8DLUGum0lyxVWbTWP
         GLMTlAFi4gS5IMlitRb5UAEYi9lVg9erNFoSAx+9Wl9ldBlWcORkTT8tkJ/G7qdhl1SB
         jXAfxnjseLTZ75nItR7k1Y2BWISicU+eTxq0JFSY1E+dN0GdISWvaycDubaHGjF11p2y
         UZTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=D/odPIAsEqnlw6wHnS+qyMx9or3tLcz+4e0MlLzaxNc=;
        fh=5kDa5UaKulsCSbexi5i6d6XPquBMwclfb6+SKkF62c0=;
        b=Nz0w7n0N7O5xge5u/jAXL/U4/mHtsD4c1dcgYGWGPGF6ILcqcMlXemAioCqdq9wXG7
         IQ25JaWFe6yrOfRaDFjhdgZ3DerS/5OJmGxjHa446T+0ewsRe9wAiGYHqSrzHNu6uDtb
         syZAw6GMP00My7oKf1by2sIis8QuNmggWogeigTInBA7R6M+L0S8I0WSlN6tR5MWdmg0
         s8IfeYY2FEFMqZc8WI6Zqcux3s+sPCZ/8dd/NU78bZcRsie6D/LZDkBfncQ9ROaaf3Zc
         xTt+HJiPeexLFhJKXcLezi63r4vRsNE1dH6UfRqlSl+OgEZPb43U1/shdz82G0VQn/Te
         5PsA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tM4cU+A6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1236 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-dl1-x1236.google.com (mail-dl1-x1236.google.com. [2607:f8b0:4864:20::1236])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-457b3c6f22dsi173024b6e.3.2025.12.19.11.00.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 11:00:08 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1236 as permitted sender) client-ip=2607:f8b0:4864:20::1236;
Received: by mail-dl1-x1236.google.com with SMTP id a92af1059eb24-11b6bc976d6so4672669c88.0
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 11:00:07 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUM/nHx0a1pzPk4MkIxQ9oHbt9mVUxVSpW/BAg56nZIzUnkfYF27j9t6Kqkdp1+3dDvY97RTWnrXv8=@googlegroups.com
X-Gm-Gg: AY/fxX7+zFE9SPr0hWlapgKfcB9MzQXed12lt7IGGO8+G0dlMhFyeXE11vzFg3/0vj5
	4oNw/KBtKBf5Ai4OS35ZpcMV3+Pz7xrOu/g/2fMfo1kZx8vvGjRkOcavJwA0MmfmO/NGE8+5d0T
	8QKO9hdhmAlB00BfGZBxB+UXs6wyhijhvHtjE1tjtbRpyGYZZ25KybaiRsRKmrt+38E0lmCcax2
	TFca4bPZLv3iCC+uIlvU2tIBgWN7YOJeEjVU1hkTUHMEpbSJChSXbK5p1Zfe0bnN9EwnXx4pCqq
	HmxBIMhT4ciQgNZC722BjoQ4TW0=
X-Received: by 2002:a05:7022:688:b0:119:e569:f86c with SMTP id
 a92af1059eb24-12171a75857mr5077504c88.9.1766170806408; Fri, 19 Dec 2025
 11:00:06 -0800 (PST)
MIME-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com> <20251219154418.3592607-3-elver@google.com>
 <97e832b7-04a9-49cb-973a-bf9870c21c2f@acm.org>
In-Reply-To: <97e832b7-04a9-49cb-973a-bf9870c21c2f@acm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 19 Dec 2025 19:59:29 +0100
X-Gm-Features: AQt7F2ouc-8nhWnrDvuFRBnm-IOIeCWwTeXWCxaDLix1ft6mKkghBhqY0U-N9rY
Message-ID: <CANpmjNM=4baTiSWGOiSWLfQV2YqMt6qkdV__uj+QtD4zAY8Weg@mail.gmail.com>
Subject: Re: [PATCH v5 02/36] compiler-context-analysis: Add infrastructure
 for Context Analysis with Clang
To: Bart Van Assche <bvanassche@acm.org>
Cc: Peter Zijlstra <peterz@infradead.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>, 
	"David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, Christoph Hellwig <hch@lst.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland <mark.rutland@arm.com>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Miguel Ojeda <ojeda@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
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
 header.i=@google.com header.s=20230601 header.b=tM4cU+A6;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1236 as
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

On Fri, 19 Dec 2025 at 19:39, 'Bart Van Assche' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
> On 12/19/25 7:39 AM, Marco Elver wrote:
> > +#if defined(WARN_CONTEXT_ANALYSIS)
> > +
> > +/*
> > + * These attributes define new context lock (Clang: capability) types.
> > + * Internal only.
> > + */
>
> How can macros be "internal only" that are defined in a header file that
> will be included by almost all kernel code? Please consider changing
> "internal only" into something that is more clear, e.g. "should only be
> used in the macro definitions in this header file".

Sure, comment could be improved.

Let's say they aren't for general use by normal code that just enables
the analysis for checking; for that we define the shorter (retaining
previous names already in use) ones below. But some of these
attributes can and are used by implementing support for some of the
synchronization primitives.

> > +/*
> > + * The below are used to annotate code being checked. Internal only.
> > + */
>
> Same comment here about "internal only".

Sure, can be clarified.

> > +/**
> > + * context_lock_struct() - declare or define a context lock struct
> > + * @name: struct name
> > + *
> > + * Helper to declare or define a struct type that is also a context lock.
> > + *
> > + * .. code-block:: c
> > + *
> > + *   context_lock_struct(my_handle) {
> > + *           int foo;
> > + *           long bar;
> > + *   };
> > + *
> > + *   struct some_state {
> > + *           ...
> > + *   };
> > + *   // ... declared elsewhere ...
> > + *   context_lock_struct(some_state);
> > + *
> > + * Note: The implementation defines several helper functions that can acquire
> > + * and release the context lock.
> > + */
> > +# define context_lock_struct(name, ...)                                                                      \
> > +     struct __ctx_lock_type(name) __VA_ARGS__ name;                                                  \
> > +     static __always_inline void __acquire_ctx_lock(const struct name *var)                          \
> > +             __attribute__((overloadable)) __no_context_analysis __acquires_ctx_lock(var) { }        \
> > +     static __always_inline void __acquire_shared_ctx_lock(const struct name *var)                   \
> > +             __attribute__((overloadable)) __no_context_analysis __acquires_shared_ctx_lock(var) { } \
> > +     static __always_inline bool __try_acquire_ctx_lock(const struct name *var, bool ret)            \
> > +             __attribute__((overloadable)) __no_context_analysis __try_acquires_ctx_lock(1, var)     \
> > +     { return ret; }                                                                                 \
> > +     static __always_inline bool __try_acquire_shared_ctx_lock(const struct name *var, bool ret)     \
> > +             __attribute__((overloadable)) __no_context_analysis __try_acquires_shared_ctx_lock(1, var) \
> > +     { return ret; }                                                                                 \
> > +     static __always_inline void __release_ctx_lock(const struct name *var)                          \
> > +             __attribute__((overloadable)) __no_context_analysis __releases_ctx_lock(var) { }        \
> > +     static __always_inline void __release_shared_ctx_lock(const struct name *var)                   \
> > +             __attribute__((overloadable)) __no_context_analysis __releases_shared_ctx_lock(var) { } \
> > +     static __always_inline void __assume_ctx_lock(const struct name *var)                           \
> > +             __attribute__((overloadable)) __assumes_ctx_lock(var) { }                               \
> > +     static __always_inline void __assume_shared_ctx_lock(const struct name *var)                    \
> > +             __attribute__((overloadable)) __assumes_shared_ctx_lock(var) { }                        \
> > +     struct name
>
> I'm concerned that the context_lock_struct() macro will make code harder
> to read. Anyone who encounters the context_lock_struct() macro will have
> to look up its definition to learn what it does. I propose to split this
> macro into two macros:
> * One macro that expands into "__ctx_lock_type(name)".
> * A second macro that expands into the rest of the above macro.
>
> In other words, instead of having to write
> context_lock_struct(struct_name, { ... }); developers will have to write
>
> struct context_lock_type struct_name {
>      ...;
> };
> context_struct_helper_functions(struct_name);

This doesn't necessarily help with not having to look up its
definition to learn what it does.

If this is the common pattern, it will blindly be repeated, and this
adds 1 more line and makes this a bit more verbose. Maybe the helper
functions aren't always needed, but I also think that context lock
types should remain relatively few.  For all synchronization
primitives that were enabled in this series, the helpers are required.

The current usage is simply:

context_lock_struct(name) {
   ... struct goes here ...
};  // note no awkward ) brace

I don't know which way the current kernel style is leaning towards,
but if we take <linux/cleanup.h> as an example, a simple programming
model / API is actually preferred.

> My opinion is that the alternative that I'm proposing is easier to read.
> Additionally, it doesn't break existing tools that support jumping from
> the name of a struct to its definition, e.g. ctags and etags.
>
> > +config WARN_CONTEXT_ANALYSIS_ALL
> > +     bool "Enable context analysis for all source files"
> > +     depends on WARN_CONTEXT_ANALYSIS
> > +     depends on EXPERT && !COMPILE_TEST
> > +     help
> > +       Enable tree-wide context analysis. This is likely to produce a
> > +       large number of false positives - enable at your own risk.
> > +
> > +       If unsure, say N.
>
> Why !COMPILE_TEST?

That's the idiomatic way to prevent this being enabled in allyesconfig
builds, and other compile-only random configs enabling this and then
stumbling over 1000s of warnings.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM%3D4baTiSWGOiSWLfQV2YqMt6qkdV__uj%2BQtD4zAY8Weg%40mail.gmail.com.
