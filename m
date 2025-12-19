Return-Path: <kasan-dev+bncBC7OBJGL2MHBBW4BS7FAMGQELDFDDSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D6EECD1F1C
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 22:17:17 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-34aa6655510sf3183530a91.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 13:17:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766179036; cv=pass;
        d=google.com; s=arc-20240605;
        b=AmBTVCPigP3O3Lh2tUbEeDj3xqg90t1kEBMpqpJF8foJRvbwxu0BWCTjI/QsuPG/9a
         5vb+rlIKmuKK8+63ejcr8FblrrlyIDbXS6JfhKkYRYeIEK3y6OVh2vIH00IRwbRhaxAr
         ertsGXXFGX09S+fo6apU59LWj58CLjObHcaC0ahxdHKyRBNGdTH1EVzMuWOwXKGg0P1K
         iPZ61/vmKPnNdRkYSWXLGSCN85EUzjsHhzPyEO9Vmk9pPyehl0MgBf9wcDG03zDBipIM
         2jnDXxB7dYjUa+shGnP8fIjZ6S2X8xGU2scWob4CGfFqZW1eORGqzhRoEfthQCWt0r67
         Wrug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zLeoDZZIzeSOkMlAORZOUJz4IWeU8HrenIpeNTLCs9Y=;
        fh=bkxt+/JX7zb++8tV1f7WtEVaa71EQHjzU0q3kmA34iU=;
        b=XkPgSe1QdpWc6ju3F7v3+tBo2oZgCf1kLEzEDLNNEIVhrXQ/t0AOgqUlaSWRmYAt2R
         szagGr912P83p9B4M9l3WL0Rtc1QO9W5HWVMgmuJX4+W4joEDf6n0Hm5paPQgmQoOh6n
         0PA0cXIOAl/a1Bon/b86nB3Jvb1108ZhZr4UXz+V8T+pT5Mjpjy7jbnA4XjlrxDptOts
         N/ul+16rHeylUr8h8HMrRMbmTziVrmm2SfhLcQYh3uyrGCP04eAwto239r0qSdp9gOhB
         mBdBauazTPcjAZWGYOBKgQJ020hn7lg5yTfhnUdIZ4auSmNEHGK92nkNgkqSI+/1huJS
         WMKw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=lj4UMLbp;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766179036; x=1766783836; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zLeoDZZIzeSOkMlAORZOUJz4IWeU8HrenIpeNTLCs9Y=;
        b=uOKvD51LETZ+lFWNk43A9xCCIy9saOFg5OtYF4uDikzKynfS4iSkXKBbDwJAECECFH
         pggj5h2GsYvca0vmnOA/Qi6JVlNS+ZLn6Ml0D9Bn/UUQlrCguidjxk5JHKXiIM9a0mKb
         5qLyWGk51cX0WH+lqcCER4Pf817sOK89dCGD4rkwowTzw9ufhACV5FiFP53P6xNBF34+
         nBGk7KkpaNxyH+Km78Ai6I/JxJxorBE/q0fofuCbROq/1QirW6RS/Os+Dc74jPfmpH4W
         D1CrsD3ZzKxcO1I2Zz1MeF5Nh4cj3EcU9ucjw0QKjfnkbrNlm8/ecgoS+vxdFmKHa+kp
         SGkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766179036; x=1766783836;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zLeoDZZIzeSOkMlAORZOUJz4IWeU8HrenIpeNTLCs9Y=;
        b=ZeNcc7OJV9KaFZ18KwQPPs8Sf1Pp8guYL/ZpmkWskfK+S3dOT+bOURUGnzar0fVlm3
         B6darCpK7Vq/0+Iyegb4/TzlFihBKZXFtxqrkqpMQITkOqiGoGHG/EWP0vG0lPn4nLAT
         IftkmDIOfP5hVDifIxyapRi5NU/S2vayZoBLg/pFSwqel+xR6GykEpaFJ6MszLPRM0Vv
         c1doTFUPP5qy8erLHAjBfouUFUTOTftqOvqOvvAjPm7YEH4CSeNctX3dW/NBXwvMyajo
         o3pXN+syv+YMIXPMa00SRkIhp8KAMlCRoy9+LSmcMO2B5rV97brs9u6csFye+jwtV0f3
         dZiA==
X-Forwarded-Encrypted: i=2; AJvYcCVWwLuXsXTLrT2IdI8HbZaBmorIRquROEgWOzExIvlr6rOSUADNnk9sSf+JPGN63NksFScCNQ==@lfdr.de
X-Gm-Message-State: AOJu0YwBm96ajJD1AIhlg7EPbvTiYy5uCMVB5VPv5AWv6HRc7NnJGmMj
	qBPT1nhJVeVEtaW/86CEYKlhSkclU1zcIublpd9X9Vvd5dF4xKimBH0c
X-Google-Smtp-Source: AGHT+IEQqhpCbcmglwICuC0/RaIvcV79h/wTS4TTMtwOQIlKQMwNjJW0qdZtZgQF+FVTt1HDkrlwOQ==
X-Received: by 2002:a17:90b:3c4d:b0:32e:3829:a71c with SMTP id 98e67ed59e1d1-34e9212a361mr3011017a91.16.1766179035518;
        Fri, 19 Dec 2025 13:17:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWb6yUilBkUOmIoZliBgfsKXL0V5KGM09ZojPGQy2M/gFw=="
Received: by 2002:a17:90b:4c90:b0:330:4949:15b5 with SMTP id
 98e67ed59e1d1-34abcc5d730ls8751226a91.1.-pod-prod-07-us; Fri, 19 Dec 2025
 13:17:14 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWrxr+YKjYzHwVRGN3a2kj8WNQf2S8vgyEcMc/LszGDeUjMcR2iNRH4zDJaZPfNcymnEqSAWROHM50=@googlegroups.com
X-Received: by 2002:a17:90b:49:b0:340:ec8f:82d8 with SMTP id 98e67ed59e1d1-34e9212a245mr3720980a91.12.1766179033756;
        Fri, 19 Dec 2025 13:17:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766179033; cv=none;
        d=google.com; s=arc-20240605;
        b=LHHo2Qc03nJSR9hi+RTE9/ymEfn7wMf26C3OwmjWEbflrhEb1Nxasbdh0jTQeo/2yR
         r3cLwAh8zJ/nK/lUBnBIMxYe498jkkd3wEoiUBukFNNA6KXzYrSqaJMBUIyAvyom2g9f
         JiSM2/kq09Ct/f2Qjtq8DUeVxsY1l6c8DAgtSCH+s2ZVvbEjzf7EWgdOSBA3caC3o38A
         XeF1vw5KakOXco2tBPfXFjhdsUS+irrvzMgTif26vLvHabWEgSQRzihxBuQUGNHW0A4Y
         Y8CjdeQP6dfWb8dzkfmEcHx+Z/0+ifWZwJ0B4pnpvE6suD5GFk0Xb8mU3wraa2DBTt6v
         hbiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0rK9w1Snx+IiOS1yyTvDXywJSRfl2rZ6jIui6kPmEaA=;
        fh=CWkm5g6so/CzysEu7JiakPwkswjvwx/JqYyybF2hFVM=;
        b=NrpLiHseILKlO/IRHYeSPKmeaht6VZa7qUmFG7zsOMw0N3r9fb7JxYxteAVw7ZZbRz
         L43kDknGjEmV0e6GFuMvzWwNo+7HEknAU/zVlLVV7efzxfLCNE84HIbLj/zRwndf5uf7
         ua+AtLrs0/0WTYjeJWbd6bFi9eMHqVpl2alVGKRe7pZM3vJNKu7hH950xa1WjWWxXWn8
         4y++JkJ44n2rGWxBpj1uXwhsQRKyh9qcU0aB6P4+St9HdDVgD6JnPqq9vwA/PCetTxMO
         tYGTeP1X7dafdCEdcADkIGsV4go8bZA9bKw/SH9OLLfp/N4QHBRlB0PG79SPAHfpAXK0
         HOXQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=lj4UMLbp;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-34e76ee8e09si79449a91.1.2025.12.19.13.17.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 13:17:13 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id d2e1a72fcca58-7b9c17dd591so1994507b3a.3
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 13:17:13 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWX4TVuuUpXsIIX6utj9ccWPljoOU6/o2yyh75EoLU63sPcPD3ZBthO/+G/qNSchccbyu9m2Y9EYrQ=@googlegroups.com
X-Gm-Gg: AY/fxX5S0zxJgZynb9Rdb8P2IhxwSPYeToSHwcV8KyWFgcqWaYXs00cd8pMk3lVVJ7+
	qutD8LrTX7CyJpBEC/z0vOYW2zeJKDcTQyeGoXcG4GNNV8dgPC8/y9vnqODPm8R+rmXIAUBUbKZ
	PnF22u6GYZZpJfl1/rJC3030nUwGElDsikPZV9zDwvEONydPELsQ95sjOyHwXCByQlXE/lK737K
	9ZfQI/R4m33tDtDlfY0TzCT1tf7tbnZ/tzA71Sd7b6f+U5xCWfu6lQaOFfZWUgFtt/Oj6Qh5gFs
	sBlxqM8YwPsCISEkV2mtipF6Lpi1vhsMHdRbUQ==
X-Received: by 2002:a05:7022:2586:b0:11d:f037:891c with SMTP id
 a92af1059eb24-12172311ffamr3088830c88.44.1766179032817; Fri, 19 Dec 2025
 13:17:12 -0800 (PST)
MIME-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com> <20251219154418.3592607-8-elver@google.com>
 <cdde6c60-7f6f-4715-a249-5aab39438b57@acm.org>
In-Reply-To: <cdde6c60-7f6f-4715-a249-5aab39438b57@acm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 19 Dec 2025 22:16:36 +0100
X-Gm-Features: AQt7F2oJirW61gdd7JR_kO6v8Pm8LYFzp_d0WJmR_my_E34K94emt-YaA94Rukg
Message-ID: <CANpmjNPJXVtZgT96PP--eNAkHNOvw1MrYzWt5f2aA0LUeK8iGA@mail.gmail.com>
Subject: Re: [PATCH v5 07/36] lockdep: Annotate lockdep assertions for context analysis
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
 header.i=@google.com header.s=20230601 header.b=lj4UMLbp;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42e as
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

On Fri, 19 Dec 2025 at 21:54, 'Bart Van Assche' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On 12/19/25 7:39 AM, Marco Elver wrote:
> > diff --git a/include/linux/lockdep.h b/include/linux/lockdep.h
> > index dd634103b014..621566345406 100644
> > --- a/include/linux/lockdep.h
> > +++ b/include/linux/lockdep.h
> > @@ -282,16 +282,16 @@ extern void lock_unpin_lock(struct lockdep_map *lock, struct pin_cookie);
> >       do { WARN_ON_ONCE(debug_locks && !(cond)); } while (0)
> >
> >   #define lockdep_assert_held(l)              \
> > -     lockdep_assert(lockdep_is_held(l) != LOCK_STATE_NOT_HELD)
> > +     do { lockdep_assert(lockdep_is_held(l) != LOCK_STATE_NOT_HELD); __assume_ctx_lock(l); } while (0)
> >
> >   #define lockdep_assert_not_held(l)  \
> >       lockdep_assert(lockdep_is_held(l) != LOCK_STATE_HELD)
> >
> >   #define lockdep_assert_held_write(l)        \
> > -     lockdep_assert(lockdep_is_held_type(l, 0))
> > +     do { lockdep_assert(lockdep_is_held_type(l, 0)); __assume_ctx_lock(l); } while (0)
> >
> >   #define lockdep_assert_held_read(l) \
> > -     lockdep_assert(lockdep_is_held_type(l, 1))
> > +     do { lockdep_assert(lockdep_is_held_type(l, 1)); __assume_shared_ctx_lock(l); } while (0)
> >
> >   #define lockdep_assert_held_once(l)         \
> >       lockdep_assert_once(lockdep_is_held(l) != LOCK_STATE_NOT_HELD)
> > @@ -389,10 +389,10 @@ extern int lockdep_is_held(const void *);
> >   #define lockdep_assert(c)                   do { } while (0)
> >   #define lockdep_assert_once(c)                      do { } while (0)
> >
> > -#define lockdep_assert_held(l)                       do { (void)(l); } while (0)
> > +#define lockdep_assert_held(l)                       __assume_ctx_lock(l)
> >   #define lockdep_assert_not_held(l)          do { (void)(l); } while (0)
> > -#define lockdep_assert_held_write(l)         do { (void)(l); } while (0)
> > -#define lockdep_assert_held_read(l)          do { (void)(l); } while (0)
> > +#define lockdep_assert_held_write(l)         __assume_ctx_lock(l)
> > +#define lockdep_assert_held_read(l)          __assume_shared_ctx_lock(l)
> >   #define lockdep_assert_held_once(l)         do { (void)(l); } while (0)
> >   #define lockdep_assert_none_held_once()     do { } while (0)
>
> I think these macros should use __must_hold() instead of __assume...().
> lockdep_assert_held() emits a runtime warning if 'l' is not held. Hence,
> I think that code where lockdep_assert_held() is used should not compile
> if it cannot be verified at compile time that 'l' is held.

That's not the purpose of this - if a function or variable should have
a lock held, we mark them explicitly with __must_hold() or
__guarded_by(), and we don't really need to use lockdep_assert,
because the compiler helped us out. In an ideal world, every function
or variable that requires a lock held is annotated, and we don't need
to ever worry about explicitly checking if a lock is held (but we'll
be far from that for a while).

The purpose is described in the commit message:

> Presence of these annotations causes the analysis to assume the context
> lock is held after calls to the annotated function, and avoid false
> positives with complex control-flow; [...]

It's basically an escape hatch to defer to dynamic analysis where the
limits of the static analysis are reached. This is also the original
purpose of the "assert"/"assume" attributes:
https://clang.llvm.org/docs/ThreadSafetyAnalysis.html#assert-capability-and-assert-shared-capability

Without this escape hatch, and deferral to dynamic analysis, we'd be
stuck in some cases.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPJXVtZgT96PP--eNAkHNOvw1MrYzWt5f2aA0LUeK8iGA%40mail.gmail.com.
