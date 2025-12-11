Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCEK5PEQMGQEQFSFMSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113f.google.com (mail-yw1-x113f.google.com [IPv6:2607:f8b0:4864:20::113f])
	by mail.lfdr.de (Postfix) with ESMTPS id 54A86CB5FE1
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Dec 2025 14:20:10 +0100 (CET)
Received: by mail-yw1-x113f.google.com with SMTP id 00721157ae682-78933e02c1bsf1613827b3.0
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Dec 2025 05:20:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765459208; cv=pass;
        d=google.com; s=arc-20240605;
        b=bKFi3F2klSV5E4xDet03VVnlkJxZXRQoW798yXBlI1yaGew3Mma0/jD8bRanaOdUqv
         s0UF4UhJWKH2OHTk+TLc/ey+cCd2m4dT2hX0b/JDd3rwIqCujNqauk05vc94rBzTUO7Y
         f4EhQ971sX7fhmNf9rDIR00QyUSRlbkc2yvFI4NvS6yyzhUXPN9GROgJbCJjkvuvGq9s
         QFz5x7OoVXb0DVNdPPslHH8o73QFps82fTKx2K3JiZxoVc1WI6y4IuX/YLM8lmRZ0Vcu
         bx1P4OtzfuipZQKWSOuMluYrHbf33QQGMxveJZUh7H3LujFbzrLtQArvyeWKTyKrf9g5
         AcNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TB0iZrrGWxVYE738oVLr519VqF3MCsyc+yJhH3k7NDo=;
        fh=TXjtJQMSRk2+4PiCYP9YwTqdH/dsY+0qF/mVENO9CV4=;
        b=ABPq/2xauHWluhYiwe/e5Xiv0UVEn1DazOT5N+lO6OlqV4jmZ0x7oZWQrfXtWL7tM9
         xaMQZVn8B2WkQNYmfX4gmfadeMvz4hQjeD3zpUEg5PKdxBkAPIvFPg+5YeEPxbmHsh3+
         L0MgYcwUQhAgB71eAYgLpeEDL4SduwyGN2hVMemI8/e8TIINXnUArlq4fo6w0OOs7Fxn
         l2Lz1a92Ynv+jro6HAZdX7xcXwK8IEQ/K4YseOHvKUcgGCSXorL0OKDdQLufLBgmRm3b
         YcoVvyn/qC2CuE/MJFdEkqF+t+K+z6dF7DX29xndt3oB7w4Hg8U9+N+th5EhHwBgdOVQ
         FHZA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Ki8zZLOi;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765459208; x=1766064008; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TB0iZrrGWxVYE738oVLr519VqF3MCsyc+yJhH3k7NDo=;
        b=KEnmyQciumkDitr3LXmNZ17ZUXbNIERD468XG2zpVp7wsTzFR5PEzCeqRqLEHese6Z
         LIDw4yOOHJlTmRdHWg9zQxL2bIf69e+dZvTnB0R/ULuw9L5GeR09uq7CAOybMysdjkXl
         wnIAwu2WrPpiF8Vpsr2Dq7p0zMbidjUNpbPbcYI3xUO5rxrama6/j9rDScG7i3u4CtCR
         YkbH5dpf2rOsmQ2wuAi1TLWJ7HtLo+C5+RDbADYVRBoFPnlyI0N5ufQji4IlTlbxatZk
         1/0YNNapbzkG3/At/LD7NcBkyu8Z1QSXdKhnaintUQQYZGuyBeCA1k7lW205OSRCwiPs
         5GbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765459208; x=1766064008;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TB0iZrrGWxVYE738oVLr519VqF3MCsyc+yJhH3k7NDo=;
        b=fdsd/zRGlfYLaJwEsF78tS+wQKRwWD7VmQmifIq4S3tmgC1oYtVXYR7ysUcxmF6Omw
         SW6hw6grRKnc1gr7rpewxa02E2Tapse2HtN/zI6CLmoMikywqoTZ8etlcesn3iQhxWhX
         Q2dyjc2M3Tyv00/L+PNcRezPn0oztdGMuk5k63LRkUtCzZPvC4RIWn08yGkFEbrA2Ww0
         v8/bizPigWvDj0ItVujB2rw7ie3+vsPmkfnryIi4A9wCYD8geie7yWJcz66c8k3FNreI
         IjYpY2LHnwxJXM5Por3fBmKcFHN8dE85KuyOUujZae+82+uxoNxyFf8bsGM3+DTr3AWG
         jz3g==
X-Forwarded-Encrypted: i=2; AJvYcCUucPbFQSzrH3xFhwh3YfXG52EIhBbFpOuiMEx9bVP65lf/3k0+x8u9YwC5RL5Z5qEe94LXWQ==@lfdr.de
X-Gm-Message-State: AOJu0YxRGoFWHPBlS3ka13rFUFrshnG+Ka19ql8N6XegzLFtdG+GfrLL
	igZ9yrzVG4A4stIQ96oSj8hFPJy6M/BMDk5E0dPFasYF9sAakPvRJ7ah
X-Google-Smtp-Source: AGHT+IFdAJ5tMliKEc6S7iF0ID5pQqYyu5kXF/twth6/UCZ8Md+G8R873CdK1mvu0e6QlXWXoBkmlw==
X-Received: by 2002:a05:690e:4090:b0:63f:b353:8fb5 with SMTP id 956f58d0204a3-6447a78e44cmr1465690d50.15.1765459208523;
        Thu, 11 Dec 2025 05:20:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYXXlaQYrlSS+r4kyT6wgA+9nyO4xg/fQYa0ZB+QdQWDw=="
Received: by 2002:a53:d057:0:10b0:644:368f:fd30 with SMTP id
 956f58d0204a3-6446d8c9a85ls759164d50.2.-pod-prod-00-us-canary; Thu, 11 Dec
 2025 05:20:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXS3jdKwNtLKXcjF9laEw8w51UXRQ3b9jBIZHWfzpiUMIXTP4xzzD6QgC5JVzmlu51QPJdFOBVsElM=@googlegroups.com
X-Received: by 2002:a05:690c:9e:b0:78c:d4ce:411b with SMTP id 00721157ae682-78d6deb4eb9mr16904207b3.8.1765459207319;
        Thu, 11 Dec 2025 05:20:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765459207; cv=none;
        d=google.com; s=arc-20240605;
        b=HFoXZwe8b0Gs3F2mKwZEuY2cSFrcqInK1oo3kOmyC73FTVuNxUp2XuroC49YaGOK6R
         elnixLADxFrpZe2CBHMEXfPno8Ziul1grfFMmOs4183U8b9qYBZYEA+wzfRmEB634lW/
         R8wJ3GBtUWD5whKE9UdjeCKZA5lHA9AcHuXRP5tOhmvgd+ThBOLLsPHtHgh7mQCNAVG+
         EiszIGSc71SjLcGs7CLLN8NwMQRWl8Lyno0hiMuHlASxbwwYHa8Jgn9+ru/EJOI+cQ8c
         hRvtbWtppOpjxs8iqPLJKFlxLLCkW4PSeA2IE0meAgFkN1mqs4I3Frk98gaox5e4KHx9
         imhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aINMqpJxr1DSJJ7CC9TS1ttoat4qqoJbgL8dBerwdo8=;
        fh=vh7AcqePf4ZbfwRps0D46uanUoa0VQJsbGdUogkOQS0=;
        b=Ylrbx22kSf7lcpqYT2UeTNNPV1b9mAsRx0ZVm6msSL0RTKKVBh2p9rNOMyu0fm4utZ
         QizJoLWaCKD75gkJG9xvQL5BiBUgdNLKNRnr8v9OA9ZnKZuqBmZr3z+rCxkxE5g3Z146
         5Wp5BK+82MNRgaEiU4ZWYF9KTb7sz9Oieq44Tnl7aa/VxNadgW8HnpeyVLY1Eq/ZKYxH
         FFp25sKdOgEav9jc3XWlJzBjPtzwG/jGDu3xJ5Pux2yBBcr27PVGA1uepxHgzGx8fqA0
         JxLJs11AHPK6/QB2shgNetHYOp84/8CQprUcpN75OFYbg7Lp9fDlOaqSJyXe8/RgIUyJ
         +8+Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Ki8zZLOi;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x1136.google.com (mail-yw1-x1136.google.com. [2607:f8b0:4864:20::1136])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-78d69db0dc9si1376597b3.3.2025.12.11.05.20.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Dec 2025 05:20:07 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) client-ip=2607:f8b0:4864:20::1136;
Received: by mail-yw1-x1136.google.com with SMTP id 00721157ae682-78c5b5c1eccso1098407b3.1
        for <kasan-dev@googlegroups.com>; Thu, 11 Dec 2025 05:20:07 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXrJ075fMOA0ZBm4iQkMFQlx1IrwaCy3Y5elkHpzyWDz66HAn1LWVKNHK1+tWpWUeuLJwreNYJJX2M=@googlegroups.com
X-Gm-Gg: AY/fxX4Bo3ZuzZk6AorG3yUbYAyMYc0phMm7bmaAmmjabIzaQmo6zLcKNbp8YXMxMr1
	/tNsc5G/CLyQxfzr1WxbwGynuGRa2beW6OzVYHBy6Pf0H2uIXUnNg9gsez8ceOsd2JndcxJFDVR
	x3chkuw5vdftk+zkI8rConuGk/08EWlKAiXroWxtSs9pYWPYVSyK6zTMLkP7fRe+1upbvNdkgYq
	e2XkJ/4dbAVkgK5QiAFqZVzUfs7x5c9E9bNbjvrr4EYiEkE0N7J2appXzctPGVXVVHbIqMy6zw+
	UB6qTws98pAaOu+y4Kwja7rb28DQM+Gr4VI=
X-Received: by 2002:a05:690c:14:b0:78c:3835:496a with SMTP id
 00721157ae682-78d6dfa0ba0mr18429857b3.24.1765459206488; Thu, 11 Dec 2025
 05:20:06 -0800 (PST)
MIME-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
 <20251211121659.GH3911114@noisy.programming.kicks-ass.net>
In-Reply-To: <20251211121659.GH3911114@noisy.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Dec 2025 14:19:28 +0100
X-Gm-Features: AQt7F2pfFUoFUVEdkJ6Nswms767xMhA__DttYAE1PqX0AgFhiN8dcasmhdnfxEw
Message-ID: <CANpmjNOmAYFj518rH0FdPp=cqK8EeKEgh1ok_zFUwHU5Fu92=w@mail.gmail.com>
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
 header.i=@google.com header.s=20230601 header.b=Ki8zZLOi;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as
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

On Thu, 11 Dec 2025 at 13:17, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Thu, Nov 20, 2025 at 04:09:31PM +0100, Marco Elver wrote:
> > Introduce basic compatibility with cleanup.h infrastructure: introduce
> > DECLARE_LOCK_GUARD_*_ATTRS() helpers to add attributes to constructors
> > and destructors respectively.
> >
> > Note: Due to the scoped cleanup helpers used for lock guards wrapping
> > acquire and release around their own constructors/destructors that store
> > pointers to the passed locks in a separate struct, we currently cannot
> > accurately annotate *destructors* which lock was released. While it's
> > possible to annotate the constructor to say which lock was acquired,
> > that alone would result in false positives claiming the lock was not
> > released on function return.
> >
> > Instead, to avoid false positives, we can claim that the constructor
> > "assumes" that the taken lock is held via __assumes_ctx_guard().


> Moo, so the alias analysis didn't help here?

Unfortunately no, because intra-procedural alias analysis for these
kinds of diagnostics is infeasible. The compiler can only safely
perform alias analysis for local variables that do not escape the
function. The layers of wrapping here make this a bit tricky.

The compiler (unlike before) is now able to deal with things like:
{
    spinlock_t *lock_scope __attribute__((cleanup(spin_unlock))) = &lock;
    spin_lock(&lock);  // lock through &lock
    ... critical section ...
}  // unlock through lock_scope (alias -> &lock)

> What is the scope of this __assumes_ctx stuff? The way it is used in the
> lock initializes seems to suggest it escapes scope. But then something
> like:

It escapes scope.

>         scoped_guard (mutex, &foo) {
>                 ...
>         }
>         // context analysis would still assume foo held
>
> is somewhat sub-optimal, no?

Correct. We're trading false negatives over false positives at this
point, just to get things to compile cleanly.

> > Better support for Linux's scoped guard design could be added in
> > future if deemed critical.
>
> I would think so, per the above I don't think this is 'right'.

It's not sound, but we'll avoid false positives for the time being.
Maybe we can wrangle the jigsaw of macros to let it correctly acquire
and then release (via a 2nd cleanup function), it might be as simple
as marking the 'constructor' with the right __acquires(..), and then
have a 2nd __attribute__((cleanup)) variable that just does a no-op
release via __release(..) so we get the already supported pattern
above.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOmAYFj518rH0FdPp%3DcqK8EeKEgh1ok_zFUwHU5Fu92%3Dw%40mail.gmail.com.
