Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJXJVD3QKGQEIVNJE5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 295A91FD0C3
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 17:20:07 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id dh12sf1008208edb.9
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 08:20:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592407207; cv=pass;
        d=google.com; s=arc-20160816;
        b=qwxyHYcl/Nd5BisQgNSKv3Q9CUvkuSItDfgkf23RYgV0s1TqfB5lNqffc5SpMegdnL
         b1dqkvhOVRt+73T9n8lKZHcpNo+mKWxNb0hWXHYWM3niwRMUfyVS5faFarSzy8aL4h6T
         iCCG4H6ZcTcpyboExSviltrD/b4XdRa0dfn7hBAlR7TP5V+JM6oqHBwOJINPQhHa3l3L
         ZIgT+j7KUvhXRmgJieYCNkfHBP2xk7tNNnIP4nWFzmd/JahPYoB73FLZEHYoLD0s4lzM
         mRaCnm0LTbOCuFWRrLtiEX5fPbku5ab5AYrg4dayozGzmYR1nWEK4M/bB3QVseTvAEnk
         bHsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=mjTa/CMc942K8/BoQoEGXu39+rw9PLZtYUDrHGAE6Yo=;
        b=nX1H4ZiL0DDJ7Hg+8J5p6XOZr+Y9Ro3tBnMrdmTQEneqvs9wg/Kaww9zTWYPJEI2y6
         nyR0bxvxi4Tcrh1Kk5yYu8uNrGcfpRG/jnybc/Al0ilMwBf0ovv/Z5PSkVs2JAvCLQMW
         07ofNP+llgkqOtBGr+Tx3lxhVLDb7YIftp9eBwvmTDt1WfGooFiKArdoHBYi3K32Lerc
         YAsP+FPxvnGuJnAd8v4W790bxcj2+FZoD5yvUAWdr1rJg0TvmufWiVQfew0+7o5bvD0b
         wcynFLATPY23QmPa6cbj85m1WWpsKjiG8ei49dfixH0vn8nJO3PFkGPjmaaDNtTqcEjQ
         kSXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KHJyeHZ1;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=mjTa/CMc942K8/BoQoEGXu39+rw9PLZtYUDrHGAE6Yo=;
        b=YkcxwIh7YTDP5Dc19AZ04ro1dIjZzxLy8NhJdiLWUzoTUeosX6ViUyv1fIT+Pe9SD3
         a5dRUvXA0aQwY7UfGYm8aNT/F7S6ngYZy0DTgn0FtxwfLNg/3O5RF2roa8fZDEQlloQg
         yDo4tmzQ/Dkcm2qPIGvXy/XnQ7SFEDrEKujBGXJJG8OWpvmLa8OiNZafZtYNQhpY1tT9
         F09GeWkwytkPrB0I6+/9Utvnr5A5yaCne3mgsCkgPgoVmb0zpI+v3Nc9OpQaCxq/4O+P
         Z47wX0AkGiGVonkgn3Ag8nHE/vaYNjQbhfl0lup//3jKX6aNRrWUVxIH5LTWorz9tVM6
         S3Dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mjTa/CMc942K8/BoQoEGXu39+rw9PLZtYUDrHGAE6Yo=;
        b=IRHsSJ2pk93HIGLGY2dtzemcmdstf5GC3rGOC1reysAbsGpshUOy7k0BQ5ZEXx5NaL
         RZ8rjzGW0/SD6qGKZDF700HR6SKOlJf6G5hnj9xNvHBzI67qk3Vhc0Y+G0ONGDiylDB2
         4ukEtZfQfoKnJaQjuNpKZWTQ+58urN2V+XSmZz6uM2gCdg/tNRHAiKzZ0GsuaGgo5cz8
         bvTL2teNpwmYRVuXQmNdOuthmKfyMWVLS41O3KlFoV/0Ra1bNiRQcz9tVm2aiTXfJQav
         b/m6AdmPsFEj+HyukQ1gKnDq/v7E8unit7rc3u4yi52L6RX/K7nktX7PtqzeHB05XC6b
         FLOw==
X-Gm-Message-State: AOAM5332iAdpiv4H+9MOntgDccK/tF4WMfJlwOdB6rIgGbNXgFA/XxIr
	qIPKp84KJHQl7QoqdbTbtic=
X-Google-Smtp-Source: ABdhPJw/fvOszYVfAYmm9ybdJBIuMinNvxp85jfuvM3P3hgnisQfhBexQNi6WDFpIYTu7uW50LECFA==
X-Received: by 2002:a17:906:7b54:: with SMTP id n20mr7914807ejo.144.1592407206899;
        Wed, 17 Jun 2020 08:20:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:84a:: with SMTP id f10ls1287091ejd.10.gmail; Wed, 17
 Jun 2020 08:20:06 -0700 (PDT)
X-Received: by 2002:a17:906:b2c1:: with SMTP id cf1mr8541748ejb.135.1592407206291;
        Wed, 17 Jun 2020 08:20:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592407206; cv=none;
        d=google.com; s=arc-20160816;
        b=kCTvyP/XKG6BvLmyzNL8x+W/CoNY9a0pN3aZsX0o00QR+fl7iEZ5wCLgU/sHZ16yTD
         ixKweiifJIjDGIr0IA1UaRrOiXovNZP4ge1Yhqba2uLsONblzfFQPvfblnhXb/Yn7kOc
         5FRdmCxE3UMDWET272nmpHAVxpUkLAskV9yxHnCdBwnjvLeI9kEewFstBYlaD+G1SLVH
         9xpCAqueu1Jh/7rHQkHjfTx8aCIibaCzxMSAgvIVjqOJgLwacBtWO/8ZF+GxRtsRXJqb
         oNyiPfrotrutYiU+DgNc1V0nsFJp21fqgOvcr8DZCq9mKki+1Jk/iEnm+p4ij9Y9iIjF
         r58Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=qQ975hNqevvgdpm9NCP0Rb6tLrxCJzAg5/lXYcYf+h8=;
        b=DUU0gtmqrQQe1f+VSRwM5UrYP/WmQaAV1SXFC6DdSwDUPkgAPzhOTJxvAfRmI0EIZ6
         F8+mZ4Swi77mZGkkZuSjx+7ecsT7GlL46v+pnQE4+ae+XeB3Lnk+cNLyng57RHNVb3mQ
         XtSblNEbpksKj6xd0cWpu6pZY5HSJyIXL7cWBnRL6ytZZILjoyhoNN4KsXB2qgUBEk1v
         4HZFr3fktXEbytsC99FSd6wZSVu0EoQJIo3lTUve/dvl3DjbnHZuVhBt+CfBatXLGnXG
         aqxz6Z4nLfgLXhq+ShfYbLDxaemMfjx8aUc1zc9NKrfs969bUhE32+cj63vnmvJrqwbo
         R4hA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KHJyeHZ1;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id r19si1894eja.1.2020.06.17.08.20.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Jun 2020 08:20:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id y20so2424368wmi.2
        for <kasan-dev@googlegroups.com>; Wed, 17 Jun 2020 08:20:06 -0700 (PDT)
X-Received: by 2002:a1c:5fd4:: with SMTP id t203mr8524133wmb.184.1592407205801;
        Wed, 17 Jun 2020 08:20:05 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id y14sm76303wma.25.2020.06.17.08.20.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Jun 2020 08:20:05 -0700 (PDT)
Date: Wed, 17 Jun 2020 17:19:59 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Mark Rutland <mark.rutland@arm.com>, Borislav Petkov <bp@alien8.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Josh Poimboeuf <jpoimboe@redhat.com>, ndesaulniers@google.com
Subject: Re: [PATCH -tip v3 1/2] kcov: Make runtime functions
 noinstr-compatible
Message-ID: <20200617151959.GB56208@elver.google.com>
References: <CACT4Y+aKVKEp1yoBYSH0ebJxeqKj8TPR9MVtHC1Mh=jgX0ZvLw@mail.gmail.com>
 <20200612114900.GA187027@google.com>
 <CACT4Y+bBtCbEk2tg60gn5bgfBjARQFBgtqkQg8VnLLg5JwyL5g@mail.gmail.com>
 <CANpmjNM+Tcn40MsfFKvKxNTtev-TXDsosN+z9ATL8hVJdK1yug@mail.gmail.com>
 <20200615142949.GT2531@hirez.programming.kicks-ass.net>
 <20200615145336.GA220132@google.com>
 <20200615150327.GW2531@hirez.programming.kicks-ass.net>
 <20200615152056.GF2554@hirez.programming.kicks-ass.net>
 <20200617143208.GA56208@elver.google.com>
 <20200617144949.GA576905@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200617144949.GA576905@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.13.2 (2019-12-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=KHJyeHZ1;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as
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

On Wed, Jun 17, 2020 at 04:49PM +0200, Peter Zijlstra wrote:
> On Wed, Jun 17, 2020 at 04:32:08PM +0200, Marco Elver wrote:
> > On Mon, Jun 15, 2020 at 05:20PM +0200, Peter Zijlstra wrote:
> > > On Mon, Jun 15, 2020 at 05:03:27PM +0200, Peter Zijlstra wrote:
> > > 
> > > > Yes, I think so. x86_64 needs lib/memcpy_64.S in .noinstr.text then. For
> > > > i386 it's an __always_inline inline-asm thing.
> > > 
> > > Bah, I tried writing it without memcpy, but clang inserts memcpy anyway
> > > :/
> > 
> > Hmm, __builtin_memcpy() won't help either.
> > 
> > Turns out, Clang 11 got __builtin_memcpy_inline(): https://reviews.llvm.org/D73543
> > 
> > The below works, no more crash on either KASAN or KCSAN with Clang. We
> > can test if we have it with __has_feature(__builtin_memcpy_inline)
> > (although that's currently not working as expected, trying to fix :-/).
> > 
> > Would a memcpy_inline() be generally useful? It's not just Clang but
> > also GCC that isn't entirely upfront about which memcpy is inlined and
> > which isn't. If the compiler has __builtin_memcpy_inline(), we can use
> > it, otherwise the arch likely has to provide the implementation.
> > 
> > Thoughts?
> 
> I had the below, except of course that yields another objtool
> complaint, and I was still looking at that.
> 
> Does GCC (8, as per the new KASAN thing) have that
> __builtin_memcpy_inline() ?

No, sadly it doesn't. Only Clang 11. :-/

But using a call to __memcpy() somehow breaks with Clang+KCSAN. Yet,
it's not the memcpy that BUGs, but once again check_preemption_disabled
(which is noinstr!). Just adding calls anywhere here seems to results in
unpredictable behaviour. Are we running out of stack space?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200617151959.GB56208%40elver.google.com.
