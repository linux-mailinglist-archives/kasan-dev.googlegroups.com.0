Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTH2VCPQMGQEIOLZLSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5844D69472C
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 14:38:22 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id m10-20020a170902f64a00b0019a68e484e1sf6247682plg.14
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 05:38:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676295501; cv=pass;
        d=google.com; s=arc-20160816;
        b=QEnfmA2tb5PaZkEgTCXEXrEjdT5jAUZyay1QCQVXCFLus4kS+UiYG6Hv/X/LtZU533
         SQvhY2q4pGrJaUup5FYQLsP+ebDtDIvKisdEA6NM4JNZJK7HFCV/LQNXsVyb0S3FS0cx
         7EbzgbuqXlmqzasdP+DQ3dholOw8jIa8/20KBQQInw/Vcfp7+fclnffpLEOEq7y4+Jn4
         6mWLZPYcplHlveVHsc4q97DcGIlqxLsKv68HjRXcauVe/0/T/5H5f7utBo7GLnNaTQsR
         2L/wGfUu5WexCJnlTinPlBtv5TljHNH+/xr0wsIL3MRB9rJ2jOggnlEvLoW3gjxQG4Lk
         hvnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5vEy6GC/x82oeX0CqUyMI26ueMJPOsvaokPqsISf8u4=;
        b=JhrWOfG5BwuoYeHJ6KgzlEFe0KwLLfb07KPhgWwQPcpPnmIXtakGE8OKDPCCy2mqJn
         XxccDdGjNohrBLOMmPRHUl3c6/6GxDJZHbsWT4VhTqW3PJPW6QuebNLE1eIJ+X07w3LF
         G8I9gg9KcX7QnX9QN78Vx6knxFdGBXQU79NRVxS3MnPdMr8+TyKbnr8TTay0+y+jxxp+
         mF5of+8wyNasumfLR4ZnpK54WP4AX++FPUnxsdHPm2LeHB3XvbkaqsGvqzEn70iynIni
         +acvdRqBAK0gJhhs+OAKnWHGhELer+BEGqOfxH7UK69xilDeKhtOCloCuVlsWcLg1whD
         Z7ug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HxTUETCU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1676295501;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5vEy6GC/x82oeX0CqUyMI26ueMJPOsvaokPqsISf8u4=;
        b=RS7DVxuAnNu/v88Nulo6e3zilcfJt505y1emko51O52y5uFRSvdr88I+YzP/MIi5lx
         6bHHkPg+g9AWeMOGt8TMD0FIXXGjpCQixSlcEUg9xleRNZNY3tfN/TXlIILeQnHWENJa
         fwG9CyZON3tmZrauQqqOHeed79GjtZ/58oZlA+nv/6m0B64N5bZ/Xn7dWm1T41pcz5X8
         wX+45XlauolikofYcvpr8UPGX3CFWej/fG4LwIzro8QjQAb9gijaAG4My8B7Ynz0tfWD
         uevFVWpCElQ7SPIsUU1PSCv9C2+Zs6ahood6uN5eO0os1QCeGwXSwbceU3s6wvEtxPSY
         oYwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1676295501;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=5vEy6GC/x82oeX0CqUyMI26ueMJPOsvaokPqsISf8u4=;
        b=B7xOcLbnSkoD10o9VB917vZhuJS7j9ai3NYqiJ+l6qSaXO4u4x0wYX0USoD6NULGlQ
         8YFu9gpmIYGiLfeFvVGwSwSezIN1fPe2DxoA1fiIxTNOa4ibh74MZ+xE+lwQdIC4Bs4j
         FYNcpAKu60FQ1JzBZDuKXc6NZ1Egfmsl3tD4RxFOJcxCeXShGsyr/rgrwW3edLCeXiqc
         6XFPwRkcmXsbcUw52jBbaOE/jRtNP0ESBtmCfzBZuUcFNbv3gwYR2eTAj+yAx8h8f4QR
         wECHUAuGHSz2k7JXR7C4WmMfv7jLWCZ6EWlNdjfz7xxx14BRbUXX3W0TfGL3DJnE0XqE
         mmOQ==
X-Gm-Message-State: AO0yUKWLb+yk7PH7OA9Y9rosVuk3VylLMobBe4IyVq8SBjYBHNF7I4kZ
	oBst24JQwdfaAy1GcDKkwg8=
X-Google-Smtp-Source: AK7set+8AbTXUo0CX0hUhJj/0OUe2NPrt61JdDVsZLJx6drkTJrJSEqcD+tQo6FJrZDyVtZ7xbcb7w==
X-Received: by 2002:aa7:9ec5:0:b0:5a8:beb3:d561 with SMTP id r5-20020aa79ec5000000b005a8beb3d561mr449401pfq.17.1676295500814;
        Mon, 13 Feb 2023 05:38:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ebc4:b0:19a:a6bf:cc9c with SMTP id
 p4-20020a170902ebc400b0019aa6bfcc9cls1972775plg.4.-pod-prod-gmail; Mon, 13
 Feb 2023 05:38:20 -0800 (PST)
X-Received: by 2002:a17:90b:1c10:b0:232:db7b:5698 with SMTP id oc16-20020a17090b1c1000b00232db7b5698mr15591662pjb.15.1676295500026;
        Mon, 13 Feb 2023 05:38:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676295500; cv=none;
        d=google.com; s=arc-20160816;
        b=gotg3xA2c4NqQ/f1LZjK1LSK1rXkESH+jGFw9r+xEffxJo4vsH6ZPhrgr3UlaPchbk
         4Xl95MEe5gmJgzhejh3wYKEUKZvrHuBo2QCNmDt+ngbl1v5Dw47v0ls0DkVKYIjzwwWC
         uIe6Lwg6XrtpNm9e0TDGrfFvxANTMjJlKYRwIeex69Z86kUFewUTK/2FeV67jQ41gJ7y
         qyUgXkJ+TtMdBuJiyMfq2ho7yhZxTNuHSATNH0Aatp/VoHX8h3BcMFTWjwjUP8TWhdJG
         Xdc8AfOh6j3sK7ArwGwBxGDUABcFvNxt50h1bUDF8CpsKZ9lRO8ukU7tZQ9ZhqlLeSUE
         3sww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QiocV00En5D5cLXBZHTCzW16cVc0Pj8et9mT/H0L18Y=;
        b=SN4LcFRzGHXTskmOSiXCj3zHVHtnh923+Zni0rJd4jzNpX7V23u83oRGuvoWSUJidU
         AJeyKAePrxgItTQaVwNWPP2dFlVnI3u5zkIGDAbdlNh4CPAh9oE17jMbhwlvm6WW0+7Y
         /dslpFc9OPQa+68W6otge+4dn4xbaf+2/CMIsbXqVw1rt3VzrgipwJ8tLR6UzXNukp+h
         N+XJK4gsjQD/s3q6HLjr7w0a3gV6T4JBa1pUpzaundzTnJNgss3vIq2MCQebNZt7cMoW
         ZWKqScASD++S0pe04IuYswCD4BBeV1RCeKy+sUJupe1NnjbURiOq8LUaRHcKGWU+ER4I
         YapA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HxTUETCU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa36.google.com (mail-vk1-xa36.google.com. [2607:f8b0:4864:20::a36])
        by gmr-mx.google.com with ESMTPS id kb13-20020a17090ae7cd00b002340b20225asi141842pjb.1.2023.02.13.05.38.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Feb 2023 05:38:20 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a36 as permitted sender) client-ip=2607:f8b0:4864:20::a36;
Received: by mail-vk1-xa36.google.com with SMTP id n22so2320334vkm.11
        for <kasan-dev@googlegroups.com>; Mon, 13 Feb 2023 05:38:19 -0800 (PST)
X-Received: by 2002:a1f:2bd0:0:b0:3e8:a035:4860 with SMTP id
 r199-20020a1f2bd0000000b003e8a0354860mr4437186vkr.7.1676295499037; Mon, 13
 Feb 2023 05:38:19 -0800 (PST)
MIME-Version: 1.0
References: <20230208184203.2260394-1-elver@google.com> <Y+aaDP32wrsd8GZq@tucnak>
 <CANpmjNO3w9h=QLQ9NRf0QZoR86S7aqJrnAEQ3i2L0L3axALzmw@mail.gmail.com>
 <Y+oYlD0IH8zwEgqp@tucnak> <Y+ouq8ooI7UH4cL+@hirez.programming.kicks-ass.net>
In-Reply-To: <Y+ouq8ooI7UH4cL+@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 13 Feb 2023 14:37:42 +0100
Message-ID: <CANpmjNNxX-YpRkEHYjpZGVDw=9nRpyHbGRz6jCV14=bxtsXENg@mail.gmail.com>
Subject: Re: [PATCH -tip] kasan: Emit different calls for instrumentable memintrinsics
To: Peter Zijlstra <peterz@infradead.org>
Cc: Jakub Jelinek <jakub@redhat.com>, Masahiro Yamada <masahiroy@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Nicolas Schier <nicolas@fjasle.eu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Ingo Molnar <mingo@kernel.org>, 
	Tony Lindgren <tony@atomide.com>, Ulf Hansson <ulf.hansson@linaro.org>, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=HxTUETCU;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a36 as
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

On Mon, 13 Feb 2023 at 13:36, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Mon, Feb 13, 2023 at 12:01:40PM +0100, Jakub Jelinek wrote:
>
> > The current gcc behavior is that operations like aggregate copies, or
> > clearing which might or might not need memcpy/memset/memmove under the hood
> > later are asan instrumented before the operation (in order not to limit the
> > choices on how it will be expanded), uses of builtins (__builtin_ prefixed
> > or not) are also instrumented before the calls unless they are one of the
> > calls that is recognized as always instrumented.  None for hwasan,
> > for asan:
> > index, memchr, memcmp, memcpy, memmove, memset, strcasecmp, strcat, strchr,
> > strcmp, strcpy, strdup, strlen, strncasecmp, strncat, strncmp, strcspn,
> > strpbrk, strspn, strstr, strncpy
> > and for those builtins gcc disables inline expansion and enforces a library
> > call (but until the expansion they are treated in optimizations like normal
> > builtins and so could be say DCEd, or their aliasing behavior is considered
> > etc.).  kasan behaves the same I think.
> >
> > Now, I think libasan only has __asan_ prefixed
> > __asan_memmove, __asan_memset and __asan_memcpy, nothing else, so most of
> > the calls from the above list even can't be prefixed.

Correct, right now libasan only does memmove, memset, and memcpy. I
don't think it'll ever do more, at least not in the near future.

> > So, do you want for --param asan-kernel-mem-intrinsic-prefix=1 to __asan_
> > prefix just memcpy/memmove/memset and nothing else?

Yes.

> > Is it ok to emit
> > memcpy/memset/memmove from aggregate operations which are instrumented
> > already at the caller (and similarly is it ok to handle those operations
> > inline)?

Yes, I think that's fair.

> I'm thinking it is trivial to add more __asan prefixed functions as
> needed, while trying to untangle the trainwreck created by assuming the
> normal functions are instrumented is much more work.

For the kernel param, I'd only do memcpy/memmove/memset, as those are
the most brittle ones. The string functions are instrumented on most
architectures through lib/string.c being instrumented.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNxX-YpRkEHYjpZGVDw%3D9nRpyHbGRz6jCV14%3DbxtsXENg%40mail.gmail.com.
