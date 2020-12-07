Return-Path: <kasan-dev+bncBCMIZB7QWENRBNOEXD7AKGQEM5MTK5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2506A2D10A6
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 13:38:15 +0100 (CET)
Received: by mail-qk1-x73f.google.com with SMTP id c25sf1433006qko.19
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 04:38:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607344694; cv=pass;
        d=google.com; s=arc-20160816;
        b=MKwEBRc6BsoM8m+hSWhPveH4dYi2hHAYOyhSzvTMAKii7V3Oyo9O4Znb3sGVC7NXjn
         OGQZ5fB5gH7xuLbqn/aC+NlRLJGZO/Xx8eIbUPhyaxyPJBoP5VJDTHJENfubBdTvS0KB
         XpDnz88Xz2FuW5ArZSdNeRcgXq4fqfjHmEeLxcs9Ul8xiMhKuAEPWVRI5gBAf+PD/yml
         9wcWoVsOK/i3aAdEiDEQob6RngV+nhjlwZeu90euSwc4ajkCSW3ylrIAIUvohvX3rgX1
         qwCabmNK5sUweKFmGX/DB6FbVf1QqGnQbryaCGOGSxMgWpWXeXy45fzNKiVPXv0S4r9v
         hQfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=FRcJZ2BAoV4a7xT8NhuK04EF+rcFtHobXj6SuEDqVdw=;
        b=f8Ql4sMEThlr1GrgZqbYM4+cpy/Z6AKhozAbVr3qX2ERlJ62pbqs4+eG6wI/lEZS6q
         8xNAreLjpIoJoLe1I2JoScfun6qbYKZDYeUBlX4Xb7byEiKIE1FMW57noGrEOgD1Gqw6
         3X9RlmhIAL/r93GjD8I5+zLbYmUvtUnL2UOADA3LCIP8R0M9pJER2WjUy7+IXrvnxUV6
         k72hLHeWutCd2juisTJXK60hSohZ06JPCq7Lux0WigDbO2e30AZQzz+q44u++4p7li7h
         vAdXDQMZIojP1TMWVbZKQ1u7FiYQTJx3YtgKKz+X5sY5DneJ8CH+5or4l0GGE4uEdyw2
         SDbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lnpAQpGw;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FRcJZ2BAoV4a7xT8NhuK04EF+rcFtHobXj6SuEDqVdw=;
        b=pJ+7WCCtxQDMCKKN23VVt+acoBPAORHoRLEi+2QM5R/CmnLZfqdV9jYYxs9EaLDy2l
         sfI3Drh8hTELhn4LNopnUECbp3ZUNcyqmkVbDlQ1YCgXW0PNNDYNCqzmNue+EguTCQoA
         wXImBadPMWAWcX/hwPrs9QYZodIdoNquKMNP8nkJMbZZ+vTg61GrSe+m5a7WVXkLs9Lg
         HKnFBjLSzBBjDjo9GWk7Sr+aH44SB41DeOX+iprHsgqMLY/pLWRxBL4lH8wFjhSiS5d8
         I1OOQwZapBzNBVzHd4kF9I5iHddUkvlw0zG+BM7sm/Ik6JJjnKSdSLbuteppJxxqYhJF
         r8bA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FRcJZ2BAoV4a7xT8NhuK04EF+rcFtHobXj6SuEDqVdw=;
        b=t+eECf5LWg7jdzXFf0FyhrxuMC4FSZjuu0ekZUsAwuPnv7mcGXLkq4/eQ5pyxkM2cb
         rvHvLBUXlgLARHmBCPFnJbvVfv4hrxRjYEzeIF3yU2DWZjDsQNg917HrMP5JzyzxCKew
         jzLe3Kx1xbIWzbIrYC9kflV5ggKDJLgCwQV30oKUqjs//5PGZaDyQdQjhv+zv3bdi14u
         5rN3J/oO0ytNuGfqsfk/UvTESN7+W6lcPhxX3w7vBjz3ySrDppOU/qHzQFQNrW3f4jR6
         1HgjSPD4dabV3Lht1YGDXg94jp9DKid/c3spTpnmOY40BfmT4mq6J2RyiU5o8NH9rccM
         eS1Q==
X-Gm-Message-State: AOAM532yYCXOM+cifM3LEf7A8nl+p206Gw0NdOM3oY5bDP/nfCqy7+2e
	2uiko74LszkiPwC5Ky/USpk=
X-Google-Smtp-Source: ABdhPJzeGmoeUe862CTi/aNRp8b+b8CBlhQGjdZ1YmOs2nlUKdQZarC81ZzqlS40zYzZ/+soUyJ3CA==
X-Received: by 2002:ad4:4ee7:: with SMTP id dv7mr21045315qvb.43.1607344693847;
        Mon, 07 Dec 2020 04:38:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:18c:: with SMTP id q12ls1319487qvr.5.gmail; Mon, 07
 Dec 2020 04:38:13 -0800 (PST)
X-Received: by 2002:a0c:fa4f:: with SMTP id k15mr20754799qvo.62.1607344693403;
        Mon, 07 Dec 2020 04:38:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607344693; cv=none;
        d=google.com; s=arc-20160816;
        b=Zw3B/ZaxJhJtRyxnQSFCGzxB5VT+vvLOpGcOSRqsPBZP051TPqUrwZEvk4pnXgzSi6
         Vp65+4cxOWgcTXoyNKnwG7XFTF7XRoYQu9gChHCp9c206iSOushRzf2H/klv/XmI9OVd
         tdlsvXCGRDs9CGhBmJXW6ETsyPkqnKgyM7ziv0fNupnfyFZ/NCVMeATLoFGkd+nf8TR2
         8UxWAyEBSoNqlN2pgHszfyTzMgZPeWU9bcZu04QjqUUbhYjgX+IXaCM3owkphtE8xF+u
         UWjMY7RlnYKHbSBCkRzAsRbBrwSM3hgzOEt97cpwjwpGD8orr3rPW3U2QqIN0muCGr43
         k/0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+PTUJT/idtBQgSL9lEX0jZu/szKSBgzCqPF6wc7xp2Q=;
        b=Uw2vCgArhzQrggr0EIIAOT085tbie3uMh3FfWRqpUANAPxNYtiKd6z/Z6O9Rq5e9BN
         NLiKJAIgGHAarIKKAfYKMyYfhSOyZnGlGyrhiuHcT/7lg0T4vtzwN2/KMrB6Pa7rfAbc
         zasy9i+0nk9MHLilAo+j9e7/F+QsB/pNtb1/JcNLg3vcOu2fozjsWemwlgHPI1AaevBL
         RiD7Q5/eWf1ghoEVLprLRM7j/FnVeP761FHU74RuHbis7gWhTRVe0m+ih6RxEPweGKsS
         Q3v1fULFnM4VdjPuA+IxciPytA9wAlloT0jcyMrGpT41n6Ho11RrS5sQb0TlDHFWAiM4
         fM5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lnpAQpGw;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf43.google.com (mail-qv1-xf43.google.com. [2607:f8b0:4864:20::f43])
        by gmr-mx.google.com with ESMTPS id g2si787008qko.5.2020.12.07.04.38.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Dec 2020 04:38:13 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) client-ip=2607:f8b0:4864:20::f43;
Received: by mail-qv1-xf43.google.com with SMTP id a13so1290029qvv.0
        for <kasan-dev@googlegroups.com>; Mon, 07 Dec 2020 04:38:13 -0800 (PST)
X-Received: by 2002:a0c:b20d:: with SMTP id x13mr16917256qvd.18.1607344692881;
 Mon, 07 Dec 2020 04:38:12 -0800 (PST)
MIME-Version: 1.0
References: <20201204210000.660293c6@canb.auug.org.au> <20201204211923.a88aa12dc06b61780282dd1b@linux-foundation.org>
 <CACT4Y+bYVC=r+bPF7MziOZpJCYqrUj7CFt47Z5PSWjohZLYm+w@mail.gmail.com>
In-Reply-To: <CACT4Y+bYVC=r+bPF7MziOZpJCYqrUj7CFt47Z5PSWjohZLYm+w@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Dec 2020 13:38:01 +0100
Message-ID: <CACT4Y+bPPSQ1OgZ1NmUckOO2=07RE3C=deW6BpF0cOR9wnJsoA@mail.gmail.com>
Subject: Re: linux-next: build warning after merge of the akpm tree
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Stephen Rothwell <sfr@canb.auug.org.au>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	Linux Next Mailing List <linux-next@vger.kernel.org>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Kees Cook <keescook@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lnpAQpGw;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, Dec 7, 2020 at 1:08 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > Hi all,
> > >
> > > After merging the akpm tree, today's linux-next build (powerpc
> > > allyesconfig) produced warnings like this:
> > >
> > > kernel/kcov.c:296:14: warning: conflicting types for built-in function '__sanitizer_cov_trace_switch'; expected 'void(long unsigned int,  void *)' [-Wbuiltin-declaration-mismatch]
> > >   296 | void notrace __sanitizer_cov_trace_switch(u64 val, u64 *cases)
> > >       |              ^~~~~~~~~~~~~~~~~~~~~~~~~~~~
> >
> > Odd.  clang wants that signature, according to
> > https://clang.llvm.org/docs/SanitizerCoverage.html.  But gcc seems to
> > want a different signature.  Beats me - best I can do is to cc various
> > likely culprits ;)
> >
> > Which gcc version?  Did you recently update gcc?
> >
> > > ld: warning: orphan section `.data..Lubsan_data177' from `arch/powerpc/oprofile/op_model_pa6t.o' being placed in section `.data..Lubsan_data177'
> > >
> > > (lots of these latter ones)
> > >
> > > I don't know what produced these, but it is in the akpm-current or
> > > akpm trees.
>
> I can reproduce this in x86_64 build as well but only if I enable
> UBSAN as well. There were some recent UBSAN changes by Kees, so maybe
> that's what affected the warning.
> Though, the warning itself looks legit and unrelated to UBSAN. In
> fact, if the compiler expects long and we accept u64, it may be broken
> on 32-bit arches...

No, I think it works, the argument should be uint64.

I think both gcc and clang signatures are correct and both want
uint64_t. The question is just how uint64_t is defined :) The old
printf joke that one can't write portable format specifier for
uint64_t.

What I know so far:
clang 11 does not produce this warning even with obviously wrong
signatures (e.g. short).
I wasn't able to trigger it with gcc on 32-bits at all. KCOV is not
supported on i386 and on arm I got no warnings even with obviously
wrong signatures (e.g. short).
Using "(unsigned long val, void *cases)" fixes the warning on x86_64.

I am still puzzled why gcc considers this as a builtin because we
don't enable -fsanitizer-coverage on this file. I am also puzzled how
UBSAN affects things.

We could change the signature to long, but it feels wrong/dangerous
because the variable should really be 64-bits (long is broken on
32-bits).
Or we could introduce a typedef that is long on 64-bits and 'long
long' on 32-bits.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbPPSQ1OgZ1NmUckOO2%3D07RE3C%3DdeW6BpF0cOR9wnJsoA%40mail.gmail.com.
