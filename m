Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAGLXD7AKGQERFP2HDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BBE62D1107
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 13:52:17 +0100 (CET)
Received: by mail-io1-xd3e.google.com with SMTP id h206sf11715068iof.18
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 04:52:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607345536; cv=pass;
        d=google.com; s=arc-20160816;
        b=zyVXRtaz2poG7MKurlhnMijKxNtQnuGoyMHtRMXKM9gIbx2P+tg2zVjJ3FgTbOfRZn
         2iCMneMuwQVSltHUl5dqBJMtcFkOqfFqQ1cnLX4yFePOSgsPT7n581Vr/VPXQ5EU0xQJ
         L2SDPmzbml+T1/OCYDXzuiYyAm0cNnzfhg//oqHMPRQuoWgUFyTkxNf5//ZeYtIsq3eG
         JJs0dg13e7FqSpiZJaP76dTJl16FJwL3eMaCiu1oiUdoEIGMzyD1G0P3HqIqcSfLwi1T
         TzDUh9nR/q6QDjJ9vV1Y4WagPXaAQn+W/lssikcM32Kw2YNIHXXLVs7rpOo7yo2/hUf8
         vjqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1nzLwuGJP47ZWVLiWQlzb8GcdhlMQ2whAUJbya7MZ9A=;
        b=IzudMZN2Rqt1zPfFGh/k1QgaqtkuQPhVzzfwCjoES4lyQk83pBgjqEuEb9d1jSpASL
         wdZYITJmiKgcuXn3qxpojhv5a7KQ9jMoQZl8U+AT7YFjL07iFxxowcvEwJI4thmeuS5I
         KhpJeztxZlBgjUtIhVBCUvWXyjuRuP6LE2tqLSErQK+OtiRxoyLDGwSVzsLmmK34Up3G
         av4xGG9U0+H3PmFv/2umy90ZShFZJAdelM/qZMnwTcM6dHWHF85BVwfzcOjagncqPVmX
         qPoLw6ShvNAaeftfIzS+sMQ39VO40UxeLd2LaM8dpK6dIENi1ACvGHbBy0K4bVKmpo5y
         DRnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CuoNQ1ZH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1nzLwuGJP47ZWVLiWQlzb8GcdhlMQ2whAUJbya7MZ9A=;
        b=XgakwPHSuVJH336sCWohpbROBqJH9E4z2ZLnRkHuv4arUep2pZpMWQ+k79uWXTBCVx
         EoCagFMLo/9CX6m3x1dsIyZWKH6dRP9Ccw278IrLzIVXyBb1ejLFTC+EC+t4n/Pjk9Tf
         mq+eTZ2SGAHgrnUR1xuTJkptbiAAOv6/EWiCLCXYk7DDOa6p88YQA9C2Tr6zid1NGS4M
         pbK8BVtbrLb+qJU2FltW4tPQHi9xopRK6gWgY1rD3OOmZFLn4M7UZNhXkqPpkGxbDF+c
         kxUOIIQmOwnaDqwH5D2OdYVwYI+LmcgAgxWI/cXKobBAo+QYyPfxpr7SXtBPbFg5pRhc
         xZxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1nzLwuGJP47ZWVLiWQlzb8GcdhlMQ2whAUJbya7MZ9A=;
        b=ne1K+Q4o9bJwwOsUrF5KlumXM4P6zCa7TGpDQ1YdVrIg6e0SWuY0do9dc1dILsFasb
         zRCMbkUaXmv99LTnYlkWNPKaTZxsa2aR1YZvcd1BOMvfd+Ts44J+pzXrnvVYkEU4Ym9a
         LIMyBLl1e7agqUigx7VUFRItA45vAZAl69Y/4izXrSnQqbk0CHNe9CeTeqFqbGSxVCkw
         WouZLY4R3jFbREJjZeRNnjvByjbT03AST8fu/i0RuyDT1KI/e6aDU46S2Bv8yPBNAbus
         v0CJw2VLwjbtAauZmw3LrJIChyVA7A9+hD4F0jerOqklH/APy10RHyXZF+kZxYAre0gn
         SgVQ==
X-Gm-Message-State: AOAM531iZZr8plpyQUtJFLGgY4DfK8YMxH0qexbYacLslM1NGOR5H2AO
	FA4mJeufQpJBilMfyKYkQtE=
X-Google-Smtp-Source: ABdhPJzVUNu21x1SYtv7Q/hOHlrYRjonUE8c1UnyJcKW/fva7E+S1AxUo9Hq0L7jtWGKRu271UCvLw==
X-Received: by 2002:a92:130e:: with SMTP id 14mr21331897ilt.281.1607345536261;
        Mon, 07 Dec 2020 04:52:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1048:: with SMTP id p8ls4209835ilj.11.gmail; Mon,
 07 Dec 2020 04:52:15 -0800 (PST)
X-Received: by 2002:a05:6e02:1292:: with SMTP id y18mr11147614ilq.284.1607345535805;
        Mon, 07 Dec 2020 04:52:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607345535; cv=none;
        d=google.com; s=arc-20160816;
        b=f2UZlJ+jOM6mGmzt3s3NKWiOOhXQKLpiVZh5nzZDFMTvRsWNBuF/xZpC879E5FYyA8
         k5qkWoRfMNcDjgZvvPaTyjqfH/ZtMSN6QE2Yq0kQBHQnUlwfIFtZfhc8324f0gl42bin
         W6fYDP498ygDPLuC8aKOVFGuVtDBzAUprYAUcfxnPDMFMHRIfYy40YojxJfApVc5CeJo
         HUBNlSjvvvv4kJe11W2slU3wAXOMTfha278o38A+HNT0AJTfxv1ibfoG9pAtLkJzy+IO
         V77iPdhq/il26wHE/5xwp54kk2zJVO5lT8m9dPj3BGaEXi0JCrI7HWDRqLfYLKT7jqDQ
         2yHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EyGMufKhn3rdsN41H0khe/e5DDZRz7d+ODZIwycAubY=;
        b=LMMqsU2p9/8mNWVN4gK3ROWwZHLuuXEahBbhNeGdruyvVvTIjKp9r4Lgm7Qz7JXXKO
         9nYvwG2Z3Zra3ihlxyB9/cy9Ms99CIOTb/8DOM8ZIYpUureO3oH7Lr0MfwnmWA/7xuqp
         NFqCf0qMHbjnbQTR3CfgmmsZZe5n9H6YucVe/QtekCOomhMaT7oGJFJ4hsFx1B90whqF
         JFxW1sTt7U5Irz8uNBXGgGrLYJjskhfUZUCC7E3xThx1heILgDd3RNc78wPyQzEIjQD0
         EUflSesbBFRhCEZ+ZbychOwtv44Rrq/tIV5jcqFzI2U1FSZFPIg+D5rLP4IqIakTin+0
         HonQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CuoNQ1ZH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id q4si730116iog.3.2020.12.07.04.52.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Dec 2020 04:52:15 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id f16so12284401otl.11
        for <kasan-dev@googlegroups.com>; Mon, 07 Dec 2020 04:52:15 -0800 (PST)
X-Received: by 2002:a9d:6199:: with SMTP id g25mr2798381otk.17.1607345535306;
 Mon, 07 Dec 2020 04:52:15 -0800 (PST)
MIME-Version: 1.0
References: <20201204210000.660293c6@canb.auug.org.au> <20201204211923.a88aa12dc06b61780282dd1b@linux-foundation.org>
 <CACT4Y+bYVC=r+bPF7MziOZpJCYqrUj7CFt47Z5PSWjohZLYm+w@mail.gmail.com> <CACT4Y+bPPSQ1OgZ1NmUckOO2=07RE3C=deW6BpF0cOR9wnJsoA@mail.gmail.com>
In-Reply-To: <CACT4Y+bPPSQ1OgZ1NmUckOO2=07RE3C=deW6BpF0cOR9wnJsoA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Dec 2020 13:52:03 +0100
Message-ID: <CANpmjNObNia7mFFJDz6ofG06QOTzad=iU=b_C=E97nV2hB-hng@mail.gmail.com>
Subject: Re: linux-next: build warning after merge of the akpm tree
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Stephen Rothwell <sfr@canb.auug.org.au>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	Linux Next Mailing List <linux-next@vger.kernel.org>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Kees Cook <keescook@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CuoNQ1ZH;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
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

On Mon, 7 Dec 2020 at 13:38, 'Dmitry Vyukov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
> On Mon, Dec 7, 2020 at 1:08 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > > Hi all,
> > > >
> > > > After merging the akpm tree, today's linux-next build (powerpc
> > > > allyesconfig) produced warnings like this:
> > > >
> > > > kernel/kcov.c:296:14: warning: conflicting types for built-in function '__sanitizer_cov_trace_switch'; expected 'void(long unsigned int,  void *)' [-Wbuiltin-declaration-mismatch]
> > > >   296 | void notrace __sanitizer_cov_trace_switch(u64 val, u64 *cases)
> > > >       |              ^~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > >
> > > Odd.  clang wants that signature, according to
> > > https://clang.llvm.org/docs/SanitizerCoverage.html.  But gcc seems to
> > > want a different signature.  Beats me - best I can do is to cc various
> > > likely culprits ;)
> > >
> > > Which gcc version?  Did you recently update gcc?
> > >
> > > > ld: warning: orphan section `.data..Lubsan_data177' from `arch/powerpc/oprofile/op_model_pa6t.o' being placed in section `.data..Lubsan_data177'
> > > >
> > > > (lots of these latter ones)
> > > >
> > > > I don't know what produced these, but it is in the akpm-current or
> > > > akpm trees.
> >
> > I can reproduce this in x86_64 build as well but only if I enable
> > UBSAN as well. There were some recent UBSAN changes by Kees, so maybe
> > that's what affected the warning.
> > Though, the warning itself looks legit and unrelated to UBSAN. In
> > fact, if the compiler expects long and we accept u64, it may be broken
> > on 32-bit arches...
>
> No, I think it works, the argument should be uint64.
>
> I think both gcc and clang signatures are correct and both want
> uint64_t. The question is just how uint64_t is defined :) The old
> printf joke that one can't write portable format specifier for
> uint64_t.
>
> What I know so far:
> clang 11 does not produce this warning even with obviously wrong
> signatures (e.g. short).
> I wasn't able to trigger it with gcc on 32-bits at all. KCOV is not
> supported on i386 and on arm I got no warnings even with obviously
> wrong signatures (e.g. short).
> Using "(unsigned long val, void *cases)" fixes the warning on x86_64.
>
> I am still puzzled why gcc considers this as a builtin because we
> don't enable -fsanitizer-coverage on this file. I am also puzzled how
> UBSAN affects things.

It might be some check-for-builtins check gone wrong if it enables any
one of the sanitizers. That would be confirmed if it works with

UBSAN_SANITIZE_kcov.o := n

> We could change the signature to long, but it feels wrong/dangerous
> because the variable should really be 64-bits (long is broken on
> 32-bits).
> Or we could introduce a typedef that is long on 64-bits and 'long
> long' on 32-bits.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNObNia7mFFJDz6ofG06QOTzad%3DiU%3Db_C%3DE97nV2hB-hng%40mail.gmail.com.
