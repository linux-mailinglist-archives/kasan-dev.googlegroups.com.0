Return-Path: <kasan-dev+bncBCMIZB7QWENRB7755D5AKGQEIKJJOMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 39DAB264883
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 16:58:09 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id bg5sf1119113plb.18
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 07:58:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599749888; cv=pass;
        d=google.com; s=arc-20160816;
        b=pgzMBmPsHHgF1lwQvMtrw4FgleLKtDFk3UnAOYa7Bvzda3Sz1gAHxQCAW2WLPX22AQ
         ZXXPd+ghsfBxPskqyAjrOJ7EYor6PQo+MWLuNorCj9raT00E4i5dS1GzV44DmRKhiHJs
         8Ks06xCrlQN/6nXDQnKTOzY6tZU5hjMza6sxZ4QyR3dgYgkHdJN7kRveq/7jsr7eHzyb
         +p5S68Tu+bqID1a/2I0gFIygtVk9p2xXz2vnoT3ono039uFiUltDkt291vTXrWClPLVG
         fyLSJUFlJcXcGfRoQwez7bcImG1DeOYL+o7fcYVVqZJVobqg0LVCQ60KDXsTrE8h46DJ
         x6TA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Q+jQljrgE0IfBgRj/bbbJYtRemc8NfIGKNdmio03aSc=;
        b=RLCUTQL4xZafEptU/6ic6jYMcYcAAVTLxWwvdaJ0tL/kbl/GALbFBmpVxgBjWKWYZA
         hO0wzBA8dtBeMi/apHcD1xyBEvt9rTEUz9RqPGEE9kv075uAEFnOqsrcnvqM0auinaXh
         YgbOCwixkz+LByUY1tDa1KWO5QLYCmkJYamANki+lMQdmIUOWsXKm68t20xMTPyUCWHC
         e/TZFWSl164gy15Oon0JDm0QjKdikOcaDbxbU645iMMUl4qAI1E9JeMTEeqPNLjpyGNF
         NE5Gzf3h4FCOFOphO5Qyp1EsIXeMiSxarUoF0GkDIvZYhXMQNUKyQCzG2auVzwRUbZQf
         YvcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uBOlTGMa;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q+jQljrgE0IfBgRj/bbbJYtRemc8NfIGKNdmio03aSc=;
        b=YwwYY/nUAYolJLLnGwr6n+B7+jZSj7n6ZDlRfN7ANUHFUdHcda0LYrtbthm/o+e74e
         0a31+nki9Jzvlm4RnViP66371fXfAgsrGFPdiboj8qCXXW6pMoRHXHcWTmouWc+jB7CQ
         89trm6BrnXfA4rbmOqdQGPIsj3aZLJJX2CjOUvJR923AmRMyr7wVW2BlE92AdiyLlS7B
         aUxZqhTsqnp3Jv4fm7KQBnb4xSONctvD+qSvCSwd2OnWpXGvozuNiU5fXKORZ7n8c5RP
         y206h1mFb4vKaFmEMGgec8vfPDex31Zwm5UGt81sDof30HtObsg+RqzPJumOeG8BMxIm
         LcrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q+jQljrgE0IfBgRj/bbbJYtRemc8NfIGKNdmio03aSc=;
        b=L/JIl9irEwPEXBG07D74DVzpxooSGLBrLcpD7mI43GjVnobkuO7/hfM/grDPcvpQpD
         nL2jQvEFDRPHCa4lmYLm5my6WbBwttzSYJ0GBCEhp/7vWN5RnuTRFkRNQdJFmajOkPcr
         h4nJgHFcZ5vJ54hMGJGWL7YZnQfJ7UZ5K6DCIb6gK9BmX0OAi0QIZvLbiEFFXM3DezEi
         ggFnPHipie0hZxE2JoVOt3tZs5NewYMsMPfkcPYJJlEg10PksTElUeXov7b03QgrQ6Zx
         hYd5Sbvk2SC76jLHQ12K2Pv85aBsP9CUnjsrJKDH+FC7KEgrxZJvC3OYUs3vgAIK55Hq
         U9ag==
X-Gm-Message-State: AOAM530u8vEjaf69CIaR0gZUsIniT+3SGlisDZ2awFvxjpKn0ASQW9R2
	BiChELj11sPoT4xoyu/PlTk=
X-Google-Smtp-Source: ABdhPJxRocgbDnaHoRz4X20FF2uBCt5Aein0UVD4D+hfnkw9j3ZpBsERUFmlzlBi+Gl0hOp5GwfD2Q==
X-Received: by 2002:a17:90b:208:: with SMTP id fy8mr305352pjb.153.1599749887879;
        Thu, 10 Sep 2020 07:58:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d704:: with SMTP id y4ls1521569pju.3.canary-gmail;
 Thu, 10 Sep 2020 07:58:07 -0700 (PDT)
X-Received: by 2002:a17:902:d201:b029:d0:cbe1:e73e with SMTP id t1-20020a170902d201b02900d0cbe1e73emr6165690ply.25.1599749887247;
        Thu, 10 Sep 2020 07:58:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599749887; cv=none;
        d=google.com; s=arc-20160816;
        b=vCmCHO798nHkEZy2eqj3tNakHEZdtoakO15Daad1acrJbzvoHTXHDlhAPDAWrGh2oa
         /j8+CTstS1eUuvRP0Tbr78NnPweyvl7nS1q4GhSnxrtk2kANA5hLQP4ePwp9nFdzYocv
         Tai50MvWo+eycKwuJzhS4aEzPPnRGX9gwuM+naYhhsGvFEOHoF0ltinI5oUm6wviTkdm
         f4IN7Fwe/QwBmCb/OQru2MOlnoW9nTEdi3+Bl3EKCyk9iLagxjI8W+S4J+dW8ukVJ5hL
         zxQqAhds2qoGeQMxgJWifAflK+AU1PAulUuzprPUsLK/ooHf71p3/oJ5gfOaq8LDylIB
         CmdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=psWYZztgZCmOanZbN0KVSKVg8aC+fzD9jcmxhuC+NNI=;
        b=UjB8trtA+hS00K7x3Ih6f+DuqnWfF88Tt2eaaon4L5aO4V0GnIUg/1mS0Ce0kkEFCM
         HwuTxVDdKkMIrExc2hgJ1qdyc5xXNftlDhSiiOXomyKPjX0CYw/XdnMz3onhdPbE6uWA
         Eyq2KxTiRW80qJGhAniFtJ3QBreXb8NOYiXwCv9QoxeKw//+Xt7rDe0GynJgJeRdwoHz
         lYe3GAvWfq8/R1zmTer13m6rP+DrMOrb8cTqeusQIpexWR2xfmUhmSX3cL5tizAhJKNe
         KS75vEpa2QaxUOqD9ECoMBieGm2BZ9uW+sGYHDD8Hgy4V9+DXUYn996rF/yWhRp27/zp
         hTng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uBOlTGMa;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id a199si582048pfd.1.2020.09.10.07.58.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Sep 2020 07:58:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id p65so5072159qtd.2
        for <kasan-dev@googlegroups.com>; Thu, 10 Sep 2020 07:58:07 -0700 (PDT)
X-Received: by 2002:ac8:5215:: with SMTP id r21mr8150267qtn.257.1599749886066;
 Thu, 10 Sep 2020 07:58:06 -0700 (PDT)
MIME-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com> <20200907134055.2878499-2-elver@google.com>
In-Reply-To: <20200907134055.2878499-2-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 10 Sep 2020 16:57:54 +0200
Message-ID: <CACT4Y+aBpeQYOWGrCoaJ=HAa0BsSekyL88kcLBTGwc--C+Ch0w@mail.gmail.com>
Subject: Re: [PATCH RFC 01/10] mm: add Kernel Electric-Fence infrastructure
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Mark Rutland <mark.rutland@arm.com>, Pekka Enberg <penberg@kernel.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@redhat.com>, 
	Jann Horn <jannh@google.com>, Jonathan Corbet <corbet@lwn.net>, Kees Cook <keescook@chromium.org>, 
	Peter Zijlstra <peterz@infradead.org>, Qian Cai <cai@lca.pw>, Thomas Gleixner <tglx@linutronix.de>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uBOlTGMa;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844
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

On Mon, Sep 7, 2020 at 3:41 PM Marco Elver <elver@google.com> wrote:
> +config KFENCE_NUM_OBJECTS
> +       int "Number of guarded objects available"
> +       default 255
> +       range 1 65535
> +       help
> +         The number of guarded objects available. For each KFENCE object, 2
> +         pages are required; with one containing the object and two adjacent
> +         ones used as guard pages.

Hi Marco,

Wonder if you tested build/boot with KFENCE_NUM_OBJECTS=65535? Can a
compiler create such a large object?


> +config KFENCE_FAULT_INJECTION
> +       int "Fault injection for stress testing"
> +       default 0
> +       depends on EXPERT
> +       help
> +         The inverse probability with which to randomly protect KFENCE object
> +         pages, resulting in spurious use-after-frees. The main purpose of
> +         this option is to stress-test KFENCE with concurrent error reports
> +         and allocations/frees. A value of 0 disables fault injection.

I would name this differently. "FAULT_INJECTION" is already taken for
a different thing, so it's a bit confusing.
KFENCE_DEBUG_SOMETHING may be a better name.
It would also be good to make it very clear in the short description
that this is for testing of KFENCE itself. When I configure syzbot I
routinely can't figure out if various DEBUG configs detect user
errors, or enable additional unit tests, or something else.
Maybe it should depend on DEBUG_KERNEL as well?

> +/*
> + * Get the canary byte pattern for @addr. Use a pattern that varies based on the
> + * lower 3 bits of the address, to detect memory corruptions with higher
> + * probability, where similar constants are used.
> + */
> +#define KFENCE_CANARY_PATTERN(addr) ((u8)0xaa ^ (u8)((unsigned long)addr & 0x7))

(addr) in macro body

> +       seq_con_printf(seq,
> +                      "kfence-#%zd [0x" PTR_FMT "-0x" PTR_FMT

PTR_FMT is only used in this file, should it be declared in report.c?

Please post example reports somewhere. It's hard to figure out all
details of the reporting/formatting.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaBpeQYOWGrCoaJ%3DHAa0BsSekyL88kcLBTGwc--C%2BCh0w%40mail.gmail.com.
