Return-Path: <kasan-dev+bncBC7OBJGL2MHBBY7D5DTQKGQEJXEOVIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3726438744
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Jun 2019 11:44:04 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id s9sf1354490qtn.14
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Jun 2019 02:44:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559900643; cv=pass;
        d=google.com; s=arc-20160816;
        b=O8LcgcjUn4/vi2sI6UVSX7Jjsmo6pVjtqD1apcsQaRdn1WzFvvOH5vtQdRIgEG6QBV
         K9uWxPB3pq303KvK/FvCYHW6WTCUfo/J+QP4plgDxklW1fHaC1MDDx48jStf78U0SbYk
         M/0epP4Yv2MrmrtLY/UNYAzvwmBPIcLJ9yNtPtmsQKd++MpvHzLLGIri3AjQbHBKTtzU
         uV9FMre71VQ9KGe7VLy6knvHhM+foppa4RCktP7kAUbH6TlEhuUbMFu41g1mlffLTCFr
         bDWd2HXos4ia0z94JIk0jcfFujl0impym1yrzxGx+pT19bz/Nltej1lqbxKA2rOZ7SGD
         BXfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=KOqzq/5kfhx2sIeHnXYzBYJ3kopVz23I7N8SB4/v2RA=;
        b=wGIbR0Yi+/+XRcEdbVf5spLyE/pTn+7YtHkeujKL8+D2YPgJmY4x4UB855Pi2kcayZ
         gJHX9kE+ssDk2aC2b4qQQ13X5iYbOOXEea/goFXjiV/rGDDbxNCbULk+4xdgj/0EMgqW
         Lcqqvvxd5oB6UTHT2CQAN+ywvm9ADxv3pWB8CnuOcXRyuPHvCP1PpAE53bfGMQ+L8L3N
         AknNlufi4eZdI1xQocaSQ9Zxgoy5XnnG3vFePVv+OHwc69IzgpMWrmQtWSu2Li0IP3fX
         HP/vr5WUXhFpuvkoioDlc5d3f9xUWk5sZoYzK77Mif5NrjjXUn4nYrYOXWiECG/m7Mz1
         T3HA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="sSmDgj/n";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KOqzq/5kfhx2sIeHnXYzBYJ3kopVz23I7N8SB4/v2RA=;
        b=CVWcm2SvqP5hMmYYB8op4yq2O2qPxajLlBVLXl63WppfizcsMESvR2fsynN+9zBz3y
         dPIyb04rxd1A3kfQK7c+aA9khCFlLi5lBv3JPE8F/lJ8EPEX8ViL1RIBuquE87ubHppt
         lOJeNLV1unaJQf88CpchEBoVHh4fSMSBlcWHXwGEbLCoJqZN4z/t5lonJzCmdM8DQ384
         Cg9YwtUrG2QrQZ3bikML54QNjI0cloBsmvzvc4OJY2s2E2rOktoB8ItjzR56juKULz4h
         sZMWlnYDZAH/Bn57O3/hnMGZ0BjFD5MIQdhzRQSgjjvEYKGFLK7FuUWwXsK0SCoxO4aX
         BJWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KOqzq/5kfhx2sIeHnXYzBYJ3kopVz23I7N8SB4/v2RA=;
        b=UQnce6MiTVYZorOeavUjd3CcX3yA4jhAwgYU8ZzCsjBNjCDWfALD5HQcjeSLRTGlVo
         uo7/ObKt4GRg+amrPE5wkVnmUDLsBSySuamFgn2/NE7jjR7yH8ByczVouduNRqxK9dUM
         wEwtdY8cRdV3pBN3fII+GxUOJrQUcaVPIWmk3rtirCQ55/eL4BHjv0C9pK+dkINgb3ru
         QmVMUhVn3t8uSW3f0VvHRSb3+ASwj5FA3XYr1CUrJcyf3VXW5qducB5JoVFvhw9/YX/m
         2r8wt7eY15wXCKpoPbVaBMCvKlpveSUiqPBcaNst+yPkA3nAilVNJE5EvouuPQRJnVqM
         3RCQ==
X-Gm-Message-State: APjAAAW7zUQHkNSw2kv/AsbxPwoxKhsVp80c0a8Um5JA2II7tlPReRjU
	us0mfDsz8a3jwkwYtDTdwY4=
X-Google-Smtp-Source: APXvYqzIC2j3uiJdtmS9IZ/qpcl9fFKBJ9qZLyXWi5IKg3cnJOQLvrOJiXqITS5wd9phQ9E5E8XJ8A==
X-Received: by 2002:ac8:1a3c:: with SMTP id v57mr44951526qtj.339.1559900643146;
        Fri, 07 Jun 2019 02:44:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:26ea:: with SMTP id 39ls2496600qtp.11.gmail; Fri, 07 Jun
 2019 02:44:02 -0700 (PDT)
X-Received: by 2002:ac8:d9:: with SMTP id d25mr14162132qtg.29.1559900642910;
        Fri, 07 Jun 2019 02:44:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559900642; cv=none;
        d=google.com; s=arc-20160816;
        b=HkI1wHRRvgfiSAhChu/K2inOHDDGKXKnrkME1r2MQq3Hffb8Z8cSlF1AggfUmOOkKt
         3PYEIEsV/vxHNpOhuEAjmgfcyihn7Cxxb29P6rBpxUnx2qa4eCJrWDCKsyJy+m7Ki4/A
         IKjNOXZLc/cYxjHaqu3DKeKvURntvo0YZcESnpBxOk2rTsuiHtD0R7mFPNYHINBz47F+
         xhdK2wSy2SDzTz8iUSHjUOs65NIpiynIUut+GNbyqyqUsH5eHySW1K3fFh1he11uQFEB
         juqs2j84kBl6wM9Sc+f/vpdOuHafN1fvIti64fqYGvedoo/7JyC8zc01t/jVD8xEqKIN
         GvbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/SDwCL8ynt08bvLIbUkukhDwVZ2Lp8wrEvUT6aIHtho=;
        b=Nzheoj1AQJV7a+tBRGWmeGRjWED3B6tVMcgW1CRPPBFp95pQ5GaUafIgdfbN0Pn8Xm
         NdJJ81WpjQMKqBqNo8HP62AGd3dRSDrwRdPEChMXeAOrGfyZWPqXBewHAgz0U14hHEMR
         tHcugHAmgfSBPKNFQ4xNvHNORezXbV9G4DxpNI8fGh4G5ZQgxGdsXFubsVewsHej7Vny
         8ulygdCDd1YiNSCK+v+guIoU/1hwDyuUW3lEId14lzk4escQa2zVDEVFZFzbIKOVz661
         eBVn3qSrYc/mcg0HESxUd3EDfgIzedxDahEXb4A2Gjxn9tfMoNMa838X6YP5OhaaFlIs
         aztg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="sSmDgj/n";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id w79si64351qka.3.2019.06.07.02.44.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Jun 2019 02:44:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id m202so996755oig.6
        for <kasan-dev@googlegroups.com>; Fri, 07 Jun 2019 02:44:02 -0700 (PDT)
X-Received: by 2002:aca:e044:: with SMTP id x65mr3104140oig.70.1559900642006;
 Fri, 07 Jun 2019 02:44:02 -0700 (PDT)
MIME-Version: 1.0
References: <20190531150828.157832-1-elver@google.com> <20190531150828.157832-3-elver@google.com>
In-Reply-To: <20190531150828.157832-3-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 7 Jun 2019 11:43:50 +0200
Message-ID: <CANpmjNP_-J5dZVtDeHUeDk2TBBkOgoPvGKq42Qd7rezbnFWNGg@mail.gmail.com>
Subject: Re: [PATCH v3 2/3] x86: Use static_cpu_has in uaccess region to avoid instrumentation
To: Peter Zijlstra <peterz@infradead.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	"H. Peter Anvin" <hpa@zytor.com>
Cc: Jonathan Corbet <corbet@lwn.net>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, "the arch/x86 maintainers" <x86@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, linux-arch <linux-arch@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="sSmDgj/n";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
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

Gentle ping.  I would appreciate quick feedback if this approach is reasonable.

Peter: since you suggested that we should not change objtool, did you
have a particular approach in mind that is maybe different from v2 and
v3? Or is this what you were thinking of?

Many thanks!

On Fri, 31 May 2019 at 17:11, Marco Elver <elver@google.com> wrote:
>
> This patch is a pre-requisite for enabling KASAN bitops instrumentation;
> using static_cpu_has instead of boot_cpu_has avoids instrumentation of
> test_bit inside the uaccess region. With instrumentation, the KASAN
> check would otherwise be flagged by objtool.
>
> For consistency, kernel/signal.c was changed to mirror this change,
> however, is never instrumented with KASAN (currently unsupported under
> x86 32bit).
>
> Signed-off-by: Marco Elver <elver@google.com>
> Suggested-by: H. Peter Anvin <hpa@zytor.com>
> ---
> Changes in v3:
> * Use static_cpu_has instead of moving boot_cpu_has outside uaccess
>   region.
>
> Changes in v2:
> * Replaces patch: 'tools/objtool: add kasan_check_* to uaccess
>   whitelist'
> ---
>  arch/x86/ia32/ia32_signal.c | 2 +-
>  arch/x86/kernel/signal.c    | 2 +-
>  2 files changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/arch/x86/ia32/ia32_signal.c b/arch/x86/ia32/ia32_signal.c
> index 629d1ee05599..1cee10091b9f 100644
> --- a/arch/x86/ia32/ia32_signal.c
> +++ b/arch/x86/ia32/ia32_signal.c
> @@ -358,7 +358,7 @@ int ia32_setup_rt_frame(int sig, struct ksignal *ksig,
>                 put_user_ex(ptr_to_compat(&frame->uc), &frame->puc);
>
>                 /* Create the ucontext.  */
> -               if (boot_cpu_has(X86_FEATURE_XSAVE))
> +               if (static_cpu_has(X86_FEATURE_XSAVE))
>                         put_user_ex(UC_FP_XSTATE, &frame->uc.uc_flags);
>                 else
>                         put_user_ex(0, &frame->uc.uc_flags);
> diff --git a/arch/x86/kernel/signal.c b/arch/x86/kernel/signal.c
> index 364813cea647..52eb1d551aed 100644
> --- a/arch/x86/kernel/signal.c
> +++ b/arch/x86/kernel/signal.c
> @@ -391,7 +391,7 @@ static int __setup_rt_frame(int sig, struct ksignal *ksig,
>                 put_user_ex(&frame->uc, &frame->puc);
>
>                 /* Create the ucontext.  */
> -               if (boot_cpu_has(X86_FEATURE_XSAVE))
> +               if (static_cpu_has(X86_FEATURE_XSAVE))
>                         put_user_ex(UC_FP_XSTATE, &frame->uc.uc_flags);
>                 else
>                         put_user_ex(0, &frame->uc.uc_flags);
> --
> 2.22.0.rc1.257.g3120a18244-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP_-J5dZVtDeHUeDk2TBBkOgoPvGKq42Qd7rezbnFWNGg%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
