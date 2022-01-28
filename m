Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPEB2GHQMGQEB6TANFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 0996E4A00B7
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 20:15:10 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id n6-20020a63b446000000b0034c0280aa73sf3856107pgu.15
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 11:15:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643397308; cv=pass;
        d=google.com; s=arc-20160816;
        b=bLY6ELQ/nJrUNPnFA6APbv3458izk1ugaCvm/gvYniQ+I317xvoWYPeaJ3MuCJ8C/+
         1Q/zgwQybNgYcmgjbgup1LUrdlfMx1C1J9jeObTq+Og49Wry0IQGxg9y95KxCenLECLZ
         gbu9H3VYD/dxvhUxQLYopihuRD7gP1TVm5KhLvahBw+DmxPWptl832S6Ar0IoMMaRgsx
         5qbzBI7AJjy4VjKuM1+Sz9v9DusdJiQhAeLyP2JbqSV1z9UljyHmXlKcQRvpaIEvzCMv
         8ggeNm/ZJpWwv0qy03txzZIfoaePCykaJV0lFAonZMvbR2/4rqccZvt4Lo1WvBI6JT6V
         2xFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PW+yRcHDlFn+VODBEdqz7H287c6TmckZjePbLWGyJfg=;
        b=oSZcKH9Xt0SIq6TOJhxG7uHMuGoqq0QdMp3B06e3EZ1sKaH+Gh2n+wl65Ah3jHUvnd
         Jy9xxUXfqP9/0LvIQZBBibcXEu9N+ie4CEw5W3z0TSD7cPx79DYQZVJ787HrBhUnSjq+
         gJ20olzprp1BV8x6Y+QNFw4mxdyFLBUeVE+JrJ6eIrSh8x/l9NmmSKdXJTO9qFMRZBky
         hOcQ2YwoMk7rsEIBm0dmwZ7/k4LOwfeeLFuJkIPAlbKoWNnrR0V6P5PD4xG+iNRG73Yk
         lRSlFzZsLI7zPt4JuYwfNIEqoCUcMIKZO2zkeQ6iK6RbZkL2gvR4YVgsFHEoG7iLdnd1
         dUJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=H85h2T7h;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PW+yRcHDlFn+VODBEdqz7H287c6TmckZjePbLWGyJfg=;
        b=WsNCJHJWPdccuWld6Gg6GKA2Dl5IFotNcQY7teYokdc8cWljdTs1ojXXF7c7VLjA/3
         /R+omtwHF9Q1kXH5/rHJ7MMzq+6w29T/iq8l2bKqmEbn9pUBZ0ZclZMnkdih/7gJcq9P
         4alyuKiVEBXvT3gtj1xd8IWVNkOuO0lNBBMP65mfXQTlA4Fd5rtjIu0pmUTfZTXDAK28
         VPx/CXqHiO80hI1Qvlt1kw0pI13HO7LXXhy5i41lpxxaw0PaxY+ZBZFSfFG60djQVr4o
         W/CTFIaEc7XN9gegSv6TycyAJ3VWNNp2l3KDZbvXPAWGmhLFmNHBXclJpf43MJa0BkU3
         PoWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PW+yRcHDlFn+VODBEdqz7H287c6TmckZjePbLWGyJfg=;
        b=MYz+3HWq4ZdE60azWYVO/o9QD7cSRBiZUxy6dfnAjC6sw+qHovTYgP3I2nbPSfbrC1
         g9MZvMrIoDqtB8pZbETBTebIHvCWiGxknOuOLb6eywrVE9bf7Khuf2/Hi8SmlucR+h5i
         qZDvH6OMKYkF9cn7zOtNWPJBNi5RS6fqYmDQ7K2VQrTwL2q3HmtN8TDtn9/BFRjCFges
         8CEeYGysnNmQrEfas8HeRCQHEMCk0fcfcfwgfJVk0j8zgyzBWDB0YEaSRTZz2n7eGXin
         ZsISRsynK0yagfI64HJR0AlwkGm11y2+aRa6qupk0l3yz0WYtjRL2pqkFKL5sr4ivBM5
         FWmg==
X-Gm-Message-State: AOAM533DIiXfA/yA7kQHCMCpfmHtxYdbwCIgOgmwK6jnkZL1SJ/icj8n
	I/OkKq8Uw9xcHUOPRk5Uamo=
X-Google-Smtp-Source: ABdhPJw3dvjZpnIcFWaOmIhOcUuNrhTHWFR/7BWTio4p6mq4fh2etchgvEkEWQsuCSo2tmCrWa8SBQ==
X-Received: by 2002:a17:902:9a42:: with SMTP id x2mr9931444plv.58.1643397308718;
        Fri, 28 Jan 2022 11:15:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1913:: with SMTP id y19ls4189568pfi.6.gmail; Fri,
 28 Jan 2022 11:15:08 -0800 (PST)
X-Received: by 2002:a05:6a00:1a53:: with SMTP id h19mr9420446pfv.65.1643397308070;
        Fri, 28 Jan 2022 11:15:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643397308; cv=none;
        d=google.com; s=arc-20160816;
        b=fkvKJIHT/aQr5PU5YmaJHCPNKAAwj6PaR0KV5QrkEJGH7HUYrua2m2PCBklvrEFGB6
         P241svKK39tyHbYoT6rYSDoN2pLMEXh2rbZog3HHoAVBCFG+VlxV6uzSzN01YVElYBNk
         EzCrgYJqlvhaBdtfjlIXK4owAzNJ6/uoN8RwiMayady8/T43YSdGy+SjORyVw1BpCTAR
         2fRvL73g+7HUZTjwGp4awtuh5ujSj1M3cUQ+aYHt38oKhXixX9dswsD3l4JNegbL0hzz
         pHGbezIQDEHzSCgw4Ub/7WvFgrOJXKrcnzTJSBnNP3XkmjRo+FqUXpNB2q6eq2Sf4bY4
         eHFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7jg3x9AtL/f6z9LGi2iYoNteBrHSWn1nyhxat7ZXxLM=;
        b=JBV8KH42VBFIeckTjtjoi5DCkKyCbdB7eThuMcYO940atgC89gqX1QwozLxE+AgVPw
         h8ndFfKazAOKqQXx1Godej/+3S9phYvNNe91eTtJRQvBNU93Xe3ZLI50jY3ox32NVGSO
         re4KEtzjpdW0EqoWhCIXgOy5QAHcOL/Tux5IIH3WflTSbNLGzLVOvWyQyQBmqmGx6VFg
         I5PB+V9PMwk5tCpPWNTsi79KofBps/CDTpsjRYCNKQNz8MUn67LIXjnmVbzrZXXbiAWN
         0MfHz4YqA0z5x2weE7MgcEJWOloWclMBtJ5J6gSuz1NuVG850UGbcPLDNvz0t2S1m6Rh
         KUsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=H85h2T7h;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x234.google.com (mail-oi1-x234.google.com. [2607:f8b0:4864:20::234])
        by gmr-mx.google.com with ESMTPS id g15si606769pfc.3.2022.01.28.11.15.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Jan 2022 11:15:08 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) client-ip=2607:f8b0:4864:20::234;
Received: by mail-oi1-x234.google.com with SMTP id s127so14201591oig.2
        for <kasan-dev@googlegroups.com>; Fri, 28 Jan 2022 11:15:08 -0800 (PST)
X-Received: by 2002:aca:2b16:: with SMTP id i22mr9743887oik.128.1643397307599;
 Fri, 28 Jan 2022 11:15:07 -0800 (PST)
MIME-Version: 1.0
References: <20220128114446.740575-1-elver@google.com> <20220128114446.740575-2-elver@google.com>
 <YfQ8IwCSzbtAhC3B@dev-arch.archlinux-ax161>
In-Reply-To: <YfQ8IwCSzbtAhC3B@dev-arch.archlinux-ax161>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 28 Jan 2022 20:14:55 +0100
Message-ID: <CANpmjNOVWx_Vpy6kuSzR9E0m=xJqbsF6ypCyfdzGZsGzgUfccQ@mail.gmail.com>
Subject: Re: [PATCH 2/2] stack: Constrain stack offset randomization with
 Clang builds
To: Nathan Chancellor <nathan@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Kees Cook <keescook@chromium.org>, 
	Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Elena Reshetova <elena.reshetova@intel.com>, 
	Alexander Potapenko <glider@google.com>, llvm@lists.linux.dev, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=H85h2T7h;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as
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

On Fri, 28 Jan 2022 at 19:55, Nathan Chancellor <nathan@kernel.org> wrote:
[...]
>
> Reviewed-by: Nathan Chancellor <nathan@kernel.org>
>
> One comment below.

Thanks!

Though with Kees's requested changes I'll probably let you re-review it.

> > ---
> >  arch/Kconfig                     |  1 +
> >  include/linux/randomize_kstack.h | 14 ++++++++++++--
> >  2 files changed, 13 insertions(+), 2 deletions(-)
> >
> > diff --git a/arch/Kconfig b/arch/Kconfig
> > index 2cde48d9b77c..c5b50bfe31c1 100644
> > --- a/arch/Kconfig
> > +++ b/arch/Kconfig
> > @@ -1163,6 +1163,7 @@ config RANDOMIZE_KSTACK_OFFSET
> >       bool "Support for randomizing kernel stack offset on syscall entry" if EXPERT
> >       default y
> >       depends on HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
> > +     depends on INIT_STACK_NONE || !CC_IS_CLANG || CLANG_VERSION >= 140000
> >       help
> >         The kernel stack offset can be randomized (after pt_regs) by
> >         roughly 5 bits of entropy, frustrating memory corruption
> > diff --git a/include/linux/randomize_kstack.h b/include/linux/randomize_kstack.h
> > index 91f1b990a3c3..5c711d73ed10 100644
> > --- a/include/linux/randomize_kstack.h
> > +++ b/include/linux/randomize_kstack.h
> > @@ -17,8 +17,18 @@ DECLARE_PER_CPU(u32, kstack_offset);
> >   * alignment. Also, since this use is being explicitly masked to a max of
> >   * 10 bits, stack-clash style attacks are unlikely. For more details see
> >   * "VLAs" in Documentation/process/deprecated.rst
> > + *
> > + * The normal alloca() can be initialized with INIT_STACK_ALL. Initializing the
> > + * unused area on each syscall entry is expensive, and generating an implicit
> > + * call to memset() may also be problematic (such as in noinstr functions).
> > + * Therefore, if the compiler provides it, use the "uninitialized" variant.
> >   */
> > -void *__builtin_alloca(size_t size);
>
> Is it okay to remove the declaration? Why was it even added in the first
> place (Kees)?

Declaring __builtins is redundant for as long as I remember.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOVWx_Vpy6kuSzR9E0m%3DxJqbsF6ypCyfdzGZsGzgUfccQ%40mail.gmail.com.
