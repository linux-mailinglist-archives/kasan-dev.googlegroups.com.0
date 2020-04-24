Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXMYRT2QKGQE2SUWZVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C7131B7ADF
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 17:57:18 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id u137sf9405332pfc.1
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 08:57:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587743837; cv=pass;
        d=google.com; s=arc-20160816;
        b=yfNCQL+v8ts96mHooqH/jyNPVaJRPgKqDgVWeV70WK3upBC0+q+uRQkM2xjWu29mpc
         sezxHK2+WU5jRLHcGUy1e1zFdhz2ih7b3TlbzzHqfKuK6CBMCzn1+jMMltsSo4KCfMNE
         TaV/jk8lZkJprF7eyB8Mu5rLpG3u+WZObPJxvzaH3PXWdGUiDRwE99+d/Aa9VT1txIeA
         1eIhlvQ7g6wPYYw1Xva6ZXYH3BDQlzTcsepaiQPtoXwoRioY/YzMOZxJ4C33ECP8nNHZ
         nn45+C45WSg/6fyp73+lJSbcsvZymtZwnACtpPe6jwky6WdedxIgq10TOLrylIFoessb
         EwDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wylS//RdGCLtwaAD9ZlXvsS0siOpq4tb2uFNeRnB+4Q=;
        b=s5JNrXpZvZyqJiopw2KAu8uy3T6fdvZruKPCCFAdpCgou5Pr0SSX/C/3ul5x6OF1UJ
         PLqA8OEqB5W3IRkyqCaWd5IQcfRe2rDunwjc8L8tLLnH7xUA+umkeNIJzBoasQ1FHctk
         Lh4wy11j1TOtY3l1AY+0YMDdGSC9dvfPPHG1zWHc080I65lcQrB1NSKf3oh+oqKNm/bX
         rC1+JGguUDyl721Ggk2v0VDIgSKAeV6zQZHywSVtmHoUKrHFt42zgTzxb/q2/MpRoVBY
         JDjRUS4a8eGMnKxT/KrTGi0VFeAB3L9XIlzU6iRKQgfN0m5IGjcvTXly8X/d5wElEqQp
         LEQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AwIFz5K7;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wylS//RdGCLtwaAD9ZlXvsS0siOpq4tb2uFNeRnB+4Q=;
        b=elu/zOf71Vs6EaFmeC7K5LBiwHVX4DDZKBGxhZlYG0e4RE/BxDLBUJSkdq1wK6QpmN
         rWW9KVSy8NmbKikIF6e/eaqsh6a4wQ9SYSDqquhs2b7kQOYCh+XsjKYMB72qvP7vkqgO
         mg9Q3daw3BZiMKPLbO8lLyBeDk/ZVDeC5S7oGAcuz9TvU3IiB1ic5xesqiP2sVeU30OJ
         w62DqD7ebNBGukisVkVwk7d6wcVjJ1ZBIglJoPAuJqtGGeKAv+DTgKMW7iv2fMR9xII8
         ZJEmPPBMPq7+vYCmNfl28VEUoa00UbXGI8N0OlBPMYLdBkqYEZHTxjMZe5ySl/rtgdrm
         rjRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wylS//RdGCLtwaAD9ZlXvsS0siOpq4tb2uFNeRnB+4Q=;
        b=Oe5pNBWFm4PYlNb2rBC4CqDsJhkVJ+0IbU+NqI0YDts5SDfXOzCn0byXFOp9UvGu2z
         cTkae0xPAEnd+N4L7mBbdfj4KFi8dPmimCLbf0nFaUqiBuYk2CczzExRyNWf3ETISa6e
         ZDDAjd5ED7enxP+3E7wO7P4j8Sit+Bo8bolZG2dXCQGoCBjft7lGatuAWZe1s4TIPT6W
         Tuu9u88uiT7GxCQs0n/+yYJw2xtRq+hOLq42ZbMSldITjni3t23o2oSnhpr/jqhsw0X1
         SZlWxvg7lTQkhyjq3779Z6BwajsrJkR1kI5lo0S+8soydd7NreJfbd09fCyuobP0JKdk
         YUCg==
X-Gm-Message-State: AGi0PubaUIcpMOyhwvnflL81oJ630glP0Hpzy3Lim6ojnO1AjkfISzXu
	LZGDoE3qda6JjRrFACdMIZc=
X-Google-Smtp-Source: APiQypL3ME/B3SkF2rDOzAhJXG+oMjIQc6nh3jozLZuP6dAxM3r5IA92VnqA9CWpDf73gnxGfAFyTw==
X-Received: by 2002:a17:902:be12:: with SMTP id r18mr9483801pls.206.1587743837249;
        Fri, 24 Apr 2020 08:57:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:ed0f:: with SMTP id d15ls6152133pgi.11.gmail; Fri, 24
 Apr 2020 08:57:16 -0700 (PDT)
X-Received: by 2002:a63:f843:: with SMTP id v3mr10085417pgj.421.1587743836812;
        Fri, 24 Apr 2020 08:57:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587743836; cv=none;
        d=google.com; s=arc-20160816;
        b=eYOcSz+luJV43obAv8XscnQvh54/vyLKRl/mIHUgXEHFBKWzr7gKwkCtwQ6wJhLMOt
         5L6vC/o/qsrp0OIpZGLcGTV8Gt2yCk3tDUVAgU15EJ+6X0CcDh76G8nKZvWOrqqVu4Qu
         B1rtKuvs75Zi3Zr4ACae73pTH6bDlpx+EWGdC0jLRag3gdGkNyZo1cHU+eNApFCPLimW
         d/yp5V+zm6Gfo0qRzoPaoDxiegcEJlDnvipC1E8u5lW+H2m/Hi04Ip23KMegW9kp24kl
         6j8ANbuWbAFFqDU5quYGdIaSWt5zCAvP49pf4Di2nYBALV7nZ9XUmPF9k8VGZ+IdhKjI
         QexA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LCU0zEm2bNycf7DvAmLbUzalJnJrzqnH9qv/4oyQ1dU=;
        b=ymfHv9KAze+GTEh74nC1aaiqzAF7WfLwqQ+YUGJSpJ5whS0gThDrB4lTRsfAAQLd3w
         mFWhT7aUodwdAobTfdgI4Yznu3qMfi0A3TnfLnRF6mJE2MieKNoWKxAFopLWQsOkdGa5
         1zssIwzhhBTBXt+NVseF8s7gaGcCbGVqAaljQeUhHH54vCCZ3qawqeCHFl+Q5c5ln9uF
         KZMlE4dI+lWXtCbenMNzFVdOcwy54VRL7fqJgifbg2Nh3irodWnEM/wcHn8K2jwZHZeF
         zuTCQMJjU1TIwG8FhdJnDrjrC3ljRJLokVeLYuWwAKnxiFEbp6Ua7RdIcladgO4FA2or
         ac5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AwIFz5K7;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id a13si491830pjv.2.2020.04.24.08.57.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Apr 2020 08:57:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id m18so13157652otq.9
        for <kasan-dev@googlegroups.com>; Fri, 24 Apr 2020 08:57:16 -0700 (PDT)
X-Received: by 2002:a9d:7589:: with SMTP id s9mr7701270otk.251.1587743835871;
 Fri, 24 Apr 2020 08:57:15 -0700 (PDT)
MIME-Version: 1.0
References: <20200424154730.190041-1-elver@google.com>
In-Reply-To: <20200424154730.190041-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 24 Apr 2020 17:57:04 +0200
Message-ID: <CANpmjNOaUc8-Y4MMre5mWLjywTZ+B0B9L-cQijeYEMcw9Vapsw@mail.gmail.com>
Subject: Re: [PATCH 1/2] kcsan: Add __kcsan_{enable,disable}_current() variants
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Peter Zijlstra <peterz@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=AwIFz5K7;       spf=pass
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

On Fri, 24 Apr 2020 at 17:47, Marco Elver <elver@google.com> wrote:
>
> The __kcsan_{enable,disable}_current() variants only call into KCSAN if
> KCSAN is enabled for the current compilation unit. Note: This is
> typically not what we want, as we usually want to ensure that even calls
> into other functions still have KCSAN disabled.
>
> These variants may safely be used in header files that are shared
> between regular kernel code and code that does not link the KCSAN
> runtime.
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> This is to help with the new READ_ONCE()/WRITE_ONCE():
> https://lkml.kernel.org/r/20200424134238.GE21141@willie-the-truck
>
> These should be using __kcsan_disable_current() and
> __kcsan_enable_current(), instead of the non-'__' variants.
> ---

Paul: These 2 patches may want to be in the set for 5.8, depending on
what Will wants to do.

An alternative would be that Will takes my 2 patches and carries them,
avoiding some complex patch-dependency. That is assuming his set of
patches will go in -tip on top of KCSAN.

Thanks,
-- Marco

>  include/linux/kcsan-checks.h | 17 ++++++++++++++---
>  kernel/kcsan/core.c          |  7 +++++++
>  2 files changed, 21 insertions(+), 3 deletions(-)
>
> diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
> index ef95ddc49182..7b0b9c44f5f3 100644
> --- a/include/linux/kcsan-checks.h
> +++ b/include/linux/kcsan-checks.h
> @@ -49,6 +49,7 @@ void kcsan_disable_current(void);
>   * Supports nesting.
>   */
>  void kcsan_enable_current(void);
> +void kcsan_enable_current_nowarn(void); /* Safe in uaccess regions. */
>
>  /**
>   * kcsan_nestable_atomic_begin - begin nestable atomic region
> @@ -149,6 +150,7 @@ static inline void __kcsan_check_access(const volatile void *ptr, size_t size,
>
>  static inline void kcsan_disable_current(void)         { }
>  static inline void kcsan_enable_current(void)          { }
> +static inline void kcsan_enable_current_nowarn(void)   { }
>  static inline void kcsan_nestable_atomic_begin(void)   { }
>  static inline void kcsan_nestable_atomic_end(void)     { }
>  static inline void kcsan_flat_atomic_begin(void)       { }
> @@ -165,15 +167,24 @@ static inline void kcsan_end_scoped_access(struct kcsan_scoped_access *sa) { }
>
>  #endif /* CONFIG_KCSAN */
>
> +#ifdef __SANITIZE_THREAD__
>  /*
> - * kcsan_*: Only calls into the runtime when the particular compilation unit has
> - * KCSAN instrumentation enabled. May be used in header files.
> + * Only calls into the runtime when the particular compilation unit has KCSAN
> + * instrumentation enabled. May be used in header files.
>   */
> -#ifdef __SANITIZE_THREAD__
>  #define kcsan_check_access __kcsan_check_access
> +
> +/*
> + * Only use these to disable KCSAN for accesses in the current compilation unit;
> + * calls into libraries may still perform KCSAN checks.
> + */
> +#define __kcsan_disable_current kcsan_disable_current
> +#define __kcsan_enable_current kcsan_enable_current_nowarn
>  #else
>  static inline void kcsan_check_access(const volatile void *ptr, size_t size,
>                                       int type) { }
> +static inline void __kcsan_enable_current(void)  { }
> +static inline void __kcsan_disable_current(void) { }
>  #endif
>
>  /**
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 40919943617b..0a0f018cb154 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -625,6 +625,13 @@ void kcsan_enable_current(void)
>  }
>  EXPORT_SYMBOL(kcsan_enable_current);
>
> +void kcsan_enable_current_nowarn(void)
> +{
> +       if (get_ctx()->disable_count-- == 0)
> +               kcsan_disable_current();
> +}
> +EXPORT_SYMBOL(kcsan_enable_current_nowarn);
> +
>  void kcsan_nestable_atomic_begin(void)
>  {
>         /*
> --
> 2.26.2.303.gf8c07b1a785-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOaUc8-Y4MMre5mWLjywTZ%2BB0B9L-cQijeYEMcw9Vapsw%40mail.gmail.com.
