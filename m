Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6FJZOCAMGQERIHWVUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F83B374374
	for <lists+kasan-dev@lfdr.de>; Wed,  5 May 2021 19:25:13 +0200 (CEST)
Received: by mail-vs1-xe3c.google.com with SMTP id e17-20020a67d8110000b0290225d135fa8csf1374565vsj.22
        for <lists+kasan-dev@lfdr.de>; Wed, 05 May 2021 10:25:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620235512; cv=pass;
        d=google.com; s=arc-20160816;
        b=uGNwEmy6Cyh4gLyoBy62wVHi5Z7Rn7cUFB2yRbAE502YgZx0PAX09OkdrahQW8H9RF
         VtHxbaoucyyzjkrSXWfLCFdXs+HwPgRrhVNUrtefg0Zy9nMM6QCIxSizk9+UPoLVH/Qk
         K9NQh14lXHKQh7bJJhb35bG1CZz+i+SB1Js7APsxJFl10uETG/ADPe6JDVFcgHeLRnu4
         aEzj+7R/qmWxLtS2VRru27sOZH1aIpB0QxcBvjmKeMzTgvupDgUFMxAaoEKYeZ7fHPXp
         AiwYiOTb5EJBE6WA5DHWoY1C/KtNpRGzkH530/HhcZzgm3zaQ4nFFYGtiuzwe8kLjQlL
         y54Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3KcLgGZi622UFGCGVPUd1I5HTsHEM+nPQhrsDeFrQzo=;
        b=aSfYnD0mKfIUbpEq3OTXImRE8HDp4QzPMX/J5rqien6T9WTbxTMjQQqH3uQ6te7qxc
         nOHYuQMVFEiM7+bqJcd2tmY+RFYgGrAwHHgaIEt91eBSZyoGH83/jeuRULtzMakbYZB1
         cBHQ9gOFs0Rq42qRQantLNt1aiwNuqUr8eG+uo86ej7Du5edsdaWJRg2Qwj32591V+QB
         +kvYpoakxmzKTYwigWzrFMqwufkxM0v74OspKeT/PlvNnAk9/QANYtPdoKZQwoXVQ5e8
         RuwMJKe++HcxbRA+7R5ZRf+D+KFtCwGQLB3/eVtlGpd/9iCkqTIKakGwYd9O6VMdilBT
         UF/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XwV87+f8;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3KcLgGZi622UFGCGVPUd1I5HTsHEM+nPQhrsDeFrQzo=;
        b=L++0k7P2lfYO5Bk9jcIJRM6jZK0yV5GpUVS8jZhoScJiTeLIeqTuuxoNFuq9AJGnF8
         aElNRY/7EvY1YrW4gZ5Bj/zipmXmh+vnSzeH9FWGMdkvDb3IUInGdNh1VrXPiQpD66UK
         XiiwG+1ETZUto8yjO1ie2IOjQMgaAMGMh2qVb584N/ipW/TBJ9wdfnu0SDdSLXMBZUZL
         W+GV9GuBZJUxdd8NXU/sCWi4UvTzhgk8y+LXHUnbb8z0Ab2EtBP0gk0PKP8aBfmN4dWL
         O+PhxqZx5GnCA5o1MZA2puQ6OR2DiNNs89XkWugrV2vbQemdfxrwz3p9EgKNm9jrJbJ9
         rTGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3KcLgGZi622UFGCGVPUd1I5HTsHEM+nPQhrsDeFrQzo=;
        b=tG8SgUL0c1y+SNHkeOKfHsuSuibgMAQnPwuMnH2uyO217jX82/dF07gD6hzgH9DZP0
         UnpVc4ODVt0/42YCXhXWoYbVc24LseaOtZF9deE53diaUQkXf1jNAXF62nZ1CWa7InUR
         q+92omGzTDCRYGnwzI6BsA3dXGsStFV7Zg1WlM7wU424JkMs4uPp9eFJeh9mBb5B4XB5
         5nVTxrvLpWA96OenH00U/gtks643WRQKCF2aIvE/OPzUY9qgF0aDpft/D1p1Scr2sPLX
         +I7Rqtc7SdJ8JiBUa/kw0v0s2iohd7QzbH8W1qoh3qvLNYUCirGDsNsZZ+K9R2qbcUym
         9VHA==
X-Gm-Message-State: AOAM5323/Dis9o8Sikk6zFd6zJ/EqbB3+YRzL8xQFeppwHP166P5kgHX
	Kq9hGbxHpLDJfj77yXelF10=
X-Google-Smtp-Source: ABdhPJyj0av5tFw6goCsLkw25WKVdVzJyfpQY12BoJ4R0UZqCfC4klMRLfdzJtyflraipuMlN1bUGw==
X-Received: by 2002:ab0:3403:: with SMTP id z3mr138339uap.113.1620235512421;
        Wed, 05 May 2021 10:25:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f301:: with SMTP id p1ls5411vsf.10.gmail; Wed, 05 May
 2021 10:25:11 -0700 (PDT)
X-Received: by 2002:a67:be10:: with SMTP id x16mr9196925vsq.60.1620235511728;
        Wed, 05 May 2021 10:25:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620235511; cv=none;
        d=google.com; s=arc-20160816;
        b=QEx2LVInC7jujjEy/Mhv9A7jXnRPFF5sp4OuZsaOCuwUYnov+ZrC1a+iNue7yadi4X
         MJZo9iflqVpdA3fiKFxdRDQEFAVJgBCnmDGZ1eFzzmbimRMcVW7L6DpLSDEEtVPpEkg3
         C07Q4Z9YZtjZgvt4oj9i+0TwrbtzEMIgA1FKm5xv9eO6wmlTNfVbx0XSBTxXNrnx6TMa
         wreHJwhG6L95ir8GG1M7SPh6mN5x16ySaIkBAaSg4xTBBWQjdkY5f5VCo09cYCO8lvvH
         LpPWE1JdxnQimWo++ertFxOXeWrpdJI+xpzMXsqa7rohQjpnT1oTjuuK0wRA42co3WYy
         PRgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mhdimRmcWFxSoj8AFDYbNHsikBJUsUucL4YCEQ/2njw=;
        b=dl7+SstcamW/mrY+bvI2nBOqMlqdIAENpmuE9xiIVEWxlLb/3nN3kv629pfKZgtwxx
         IF4WuTa7v9G5hRH/tF/k76J9QVmbWTsZMr8OenuUOthJ3LEpXVpK3KpIpz6mPrxWJwtF
         /VSN082JUec0JMhFX6u0X1DQ1aM8O8lgpLNxicoSLrbviZuGFI2W52mcGB2yxTiLAscq
         9KMB3lCEZLNhRTvT4Mhu1viQoER162moW3vcNXMincWZLVXuqIBVuIYLqbLaBryhuX6W
         etWy0azxt1OuimbVzgP9mIYRNcHIqYB3pHCbozwhH3xuK+vWqoFGe8bLf3OJhMJ43Pao
         nAHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XwV87+f8;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x331.google.com (mail-ot1-x331.google.com. [2607:f8b0:4864:20::331])
        by gmr-mx.google.com with ESMTPS id f9si520420vkm.2.2021.05.05.10.25.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 May 2021 10:25:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) client-ip=2607:f8b0:4864:20::331;
Received: by mail-ot1-x331.google.com with SMTP id q7-20020a9d57870000b02902a5c2bd8c17so2390558oth.5
        for <kasan-dev@googlegroups.com>; Wed, 05 May 2021 10:25:11 -0700 (PDT)
X-Received: by 2002:a05:6830:410e:: with SMTP id w14mr23863201ott.251.1620235511237;
 Wed, 05 May 2021 10:25:11 -0700 (PDT)
MIME-Version: 1.0
References: <m1tuni8ano.fsf_-_@fess.ebiederm.org> <20210505141101.11519-1-ebiederm@xmission.com>
 <20210505141101.11519-4-ebiederm@xmission.com>
In-Reply-To: <20210505141101.11519-4-ebiederm@xmission.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 5 May 2021 19:24:00 +0200
Message-ID: <CANpmjNNJ0vHq3s+mEqR1q8jqCzgHmivRcU+1m_Q8vquV5t5xWw@mail.gmail.com>
Subject: Re: [PATCH v3 04/12] signal: Verify the alignment and size of siginfo_t
To: "Eric W. Beiderman" <ebiederm@xmission.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Florian Weimer <fweimer@redhat.com>, 
	"David S. Miller" <davem@davemloft.net>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, sparclinux <sparclinux@vger.kernel.org>, 
	linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux API <linux-api@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XwV87+f8;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as
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

On Wed, 5 May 2021 at 16:11, Eric W. Beiderman <ebiederm@xmission.com> wrote:
> From: "Eric W. Biederman" <ebiederm@xmission.com>
>
> Update the static assertions about siginfo_t to also describe
> it's alignment and size.
>
> While investigating if it was possible to add a 64bit field into
> siginfo_t[1] it became apparent that the alignment of siginfo_t
> is as much a part of the ABI as the size of the structure.
>
> If the alignment changes siginfo_t when embedded in another structure
> can move to a different offset.  Which is not acceptable from an ABI
> structure.
>
> So document that fact and add static assertions to notify developers
> if they change change the alignment by accident.
>
> [1] https://lkml.kernel.org/r/YJEZdhe6JGFNYlum@elver.google.com
> Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>

Acked-by: Marco Elver <elver@google.com>

> ---
>  arch/arm/kernel/signal.c           | 2 ++
>  arch/arm64/kernel/signal.c         | 2 ++
>  arch/arm64/kernel/signal32.c       | 2 ++
>  arch/sparc/kernel/signal32.c       | 2 ++
>  arch/sparc/kernel/signal_64.c      | 2 ++
>  arch/x86/kernel/signal_compat.c    | 6 ++++++
>  include/uapi/asm-generic/siginfo.h | 5 +++++
>  7 files changed, 21 insertions(+)
>
> diff --git a/arch/arm/kernel/signal.c b/arch/arm/kernel/signal.c
> index 2dac5d2c5cf6..643bcb0f091b 100644
> --- a/arch/arm/kernel/signal.c
> +++ b/arch/arm/kernel/signal.c
> @@ -737,6 +737,8 @@ static_assert(NSIGBUS       == 5);
>  static_assert(NSIGTRAP == 6);
>  static_assert(NSIGCHLD == 6);
>  static_assert(NSIGSYS  == 2);
> +static_assert(sizeof(siginfo_t) == 128);
> +static_assert(__alignof__(siginfo_t) == 4);
>  static_assert(offsetof(siginfo_t, si_signo)    == 0x00);
>  static_assert(offsetof(siginfo_t, si_errno)    == 0x04);
>  static_assert(offsetof(siginfo_t, si_code)     == 0x08);
> diff --git a/arch/arm64/kernel/signal.c b/arch/arm64/kernel/signal.c
> index af8bd2af1298..ad4bd27fc044 100644
> --- a/arch/arm64/kernel/signal.c
> +++ b/arch/arm64/kernel/signal.c
> @@ -985,6 +985,8 @@ static_assert(NSIGBUS       == 5);
>  static_assert(NSIGTRAP == 6);
>  static_assert(NSIGCHLD == 6);
>  static_assert(NSIGSYS  == 2);
> +static_assert(sizeof(siginfo_t) == 128);

Would using SI_MAX_SIZE be appropriate? Perhaps not.. in case somebody
changes it, given these static asserts are meant to double-check.

I leave it to you to decide what makes more sense.

> +static_assert(__alignof__(siginfo_t) == 8);
>  static_assert(offsetof(siginfo_t, si_signo)    == 0x00);
>  static_assert(offsetof(siginfo_t, si_errno)    == 0x04);
>  static_assert(offsetof(siginfo_t, si_code)     == 0x08);
> diff --git a/arch/arm64/kernel/signal32.c b/arch/arm64/kernel/signal32.c
> index b6afb646515f..ee6c7484e130 100644
> --- a/arch/arm64/kernel/signal32.c
> +++ b/arch/arm64/kernel/signal32.c
> @@ -469,6 +469,8 @@ static_assert(NSIGBUS       == 5);
>  static_assert(NSIGTRAP == 6);
>  static_assert(NSIGCHLD == 6);
>  static_assert(NSIGSYS  == 2);
> +static_assert(sizeof(compat_siginfo_t) == 128);
> +static_assert(__alignof__(compat_siginfo_t) == 4);
>  static_assert(offsetof(compat_siginfo_t, si_signo)     == 0x00);
>  static_assert(offsetof(compat_siginfo_t, si_errno)     == 0x04);
>  static_assert(offsetof(compat_siginfo_t, si_code)      == 0x08);
> diff --git a/arch/sparc/kernel/signal32.c b/arch/sparc/kernel/signal32.c
> index 778ed5c26d4a..32b977f253e3 100644
> --- a/arch/sparc/kernel/signal32.c
> +++ b/arch/sparc/kernel/signal32.c
> @@ -757,6 +757,8 @@ static_assert(NSIGBUS       == 5);
>  static_assert(NSIGTRAP == 6);
>  static_assert(NSIGCHLD == 6);
>  static_assert(NSIGSYS  == 2);
> +static_assert(sizeof(compat_siginfo_t) == 128);
> +static_assert(__alignof__(compat_siginfo_t) == 4);
>  static_assert(offsetof(compat_siginfo_t, si_signo)     == 0x00);
>  static_assert(offsetof(compat_siginfo_t, si_errno)     == 0x04);
>  static_assert(offsetof(compat_siginfo_t, si_code)      == 0x08);
> diff --git a/arch/sparc/kernel/signal_64.c b/arch/sparc/kernel/signal_64.c
> index c9bbf5f29078..e9dda9db156c 100644
> --- a/arch/sparc/kernel/signal_64.c
> +++ b/arch/sparc/kernel/signal_64.c
> @@ -567,6 +567,8 @@ static_assert(NSIGBUS       == 5);
>  static_assert(NSIGTRAP == 6);
>  static_assert(NSIGCHLD == 6);
>  static_assert(NSIGSYS  == 2);
> +static_assert(sizeof(siginfo_t) == 128);
> +static_assert(__alignof__(siginfo_t) == 8);
>  static_assert(offsetof(siginfo_t, si_signo)    == 0x00);
>  static_assert(offsetof(siginfo_t, si_errno)    == 0x04);
>  static_assert(offsetof(siginfo_t, si_code)     == 0x08);
> diff --git a/arch/x86/kernel/signal_compat.c b/arch/x86/kernel/signal_compat.c
> index 0e5d0a7e203b..e735bc129331 100644
> --- a/arch/x86/kernel/signal_compat.c
> +++ b/arch/x86/kernel/signal_compat.c
> @@ -34,7 +34,13 @@ static inline void signal_compat_build_tests(void)
>         BUILD_BUG_ON(NSIGSYS  != 2);
>
>         /* This is part of the ABI and can never change in size: */
> +       BUILD_BUG_ON(sizeof(siginfo_t) != 128);
>         BUILD_BUG_ON(sizeof(compat_siginfo_t) != 128);
> +
> +       /* This is a part of the ABI and can never change in alignment */
> +       BUILD_BUG_ON(__alignof__(siginfo_t) != 8);
> +       BUILD_BUG_ON(__alignof__(compat_siginfo_t) != 4);
> +
>         /*
>          * The offsets of all the (unioned) si_fields are fixed
>          * in the ABI, of course.  Make sure none of them ever
> diff --git a/include/uapi/asm-generic/siginfo.h b/include/uapi/asm-generic/siginfo.h
> index 03d6f6d2c1fe..91c80d0c10c5 100644
> --- a/include/uapi/asm-generic/siginfo.h
> +++ b/include/uapi/asm-generic/siginfo.h
> @@ -29,6 +29,11 @@ typedef union sigval {
>  #define __ARCH_SI_ATTRIBUTES
>  #endif
>
> +/*
> + * Be careful when extending this union.  On 32bit siginfo_t is 32bit
> + * aligned.  Which means that a 64bit field or any other field that
> + * would increase the alignment of siginfo_t will break the ABI.
> + */
>  union __sifields {
>         /* kill() */
>         struct {
> --
> 2.30.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNJ0vHq3s%2BmEqR1q8jqCzgHmivRcU%2B1m_Q8vquV5t5xWw%40mail.gmail.com.
