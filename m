Return-Path: <kasan-dev+bncBDYJPJO25UGBBWHP5H3AKGQE6GGGKLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id D44D21EFE3A
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Jun 2020 18:50:33 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id f187sf12693114ybc.2
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Jun 2020 09:50:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591375832; cv=pass;
        d=google.com; s=arc-20160816;
        b=VjiRgAj42Vq8AetoJl9q6bcC2OIbIsuibJa/p6fVGNcfd+EiB2iJFm8IXMnywd6H5q
         qv4jxYETX9ep+KLDpmqmvSQ08+PoW3y4t7O/6vdFNpuu/tAyfbWiIk783AZ0TrM8it4Y
         h9uAi/ZSkNeDhEAgrV0Y51ILAvRDBsI5ZEOlLKCdfo3aUwJfh2l2+4H7XhbyepjasvXs
         yKvG0PlzBDrp7FQc1uYN2WlZelmiB8KO0m8+530WH0pvqumFXH5n6rzJ+eHuESxC3Hrk
         IE9pBaTkpJlT+GR8dm0Krmb4xXIQVFxHGVnB1WsJoFRJvlTSHwsDeERquijm7S57z/TX
         PFxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9kG+WEmUKafhm565H0mzMQayFXd0QzRGrRzQFD12mlA=;
        b=Z3GQF2qrteHTAM/ku4m6+5uwDwOAX9nxHFgmqL6m9IWGvGSD2gZd5+VzuP9i9OWaU1
         zFtlFl1ibi3Jbyd9FJqsItFyGTFWt9vp0CwVFy64sWVdtn/s3CGMtS+RffKbOCSex+1L
         rAR6VbWCJ1UTJA6D7usEn8z1AbC/QeEa6DupYeY2n5kQrMeJ3QAfcazMg3MzDs5EIq3H
         1OAmA4XgAUUbRgF0mH4epwInaphVVZ4Q0aZ9ZxlVFVe0YTsMWaV46uY2D5FsH719KBZ2
         tb1DMLO78k0K6noNNhHBcwMmAAq4pEbsICh6E5mnXNUFUMuAreUhXoODnJhoYAdU3t8R
         RiXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Xlk62jXK;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9kG+WEmUKafhm565H0mzMQayFXd0QzRGrRzQFD12mlA=;
        b=rqlerCXa/ZKG9rU6tFlrhyfU0wdUh9i5h3sD9LQRIyM1w2XfuwDBYQF9nWDvtIOfu9
         HKiEiIPD1hiRrkIqCJapZW1xMY6fuz+lUnE0Nlo52uXF/XUgSNtRBCb0t91UVHbKFSS8
         l5DmSn3a/7ua2nWefQFLGtJRady8wqQYttbaXEroLRd1b+mBqXrS15cSLk3XhsDVhnrK
         Z3LK1H7tGVWGTS19lLAGUyyHFH/ubNWknjOvretQcT2uG2Ml8jTPiI+Njcsqo6pSTPXH
         3ZhT5U8gZ3w5/pkEk+uRDb9c7GVn9/UIbNUwMYh4Y5NAMLs+BiZOYFSyC+HspVW67Vbd
         uysw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9kG+WEmUKafhm565H0mzMQayFXd0QzRGrRzQFD12mlA=;
        b=VQ0aUV80xqDxmO0v9xJXHF4HvlGSZvPF+YTxkaXxJ1pC0eGuUHaWoctYTuU1Tt488t
         dsnfyFyTKKbG/uwHJnoqw3iZNcfkfflZIAckkctNJMFlMrGaRomLWNJcCgJk8ekizvLn
         DXx4OXoeIQ9+XfUhfOAYLAnqSCxfF4rSWoOHBhTvCfQLT8cTz1hjTwtpIT2XlOR/Bke0
         nNxkPuonpS9BRnmoQXDT/7hkVzvXMTVMZ+gxXTGwllh757j0qK8G0iU82p8bgaHDCSkJ
         kMaI7hnuOOuqSJGTnv47bvNkYu6XNCV6h/gs+TFEcZokuX9DIn6zObWXyutToEXfUe6H
         SSXA==
X-Gm-Message-State: AOAM531cGtsxM+/E1u5LnDIUjWWI8XqHw+2h/wXdr1cJhYfwribGwL1p
	bsqPVRePnj5/YcR2o3MUhx8=
X-Google-Smtp-Source: ABdhPJz5kvLJ1QKdkoqWAkIxpYHe5NF8NUNNw0XsB+AgnSaGunZ0SJIXJm4NygtRvmyadDTQCpGkig==
X-Received: by 2002:a25:7a06:: with SMTP id v6mr18118827ybc.152.1591375832652;
        Fri, 05 Jun 2020 09:50:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2057:: with SMTP id g84ls4041745ybg.7.gmail; Fri, 05 Jun
 2020 09:50:32 -0700 (PDT)
X-Received: by 2002:a25:244b:: with SMTP id k72mr18342772ybk.477.1591375832347;
        Fri, 05 Jun 2020 09:50:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591375832; cv=none;
        d=google.com; s=arc-20160816;
        b=JHml0XJGPoRD7dvFDl0/rk3rbAPIoRDjf0ZQ6mKAtP6HvBDs7GgLAmMoDB4PFA0DCV
         YVByASu0kOuaShZpSqOIWPC0zoy3xxhJYVJTENrT+y4Q0ZcHFb/QPO/mkuxX4Xfaf0pg
         wQmDPkUGgZT/VsbM8im4Bm39cYDjjHew6I2DOYQ7KmNrhrAZ5k63QyYzNY4utGUYXwwh
         5zP2j35aHe/v1YcOK87ahRcBjPQKScMhTvdoszmEzB8ooJRF0gDkc2btgdwVVJ00Ok8c
         fmn1nocfYr/my+tIuFUysigo+VoS8BYfoT5R+E9b6PPXzkFlSNHlTc+Hj41VFTlqxm7g
         xy8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ndEcXCs8HGuPHBOdpnF2uLFbc3ITmk/itvLe9IIcUiU=;
        b=NoC51f8Ucc77qAaQFidmP1UYWwI2RnEfO52lixPF3piYWzaEaKPjA/AKmS9uVVYaGX
         0sLC5Z/oduTtuNSRJYxvDzD2/2YlaStrS2GoI0haKYViLhJYReJhW6CaZgJ30j6jGnQx
         F2M+6DIBlkYZvGz3G3sR7pEvSb/IRsFh0fHb7w1s44QQDKuHUZd9JuijrVJTdXZLh2zW
         OYOV1m8hv8eud6xcJAwLyivClev0CYABCxkc+1FX19f78ViM9yy7KuDRV3iVMdl4Mc0m
         44GG8DawGvMW5dh+pIYmZQWtXBpfcDbeEr/ffucUPlUpwSkM0NJd0vt8CACWrzj55lNr
         0dmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Xlk62jXK;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id s63si712454yba.2.2020.06.05.09.50.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Jun 2020 09:50:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id bh7so3864970plb.11
        for <kasan-dev@googlegroups.com>; Fri, 05 Jun 2020 09:50:32 -0700 (PDT)
X-Received: by 2002:a17:90a:4802:: with SMTP id a2mr3849393pjh.25.1591375831319;
 Fri, 05 Jun 2020 09:50:31 -0700 (PDT)
MIME-Version: 1.0
References: <20200605082839.226418-1-elver@google.com> <20200605082839.226418-2-elver@google.com>
In-Reply-To: <20200605082839.226418-2-elver@google.com>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 5 Jun 2020 09:50:20 -0700
Message-ID: <CAKwvOd=EOQ8g43aC2=aW1kKPmroPCjBJ_1yDwo_zTCgvCuDG5A@mail.gmail.com>
Subject: Re: [PATCH -tip v3 2/2] kcov: Unconditionally add -fno-stack-protector
 to compiler options
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Borislav Petkov <bp@alien8.de>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	"maintainer:X86 ARCHITECTURE (32-BIT AND 64-BIT)" <x86@kernel.org>, Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Xlk62jXK;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::641
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
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

On Fri, Jun 5, 2020 at 1:28 AM Marco Elver <elver@google.com> wrote:
>
> Unconditionally add -fno-stack-protector to KCOV's compiler options, as
> all supported compilers support the option. This saves a compiler
> invocation to determine if the option is supported.
>
> Because Clang does not support -fno-conserve-stack, and
> -fno-stack-protector was wrapped in the same cc-option, we were missing
> -fno-stack-protector with Clang. Unconditionally adding this option
> fixes this for Clang.
>
> Suggested-by: Nick Desaulniers <ndesaulniers@google.com>
> Signed-off-by: Marco Elver <elver@google.com>

Thanks for considering the suggestion.
Reviewed-by: Nick Desaulniers <ndesaulniers@google.com>

> ---
> v3:
> * Do not wrap -fno-stack-protector in cc-option, since all KCOV-supported
>   compilers support the option as pointed out by Nick.
> ---
>  kernel/Makefile | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/kernel/Makefile b/kernel/Makefile
> index ce8716a04d0e..71971eb39ee7 100644
> --- a/kernel/Makefile
> +++ b/kernel/Makefile
> @@ -35,7 +35,7 @@ KCOV_INSTRUMENT_stacktrace.o := n
>  KCOV_INSTRUMENT_kcov.o := n
>  KASAN_SANITIZE_kcov.o := n
>  KCSAN_SANITIZE_kcov.o := n
> -CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> +CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack) -fno-stack-protector
>
>  # cond_syscall is currently not LTO compatible
>  CFLAGS_sys_ni.o = $(DISABLE_LTO)
> --
> 2.27.0.278.ge193c7cf3a9-goog
>


-- 
Thanks,
~Nick Desaulniers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKwvOd%3DEOQ8g43aC2%3DaW1kKPmroPCjBJ_1yDwo_zTCgvCuDG5A%40mail.gmail.com.
