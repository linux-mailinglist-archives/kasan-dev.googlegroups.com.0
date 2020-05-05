Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBXUYX2QKGQEMHJTGRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 973601C59C4
	for <lists+kasan-dev@lfdr.de>; Tue,  5 May 2020 16:36:55 +0200 (CEST)
Received: by mail-vk1-xa3f.google.com with SMTP id l188sf1055821vke.23
        for <lists+kasan-dev@lfdr.de>; Tue, 05 May 2020 07:36:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588689414; cv=pass;
        d=google.com; s=arc-20160816;
        b=FdR13MwiaUa38KpVk+MGN0NlADgATpzCmxdrp9wyxNHJtCDrY6luocI/pBsmyatTYH
         hkDN8LOv0PmZ8SaW15X7dJyFi6TaiHoDFRo9d50phRq+3jcUlYopzuOypN6lCjf/TckC
         fmgaHjfcXsYr0iJVpkABY+g1hIbD+GNYLVCAsZSFfXqtWNMJNlMuMpsOktrCkp9K/viE
         mFsWtw+oxttw/zgSmyHfgW/53V+Z4aWUppXczhe2eu6mRMLDoVNHGsu3n1wh6gqtb2B5
         UE0D/ErgrduV71QjQCQCd9pYfa8phOKP5ncaFf/Fd9sYXiFgOv7bihMnSG0+eTyLuwj+
         QfaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=B3HrXpuoxwB1LgCwgZXOBSFBcrzOnHCnaw6txWamcfE=;
        b=rYMRp37f/f1fn1NKdsbrdalkZWcYxnPn2oyVXt3hffIcr+2fWhuVNbfsFT7aaMT7V4
         8RstYZIg9RIFffKfa/MhKlnL/qjmkM+IQ7Nmif2D1KuOYS2892qthO+qq/r6wlQr4fBz
         A9tfdlzpmYs/DMblbkgxqk4UNoyJiN5CBR6cbZti9h3H07AuB/XoW4KZ/r4LgmY+OvKT
         HtQnEBtnTjlOTgGlT9fkkx/YqwLlodVQq1j+SJICRqHaVJv/gQXFq0spGf34UiAP8PNa
         UvjmovOI15oRm7qhJcJpA/cqz0dhyeG1rYBjrJ5H11ea4sG7dI+IDiS7OCluDVrKNhrc
         eowA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TLnOYtAO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B3HrXpuoxwB1LgCwgZXOBSFBcrzOnHCnaw6txWamcfE=;
        b=h30ucOn7qo0+e0dcX+pGFa+qjQS30kGYMUnVvxNze/AONuuwli4wTT2IWFqvexHT7Q
         2ozKSBq7S88tOYnNGnMFo5gQ7n2uzGLEQiTonFQcS43cf/eoekk1nzosC3JnGTsFYA/G
         EOxYbyZU9ZyLDdqv47KFTMjW5f6Q8Uy/8FrmDLswGWGUkJhDCW9BRHM/0h1ddA2989VN
         95NhUEkk56iPvsIgbTHo7sPi1LuwLWINSrxk1L0BMEf66zW5Cx5YqMWJiEOKXXum5F+Z
         yIVeTnFWMdHx9NP1m0LxBx5qIbgE2X3WxU/ge6H4C6fXfiyg9Iy1AtBvzy6A29zgYCxS
         DjDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B3HrXpuoxwB1LgCwgZXOBSFBcrzOnHCnaw6txWamcfE=;
        b=rj62X+W8wbWotmX53JSUwIaBeqsTzGchbytYqfWSY4AcWcjqKU2Rqs+iYBO59nlW8A
         x7Vl50NCURmYHJEW6VgIWAH0KUl+reKI2RANxQfDwei/Nc/KB74mf84cMK+J8cdQfYmD
         IsvcrF/Rdl56nAJrGdSitOv0CRWqfiapJe3BNr/zXL9LewxuRu40yXuUMHH8+CW64GFt
         98yE9014XJoIMRYr0S0HhwmJI1UwRl1Djl9WeWN/060FU/ZxPYILdDVCJWyc/vA7Gdlo
         zB6u8p0y2vpeGrBnqM3LMR+V1oj0PS5OUGW3X+UfJARMOly7XaUgNcrnVmAJr58NRe73
         08aA==
X-Gm-Message-State: AGi0Publ77heITBxZc35gE4N/MQOWdRKmn8vH+0zX9Umqk7qc65X4gIf
	QOjFyW3/Sv8zzePdR+RQsQU=
X-Google-Smtp-Source: APiQypLSOmfYWQwW3sK3o8EeKFxXwCz7MB60sYencCH+c+nu29vFaUfoRvjB9/Mm+w9onIONf7631g==
X-Received: by 2002:a67:69ca:: with SMTP id e193mr2942610vsc.19.1588689414390;
        Tue, 05 May 2020 07:36:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:484:: with SMTP id 126ls337411vse.7.gmail; Tue, 05 May
 2020 07:36:54 -0700 (PDT)
X-Received: by 2002:a67:8704:: with SMTP id j4mr3055992vsd.219.1588689413857;
        Tue, 05 May 2020 07:36:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588689413; cv=none;
        d=google.com; s=arc-20160816;
        b=GqEIzzr6S7vZgIwrqKxWyL7vAP8xp6P3Qvn6FdASgYJBAUzYyxiGKHERvO7KB0FaDF
         nrXyJIeOdbxh8paFrB+BFLyOr9CKX6pZKbe/Xxh4X5EYSZdzut3IoCbAvH11QzfWbbox
         3oeHbWyM+ucFZOxETR07ZT2DmzOZqCnyO9HRevvomYSL6FG9ILPnhFhgq0cmcCmtXKVm
         cx9u3QgsyyFALbmCVJ7mQ5QFYmD/RsdW4+AzlaGR6torvxFCYXFn29put0HQdgLnArpy
         a1fKYcvTAlVxyLEmajNqh6YGkVRuTimWBRHsRRuX54t9+NwAcL/UtRvgVw6n6uc55Lu6
         ki9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jKuEOwL1JP6YyFDs25REhPwIl6Gu+3wkdYT2D/cl688=;
        b=WEKkQkqVMuTEOA7sow8NqsSncVpLY+Z1q40jRPZKymWcB3iBJeYa9P2L+MDgsFwvPg
         lTc3txmTGA5smg/sQmpbEQ1ZHdd4bzRsFzP8Uqk3BHeb5YcuFw4LWYgrdv5megiDkzbs
         nNxEd7yhUcv1Z49ZXCNUtuWLs7zhryh0YwzvXL52SZ1dye5jmzKzHFLYEzGLDDiRPM3a
         muojKWK9uqxN6BoW9VvkDmEow1fAF3ReyvBo5zyhczOXAprfKqexqrnyHGHJbGBeNojC
         LkiQjkke0FudgwF4oxwXVzqTmuMcNzllq+FEuN5DoaACbBunnVqV4G//hHfZsxaBILzw
         khGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TLnOYtAO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id e22si182974vkn.4.2020.05.05.07.36.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 May 2020 07:36:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id j26so1831465ots.0
        for <kasan-dev@googlegroups.com>; Tue, 05 May 2020 07:36:53 -0700 (PDT)
X-Received: by 2002:a9d:7589:: with SMTP id s9mr2280188otk.251.1588689413307;
 Tue, 05 May 2020 07:36:53 -0700 (PDT)
MIME-Version: 1.0
References: <20200505142341.1096942-1-arnd@arndb.de>
In-Reply-To: <20200505142341.1096942-1-arnd@arndb.de>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 May 2020 16:36:40 +0200
Message-ID: <CANpmjNMtGy6YK8zuqf0dmkykZMt=qkxkZrZNEKde1nbw84ZLkg@mail.gmail.com>
Subject: Re: [PATCH] ubsan, kcsan: don't combine sanitizer with kcov
To: Arnd Bergmann <arnd@arndb.de>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Kees Cook <keescook@chromium.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Thomas Gleixner <tglx@linutronix.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	clang-built-linux@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TLnOYtAO;       spf=pass
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

On Tue, 5 May 2020 at 16:23, Arnd Bergmann <arnd@arndb.de> wrote:
>
> Clang does not allow -fsanitize-coverage=trace-{pc,cmp} together
> with -fsanitize=bounds or with ubsan:
>
> clang: error: argument unused during compilation: '-fsanitize-coverage=trace-pc' [-Werror,-Wunused-command-line-argument]
> clang: error: argument unused during compilation: '-fsanitize-coverage=trace-cmp' [-Werror,-Wunused-command-line-argument]
>
> To avoid that case, add a Kconfig dependency. The dependency could
> go either way, disabling CONFIG_KCOV or CONFIG_UBSAN_BOUNDS when the
> other is set. I picked the second option here as this seems to have
> a smaller impact on the resulting kernel.
>
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> ---
>  lib/Kconfig.kcsan | 2 +-
>  lib/Kconfig.ubsan | 1 +
>  2 files changed, 2 insertions(+), 1 deletion(-)
>
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index ea28245c6c1d..8f856c8828d5 100644
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -5,7 +5,7 @@ config HAVE_ARCH_KCSAN
>
>  menuconfig KCSAN
>         bool "KCSAN: dynamic data race detector"
> -       depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN
> +       depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN && !KCOV

This also disables KCOV with GCC. Why does this not work with KCSAN?

This is a huge problem for us, since syzbot requires KCOV. In fact
I've always been building KCSAN kernels with CONFIG_KCOV=y (with GCC
or Clang) and cannot reproduce the problem.

>         select STACKTRACE
>         help
>           The Kernel Concurrency Sanitizer (KCSAN) is a dynamic
> diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
> index 929211039bac..f98ef029553e 100644
> --- a/lib/Kconfig.ubsan
> +++ b/lib/Kconfig.ubsan
> @@ -29,6 +29,7 @@ config UBSAN_TRAP
>  config UBSAN_BOUNDS
>         bool "Perform array index bounds checking"
>         default UBSAN
> +       depends on !(CC_IS_CLANG && KCOV)

Ditto, we really need KCOV for all sanitizers. I also just tried to
reproduce the problem but can't.

Which version of clang is causing this? I'm currently using Clang 9.
My guess is that we should not fix this by disallowing KCOV, but
rather make Clang work with these configs.

Dmitry, can you comment?

Thanks,
-- Marco

>         help
>           This option enables detection of directly indexed out of bounds
>           array accesses, where the array size is known at compile time.
> --
> 2.26.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMtGy6YK8zuqf0dmkykZMt%3DqkxkZrZNEKde1nbw84ZLkg%40mail.gmail.com.
