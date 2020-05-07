Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5HY2D2QKGQEHFDIHGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EBB31C96E0
	for <lists+kasan-dev@lfdr.de>; Thu,  7 May 2020 18:51:01 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id y31sf7427396qta.16
        for <lists+kasan-dev@lfdr.de>; Thu, 07 May 2020 09:51:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588870260; cv=pass;
        d=google.com; s=arc-20160816;
        b=gxjUbG9RfdRB+CgfSXTnJhYgtue5JKbmMDQX2Qdpd2BwB+MoT8qS5DXBk+LtTRuedp
         kdO42UwmWylWGC6JTwcijK+CnwdjrOJGCOSBdQ5PFReQzriyuvNqyv5+P1qr6xtyHXI3
         x+jglnbEZCWP6giIawyN1kE5LSSKjhwfRnLkWoPXBmfZpPkHmox3V3v2lekGK2lXV2xF
         b32zGiZAd+HAbuQhOWq51hsPLZXDo/5kqr0+U6OX6qnaHoubO8hM3c5e5VIiHsW9TbyI
         OhjOLEKlUYIZPtA0W6lT4SvhoVfxLipS0ZY3FHD5+GzZUDMtnZLWao4Ku8Mc0rE+Tui6
         wcrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=FdZu+UNs9YrX5gPVGttycbr/qBIiXevL19Wm0nb4xv4=;
        b=xmOi/cgMTMYQRM5Nkysf4qgx9FvFF5dMouejoEhC2JtsVk7E0K0nqxO+i8ntmRmtDM
         j+qZ7HjMFSS05n4zMrqNu8whiwmubUReDaScHmqg8F0qkq9/htKM4AQuheqqpVL8tBj+
         tslHGfkFsCEY0YbsZC0XgWOt2Pu23jPrLpMhxG2Yu5To3RKg3h4rfQHvJb/fTkFtQWyO
         SnYoXUCz2sXD5Gl/WKZ7Jy9v9UQ09EIDIKrWG+8CksuS299hAt1StyXtiU+teSmwAHtA
         YICoWvdSel8K50bo7C1puBaazQFxePtwpqs0M9bafEqXv3Bs9Iz2QNhinQAKjy9HRSgb
         VYSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dRJdY9jA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FdZu+UNs9YrX5gPVGttycbr/qBIiXevL19Wm0nb4xv4=;
        b=OKdO8kpjAH8M+BmysiUHLKYDigFiuQdEign3bY3Y5N5NFucEg06W0kJiVq9EPCLogA
         ByUDOg8NsSxYJin/xWTwSE6e7io+GGBpyhIN+jB2/4VF2lDSVfvYd61izr2e1OGxfuNt
         0sHwmq6FZ03Ms5DCreEmov5/SwCMCcgY5mi9opU+cIUBGuAg3lNlu0UetypmwVGfRI99
         5heiTnS9b5Zt3IvKMSpYH49isIOWQyxNEBEHYhcURHI9WjhsnhgJMD0sAgR/Z6iZ2Boi
         mTBKO0TR9ET3eIQTnoNLi+vj4mPhZgnuMOYzZckDRbCETALalHRBSnX3narvhW23Mff8
         XIYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FdZu+UNs9YrX5gPVGttycbr/qBIiXevL19Wm0nb4xv4=;
        b=N4F2AhPyDaTGSUsedWkiq1a3uXQdwPOMg5Ixwu8JVpHW4sYifDnmyhigBkxlZYF0PP
         TA3I8R0HdqR4fFUTv32ISEF6ajmd8zXiKhqMoNuahzxOZcVh27iOhXmkfygv9s9s27/z
         Dgnhx8Lf4HSNecdew8wG6AKYfWNYy34SjCC6RPyWD73PxcFGPPcsi1csi8Z90SLDJ1le
         rse07cDdXa11yX6NWwzKVAVgbyr5tRMxfDYzuwjOiIUvoJWqHeAs3Myv8aNmgc8MKhUj
         s0YGCpBX4/K5ZDbhT/Cnpm3oqAhUJ0IqkB5fbQPNznpotseYmwB/35fXgRAtoApifWDQ
         jbDg==
X-Gm-Message-State: AGi0Pubd4SsZpHg+6nf31mzq5hkQH9mIC0wWZxntSTT9VtZ5X8OImD8D
	dfl6Bn/zIs46zf1MxhxwqxU=
X-Google-Smtp-Source: APiQypIJhJu7tDRqfFPPiRgCMOaSDt2L7Es2eqjJzztxUv4TLL2oX1DgZm4OosddLuuz/JROWpaJQw==
X-Received: by 2002:a05:6214:150e:: with SMTP id e14mr14707227qvy.65.1588870260459;
        Thu, 07 May 2020 09:51:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:2205:: with SMTP id m5ls6182537qkh.1.gmail; Thu, 07
 May 2020 09:51:00 -0700 (PDT)
X-Received: by 2002:a37:9bcf:: with SMTP id d198mr13031327qke.423.1588870260016;
        Thu, 07 May 2020 09:51:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588870260; cv=none;
        d=google.com; s=arc-20160816;
        b=fQ0tiCkEzEwUX8ERhaIS/nqb7yr4yBj6Vi0q9vTkgayjDn0WYioaFHEUZdlSV6ib4X
         pr+4c19pBC1SuUnsSayYKfGB443+dVi43vL6B15zHilqSO/nJaRk0yBtRWlx/YU2v0Iq
         0Y5+4Gvb68QmZrT0NBxexuZU/3BOeHgmwMIBOBElfP6rWOSN47q4/AdL48vQdpenXByM
         kotyoA8OYGh0kS5WghQ/BhoTOip137Zitcsenz9RrW/Rqpmzt7Fv2PDojilOgxQ1jgrY
         gi88Pi4JX95qT6x9P0aLsRup+EV4DiUcQW3QinfvCdevIeDWpsq49qdnPvs08HYacrRw
         azBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kMWnRRDjjsl8pcwIzMkXZpSdECOOZg3cVfKKxGE9IxU=;
        b=FnGBmMOuHkUvu05sOlgm/2gxAph5TQ/yv0egNksCkEDsyp6B28TFtlCi1WZUrW+HKJ
         3E9jh/yfKQqSkUftgt/GKT+fUuKkwPF+PVkag88jAU+tlSF2TkZfxnnS/byT6xumIohH
         /+U1zd7nsVZYoAfpOLBoY6Z5lzUb9c+mT9nmZIe3CxqIvR7y6qPD5u1X6aM4DwkgE3mn
         VoX2SGNahBKgIfa9zfYKdqNs6PYSocqspBkC9n4v/DxlRn3mKTtQw9uxbryu8TIqL/NS
         xdICo5qgMHZ9ad+YYsdxjJLyn8mbQj6QKWOMTkVVdMdeyA4BigST/RtTEh9i7ugw9hft
         tErg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dRJdY9jA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id q46si134825qte.0.2020.05.07.09.50.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 May 2020 09:51:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id j16so5773166oih.10
        for <kasan-dev@googlegroups.com>; Thu, 07 May 2020 09:50:59 -0700 (PDT)
X-Received: by 2002:aca:1c08:: with SMTP id c8mr7227783oic.172.1588870259205;
 Thu, 07 May 2020 09:50:59 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNPCZ2r9V7t50_yy+F_-roBWJdiQWgmvvcqTFxzdzOwKhg@mail.gmail.com>
 <20200507162617.2472578-1-arnd@arndb.de>
In-Reply-To: <20200507162617.2472578-1-arnd@arndb.de>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 7 May 2020 18:50:47 +0200
Message-ID: <CANpmjNObn6aXUe95e9UpuVwxHQ5ubMx_n3LLEgh=pe4rJd-Qyw@mail.gmail.com>
Subject: Re: [PATCH] [v2] ubsan, kcsan: don't combine sanitizer with kcov on clang
To: Arnd Bergmann <arnd@arndb.de>
Cc: Dmitry Vyukov <dvyukov@google.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Kees Cook <keescook@chromium.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Thomas Gleixner <tglx@linutronix.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dRJdY9jA;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Thu, 7 May 2020 at 18:26, Arnd Bergmann <arnd@arndb.de> wrote:
>
> Clang does not allow -fsanitize-coverage=trace-{pc,cmp} together
> with -fsanitize=bounds or with ubsan:
>
> clang: error: argument unused during compilation: '-fsanitize-coverage=trace-pc' [-Werror,-Wunused-command-line-argument]
> clang: error: argument unused during compilation: '-fsanitize-coverage=trace-cmp' [-Werror,-Wunused-command-line-argument]
>
> To avoid the warning, check whether clang can handle this correctly
> or disallow ubsan and kcsan when kcov is enabled.
>
> Link: https://bugs.llvm.org/show_bug.cgi?id=45831
> Link: https://lore.kernel.org/lkml/20200505142341.1096942-1-arnd@arndb.de
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> ---
> v2: this implements Marco's suggestion to check what the compiler
> actually supports, and references the bug report I now opened.
>
> Let's wait for replies on that bug report before this gets applied,
> in case the feedback there changes the conclusion.

Waiting makes sense, if this is not very urgent.

Acked-by: Marco Elver <elver@google.com>

Thank you!

> ---
>  lib/Kconfig.kcsan | 11 +++++++++++
>  lib/Kconfig.ubsan | 11 +++++++++++
>  2 files changed, 22 insertions(+)
>
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index ea28245c6c1d..a7276035ca0d 100644
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -3,9 +3,20 @@
>  config HAVE_ARCH_KCSAN
>         bool
>
> +config KCSAN_KCOV_BROKEN
> +       def_bool KCOV && CC_HAS_SANCOV_TRACE_PC
> +       depends on CC_IS_CLANG
> +       depends on !$(cc-option,-Werror=unused-command-line-argument -fsanitize=thread -fsanitize-coverage=trace-pc)
> +       help
> +         Some versions of clang support either KCSAN and KCOV but not the
> +         combination of the two.
> +         See https://bugs.llvm.org/show_bug.cgi?id=45831 for the status
> +         in newer releases.
> +
>  menuconfig KCSAN
>         bool "KCSAN: dynamic data race detector"
>         depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN
> +       depends on !KCSAN_KCOV_BROKEN
>         select STACKTRACE
>         help
>           The Kernel Concurrency Sanitizer (KCSAN) is a dynamic
> diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
> index 929211039bac..a5ba2fd51823 100644
> --- a/lib/Kconfig.ubsan
> +++ b/lib/Kconfig.ubsan
> @@ -26,9 +26,20 @@ config UBSAN_TRAP
>           the system. For some system builders this is an acceptable
>           trade-off.
>
> +config UBSAN_KCOV_BROKEN
> +       def_bool KCOV && CC_HAS_SANCOV_TRACE_PC
> +       depends on CC_IS_CLANG
> +       depends on !$(cc-option,-Werror=unused-command-line-argument -fsanitize=bounds -fsanitize-coverage=trace-pc)
> +       help
> +         Some versions of clang support either UBSAN or KCOV but not the
> +         combination of the two.
> +         See https://bugs.llvm.org/show_bug.cgi?id=45831 for the status
> +         in newer releases.
> +
>  config UBSAN_BOUNDS
>         bool "Perform array index bounds checking"
>         default UBSAN
> +       depends on !UBSAN_KCOV_BROKEN
>         help
>           This option enables detection of directly indexed out of bounds
>           array accesses, where the array size is known at compile time.
> --
> 2.26.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNObn6aXUe95e9UpuVwxHQ5ubMx_n3LLEgh%3Dpe4rJd-Qyw%40mail.gmail.com.
