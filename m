Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZ57RSFAMGQEXQBOZFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B3C040D7A9
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 12:43:53 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id g2-20020a62f9420000b029035df5443c2esf4378772pfm.14
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 03:43:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631789032; cv=pass;
        d=google.com; s=arc-20160816;
        b=KtRajXVoBaydz3przLpcE/O2dRkBXJ83VssdW+O8HAWom+u6wgmY+CMxmAlg47OioE
         RHBGGUHJZRM5QCLbj5vu5thQewiUBC6dyAtPi6grIi/mjziv8hQnmAZDSOUtjK5M8+rQ
         Eo84/CjYJx/BRW/sm4D32YinK3QNAKdZHJhBkpS4IqVHNP+T9UYXh0IhFu6HTXOkuctL
         c4Xkv/Z1fN7kKya/gBmU/ClC8DXCusIq26qv7clqZ+aMAXrd6EBbJ75TJO+Tv6IW6Noo
         /t254APQ7/eCyinKx4Kqd0Hyi6IM8MtIudL7eSXNTh6gu/QI0d6YBNsDxvDxDUNUlDGn
         AbuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=puL5i8fO5aCkhJ6jLz3RA9mW2uEkz0wFDR1iJ4XPFJk=;
        b=XjvBujvvFbU/dHpqRMAVIWGkk536KCQTDWaHqTKTDy1MzVCv2YCsTMCCFfOw1excuA
         zTNXteFqV4c06+FesW9Bh/ajayO2o12k18vlXTktmCYCd4FUYZnOUC8xkAxuYuFZlyba
         su3pqEWSwoxfUSvil2u6JIwPi9vP7HUJmPS3ODatYYC+gPxCIK6ZUsBsMLpJNoAsJG0s
         r9wojW5eL8wyoTtI0jKG7qcC70J0klMAJ/X3c3rO7igVy2YEfidLkn/7mxDx+piDVRUm
         4HLZGWC1G4mxvU0whm3bliosXFFui4HRG0NpkHAR4b84p/d8EFm/EMPMP6Yc5GESSngO
         OcxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="RnQk/0ye";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=puL5i8fO5aCkhJ6jLz3RA9mW2uEkz0wFDR1iJ4XPFJk=;
        b=TF0hHPwEAKw68/UL6IZ6HRnAPuqKzuu8/JvDDn5Fbqr8ZxeFPIdZ1jEu6GxsstKq96
         ZdH1rpO7t8Z3dzMpHRccdB/e+E5bhFWYQ0qnikNX/sozZqVpry1p7W4oY5GPnwzs4xKH
         mSxlCOLpObWIMD3V7Dm7MV4UPT7hnEehXpRmLHJMQnv5l35AgUzGzrGcvJVA/d65vt2J
         GFTNm4iP2uP874j4INIJvjO3Ne1qfF+B7myPhyXVTNLVLNSb7Z+Cd0SXuTvjlR31YkDk
         GglwOmSxs6pfY0nzPs9+je4lRGvQWvZixI42kyFrVGN/H5iEy7FncyId1roVA/lW7SJE
         rJig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=puL5i8fO5aCkhJ6jLz3RA9mW2uEkz0wFDR1iJ4XPFJk=;
        b=43lB/2JHYNMYLAjCCAkBL3lbdVDVsw5h82w1o+CNrSdVv3YiGjI+Lx+7Yey1969M/0
         3ke0HIIw80z71Mw5Fd1A0t90JJ/LtqZe7mso7drusImNtFHno8wUPopPlHcKtZIBP+u/
         J4+/Nmc0nNY/OmbRN0QRfB/QiSB5GWqjLrUYHmYpQvZjx0CAAUysMQTeyHH0K/FZMX0J
         HP8rf5Ac7rrpRLjCUEYOvqAFeD2ILBTctsCbK5pRhmtC6TgD8J6q3Ku1ms9a94ag9Iaf
         llEU2RgH8R/zH3WTAfdR7vslSCnKpIg0Fcw9BCppCW+osewFZK3lhT993NHDp5S3g1d5
         5LGQ==
X-Gm-Message-State: AOAM532hacpPqzzDOkuEBqpGdtetGLZCRK75gPxwYCJXlfqbbHXXO58D
	Ed4Nr1piGEvAzsVIX6ap09g=
X-Google-Smtp-Source: ABdhPJzeMiaKVwTaFypuFVP4lLy2SFgsAQxEi7SqNBiWO+e67CBaVe7K8lxqTXBDwIHojsJiGEeNxw==
X-Received: by 2002:a17:90b:1b0b:: with SMTP id nu11mr14215234pjb.74.1631789031857;
        Thu, 16 Sep 2021 03:43:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6643:: with SMTP id z3ls1410021pgv.3.gmail; Thu, 16 Sep
 2021 03:43:51 -0700 (PDT)
X-Received: by 2002:a65:62c1:: with SMTP id m1mr4448320pgv.339.1631789031214;
        Thu, 16 Sep 2021 03:43:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631789031; cv=none;
        d=google.com; s=arc-20160816;
        b=M9Ex2sD5WOekzMq455PW7oiPZoG5iQGvEEUapJ0o+DM6zZpJvyjEsPFpN2d2/7tbbu
         XEywukyEmsPWWj/Db0zIg5CZCUK0eUAUnd+YdHnAW3tGmnUQquwEKdpZHjtfT4PA/lGu
         kjDfEWHtcjeojzze+b91yO9Y+4mRxIgApzkAzWaxtVjE08xQVSeOvLSbXejCwaMPK5Cd
         rjKj9qX47fas0DSMKQjPd7nQ5Autm8KSnkvx/TSZ0rNdEEFzoB7Q/SciuAHu40dHxUy4
         RksPa2YRstdTxw/JO1nhMXef/i4kRn2LtZmJ/8I6A0/x5f+3xnbo3aDaYZC/rpkEyEUw
         kuKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6eQIzAzVo2s4sy2RQ7zzgd6LAmuLkNzHqLQDH9kJDzc=;
        b=jCAQZN8umB3Bj2R0KwU/1XUQkOxQ0Cfvvv9FASoTpNokjvvxbZddXXqxje1rJ87sRf
         Nd2WurnDAJpnmZfZVtAJORaPi2hvKnQWEAknlHLjkO+X4qr3lCM/RkxglNX1s9HUjBRf
         iM4GhEcExHAYqb8TvtKVstXZZcq6igUof8kLl7seo4X9AUA6/qojzpl3+C0nb2C1FJc8
         sDuV1+haI+vzL+5GOYuxo1YstpCxQSUB+5VBemir5gskvvmB0MLkxlkqG5EnKggFQLFZ
         cwOHjSAZM/Mfsj3vL6fLj4tg1nt82MehBTK9c3Z1TvADR0BQDtyhuGp+7+EQYLvAWv97
         4QSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="RnQk/0ye";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x335.google.com (mail-ot1-x335.google.com. [2607:f8b0:4864:20::335])
        by gmr-mx.google.com with ESMTPS id o5si421986pgv.1.2021.09.16.03.43.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Sep 2021 03:43:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) client-ip=2607:f8b0:4864:20::335;
Received: by mail-ot1-x335.google.com with SMTP id k12-20020a056830150c00b0051abe7f680bso7759878otp.1
        for <kasan-dev@googlegroups.com>; Thu, 16 Sep 2021 03:43:51 -0700 (PDT)
X-Received: by 2002:a9d:71db:: with SMTP id z27mr4101897otj.292.1631789030313;
 Thu, 16 Sep 2021 03:43:50 -0700 (PDT)
MIME-Version: 1.0
References: <20210913081424.48613-1-vincenzo.frascino@arm.com> <20210913081424.48613-6-vincenzo.frascino@arm.com>
In-Reply-To: <20210913081424.48613-6-vincenzo.frascino@arm.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Sep 2021 12:43:38 +0200
Message-ID: <CANpmjNN5atO1u6+Y71EiEvr9V8+WhdOGzC_8gvviac+BDkP+sA@mail.gmail.com>
Subject: Re: [PATCH 5/5] kasan: Extend KASAN mode kernel parameter
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="RnQk/0ye";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as
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

On Mon, 13 Sept 2021 at 10:14, Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> Architectures supported by KASAN_HW_TAGS can provide an asymmetric mode
> of execution. On an MTE enabled arm64 hw for example this can be
> identified with the asymmetric tagging mode of execution. In particular,
> when such a mode is present, the CPU triggers a fault on a tag mismatch
> during a load operation and asynchronously updates a register when a tag
> mismatch is detected during a store operation.
>
> Extend the KASAN HW execution mode kernel command line parameter to
> support asymmetric mode.
>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  Documentation/dev-tools/kasan.rst | 10 ++++++++--
>  mm/kasan/hw_tags.c                | 27 ++++++++++++++++++++++-----
>  mm/kasan/kasan.h                  |  5 +++++
>  3 files changed, 35 insertions(+), 7 deletions(-)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index 21dc03bc10a4..7f43e603bfbe 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -194,14 +194,20 @@ additional boot parameters that allow disabling KASAN or controlling features:
>
>  - ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
>
> -- ``kasan.mode=sync`` or ``=async`` controls whether KASAN is configured in
> -  synchronous or asynchronous mode of execution (default: ``sync``).
> +- ``kasan.mode=sync``, ``=async`` or ``=asymm`` controls whether KASAN
> +  is configured in synchronous, asynchronous or asymmetric mode of
> +  execution (default: ``sync``).
>    Synchronous mode: a bad access is detected immediately when a tag
>    check fault occurs.
>    Asynchronous mode: a bad access detection is delayed. When a tag check
>    fault occurs, the information is stored in hardware (in the TFSR_EL1
>    register for arm64). The kernel periodically checks the hardware and
>    only reports tag faults during these checks.
> +  Asymmetric mode: a bad access is detected immediately when a tag
> +  check fault occurs during a load operation and its detection is
> +  delayed during a store operation. For the store operations the kernel
> +  periodically checks the hardware and only reports tag faults during
> +  these checks.
>
>  - ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
>    traces collection (default: ``on``).
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 05d1e9460e2e..87eb7aa13918 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -29,6 +29,7 @@ enum kasan_arg_mode {
>         KASAN_ARG_MODE_DEFAULT,
>         KASAN_ARG_MODE_SYNC,
>         KASAN_ARG_MODE_ASYNC,
> +       KASAN_ARG_MODE_ASYMM,
>  };
>
>  enum kasan_arg_stacktrace {
> @@ -49,6 +50,10 @@ EXPORT_SYMBOL(kasan_flag_enabled);
>  bool kasan_flag_async __ro_after_init;
>  EXPORT_SYMBOL_GPL(kasan_flag_async);
>
> +/* Whether the asymmetric mode is enabled. */
> +bool kasan_flag_asymm __ro_after_init;
> +EXPORT_SYMBOL_GPL(kasan_flag_asymm);
> +
>  /* Whether to collect alloc/free stack traces. */
>  DEFINE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
>
> @@ -69,7 +74,7 @@ static int __init early_kasan_flag(char *arg)
>  }
>  early_param("kasan", early_kasan_flag);
>
> -/* kasan.mode=sync/async */
> +/* kasan.mode=sync/async/asymm */
>  static int __init early_kasan_mode(char *arg)
>  {
>         if (!arg)
> @@ -79,6 +84,8 @@ static int __init early_kasan_mode(char *arg)
>                 kasan_arg_mode = KASAN_ARG_MODE_SYNC;
>         else if (!strcmp(arg, "async"))
>                 kasan_arg_mode = KASAN_ARG_MODE_ASYNC;
> +       else if (!strcmp(arg, "asymm"))
> +               kasan_arg_mode = KASAN_ARG_MODE_ASYMM;
>         else
>                 return -EINVAL;
>
> @@ -116,11 +123,13 @@ void kasan_init_hw_tags_cpu(void)
>                 return;
>
>         /*
> -        * Enable async mode only when explicitly requested through
> -        * the command line.
> +        * Enable async or asymm modes only when explicitly requested
> +        * through the command line.
>          */
>         if (kasan_arg_mode == KASAN_ARG_MODE_ASYNC)
>                 hw_enable_tagging_async();
> +       else if (kasan_arg_mode == KASAN_ARG_MODE_ASYMM)
> +               hw_enable_tagging_asymm();
>         else
>                 hw_enable_tagging_sync();
>  }
> @@ -143,16 +152,24 @@ void __init kasan_init_hw_tags(void)
>         case KASAN_ARG_MODE_DEFAULT:
>                 /*
>                  * Default to sync mode.
> -                * Do nothing, kasan_flag_async keeps its default value.
> +                * Do nothing, kasan_flag_async and kasan_flag_asymm keep
> +                * their default values.
>                  */
>                 break;
>         case KASAN_ARG_MODE_SYNC:
> -               /* Do nothing, kasan_flag_async keeps its default value. */
> +               /*
> +                * Do nothing, kasan_flag_async and kasan_flag_asymm keep
> +                * their default values.
> +                */
>                 break;
>         case KASAN_ARG_MODE_ASYNC:
>                 /* Async mode enabled. */
>                 kasan_flag_async = true;
>                 break;
> +       case KASAN_ARG_MODE_ASYMM:
> +               /* Asymm mode enabled. */
> +               kasan_flag_asymm = true;
> +               break;
>         }
>
>         switch (kasan_arg_stacktrace) {
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 3639e7c8bb98..a8be62058d32 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h

Shouldn't kasan.h also define kasan_asymm_mode_enabled() similar to
kasan_async_mode_enabled()?

And based on that, also use it where kasan_async_mode_enabled() is
used in tests to ensure the tests do not fail. Otherwise, there is no
purpose for kasan_flag_asymm.

Thanks,
-- Marco

> @@ -287,6 +287,9 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>  #ifndef arch_enable_tagging_async
>  #define arch_enable_tagging_async()
>  #endif
> +#ifndef arch_enable_tagging_asymm
> +#define arch_enable_tagging_asymm()
> +#endif
>  #ifndef arch_force_async_tag_fault
>  #define arch_force_async_tag_fault()
>  #endif
> @@ -302,6 +305,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>
>  #define hw_enable_tagging_sync()               arch_enable_tagging_sync()
>  #define hw_enable_tagging_async()              arch_enable_tagging_async()
> +#define hw_enable_tagging_asymm()              arch_enable_tagging_asymm()
>  #define hw_force_async_tag_fault()             arch_force_async_tag_fault()
>  #define hw_get_random_tag()                    arch_get_random_tag()
>  #define hw_get_mem_tag(addr)                   arch_get_mem_tag(addr)
> @@ -312,6 +316,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>
>  #define hw_enable_tagging_sync()
>  #define hw_enable_tagging_async()
> +#define hw_enable_tagging_asymm()
>
>  #endif /* CONFIG_KASAN_HW_TAGS */

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN5atO1u6%2BY71EiEvr9V8%2BWhdOGzC_8gvviac%2BBDkP%2BsA%40mail.gmail.com.
