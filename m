Return-Path: <kasan-dev+bncBDX4HWEMTEBRBDWMQ6AAMGQEP27Z6KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AB3F2F84F3
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 19:59:27 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id e2sf7033629pgg.10
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 10:59:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610737166; cv=pass;
        d=google.com; s=arc-20160816;
        b=WTuEOGJqxWzR/6Fc3r4iJqEGKy3wy6WVP+68TrDo9+NI+seC0cejR3bcUGaUm8d3Ve
         yrlyf8ESVcEvf3iNRyGKsNwj0+EV5Mmvy9xrJtBswEEVcKB4jCx1o3WSR7wVL4XleFr6
         ku1d38dnhXvuzDBxr+VcIV+bsvElDgz8FxDSg91hcA0EK0odTxb2j9M+ykorm/qwIH2i
         /yDSnJSR5twt2gzWYrnse6EE4nEghDzCXchPWGjSRkKGSA00ne1bUTtaMhH9b0zEyahp
         XgmjpkG9yZSjcZH6o9kdd78jag0Ctpoj6fJi6MgB5p/W5Ki/3st7ibJGorQ1Y/whxqDX
         GjjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=K/zs+XBC32bjSf0FsEMwQnEK2qZBakYOsl4oXDBHHIE=;
        b=FH+pLyobY4RgFMq169iJ2vC9RNNtRbhgWIwiW1C4uwGiWcZ2O5kXaOYsMw5Zli4AQa
         R/leK4hA/GWFoCmCjf5AyBTXA45e2tQ2MOfmT3szaso6ATMFAQCzF+/24VSw2KNKIkdf
         7Uw4+FpBL1bgx55aUhF0YaSD6lva15ZibqtiHp+1eHRxXNQQlndMlnT6cuF7M7RgLY3l
         g8n5g5tY6RypLV8quyq0AW3QvIIYg/2rawslEFVRoSpw4RIuOuR88mnFL16s2uCnaQqZ
         Ak3B3OaJJMPHfgAgj6RztukESx1KI/AnDh8Ffm+3AMogL46Udwx/qPrmWkkyub8CpEEZ
         gxnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=P4vaNsmj;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K/zs+XBC32bjSf0FsEMwQnEK2qZBakYOsl4oXDBHHIE=;
        b=UuIktOwwNy0WFNdZHxx62rHmXhn2zPReBN+UQvxDXe4rLg9ExbJgRKTQ8smAYKxg0h
         GS0i4WpRpuxZufaZbzNAOFE/HVkQbYRblm4m4OWWjSxu7oHiBm5xEdRpa2nLqKAYev5P
         NbcZAgrUdWsiS+2GQqWf7AQ8oU4TYmipiJVJGEtP217G1LOrsAALHPwmLg8pWp1d9P6F
         mZokoqY1MNWCl6NeA/h4xkTsxFjNW1pgr2xjoji9psllfxr8sBWAqp+JYeu0aTfpM4w6
         aAeF90EmVDurIJERv6Ctg1PT6VDxIjONvTCWlUVBcad2NJeRj7UDfsI1dsWqMPrYfyCq
         xaWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K/zs+XBC32bjSf0FsEMwQnEK2qZBakYOsl4oXDBHHIE=;
        b=TBrRM0w8LgfXZTr7imtFt4J9fUyOTU/Bl3yxsqdbuvd3ttm7Cv9q+XYPa3/6PkmElG
         jZhx2fl3N6JjW8oAirsGORl5rdkPaZvVirA51RPcnN15gF8vV1EvIYig8SGIa0yS0d7X
         sQTQ9HQcGYEHuclG2mDZ2DnF8tmyN3wEdXLIsJieWfAJeZfIOgu1ArWtoxTZ+C6c6jM9
         +JVvvA15w+6yoLxNxzioqtLn+5iHKG+XqTEgGeY8lM3oe0bBhQLxS8gbcJhFsnM4h2G/
         u48+jF11xnTR+eu0BRk5GJZ6DXMD97ZOD0qx3ZEmRPuBum/lz6/c3dW9Xvykrkk4YPNT
         6lEw==
X-Gm-Message-State: AOAM531pi62IrjC+R5KuKDiwyo0hwQxCEgQxnJ3MX69b9cVXTeCYzejz
	UxkEhCXXb1ZsLPHfm5kPKp0=
X-Google-Smtp-Source: ABdhPJxH8zSYogByNOvsgs6lTtA0c9i41JeDhHHP1hy+yBcjQRDsAEJTCOMkbVUf8nevBojiETIHAg==
X-Received: by 2002:a17:90b:60c:: with SMTP id gb12mr1956986pjb.125.1610737166130;
        Fri, 15 Jan 2021 10:59:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:5c85:: with SMTP id q127ls3844007pfb.11.gmail; Fri, 15
 Jan 2021 10:59:25 -0800 (PST)
X-Received: by 2002:a63:34d:: with SMTP id 74mr13895215pgd.388.1610737165593;
        Fri, 15 Jan 2021 10:59:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610737165; cv=none;
        d=google.com; s=arc-20160816;
        b=ix1tkfdY78F304oWqzpno0mWzRMZhbbR93vFE9qFIRvfRc6GgWDOIXH0a6vea/w2d5
         6aFnGDCQlGWHSQ8rfTWt1APrmN5adeGz4RuBZFh2Gi+y4KAXRP2dB/vEm1o1gIPxdq4F
         lmOLIqiWfDQ2JkyaI+o10Gh9PvYkL43GNBrB9Qz9fw8cgGi9dUUeaTXwqOToYUAHXrC/
         Pc8u4+vEJhLure72SBXCcrwUHxuP9N9fCqzqbNlrPQwrZa9BdhHBvApdV+5RnCI4wWH6
         JCEWQzqc3J6B8qYKmxR8I6FfUDXebDrx2mSV+0SHdVsfb4zxC7302iSSvdV537dC8Pre
         oeTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Mshc83SuDBHE0gmn74N7RVlZXLCk81hGs63s6jVC/4c=;
        b=Dmc53Hrzo5FwjL42AqfjI42nvdeiKisGgDz3tSDvAKAq9q5J2rZHAQlRPMsJWx3QtV
         4aiFTWm1Q76iUw4WEwXJ0c7g2WxWScSO1i+CWCw/clM3VtLz5hNY2PPdSpxawOWUY9CI
         mgERiu3eD5F4MdU/jWBDWIF71+dKTHy+ysSh8AFs2UUWek+WQTKbDsSd0f8pH5nPm2QL
         eLUVOZjSy1YbnW7abXnJCFaRP/Di2kyYYnI6GpYj6OucSs0BE9j7CwzwDmxDYe1SFwbo
         z1xJF6nvTVdQ1qFAZ5b75S2GS8vQmlR9CP2NrUvf0u0UHWNyQtX1kJQX/0mw/bzL7BMS
         Op0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=P4vaNsmj;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x532.google.com (mail-pg1-x532.google.com. [2607:f8b0:4864:20::532])
        by gmr-mx.google.com with ESMTPS id h11si1073629pjv.3.2021.01.15.10.59.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 10:59:25 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::532 as permitted sender) client-ip=2607:f8b0:4864:20::532;
Received: by mail-pg1-x532.google.com with SMTP id q7so6590725pgm.5
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 10:59:25 -0800 (PST)
X-Received: by 2002:a65:430b:: with SMTP id j11mr13654991pgq.130.1610737165149;
 Fri, 15 Jan 2021 10:59:25 -0800 (PST)
MIME-Version: 1.0
References: <20210115120043.50023-1-vincenzo.frascino@arm.com> <20210115120043.50023-2-vincenzo.frascino@arm.com>
In-Reply-To: <20210115120043.50023-2-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Jan 2021 19:59:14 +0100
Message-ID: <CAAeHK+xt4MWuxAxx_5nJNvC5_d7tvZDqPaA19bV0GNXsAzYfOA@mail.gmail.com>
Subject: Re: [PATCH v3 1/4] kasan, arm64: Add KASAN light mode
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=P4vaNsmj;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::532
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Fri, Jan 15, 2021 at 1:00 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> Architectures supported by KASAN HW can provide a light mode of
> execution. On an MTE enabled arm64 hw for example this can be identified
> with the asynch mode of execution.
> In this mode, if a tag check fault occurs, the TFSR_EL1 register is
> updated asynchronously. The kernel checks the corresponding bits
> periodically.
>
> KASAN requires a specific mode of execution to make use of this hw feature.
>
> Add KASAN HW light execution mode.
>
> Note: This patch adds the KASAN_ARG_MODE_LIGHT config option and the
> "light" kernel command line option to enable the described feature.
> This patch introduces the kasan_def.h header to make easier to propagate
> the relevant enumerations to the architectural code.
>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  arch/arm64/include/asm/memory.h    |  2 +-
>  arch/arm64/include/asm/mte-kasan.h |  5 +++--
>  arch/arm64/kernel/mte.c            |  2 +-
>  include/linux/kasan.h              |  1 +
>  include/linux/kasan_def.h          | 10 ++++++++++
>  mm/kasan/hw_tags.c                 | 19 ++++++++++++++++++-
>  mm/kasan/kasan.h                   |  2 +-
>  7 files changed, 35 insertions(+), 6 deletions(-)
>  create mode 100644 include/linux/kasan_def.h
>
> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
> index 18fce223b67b..3a7c5beb7096 100644
> --- a/arch/arm64/include/asm/memory.h
> +++ b/arch/arm64/include/asm/memory.h
> @@ -231,7 +231,7 @@ static inline const void *__tag_set(const void *addr, u8 tag)
>  }
>
>  #ifdef CONFIG_KASAN_HW_TAGS
> -#define arch_enable_tagging()                  mte_enable_kernel()
> +#define arch_enable_tagging(mode)              mte_enable_kernel(mode)
>  #define arch_init_tags(max_tag)                        mte_init_tags(max_tag)
>  #define arch_get_random_tag()                  mte_get_random_tag()
>  #define arch_get_mem_tag(addr)                 mte_get_mem_tag(addr)
> diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
> index 26349a4b5e2e..5402f4c8e88d 100644
> --- a/arch/arm64/include/asm/mte-kasan.h
> +++ b/arch/arm64/include/asm/mte-kasan.h
> @@ -9,6 +9,7 @@
>
>  #ifndef __ASSEMBLY__
>
> +#include <linux/kasan_def.h>
>  #include <linux/types.h>
>
>  /*
> @@ -29,7 +30,7 @@ u8 mte_get_mem_tag(void *addr);
>  u8 mte_get_random_tag(void);
>  void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
>
> -void mte_enable_kernel(void);
> +void mte_enable_kernel(enum kasan_hw_tags_mode mode);
>  void mte_init_tags(u64 max_tag);
>
>  #else /* CONFIG_ARM64_MTE */
> @@ -52,7 +53,7 @@ static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>         return addr;
>  }
>
> -static inline void mte_enable_kernel(void)
> +static inline void mte_enable_kernel(enum kasan_hw_tags_mode mode)
>  {
>  }
>
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index dc9ada64feed..53a6d734e29b 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -151,7 +151,7 @@ void mte_init_tags(u64 max_tag)
>         write_sysreg_s(SYS_GCR_EL1_RRND | gcr_kernel_excl, SYS_GCR_EL1);
>  }
>
> -void mte_enable_kernel(void)
> +void mte_enable_kernel(enum kasan_hw_tags_mode mode)
>  {
>         /* Enable MTE Sync Mode for EL1. */
>         sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 5e0655fb2a6f..026031444217 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -2,6 +2,7 @@
>  #ifndef _LINUX_KASAN_H
>  #define _LINUX_KASAN_H
>
> +#include <linux/kasan_def.h>
>  #include <linux/static_key.h>
>  #include <linux/types.h>
>
> diff --git a/include/linux/kasan_def.h b/include/linux/kasan_def.h
> new file mode 100644
> index 000000000000..0a55400809c9
> --- /dev/null
> +++ b/include/linux/kasan_def.h
> @@ -0,0 +1,10 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +#ifndef _LINUX_KASAN_DEF_H
> +#define _LINUX_KASAN_DEF_H
> +
> +enum kasan_hw_tags_mode {
> +       KASAN_HW_TAGS_SYNC,
> +       KASAN_HW_TAGS_ASYNC,
> +};
> +
> +#endif /* _LINUX_KASAN_DEF_H */
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 55bd6f09c70f..6c3b0742f639 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -22,6 +22,7 @@
>  enum kasan_arg_mode {
>         KASAN_ARG_MODE_DEFAULT,
>         KASAN_ARG_MODE_OFF,
> +       KASAN_ARG_MODE_LIGHT,
>         KASAN_ARG_MODE_PROD,
>         KASAN_ARG_MODE_FULL,
>  };
> @@ -60,6 +61,8 @@ static int __init early_kasan_mode(char *arg)
>
>         if (!strcmp(arg, "off"))
>                 kasan_arg_mode = KASAN_ARG_MODE_OFF;
> +       else if (!strcmp(arg, "light"))
> +               kasan_arg_mode = KASAN_ARG_MODE_LIGHT;

Hi Vincenzo,

I've just mailed the change to KASAN parameters [1] as discussed, so
we should use a standalone parameter here (kasan.trap?).

Thanks!

[1] https://lkml.org/lkml/2021/1/15/1242

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bxt4MWuxAxx_5nJNvC5_d7tvZDqPaA19bV0GNXsAzYfOA%40mail.gmail.com.
