Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFPWU2AAMGQEGHR33GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id EF8E72FF206
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 18:34:13 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id z8sf1584064wrh.5
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 09:34:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611250453; cv=pass;
        d=google.com; s=arc-20160816;
        b=UvTwGTkdBX8jbyD2j2VOtqPNLQmmzRCCycqHL9hXVJQBxtdGPuMy8QJvrySNumOqX+
         OxznmSa7EQxA09f7q/5Go4HotedBkUdqjXJevxR4+yubVlU5Lqv5wtHPI9aip7angQsG
         0hkVM/mL1hTifudLzRSDHNNE/wP0cCTK34ldz9kbchc/mq+IKtpc4k3T8CxqOEXndlSe
         qBKueEIxSTYZUH2IkCwCDu8fxmxleS38Ln09OFbp4bwj08I6zCkigVOtjDzkcdB9IEjM
         HykxK/aOD//7uPcsZZPBdePG6StJYZLPae7QhJP6+SzwHpjLRESWCpRsw+bOS4Ub6UHa
         gWAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PE8rNXzuvD95nZulaF8v5wUXYvbeZx2KcfvB4nAGQ70=;
        b=nNjUh5K3LZej6ws0XJvZzs+tC6xSAmO0j5pY287kiUv1MCCyd2NTSilL0yQvqnSlC4
         xdreYSG73eIrdbFepdWdx7IKwtIlGqsJfMsjDXZe+/gObhj6lJgSEHNGjWUpdmd8iPGu
         u7xxVLP/NzX9cQidN3+c5rHu9ZE/KZaupAjljfGv3avWNmtUm+UMfxZXyNu2HRnGiCY+
         am5BfLzWLHoDzKz8oIcmTyPKi6wZXu7nA5+pLF1Dnh8E1q4rk+YSYH5pFSiDdQYDIcXb
         rlmRfeCMhdlYQHOWk4Zcwuw74CNEOFVDGvXoogDqzdrOhKIsqjSCx+2CX3zXsNKd8APu
         qT+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=l0fIIbSN;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PE8rNXzuvD95nZulaF8v5wUXYvbeZx2KcfvB4nAGQ70=;
        b=YxjUKRXnfA9k/DgtqUVGzbo3CDzePH+TDHE0mJs3LVrETCFix/Im4C9oFMcYu9PcMv
         H+NayLntnEGT1HSxc3dnVJx5QloJMQhX+iHJJ7hJj9QYZmNMfG7rkKBTMsalCO47r2ZG
         ScfnGYRU4J5s5TKptWCsrOqY/tlCNSBCgsgeT6C0pILYmRj4YJvC9TAsVdSrLfDw0Qe8
         X6knzBv3UJG79XFG6FpUF/MY8uWVpbQ7MLo/V1KOCWcukYRDPfLyf/JOtCxFyF/AR94x
         yyuTeX0M3PLdON1AF5xOcka7CM+nhvN7eBpYWrYxClk3amAOh19LoUqrYWlNMccUzsYO
         LPkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PE8rNXzuvD95nZulaF8v5wUXYvbeZx2KcfvB4nAGQ70=;
        b=LXTDku9EgZqFZw1Vk5z4uYuhxufBq8Ahl1iOiUp6GldTJKMYGKaQrLMnxrXnHXyjMh
         YVLo88ozQStEM8M7o9HeMFL9Qy5sHOwpw4kjLW7i1RYKuOAT7wBEz+r9zFfO4woARpx/
         9T0vGHveSRDMpfyXlkDQEoOUDyaiPGChX2cQ9WbTEbLJAEZ5pe197l7n8CfisGwHuJfq
         0pUbPNrGOGfW48t7gU9GNztKYSFlWrFSESg/RIcCk+kizC3vIFp6XOXaLJqGZzdZmGks
         pr5HvUSFRGPOOZkFqLstF9Wn0SuRVC8kJeS6JHeVfLEwwegFP9xImgHBD8Bze8NRmk84
         JRFQ==
X-Gm-Message-State: AOAM531CDv4/yGe1iJ8/J/9jz1N/zD1BhQac9LkcIr7eS9ecWiGX9X3U
	n7gDfOBItMaakqY5BGmkTL8=
X-Google-Smtp-Source: ABdhPJx6oDTElXtKKSl9pX5tbvECkutHoR9GtEyiR/Jk9Kv/myIoh4qgnTOCTByW/hjVSlOZS3dAZg==
X-Received: by 2002:a1c:3c04:: with SMTP id j4mr382338wma.147.1611250453708;
        Thu, 21 Jan 2021 09:34:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e608:: with SMTP id p8ls2883035wrm.2.gmail; Thu, 21 Jan
 2021 09:34:12 -0800 (PST)
X-Received: by 2002:adf:ded0:: with SMTP id i16mr556580wrn.264.1611250452751;
        Thu, 21 Jan 2021 09:34:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611250452; cv=none;
        d=google.com; s=arc-20160816;
        b=SV/Pi+2uAjx1Q0USde0VaDc/eWzwl3alQA/ZDorMA6OniyQnQ+xFhd1GF0hmBrBHc7
         doWU/eXWKf3HZgeXKdb3/6x7gH+/IahIwWfSsF/JtJKhvOdjkbNL7IHvwgs8w6IpOYAc
         TXABl7iMvtQtYqjsnDgjrdXQRJbPUCaPkFYnxeSaaP6UjkLDVpc3JUWn/Z98IeBXBFjy
         YQ6rSo20BVruR1LYw0JNpOrCvkM7OQ69QTmaxaq/iKFotdi3sWCogPfGP4XDIA+uLoaE
         Fv+USLL0jThtFWEauve7xpA5qNaPMzb1fTeF/9MQJqRPHZFx2zvuIdBsAMNUPcYMakVb
         KIFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kWpM9JlBh2PjRj9rPNDgayDsvoJuIDrT02opFblBIwI=;
        b=RA0Ss75sJFYuKI24957pe8ImgeTrleWYB3qDQkWzMXpReQoHAYe2PKd+mAoVTby3RX
         MLe7Sven5y/jkkLZvez6ELwUY249fF9fD0EFN86nhslQ+6vPEMhx5Qi6V6LDG/1YmVTV
         ULd8AIyjz38e4CKCu9Ea9uZFDcjrgmiKvSPQRbkEuptEVaW/zAiqVbYd+Tl9CfGbAHta
         Ye6z/zmDwXR4uiC4fi/6L4XZjSoCFKjh28TQh7tFZRCj7BXxEcJ/DQIJzVKbr1vetHFK
         igIcwOgoIpxne2iTVhOapTN79xM6bEO4sgH36WQz1D+rlYmvA3PCUERr34H8a5cgiik7
         hCaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=l0fIIbSN;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12f.google.com (mail-lf1-x12f.google.com. [2a00:1450:4864:20::12f])
        by gmr-mx.google.com with ESMTPS id 7si229892wrp.3.2021.01.21.09.34.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Jan 2021 09:34:12 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::12f as permitted sender) client-ip=2a00:1450:4864:20::12f;
Received: by mail-lf1-x12f.google.com with SMTP id q12so3624527lfo.12
        for <kasan-dev@googlegroups.com>; Thu, 21 Jan 2021 09:34:12 -0800 (PST)
X-Received: by 2002:a05:6512:788:: with SMTP id x8mr148696lfr.250.1611250452285;
 Thu, 21 Jan 2021 09:34:12 -0800 (PST)
MIME-Version: 1.0
References: <20210121163943.9889-1-vincenzo.frascino@arm.com> <20210121163943.9889-3-vincenzo.frascino@arm.com>
In-Reply-To: <20210121163943.9889-3-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Jan 2021 18:34:00 +0100
Message-ID: <CAAeHK+z3QrZr3OWcvetyChk9GMPuBZVTBjWoqQB45ZSFBOJHwQ@mail.gmail.com>
Subject: Re: [PATCH v5 2/6] kasan: Add KASAN mode kernel parameter
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
 header.i=@google.com header.s=20161025 header.b=l0fIIbSN;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::12f
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

On Thu, Jan 21, 2021 at 5:39 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> Architectures supported by KASAN_HW_TAGS can provide a sync or async mode
> of execution. On an MTE enabled arm64 hw for example this can be identified
> with the synchronous or asynchronous tagging mode of execution.
> In synchronous mode, an exception is triggered if a tag check fault occurs.
> In asynchronous mode, if a tag check fault occurs, the TFSR_EL1 register is
> updated asynchronously. The kernel checks the corresponding bits
> periodically.
>
> KASAN requires a specific kernel command line parameter to make use of this
> hw features.
>
> Add KASAN HW execution mode kernel command line parameter.
>
> Note: This patch adds the kasan.mode kernel parameter and the
> sync/async kernel command line options to enable the described features.
>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  Documentation/dev-tools/kasan.rst |  7 +++++++
>  lib/test_kasan.c                  |  2 +-
>  mm/kasan/hw_tags.c                | 27 ++++++++++++++++++++++++++-
>  mm/kasan/kasan.h                  |  6 ++++--
>  4 files changed, 38 insertions(+), 4 deletions(-)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index e022b7506e37..7e4a6e0c9f57 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -161,6 +161,13 @@ particular KASAN features.
>
>  - ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
>
> +- ``kasan.mode=sync`` or ``=async`` controls whether KASAN is configured in
> +  synchronous or asynchronous mode of execution (default: ``sync``).
> +  ``synchronous mode``: an exception is triggered if a tag check fault occurs.

Synchronous mode: a bad access is detected immediately when a tag
check fault occurs.

(No need for `` here, "synchronous mode" is not an inline snippet.)

> +  ``asynchronous mode``: if a tag check fault occurs, the information is stored
> +  asynchronously in hardware (e.g. in the TFSR_EL1 register for arm64). The kernel
> +  checks the hardware location and reports an error if the fault is detected.

Asynchronous mode: a bad access detection is delayed. When a tag check
fault occurs, the information is stored in hardware (in the TFSR_EL1
register for arm64). The kernel periodically checks the hardware and
only reports tag faults during these checks.

> +
>  - ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
>    traces collection (default: ``on`` for ``CONFIG_DEBUG_KERNEL=y``, otherwise
>    ``off``).
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index d16ec9e66806..7285dcf9fcc1 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -97,7 +97,7 @@ static void kasan_test_exit(struct kunit *test)
>                         READ_ONCE(fail_data.report_found));     \
>         if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {                 \
>                 if (READ_ONCE(fail_data.report_found))          \
> -                       hw_enable_tagging();                    \
> +                       hw_enable_tagging_sync();               \
>                 migrate_enable();                               \
>         }                                                       \
>  } while (0)
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index e529428e7a11..224a2187839c 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -25,6 +25,11 @@ enum kasan_arg {
>         KASAN_ARG_ON,
>  };
>
> +enum kasan_arg_mode {
> +       KASAN_ARG_MODE_SYNC,
> +       KASAN_ARG_MODE_ASYNC,

For other modes I explicitly added a _DEFAULT option first. It makes
sense to do this here as well for consistency.

> +};
> +
>  enum kasan_arg_stacktrace {
>         KASAN_ARG_STACKTRACE_DEFAULT,
>         KASAN_ARG_STACKTRACE_OFF,
> @@ -38,6 +43,7 @@ enum kasan_arg_fault {
>  };
>
>  static enum kasan_arg kasan_arg __ro_after_init;
> +static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
>  static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
>  static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
>
> @@ -68,6 +74,21 @@ static int __init early_kasan_flag(char *arg)
>  }
>  early_param("kasan", early_kasan_flag);
>
> +/* kasan.mode=sync/async */
> +static int __init early_kasan_mode(char *arg)
> +{
> +       /* If arg is not set the default mode is sync */
> +       if ((!arg) || !strcmp(arg, "sync"))
> +               kasan_arg_mode = KASAN_ARG_MODE_SYNC;
> +       else if (!strcmp(arg, "async"))
> +               kasan_arg_mode = KASAN_ARG_MODE_ASYNC;
> +       else
> +               return -EINVAL;
> +
> +       return 0;
> +}
> +early_param("kasan.mode", early_kasan_mode);
> +
>  /* kasan.stacktrace=off/on */
>  static int __init early_kasan_flag_stacktrace(char *arg)
>  {
> @@ -115,7 +136,11 @@ void kasan_init_hw_tags_cpu(void)
>                 return;
>
>         hw_init_tags(KASAN_TAG_MAX);
> -       hw_enable_tagging();
> +

Let's add a comment:

/* Enable async mode only when explicitly requested through the command line. */

> +       if (kasan_arg_mode == KASAN_ARG_MODE_ASYNC)
> +               hw_enable_tagging_async();
> +       else
> +               hw_enable_tagging_sync();
>  }
>
>  /* kasan_init_hw_tags() is called once on boot CPU. */
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 07ef7fc742ad..3923d9744105 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -294,7 +294,8 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>  #define arch_set_mem_tag_range(addr, size, tag) ((void *)(addr))
>  #endif
>
> -#define hw_enable_tagging()                    arch_enable_tagging()
> +#define hw_enable_tagging_sync()               arch_enable_tagging_sync()
> +#define hw_enable_tagging_async()              arch_enable_tagging_async()
>  #define hw_init_tags(max_tag)                  arch_init_tags(max_tag)
>  #define hw_set_tagging_report_once(state)      arch_set_tagging_report_once(state)
>  #define hw_get_random_tag()                    arch_get_random_tag()
> @@ -303,7 +304,8 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>
>  #else /* CONFIG_KASAN_HW_TAGS */
>
> -#define hw_enable_tagging()
> +#define hw_enable_tagging_sync()
> +#define hw_enable_tagging_async()
>  #define hw_set_tagging_report_once(state)
>
>  #endif /* CONFIG_KASAN_HW_TAGS */
> --
> 2.30.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bz3QrZr3OWcvetyChk9GMPuBZVTBjWoqQB45ZSFBOJHwQ%40mail.gmail.com.
