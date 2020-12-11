Return-Path: <kasan-dev+bncBCRKNY4WZECBBTM5ZP7AKGQEMUX33YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id D99282D6DAF
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Dec 2020 02:43:42 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id m91sf5171026qva.21
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Dec 2020 17:43:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607651022; cv=pass;
        d=google.com; s=arc-20160816;
        b=c9Gk8br/jyfJASsKQXdcqNt826qQ1pKmFFRDEGNCfZmW4SIHTdufzZgtiwVjnvJWVc
         7Ujl8voB2GmThEODsALLjUWCkNuOk/ZhpW87e/zLkl8S/Wel8+5gJuf5jajQ2ujzQoNr
         hLrbcfiGCQnkonfVAkMDjUyp/RehATd4hx/5AD5J1vqNOYJBthuVLLgJxdJk4mMjGxtL
         cfcu2npHUmCJZqK9F+ZlFUY4+s/GVcv9uxMy3XvKCqwLphU/QlXzl4nYkW2o+tjZPuem
         ak8Wev/Z0gNiRxrnveHrvoBm848OpUaBKgn05pkga9AKrqHI0LlfUOjAWAgoqE+IN1am
         Q7iQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=5wGwOi09eSrcWxkPKHwfwQyn4+AnXTtn1gjjGWsHjr0=;
        b=Ah1QOgIOhqJrf1ys+JxBGnO+Z9SN1wftKEq8tkvokfjp7FoDeFALXDYupWCAS5lnwT
         L9ysqChhVtN746bUA1BX1eB0QDOk76FFbzWLPLLLaHJhGAN8gh0nKECk5MMDTP1gaKW3
         /Lb8JS8VcVSeGJuJTPhHj4DIueVgn2v1g13O1nKsT4cheAl7XX/FC3WSXiXe5KyKox0u
         4J84i61lyJD8IABaJarf3UnYCjbcNwARj7GcvmhA+WF53jQUg8AgFGCPCybWU9XOxQFu
         2gJyIUw3RTLOccGbeWMCCoHgHvJODOzwZzL5RI/fzSy1wOzTLkUF6Km7nVdNmpugzGx/
         gbEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=P444x4XO;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5wGwOi09eSrcWxkPKHwfwQyn4+AnXTtn1gjjGWsHjr0=;
        b=IdOHk0u+pvHcPnZqLrPTkbw8PrJa0S0B6+s0tcwdVlBa83nl5juaeO1Fjh6oM3k9wH
         gJQ2IuMH1BJHRGuFC88HG3TCLoNsQdcgkpmJZa7nb047LvmKK3HwXIBEI+EiWbfLWJg9
         D0A4I4Bf0gprO6OrPYVd1B2SOTs7LXBlwdQ+mugsvcMyCUpW9EsTlWCw3IhTe1TRhMdy
         UIofvf9ZY0+O5YTjjfhoizkeVs4QZyX/hzc7ax5oN0LWf3jYi6V6mLjXEl3W8VolDdrw
         P8UCqsoJG9kTH7aVlnYDS5PHwaZ/IDkhzgHuW7P7iq+lDnDKUVDS96zQb6PewUbNK67h
         ZeXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5wGwOi09eSrcWxkPKHwfwQyn4+AnXTtn1gjjGWsHjr0=;
        b=cPK85ekvzWeiCF+yOAi7ePxBAuJgi2IYy4VskrXXkmAYDHKPYsV3TSQMPMwlpxqJsX
         K6oq9XfrykUYHYA3Zq1AfrsuY1Sh2D/sUXxvrk6CoL0ZMxOrpgjQBCLmfaDeR5o7yIU7
         6WdUah7U8sMZ0JGAN/FLEO3Z1PZEg/NcDd6KtVX/uxYoBxkgjCGkDV5acCvaPyl9nD8g
         ZNFgumo6stLisSmOJ7YmZu4AH9Lh4smNVcepJsVSag9VYu9eH8x1r1iePezvCBzb0Opw
         fXaFfMUUQDnlHIEcdQyqbYm7HA/7DS9P8MeMPOe5n/tse2g6zqqk2Kr8LP/pygGmOqIg
         eVgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530+/YHPqF+IlEYbb0/RcFMdsRy4KMnvAOweCgpgmKuDiJcat3h1
	B/Xo/5N4FUVCKIiGhSxv0ZM=
X-Google-Smtp-Source: ABdhPJwDUTVR0SVsuNzhnwU9wunm55+zr/ENzATjo8+ul+RycnjI4r4HO7zEhNFtUlJXkAUtH4et/Q==
X-Received: by 2002:a37:a315:: with SMTP id m21mr12602839qke.279.1607651021989;
        Thu, 10 Dec 2020 17:43:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:26c6:: with SMTP id q64ls957355qtd.6.gmail; Thu, 10 Dec
 2020 17:43:41 -0800 (PST)
X-Received: by 2002:ac8:5a90:: with SMTP id c16mr11230315qtc.331.1607651021391;
        Thu, 10 Dec 2020 17:43:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607651021; cv=none;
        d=google.com; s=arc-20160816;
        b=pj9sqtB70OZxTpOSRgQ2bjP+4QzO73B4VKAV4SY6L5vrUG600wKMi0U3K0qcti4fMZ
         /ZBazocQOyD2HLAVWP6IKxiKv5spuCm2LXUYGxe4K3yvo4Fvi0f8byeZ8QPLFdT0KJyG
         cAXftQK6tsXZsCclrf8kYYqQDo2w3p8T5wspjoWq/Ni8Hyp7Q+hkLkeh6jcNT3S1yMUE
         fAqK9pZxVCJM+/8HIz04/WrYIDo+MLcIj93CB2hDN3mm1kS8QjS2nWgUUoObK2Yrj3/Q
         hvSRNsqgCXKJboWhTktgKX8FGxYOgmmIuxSlaKP8HTjayucMlJK9hTiLcG/k7iwm+/zV
         A6gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=pQu0LnGna1dWoV0eZjzZ6tJ6W057k3Sx2X7eDqkVyI4=;
        b=Az81Dpi8a4GSc3A+c5dURqz2sYEB9JyrcMmloB29ZXenIT+qrhaL/pPYhAMzXyitrf
         t4IOMoO3f2eUuRwp5f2s+YPgdz3feMGWmm5NJMj1K7npe5uT3PAZsAy0s4WrYfPX0vGH
         +fUZJ6ffxVz7Q3r1XSwv/nuGHp8YwKppprlXxL/+mQAEtF6snKd4Jos9ahiKddiJcs1x
         H6Y1ajFfPE/UQjxpcLdokOnXgV4BpvtSa2vzOJoVqfmQHzwh1ZW78aLnnfCw0E+PcYTD
         ghKfo8YHBcerIvItmGaJNpJGstE8INiwQC/2kWsddfmBJ8OAtBhHEKAzAtN6GLIQlGuw
         HxNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=P444x4XO;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id z94si196807qtc.0.2020.12.10.17.43.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Dec 2020 17:43:41 -0800 (PST)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id t37so6058798pga.7
        for <kasan-dev@googlegroups.com>; Thu, 10 Dec 2020 17:43:41 -0800 (PST)
X-Received: by 2002:a65:5bcd:: with SMTP id o13mr9267114pgr.81.1607651020439;
        Thu, 10 Dec 2020 17:43:40 -0800 (PST)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id x28sm7592780pff.182.2020.12.10.17.43.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Dec 2020 17:43:39 -0800 (PST)
Date: Thu, 10 Dec 2020 17:43:39 -0800 (PST)
Subject: Re: [PATCH 1/1] riscv: provide memmove implementation
In-Reply-To: <1606727599-8598-2-git-send-email-nylon7@andestech.com>
CC: aryabinin@virtuozzo.com, glider@google.com, dvyukov@google.com,
  kasan-dev@googlegroups.com, akpm@linux-foundation.org, Paul Walmsley <paul.walmsley@sifive.com>,
  aou@eecs.berkeley.edu, nickhu@andestech.com, nylon7@andestech.com, luc.vanoostenryck@gmail.com,
  greentime.hu@sifive.com, linux-riscv@lists.infradead.org, nylon7717@gmail.com, alankao@andestech.com,
  nick650823@gmail.com
From: Palmer Dabbelt <palmer@dabbelt.com>
To: nylon7@andestech.com
Message-ID: <mhng-d7cf2bc5-2d77-4da4-ad30-206628447bc1@palmerdabbelt-glaptop1>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b=P444x4XO;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Mon, 30 Nov 2020 01:13:19 PST (-0800), nylon7@andestech.com wrote:
> The memmove used by the kernel feature like KASAN.
>
> Signed-off-by: Nick Hu <nickhu@andestech.com>
> Signed-off-by: Nick Hu <nick650823@gmail.com>
> Signed-off-by: Nylon Chen <nylon7@andestech.com>
> ---
>  arch/riscv/include/asm/string.h |  8 ++---
>  arch/riscv/kernel/riscv_ksyms.c |  2 ++
>  arch/riscv/lib/Makefile         |  1 +
>  arch/riscv/lib/memmove.S        | 64 +++++++++++++++++++++++++++++++++
>  4 files changed, 71 insertions(+), 4 deletions(-)
>  create mode 100644 arch/riscv/lib/memmove.S
>
> diff --git a/arch/riscv/include/asm/string.h b/arch/riscv/include/asm/string.h
> index 924af13f8555..5477e7ecb6e1 100644
> --- a/arch/riscv/include/asm/string.h
> +++ b/arch/riscv/include/asm/string.h
> @@ -12,16 +12,16 @@
>  #define __HAVE_ARCH_MEMSET
>  extern asmlinkage void *memset(void *, int, size_t);
>  extern asmlinkage void *__memset(void *, int, size_t);
> -
>  #define __HAVE_ARCH_MEMCPY
>  extern asmlinkage void *memcpy(void *, const void *, size_t);
>  extern asmlinkage void *__memcpy(void *, const void *, size_t);
> -
> +#define __HAVE_ARCH_MEMMOVE
> +extern asmlinkage void *memmove(void *, const void *, size_t);
> +extern asmlinkage void *__memmove(void *, const void *, size_t);
>  /* For those files which don't want to check by kasan. */
>  #if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
> -
>  #define memcpy(dst, src, len) __memcpy(dst, src, len)
>  #define memset(s, c, n) __memset(s, c, n)
> -
> +#define memmove(dst, src, len) __memmove(dst, src, len)
>  #endif
>  #endif /* _ASM_RISCV_STRING_H */
> diff --git a/arch/riscv/kernel/riscv_ksyms.c b/arch/riscv/kernel/riscv_ksyms.c
> index 450492e1cb4e..5ab1c7e1a6ed 100644
> --- a/arch/riscv/kernel/riscv_ksyms.c
> +++ b/arch/riscv/kernel/riscv_ksyms.c
> @@ -11,5 +11,7 @@
>   */
>  EXPORT_SYMBOL(memset);
>  EXPORT_SYMBOL(memcpy);
> +EXPORT_SYMBOL(memmove);
>  EXPORT_SYMBOL(__memset);
>  EXPORT_SYMBOL(__memcpy);
> +EXPORT_SYMBOL(__memmove);
> diff --git a/arch/riscv/lib/Makefile b/arch/riscv/lib/Makefile
> index 47e7a8204460..ac6171e9c19e 100644
> --- a/arch/riscv/lib/Makefile
> +++ b/arch/riscv/lib/Makefile
> @@ -2,5 +2,6 @@
>  lib-y			+= delay.o
>  lib-y			+= memcpy.o
>  lib-y			+= memset.o
> +lib-y			+= memmove.o
>  lib-$(CONFIG_MMU)	+= uaccess.o
>  lib-$(CONFIG_64BIT)	+= tishift.o
> diff --git a/arch/riscv/lib/memmove.S b/arch/riscv/lib/memmove.S
> new file mode 100644
> index 000000000000..07d1d2152ba5
> --- /dev/null
> +++ b/arch/riscv/lib/memmove.S
> @@ -0,0 +1,64 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +
> +#include <linux/linkage.h>
> +#include <asm/asm.h>
> +
> +ENTRY(__memmove)
> +WEAK(memmove)
> +        move    t0, a0
> +        move    t1, a1
> +
> +        beq     a0, a1, exit_memcpy
> +        beqz    a2, exit_memcpy
> +        srli    t2, a2, 0x2
> +
> +        slt     t3, a0, a1
> +        beqz    t3, do_reverse
> +
> +        andi    a2, a2, 0x3
> +        li      t4, 1
> +        beqz    t2, byte_copy
> +
> +word_copy:
> +        lw      t3, 0(a1)
> +        addi    t2, t2, -1
> +        addi    a1, a1, 4
> +        sw      t3, 0(a0)
> +        addi    a0, a0, 4
> +        bnez    t2, word_copy
> +        beqz    a2, exit_memcpy
> +        j       byte_copy
> +
> +do_reverse:
> +        add     a0, a0, a2
> +        add     a1, a1, a2
> +        andi    a2, a2, 0x3
> +        li      t4, -1
> +        beqz    t2, reverse_byte_copy
> +
> +reverse_word_copy:
> +        addi    a1, a1, -4
> +        addi    t2, t2, -1
> +        lw      t3, 0(a1)
> +        addi    a0, a0, -4
> +        sw      t3, 0(a0)
> +        bnez    t2, reverse_word_copy
> +        beqz    a2, exit_memcpy
> +
> +reverse_byte_copy:
> +        addi    a0, a0, -1
> +        addi    a1, a1, -1
> +
> +byte_copy:
> +        lb      t3, 0(a1)
> +        addi    a2, a2, -1
> +        sb      t3, 0(a0)
> +        add     a1, a1, t4
> +        add     a0, a0, t4
> +        bnez    a2, byte_copy
> +
> +exit_memcpy:
> +        move a0, t0
> +        move a1, t1
> +        ret
> +END(__memmove)

Thanks, this is on for-next.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-d7cf2bc5-2d77-4da4-ad30-206628447bc1%40palmerdabbelt-glaptop1.
