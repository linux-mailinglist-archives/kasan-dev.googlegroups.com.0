Return-Path: <kasan-dev+bncBDW2JDUY5AORBRGK46FAMGQEUHTWGPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B87A42030E
	for <lists+kasan-dev@lfdr.de>; Sun,  3 Oct 2021 19:15:50 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id x5-20020a1709028ec500b0013a347b89e4sf6362542plo.3
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Oct 2021 10:15:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633281349; cv=pass;
        d=google.com; s=arc-20160816;
        b=XySedEXE7CKo2XU1gDojehgtstO8sNszhS6nSE88dpWa7M6irRLfUsZoNX9sJaCtZy
         uvXvyTyfG1ZRiN3l6WnsDv51Iy+/jK10a0a9cnrNPnNwBFnQufTVxmxipD67W9P0MeiM
         Hj1xraq4MO1ssLv7g0biH86DTOqRpNWwUx3bAZ8eytR7DFgQhUEc9nc9/7X4gwWrUqGr
         409rnKd4dlLx6fCmX7XJoJgVz4yG9z2p7CdtM+78wu7YynQVCQmWOF53tOq6nPGGRWye
         nD1aMbxlWtk9HzUsDqOrwe270yKLQPg/PamJXu7sKsVgRXFTAJ8E/dz6Uphecr7tFdys
         8UJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=h0PBWsNNDOXta6BM9rC4HAAFi7SeLK2zaaX0Q0mDcUI=;
        b=WhenLi8Reoty9FGNzqNoFIvaBzWvNvifqw9V7xprX52nNiCLmo7RwefbHsHUzmK9Rb
         En6DAF0wSVB4YDb9WCUvjB0ZEnK9CPOk3edtrwi8QawBv+PYgo5GgFAxIOnIhVTnZ3RK
         uKZIV6Pltdf4TmuP/4GP0hBa8D6/dT7jnXW505E4iw+cRGCsGFlzqSXT5XadmrcNRH5e
         HMfMSqlnwKL5WIxH07JZRflI/gp05rllgWUXFB8Ptk2S0bRqgTSFt5RFlp3I9flaXG61
         95oG+RLxEYttgQg+WntprgGt32ZFxEx3Hkgq+JM8Q3tSAVTS6LOBITk3EFmSjQ2jA9kz
         WNAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=emCHt75x;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::136 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h0PBWsNNDOXta6BM9rC4HAAFi7SeLK2zaaX0Q0mDcUI=;
        b=PAscavZfdHIRXd6g+YkpInPHj3hUFPDCk+f30BvCuOlQ2namtUJadj3Deri0dlGwlf
         1KV6OTKw142+5ZHSfvR/IHGgQca5PAeHWNDAU2aWfXSEl50KyHHTGK0bQriAGnRBkxkV
         vw93wh2y0AKVSRR9YiBXdHO6hh+yh7Cz7d1JczzgTY35dVdYpWbZLv41F7K350o9J2yv
         nzHxknlQP2whnNHpaxT0yUhqQZQNacDUpN0n+UDG0+9aufto8bSPgoRgqVp4YNfQQmOa
         4m5LtwySej6fm0tTZu9BXe7sVHXx4aMCMMTzHQRsTtIKbRxw7uSCPUR8tpYGDxjW7xAb
         mlCg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h0PBWsNNDOXta6BM9rC4HAAFi7SeLK2zaaX0Q0mDcUI=;
        b=dhcc3zNKMZmIYPb7YMnGSR3srDRThO3C7dpb2aRQSnwVvz8WC/C2rGArxLuLJlgXb8
         VjpLqikTVOxQjH+am8imtvc6Xh68dbVH7eyPAtuEer4eRzQlLo9k36eFE7u+FOh/9hTg
         OaZF536gI6rabEMrJN48qERfSDSqVfXl8yAYCWg2a9d5FJPowF+G649i1Jpyid86iuJk
         YVp8IZ2Z5zOqA8eu3DdiRM/o8fwKwMqHiyfVMwaHdP5draL8sv9S0QLPclABcPjjwgel
         0qWtFb/vVicYh5SfAF+bLh5nTgILio/UfICzhmTP7IjqC5YggPO/ouWnqnTQSr4leJ5i
         AckA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h0PBWsNNDOXta6BM9rC4HAAFi7SeLK2zaaX0Q0mDcUI=;
        b=LwvhZxb9zOj91d6q3SmFvK/FfrYZviVlmnxtv54hIMJM1KZmNGIKsYbhg9rtd9Al7w
         mV1l2A/dWlGNQmV6PNTi7R7pyitwtc77BUuq/MYlphuXApGCyZa3FOZIpezms2XJxT/e
         JlyglPPwLn6XoJ5Fi/jheouTDpi6+7p40dC4RXMRdz1IvYW07iOpvJ8DYL9TY4IqZrYm
         +qQQIDl0ZimOF64boVIDF4IRP279M+LBR+VAFnYpv9yOzPDmAjKocD6r84svgAMFDmcq
         OOzfF0rCGNSQh2vFymL12Bh6/NZz2ypRSWNohK59tG6pSYv7fZdp7iGCT864OW1M7Xke
         ltlw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532npB7sVi/sk117uZYMdTF4cWlaMZGL4DeiXkfuOM0PNuYq4bX+
	/Ue3mLONCsMM66skIeaH87w=
X-Google-Smtp-Source: ABdhPJzXHJQTci5NK1i/iIoiJr2vaakUmAP0B4+kj14WiiClQfn/kdskJNdAAqlvoWINUgN8e8zNow==
X-Received: by 2002:a17:902:dacf:b0:13e:ab53:87dc with SMTP id q15-20020a170902dacf00b0013eab5387dcmr5589169plx.78.1633281348819;
        Sun, 03 Oct 2021 10:15:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6643:: with SMTP id z3ls5457311pgv.3.gmail; Sun, 03 Oct
 2021 10:15:48 -0700 (PDT)
X-Received: by 2002:a65:6a0a:: with SMTP id m10mr7363582pgu.82.1633281348278;
        Sun, 03 Oct 2021 10:15:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633281348; cv=none;
        d=google.com; s=arc-20160816;
        b=imtZfLt5atAEmjPaUCXGaPAbA+phIeSGKuouCfGdWqveis1B6v1ngPtB8wTCg4P3zC
         cXGGxP3K9yn8Pyrgf+6u4qEwOGrl8L2nRvIYpBnADs7BtdYF1dmr/cSutjjdJfm57gFt
         NtDfgW2TbVcLF/lL3MVm6sHrvi6au5skHjLscY1p1OtVxLWettP8wlu24hwVmEuuNgF3
         9xsF1Oy23KoQ6WwySoa+K9VZeJ4MrwQxukDAwyDPn4fHihZPA6/Fg/soR4cRxTIsT/zV
         S8Fyzy31gm4Rq/i4Mo93eUXjGzPo9XblmMxWah8KB9Xq+h//Jgj/sfur3hVeoTzXlAwB
         UiEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+JhNHAkQYs0q543UXbdIS0YUcmawVIjR2itOxVo67Ac=;
        b=ZZhvt1GwaAfqHy7jE4ZeYD8jt/ttK7zbKf8d7LeG4d8u0Rca/zMQhbvZSSwgg7KBY6
         8pFQ75+i3UEfHltHNqc65QaMYJ8ZO/T3vMDi9f4jz4euU9iISxlL607CgaEbACJMzBUP
         Wwdtzw5Qv77oJNUKQfpeB7O5qahFPuav2VbeMJ454sJAz4iBkMmgMt2lwAwkWspmzlCD
         1qMnWVN6weLnChJxu6uUAtoS0YbtAtvY7TFWGi7GCAG7EjlOkAhwGFSe8gXDUPK+Q/x9
         2lBqICy988nN6uJM5gW6UcMdZeQ86KhRFiec2CGl1DAZrvkyeMclt069/dVq0C8HJW4W
         i7lQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=emCHt75x;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::136 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x136.google.com (mail-il1-x136.google.com. [2607:f8b0:4864:20::136])
        by gmr-mx.google.com with ESMTPS id b15si435637pjp.1.2021.10.03.10.15.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 03 Oct 2021 10:15:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::136 as permitted sender) client-ip=2607:f8b0:4864:20::136;
Received: by mail-il1-x136.google.com with SMTP id y15so15877550ilu.12
        for <kasan-dev@googlegroups.com>; Sun, 03 Oct 2021 10:15:48 -0700 (PDT)
X-Received: by 2002:a92:ca4a:: with SMTP id q10mr360097ilo.233.1633281348059;
 Sun, 03 Oct 2021 10:15:48 -0700 (PDT)
MIME-Version: 1.0
References: <20210913081424.48613-1-vincenzo.frascino@arm.com> <20210913081424.48613-5-vincenzo.frascino@arm.com>
In-Reply-To: <20210913081424.48613-5-vincenzo.frascino@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 3 Oct 2021 19:15:37 +0200
Message-ID: <CA+fCnZeW35+ZmvM6SxZSb_NAMqsK42Ds_ADVKeVkfs9MT=Aovg@mail.gmail.com>
Subject: Re: [PATCH 4/5] arm64: mte: Add asymmetric mode support
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=emCHt75x;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::136
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Sep 13, 2021 at 10:14 AM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> MTE provides an asymmetric mode for detecting tag exceptions. In
> particular, when such a mode is present, the CPU triggers a fault
> on a tag mismatch during a load operation and asynchronously updates
> a register when a tag mismatch is detected during a store operation.
>
> Add support for MTE asymmetric mode.
>
> Note: If the CPU does not support MTE asymmetric mode the kernel falls
> back on synchronous mode which is the default for kasan=on.
>
> Cc: Will Deacon <will@kernel.org>
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  arch/arm64/include/asm/memory.h    |  1 +
>  arch/arm64/include/asm/mte-kasan.h |  5 +++++
>  arch/arm64/kernel/mte.c            | 26 ++++++++++++++++++++++++++
>  3 files changed, 32 insertions(+)
>
> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
> index f1745a843414..1b9a1e242612 100644
> --- a/arch/arm64/include/asm/memory.h
> +++ b/arch/arm64/include/asm/memory.h
> @@ -243,6 +243,7 @@ static inline const void *__tag_set(const void *addr, u8 tag)
>  #ifdef CONFIG_KASAN_HW_TAGS
>  #define arch_enable_tagging_sync()             mte_enable_kernel_sync()
>  #define arch_enable_tagging_async()            mte_enable_kernel_async()
> +#define arch_enable_tagging_asymm()            mte_enable_kernel_asymm()
>  #define arch_force_async_tag_fault()           mte_check_tfsr_exit()
>  #define arch_get_random_tag()                  mte_get_random_tag()
>  #define arch_get_mem_tag(addr)                 mte_get_mem_tag(addr)
> diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
> index 22420e1f8c03..478b9bcf69ad 100644
> --- a/arch/arm64/include/asm/mte-kasan.h
> +++ b/arch/arm64/include/asm/mte-kasan.h
> @@ -130,6 +130,7 @@ static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag,
>
>  void mte_enable_kernel_sync(void);
>  void mte_enable_kernel_async(void);
> +void mte_enable_kernel_asymm(void);
>
>  #else /* CONFIG_ARM64_MTE */
>
> @@ -161,6 +162,10 @@ static inline void mte_enable_kernel_async(void)
>  {
>  }
>
> +static inline void mte_enable_kernel_asymm(void)
> +{
> +}
> +
>  #endif /* CONFIG_ARM64_MTE */
>
>  #endif /* __ASSEMBLY__ */
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 9d314a3bad3b..ef5484ecb2da 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -137,6 +137,32 @@ void mte_enable_kernel_async(void)
>         if (!system_uses_mte_async_mode())
>                 static_branch_enable(&mte_async_mode);
>  }
> +
> +void mte_enable_kernel_asymm(void)
> +{
> +       if (cpus_have_cap(ARM64_MTE_ASYMM)) {
> +               __mte_enable_kernel("asymmetric", SCTLR_ELx_TCF_ASYMM);
> +
> +               /*
> +                * MTE asymm mode behaves as async mode for store
> +                * operations. The mode is set system wide by the
> +                * first PE that executes this function.
> +                *
> +                * Note: If in future KASAN acquires a runtime switching
> +                * mode in between sync and async, this strategy needs
> +                * to be reviewed.
> +                */
> +               if (!system_uses_mte_async_mode())
> +                       static_branch_enable(&mte_async_mode);

This part is confusing: mte_async_mode gets enabled for the asymm
mode, which contradicts the comment next to the mte_async_mode
definition.

> +       } else {
> +               /*
> +                * If the CPU does not support MTE asymmetric mode the
> +                * kernel falls back on synchronous mode which is the
> +                * default for kasan=on.
> +                */
> +               mte_enable_kernel_sync();
> +       }
> +}
>  #endif
>
>  #ifdef CONFIG_KASAN_HW_TAGS
> --
> 2.33.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeW35%2BZmvM6SxZSb_NAMqsK42Ds_ADVKeVkfs9MT%3DAovg%40mail.gmail.com.
