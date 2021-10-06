Return-Path: <kasan-dev+bncBDW2JDUY5AORBA6Y7CFAMGQEJCGTZCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 649DA424A53
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Oct 2021 01:06:44 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id m10-20020a4a240a000000b002adae1d3d06sf2590090oof.9
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Oct 2021 16:06:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633561603; cv=pass;
        d=google.com; s=arc-20160816;
        b=EplHwECRJ7h8nUiM9t3wGbbD8K2PhI1YyZXAkJ82O1hY4Q8ijbHCfatuLX6qRAYYIH
         PSiwtEj4PbrFopH3sPvZrjttP1TQmtXLNeUkZRAQ2nUZiG+Z+gG5XmAhSTSSmRGUdj21
         x8mif1OlmEcQkpY5dzV3XLivnDFiBXP9RqtSo+ussuUUX+NYyMT3KiL2ajQaji5zbd12
         F/7OHh6rq2VpcgpYAZPdXOktyJDBfEDYF08K517N27SabMGjMsl4tQd2P6P+cI0bS/Fh
         iSVXVRltGpHfvYQLRgLcgixboM3k62kgRcQc6OK38btdWlHD6bZIp6AUEFafP0+jVwNl
         ckxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=/kvhiwHhbmi5Jtzqp6xofXhqisH/BLlGSmQSPnVsRWo=;
        b=RpkSXl+wAgBoQeqOPK9D0v9OBHiLdC3AN8XAxklPChzTOTVo8gW5n3QhobVDk15tts
         0kTGOKKjzwY+R6hSA0qDw8pp1qyqTcXfyC7ryntt9cRKijaPqWbXxwskrw9mZU22FUUP
         zi2k6J2zZs8TOv1Sgl7Y2UfRSBBrXXH+8pD/HN9pfIJqPDQ/l0cDiqZkdtnblI/LWyk9
         vKnHD/D7aTgo17rAF3LJU6ebGb7sMcla4UcAA8YBqBAC6S3IY/fCtrz1woRR/lBAVzE3
         G93L+ieFxrsForzgGryT55TZHvEamMTqafgD/CCKhsVC7+g/ZIUo337KUxbO8V4ehygM
         BKCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=DCHttdwY;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::133 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/kvhiwHhbmi5Jtzqp6xofXhqisH/BLlGSmQSPnVsRWo=;
        b=aj2VOCeC0H9PFAUH64j/Esig+FTRKZxFcQ7qiRyqOwTIijoUhyKzEnygfWjak7PF1k
         uTVluAClxavlIhGVc0HE+yVb6+0iiTsqz9WmXnKlSyBrIvDdsTjRby/ImXW/2Kfx6Qav
         2t+gA9h0hqDBvuno0EmTB3Qsc3AZ7J532xbIbVhutvNceXV+w3EAPWg0baWr0cUM4kmj
         YAVqzTKX+azY2Fj0tfLnb/pkaGayeD/QNFL7uh3H3IwRYJdK60fzATHGYrmUxFrX0znM
         jqN6AUd+p4oM61yP/h2WcUZ5i6vfQkAnUSU88Ql5bI+8unrSiJvmJTBAtyO945r0Y0JQ
         vMfg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/kvhiwHhbmi5Jtzqp6xofXhqisH/BLlGSmQSPnVsRWo=;
        b=OfAK101BHMR5G9/qloo9TmvgHZwTnUBCasDVdnua3fgWemw/SvFbFEM8n5hU3D2niO
         8lOTf823nVEtoDQ3pzX21PT1FABbJwG7UFcRBzxA+V2NVXW/cefyGFpT+prC5Ec9nAO9
         5PaBjni3XVmLAFEe2g8oI5AIFk1Nt+CdzrOJ51eOtt9mSPTkmZuXc6sIUkWUNrx6o5Rn
         VMajVovKsI8JSgIADXEKklcHlLpl71DiBdPfiiVnxbeUjnhWDMl/6rOBJNPfeK35C6h1
         EgxmXuiLDYgGaFSrlkDSBs7dFS+Qv+gMh8fJ4elYmBM7+JS4VuPUDmwtmynXLTbmZrAO
         BD/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/kvhiwHhbmi5Jtzqp6xofXhqisH/BLlGSmQSPnVsRWo=;
        b=E4I6YJwrSlURuAdkLLD3kHAc8AdnWKnktnt5icUlTwGndBM5HCt4uNy4jtHkavt+bE
         dvHhOTBWAft9Z1dlKeCorMUyXmyv2SkOgggFrhx6cq/plShvoyejHziAhdDt0E/ZdFJP
         iUwK4zB9jIGZOcVCgcKNQDQN2Eai0OToouRyxQNZlfWRdPlJJk7xMKVulglExYA0q6Oa
         /fliYjhfArDrqrop0TPiqWTrDT7vxD1Kg7UxD6njEqlbW7BAzkgL8pRIpG2VRvZi3iGv
         gMpt4bqK+lmGXik7GJku49LMH+BC1SAkrTJC0zXPcw/qQZ2culWAfLC6ySqpkpyexTtb
         nUfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5331fvmi82bFyCu6mG/QPTvxURDcc/dcoJEIX0hbEZIvD2By02Wu
	lMtewLdGMI0O5x6HHwZzhbQ=
X-Google-Smtp-Source: ABdhPJzrDT2dvCCfCLkQ2hWIHLTJnBqhk2k8neZ7M+a/yVK/FbwTmnMo3cqJ9h0CVh8PKcLIsrBdhw==
X-Received: by 2002:a54:489a:: with SMTP id r26mr746535oic.158.1633561603411;
        Wed, 06 Oct 2021 16:06:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:4a3:: with SMTP id 32ls490730otm.2.gmail; Wed, 06 Oct
 2021 16:06:43 -0700 (PDT)
X-Received: by 2002:a9d:3e5e:: with SMTP id h30mr824022otg.255.1633561603056;
        Wed, 06 Oct 2021 16:06:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633561603; cv=none;
        d=google.com; s=arc-20160816;
        b=nOmTLvwqRnjWIdse68PViioK7KhHg1AacwwR3Lm1nx4bYubhjxFSTKvaRnUY8O/HGd
         /lvXya/W0B/x2cs7YmueWl8N5aZUTkrlRe/HYU5cr1B2RKVJ4QReIlQL/EFbc78ZuI6f
         yrxc1yMG2FyE20yU5Oyn+JT2w61doIVpcWVIpbAI2DOb4GAT3bPMHROs7edxfCHjwerH
         XZxJBaTsX1kQO118mwCtjQCgF3krhwuY7l83HVyRupOXmhfV+D9c2bjbjkgr6OwAMnPZ
         ddEJsiCWOv25CexDYglpBLWNn4468iJOyLaqbXr+N7Zld6lPyAWEcZ2OFUe5Wx4eLnS2
         /2SQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=znqj6PDNlxs5ZVl1qSnYWTeuoiic0iOQZuplncjvoDU=;
        b=QY3FQfZp/sbfzOWUV6V2OhYjcItuLkHnYU/0xa8xT01yBFaPmZaGIuAFNfYywkQxH+
         330mgp/Zxto77Th7f4POQR4T8gDUuEyhElFyB/B5CGWDQ5usVzSKi11+gs/UaWWN7fTf
         5j6T3k4mNqHIXCA9r0+MRALfVhK+ewkCfmlDXR3FSSujFkhH1M86zkyo/gIRvL+W6Feb
         /4rOcm5mR9lQLjeYsLAQ0zqlFyJMURJp2YH6HSLvjIwD/87HN6orq7z+QwVnOQrYgX6w
         SRlgTBDTlnVXYRBsW9TR+ktWlUiPatxCQ6atfeEfWjalEPDszuNpxnsBP95RbEzJzEBj
         q1ng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=DCHttdwY;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::133 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x133.google.com (mail-il1-x133.google.com. [2607:f8b0:4864:20::133])
        by gmr-mx.google.com with ESMTPS id m30si2211224ooa.1.2021.10.06.16.06.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Oct 2021 16:06:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::133 as permitted sender) client-ip=2607:f8b0:4864:20::133;
Received: by mail-il1-x133.google.com with SMTP id w11so1223748ilv.6
        for <kasan-dev@googlegroups.com>; Wed, 06 Oct 2021 16:06:43 -0700 (PDT)
X-Received: by 2002:a92:4453:: with SMTP id a19mr654042ilm.233.1633561602833;
 Wed, 06 Oct 2021 16:06:42 -0700 (PDT)
MIME-Version: 1.0
References: <20211006154751.4463-1-vincenzo.frascino@arm.com> <20211006154751.4463-5-vincenzo.frascino@arm.com>
In-Reply-To: <20211006154751.4463-5-vincenzo.frascino@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 7 Oct 2021 01:06:32 +0200
Message-ID: <CA+fCnZeeDhBEEgYBXLJr7CG9kac+_VQeFgfgGp=3cjUjsfq0GA@mail.gmail.com>
Subject: Re: [PATCH v3 4/5] arm64: mte: Add asymmetric mode support
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
 header.i=@gmail.com header.s=20210112 header.b=DCHttdwY;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::133
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

On Wed, Oct 6, 2021 at 5:48 PM Vincenzo Frascino
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
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
> ---
>  arch/arm64/include/asm/memory.h    |  1 +
>  arch/arm64/include/asm/mte-kasan.h |  5 ++++
>  arch/arm64/include/asm/mte.h       |  8 +++---
>  arch/arm64/include/asm/uaccess.h   |  4 +--
>  arch/arm64/kernel/mte.c            | 43 +++++++++++++++++++++++++-----
>  5 files changed, 49 insertions(+), 12 deletions(-)
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
> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> index 02511650cffe..075539f5f1c8 100644
> --- a/arch/arm64/include/asm/mte.h
> +++ b/arch/arm64/include/asm/mte.h
> @@ -88,11 +88,11 @@ static inline int mte_ptrace_copy_tags(struct task_struct *child,
>
>  #ifdef CONFIG_KASAN_HW_TAGS
>  /* Whether the MTE asynchronous mode is enabled. */
> -DECLARE_STATIC_KEY_FALSE(mte_async_mode);
> +DECLARE_STATIC_KEY_FALSE(mte_async_or_asymm_mode);
>
> -static inline bool system_uses_mte_async_mode(void)
> +static inline bool system_uses_mte_async_or_asymm_mode(void)
>  {
> -       return static_branch_unlikely(&mte_async_mode);
> +       return static_branch_unlikely(&mte_async_or_asymm_mode);
>  }
>
>  void mte_check_tfsr_el1(void);
> @@ -121,7 +121,7 @@ static inline void mte_check_tfsr_exit(void)
>         mte_check_tfsr_el1();
>  }
>  #else
> -static inline bool system_uses_mte_async_mode(void)
> +static inline bool system_uses_mte_async_or_asymm_mode(void)
>  {
>         return false;
>  }
> diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
> index 190b494e22ab..315354047d69 100644
> --- a/arch/arm64/include/asm/uaccess.h
> +++ b/arch/arm64/include/asm/uaccess.h
> @@ -196,13 +196,13 @@ static inline void __uaccess_enable_tco(void)
>   */
>  static inline void __uaccess_disable_tco_async(void)
>  {
> -       if (system_uses_mte_async_mode())
> +       if (system_uses_mte_async_or_asymm_mode())
>                  __uaccess_disable_tco();
>  }
>
>  static inline void __uaccess_enable_tco_async(void)
>  {
> -       if (system_uses_mte_async_mode())
> +       if (system_uses_mte_async_or_asymm_mode())
>                 __uaccess_enable_tco();
>  }
>
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index e5e801bc5312..d7da4e3924c4 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -26,9 +26,14 @@
>  static DEFINE_PER_CPU_READ_MOSTLY(u64, mte_tcf_preferred);
>
>  #ifdef CONFIG_KASAN_HW_TAGS
> -/* Whether the MTE asynchronous mode is enabled. */
> -DEFINE_STATIC_KEY_FALSE(mte_async_mode);
> -EXPORT_SYMBOL_GPL(mte_async_mode);
> +/*
> + * The MTE asynchronous and asymmetric mode have the same
> + * behavior for the store operations.
> + *
> + * Whether the MTE asynchronous or asymmetric mode is enabled.

Nit:
The asynchronous and asymmetric MTE modes have the same behavior for
store operations. This flag is set when either of these modes is
enabled.

> + */
> +DEFINE_STATIC_KEY_FALSE(mte_async_or_asymm_mode);
> +EXPORT_SYMBOL_GPL(mte_async_or_asymm_mode);
>  #endif
>
>  static void mte_sync_page_tags(struct page *page, pte_t old_pte,
> @@ -116,7 +121,7 @@ void mte_enable_kernel_sync(void)
>          * Make sure we enter this function when no PE has set
>          * async mode previously.
>          */
> -       WARN_ONCE(system_uses_mte_async_mode(),
> +       WARN_ONCE(system_uses_mte_async_or_asymm_mode(),
>                         "MTE async mode enabled system wide!");
>
>         __mte_enable_kernel("synchronous", SCTLR_ELx_TCF_SYNC);
> @@ -134,8 +139,34 @@ void mte_enable_kernel_async(void)
>          * mode in between sync and async, this strategy needs
>          * to be reviewed.
>          */
> -       if (!system_uses_mte_async_mode())
> -               static_branch_enable(&mte_async_mode);
> +       if (!system_uses_mte_async_or_asymm_mode())
> +               static_branch_enable(&mte_async_or_asymm_mode);
> +}
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
> +               if (!system_uses_mte_async_or_asymm_mode())
> +                       static_branch_enable(&mte_async_or_asymm_mode);
> +       } else {
> +               /*
> +                * If the CPU does not support MTE asymmetric mode the
> +                * kernel falls back on synchronous mode which is the
> +                * default for kasan=on.
> +                */
> +               mte_enable_kernel_sync();
> +       }
>  }
>  #endif
>
> --
> 2.33.0
>

Acked-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeeDhBEEgYBXLJr7CG9kac%2B_VQeFgfgGp%3D3cjUjsfq0GA%40mail.gmail.com.
