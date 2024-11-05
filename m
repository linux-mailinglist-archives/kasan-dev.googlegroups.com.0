Return-Path: <kasan-dev+bncBC7PZX4C3UKBBDGEVC4QMGQEI2ADJRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8001A9BCE3E
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Nov 2024 14:47:58 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-539e75025f9sf3115392e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Nov 2024 05:47:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730814478; cv=pass;
        d=google.com; s=arc-20240605;
        b=PTDJuXI/60Wk63oD4idtJ6DUOWA+zCfalN/s9y7d4W4QtwowFj1b7g/n2yOpYilAFE
         56dzxbeJ5yAn2sFIS+VxFKUs+cHuqNwlFDYsCpCYbDXC3b3gvePisBGsYdVy2monjCHf
         b6gtEhRzWYrnwT8fyhRdPPzRrCn7mtVxhclxzH0FOiiQgb62c6MoxhyMJke0/ki9FRSC
         wiK8Qe0WoxwZozTHqliKETiBA/pl1Rq8oKC6yVc+VSYl7tDbQXSn0m7GYTLn0OhCtdC5
         TCVPMJSDyPjJQQ1f+sNGhH5Gz+uJ0jNJkNWPDL2u8ru44xap9GYkqg3zk+uyImRDGbq3
         vL6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=F6gqpxx0ocVeCnJ2J8H8NqrY/oKA9lNkJZZSC28mjOY=;
        fh=VEkPNWXu2WHavpJk2TLLi4W5nMZRymB+y2bMd8k44/0=;
        b=Qzd8RrHkN2Awc5zo6z+L/O5OKam7a4b+br9BwdeIKRc7lJ3gjJX5PZumd5DhXuLuNo
         mHuffIM3MlkPQ1G/90Xj9ja8UrYuRRAUuQ9mJvmTvulJYR3c/NoMiZ10jEziAJQD5gDI
         byPsLRNH1uuEb6F7ERvUVB1f/hsgi0GcMnEZGxwyvWQ2DPAYCPAwrq82YbR4YrjfYmo6
         r0pXkJbDIxIgt2OfnkCnK7GJUWmZXro7khFOuvKQkK75zjEoTgLHzQB31ebRKLXGQeox
         6ttA1iVGa7k9FQPa/BTDYncBY6sbX2DlXIx+5yNjFm8OIc5UlofrguipoZe5TWQ2JZcq
         RpKw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of alex@ghiti.fr designates 217.70.183.195 as permitted sender) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730814478; x=1731419278; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=F6gqpxx0ocVeCnJ2J8H8NqrY/oKA9lNkJZZSC28mjOY=;
        b=jaEWDLcWlrjiQ40xFPlWPcmi/O3IgWNpa8e2ZpyYUDFY+2jT7WNI75dGoKCbodzLlc
         FxGYaNoNLvtUZsjId+wuH+F5uF+61bgkpxIaHvPJ8t0XvIn39VEEX16HgjXS0YxGWDyg
         8Wm1SxPxCaoGMmLrUkbaRoPNxks5atYRpUd7Y/RLcduHNuWVi/5YT841NXts70ay8rid
         C5eqWN8yJMJr7sNVH20BRUCI7FpOxeEk0Y4y0n3TDn+lOKuROWFdWchg0kQa4WaUdi1y
         dQ2exF1oNSBFDQYLkG+rvni9sa9QQvKIIuJfxfqolm6zROs/ct0FC/fXEH+L61A0id2O
         o02w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730814478; x=1731419278;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=F6gqpxx0ocVeCnJ2J8H8NqrY/oKA9lNkJZZSC28mjOY=;
        b=B9tl2/gHysews3m7SMUDxD6WXcQmA+Vn6/JKSiBxBEDTWZdmfExq6WZvNdqPX2pTuN
         J0HA+K61a2Kz4MkoRVI8/GRrXlC3xPFzbpBUfL9QlU6ojD5d5YkCfa8Ik2nb3XWmpuWg
         roDBG4876H8zMbJXtHtVNo5CyuJ0KogMnI3Zsqu6rlweywV+Pjxkp6MdWyqBzLe42giG
         k+ZwyRI6CqES6Oh6q4Rm8qM7rlRdLKG2QDGbjO4s0cT3JI/6dUS9kJIfcaQUgcfCkTL2
         XFK9YwZ4BUzFmjlKN6NgzmnNal1JUYSD3ulOZAnaPyuKDiMeLB7E1iYSSb2cT4AoZ4U2
         Zs7g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXusXskwOZPE0b1uxbP1pHH/F05KSxMtMspeGeGBmXyYzBAmbbcLiJ2vP9EO0gEXZ2cqkd7YA==@lfdr.de
X-Gm-Message-State: AOJu0YzoeVm4YWROFoT3DCI5m5es81/tuDBztfaKA9s5xKDeKOx8E+GL
	V0+TpQouyPF6e3zXwOezu1o7y2BVP1Ei7NyQL6R7vwLfz3IeUAtc
X-Google-Smtp-Source: AGHT+IEA2aobbEPVkAMdFJnNi5MhAlhYfKK1azscGNivG5F1HdDHm6USKHiZBsP/Khm0iRbxlNP2+A==
X-Received: by 2002:a05:6512:2341:b0:536:554a:24c2 with SMTP id 2adb3069b0e04-53b348c8978mr19022588e87.13.1730814477367;
        Tue, 05 Nov 2024 05:47:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6c3:b0:53c:5873:6334 with SMTP id
 2adb3069b0e04-53c791f83b3ls26299e87.0.-pod-prod-07-eu; Tue, 05 Nov 2024
 05:47:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXD/JFKIc+3zPBu27eySUSXndm4jCt7dohBnhKBMDy4cGj7gh6I/wsOVdRt0KK+kGfmqvYZOHSc6u4=@googlegroups.com
X-Received: by 2002:a05:6512:12c5:b0:539:e88f:23a1 with SMTP id 2adb3069b0e04-53b3491c80emr18609296e87.44.1730814474549;
        Tue, 05 Nov 2024 05:47:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730814474; cv=none;
        d=google.com; s=arc-20240605;
        b=K0wRkXVfvWhVASaxLrR5Y00QFk3hAgO8TzXHkRVLwTxBpGVNoRvrb8JHj1njzMnzBe
         Z5jUcLAp2388X29AQazWAgkIBJpYezhkG6+smR/SIoR9T1838/tjHmWji20dQr6N03dB
         gt4kXQVH1SY1xxKioez2pAz361QKytrg14emH0tJCYEugqEFVtNNQn+XDQm2/BtOS3Ss
         U46UmB0KmsFC/ANxpCApQ7lS6omft5R5Sb9SW+Pla+eKLhE4+uamKsTczXOqBvd5BC8r
         auKe0L95+YxiVTWMC9a9jlWJp+88/F1FAmsDKr4x3MWsCgVr2p1kc6LObJKOJVZjQSIX
         pMiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=eWBOU50NMVClOofrTjnG0sXctFUv89sR6AoIkhZtdhs=;
        fh=wvldyurcQnVqad/CC8p6Yx1BbEAKW7gpyVOiaFd/g48=;
        b=W20RNNyapA2JUbgTGOyMhqcb/T4O6THG+gddi6xZh13718LsorOKkpaAo+HMl7tLGo
         F1fXECtfbKeDbUrAP67orLe+SePbVlc2ylu+8hFmWVf1LG5LhBNm6u0SCraMDcr9NDgj
         IMbzVV1xuxeG04/RtU1oCw5LNkRaqS6dPV5hfFC9Ny7ik7r8VzquuelxaLO7KVNktFaD
         pGhtPhlF5/BuXruvmuNgnVkY5R9xhTlypUARr7Nki32aft1eDsXbB7ud4fJiCKv3BZ5Y
         jXmhG7dmqtDL/17F3LacRv/Ps3oM94Vv8XW4V6//Oc8XMUSNEv8l9mDV1X694bhHtCbW
         d0rA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of alex@ghiti.fr designates 217.70.183.195 as permitted sender) smtp.mailfrom=alex@ghiti.fr
Received: from relay3-d.mail.gandi.net (relay3-d.mail.gandi.net. [217.70.183.195])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53c7bbcc169si232822e87.0.2024.11.05.05.47.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 05 Nov 2024 05:47:54 -0800 (PST)
Received-SPF: pass (google.com: domain of alex@ghiti.fr designates 217.70.183.195 as permitted sender) client-ip=217.70.183.195;
Received: by mail.gandi.net (Postfix) with ESMTPSA id 39DD160003;
	Tue,  5 Nov 2024 13:47:51 +0000 (UTC)
Message-ID: <717b3757-4f6f-49f3-9da1-82faaff57485@ghiti.fr>
Date: Tue, 5 Nov 2024 14:47:50 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 6/9] riscv: Do not rely on KASAN to define the memory
 layout
Content-Language: en-US
To: Samuel Holland <samuel.holland@sifive.com>,
 Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com
Cc: llvm@lists.linux.dev, Catalin Marinas <catalin.marinas@arm.com>,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 Alexandre Ghiti <alexghiti@rivosinc.com>, Will Deacon <will@kernel.org>,
 Evgenii Stepanov <eugenis@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 linux-arm-kernel@lists.infradead.org
References: <20241022015913.3524425-1-samuel.holland@sifive.com>
 <20241022015913.3524425-7-samuel.holland@sifive.com>
From: Alexandre Ghiti <alex@ghiti.fr>
In-Reply-To: <20241022015913.3524425-7-samuel.holland@sifive.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-GND-Sasl: alex@ghiti.fr
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of alex@ghiti.fr designates 217.70.183.195 as permitted
 sender) smtp.mailfrom=alex@ghiti.fr
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

On 22/10/2024 03:57, Samuel Holland wrote:
> Commit 66673099f734 ("riscv: mm: Pre-allocate vmemmap/direct map/kasan
> PGD entries") used the start of the KASAN shadow memory region to
> represent the end of the linear map, since the two memory regions were
> immediately adjacent. This is no longer the case for Sv39; commit
> 5c8405d763dc ("riscv: Extend sv39 linear mapping max size to 128G")
> introduced a 4 GiB hole between the regions. Introducing KASAN_SW_TAGS
> will cut the size of the shadow memory region in half, creating an even
> larger hole.
>
> Avoid wasting PGD entries on this hole by using the size of the linear
> map (KERN_VIRT_SIZE) to compute PAGE_END.
>
> Since KASAN_SHADOW_START/KASAN_SHADOW_END are used inside an IS_ENABLED
> block, it's not possible to completely hide the constants when KASAN is
> disabled, so provide dummy definitions for that case.
>
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> ---
>
> (no changes since v1)
>
>   arch/riscv/include/asm/kasan.h | 11 +++++++++--
>   arch/riscv/mm/init.c           |  2 +-
>   2 files changed, 10 insertions(+), 3 deletions(-)
>
> diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasan.h
> index e6a0071bdb56..a4e92ce9fa31 100644
> --- a/arch/riscv/include/asm/kasan.h
> +++ b/arch/riscv/include/asm/kasan.h
> @@ -6,6 +6,8 @@
>   
>   #ifndef __ASSEMBLY__
>   
> +#ifdef CONFIG_KASAN
> +
>   /*
>    * The following comment was copied from arm64:
>    * KASAN_SHADOW_START: beginning of the kernel virtual addresses.
> @@ -33,13 +35,18 @@
>   #define KASAN_SHADOW_START	((KASAN_SHADOW_END - KASAN_SHADOW_SIZE) & PGDIR_MASK)
>   #define KASAN_SHADOW_END	MODULES_LOWEST_VADDR
>   
> -#ifdef CONFIG_KASAN
>   #define KASAN_SHADOW_OFFSET	_AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
>   
>   void kasan_init(void);
>   asmlinkage void kasan_early_init(void);
>   void kasan_swapper_init(void);
>   
> -#endif
> +#else /* CONFIG_KASAN */
> +
> +#define KASAN_SHADOW_START	MODULES_LOWEST_VADDR
> +#define KASAN_SHADOW_END	MODULES_LOWEST_VADDR
> +
> +#endif /* CONFIG_KASAN */
> +
>   #endif
>   #endif /* __ASM_KASAN_H */
> diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
> index 0e8c20adcd98..1f9bb95c2169 100644
> --- a/arch/riscv/mm/init.c
> +++ b/arch/riscv/mm/init.c
> @@ -1494,7 +1494,7 @@ static void __init preallocate_pgd_pages_range(unsigned long start, unsigned lon
>   	panic("Failed to pre-allocate %s pages for %s area\n", lvl, area);
>   }
>   
> -#define PAGE_END KASAN_SHADOW_START
> +#define PAGE_END (PAGE_OFFSET + KERN_VIRT_SIZE)
>   
>   void __init pgtable_cache_init(void)
>   {


Looks good and cleaner, you can add:

Reviewed-by: Alexandre Ghiti <alexghiti@rivosinc.com>

Thanks,

Alex

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/717b3757-4f6f-49f3-9da1-82faaff57485%40ghiti.fr.
