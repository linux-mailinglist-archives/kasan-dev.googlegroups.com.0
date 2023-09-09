Return-Path: <kasan-dev+bncBAABBWGL6KTQMGQEOZVPSTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 1689F799A2B
	for <lists+kasan-dev@lfdr.de>; Sat,  9 Sep 2023 19:05:30 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-1c8d3bfbdbfsf850035fac.1
        for <lists+kasan-dev@lfdr.de>; Sat, 09 Sep 2023 10:05:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694279128; cv=pass;
        d=google.com; s=arc-20160816;
        b=fCZVkzpp1AarQChebyszpfriPJ0OjlytOCaKuJQyFkJgpnK3I3b0upGPnfZATIopix
         zFaccs6DrOBaG8Gyz/NN0Xnr71EiwrbiaQveeePxe20qP/GIgz5sdix/jQBPm/HKuTZU
         gZQLJTJKoWFx2ft4iIosyWaWIW2Y8hb8Ux7t4a1CJPVJk+VeJd2PmsBeGSOf09skaESI
         QMDCnfc9R0f6b6D07VWDqfHJAXQ4LsewZipAv3pRcPkEuM/k2YNlNg2dTBrQdGFcbMpb
         4g8zx2iU/aLmyD03t1qq6npWG2s6Ys/c5+hPuD8lUA94PVBFzISGJm67cMfc4/KwSIe/
         gQiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=Bd5KiAiZdDZsCD70naukUNQ1WQr+BWYZBfxZ2iAOL1Q=;
        fh=3dsbSci+tAkSjBLC9NYuww3Ydg6w6l16vREXpchVQqU=;
        b=WZFs4jZt7L168xYmZu4pZ7TbacFxTncVO52Hh3eaTyhJ9kRqUqDqv2zuF4GD/d0NWc
         EEdHjTWLdJx5UKztRQcjypSqT5+dDsUNRK9HtuvoE23J4oz2UoNEIST0VhYjEaqmyT96
         RugujUlkD8PYwTNJ3Tk/8e0H//NnMbDS9Wm4aocnT9DWf2bEVAQqUtcQ7g6OkgaWpgrP
         dkdtyUOP+BFJk4hFb6K1sNPFrSpqI0a8bB8aqdV4EsciHdz/XWNQ853o38jSHuP8delA
         TMG3o1ibDT7vHtizSDLfDcDhgoZIa+uasrAwPZWbbh0SrkE+rX/lzwZksbObl7G7kl/b
         AIbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@xen0n.name header.s=mail header.b=ku0aRmJt;
       spf=pass (google.com: domain of kernel@xen0n.name designates 115.28.160.31 as permitted sender) smtp.mailfrom=kernel@xen0n.name
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694279128; x=1694883928; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Bd5KiAiZdDZsCD70naukUNQ1WQr+BWYZBfxZ2iAOL1Q=;
        b=clz7DmHAGff8LgW2TEZ7Ken4nhA8lLzdmKW8fn81jEIphqwtmtpHnWkOTLilDmc1Jw
         1WNwcc1rDeIRCtUA6X2Fhm0+YlX3UAr49QwRCxxoJeudAislmwu7iA3Z9azwBlpEtPGh
         rwiilSsOwihERSd+L7St2fboCEalVm7nmRjDbiXVHEhexX3+YfToka/s5Qj740hNzqCH
         qu8E5uhKD7QgYcNtxEOQBRQE8jzb0Hsu6a5KFaySKmgLfo1ROWcm6ADtEshSwnZxUjrN
         ADziAxjo2wxg406SJSqMFW/wUScs5noL0YxZzMCrclJxAo3h7+E1kx5gBv2lX7VIdmX8
         StHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694279128; x=1694883928;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Bd5KiAiZdDZsCD70naukUNQ1WQr+BWYZBfxZ2iAOL1Q=;
        b=b/qSkpMFSQqG5yRjet8Vm/7AB3YsqT8cfThG8sCFEGL6i8+AiQuPnC6x0cYQfemFyK
         AT6adqYIj4TyzZ1j36nxaTEPtvCfrdUJq72Zykkb9nSXpRtDzII9xiqkYzB71dq+PQb8
         ysxc8eO0p152xGQ8XsWmUj/OaAgeeNhMaTO576aBLY5o+iLDc4GeN3VwCEergW1PF5iD
         gCbwFK0Ek6vkqz4B1epcyqtJv/nLITZSxfYJZsRz64dTM8ME6+gvfXQtjhiymVpX1wBK
         85yFUlEF9F/s5+df762i/p/VGy97eORAaTXHnawycfE/ft3h2XQi6Mp8G1c8dwPQbxUZ
         iLMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwJs31LmwC8btPiUDR4anEotFRrSJ/EsAyV3ya+bNfFYNcoiFZw
	s9HEwicBPtmlyg71H6wdkhA=
X-Google-Smtp-Source: AGHT+IECy7zYAEw1GuRryDfuH07V5KPUeODxJ+8jA0cZX7cELa8EGfEkkkQiAGspHKbYDITn8uMqAg==
X-Received: by 2002:a05:6870:15c5:b0:1b7:613c:2e30 with SMTP id k5-20020a05687015c500b001b7613c2e30mr5859921oad.2.1694279128390;
        Sat, 09 Sep 2023 10:05:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:3313:b0:1bb:6485:798a with SMTP id
 x19-20020a056870331300b001bb6485798als2098620oae.1.-pod-prod-02-us; Sat, 09
 Sep 2023 10:05:27 -0700 (PDT)
X-Received: by 2002:a05:6870:340a:b0:1bb:5af8:701f with SMTP id g10-20020a056870340a00b001bb5af8701fmr6634890oah.23.1694279127693;
        Sat, 09 Sep 2023 10:05:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694279127; cv=none;
        d=google.com; s=arc-20160816;
        b=SqH5wD+4GCYVIx8J6Mf6ydGzbtzitkqXg8ih2jX/Bndvd6JLOzYsTiduGWovURKomu
         AScl/dJWaa358718nLDufBMsBvWJCmG3DcLsPSjRORHSu0u3k9Px90UYv+sMYADP5nD4
         s2r6G7OLYMeqp56yj+c0NKSp17z1mu0Kk+ZUNjW1Wii28hcWST5tFJmHgOf3mz43E0u1
         /sL31ND2awjNgRj38WbI2ANfOs+CkgVEg8el9TcvD4i8LIvBKntW2Mcf7sR0cMHoM42Z
         C/kHIvRdXNHtgAYNGSdoWJIVxxI9VlmQddJTc9/gwHQsT1ozYWYPhxhlDzg755sbm+rC
         UrGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=C6jenCbCnB4h7iBrMsdz5u7QLHtc8tgkUkifabuEVVQ=;
        fh=3dsbSci+tAkSjBLC9NYuww3Ydg6w6l16vREXpchVQqU=;
        b=WSNyc/S0A74ZzJKcOo7erHJUXo7CIywznmEZFP5Ndlb0V1K1YcWGBcaw2eI7whk6Bu
         +rUxF5XaFhkHzfxui+ys8INTAeO4u3VY3IkFGFFHOxRFSL55qMHw+UTPT8WoVr432J0d
         QGawk2TePe5WArEjnvB/izmOA1ShawEwjmHh1R3SBaOIwT+ysACtYkSlPEPmZQ5XmgwN
         JZCoaftOhde7zuS7rDtsgAuwEJb4bVIa0nYJEc1MY4Ram7/8dsAxWTWqywt5MNng5aCV
         Uj54xxb1T0vsjpRm6Hey8of7yOxB9wDHf2CzrscAvLdQ/Ni4bXaIPP8SYGQ3ZElhaVl8
         AWlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@xen0n.name header.s=mail header.b=ku0aRmJt;
       spf=pass (google.com: domain of kernel@xen0n.name designates 115.28.160.31 as permitted sender) smtp.mailfrom=kernel@xen0n.name
Received: from mailbox.box.xen0n.name (mail.xen0n.name. [115.28.160.31])
        by gmr-mx.google.com with ESMTPS id m7-20020a632607000000b0054fdb18c859si578669pgm.1.2023.09.09.10.05.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 09 Sep 2023 10:05:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of kernel@xen0n.name designates 115.28.160.31 as permitted sender) client-ip=115.28.160.31;
Received: from [192.168.9.172] (unknown [101.88.25.36])
	(using TLSv1.3 with cipher TLS_AES_128_GCM_SHA256 (128/128 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mailbox.box.xen0n.name (Postfix) with ESMTPSA id E2B8560117;
	Sun, 10 Sep 2023 01:05:23 +0800 (CST)
Message-ID: <fc0f52e0-99a7-bde7-6674-9c1c579c6bc7@xen0n.name>
Date: Sun, 10 Sep 2023 01:05:21 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.15.0
Subject: Re: [PATCH 1/2] kasan: Cleanup the __HAVE_ARCH_SHADOW_MAP usage
To: Huacai Chen <chenhuacai@loongson.cn>, Huacai Chen
 <chenhuacai@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Alexander Potapenko <glider@google.com>
Cc: loongarch@lists.linux.dev, Jiaxun Yang <jiaxun.yang@flygoat.com>,
 Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, loongson-kernel@lists.loongnix.cn,
 Linus Torvalds <torvalds@linux-foundation.org>
References: <20230909115450.1903218-1-chenhuacai@loongson.cn>
Content-Language: en-US
From: WANG Xuerui <kernel@xen0n.name>
In-Reply-To: <20230909115450.1903218-1-chenhuacai@loongson.cn>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: kernel@xen0n.name
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@xen0n.name header.s=mail header.b=ku0aRmJt;       spf=pass
 (google.com: domain of kernel@xen0n.name designates 115.28.160.31 as
 permitted sender) smtp.mailfrom=kernel@xen0n.name
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

Hi,

On 9/9/23 19:54, Huacai Chen wrote:
> As Linus suggested, __HAVE_ARCH_XYZ is stupid and only for historical
> uses. So cleanup the __HAVE_ARCH_SHADOW_MAP usage and use self-defined

For the first sentence, I suggest adding quotation marks to make the 
opinion expression clearer. And paraphrasing a bit:

 > As Linus suggested, __HAVE_ARCH_XYZ is "stupid" and "having 
historical uses of it doesn't make it good".

What do you think?

> macros instead.
"self-defined macro" doesn't really make sense, at least to me. I'd 
suggest something like "migrate __HAVE_ARCH_SHADOW_MAP to separate 
macros named after the respective functions", what about this one?
>
> Suggested-by: Linus Torvalds <torvalds@linux-foundation.org>
> Signed-off-by: Huacai Chen <chenhuacai@loongson.cn>
> ---
>   arch/loongarch/include/asm/kasan.h | 10 ++++++++--
>   include/linux/kasan.h              |  2 +-
>   mm/kasan/kasan.h                   |  8 +++-----
>   3 files changed, 12 insertions(+), 8 deletions(-)
>
> diff --git a/arch/loongarch/include/asm/kasan.h b/arch/loongarch/include/asm/kasan.h
> index deeff8158f45..a12ecab37da7 100644
> --- a/arch/loongarch/include/asm/kasan.h
> +++ b/arch/loongarch/include/asm/kasan.h
> @@ -10,8 +10,6 @@
>   #include <asm/io.h>
>   #include <asm/pgtable.h>
>   
> -#define __HAVE_ARCH_SHADOW_MAP
> -
>   #define KASAN_SHADOW_SCALE_SHIFT 3
>   #define KASAN_SHADOW_OFFSET	_AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
>   
> @@ -68,6 +66,7 @@ static __always_inline bool kasan_arch_is_ready(void)
>   	return !kasan_early_stage;
>   }
>   
> +#define kasan_mem_to_shadow kasan_mem_to_shadow
>   static inline void *kasan_mem_to_shadow(const void *addr)
>   {
>   	if (!kasan_arch_is_ready()) {
> @@ -97,6 +96,7 @@ static inline void *kasan_mem_to_shadow(const void *addr)
>   	}
>   }
>   
> +#define kasan_shadow_to_mem kasan_shadow_to_mem
>   static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
>   {
>   	unsigned long addr = (unsigned long)shadow_addr;
> @@ -119,6 +119,12 @@ static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
>   	}
>   }
>   
> +#define addr_has_metadata addr_has_metadata
> +static __always_inline bool addr_has_metadata(const void *addr)
> +{
> +	return (kasan_mem_to_shadow((void *)addr) != NULL);
Drop the outermost pair of parens that's not necessary? It's only a 
simple comparison after all (although the left hand side is a bit "heavy").
> +}
> +
>   void kasan_init(void);
>   asmlinkage void kasan_early_init(void);
>   
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 3df5499f7936..842623d708c2 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -54,7 +54,7 @@ extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
>   int kasan_populate_early_shadow(const void *shadow_start,
>   				const void *shadow_end);
>   
> -#ifndef __HAVE_ARCH_SHADOW_MAP
> +#ifndef kasan_mem_to_shadow
>   static inline void *kasan_mem_to_shadow(const void *addr)
>   {
>   	return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index f70e3d7a602e..d37831b8511c 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -291,7 +291,7 @@ struct kasan_stack_ring {
>   
>   #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>   
> -#ifndef __HAVE_ARCH_SHADOW_MAP
> +#ifndef kasan_shadow_to_mem
>   static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
>   {
>   	return (void *)(((unsigned long)shadow_addr - KASAN_SHADOW_OFFSET)
> @@ -299,15 +299,13 @@ static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
>   }
>   #endif
>   
> +#ifndef addr_has_metadata
>   static __always_inline bool addr_has_metadata(const void *addr)
>   {
> -#ifdef __HAVE_ARCH_SHADOW_MAP
> -	return (kasan_mem_to_shadow((void *)addr) != NULL);
> -#else
>   	return (kasan_reset_tag(addr) >=
>   		kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
> -#endif
>   }
> +#endif
>   
>   /**
>    * kasan_check_range - Check memory region, and report if invalid access.

The other parts look mechanical and okay to me. With the minor nits 
addressed (or justified):

Reviewed-by: WANG Xuerui <git@xen0n.name>

-- 
WANG "xen0n" Xuerui

Linux/LoongArch mailing list: https://lore.kernel.org/loongarch/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fc0f52e0-99a7-bde7-6674-9c1c579c6bc7%40xen0n.name.
