Return-Path: <kasan-dev+bncBCU4TIPXUUFRBTFAT3BQMGQEYEGQANY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id E4C87AF8B66
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Jul 2025 10:26:54 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-23638e1605dsf6617145ad.0
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Jul 2025 01:26:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751617613; cv=pass;
        d=google.com; s=arc-20240605;
        b=PVIBzDP1PK+wZE6FQQd6g1md/4n+1GJ3bRwfhVDCfB4hglEl+/8iBBb8BU82vTB+kH
         W5QbWITPzZUSfAx3C3tUf/FTMHfwXYbjN9I0XwDCgUDaCgNS8chK1gD7DtfWnWGXdue3
         llTpGKbiAFmycf/s7pU+G1qnFQz0gUso02aJCsVW++UmY5/s6/btMsUj366/T7zyYq5I
         VhEmVf2aaIQhIZF4RC8z3fvIYcCTeB0dnPLIpJeHPiqou6eh8+flbwy/YJwg7QEHPd3i
         Hl867XdGy1NXai2oPmu/29BtVUCL7oQ5B2WwaVyRtaIh25hs9Vq3+1PHTAJtAmoOT68U
         xuZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ANBcH5ze6dVHz7UKqOcmFV9z1aBPL9adghJHnSMwMIA=;
        fh=7ObvARqt9UP+/zN+YyszDVUykadpFLD3u8SOJTSk6sQ=;
        b=S90kd9a8Q64O6aQfEQailocHL/8pknlDq4EGnYgPVkxAUmdKxx5UnbzDl5NPF8i3X3
         qXyAw0xUXKs+PoOMlxFiND9atF6SoE1EMrjfCKl+S54HqH4d7kwe/Eu2Je3i14Y+hD9y
         cmT2uN8zGstUPWM3CYKBNYHBPHHE+S04ZM+rzxADHIE+uPNjKbyX+IrJ1uoHeb4d8LUJ
         6qVFfF7i7DnQSxLUYx7aV51gpknP6bn6cAsiZdeo/B0xOnMiW0Z9h6JP6hnprsgBKTeL
         cWG9bVB6YeoUIP/SLMIIfnXATGd2miU30INIct7oKCiPHbyOcgFK/1CwyTQo1pLjgrSe
         rBXA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OURYlIL9;
       spf=pass (google.com: domain of ardb@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751617613; x=1752222413; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ANBcH5ze6dVHz7UKqOcmFV9z1aBPL9adghJHnSMwMIA=;
        b=I8DwYEXdfIl8KHs27mXpE/miizYlIg8gmshBhuyMMurwAnt5Wf862Xd1gfTZKd3qrU
         DeZ2Mal7erpUx4CaA0cPqGlYzmcSKetpeGeRQgnrPNeg5BxXSYOxwWndX4bwLao8UNV1
         E8R4rB6QRMFY2tv8Sxavw7mI5U0Rv4lSVwpQ7Azexa5JW8Q+qyEHztAG6SC/Z1QgHleJ
         tduhkUn9hXeriVv3gLhmRan2hEFzgWP13qLTIo4pMEW2p4P/l+hi6POH/jOc87IQAKF1
         IIp7zw4Kv3urhze8jaKlG0DQBwtu5DCnoPsLF5LE92j/y2zSGWWC7GAesoWmNlVxQatb
         j0PQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751617613; x=1752222413;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ANBcH5ze6dVHz7UKqOcmFV9z1aBPL9adghJHnSMwMIA=;
        b=fvk0CzcNSnPIdgx4VLglbMESEHZD/FiFHlVxx4znWU/qu1nmrJF08FZ86KguV6P3Oz
         8G6J1T3/5BbEzmPfXZW0pQjqoVYCpbxFCIhqkA6D4PrigoUvChzdTfa43uc12Bi48Rxw
         jJesDCWOENC94kaG3R+Q35bmlBXQSjFAUkCH7ai50Wk/415vF636hl1/Lbrn7zSc9iEd
         rOfIz18mZcUDOkf2QNTo44Ug0FOWWhqXMDRfm2ziEp8/gt4U8k79q1pUeizKa4etIbBg
         0+bBtUzI5cix7M5ajb+3yNklWqIB5YVPMc7hAnUEFSux31AaceAFSyJmmp72n4+ENcfX
         vouQ==
X-Forwarded-Encrypted: i=2; AJvYcCXrE99aur1inagu6Ix7inh/cQlDZB2nd3Au987hIq/h75/2nmNcyaJpceldeGmq5U7dg8P26Q==@lfdr.de
X-Gm-Message-State: AOJu0YwtE3idIs1RjNBNBjEEmlEq8bh7N8jaKeyR9cDKOlG27EV/Hszg
	1F5FEG71XPfR5tnZ368YVHG/0nFC03qOmnxvTSB+MRn6Mka121pWKu6a
X-Google-Smtp-Source: AGHT+IHLJhOwVhgig2f2v0qizT9STMnBLc/OSmBxFifWstJAoiLWPmyoM70TTVh+vhB84lFbjpsCdw==
X-Received: by 2002:a17:902:ce85:b0:234:e655:a618 with SMTP id d9443c01a7336-23c8755bdbcmr19194525ad.25.1751617613277;
        Fri, 04 Jul 2025 01:26:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfKhkDzSjciOpGbAO8/TWl8GrC0gYn06jLGlPqR5Tmn1g==
Received: by 2002:a17:902:e88b:b0:234:aa6d:511a with SMTP id
 d9443c01a7336-23c89ac2454ls2309165ad.0.-pod-prod-07-us; Fri, 04 Jul 2025
 01:26:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXLIGRihYcP9lx0CoUTR2IW6arUj1+hC5JMvscVlzf/j0uE7S4elgLIDe+QfGICh/ODj9eR6Q0IBGs=@googlegroups.com
X-Received: by 2002:a17:902:daca:b0:235:f298:cbbd with SMTP id d9443c01a7336-23c8747eddcmr26934975ad.21.1751617611518;
        Fri, 04 Jul 2025 01:26:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751617611; cv=none;
        d=google.com; s=arc-20240605;
        b=NJonUvAiFF8rZzD/cyGmiM4ntwxm1luyd4AVBb+Z4mPiWBmaAouJZKg5FG5FIAAMw5
         JFoAGRUaH32AVVC/pvAiZziAGNTlFm9P6atvvl6XCuqoBzlOzvlRyvpIYiIHomQfoaNk
         pczb1Cf5JH0KZRwaUFIRTn7nDFdThjNkLVxsbRdx/21m54LCe9PecCMdtLVS5Nblu8zG
         2ySrQuwsF9HDuNeqIJVbxf1SoWNNMSAgualxH12RDPyfsvdXf8rjkVbA4/hVO+UY0S1w
         XEd1ZfH0d9np2td+SwEGaoRElEpPZ0qivDJIvSxMad8iqxkOY5eVXl1mMNUMlIACN77R
         Mx5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gx3SHwSSOHA1sK+lAyXr0DHkaYK3RbpLwm1zJ8Ey4Lc=;
        fh=WbASvt3sCH75tEmR+c7q0c18GszoZxW+58rNuON1Kqo=;
        b=CrzCjefbGlMZBN2xZOP7bHfkgl0N7r08RnRQi+yEPHo7Tydngs3y6M/XSyt+c5J+xe
         1rZ9kfQ8r7jmz5gg5PfS7RryJgC6TDpr6Bcu0s6oDYgP4/ZVEFMMJ6qyCleW0EakX564
         S1+8esTLsJmYv1DIpUjmsQNizrUwCR5TwaLOZm0/TFPpnA1YqgVJjtFQDR9nvWACK0cV
         YzDN0F5+hpALvD4jvjelMed0UbCmlxlhw/V2HhiTRUn+eqyp7Bxl4ulal4eLMRCI5+P7
         mnye4ar5UIHJCW/S3mvc5Unsu4hDwwGNlaoKbCAA3Vad+Y9ReJppo05Cqs/qwq3vewf2
         Gosg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OURYlIL9;
       spf=pass (google.com: domain of ardb@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-23c842b4678si584775ad.1.2025.07.04.01.26.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 04 Jul 2025 01:26:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 30F2B46743
	for <kasan-dev@googlegroups.com>; Fri,  4 Jul 2025 08:26:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 11EB5C4CEED
	for <kasan-dev@googlegroups.com>; Fri,  4 Jul 2025 08:26:51 +0000 (UTC)
Received: by mail-lf1-f44.google.com with SMTP id 2adb3069b0e04-553b16a0e38so886039e87.1
        for <kasan-dev@googlegroups.com>; Fri, 04 Jul 2025 01:26:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW0NS7iLOj6HT3RICioh3mmhu8X1KzKGuK2AQNUj50T7Th/e/HQuoJoUVjgV4xcrE5/0MGOoc2dXQk=@googlegroups.com
X-Received: by 2002:a05:6512:3690:b0:553:3770:c91d with SMTP id
 2adb3069b0e04-556d160f06bmr486751e87.4.1751617609446; Fri, 04 Jul 2025
 01:26:49 -0700 (PDT)
MIME-Version: 1.0
References: <20250624-arm_kasan-v1-1-21e80eab3d70@debian.org> <aGaxZHLnDQc_kSur@arm.com>
In-Reply-To: <aGaxZHLnDQc_kSur@arm.com>
From: "'Ard Biesheuvel' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 4 Jul 2025 10:26:37 +0200
X-Gmail-Original-Message-ID: <CAMj1kXFadibWLnhFv3cOk-7Ah2MmPz8RqDuQjGr-3gmq+hEnMg@mail.gmail.com>
X-Gm-Features: Ac12FXxELlmJOgclmPetSiXcBqm7bPSktVfuSqSd0ARv_5mIl32jvgAoBlJoUvA
Message-ID: <CAMj1kXFadibWLnhFv3cOk-7Ah2MmPz8RqDuQjGr-3gmq+hEnMg@mail.gmail.com>
Subject: Re: [PATCH] arm64: efi: Fix KASAN false positive for EFI runtime stack
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Breno Leitao <leitao@debian.org>, Will Deacon <will@kernel.org>, usamaarif642@gmail.com, 
	rmikey@meta.com, andreyknvl@gmail.com, kasan-dev@googlegroups.com, 
	linux-efi@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, kernel-team@meta.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=OURYlIL9;       spf=pass
 (google.com: domain of ardb@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Ard Biesheuvel <ardb@kernel.org>
Reply-To: Ard Biesheuvel <ardb@kernel.org>
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

On Thu, 3 Jul 2025 at 18:35, Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Tue, Jun 24, 2025 at 05:55:53AM -0700, Breno Leitao wrote:
> > KASAN reports invalid accesses during arch_stack_walk() for EFI runtime
> > services due to vmalloc tagging[1]. The EFI runtime stack must be allocated
> > with KASAN tags reset to avoid false positives.
> >
> > This patch uses arch_alloc_vmap_stack() instead of __vmalloc_node() for
> > EFI stack allocation, which internally calls kasan_reset_tag()
> >
> > The changes ensure EFI runtime stacks are properly sanitized for KASAN
> > while maintaining functional consistency.
> >
> > Link: https://lore.kernel.org/all/aFVVEgD0236LdrL6@gmail.com/ [1]
> > Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
> > Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
> > Signed-off-by: Breno Leitao <leitao@debian.org>
> > ---
> >  arch/arm64/kernel/efi.c | 9 ++++++---
> >  1 file changed, 6 insertions(+), 3 deletions(-)
> >
> > diff --git a/arch/arm64/kernel/efi.c b/arch/arm64/kernel/efi.c
> > index 3857fd7ee8d46..d2af881a48290 100644
> > --- a/arch/arm64/kernel/efi.c
> > +++ b/arch/arm64/kernel/efi.c
> > @@ -15,6 +15,7 @@
> >
> >  #include <asm/efi.h>
> >  #include <asm/stacktrace.h>
> > +#include <asm/vmap_stack.h>
> >
> >  static bool region_is_misaligned(const efi_memory_desc_t *md)
> >  {
> > @@ -214,9 +215,11 @@ static int __init arm64_efi_rt_init(void)
> >       if (!efi_enabled(EFI_RUNTIME_SERVICES))
> >               return 0;
> >
> > -     p = __vmalloc_node(THREAD_SIZE, THREAD_ALIGN, GFP_KERNEL,
> > -                        NUMA_NO_NODE, &&l);
> > -l:   if (!p) {
> > +     if (!IS_ENABLED(CONFIG_VMAP_STACK))
> > +             return -ENOMEM;
>
> Mark Rutland pointed out in a private chat that this should probably
> clear the EFI_RUNTIME_SERVICES flag as well.
>

If VMAP_STACK is a hard requirement, should we make CONFIG_EFI depend
on it for arm64?

> > +
> > +     p = arch_alloc_vmap_stack(THREAD_SIZE, NUMA_NO_NODE);
> > +     if (!p) {
> >               pr_warn("Failed to allocate EFI runtime stack\n");
> >               clear_bit(EFI_RUNTIME_SERVICES, &efi.flags);
> >               return -ENOMEM;
> >
>
> With that:
>
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
>
> (but let's see if Ard has a different opinion on the approach)
>

I think this is fine - the stack just needs to be disjoint from the
ordinary kernel mode task stack so that buggy firmware is less likely
to corrupt it, and so that we can recover from an unexpected
synchronous exception more reliably.

In that sense, the old and the new code are equivalent, so no
objections from me.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXFadibWLnhFv3cOk-7Ah2MmPz8RqDuQjGr-3gmq%2BhEnMg%40mail.gmail.com.
