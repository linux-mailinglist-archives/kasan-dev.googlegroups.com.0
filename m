Return-Path: <kasan-dev+bncBDAOJ6534YNBB6FXT7DQMGQE5FCZGKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 24890BC9E49
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 17:59:54 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-42421eb1693sf177013f8f.3
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 08:59:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760025593; cv=pass;
        d=google.com; s=arc-20240605;
        b=ejHPfLSVVpw7pvcXoB3zhivDYOUtPuyzdJ6wCyM+XGbIiqSPqR4TmDMT7O6st5f5cG
         hmEUffKD+x4IRh8gHOqdeRleGxQJC2RfFft3A0EhjVP6S7425ZK9GWvo4igh5XV7uaF7
         xhan0jp4DDCtmR0ZciFYb4l+ftn82k23xcVCVmK1xvDktk2puCoBpnoTX39ZtLoXeU1T
         J+Y0sLEIiWGMbk0gBIhiX2i7t3hqFaafmVohHYmbn32nTyYQ5T8nZHk7yWd3vMMmh6lI
         oTjNOdzqCtphBDQG2ZjNfiHm9Axmy8mID8hSmf1EuVZVu56JuWC9pwvp8hd+y0h0e2Qk
         cJgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=sWJsWI7YC3HCUKFnghUzz0DvTLcAvzcQbdenn79eM4M=;
        fh=B8kGYkr2AMJYI3dzSxkxgtZJJCfMcaaqSRQtP0xDCbs=;
        b=JSq0xhWpPBdEQWWgnljf0AU0GcUC+YhFkE3UJXcvYvIgilrWY/VH3Vx65tLf9fNC/g
         Cy+UAunhTccytk3nY/zcufClJraFRlaxyNzGamS66h9g6iI6ty+P9Zp2W4KO0wQ2ckVb
         NcbPpVUP+pz9bLk21TL6dYmrok5hHG8GFIJg5Nbs4mSFznQv9UmEeWbfMIoAJ2WNPRb8
         DhbUO/TqghFAjw9eJ1gcGAVTWcZpN97PwbhJYMtDMEBo/lTQqkDp1YFaabcATyaZzhZg
         i44wrd5znKhPSZwUm6Nxu/ezcaJ0eoN6fy3GpprUZU1LZeyNI287KPi4udEfF4KHElLQ
         nIAg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nUtNOO8c;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760025593; x=1760630393; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=sWJsWI7YC3HCUKFnghUzz0DvTLcAvzcQbdenn79eM4M=;
        b=CxUPQCF/INIYnFtdaCBww6IKoR0LptzPNXv6CwyYjkUtZir38C6cXGVfw4fOwvFTG5
         vQt7OAAKLyv03KMY/7ApSusJnYCcHspRbgqvGDEAYB+R94X8zDGiWEO/UcrumzKPxVlv
         qzwboG3Pspr0KUNICmDjJ5jm7xNR+bybTl5jy9dPqbtCEKYeLpocLjplM2EFRQ5VRyZ/
         4SE3kxRGJj32jnW+CRCyB2jw6jQl262PuTJKIx7tRZNIf2Tn2p3JgzDqFtJ7yME26+jV
         Fh6OekQCjcRphJXV5ANMdQCO/3HSQwRJgFwkxu+UfUq2VV+eKwzk/nfW7pEUTHLxZeV3
         hvUA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760025593; x=1760630393; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sWJsWI7YC3HCUKFnghUzz0DvTLcAvzcQbdenn79eM4M=;
        b=JCD9S9HZvEWH3x48Qc/BDBmtMIvtgexJNkAxvNyTeWHFNQeV4YVGI4x/Um+litzsmx
         MAWFprVcZUGYJTefuFz7ruULc7lO+45MSsKd1xR+yEx4cmcD0kpT8dQFJH3Ut7KJP6HV
         S85Sb1Tnpj542O7F46Yh97dnMlOBVMceGKEvoPiWdX25E/ZnpJTrdbpa4pKMtKrDH9Xv
         22CCh0Tc5zg9pJazOXUrQxw2ufP+v11YNzf7rnFFs8N7GxvV01oR+bWCT5vVt5RycYhs
         1tOvKP2Twfxbtz9lnWOnurHNZ03soiUyZeeDtt0RSq0Le7hyBwPgAaKe1Q/845Ua5Ksz
         7KHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760025593; x=1760630393;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=sWJsWI7YC3HCUKFnghUzz0DvTLcAvzcQbdenn79eM4M=;
        b=BqcCw3O07+3+8ELqotSNgDDiATGeQv0pANSL7sLIngrvu/AA09zOOpEUIx0vnnhpGF
         u0g6mKxUOYO5/bRnMIbDk3JS+WqYqyLwCA5LHMMIzcYqz9rkRoecLD0s+xGqrrma1nwC
         /i2sR1BuwSR9qc1cVJ4P2Hs76GbB4UP0YTvuMTTEzPKDgMJp3JzTuuv1B060mBoHEYBy
         +W121+RZXtJ2I/o6DC86hCX909Bl341h+srEn3dOwRXMuyZ2Uth5GZIl1LQ2xe0e5qX3
         f1XnUoA0VKnL3kBRecA34gY2jS23jWlAsmigsefztCNmd2R513ACV2R7w1CM597I9rNr
         P8eQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXQInDlNz1gnF5mqo6z3HCwgcRD3zovARQga6/aJq/1lP9K/Oiu80/RElFDKjNr74EO2SIhpA==@lfdr.de
X-Gm-Message-State: AOJu0YxCasT8DSnrpiIBSKioQ2R9TaQWCPWfBviu9J0YMcskyJFHaeWM
	ZIU/NCAxIWzyuW0ieT3e+6vhWjJ5Z9Zo7ivdm3epF4dtQ9ZWSPjgPKFZ
X-Google-Smtp-Source: AGHT+IGzo2DoKxHEWX5cbWp17eMzWVydjNLcGDUyL3y9SccQVbfkswGpFPEkxW0z1sYKIQ36jV4ASg==
X-Received: by 2002:a05:6000:4387:b0:3fc:740f:ff65 with SMTP id ffacd0b85a97d-4266e8e092emr2754066f8f.6.1760025593424;
        Thu, 09 Oct 2025 08:59:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6HlHPP301xOfz4R5YIL3RqwFodj88tH/lgog/obrDfng=="
Received: by 2002:a7b:c84a:0:b0:46e:1d97:94c3 with SMTP id 5b1f17b1804b1-46faf62f714ls6230635e9.1.-pod-prod-09-eu;
 Thu, 09 Oct 2025 08:59:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV+YQDmOJAqTuvjHm/xhvdG+VC2Typ3Dm0kLzR0z6VKO3X8ppRpNjqqCaa6jJca+1tnhi/F9D9HVfo=@googlegroups.com
X-Received: by 2002:a05:600c:4e47:b0:46e:652e:16a1 with SMTP id 5b1f17b1804b1-46fa9a8b482mr53291335e9.7.1760025590550;
        Thu, 09 Oct 2025 08:59:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760025590; cv=none;
        d=google.com; s=arc-20240605;
        b=kSd5groIw9py3OXy+Avuyk6Yjr74NKUU9HT7FKaleacm2L7wcSCGDrBpT14Jh7icJZ
         ty8gWUxSGdCMq1w4ikXb5FIvLGpfFUs9iS292BOeYKaTj0/dt/DeUrxIGhWc4ZSc2Pyr
         n/JERI7o/KPt2Ik8mKTC/nHSGbv2iO7Gsvx+QbrRst8+FohUvEwZj1X9+A202iIKKY+Z
         jOI/NsJRWpBdiETRy3ZRiW7411cDGFPbkLVrqFkcW27pT+w1eV88FehN13z/f3rs8ea/
         4mf1MfbNhKW+XfSwWj4/vnL69QxAnvKFmvdw4V1GIj3WWQj3hiaYCqrh6ZMHtXtrrl6a
         jIug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=WQBxmURKiGaN3QIqBhTff7pEbZ70mJ9TllMgftPCUcQ=;
        fh=VVXYfUmLOOYuG2dbbCBnUD9ZgyZSvIFu3NyAm6tIbJc=;
        b=VVqAXnJwfFZI8lsWI2G4lrrMoBg9SOuPTSPlQnLU3eDkos5rbeYMHd4ZLriCZbLc8V
         ABDtuhFOyrmEBsvX2LgYJzoBy3bFM1htiAtjFDkYfc4xcxEaAlm4NKbBmGYPd3eyiMpE
         elQA0Fk3aTp0X56R0fNcxGS6GqUZ/MWUPlNTZBFZQIXq2lolhaGuHngyq3wH3MsVFFzj
         IXdXmmZ+kckGO8dlUNHn9Zu8U24khJ2hC7R2KhDeR0lQJL2pD4gS+3T8zCXZEzPclDm0
         vnTR/oOcbMf9zX1/0ITDTqkfAMO4DW6po9DerVjtNVCHJvurU3j1uwOgxAhhmhyKCA7N
         BIbA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nUtNOO8c;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x131.google.com (mail-lf1-x131.google.com. [2a00:1450:4864:20::131])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-426cd5da2easi14031f8f.7.2025.10.09.08.59.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 08:59:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) client-ip=2a00:1450:4864:20::131;
Received: by mail-lf1-x131.google.com with SMTP id 2adb3069b0e04-579d7104c37so1446737e87.3
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 08:59:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW/QJpfBgFtMNCxpO1TFPxeg4xBXy5Qk+2jDFe8qMW0WSGBp2rLwbY/SHqPO2NNBDg9yjM4+xvYUr4=@googlegroups.com
X-Gm-Gg: ASbGnctiCFRgoAyPZ159txB48i+4P6KyyEsuU69ppb0C7J0L23fDSNjplNAkEkjsPVn
	T0tG4OsIOdmkITMgv93cMzpOLEvmkndQ47V+ZdmWrEqI5F1b9rJ5jt56rTDbZvT+6rE7uuqBO51
	rp5bT50VXCLqTJThUAZfGaymJ9Ye7iaUXmqt1+W6nqod9Zc5QsFRDj+rOFNwO3n5939hcmA05MB
	0+tx9ibfXkXevr+mTyLgaBZhoHURAO38qWn5L5cTg==
X-Received: by 2002:a05:6512:1291:b0:57d:ffa4:56f4 with SMTP id
 2adb3069b0e04-5906dae5904mr2393608e87.41.1760025589415; Thu, 09 Oct 2025
 08:59:49 -0700 (PDT)
MIME-Version: 1.0
References: <20250810125746.1105476-1-snovitoll@gmail.com> <20250810125746.1105476-2-snovitoll@gmail.com>
 <87ldmv6p5n.ritesh.list@gmail.com>
In-Reply-To: <87ldmv6p5n.ritesh.list@gmail.com>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Thu, 9 Oct 2025 20:59:32 +0500
X-Gm-Features: AS18NWAnJdcYDP3fsUmpv8ZuZnvVnkv1zMHsU4QWH3X3orZoE8748Ur0FWZohd0
Message-ID: <CACzwLxia6xMcQ=vsYG7SE+pUO8=4DiRWD_Omq3wzRyuhDjGcPQ@mail.gmail.com>
Subject: Re: [PATCH v6 1/2] kasan: introduce ARCH_DEFER_KASAN and unify static
 key across modes
To: Ritesh Harjani <ritesh.list@gmail.com>
Cc: ryabinin.a.a@gmail.com, christophe.leroy@csgroup.eu, bhe@redhat.com, 
	hca@linux.ibm.com, andreyknvl@gmail.com, akpm@linux-foundation.org, 
	zhangqing@loongson.cn, chenhuacai@loongson.cn, davidgow@google.com, 
	glider@google.com, dvyukov@google.com, alexghiti@rivosinc.com, alex@ghiti.fr, 
	agordeev@linux.ibm.com, vincenzo.frascino@arm.com, elver@google.com, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, loongarch@lists.linux.dev, 
	linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org, 
	linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=nUtNOO8c;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::131
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Thu, Sep 4, 2025 at 5:38=E2=80=AFAM Ritesh Harjani <ritesh.list@gmail.co=
m> wrote:
>
>
> Only book3s64 needs static keys here because of radix v/s hash mode
> selection during runtime. The changes in above for powerpc looks good to
> me. It's a nice cleanup too.
>

Hello,
Thanks for the review and sorry for the late reply. This has already
been merged.
AFAIU, in arch/powerpc/Kconfig

config PPC
...
        select ARCH_NEEDS_DEFER_KASAN if PPC_RADIX_MMU

and in arch/powerpc/platforms/Kconfig.cputype:

config PPC_RADIX_MMU
        bool "Radix MMU Support"
        depends on PPC_BOOK3S_64
        select ARCH_HAS_GIGANTIC_PAGE
        default y

So the KASAN static key is enabled only for PPC_BOOK3S_64 by this
Kconfig selection.
In other git changes like:
arch/powerpc/mm/kasan/init_32.c
arch/powerpc/mm/kasan/init_book3e_64.c

, where we call kasan_init_generic() -> kasan_enable() does nothing because
CONFIG_ARCH_DEFER_KASAN is not selected.

> So feel free to take:
> Reviewed-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com> #powerpc
>
> However I have few comments below...
>
> > @@ -246,7 +255,7 @@ static inline void poison_slab_object(struct kmem_c=
ache *cache, void *object,
> >  bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
> >                               unsigned long ip)
> >  {
> > -     if (!kasan_arch_is_ready() || is_kfence_address(object))
> > +     if (is_kfence_address(object))
>
> For changes in mm/kasan/common.c.. you have removed !kasan_enabled()
> check at few places. This seems to be partial revert of commit [1]:
>
>   b3c34245756ada "kasan: catch invalid free before SLUB reinitializes the=
 object"
>
> Can you please explain why this needs to be removed?

kasan_arch_is_ready() was removed here because in
commit 1e338f4d99e6("kasan: introduce ARCH_DEFER_KASAN and unify
static key across modes")
I've unified the check with kasan_enabled() which is already called in
the __wrapper
__kasan_slab_pre_free in include/linux/kasan.h

> Also the explaination of the same should be added in the commit msg too.
>
> [1]: https://lore.kernel.org/all/20240809-kasan-tsbrcu-v8-1-aef4593f9532@=
google.com/
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACzwLxia6xMcQ%3DvsYG7SE%2BpUO8%3D4DiRWD_Omq3wzRyuhDjGcPQ%40mail.gmail.com.
