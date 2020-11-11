Return-Path: <kasan-dev+bncBDX4HWEMTEBRB3HEWD6QKGQECBCF2KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D6A62AF88B
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 19:50:22 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id o3sf1629168plk.20
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 10:50:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605120621; cv=pass;
        d=google.com; s=arc-20160816;
        b=XA+y7Ovid40HdXykKHJpmzYg3Qm1rmcok6BRMSr8aJWr1XYIQ5uZT95WFTx/YN+Dto
         R5KhHSZaA+cMYhyH8+MXb+QO/XVeziDG+gF/DJLt6BXLJMfim+vsSU/WJmnU/Yt5TmyQ
         6d3HzkA/1SKRWla4TLyY67UI1POH+nCtMCf+N3ua0yr8dCVXnKVN8JOAl02chCQKpB5F
         N3UAt9GvlV+gmiJfJg8bhpYSi1850obn1oVzdyDPOQaeTuURGpFnZF6bx0MzufHG8pni
         008pd0LMXKpuGJovCaDFO41aLMfTyHJKXBqanl3qErndINu6RIutgI6QTyr7KVtWK7H3
         /ozw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=UeINy7bphwj7JlLsCwNLVLJV5mIF1x8Fp0uWTZeOpq8=;
        b=Iul9AhdZDak8SGoFgvzV6/jEEQIhX/KtjHuHZblvnnwVr2D2XsONr5tSgijBkahYdi
         6IPJeDV5S4Gp7V/m+hl1Jsja2yLUpraI3AT/MH8ZoJg0G2xFxjNlfSiT+glo0LvC+xCh
         wQ1D9lFSH0UPzGdPrmdD37naiT1voVMPlyVYKQPteDEbuB8M2mPSmpXu/ZaLFWHqNYv8
         MnfEHLCFRhI4xUiMpJ90qwtQcnmuBQH4+hYxzWu/H2WRmfkIakv2tG1DlQvZs1krqHFk
         5K2DVLSvma2VKBzCokaXTtbstXY3202O6aGHahbRjtCHb7HyGxCyWGDRtzffZq4Dr6h+
         g/TQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Kp0u3B28;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UeINy7bphwj7JlLsCwNLVLJV5mIF1x8Fp0uWTZeOpq8=;
        b=jRGo9Pv1bGaHuiBS0xCU/By0PwZFdWxBwE6uBGokFrfVLOpHip5DBndFEan/TXcKKp
         m6x/0n96GkWPwCzf7C9qLjv/FFQ2mY6bPnYmDHYFUoZYlFnBhe/d2wXPPo7NKs0ccfxE
         IcM3RMwSduT14IyWV9qKPI9u8IvPiMWK/l/fzTtpxVR5kvUDwpP0k096SC041LlF3KVe
         FD81GcurGqzrE6ExmWXYgttzUH1jHaagBGEA285WZL3X5vOp+sLJcAK13vx6SX1JuUjM
         DFrrbF75XKYmNd13Vr1oCkB2Q5ad42a9+7s2AmlnMqHDLMtIdzOm4SVv/dHGWMprRARb
         0jew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UeINy7bphwj7JlLsCwNLVLJV5mIF1x8Fp0uWTZeOpq8=;
        b=uU2Kcw0KD8AGm9BggglbMQ21b+BMoKwgLXP2FXM3gqcgbKGiD2egaPXLYhM8uRNoDN
         D4YkIOm24fUNFzuAEbAYyVV2hAmFsOuFqFHteBKyEWS5UqOpkVIGBt2x87kzl1bmB6Xj
         NDVPXtCGX/AMAqLjhBIHm1X3pB8pD5x1YHOsJmwX/dgUzN7Ag6ITlXxnDpvPTVss0RKO
         p82MBu7AyaqIlcd1clGWUisWoiWNq/Z8u5zzfRU41AFup23+/TTUP1neUAj/vAUcXviW
         oatq4+JcUC6Xle2Eak5vcJtDqAOoGCgmSB4z5cdsGQJHNA5aT5BcxetVyPRvQjzxXYpW
         a8Zg==
X-Gm-Message-State: AOAM533+iJ3NKtfwbDFZyOFUcmXts+QqzcwWMiCAHmgs+0HHel4/ShQm
	1SnAtAIR8neSyzdsgI7XtWc=
X-Google-Smtp-Source: ABdhPJzEwNtN5jWxf0RU5LXXf8Lqx/OM0h2rNd/B2NWFsl7XzXI0ug2akf1pEtm10vTOfw3Ry4m4BQ==
X-Received: by 2002:a62:834a:0:b029:18a:e0b1:f0d9 with SMTP id h71-20020a62834a0000b029018ae0b1f0d9mr24967014pfe.73.1605120621043;
        Wed, 11 Nov 2020 10:50:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bd82:: with SMTP id z2ls88267pjr.3.canary-gmail;
 Wed, 11 Nov 2020 10:50:20 -0800 (PST)
X-Received: by 2002:a17:90a:df8f:: with SMTP id p15mr5295486pjv.29.1605120620565;
        Wed, 11 Nov 2020 10:50:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605120620; cv=none;
        d=google.com; s=arc-20160816;
        b=eTPKDBa4siutBzXSh6JL52nhDQqBekbulviD/tIBY38Io33nSzLWVvalDWHcC6T/3P
         w4CTp9Hm7C3hS5CoyAEFj3B0EL8o9xdJC6k3kN0Bds0eSCbBZYTIkCVL01b6q31NIKYw
         fA/RZSKaHnsDKe8lL8MK67siQlwBjnao0nNSDtsUIsnDmLJu5GdaBaAj/hkoFCLOgjYL
         FRjhmq8YTbMupXkES+bMzT6cXtsHLH9C6Pvu6glWlt3ospV2i6LxWlgi8BqdnivXYNPH
         7jm4llko7IbyUQnrO7z+tb82fK7ry8rN7dLPLsbi7UOxzD7GBEExEHwgkSC0Qx+EJHs2
         wb/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VJh1hc9aoLNnAEUPgEfQmYydHZQ7GWODzgkyZKHT9uI=;
        b=QBunEpuWzAnOzs44xdvrvhvQ2ExQKVhojBO8Et9pLwyBeS/eEOfwTyQ4iqFizH94JX
         y3yRAM/A2cOiYabYPYqrNFcg17tqGim7a/Dv4PmoSYRRqdtQN1mzjx/GrAOKRZmakNaQ
         7zLSY4iVCQYMZCYq/Ew9rkzFiluhDMZPsCIwXkzjZNQ2vsCn8OBmYHAnR6bHuhRRxD4b
         wuF8nC5UOAXAnp7HtSwvaC06u6Ozxa0djK+gO2DE60jTGlJvbPyZF1YGCSUQpVukQz/w
         IdY3S8mm5DduFavjCz86c5lJIiXZJCluJdQds3cvUMFXYV/19hWgMYnUfp9+8ThD39Ug
         +j9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Kp0u3B28;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1044.google.com (mail-pj1-x1044.google.com. [2607:f8b0:4864:20::1044])
        by gmr-mx.google.com with ESMTPS id h17si160882pjv.3.2020.11.11.10.50.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 10:50:20 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) client-ip=2607:f8b0:4864:20::1044;
Received: by mail-pj1-x1044.google.com with SMTP id r9so1147593pjl.5
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 10:50:20 -0800 (PST)
X-Received: by 2002:a17:90a:4215:: with SMTP id o21mr5064897pjg.166.1605120620141;
 Wed, 11 Nov 2020 10:50:20 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <619cb0edad35d946c4796976c25bddb5b3eb0c56.1605046192.git.andreyknvl@google.com>
 <CAG_fn=UKSp8shtYujRbM=8ndhLg_Ccdpk9eSfOeb=KpwNi7HBg@mail.gmail.com>
In-Reply-To: <CAG_fn=UKSp8shtYujRbM=8ndhLg_Ccdpk9eSfOeb=KpwNi7HBg@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 19:50:09 +0100
Message-ID: <CAAeHK+zh6tOh91Dg4n4NrJwdPWRaDEtz_Btitg8viQQk7Zm_JQ@mail.gmail.com>
Subject: Re: [PATCH v9 17/44] kasan, arm64: move initialization message
To: Alexander Potapenko <glider@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Kp0u3B28;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044
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

On Wed, Nov 11, 2020 at 4:04 PM Alexander Potapenko <glider@google.com> wrote:
>
> On Tue, Nov 10, 2020 at 11:11 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > Software tag-based KASAN mode is fully initialized with kasan_init_tags(),
> > while the generic mode only requires kasan_init(). Move the
> > initialization message for tag-based mode into kasan_init_tags().
> >
> > Also fix pr_fmt() usage for KASAN code: generic.c doesn't need it as it
> > doesn't use any printing functions; tag-based mode should use "kasan:"
> > instead of KBUILD_MODNAME (which stands for file name).
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
> > ---
> > Change-Id: Iddca9764b30ff0fab1922f26ca9d4f39b6f22673
> > ---
> >  arch/arm64/include/asm/kasan.h |  9 +++------
> >  arch/arm64/mm/kasan_init.c     | 13 +++++--------
> >  mm/kasan/generic.c             |  2 --
> >  mm/kasan/sw_tags.c             |  4 +++-
> >  4 files changed, 11 insertions(+), 17 deletions(-)
> >
> > diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasan.h
> > index f7ea70d02cab..0aaf9044cd6a 100644
> > --- a/arch/arm64/include/asm/kasan.h
> > +++ b/arch/arm64/include/asm/kasan.h
> > @@ -12,14 +12,10 @@
> >  #define arch_kasan_reset_tag(addr)     __tag_reset(addr)
> >  #define arch_kasan_get_tag(addr)       __tag_get(addr)
> >
> > -#ifdef CONFIG_KASAN
> > -void kasan_init(void);
> > -#else
> > -static inline void kasan_init(void) { }
> > -#endif
> > -
> >  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
> >
> > +void kasan_init(void);
> > +
> >  /*
> >   * KASAN_SHADOW_START: beginning of the kernel virtual addresses.
> >   * KASAN_SHADOW_END: KASAN_SHADOW_START + 1/N of kernel virtual addresses,
> > @@ -43,6 +39,7 @@ void kasan_copy_shadow(pgd_t *pgdir);
> >  asmlinkage void kasan_early_init(void);
> >
> >  #else
> > +static inline void kasan_init(void) { }
> >  static inline void kasan_copy_shadow(pgd_t *pgdir) { }
> >  #endif
> >
> > diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> > index 5172799f831f..e35ce04beed1 100644
> > --- a/arch/arm64/mm/kasan_init.c
> > +++ b/arch/arm64/mm/kasan_init.c
> > @@ -278,17 +278,14 @@ static void __init kasan_init_depth(void)
> >         init_task.kasan_depth = 0;
> >  }
> >
> > -#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) */
> > -
> > -static inline void __init kasan_init_shadow(void) { }
> > -
> > -static inline void __init kasan_init_depth(void) { }
> > -
> > -#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> > -
> >  void __init kasan_init(void)
> >  {
> >         kasan_init_shadow();
> >         kasan_init_depth();
> > +#if defined(CONFIG_KASAN_GENERIC)
> > +       /* CONFIG_KASAN_SW_TAGS also requires kasan_init_tags(). */
> >         pr_info("KernelAddressSanitizer initialized\n");
> > +#endif
> >  }
>
> Cannot we have a single kasan_init() function that will call
> tool-specific initialization functions and print the message at the
> end?

Unfortunately no. For different modes we need different functions that
are called in different places in the kernel. E.g. for generic KASAN
we only need kasan_init() to setup shadow pages; for SW tags we also
need kasan_init_sw_tags() which initializes per-cpu state and
finilizes initialization process.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bzh6tOh91Dg4n4NrJwdPWRaDEtz_Btitg8viQQk7Zm_JQ%40mail.gmail.com.
