Return-Path: <kasan-dev+bncBCCJX7VWUANBBH7E26BAMGQEPCX3C6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id F164C342CED
	for <lists+kasan-dev@lfdr.de>; Sat, 20 Mar 2021 14:01:20 +0100 (CET)
Received: by mail-vk1-xa3f.google.com with SMTP id m21sf599445vko.18
        for <lists+kasan-dev@lfdr.de>; Sat, 20 Mar 2021 06:01:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616245279; cv=pass;
        d=google.com; s=arc-20160816;
        b=IaTr4xxi0TJuPwnoZcrwnWpt3E6KI7q4DabydH6Kt6CwzEHoaHF2piLCM18lWE/GRt
         P/fXqgbU3l/TmMz1KNUGxFOdt2HnB6w+NkSmNKCBW+zvDysXAhpGzWLjTQELkiWjS0N4
         NzX7vuKQF3KXyw9p+IctQ/u8SOq1Vtt4mAKh0dFFmWrTF0zc5sswABuIECgKXqdzY8Mv
         XqDKtZM6JYiLpnvLUp3O7oU46hs9dlpd9WvE1/QuBjn4YPIRkDvTXbE9sPcz7+iBoTKo
         htwXfvn+umXXjZbuZF4vxpKejyLzrxEMS3uhuHy4+N9eAgwMLq9bMgwkKpjr5hilLq96
         9cGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=SXYjd38w89LL6b4yYa9blug/KW7w06SevkgztahPGRQ=;
        b=lRKYCm7RgDcsUybYIiLEOslfw5MGaHR4UAMsf59q9DAiCnWkVaogpWeXTiYg7rh1qp
         2UMBU5voLwjyYqAgIHBCVZiPWq2Y/OFEy+5kJXukKmxgoABkWQ3rb6WK7z2QG224gP86
         kcn15iDguZd7V5im1jEVEWTrZsiPGZ3IBytPYfX5dQd9AmFbC6HW65vG9en64RKRElIs
         Y/44AmyfXu3PJ3bWcgMmWhsjNQQO8pKC7/z7Ik11/XEMgczLatJeS5Gj53N50kxGumKi
         25F1bWTryCH29TEyYsba+x8vxf1TqsnXjufOVXa95RTKsHO7tNK63Y1EUR6x74DUR2m/
         ZYNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=QZgnK16r;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SXYjd38w89LL6b4yYa9blug/KW7w06SevkgztahPGRQ=;
        b=sbwCtpsbeLSmKL3iMafw6HLF/RsEkrsKzYWzsvnF5WD8J1xfBBInhJ6bjBVWEG+OCE
         AZsmOzVluTS8n+kn2WtkTjK/Xk7/fPU0E0nc0Y/MFkwsub89CwbEBfsSp1VrVdKn43Zc
         11Dld4nX5suZNPNz2giXZyQz4p063/W+NVK2d2/QY60gK9SOcIpBWeDEMic3T7TiWNNh
         zohaGAac5rvTZ5jFEHGQuqIM7914s1KQ3zxHT35FaN+m8CHEoYBypRk1ibuiVh44xr2O
         l48/JZop2qBmUtHW0B9gQ4t04e+LIvU+Tjh3r9XoJuhEI7kbN8GsxH4yfq/tnmBbYhX5
         25cQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SXYjd38w89LL6b4yYa9blug/KW7w06SevkgztahPGRQ=;
        b=IJj8JkOe8wHgIcyka4v6a1bxUHWTrMWZek1wHuvDewoGNGoNg8yel2lElzp+9+6OCs
         r0CYC2GyjJn2FAsIOCjpwa2+XLxeF9LnKstFVcUtnyo2IhRhewe6RhGI+JPKb70ysXHo
         KQJk4CTRxkl8+b0v1MFPUfHs8hhJq0jiTwyB5YpPsuqOplTxRy2f9UVkEBd69iiiEWVN
         YcfDNJzZkpHR2QyWLkBykf0gdIhvGquij/ep/dg2Jqfge/UpyBJkLEOAHw26KrfoPSL9
         +Fnlhfh3hEctVg66lGgSRh6ZpR/KGMWiuq5FNT1V6+JIOOO2CzuMBQJGnc6coU2jFsjz
         l25w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SXYjd38w89LL6b4yYa9blug/KW7w06SevkgztahPGRQ=;
        b=GfhPgQqJLcbVprtib4V5gz/6Ehb7KpC6ukTNIXYxnAlxEGW7MkBPe8dyZ8MsFHrlzl
         LOVoxCabAd5lSlstGR2prt4PF7xWpq7XL+wZGKeqMd25VZakSlFJDQP84KM4yjVAUqeG
         RMAmB1Ay2bjSskSouD4NulDZQZWHJ5nyIfWsJGfM4eb8Po8tGwINlrXAIVc7g5jT+sTV
         GGj/YD1l7owLgzQw2hYolN2splGL7ZW6mhyGhmVYGsHrugdbWB1x1A1I1LzNKqkMtUSS
         Zuqs39uW9p0kM0+pJYtIywEoFlDqmHoaoQRjY/TltSSXD5XiF3TkyLaDLW0770bBgWZ0
         YSHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532XT/0LtJ+41hcFH1WlVOGzpO6nLnGL4bT2MJfnb9Y3VhmstF+Y
	Qk3hEviszUm5lG4hmmUY4Co=
X-Google-Smtp-Source: ABdhPJydgDaflFxoc9vqJVFEvVpNl180ijgA5gy+4KfX6cLwQAN4GFr9CGGkgozFMKcCsAmS0MsfHg==
X-Received: by 2002:ab0:7088:: with SMTP id m8mr1352729ual.17.1616245279667;
        Sat, 20 Mar 2021 06:01:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:63c3:: with SMTP id x186ls420344vkb.7.gmail; Sat, 20 Mar
 2021 06:01:19 -0700 (PDT)
X-Received: by 2002:a1f:2502:: with SMTP id l2mr5138571vkl.5.1616245279209;
        Sat, 20 Mar 2021 06:01:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616245279; cv=none;
        d=google.com; s=arc-20160816;
        b=Evtsj+A0cSTMBJBH3/bprpzSNsjx7A7CGvNE+y/oOGR8qMwZo7nDG5PNgV3gFSQ2GP
         bCZr2V6cAGWGGwjUoINtZoR7WtwvjSx088bhffPhHkAujHbN7SuJ3AsE2sWZiHm9sIBY
         VQ+vxU/PPelzMmUAstkicLgzcZeBd9PGSmZ/sdTdqUqogyv3sIv1N3EVtSXc1Otj1yUQ
         JUnndvR+AdYAWEL95FtxjNIkRcjFfsBBD0czdXabyRVVhUpTrGLHORlA+uPyfDLKAmdi
         lxCefr2SfGBNb51MOH/JG3fRvtmuLObYJg05KrbqGa5XpjVFcikNwdDPRdG6zfzrZrhi
         LXjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9ON3r+aiJR5Q+UUgakEzAMuWKjcsi9+uuz4/fBWDEro=;
        b=tHjEdMbj1wfWKxszCCUDinELi7IndJL7B+OEUuI5yOavxCMZALv0l5MVUXWN5bxfMT
         gZ7/tP1DMigulq6qoM5XXNIQbSFrisCa5hcZYarIQsUe1mtEqUQodz7Cx42z5jssd3mR
         43tIoPPBAlRGtC2jgGW05XEzNiOewIN8hLHTbSCCuEyci0fzyTEB8b4R6QhzeDKV0Csl
         YJM/oJxeYuU4dLCv8XQRy8wiU3+8v1ML+iF909kYEvH8zpqEhKV5dO4dTsxCnMRxW+2P
         FsFvk+eXAPQTtC0J/hQ9BH57hx3EgJHorx6rRl0Gx7Ak6K0U6yigxeH5XF64c/f+Vu+y
         iDhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=QZgnK16r;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102d.google.com (mail-pj1-x102d.google.com. [2607:f8b0:4864:20::102d])
        by gmr-mx.google.com with ESMTPS id n3si524803uad.0.2021.03.20.06.01.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 20 Mar 2021 06:01:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::102d as permitted sender) client-ip=2607:f8b0:4864:20::102d;
Received: by mail-pj1-x102d.google.com with SMTP id kr3-20020a17090b4903b02900c096fc01deso6189528pjb.4
        for <kasan-dev@googlegroups.com>; Sat, 20 Mar 2021 06:01:19 -0700 (PDT)
X-Received: by 2002:a17:90a:4104:: with SMTP id u4mr3445045pjf.81.1616245278293;
 Sat, 20 Mar 2021 06:01:18 -0700 (PDT)
MIME-Version: 1.0
References: <20210206083552.24394-1-lecopzer.chen@mediatek.com>
 <20210206083552.24394-2-lecopzer.chen@mediatek.com> <20210319173758.GC6832@arm.com>
In-Reply-To: <20210319173758.GC6832@arm.com>
From: Lecopzer Chen <lecopzer@gmail.com>
Date: Sat, 20 Mar 2021 21:01:07 +0800
Message-ID: <CANr2M18q-EfmUvX=LbP2wLOX-=qJqPK9cH=EUKp3T9Nh6SLsGg@mail.gmail.com>
Subject: Re: [PATCH v3 1/5] arm64: kasan: don't populate vmalloc area for CONFIG_KASAN_VMALLOC
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Lecopzer Chen <lecopzer.chen@mediatek.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, 
	linux-arm-kernel <linux-arm-kernel@lists.infradead.org>, Will Deacon <will@kernel.org>, 
	dan.j.williams@intel.com, aryabinin@virtuozzo.com, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mediatek@lists.infradead.org, 
	yj.chiang@mediatek.com, ardb@kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, broonie@kernel.org, linux@roeck-us.net, 
	rppt@kernel.org, tyhicks@linux.microsoft.com, robin.murphy@arm.com, 
	vincenzo.frascino@arm.com, gustavoars@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: lecopzer@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=QZgnK16r;       spf=pass
 (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::102d
 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;       dmarc=pass
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

On Sat, Mar 20, 2021 at 1:38 AM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Sat, Feb 06, 2021 at 04:35:48PM +0800, Lecopzer Chen wrote:
> > Linux support KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> > ("kasan: support backing vmalloc space with real shadow memory")
> >
> > Like how the MODULES_VADDR does now, just not to early populate
> > the VMALLOC_START between VMALLOC_END.
> >
> > Before:
> >
> > MODULE_VADDR: no mapping, no zoreo shadow at init
> > VMALLOC_VADDR: backed with zero shadow at init
> >
> > After:
> >
> > MODULE_VADDR: no mapping, no zoreo shadow at init
> > VMALLOC_VADDR: no mapping, no zoreo shadow at init
>
> s/zoreo/zero/
>

thanks!

> > Thus the mapping will get allocated on demand by the core function
> > of KASAN_VMALLOC.
> >
> >   -----------  vmalloc_shadow_start
> >  |           |
> >  |           |
> >  |           | <= non-mapping
> >  |           |
> >  |           |
> >  |-----------|
> >  |///////////|<- kimage shadow with page table mapping.
> >  |-----------|
> >  |           |
> >  |           | <= non-mapping
> >  |           |
> >  ------------- vmalloc_shadow_end
> >  |00000000000|
> >  |00000000000| <= Zero shadow
> >  |00000000000|
> >  ------------- KASAN_SHADOW_END
> >
> > Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> > ---
> >  arch/arm64/mm/kasan_init.c | 18 +++++++++++++-----
> >  1 file changed, 13 insertions(+), 5 deletions(-)
> >
> > diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> > index d8e66c78440e..20d06008785f 100644
> > --- a/arch/arm64/mm/kasan_init.c
> > +++ b/arch/arm64/mm/kasan_init.c
> > @@ -214,6 +214,7 @@ static void __init kasan_init_shadow(void)
> >  {
> >       u64 kimg_shadow_start, kimg_shadow_end;
> >       u64 mod_shadow_start, mod_shadow_end;
> > +     u64 vmalloc_shadow_end;
> >       phys_addr_t pa_start, pa_end;
> >       u64 i;
> >
> > @@ -223,6 +224,8 @@ static void __init kasan_init_shadow(void)
> >       mod_shadow_start = (u64)kasan_mem_to_shadow((void *)MODULES_VADDR);
> >       mod_shadow_end = (u64)kasan_mem_to_shadow((void *)MODULES_END);
> >
> > +     vmalloc_shadow_end = (u64)kasan_mem_to_shadow((void *)VMALLOC_END);
> > +
> >       /*
> >        * We are going to perform proper setup of shadow memory.
> >        * At first we should unmap early shadow (clear_pgds() call below).
> > @@ -241,12 +244,17 @@ static void __init kasan_init_shadow(void)
> >
> >       kasan_populate_early_shadow(kasan_mem_to_shadow((void *)PAGE_END),
> >                                  (void *)mod_shadow_start);
> > -     kasan_populate_early_shadow((void *)kimg_shadow_end,
> > -                                (void *)KASAN_SHADOW_END);
> >
> > -     if (kimg_shadow_start > mod_shadow_end)
> > -             kasan_populate_early_shadow((void *)mod_shadow_end,
> > -                                         (void *)kimg_shadow_start);
>
> Not something introduced by this patch but what happens if this
> condition is false? It means that kimg_shadow_end < mod_shadow_start and
> the above kasan_populate_early_shadow(PAGE_END, mod_shadow_start)
> overlaps with the earlier kasan_map_populate(kimg_shadow_start,
> kimg_shadow_end).

In this case, the area between mod_shadow_start and kimg_shadow_end
was mapping when kasan init.

Thus the corner case is that module_alloc() allocates that range
(the area between mod_shadow_start and kimg_shadow_end) again.


With VMALLOC_KASAN,
module_alloc() ->
    ... ->
        kasan_populate_vmalloc ->
            apply_to_page_range()
will check the mapping exists or not and bypass allocating new mapping
if it exists.
So it should be fine in the second allocation.

Without VMALLOC_KASAN,
module_alloc() ->
    kasan_module_alloc()
will allocate the range twice, first time is kasan_map_populate() and
second time is vmalloc(),
and this should have some problems(?).

Now the only possibility that the module area can overlap with kimage
should be KASLR on.
I'm not sure if this is the case that really happens in KASLR, it depends on
how __relocate_kernel() calculates kimage and how kaslr_earlt_init()
decides module_alloc_base.


> > +     if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
> > +             kasan_populate_early_shadow((void *)vmalloc_shadow_end,
> > +                                         (void *)KASAN_SHADOW_END);
> > +     else {
> > +             kasan_populate_early_shadow((void *)kimg_shadow_end,
> > +                                         (void *)KASAN_SHADOW_END);
> > +             if (kimg_shadow_start > mod_shadow_end)
> > +                     kasan_populate_early_shadow((void *)mod_shadow_end,
> > +                                                 (void *)kimg_shadow_start);
> > +     }
> >
> >       for_each_mem_range(i, &pa_start, &pa_end) {
> >               void *start = (void *)__phys_to_virt(pa_start);
> > --
> > 2.25.1
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANr2M18q-EfmUvX%3DLbP2wLOX-%3DqJqPK9cH%3DEUKp3T9Nh6SLsGg%40mail.gmail.com.
