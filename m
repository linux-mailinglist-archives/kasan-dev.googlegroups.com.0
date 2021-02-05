Return-Path: <kasan-dev+bncBDX4HWEMTEBRBO6762AAMGQEN73UFYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id D81423112CA
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 21:51:08 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id r140sf7325258iod.6
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 12:51:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612558268; cv=pass;
        d=google.com; s=arc-20160816;
        b=IZ2Eaq2jDTo9vd+fpgnoHbjC66kCSeUQpJoLcrrO/XkOXAedw1guGTpWYFIvnpqsF4
         +t2ylVa3fj50KkSOKRjS42SpZ1eP6ucdDVl4j9A10ZcdwjdAWMqghJGV3QAABleVGa03
         aXaWd4CfX6WPjUKq/8so/Fxr1n+7yCaytak4lZCLofCFUAEiQu15toF1yADX/OBiaJLc
         7+goGZukkzS0uDGMhjcZLUt7N7gNOZwhs2umsb/3UxLcMoLG9n5OIeZr+17iqSX56roC
         pzcY/9GlbNyI3lRsaeG7LeBCblOxM9p6m9K6idDW4QjpEfgHJMN3sQxTx6B5CfbBQgej
         5vzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VdxVR+i2VIItFhX39ThRkhjWXGkWaX4DPY7AcXhV8QU=;
        b=kzJN4bQGTUB2nAC7JaAJhAo2NkyAdJ/mUMK3wfz/fpDdsIC7NiPZN1QODUIy+9jldn
         2Nj0/fSbVDqeUCs0xXxom4Z+SnWoKZtVoCgjzdqF7YN4ToWXJwVgPybDnrzuan4ZN9n4
         WpwCs+0+WtcESSFdOWkmvGknEciRZ+8HooVKNXNeIskfA8lKxuiwY3ra3k4ztOGBGUJ3
         +MwUlcDRDVaAs7Z40Hal8hNv5aF4Nt+Q0lYq79dd8G1EbpOmI6AmiQEMjDVZFLtfjxtA
         b5AsUM+aZcqd2ZAphukFQe/1sdrIT4Skk5Vk71DDs61dI/4KWTw4N3//34xaj1jVh/Ou
         R6gQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=J97dVjLj;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VdxVR+i2VIItFhX39ThRkhjWXGkWaX4DPY7AcXhV8QU=;
        b=ElIhYvLgFIpGMB01rRnImYaJgHUCA4c1dFN8WAK8fvEpm6wzvAWFcpZm7OHzQG9fht
         4fs0DyHzoe3B8n9tXfKOSBCoIw8/SvE8zlTshC1AlyXOpnYrwzuqJ4jq3fMzNX8C+u5w
         dR+sI35ftS0jvfjPDbwvXJet+S8EWhsU63H6685/cucLrOht0oBuurtr1EmzbGcSDBLD
         LfKUDR8ogJqnT/jFogZW8flPpmqmEHjjbUY9CIvDbchx4wvzNikO8ABOp6/55/IPNRME
         8smYGFogaJHyoESTFDXdq8uzmLT3IO248Z7IYmxznaU0haPkcCEvrOmNjeBmcJ3Lr5V3
         WKzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VdxVR+i2VIItFhX39ThRkhjWXGkWaX4DPY7AcXhV8QU=;
        b=KTnxvNDEkZLDMYV6KHB0ukNRaU3S600+BulIxK/cYL+0mwfKonyPTEztsmvfra3fxY
         6YpMOuPZm2o32byVSLAilusz/V2L6OFoZ5QuxK1oWrgV23Y03atx/QX2A3jDdigP8klC
         E475Pv70fh/eUDkK8MZecxNAi6EJ/+BuXcIVRnc9gbiqKC2qGvOhv3yUDoWUqgwRKR+2
         xZrIFxgOpCFobrneSQjfsNW31a3SHUXs0dGAGXmHPwLUIwZNfw5SLGRvR3ftD/ztOfnj
         dDsOkGiCcbluCIoujLbpVwDGXfbno7B+aEDk9CnwaMiS15pViJc6WNQ63VbthOhduRIQ
         i83g==
X-Gm-Message-State: AOAM530onKE2EK3RdcZS//knCb82VvOkJnvO38GH1lyQicQ347qUClI8
	eLKUSlGnd0N8iwQy48rX/Vw=
X-Google-Smtp-Source: ABdhPJyq2YhNUpR5BSvsPGy9iezIwMhlZdwQbem0dhue+3KTl7biLtkKGs09oA2vKfh48nx2J7W+Jw==
X-Received: by 2002:a92:c26f:: with SMTP id h15mr5273879ild.65.1612558267906;
        Fri, 05 Feb 2021 12:51:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1385:: with SMTP id d5ls2578620ilo.5.gmail; Fri, 05
 Feb 2021 12:51:07 -0800 (PST)
X-Received: by 2002:a05:6e02:20e5:: with SMTP id q5mr5267152ilv.131.1612558267458;
        Fri, 05 Feb 2021 12:51:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612558267; cv=none;
        d=google.com; s=arc-20160816;
        b=yHx2s1erwvQ4jUaYEnadM+Y6WsFhU7jlThqA0JY389kBWMCsbxnqAkETVj9BN5Yqt9
         X2QAJGVBZ9/lzJ2OqUFUvVj8BBgvdY75jTUm96dsHkZIUcvVNtDlBLDmVChSnO3VaKEO
         MexX8yP/PcLwPehBMDLpQ/wMremMDs0ymDxirA2F3QhCtG72uTpRoBNJmuJqURJLhqw8
         RDppepO+KqNU8/HK5x0gL8Thvk1/WHc6RdKeDdIkYvKlxOZDMsIMPFImC6BUKoC6UOgd
         W/ITmF2N/D+kkare2G3J9uX8Ikn91VAf+WB2Mt7p1npwAB5AxqgTk04FlNxhA/O8/+IY
         ahmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WZLU4c8CFtN82E3juz+QcV9FF1JDMzfdyAO1GFaD3hY=;
        b=bxBhqWhCI6Y1cPXghgiRNCnsT/AQcE+0hroQLNrGY/qBgWkegKxqPe/ZrRqgZFDww7
         iGFJLjIdFyzRGvNCWnTCWLfLhmE9BbZ2UOM3miFoUQIont6R3DP4oDF+RN7qBCAzhx5C
         OdcjyHXK9/DR3p76nT10d2IvT0i51ADs6EdT1s1wXE9jUv4KJT3SgdqbWFdhhr8zkgWo
         eeUnmRPUzliSyTMPHfnT59O2+i0uokU7qfjHjTnAUQMbu7FRd+VqvGo/ncyMZZKApYXA
         s4sAy2EPOOyEck//iCDihDP4mIThG5bzlUyTVr9OSUWYZ8VDUVeOOzeY07+GhnFHYn5i
         mGjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=J97dVjLj;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id m132si431920ioa.3.2021.02.05.12.51.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 12:51:07 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id j11so4167683plt.11
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 12:51:07 -0800 (PST)
X-Received: by 2002:a17:90b:3756:: with SMTP id ne22mr5531867pjb.41.1612558266710;
 Fri, 05 Feb 2021 12:51:06 -0800 (PST)
MIME-Version: 1.0
References: <20210204150100.GE20815@willie-the-truck> <20210204163721.91295-1-lecopzer@gmail.com>
 <20210205171859.GE22665@willie-the-truck> <CAAeHK+zppv6P+PqAuZqAfd7++QxhA1rPX6vdY5MyYK_v6YdXSA@mail.gmail.com>
 <20210205174301.GF22665@willie-the-truck>
In-Reply-To: <20210205174301.GF22665@willie-the-truck>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 5 Feb 2021 21:50:55 +0100
Message-ID: <CAAeHK+ysNmkxEZqQ_rEsa7bh_ZZEtOHaMstXumtzWJLu1LdDyQ@mail.gmail.com>
Subject: Re: [PATCH v2 1/4] arm64: kasan: don't populate vmalloc area for CONFIG_KASAN_VMALLOC
To: Will Deacon <will@kernel.org>
Cc: Lecopzer Chen <lecopzer@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Ard Biesheuvel <ardb@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Mark Brown <broonie@kernel.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Dan Williams <dan.j.williams@intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, gustavoars@kernel.org, 
	kasan-dev <kasan-dev@googlegroups.com>, Lecopzer Chen <lecopzer.chen@mediatek.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, LKML <linux-kernel@vger.kernel.org>, 
	"moderated list:ARM/Mediatek SoC..." <linux-mediatek@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Guenter Roeck <linux@roeck-us.net>, 
	Robin Murphy <robin.murphy@arm.com>, rppt@kernel.org, tyhicks@linux.microsoft.com, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, yj.chiang@mediatek.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=J97dVjLj;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::633
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

On Fri, Feb 5, 2021 at 6:43 PM Will Deacon <will@kernel.org> wrote:
>
> On Fri, Feb 05, 2021 at 06:30:44PM +0100, Andrey Konovalov wrote:
> > On Fri, Feb 5, 2021 at 6:19 PM Will Deacon <will@kernel.org> wrote:
> > >
> > > On Fri, Feb 05, 2021 at 12:37:21AM +0800, Lecopzer Chen wrote:
> > > >
> > > > > On Thu, Feb 04, 2021 at 10:46:12PM +0800, Lecopzer Chen wrote:
> > > > > > > On Sat, Jan 09, 2021 at 06:32:49PM +0800, Lecopzer Chen wrote:
> > > > > > > > Linux support KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> > > > > > > > ("kasan: support backing vmalloc space with real shadow memory")
> > > > > > > >
> > > > > > > > Like how the MODULES_VADDR does now, just not to early populate
> > > > > > > > the VMALLOC_START between VMALLOC_END.
> > > > > > > > similarly, the kernel code mapping is now in the VMALLOC area and
> > > > > > > > should keep these area populated.
> > > > > > > >
> > > > > > > > Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> > > > > > > > ---
> > > > > > > >  arch/arm64/mm/kasan_init.c | 23 ++++++++++++++++++-----
> > > > > > > >  1 file changed, 18 insertions(+), 5 deletions(-)
> > > > > > > >
> > > > > > > > diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> > > > > > > > index d8e66c78440e..39b218a64279 100644
> > > > > > > > --- a/arch/arm64/mm/kasan_init.c
> > > > > > > > +++ b/arch/arm64/mm/kasan_init.c
> > > > > > > > @@ -214,6 +214,7 @@ static void __init kasan_init_shadow(void)
> > > > > > > >  {
> > > > > > > >   u64 kimg_shadow_start, kimg_shadow_end;
> > > > > > > >   u64 mod_shadow_start, mod_shadow_end;
> > > > > > > > + u64 vmalloc_shadow_start, vmalloc_shadow_end;
> > > > > > > >   phys_addr_t pa_start, pa_end;
> > > > > > > >   u64 i;
> > > > > > > >
> > > > > > > > @@ -223,6 +224,9 @@ static void __init kasan_init_shadow(void)
> > > > > > > >   mod_shadow_start = (u64)kasan_mem_to_shadow((void *)MODULES_VADDR);
> > > > > > > >   mod_shadow_end = (u64)kasan_mem_to_shadow((void *)MODULES_END);
> > > > > > > >
> > > > > > > > + vmalloc_shadow_start = (u64)kasan_mem_to_shadow((void *)VMALLOC_START);
> > > > > > > > + vmalloc_shadow_end = (u64)kasan_mem_to_shadow((void *)VMALLOC_END);
> > > > > > > > +
> > > > > > > >   /*
> > > > > > > >    * We are going to perform proper setup of shadow memory.
> > > > > > > >    * At first we should unmap early shadow (clear_pgds() call below).
> > > > > > > > @@ -241,12 +245,21 @@ static void __init kasan_init_shadow(void)
> > > > > > > >
> > > > > > > >   kasan_populate_early_shadow(kasan_mem_to_shadow((void *)PAGE_END),
> > > > > > > >                              (void *)mod_shadow_start);
> > > > > > > > - kasan_populate_early_shadow((void *)kimg_shadow_end,
> > > > > > > > -                            (void *)KASAN_SHADOW_END);
> > > > > > > > + if (IS_ENABLED(CONFIG_KASAN_VMALLOC)) {
> > > > > > >
> > > > > > > Do we really need yet another CONFIG option for KASAN? What's the use-case
> > > > > > > for *not* enabling this if you're already enabling one of the KASAN
> > > > > > > backends?
> > > > > >
> > > > > > As I know, KASAN_VMALLOC now only supports KASAN_GENERIC and also
> > > > > > KASAN_VMALLOC uses more memory to map real shadow memory (1/8 of vmalloc va).
> > > > >
> > > > > The shadow is allocated dynamically though, isn't it?
> > > >
> > > > Yes, but It's still a cost.
> > > >
> > > > > > There should be someone can enable KASAN_GENERIC but can't use VMALLOC
> > > > > > due to memory issue.
> > > > >
> > > > > That doesn't sound particularly realistic to me. The reason I'm pushing here
> > > > > is because I would _really_ like to move to VMAP stack unconditionally, and
> > > > > that would effectively force KASAN_VMALLOC to be set if KASAN is in use.
> > > > >
> > > > > So unless there's a really good reason not to do that, please can we make
> > > > > this unconditional for arm64? Pretty please?
> > > >
> > > > I think it's fine since we have a good reason.
> > > > Also if someone have memory issue in KASAN_VMALLOC,
> > > > they can use SW_TAG, right?
> > > >
> > > > However the SW_TAG/HW_TAG is not supported VMALLOC yet.
> > > > So the code would be like
> > > >
> > > >       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> > >
> > > Just make this CONFIG_KASAN_VMALLOC, since that depends on KASAN_GENERIC.
> > >
> > > >               /* explain the relationship between
> > > >                * KASAN_GENERIC and KASAN_VMALLOC in arm64
> > > >                * XXX: because we want VMAP stack....
> > > >                */
> > >
> > > I don't understand the relation with SW_TAGS. The VMAP_STACK dependency is:
> > >
> > >         depends on !KASAN || KASAN_HW_TAGS || KASAN_VMALLOC
> >
> > This means that VMAP_STACK can be only enabled if KASAN_HW_TAGS=y or
> > if KASAN_VMALLOC=y for other modes.
> >
> > >
> > > which doesn't mention SW_TAGS at all. So that seems to imply that SW_TAGS
> > > and VMAP_STACK are mutually exclusive :(
> >
> > SW_TAGS doesn't yet have vmalloc support, so it's not compatible with
> > VMAP_STACK. Once vmalloc support is added to SW_TAGS, KASAN_VMALLOC
> > should be allowed to be enabled with SW_TAGS. This series is a step
> > towards having that support, but doesn't implement it. That will be a
> > separate effort.
>
> Ok, thanks. Then I think we should try to invert the dependency here, if
> possible, so that the KASAN backends depend on !VMAP_STACK if they don't
> support it, rather than silently disabling VMAP_STACK when they are
> selected.

SGTM. Not sure if I will get to this in the nearest future, so I filed
a bug: https://bugzilla.kernel.org/show_bug.cgi?id=211581

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BysNmkxEZqQ_rEsa7bh_ZZEtOHaMstXumtzWJLu1LdDyQ%40mail.gmail.com.
