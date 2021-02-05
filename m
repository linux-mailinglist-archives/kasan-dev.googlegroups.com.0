Return-Path: <kasan-dev+bncBDX4HWEMTEBRBUEB62AAMGQEPUHKTVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id F2EED310EB0
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 18:30:57 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id u14sf4814278plf.4
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 09:30:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612546256; cv=pass;
        d=google.com; s=arc-20160816;
        b=azlEWD3qaJkiNfzCkWGWZy4Hh9dR+KPTFcXpQ9UtViCjsBCezj2Karuff8HuVh1M6q
         +2uAPSm0TnUuk8CJ/x0/3SCzVo1TO8eOISe0CblxWLldLIgTCv0LqWuU5o+DIkYh9o9w
         MUwlTfKLP26auHO/GgSxn9al4EY9IvWt7wLmohRzuZ4eurL0uB97I0kRb5rn4OUYBiKx
         5Vt0l/JohlLWMNxOUXrJHJ6Mx26nm34HZEDxpUsJgsv1a7hl+uwjuOoFeiPclycxoquX
         EJZCc66CHOJcWuWtcyxo025ocfpEh9cvieV6/tQpmntXkM2suCKvWuG/t4fJZzy4uyzx
         zw+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2/PYqbbM2V2enFkk0HEgpvlpXG2F33WJD1plhh46ikk=;
        b=j7+e8tQtZR5DHdrjVopyejrbJsdIiAGPIeTgGWBaf4p+TX8IE8S6+osZx05jqMenzx
         E5UXomogSDY3Nxch3miyqVDmYj6HgIrpdLUDDzihzrxHx7he9o4QYbn9PCwq/hTGT/mq
         qOABA3AzHb9SSO7AXFZJHID15doiMl3YaMW0GC0cP4gftFteH38fb4UK2Vxa3XczNBlN
         bkjyhobenQFfSkvtK+7+6NDq6QTgCKGCgH8/kPS68kWhIs5ds5HjnWVr43/VXUBaaSqU
         7RheIjAwvwesPR6IOMqaQ7hs+srAFTh+zksaBlT39IQQc45cvRgpFnet32x0HKrfrbBn
         mzqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="bSEk/I22";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2/PYqbbM2V2enFkk0HEgpvlpXG2F33WJD1plhh46ikk=;
        b=ApM3yYa/EqXaGY+cX1r584OvjttcOR9MAw0W88QeLVseySbZ56izxKKPlmzPyRd9yH
         BM+0qv5zeTnqAtc1jGTmaJopY3O9Mt0MUHvENuWqBtIr541XJVDWtz9JuqgO2j80JrAN
         6wrPJ431H3xgkDwSa4QMJUcCxX6R+tT1woeokTLm0h1+K3EehtxFxR79o7Bt1ACQcH+Y
         ltzNv+CzDOxAMJ5BGKvs5V+l4+TqgI/0+47mA9oVj5w9t0V3M94ZgIzHqBg6miBxN0qO
         0cz3BP1AgBKCp2uRDCpunw/f+J+14CQ1XR/9bSPUBinLlbtWIul+F4uGJF+0B39SdrMp
         cFww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2/PYqbbM2V2enFkk0HEgpvlpXG2F33WJD1plhh46ikk=;
        b=bFBDcWnu4D/JEdbl6xN1sbdNt9kgBqH/eVFeBqwArD9D2L2m+DrG2kmh2xion7IsSJ
         yPkXO+Y3WUegay43ICnw3yP82gUGGQMZNONGfCSS+v7Pak4KU9HS8MVmb04TL6d8LKYZ
         55hUdcSDfNgBbt2KmoGOg1YZSnSKB2UdZpPdUhxWSmxYXXz1Z/PGPZMg7ywb+0qpuoq2
         +JkPg+1GmwEgPWZEcuAX/8kfdpFOoI978PuGjxb+Q6ytBGasCVxMU5Jnhj4WQMtC26RA
         eMUx8TpSAjwTBM9e1JxcYqwT/2guz0hKs+uXopR0UErOpFIIPd8DBoM9AnG8NbQzJvqQ
         UVvg==
X-Gm-Message-State: AOAM5331rWQ8VExtCFlEDA0PNMUGaXMerC2c9xMtTaeNzBYx1c0xeAGY
	KYI3okv7FtKPcDLIIKv4bNo=
X-Google-Smtp-Source: ABdhPJxvqlbW5W1kTSXYpcLx2YUvhOi4pwV8t4kdwfU6rkS84RNI9nCysjv2jxxpRuhdpHGyQKOJXA==
X-Received: by 2002:a63:f011:: with SMTP id k17mr5126549pgh.227.1612546256654;
        Fri, 05 Feb 2021 09:30:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8b8a:: with SMTP id ay10ls4639480plb.5.gmail; Fri,
 05 Feb 2021 09:30:56 -0800 (PST)
X-Received: by 2002:a17:90a:550c:: with SMTP id b12mr1968860pji.144.1612546255993;
        Fri, 05 Feb 2021 09:30:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612546255; cv=none;
        d=google.com; s=arc-20160816;
        b=T5emyCaOixIW03YYa41OLN398fhoxq7r1sVFLkuqR2+X4XBkc6Mh7PsqjjciTSc7WU
         dXhm3deGQBHx/LVGEtIyG9cHOUO5PxpJnv/maoBJsVS/U0VEeUwFZT6+O9h9Opq0Ibhk
         O0izLhOUIaFlrfQQgHtpqn+6ED3emuJBNiy1gT9ijFnGoi5IH6i60+qP9skYnoz7yzB4
         RBQLXJryzMSfRBM6EuTNXgqXztKDdhdcQ35eFfJmZEOM7UVvjs2zGx3SYvg4/+w89SBg
         Qmxgrs3YAjL2PDtGjegsNbMycXT7gf7vs6Zzc4GzjGi/M1EZd8j8IolZlNZXTz1umz3B
         xbFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dqdujun8wGwVR12tCa3y7+xoN9EW0D48IZceWkJl7oI=;
        b=D8YCOolTx9ITM29yenwXAg9DX0JfJDMkBKbQqtc1WbHMHppHmRa9UDCD9Q/gvlHBOL
         RhwfS3hvYriP/q4y+QzQKmKe0UgGJiGgyUHCZhmbHauyFhbHFzbSYy4Q06ApoJZDIxNM
         6h+KHTnvpLViol0UGk6URnYbeChWfKrqmAChWjFk+02NTFCu8qgpgDwdhSPwDnhgpEos
         SUvYiS8szymno/9rqLaSCPkT2CrvnPhTa+x1W9GkpSZqk1jjCNR8Kz8M+N9S4YRQjKkw
         N+yc03F3KQXDS5t8M6ifxcftlS0utWxdn9pC0jUn79Vgk+KP9iVG7UmBu3P2SDjG6Jv/
         Azcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="bSEk/I22";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id p10si463857plq.0.2021.02.05.09.30.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 09:30:55 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id a16so3911773plh.8
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 09:30:55 -0800 (PST)
X-Received: by 2002:a17:90b:350b:: with SMTP id ls11mr5060341pjb.166.1612546255453;
 Fri, 05 Feb 2021 09:30:55 -0800 (PST)
MIME-Version: 1.0
References: <20210204150100.GE20815@willie-the-truck> <20210204163721.91295-1-lecopzer@gmail.com>
 <20210205171859.GE22665@willie-the-truck>
In-Reply-To: <20210205171859.GE22665@willie-the-truck>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 5 Feb 2021 18:30:44 +0100
Message-ID: <CAAeHK+zppv6P+PqAuZqAfd7++QxhA1rPX6vdY5MyYK_v6YdXSA@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b="bSEk/I22";       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::631
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

On Fri, Feb 5, 2021 at 6:19 PM Will Deacon <will@kernel.org> wrote:
>
> On Fri, Feb 05, 2021 at 12:37:21AM +0800, Lecopzer Chen wrote:
> >
> > > On Thu, Feb 04, 2021 at 10:46:12PM +0800, Lecopzer Chen wrote:
> > > > > On Sat, Jan 09, 2021 at 06:32:49PM +0800, Lecopzer Chen wrote:
> > > > > > Linux support KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> > > > > > ("kasan: support backing vmalloc space with real shadow memory")
> > > > > >
> > > > > > Like how the MODULES_VADDR does now, just not to early populate
> > > > > > the VMALLOC_START between VMALLOC_END.
> > > > > > similarly, the kernel code mapping is now in the VMALLOC area and
> > > > > > should keep these area populated.
> > > > > >
> > > > > > Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> > > > > > ---
> > > > > >  arch/arm64/mm/kasan_init.c | 23 ++++++++++++++++++-----
> > > > > >  1 file changed, 18 insertions(+), 5 deletions(-)
> > > > > >
> > > > > > diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> > > > > > index d8e66c78440e..39b218a64279 100644
> > > > > > --- a/arch/arm64/mm/kasan_init.c
> > > > > > +++ b/arch/arm64/mm/kasan_init.c
> > > > > > @@ -214,6 +214,7 @@ static void __init kasan_init_shadow(void)
> > > > > >  {
> > > > > >   u64 kimg_shadow_start, kimg_shadow_end;
> > > > > >   u64 mod_shadow_start, mod_shadow_end;
> > > > > > + u64 vmalloc_shadow_start, vmalloc_shadow_end;
> > > > > >   phys_addr_t pa_start, pa_end;
> > > > > >   u64 i;
> > > > > >
> > > > > > @@ -223,6 +224,9 @@ static void __init kasan_init_shadow(void)
> > > > > >   mod_shadow_start = (u64)kasan_mem_to_shadow((void *)MODULES_VADDR);
> > > > > >   mod_shadow_end = (u64)kasan_mem_to_shadow((void *)MODULES_END);
> > > > > >
> > > > > > + vmalloc_shadow_start = (u64)kasan_mem_to_shadow((void *)VMALLOC_START);
> > > > > > + vmalloc_shadow_end = (u64)kasan_mem_to_shadow((void *)VMALLOC_END);
> > > > > > +
> > > > > >   /*
> > > > > >    * We are going to perform proper setup of shadow memory.
> > > > > >    * At first we should unmap early shadow (clear_pgds() call below).
> > > > > > @@ -241,12 +245,21 @@ static void __init kasan_init_shadow(void)
> > > > > >
> > > > > >   kasan_populate_early_shadow(kasan_mem_to_shadow((void *)PAGE_END),
> > > > > >                              (void *)mod_shadow_start);
> > > > > > - kasan_populate_early_shadow((void *)kimg_shadow_end,
> > > > > > -                            (void *)KASAN_SHADOW_END);
> > > > > > + if (IS_ENABLED(CONFIG_KASAN_VMALLOC)) {
> > > > >
> > > > > Do we really need yet another CONFIG option for KASAN? What's the use-case
> > > > > for *not* enabling this if you're already enabling one of the KASAN
> > > > > backends?
> > > >
> > > > As I know, KASAN_VMALLOC now only supports KASAN_GENERIC and also
> > > > KASAN_VMALLOC uses more memory to map real shadow memory (1/8 of vmalloc va).
> > >
> > > The shadow is allocated dynamically though, isn't it?
> >
> > Yes, but It's still a cost.
> >
> > > > There should be someone can enable KASAN_GENERIC but can't use VMALLOC
> > > > due to memory issue.
> > >
> > > That doesn't sound particularly realistic to me. The reason I'm pushing here
> > > is because I would _really_ like to move to VMAP stack unconditionally, and
> > > that would effectively force KASAN_VMALLOC to be set if KASAN is in use.
> > >
> > > So unless there's a really good reason not to do that, please can we make
> > > this unconditional for arm64? Pretty please?
> >
> > I think it's fine since we have a good reason.
> > Also if someone have memory issue in KASAN_VMALLOC,
> > they can use SW_TAG, right?
> >
> > However the SW_TAG/HW_TAG is not supported VMALLOC yet.
> > So the code would be like
> >
> >       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
>
> Just make this CONFIG_KASAN_VMALLOC, since that depends on KASAN_GENERIC.
>
> >               /* explain the relationship between
> >                * KASAN_GENERIC and KASAN_VMALLOC in arm64
> >                * XXX: because we want VMAP stack....
> >                */
>
> I don't understand the relation with SW_TAGS. The VMAP_STACK dependency is:
>
>         depends on !KASAN || KASAN_HW_TAGS || KASAN_VMALLOC

This means that VMAP_STACK can be only enabled if KASAN_HW_TAGS=y or
if KASAN_VMALLOC=y for other modes.

>
> which doesn't mention SW_TAGS at all. So that seems to imply that SW_TAGS
> and VMAP_STACK are mutually exclusive :(

SW_TAGS doesn't yet have vmalloc support, so it's not compatible with
VMAP_STACK. Once vmalloc support is added to SW_TAGS, KASAN_VMALLOC
should be allowed to be enabled with SW_TAGS. This series is a step
towards having that support, but doesn't implement it. That will be a
separate effort.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bzppv6P%2BPqAuZqAfd7%2B%2BQxhA1rPX6vdY5MyYK_v6YdXSA%40mail.gmail.com.
