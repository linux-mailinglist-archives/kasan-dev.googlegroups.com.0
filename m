Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPEGQ6AAMGQEEXNFXGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id F0BFF2F80CE
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 17:30:53 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id p80sf4792140ybg.10
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 08:30:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610728253; cv=pass;
        d=google.com; s=arc-20160816;
        b=cG77D7SGBvkLqiCVe7iB3gUQzKAyqZLDoOaJfeZuj1Dhio0isBv4ybPA3+bNaKyNZJ
         kxMgLGNkRfjbCuBMw558t6yr4Kn3MIpqdyvHcp/mZLlrySeowlDGPURVKq3zIHqtetQF
         b13F03Am7eY4FeNTWHaT1hR50il9E3HLtjhNSNDN9A2+8X/YwKuxb87Nq77jq5K2AckH
         kWy4KcbKgjUc0oN1mQU6yB1KGpIaxExr2ryx3hdVncNiwUnHM/2gGckFjE9ts0X0Yr0T
         SRHvpwlqIYVIjAL1L3nb6uy/G3Be+pcCBzf+nMcNDnDXwhLmNFgMUbt8gyWR6Eo2Ntc1
         b+Uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=NOyW9AuVA8BIynTAjzKfTt6MBDQ/jBVMzK3BKpG3hNg=;
        b=lKU143xx1mYUTMI5tndXlUa67mvNQyc6DHZLU8vSH7abHLVNoA80a7c4zWO4c97mhS
         HHq0vknFgwLudZF8UJ+ek/bZJ12SNtzf9zpZxryRb9qlHIeL43LKExnlgL9E71GQG5jr
         LYFQbBD0InQ3i/ZTWsxPsGPk7x7MGnN47cg0b9i9pLKmXy7i2sYoJPto6BBeeSvrf7fF
         7nsyE4nI2HFBjEm5BUSqylZrmI9UKM/Lo1Y/s4KK5j+EkEpJ+UOw/y6XzLOAG5wpPx20
         F3/3XEF7nbj0SDEXj5pmn5+h+AKAS+nxC4QvAGJvetNRw7vcGD+9bRG8iYHBityBwcmW
         cLOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mjEuakf3;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NOyW9AuVA8BIynTAjzKfTt6MBDQ/jBVMzK3BKpG3hNg=;
        b=UgmAIlghnX62H0FX4g9K1itDRmIkQheFJd13a6eHrKwmOiR6INqnuoTeGzTPzACdpB
         CT+Nnck+Fk1YbBFU1k2bQ/lB/llHbukFmoYHHdd0bxGPDEXvyQBmN7SGp4uJKcW15ENE
         k9+6vtj69yzlik9uoC6PxmoM9rsHgubCiItAN5mO0Rmc9KbIq9txWkoLqbcycSgxGXut
         Xiof63atdvX2kxjmgdqZ5Lt4/7B9rJPuL5LiqamM9k1KbxmD0QyYwEBs1j3QxPw9G8Lx
         Pe+EbkUeBDQ5ZfLHTL9h2Hcc9nL3sBh3L8opVmX5K4kS7XqJWD9q9qGj1Z+MJ7S+RxeN
         zuIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NOyW9AuVA8BIynTAjzKfTt6MBDQ/jBVMzK3BKpG3hNg=;
        b=qlwWK2TXB6tYdcdAXI2qIO+0uv+w2NWTMLJJZEhwwjANTU3QjAg3PR3XH45T4pUnfP
         l376yxrwVFUVNXk+eo15v8gxKQ1ZqpqYAguWwHTEvDYKAzgWs35H2TzNoCDPfKSH24sh
         0oIaVmMPlcdbcXTq9o6QVFalC+qs17cctOdmIniN+Z0K05xmm3hLPjP6R1/YSf9XKKXR
         cN6+M0rzM2WLU1eQ0B6uIOkDp37f1gUk4z5YTHD/Vtg63IfqhHT2YeL7S2F63TVXBj/2
         YgbitLoWbZ6/fRJD7fG+fQ4H5vbIc5Tm/h2/9/H0LB6pl+GovuKlX3ZpeL1FzijoLFvb
         Ps5g==
X-Gm-Message-State: AOAM533Ml3oBkLS+jJpzGy3BAnmVlO3/cGn7CR+s38GuCyPotWvHJNbc
	1CEQ4yOAdoKdUevBWFWGZqk=
X-Google-Smtp-Source: ABdhPJycYI5Z5JI1r4HMtx832/+Ly2lN1UIc+FiLGUhu4HFHq8YAkOlbBPHpgQdvVYE9GcdLO2Fp4A==
X-Received: by 2002:a25:500b:: with SMTP id e11mr18844753ybb.138.1610728253055;
        Fri, 15 Jan 2021 08:30:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:e407:: with SMTP id b7ls4661620ybh.6.gmail; Fri, 15 Jan
 2021 08:30:52 -0800 (PST)
X-Received: by 2002:a25:2d68:: with SMTP id s40mr19626622ybe.163.1610728252595;
        Fri, 15 Jan 2021 08:30:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610728252; cv=none;
        d=google.com; s=arc-20160816;
        b=BiqN49luwegMaDM1nrPMAg3aIfpnAdIMTaR9YhRN2TlypRKsBDiZ5VfUkyKZoF3ox6
         QGQMQOmpqYYmpbVeB6MdjjoFyWKkSRbpGdu4mfReeLFUVn/t9Xk2rb8vXIrX1/aGeXv/
         988LOFObSJbfSbxFGK3eoxZ2Il4Kp5VeVaRYazg5+VAcF8X1JK9YTQbaRybaJ6v6QzPj
         EPQSYb1itingNIh7OuoA67pkMoysvsy2JVB88gbdNNaCWQSok3GEOT68/bBckidLoR0d
         A8DalPOF6oPfUsqWaxDj+r/Wjz2IXJQOHTIwn9+INh83nNLTIC3ZdCzBDfY/CKvFStny
         iNxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uEsRmwU2Zg9Pm7ZYfxs6cFkd37PnI+Hzer0Thh9MkrA=;
        b=ymjvIfrCsYchJEG9zDhUM0uvk9SN4/hgYI1NODv263s6dcCUCrHUXG++xBsqg7ROw2
         Smtr1O35d3Hll1FqdbCLRTtOJ8a5Vvyj9qiEH48LqpOhXql838AElPX8dVD1QItuHdtt
         K1p+sxg6QshISBNPHCYkmzPFG/Yn69rRzlFEpCATl5of3QafDHxTcRkyFPFjv8IN0HQS
         yVxbs6WJKOXSbGVSI6Qx42V7RY3pcQgHSw4m1LpsPqS7P7KCAMGgx1htKzbKvzz+suvU
         epqcmJBKT41pEHs0Juoz7jIjRAQpFlPmt9zdRla1BA6KpVyE308MWU+6ta/qqRr0QeXj
         wvdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mjEuakf3;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id k19si700198ybj.5.2021.01.15.08.30.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 08:30:52 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id x126so5800113pfc.7
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 08:30:52 -0800 (PST)
X-Received: by 2002:a62:e309:0:b029:1ae:5b4a:3199 with SMTP id
 g9-20020a62e3090000b02901ae5b4a3199mr13127964pfh.24.1610728252059; Fri, 15
 Jan 2021 08:30:52 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610553773.git.andreyknvl@google.com> <1965508bcbec62699715d32bef91628ef55b4b44.1610553774.git.andreyknvl@google.com>
 <20210113165441.GC27045@gaia>
In-Reply-To: <20210113165441.GC27045@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Jan 2021 17:30:40 +0100
Message-ID: <CAAeHK+y8VyBnAmx_c6N6-40RqKSUKpn-vzfeOEhzAnij93hnqw@mail.gmail.com>
Subject: Re: [PATCH 2/2] kasan, arm64: fix pointer tags in KASAN reports
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mjEuakf3;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::434
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

On Wed, Jan 13, 2021 at 5:54 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Wed, Jan 13, 2021 at 05:03:30PM +0100, Andrey Konovalov wrote:
> > As of the "arm64: expose FAR_EL1 tag bits in siginfo" patch, the address
> > that is passed to report_tag_fault has pointer tags in the format of 0x0X,
> > while KASAN uses 0xFX format (note the difference in the top 4 bits).
> >
> > Fix up the pointer tag before calling kasan_report.
> >
> > Link: https://linux-review.googlesource.com/id/I9ced973866036d8679e8f4ae325de547eb969649
> > Fixes: dceec3ff7807 ("arm64: expose FAR_EL1 tag bits in siginfo")
> > Fixes: 4291e9ee6189 ("kasan, arm64: print report from tag fault handler")
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > ---
> >  arch/arm64/mm/fault.c | 2 ++
> >  1 file changed, 2 insertions(+)
> >
> > diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> > index 3c40da479899..a218f6f2fdc8 100644
> > --- a/arch/arm64/mm/fault.c
> > +++ b/arch/arm64/mm/fault.c
> > @@ -304,6 +304,8 @@ static void report_tag_fault(unsigned long addr, unsigned int esr,
> >  {
> >       bool is_write  = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
> >
> > +     /* The format of KASAN tags is 0xF<x>. */
> > +     addr |= (0xF0UL << MTE_TAG_SHIFT);
>
> Ah, I see, that top 4 bits are zeroed by do_tag_check_fault(). When this
> was added, the only tag faults were generated for user addresses.
>
> Anyway, I'd rather fix it in there based on bit 55, something like (only
> compile-tested):
>
> diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> index 3c40da479899..2b71079d2d32 100644
> --- a/arch/arm64/mm/fault.c
> +++ b/arch/arm64/mm/fault.c
> @@ -709,10 +709,11 @@ static int do_tag_check_fault(unsigned long far, unsigned int esr,
>                               struct pt_regs *regs)
>  {
>         /*
> -        * The architecture specifies that bits 63:60 of FAR_EL1 are UNKNOWN for tag
> -        * check faults. Mask them out now so that userspace doesn't see them.
> +        * The architecture specifies that bits 63:60 of FAR_EL1 are UNKNOWN
> +        * for tag check faults. Set them to the corresponding bits in the
> +        * untagged address.
>          */
> -       far &= (1UL << 60) - 1;
> +       far = (untagged_addr(far) & ~MTE_TAG_MASK) | (far & MTE_TAG_MASK) ;
>         do_bad_area(far, esr, regs);
>         return 0;
>  }

BTW, we can do "untagged_addr(far) | (far & MTE_TAG_MASK)" here, as
untagged_addr() doesn't change kernel pointers.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2By8VyBnAmx_c6N6-40RqKSUKpn-vzfeOEhzAnij93hnqw%40mail.gmail.com.
