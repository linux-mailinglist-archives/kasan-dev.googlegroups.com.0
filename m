Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMU6Q2AAMGQEOB4LDRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BBC72F7A47
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 13:48:51 +0100 (CET)
Received: by mail-oi1-x238.google.com with SMTP id z7sf4117808oic.21
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 04:48:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610714930; cv=pass;
        d=google.com; s=arc-20160816;
        b=CyusaO5/RTUR/COHzn6p4NDZ2D9bzTBNAmP1xDgsTb54BxyqJ6OpBW///WJRAllE07
         6jCpIkdq+R91M+1/uIxfTVeklAfy+UIcrvNMEbxwhgCesD5IOhc9KkhYxS3EDWEXP2ft
         S9j8lRMi1/TLKKJNyVruV8jU806gqINFNjuJePR10evpT3985NW654Wx39YHaLEbgdVu
         ISl/LuY6/lfXtrg0op7Qubqw79IadKMImtx4Yx7o+64o/g4YLGjPqXIs7S25v3I+BL+A
         dHVHqXcOFV/C1HvIV69n3prOJd+nd8LlAV2cgIDcpkcNKcCKzT5bDpaxFEhXGxPzM47P
         JECw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=X7uzrrzfm02/To8iazxW41vG3WpA0lZ7g0ZyPWawGU4=;
        b=cAmwH59RqqbxBPPPdKu/B0iArLo02fcKFcdipLrLGoP2HvEo1W2c3HsR0TyxyeIn+o
         TMa5tIwQH5JaaInWXrNCJ8w6mIXnCJ0vpkZO+rxl+1PzTu8BWj7cSXpyYgdLNtx0eMWN
         6r55n+ITEaINAKP+CAv5HUl+uNi6HL01yC4B3ewesrbTiUTYZ5/6zrGJgBVgEgsdUrGi
         m2OrUQ3WotYmy/mluM/0ZJqEAVF1bWfl0WdbwvfnPQWN19MFCbS3aPxrd+Ekz2oQYNy6
         ruCAdluTa9n4dNxgZ4OoBCZaP18/IK/hz+WVMiiq1zAsoA4PCPIpOxYxEHKdZv7gCM2I
         oFkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Nf+g+Cuf;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=X7uzrrzfm02/To8iazxW41vG3WpA0lZ7g0ZyPWawGU4=;
        b=J97Vlao3zb3vwVG6ngpHJ3BxYSo4tn+LaKJ6vPdpe01w3/wDQ+gv/WESPc6qtdB+XU
         CXMA8TOK4MMVO+pW/30UJP/kY+M1ITA3a/+zSustozEfnOOP7624U0ZDPHQADXN6ejdA
         O7EcBMdr4cKrEn0esS/hOtGF7hFsp7e4bXFg0csocYv9vc5mOBp+X7Yb+sJ50KF1QRH4
         DFahM5qoB4R9HN0ctnJeKsJ8l/mPjWkUUZgqqoNyNAdmj/xuUcYdQ+lOR2pqFU/+ERin
         W7ltpeYznyTKzaWmvjBBPNCDoTIqRT74p4xOZJ5XuXuI4HV6Gaj0SBozGjq62fs9uzQa
         S5MA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=X7uzrrzfm02/To8iazxW41vG3WpA0lZ7g0ZyPWawGU4=;
        b=uSwghVjibX2qSd83ei+OV3p5zH19xcsn5Uaa1JrbZS5Vd7/jOvdJ7V0aFMNZVv89EY
         jaLRnsHNPZ6CUWKDxlJDA8Ba6A1Ec/20XmUYirUdbKy3ck1WrPiyPCsQR4D6y+w9XHfj
         O1ReFO82e2f/0DO5oIzIch10dHMvqm1NngUAcsgx+oVOHXd2TWEG13Cl5Gzoc3Pucpa+
         3oXhdA6aLcaTKxeY4Uyo/uXgTsPJVdVK4JGljNPkStQznhrkf60M/+6A4U/wBSw9PCZX
         s7/jc4jwRzUXWav+rj1oApj46ZS0CmWVmHZgdDOO3Nwe+TDE+/cq7gyYfXBACtSGxBmC
         vd8w==
X-Gm-Message-State: AOAM533icG0XRNqNj6igy2LMG0sS5RrChyXDLZUO/edRt5mGFEYREeOA
	zbKPSnsQ5OcLLnGs1h47pkQ=
X-Google-Smtp-Source: ABdhPJyeqH+xcv8q6eJP2y5TQ+0roaDt53kkKQEDhEbJKZVKc2H9M8sUK0pqJHb73nfEu97aWWmLBg==
X-Received: by 2002:a05:6830:2113:: with SMTP id i19mr7976597otc.209.1610714930637;
        Fri, 15 Jan 2021 04:48:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c413:: with SMTP id u19ls2134390oif.11.gmail; Fri, 15
 Jan 2021 04:48:50 -0800 (PST)
X-Received: by 2002:a05:6808:28a:: with SMTP id z10mr5796872oic.174.1610714930255;
        Fri, 15 Jan 2021 04:48:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610714930; cv=none;
        d=google.com; s=arc-20160816;
        b=KKytIHrvpeDieStReI03Jms953zNXQcjmbyAU7DPJBPZ2qfZvoMcT/O16H+u/brKj+
         c0H292pg9idy4b0OqNfHG2GV1sxPjwY0AgTWcxVnpA2CN79gjcrTz02syQEICtYevnjx
         awm5PDH81c58HPhsx6Z7RjqKLjUS7ANTR4njUXoibKaXEooh3PNRvC8Q5eH+0tbolO4m
         yOfqBlsbv9fQq20k13LLXhISs8I3kYMfMdQrk3HF9mV010ZbhDOwtCFnDhxFRvcc9+Ce
         O3s3adBicCwOTJUqoLq/axEinQP8LmQxEvPZtZ0CSpBCiMFWphYc1SRfsAi+C7+E3Uo3
         i2jw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IwEZ0vJjMhibVYpx1I3U5rxwVwXQCQH8qptIRt+vn6E=;
        b=Dh4+KwlPqvAUKvcUBzpQa9Aq5K1NXlj6LB3Wpb4YWPMpFsHg2WmdQubJ3mRXS3wKoV
         MVgFvWrpNCmD0RprJ5TQkS41X7g6lXRaa6JqOp0zJzqIURXnM52lpoAsNgsaXpEDLYS7
         /gd4pi6H1uzWYG/upccj3KSEJUlnkryqB83g+D/vwqhZNZParCE3V3O0DXwfwHu9ZlCO
         sORFQQlOnZDvl+/iSs5LLUM1/pnD2Ux0b5ljaMgyIjiJujEMwKc3kPOvi8ZKXnE535RR
         w2Z8pbk7HIz4KAz4UGJzrXLk5IaaIr4o/hJx6DAdxVfVhqJkSWJunWen8A/fmsf+W618
         x36A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Nf+g+Cuf;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id f7si534839otf.3.2021.01.15.04.48.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 04:48:50 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id b8so4664382plx.0
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 04:48:50 -0800 (PST)
X-Received: by 2002:a17:902:ff06:b029:de:362c:bd0b with SMTP id
 f6-20020a170902ff06b02900de362cbd0bmr11764451plj.13.1610714929783; Fri, 15
 Jan 2021 04:48:49 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610652791.git.andreyknvl@google.com> <3d9e6dece676e9da49d9913c78fd647db7dad552.1610652791.git.andreyknvl@google.com>
 <20210115104945.GB16707@gaia>
In-Reply-To: <20210115104945.GB16707@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Jan 2021 13:48:38 +0100
Message-ID: <CAAeHK+w49og7TTfwA3MdySkXsc0ndNYDNTO2o2YTo=kqb7U3Fw@mail.gmail.com>
Subject: Re: [PATCH v2 2/2] kasan, arm64: fix pointer tags in KASAN reports
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Nf+g+Cuf;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::630
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

On Fri, Jan 15, 2021 at 11:49 AM Catalin Marinas
<catalin.marinas@arm.com> wrote:
>
> On Thu, Jan 14, 2021 at 08:33:57PM +0100, Andrey Konovalov wrote:
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
> >       /*
> >        * SAS bits aren't set for all faults reported in EL1, so we can't
> >        * find out access size.
>
> I already replied here but I don't see any change in v2:
>
> https://lore.kernel.org/linux-arm-kernel/20210113165441.GC27045@gaia/

Hi Catalin,

Sorry, Gmail decided to mark all your emails as spam for some reason,
so I didn't see any of them :(

I'll fix this in v3.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bw49og7TTfwA3MdySkXsc0ndNYDNTO2o2YTo%3Dkqb7U3Fw%40mail.gmail.com.
