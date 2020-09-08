Return-Path: <kasan-dev+bncBDDL3KWR4EBRBM5U335AKGQEWO24O2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id AF3542612F5
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 16:50:28 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id v195sf289076oia.18
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 07:50:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599576627; cv=pass;
        d=google.com; s=arc-20160816;
        b=sFLhWssIzJM0OmfBsstdYFXwvm/QfqHN+xDe5UcSh/AUeBTEmtdJEhMzqIGGOUF6sf
         KuL1tcwyGAxHr3GOtIYZ4ucor3xj7bBu7i0HYyuVyMsN2itxX3b21kh+ZPRa6ry8FeE4
         I4ZcGg3++FvF+k3wPBX98RcP0FxsXdFwriGForV9PtTs3WVrwiU6ySAdHQ6Ttg36HEuM
         JitiC2Sqg4vYCuh0zftHZ9JDkQY6GPH01lYnbCs4l0NB4ZH0H5RcCQG+kcHDi7dMPIOn
         OnqTMIbtm9FlM6ThAzkABoKb4I9OZ5tiazoDSFnB+dB3praK0yUFDkMvMB4myn5rgePX
         B+ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=Bm0VNykcapHkFa4LOAzox3UlI4q5e8T4p0p7qxkW7R4=;
        b=uxdzLCULJvCJvW3GVU3xRqr988mc6Ts7lYOSocn8uZWYmXY389XrU8han6ZhMWPs2u
         laE4H74kpLp/YTCXvDUMvcsTEMEUy6LCV7I24eZ8xJo8hIuNk0y1CzTzZUC8UrTu+diZ
         StLv8ziEeGvYAYE89X3rGdfPaJHTz/UnxDmU08f/Og3OAkLnGgwMEQmrWXScht86BLf/
         CO8q5izNIasAGvthgJMJc3nictYP6kC2yyRqWCgZ+I2HlVaWUzM6UHIRh6WtxR+7Aem5
         mhyaIyqCiutMQfGQAeZvCwGzncjSxrY6emHNHsGd3t9cknjmJihDA/zRRdCUMbvjyjG1
         g4HA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Bm0VNykcapHkFa4LOAzox3UlI4q5e8T4p0p7qxkW7R4=;
        b=B4ctw/3R3iQPICidHxChQO7hXFyPYuywzq1M9IpbTE1RYLldXJUcZpRjOXXr5nMxda
         Y8arTThZMCCJqGU1aaIXAWAC037m9w52fFxSXXsu/L52WgwWfcqagAIbeX/dvrvXb4MZ
         SFHfEVJt4DEJGM0Eou4b+1q998k+zo8RjxhCH4zUJcCv0iyhpVtE8q0ePdzNG0T+ruV6
         FTyPFTAhU6RfGgR9xDx4kB7izEjxQVKjiGAQd9/iU3uRFZtFwGdSyqJn2HLoP8pyfwsw
         JIGkwNQQ4Tyf30Q4Ov5q++BqKVVv46yGRhgKgoRnKP2KQ9n+WK/LFb93mM0FeyO9wl0D
         9LNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Bm0VNykcapHkFa4LOAzox3UlI4q5e8T4p0p7qxkW7R4=;
        b=fgyRDolD8d/rWsbmuZTD87bNReasgHGx/iwwEwN2qgsriQttJ30aDEFSK4HJoc46B7
         HnXvDinqJFskGsC7wlrnF9TIL5H61IxMYCZNioJ/ftYBi1p+qi5NnWmtmjmFjGuR8s5j
         cxr9NJbR7VnXRT/L95lbBQVll+HshO3LIAKoAm03KuvKZwxvOS53KbnXVqb43hGBOPZ/
         YGDsjbbbm/g1rytTdfr0Lo4xVhUzlPKgj78+wDM3bNH0RdQn8brSvbWMOPWcsSIz1VXz
         9784YL7gtczsnBDF85fjRDAxBUUbWF/6u3Me5V8k/uSRp2aiyRwrTlrNaZNNJ4jrNd7J
         x6wg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533WhzeLcEUjyx7dCPF785lwoWHF9HE31Q4dJgTLb+DovJzYzS+B
	u7RAccV4JsHbIiu5XfGefg4=
X-Google-Smtp-Source: ABdhPJw+PJORqx/URxS6uUzm+Z1H6ZxQSlvXvpeTlp/gHO06RDyultz8Ak+E5TP32dn/l7AIxKW13Q==
X-Received: by 2002:a9d:128f:: with SMTP id g15mr17658631otg.93.1599576627586;
        Tue, 08 Sep 2020 07:50:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4816:: with SMTP id v22ls102150oia.6.gmail; Tue, 08 Sep
 2020 07:50:27 -0700 (PDT)
X-Received: by 2002:aca:1807:: with SMTP id h7mr2925650oih.91.1599576627221;
        Tue, 08 Sep 2020 07:50:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599576627; cv=none;
        d=google.com; s=arc-20160816;
        b=h3+FaJOIO3Ebfrb1tZdlmid08Q9boyrxVGsk29oG4ce3LtYuhOLdOa9mi9Wzk4XtNm
         56JrO/KBdyrBSBOiMGD0J+tYNAA8APka9hmLBUn/8MBczLHO5IQqzS7dPubgc/MU7+UW
         ByZFMaIoSxRE1dm1wCZeWgJeUJKeZPF4U0Rje454/Yonz2jlLeIUgcOlEn+f5L0uJnDe
         /8HWc9OhgQIe1scUlu9cYKgtn696fQ01Gav6z4XipsDDWLMLek7vLEclclAhgR7lntPd
         BABslW9XqzNqa/WxeALnC5k1QZKVYbp6kUjnxPvwcCA+sS/o12vVY0Qy3b+ba22+NpLo
         4rzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=uMjqoCJUkE47tOrGF84mZmFcjWNk0m/2kg1m5CkKL2w=;
        b=scohXpzDJaITtgXy4KosTN50AHBssHpWrF8qxPeDon6wfZsdB+iheTakZptoPxAFVn
         qbbP2eG1UWCipBe10i/VSpo07SNaG6Qi0WMNf3yb+pFwEiRoBxsPPX9RhL5WE1Ra/IC3
         TnQqAVQitk36OPXCXWXRONUdsE1g1DRmK1Oyq5e/OZ/1wkGdlT7P7e+rNPqBSkNnyeWu
         YkHoQ64bN7ICRxiX1J2d+DqRnYHFz/2M7GtcrhJSJeENWMCa85NAJLkubu7N93mkQVWh
         aB3GejcgzJjfUR7hqlcz0NcxePONS1Z/dO1r/fTF0IfyEyWQMoPmrwHrVZHPggz1iKAv
         Y4IQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m3si974700otk.4.2020.09.08.07.50.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Sep 2020 07:50:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [46.69.195.48])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 8D4D522B49;
	Tue,  8 Sep 2020 14:50:22 +0000 (UTC)
Date: Tue, 8 Sep 2020 15:50:20 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH 20/35] arm64: mte: Add in-kernel MTE helpers
Message-ID: <20200908145019.GH25591@gaia>
References: <cover.1597425745.git.andreyknvl@google.com>
 <2cf260bdc20793419e32240d2a3e692b0adf1f80.1597425745.git.andreyknvl@google.com>
 <20200827093808.GB29264@gaia>
 <CAAeHK+w-NLfCXFxJNEQ2pLpS6P3KCtAWJrxAFog9=BNiZ58wAQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+w-NLfCXFxJNEQ2pLpS6P3KCtAWJrxAFog9=BNiZ58wAQ@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Tue, Sep 08, 2020 at 03:23:20PM +0200, Andrey Konovalov wrote:
> On Thu, Aug 27, 2020 at 11:38 AM Catalin Marinas
> <catalin.marinas@arm.com> wrote:
> > On Fri, Aug 14, 2020 at 07:27:02PM +0200, Andrey Konovalov wrote:
> > > diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> > > index 1c99fcadb58c..733be1cb5c95 100644
> > > --- a/arch/arm64/include/asm/mte.h
> > > +++ b/arch/arm64/include/asm/mte.h
> > > @@ -5,14 +5,19 @@
> > >  #ifndef __ASM_MTE_H
> > >  #define __ASM_MTE_H
> > >
> > > -#define MTE_GRANULE_SIZE     UL(16)
> > > +#include <asm/mte_asm.h>
> >
> > So the reason for this move is to include it in asm/cache.h. Fine by
> > me but...
> >
> > >  #define MTE_GRANULE_MASK     (~(MTE_GRANULE_SIZE - 1))
> > >  #define MTE_TAG_SHIFT                56
> > >  #define MTE_TAG_SIZE         4
> > > +#define MTE_TAG_MASK         GENMASK((MTE_TAG_SHIFT + (MTE_TAG_SIZE - 1)), MTE_TAG_SHIFT)
> > > +#define MTE_TAG_MAX          (MTE_TAG_MASK >> MTE_TAG_SHIFT)
> >
> > ... I'd rather move all these definitions in a file with a more
> > meaningful name like mte-def.h. The _asm implies being meant for .S
> > files inclusion which isn't the case.
> >
> > > diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> > > index eb39504e390a..e2d708b4583d 100644
> > > --- a/arch/arm64/kernel/mte.c
> > > +++ b/arch/arm64/kernel/mte.c
> > > @@ -72,6 +74,47 @@ int memcmp_pages(struct page *page1, struct page *page2)
> > >       return ret;
> > >  }
> > >
> > > +u8 mte_get_mem_tag(void *addr)
> > > +{
> > > +     if (system_supports_mte())
> > > +             addr = mte_assign_valid_ptr_tag(addr);
> >
> > The mte_assign_valid_ptr_tag() is slightly misleading. All it does is
> > read the allocation tag from memory.
> >
> > I also think this should be inline asm, possibly using alternatives.
> > It's just an LDG instruction (and it saves us from having to invent a
> > better function name).
> 
> Could you point me to an example of inline asm with alternatives if
> there's any? I see alternative_if and other similar macros used in
> arch/arm64/ code, is that what you mean? Those seem to always use
> static conditions, like config values, but here we have a dynamic
> system_supports_mte(). Could you elaborate on how I should implement
> this?

There are plenty of ALTERNATIVE macro uses under arch/arm64, see
arch/arm64/include/asm/alternative.h for the definition and some simple
documentation.

In this case, something like (untested, haven't even checked whether it
matches the mte_assign_valid_ptr_tag() code):

	asm(ALTERNATIVE("orr %0, %1, #0xff << 56", "ldg %0, [%1]", ARM64_HAS_MTE));

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200908145019.GH25591%40gaia.
