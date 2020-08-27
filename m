Return-Path: <kasan-dev+bncBDX4HWEMTEBRBY6QT35AKGQEOZBTPRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id E77B6254504
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 14:34:44 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id t3sf2768095pgc.21
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 05:34:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598531683; cv=pass;
        d=google.com; s=arc-20160816;
        b=KdkC0x7fg1cZ/XP9vMsHX9IqovbtaO6aJWs0LlA3z5ccCRrnLHdXqOFzUh8EwtzYoM
         mJtK1FrKqIVZkD4nLepIIIUKRUcegV1yYMQzVgAyA+KigICGEc/MhSfEg0coAbUEgkE3
         pyrbbOUpme2uMKyJVKbunbOAutFr4BnLANWQDkdoYBNWnhvbZN4b9NJfsDe/evlsn+3P
         qkdazQ524h5AOt4w/rUQKUbhsUCzalr9D4p5knCtwwUUvhwJ0WrdMQI+ih5ff0yLC7bR
         poWUMqzeYRMVwbiTtC9DQPRdNlzHiZOCAYow3fpvLC/2o0Dt4fCO5PwoGBCl5CD43grc
         QnZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=EbmwAXGSLy8lTGxBdN7/Qi/kJFv7ji1vDr1nqdY7gMQ=;
        b=hv8PpNreOfsaRwpM9tQdSACI4KLP0wY46KT3K7v/OjlhSNYDZ1IGgbaF7cvFGw2dfO
         OR8XIG+KcDYiTfOHZoHNrNmkCTRDdsNuG3gLAFkik6WLJSRUOFCQ4nPmyVh5zz+qdgIJ
         D/xuapcQLhJUzmzXfECfDJi2bVQ7v+TOf21N7AHhI9nRX4RoeR8Wvq6xZ78M98Lug+Gg
         6jgnn+ZcFkxGSP5WlBYpscNZ2DvxTlooNiVOvMjI6oqjyAShVItS4qwOm3wzYE03u2jd
         +dNkMZiPzvqi4v5WO+NQ4brPTAyDn68sGemlol8jrXo9ukqgVmCT2/hIBWDctp6tmE55
         C7aQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uYOH6B48;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EbmwAXGSLy8lTGxBdN7/Qi/kJFv7ji1vDr1nqdY7gMQ=;
        b=Bwym/VYhiznUf+apZD/ZbgmKlFm74EUcg3PJnKroUOJMWotKyqWEMvySHW6HX6KPNt
         18FIWFC4oFizn66YD/rYeqzAMHgE/DK2nENwpgQBT9NzOprCcYK6CE9LO86jm+H+aAzV
         zmzM3gNY0Xe3Hm6ZsgMcNw3SoZ/bOFSE0SIbhmmA+0yunoAKVCrqiWGWVINc93AcSNT0
         KwYtM83p1Gx3gcTZS8iaZROdZNh+D+aOHcyK5lcGrBPEZSD0v7RTgEUCzGpqxBJvzE5t
         xuw24hGLIX6EXNregrbSDgXbOUt/Oh2iJV3Eb1gVAVVOTw3Xc72k6NmpI283MbaLHRQr
         gp9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EbmwAXGSLy8lTGxBdN7/Qi/kJFv7ji1vDr1nqdY7gMQ=;
        b=RF1V5zZBvrRJwVcZAQFtEyNClEw8PRP3Yu281rEcFVRLfZb2ug2pSYo1MZL6m09HUi
         vbFidv3j8515f6+fyeCV+Lx79l3BnAeFTjv5BfNU8pmZhIlDKRewipTKiWDp4gEOR6YU
         cE5jua52A+sC4FORzEb4HpKk1RXr4pJUSU7mcKLMkPuueDExSkMSSRttUYcF0HziKl3g
         Cj+bXv/7/z+TFlFL3wqOPSZRC7ShZeYwsR6WUFmWGuH3lP1bYj9UHRvexFZ516LfmcbS
         zHWxI/tktWCMmXMsRmMYmMmQHqLA136gNxUAHE4vNjnSjMMQYjDVg6QNdCfI8hH388B8
         7r8Q==
X-Gm-Message-State: AOAM530YsMrBQegPPYkN/Mch42qFQ25ivDVARqHptzyGeyJBvCwP8oCE
	ENxo7gIfBAXx74VjzxIkmeA=
X-Google-Smtp-Source: ABdhPJzTscdjP0wMpwW6XVBIYUHrfrox+0gMcjp6OwsX9m1q2lOVfBL1rrxfQ7NLhY4gu9XALd/Z/g==
X-Received: by 2002:a17:90a:ca89:: with SMTP id y9mr10627045pjt.108.1598531683346;
        Thu, 27 Aug 2020 05:34:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ee0c:: with SMTP id z12ls1167821plb.6.gmail; Thu, 27
 Aug 2020 05:34:43 -0700 (PDT)
X-Received: by 2002:a17:90b:1214:: with SMTP id gl20mr10960508pjb.225.1598531682864;
        Thu, 27 Aug 2020 05:34:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598531682; cv=none;
        d=google.com; s=arc-20160816;
        b=GPHYZ3USLrBiM2/04tMoPXqyVo9DVEkaUy2+sxwtxj6HtBYRkBJv7sy3r69DrdGWHM
         LuW2bGmh4t99WEbHNG4Fc79qTXAi+WGKJJaNuAfm8oOdDxow81srVaK3QkDNmG5FfZd0
         7J0ChxU0uSQkLOGvPbWyF49P+RdMNdTVh9e9vlEkSwFrID9NMQ8UTkg6J1JobfRYf22k
         IYxCYPNRUI+oGQguJEZjXNp1wEZlE0auGPlqcsIZ/emM43TQCMBbMtryPzbREiqGwQvv
         Jt+SrJmAmSL5Rn9qC51M2FrKwKhTCbL52PLFiiuglLWQhghyuBwARNXpTc/n6brxwwE8
         ZvAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+QQzTLJnBa36P3H2hTUyCcrUla2gQmiA7N8bvUye5ww=;
        b=neQ9CpN6tW9hyejxaI4qhXZaF3xsaxrDf6HTKnVKHlqSVQ4IoEQyDjmMPz+pYFon6D
         PLqaTqwFDptNvnq27rWxlOIFg4dyXyq2CZVVVFq0WRGUIbewHu9fkW45dCoAhHYaLCh4
         IqQFRW5OO2snhkX/ANTwH5bonKbXYAxJX7+mWpucvMffa5AqwNrOQg0WzziCaP4T8adz
         zPxxvVAsv/2/r24Uo9gPZEdy8DOFZekykikfgKLH2RP3V+EAdX1/+Bll74aUN77C10K5
         vLKmt95HTLD18WYfkyDX+9+Dus/zogqwZo+1YZrwugFoUF8NMRb5EBnWGNHr8Of2roCT
         gFRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uYOH6B48;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id u204si113849pfc.1.2020.08.27.05.34.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Aug 2020 05:34:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id l191so3255908pgd.5
        for <kasan-dev@googlegroups.com>; Thu, 27 Aug 2020 05:34:42 -0700 (PDT)
X-Received: by 2002:a17:902:bb82:: with SMTP id m2mr16297954pls.115.1598531682160;
 Thu, 27 Aug 2020 05:34:42 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com> <4691d6019ef00c11007787f5190841b47ba576c4.1597425745.git.andreyknvl@google.com>
 <20200827104816.GI29264@gaia>
In-Reply-To: <20200827104816.GI29264@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 27 Aug 2020 14:34:31 +0200
Message-ID: <CAAeHK+zO8EJrmX5NjkKTB35eot1rDLjoqGyfoqF_quDV=VEvrQ@mail.gmail.com>
Subject: Re: [PATCH 32/35] kasan, arm64: print report from tag fault handler
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uYOH6B48;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542
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

On Thu, Aug 27, 2020 at 12:48 PM Catalin Marinas
<catalin.marinas@arm.com> wrote:
>
> On Fri, Aug 14, 2020 at 07:27:14PM +0200, Andrey Konovalov wrote:
> > diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> > index c62c8ba85c0e..cf00b3942564 100644
> > --- a/arch/arm64/mm/fault.c
> > +++ b/arch/arm64/mm/fault.c
> > @@ -14,6 +14,7 @@
> >  #include <linux/mm.h>
> >  #include <linux/hardirq.h>
> >  #include <linux/init.h>
> > +#include <linux/kasan.h>
> >  #include <linux/kprobes.h>
> >  #include <linux/uaccess.h>
> >  #include <linux/page-flags.h>
> > @@ -314,11 +315,19 @@ static void report_tag_fault(unsigned long addr, unsigned int esr,
> >  {
> >       bool is_write = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
> >
> > +#ifdef CONFIG_KASAN_HW_TAGS
> > +     /*
> > +      * SAS bits aren't set for all faults reported in EL1, so we can't
> > +      * find out access size.
> > +      */
> > +     kasan_report(addr, 0, is_write, regs->pc);
> > +#else
> >       pr_alert("Memory Tagging Extension Fault in %pS\n", (void *)regs->pc);
> >       pr_alert("  %s at address %lx\n", is_write ? "Write" : "Read", addr);
> >       pr_alert("  Pointer tag: [%02x], memory tag: [%02x]\n",
> >                       mte_get_ptr_tag(addr),
> >                       mte_get_mem_tag((void *)addr));
> > +#endif
> >  }
>
> More dead code. So what's the point of keeping the pr_alert() introduced
> earlier? CONFIG_KASAN_HW_TAGS is always on for in-kernel MTE. If MTE is
> disabled, this function isn't called anyway.

I was considering that we can enable in-kernel MTE without enabling
CONFIG_KASAN_HW_TAGS, but perhaps this isn't what we want. I'll drop
this part in v2, but then we also need to make sure that in-kernel MTE
is only enabled when CONFIG_KASAN_HW_TAGS is enabled. Do we need more
ifdefs in arm64 patches when we write to MTE-related registers, or
does this work as is?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzO8EJrmX5NjkKTB35eot1rDLjoqGyfoqF_quDV%3DVEvrQ%40mail.gmail.com.
