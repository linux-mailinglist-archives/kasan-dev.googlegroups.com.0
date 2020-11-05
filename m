Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7GGR76QKGQETJUMBMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E1A62A7D1D
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 12:35:25 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id u3sf663734qvb.19
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 03:35:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604576124; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ou102aEJWBqwqc9Ut35Imf3NCpF3yXbssD708fqaE2DfXu9etadXzioIGG/f2NjSK2
         q9zX+sKXeyzuccPV5wSd9cJtxs7/qPTvylYLqR5XfaxjjXqb2njnXwzzB6q/AsEoatfw
         GwbUVKtK61EGpLX6uB7OJDcMjMTscfp0ltdOLwDj2zvGTVKJKpvzaiYkT0tPAdUkoitF
         FoZtOvb9FERFE9W8s5+7biPgU850unWItR7EmMusbXW6WJ2d9actfHEPp7YKVY03/KmX
         7CnHry/kElbJBZ1bBEkfXf0IHTaCl6uIPWwvLirsnfZVeJBtfQiyvfmNHdfIu/8kVbqm
         Q6GA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=mZ85Jzr6bhrd/yMzz6U4tvbhscqllEXK8DVvbTn653o=;
        b=rLcOMLO9PiCmSuzkOybSTifDrKyLnfqBYaq2mQcKty56IpEtTRgheSYRBuefDYHgLA
         +ifbIWilHeyMk46uBxSI9Pnkqqy7t+grF8iWAe8DSQgZD5s59YpILJe0PetzQLl+RYiw
         DXJOND99aLO8+qhGDivSHJt3Ywup8gWSg7FqFOEUQ4Nl/Xyh1bCyBeQIZpwI7BC0dVUM
         keYnkfkGet4LwfNcPMwYu8p4nCi75j2uMfosbjVsetTwe1uEWnVxzuCDxiNb7DWhKWNO
         aQMa4YT+F2Iy9OyV4S19/TaM5nKixsvjdRsm/hiaYHBmB9+wVi7rxdUwlshePHGGaE3r
         2CGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sR+Li0rd;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mZ85Jzr6bhrd/yMzz6U4tvbhscqllEXK8DVvbTn653o=;
        b=bFHrB5eQPVkGqh8CzztMlPczCOWIwIbbDqpMpd0f9ZIx8JfohSnxs3B8zZAzEr50ag
         mEhXdqpdcXtPL4MTL2prm33/kX4VOnOrqqz4zCfb+lCKaZVcMFq6nBmXlmK0EzsMRNSm
         C+ywA+HRnbuVHgmCyvbu6Fj/OYGFzvjASEZjxic2XQ/EMQLUg9IMCvO9tFhYNdPEEWoj
         ym9EDNV5fyyDJlq/y6WTjeFqeJhtMg51uUZMdG8ayCraiRUo4o8nYADntjQ4OvhpsiPe
         R7cRVxXZlxFFZ3O4Uq+iYFG9Yg8OhTn+BQcBnCA3GhDb6wT5t+bFKVehhWzaxrTOVCoV
         gQhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mZ85Jzr6bhrd/yMzz6U4tvbhscqllEXK8DVvbTn653o=;
        b=jNY6XlUCS3t3JuZPoZA0Ph2tQsU7iGwW6gzDbiOMF3Y9z4gFK1KlDsS0kjQKwu5lqo
         HjEbqA+TxAVpzUg61FEyyBRiRsO/P1GZEPbNSG+osMgmt1OeVU2IqtZoiUjwSLyWqlhw
         aXCJg++ZLSCiTLpZtiWEIS5ie8c/MLMEIvk9hwiH9Y2nEC9e33KhJxtp0nbSOtbjo/eC
         k4CpiyuG31k6bIXZaZOaAbhhFLTBZJW+OdApbhgUXUr/zc3Uex5vWU1CqnC8nrPkKP+7
         5t7KX8F//3KPkw9zvNi3+Wd1Ro92Ap/vZHVm0Kl9I0SkzlR5tuE2CCipiTS0bJUv3GJD
         DIuA==
X-Gm-Message-State: AOAM53340tzrJLc/A83atV9QW7yPJWy5rjJhS8lR1MhN5vYy0KlOZ+a+
	RDMEAkII9BJZ+ImyseTLMUU=
X-Google-Smtp-Source: ABdhPJxtM4Romkye34lBMRg/B1tPlQwQgrd+S1uIHG5MMT7O6YGW9daMOilhiS6N9YMekThrlqu3mQ==
X-Received: by 2002:a05:6214:1341:: with SMTP id b1mr1821223qvw.54.1604576124339;
        Thu, 05 Nov 2020 03:35:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7441:: with SMTP id h1ls535880qtr.2.gmail; Thu, 05 Nov
 2020 03:35:23 -0800 (PST)
X-Received: by 2002:ac8:b87:: with SMTP id h7mr1425595qti.87.1604576123878;
        Thu, 05 Nov 2020 03:35:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604576123; cv=none;
        d=google.com; s=arc-20160816;
        b=b8Zl6apEYBK9QwiMmMeOiHJQbAJ+6gMvcacyKthBrGRbF33L5dGNhixdDPysDWYrEO
         CYNBYE03O3tQDq2ItOx2bvr5u0WKTsc2l6DoU4k9fDpWfl+Prh7EIjKMuFIeXBnGeia7
         Zd/4xUv6XR6mHitSiXJGETYkGmItjwAmZHNh5bL0VSka+SgVtUTuhCkiN/skkh/zSWQ4
         P85c4fgW3iuEk+nIQV7Nm47atZZVV9Zy3I5bllXBjgaHEWT9D8rUVfKpdMQGc1Zmmjmf
         LMt2OpRr9LNh0oLCTJitwi62/BZw/veQ4IqLh02zP0uvagxx/FihjBZgzdcm9eagodHi
         1beg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=S+r/dPqbzqLZgGMdUBdXFU/WPqHd1cGIgABAmt0Dvlo=;
        b=kg9uphpmDStXLFRUZS1S7VNS/plMD0TsdRV2PxzAaR2/CxlUU3cbU59s9dgdiySuDI
         CmI04sOO/EPjhr+vOxMthrOB32k+RyXGawFWuPmyuS43pP+6cibNmluqIWe9NcrkQjI7
         vP2qQpH6zwmMm8W8EOCHSGxHDxKhOqFl94NgcrUadct/qARkYY4Gdp1din5DZ6TqdhWm
         zs7kRMjHACLxQd8EH1ww1I+/cXb5nr1OuvcUJ4yu6A+csgT46EwX+liy0kyJCyJOZkGS
         vRVJaIyCA2m4Gv9BhEIc53xqdSJrGjirVwNuHIuz1HFR9jMuVCY3c06k9gjD05ZOOR/P
         ZCcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sR+Li0rd;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id z205si75867qkb.1.2020.11.05.03.35.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Nov 2020 03:35:23 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id g7so995455pfc.2
        for <kasan-dev@googlegroups.com>; Thu, 05 Nov 2020 03:35:23 -0800 (PST)
X-Received: by 2002:a63:5153:: with SMTP id r19mr2005408pgl.130.1604576122878;
 Thu, 05 Nov 2020 03:35:22 -0800 (PST)
MIME-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com> <5e3c76cac4b161fe39e3fc8ace614400bc2fb5b1.1604531793.git.andreyknvl@google.com>
 <58aae616-f1be-d626-de16-af48cc2512b0@arm.com>
In-Reply-To: <58aae616-f1be-d626-de16-af48cc2512b0@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Nov 2020 12:35:11 +0100
Message-ID: <CAAeHK+yfQJbHLP0ja=_qnEugyrtQFMgRyw3Z1ZOeu=NVPNCFgg@mail.gmail.com>
Subject: Re: [PATCH v8 30/43] arm64: kasan: Allow enabling in-kernel MTE
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=sR+Li0rd;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442
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

On Thu, Nov 5, 2020 at 12:13 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> Hi Andrey,
>
> On 11/4/20 11:18 PM, Andrey Konovalov wrote:
> > Hardware tag-based KASAN relies on Memory Tagging Extension (MTE)
> > feature and requires it to be enabled. MTE supports
> >
> > This patch adds a new mte_init_tags() helper, that enables MTE in
> > Synchronous mode in EL1 and is intended to be called from KASAN runtime
> > during initialization.
> >
> > The Tag Checking operation causes a synchronous data abort as
> > a consequence of a tag check fault when MTE is configured in
> > synchronous mode.
> >
> > As part of this change enable match-all tag for EL1 to allow the
> > kernel to access user pages without faulting. This is required because
> > the kernel does not have knowledge of the tags set by the user in a
> > page.
> >
> > Note: For MTE, the TCF bit field in SCTLR_EL1 affects only EL1 in a
> > similar way as TCF0 affects EL0.
> >
> > MTE that is built on top of the Top Byte Ignore (TBI) feature hence we
> > enable it as part of this patch as well.
> >
>
> seems that in this patch you dropped me as author. Would you mind to clarify the
> reason?

Sorry, a mistake while squashing/rebasing, will fix in the next version.

>
> > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > ---
> > Change-Id: I4d67497268bb7f0c2fc5dcacefa1e273df4af71d
> > ---
> >  arch/arm64/include/asm/mte-kasan.h |  6 ++++++
> >  arch/arm64/kernel/mte.c            |  7 +++++++
> >  arch/arm64/mm/proc.S               | 23 ++++++++++++++++++++---
> >  3 files changed, 33 insertions(+), 3 deletions(-)
> >
> > diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
> > index 3a70fb1807fd..ae75feaea2d4 100644
> > --- a/arch/arm64/include/asm/mte-kasan.h
> > +++ b/arch/arm64/include/asm/mte-kasan.h
> > @@ -29,6 +29,8 @@ u8 mte_get_mem_tag(void *addr);
> >  u8 mte_get_random_tag(void);
> >  void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
> >
> > +void __init mte_init_tags(u64 max_tag);
> > +
> >  #else /* CONFIG_ARM64_MTE */
> >
> >  static inline u8 mte_get_ptr_tag(void *ptr)
> > @@ -49,6 +51,10 @@ static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> >       return addr;
> >  }
> >
> > +static inline void mte_init_tags(u64 max_tag)
> > +{
> > +}
> > +
> >  #endif /* CONFIG_ARM64_MTE */
> >
> >  #endif /* __ASSEMBLY__ */
> > diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> > index 06ba6c923ab7..fcfbefcc3174 100644
> > --- a/arch/arm64/kernel/mte.c
> > +++ b/arch/arm64/kernel/mte.c
> > @@ -121,6 +121,13 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> >       return ptr;
> >  }
> >
> > +void __init mte_init_tags(u64 max_tag)
> > +{
> > +     /* Enable MTE Sync Mode for EL1. */
> > +     sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
> > +     isb();
>
> I am fine with the approach of letting cpu_enable_mte() call directly
> kasan_init_tags(), but how does it work of the other 2 implementation of KASAN?
> Is it still called in arch_setup()?

Yes, the other 2 modes are initialized in setup_arch().

> I would prefer to keep the code that initializes the sync mode in
> cpu_enable_mte() (calling kasan_init_tags() before then that)

This won't work, we'll later need to make the decision about whether
to turn on MTE at all in KASAN runtime based on KASAN boot flags.

> or in a separate
> function since setting the mode has nothing to do with initializing the tags.

This will work. Any preference on the name of this function?

Alternatively we can rename mte_init_tags() to something else and let
it handle both RRND and sync/async.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByfQJbHLP0ja%3D_qnEugyrtQFMgRyw3Z1ZOeu%3DNVPNCFgg%40mail.gmail.com.
