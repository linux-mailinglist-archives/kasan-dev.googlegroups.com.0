Return-Path: <kasan-dev+bncBDW2JDUY5AORB5EIXCHAMGQEBFKI37Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x940.google.com (mail-ua1-x940.google.com [IPv6:2607:f8b0:4864:20::940])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FA39481F6F
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:11:49 +0100 (CET)
Received: by mail-ua1-x940.google.com with SMTP id q19-20020ab054d3000000b002fb1541af86sf9837069uaa.10
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:11:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891508; cv=pass;
        d=google.com; s=arc-20160816;
        b=dEBMCQa5Ny15LrxQO5fO0kMgSyEwf0o2MzpCwzCGdJpRSq2hZA1pQ0iwPguBGM8SWB
         TnfheLTAvqdgpZYHYoBrPP8WUO3qSYmcGpMk2W1nuwF+j6ar8Q6XLE9lOUacJc/e6MZB
         tKpyTzb8IXJggVg60hzbF1xNih9Px4U2v/R4dPko70cJgKEL2ppJeYIO5obWDQ1IhYJQ
         XN9yk9yzbmBnlX7hNzcU8s5p4Su4HW74I97BIv7SonNwZpc3gNObq5XdzECYbEawz/mG
         wHTHcc0BhWzYkv8GjeFkixqcLqDm6C5b97Bt288wc6RLl/eU3/boPCOHivZpKNkAsMPw
         Uw5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=Mjo+/gTEC4Kuv+vFpidsaEsa7UwJHHC7ylfpR4LA4ek=;
        b=IRASJtqKEaLGRO9NXz+WGLPvr1LhQnli3OJGsWsrVfhmmA2tTa6Dolr5rwyxZ7/meI
         bc3bVMy3O/X7CrgeBgnuuSWG6vQ94sNAgWaxZqIblg9EPNI0T92yKL6wNKqU7t12Hryc
         buyg/i/FaQU1Pbvpy1jWzCwHFYRKauPqStbpX3bXFtmtQAEuwrSL06d+sNPcHrYvvZFR
         GYSuUaxTBkUtvOWNb3UfcTQQaWVG0/Bn4X9ATGDc3JBkaSSOki6EZRogn28rnUIfdBAT
         yKCaS5fZfJ+GDau7GooT0Z0XOVUuvrbnqSTb1Gn91KRdnLBJC9Z21iAr9j1IC2KCIYFm
         1+8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=eukBzX8N;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Mjo+/gTEC4Kuv+vFpidsaEsa7UwJHHC7ylfpR4LA4ek=;
        b=OEp5RUDq2BO3MAPduBcdo5lba8pFxiHvw3pZmD8PVEeidx9Uw015yfgqFhJEKO/Oxi
         zIVSwJRctn7PjX8kM/+YALAd1S6e40h4OPnNxaXOFsptzUZEazfBRwMGJQnYMTBP9/kz
         jw0enhpeoSnpUb+PtUoCENSljxmtkb7y0/JPonu+oKycGuhJuG7aY+xkaDE+Ntb6s/xP
         XGQDeDjdMRoAA92WZVrDmIB3NFj1nM3+f+r0iif74Ter6ylYQgA/jj0BomhvvFPDYPb3
         tAqYK2wRs0jIXrt//VSbRvRBs+1KmauDDBlPZcbjp7r7rMiUjZPYvHzyHPqDBNra8DiO
         3PnQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Mjo+/gTEC4Kuv+vFpidsaEsa7UwJHHC7ylfpR4LA4ek=;
        b=SFVkLKXanPiEEO+APjsBf+ZRSHmllP8efUjYneVNMn80TZLhI9KC1tPDRNJHJvSFQE
         IW1q1PWjVnSSsDoeOFgjkAGUamml6fucX2PHpMunVDc6Uuwluy8NzQukm+aDQiFbObgb
         +IGd3jwIkf2W7B+7HSqdFV49S2jOvQU/cmMfX2KFfN5FyoT9czgmstL6P8TH0EXdrrrY
         iPReDLD11J+Qd30lKl2kAAI+Nsq98djP1/FtwXbYDnD1EcYZsebTeruSrzB25HjwBs8m
         seA7CQ7MPKwKqWxsIal/aeheKDl7tCfPj6C+Mh+pJZyoKGhnqNixMVQ57qlTB7shYLH2
         IYpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Mjo+/gTEC4Kuv+vFpidsaEsa7UwJHHC7ylfpR4LA4ek=;
        b=YqRxnL/iRU2hzj4L3CCQqUsX/O7CL+mKG2Z+JL6J+NjAisibpVd/+dYiHy2aZytmzp
         JRFC3DunwNI622r8cmvzdAe10BVFU4Ex7ekTPBu2pPMSgi+u5K7jX10Vs9pdnYmZK+gk
         vzCOC3jsnKRlay1pIb7mF3mHysCUcps/+3ihmkW5PnWgU/756LszvPX8jLn3LQgyK9YR
         a4175CZDZPIBGbGrUSvkND01ugyYEzyQzATH21NJp+B0lGjWxO5hxRozsyIOij6cqurW
         vQPdO6hLM7/xNKHvGDsOh+0ghqFGB5k5eo1W4Few8eJBnTL1msE81klowJrXBhIDqYS8
         b72w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533NaG03TVlercp3zxkn/WcwEl3w5GC4UHKQZNUC6qTUUN4YLdyF
	/AV3hUZKEBK/db2/lPBDy3Y=
X-Google-Smtp-Source: ABdhPJxS994K7uQWu3zua5BHd2vMR385XtCHTdPJvHCiU38MstFrjEOcJOsfbkzuWDXAHLq5NwuL3A==
X-Received: by 2002:ac5:c2d2:: with SMTP id i18mr10777119vkk.29.1640891508640;
        Thu, 30 Dec 2021 11:11:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac5:cc7a:: with SMTP id w26ls1573061vkm.11.gmail; Thu, 30
 Dec 2021 11:11:48 -0800 (PST)
X-Received: by 2002:a05:6122:1073:: with SMTP id k19mr7026619vko.37.1640891508189;
        Thu, 30 Dec 2021 11:11:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891508; cv=none;
        d=google.com; s=arc-20160816;
        b=yczLZAhbodGn1vfrMXto1U5sQLnreeRLw5N+CjE2voGs7BAOKGPNBIYnIUPefviyUf
         5aDr4xb88DI9O28NrReXPrmlFquAF9DdMpNiisohrIIk5iAB4QWuccbv9nmavEDY90l+
         tT8t3So51YjKLRWKgUT5nRQiK9E4i+2MUWJpZmH+yC8hAqhTS6iFJaaL6ybzjPZMABDH
         QYwAsk8UDAz4fl/eUPTAytq+P0aB6VV/eRJodtPovMr6bhjMjeEqa9uFM+NMrINnbcMJ
         mfUb9+ObzM5v4nJVKR11amzGbw+ZKEdiHoUitU3wE4KGu9Pnt+iLtdRXAUNSuvQrPpxg
         4seQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rrhmOz+RWOitrnUQCMaMCSKwtj1JoPe3FFZpv8eycXk=;
        b=yGUK4WBJXqKW8LGg5Jj2wbh0VnzA5E/6NbhUN8j2ShY9E4mdPZDfof9Xa/+wMbjC5i
         qnDSHolUJwBMY5WqKpQ73YPSe/hY3f8Tsa80oXnQU6YUTtWbkFbCv9S0HwSPb7RSd3k4
         +F7XDCgMwA4pOgTG5fr55aHI+8hYRiVlv6qaAiAwn1Vkp+w7Qs1uhzXyy8aEseDFpGi2
         2UKVgUw7ouTt02S3sA/EdG8NUi8XiSM4LCWcbbhld0LPNsLokzz2H2iINaLxhgE9AEHZ
         R5v1nLME9sQ9yFF6ZZ/Wc8XI4twd6sPJxt03R4qza2zRJ0lxOIKVyFdy1q+GznjSkIqT
         uacQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=eukBzX8N;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd34.google.com (mail-io1-xd34.google.com. [2607:f8b0:4864:20::d34])
        by gmr-mx.google.com with ESMTPS id s10si1073444vks.3.2021.12.30.11.11.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Dec 2021 11:11:48 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) client-ip=2607:f8b0:4864:20::d34;
Received: by mail-io1-xd34.google.com with SMTP id h23so20465555iol.11
        for <kasan-dev@googlegroups.com>; Thu, 30 Dec 2021 11:11:48 -0800 (PST)
X-Received: by 2002:a5e:d502:: with SMTP id e2mr14473843iom.118.1640891507994;
 Thu, 30 Dec 2021 11:11:47 -0800 (PST)
MIME-Version: 1.0
References: <cover.1640036051.git.andreyknvl@google.com> <dea9eb126793544650ff433612016016070ceb52.1640036051.git.andreyknvl@google.com>
 <YcHI34KT8Am4n45x@elver.google.com>
In-Reply-To: <YcHI34KT8Am4n45x@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 30 Dec 2021 20:11:37 +0100
Message-ID: <CA+fCnZf21dKQLZZf+NNXQ0J0HAdjQLxbGxZqgfxACBb5kUcgNA@mail.gmail.com>
Subject: Re: [PATCH mm v4 29/39] kasan, page_alloc: allow skipping memory init
 for HW_TAGS
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=eukBzX8N;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Tue, Dec 21, 2021 at 1:30 PM Marco Elver <elver@google.com> wrote:
>
> On Mon, Dec 20, 2021 at 11:02PM +0100, andrey.konovalov@linux.dev wrote:
> [...]
> >  /* Room for N __GFP_FOO bits */
> >  #define __GFP_BITS_SHIFT (24 +                                       \
> > +                       IS_ENABLED(CONFIG_KASAN_HW_TAGS) +    \
> >                         IS_ENABLED(CONFIG_KASAN_HW_TAGS) +    \
> >                         IS_ENABLED(CONFIG_KASAN_HW_TAGS) +    \
> >                         IS_ENABLED(CONFIG_LOCKDEP))
>
> Does '3 * IS_ENABLED(CONFIG_KASAN_HW_TAGS)' work?

Yes, will do in v5.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZf21dKQLZZf%2BNNXQ0J0HAdjQLxbGxZqgfxACBb5kUcgNA%40mail.gmail.com.
