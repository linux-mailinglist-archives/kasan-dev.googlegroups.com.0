Return-Path: <kasan-dev+bncBDDL3KWR4EBRBTOA335AKGQE4FTBEEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id B3901261349
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 17:16:30 +0200 (CEST)
Received: by mail-vs1-xe3b.google.com with SMTP id a15sf2349393vso.7
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 08:16:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599578189; cv=pass;
        d=google.com; s=arc-20160816;
        b=c6g8TG6FhrdC12lgFuEWb0HEVDEUzbemPdABFWnude5JgffFeSqP0ZJqaJptaVzwzp
         ZlysNx/IHMU2gx9OvQ72aLZ7XL8tw8ERfgJsLnsT2UL3j3xiilRtdsTde5M34V8Q3ycN
         rpYUQ5EFRnBTIcoa58WsNdpSYt/sellOoKm92Fe6yfhAJab6O/gMg6/Qe+hg2+CuN+Tf
         atCM7L9BT0aADsz0fOIrgu2APGo/gSXdBbyofP9xpO4BZyUdpTaHX1qe5To+u7iljoe+
         8OLZKaZi1MxGs7pa3v8O6H+dRXlDuWlQWWgjNVAlyJKI/WIE9ZvGmawQ8+3cAb9+BJZI
         3Euw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=fb2pdFyRzW//BpsXAxACs61EUax/NZM5UalG5PhSyvk=;
        b=PUnkYBklxin4qSLuzZBG2tyynGnRNXGMOQqTYVDAJTU4txkyJo3VZl07DAU3I95zV6
         vJ81nZjZCjG2dEgq7ox7//1ycT5Pr6dZy4QFaolY0FVfrfy842KnBfn0wb17dJ7kmpAW
         GSMVHWQgOp4Ck0I96LvggW/YPbW+jhlC3KHzXqwRmknE29ptQq1FXNhFXNpEAxSV+SNi
         mzh57lqbZXtqyxFYv8mg52JUWz+KiQEbfo4T7+y0I+hhzstZ4QJve9yzebq0CBEUgGox
         KuJ7VUn+JGPjlU+bMOvCCsHbdVFwtI9Dp5a78xf6RhVZjlci+uoWjhFNloKKfi4dE/oH
         wrAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fb2pdFyRzW//BpsXAxACs61EUax/NZM5UalG5PhSyvk=;
        b=FMFTlwqrY++88OuI7dqSQ16BQMBrgWELhMo66HCOwuOp5VvEpTdVV9p2gOXAuPu8NR
         q209j3QgHbZFZe49uGZB6gSyC5G5oiU6FjZz893weriZfqWukvGnWpCh+ZhWNwyM6+II
         st9vYuK01/bTFPvHCgGFGQRQNi54Iwrh6o6TaretBMLBGGP26BC2awmo5vEP+9oRfkX5
         oLP9G9RA/Fu6QRygQrRCF6FgQJEn2KEicye+qv9eVOBtbSCbB7raJ8auSdB+Y26oODTV
         cX8CiG8zVn5no60k13LYAySDVBsRIdaVNL7bCUiS8+FUHN/f7dXjeba+YyrbnoeBoKVl
         QnhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fb2pdFyRzW//BpsXAxACs61EUax/NZM5UalG5PhSyvk=;
        b=R4rNRxmKMOlCNt8XZyJ+eDIwYcGMux8BtehEqDlnFdru5ko7lcXTYXj/4QKiquaatF
         Snt/5BiRvmS4yrOlZFDXa72fWhwMogmDQyDVGeke2ioBwV5W7ia3nq9aAp+8lsyBAkGr
         Yh0vutV1cEW55EvbjPoAyXW5nSMm+7+BqgfY4+GAHX8EEFbddxQKoTP6Tuwi3kNagKWS
         VymggCPAouh9g497zUsblRm43J0JBzWFizjqCPrihd7xem4ylr8dGMD0sJmyKBSevpwI
         hTaKtURjT6t4ge62Siq9xTH74AMzHRR0/yo530KheVHuZG5pi6dtyPpe6fu//rNzZPAV
         +Vxw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531uN1NxTuKq6cvhbwNSrVkeQQcBGtjsD2MRr3GrBV9jk8Rj9UoC
	GW2Vi7OrAOjQ3fvtHcNzj4g=
X-Google-Smtp-Source: ABdhPJyCCifxXupFOjfeCqexUbwOeIY3CgSLtUoxpKHTZuUM7qg2+dFFkStkQ8TApL7QAAm3sDXurA==
X-Received: by 2002:a05:6102:82c:: with SMTP id k12mr15490261vsb.24.1599578189766;
        Tue, 08 Sep 2020 08:16:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:bb07:: with SMTP id m7ls1223929vsn.4.gmail; Tue, 08 Sep
 2020 08:16:29 -0700 (PDT)
X-Received: by 2002:a67:af13:: with SMTP id v19mr1204622vsl.14.1599578189069;
        Tue, 08 Sep 2020 08:16:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599578189; cv=none;
        d=google.com; s=arc-20160816;
        b=1HXfIaZSLR/DtxH5kgkAvjX/7u1sMmsKXIkiGxwuXa8EILZRGDHhWM0soFwRP4GWi6
         Nfp4RtTpCyS7Z7E5vaQyRkBWW5o3nGbpjDBpzg38TUsjWqQJh64Xv0cS6NZHQWpAbNJd
         lelqMYG1pEd6LOsSI2ITDHt7PP6LhCVrLy0PklOL0AJjHB3CyswGC5aGsL8723CLDLvH
         h8GKIffK5OWZ/tgVAWnxCmF921GQOSnHbtif53B8VVIk1n1ATIQw4na+svpzISg92Wbg
         sKXfTcf/lVijJ1v3m6XpYxn/xFcKmxSS+IVLZMKVCH9SqAH3up3yk0umw0PEbme+4RB8
         NiVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=+kmO/GGXboTB28xuA3RPyLhNBiI2u40qRzoxry71oKA=;
        b=PcL7VJpiWV/+dRrcxlr6rRg6BcC7BzWBPAUeXRIqsDDVZPGCeiozOwhGp6Meez0wft
         ylNke2q9okjyZIt6piW8iHX5yeaAklFxupuBy0Uo9khbIIvVhWA32xPVHAxTP+MG+S+o
         YcZm4ujY9SfUX4jg1CayCvC91EvdbRmoRTNRHhywmXYk5qOEpGk3K0c8lJo7IQc5TUxT
         NB8hN4C5mor9MstLUlrSqfQY/aEovGZt/Qyiw0CDnZmGPOyMjx03UgJbyfbzC3MOede0
         YW73l3qaGl1jAEzWBEQvK8RE8L2eYJFelLLz4qpYotuKAlB/P5beWPBBSGnCBUhPbnDL
         cC9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u25si774138vkl.5.2020.09.08.08.16.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Sep 2020 08:16:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [46.69.195.48])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 98CA822404;
	Tue,  8 Sep 2020 15:16:25 +0000 (UTC)
Date: Tue, 8 Sep 2020 16:16:23 +0100
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
Subject: Re: [PATCH 24/35] arm64: mte: Switch GCR_EL1 in kernel entry and exit
Message-ID: <20200908151622.GJ25591@gaia>
References: <cover.1597425745.git.andreyknvl@google.com>
 <ec314a9589ef8db18494d533b6eaf1fd678dc010.1597425745.git.andreyknvl@google.com>
 <20200827103819.GE29264@gaia>
 <CAAeHK+wX-8=tCrn_Tx7NAhC4wVSvooB=CUZ9rS22mcGmkLa8cw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+wX-8=tCrn_Tx7NAhC4wVSvooB=CUZ9rS22mcGmkLa8cw@mail.gmail.com>
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

On Tue, Sep 08, 2020 at 03:58:07PM +0200, Andrey Konovalov wrote:
> On Thu, Aug 27, 2020 at 12:38 PM Catalin Marinas
> <catalin.marinas@arm.com> wrote:
> >
> > On Fri, Aug 14, 2020 at 07:27:06PM +0200, Andrey Konovalov wrote:
> > > @@ -957,6 +984,7 @@ SYM_FUNC_START(cpu_switch_to)
> > >       mov     sp, x9
> > >       msr     sp_el0, x1
> > >       ptrauth_keys_install_kernel x1, x8, x9, x10
> > > +     mte_restore_gcr 1, x1, x8, x9
> > >       scs_save x0, x8
> > >       scs_load x1, x8
> > >       ret
> >
> > Since we set GCR_EL1 on exception entry and return, why is this needed?
> > We don't have a per-kernel thread GCR_EL1, it's global to all threads,
> > so I think cpu_switch_to() should not be touched.
> 
> Dropping this line from the diff leads to many false-positives... I'll
> leave this to Vincenzo.

I wouldn't expect this to have any effect but maybe the
mte_thread_switch() code still touches GCR_EL1 (it does this in the
user-space support, Vincenzo's patches should move that to exception
entry/return).

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200908151622.GJ25591%40gaia.
