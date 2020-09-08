Return-Path: <kasan-dev+bncBDDL3KWR4EBRBJOL335AKGQES6X25UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id DAB152613A8
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 17:39:18 +0200 (CEST)
Received: by mail-vs1-xe38.google.com with SMTP id 3sf3400654vsx.13
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 08:39:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599579558; cv=pass;
        d=google.com; s=arc-20160816;
        b=ItHdCffe+2zd3t88G2vfibX1P/jldAwZMnhSlKHQPEUAwxGOvTkegzK6TAiUf/baRF
         mXsiGpzq2uiDIfT6cikJU2iQ+vAJtXKi8vTi1IO185xE0td4yvS19cSkkLkB3dsOW2J6
         NJVe/LKu1lU3WYopEBSWYXauDXmU+lXOm0mzSuOEyNFFYlFQ+5hqfr8C65wwSTQpx1L6
         Ma86vgZNtKN0fBvR87qyJafS0aNjX+tDCjZjQOA4YzgEeOrB4b4tHOhkzXhf5NiJTyaW
         E52qh1ej7IuAt5v47HsKlDZSVarfkWqABD6AOlIHlaySmqCXnxGRnyseoajPRt8Z8Oxy
         SHhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=9M2s8ctc2ZSHUJqKOdOOAAxvjr0m6pkzOHfezWJNdw4=;
        b=y9znbJzB8qetcoELxhFjrm05aLtzL46mIXwN5W0EzAJ0EqRvsNPzWmqDSd9WiKmLoJ
         6pL18Coy3kzhAreWuh5fCLQ6cKZoYo0E9zbesUo8gi2CS52SyZmzhwIFxpDD33lFbGdO
         /I9D3J5TF/giciJBmF290iYzzB3pa1M559tnMPWTAU4j6GClPgU0Qd/g9NoPXkMebZs4
         9SpWB7PDxOWf8AIfqSjOKt8psCOLef2pA+kQSGAY+pDnddAHX4qXTP4gpO+YvSBqv9nN
         JSdOu42NCIGe4PXVIWNKOYOUkh55I+0A+AHe7+kEabyOEFRh9lfEUjgkeXD50HP7Almw
         UROQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9M2s8ctc2ZSHUJqKOdOOAAxvjr0m6pkzOHfezWJNdw4=;
        b=SyGCl/0pyEdRsCKM6KCgUhLj+tLh+mNl9faIYJe0T/JKJv7nbeUM3MuKZr+068krov
         mmUXSMVqac+yrMWcMOMt+RJyJyIPabfYEWe1rwARtOdcu+JoOSubHXIkkhAW78QkkM0f
         OyZkdZSrP/5jWTLaW3Tq+BhPf79E90Q180jpIxSIV0G1zzG6WTIEBsMoJg3TX2lCm35t
         q61kyXMTYqqGSt1/SMM/Ig8IvpuYg4wklK7OUp7Z1eoL9qTU1n2nSHrVIAVwYMEQ7fxc
         tnNwgHdmPEGgwn+IHudELqiIZErF+/xan8LNunWzsjLVNxP4tmPLaMg5vBkIo1BCDiCH
         qwXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9M2s8ctc2ZSHUJqKOdOOAAxvjr0m6pkzOHfezWJNdw4=;
        b=Kja4ibJ2FZp+n/tghaEs6DhmWgQI/aMtpumIrhRRmCrv0+Df2V7WZOXIEgzhSWqEsz
         WTlLFXqjJBw//FcwKd/ZJ7LDjG7i1ZioimRYj585barXg7LsyXgn7wS30PkMItl4znbf
         w1ZZA8iXR75ZxibnhD8a/1CAJjHHzzSeKj3MT6w0+KQAor4EAOhQKuYqYu5zfFJgNL0X
         yoDGQ9tbnWgFTN2iXoZxav4NydkJMJIClrnvZxw4fzmL5dy2VD+R4PZWw1pbc+1H0+MO
         1KYYLewszTLgMSDvBw0t8aXcyHvcm+6bqastJzuUC2G9eQlHBYrFKQ+wSU6ws5L6y0Sr
         DhBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530vNyuGZxpzzNnTdNJfXZy+WEnrXSUe6gvb3aVuT4aO6If1MfqU
	BLW8Ib8agaopmBeE5ZVTqMU=
X-Google-Smtp-Source: ABdhPJxDMretSoGhYesgVvRjHnkLr/bjPGvqLcofL5nqp3E4zEMTKNsLzgUlJUDibGb9w5m2nDJ/aw==
X-Received: by 2002:a67:7d52:: with SMTP id y79mr15312238vsc.34.1599579557932;
        Tue, 08 Sep 2020 08:39:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:3183:: with SMTP id c3ls2457605vsh.5.gmail; Tue, 08
 Sep 2020 08:39:17 -0700 (PDT)
X-Received: by 2002:a05:6102:226a:: with SMTP id v10mr1347003vsd.28.1599579557337;
        Tue, 08 Sep 2020 08:39:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599579557; cv=none;
        d=google.com; s=arc-20160816;
        b=v0FysxLcrB/PXkF7ya+F6bk4X9diY3oFJUBHuoBLaSW40whFpasR7Zqi7Osp2AvFKX
         SwmpJPrVzYLbOiLTpz8Qz3/QBTTfZHCrSCzuKVei1NF1HhivSV+J/CagFu3WbxThse8J
         Ui9M2p4sripFOrovOb4tlqrt+JsGBFyMNlbMHPhTFsPaVLcDaoVg/pTjigezumo1+LNt
         KTNE2BhRi65jq77TFUQQl6SVhUCS6VN5vLwlCCVn2GUBR4FKG/C1EW/Hn+TCnho1NIvM
         gjB/T/IVT5YhI6O3K3YzdbUkpzp15sZYcSYQWlIIgt3rsltRdeC6urlWlG+AhGt/Lh6u
         OEmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=CzeQ9DdrbquynWH3MRxVx2h7XesAlGjIoWK9Q/P/Yxw=;
        b=a4ebu318vVpkwvU70PdNmLZgkXYyw+IAC7SXq+gwZuosDVqMsI+C2yoUlITBV4xp6k
         VMOf5kVgnb0DxEDxLHgf0hWPXtu+dX1yjJj22+ByiIZdvqSYaGa9qr3JxpKODhOaF5L3
         L25FkjHBZRXb361PSlA7trlkVE35RUx61YwduvShZH/RWCvRUxUWe9CYDgGRhmMPSrke
         xk/EfGz3uDA2qYjHLylmLI1Sm1/qgmCDY1OaKD+CCbEcjBEYIGJxU8ncR+wNtYlgHg3s
         DvfTo292Zrci3j4/yEYLj3si4WKCw4WLvA/MFHnnDRGlEr7LtWsHm3Bp8hLow/biMoPY
         PDOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u19si989086vsl.0.2020.09.08.08.39.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Sep 2020 08:39:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [46.69.195.48])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id D6EA92463B;
	Tue,  8 Sep 2020 15:39:13 +0000 (UTC)
Date: Tue, 8 Sep 2020 16:39:11 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
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
Message-ID: <20200908153910.GK25591@gaia>
References: <cover.1597425745.git.andreyknvl@google.com>
 <ec314a9589ef8db18494d533b6eaf1fd678dc010.1597425745.git.andreyknvl@google.com>
 <20200827103819.GE29264@gaia>
 <8affcfbe-b8b4-0914-1651-368f669ddf85@arm.com>
 <20200827121604.GL29264@gaia>
 <CAAeHK+yYEFHAQMxhL=uwfgaejo3Ld0gp5=ss38CjW6wyYCaZFw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+yYEFHAQMxhL=uwfgaejo3Ld0gp5=ss38CjW6wyYCaZFw@mail.gmail.com>
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

On Tue, Sep 08, 2020 at 04:02:06PM +0200, Andrey Konovalov wrote:
> On Thu, Aug 27, 2020 at 2:16 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> > On Thu, Aug 27, 2020 at 11:56:49AM +0100, Vincenzo Frascino wrote:
> > > On 8/27/20 11:38 AM, Catalin Marinas wrote:
> > > > On Fri, Aug 14, 2020 at 07:27:06PM +0200, Andrey Konovalov wrote:
> > > >> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> > > >> index 7717ea9bc2a7..cfac7d02f032 100644
> > > >> --- a/arch/arm64/kernel/mte.c
> > > >> +++ b/arch/arm64/kernel/mte.c
> > > >> @@ -18,10 +18,14 @@
> > > >>
> > > >>  #include <asm/barrier.h>
> > > >>  #include <asm/cpufeature.h>
> > > >> +#include <asm/kasan.h>
> > > >> +#include <asm/kprobes.h>
> > > >>  #include <asm/mte.h>
> > > >>  #include <asm/ptrace.h>
> > > >>  #include <asm/sysreg.h>
> > > >>
> > > >> +u64 gcr_kernel_excl __read_mostly;
> > > >
> > > > Could we make this __ro_after_init?
> > >
> > > Yes, it makes sense, it should be updated only once through mte_init_tags().
> > >
> > > Something to consider though here is that this might not be the right approach
> > > if in future we want to add stack tagging. In such a case we need to know the
> > > kernel exclude mask before any C code is executed. Initializing the mask via
> > > mte_init_tags() it is too late.
> >
> > It depends on how stack tagging ends up in the kernel, whether it uses
> > ADDG/SUBG or not. If it's only IRG, I think it can cope with changing
> > the GCR_EL1.Excl in the middle of a function.
> >
> > > I was thinking to add a compilation define instead of having gcr_kernel_excl in
> > > place. This might not work if the kernel excl mask is meant to change during the
> > > execution.
> >
> > A macro with the default value works for me. That's what it basically is
> > currently, only that it ends up in a variable.
> 
> Some thoughts on the topic: gcr_kernel_excl is currently initialized
> in mte_init_tags() and depends on the max_tag value dynamically
> provided to it, so it's not something that can be expressed with a
> define. In the case of KASAN the max_tag value is static, but if we
> rely on that we make core MTE code depend on KASAN, which doesn't seem
> right from the design perspective.

The design is debatable. If we want MTE to run on production devices, we
either (1) optimise out some bits of KASAN (configurable) or (2) we
decouple MTE and KASAN completely and add new callbacks in the core code
(slab allocator etc.) specific to MTE.

My first choice is (1), unless there is a strong technical argument why
it is not possible.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200908153910.GK25591%40gaia.
