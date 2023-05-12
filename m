Return-Path: <kasan-dev+bncBDV37XP3XYDRBI6B7GRAMGQEHUJOI4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id B5675700C4B
	for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 17:52:04 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-3f41ce0a69fsf29169225e9.1
        for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 08:52:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683906724; cv=pass;
        d=google.com; s=arc-20160816;
        b=DeXs5Wxz5kXsea50gu7C5CabBNmMVaJGYk8G9eokdMOq4bl8HWmd4N6wsEUoCNWy4p
         gFMtpRjKmcCb9dHhyf/M5M+49IMBciVJ8fXWUN3ry08C7Us72OJusUmuNbr1GAVJRl21
         bxp7nHEzUjegZcKP/z3D2NcOgIpAUeIRE8yTA+Lsftkto1cvlWc6BtCaWsuskQ6/PV28
         jZEeM/AdM2vRGCEv1trrEEUY2hkcOuM9qUMffaDy2GSxix4ypXr2lQJzUZXGwYeJQLpu
         mmXPa2Qc5sU7WYoYOwNJv6rqZZbu+Tube7th9OfvTp1aetp/njg9afcm0pSol3SGq9oZ
         JmOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=CxanaUMVVDjxHveeF8HVRqJ5e6CdcU6kz3lBzvBI7Qo=;
        b=BvLshRP4baMGrMp65yt0XKAcVgXKjzVFZxpP3CxoY7924IVZk0RUR5RvsxFyeDQQj/
         nH10H/JH65Sis7t0M+lB9TeYXwRuaGhc6epMhsQuOVMwC82ng5PWHm3fZG2RrXLvXhZ2
         f0NygwGsY3+stacBTigbxpWHngzdnee6ejHDW2ut0hRMqaq6+xSyjfwLUgeizc+Ha15n
         dkRTwaRvGuQxJVuoz4wMUg69BWWsPWzbhpS3/8Q5WnLoAKjGiitsxfMYSRPEXTJKVJWQ
         PyUZLYp88Px4deWK5OQYWvOX8B4sRlW7SoQfyIidBgfVC71WE4DuGh0XkCvluLso8E4J
         7SDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683906724; x=1686498724;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CxanaUMVVDjxHveeF8HVRqJ5e6CdcU6kz3lBzvBI7Qo=;
        b=gTxaR9D8bVGYSSWdF3eFOWjnT1b419D7Uz6zQRn1GYPv+K49hyFR24jm4jsjO2EbHj
         eXPFyZ0GTQKiZL/NAfB+UUdierGkz4sjnh4MhRKgS6roh/9X26QCo2S+uPmuW4xwVPCw
         bQMtVjRm29LrADbijwRU44DurNzVegEL8Z40HaIp85WsXcZ02vPN60vQmNUf/YEO1Dc/
         O2H/iMq7s1oBPVPX+rZKWgouLlPcJ+0yGzgiBvMNUobRmR92EuAIa817+Y1oeobXgvBq
         dCQSRdIXxoY5j0aLtm7MTR8QuobkthguziF3/5Xa3LZ2AnjQ9kSaAOZcjo7IxrLEYyEd
         NwvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683906724; x=1686498724;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CxanaUMVVDjxHveeF8HVRqJ5e6CdcU6kz3lBzvBI7Qo=;
        b=d/Ms2kyfMOOiV+6kZPqqYFzzfbj/eXgr+irRFORPRhCBoG1+lj74dOpvwMS6uD7pjb
         vQcrAcd2NpuwQCJmwQrXbBQ0QOblacQhwABMb1D3YlQtg39OGtLXzMwy6pn5ocaXiqLK
         Wq49unnO6m4Bjvo+uhfChBBQXzr8OF+j+SVAgI3SC5XiV/K49xVNtHJgDeGmATsZGgdX
         jicdeIZssJYPD0XfcDEtX2+L6r36BmjrscyOtyprd9HHVpfhP6LqH2IX0sz3yFPmSFmE
         Db25oy3g+nJyUZaWloaZeoRmqJqGPnpIfIGFfIhkBCpSTTI6kl3nsI6lQGoUsejj/q1k
         7Zww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDx8oCPsAebd1BlUR2iwOJS9kam7gPVLg4TCSI7XQVvuBpCLfEOl
	tGzSxIGIzJcfgsnK5jCv5Ig=
X-Google-Smtp-Source: ACHHUZ4c9ZQD7qk7LuhhjFMm/GjRf0bCBX+3qdvVTSyRBGbOiAGPZyMeVt/6DculLS7/261w33Yucg==
X-Received: by 2002:a05:600c:2218:b0:3f4:22ce:bb21 with SMTP id z24-20020a05600c221800b003f422cebb21mr3573319wml.8.1683906724083;
        Fri, 12 May 2023 08:52:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:16cd:b0:2f4:1b04:ed8f with SMTP id
 h13-20020a05600016cd00b002f41b04ed8fls2254430wrf.1.-pod-prod-gmail; Fri, 12
 May 2023 08:52:02 -0700 (PDT)
X-Received: by 2002:a5d:6146:0:b0:307:8d73:fa3b with SMTP id y6-20020a5d6146000000b003078d73fa3bmr13143131wrt.39.1683906722616;
        Fri, 12 May 2023 08:52:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683906722; cv=none;
        d=google.com; s=arc-20160816;
        b=HNVTZ2l6VytSLpZncsL6y4fHDn0rJPWBP0RmyiYE5pd35zqXyWpnCs244l9G+y4K4k
         9ofwas3FsWGXeT+C8nBUsDWlfgeokcqWbguYvjSgobhyreN6e3FwYURQbkCh12El4sKq
         Wy0sNo8Jt6EMfj9PZPMdnbFRZMyIEubINadyMC2OqnsBJFCJN7TOlAOUVULuU98JegLQ
         8rnMwiJNn4RYWOXRZP1uxfd63e6Z/m4ll3IcJP47VFYeaIeW/h5H1MTy0TubJ7GlrX6O
         GxcayOaeRjcuwNkeYDH6VTjwhEEEYQtAb/8XcHRuCvp7FW9GxURENBHnp7mfm2zkDMc3
         KjaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=3Etwq9B2EphPskXlWYf31bQ00ubvWT8HbytoDJMdcCk=;
        b=aHzU4mEL9rJXz+cpCo40GKHmNiO58Pds6ZQi58x+8B3CRpg0r17eVFfTN+SPpIk1y1
         n9jxnDnIsgH4zi+msR55gTue6NkctuH9T3KIRN0oHJ8s0kMXX+AbtC+DPM7mbNWqLMBt
         BNce+aKDEik4MDBHZS0U1vMUq9FBt9/ong4aGM/aShncl9fpvQmn/hpg9m0iGLrPLxwT
         6K1TwOn7+iwpJ7f1/Clf9Q74ML0T3eIMylIhGJSEJSEmmMt/GIqN/cpzaioNftmRtyjr
         aFL8yKfLHWOk+bzg44SjpcjPMSXKZV2XL0KBzKBwIIlOMmqPrmbquf/bpWOpm+LNCcxY
         Dbqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id k9-20020a05600c1c8900b003f16ecd5e6esi1005808wms.4.2023.05.12.08.52.02
        for <kasan-dev@googlegroups.com>;
        Fri, 12 May 2023 08:52:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 6BB40D75;
	Fri, 12 May 2023 08:52:46 -0700 (PDT)
Received: from FVFF77S0Q05N (unknown [10.57.57.221])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id A6D463F663;
	Fri, 12 May 2023 08:51:59 -0700 (PDT)
Date: Fri, 12 May 2023 16:51:52 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Youngmin Nam <youngmin.nam@samsung.com>
Cc: alexandru.elisei@arm.com, andreyknvl@gmail.com,
	anshuman.khandual@arm.com, ardb@kernel.org, broonie@kernel.org,
	catalin.marinas@arm.com, d7271.choe@samsung.com, dvyukov@google.com,
	hy50.seo@samsung.com, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, maz@kernel.org,
	will@kernel.org
Subject: Re: [PATCH] arm64: set __exception_irq_entry with __irq_entry as a
 default
Message-ID: <ZF5gmBz4NbDseDHp@FVFF77S0Q05N>
References: <CGME20230424003252epcas2p29758e056b4766e53c252b5927a0cb406@epcas2p2.samsung.com>
 <20230424010436.779733-1-youngmin.nam@samsung.com>
 <ZEZhftx05blmZv1T@FVFF77S0Q05N>
 <CACT4Y+bYJ=YHNMFAyWXaid8aNYyjnzkWrKyCfMumO21WntKCzw@mail.gmail.com>
 <ZEZ/Pk0wqiBJNKEN@FVFF77S0Q05N>
 <ZEc7gzyYus+HxhDc@perf>
 <ZEfYJ5gDH4s6QJqp@FVFF77S0Q05N.cambridge.arm.com>
 <ZEixUYKPr3F0Y8Xn@perf>
 <ZF1+cLp7Io7L25yG@perf>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZF1+cLp7Io7L25yG@perf>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi,

On Fri, May 12, 2023 at 08:46:56AM +0900, Youngmin Nam wrote:
> On Wed, Apr 26, 2023 at 02:06:25PM +0900, Youngmin Nam wrote:
> > On Tue, Apr 25, 2023 at 02:39:51PM +0100, Mark Rutland wrote:
> > > On Tue, Apr 25, 2023 at 11:31:31AM +0900, Youngmin Nam wrote:
> > > > On Mon, Apr 24, 2023 at 02:08:14PM +0100, Mark Rutland wrote:
> > > > > With that in mind, I think what we should do is cut this at the instant we
> > > > > enter the exception; for the trace below that would be el1h_64_irq. I've added
> > > > > some line spacing there to make it stand out.

> > > I'd meant something like the below, marking the assembly (as x86 does) rather
> > > than the C code. I'll try to sort that out and send a proper patch series after
> > > -rc1.
> > > 
> > > Thanks,
> > > Mark.
> 
> Hi Mark.
> This is gentle remind for you.
> Can I know that you've sent the patch ?
> Actually I'm looking forward to seeing your patch. :)

Sorry; I haven't yet sent this out as I'm still looking into how this interacts
with ftrace.

I'll try to flesh out the commit message and get this out next week. You will
be Cc'd when I send it out.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZF5gmBz4NbDseDHp%40FVFF77S0Q05N.
