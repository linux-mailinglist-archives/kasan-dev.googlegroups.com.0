Return-Path: <kasan-dev+bncBDDL3KWR4EBRBOOJW75QKGQEVMJNHQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3a.google.com (mail-vs1-xe3a.google.com [IPv6:2607:f8b0:4864:20::e3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E23927875D
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 14:38:18 +0200 (CEST)
Received: by mail-vs1-xe3a.google.com with SMTP id v131sf659099vsv.9
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 05:38:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601037497; cv=pass;
        d=google.com; s=arc-20160816;
        b=K+cTh98gb4u3lJjg8u4N66a4rwH9nnWoNltOKtwnIIfZf5O9jF//FgEmcL2LH7E3Vj
         DpOBZ6HarvtNeMrkLdf31HDWrYODgIM1DbA3CyR2uTH+KqRRqcFieTpXsQ+nqAA3FqVO
         nBmH4DO0MuBO6NnjaW1WlzljDF+C74BYmvbUZVtO0LATmxX1cR0QXNpZEaVjWSYKbr9J
         9eWACWhlXngOXeQssGtoEca0frvcQl7S7XD9Ny4m8Ne2ipBGB1DEF0kWz2HF3VzEEnxh
         qzVC7JVX7GG+80GrquYQo66qQ/ntkADRqhqsIcdTFXtdgpOZ2OkXrtDWSFJjihlgoj5a
         1PCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=NYpw/113QJNK/toG4O4lqxfV3QD/RyqXSnc2Xktg9xk=;
        b=qqIHUF+mynDREdbEVVOal0hSKMt+ZHEe3hnLffJhTseiC/1br7im12lEuJeGJsDRJ3
         KMge7hXRdt7IwMsHucau3O5mpUfPOaLip21SPo2gaPDdA8SehmyBOrv8JACgZt0qq/Vx
         4Zf59umGE/d8hnW0WWwkt/fwXqm6XBWUUoVjK0aFdPe88IXx2x8eEeiqcEDtzwgdkABr
         ujM7yUdyRH8Fba7G+dX7SxuNwsR7l6CnWmqrCw/Qr5UyLe2ls2C8WZiJFrS9ImBSICY4
         t4dIXd/VUx/j6W/yTpvxdGcYbPRTchdg/KWzjT1lm3T63XwrYwrCR7ZyFHSEdk24KCMg
         oImQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NYpw/113QJNK/toG4O4lqxfV3QD/RyqXSnc2Xktg9xk=;
        b=OyylL9R3902roZVYWS//IlJ5hOZ8ivGdvdte5ubXr8F9x5pUcXnaDoLauCmKlaTzDv
         xt1qneb543FbPVuiteBlZNjsdL1UfJRpudpvn2YKpi5IeBcGorWq1+drYrcoEjqdCUOA
         GEounbeg+SDrD/5LzZFUlADpCC6MZZcfptC9CqK/jRCmzg5TAqDVxNS+qJpfg0z0uw75
         nNiOUkth5UyqDoWxr1Fpehh6Dohvc3lNc3xn4NVRTySi+rH+hCG9RQPTlk60PWFG+GBu
         Fs5Q4bM/RDj9Hz5fUwvFopeldDYwud5kO3xOVYCx/S4KjuVP7qvNaZ2h/cWLUHMeJn3H
         MFkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NYpw/113QJNK/toG4O4lqxfV3QD/RyqXSnc2Xktg9xk=;
        b=oiWcKFksZ22mgU2tPsZmDlvqvtMPE3oNhRC9G8NZRUizgm3zom+2M13a8fgh0EHXjY
         kOmQMDU3XEp6Zis3Uy2Jbiy/4CWeflCjKxK7/4BK00XvUjevi1q6w2DSlZBnT2hga2KU
         iJV9qR4Sf691rMnzH50NujgFXi9dmjc3PAn3ZUWvlpv2mewfYop8ri34a7hFKoqLMav2
         +zO/KfUlrIjqH4aNrozAgLvbQnJ9scVZLmJMJxCEiu9XiAQmu7mMQ1P7RdGEScuLZAs5
         V2MEtS29IGvr8cnEgfgkwMm0sdVSuksizjh7SVzOC/5+H+PEokzk6/ak7XDSyhYqSfpU
         1Rvg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530IXWOnbYVxStJVsMSQ0syZ8bsBH3EFV9slYxGyfzYUUXQlrFrl
	WjTz6kyxW/G/dGauWW4qwto=
X-Google-Smtp-Source: ABdhPJzQhk34+jUeYKA1K+e2Yn1GLM3GBU21OBaW1W5QDgIb9ofd4X0SY6T17rU0gUSOeT8iIHKo7w==
X-Received: by 2002:a67:e3aa:: with SMTP id j10mr2472765vsm.51.1601037497465;
        Fri, 25 Sep 2020 05:38:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:441:: with SMTP id 59ls217573uav.5.gmail; Fri, 25 Sep
 2020 05:38:16 -0700 (PDT)
X-Received: by 2002:ab0:7018:: with SMTP id k24mr2215766ual.131.1601037496845;
        Fri, 25 Sep 2020 05:38:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601037496; cv=none;
        d=google.com; s=arc-20160816;
        b=gm4AYK/5fxPqBp3TFQQaruFXKvyamrUuiccb6pushU/1EXjDXeYrkOD2WpW03G392T
         NedXWdEaKQmpGVNym/8mxqxrjjF7a0NqTM7CLcIKqdqDV8dHH2Y/HmwkbiYXWjzjw2pU
         Cxp74hRn0GJPpkm8tJpmzLnelVqcbUXlcxa1tjm7uyCeeN+HVQ0uukIngTnsINf20jbR
         grDlU0Yo33A9bytrsuWNh69ABadal7GhXUXtEqlFcvEQ5LpfhNrtnbd5RznMnEpboq3V
         PkmEGCFi/9ONzVJw7EHUnIcNrHx7xDLeC0mhLtQb84zD9U6N0IEFUqoYwOB9UQL8aD5R
         +g1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=9+ETZFBB2T3G0pHYyzjdCHymF7hNCm5BONtR8ywrMPI=;
        b=Koc3/xY757X6jixj/cldssjQvcWj+2Glx4mSJO24xadYM99rbcjnHEcNMWXSnP91yM
         6iQmx2fDSmFelMfEqNz9eupnMJuJAVvoiMXpAP3Ecolv1yfh9pkTmlPxB/cYyRyMH96w
         LEptyUPCyGutm4xfxhVsUK/me4WrVrdpMEzFBIXZe9fpiV9hqOR2dxMH5nwn0+Cn0DYH
         H0jm4hXa2d1r7jhDBFO3C33pBwSanc44KejnmpTmmMU/rWFTOUMwWtKjnol+QFbqhfxx
         K+uVOrt5iXiAUVwuAIdMDlo877FtepzRqfO/yBuI9mYCDMNJXdFPVP7pzXcrgvPCMo9F
         cmWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x127si136559vkc.4.2020.09.25.05.38.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 25 Sep 2020 05:38:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 200A721D7A;
	Fri, 25 Sep 2020 12:38:12 +0000 (UTC)
Date: Fri, 25 Sep 2020 13:38:10 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 29/39] arm64: mte: Switch GCR_EL1 in kernel entry and
 exit
Message-ID: <20200925123810.GL4846@gaia>
References: <cover.1600987622.git.andreyknvl@google.com>
 <4e503a54297cf46ea1261f43aa325c598d9bd73e.1600987622.git.andreyknvl@google.com>
 <20200925113433.GF4846@gaia>
 <e4624059-1598-17eb-2c64-3e7f26c2a1ba@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <e4624059-1598-17eb-2c64-3e7f26c2a1ba@arm.com>
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

On Fri, Sep 25, 2020 at 12:50:23PM +0100, Vincenzo Frascino wrote:
> On 9/25/20 12:34 PM, Catalin Marinas wrote:
> > On Fri, Sep 25, 2020 at 12:50:36AM +0200, Andrey Konovalov wrote:
> >> +	/*
> >> +	 * Calculate and set the exclude mask preserving
> >> +	 * the RRND (bit[16]) setting.
> >> +	 */
> >> +	mrs_s	\tmp2, SYS_GCR_EL1
> >> +	bfi	\tmp2, \tmp, #0, #16
> >> +	msr_s	SYS_GCR_EL1, \tmp2
> >> +	isb
> >> +1:
> >> +#endif
> >> +	.endm
> >> +
> >> +	.macro mte_set_kernel_gcr, tsk, tmp, tmp2
> > 
> > What's the point of a 'tsk' argument here?
> 
> It is unused. I kept the interface same in between kernel and user.
> I can either add a comment or remove it. Which one do you prefer?

Please remove it. Having the same interface is more confusing since you
have a single kernel gcr_excl but multiple user gcr_excl.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200925123810.GL4846%40gaia.
