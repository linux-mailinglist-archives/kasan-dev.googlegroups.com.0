Return-Path: <kasan-dev+bncBDDL3KWR4EBRBEVOW75QKGQEBMEBMQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id DAFFE278617
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 13:40:03 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id p11sf1739548pjv.2
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 04:40:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601034002; cv=pass;
        d=google.com; s=arc-20160816;
        b=OYt1lvaz+a0i0oUTZpcj8tW70vgA6i9g7fG8+G0ho70vSnpwLRIHKj1FTDdMAwFvMQ
         /p6NkVFABClHpQ1sTsLkjoGrT2dHjCoU39VnWMChQrZRV9aPGhkzBfN/pFt5t+2YyoaB
         DzzSF3tLn5PAOQCP7jEtQoda88qP64FABXGAiP0vRlxRhm/TcRjAlhnZnZOYivMTRLHv
         VRvsy6lAks3qFK+vSwgc0VBI/pfXKwzwTBCJGjDh+kDCUro8d+/ghVitluj2UUsN3ch3
         UG7qfltbXu2MrBGRrJ/DS9gi82ymaN9Ywirn9kLinfB6koni0MTg00GAmpFwhTM0xZzd
         JssQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=vgGFW6qkxDz2GyMubHboQ/zUSZRMHn7dsamzugM2AF4=;
        b=eeqFPp7m3fegRBDlOB+ABiYvZMOdwQ3lwpPe0irDXyCNs+7zw08740dE9NDzia2EvL
         VxmNQnjFMWC6K7f8Tu1pT6B2w4f0MioesQR02M7CndaFkM399R6LkOGTn3N7yUmuum4o
         SDlDig/tY+flcZyUtkbEWGg6U4P6jPpPm9mPA4USIK0uKBBkyKKAOtH9Kzk3qd7WvmdV
         cbPKfAUPfizYiUFFfzoXcZoSm21fiYazvRTpJ0s4UYTy6rfYuP5O3lPb0kVgKZv4XPGd
         BOxrBCqn57kr09x42dgf5dlyiT3pM0x2eb44PJoc40S9giiGkGYAiZ1mET5R9+pHrhC5
         p30w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vgGFW6qkxDz2GyMubHboQ/zUSZRMHn7dsamzugM2AF4=;
        b=dTYcnUuc0SlvoHnNIfts4Q0frIrYmqTzkvLju19C/izapmgC9Y56TY3ZdJesNaK5ca
         XjbmnvuRZ5ek8dOnHjCl1osX4QyxjIz/L2xHc1HNgHSSXy5Y6IUvJPJCPyljNmINGaa9
         yR4Ti2/SDBHpeFvvvccEP4e77PU/re4QYxQ7Ym0AwqOa0dpCXHjP1hNVm8dhvD+H3zIB
         YzdSwBNSApY1t7/BYKdcigOfbE/NJX7RN6pv5YTN9xfFCnw0fBE0ylFOPNQ0r+PkFg00
         C1XtcBWwXplJicYxhQO38fBZmyx8tKyuZAdpIMTv99+OFR1dneddZ4947UB34oWAKNcD
         BQWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vgGFW6qkxDz2GyMubHboQ/zUSZRMHn7dsamzugM2AF4=;
        b=N4LH4bHDX2aaoFDqXr0E0tTaQT3OyrRT7WBOJzOPe5IZSge0d5xxHpIrYRDZ6LIir9
         qFRXzRVUa3gCRDDi/gHgrrxtI+Dh9Qu3ABk1hMHNQ7B7NOPhXDFSfUk35Ab+Zacl1ZQd
         ViYFHeBQ4guLUYX8BuNpqnCq0FlkkWeOBCf6NKyCk3tbQd/98mCTCwDZ9pLJkr4y3pa2
         NcbRF19663xpZ+OcEcOBlFzEPx2gZX3x80PkhpGh6CeG6nu/Jn1OHfQY5nNxyxR672hV
         LqJvt7QjUQ9VAdmfHsBZUtNq5MiHLvFhXvRqt2PaNih9DJMS1EsAPF8jwC/qcnWfdOhS
         +EjQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530es+SiPYiR6P5gHI0ExqW4HIUtGDjqWgU0Zxam04LVvAv6k0qO
	fjl1soWGSUNQ7yCvL2GGLVc=
X-Google-Smtp-Source: ABdhPJylkRpeZC1ftLxIJvRbJb+d+DYOIK+7e/4NVv1Uo5F6hfZPuRSd1j8goA+nJFrt7gVsmTGJqA==
X-Received: by 2002:a17:902:9343:b029:d1:f3e1:c190 with SMTP id g3-20020a1709029343b02900d1f3e1c190mr4062300plp.2.1601034002594;
        Fri, 25 Sep 2020 04:40:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:7d09:: with SMTP id y9ls979093pgc.3.gmail; Fri, 25 Sep
 2020 04:40:01 -0700 (PDT)
X-Received: by 2002:a63:801:: with SMTP id 1mr3216811pgi.48.1601034001840;
        Fri, 25 Sep 2020 04:40:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601034001; cv=none;
        d=google.com; s=arc-20160816;
        b=LmDEZt9D0rVN9F5uChEQI/PJRWHX9RdFZWevZm+quiGjvGyJ6FvMgTeMYic9ksfxua
         4l9quSpMBGRdFpyBTO6sN0WzdWlRN0WY96B62noPV+X2uPZcygzdTVHbY7saysfXHgya
         HDTfdyURvxvzjfSLnwxW82w/J88mukn23ELgnwVTVCHAQuqqpcFTzJ9onWIzgtph/n6F
         +4VVFP4tLgiZKyAuDMQvSVmm073jJLrFx5adTZ5p12+eTE47MhFjulFjPLvgZUJCYWTM
         tJppe1j5VRl/YG9e76LxQrUnoeWTgvOXjlD+DF1z5Evckugyv0k/Cyo6LP+JOhPKOrbH
         ZUSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=Ywn1dfTmAWs5UaUsl3pAQD2FaKkGjyEvvtRSF3VDL2g=;
        b=BrDI4gHJkbC1WzlECPjUsrXifCRmC9VPQ1lCoGlkFC+N/bZpVZT8ogqUmTEwpSVFhn
         v82D6SFxKbNSsP3kR/6J/SseF/KgzxaiZfSrvR98EkW1QVF9w0O3VGpQk5ad2kvTMnpR
         C6IiTbny6hI48FN9dsqIsBWgLlZj8Xt7Y+CfFrPebvfZFyVF2NWzgfth2qqYknQqNim1
         BEwaNkAlGtg2c526pzBJX0o55DYWN25Kb2qmUMSvRQe0mz2D2KFbVV7wgJR9jFTSYbHE
         D4OYcWbPYwmkDHMXQdQWistb8Jc+ftkP5uvzrFKv7iGXbb2UJAoDJRSxb0fzxJSXcQgP
         maYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c4si168400plz.2.2020.09.25.04.40.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 25 Sep 2020 04:40:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 0AAE82075E;
	Fri, 25 Sep 2020 11:39:58 +0000 (UTC)
Date: Fri, 25 Sep 2020 12:39:56 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
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
Subject: Re: [PATCH v3 36/39] kasan, arm64: print report from tag fault
 handler
Message-ID: <20200925113956.GH4846@gaia>
References: <cover.1600987622.git.andreyknvl@google.com>
 <6296d106e480eed388f86e3c8fce10a14bead75a.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <6296d106e480eed388f86e3c8fce10a14bead75a.1600987622.git.andreyknvl@google.com>
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

On Fri, Sep 25, 2020 at 12:50:43AM +0200, Andrey Konovalov wrote:
> Add error reporting for hardware tag-based KASAN. When CONFIG_KASAN_HW_TAGS
> is enabled, print KASAN report from the arm64 tag fault handler.
> 
> SAS bits aren't set in ESR for all faults reported in EL1, so it's
> impossible to find out the size of the access the caused the fault.
> Adapt KASAN reporting code to handle this case.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200925113956.GH4846%40gaia.
