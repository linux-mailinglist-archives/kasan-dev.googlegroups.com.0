Return-Path: <kasan-dev+bncBDAZZCVNSYPBBXUC62FAMGQESEXIMCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id EC850423BD7
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Oct 2021 12:58:39 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id r14-20020a056830080e00b0053b7b79c0d0sf1297913ots.6
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Oct 2021 03:58:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633517918; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wxo2HfpAIugMw5eSwyEuOjDIq8rLlrY5wERzoDU3Ah5pLUyUl2hRwklffzgBHwbXqE
         El07jquFpx+aF2poaN9n/ET29CvJ+2EO8tgGlGZR5pYcOxMwAG6JXk5ysJ0ZYXVtYIes
         h0vdQ/KkI1o7AqiJB3vGvFDAj5s4GOJAwU+BkvBVb/pJRMNXbNkJ1dRTlvtzNoNMlOPt
         5LlB+HBds2qQrlAxm1vPyR26bXrrB8HhfEyj86jCx0V94TeC1gzcILrQSeg6D9F4HWSC
         KJwVx5dJilviSwsSFR9sPdH/I3iyZ2VaivAImwYtNGTwqTqptA3TdLssGOiQ8r5Ttecx
         Ly6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=lXLHCJNq8N5nkn/ADIw+sk279yh2BbJ05oqITeJuVq8=;
        b=v6LtVu4yiPCC/vn0cs6Gcu8dMdtFAvHQLmbDvm8RtAXhV4EzjqjNev2jyBFysGdXdU
         EmJkPU05xcN1JKi4I0bRQiR8MYoMpUAs+oVZvNGoWOZVh+PV5MvQzIs5BG7Jq+dRuHl+
         nly1709IPuzv09b5XdkK8NHsALwBzbGhWLNnYSNhx7O0ALBHK0X19MDx/xgMqayawHbh
         M3lFm9gJeIaWS9b9sBKxKDdd5bZMCNOZAZ3qmNMkDEVB8+Ht46XCxVbPKDw6qcXG+ohD
         FWsqIKnt3LAtzgETEL/HPEZUqm0Ii1sr/rVWQJrn+X7N7b5K3iUbpdatFZK8xkC6IK2b
         i+yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=A3g23Vuz;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lXLHCJNq8N5nkn/ADIw+sk279yh2BbJ05oqITeJuVq8=;
        b=lzMKBbdVJBGMGqMdvcbxQq+IRL898dtuS4aiJ9ekAl+eYGlqaTHDe2glBHZgPEWaHI
         fu57Rgnb76a1T06Vr/9hf0l6bt06hS+J2wgnc6b90cb+raCtSggoGdkJpSjVOsTK/sf1
         K+Xej+iyWrwuPa0NgAOMOWf+ycf5u/LRzYhI7x+LgYDzhzh0tVDIpMKlL8EZaq4mxpqI
         fza/0/ZIRH3MEhU2bw7b2PxSrXEODHeBvDPFtpD4rmXFEU0EeN1mOo5UncNi/6HMmaJm
         nTUNNHEADKHTrPAv6oN0R3Av6aRGkiVJBI5564cFRREAHoq1tTBfYrwTZB8GgYkZJAyU
         Ra7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lXLHCJNq8N5nkn/ADIw+sk279yh2BbJ05oqITeJuVq8=;
        b=u6cWYmsNBEUe7JXxPxqE+QmMN4ySPIAeW+TWSBEywE2LHW1SoobyzAiEZrb9beazIQ
         0WQLc5Q34KaIXmWoL4dm5A3uWB6/BkYYj2YBVbuZDTyrUi+N+4kkz/zG9ZcPemRhrX1O
         Df/A/RefZWYPwUkYGfKnLX7add2I+vlDFZ3owg0kTjfT5tpI6NaXTGqzLhSEpgXuaCzz
         SFf/jN9VJchOgvLE7FemDj1le+KkkIdbI7SfkDwcPTb+3ipYPY/FGIJ5vCqRspV3MoXR
         rvcXlJ2jL+zmPati4ugn2QG/Wp3Tx+PjU8k4qUu1uv+Js+QkZlVwyKjcB0K+ytmV7z5j
         mtpA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5339k8KCNaOUcDD5cclOKjag+NCbqQtgH6eUlAjijCZGNtxXkExk
	MHlZ/I692pwR8SAT0WauC/4=
X-Google-Smtp-Source: ABdhPJxZDGahxk4vNtpQ7C/NN2sMTNJ6ECU3Zr9dAOCDT8sHDf0usHvLH4fsgRURg7TdrXpXdKLxHw==
X-Received: by 2002:aca:d78b:: with SMTP id o133mr6642543oig.136.1633517918446;
        Wed, 06 Oct 2021 03:58:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:ab82:: with SMTP id u124ls255716oie.0.gmail; Wed, 06 Oct
 2021 03:58:38 -0700 (PDT)
X-Received: by 2002:aca:2112:: with SMTP id 18mr1336739oiz.80.1633517918159;
        Wed, 06 Oct 2021 03:58:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633517918; cv=none;
        d=google.com; s=arc-20160816;
        b=aC0x+B0yTFQIplTnGpnfT5MB9s4sDvNDBycEifoo/kB8F//qONOHcjNQZF7hlP2JgY
         NVjreGg8+tFm0L2bSmAwf3qWfUnu8JEPr2aloe0NK16jNqQmmDCkta8md7gffMSsNGv8
         7Jrk9DHtNz9t2I6vvcXjzuTeGdFelxTIeAzTvkgMai73W+KavfBo31pUYIEOuH508ldH
         P69fjYfFYk8S84pixC8SKW4pjaGtxpsNJ374NXOcFWwJqPWusllNV2ge53FdDtvDE92W
         TRKE55azP/IT6kD2IMjXirppTAm81ISfrFcuv9B04W13wMus/JY6tDJdQ34W7ws6SHk0
         3XVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=I/OLsc20figACzRHiA/tK9zuHN/0NyqmFuiA1Fyjess=;
        b=iajCMaJprEBn3Yj22Tjp0KCYPKL1RydtJaVrdue4VAhx6R7PJFEO+D+zVg17VKSaH6
         H7QNhmKhMeak+xRgKf2nWGXPL57lsAnqP9GgFmIpT7HzgUXreSVbMHB60h9xs3s6Qyb/
         xLaMUwBwqVkkJF5nG4aNp9cxitnkY7d4Yxr9MKUGFt4RIIhUk/uCx3twCp1Rm3w2195C
         iyVaq77Sya/HlpittMV41mRl2FNq8dWFv2jxGyaUFdf2udWip6Wu1f+XrBQvJvNDl4le
         8nISYx/C/rC1uqmwJBFvK4heWxuAhysBfBPtE8c+IvZCZVZ6mYgF3x1qBeFl/2gofCYk
         MUQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=A3g23Vuz;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id bf17si1818393oib.5.2021.10.06.03.58.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 06 Oct 2021 03:58:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 5630D610C9;
	Wed,  6 Oct 2021 10:58:35 +0000 (UTC)
Date: Wed, 6 Oct 2021 11:58:31 +0100
From: Will Deacon <will@kernel.org>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: Re: [PATCH v2 5/5] kasan: Extend KASAN mode kernel parameter
Message-ID: <20211006105831.GA30555@willie-the-truck>
References: <20211004202253.27857-1-vincenzo.frascino@arm.com>
 <20211004202253.27857-6-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211004202253.27857-6-vincenzo.frascino@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=A3g23Vuz;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Mon, Oct 04, 2021 at 09:22:53PM +0100, Vincenzo Frascino wrote:
> Architectures supported by KASAN_HW_TAGS can provide an asymmetric mode
> of execution. On an MTE enabled arm64 hw for example this can be
> identified with the asymmetric tagging mode of execution. In particular,
> when such a mode is present, the CPU triggers a fault on a tag mismatch
> during a load operation and asynchronously updates a register when a tag
> mismatch is detected during a store operation.
> 
> Extend the KASAN HW execution mode kernel command line parameter to
> support asymmetric mode.
> 
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
> ---
>  Documentation/dev-tools/kasan.rst |  7 +++++--
>  lib/test_kasan.c                  |  2 +-
>  mm/kasan/hw_tags.c                | 27 ++++++++++++++++++++++-----
>  mm/kasan/kasan.h                  | 22 +++++++++++++++++++---
>  mm/kasan/report.c                 |  2 +-
>  5 files changed, 48 insertions(+), 12 deletions(-)

I'll wait for an Ack from Andrey or Marco before queueing this.

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211006105831.GA30555%40willie-the-truck.
