Return-Path: <kasan-dev+bncBDDL3KWR4EBRBAFPR35QKGQEYWEBGFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5419226E1BA
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 19:06:09 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id w126sf2085851qka.5
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 10:06:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600362368; cv=pass;
        d=google.com; s=arc-20160816;
        b=oYI0s46ckEEbOTNuC1CzkUBdjQ3qoB82is05vnDH/CeCDvfGxxc1+hosUleQVPiyHD
         Ye9hdip2Wk6T6W3bu7iafw1BvpoFuqLEN3U5uS4hEjgD91t1Ir2wi2QofqR5vE8Ei+aW
         F9ARyWZ5gDh/Ec7Pg52kM0NuE3kx0WhcnHgC8DXk099kM/Ihrh5Vtyvhg/GGbHHFO1uy
         7FfzW4nbHZs/T26IHxH5W62c4Y4g2ymhE+jai09iIFXVDhuuOT3phCLqizhHYK2UE2cB
         n8E7XA1Pq1p/B3ciGjKUgDyPUMt20YnFC0SyuLl7ME6/SqW5s1b99YQ3Xn8Ft6J72Od9
         TPSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=LF2UCyzcz65iwKSU+sLPGrOrO+p3uZlDf+EXF91tKGc=;
        b=dp1CvURlKoT8MIic/+celEe9jGkt/g3Y/DxKP08lMwQK6/WIFaUc9so+qpO0GQZRDQ
         ugubAPr1gs11kz8pPSRFc8VxVq4Z0F1GM3yenLjc4B8u8K5swOQ3HrlVCrKDTRB6x0oT
         usfDGjog20XbiUGUCQJm2D2ReghT8c4CZSDtpvxe9GyM3gvdsVL7nUU98t7JsqXAB7/z
         Q3FndATAYrxxFQgV5I4lJRAKkXg6fAKNuqtX8e/2SOeUUdAnmF6Hbxjtwv2V8f1hT30j
         7gFLVHTB7R0r/+x8LdzB5/a5VzIfNfLhXy1MpijRj47Yyi0dtNHnC0pGm3iSKo5i91CP
         IzPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LF2UCyzcz65iwKSU+sLPGrOrO+p3uZlDf+EXF91tKGc=;
        b=F2t6HMpCsYuq1uqLllWMy1ALwHIY07LxFKVRzrQ4YlJS94JMf+x/cQm3Hb7/cOucam
         za611wZhoQJjYNaM3XPehA9WTooY/ddSgoaBRU7XretvKxZVT9VtT3d0nfzHtL/CZaCy
         GtuaWAZZFnGsHHu/rcnfF0OVHLb11LGWH7XGEcq4LMjZWwUSOO5bVJEvaSsRUvKud0hs
         8I7v6HHfNr3lEoL6rONN3lUvNS4zR512pQaba8P5BXnlFiBnsJPRbrdmWxUhaYqDxEUh
         kmNv8H8hAz0npi/qt2IvQtTR8PuFfgYVw7HvfAv6OZg4nS1k0hahUI6nuGHtPUdMLoLs
         Gywg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LF2UCyzcz65iwKSU+sLPGrOrO+p3uZlDf+EXF91tKGc=;
        b=i7fC82aXx5EssshIxWYQ480mL54PyriTiLkABSMtnTwMyOB4LcekuxImPwgfT6ASPB
         3EjeTcchj8mLT5PcI5HR7EiAOUWLdMfoiLi6d66QqIZbAryJcz2fiZd6yFKyH+oc81Jw
         L5BqUx8txcq6ku8fcBnBXg8U509FxCbwXran02tK8mbZtyO+PEKTNAgGC/clKM6hkWDk
         V40gzPyGLXur22gJzIa9wdyESj1y1QN3So9rAOPmqVbbp6g5dbn/ltHad3GPBvOzhDlb
         GDhJv+FgR/xM+SRfxHsxX9M4vFtRt3MLdqFlXHZFcWE9NpkKoEOvmncdpewSypMJTwsJ
         2BxQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532KpHP2JnhKU0NyKqbppL8UAyf2azK+HWlUxy9HnSPNzjy1DQwV
	4Qwdja9W+3mGj6ofqpoJG38=
X-Google-Smtp-Source: ABdhPJxh+9a+eJZ+9XIs6O+DiyrwnIBhCBGVWQAHiWDWdx3edcPbg6+y0XXyMi0iGv6GMzFd2q9YXQ==
X-Received: by 2002:ac8:d01:: with SMTP id q1mr29660436qti.276.1600362368428;
        Thu, 17 Sep 2020 10:06:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:eb82:: with SMTP id x2ls720168qvo.1.gmail; Thu, 17 Sep
 2020 10:06:07 -0700 (PDT)
X-Received: by 2002:ad4:42b3:: with SMTP id e19mr29995450qvr.6.1600362367806;
        Thu, 17 Sep 2020 10:06:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600362367; cv=none;
        d=google.com; s=arc-20160816;
        b=rMCN1Tqv6b3x4+xfd/CnwWUACFJZaRcSFrcFhc6Dk+EUZ41c4t3WVjxIwHHNiMnmxn
         wtg/b++yXCy7jw2IaR6BXFKnLkTpOuU7wIzR/bD4KtoWBEVTK422khnIQCRDtnQ2BM5S
         WflUfRUkA29OTwKV0tAP0l3Wr0M24KZjTl12LBGkMcuPXb25I+HpXkjYclEM2rFEi0es
         B+3HQS5wQrl82kln65twwLhXA8x5SAAlzVWs0g4LOCajmTbmdvDdb1pe2B+dDgvlpHMu
         x11AcoWnI76987NV7yFkXbzPF2S17/zb3h0U6nKz2ENeN4+iUMIK6PC8sk6CDyVcaVbm
         N1rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=QkMt6RKx+NdvmhPjLrxW78zGoWVq8JX7P0x7UdXaBZc=;
        b=dXskdic/HRzONJJNnnRvXJHFoEjp++7od7MP4kaaB3FyGwNaGtCcJ+CDvJDiZCzQK5
         SDiiZVGkQMnIRaTeUjWf8W0bvd+/oXKUzyc1/2rbJWAljfMUCXsswQu9G6KKE5rbMVvQ
         ObLoKB1vIsXOUBenDsZDCAMyTzRwiN9wXJNGJyKV72JZ3pk27tMPrtlXh0Wqx79/kXmN
         MAOB0P/uOOs/w9ZgGs6ucqJX4DxXyrkVDqFRPWqt/mZhUW5Sj8el9VJ8F6cASKTcU0YO
         y7xAgHcKrDydyKjEeaw24DAC+GfBALw23WA7ylWjQZQLADMe8zVCTaT85iRoV+e1paB/
         pO/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h18si24159qkg.3.2020.09.17.10.06.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Sep 2020 10:06:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 49B78214D8;
	Thu, 17 Sep 2020 17:06:04 +0000 (UTC)
Date: Thu, 17 Sep 2020 18:06:01 +0100
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
Subject: Re: [PATCH v2 26/37] arm64: mte: Convert gcr_user into an exclude
 mask
Message-ID: <20200917170601.GO10662@gaia>
References: <cover.1600204505.git.andreyknvl@google.com>
 <dbe7d509102cbbefe0bafb38e9367b5b323bfebd.1600204505.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <dbe7d509102cbbefe0bafb38e9367b5b323bfebd.1600204505.git.andreyknvl@google.com>
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

On Tue, Sep 15, 2020 at 11:16:08PM +0200, Andrey Konovalov wrote:
> From: Vincenzo Frascino <vincenzo.frascino@arm.com>
> 
> The gcr_user mask is a per thread mask that represents the tags that are
> excluded from random generation when the Memory Tagging Extension is
> present and an 'irg' instruction is invoked.
> 
> gcr_user affects the behavior on EL0 only.
> 
> Currently that mask is an include mask and it is controlled by the user
> via prctl() while GCR_EL1 accepts an exclude mask.
> 
> Convert the include mask into an exclude one to make it easier the
> register setting.
> 
> Note: This change will affect gcr_kernel (for EL1) introduced with a
> future patch.
> 
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200917170601.GO10662%40gaia.
