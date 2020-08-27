Return-Path: <kasan-dev+bncBDDL3KWR4EBRBQ45T35AKGQEV32HLCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D8352543FA
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 12:45:25 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id v2sf3201128pjh.3
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 03:45:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598525124; cv=pass;
        d=google.com; s=arc-20160816;
        b=OZ/L2VP4iC06d2ANTygg4jFtQZYDoxr4JFuLB3ndEYEU3gufmFK49dZJqY/4enZuYm
         tDuE9GBO4SAQcHA8E0ZYbtAxonvPTz/4NDIjD6/Bhg4sqtz+phSVH7DATBcPALUfLrMo
         tRK+gtqmcN9u1a0rXxYjm+b+CsUD4XWyr4QW/Z3sIWiBOPu7CmAYVMATrLhvb7s8MoQr
         ZRoajYM0vQZoSiApZwCBQBszrh8fctkbc8iQW8SBLKOaybNLtXJWOZ9cHewUtzt/cBl1
         5g78sIBwdH0Fo7nTm9GxhbZEBZcimyHUylVlDA/YobxSFl94LdkfRZC+ydL64syW6RZL
         sQ5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=lOwnNVBA3qYanzleFAK9b0HFSkL9m0dHy6rAUQn/4ks=;
        b=aLSZF/0bIWDW60QnD6zh3GzW81k+yiAR0hyEzBofboN5akcBc2imoK7qbct3BR19dm
         9If+PA1OXHPlC3n6G2nls+HHcweUCZcSeorv/XP7JS6p5z2ClRvI3fcDzDARRfB+rie3
         MgCfZ2K8h+dzhCARWqUsnhKVYLYwHgSWXZE6RrSMclXi2CEOTAmfmnjRXUn84dyR0gSB
         +EBI96Lzj3bEXN8PbXu+pdaiibym5Z5ek16x6oGtFL9YMkyc9tUNJTUD3yco89DG05bG
         yQozHmdr6bY+twYmrThGegNwazRxFENz/BGz9qxRhkhIQu13+DGMqU74VF4ncCheca0i
         RpnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lOwnNVBA3qYanzleFAK9b0HFSkL9m0dHy6rAUQn/4ks=;
        b=Qdd1vG9pY67StjXYCYyljROoblZiRbm4PQWURxG+p8Mp1RtAa6YH4u3DKfFiGsLQdP
         lccI06M4waq+Le1M4SwfNIS4TfdzmgkbunJYe0srBdHe4BvCZIUisdwsNEn90QyPW4jX
         AQ6v7C6H7X9TE1TVwtaPi11T9NkVmgwSVvdafu/yQM9zSTsOMKjdQwGXXLFlONRk0SlR
         tyrE/r+AE3OJ7FSniP7FFQFM9pLt8R+B7t86c0FWdzoQ5UDPv4/yrd5rEMB9iydZ/vRa
         B+IwihNtFpGQJ9QcNmJchemDYVCTnhZ7hbHNk5O6SuDSzHXqxwqHPgWH67Qbe4I5fg8h
         iEOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lOwnNVBA3qYanzleFAK9b0HFSkL9m0dHy6rAUQn/4ks=;
        b=Eh4y8YK/oN35i0YlHNh0JbnwvPTtROJzj+VOTX3iWLmba1l8mSS3Mb3T4rzoywIFph
         lEsW2BPq0v7W0toJTzRfuFWKN7hVR8BotURN08eBAp+bdvacAcfGOGFhcubIE42C70vw
         KBCyl/3VWPmZAHnhjkaFqQGTguQpBYoC4Q+dwXexJB0A9JAibaw8IB446RDm4rI61DUk
         l6E5T40UXJcSuzZlcRuLeeuoqeoD1pa9MSObmf2X4vanE5uYNfr/bYcGfA8tOR/kpulD
         57j9IS96oXS10ZqK8w5LOx4XKglecdtRe4pU9xU3f1iPaZgcIgD4V4oQBD6gzYRhC+O4
         GfkA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531hpVyvPgq0lZZ+s/EnsN3Qi27upHgKUxRNbfzPYDiFAVJXLvOX
	7uNpGUqSWlDKDaITFPxXVk4=
X-Google-Smtp-Source: ABdhPJyDDtgUxIK9BvwCzMpW8nmNFnzUn2I2rin13BuuP6QuhgJgrtjfM4T02v/So0XV+nQJoYNAwQ==
X-Received: by 2002:a17:902:e901:: with SMTP id k1mr16029189pld.189.1598525123942;
        Thu, 27 Aug 2020 03:45:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:142:: with SMTP id 60ls1028910plb.9.gmail; Thu, 27
 Aug 2020 03:45:23 -0700 (PDT)
X-Received: by 2002:a17:90a:a401:: with SMTP id y1mr10312261pjp.199.1598525123386;
        Thu, 27 Aug 2020 03:45:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598525123; cv=none;
        d=google.com; s=arc-20160816;
        b=sd6zha8GlVH6InM/khannnFDBJNCQXPgI+TxU8dkRfYZwk+s/LwFQLgp8OrEBZzZLX
         EGprUDhWrbSiMwMXkVqbIzAKzE5XXPL1dDKgOdCuiFM8xzlDOKRl35AmGpIuALwdBq0W
         uSJ++YI/MzpR6yhDCA92Pw/EBQU63L2jKxuxPBlvbdK3hIOpSNxgsV4pVRM4E19NIYA8
         WRBZ5aWryW0wNHXzuuZsJb5EcJE/Dt3+w3bYagG9r2Vk7G3s56APYuKm7+B4pqfEa3Zj
         MdxGUqBkdyu8u9Z7fzYNXCkxQDSXu3JpqdElgKnmuW3FP79ZDjZBRsz0zVVCB2mdtsY5
         OaTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=51ec9mDAGx+6O2m2DsvGHOAIpOdETYzu6nMNTaoiAuA=;
        b=tIe9ON1UY3CLuFFI92wz6OR6WWSU7PSVdOgEnJsw7/RFO28GHjEgcNQ8c/2GStKCrY
         Gz+UadaLfRtMSi9eRVt5PuehZlxmrHPDAZkERtFs/t1WSO7aByHYnaV14P9Lz1C2DXiQ
         goUUO24us/ee9NxBUFdRDcD4kISV5KFSKv0jiIid7SxMIORTYUcBGfM9MqVQQyUBwqb/
         9OeeX304CO9f2MGipm3ELvVDCxoYz26b32kS/XfFpAZVqKTRMk84ccn7pR+MoB8c5y7h
         PRswTlhcKS/MXDCb88sQaj0UjhF6Y8SA6BNKs6Fs3wGCT6dVPGkDb+BIPuyn6X2shb4H
         EZKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v17si114025pjy.3.2020.08.27.03.45.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Aug 2020 03:45:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [46.69.195.127])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 7AF46207F7;
	Thu, 27 Aug 2020 10:45:20 +0000 (UTC)
Date: Thu, 27 Aug 2020 11:45:18 +0100
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
Subject: Re: [PATCH 31/35] kasan, arm64: implement HW_TAGS runtime
Message-ID: <20200827104517.GH29264@gaia>
References: <cover.1597425745.git.andreyknvl@google.com>
 <4e86d422f930831666137e06a71dff4a7a16a5cd.1597425745.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4e86d422f930831666137e06a71dff4a7a16a5cd.1597425745.git.andreyknvl@google.com>
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

On Fri, Aug 14, 2020 at 07:27:13PM +0200, Andrey Konovalov wrote:
> diff --git a/mm/kasan/mte.c b/mm/kasan/mte.c
> new file mode 100644
> index 000000000000..43b7d74161e5
> --- /dev/null
> +++ b/mm/kasan/mte.c

Since this is an arm64-specific kasan backend, I wonder whether it makes
more sense to keep it under arch/arm64 (mte-kasan.c).

> diff --git a/mm/kasan/report_mte.c b/mm/kasan/report_mte.c
> new file mode 100644
> index 000000000000..dbbf3aaa8798
> --- /dev/null
> +++ b/mm/kasan/report_mte.c

Same for this one.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200827104517.GH29264%40gaia.
