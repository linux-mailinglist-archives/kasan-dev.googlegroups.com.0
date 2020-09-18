Return-Path: <kasan-dev+bncBDDL3KWR4EBRBSMASL5QKGQEBHPI4DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id BDB7726F96D
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 11:39:22 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id i3sf2609978pjs.6
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 02:39:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600421961; cv=pass;
        d=google.com; s=arc-20160816;
        b=cJStFp5Fo/mBw+t//bQmY29Nv+tHcvoXX0j8CsqffLvy/e9XyBr9JB6jzh1PkEAORL
         nfpRnXRg/ISp6OyszK+8XSOm8r3TcoSXk5zipSh8S3FIRx8+eIIsAlMhFG4vaaegjhxP
         PYKBZICIMoBnDA2+XgOq8PLCoNmPJpNT0Z20fvWILvBOKxHqmqxKuumKNhhQC6cTWA2L
         w4xw1Ya21QFppaDpWEP3rddKOHJ6V5t8Bsgrac4qNhkSMMn67H5M20VizgLNLIRegR2o
         LoBdMN9Hm5WgHnYGQkMnOe3uyEWdaeglY5XuGhG+Jya92aaJsNDlr5y2dpzvCTEa2gD1
         57MA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=dpgSJUIry2yHttXhsZkCtPfezRncV2sZ2MgaFy+oCYs=;
        b=vQaHcA9iXipewKreOIOILdPQx+0t62L7fp3o2dR3bLvCXBEZV77upu3/hLIDpCquvh
         ZEKNsnabn0K6f3iNT7vh6DR3xrVdQAHRVdmrAq0CPxsxHDNiYZl1OJMayupVgfUD74O6
         VLY1yUC+PDobGje+P2Jf7X9p7SozHF6uUYEf5IckZS2vM4GnPAgw9mrs2szdDQnk6fHu
         BoN5TlZqkYigViOTA39Qn3P+7fGtzjyJw1DCEVr/Joicrghlhve8UOZVcKcb/l0N+g2S
         dq5S8uglK2d9N0i368fbpKfgyiui0XhnBGOlUZCRBZ1w66TtFvnHQ9hxLXOOPucQqbs6
         KW0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dpgSJUIry2yHttXhsZkCtPfezRncV2sZ2MgaFy+oCYs=;
        b=cEywP9pqFR1/l0l3EUfDDOdu7hPNXii3YrVoCdDOroINaxhrr2AcerYAQe147vhhw1
         T//FbeDYtxZv7PC8XefnyORwARpKpks4WUW5PUBN0JKJPNdFM5nZi4sLcEYdwFBe0XvB
         1AMp/IH7Ml+x6Dbkhix1HUf2H2LJIb2XXnOyPbnd7YxfOqUFMl6eCmy7c55gsqaqWPyH
         XpQQwyCUB4Dsh2Q1GrlbjuYS9EPR3F/B6capn6gqfP+XWuxlctM/ZuPQxBjkZwblDOKq
         CVFh2P77dR5TfCBCoqZ2tphFOqlShxBstnaANxOVL9ZjL6iyakGJqaKdc0j16vmCL7mg
         XDOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dpgSJUIry2yHttXhsZkCtPfezRncV2sZ2MgaFy+oCYs=;
        b=DNYBFKXpncYRvYYpkK5B5PSie+jnwCN04sYlYraEn25Zn2+7OY5njzlxcAXZ1MwW2d
         xLvV88STcqpJXdS69Y2CD6fAHHYVq1yXe/stqjFGaQ7p0jstUppW56ACZEPO5AbpWGb1
         dogP2fPybXtCdCpK6xkJ/W9aaHi6HmZve4oy0y6roFrw9N0NYEZCLevEWiMIe2+9yMUI
         B1jEsa63fHGV+qLQ+8rwFAapsXNk7jA+bO73eafnn2abzJe2POdWTU/0MayKWYB05uQc
         J2k85qA0Mz/gDd451U7tQAemP4eHEln7JC+gpZeBcQ50R25Dw1bWmATCjyGq/EBy7u1c
         4Q3A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531MdDI1FnLZ80VERGEKzOcEnk74UO9dwO+Rj5U8pkMRlUjib/cM
	B+AMyMEDODE05083c3ALNTs=
X-Google-Smtp-Source: ABdhPJwGnUgURdEye7/dpXPjzIsIMCYWwRwHXXfPMbXg9ooIAMBOjm5mUDEzXtYwe91LmhTYsK2evg==
X-Received: by 2002:a63:4c49:: with SMTP id m9mr9431154pgl.391.1600421961347;
        Fri, 18 Sep 2020 02:39:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7449:: with SMTP id e9ls2513927plt.0.gmail; Fri, 18
 Sep 2020 02:39:20 -0700 (PDT)
X-Received: by 2002:a17:902:c20a:b029:d1:e598:400d with SMTP id 10-20020a170902c20ab02900d1e598400dmr14728236pll.71.1600421960488;
        Fri, 18 Sep 2020 02:39:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600421960; cv=none;
        d=google.com; s=arc-20160816;
        b=himoKdEh1QEYQXwWerbftSsgwsHVyButChsPmWGV47YCtivrZJx7e09l8EdtPzBdaC
         0LaPzFilMYpAdNXrXmbtOINy/e+0Oc8Flv2VrVjjQnF4yJLzQDf6sg7JEx+RyQgtT2Bu
         8kYn4916zBidrDzRpu/G72fvU125Q9fDHuqCHRvxGmDkmFCSbrru1JQPewkzeUEi2x4s
         TdMV8q0PwmzsXUshO8vopRIrTFE+WpRi1uMO0vLcQv032X5CZPRfgT9a+CLMdxAzRy+w
         uDUvAoNQr8Qe0WZ2VKkFAJWtNfN5MTo37FhdaKiiy9jA0splC/04BreInBJedrUHsEul
         hQvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=4pEO7MgcNIyRFQSWOBj4xnFTdORNoxK0titVn0nND7E=;
        b=T3C+UKK/RSSxiZ/y+rGGpx9FSbMrZYsmXBglBTTBnVSFqWMgBtgpXCsnrcCdmTIuah
         ayqDTaiJN/Pw3Re/M0BYYD+mVCcTb4pZAyXGJx/yH0LofVh5DbPqxQH2Rbn9PeCn5LTv
         3FnfpAQ456+uR7Uz+xsi43sktqCJxxikxizrHKAbZPPZOx2c03nt4lqg1TINyo/Aq/E6
         Vk2311iwRR8uPQjunFPyUPt/gUZ3Wgu9uWfzVnXUfw68wXgeIC5Tu+ehpgoPrx0s/NgD
         pixIrDJq2J6xub7ZJOKL7Lk3RZiWVuojxGbV2713OQMucsBRW3ruTppPMl+Fsp1cxeXI
         N7XQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 17si50025plg.2.2020.09.18.02.39.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 18 Sep 2020 02:39:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 5ED6F21D20;
	Fri, 18 Sep 2020 09:39:17 +0000 (UTC)
Date: Fri, 18 Sep 2020 10:39:14 +0100
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
Subject: Re: [PATCH v2 27/37] arm64: mte: Switch GCR_EL1 in kernel entry and
 exit
Message-ID: <20200918093914.GC6335@gaia>
References: <cover.1600204505.git.andreyknvl@google.com>
 <c801517c8c6c0b14ac2f5d9e189ff86fdbf1d495.1600204505.git.andreyknvl@google.com>
 <20200917165221.GF10662@gaia>
 <c7cb0642-8e20-b478-96bf-87807a29fc71@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <c7cb0642-8e20-b478-96bf-87807a29fc71@arm.com>
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

On Thu, Sep 17, 2020 at 07:47:59PM +0100, Vincenzo Frascino wrote:
> On 9/17/20 5:52 PM, Catalin Marinas wrote:
> >> +void mte_init_tags(u64 max_tag)
> >> +{
> >> +	u64 incl = GENMASK(max_tag & MTE_TAG_MAX, 0);
> >> +
> >> +	gcr_kernel_excl = ~incl & SYS_GCR_EL1_EXCL_MASK;
> >> +}
> > Do we need to set the actual GCR_EL1 register here? We may not get an
> > exception by the time KASAN starts using it.
> 
> It is ok not setting it here because to get exceptions cpuframework mte enable
> needs to be executed first. In that context we set even the register.

OK, that should do for now. If we ever add stack tagging, we'd have to
rethink the GCR_EL1 initialisation.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200918093914.GC6335%40gaia.
