Return-Path: <kasan-dev+bncBDAZZCVNSYPBBTNOVGNQMGQE4XYW64Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id AB55A62122A
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Nov 2022 14:19:11 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id cj8-20020a056a00298800b0056cee8a0cf8sf7197630pfb.9
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Nov 2022 05:19:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1667913550; cv=pass;
        d=google.com; s=arc-20160816;
        b=oM5cvd2eQbwIKUL6EoEaoy2ByHX3NpWSFgJwmd/CVUdxUh7vhHw4choXYfD8oD1RDT
         fSWn0lS4p9I3u/wCIQzO+o0gJE9OGQcsBdBNCJVWWDVpxz2awWhbbfWABy0ovVGJAfLW
         vqmbQdlFuegnPWVhc/FgMHYasWKh7FhEzwPqn2If76BPCaBfO2Nu+Hi5xyK9AvESahWi
         fmXon2VTlReAr8zikYJ+wCIfBhYXlIynHE5sWdhkaswdJtGFWcHxWqehOlwcEVny+9f1
         GMitRNZk8uk15egagQAlOxhJfXsLrWta1vN/wECvp0SzOoghV9CMoYuvHgmV34cP+4JN
         h9JQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=gEUvGasuErUiL8XnaGDfGgaSh1Hm2Yf8Qo14VTdq8Xw=;
        b=KWNXQFs4XsigWH4Nmcx6kuTegoX1+663soHFFbTEXtz3Wt6ybHn9J78voJ6gpHNvS0
         yzMF/q5w6Ne1vYzaLzm34txwUGjFeVAeLLh/QtlJu3CoJ69VK5mwz0Zsm/B0CvPnBUsr
         4NNXXgzfA/BZynflYD8T/0h6Ch6ppb6RUPPfktfo10HoDHrSix3gAJRNrkN7gQjrDfCp
         44C3AfJ6xr9r1nyqeqJvBiTFymFq0KHFuARlGs+L/lx47d2EYwzPjyODIYjXHSwE3ekW
         fp7axO2teOhjGBtiN3j5C0yVimBS6Pr/Ia2EGcy0cwss4yVQ1xDy7Vv4f1bROongAt3v
         26Iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nwQxPA0g;
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gEUvGasuErUiL8XnaGDfGgaSh1Hm2Yf8Qo14VTdq8Xw=;
        b=Cqug+YkMbLPrvh9Dd8zG0dlu17PjrEz061hR/BdTTnNCK5QBEn08/dVmzCAl7wruir
         CcxpjamVWvOEu58/6N6DPd7i4WjSieRASgg/r5fMUsaxF7zlzROvvQ1NNR8m824axuPs
         F3+uZEQTO/lK0Tub+J6RF/4DsMdMgx0hs3GGhup/OgxoBiuZAgL6Ikd8ecAxSouJ6odT
         Wr5VU+H+gqAun9hJ39zZEzvQVcWHUlPvEwNr9LFhfedeaiZd179TqHzlUVz/lBtsJl/Y
         e3VHzv+VGBwVYx6jbfu3rnK266yykb3IUMe4GBz++YS0QXUyf/DV6Gn2AIMgPoPf9rOI
         vopw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gEUvGasuErUiL8XnaGDfGgaSh1Hm2Yf8Qo14VTdq8Xw=;
        b=FwfMVsekMIBdEGI9y4d6IIYQBtz+IzQVbR+2oTAp48lOQ3U9KtTLtTumD5Dpby4ys5
         WewqmC6HG047hjTR60JppbRbH5yE3RaigpjB2G7L8BH8rKK8ddvr79Fya6XfAZBXNI2H
         iJ5rBsMarAcm0z0ktkdWfQL0jsrgD6Ssrxet428+ig6gGBix1eehJ779SemyQZcbYHmU
         8hg7oWUsRTBvWds3uHDiilBpF4q3VIBFjG5a3IHMGNOEejwETRPmgCOx1/VLUbBXBSFi
         EabfrG7AjxzK+ABhBAbmvR5ckDiJ/jmfOuN24qsPuJKMPetT2jRv9BmNMNnw2GVygZV8
         IlYA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1wa+aQuJvelFSS/KmZ3uNvibE9yXdD3+MadYUnRAcIRWcbpcFV
	1d7lrfvO9NdiVUeRT4yX67U=
X-Google-Smtp-Source: AMsMyM7UhexoL15aQSRyA4kF6bgCGv3G9bA4+cKdnpMxoOs2T/WbYqtjFAvr52q9ED5t558cCPnmyw==
X-Received: by 2002:a65:6ccd:0:b0:439:2033:6ee with SMTP id g13-20020a656ccd000000b00439203306eemr48609428pgw.271.1667913549807;
        Tue, 08 Nov 2022 05:19:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:d107:0:b0:56b:9c05:6aa7 with SMTP id z7-20020a62d107000000b0056b9c056aa7ls3690774pfg.3.-pod-prod-gmail;
 Tue, 08 Nov 2022 05:19:09 -0800 (PST)
X-Received: by 2002:a63:db42:0:b0:45c:9c73:d72e with SMTP id x2-20020a63db42000000b0045c9c73d72emr46423097pgi.181.1667913549086;
        Tue, 08 Nov 2022 05:19:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1667913549; cv=none;
        d=google.com; s=arc-20160816;
        b=GFufVLV8LvBnpJbTIB6NZ3Cj109RkBsPbRVdKMix7PB3sNJNtxhTlGXQW51iLB7SaF
         u650bX0bWAhZvNENGppgUo8mibB3zZbaqEKQClpohM66c01RrFcgS3EkUVi53xCDCBU6
         g0RNO7gcd0emb8o9mRhFSwBvHOvXkTZvV+ETiwuXnUFPOEFmWYFbGzTenIpHbVkMzuXd
         H7s6Y1xK1aX2w7LIPYxBxlkdPg8Ptls15GhLl7H+4xQrecaxCfPWdWN+V3/qQFK7GzPy
         0SdRKhAttJakoNVB/2s2nXbgzzNLnZ74weu42lXagQkkHGPH3ayPEZr9nJ1TGA2RixbH
         DAzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=LdiyojhrAwuHvl7JH2TxTWA3W/mjVE+HNMl5wH3S7bg=;
        b=D+HfrVUrlb8bjXxHqvuXFK/QsW18FaHpqMY2vTuTFYIlh/LnuuBCZJWEcoIejALw97
         uYUKjV/OKP6VsWosfDMnYbgNI0/j9umXqwzW5aaGyT1NeTilZ2YDHC8RD2CWBmbzcXBf
         O0ZEjUJXaNdZ3cr9VedL5trGVDBLBtiUz3PG0V+yA1K8vc9wUD000etUKZY1g6k7Zs/H
         RI0FBXfnRffuau4+S14NP4usUiQJXgtaIGiKHAQpV20/WRv/2wqvh1nl/ekojsJqNiWJ
         ux+zYQ2g8BijwOuiHYPp612ADR/xUx6RV2atuOSuTOJcQ+1wOgMDf2G7BvKROIeYepvI
         5MxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nwQxPA0g;
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id v5-20020aa799c5000000b0056b8f6cd3f8si423109pfi.5.2022.11.08.05.19.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Nov 2022 05:19:09 -0800 (PST)
Received-SPF: pass (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 708286148D;
	Tue,  8 Nov 2022 13:19:08 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C35EBC433C1;
	Tue,  8 Nov 2022 13:19:06 +0000 (UTC)
Date: Tue, 8 Nov 2022 13:19:02 +0000
From: Will Deacon <will@kernel.org>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Catalin Marinas <catalin.marinas@arm.com>
Subject: Re: [PATCH v2] mte: Initialize tag storage to KASAN_TAG_INVALID
Message-ID: <20221108131901.GA22816@willie-the-truck>
References: <20220907110015.11489-1-vincenzo.frascino@arm.com>
 <20221107151929.GB21002@willie-the-truck>
 <e1d857df-7b6b-113f-1bed-2b5274d887c1@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <e1d857df-7b6b-113f-1bed-2b5274d887c1@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=nwQxPA0g;       spf=pass
 (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, Nov 07, 2022 at 04:47:14PM +0000, Vincenzo Frascino wrote:
> Hi Will,
> 
> On 11/7/22 15:19, Will Deacon wrote:
> > On Wed, Sep 07, 2022 at 12:00:15PM +0100, Vincenzo Frascino wrote:
> >> When the kernel is entered on aarch64, the MTE allocation tags are in an
> >> UNKNOWN state.
> >>
> >> With MTE enabled, the tags are initialized:
> >>  - When a page is allocated and the user maps it with PROT_MTE.
> >>  - On allocation, with in-kernel MTE enabled (HW_TAGS KASAN).
> >>
> >> If the tag pool is zeroed by the hardware at reset, it makes it
> >> difficult to track potential places where the initialization of the
> >> tags was missed.
> >>
> >> This can be observed under QEMU for aarch64, which initializes the MTE
> >> allocation tags to zero.
> >>
> >> Initialize to tag storage to KASAN_TAG_INVALID to catch potential
> >> places where the initialization of the tags was missed.
> >>
> >> This is done introducing a new kernel command line parameter
> >> "mte.tags_init" that enables the debug option.
> >>
> >> Note: The proposed solution should be considered a debug option because
> >> it might have performance impact on large machines at boot.
> >>
> >> Cc: Catalin Marinas <catalin.marinas@arm.com>
> >> Cc: Will Deacon <will@kernel.org>
> >> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> >> ---
> >>  arch/arm64/kernel/mte.c | 47 +++++++++++++++++++++++++++++++++++++++++
> >>  1 file changed, 47 insertions(+)
> > 
> > I don't really see the point in this change -- who is going to use this
> > option?
> > 
> 
> I think this option can be useful to someone who is trying to debug a problem
> that is related to a missed tag initialization and it is doing it on QEMU.
> 
> QEMU by default would mask this class of problems because it initializes to zero
> the tags at "reset" (which is a valid UNKNOWN STATE according to the architecture).
> 
> I noticed this behavior because I was trying to debug a similar issue which I
> was able to reproduce only on FVP.
> 
> Said that, I originally posted this patch as RFC back in April this year to find
> out if someone else would find it useful, in fact my idea was to keep it locally.
> 
> Please let me know what do you want to do.

I'd prefer to leave the code as-is until we have a concrete ask for this
feature.

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221108131901.GA22816%40willie-the-truck.
