Return-Path: <kasan-dev+bncBDDL3KWR4EBRBIWWVWKQMGQEIQWEFGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id BC49454E8B9
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jun 2022 19:40:51 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-f313416010sf1331535fac.2
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jun 2022 10:40:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655401250; cv=pass;
        d=google.com; s=arc-20160816;
        b=kQSLmdI75Mx1t5gJyhFgpuZR4mTXuAIqxMRn+BdqrzdfFCkvi9Gw2jMOkPo7PaoDuQ
         tdTfxNpD6NSlVKl1o+WmEi132voLI44ALWPb8oRhKbbVilyzlJ4B9+4QyAq7IG9vGo80
         xnXu84kdl89AxP/7idBcQDkbKpLomOXZgc0O0n6LdPW5Hbw6e+e0MVQ0BCEh9XYPwmDU
         qcdnv2CcC2PnzwblftSIeif9iQOATDjJbaLL7Ml2LTIy95KJGJJfssc3xk5TZzalDrvz
         JkS4QumGmix/X7SGaadcQi9HMfxT0rdORIDRZcxpXHMuxZbopjxcLQdqlEZa1EOlWYjW
         iLpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=IMGcm67iuUOntWJGShtaKZKu9cVApWq7dRTxr8PxGZk=;
        b=P1NmPBz7AJDUF599avm19r3NPWK6iRazIZjfDdBswwiCj/tgJvYlq/rVNU3Mdf1r9p
         oMefk3Qw/YDdb0qXAazyDA8DI7+smJ4sJKMmI9MMmCUsSMEM19peGiAsNJqcwxDS1Qt0
         6XV4TEkWwgpb8tJVFtQYDu58gqh7fGML/lCCI3eRd50Vl/tZliPIwB5oLNisRJUNM9z2
         jG9jV0VbHq/PJ5hrr3x1WAF5KGjdwf8md3e+e3H4ogimtfVyxiKLXCXQajCKx97N0F/A
         Q3s4YPnMTbyaOiK7sfnByn6TCmFMIwUZ8cF7wn0jLImf/x8dybuyyn62cRlOTz8UR6Q+
         6KpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IMGcm67iuUOntWJGShtaKZKu9cVApWq7dRTxr8PxGZk=;
        b=KVTqqLbxYnMdV7z2g07yH5chNk1dv0+YfF+90S77fofhHsLW5D9cMwWjhJAMeYdhsa
         nM80aNSpkYWxJCTXd3i4D3FEvaeWCFHqSqvSfKMd8kAhdlvrK1jPz+Vq/8AWcezk2bDm
         DWj6PyH67d5e3FXc1uT5l+vyJfBp8l5sCX7+vr1ME0UIorQuySUtO3MkN+t7JI7RXhIU
         ip/twBLkxnzJvxC7g0ZMMvqto9G0iM56Vw7ceY3Q7wzkF2/802/w/sdHZAuZyYognpGP
         A8Ae2lnYcDtcnH0ZOown5f8sWdRFIVp+H+nXsZHYtFiwsKsw7ATrVnmrTvSaGKcUo2Co
         cz+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=IMGcm67iuUOntWJGShtaKZKu9cVApWq7dRTxr8PxGZk=;
        b=UeFE1RqdOQ10DtUoMJxqFsYy8yA8bdNVAGuwqvB8laCBwMQyMjxmsWzKCELtHxGjrM
         aQJh4uHKFilungARhSmlUQUg8ze/eYYf4YCBWbj9BJ0a9cARqOrCX4MIMxiNChOAdaWv
         Z8KScDUXHTd2TQjfGDvWvIq6W1NgV0WAXy2LJMWTynMXleq1DUbfcXizd/DNNZ82xehp
         tqPufouDYLBbZqrfZRO3V/7Ayh16dQKXhLcMSP9SG4FMwlQQQZvfUDUcjF50gt521uEn
         aGp6fxEAGxrp6pzJ4R0+MCDpdJi51Leur0uHWOvVRiOqnsQtBq6YxzJdm7j3PP+XrERr
         HN3w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora91H5CazQQdZbfCzRhSkTQnQyoTtp4XG8myDQnGBDrQ43Q0410+
	HuDNG3FsG399uzMQ7avdhQ8=
X-Google-Smtp-Source: AGRyM1uX0F739mnzU9YhwYlSdHqhf6Wu5IP2ZQ2b3MKOE97Fah0tB1by0B/Exdyac19RQn85yba6vA==
X-Received: by 2002:a9d:3e06:0:b0:60b:f617:ff98 with SMTP id a6-20020a9d3e06000000b0060bf617ff98mr2456982otd.3.1655401250178;
        Thu, 16 Jun 2022 10:40:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:650:0:b0:60b:e780:9021 with SMTP id 74-20020a9d0650000000b0060be7809021ls463680otn.3.gmail;
 Thu, 16 Jun 2022 10:40:49 -0700 (PDT)
X-Received: by 2002:a9d:f07:0:b0:60c:645:299b with SMTP id 7-20020a9d0f07000000b0060c0645299bmr2506443ott.6.1655401249760;
        Thu, 16 Jun 2022 10:40:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655401249; cv=none;
        d=google.com; s=arc-20160816;
        b=AcHDqJ+EFu61C2JtGSiqeCLI4NAoxPV1szIdW3VJyj/H300voKJUe0qU3gfQl0FnNZ
         BcZJPCudHEcGeE5AVICdb21qzHMFWSlPNb7mNK4Txl73ZK6eFHFpNDQS4a64Gs7CjOxA
         ZxML28uiBQ4ZAe/0h1TMVMEmjCiSPYmIOnP21l7AoI3AiGzpYkEpKPuheFg0DWtrQR4z
         XplNjINNH80o4+vKEjfKebCHIAbYEMsSqD+PvwyH+DAA18f0GSgvPOZf8StTvcaFN90c
         e3efKZznqzJzFymlobFDeYJ0GvVg7Z5kx/sit59KZJTJGKYlIirwSxxQA3VOKImV7vY6
         vuBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=YmM7gFlHCeAyh8Bm+tJ46gEZhXOhjtfC7KWDV6SGV7k=;
        b=zwdFCZQvhJRN/NqqGEFBT3e1iaATbaOeESqP8oKJhc6NgSGF4HNHqGf+O+bOeSu0q9
         prSc8SbOJpbjJESxFu9Ub/oswhTeNN43OGX9v+FBuKU2Ub9Ik6PUkfZP3YjxpCtYg3uG
         7v9BJ+TEOu9pYIASbE9AMs/ZPur0KktljRQRewrx6w8PbuLUxzHAb1vXRxyd7gwTbkPN
         2iJZ6hdWDl6P3LuhFSVnpSJ7oqPmJC3mzvK7npLVgl4/dDJrZ/ASrvoiCAVnA4L52HJo
         nIQGetZ8Vo2HxAfS+RaujVK6OtUPIr2lkI4Nvlbp3hdd90wa9CBx+6Xf405wc95Geuqx
         xhvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id w8-20020a056808140800b003222fdff9aesi133510oiv.0.2022.06.16.10.40.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Jun 2022 10:40:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id 9A008CE2644;
	Thu, 16 Jun 2022 17:40:47 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6DC5AC34114;
	Thu, 16 Jun 2022 17:40:44 +0000 (UTC)
Date: Thu, 16 Jun 2022 18:40:40 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Will Deacon <will@kernel.org>, Peter Collingbourne <pcc@google.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH v2 2/4] mm: kasan: Skip unpoisoning of user pages
Message-ID: <YqtrGLhheCpkBI09@arm.com>
References: <20220610152141.2148929-1-catalin.marinas@arm.com>
 <20220610152141.2148929-3-catalin.marinas@arm.com>
 <75aa779d-785f-6515-51cd-654e8c5d18f5@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <75aa779d-785f-6515-51cd-654e8c5d18f5@arm.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 2604:1380:40e1:4800::1
 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail
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

On Thu, Jun 16, 2022 at 09:42:10AM +0100, Vincenzo Frascino wrote:
> On 6/10/22 16:21, Catalin Marinas wrote:
> > diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> > index e008a3df0485..f6ed240870bc 100644
> > --- a/mm/page_alloc.c
> > +++ b/mm/page_alloc.c
> > @@ -2397,6 +2397,7 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
> >  	bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags) &&
> >  			!should_skip_init(gfp_flags);
> >  	bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
> > +	int i;
> >  
> 
> Nit: Since "i" is not used outside of the for loop context we could use the
> contract form "for (int i = 0; ..." which is allowed by C11.

Oh yeah, Linux moved to C11 in 5.18. But it looks better to be
consistent with the other for loop in this file.

> Reviewed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Thanks.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YqtrGLhheCpkBI09%40arm.com.
