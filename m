Return-Path: <kasan-dev+bncBDDL3KWR4EBRB6MBWT6QKGQETIWVKXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B6DB2B01FB
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 10:31:41 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id u14sf3102970plq.5
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 01:31:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605173497; cv=pass;
        d=google.com; s=arc-20160816;
        b=zdPtkRVT16gxW8ulV5edkPRm66q+yLkN/ZywLRzwh/oOHcW+24WzGPQNlRDuH+RQTe
         s3jvOv1l/oD5luPA67IyaxRB99iwLXAoF/PE2lQZ8RiHqkIyD89l8p4XIIH02LLM9YOE
         q8Wi6lMB1+JGijEAJyeejrLT/XnCb811cSFMGPqenucce9fUaDS+ZmbzM+EOwJLBsa9I
         S7pGpJunZtQJOVKWRkaA7BK2kMpyZ0eZ4gBs2pXi/acxgC02vYECgbClMnIW7d6CcfXT
         88PHV2HmK1Kbv9JUnT42rI26qG5roS70UU04XAjOh+8cqo95IGQHHAE4aMeX4aIMndp7
         PGtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=3eNYWZ3+Tc6p2/OxChaJqsrzY0lS6z28KEddTeuUOb0=;
        b=KD01IgqRfuEJza0+m0tX+KPUZZoXcDEDnUn2PmueWs44YZ7ntbjU3vBA4FeXKMV/zz
         y1mUqewhcqhoX3qPVFsY0LUj4DHfnAsjkGZx2X+REtALZI6phgqm3HtmccWu3EEgvJPB
         jqXjv8sNhrzVWJaBcJ8lOI2Uo9OU3S/RynqDrrYzlflC82+vrAqD/p7OU49UE6mWXY4D
         wY1Cc9zYSBCb32of6aB17Eq9cHhmT5C9U2JlSaJ58nEFnt9v6g2foYir7KuIi1zMWU54
         qVfipjCZp3NCbbTr87rSPEmKflJSQKLLZtX/0qspHedYtr8Ph175jxKDF8M827FYgVAC
         EFmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3eNYWZ3+Tc6p2/OxChaJqsrzY0lS6z28KEddTeuUOb0=;
        b=thj4yCkLtzCo70RY8v/cGsWMd0tqyNh+L1SnnmtvRH+aIoU/lbVJ8sdLmn3w2kgZSX
         +KnsYYHAqQBmkzfKiai4mZQ8md1APanrYXWA6j3BN8VqNy/5aDx+rSgDzhH8VsL6bBwq
         bKih5zlmhfCOMGEJ5GljLcfsi1G5X5Wm56iTUpn56o73Jpm4odgA2s9ZOcyOnTdYfXai
         I1veOxeDm24uEV9PfhVHKHoGh2aX/WnTSeIMBdSxKcMjavFQe1TAceWqmXE2OT/dTt0H
         uOPhOy+PBzyjMwjmowGTUsq2eLl0Px1t2IDfj1dtaxz3FiTKv/3orAsH5I1zruunV5bN
         6znQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3eNYWZ3+Tc6p2/OxChaJqsrzY0lS6z28KEddTeuUOb0=;
        b=CsSdOJuIkvP3hlLgJ59Tvob/uhggmCPAF8Scpk2kGkFPzcckc0Dk4X5dJi+RCnLbJp
         uCSs5zgu0ZScOLk7faJS7L72c+Jmle279W6d2o0kL42xFpN6Izav9/GB5p5tP8IQFlMG
         d+7Uvps7GL3VsNhV7NTspoYqvDKob0TUiHyDsDYO2pR8+r2Ns14mc5xXkyLfud1Vs30k
         VMen62Kz6Z0FyHYk79DonP/dsGGU2VfZJlPHMsL+pLe3wOZ1ayV2+X5EIUURo/sdZLfy
         gGwtOxqPQqIM3JwxlEHD0UJ2qrrUESH1bzWVbdWlwk1CiZmxGahR0SCWCbzHwjItwLNR
         4oMg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530QBf4pEnaPjvzRo5g5BovZ9k+5LAWStAA9cgp6sRw6tQ1zjV7+
	uhHtK6Yy0lZqe7nyRhMmuoY=
X-Google-Smtp-Source: ABdhPJxuf4xA457qcdP2fIfiDcCNyRjBKf3ZzsytUEeEEz+FHsjoaGiYrymDlKJO0F1ulxFG6TqBjw==
X-Received: by 2002:a63:7e09:: with SMTP id z9mr25307446pgc.150.1605173497547;
        Thu, 12 Nov 2020 01:31:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7488:: with SMTP id h8ls1214694pll.11.gmail; Thu, 12
 Nov 2020 01:31:37 -0800 (PST)
X-Received: by 2002:a17:90b:f10:: with SMTP id br16mr8347078pjb.60.1605173496966;
        Thu, 12 Nov 2020 01:31:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605173496; cv=none;
        d=google.com; s=arc-20160816;
        b=dnrSjDrF3/o1dqzUzXwK/ZTQK74SxAAQf8SvGZRFj6VS9/X4G08FVmROm8qTEatgEu
         kg8ocit4PvkrYcBFqhx5v3GhY6HbcQjXCpWEDYpX720Yw6NOyu0qdu39EMkuawRSLWLf
         whHdRh9XLTGOvX7pHls3yMKXBs6Gdrmd3pYnkvMj8cDkufDSFfb6NvsMSSNoJzZbAtAf
         SDWa3yzsj1yT92sFdVryGvOnQ5TSgwbhpBkRwUCLh/LDsK+n7dFpUct6ov4K0rcB3BqP
         nRc3lgqFKVgQ9VsY3NAJaQzM6aXSL29EBXQBG3e4YO8IemUI1rnsaAW1T6a81VhiyrgF
         +xbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=Zk7Dh7iiJgUKyxPu0yt6ZPa9BrHZxL5pJw+8Q/BhG50=;
        b=wFU7hMjq+fo0JYpId+2MoFENRn/hquxTkui31T+xcmXKoVYtxF64ladXRhg9RFYVJU
         xFuSe01epug9+HQlUjPTFHHKgIKEx2dn/08IYcXTJU517mWXlGD/SodhNkXpAI4975Lf
         OJxVHh70o8+QscBz5dtqkS8clxphdlXh2/uTABogXhJZYHIxnBkHp4p9tDymKAAidPoV
         qwR6Y0jAJqWbq9WTPkIMiZZgP/ODM/2AvlGwRVRM8aj8vkEaBJbNl0aPtC6J/v+PYy+6
         B3/Zlb2dom5TKTTKb61nrg4fcrdIWnMxUVAfI+aYmbx0As77FCRQ/i+lJGciSWj3l/tw
         CCpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e19si194363pgv.4.2020.11.12.01.31.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 12 Nov 2020 01:31:36 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [2.26.170.190])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id D12A1207DE;
	Thu, 12 Nov 2020 09:31:33 +0000 (UTC)
Date: Thu, 12 Nov 2020 09:31:31 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v9 28/44] arm64: mte: Reset the page tag in page->flags
Message-ID: <20201112093130.GD29613@gaia>
References: <cover.1605046192.git.andreyknvl@google.com>
 <4a7819f8942922451e8075d7003f7df357919dfc.1605046192.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4a7819f8942922451e8075d7003f7df357919dfc.1605046192.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Nov 10, 2020 at 11:10:25PM +0100, Andrey Konovalov wrote:
> diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
> index 70a71f38b6a9..f0efa4847e2f 100644
> --- a/arch/arm64/mm/copypage.c
> +++ b/arch/arm64/mm/copypage.c
> @@ -23,6 +23,7 @@ void copy_highpage(struct page *to, struct page *from)
>  
>  	if (system_supports_mte() && test_bit(PG_mte_tagged, &from->flags)) {
>  		set_bit(PG_mte_tagged, &to->flags);
> +		page_kasan_tag_reset(to);
>  		mte_copy_page_tags(kto, kfrom);

Any reason why this doesn't have an smp_wmb() between resetting the tags
and copying them into kto?

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201112093130.GD29613%40gaia.
