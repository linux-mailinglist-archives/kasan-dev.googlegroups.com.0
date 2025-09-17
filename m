Return-Path: <kasan-dev+bncBDG6PF6SSYDRBE62VLDAMGQEA4KDH3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EACBB7E2F1
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 14:44:05 +0200 (CEST)
Received: by mail-ej1-x63d.google.com with SMTP id a640c23a62f3a-b0ccfdab405sf527779366b.2
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 05:44:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758113045; cv=pass;
        d=google.com; s=arc-20240605;
        b=XRuVBBYuVG78qiVBfNG2/9qersE6lqSkQK8TrFh5idGQl+scQI16GZLFSes/NPDfd4
         HkjTmuzT+l79HY4+/sjKMzKZOT+AfyPUpIekzsKMKPMoqsnYQhdIAbg0pCeB0vrE76I2
         aoMOsF4rx/WAP0MR+GvXEDHLfppGwVWOCAvTHIJJ5sPdv7ACn2laQxS78Qy1ig+Keq8f
         sD3QpWD8faDfPMdCn2t4V168tF3e94DNMRI9iY5TE48tKr8wb1srFtOVn/cwSgLDwi0V
         vxr1vbfSu9n8an0ginlcTgZSFw7pdeFMW1QvxWWPNorgXSvTuT0hrlxR9UUBk29kiWx0
         xV9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-filter:sender:dkim-signature;
        bh=cnPRn9AHdoI5bnNiAVZ0yrkamA052Gm8OhlDErLhUpo=;
        fh=JZGY4IF20t9SPTXkBMgWtMJlLTztOH0ysMo4opXM0e8=;
        b=XZN89v0AjFgxL2fa21e3Lp1t3ox3xNNq5f2sGErMuVJ9PupUuSBeAWL0y06o6uo5i7
         dLu3x8jGhJZixdfcMb0T2sMIxa88c5nq4i/NPPwPo8wH8BctR9XLsxslKApFn74bFP2X
         zHmDtedsWRtQO3A8K38tq9owkJtZJyFPjIvhLBhiuWcV3bdi0VKSwmKC5UgK1sUdzzUd
         vvHD8VULI8B4G4iQWVy7Z9JnQK1nxSX2SRopUNTWk5ACjA5Jz1axsRmI2ZGvqG14lcmn
         Zg0I+XwLMTUkY1o6Jefp99ObbuFJcd7QIe0wvHoiiet3Q1KPc78mMWq97/Hz1fyvA+84
         +x7g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=iMf+NB2v;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758113045; x=1758717845; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:in-reply-to:from:content-language:cc
         :to:subject:user-agent:mime-version:date:message-id:dkim-filter
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=cnPRn9AHdoI5bnNiAVZ0yrkamA052Gm8OhlDErLhUpo=;
        b=Us4J+cRJPLaNXONLDMktK3dj/rprg1GX2iAjxF//9hs00Te9l6xn5QYihrjldDtI9k
         ZAF6QIXXwFCgCXE5Bke6m6OrZEPDH04HvvAk5YoEBgmaloC3Wdcaw3ncYcff6mvXLH9y
         1w9a/X88Zo4PpXBbcbiLmhviXPTckJXKt67VUBf2pDzgSEwpbycL2HW49yqmyzoZoD/F
         kYaSQsAwtynRocji8NL7jesCyUmuLlCzS3dJq8foegxwMCzJzTA9uMsxcUSvxdy0hIm/
         1kkwn7N0B2BgcKlkgsMRwBPAVKbevDpzj37x8yB9S5woBNUV4pIq9j8oJy9lEahKpWF0
         KkmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758113045; x=1758717845;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :in-reply-to:from:content-language:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-filter:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cnPRn9AHdoI5bnNiAVZ0yrkamA052Gm8OhlDErLhUpo=;
        b=VYJS3f8hp1TL0e4WZEZInVIt8+S6D/1pN4SGCdxpvnOHQBW94wpBcPL87ohDy9i723
         9vNH2pV5BPf/cHVMgELaVyP9O1QrQ6fk2ZSha4SR0cgWhHtY8Ii21uXnUE9mSi0FBxBx
         TffHZZrgj4nylfhgh6WNjmKRN8ua24mT644au5ckTopGNC8i1Un9w2di9pa7DO4NuD4N
         8jn8qPYsO4PKbqbA9M1IPF5ARrJ2Vkyz2F3XB8dsk3ObBf70S0X6dYo0fQ5H/knVrH4O
         iWQyjWhwuS8ktiCrxxmOa38L+zCD3RO4GDUgjPhpu2+h0d9ZpTj23H4YEW7Ko4xVYk3O
         130Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVRnSh2LlhSn22iVx1HCc9cIH64pem65gFZTFFran8rTr8AvsX6o3rX7XtZOLRK7sKWTOdgDg==@lfdr.de
X-Gm-Message-State: AOJu0YzmX8tDD8QjHsVOOsn/ImJXop6sOkzh7/K7JHXYfuOTqK0y5+Ki
	VQFzTdKgyfgz1ZcKzjkS7mxhulOIn9sweHjgUD6LzSpy8EgABU5It2Ow
X-Google-Smtp-Source: AGHT+IGgVyr08FCs+C7fWidSFkeAdzKMu68P0SRDBq4mfCB1wQVM5y/cZJiM64kKHM0YB5Xs7kxV3g==
X-Received: by 2002:a05:6402:5210:b0:62f:3721:fc8c with SMTP id 4fb4d7f45d1cf-62f846a13f7mr1915890a12.37.1758113044542;
        Wed, 17 Sep 2025 05:44:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4mX8SYdFdYTyJzqPeNWtnwg3litttSHpWFXG/BKIrWEQ==
Received: by 2002:a05:6402:46cd:b0:62f:908e:11c9 with SMTP id
 4fb4d7f45d1cf-62f908e153bls581817a12.0.-pod-prod-04-eu; Wed, 17 Sep 2025
 05:44:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUHc+vA8tiQTYVxGU0NGrSXTwWMPapZ3eibWZqUd5zgXdWu0dV7H0/HeVynC76Re1pOLsztd/5+HJE=@googlegroups.com
X-Received: by 2002:a05:6402:42ce:b0:62f:345e:45df with SMTP id 4fb4d7f45d1cf-62f84213d35mr2321436a12.1.1758113041688;
        Wed, 17 Sep 2025 05:44:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758113041; cv=none;
        d=google.com; s=arc-20240605;
        b=I01oXYGZjW6hCaADbyXFE+3kwUtPQIH4GxlTWXlpaC2nilg+U/PGhHsAXHE1GszK0W
         axItF4PzkMEv1J1zMkIroNgUhIOD4+VwdbHeN6fIYnansJOZDtc4u7KtpjdjCclWT7YO
         j8+LlMZcxu0frfRRVBXIPIprNY615PAx+r2iTE2chI4eLEs0pValUA2ZDLPPWXwpbgPX
         ObaVqulrggH/M/kudJDcxOSxgvsI7D1ru6Nm1AdEYeL+jyC5nWSIa7VXrPRM1Y74+SgI
         mqjRGfM+cqsnkMK7wuEMcu8pZUqUTaRxY9BtvPRjB6rRChskYNXY3XoyWPJLfKPuH0iW
         Kqpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:content-transfer-encoding:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-filter;
        bh=a8nzCPWTXAyt6hRaDfVNErU8D7gGuDgm7hcWw0PWtq0=;
        fh=RlfmiF+DSZmJWKH6m4T7kBszGE1MO7lw08E22m2jO4I=;
        b=NsO/pkDO87alxXAUPT6q5fcBmynOouelNbYTtNHa4O963My1Yitjj3Chw0ljrCyETX
         CVHg36GosD0KhFpbqx6DhUCjpPlG7Xw7srboBVssA1Vzq8tfuc/nXseo5mKEdrPcEAzI
         a7HD9arbgpbx9lnBe83jIk+UxnxTyeK21Myk1NFZp2swsSORRrABpv59A/7JJ0MG5Ecq
         sTbgsztTNf6M77oYhMQ+SZm8Z0h1kDkQuxs59i0cCm+Aucy8JFlAhTbVu97S0A3Mbqiw
         zdtAjpmxlB0nnEskva6dV4GZ6jlnHwNNglU7o3cgOVBWpKgCMNz83j3xouiQKn5QCoQJ
         B5NQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=iMf+NB2v;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout1.w1.samsung.com (mailout1.w1.samsung.com. [210.118.77.11])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-62ed9fcbb47si372095a12.0.2025.09.17.05.44.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Sep 2025 05:44:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) client-ip=210.118.77.11;
Received: from eucas1p2.samsung.com (unknown [182.198.249.207])
	by mailout1.w1.samsung.com (KnoxPortal) with ESMTP id 20250917124401euoutp0102bfa7885bbc5d17da0d94798de4adf9~mEn8Hqyhd1720317203euoutp01k
	for <kasan-dev@googlegroups.com>; Wed, 17 Sep 2025 12:44:01 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout1.w1.samsung.com 20250917124401euoutp0102bfa7885bbc5d17da0d94798de4adf9~mEn8Hqyhd1720317203euoutp01k
Received: from eusmtip1.samsung.com (unknown [203.254.199.221]) by
	eucas1p1.samsung.com (KnoxPortal) with ESMTPA id
	20250917124400eucas1p1d013715516684550c2ccc2d97ca691a5~mEn7wddWR1561815618eucas1p1e;
	Wed, 17 Sep 2025 12:44:00 +0000 (GMT)
Received: from [106.210.134.192] (unknown [106.210.134.192]) by
	eusmtip1.samsung.com (KnoxPortal) with ESMTPA id
	20250917124400eusmtip1d574af0bda27e66bb38b688c7469d995~mEn6650ts2138821388eusmtip1i;
	Wed, 17 Sep 2025 12:44:00 +0000 (GMT)
Message-ID: <b9052d59-cba4-4855-b356-1f67f708bf8f@samsung.com>
Date: Wed, 17 Sep 2025 14:43:59 +0200
MIME-Version: 1.0
User-Agent: Betterbird (Windows)
Subject: Re: [PATCH] kmsan: fix missed kmsan_handle_dma() signature
 conversion
To: Leon Romanovsky <leon@kernel.org>
Cc: Leon Romanovsky <leonro@nvidia.com>, Jason Gunthorpe <jgg@nvidia.com>,
	Alexander Potapenko <glider@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, kasan-dev@googlegroups.com, kernel test robot
	<lkp@intel.com>, linux-mm@kvack.org
Content-Language: en-US
From: Marek Szyprowski <m.szyprowski@samsung.com>
In-Reply-To: <4b2d7d0175b30177733bbbd42bf979d77eb73c29.1758090947.git.leon@kernel.org>
X-CMS-MailID: 20250917124400eucas1p1d013715516684550c2ccc2d97ca691a5
X-Msg-Generator: CA
Content-Type: text/plain; charset="UTF-8"
X-RootMTR: 20250917063825eucas1p2364dba546022ab35fdc40dc7ada6fd20
X-EPHeader: CA
X-CMS-RootMailID: 20250917063825eucas1p2364dba546022ab35fdc40dc7ada6fd20
References: <CGME20250917063825eucas1p2364dba546022ab35fdc40dc7ada6fd20@eucas1p2.samsung.com>
	<4b2d7d0175b30177733bbbd42bf979d77eb73c29.1758090947.git.leon@kernel.org>
X-Original-Sender: m.szyprowski@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=iMf+NB2v;       spf=pass
 (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as
 permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=samsung.com
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

On 17.09.2025 08:37, Leon Romanovsky wrote:
> From: Leon Romanovsky <leonro@nvidia.com>
>
> kmsan_handle_dma_sg() has call to kmsan_handle_dma() function which was
> missed during conversion to physical addresses. Update that caller too
> and fix the following compilation error:
>
> mm/kmsan/hooks.c:372:6: error: too many arguments to function call, expected 3, have 4
>    371 |                 kmsan_handle_dma(sg_page(item), item->offset, item->length,
>        |                 ~~~~~~~~~~~~~~~~
>    372 |                                  dir);
>        |                                  ^~~
> mm/kmsan/hooks.c:362:19: note: 'kmsan_handle_dma' declared here
>    362 | EXPORT_SYMBOL_GPL(kmsan_handle_dma);
>
> Fixes: 6eb1e769b2c1 ("kmsan: convert kmsan_handle_dma to use physical addresses")
> Reported-by: kernel test robot <lkp@intel.com>
> Closes: https://lore.kernel.org/oe-kbuild-all/202509170638.AMGNCMEE-lkp@intel.com/
> Signed-off-by: Leon Romanovsky <leonro@nvidia.com>

Applied to dma-mapping-for-next branch. Thanks!

> ---
>   mm/kmsan/hooks.c | 3 +--
>   1 file changed, 1 insertion(+), 2 deletions(-)
>
> diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
> index fa9475e5ec4e9..90bee565b9bc2 100644
> --- a/mm/kmsan/hooks.c
> +++ b/mm/kmsan/hooks.c
> @@ -368,8 +368,7 @@ void kmsan_handle_dma_sg(struct scatterlist *sg, int nents,
>   	int i;
>   
>   	for_each_sg(sg, item, nents, i)
> -		kmsan_handle_dma(sg_page(item), item->offset, item->length,
> -				 dir);
> +		kmsan_handle_dma(sg_phys(item), item->length, dir);
>   }
>   
>   /* Functions from kmsan-checks.h follow. */

Best regards
-- 
Marek Szyprowski, PhD
Samsung R&D Institute Poland

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b9052d59-cba4-4855-b356-1f67f708bf8f%40samsung.com.
