Return-Path: <kasan-dev+bncBC3JRV7SWYEBBF4WQ7YQKGQEECR2UEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id E6F66140D1F
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 15:56:24 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id t2sf19113861ilp.3
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 06:56:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579272983; cv=pass;
        d=google.com; s=arc-20160816;
        b=aig+iA99AFK74BlnDKMHv/XnmQiutOtdoBZvVu5jdRusQV6D6sUdHvAae6NLPpTCYL
         P36kDE0Lw5K5a1K9SU2ySGQtkBQgEEd5LgpBr16XGcA5qXDOk8TNhuG0YiZApQn3ANNq
         W9r0rCeLcDEsPjaGnjjP0FlRaLMbRbpOB13gJSo6pGeod6qOVi0bNysCGxkuO5mdh0uj
         ivJ3j5Gwvk/MX/v1CV9cYZ4MCZQ4pqqVf6knYwkGpFwrqV4gR7WP36hd0+wP0pjRCIW4
         twOSdK7QzfQ1oena65t5TMQy9Zz/QAg74ck7goZuUmVEq+uzLTF7te51g1tXfHgPBnk7
         gTgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=NjZDQEg0A+JnX48CGJjVqo66lvTg4Ysx+JZpuS2pKEU=;
        b=aNKJAZzSBs0GD9eMuRe1uBjK3GubP2P4WHguUWs3OP1cCbc7gbzUlj4vN8apvRFU+7
         eQTiJH773vscYPpXcGdFUCuCypAghDAyx8xo94DamHuq2OTbfRwm13lAWmK81Z455bHv
         UiJoBOh19at2FckiFFs3ve3BcaLDkZPVAsN7TbJjeicqLK1Uhqo3PZvIc4O7iGNhf/uH
         8kphCz8eeD5Hp7s1aZNApIzlmiIId0xrRduiqIYGYLC4UmNd9sARs6Hj3047S+9w2RkT
         x96urwZiUPp+pT/gIrW/YTiKNxogr5rg8S910b9PCmDyTcFdeQSawLXjiUpfX6shpi3n
         9YMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2019-08-05 header.b=AgWPVT2X;
       spf=pass (google.com: domain of boris.ostrovsky@oracle.com designates 141.146.126.78 as permitted sender) smtp.mailfrom=boris.ostrovsky@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NjZDQEg0A+JnX48CGJjVqo66lvTg4Ysx+JZpuS2pKEU=;
        b=OUBnR8omqgJZHdGfKojjP5sg/eIHIzjZ6SRxO30db6JUMTf/9lUdHd5Z/AoknuZ8xL
         vTBDS1qZwL2V29lLN9tVZF8w8sQ2LcdqOGEDLcN1aNGHnp4NSP+WHJYtSS977thSVytl
         nH0SSIGyfwdfS3CWaLUXFwLNO5LEPBtFDmMA/xc6jY4a2lnx27hpNjGy4UMRNxmnqEby
         lcUhpkpXBimpIbtjHEyRhDLGcNm3CZhEJMKJ87cPjpDu10/xPsMXrDoZeRudpfXwlIPj
         tunxA+uZH+4jGvjT/BlfwRTJiK5gXziWJXPwoVxaStvDlvDYQigCaNzNFObgAjq3r53j
         2oFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NjZDQEg0A+JnX48CGJjVqo66lvTg4Ysx+JZpuS2pKEU=;
        b=FTcVYe/Fs/tmYDWtLUMgaxM0ha2vW7ocqvqr+TjhObjLhIXAeQzpdnh+5t8vOXTsCJ
         1XA5TrYswWYRT9fs67NnCqTX64mukLWfSUTO5Q7tAwa9YHilVH5PPEJTjxFdFBeDZPHp
         Qd1HrARhCfHSzH3Z9KztEU83zjV078nJ5fh8XY1jrcIjrSPC/uA3kbV37Q1OHgGuiPW4
         A7aguQcy5nfEGEKw42CGdY+wVcuyRCd8Df0ryRr9tjsLGbNl5jcomm4g/HhtrWShwrdI
         5tIYHhIMJ6SAx2xtVvGwiGNwGrqXVMs4WTygVHv1LRy4tmxFgSZONyjGrNve4w55C6/F
         SA/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVtWGVRuI189OYHTgcMoSrVfAPTC+BBsGk+NAPsGKIYOICkWmaU
	MVbScvYJdZNHrpmAh8jYiOQ=
X-Google-Smtp-Source: APXvYqzcCc8nOxn0/uE65peU6YakkV7opuAp6SNQw8MgJbVKsUSZp3u9Ou9u4E8VpfMwIFzihjdlGw==
X-Received: by 2002:a92:5c8f:: with SMTP id d15mr3490195ilg.102.1579272983779;
        Fri, 17 Jan 2020 06:56:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:cc85:: with SMTP id x5ls4545237ilo.12.gmail; Fri, 17 Jan
 2020 06:56:23 -0800 (PST)
X-Received: by 2002:a92:c647:: with SMTP id 7mr3383383ill.28.1579272983423;
        Fri, 17 Jan 2020 06:56:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579272983; cv=none;
        d=google.com; s=arc-20160816;
        b=n7F5tUHfumnvFyGF9DoziVkZysDwaktOc4oG+CW3mTZHjED/n4Eoj4R0X/3y9XAmgF
         ttQPWJGxk65/dFTAvoeh1SQsFj5lOgpvsetSvG/obBzIm9i5T8TxWmikNU8wR7rUdtOF
         tXRGW1OGdg05tb8YIkIjsZZ4U2QkUEM9kA8FF7xXNL391qdbMZ80IENtDSVFi747tzxa
         cObWFNXw9y6sPw41sjwsheo690NJCfrb4PT7zvYkPu2wpK92l4DB2FQjWqDgU1j3wAMf
         aROrhCEx0OPsVvenH5+SODwZ/cOjr9SdDEXlRVUuO/gc6kcacA0Pk5J8yon0wMZPoUmJ
         0DwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=RDYxmTVi6oTBCZ/d+490GqYHOHA9lPToi4gO08lPyRM=;
        b=ThYugkLHLhZgJCPrcAWoU7NhO1xFXOTr6FIHU9+6lJJV4mAiM61lkcpiwlMfsXD6w7
         BNYQNsWCu2BO3TDQ+2bHpen54i2vlAGRyAExhf6LkxumlSBoeg4te7MbVSCeUfmutOgq
         MZibLE3waQCTTEKdLYn2LgCNAqE3y9YhReHFgqWYulis1hK0C12MYLimb0Cj4mQioPa6
         vuUNJ+7EfD/htzylyrO2CRc4zB/RWnyp17jZKLEcmH/SIbP8Gu93P+I3aCHavl35GzoT
         bC/8bSMuYQfnC32CT8O+nkKtrDlyTy88zGRnmbU3w1hDoY78VvipPhIwvd2WBQcoVYs0
         J5/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2019-08-05 header.b=AgWPVT2X;
       spf=pass (google.com: domain of boris.ostrovsky@oracle.com designates 141.146.126.78 as permitted sender) smtp.mailfrom=boris.ostrovsky@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from aserp2120.oracle.com (aserp2120.oracle.com. [141.146.126.78])
        by gmr-mx.google.com with ESMTPS id z20si1206398ill.5.2020.01.17.06.56.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 17 Jan 2020 06:56:23 -0800 (PST)
Received-SPF: pass (google.com: domain of boris.ostrovsky@oracle.com designates 141.146.126.78 as permitted sender) client-ip=141.146.126.78;
Received: from pps.filterd (aserp2120.oracle.com [127.0.0.1])
	by aserp2120.oracle.com (8.16.0.27/8.16.0.27) with SMTP id 00HEr9gs170370;
	Fri, 17 Jan 2020 14:56:19 GMT
Received: from aserp3030.oracle.com (aserp3030.oracle.com [141.146.126.71])
	by aserp2120.oracle.com with ESMTP id 2xf73u91uj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 17 Jan 2020 14:56:19 +0000
Received: from pps.filterd (aserp3030.oracle.com [127.0.0.1])
	by aserp3030.oracle.com (8.16.0.27/8.16.0.27) with SMTP id 00HEsBST166391;
	Fri, 17 Jan 2020 14:56:19 GMT
Received: from aserv0121.oracle.com (aserv0121.oracle.com [141.146.126.235])
	by aserp3030.oracle.com with ESMTP id 2xk24f4w2f-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 17 Jan 2020 14:56:19 +0000
Received: from abhmp0014.oracle.com (abhmp0014.oracle.com [141.146.116.20])
	by aserv0121.oracle.com (8.14.4/8.13.8) with ESMTP id 00HEuH6G006884;
	Fri, 17 Jan 2020 14:56:17 GMT
Received: from bostrovs-us.us.oracle.com (/10.152.32.65)
	by default (Oracle Beehive Gateway v4.0)
	with ESMTP ; Fri, 17 Jan 2020 06:56:17 -0800
Subject: Re: [PATCH v2 2/4] x86/xen: add basic KASAN support for PV kernel
To: Sergey Dyasli <sergey.dyasli@citrix.com>, xen-devel@lists.xen.org,
        kasan-dev@googlegroups.com, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
        Alexander Potapenko <glider@google.com>,
        Dmitry Vyukov <dvyukov@google.com>, Juergen Gross <jgross@suse.com>,
        Stefano Stabellini
 <sstabellini@kernel.org>,
        George Dunlap <george.dunlap@citrix.com>,
        Ross Lagerwall <ross.lagerwall@citrix.com>,
        Andrew Morton <akpm@linux-foundation.org>
References: <20200117125834.14552-1-sergey.dyasli@citrix.com>
 <20200117125834.14552-3-sergey.dyasli@citrix.com>
From: Boris Ostrovsky <boris.ostrovsky@oracle.com>
Message-ID: <28aba070-fa53-5677-c2d2-97d06514dda8@oracle.com>
Date: Fri, 17 Jan 2020 09:56:12 -0500
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.3.0
MIME-Version: 1.0
In-Reply-To: <20200117125834.14552-3-sergey.dyasli@citrix.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9502 signatures=668685
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 suspectscore=0 malwarescore=0
 phishscore=0 bulkscore=0 spamscore=0 mlxscore=0 mlxlogscore=991
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.0.1-1911140001 definitions=main-2001170117
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9502 signatures=668685
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 priorityscore=1501 malwarescore=0
 suspectscore=0 phishscore=0 bulkscore=0 spamscore=0 clxscore=1015
 lowpriorityscore=0 mlxscore=0 impostorscore=0 mlxlogscore=999 adultscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.0.1-1911140001
 definitions=main-2001170117
X-Original-Sender: boris.ostrovsky@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2019-08-05 header.b=AgWPVT2X;
       spf=pass (google.com: domain of boris.ostrovsky@oracle.com designates
 141.146.126.78 as permitted sender) smtp.mailfrom=boris.ostrovsky@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
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



On 1/17/20 7:58 AM, Sergey Dyasli wrote:
> --- a/arch/x86/mm/kasan_init_64.c
> +++ b/arch/x86/mm/kasan_init_64.c
> @@ -13,6 +13,9 @@
>   #include <linux/sched/task.h>
>   #include <linux/vmalloc.h>
>   
> +#include <xen/xen.h>
> +#include <xen/xen-ops.h>
> +
>   #include <asm/e820/types.h>
>   #include <asm/pgalloc.h>
>   #include <asm/tlbflush.h>
> @@ -332,6 +335,11 @@ void __init kasan_early_init(void)
>   	for (i = 0; pgtable_l5_enabled() && i < PTRS_PER_P4D; i++)
>   		kasan_early_shadow_p4d[i] = __p4d(p4d_val);
>   
> +	if (xen_pv_domain()) {
> +		pgd_t *pv_top_pgt = xen_pv_kasan_early_init();
> +		kasan_map_early_shadow(pv_top_pgt);
> +	}
> +


I'd suggest replacing this with xen_kasan_early_init() and doing 
everything, including PV check, there. This way non-Xen code won't need 
to be aware of Xen-specific details such as guest types.


>   	kasan_map_early_shadow(early_top_pgt);
>   	kasan_map_early_shadow(init_top_pgt);
>   }
> @@ -369,6 +377,8 @@ void __init kasan_init(void)
>   				__pgd(__pa(tmp_p4d_table) | _KERNPG_TABLE));
>   	}
>   
> +	xen_pv_kasan_pin_pgd(early_top_pgt);
> +

And drop "_pv" here (and below) for the same reason.

-boris

>   	load_cr3(early_top_pgt);
>   	__flush_tlb_all();
>   
> @@ -433,6 +443,8 @@ void __init kasan_init(void)
>   	load_cr3(init_top_pgt);
>   	__flush_tlb_all();
>   
> +	xen_pv_kasan_unpin_pgd(early_top_pgt);
> +
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/28aba070-fa53-5677-c2d2-97d06514dda8%40oracle.com.
