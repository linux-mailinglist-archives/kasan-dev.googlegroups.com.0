Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBI4Z3HVQKGQEWXMYFSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id E216DAD980
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Sep 2019 14:59:15 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id g2sf2519010wmk.5
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Sep 2019 05:59:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568033955; cv=pass;
        d=google.com; s=arc-20160816;
        b=W5y4lZ3jmZS8llq8qDpCHXG6g5uy2n8SGCblekJABXvoETEf86MDFhgY3VHZAFALnd
         zNCLCO94CrcuddjvHDaVbHrsxXvQH4mk2ou6Ly/f0vjxVZ4I2IrkI/gdye17zsBp2QBc
         7Xg+sO7wuzr5eWbTgv8JLwLuDpeDcdVQ7RzHY/wznq+KIEY2QM6eQv22mqgk/mSMN8eK
         2ufKut/zZNT9kLA1cjbRwX+JHykvyIsIcjjCT+hlJ+Tg7JomMvPk+MG3vrwbEUxX58K/
         pYComiwLhbn5Z5k4LbGSBWu6IMbMa03WUAmccU/x/ZaV0XQnm/9NVivjnouzEbGredM4
         ATgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=GlKOxySqrI5C0JHPfl409io3xGSFrhAtAxn/KAYScto=;
        b=DDRRHdR7khpMP/o+69jksh2t6cS5AU48UDMjHDQ52E/ekYTFPlCaIqP86XAZ9Unguc
         +3qB7pI5cifb8U2Xw/cVCxv9WtFIH+Y6xYwWjUaev/y3BkvUPYWefmq625cn1DDDrt5o
         opfLTA4OODmi8XWd/2AJozc2Oa1q4tMku8XHC2e6Tvvwr7oUiMg+rbVPlvtBKyEFVlvu
         0I7AIeaN7sgc1bQimm/42BmT/U+Naa7t35nu/5hCVvrSVIlf2mYSyGOQx6oJmHDm5AbR
         X5zVy5ZsH6KVpJTgw4BmrS+LBsFLKW1q1vrkYxCAOqeYzhpoyBsDRFRwKTws0oxz936w
         fWDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GlKOxySqrI5C0JHPfl409io3xGSFrhAtAxn/KAYScto=;
        b=s32Z8MdRLkdyENcWlG/3707IgvJi7fia3Cech4VnqbAX7Edg9URd0M6hfMQkyAKCtp
         ydqGf5yaip2e41EGWosrM/FbchAeZR/stDhos6He4gKDOjwkstaut/Z8HJuwfouQfVvF
         Ff606p70H4JVK2/Ez+eY+t4zK/QXZ+wVD85Es1OPo/MICnnPqxzjOJ+DNTdxMRyZ4vt3
         ecBl9U2RmQMMcVuSkRFM08/MwfiZHaNi2tbVRq3BTuuQiRzG0t6KHEATWPRuqe/bT0ST
         aiPYJKv+LE/nJo8ZDaKagz1Xnl7nFYWseEwdvm+SZUqBgwB6yC7sSinl6sdPsJgUKfdy
         8zhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GlKOxySqrI5C0JHPfl409io3xGSFrhAtAxn/KAYScto=;
        b=L9D6vwDmiFcaMggk/+TOL1zFujID1HYZKLlf3LdoIjC5brImtuea04rHS7XxybQX5H
         uZihUgMqhy6/sup3zUjIFaJ5JKkCm66/3wGG7ew8FTyOMY7VB0Ag8bgqhJsUjrmhK2La
         Zxeb4AuFQ1SbtbEy0qdkJUoHJPSY3ShDDarrYTI18fJQklrVHIQoBZk+2ccQRYgVqI8B
         js09XZlbgD5ysNxrNx7hLWjU0FxY/sLmMi/Y9rxnXEKlz/NBteDvP8xKjnpHClDBwCo+
         bmBsLcLJapgCDBaHZ6ZIbmfEaFrJKYt+J+5D8EipP5Yfl/CRxTZ8K383oT7RqinGnWyT
         EvlQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV5La3RqLwiTfgOUx7shJIG3szJjILZ9gX+NiRDgNcHuM3YT7ba
	EahJknQAB7IknDaPm5NNiL8=
X-Google-Smtp-Source: APXvYqyUJiyq331dH3HeWnFp4afWPRkGqISL/pBV1rqqSPhKyarlnhgIOHJnQrb0s8sA5i76htVGCA==
X-Received: by 2002:a7b:cb93:: with SMTP id m19mr837303wmi.157.1568033955581;
        Mon, 09 Sep 2019 05:59:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7502:: with SMTP id o2ls5127885wmc.4.gmail; Mon, 09 Sep
 2019 05:59:15 -0700 (PDT)
X-Received: by 2002:a1c:c911:: with SMTP id f17mr18951866wmb.73.1568033955025;
        Mon, 09 Sep 2019 05:59:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568033955; cv=none;
        d=google.com; s=arc-20160816;
        b=WJzMITsMRWHOB6diJFi90KuSuAEDZ5BcZIOEMN3CDOokKgMV30C5x7w8JHKdKAtZcj
         Ah6JoMsZJualzynRQkd0XKEcTt8YS2MfjInIJNwfHrK2ZEww3rKRE2fzU8lSwQq56/IX
         fn6Pse08z8U2Uh3xTyow5mexhBpEI60+DIjCVHA1Dall1AGgumIgnw/2d0qASpB/7WRf
         xCb9ElHJipu8XGPdI5tFMjaiYRgiax/McTcdR6fC9E60V40IFQeL6LtYoLhwrGIVhFHr
         EgWqaX0Q4WjoH7QOKi663diN2nAr35GpiDy59V30kHU1sHOwMKdwA3K6MeCZGEKesOg3
         76fQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=PV1gSBJEuQAo0AkVFHlmmiU/qDCCVulJWTWljAY7zW4=;
        b=lheV3EUIgJH4U9q2x6pZTZpq6HHyvq5xoI1uzTcDnzbwBHZI5m9Q0ydZSVH/fQCGP1
         CEgGFBcUTVBFQwakm41JeF+xR2TDTU6M9y/fWFA29m+4/GqpA2dqgeO4sE5BK4TAxFm6
         oW68WeHGj+gv1H3Pflf68oBMcTaMPCXI9UE6mxgUCnUAMAgsQWwhDSmSHi2bYL0x1a5t
         Idc4kkleXzRZ/uyP5aMS4uuf9CsKpHtV43G5IfzHJeJYW6QLcc+dMDRyjGeTrpFI2ese
         LOQ2Q9fAvTw6n/nu4uapqQmoon379tqxa+qoMMZPoHV+izuKMIcO84njut6k+6dLYEGn
         1OLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id w8si142631wmk.1.2019.09.09.05.59.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Sep 2019 05:59:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id E08F0AFBA;
	Mon,  9 Sep 2019 12:59:13 +0000 (UTC)
Subject: Re: [PATCH v2 1/2] mm/page_ext: support to record the last stack of
 page
To: Walter Wu <walter-zh.wu@mediatek.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Martin Schwidefsky <schwidefsky@de.ibm.com>, Will Deacon <will@kernel.org>,
 Andrey Konovalov <andreyknvl@google.com>, Arnd Bergmann <arnd@arndb.de>,
 Thomas Gleixner <tglx@linutronix.de>, Michal Hocko <mhocko@kernel.org>,
 Qian Cai <cai@lca.pw>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org,
 linux-mediatek@lists.infradead.org, wsd_upstream@mediatek.com
References: <20190909085339.25350-1-walter-zh.wu@mediatek.com>
From: Vlastimil Babka <vbabka@suse.cz>
Message-ID: <0fd84c7b-a23b-0b09-519f-a006fade1b4f@suse.cz>
Date: Mon, 9 Sep 2019 14:59:12 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <20190909085339.25350-1-walter-zh.wu@mediatek.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

On 9/9/19 10:53 AM, Walter Wu wrote:
> KASAN will record last stack of page in order to help programmer
> to see memory corruption caused by page.
> 
> What is difference between page_owner and our patch?
> page_owner records alloc stack of page, but our patch is to record
> last stack(it may be alloc or free stack of page).
> 
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>

There's no point in separating this from patch 2 (and as David pointed 
out, doesn't compile).

> ---
>   mm/page_ext.c | 3 +++
>   1 file changed, 3 insertions(+)
> 
> diff --git a/mm/page_ext.c b/mm/page_ext.c
> index 5f5769c7db3b..7ca33dcd9ffa 100644
> --- a/mm/page_ext.c
> +++ b/mm/page_ext.c
> @@ -65,6 +65,9 @@ static struct page_ext_operations *page_ext_ops[] = {
>   #if defined(CONFIG_IDLE_PAGE_TRACKING) && !defined(CONFIG_64BIT)
>   	&page_idle_ops,
>   #endif
> +#ifdef CONFIG_KASAN
> +	&page_stack_ops,
> +#endif
>   };
>   
>   static unsigned long total_usage;
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0fd84c7b-a23b-0b09-519f-a006fade1b4f%40suse.cz.
