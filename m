Return-Path: <kasan-dev+bncBDWLZXP6ZEPRB4VPQLWAKGQEFWP7VOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 36AF2B4939
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2019 10:23:15 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 205sf205914ljf.13
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2019 01:23:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568708594; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rf/r/a3yr0hrHUZUC1IQZwJ2K3gs5VjzfS6bJCzVtSDIkq9Q/b9ja31LdlmkcVx31i
         mIEPJ+IOWJymep9fDDb4X4D9U1Jeb0+qhE2YC18nWccCTXUnAipR26DEbRVjXbdfabkm
         PBxVyQwd4lmRMgzib8pDrWPh04p3+OLivgWhQ1Qvq/dC/EZPooqKeiRMMc6WtVSMdCWL
         k3b37LrXPQleYiqCxbf31zaEmnT8ePMkVcQNpev0NTvFoXgfmdoS4wR7SPxCHRFq/e9F
         Y8oNExSVhp1xV9/X8pmTDHx0dBbP9ePwa6a29NUWNmgOtykLrD4dudgjINQr4EcoS3X7
         YZdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:openpgp:from
         :references:cc:to:subject:sender:dkim-signature;
        bh=nZKHvyWaeFGJljc0t2i2hjqUtEa1uVJHe3VUbiHztM0=;
        b=GkIMKlGw41wxKE0zDd/MvtLncXl3CvGBBSHSqTkQc5A4ekRnZHW0hUPsf+66jPNjgL
         HpNVmnPKio+guqIGVq4N2xsIXRud50l1k+v7Zy8wCxi6UtdacHxmF1d9Y0pk7HhT3cnO
         OxgfgnMw87akFEq+fbrb1X8htOnFNnXfV5+MROeSuegLrt1KTm88XSZAL/iqBUe/o4iF
         jLaqevY5KfszBdpUC8OaS49yJfdRObMs3Ml3mTzWVx1KQP+kvj9CiO7Ik89ZHJP6shj9
         D3DkBJ5eXrVFlLiG3MFesmOLUoHG6Evi2OMxCSJffbne7lA4tbqmLev57GC9jsd4QT8j
         3Ghw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:openpgp:autocrypt:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nZKHvyWaeFGJljc0t2i2hjqUtEa1uVJHe3VUbiHztM0=;
        b=FhDdQ9i0rK8cxe0UNk+hfhcMLYA8cFOn7iMn/Lujfc3DdNhS68FBbCMqbhAaZypD2m
         VjkDvi0oNRiAREiTihc7flgDVw+ltk5QcDXt4u/fYas8F6GZmxN1C0x6mlnqvV+6h1Nz
         0Tz6mlRodQasW5prEhckpA0ISr1XjmClUaCdklKg//NKTWTcWpTUAA5UToDLtOjFP9Ky
         hE9w1vmEWNAhoU+/t3QgZxeDHmXfD78kDY4cIKzd9nq06CPr+JQE5AFgb37zC1zK2t5n
         1gdy6WSHADeL3NQqEHroMjJi7dyR0bYD4RH2B7uKOMRssFCkUquRCqdJUhzE4s/ZIdGS
         GFKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:openpgp
         :autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nZKHvyWaeFGJljc0t2i2hjqUtEa1uVJHe3VUbiHztM0=;
        b=aZF/e7/u9tL8yE/vsDEKBbsRYVGGgm0waN94qcHYtkB4PAI3KdKicLqxmE8AkRjqy+
         hdi471+stmR7jQ1CjpZHpBigda2rtgLt3ja/Eqdr12eWLKWv/CgkmtSDe6hSkoKUnfBe
         B3CZgWJIVc5rm+ubBOg0fJgsZazaEn0ZeplTkDslvmcxQ9NXqB0V9jsOdayOoCMyWV2X
         VRTQbsG1w7nDJDPkgat69+9yAlNQG6V84bVpHqhvUTscXlKAz+ieIxxvVY6N33Q4KUFu
         FG4C9si6B46gYPM4TlSpsmvhKTn6Auim2wAg71tJ2/y3t/83AtuVPF5YwbgdGzU4gX4B
         8LYg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXyyVoeWOQKLC44dlLXe8I8xj5nnw1Bo1UDJy9Rf83pvTN6ToAn
	S5FFx4jxv82hgi1pau911t8=
X-Google-Smtp-Source: APXvYqxbiggbbQT9JM3L9ArgfrU/qK2092tYKPu5qOo0eMLkrQRJ+agohiKJ4PnC62yhfl56LUYfGA==
X-Received: by 2002:a2e:2c02:: with SMTP id s2mr1196637ljs.156.1568708594711;
        Tue, 17 Sep 2019 01:23:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:934e:: with SMTP id m14ls286588ljh.4.gmail; Tue, 17 Sep
 2019 01:23:14 -0700 (PDT)
X-Received: by 2002:a2e:89cd:: with SMTP id c13mr1165262ljk.174.1568708594079;
        Tue, 17 Sep 2019 01:23:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568708594; cv=none;
        d=google.com; s=arc-20160816;
        b=k2jWrtMQczMNFB7XD1otlZPQXeWL4LHEKaUfjRtXjOeP1YdYx2XZORZ0vk8F8cTe19
         k3kLagBgLwhzuLnV4LMbyjO50pB7vZSbvndtd8+ZK39uTnko8qIGwkDvIHsIs9GCuoVm
         Jex2rdDjLojJPckq6YphKysvUkq8l8WKFPOQ9x6yMpOxGTHDyoxcE4F0SiArczRHWw6j
         NiB8ZQrRyPF+y1FvO1NGofMBXvoVTjAUvgq0xiua0iYJ+TrYDLcO4UpPzYXKDN/t20Y1
         XK+FbcanjhCbthTtWRT7wee3AvbgHEG15OEppoM+fk29UO0NhnAcD+hA04R2XpMuxvTo
         j/1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:openpgp:from:references:cc:to
         :subject;
        bh=zAgtn8TtH+v11rLOQk52nzVIHXTdFvkWbiAoxA3iYiQ=;
        b=Flibi/eTZ8hOCOofEyWoM+a22GAYYB/DvWjDsysFunTPJiqngbBiuWyi7Mb7wA+TNO
         MdCGz7tFPi5He7vlnMADkQ2CEswJeN3kp37p6spr/UnBqYq8Z1RTvZCQZX7vBO5dKPl0
         lLHLKw/+FwGQLDwP7YZfOjmzhsyiFub7w089hHlbGs94N7v/uOe8676XnLS8YDABw+6s
         Ovrrga2pOSUQQ7i2vnWSpv2VeHELgIXrWyxoqANIsXBRW+EOq6C5uHgb/+8iH9Bn5ygQ
         PqvSuBB9eUO2LDKKuFYU3hwxtDtjCu91b0PzIMSCEw3qTRhqniAswRwHXsWIYpSocUf4
         xnZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id d3si277316lfq.1.2019.09.17.01.23.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 17 Sep 2019 01:23:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id 2049BAE84;
	Tue, 17 Sep 2019 08:23:12 +0000 (UTC)
Subject: Re: [PATCH v3] mm/kasan: dump alloc and free stack for page allocator
To: Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Walter Wu <walter-zh.wu@mediatek.com>
Cc: Qian Cai <cai@lca.pw>, Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
 <matthias.bgg@gmail.com>, Andrew Morton <akpm@linux-foundation.org>,
 Martin Schwidefsky <schwidefsky@de.ibm.com>,
 Andrey Konovalov <andreyknvl@google.com>, Arnd Bergmann <arnd@arndb.de>,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org,
 linux-mediatek@lists.infradead.org, wsd_upstream@mediatek.com
References: <20190911083921.4158-1-walter-zh.wu@mediatek.com>
 <5E358F4B-552C-4542-9655-E01C7B754F14@lca.pw>
 <c4d2518f-4813-c941-6f47-73897f420517@suse.cz>
 <1568297308.19040.5.camel@mtksdccf07>
 <613f9f23-c7f0-871f-fe13-930c35ef3105@suse.cz>
 <79fede05-735b-8477-c273-f34db93fd72b@virtuozzo.com>
 <6d58ce86-b2a4-40af-bf40-c604b457d086@suse.cz>
 <4e76e7ce-1d61-524a-622b-663c01d19707@virtuozzo.com>
From: Vlastimil Babka <vbabka@suse.cz>
Openpgp: preference=signencrypt
Autocrypt: addr=vbabka@suse.cz; prefer-encrypt=mutual; keydata=
 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
Message-ID: <a5103bf0-245e-5894-0486-3e92fa830e41@suse.cz>
Date: Tue, 17 Sep 2019 10:19:15 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <4e76e7ce-1d61-524a-622b-663c01d19707@virtuozzo.com>
Content-Type: text/plain; charset="UTF-8"
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

On 9/16/19 5:57 PM, Andrey Ryabinin wrote:
>> --- a/mm/page_alloc.c
>> +++ b/mm/page_alloc.c
>> @@ -710,8 +710,12 @@ static int __init early_debug_pagealloc(char *buf)
>>  	if (kstrtobool(buf, &enable))
>>  		return -EINVAL;
>>  
>> -	if (enable)
>> +	if (enable) {
>>  		static_branch_enable(&_debug_pagealloc_enabled);
>> +#ifdef CONFIG_PAGE_OWNER
>> +		page_owner_free_stack_disabled = false;
> 
> I think this won't work with CONFIG_DEBUG_PAGEALLOC_ENABLE_DEFAULT=y

Good point, thanks.

>> +#endif
>> +	}
>>  
>>  	return 0;
>>  }
>> diff --git a/mm/page_owner.c b/mm/page_owner.c
>> index dee931184788..b589bfbc4795 100644
>> --- a/mm/page_owner.c
>> +++ b/mm/page_owner.c
>> @@ -24,13 +24,15 @@ struct page_owner {
>>  	short last_migrate_reason;
>>  	gfp_t gfp_mask;
>>  	depot_stack_handle_t handle;
>> -#ifdef CONFIG_DEBUG_PAGEALLOC
>> +#ifdef CONFIG_PAGE_OWNER_FREE_STACK
>>  	depot_stack_handle_t free_handle;
>>  #endif
>>  };
>>  
>>  static bool page_owner_disabled = true;
>> +bool page_owner_free_stack_disabled = true;
>>  DEFINE_STATIC_KEY_FALSE(page_owner_inited);
>> +static DEFINE_STATIC_KEY_FALSE(page_owner_free_stack);
>>  
>>  static depot_stack_handle_t dummy_handle;
>>  static depot_stack_handle_t failure_handle;
>> @@ -46,6 +48,9 @@ static int __init early_page_owner_param(char *buf)
>>  	if (strcmp(buf, "on") == 0)
>>  		page_owner_disabled = false;
>>  
>> +	if (!page_owner_disabled && IS_ENABLED(CONFIG_KASAN))
> 
> I'd rather keep all logic in one place, i.e. "if (!page_owner_disabled && (IS_ENABLED(CONFIG_KASAN) || debug_pagealloc_enabled())"
> With this no changes in early_debug_pagealloc() required and CONFIG_DEBUG_PAGEALLOC_ENABLE_DEFAULT=y should also work correctly.

In this function it would not work if the debug_pagealloc param gets
processed later than page_owner, but should be doable in
init_page_owner(), I'll try, thanks.

> 
>> +		page_owner_free_stack_disabled = false;
>> +
>>  	return 0;
>>  }
>>  early_param("page_owner", early_page_owner_param);
>  
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a5103bf0-245e-5894-0486-3e92fa830e41%40suse.cz.
