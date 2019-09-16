Return-Path: <kasan-dev+bncBC5L5P75YUERB5HB73VQKGQE2GHKPFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id D44CAB3E3D
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Sep 2019 17:57:40 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id y25sf198077edv.20
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Sep 2019 08:57:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568649460; cv=pass;
        d=google.com; s=arc-20160816;
        b=HlcmmI3FXUVa9wpva2U2WtqVjSOnA+pWJmlTSFE/T24G9yoFwiJbgPxj+Tqzy9y6aP
         HXx79gC0oCZMsFuXuxOkn+kr+PCi7iVef38qZ1LoCeB7UQk2/Q3YEn4CLW83e6kwlgZG
         BeFS5TgM+6TKTCQDfbgJeLavQ9k7MmSNBWWlzicWVESP/mQFxeqSSpTGTm1frU48Yxjo
         tNz8emyWXmZbW4BFOKCBRc5mih7rkrOruXI8iqOQrhHk6C3LOYUVMC91IrCuvNGt9S+Z
         0fV4h0Kz/SVBBb67H/ysK2yoehj6/9rLSudjema+P40UGXuG3Kyaygeyy8p1MAiopsF7
         10zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=2ZpWWFaMxhiJmpKrWOluJDsGShXaaaMf+elZxvAltw0=;
        b=ltOsZ+Xby5tazCCrOw/2f116Vo69wxpKsZRsqc3KrO7Ignt2kcaHZ3bG9VBG+ZxmvT
         sztH1Crnr+bEERR33tr9ZvDSKGpbki6NrrhtFyA+/ZM/xK0uhHlkbCREd3HlLXzj7+H+
         6RGfvLPfarMDKAHFV22td6SG2x/dwnU/2OCYzRnfUBT0xaqSIgBlG5gmK0K72uUf7hLS
         8TunTbfl6CxLc0uvzJIFBQMr9NusrWE0G5cddcF0C+1H1JXp8zumurwNIsqW6v4ALXYK
         0MzbP5TpZCSZIbhJe3gYOca3lTbzdftoTHlkYpS8RwG4y+Gz2NXAHo1e4gkZN883Nu64
         2Cog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2ZpWWFaMxhiJmpKrWOluJDsGShXaaaMf+elZxvAltw0=;
        b=Lfa62/oTtFOSefA92HodaGg+AyIbIF2aqs9S88go/Gh0RAPh8fzepBQuqKdtNE0CHj
         Buqwfg+ljHngqPasN5NmPr3jGz8LxzsW7O6Msgcwwdrncef1PPSEnsCp6oDip6yzimqa
         hMEaZHCN4H+QCTnXx+KBnyHdb892u7GeVE4sWj5LaQv4LSv0lhqoitypi2Il7PQM/kaS
         iQSC93qpvQ7kI5OHJnsYMDQ7IQtrTFb4xcgbAWBPGg9Q5JcK2qMbHWws/fqtXilOL5X5
         EnY67jpgeAv1PDEGGvtJ75asa+64rdArQQcoVIlChC0Jq86pVuXn09xU9LY9u+CH7MKb
         VyEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2ZpWWFaMxhiJmpKrWOluJDsGShXaaaMf+elZxvAltw0=;
        b=mi3fLr3ZGwvs9dlmO7HtUVEyyZOtudAkhmTn4fjsm424IfxpVbcvNDgTTJlr23P5Cr
         Mmw7+opzS7wiaI8EfldPDmnqYBppayTTevYUNgrCK0HVwwwVgYG3s/8LfRY+GiImGUBp
         lVnc+nL1cg+3ntzuC/Bb95GWZ3B7bZBjh6DLYubO+biTwqg4i6ppFToD71CvGglQJqi5
         px3JX0TPwEBCbp1MgHSHGBTFNozR89WSL1uJKnUz8ACBHlGmCZ307vJSZBEELWWgyQWl
         LHPwB17ptC6XXae7t/xOiePVXd8fuEkhncIH/XEodriRL1G7o7CwzORdvT2RzZYO4fhD
         olZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUwAWCkM0xgTYyxSC1PfpHXsSGjF5T0DArjJhQXnveqV1WwgGfk
	3NWeYeKhd6zk1dGyqUmA3AE=
X-Google-Smtp-Source: APXvYqyBtlpLIe5EYWGxeUzS8F0egdGArjrXvZ5P+eSdOMf9ppksbqkkmkP7xqzKQgaXkbEBLyLnhw==
X-Received: by 2002:a17:906:434f:: with SMTP id z15mr713632ejm.214.1568649460551;
        Mon, 16 Sep 2019 08:57:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:3591:: with SMTP id o17ls84887ejb.5.gmail; Mon, 16
 Sep 2019 08:57:40 -0700 (PDT)
X-Received: by 2002:a17:906:434f:: with SMTP id z15mr713611ejm.214.1568649460146;
        Mon, 16 Sep 2019 08:57:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568649460; cv=none;
        d=google.com; s=arc-20160816;
        b=yMsQReT1QBWz4Jttq/9FxilmOR1ocvpoWLpgO9ICKhGqV44JGNez0IU0zOBUK0p1tC
         Nj7Jjku41toYI56UUa3xqEcYqjUBU+U0pmu3iluHB6GBCY21KkyuLuU7JV0WZZl/cp6V
         lbxPMUKGDIK7SjgfXGpebRO4jLy1JrBNBFvdXhj/8/vj0LI4gPv9tcZ7Jb0XgjONprSb
         BjV9RoeLI5mh85Pt2YmRDvc/rh8saEfTyCjIwGq4gpP4eHjloSfpZgwZDsDnrW3lYB7c
         n/SQTJkUGj61j8mG2GhtHUBKOZfylTXuE7qgXCTYIsncVMXg/d9lXdhkH0v2gt5g6FBz
         cZuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=yOrYKwpADy224jlRZ25gTWPwlOosLMaBNWto4Qr7Prs=;
        b=DxxRmash1Fkrvhs3xAXFcOfoP+2wTySB6jdT01YwnVd6oCzF4OZPe8vx3uJs7Tr2AA
         BHWvE/iACKOkSi4/PddjRSGqztlhy7L1oXm6BV24qkQFNkfInJl+yy7MuE3H2lECDBkI
         LBldskOHaLr+0e6RE30VWBIGSZgv2QL9Bto01RRr9XrLg5IeDyJiGfSTkrIdY3NXtUi/
         4LAxvettLnnBcOjKwq1dtXx6NYucLiGv6+K7LjHODi8etgrljpQhwyODyAnl1mxyWbxD
         jJc8vGsJMjt6T7a2CjraWi9B1XrRT7HUYD3cFcNKIyvbSoXSHJdEA7CGDScX/By685yZ
         0wkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id v25si2415116edw.5.2019.09.16.08.57.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 16 Sep 2019 08:57:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.5]
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1i9tNU-0003lm-Nv; Mon, 16 Sep 2019 18:57:24 +0300
Subject: Re: [PATCH v3] mm/kasan: dump alloc and free stack for page allocator
To: Vlastimil Babka <vbabka@suse.cz>, Walter Wu <walter-zh.wu@mediatek.com>
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
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <4e76e7ce-1d61-524a-622b-663c01d19707@virtuozzo.com>
Date: Mon, 16 Sep 2019 18:57:23 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <6d58ce86-b2a4-40af-bf40-c604b457d086@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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

On 9/16/19 12:42 PM, Vlastimil Babka wrote:
> On 9/12/19 7:05 PM, Andrey Ryabinin wrote:
>>
>> Or another alternative option (and actually easier one to implement), leave PAGE_OWNER as is (no "select"s in Kconfigs)
>> Make PAGE_OWNER_FREE_STACK like this:
>>
>> +config PAGE_OWNER_FREE_STACK
>> +	def_bool KASAN || DEBUG_PAGEALLOC
>> +	depends on PAGE_OWNER
>> +
>>
>> So, users that want alloc/free stack will have to enable CONFIG_PAGE_OWNER=y and add page_owner=on to boot cmdline.
>>
>>
>> Basically the difference between these alternative is whether we enable page_owner by default or not. But there is always a possibility to disable it.
> 
> OK, how about this?
> 
 ...

> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index c5d62f1c2851..d9e44671af3f 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -710,8 +710,12 @@ static int __init early_debug_pagealloc(char *buf)
>  	if (kstrtobool(buf, &enable))
>  		return -EINVAL;
>  
> -	if (enable)
> +	if (enable) {
>  		static_branch_enable(&_debug_pagealloc_enabled);
> +#ifdef CONFIG_PAGE_OWNER
> +		page_owner_free_stack_disabled = false;

I think this won't work with CONFIG_DEBUG_PAGEALLOC_ENABLE_DEFAULT=y

> +#endif
> +	}
>  
>  	return 0;
>  }
> diff --git a/mm/page_owner.c b/mm/page_owner.c
> index dee931184788..b589bfbc4795 100644
> --- a/mm/page_owner.c
> +++ b/mm/page_owner.c
> @@ -24,13 +24,15 @@ struct page_owner {
>  	short last_migrate_reason;
>  	gfp_t gfp_mask;
>  	depot_stack_handle_t handle;
> -#ifdef CONFIG_DEBUG_PAGEALLOC
> +#ifdef CONFIG_PAGE_OWNER_FREE_STACK
>  	depot_stack_handle_t free_handle;
>  #endif
>  };
>  
>  static bool page_owner_disabled = true;
> +bool page_owner_free_stack_disabled = true;
>  DEFINE_STATIC_KEY_FALSE(page_owner_inited);
> +static DEFINE_STATIC_KEY_FALSE(page_owner_free_stack);
>  
>  static depot_stack_handle_t dummy_handle;
>  static depot_stack_handle_t failure_handle;
> @@ -46,6 +48,9 @@ static int __init early_page_owner_param(char *buf)
>  	if (strcmp(buf, "on") == 0)
>  		page_owner_disabled = false;
>  
> +	if (!page_owner_disabled && IS_ENABLED(CONFIG_KASAN))

I'd rather keep all logic in one place, i.e. "if (!page_owner_disabled && (IS_ENABLED(CONFIG_KASAN) || debug_pagealloc_enabled())"
With this no changes in early_debug_pagealloc() required and CONFIG_DEBUG_PAGEALLOC_ENABLE_DEFAULT=y should also work correctly.

> +		page_owner_free_stack_disabled = false;
> +
>  	return 0;
>  }
>  early_param("page_owner", early_page_owner_param);
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4e76e7ce-1d61-524a-622b-663c01d19707%40virtuozzo.com.
