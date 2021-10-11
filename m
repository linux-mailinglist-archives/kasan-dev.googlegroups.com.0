Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBIW4SGFQMGQE52KEWSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 489B342951C
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 19:02:27 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id i40-20020a0565123e2800b003f53da59009sf13235990lfv.16
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 10:02:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633971746; cv=pass;
        d=google.com; s=arc-20160816;
        b=xXius5fiQU9g/vTZ7N245B01opDWDMvjRMBx9nxYm4p/0yot16doupeUW8kx/xnx9T
         W/G+ENOtLoXshOlG/t7+oj7LuFSwhtG16NuL/JLl29uIkgmTWM3WbRwDFq/VtuQmaBNh
         rXom1//VJjCnTNx0FL+BfVgzoBb1O+6x00imKuVKTE4OLHFzHyMTK7o2ktezf9UvuMl2
         gOvSgdzDFnnuwGU49VqbuLn7hjJrRVNSYfX0nIqcoyw0EHgfqSb8i5yT6In33przdC1L
         o5OX6lwbEGw0EvMc4T4+Tfb0Uv5T/vcX9hKR4qUeSFH8D8MOTndNsBVNUX51cEbmffGp
         1owA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:subject:from:references
         :cc:to:content-language:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=xzNg73Zo11yKYppzU4e/Z24x1HPx4kENwmPGaLWHYUA=;
        b=ZWSTkIaLfHorzdSG8w7i4rTh9q7X5M6KcOMAm/blwUwAk80rOK1osWNrkCgQ4gr6hJ
         5bPBqI5l8YqB190YF61vuaeN3Gon8EspYIHnRQpdbXC9hu8jcW7dNmf/jS4JplNHu0jN
         bHumTODpf+MUqg4ZyvBjbg+Kl1pVD7nyn+2eWVLQSGdNPFs3o+7fzn8/PBjtRbXbGmbz
         EHP/bqTx4cwBGn+C54OU2/7In0aam19lAj8/cHtO+T/ZW9J0qCaR/CEYq4sGZbTuhOME
         QJ/gOPxKwILUJ2RjtfMFkRCnp5VhrKnkFp2aRA1MRuzPbuGdshdoan4+nNcOZHHL0I2i
         MAUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=b7iLr7up;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:content-language:to
         :cc:references:from:subject:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xzNg73Zo11yKYppzU4e/Z24x1HPx4kENwmPGaLWHYUA=;
        b=XOqra2UzecxR2Ol2KPVHivnstNo1Y7GNtgdKRcsa426sSjs9MYtbDTYbNsNCwuCyNm
         Qo+rj4MF72/o67sqU8syTCEpSQ9uCFLit6QEIrRtTaynxsFjuoqeaQ9jJfPNGqwRHCir
         SgUh3ta6BkFpk8xikmMf76V+nw7zosU+dIDiipwLUpPpwVmJ95p/PMtHLKdnQfNOjtQj
         3Fr5/yrtp59fiBB3tN1sHr/hWGnw+daZyhTVhEaMWv12edA2BkcqwSLKWFejKT3ctkMF
         AwRbDYdYSdEtY1k4vucEGbS6yw+G+wLhD0tXVb1/mjJ0IO1HinI1CzNiraUKU035+V5d
         MPGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :content-language:to:cc:references:from:subject:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xzNg73Zo11yKYppzU4e/Z24x1HPx4kENwmPGaLWHYUA=;
        b=7CA+gdaT3vwoVewWsDD0zT+NFT0DGeputJhJd/RN2H61l8NQO3YIHAZG3WqtUygRL/
         IM+HJHcqoLOdVPb32Yqa6nlOi6GuWM3UhQJsOBkeyerTlo+qLtzj51Yo62WpV1IQvdAr
         Bp4Kt2xe7ptRI1xEPMWBVaDi4ocklGhrx6hrlJw/qn3vPF6jC3TPat9j1ROOGd8r6Lpy
         neUkrxkrv5gkLEqwkkEACxEUJTQJDfJmrhzVU0GDhlMwCGjFuNYGC5kvq9m7KfGoIh+H
         6zeHr47lyS58OAQ/oNF/L69x9iVr6DbPGscSHlvREum3RQ8pex04kHy1ww0kXWVRB6rl
         kDOw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530leirsvKg9/DXtYkVT5H1Eqpx+XOMUvWEe0KOgDkHHA6yLjSwI
	HpD0NisncEUGgOoEZvJDJrM=
X-Google-Smtp-Source: ABdhPJxXaiSPIv29Ib+uQVAcfRE5Kxf1JmFpenBs7H7mFmcY8aKgcpq92uXKg8XbY/hFhmQnEjGrJQ==
X-Received: by 2002:a2e:81d6:: with SMTP id s22mr18683544ljg.128.1633971746839;
        Mon, 11 Oct 2021 10:02:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3499:: with SMTP id v25ls740039lfr.0.gmail; Mon, 11
 Oct 2021 10:02:25 -0700 (PDT)
X-Received: by 2002:a05:6512:128a:: with SMTP id u10mr29083899lfs.84.1633971745735;
        Mon, 11 Oct 2021 10:02:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633971745; cv=none;
        d=google.com; s=arc-20160816;
        b=N90YYywQxRheqWHRPB35CWWl447LtdI+kpdkc92IgGtjbCsJ1w5ibVEPOhemDMacpQ
         Fytc1fOvuHZuPYkyJMY1NI3Wbybl+hvXfRY+JzjXr3Rd74ukpSxRpy4vwELo0deTckQw
         LteStn5h032xromBYFsLydE8YIJvnEHrGhMYO/c0mJDM9+Op6CQlberkgiTg5bwNLg0D
         wvKculVZKUhqzIt3J0y77DFro6RtYmji5G8Vdm11cdKFRpZ39CMen/mOf2RRyCHMQuGD
         3THQ5Ib96n0bMn8iKpiheJBUZywu1P5BBl105X033kcYppcUA4jS+Ss23aiIUAssjIgv
         jnYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:subject:from:references:cc:to
         :content-language:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=4jY518LLN0DEflKAEIOoiJENNbC5tBQaKEI9hO0rfaU=;
        b=SHvrhdFdKpisaidxrxq/pUfta/+bSLW0t3k6idsTHWW0TwThmuz35dwe4Y5E2v5H5q
         sExhu15isqdi2ERAMweg2JTx+ApK4SG4SmUbYEZt5YBnTSET4ffbnI6mZ38Fi/zqN4ec
         Teyf0Bvmo8wqoYwGHrNuFBNS/cZEjpJc4/gjT7TRxiRGtPup4LONtlpKLlwgE7edeUzG
         cDH5smwnxpQWSkCuDrA6umXfBUtOoCy9/agvY2qWPmq76X36eaCz1ir8ZdSIfvOQTiv6
         0PGdYR3sPH+WEm56+UOAgL8nlrRXfmZV3QvE2denlhsfYblvMsRpMExszkoWONRfVqZv
         aXEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=b7iLr7up;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id b25si529886lfv.9.2021.10.11.10.02.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Oct 2021 10:02:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 0AFC022007;
	Mon, 11 Oct 2021 17:02:25 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id B16C513BCE;
	Mon, 11 Oct 2021 17:02:24 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id MAS1KSBuZGEcfwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 11 Oct 2021 17:02:24 +0000
Message-ID: <2a62971d-467f-f354-caac-2b5ecf258e3c@suse.cz>
Date: Mon, 11 Oct 2021 19:02:24 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.2.0
Content-Language: en-US
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, dri-devel@lists.freedesktop.org,
 intel-gfx@lists.freedesktop.org, kasan-dev@googlegroups.com,
 Vijayanand Jitta <vjitta@codeaurora.org>,
 Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
 Maxime Ripard <mripard@kernel.org>, Thomas Zimmermann <tzimmermann@suse.de>,
 David Airlie <airlied@linux.ie>, Daniel Vetter <daniel@ffwll.ch>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Geert Uytterhoeven <geert@linux-m68k.org>, Oliver Glitta
 <glittao@gmail.com>, Imran Khan <imran.f.khan@oracle.com>
References: <20211007095815.3563-1-vbabka@suse.cz>
 <YV7TnygBLdHJjmRW@elver.google.com>
From: Vlastimil Babka <vbabka@suse.cz>
Subject: Re: [PATCH] lib/stackdepot: allow optional init and stack_table
 allocation by kvmalloc()
In-Reply-To: <YV7TnygBLdHJjmRW@elver.google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=b7iLr7up;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/7/21 13:01, Marco Elver wrote:
> On Thu, Oct 07, 2021 at 11:58AM +0200, Vlastimil Babka wrote:
> [...] 
>> - Add a CONFIG_STACKDEPOT_ALWAYS_INIT flag to keep using the current
>>   well-defined point of allocation as part of mem_init(). Make CONFIG_KASAN
>>   select this flag.
>> - Other users have to call stack_depot_init() as part of their own init when
>>   it's determined that stack depot will actually be used. This may depend on
>>   both config and runtime conditions. Convert current users which are
>>   page_owner and several in the DRM subsystem. Same will be done for SLUB
>>   later.
>> - Because the init might now be called after the boot-time memblock allocation
>>   has given all memory to the buddy allocator, change stack_depot_init() to
>>   allocate stack_table with kvmalloc() when memblock is no longer available.
>>   Also handle allocation failure by disabling stackdepot (could have
>>   theoretically happened even with memblock allocation previously), and don't
>>   unnecessarily align the memblock allocation to its own size anymore.
> ...
>> Hi, I'd appreciate review of the DRM parts - namely that I've got correctly
>> that stack_depot_init() is called from the proper init functions and iff
>> stack_depot_save() is going to be used later. Thanks!
> 
> For ease of review between stackdepot and DRM changes, I thought it'd be
> nice to split into 2 patches, but not sure it'll work, because you're
> changing the semantics of the normal STACKDEPOT.

Yeah, that's why it's a single patch. As the DRM parts are clearly separated
to their files, I think review should be fine.

> One option would be to flip it around, and instead have
> STACKDEPOT_LAZY_INIT, but that seems counter-intuitive if the majority
> of STACKDEPOT users are LAZY_INIT users.

Agree.

> On the other hand, the lazy initialization mode you're introducing
> requires an explicit stack_depot_init() call somewhere and isn't as
> straightforward as before.
> 
> Not sure what is best. My intuition tells me STACKDEPOT_LAZY_INIT would
> be safer as it's a deliberate opt-in to the lazy initialization
> behaviour.

I think it should be fine with ALWAYS_INIT. There are not many stackdepot
users being added, and anyone developing a new one will very quickly find
out if they forget to call stack_depot_init()?

> Preferences?
> 
> [...]
>> --- a/drivers/gpu/drm/drm_mm.c
>> +++ b/drivers/gpu/drm/drm_mm.c
>> @@ -980,6 +980,10 @@ void drm_mm_init(struct drm_mm *mm, u64 start, u64 size)
>>  	add_hole(&mm->head_node);
>>  
>>  	mm->scan_active = 0;
>> +
>> +#ifdef CONFIG_DRM_DEBUG_MM
>> +	stack_depot_init();
>> +#endif
> 
> DRM_DEBUG_MM implies STACKDEPOT. Not sure what is more readable to drm
> maintainers, but perhaps it'd be nicer to avoid the #ifdef here, and
> instead just keep the no-op version of stack_depot_init() in
> <linux/stackdepot.h>. I don't have a strong preference.

Hm, but in case STACKDEPOT is also selected by something else (e.g.
CONFIG_PAGE_OWNER) which uses lazy init but isn't enabled on boot, then
without #ifdef CONFIG_DRM_DEBUG_MM above, this code would call a
stack_depot_init() (that's not a no-op) even in case it's not going to be
using it, so not what we want to achieve.
But it could be changed to use IS_ENABLED() if that's preferred by DRM folks.

BTW it's possible that there won't be any DRM review because this failed to
apply:
https://patchwork.freedesktop.org/series/95549/
DRM folks, any hint how to indicate that the base was next-20211001?

>> @@ -30,13 +40,4 @@ int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
>>  
>>  void stack_depot_print(depot_stack_handle_t stack);
>>  
>> -#ifdef CONFIG_STACKDEPOT
>> -int stack_depot_init(void);
>> -#else
>> -static inline int stack_depot_init(void)
>> -{
>> -	return 0;
>> -}
>> -#endif	/* CONFIG_STACKDEPOT */
>> -
> 
> Could we avoid the IS_ENABLED() in init/main.c by adding a wrapper here:
> 
> +#ifdef CONFIG_STACKDEPOT_ALWAYS_INIT
> +static inline int stack_depot_early_init(void)	{ return stack_depot_init(); }
> +#else
> +static inline int stack_depot_early_init(void)	{ return 0; }
> +#endif	/* CONFIG_STACKDEPOT_ALWAYS_INIT */

We could, but it's a wrapper made for only a single caller...

>>  #endif
>> diff --git a/init/main.c b/init/main.c
>> index ee4d3e1b3eb9..b6a5833d98f5 100644
>> --- a/init/main.c
>> +++ b/init/main.c
>> @@ -844,7 +844,8 @@ static void __init mm_init(void)
>>  	init_mem_debugging_and_hardening();
>>  	kfence_alloc_pool();
>>  	report_meminit();
>> -	stack_depot_init();
>> +	if (IS_ENABLED(CONFIG_STACKDEPOT_ALWAYS_INIT))
>> +		stack_depot_init();
> 
> I'd push the decision of when to call this into <linux/stackdepot.h> via
> wrapper stack_depot_early_init().

No strong preferrences, if you think it's worth it.

>>  	mem_init();
>>  	mem_init_print_info();
>>  	/* page_owner must be initialized after buddy is ready */
>> diff --git a/lib/Kconfig b/lib/Kconfig
>> index 5e7165e6a346..df6bcf0a4cc3 100644
>> --- a/lib/Kconfig
>> +++ b/lib/Kconfig
>> @@ -671,6 +671,9 @@ config STACKDEPOT
>>  	bool
>>  	select STACKTRACE
>>  
>> +config STACKDEPOT_ALWAYS_INIT
>> +	bool
> 
> It looks like every users of STACKDEPOT_ALWAYS_INIT will also select
> STACKDEPOT, so we could just make this:
> 
> +config STACKDEPOT_ALWAYS_INIT
> +	bool
> +	select STACKDEPOT
> 
> And remove the redundant 'select STACKDEPOT' in Kconfig.kasan.

Right, will do, if KConfig resolver doesn't bite me.

>>  config STACK_HASH_ORDER
>>  	int "stack depot hash size (12 => 4KB, 20 => 1024KB)"
>>  	range 12 20
>> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
>> index cdc842d090db..695deb603c66 100644
>> --- a/lib/Kconfig.kasan
>> +++ b/lib/Kconfig.kasan
>> @@ -39,6 +39,7 @@ menuconfig KASAN
>>  		   HAVE_ARCH_KASAN_HW_TAGS
>>  	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
>>  	select STACKDEPOT
>> +	select STACKDEPOT_ALWAYS_INIT
> 
> [...]
>>  
>> -int __init stack_depot_init(void)
>> +/*
>> + * __ref because of memblock_alloc(), which will not be actually called after
>> + * the __init code is gone
> 
> The reason is that after __init code is gone, slab_is_available() will
> be true (might be worth adding to the comment).

OK

Thanks for the review!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2a62971d-467f-f354-caac-2b5ecf258e3c%40suse.cz.
