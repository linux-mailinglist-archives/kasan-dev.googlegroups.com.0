Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBL4T26HAMGQEWVYQ2RQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A8D24856BF
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Jan 2022 17:39:12 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id s30-20020adfa29e000000b001a25caee635sf12796739wra.19
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Jan 2022 08:39:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1641400752; cv=pass;
        d=google.com; s=arc-20160816;
        b=X2IxPFQm0rHPMGQJxdvluqrfVz3CMvHT+UZ52WsQcIbcdM0ccolHidhWLWZIjxuD2E
         8vyVYhF12n6/Q0kfBvFYpWOyCGeo6nZWbe0NKA0p+UbZJo1++xzvWoMroRZLrdM12cWp
         6lMu6SB0TSMSVp1auYA9qiiyBwXqjzxaiApiK5OCfcZPQky7R3DAI4lVcj7r+pTzESWw
         MMiKMM1yv2w5GA1Vdu1Bv9Q9IG3AelQoVYyhrUH0u30nrf2Zgymz1NiM6h+YRWyirzij
         5uYrtmwqjNFPwyQB+YGGJ516qel+dH6tKQCT7FN17BLJb+qkT/pvgKcPTXXYZOZ/9ctp
         +H5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=5zejTGsrEMdGYlk8jRFSOyhN0yGaoFVKZNyO03noMdo=;
        b=VXGIq5acSif+669gGYSwe8q/oxRgAGLUrlTOsMTM/+gjwU6LOVa6t2R4Sa5cO9rkDm
         3CJ2UV1t5tKq/0ZcEe25F7/cj+vdiuypVWNEq20+QMjDIKwaFAInoEtt0FiSJJ+Y1Vqj
         DHYfXKkfAKL6uuE9bCgUmpLa8Ln2cKoUhdf7fzsfQcZVY/cuLts2vOpRsxmd9AAzUR92
         1i5bUvumToPcSYtYN50PKZNJL5674S97og61e0nYnYieVcGlnF37TlSU/SeJpQDS8iBE
         mFi+nVTNVaNas77+vp55H66gCpXC+r11zkJm16R3H6bQmnQ96rvLnnDgs5CZ5k+DHHiR
         Fgxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=NRsZKCZi;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=A7c4TZBO;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5zejTGsrEMdGYlk8jRFSOyhN0yGaoFVKZNyO03noMdo=;
        b=lte3VHMAifjIYFdmd0j5LIyBnCEiSjRspmJlTd+PAoQkkJTEAlm4LR4V7MaFFF/quv
         n4NR1ypjblEwAiVe8aEv20bYQZs6J7D3S/UqoDNECc7X9hAuetxkls3bn5zf6HdbwWlC
         o33J/HlQD7tycGYnDjK+Xdd4GqMFDcY3TryzpFUUOlAHqQhyqVn7HMqlPZ0k6l72kfSG
         Ny5rhQGnTqTOnmyE3msgVZvPPi9pLV9rIUHhUayvDkTghES79gCBPdLq4Omxi2zpaado
         LalP4GWYG23D2HaaGJeSkpeu/zGjCF39ApfdNsm7NA7C0Hx5xou5maRVzVZ4vyWxnksC
         XX0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5zejTGsrEMdGYlk8jRFSOyhN0yGaoFVKZNyO03noMdo=;
        b=WIDYAsnngYeAlxL5Q/XqJt2PSdXglKAi5QBPmDhQSSswalIYi9vWMr0FBEURYV06SB
         XkA0gQHIo+4+Zk9i25A7OQbyMSV2j0m1FnM0Mujmr3WYjw+f6ZIaXUgxErhe1pHVYsQG
         bdLGv+lDtSXhObApqoeNUzW/We5sjXj+x3qYjcV67/VgMdJRLh+hAOrOU/67h3J6dLOZ
         MyMH0PILEXIDOgP14lQ3JW23WFkXpITlGxqt6Uehaq6BQSndQ2gyafA88dzZIstBv3MB
         +vb9+4Q4HR3qMKMNwUL0rFi3umej1CSjn6+7U2Q6Dm6RhvLQZOi4R/X1KZwtbbExcsIN
         LI/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532JyJPl92J2XL/ITc/YnWGwNbqffM5p+08WdHtwv+WLq/mUzELQ
	U85bcmu+r4OCS5NiFRuxQ1Y=
X-Google-Smtp-Source: ABdhPJxy18Lm39wG5ldWuyFWjV4d3d1taf+9NK9guRKh0KqjfCEylvZ0RotsHD73zrzpP2WMIi69lQ==
X-Received: by 2002:a5d:6f1e:: with SMTP id ay30mr1789545wrb.498.1641400751936;
        Wed, 05 Jan 2022 08:39:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a4cc:: with SMTP id h12ls37946wrb.2.gmail; Wed, 05 Jan
 2022 08:39:11 -0800 (PST)
X-Received: by 2002:adf:ec8b:: with SMTP id z11mr47974864wrn.378.1641400750999;
        Wed, 05 Jan 2022 08:39:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1641400750; cv=none;
        d=google.com; s=arc-20160816;
        b=u7Vis4DgUAgzp6GNu0tHOn2dTx1YhYBu0On78EmRvh55Zr87dd/5+ABQzY7Qn7S72E
         oafsxUzwlGydtLVme0jYArDfskbyhCsTcooaRivJ0jJ/7YA16wNHgHJzLuhYp09IvETo
         tl5rAh+/mflhLJHATuVtjYNI4TqSuA1d9NDqtjON+SMUabO7hhKjmIg0O7kaIL/uEtHG
         LNDTMjzMZJ6EC5Si/pXRmWI5WA7rBa388jE9UlU272yw9ZMqXS6Vu05kNCTH66+byEnf
         kU/HppuIidCrNbXVTt/rFGCztJCfehybb9X/I4sFZ0FszWnzcfO+ty/NvXm/w9SCAmF+
         ZbNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=671oRtpp5WCs8Fk9Hz2g9PU50UrRMSTbK7reBDGjtCs=;
        b=dwbM/e1kQWKIcE8VjrkAIaMXZybgkWscVA3hO1BcFLYoFQpxfEu6C3BP2PxNZ5QO7t
         fbEkzChtNxWmSATiPKpC5r18480p9WiJuB1FzG0XFgz0uW/1EkSBLxeTs4Q4HzVeNOC5
         smdUJo1jYq4pKn4IN6qQhRl5mFgRleMcOUnBxM41d7hWQS+j75W31birpcndFs7HGPyz
         22aO8Ugbk9dD505yGEgqxZPWtIuIP9jbFSlEZ6SiJaJO4Bh/qL9xEa2rj3RPfABOGtEB
         L+m+HH7DsbHRike+zFyGXZNiEDtqpN/cqmJW2uAbv/XitoX7LxzXG5x4gVoEn4mI88be
         DYHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=NRsZKCZi;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=A7c4TZBO;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id l19si310553wms.3.2022.01.05.08.39.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Jan 2022 08:39:10 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 9B75F1F37F;
	Wed,  5 Jan 2022 16:39:10 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 5418C13BF8;
	Wed,  5 Jan 2022 16:39:10 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id 7jnnE67J1WGcEAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 05 Jan 2022 16:39:10 +0000
Message-ID: <d49a5ea1-3592-3db2-24d5-e274be880e35@suse.cz>
Date: Wed, 5 Jan 2022 17:39:10 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.4.1
Subject: Re: [PATCH v4 22/32] mm: Convert struct page to struct slab in
 functions used by other subsystems
Content-Language: en-US
To: Roman Gushchin <guro@fb.com>
Cc: Matthew Wilcox <willy@infradead.org>, Christoph Lameter <cl@linux.com>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Pekka Enberg <penberg@kernel.org>, linux-mm@kvack.org,
 Andrew Morton <akpm@linux-foundation.org>,
 Johannes Weiner <hannes@cmpxchg.org>, Hyeonggon Yoo <42.hyeyoo@gmail.com>,
 patches@lists.linux.dev, Andrey Konovalov <andreyknvl@gmail.com>,
 Julia Lawall <julia.lawall@inria.fr>, Luis Chamberlain <mcgrof@kernel.org>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Marco Elver <elver@google.com>, Michal Hocko <mhocko@kernel.org>,
 Vladimir Davydov <vdavydov.dev@gmail.com>, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
References: <20220104001046.12263-1-vbabka@suse.cz>
 <20220104001046.12263-23-vbabka@suse.cz>
 <YdT+qU4xgQeZc/jP@carbon.dhcp.thefacebook.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <YdT+qU4xgQeZc/jP@carbon.dhcp.thefacebook.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=NRsZKCZi;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=A7c4TZBO;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 1/5/22 03:12, Roman Gushchin wrote:
> On Tue, Jan 04, 2022 at 01:10:36AM +0100, Vlastimil Babka wrote:
>> --- a/mm/kasan/report.c
>> +++ b/mm/kasan/report.c
>> @@ -249,7 +249,7 @@ static void print_address_description(void *addr, u8 tag)
>>  
>>  	if (page && PageSlab(page)) {
>>  		struct kmem_cache *cache = page->slab_cache;
>> -		void *object = nearest_obj(cache, page,	addr);
>> +		void *object = nearest_obj(cache, page_slab(page),	addr);
>                                                                   s/tab/space

Yeah it was pointed out earlier that the tab was already there but only this
change made it stand out. Fixing that up here would go against the automated
spatch conversion, so it's done in later manual patch that also touches this
line.

>> 2.34.1
>> 
> 
> Reviewed-by: Roman Gushchin <guro@fb.com>
> 
> Thanks!

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d49a5ea1-3592-3db2-24d5-e274be880e35%40suse.cz.
