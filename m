Return-Path: <kasan-dev+bncBCKLZ4GJSELRBY7E3KXAMGQEAN6PJMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 67A7685EF25
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Feb 2024 03:33:09 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-4127b4d6616sf2016955e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 18:33:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708569189; cv=pass;
        d=google.com; s=arc-20160816;
        b=gohlKCvVt4Z7nt+JL44qhRccbyhFINBh90ZlVTRLdAY5EoW4hyIilXeD+kl/DUFKOp
         /X3m0ffV8a6JU1sEuk1DuHHprtE39z0zxj9S4fqjXhYCjEHgNygZz8yHCkx30ry6QARc
         jzhpJJ+r2bJZtZMccTa9T8HJK+sN2WX3ZSkoxjYYIlOxz3XONFJ+xsADZQddu9TUU/i8
         LVDLbjOV0j7S/BRRJYCOKnBtiMyfLxg7DpclyigeoZ9YlEpyLGIo+o+J8m4RtFbEzPYW
         6KnHcSQpQ4AVT1jdgkw/vyP2J7oKC6ImF2wGXpnRAl5Db0VInl2+dETCY2DkM72Xh3/Y
         3V0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:message-id:sender
         :dkim-signature;
        bh=y72f1qaAYhRvr2yRz00LmeCEThN9QhqVs8bWoBc4pYo=;
        fh=TI+ZV1MTOIOSqQ2sRBQtsIDqOXJAQSjxwShpQJm2zAQ=;
        b=G+alaROUDHVaAv5Q0ug7QC6SldksbETv12bYgf2r3rQFueCsZxcSm6aeY1At5RwHwb
         bCHaINYm1nBNujwbe7/uUK77S51XwRpGH0SxdFnw5WgMefer8NULpPIO9JiB1UbxnWux
         ZS8XTMTyhUXXaSQiPS9V9GnOwk1zOgMxGTg/1TUkdsdnNqRRPv7jInhbMA/ggINzc4nZ
         BY9GMqLhUsAARTalYmYrs940b5UmhqTVRyKula6VN+wKppnCp4s8Coh6TbBW+/KhiO66
         NavqIocgyg4jfSIg4pBrdW3/BnJdLmwMkgVEJ9mCU/2mjbT6YR0LvlI6bkBY8NSLzzAD
         Jbwg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=WKipzrUZ;
       spf=pass (google.com: domain of chengming.zhou@linux.dev designates 2001:41d0:1004:224b::b3 as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708569189; x=1709173989; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:message-id:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=y72f1qaAYhRvr2yRz00LmeCEThN9QhqVs8bWoBc4pYo=;
        b=PZJyQ51niVVP+cJHHbUvwrW9C9ycnGF3g8FL/FobtQ7uuvQYeG/71n6m2NAHOPhhTu
         IY+JNAjhoUHFOiUr5i2XmYKAOfgPRgWpTYRTXbxox2q1HNE3fqhN5qOlm9MUeO1oAuTg
         aseSw73ZHMSfMCzabYfbk8td+R1CxvT9qE4wn2Im2GXGWREkSyQVpsZux4v2Izz21vTw
         8B5+E0Mp40ykUHZ0vKPXNql3ZWpIGCO3zqzuEXMlfZaKJuVfXRgTYX8ghDSbaB6zhPoP
         y/aie244EKxWafbgmlGgINFJUYJRkrIzXYvz7NflgxngAQ/u/sP0nL8ToOH8tQVqEl40
         5yXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708569189; x=1709173989;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=y72f1qaAYhRvr2yRz00LmeCEThN9QhqVs8bWoBc4pYo=;
        b=vP4Eo8eELpHaSdD/McrPqFnUc6fdZaj+xbI3uIRlBVKED+XXiPwSr8t8+bBgA2lCiQ
         fxacfenoetOahJK2TfILA3/a25t22XgterjcFqVy2w8aQwOdHtJYulMGRXknIUY34Ab0
         lpP1XgExWRfC/Orv4urYlQ8YYbEFcI1p/TW3UXuuA1n7sj+Tul0l8ICkR0Sf7WggXv3F
         JpUvGPYUtrS7vITbYkwIFSa9/JyRnsUVt0mqHOTNz2XCImOeuCUJpkOHmXLv4M3kYf2n
         IaMB485cA5qAFCNampX0Hr7RGB0Iu/F9RmiSFBc/9qiZuyoQ7VHO3N+NDOt7wFjBhj31
         8OuQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU8Uf8KdeKKIQJ7f7R8iMqrBxWfZ5O+29o3ZmggMP/5EnuRFlTprSL2A+Wl2MdUwCRn86vjUujpHcU1RMZfaoGbxPbDvstHow==
X-Gm-Message-State: AOJu0YxakqPF0505V6ZZ5zWkZRfeD1HZPS9TPyqiMFtcKPB2gM2BnuDx
	3CJJj7WL8py/lOrO8iQfKEhMnuPEAFBZUQipwCPDrjvjHuoTFwtb
X-Google-Smtp-Source: AGHT+IEG9l1iT2h5vNCldXpnh9Qs35C5tJe4lvw7ePOEHe/kT8uS9BOUgELXx+lNMGgooDxX9gpiKQ==
X-Received: by 2002:a05:600c:1c10:b0:412:6cc7:6938 with SMTP id j16-20020a05600c1c1000b004126cc76938mr4999615wms.8.1708569188126;
        Wed, 21 Feb 2024 18:33:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3485:b0:412:794d:9668 with SMTP id
 a5-20020a05600c348500b00412794d9668ls394096wmq.0.-pod-prod-02-eu; Wed, 21 Feb
 2024 18:33:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWoBC25X3GcHTJx63KuNg1oZY5iYb54iChr/G7pjzXCfTLXpUcw/mcc/7lRxqa4fBtqb7L9kL0Nog9p64W0vV+7EEmbmETHUigcXw==
X-Received: by 2002:a05:600c:4746:b0:412:7012:ee14 with SMTP id w6-20020a05600c474600b004127012ee14mr4071031wmo.0.1708569186223;
        Wed, 21 Feb 2024 18:33:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708569186; cv=none;
        d=google.com; s=arc-20160816;
        b=fC17hhk/zwAJk6nWhf4kRjLvovC5VZqDn7//QNENt8NP07t0EDaBx1uHQDUAF9uRSo
         2MmeGqACAeTCjR+QO0iaZxORHGUmdjhNyLlw8QvUmiTzCGgNgRRWbF5hEZrLvf8/b3vU
         1VBX5g/KWKVsfSt3wU/0tTOxYX6702euIP0HuQpC9rZWblNT5g8hM6t2GllDbOSRlo5J
         vRKU/O1ZlE+Otg/8nSo7d73ufWmlzrN6B/mnbBv7J6UZDhZQlnXL//5TkmG+lr5+TVNl
         nDIYLoLCjswuEY8D33ouuXVQ0GGD+IghCdROS52Xlc1gdx6toVr7cTAC6dsALC+1ODVa
         SKAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:dkim-signature
         :message-id;
        bh=1Lcomib2YoDBqz/0vjugx8QRFaaeaSrpG+g/RGvt17I=;
        fh=XBL6PZVWe9BWquhBWjE7SZ4EkrEvp3N021xQH0jSOCM=;
        b=B+QyNUxV/3mnKZeTtG3n83695DNCWteRw6fNiO2Cp++kn7wdMNM/1FyA49Cv15zm1v
         wzThIXmTf5oamg2OBVJQ1KYtTWOGSZB/XWmMUF6f8/HTPbaNzwJCjv9/SuSw4fx30Y3l
         cAnD8owg9bbrgtAhCIRmim7YiuqN6DfGOqp/sdmKv2JkTGCdDYczBHAekggmReL7C1DD
         WUPZmg3w3BrsJDl2eoQxHJVMYrHwUHCMIMZZuqIlHMOBZ2UX6WsHor/LFkmUI8+trlvC
         AfMxidBIxtdQmdDxUVyDm0WRkDdnn9tT6Z0fG7bkQxfCudXU8ZZtRsU3sHAhoSFYMmKw
         6TaA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=WKipzrUZ;
       spf=pass (google.com: domain of chengming.zhou@linux.dev designates 2001:41d0:1004:224b::b3 as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-179.mta0.migadu.com (out-179.mta0.migadu.com. [2001:41d0:1004:224b::b3])
        by gmr-mx.google.com with ESMTPS id l13-20020a05600c4f0d00b004126ebe1087si81148wmq.1.2024.02.21.18.33.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Feb 2024 18:33:06 -0800 (PST)
Received-SPF: pass (google.com: domain of chengming.zhou@linux.dev designates 2001:41d0:1004:224b::b3 as permitted sender) client-ip=2001:41d0:1004:224b::b3;
Message-ID: <7e27b853-e10f-4034-bc81-2d5e5a03361a@linux.dev>
Date: Thu, 22 Feb 2024 10:32:56 +0800
MIME-Version: 1.0
Subject: Re: [PATCH 1/3] mm, slab: deprecate SLAB_MEM_SPREAD flag
Content-Language: en-US
To: "Song, Xiongwei" <Xiongwei.Song@windriver.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Vlastimil Babka <vbabka@suse.cz>
Cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Zheng Yejian <zhengyejian1@huawei.com>,
 "linux-mm@kvack.org" <linux-mm@kvack.org>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 Steven Rostedt <rostedt@goodmis.org>
References: <20240220-slab-cleanup-flags-v1-0-e657e373944a@suse.cz>
 <20240220-slab-cleanup-flags-v1-1-e657e373944a@suse.cz>
 <ZdZBN_K8yJTVIbtC@P9FQF9L96D.corp.robot.car>
 <CO1PR11MB51854DA6F03753F12A540293EC562@CO1PR11MB5185.namprd11.prod.outlook.com>
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Chengming Zhou <chengming.zhou@linux.dev>
In-Reply-To: <CO1PR11MB51854DA6F03753F12A540293EC562@CO1PR11MB5185.namprd11.prod.outlook.com>
Content-Type: text/plain; charset="UTF-8"
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: chengming.zhou@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=WKipzrUZ;       spf=pass
 (google.com: domain of chengming.zhou@linux.dev designates
 2001:41d0:1004:224b::b3 as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On 2024/2/22 09:10, Song, Xiongwei wrote:
> Hi Vlastimil,
> 
>> On Tue, Feb 20, 2024 at 05:58:25PM +0100, Vlastimil Babka wrote:
>> 0;95;0c> The SLAB_MEM_SPREAD flag used to be implemented in SLAB, which was
>>> removed.  SLUB instead relies on the page allocator's NUMA policies.
>>> Change the flag's value to 0 to free up the value it had, and mark it
>>> for full removal once all users are gone.
>>>
>>> Reported-by: Steven Rostedt <rostedt@goodmis.org>
>>> Closes: https://lore.kernel.org/all/20240131172027.10f64405@gandalf.local.home/
>>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>>
>> Reviewed-by: Roman Gushchin <roman.gushchin@linux.dev>
>>
>> Do you plan to follow up with a patch series removing all usages?
> 
> If you are not available with it, I can do.

Actually, I have done it yesterday. Sorry, I just forgot this task. :)

I plan to send out it after this series merged in the slab branch. And
I'm wondering is it better to put all diffs in one huge patch or split
every diff to each patch?

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7e27b853-e10f-4034-bc81-2d5e5a03361a%40linux.dev.
