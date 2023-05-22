Return-Path: <kasan-dev+bncBAABBVO5VSRQMGQECDXKD3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id EFF8770B831
	for <lists+kasan-dev@lfdr.de>; Mon, 22 May 2023 10:59:02 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id 5614622812f47-39085e131dfsf2542715b6e.1
        for <lists+kasan-dev@lfdr.de>; Mon, 22 May 2023 01:59:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684745941; cv=pass;
        d=google.com; s=arc-20160816;
        b=PoWrGxKj5wW6a/UpvNEdIqzLgXMtzf1K9vZpgyn7EE4KkzBq4yTz3DtgadZbNc/igv
         miLaLa59aBL/BW1fUjNxPWbcqldP0DdesBqKjY3HNbh+GH8eYFeboV3YWmbotrnSZfUL
         kgeA3hra50MwWURA7O1+HooT1GYVDWlCVEgKNSNoa0dBDR6IAy/BaWm9s+PsVcQBvrkH
         oJBMAMy9/PrfBvpLKOoEWN44wJS9zPno6WnvV3RTlSfdiAoEWUocNTMFWzFHWifairgT
         T62quVx6RWOZe/t9QlYtnSa6mfSQxPvttnUiZfA+wdnhmSyLNZPaN4YJYm3HqSoubxFX
         CYvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=vE9HterktgMYG1jGA4fUIM9e+PCQIFyDSNjOg6ZEURw=;
        b=Nh58YTJIw1ykG5LULNxTJcxwFSTRRZ8Dcmy3ZHbghhcj/l/XP7JLoGymrbfsp+ts+r
         jyEmtOHo+BlM812ipB5flufj4+iSQktja/EedlK2KLRvswfMUN71CNlsruaCQWuB9f6s
         0TM8os3Z64W4OuwoCjzmnUEeK3g3+FcbGcWuUu/OpvEb1ECr+NtsjS73WslbHiV5/ODy
         q+VKgKAteb8NkUyZ+4NgAeZN1tL+eW7w1pvYiEL1wvY1rxfNGGQ6nky1RQ8odrfFwa2y
         OlBjYVLjCJvGXPpbJwcI9c5OFlLY3HzUzYBE4aTS5M7GV+rjj8O6Fwg4NMj3/KAvHdvQ
         /DLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of gongruiqi@huaweicloud.com designates 45.249.212.56 as permitted sender) smtp.mailfrom=gongruiqi@huaweicloud.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684745941; x=1687337941;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vE9HterktgMYG1jGA4fUIM9e+PCQIFyDSNjOg6ZEURw=;
        b=oU7MuQXRCJOLKz9ecC3Kqerui4km14nQhLLvmQy5OVD9f4065KkSKNpyu0PxSWwmyO
         bbCEjZ0ViCXEEW1tQ1+HUNUHEgNdCkTAETFpsGB3imogdUXwDXXgdW4mLz2HglufSFSb
         zgLffF+pGy87XLJ6hs9L6Ysr6ZBXfRPcghN+kgeoNSfblq3oSXJ91C404DMMKbx996HG
         kxKIgpAVOwDTkt2R4K/GLHJIYesKRcUvZo1YAqV/q5itJ2V1dQ+xbEnq2KFAsrcxGlng
         8GfEpU24Ltjf9slFD0rNlB0ie+ltDOJVDYYfMVAbhDhCFFlFqbqL/96Hf4sXx+7OMdmb
         ngcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684745941; x=1687337941;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vE9HterktgMYG1jGA4fUIM9e+PCQIFyDSNjOg6ZEURw=;
        b=bjJw1iQe6Df3kC7UvyKorpX3VdsowA8tFBG0dbJBrrVMYHXeCKDZzu3CPEjNyb0DnJ
         QmIUKEv61ZRZ4VN5ImLODHryViwgG+kf92MVNNPI0KN3j/GCEIKM2FvKgRKB02w7TqpV
         YNYkGhmKpE/GC7c0xfdAjVSG6mG762YMYhJwnfqfKBJywT8/AXY2lPBdu01vmokiX48r
         vkgmKBqZzHJzZz1LFbbn9yoLppexfPw70Y3LFOkLCqjD+A80eIvBHfnsbdIXogg7aO0p
         of0B2q1B61/6B2M1dE7xwrRO5Dxvutu1DVNQJTL7+ZwJklUG4YewQM3PhkJj+zH7HnFe
         3Afg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzJyr6f+60qXHlLqO9V/gIxHlg+vAdyjp7Sg2YoECYg5iNUxlUG
	7MuIr/KXCU9cykhY7pdT1VpRiQ==
X-Google-Smtp-Source: ACHHUZ6kuWuNkMFcvqOWI7zv+rBVJkBf05fXcFRxvfAydob8/YYc6aEFCpDMMJPNK+DHWwGCdPRqWQ==
X-Received: by 2002:aca:bf86:0:b0:392:5c87:34c with SMTP id p128-20020acabf86000000b003925c87034cmr2777543oif.2.1684745941436;
        Mon, 22 May 2023 01:59:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:3a2e:b0:19a:1554:7a3c with SMTP id
 du46-20020a0568703a2e00b0019a15547a3cls941787oab.1.-pod-prod-01-us; Mon, 22
 May 2023 01:59:01 -0700 (PDT)
X-Received: by 2002:a05:6871:6ab0:b0:18b:18b5:907f with SMTP id zf48-20020a0568716ab000b0018b18b5907fmr5873632oab.2.1684745941012;
        Mon, 22 May 2023 01:59:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684745940; cv=none;
        d=google.com; s=arc-20160816;
        b=y5XgcJlMZLZINxSO0CsOZA/XyRFoOsURCI0vbwe1OdQEy0F9uEh8C2RAoX+TbcFaVI
         M+h6VeFuggU0NL7jpGfJM9W+XiewfRCNRXYdS3a8R4cYb92gCYSU29zLISFnKNU8cgGd
         Pc690GVQ0BpMTc6RYbDKtzrtUjYPt552hdR9q1klGX68rAaPRXxXSlAH98P7r0BDEhcq
         PsXIMihZgOesK96RGGT5sQKWOVqzlE7X8o2f1xwJGkHLfJc2GWMl1tbr1jkZ5DtqEucY
         hPZmitl3NTyPfJpEMquh3mCPWv81lDR6B3wgnUyG2nrZLo8aOaft8h5iojMuu06airCy
         eODQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=UQeSrfWF6EvL8Tyxm40SSqQ/6Cm3EN9lJUOCedt0x48=;
        b=UaJ1F1j8M4BFQoHllCY4avHYqzzfxABr002NNxydIbvyO1mQwOxb5R+A64HO6NL2bh
         SNJYJ5ZdaPDnA8qIfCoscW6hGsiu6fP+Ycdngezm/SCqztK0LFR0uZalWftiiRLowmh+
         Y8EE58WCmwSsJxTB03C5SUtf9Shvvb8g7EJlCjtbRbWIMYHf9Nyt2gqexdnDvxdPCQB+
         PjpLpkz2pjvdezyWZb2BiXBOMRKJ5AQVrRdXWdxjs2jm9wghbAaPnp9a1eoiG/Dxq2yy
         e4KEFkUGkPSxlvrEPsWBnZPkGFwO7DUaEJLSx+dvt3taaOXzlmzLmF/1o21d2qMaq9Uu
         k9xg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of gongruiqi@huaweicloud.com designates 45.249.212.56 as permitted sender) smtp.mailfrom=gongruiqi@huaweicloud.com
Received: from dggsgout12.his.huawei.com (dggsgout12.his.huawei.com. [45.249.212.56])
        by gmr-mx.google.com with ESMTPS id r18-20020a056830419200b006aae144574bsi441162otu.3.2023.05.22.01.59.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 May 2023 01:59:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of gongruiqi@huaweicloud.com designates 45.249.212.56 as permitted sender) client-ip=45.249.212.56;
Received: from mail02.huawei.com (unknown [172.30.67.143])
	by dggsgout12.his.huawei.com (SkyGuard) with ESMTP id 4QPrw85cbYz4f3jYT
	for <kasan-dev@googlegroups.com>; Mon, 22 May 2023 16:58:48 +0800 (CST)
Received: from [10.67.110.48] (unknown [10.67.110.48])
	by APP1 (Coremail) with SMTP id cCh0CgCH6yWxLmtk91CHJQ--.43916S2;
	Mon, 22 May 2023 16:58:50 +0800 (CST)
Message-ID: <1cec95d5-5cd4-fbf9-754b-e6a1229d45c3@huaweicloud.com>
Date: Mon, 22 May 2023 16:58:25 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.10.0
Subject: Re: [PATCH RFC v2] Randomized slab caches for kmalloc()
Content-Language: en-US
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: linux-mm@kvack.org, linux-kernel@vger.kernel.org,
 linux-hardening@vger.kernel.org,
 Alexander Lobakin <aleksander.lobakin@intel.com>,
 kasan-dev@googlegroups.com, Wang Weiyang <wangweiyang2@huawei.com>,
 Xiu Jianfeng <xiujianfeng@huawei.com>, Vlastimil Babka <vbabka@suse.cz>,
 Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>, Pekka Enberg
 <penberg@kernel.org>, Kees Cook <keescook@chromium.org>,
 Paul Moore <paul@paul-moore.com>, James Morris <jmorris@namei.org>,
 "Serge E. Hallyn" <serge@hallyn.com>,
 "Gustavo A. R. Silva" <gustavoars@kernel.org>,
 Gong Ruiqi <gongruiqi1@huawei.com>
References: <20230508075507.1720950-1-gongruiqi1@huawei.com>
 <CAB=+i9QxWL6ENDz_r1jPbiZsTUj1EE3u-j0uP6y_MxFSM9RerQ@mail.gmail.com>
 <5f5a858a-7017-5424-0fa0-db3b79e5d95e@huawei.com>
 <CAB=+i9R0GZiau7PKDSGdCOijPH1TVqA3rJ5tQLejJpoR55h6dg@mail.gmail.com>
 <19707cc6-fa5e-9835-f709-bc8568e4c9cd@huawei.com>
 <CAB=+i9T-iqtMZw8y7SxkaFBtiXA93YwFFEtQyGynBsorud1+_Q@mail.gmail.com>
From: "GONG, Ruiqi" <gongruiqi@huaweicloud.com>
In-Reply-To: <CAB=+i9T-iqtMZw8y7SxkaFBtiXA93YwFFEtQyGynBsorud1+_Q@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: cCh0CgCH6yWxLmtk91CHJQ--.43916S2
X-Coremail-Antispam: 1UD129KBjvJXoW7KFWUXF1fAF47Xry3Wr47XFb_yoW8tFyUpF
	WIyF1UCr4xCr17Cry0ya10va92v3y7tF1Uu3s0gryUZr1kJw18XFsakr109r93ZF45GFy3
	XFsYkF13WF9xt3DanT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUvIb4IE77IF4wAFF20E14v26ryj6rWUM7CY07I20VC2zVCF04k2
	6cxKx2IYs7xG6r1F6r1fM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rwA2F7IY1VAKz4
	vEj48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_tr0E3s1l84ACjcxK6xIIjxv20xvEc7Cj
	xVAFwI0_Gr1j6F4UJwA2z4x0Y4vEx4A2jsIE14v26rxl6s0DM28EF7xvwVC2z280aVCY1x
	0267AKxVW0oVCq3wAS0I0E0xvYzxvE52x082IY62kv0487Mc02F40EFcxC0VAKzVAqx4xG
	6I80ewAv7VC0I7IYx2IY67AKxVWUJVWUGwAv7VC2z280aVAFwI0_Jr0_Gr1lOx8S6xCaFV
	Cjc4AY6r1j6r4UM4x0Y48IcVAKI48JM4IIrI8v6xkF7I0E8cxan2IY04v7Mxk0xIA0c2IE
	e2xFo4CEbIxvr21l42xK82IYc2Ij64vIr41l4I8I3I0E4IkC6x0Yz7v_Jr0_Gr1lx2IqxV
	Aqx4xG67AKxVWUJVWUGwC20s026x8GjcxK67AKxVWUGVWUWwC2zVAF1VAY17CE14v26r4a
	6rW5MIIYrxkI7VAKI48JMIIF0xvE2Ix0cI8IcVAFwI0_Jr0_JF4lIxAIcVC0I7IYx2IY6x
	kF7I0E14v26r4j6F4UMIIF0xvE42xK8VAvwI8IcIk0rVWrZr1j6s0DMIIF0xvEx4A2jsIE
	14v26r1j6r4UMIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr0_Gr1UYxBIdaVFxhVjvjDU0xZFpf
	9x07UZ18PUUUUU=
X-CM-SenderInfo: pjrqw2pxltxq5kxd4v5lfo033gof0z/
X-CFilter-Loop: Reflected
X-Original-Sender: gongruiqi@huaweicloud.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of gongruiqi@huaweicloud.com designates 45.249.212.56 as
 permitted sender) smtp.mailfrom=gongruiqi@huaweicloud.com
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



On 2023/05/22 16:03, Hyeonggon Yoo wrote:
> On Mon, May 22, 2023 at 4:35=E2=80=AFPM Gong Ruiqi <gongruiqi1@huawei.com=
> wrote:
>> On 2023/05/17 6:35, Hyeonggon Yoo wrote:
> [...]
>>>>>> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
>>>>>> +# define SLAB_RANDOMSLAB       ((slab_flags_t __force)0x01000000U)
>>>>>> +#else
>>>>>> +# define SLAB_RANDOMSLAB       0
>>>>>> +#endif
>>>
>>> There is already the SLAB_KMALLOC flag that indicates if a cache is a
>>> kmalloc cache. I think that would be enough for preventing merging
>>> kmalloc caches?
>>
>> After digging into the code of slab merging (e.g. slab_unmergeable(),
>> find_mergeable(), SLAB_NEVER_MERGE, SLAB_MERGE_SAME etc), I haven't
>> found an existing mechanism that prevents normal kmalloc caches with
>> SLAB_KMALLOC from being merged with other slab caches. Maybe I missed
>> something?
>>
>> While SLAB_RANDOMSLAB, unlike SLAB_KMALLOC, is added into
>> SLAB_NEVER_MERGE, which explicitly indicates the no-merge policy.
>=20
> I mean, why not make slab_unmergable()/find_mergeable() not to merge kmal=
loc
> caches when CONFIG_RANDOM_KMALLOC_CACHES is enabled, instead of a new fla=
g?
>=20
> Something like this:
>=20
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 607249785c07..13ac08e3e6a0 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -140,6 +140,9 @@ int slab_unmergeable(struct kmem_cache *s)
>   if (slab_nomerge || (s->flags & SLAB_NEVER_MERGE))
>   return 1;
>=20
> + if (IS_ENALBED(CONFIG_RANDOM_KMALLOC_CACHES) && (flags & SLAB_KMALLOC))
> + return 1;
> +
>   if (s->ctor)
>   return 1;
>=20
> @@ -176,6 +179,9 @@ struct kmem_cache *find_mergeable(unsigned int
> size, unsigned int align,
>   if (flags & SLAB_NEVER_MERGE)
>   return NULL;
>=20
> + if (IS_ENALBED(CONFIG_RANDOM_KMALLOC_CACHES) && (flags & SLAB_KMALLOC))
> + return NULL;
> +
>   list_for_each_entry_reverse(s, &slab_caches, list) {
>   if (slab_unmergeable(s))
>   continue;

Ah I see. My concern is that it would affect not only normal kmalloc
caches, but kmalloc_{dma,cgroup,rcl} as well: since they were all marked
with SLAB_KMALLOC when being created, this code could potentially change
their mergeablity. I think it's better not to influence those irrelevant
caches.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1cec95d5-5cd4-fbf9-754b-e6a1229d45c3%40huaweicloud.com.
