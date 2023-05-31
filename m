Return-Path: <kasan-dev+bncBAABBZMG3ORQMGQEWWMJRKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 466E371747A
	for <lists+kasan-dev@lfdr.de>; Wed, 31 May 2023 05:47:51 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-626195b48c8sf24500816d6.2
        for <lists+kasan-dev@lfdr.de>; Tue, 30 May 2023 20:47:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1685504870; cv=pass;
        d=google.com; s=arc-20160816;
        b=B/jZictujbA8C6byK5YM2MTe5kXGJc4I2142DRT0xvt3tfJfKvm5/esbAwGFBMh3c+
         TFMqBIIz0rdyXNkOOR42WRubBL7rEye9svoaCPO22dfoTMhrhggv0RMDhELC3XXAYtV7
         oUIqVquMwOQdB5Q5A2B4JShOEY5TyAyjrrbvPtOy7vvdA2lRcjyuDBex+Gq3HFLygB9f
         tkqFEb4T6U/c1Serxj3a8ptwG2YbR6tOANsPBmZvPW82PdiKPYKQLBELRVNZl5RczUyo
         EG63gPiLLPPZR7IptBOWMkNGfUCG4NVSbGHg8NrfRFkKTjwYBQy2IB4CFpJuH7LowsKk
         3Bow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=+tpWlaNBqdRGf9plDHsiCW+ycxIbGsBS7C5H0v1MK4I=;
        b=WkulfRwp0kLXJ1q+iCmBmGmfPS7bKOd3n6b+cig/7hAXXExjeXDsf0B/HMHQU63Rbo
         Il5HzQjNIvQb9jNdmwx6g8xNeLaL0VfrnPjoHp8iXWf9eMJ5CPhlK6wRFFL/y3nTjApE
         NN4XisIh1z0bcS2H0Cm7zhmZcsZIH/8cYYXLHON/paRzLSARN8B6OtEjuKaCBJeiL5J1
         P+9AHjT0O7q2hAQoOPmu7rIt5jxDgXx6qOStUDymrVYsjAQVwZMF0Y3E3Tt9H7z5CkPo
         tnjJLGde/vvOLeYsAA1vrpuNeBGaCfX6hZYDOgRn8C+8wK2kI8oNma+fATcUUdXfLaNV
         F+xA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of gongruiqi@huaweicloud.com designates 45.249.212.51 as permitted sender) smtp.mailfrom=gongruiqi@huaweicloud.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1685504870; x=1688096870;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+tpWlaNBqdRGf9plDHsiCW+ycxIbGsBS7C5H0v1MK4I=;
        b=fm029VtrsycXBoZRbq9Wb7WxjmvypkrS4dgAoopraTFSl1xvNI0ki9OffPQVfhWY0b
         r23Gq0SdkR8ZLV8PgbBHBatI4+FFFk3+fBNZL3bUFhpiu1Tg8/R8htsmDtjgHIrOD0DX
         9HDnusZ4ZVeCxLxZ8uVOrT9FPBndMRVjuTLHexmlF6oSMRsTA/QamuQUdKxSZ4Ah6unJ
         rkFzLjRKOctBmZIFDQIBgAsEvB+sCXndVzIumnhGsZBGhh0k6pjeR1J6Ce8pr51UlIa8
         jghYmsybZ1CV+odgapOmmRYFUPv0iUEKzuoB4yBKpN/5bHEKhg82xu5wV24deV7VTnHv
         nWQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1685504870; x=1688096870;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+tpWlaNBqdRGf9plDHsiCW+ycxIbGsBS7C5H0v1MK4I=;
        b=h4mmABZrmy5TUAVqJoDYHHYrDOJh+XwZWuhpb//p9ozrYBrPOr33ynxEeseYTF4sMe
         q6pXEZJ6BmBjpjTrR/W9W4FRfMZBJrYlvlk0T+MAAUFvYzbGN3snbvkfceOEk8vvDFHN
         vjfMrG1MiJQj7AkRbZrjJzIiVv81KjJoB2EWpZpBpkANkndkztR9vqH1gTgPn3eEFLEG
         53OIMzYhjZVzpSrixkwb0rj3rv1VA3oouhB+3vmRyzcehcILbUfxtDK675yx/YsPvkni
         YEHO9znPaKdsRHJ3vHkP39IaFLoV5yyw6+cYsP9GCDIwqIiR5keDpYidfZTxYNrgI7eJ
         Hgww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzBCzMMOGcymnj292qhFsbceyFS9ui6vyfbvb7Jv5rr689jlz/k
	Ccbh1vB0LmBQcBzUkGhSThY=
X-Google-Smtp-Source: ACHHUZ4dk1VEKKaZI5ogzRbDGF3KFv+A23HqBmyr41RTC12PQVpJCoWNmUrearyTv/uAUD8vmwwDog==
X-Received: by 2002:a05:6214:a05:b0:625:aa1a:6b8a with SMTP id dw5-20020a0562140a0500b00625aa1a6b8amr753920qvb.1.1685504870021;
        Tue, 30 May 2023 20:47:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4644:0:b0:3f5:224d:adae with SMTP id f4-20020ac84644000000b003f5224dadaels6319198qto.0.-pod-prod-03-us;
 Tue, 30 May 2023 20:47:49 -0700 (PDT)
X-Received: by 2002:a05:622a:181c:b0:3f6:824e:5104 with SMTP id t28-20020a05622a181c00b003f6824e5104mr4507205qtc.28.1685504869624;
        Tue, 30 May 2023 20:47:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1685504869; cv=none;
        d=google.com; s=arc-20160816;
        b=bMG+B+LGn0zOvwgVcrcbmB+PWV5Yi2RP64sDBPuN+3ce2p/iiPuyWHGoOgRECBVwG7
         RkETJZtTTXI13JUTXF/AoG0WAaibeGnZMgjVbTni47W5NF9M3h78SivfktJgSU8UUHUU
         DlcZXUMaPCpZybgv81rrmGiSSmLuXNi3zpLA/V3rw1vm5woksMqjgccIGIKZeppRMp6z
         N4xAeg7Gbk58HOCvCsttTfduNB1sUr6iRAo6nX7GuHrXEadxouaL5gfQaHJURdDZ6XZz
         WSUDpXxVmhHrszxNseySqk3/RyNvIedz4/jjz00c9nHnXnYdlBNugYPc8JmSLUlavrhz
         X9rA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=teIb1ws+7h85XoaOmgYta710dkH+TvsA+RviMTjWXwA=;
        b=BN2kFn1aa8HywJlnmeDmgQz6fVwQQfv6T7LvMDpUP9FPAZq/5Uz1Lz78+YI5LzS7Z3
         25N5AA/PKd+L2adcnXkd7B1blOvt0vo+gktU+hY1cbn2epnEGg2JiDg4wEUztfxxE8++
         qgUQVrm/dVbqmZmiz4Au/3zie+zav5Q3on51AcmeOKQ3CkrNBnREWxtrTaLcF4QiRZsX
         8k0R3/+lpWZBfOFwmCWxK85eH69ssfD1kjSPj3LuMohCE2UP+T6lIQinmHghsStnhq67
         KoLVbGT02tI4IroY2TCRn1eIr/aAdMwZUu8LANDm68h9zuCGUtA9qJ8/B7yEDr1KvETu
         hycw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of gongruiqi@huaweicloud.com designates 45.249.212.51 as permitted sender) smtp.mailfrom=gongruiqi@huaweicloud.com
Received: from dggsgout11.his.huawei.com (dggsgout11.his.huawei.com. [45.249.212.51])
        by gmr-mx.google.com with ESMTPS id 204-20020a1f17d5000000b00450e301dcc7si1670561vkx.3.2023.05.30.20.47.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 May 2023 20:47:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of gongruiqi@huaweicloud.com designates 45.249.212.51 as permitted sender) client-ip=45.249.212.51;
Received: from mail02.huawei.com (unknown [172.30.67.169])
	by dggsgout11.his.huawei.com (SkyGuard) with ESMTP id 4QWFb41YWjz4f3kkM
	for <kasan-dev@googlegroups.com>; Wed, 31 May 2023 11:47:44 +0800 (CST)
Received: from [10.67.110.48] (unknown [10.67.110.48])
	by APP3 (Coremail) with SMTP id _Ch0CgDXzhxKw3Zkmo0aJw--.10451S2;
	Wed, 31 May 2023 11:47:45 +0800 (CST)
Message-ID: <dac62b10-57c0-f021-0b87-5f7d0ab82678@huaweicloud.com>
Date: Wed, 31 May 2023 11:47:22 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.11.0
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
 Gong Ruiqi <gongruiqi1@huawei.com>, Jann Horn <jannh@google.com>
References: <20230508075507.1720950-1-gongruiqi1@huawei.com>
 <CAB=+i9QxWL6ENDz_r1jPbiZsTUj1EE3u-j0uP6y_MxFSM9RerQ@mail.gmail.com>
 <5f5a858a-7017-5424-0fa0-db3b79e5d95e@huawei.com>
 <CAB=+i9R0GZiau7PKDSGdCOijPH1TVqA3rJ5tQLejJpoR55h6dg@mail.gmail.com>
 <19707cc6-fa5e-9835-f709-bc8568e4c9cd@huawei.com>
 <CAB=+i9T-iqtMZw8y7SxkaFBtiXA93YwFFEtQyGynBsorud1+_Q@mail.gmail.com>
 <1cec95d5-5cd4-fbf9-754b-e6a1229d45c3@huaweicloud.com>
 <ZG2mmWT5dxfMC3DW@debian-BULLSEYE-live-builder-AMD64>
From: "GONG, Ruiqi" <gongruiqi@huaweicloud.com>
In-Reply-To: <ZG2mmWT5dxfMC3DW@debian-BULLSEYE-live-builder-AMD64>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: _Ch0CgDXzhxKw3Zkmo0aJw--.10451S2
X-Coremail-Antispam: 1UD129KBjvJXoWxWFykGF15GFyfKF1xGr43GFg_yoW5Aw48pF
	WIyFyUAr48Wry7Cry0vw10ga9av3yxtF1Uu3s0gw17Zr1ktw1xXFn5Kry09F97uF45GFy3
	ZFsYk3ZxWF9Iy3DanT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUvIb4IE77IF4wAFF20E14v26ryj6rWUM7CY07I20VC2zVCF04k2
	6cxKx2IYs7xG6r1S6rWUM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rwA2F7IY1VAKz4
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
 (google.com: domain of gongruiqi@huaweicloud.com designates 45.249.212.51 as
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

Sorry for the late reply. I was trapped by other in-house kernel issues
these days.

On 2023/05/24 13:54, Hyeonggon Yoo wrote:
> On Mon, May 22, 2023 at 04:58:25PM +0800, GONG, Ruiqi wrote:
>>
>>
>> On 2023/05/22 16:03, Hyeonggon Yoo wrote:
>>> On Mon, May 22, 2023 at 4:35=E2=80=AFPM Gong Ruiqi <gongruiqi1@huawei.c=
om> wrote:
>>>> On 2023/05/17 6:35, Hyeonggon Yoo wrote:
>>> [...]
>>>>>>>> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
>>>>>>>> +# define SLAB_RANDOMSLAB       ((slab_flags_t __force)0x01000000U=
)
>>>>>>>> +#else
>>>>>>>> +# define SLAB_RANDOMSLAB       0
>>>>>>>> +#endif
>>>>>
>>>>> There is already the SLAB_KMALLOC flag that indicates if a cache is a
>>>>> kmalloc cache. I think that would be enough for preventing merging
>>>>> kmalloc caches?
>>>>
>>>> After digging into the code of slab merging (e.g. slab_unmergeable(),
>>>> find_mergeable(), SLAB_NEVER_MERGE, SLAB_MERGE_SAME etc), I haven't
>>>> found an existing mechanism that prevents normal kmalloc caches with
>>>> SLAB_KMALLOC from being merged with other slab caches. Maybe I missed
>>>> something?
>>>>
>>>> While SLAB_RANDOMSLAB, unlike SLAB_KMALLOC, is added into
>>>> SLAB_NEVER_MERGE, which explicitly indicates the no-merge policy.
>>>
>>> I mean, why not make slab_unmergable()/find_mergeable() not to merge km=
alloc
>>> caches when CONFIG_RANDOM_KMALLOC_CACHES is enabled, instead of a new f=
lag?
>>>
>>> Something like this:
>>>
>>> diff --git a/mm/slab_common.c b/mm/slab_common.c
>>> index 607249785c07..13ac08e3e6a0 100644
>>> --- a/mm/slab_common.c
>>> +++ b/mm/slab_common.c
>>> @@ -140,6 +140,9 @@ int slab_unmergeable(struct kmem_cache *s)
>>>   if (slab_nomerge || (s->flags & SLAB_NEVER_MERGE))
>>>   return 1;
>>>
>>> + if (IS_ENALBED(CONFIG_RANDOM_KMALLOC_CACHES) && (flags & SLAB_KMALLOC=
))
>>> + return 1;
>>> +
>>>   if (s->ctor)
>>>   return 1;
>>>
>>> @@ -176,6 +179,9 @@ struct kmem_cache *find_mergeable(unsigned int
>>> size, unsigned int align,
>>>   if (flags & SLAB_NEVER_MERGE)
>>>   return NULL;
>>>
>>> + if (IS_ENALBED(CONFIG_RANDOM_KMALLOC_CACHES) && (flags & SLAB_KMALLOC=
))
>>> + return NULL;
>>> +
>>>   list_for_each_entry_reverse(s, &slab_caches, list) {
>>>   if (slab_unmergeable(s))
>>>   continue;
>>
>> Ah I see. My concern is that it would affect not only normal kmalloc
>> caches, but kmalloc_{dma,cgroup,rcl} as well: since they were all marked
>> with SLAB_KMALLOC when being created, this code could potentially change
>> their mergeablity. I think it's better not to influence those irrelevant
>> caches.
>=20
> I see. no problem at all as we're not running out of cache flags.
>=20
> By the way, is there any reason to only randomize normal caches
> and not dma/cgroup/rcl caches?

The reason is mainly because based on my knowledge they are not commonly
used for exploiting the kernel, i.e. they are not on the "attack
surface", so it's unnecessary to do so. I'm not sure if other hardening
experts have different opinions on that.

>=20
> Thanks,
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/dac62b10-57c0-f021-0b87-5f7d0ab82678%40huaweicloud.com.
