Return-Path: <kasan-dev+bncBAABBN6WQ6RQMGQEAP4EGII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id D6054702703
	for <lists+kasan-dev@lfdr.de>; Mon, 15 May 2023 10:20:09 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id af79cd13be357-75935a16b8esf90443585a.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 May 2023 01:20:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684138808; cv=pass;
        d=google.com; s=arc-20160816;
        b=aeHq73End1CQLYyZ0rF6nAH4O/U9cvk153g0A+2NIoMee7Ndg7r7z2XdRrjqDrn05W
         OVK3yt1/sfyNs6mKvf7aI+ahGFpeOnYxASvCtL/GpfRr+oefeX+G6inu8rH7t7u+CVBs
         +jGjOlP6NM8ANWnI5gqID6vdAJ7nO9fg/M/h0ZIkAYEPVzicqbj4k8Nai5ARLxl/WXUp
         dhnxPCJUdlQUKLOQgJkIMQ30RAFw47Fsqd6NyPSMWXuKfD2boy80N3WFmpmygySEjSV2
         m8pUgr9oJbv1h6lcAeqJVe1UQR+/T1klGMG92qO+6W2xEU8y9OY9oaxvtf01Yk2ONa/D
         fzhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=+ILZLfohPRob85+uI6HROtmqvgfCO49xxEPih8MQ2qc=;
        b=xO9+C+oiwf31XMmHvJByP77k9/w1S7XnZcnBejjqsEX4DyB2JRS/wiZ+xQxLUxvKRs
         ZG+uaYjFDU0vt5qNQ56pxYUrKO8ukMbI6A06WTy5dqtjRdCsFf5hvWo6Ry8dhJK7LdqA
         +jXGi+2wJVvAN6cVscHwWkn6qZWy1WZiBcz88YTHu4YzKqk0ZOnFAS6T3gW3oe7+Hh65
         CMvkUPuzqUA8D/sCxyihGZGirJySfDGjTuHWMRWvkH23hm1D+LvjNbrFPWM4ZPP1uXpq
         oEpsWc3dfSPw1v6KFlMIGv8/CRrVREkSEphvDBLyZg+OfJbUcHi4SVNfrJmQUqIJiSXo
         J8lg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684138808; x=1686730808;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+ILZLfohPRob85+uI6HROtmqvgfCO49xxEPih8MQ2qc=;
        b=o64SaMzykVoMp3HS3FIMO3LJf2iLdc83IcXGSA9zVx7TATCCS1NKVKQREB3qxzGlfv
         mF7MSLJks4qNI1F8YQnVWjLowQ6OoQOC3/BVmziOULYyZY/6/OMeKkfizX49dEhJr3fL
         lLYE0sUKg6gRfi8I4jWyWLV4vL1gkh2Y6TAfCe3+MFiWDETpnlZ57sNs6xV2f5dSuzSi
         E/B+jCK6qgJUc5A1nwXV8oKQ6cuQnKMgq+Bw+yJ4rGmj6c38AcKJfZoQDzCmYOfTNgIf
         N/n6d5xljESAR5ZnaAbLs2mjZYEz2pziE62cd1kmZCFfYX/eGghF2YKAPVyWUoCAtXY9
         vCjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684138808; x=1686730808;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+ILZLfohPRob85+uI6HROtmqvgfCO49xxEPih8MQ2qc=;
        b=aXj/TUJKAL3tIEE2tFS+/drC4wlQMWS77/biKfVJPn1ftRuPFcnLtSQn1t9ZGCeWvs
         mGkjx44aPyr/dI+EDnWoutlZzN+rRK3khLkgTB/P60nM1DS466+WlDTH619jI3LrCw/w
         Jyg1TwArlrWUxCDqNTwDSsp9Z+el0zgT0OYayc09RWrj8bDuJvVeKp89V3paBEd0sRSD
         /TdeImP61kA0zSjsSk84dZ9V76qu7LmtrhfNR1diztV7nGG0gxasu8Gyg+QzI56I9zpI
         tgEab4mk+IgCv2AiNyCTTykhzS7CDmKTmdIjZfcFBYrA8KLbAJML8iWtFlCavFrjb2xH
         gfUg==
X-Gm-Message-State: AC+VfDz/xhRRMFLyFapr0n5IuSggNp6tEMH7pS+wJAQmOSRdRZ8Ks1HM
	j1LcVeVyY7V/Y4Q5CN8Tr8k=
X-Google-Smtp-Source: ACHHUZ7LbRV9LVlgn8wuGP/BBMmDcKVYy3SS9BNg909cd1rPVjfyAM7442lX8i/t/Uk4D1Tyaokmiw==
X-Received: by 2002:a05:620a:c53:b0:748:59c2:c071 with SMTP id u19-20020a05620a0c5300b0074859c2c071mr8676197qki.4.1684138807544;
        Mon, 15 May 2023 01:20:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:3d85:b0:5ef:61a6:9da2 with SMTP id
 om5-20020a0562143d8500b005ef61a69da2ls4644609qvb.11.-pod-prod-gmail; Mon, 15
 May 2023 01:20:07 -0700 (PDT)
X-Received: by 2002:ad4:4ee8:0:b0:5ef:83cf:91c2 with SMTP id dv8-20020ad44ee8000000b005ef83cf91c2mr56348632qvb.45.1684138807123;
        Mon, 15 May 2023 01:20:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684138807; cv=none;
        d=google.com; s=arc-20160816;
        b=Dp54YAlis6iE72ijUU84YMxu6BPegjDOj8yk+xr09I3T4FIFBbvRO9hNjVmG/4Ar/D
         Rj4ewfS39P9Ekl4Y3IIOgTcg5BekisQTqVp8czoH1IwUGFk9bDpT3cpXlLY3db7L0zYd
         fBYQYlSTegRy8GJYMcPUQDYu0ohFTh5NSPgTGqkASIeOe5Fgcf3aH4XTY9l9NCAdD+D/
         rTrvkhbUVhTzqKQcxGPscWoF9oMi7GRhLmtBOl6D7dLeQxR9EPiJ8K1tEvgkBoF37AuI
         C5Mpy+i4h5ck33+Jm+DCRj8qKCLzyGQczSpn9RifB6iQ7hffMghUBIMas8/+b9NyX5ht
         uTpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=1NsOqaCvkMVHyBArQlFng09a1+LaVyICgzskB82sxBU=;
        b=axaA9ErEtzdtOtrB7hDKWPnvfLoYkLZQw6C9rc8JdXnLj3K5ZgaF4xV/W1zwANn1fn
         OyZkDdgX25x3HzA1MQSusValNzR2z18QtY3pcgsnHvQF1ukaOlZ98z7EXYbFhzdJskJi
         dtmf1voDOZgk8LVkLN6FgJwfXsZXSqritNhZq91YawYHKAZTSWXfWlDdakawc7kAjjRI
         cjsBibmZOfiPhWl8lEUQDFIrauFwG6v+k3lIuqbDduAuFk908ZoSlM/HcjsvICVpcBXj
         n8SNN7LrzoAC7lmkFUrIWx+EdrzfTdk72VNITfjDKdNdWFvUUuonp2ZOlYgQ0yDdrA/I
         qONA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id og9-20020a056214428900b005fc5135c65csi965671qvb.4.2023.05.15.01.20.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 May 2023 01:20:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggpemm500016.china.huawei.com (unknown [172.30.72.57])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4QKXLN6zGXzsR3y;
	Mon, 15 May 2023 16:18:04 +0800 (CST)
Received: from [10.67.110.48] (10.67.110.48) by dggpemm500016.china.huawei.com
 (7.185.36.25) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id 15.1.2507.23; Mon, 15 May
 2023 16:20:02 +0800
Message-ID: <6db163dc-e7fc-e304-5007-74db66a3ad1a@huawei.com>
Date: Mon, 15 May 2023 16:20:02 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.10.0
Subject: Re: [PATCH RFC v2] Randomized slab caches for kmalloc()
Content-Language: en-US
To: Vlastimil Babka <vbabka@suse.cz>, Hyeonggon Yoo <42.hyeyoo@gmail.com>
CC: <linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>,
	<linux-hardening@vger.kernel.org>, Alexander Lobakin
	<aleksander.lobakin@intel.com>, <kasan-dev@googlegroups.com>, Wang Weiyang
	<wangweiyang2@huawei.com>, Xiu Jianfeng <xiujianfeng@huawei.com>, Christoph
 Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Roman Gushchin
	<roman.gushchin@linux.dev>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew
 Morton <akpm@linux-foundation.org>, Pekka Enberg <penberg@kernel.org>, Kees
 Cook <keescook@chromium.org>, Paul Moore <paul@paul-moore.com>, James Morris
	<jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>, "Gustavo A. R.
 Silva" <gustavoars@kernel.org>
References: <20230508075507.1720950-1-gongruiqi1@huawei.com>
 <CAB=+i9QxWL6ENDz_r1jPbiZsTUj1EE3u-j0uP6y_MxFSM9RerQ@mail.gmail.com>
 <5f5a858a-7017-5424-0fa0-db3b79e5d95e@huawei.com>
 <b9331fe4-11c8-5323-e757-5cae3c1e2233@suse.cz>
From: "'Gong Ruiqi' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <b9331fe4-11c8-5323-e757-5cae3c1e2233@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.67.110.48]
X-ClientProxiedBy: dggems706-chm.china.huawei.com (10.3.19.183) To
 dggpemm500016.china.huawei.com (7.185.36.25)
X-CFilter-Loop: Reflected
X-Original-Sender: gongruiqi1@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.187 as
 permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Gong Ruiqi <gongruiqi1@huawei.com>
Reply-To: Gong Ruiqi <gongruiqi1@huawei.com>
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



On 2023/05/14 17:30, Vlastimil Babka wrote:
> On 5/12/23 12:11, Gong Ruiqi wrote:
>>
>>
>> On 2023/05/11 2:43, Hyeonggon Yoo wrote:
>>> On Mon, May 8, 2023 at 12:53=E2=80=AFAM GONG, Ruiqi <gongruiqi1@huawei.=
com> wrote:
>>>>
>>
>> [...]
>>
>>>>
>>>> The overhead of performance has been tested on a 40-core x86 server by
>>>> comparing the results of `perf bench all` between the kernels with and
>>>> without this patch based on the latest linux-next kernel, which shows
>>>> minor difference. A subset of benchmarks are listed below:
>>>>
>>>
>>> Please Cc maintainers/reviewers of corresponding subsystem in MAINTAINE=
RS file.
>>
>> Okay, I've appended maintainers/reviewers of linux-hardening and
>> security subsystem to the Cc list.
>=20
> I think they were CC'd on v1 but didn't respond yet. I thought maybe if
> I run into Kees at OSS, I will ask him about it, but didn't happen.

Yeah it would be great if you can contact Kees or other developers of
hardening to know their opinions about this, since I'm curious about
what they think of this as well.

> As a slab maintainer I don't mind adding such things if they don't
> complicate the code excessively, and have no overhead when configured
> out. This one would seem to be acceptable at first glance, although
> maybe the CONFIG space is too wide, and the amount of #defines in
> slab_common.c is also large (maybe there's a way to make it more
> concise, maybe not).
>=20
> But I don't have enough insight into hardening to decide if it's a
> useful mitigation that people would enable, so I'd hope for hardening
> folks to advise on that. Similar situation with freelist hardening in
> the past, which was even actively pushed by Kees, IIRC.

For the effectiveness of this mechanism, I would like to provide some
results of the experiments I did. I conducted actual defense tests on
CVE-2021-22555 and CVE-2016-8655 by reverting fixing patch to recreate
exploitable environments, and running the exploits/PoCs on the
vulnerable kernel with and without our randomized kmalloc caches patch.
With our patch, the originally exploitable environments were not pwned
by running the PoCs.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/6db163dc-e7fc-e304-5007-74db66a3ad1a%40huawei.com.
