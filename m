Return-Path: <kasan-dev+bncBAABB5743ORQMGQEYBNMACA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id EF83A717955
	for <lists+kasan-dev@lfdr.de>; Wed, 31 May 2023 09:59:52 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id ca18e2360f4ac-7748b80141asf339035839f.0
        for <lists+kasan-dev@lfdr.de>; Wed, 31 May 2023 00:59:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1685519991; cv=pass;
        d=google.com; s=arc-20160816;
        b=0EgLX7ITMAFT7zpJT+GqA+8CqT10VtLQ9m8KTsQ/2YoJ2CsE5smV9qDQKu74x9ufHp
         xQEwKkCjJzncfwiu6DEItnlLa0OWAYK7/mmeKNM17vAl5wk1aE5Ze/ik3mh+ql3ogdp2
         PLPDLngB78RrW07BinpAVBl6fvh1Q509XJotA2t+cuMA/GdtFAAn1ajcVyY6vFlQJqEx
         nbPuoZx5M8iyuGIwFzNXu4VkmDZCcAD/bBeqPnTRcFPQKHtOQg52oVVPqORByGaiQlRl
         qHBcq4l0u9gpGyYLFhRS3ifpQGswAupizuRX9n50x1D0VqeBY79LE+lvItfBicrgmT0E
         9eTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=eHxhx3cMoQz1DjpEImKHTadc4xhEAwLQs+6lny1Okn0=;
        b=zUmqDtmcYbSEusgPBHrpPD7+vyrKBV3lXtmJYBRN9nHB390kxtdN1+Q6sHOT1CJSSa
         qfUgyG0kG7Pvi4Il/WpaDtAQ4+65kPKgjbLQ2u72GUeHlMIwPEIrvk3EJoGJvT+7cysw
         s7iFN2v+wAWaLFZg/csZgoRtBgIbAD6UM24WGNvSmNzBW/cK66V0cC++g/7Vm1e0QMpX
         rJC0BI7PmaDSgJ9RpeXWzYBxtYZvq8TUt99SAjCbHAJLoo19YLgrsn1t+1e6LryBHDCR
         c3OnGlqg8NzVS2fwpyVbOHGht7OYjnWmdGu4bDVN+SGEPBVEOTfX/6c6Ga4BzAHQXUgK
         C2yA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1685519991; x=1688111991;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eHxhx3cMoQz1DjpEImKHTadc4xhEAwLQs+6lny1Okn0=;
        b=ae/5A0cvzATa5crIwuqcY+Ga9adkw+jKOxdQEZHG0nlm4WBZq/nYMTaeHQX3DGNCqQ
         /14mfB+x8oknZV8EYE8u0OohdnzYLWiToqxXuSJ+rOOBH/mfDuWGmdQHbO7VapHA7LJ2
         aYWwuHElAtpn8Ei6SC9lQGpwITP9k2BQpwwRFYChw4jIwO1IVgaNg+7D6WzWjb63KPTH
         3hFNOw3BHZv234iPU+nyVoD2a0OsaUBgf/7szKO9rb3cuAZKyG8wx/WDrpPFuUKFQGQF
         BEtAk73b8ghqPMeciAj8Xmtd3tIhPTB4ciwBG/Tyt9ZfC+AhQSclBmSnkJG/sZ5H3r42
         iwNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1685519991; x=1688111991;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=eHxhx3cMoQz1DjpEImKHTadc4xhEAwLQs+6lny1Okn0=;
        b=dh8MJrHSJEQYajS1Jg6MLbRcNOLnbjQ3z9JJgDairG165dqFqerw0BUzpuKZBiQ/n6
         L1b21SdpT4PMEnwoxG8m19kuAOXAXfIUThurGOic4jcInk5D9GhnG9t0+XG6CvdAQUvJ
         dl9lJRNZJA3BHonBXRZJ9NB+ocM8P3y5kf4fYoZi4iY7fAx2ykyLPkN6vMur4uYvBbcD
         XTkBBDYmwBsx0VnWnhWFxurGNaSnfSG1LggDHPViFqdGGF7JwtJQIvgKc9Rdex/20TGe
         s2h7Aw0/WBeUM1IyYbi9CDYh8hl3sNhHucuF5NRvYmUDnQIJqUcznLqyC87cCX4VsgrZ
         kVLw==
X-Gm-Message-State: AC+VfDxEMQIkay/dI4a5GYuH2Ag6FH9qoB3QB3zasHBKpddficX6ojF6
	rSMYSRejB7ADsNNjAPOBHfU=
X-Google-Smtp-Source: ACHHUZ5cuNrqZKgJi8XZ/SLtKmyGAdzEGV6oikTVA+oqQ4R/YB8ZSOB/8WYhnG9G0XRwCWhq543sKQ==
X-Received: by 2002:a92:d4c4:0:b0:32f:776d:711 with SMTP id o4-20020a92d4c4000000b0032f776d0711mr1326281ilm.30.1685519991543;
        Wed, 31 May 2023 00:59:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1aad:b0:33b:7f21:7d7e with SMTP id
 l13-20020a056e021aad00b0033b7f217d7els1192196ilv.0.-pod-prod-09-us; Wed, 31
 May 2023 00:59:51 -0700 (PDT)
X-Received: by 2002:a92:dacd:0:b0:33b:ea2:fe6c with SMTP id o13-20020a92dacd000000b0033b0ea2fe6cmr1558943ilq.24.1685519991051;
        Wed, 31 May 2023 00:59:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1685519991; cv=none;
        d=google.com; s=arc-20160816;
        b=zQk3FlRb/CnCaviqiV3dmZ80y59E+VXcEmilb3+S9s5vDXQFbtmZwZKH15vbsdk42/
         rv00mOUoKlbpSQlWIe1UNYCnl2X5ICoPBm7tYXtCnzedwFNQ+b1O5/zGe/QVKMIdxYc1
         4I1an9IaqWmFZcfwS8k/eSbsQrh6Sf0VSQdwNSaw9ew2w8eeK9D3sB8bZ7qOQ3IRADDH
         3rxiccAWONwXYRgPwLyvN8xlM2SKGNqDkPYltIoj5tlwwGUcfuN1Acd9LR4Ni6Wzswb8
         zEbdCrMG6s8wPeQNecsnwiJlwAQX2/d477VoFp4huLQDOYXx9r0zvTES+Bl1Fig8X53H
         0Ntg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=xe/kXwhcoI5dvncy643diuvWWH0RH7DOGcTshuZsb+Y=;
        b=G7ULCSzIkpWgyhSIoVJ+yRZdyN+KjI3h3tRWmazYocR69LrjgrpFpDeNt5stdhZ3Y5
         QF5vIubsPc18lLJSSz2k0ovLFyhWHVcyVDWziwgg2TCgztVL135r31ilfTXpw1CWgagh
         katdZaoIZqQiMNThQtHeWJUuKF+RegsQcmwK0nmKy1siFhiaid9kO/VrY+tYuLkfscLf
         Tkz/JfB+FzUUv5miezY3xqjJCLZK2bodg/Ibmcna2F+pym0v29oCe1X4Vr5ycJhQBFR2
         UEgPPIGHy8n50r926krbaBFWwwAbAEZlV7sXLFcv76K1cOkbFzp8IvV/tRJpSxP1Dtct
         /cjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id j15-20020a056e02124f00b0033b35ceaa04si807152ilq.5.2023.05.31.00.59.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 31 May 2023 00:59:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from dggpemm500016.china.huawei.com (unknown [172.30.72.54])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4QWM4Z0qGdz18Lsy;
	Wed, 31 May 2023 15:55:10 +0800 (CST)
Received: from [10.67.110.48] (10.67.110.48) by dggpemm500016.china.huawei.com
 (7.185.36.25) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id 15.1.2507.23; Wed, 31 May
 2023 15:59:47 +0800
Message-ID: <83f6cfbd-d081-5a76-7c7f-5e0b90b4ac74@huawei.com>
Date: Wed, 31 May 2023 15:59:47 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.11.0
Subject: Re: [PATCH RFC v2] Randomized slab caches for kmalloc()
Content-Language: en-US
To: Kees Cook <keescook@chromium.org>, Jann Horn <jannh@google.com>
CC: Vlastimil Babka <vbabka@suse.cz>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-hardening@vger.kernel.org>, Hyeonggon
 Yoo <42.hyeyoo@gmail.com>, Alexander Lobakin <aleksander.lobakin@intel.com>,
	<kasan-dev@googlegroups.com>, Wang Weiyang <wangweiyang2@huawei.com>, Xiu
 Jianfeng <xiujianfeng@huawei.com>, Christoph Lameter <cl@linux.com>, David
 Rientjes <rientjes@google.com>, Roman Gushchin <roman.gushchin@linux.dev>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton
	<akpm@linux-foundation.org>, Pekka Enberg <penberg@kernel.org>, Paul Moore
	<paul@paul-moore.com>, James Morris <jmorris@namei.org>, "Serge E. Hallyn"
	<serge@hallyn.com>, "Gustavo A. R. Silva" <gustavoars@kernel.org>, "GONG,
 Ruiqi" <gongruiqi@huaweicloud.com>
References: <20230508075507.1720950-1-gongruiqi1@huawei.com>
 <202305161204.CB4A87C13@keescook>
From: "'Gong Ruiqi' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <202305161204.CB4A87C13@keescook>
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.67.110.48]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 dggpemm500016.china.huawei.com (7.185.36.25)
X-CFilter-Loop: Reflected
X-Original-Sender: gongruiqi1@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.255 as
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

Sorry for the late reply. I was trapped by other in-house kernel issues
these days.

On 2023/05/17 3:34, Kees Cook wrote:
> For new CCs, the start of this thread is here[0].
> 
> On Mon, May 08, 2023 at 03:55:07PM +0800, GONG, Ruiqi wrote:
>> When exploiting memory vulnerabilities, "heap spraying" is a common
>> technique targeting those related to dynamic memory allocation (i.e. the
>> "heap"), and it plays an important role in a successful exploitation.
>> Basically, it is to overwrite the memory area of vulnerable object by
>> triggering allocation in other subsystems or modules and therefore
>> getting a reference to the targeted memory location. It's usable on
>> various types of vulnerablity including use after free (UAF), heap out-
>> of-bound write and etc.
> 
> I heartily agree we need some better approaches to deal with UAF, and
> by extension, heap spraying.

Thanks Kees :) Good to hear that!

> 
>> There are (at least) two reasons why the heap can be sprayed: 1) generic
>> slab caches are shared among different subsystems and modules, and
>> 2) dedicated slab caches could be merged with the generic ones.
>> Currently these two factors cannot be prevented at a low cost: the first
>> one is a widely used memory allocation mechanism, and shutting down slab
>> merging completely via `slub_nomerge` would be overkill.
>>
>> To efficiently prevent heap spraying, we propose the following approach:
>> to create multiple copies of generic slab caches that will never be
>> merged, and random one of them will be used at allocation. The random
>> selection is based on the address of code that calls `kmalloc()`, which
>> means it is static at runtime (rather than dynamically determined at
>> each time of allocation, which could be bypassed by repeatedly spraying
>> in brute force). In this way, the vulnerable object and memory allocated
>> in other subsystems and modules will (most probably) be on different
>> slab caches, which prevents the object from being sprayed.
> 
> This is a nice balance between the best option we have now
> ("slub_nomerge") and most invasive changes (type-based allocation
> segregation, which requires at least extensive compiler support),
> forcing some caches to be "out of reach".

Yes it is, and it's also cost-effective: achieving a quite satisfactory
mitigation with a small amount of code (only ~130 lines).

I get this impression also because (believe it or not) we did try to
implement similar idea as the latter one you mention, and that was super
complex, and the workload was really huge ...

> 
>>
>> The overhead of performance has been tested on a 40-core x86 server by
>> comparing the results of `perf bench all` between the kernels with and
>> without this patch based on the latest linux-next kernel, which shows
>> minor difference. A subset of benchmarks are listed below:
>>
>> 			control		experiment (avg of 3 samples)
>> sched/messaging (sec)	0.019		0.019
>> sched/pipe (sec)	5.253		5.340
>> syscall/basic (sec)	0.741		0.742
>> mem/memcpy (GB/sec)	15.258789	14.860495
>> mem/memset (GB/sec)	48.828125	50.431069
>>
>> The overhead of memory usage was measured by executing `free` after boot
>> on a QEMU VM with 1GB total memory, and as expected, it's positively
>> correlated with # of cache copies:
>>
>> 		control		4 copies	8 copies	16 copies
>> total		969.8M		968.2M		968.2M		968.2M
>> used		20.0M		21.9M		24.1M		26.7M
>> free		936.9M		933.6M		931.4M		928.6M
>> available	932.2M		928.8M		926.6M		923.9M
> 
> Great to see the impact: it's relatively tiny. Nice!
> 
> Back when we looked at cache quarantines, Jann pointed out that it
> was still possible to perform heap spraying -- it just needed more
> allocations. In this case, I think that's addressed (probabilistically)
> by making it less likely that a cache where a UAF is reachable is merged
> with something with strong exploitation primitives (e.g. msgsnd).
> 
> In light of all the UAF attack/defense breakdowns in Jann's blog
> post[1], I'm curious where this defense lands. It seems like it would
> keep the primitives described there (i.e. "upgrading" the heap spray
> into a page table "type confusion") would be addressed probabilistically
> just like any other style of attack. Jann, what do you think, and how
> does it compare to the KCTF work[2] you've been doing?

A kindly ping to Jann ;)

> 
> In addition to this work, I'd like to see something like the kmalloc
> caches, but for kmem_cache_alloc(), where a dedicated cache of
> variably-sized allocations can be managed. With that, we can split off
> _dedicated_ caches where we know there are strong exploitation
> primitives (i.e. msgsnd, etc). Then we can carve off known weak heap
> allocation caches as well as make merging probabilistically harder.

Would you please explain more about the necessity of applying similar
mitigation mechanism to dedicated caches?

Based on my knowledge, usually we believe dedicated caches are more
secure, although it's still possible to spray them, e.g. by the
technique that allocates & frees large amounts of slab objects to
manipulate the heap in pages. Nevertheless in most of cases they are
still good since such spraying is (considered to be) hard to implement.

Meanwhile, the aforementioned spraying technique can hardly be mitigated
within SLAB since it operates at the page level, and our randomization
idea cannot protect against it either, so it also makes me inclined to
believe it's not meaningful to apply randomization to dedicated caches.

> I imagine it would be possible to then split this series into two
> halves: one that creates the "make arbitrary-sized caches" API, and the
> second that applies that to kmalloc globally (as done here).
> 
>>
>> Signed-off-by: GONG, Ruiqi <gongruiqi1@huawei.com>
>> ---
>>
>> v2:
>>   - Use hash_64() and a per-boot random seed to select kmalloc() caches.
> 
> This is good: I was hoping there would be something to make it per-boot
> randomized beyond just compile-time.
> 
> So, yes, I think this is worth it, but I'd like to see what design holes
> Jann can poke in it first. :)

Thanks again! I'm looking forward to receiving more comments from mm and
hardening developers.

> 
> -Kees
> 
> [0] https://lore.kernel.org/lkml/20230508075507.1720950-1-gongruiqi1@huawei.com/
> [1] https://googleprojectzero.blogspot.com/2021/10/how-simple-linux-kernel-memory.html
> [2] https://github.com/thejh/linux/commit/a87ad16046f6f7fd61080ebfb93753366466b761
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/83f6cfbd-d081-5a76-7c7f-5e0b90b4ac74%40huawei.com.
