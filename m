Return-Path: <kasan-dev+bncBAABBWNB7CRAMGQE4YVPJSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id DA21D7004EF
	for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 12:11:38 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3352698e6e6sf46258025ab.1
        for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 03:11:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683886297; cv=pass;
        d=google.com; s=arc-20160816;
        b=tJ90WdVc7gcId1UIvLpwP7+6zjXEHVTaQ98R2bUaDnMQdQityPGEbVJHjqqPTBhTZB
         rlmb0L5cOzqIvhYKc4nQuYvwgVCC1+1MOQ+OKKJG+9IXMNme5BW1rixKDYuz7kPKpn5J
         yjOgmvxtnJToFfSB4K0sa+44W7V+Oh/4k/hns/fzVizSUvUNIesrpQrZyGRfWiqK48/c
         1VxF2F50rzoiWIM6rgTcUGuITMe6A4ZzfBf/iG0o1M09cNQ7HyEkDXhbnLsYTohAf5iA
         LenQFoYhvSBmEElstvXDGtc5+6rB7/h4zv/9VbY6Et4gL5XvPiTuGyT5Y+oH/FDbxx3k
         WVOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:content-language:references:cc:to:subject:from
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=E5BgDEmtAsVLIjn+jXHT4/GvDALVWx4v6Wd19fCVK9s=;
        b=hgLsMtUvEE6ykKZduc5AYNSNhJ2iGuuZKF9KN5aoAxZJuEPcRLmZMXsTpV1wuNqqum
         7Tre/pvskh7awAPQBHjWdjyErkONFPRGOVCW9oBLj9wN1/gyuA5huVroAIe8MXmsahuR
         kUyb6yvBk+Ckm1Ib4lMiLfjdZw9aIHoojXo1bxi/4jP0krJTcHyxgTtWCQ07W3xHyz9o
         HVdZ15mKozzSBARCFaJO3jz8AGjNX25mfmUVTZA6NiFECBL/+dfWojcq8ErRXUNnD4xh
         HwZofM863BYMJ+nZLlt6XW0oAtELXdhWlyLIOBWYOgDHheKb6MhTE9UOf648FavOnzVs
         zqQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683886297; x=1686478297;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:references
         :cc:to:subject:from:user-agent:mime-version:date:message-id:from:to
         :cc:subject:date:message-id:reply-to;
        bh=E5BgDEmtAsVLIjn+jXHT4/GvDALVWx4v6Wd19fCVK9s=;
        b=cSwCk0RQs+MwSbWCzHFvRsVCV0PAsVKmVJz1zKR8//mSk0ebJDpiIhrq3m0Iliovb9
         kBlzmlMe2UjGT/wLcGjHjlMcgVy7PgnwMz+LebITDb2QwJlX8aNKrT5cuz66Y4RyLmn2
         I89K2FGULrWvprlo3Pt5IzYlCZz5PiYjUo67+TvOJrB7B+3YbGAzFrPa3FXhTfMD2OxX
         ZC+iIxNl9R+IdNpweS7PLT9dGCER+pX16cA69agRmxv4i+MDKojIqnT68I5Tj2AWaxUD
         ngXmVbIDEJXp4FQO/5PB4TWJ93KeOAY9f9BBZi/glWi1Nr72dw/OUEGwUWGYv5tIcBQS
         zXeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683886297; x=1686478297;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:references
         :cc:to:subject:from:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=E5BgDEmtAsVLIjn+jXHT4/GvDALVWx4v6Wd19fCVK9s=;
        b=BDzMbYRaP/PTZy63YYTHwLzP0jYXINfXzhLhowPZOh8CuA2MdZs1WGWEk4nJ3Q9Hus
         XOts5Ol1DKl98YHdQY8askU0HRwIxAbYrMOILtcVGHPxaaXpkNw5kfmZZSQGInKazQX6
         n5TGQk1LT45iyj331MTegt7meAGifbCWiOay0B07DQbRK6tEuTm6/jtXdnK0qRTTNa2X
         lTvlCee49mG5DTuA+ly0zqdDrYG/Ip+Jw92g1T64IZp+qmwHdJIeUdpzsYiL93rDhYeQ
         TMkA9VzZ8PHzo9Rv1VOZcBHudgZawFoz6xzVz5ZItGL1FvjZvWxgCzdAGyfGDcyI1OBa
         BytA==
X-Gm-Message-State: AC+VfDw9avL3W9dpFPzIC+ZknysZhB+tHBVcLqLgYRSnB9VNIYIPCBE8
	AhEpMUgoffs2V9TPtOSIWt8=
X-Google-Smtp-Source: ACHHUZ4Sq28CNNDOsrZJl/xynywJzPHWo0TpELxlELF4tZ8HLYDumeJykHgIugVVIW/IEQHwC3yA0w==
X-Received: by 2002:a02:8647:0:b0:414:401d:b69a with SMTP id e65-20020a028647000000b00414401db69amr6345692jai.3.1683886297190;
        Fri, 12 May 2023 03:11:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:dcf:b0:337:3577:280a with SMTP id
 l15-20020a056e020dcf00b003373577280als63479ilj.1.-pod-prod-03-us; Fri, 12 May
 2023 03:11:36 -0700 (PDT)
X-Received: by 2002:a92:d782:0:b0:331:e0de:96a2 with SMTP id d2-20020a92d782000000b00331e0de96a2mr17176703iln.6.1683886296710;
        Fri, 12 May 2023 03:11:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683886296; cv=none;
        d=google.com; s=arc-20160816;
        b=ZZhxi4RyVPeF7v5d6YQU/MSGmkD22GLADOpSGxqx5k0BbxnlPow4rlzgsehit5UyCE
         6BsrGpXvCN+qR0oNoPvuy14KAYMOEho9qxITPe6V+GiutuNrWu9i5FEdonDygaYg5QGY
         uBTLUU8ktmoQMNS1XmVav+/h6HYKBk8wf1Zppmb0p93Ha6jevdAof1a1noqlicZjCIYY
         PiS6VkCRP4XIiCwAtFdYpeOHObTZ9YCOKcx3QlNRe3JLONUcW+XuJpVSwucZS5oll/fb
         eqfjbLk2p5pS62iHeriG8DtHo13C56j3zHniomWy7Ou2eYLw5DyUF09fscIdYegqiSkL
         unMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:content-language:references
         :cc:to:subject:from:user-agent:mime-version:date:message-id;
        bh=XCeGsWWwF+LMD0eMBq6fJN72mBwlLCy9gn2v0nn3cIU=;
        b=J8P/qN/R74jqQ22b1Gud62G4x3zPzyDD3w+AY2YLTW6wsrrRQ7jW/07LhJkNJUPYRX
         IiAnen8dc277Ko9irTZ6bi1b21wEwOqtKU4k5LUCm3RM8RwkbrMirLlU49I5kbLX89Zg
         6rw6M97un6ERWJsQUO+id5TYKPsDHDTsWgUVMVdW+sgnKAlCpMSim2eu9vEpRjNc8oQB
         IIRmWQe9bQ66RAeDwDSClnmf+d6Cmp/AXlmOQhUMzfq55XRTyDR5aaQaUs1sMGCrfUr2
         R3nN3ASnwpoMaJ7HwMOqKaYpAzU9DRnbuOYvA3mnN0GaJymMd41VTEoN3e2TxRIsv/f2
         421Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id bk14-20020a056602400e00b0076c863e1ef9si398649iob.0.2023.05.12.03.11.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 May 2023 03:11:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggpemm500016.china.huawei.com (unknown [172.30.72.53])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4QHkvD1jwhzqSHw;
	Fri, 12 May 2023 18:06:48 +0800 (CST)
Received: from [10.67.110.48] (10.67.110.48) by dggpemm500016.china.huawei.com
 (7.185.36.25) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id 15.1.2507.23; Fri, 12 May
 2023 18:11:02 +0800
Message-ID: <5f5a858a-7017-5424-0fa0-db3b79e5d95e@huawei.com>
Date: Fri, 12 May 2023 18:11:02 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.10.0
From: "'Gong Ruiqi' via kasan-dev" <kasan-dev@googlegroups.com>
Subject: Re: [PATCH RFC v2] Randomized slab caches for kmalloc()
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>
CC: <linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>,
	<linux-hardening@vger.kernel.org>, Alexander Lobakin
	<aleksander.lobakin@intel.com>, <kasan-dev@googlegroups.com>, Wang Weiyang
	<wangweiyang2@huawei.com>, Xiu Jianfeng <xiujianfeng@huawei.com>, Vlastimil
 Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>, David Rientjes
	<rientjes@google.com>, Roman Gushchin <roman.gushchin@linux.dev>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, Pekka
 Enberg <penberg@kernel.org>, Kees Cook <keescook@chromium.org>, Paul Moore
	<paul@paul-moore.com>, James Morris <jmorris@namei.org>, "Serge E. Hallyn"
	<serge@hallyn.com>, "Gustavo A. R. Silva" <gustavoars@kernel.org>
References: <20230508075507.1720950-1-gongruiqi1@huawei.com>
 <CAB=+i9QxWL6ENDz_r1jPbiZsTUj1EE3u-j0uP6y_MxFSM9RerQ@mail.gmail.com>
Content-Language: en-US
In-Reply-To: <CAB=+i9QxWL6ENDz_r1jPbiZsTUj1EE3u-j0uP6y_MxFSM9RerQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.67.110.48]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
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



On 2023/05/11 2:43, Hyeonggon Yoo wrote:
> On Mon, May 8, 2023 at 12:53=E2=80=AFAM GONG, Ruiqi <gongruiqi1@huawei.co=
m> wrote:
>>

[...]

>>
>> The overhead of performance has been tested on a 40-core x86 server by
>> comparing the results of `perf bench all` between the kernels with and
>> without this patch based on the latest linux-next kernel, which shows
>> minor difference. A subset of benchmarks are listed below:
>>
>=20
> Please Cc maintainers/reviewers of corresponding subsystem in MAINTAINERS=
 file.

Okay, I've appended maintainers/reviewers of linux-hardening and
security subsystem to the Cc list.

>=20
> I dont think adding a hardening feature by sacrificing one digit
> percent performance
> (and additional complexity) is worth. Heap spraying can only occur
> when the kernel contains
> security vulnerabilities, and if there is no known ways of performing
> such an attack,
> then we would simply be paying a consistent cost.
>=20
> Any opinions from hardening folks?

I did a more throughout performance test on the same machine in the same
way, and here are the results:

              sched/  sched/  syscall/       mem/         mem/
           messaging    pipe     basic     memcpy       memset
control1       0.019   5.459     0.733  15.258789    51.398026
control2       0.019   5.439     0.730  16.009221    48.828125
control3       0.019   5.282     0.735  16.009221    48.828125
control_avg    0.019   5.393     0.733  15.759077    49.684759

exp1           0.019   5.374     0.741	15.500992    46.502976
exp2           0.019   5.440     0.746	16.276042    51.398026
exp3           0.019   5.242     0.752	15.258789    51.398026
exp_avg        0.019   5.352     0.746	15.678608    49.766343

I believe the results show only minor differences and normal
fluctuation, and no substantial performance degradation.

As Pedro points out in his reply, unfortunately there are always
security vulnerabilities in the kernel, which is a fact that we have to
admit. Having a useful mitigation mechanism at the expense of a little
performance loss would be, in my opinion, quite a good deal in many
circumstances. And people can still choose not to have it by setting the
config to n.

>=20
>>                         control         experiment (avg of 3 samples)
>> sched/messaging (sec)   0.019           0.019
>> sched/pipe (sec)        5.253           5.340
>> syscall/basic (sec)     0.741           0.742
>> mem/memcpy (GB/sec)     15.258789       14.860495
>> mem/memset (GB/sec)     48.828125       50.431069
>>
>> The overhead of memory usage was measured by executing `free` after boot
>> on a QEMU VM with 1GB total memory, and as expected, it's positively
>> correlated with # of cache copies:
>>
>>                 control         4 copies        8 copies        16 copie=
s
>> total           969.8M          968.2M          968.2M          968.2M
>> used            20.0M           21.9M           24.1M           26.7M
>> free            936.9M          933.6M          931.4M          928.6M
>> available       932.2M          928.8M          926.6M          923.9M
>>
>> Signed-off-by: GONG, Ruiqi <gongruiqi1@huawei.com>
>> ---
>>
>> v2:
>>   - Use hash_64() and a per-boot random seed to select kmalloc() caches.
>>   - Change acceptable # of caches from [4,16] to {2,4,8,16}, which is
>> more compatible with hashing.
>>   - Supplement results of performance and memory overhead tests.
>>
>>  include/linux/percpu.h  | 12 ++++++---
>>  include/linux/slab.h    | 25 +++++++++++++++---
>>  mm/Kconfig              | 49 ++++++++++++++++++++++++++++++++++++
>>  mm/kfence/kfence_test.c |  4 +--
>>  mm/slab.c               |  2 +-
>>  mm/slab.h               |  3 ++-
>>  mm/slab_common.c        | 56 +++++++++++++++++++++++++++++++++++++----
>>  7 files changed, 135 insertions(+), 16 deletions(-)
>>
>> diff --git a/include/linux/percpu.h b/include/linux/percpu.h
>> index 1338ea2aa720..6cee6425951f 100644
>> --- a/include/linux/percpu.h
>> +++ b/include/linux/percpu.h
>> @@ -34,6 +34,12 @@
>>  #define PCPU_BITMAP_BLOCK_BITS         (PCPU_BITMAP_BLOCK_SIZE >>      =
\
>>                                          PCPU_MIN_ALLOC_SHIFT)
>>
>> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
>> +#define PERCPU_DYNAMIC_SIZE_SHIFT      13
>> +#else
>> +#define PERCPU_DYNAMIC_SIZE_SHIFT      10
>> +#endif
>> +
>>  /*
>>   * Percpu allocator can serve percpu allocations before slab is
>>   * initialized which allows slab to depend on the percpu allocator.
>> @@ -41,7 +47,7 @@
>>   * for this.  Keep PERCPU_DYNAMIC_RESERVE equal to or larger than
>>   * PERCPU_DYNAMIC_EARLY_SIZE.
>>   */
>> -#define PERCPU_DYNAMIC_EARLY_SIZE      (20 << 10)
>> +#define PERCPU_DYNAMIC_EARLY_SIZE      (20 << PERCPU_DYNAMIC_SIZE_SHIFT=
)
>>
>>  /*
>>   * PERCPU_DYNAMIC_RESERVE indicates the amount of free area to piggy
>> @@ -55,9 +61,9 @@
>>   * intelligent way to determine this would be nice.
>>   */
>>  #if BITS_PER_LONG > 32
>> -#define PERCPU_DYNAMIC_RESERVE         (28 << 10)
>> +#define PERCPU_DYNAMIC_RESERVE         (28 << PERCPU_DYNAMIC_SIZE_SHIFT=
)
>>  #else
>> -#define PERCPU_DYNAMIC_RESERVE         (20 << 10)
>> +#define PERCPU_DYNAMIC_RESERVE         (20 << PERCPU_DYNAMIC_SIZE_SHIFT=
)
>>  #endif
>>
>>  extern void *pcpu_base_addr;
>> diff --git a/include/linux/slab.h b/include/linux/slab.h
>> index 6b3e155b70bf..939c41c20600 100644
>> --- a/include/linux/slab.h
>> +++ b/include/linux/slab.h
>> @@ -18,6 +18,9 @@
>>  #include <linux/workqueue.h>
>>  #include <linux/percpu-refcount.h>
>>
>> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
>> +#include <linux/hash.h>
>> +#endif
>>
>>  /*
>>   * Flags to pass to kmem_cache_create().
>> @@ -106,6 +109,12 @@
>>  /* Avoid kmemleak tracing */
>>  #define SLAB_NOLEAKTRACE       ((slab_flags_t __force)0x00800000U)
>>
>> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
>> +# define SLAB_RANDOMSLAB       ((slab_flags_t __force)0x01000000U)
>> +#else
>> +# define SLAB_RANDOMSLAB       0
>> +#endif
>> +
>>  /* Fault injection mark */
>>  #ifdef CONFIG_FAILSLAB
>>  # define SLAB_FAILSLAB         ((slab_flags_t __force)0x02000000U)
>> @@ -331,7 +340,9 @@ static inline unsigned int arch_slab_minalign(void)
>>   * kmem caches can have both accounted and unaccounted objects.
>>   */
>>  enum kmalloc_cache_type {
>> -       KMALLOC_NORMAL =3D 0,
>> +       KMALLOC_RANDOM_START =3D 0,
>> +       KMALLOC_RANDOM_END =3D KMALLOC_RANDOM_START + CONFIG_RANDOM_KMAL=
LOC_CACHES_NR - 1,
>> +       KMALLOC_NORMAL =3D KMALLOC_RANDOM_END,
>>  #ifndef CONFIG_ZONE_DMA
>>         KMALLOC_DMA =3D KMALLOC_NORMAL,
>>  #endif
>> @@ -363,14 +374,20 @@ kmalloc_caches[NR_KMALLOC_TYPES][KMALLOC_SHIFT_HIG=
H + 1];
>>         (IS_ENABLED(CONFIG_ZONE_DMA)   ? __GFP_DMA : 0) |       \
>>         (IS_ENABLED(CONFIG_MEMCG_KMEM) ? __GFP_ACCOUNT : 0))
>>
>> -static __always_inline enum kmalloc_cache_type kmalloc_type(gfp_t flags=
)
>> +extern unsigned long random_kmalloc_seed;
>> +
>> +static __always_inline enum kmalloc_cache_type kmalloc_type(gfp_t flags=
, unsigned long caller)
>>  {
>>         /*
>>          * The most common case is KMALLOC_NORMAL, so test for it
>>          * with a single branch for all the relevant flags.
>>          */
>>         if (likely((flags & KMALLOC_NOT_NORMAL_BITS) =3D=3D 0))
>> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
>> +               return KMALLOC_RANDOM_START + hash_64(caller ^ random_km=
alloc_seed, CONFIG_RANDOM_KMALLOC_CACHES_BITS);
>> +#else
>>                 return KMALLOC_NORMAL;
>> +#endif
>>
>>         /*
>>          * At least one of the flags has to be set. Their priorities in
>> @@ -557,7 +574,7 @@ static __always_inline __alloc_size(1) void *kmalloc=
(size_t size, gfp_t flags)
>>
>>                 index =3D kmalloc_index(size);
>>                 return kmalloc_trace(
>> -                               kmalloc_caches[kmalloc_type(flags)][inde=
x],
>> +                               kmalloc_caches[kmalloc_type(flags, _RET_=
IP_)][index],
>>                                 flags, size);
>>         }
>>         return __kmalloc(size, flags);
>> @@ -573,7 +590,7 @@ static __always_inline __alloc_size(1) void *kmalloc=
_node(size_t size, gfp_t fla
>>
>>                 index =3D kmalloc_index(size);
>>                 return kmalloc_node_trace(
>> -                               kmalloc_caches[kmalloc_type(flags)][inde=
x],
>> +                               kmalloc_caches[kmalloc_type(flags, _RET_=
IP_)][index],
>>                                 flags, node, size);
>>         }
>>         return __kmalloc_node(size, flags, node);
>> diff --git a/mm/Kconfig b/mm/Kconfig
>> index 7672a22647b4..e868da87d9cd 100644
>> --- a/mm/Kconfig
>> +++ b/mm/Kconfig
>> @@ -311,6 +311,55 @@ config SLUB_CPU_PARTIAL
>>           which requires the taking of locks that may cause latency spik=
es.
>>           Typically one would choose no for a realtime system.
>>
>> +config RANDOM_KMALLOC_CACHES
>> +       default n
>> +       depends on SLUB
>> +       bool "Random slab caches for normal kmalloc"
>> +       help
>> +         A hardening feature that creates multiple copies of slab cache=
s for
>> +         normal kmalloc allocation and makes kmalloc randomly pick one =
based
>> +         on code address, which makes the attackers unable to spray vul=
nerable
>> +         memory objects on the heap for exploiting memory vulnerabiliti=
es.
>> +
>> +choice
>> +       prompt "Number of random slab caches copies"
>> +       depends on RANDOM_KMALLOC_CACHES
>> +       default RANDOM_KMALLOC_CACHES_16
>> +       help
>> +         The number of copies of random slab caches. Bigger value makes=
 the
>> +         potentially vulnerable memory object less likely to collide wi=
th
>> +         objects allocated from other subsystems or modules.
>> +
>> +config RANDOM_KMALLOC_CACHES_2
>> +       bool "2"
>> +
>> +config RANDOM_KMALLOC_CACHES_4
>> +       bool "4"
>> +
>> +config RANDOM_KMALLOC_CACHES_8
>> +       bool "8"
>> +
>> +config RANDOM_KMALLOC_CACHES_16
>> +       bool "16"
>> +
>> +endchoice
>> +
>> +config RANDOM_KMALLOC_CACHES_BITS
>> +       int
>> +       default 0 if !RANDOM_KMALLOC_CACHES
>> +       default 1 if RANDOM_KMALLOC_CACHES_2
>> +       default 2 if RANDOM_KMALLOC_CACHES_4
>> +       default 3 if RANDOM_KMALLOC_CACHES_8
>> +       default 4 if RANDOM_KMALLOC_CACHES_16
>> +
>> +config RANDOM_KMALLOC_CACHES_NR
>> +       int
>> +       default 1 if !RANDOM_KMALLOC_CACHES
>> +       default 2 if RANDOM_KMALLOC_CACHES_2
>> +       default 4 if RANDOM_KMALLOC_CACHES_4
>> +       default 8 if RANDOM_KMALLOC_CACHES_8
>> +       default 16 if RANDOM_KMALLOC_CACHES_16
>> +
>>  endmenu # SLAB allocator options
>>
>>  config SHUFFLE_PAGE_ALLOCATOR
>> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
>> index 6aee19a79236..8a95ef649d5e 100644
>> --- a/mm/kfence/kfence_test.c
>> +++ b/mm/kfence/kfence_test.c
>> @@ -213,7 +213,7 @@ static void test_cache_destroy(void)
>>
>>  static inline size_t kmalloc_cache_alignment(size_t size)
>>  {
>> -       return kmalloc_caches[kmalloc_type(GFP_KERNEL)][__kmalloc_index(=
size, false)]->align;
>> +       return kmalloc_caches[kmalloc_type(GFP_KERNEL, _RET_IP_)][__kmal=
loc_index(size, false)]->align;
>>  }
>>
>>  /* Must always inline to match stack trace against caller. */
>> @@ -284,7 +284,7 @@ static void *test_alloc(struct kunit *test, size_t s=
ize, gfp_t gfp, enum allocat
>>                 if (is_kfence_address(alloc)) {
>>                         struct slab *slab =3D virt_to_slab(alloc);
>>                         struct kmem_cache *s =3D test_cache ?:
>> -                                       kmalloc_caches[kmalloc_type(GFP_=
KERNEL)][__kmalloc_index(size, false)];
>> +                                       kmalloc_caches[kmalloc_type(GFP_=
KERNEL, _RET_IP_)][__kmalloc_index(size, false)];
>>
>>                         /*
>>                          * Verify that various helpers return the right =
values
>> diff --git a/mm/slab.c b/mm/slab.c
>> index bb57f7fdbae1..82e2a8d4cd9d 100644
>> --- a/mm/slab.c
>> +++ b/mm/slab.c
>> @@ -1674,7 +1674,7 @@ static size_t calculate_slab_order(struct kmem_cac=
he *cachep,
>>                         if (freelist_size > KMALLOC_MAX_CACHE_SIZE) {
>>                                 freelist_cache_size =3D PAGE_SIZE << get=
_order(freelist_size);
>>                         } else {
>> -                               freelist_cache =3D kmalloc_slab(freelist=
_size, 0u);
>> +                               freelist_cache =3D kmalloc_slab(freelist=
_size, 0u, _RET_IP_);
>>                                 if (!freelist_cache)
>>                                         continue;
>>                                 freelist_cache_size =3D freelist_cache->=
size;
>> diff --git a/mm/slab.h b/mm/slab.h
>> index f01ac256a8f5..1e484af71c52 100644
>> --- a/mm/slab.h
>> +++ b/mm/slab.h
>> @@ -243,7 +243,7 @@ void setup_kmalloc_cache_index_table(void);
>>  void create_kmalloc_caches(slab_flags_t);
>>
>>  /* Find the kmalloc slab corresponding for a certain size */
>> -struct kmem_cache *kmalloc_slab(size_t, gfp_t);
>> +struct kmem_cache *kmalloc_slab(size_t, gfp_t, unsigned long);
>>
>>  void *__kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags,
>>                               int node, size_t orig_size,
>> @@ -319,6 +319,7 @@ static inline bool is_kmalloc_cache(struct kmem_cach=
e *s)
>>                               SLAB_TEMPORARY | \
>>                               SLAB_ACCOUNT | \
>>                               SLAB_KMALLOC | \
>> +                             SLAB_RANDOMSLAB | \
>>                               SLAB_NO_USER_FLAGS)
>>
>>  bool __kmem_cache_empty(struct kmem_cache *);
>> diff --git a/mm/slab_common.c b/mm/slab_common.c
>> index 607249785c07..70899b20a9a7 100644
>> --- a/mm/slab_common.c
>> +++ b/mm/slab_common.c
>> @@ -47,6 +47,7 @@ static DECLARE_WORK(slab_caches_to_rcu_destroy_work,
>>   */
>>  #define SLAB_NEVER_MERGE (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER=
 | \
>>                 SLAB_TRACE | SLAB_TYPESAFE_BY_RCU | SLAB_NOLEAKTRACE | \
>> +               SLAB_RANDOMSLAB | \
>>                 SLAB_FAILSLAB | kasan_never_merge())
>>
>>  #define SLAB_MERGE_SAME (SLAB_RECLAIM_ACCOUNT | SLAB_CACHE_DMA | \
>> @@ -679,6 +680,11 @@ kmalloc_caches[NR_KMALLOC_TYPES][KMALLOC_SHIFT_HIGH=
 + 1] __ro_after_init =3D
>>  { /* initialization for https://bugs.llvm.org/show_bug.cgi?id=3D42570 *=
/ };
>>  EXPORT_SYMBOL(kmalloc_caches);
>>
>> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
>> +unsigned long random_kmalloc_seed __ro_after_init;
>> +EXPORT_SYMBOL(random_kmalloc_seed);
>> +#endif
>> +
>>  /*
>>   * Conversion table for small slabs sizes / 8 to the index in the
>>   * kmalloc array. This is necessary for slabs < 192 since we have non p=
ower
>> @@ -721,7 +727,7 @@ static inline unsigned int size_index_elem(unsigned =
int bytes)
>>   * Find the kmem_cache structure that serves a given size of
>>   * allocation
>>   */
>> -struct kmem_cache *kmalloc_slab(size_t size, gfp_t flags)
>> +struct kmem_cache *kmalloc_slab(size_t size, gfp_t flags, unsigned long=
 caller)
>>  {
>>         unsigned int index;
>>
>> @@ -736,7 +742,7 @@ struct kmem_cache *kmalloc_slab(size_t size, gfp_t f=
lags)
>>                 index =3D fls(size - 1);
>>         }
>>
>> -       return kmalloc_caches[kmalloc_type(flags)][index];
>> +       return kmalloc_caches[kmalloc_type(flags, caller)][index];
>>  }
>>
>>  size_t kmalloc_size_roundup(size_t size)
>> @@ -754,7 +760,7 @@ size_t kmalloc_size_roundup(size_t size)
>>                 return PAGE_SIZE << get_order(size);
>>
>>         /* The flags don't matter since size_index is common to all. */
>> -       c =3D kmalloc_slab(size, GFP_KERNEL);
>> +       c =3D kmalloc_slab(size, GFP_KERNEL, _RET_IP_);
>>         return c ? c->object_size : 0;
>>  }
>>  EXPORT_SYMBOL(kmalloc_size_roundup);
>> @@ -777,12 +783,44 @@ EXPORT_SYMBOL(kmalloc_size_roundup);
>>  #define KMALLOC_RCL_NAME(sz)
>>  #endif
>>
>> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
>> +#define __KMALLOC_RANDOM_CONCAT(a, b, c) a ## b ## c
>> +#define KMALLOC_RANDOM_NAME(N, sz) __KMALLOC_RANDOM_CONCAT(KMALLOC_RAND=
OM_, N, _NAME)(sz)
>> +#if CONFIG_RANDOM_KMALLOC_CACHES_BITS >=3D 1
>> +#define KMALLOC_RANDOM_1_NAME(sz)                             .name[KMA=
LLOC_RANDOM_START +  0] =3D "kmalloc-random-01-" #sz,
>> +#define KMALLOC_RANDOM_2_NAME(sz)  KMALLOC_RANDOM_1_NAME(sz)  .name[KMA=
LLOC_RANDOM_START +  1] =3D "kmalloc-random-02-" #sz,
>> +#endif
>> +#if CONFIG_RANDOM_KMALLOC_CACHES_BITS >=3D 2
>> +#define KMALLOC_RANDOM_3_NAME(sz)  KMALLOC_RANDOM_2_NAME(sz)  .name[KMA=
LLOC_RANDOM_START +  2] =3D "kmalloc-random-03-" #sz,
>> +#define KMALLOC_RANDOM_4_NAME(sz)  KMALLOC_RANDOM_3_NAME(sz)  .name[KMA=
LLOC_RANDOM_START +  3] =3D "kmalloc-random-04-" #sz,
>> +#endif
>> +#if CONFIG_RANDOM_KMALLOC_CACHES_BITS >=3D 3
>> +#define KMALLOC_RANDOM_5_NAME(sz)  KMALLOC_RANDOM_4_NAME(sz)  .name[KMA=
LLOC_RANDOM_START +  4] =3D "kmalloc-random-05-" #sz,
>> +#define KMALLOC_RANDOM_6_NAME(sz)  KMALLOC_RANDOM_5_NAME(sz)  .name[KMA=
LLOC_RANDOM_START +  5] =3D "kmalloc-random-06-" #sz,
>> +#define KMALLOC_RANDOM_7_NAME(sz)  KMALLOC_RANDOM_6_NAME(sz)  .name[KMA=
LLOC_RANDOM_START +  6] =3D "kmalloc-random-07-" #sz,
>> +#define KMALLOC_RANDOM_8_NAME(sz)  KMALLOC_RANDOM_7_NAME(sz)  .name[KMA=
LLOC_RANDOM_START +  7] =3D "kmalloc-random-08-" #sz,
>> +#endif
>> +#if CONFIG_RANDOM_KMALLOC_CACHES_BITS >=3D 4
>> +#define KMALLOC_RANDOM_9_NAME(sz)  KMALLOC_RANDOM_8_NAME(sz)  .name[KMA=
LLOC_RANDOM_START +  8] =3D "kmalloc-random-09-" #sz,
>> +#define KMALLOC_RANDOM_10_NAME(sz) KMALLOC_RANDOM_9_NAME(sz)  .name[KMA=
LLOC_RANDOM_START +  9] =3D "kmalloc-random-10-" #sz,
>> +#define KMALLOC_RANDOM_11_NAME(sz) KMALLOC_RANDOM_10_NAME(sz) .name[KMA=
LLOC_RANDOM_START + 10] =3D "kmalloc-random-11-" #sz,
>> +#define KMALLOC_RANDOM_12_NAME(sz) KMALLOC_RANDOM_11_NAME(sz) .name[KMA=
LLOC_RANDOM_START + 11] =3D "kmalloc-random-12-" #sz,
>> +#define KMALLOC_RANDOM_13_NAME(sz) KMALLOC_RANDOM_12_NAME(sz) .name[KMA=
LLOC_RANDOM_START + 12] =3D "kmalloc-random-13-" #sz,
>> +#define KMALLOC_RANDOM_14_NAME(sz) KMALLOC_RANDOM_13_NAME(sz) .name[KMA=
LLOC_RANDOM_START + 13] =3D "kmalloc-random-14-" #sz,
>> +#define KMALLOC_RANDOM_15_NAME(sz) KMALLOC_RANDOM_14_NAME(sz) .name[KMA=
LLOC_RANDOM_START + 14] =3D "kmalloc-random-15-" #sz,
>> +#define KMALLOC_RANDOM_16_NAME(sz) KMALLOC_RANDOM_15_NAME(sz) .name[KMA=
LLOC_RANDOM_START + 15] =3D "kmalloc-random-16-" #sz,
>> +#endif
>> +#else // CONFIG_RANDOM_KMALLOC_CACHES
>> +#define KMALLOC_RANDOM_NAME(N, sz)
>> +#endif
>> +
>>  #define INIT_KMALLOC_INFO(__size, __short_size)                        =
\
>>  {                                                              \
>>         .name[KMALLOC_NORMAL]  =3D "kmalloc-" #__short_size,      \
>>         KMALLOC_RCL_NAME(__short_size)                          \
>>         KMALLOC_CGROUP_NAME(__short_size)                       \
>>         KMALLOC_DMA_NAME(__short_size)                          \
>> +       KMALLOC_RANDOM_NAME(CONFIG_RANDOM_KMALLOC_CACHES_NR, __short_siz=
e)      \
>>         .size =3D __size,                                         \
>>  }
>>
>> @@ -878,6 +916,11 @@ new_kmalloc_cache(int idx, enum kmalloc_cache_type =
type, slab_flags_t flags)
>>                 flags |=3D SLAB_CACHE_DMA;
>>         }
>>
>> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
>> +       if (type >=3D KMALLOC_RANDOM_START && type <=3D KMALLOC_RANDOM_E=
ND)
>> +               flags |=3D SLAB_RANDOMSLAB;
>> +#endif
>> +
>>         kmalloc_caches[type][idx] =3D create_kmalloc_cache(
>>                                         kmalloc_info[idx].name[type],
>>                                         kmalloc_info[idx].size, flags, 0=
,
>> @@ -904,7 +947,7 @@ void __init create_kmalloc_caches(slab_flags_t flags=
)
>>         /*
>>          * Including KMALLOC_CGROUP if CONFIG_MEMCG_KMEM defined
>>          */
>> -       for (type =3D KMALLOC_NORMAL; type < NR_KMALLOC_TYPES; type++) {
>> +       for (type =3D KMALLOC_RANDOM_START; type < NR_KMALLOC_TYPES; typ=
e++) {
>>                 for (i =3D KMALLOC_SHIFT_LOW; i <=3D KMALLOC_SHIFT_HIGH;=
 i++) {
>>                         if (!kmalloc_caches[type][i])
>>                                 new_kmalloc_cache(i, type, flags);
>> @@ -922,6 +965,9 @@ void __init create_kmalloc_caches(slab_flags_t flags=
)
>>                                 new_kmalloc_cache(2, type, flags);
>>                 }
>>         }
>> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
>> +       random_kmalloc_seed =3D get_random_u64();
>> +#endif
>>
>>         /* Kmalloc array is now usable */
>>         slab_state =3D UP;
>> @@ -957,7 +1003,7 @@ void *__do_kmalloc_node(size_t size, gfp_t flags, i=
nt node, unsigned long caller
>>                 return ret;
>>         }
>>
>> -       s =3D kmalloc_slab(size, flags);
>> +       s =3D kmalloc_slab(size, flags, caller);
>>
>>         if (unlikely(ZERO_OR_NULL_PTR(s)))
>>                 return s;
>> --
>> 2.25.1
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/5f5a858a-7017-5424-0fa0-db3b79e5d95e%40huawei.com.
