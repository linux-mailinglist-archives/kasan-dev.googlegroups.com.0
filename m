Return-Path: <kasan-dev+bncBDGZTDNQ3ICBBN7IVKQQMGQESYLZN4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id AB8196D4307
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Apr 2023 13:10:48 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id a3-20020a92c543000000b0032651795968sf5053540ilj.19
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Apr 2023 04:10:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680520247; cv=pass;
        d=google.com; s=arc-20160816;
        b=wQh3C3Ed0qys5AiTiABSIvRrJ1DXtZB3oGFMVVV1d35En4Q8J7rUmb00tBuyWN1XvI
         oLQaC/ct0AfqJtqY6d4rtdIf4TBG1SlceY1/0aQFAJU2PLTvTl4ThHQibnCLOLMbetCj
         a8m3BiDpgN0X7GBOQ88lExmOpz2LUoiqx5lZFS2RC/4gMM+9gEif0WKaB2QiJovvRedM
         mvVNPPsL0PDKBnnD21lgsRC/5A62E+BOwYI5k/abtyrMndmuEsEYNsYSzcV2TDmXQEde
         hg8+VqKOI8VVBCdabWLFZUrZRz4AL4YWuqKrL50Ikxb6uBG8+Dwu8SDSc0VZw09bqNfT
         5hgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=ReCyfn3ulp79r8PZtm1w1Sm5AX6g+FxNBuWr9hT2NME=;
        b=Mq/TwXR86j0wtbeGa5ANeFFoadt1Yrn8Vw6ZaJopjkPBfH98NE1AcLL+jT7Lbck5Fy
         +My/VPrz1gdIA61Lk+hNQio/sZw4Gm13pcPuJNEspW/Kh7DJELjfVn28eF/MgaUD1fuP
         DWIlr0D6eodglU+Fe2ggKNZDTBPqQ2mnopEeczQJDA8Eh63PUM8XsGNjcMtAGYqEB9iD
         lilsCsEdQ55gHTBuinz5jlohjvbY4Uil4G6iYGdhDEpel39CY6SJhek6/qByv6EraGlO
         nRakoTAEXK3LdJtOA8EtIgSFQKMFk+FCpB7HEN1H1G2X4MJbyj7QQEo553MjfAdgYDl0
         FGrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=FoILJWvg;
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680520247;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ReCyfn3ulp79r8PZtm1w1Sm5AX6g+FxNBuWr9hT2NME=;
        b=cSe9RSJLfi5SRQgyuMQS/Dn9jbeE+qLp2wtBOGvBlOAebILM+FP1d/sZN/2bwa5xcD
         2QaxA7zrHZv5oEd9vlW+xbasKBy8IpG2nudvg/4WnD4lJOKkTgy6Ba/ulDVPH6sOYztJ
         G+lUTiLBRNH4azJ7sLomvv+c1i+tsVQ61bNHXUWqDcq52TDSe05jLWTjyXyZMYwSFVMA
         RKXRmRzOa19U8sn8hOV1F16lHKhvZuvCsdIebCMYqTSb0OjSZMW9ogirkMMorjnZvTqb
         PcYWh9BbU+9K/1JiBoBAY1abBywytcrskc58tODxk2ooINYtdOlh+6Jcs1L14Pq+QOdZ
         psDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680520247;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ReCyfn3ulp79r8PZtm1w1Sm5AX6g+FxNBuWr9hT2NME=;
        b=ltRIcrRoRPcMXCVlp9w42YUDtTfyDBsg2za/N9D08V0U35FDTVQwgT0qrU3rFzDx+1
         bJdmKj5COeYjVzx7k1qbxkiqMzHEr84NUThE+deB2kO1ePjXXnSsRXYpfj+M9j9qqWRv
         ELR6IzPpk5BYkR9zir6L/NSe0dxO8SMgphHfvd8Mj3Ce4YD4aO7zYIxrdIu7/6mLTMTs
         Ma6OxcV1sRpLl1sNeyMNdnUO0fSTVm7BvcFd87ynAPx4TFzSKms+rEEtGN4Ojwiow/X1
         O257R6tNAcP5bJKrzDj9Hm61nHPjJVzgwYaAEhJxTF2C9lbiKS6cFvr+shVYs6PWH02i
         pv9A==
X-Gm-Message-State: AAQBX9dwAxigBUeEQllUb/RljgvBLHDroNtjS5PBQ0tttLTUqBHHAszi
	rege4INlQ9J1sWHxej77JSg=
X-Google-Smtp-Source: AKy350ZF0AOjKRDBc3NADpl6T2mYgEpX/EuVxfFkeI21yTU0itX0sma54PUyCtBg4RS0LgJpJraiIQ==
X-Received: by 2002:a05:6e02:1543:b0:317:9cdf:54b9 with SMTP id j3-20020a056e02154300b003179cdf54b9mr18373963ilu.3.1680520247286;
        Mon, 03 Apr 2023 04:10:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:12a9:b0:316:e54a:82ff with SMTP id
 f9-20020a056e0212a900b00316e54a82ffls3472520ilr.10.-pod-prod-gmail; Mon, 03
 Apr 2023 04:10:46 -0700 (PDT)
X-Received: by 2002:a92:c98b:0:b0:323:1972:ec16 with SMTP id y11-20020a92c98b000000b003231972ec16mr24455921iln.18.1680520246752;
        Mon, 03 Apr 2023 04:10:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680520246; cv=none;
        d=google.com; s=arc-20160816;
        b=lr6/O57FVOdV4YXppOll7JdpUjOTx1jKbeWkreqzA93vQFACumGKul43siDYvqLa5N
         MR8W8opyNLaCWsHCU/0nQ2Idj/+sME85rwaSLBsSQDUD53U2QeezXyX16yjN9NbQO8zN
         BH9xnmGvBoQxMGgEiKW5JpWo7iiKLFD6xCGOZgZ0UQZzJk+y8iQScuyxMoJ2uWWsNwn3
         6SkzGQPGRZMi9XKTsimPJMfhlU/SgfcNy92EPARBVAFkbo974cylWxfc8Vtfc120/MlM
         lfy/YBLigT0Avd9fdrJOgUFmSHhGEjsdkVWohhiXmNrBq6JeNh3v24MJk2XxqTufvat6
         hmvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=jNd8dznDa6qafxBwtS27BSWf68Ex5hvYx12J2zeUsyk=;
        b=BJ3NQaHBZk839AKFdUchNX3b56CjzBiFqrFXtT3aUHU4m+NqYyfE8mBSQt9t+gOED7
         Yr+zw0LqPUJsezzHc9qUYLFf5J/UOlohtasVMVzWs9ZWWshNwrWnRopDh8KDidaBdYpE
         NXbVIZs3nc9QJsTiieje/iiKIOJHHKSfQ1++YkySvTj8nLg4kDeV0V7pITnQ0L0eCepJ
         VpGIHyIodXSdT8NxwbviuuIZsNVK9fzV62FLElxP3tnFmJja8LOBJG/83KN+jr4V8fjo
         7lzfqXADA9oTCgwnDhFZG7k7wMj84oNDYdfkt4kb1eCiWQJzpN5O1VY964RR78kQoi9T
         GPYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=FoILJWvg;
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pf1-x42d.google.com (mail-pf1-x42d.google.com. [2607:f8b0:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id i12-20020a056e021d0c00b00326652f9c2csi262201ila.4.2023.04.03.04.10.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 03 Apr 2023 04:10:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::42d as permitted sender) client-ip=2607:f8b0:4864:20::42d;
Received: by mail-pf1-x42d.google.com with SMTP id ce4so5842043pfb.1
        for <kasan-dev@googlegroups.com>; Mon, 03 Apr 2023 04:10:46 -0700 (PDT)
X-Received: by 2002:a62:1811:0:b0:62a:4503:53ba with SMTP id 17-20020a621811000000b0062a450353bamr32121258pfy.26.1680520245583;
        Mon, 03 Apr 2023 04:10:45 -0700 (PDT)
Received: from [10.200.10.217] ([139.177.225.248])
        by smtp.gmail.com with ESMTPSA id s21-20020a056a00195500b0062dd1c55346sm6693830pfk.67.2023.04.03.04.10.42
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 03 Apr 2023 04:10:45 -0700 (PDT)
Message-ID: <b4cc39c7-7e52-f9eb-8103-4b7e55f474a6@bytedance.com>
Date: Mon, 3 Apr 2023 19:10:40 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:102.0)
 Gecko/20100101 Thunderbird/102.9.1
Subject: Re: [PATCH] mm: kfence: Improve the performance of __kfence_alloc()
 and __kfence_free()
To: Marco Elver <elver@google.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
References: <20230403062757.74057-1-zhangpeng.00@bytedance.com>
 <CANpmjNMOJ9_AU++eNF=F9hwCveeJmM7r0sEQAf0a=0pOa=dGfg@mail.gmail.com>
From: "'Peng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CANpmjNMOJ9_AU++eNF=F9hwCveeJmM7r0sEQAf0a=0pOa=dGfg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: zhangpeng.00@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=FoILJWvg;       spf=pass
 (google.com: domain of zhangpeng.00@bytedance.com designates
 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
X-Original-From: Peng Zhang <zhangpeng.00@bytedance.com>
Reply-To: Peng Zhang <zhangpeng.00@bytedance.com>
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


=E5=9C=A8 2023/4/3 17:21, Marco Elver =E5=86=99=E9=81=93:
> On Mon, 3 Apr 2023 at 08:28, Peng Zhang <zhangpeng.00@bytedance.com> wrot=
e:
>> In __kfence_alloc() and __kfence_free(), we will set and check canary.
>> Assuming that the size of the object is close to 0, nearly 4k memory
>> accesses are required because setting and checking canary is executed
>> byte by byte.
>>
>> canary is now defined like this:
>> KFENCE_CANARY_PATTERN(addr) ((u8)0xaa ^ (u8)((unsigned long)(addr) & 0x7=
))
>>
>> Observe that canary is only related to the lower three bits of the
>> address, so every 8 bytes of canary are the same. We can access 8-byte
>> canary each time instead of byte-by-byte, thereby optimizing nearly 4k
>> memory accesses to 4k/8 times.
>>
>> Use the bcc tool funclatency to measure the latency of __kfence_alloc()
>> and __kfence_free(), the numbers (deleted the distribution of latency)
>> is posted below. Though different object sizes will have an impact on th=
e
>> measurement, we ignore it for now and assume the average object size is
>> roughly equal.
>>
>> Before playing patch:
>> __kfence_alloc:
>> avg =3D 5055 nsecs, total: 5515252 nsecs, count: 1091
>> __kfence_free:
>> avg =3D 5319 nsecs, total: 9735130 nsecs, count: 1830
>>
>> After playing patch:
>> __kfence_alloc:
>> avg =3D 3597 nsecs, total: 6428491 nsecs, count: 1787
>> __kfence_free:
>> avg =3D 3046 nsecs, total: 3415390 nsecs, count: 1121
> Seems like a nice improvement!
>
>> The numbers indicate that there is ~30% - ~40% performance improvement.
>>
>> Signed-off-by: Peng Zhang <zhangpeng.00@bytedance.com>
>> ---
>>   mm/kfence/core.c   | 71 +++++++++++++++++++++++++++++++++-------------
>>   mm/kfence/kfence.h | 10 ++++++-
>>   mm/kfence/report.c |  2 +-
>>   3 files changed, 62 insertions(+), 21 deletions(-)
>>
>> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
>> index 79c94ee55f97..0b1b1298c738 100644
>> --- a/mm/kfence/core.c
>> +++ b/mm/kfence/core.c
>> @@ -297,20 +297,13 @@ metadata_update_state(struct kfence_metadata *meta=
, enum kfence_object_state nex
>>          WRITE_ONCE(meta->state, next);
>>   }
>>
>> -/* Write canary byte to @addr. */
>> -static inline bool set_canary_byte(u8 *addr)
>> -{
>> -       *addr =3D KFENCE_CANARY_PATTERN(addr);
>> -       return true;
>> -}
>> -
>>   /* Check canary byte at @addr. */
>>   static inline bool check_canary_byte(u8 *addr)
>>   {
>>          struct kfence_metadata *meta;
>>          unsigned long flags;
>>
>> -       if (likely(*addr =3D=3D KFENCE_CANARY_PATTERN(addr)))
>> +       if (likely(*addr =3D=3D KFENCE_CANARY_PATTERN_U8(addr)))
>>                  return true;
>>
>>          atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
>> @@ -323,11 +316,27 @@ static inline bool check_canary_byte(u8 *addr)
>>          return false;
>>   }
>>
>> -/* __always_inline this to ensure we won't do an indirect call to fn. *=
/
>> -static __always_inline void for_each_canary(const struct kfence_metadat=
a *meta, bool (*fn)(u8 *))
>> +static inline void set_canary(const struct kfence_metadata *meta)
>>   {
>>          const unsigned long pageaddr =3D ALIGN_DOWN(meta->addr, PAGE_SI=
ZE);
>> -       unsigned long addr;
>> +       unsigned long addr =3D pageaddr;
>> +
>> +       /*
>> +        * The canary may be written to part of the object memory, but i=
t does
>> +        * not affect it. The user should initialize the object before u=
sing it.
>> +        */
>> +       for (; addr < meta->addr; addr +=3D sizeof(u64))
>> +               *((u64 *)addr) =3D KFENCE_CANARY_PATTERN_U64;
>> +
>> +       addr =3D ALIGN_DOWN(meta->addr + meta->size, sizeof(u64));
>> +       for (; addr - pageaddr < PAGE_SIZE; addr +=3D sizeof(u64))
>> +               *((u64 *)addr) =3D KFENCE_CANARY_PATTERN_U64;
>> +}
>> +
>> +static inline void check_canary(const struct kfence_metadata *meta)
>> +{
>> +       const unsigned long pageaddr =3D ALIGN_DOWN(meta->addr, PAGE_SIZ=
E);
>> +       unsigned long addr =3D pageaddr;
>>
>>          /*
>>           * We'll iterate over each canary byte per-side until fn() retu=
rns
> This comment is now out-of-date ("fn" no longer exists).
>
>> @@ -339,14 +348,38 @@ static __always_inline void for_each_canary(const =
struct kfence_metadata *meta,
>>           */
>>
>>          /* Apply to left of object. */
>> -       for (addr =3D pageaddr; addr < meta->addr; addr++) {
>> -               if (!fn((u8 *)addr))
>> +       for (; meta->addr - addr >=3D sizeof(u64); addr +=3D sizeof(u64)=
) {
>> +               if (unlikely(*((u64 *)addr) !=3D KFENCE_CANARY_PATTERN_U=
64))
>>                          break;
>>          }
>>
>> -       /* Apply to right of object. */
>> -       for (addr =3D meta->addr + meta->size; addr < pageaddr + PAGE_SI=
ZE; addr++) {
>> -               if (!fn((u8 *)addr))
>> +       /*
>> +        * If the canary is damaged in a certain 64 bytes, or the canay =
memory
> "damaged" -> "corrupted"
> "canay" -> "canary"
>
>> +        * cannot be completely covered by multiple consecutive 64 bytes=
, it
>> +        * needs to be checked one by one.
>> +        */
>> +       for (; addr < meta->addr; addr++) {
>> +               if (unlikely(!check_canary_byte((u8 *)addr)))
>> +                       break;
>> +       }
>> +
>> +       /*
>> +        * Apply to right of object.
>> +        * For easier implementation, check from high address to low add=
ress.
>> +        */
>> +       addr =3D pageaddr + PAGE_SIZE - sizeof(u64);
>> +       for (; addr >=3D meta->addr + meta->size ; addr -=3D sizeof(u64)=
) {
>> +               if (unlikely(*((u64 *)addr) !=3D KFENCE_CANARY_PATTERN_U=
64))
>> +                       break;
>> +       }
>> +
>> +       /*
>> +        * Same as above, checking byte by byte, but here is the reverse=
 of
>> +        * the above.
>> +        */
>> +       addr =3D addr + sizeof(u64) - 1;
>> +       for (; addr >=3D meta->addr + meta->size; addr--) {
> The re-checking should forward-check i.e. not in reverse, otherwise
> the report might not include some corrupted bytes that had in the
> previous version been included. I think you need to check from low to
> high address to start with above.

Yes, it's better to forward-check to avoid losing the corrupted bytes
which be used in report.
I will include all your suggestions in the next version of the patch.
Thanks.

>
>> +               if (unlikely(!check_canary_byte((u8 *)addr)))
>>                          break;
>>          }
>>   }
>> @@ -434,7 +467,7 @@ static void *kfence_guarded_alloc(struct kmem_cache =
*cache, size_t size, gfp_t g
>>   #endif
>>
>>          /* Memory initialization. */
>> -       for_each_canary(meta, set_canary_byte);
>> +       set_canary(meta);
>>
>>          /*
>>           * We check slab_want_init_on_alloc() ourselves, rather than le=
tting
>> @@ -495,7 +528,7 @@ static void kfence_guarded_free(void *addr, struct k=
fence_metadata *meta, bool z
>>          alloc_covered_add(meta->alloc_stack_hash, -1);
>>
>>          /* Check canary bytes for memory corruption. */
>> -       for_each_canary(meta, check_canary_byte);
>> +       check_canary(meta);
>>
>>          /*
>>           * Clear memory if init-on-free is set. While we protect the pa=
ge, the
>> @@ -751,7 +784,7 @@ static void kfence_check_all_canary(void)
>>                  struct kfence_metadata *meta =3D &kfence_metadata[i];
>>
>>                  if (meta->state =3D=3D KFENCE_OBJECT_ALLOCATED)
>> -                       for_each_canary(meta, check_canary_byte);
>> +                       check_canary(meta);
>>          }
>>   }
>>
>> diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
>> index 600f2e2431d6..2aafc46a4aaf 100644
>> --- a/mm/kfence/kfence.h
>> +++ b/mm/kfence/kfence.h
>> @@ -21,7 +21,15 @@
>>    * lower 3 bits of the address, to detect memory corruptions with high=
er
>>    * probability, where similar constants are used.
>>    */
>> -#define KFENCE_CANARY_PATTERN(addr) ((u8)0xaa ^ (u8)((unsigned long)(ad=
dr) & 0x7))
>> +#define KFENCE_CANARY_PATTERN_U8(addr) ((u8)0xaa ^ (u8)((unsigned long)=
(addr) & 0x7))
>> +
>> +/*
>> + * Define a continuous 8-byte canary starting from a multiple of 8. The=
 canary
>> + * of each byte is only related to the lowest three bits of its address=
, so the
>> + * canary of every 8 bytes is the same. 64-bit memory can be filled and=
 checked
>> + * at a time instead of byte by byte to improve performance.
>> + */
>> +#define KFENCE_CANARY_PATTERN_U64 ((u64)0xaaaaaaaaaaaaaaaa ^ (u64)(0x07=
06050403020100))
>>
>>   /* Maximum stack depth for reports. */
>>   #define KFENCE_STACK_DEPTH 64
>> diff --git a/mm/kfence/report.c b/mm/kfence/report.c
>> index 60205f1257ef..197430a5be4a 100644
>> --- a/mm/kfence/report.c
>> +++ b/mm/kfence/report.c
>> @@ -168,7 +168,7 @@ static void print_diff_canary(unsigned long address,=
 size_t bytes_to_show,
>>
>>          pr_cont("[");
>>          for (cur =3D (const u8 *)address; cur < end; cur++) {
>> -               if (*cur =3D=3D KFENCE_CANARY_PATTERN(cur))
>> +               if (*cur =3D=3D KFENCE_CANARY_PATTERN_U8(cur))
>>                          pr_cont(" .");
>>                  else if (no_hash_pointers)
>>                          pr_cont(" 0x%02x", *cur);
>> --
>> 2.20.1
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/b4cc39c7-7e52-f9eb-8103-4b7e55f474a6%40bytedance.com.
