Return-Path: <kasan-dev+bncBDGZTDNQ3ICBBPOMXGSQMGQEHGZDXQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id E549A7501BD
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Jul 2023 10:37:18 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-403aa344d39sf35681391cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Jul 2023 01:37:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689151037; cv=pass;
        d=google.com; s=arc-20160816;
        b=kAoeczi7ppfJhJADI5NEK5mTe93JrnrkhRdEVpOCMnorYz+ORqdo/IXqCzB4r/dNu/
         mQh7Qm4AYtrpP4lSvWA7AfD376zJX0T3PYiFsDoeTGLaAPfe22NAFL1o3u65S2cDSXsq
         6tBXghoQgI4nC3Gts0RtEknvY52u176tuQtNr3zlHn4iz3p5PPlwmXXZOXlBsCvPB/BQ
         EfhQjG0QO7q/7MpnyFkotCKx2LvxismHlRs78XdPwtWeLJHUI26oo+mNSeVPBn3zDl8n
         7AY5LiuGCr7bb+FrYrSKO2dm3EzhH/A625d9JuJxgJ9gYM+y24MZwOigi8cZ7N3Q3ZEt
         vbkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=1gymDNwv1JH6j/6trKBhFJyByhxuV2CFLhHFS5dny4Y=;
        fh=xaNQ03ZTPjkLPbl1y3SHon6VkANOOyBKS1wBYglxN6E=;
        b=n2LgmB5ofjZP4MPm5vE2VAHK43ZvWGhKLlSw/Swf687M1VffdJ1KSX9W1F2ajNQJFk
         tYxuayDXekOlCTJ/DFeSl6yiEP7Tte6QGRxmfRnM/KGnt/x7pvstV5yDeaM4DpG2DYBx
         upnJLrqgp7NC7kncZNXy45rM7toHeqMxYC61mxwDw1RJMOGThMwdXh6eYf5N54GwxcLr
         zH/luEZ/spwo0BNphy3hDa9SvjSxqRSc09u8qSUeeopAXimPYx9YCwEvjHqSouxtLS0r
         ZoFLuJBqWOM30sftd3s1vGMEACb2JmxW7TrgpJhaV7+bIqtrHMd5aJeLVMO6VfBR9SFg
         w5zg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=VqzN9T6Q;
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689151037; x=1691743037;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1gymDNwv1JH6j/6trKBhFJyByhxuV2CFLhHFS5dny4Y=;
        b=msr5UlpFYzILi2ZME2DWPQjRZVkS5OiGzuqA79bGlkRgx+cKqDlMYJGv8gTV05Srqj
         pAdkigvVEAHw8Cka7Pj3NbDGv4G0tsdXgbmiD76tsVpKr3uhO9mn+/gFqhI2w++jKxQj
         Xk6ZLjWOSRP7At2pA1wmYqBXNKhQnRNUfT7Gpu5q/oQ0puE3OWVBEyVeLIU4Ix7HlfXZ
         vlBhUjRTYpJ9ilovM7jXMVFw83fkuGZgu/oIybCjJMPAgBR/hF4zv6dkSqoa8KUdIJU3
         ydd1/fgAmSKh/FLB/+QKy5N+HOD6KdRyA9wdEDfnQUL3kJ09qhV/BNJpYN7SB3utCRbN
         RKAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689151037; x=1691743037;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=1gymDNwv1JH6j/6trKBhFJyByhxuV2CFLhHFS5dny4Y=;
        b=YvABMiaQRVFQCbIsnxy6kzUCupN4QiZGg63XqCm8k77Z22naT+4NhUUKtvuCmXg6Kq
         h4MkfQVu+RHCe3z8+Km/Adl6iqDNQJLdmGMVyqVEl8tUclmbJRL1Lr6GYab/wtP7VFMq
         KZdhFV17JvuxBXLArqoYfJ/t/mLTxW9ZShxlRv0B+6flx8OEyPV640Hr9DGzBIy/gRvl
         wt/F2YhbwsrDX5lGI2JqIaWusz2zbClz7LFMhYgXh90BmxO+HosLBNIFuN5s5ZioOmvv
         M7x9/eLhLHhmR3vJKUidGxy0sKzc6z91PxbnL8etW6pC8bi8MDjjfBMn3REJg4plFDr2
         cjvQ==
X-Gm-Message-State: ABy/qLaZPKSkoAvh7rdQ7oEYKwvBfbUtzu/utO0DT9iv50pTsUPyieRR
	9913TX7AA15Zr357CJbnFTvTaA==
X-Google-Smtp-Source: APBJJlEnvxTX36c24bQLBN70hMVaV0EmYOPM/P/oCoFj+HsdSOLpgbQs0H0AHo/TTFarBVh/bRT4uQ==
X-Received: by 2002:ac8:59c4:0:b0:403:27c5:ac79 with SMTP id f4-20020ac859c4000000b0040327c5ac79mr26386848qtf.54.1689151037636;
        Wed, 12 Jul 2023 01:37:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e004:0:b0:635:e8a7:8831 with SMTP id j4-20020a0ce004000000b00635e8a78831ls1285640qvk.2.-pod-prod-05-us;
 Wed, 12 Jul 2023 01:37:17 -0700 (PDT)
X-Received: by 2002:a0c:e3c5:0:b0:625:99ee:3ad8 with SMTP id e5-20020a0ce3c5000000b0062599ee3ad8mr16061301qvl.31.1689151037085;
        Wed, 12 Jul 2023 01:37:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689151037; cv=none;
        d=google.com; s=arc-20160816;
        b=MQuvryq/Y5HHeW53rhQVWiZBHY7GVyyZgWhRZ0BVBQzuejsp1VW48Hxs8JHCn+8knh
         cn5ma6NmpQ+BaAIu4OuWlBOYs68Pj1WfoUdhjx8pMtSn+hSNcKdVr4GNPcGanpPWRWMW
         /fDRM8iffDd3vmHxqzt6rP9kbDw2gpMfd+2o2GDu3CwcEEqSayD5Pwf3rinW/DfBQEEk
         /UcVIW89GJDgPLOefQry7mpSya/MNpM8V3vjto4vmxFT1/cbqbVJhCvTDtRPPa1xk24s
         fi0ufmCuMVqKp3LqRDrtMN7/PHwjz1JGkVBzePGR3xyWKZCUx7MfE0kwmKwzmuOIAOt5
         BJeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=rBUqtpQ/qPgW5u7ywMLTowE+PlXrM3g8tx27h51sMCE=;
        fh=K2x+m+hFjceLF2wk8ADStJsgy5QAj4/zR9EywkGKr8s=;
        b=rlYhH4dguyaFJjYCXXZk4HGn2B7mn/rPHJ7+/fGEl0a0z13NUAwgEfemGHd5Izi5B3
         8Jqlfk+E1j/cojSG/i0c/+qrJN0DaXvslraRgJkBKIYc6cntmPJP/9aD4h5tDohU2Mx5
         vFzd66//mESsmBbBi1S6YKxwJItLLRB50aPDmVH6MYgDRL+jNePwIs36fuL/xwY8AhKf
         08H/bCc/tT7+4NXf27BMxsFqjbdpa1HiHTOFGYWMvGhYahHFw3FpXEcGr/w6/6YMWAsu
         Vkw8YK6C1LH1T2BheOYk3wPIZeaRz04R3ojspHXpDDEaQXOnukprSTwrvLjqsSjb/nHV
         JG2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=VqzN9T6Q;
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pf1-x42c.google.com (mail-pf1-x42c.google.com. [2607:f8b0:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id h1-20020ad45441000000b006261d48d4c2si220935qvt.0.2023.07.12.01.37.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Jul 2023 01:37:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::42c as permitted sender) client-ip=2607:f8b0:4864:20::42c;
Received: by mail-pf1-x42c.google.com with SMTP id d2e1a72fcca58-666ecf9a0ceso3687983b3a.2
        for <kasan-dev@googlegroups.com>; Wed, 12 Jul 2023 01:37:17 -0700 (PDT)
X-Received: by 2002:a05:6a00:1409:b0:673:5d1e:6654 with SMTP id l9-20020a056a00140900b006735d1e6654mr16234608pfu.33.1689151036022;
        Wed, 12 Jul 2023 01:37:16 -0700 (PDT)
Received: from [10.254.22.102] ([139.177.225.243])
        by smtp.gmail.com with ESMTPSA id c19-20020aa78e13000000b00682b2fbd20fsm3078868pfr.31.2023.07.12.01.37.12
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Jul 2023 01:37:15 -0700 (PDT)
Message-ID: <ed82e6b9-3d9f-259a-82bc-cc51f9131f29@bytedance.com>
Date: Wed, 12 Jul 2023 16:37:10 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:102.0)
 Gecko/20100101 Thunderbird/102.13.0
Subject: Re: [PATCH] mm: kfence: allocate kfence_metadata at runtime
To: Peng Zhang <zhangpeng.00@bytedance.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, muchun.song@linux.dev,
 Marco Elver <elver@google.com>
References: <20230710032714.26200-1-zhangpeng.00@bytedance.com>
 <CANpmjNOHz+dRbJsAyg29nksPMcd2P6109iPxTem_-b2qfUvXtw@mail.gmail.com>
 <2a16a76c-506c-f325-6792-4fb58e8da531@bytedance.com>
From: "'Peng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <2a16a76c-506c-f325-6792-4fb58e8da531@bytedance.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: zhangpeng.00@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=VqzN9T6Q;       spf=pass
 (google.com: domain of zhangpeng.00@bytedance.com designates
 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
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



=E5=9C=A8 2023/7/12 16:28, Peng Zhang =E5=86=99=E9=81=93:
>=20
>=20
> =E5=9C=A8 2023/7/10 18:19, Marco Elver =E5=86=99=E9=81=93:
>> On Mon, 10 Jul 2023 at 05:27, 'Peng Zhang' via kasan-dev
>> <kasan-dev@googlegroups.com> wrote:
>>>
>>> kfence_metadata is currently a static array. For the purpose of
>>> allocating scalable __kfence_pool, we first change it to runtime
>>> allocation of metadata. Since the size of an object of kfence_metadata
>>> is 1160 bytes, we can save at least 72 pages (with default 256 objects)
>>> without enabling kfence.
>>>
>>> Below is the numbers obtained in qemu (with default 256 objects).
>>> before: Memory: 8134692K/8388080K available (3668K bss)
>>> after: Memory: 8136740K/8388080K available (1620K bss)
>>> More than expected, it saves 2MB memory.
>>>
>>> Signed-off-by: Peng Zhang <zhangpeng.00@bytedance.com>
>>
>> Seems like a reasonable optimization, but see comments below.
>>
>> Also with this patch applied on top of v6.5-rc1, KFENCE just doesn't
>> init at all anymore (early init). Please fix.
> I'm very sorry because I made a slight modification before sending the
> patch but it has not been tested, which caused it to not work properly.
> I fixed some of the issues you mentioned in v2[1].
>=20
> [1]=20
> https://lore.kernel.org/lkml/20230712081616.45177-1-zhangpeng.00@bytedanc=
e.com/
>=20
>>
>>> ---
>>> =C2=A0 mm/kfence/core.c=C2=A0=C2=A0 | 102 +++++++++++++++++++++++++++++=
+++-------------
>>> =C2=A0 mm/kfence/kfence.h |=C2=A0=C2=A0 5 ++-
>>> =C2=A0 2 files changed, 78 insertions(+), 29 deletions(-)
>>>
>>> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
>>> index dad3c0eb70a0..b9fec1c46e3d 100644
>>> --- a/mm/kfence/core.c
>>> +++ b/mm/kfence/core.c
>>> @@ -116,7 +116,7 @@ EXPORT_SYMBOL(__kfence_pool); /* Export for test=20
>>> modules. */
>>> =C2=A0=C2=A0 * backing pages (in __kfence_pool).
>>> =C2=A0=C2=A0 */
>>> =C2=A0 static_assert(CONFIG_KFENCE_NUM_OBJECTS > 0);
>>> -struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];
>>> +struct kfence_metadata *kfence_metadata;
>>>
>>> =C2=A0 /* Freelist with available objects. */
>>> =C2=A0 static struct list_head kfence_freelist =3D=20
>>> LIST_HEAD_INIT(kfence_freelist);
>>> @@ -643,13 +643,56 @@ static unsigned long kfence_init_pool(void)
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return addr;
>>> =C2=A0 }
>>>
>>> +static int kfence_alloc_metadata(void)
>>> +{
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long nr_pages =3D KFENCE=
_METADATA_SIZE / PAGE_SIZE;
>>> +
>>> +#ifdef CONFIG_CONTIG_ALLOC
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct page *pages;
>>> +
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pages =3D alloc_contig_pages(nr_p=
ages, GFP_KERNEL,=20
>>> first_online_node,
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 NULL);
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (pages)
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 kfence_metadata =3D page_to_virt(pages);
>>> +#else
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (nr_pages > MAX_ORDER_NR_PAGES=
) {
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 pr_warn("KFENCE_NUM_OBJECTS too large for buddy=20
>>> allocator\n");
>>
>> Does this mean that KFENCE won't work at all if we can't allocate the
>> metadata? I.e. it won't work either in early nor late init modes?
>>
>> I know we already have this limitation for _late init_ of the KFENCE=20
>> pool.
>>
>> So I have one major question: when doing _early init_, what is the
>> maximum size of the KFENCE pool (#objects) with this change?
> It will be limited to 2^10/sizeof(struct kfence_metadata) by buddy
                 Sorry,  2^10*PAGE_SIZE/sizeof(struct kfence_metadata)
> system, so I used memblock to allocate kfence_metadata in v2.
>>
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 return -EINVAL;
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kfence_metadata =3D alloc_pages_e=
xact(KFENCE_METADATA_SIZE,
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 GFP_KERNEL);
>>> +#endif
>>> +
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!kfence_metadata)
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 return -ENOMEM;
>>> +
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memset(kfence_metadata, 0, KFENCE=
_METADATA_SIZE);
>>
>> memzero_explicit, or pass __GFP_ZERO to alloc_pages?
> Unfortunately, __GFP_ZERO does not work successfully in
> alloc_contig_pages(), so I used memzero_explicit() in v2.
> Even though I don't know if memzero_explicit() is necessary
> (it just uses the barrier).
>>
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>>> +}
>>> +
>>> +static void kfence_free_metadata(void)
>>> +{
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (WARN_ON(!kfence_metadata))
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 return;
>>> +#ifdef CONFIG_CONTIG_ALLOC
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 free_contig_range(page_to_pfn(vir=
t_to_page((void=20
>>> *)kfence_metadata)),
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 KFENCE_METADATA_SIZE / PAGE_SIZE);
>>> +#else
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 free_pages_exact((void *)kfence_m=
etadata, KFENCE_METADATA_SIZE);
>>> +#endif
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kfence_metadata =3D NULL;
>>> +}
>>> +
>>> =C2=A0 static bool __init kfence_init_pool_early(void)
>>> =C2=A0 {
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long addr;
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long addr =3D (unsigned =
long)__kfence_pool;
>>>
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!__kfence_pool)
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 return false;
>>>
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!kfence_alloc_metadata())
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 goto free_pool;
>>> +
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 addr =3D kfence_init_p=
ool();
>>>
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!addr) {
>>> @@ -663,6 +706,7 @@ static bool __init kfence_init_pool_early(void)
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 return true;
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>>
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kfence_free_metadata();
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * Only release u=
nprotected pages, and do not try to go back=20
>>> and change
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * page attribute=
s due to risk of failing to do so as well.=20
>>> If changing
>>> @@ -670,31 +714,12 @@ static bool __init kfence_init_pool_early(void)
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * fails for the =
first page, and therefore expect=20
>>> addr=3D=3D__kfence_pool in
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * most failure c=
ases.
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>>> +free_pool:
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memblock_free_late(__p=
a(addr), KFENCE_POOL_SIZE - (addr -=20
>>> (unsigned long)__kfence_pool));
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __kfence_pool =3D NULL=
;
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return false;
>>> =C2=A0 }
>>>
>>> -static bool kfence_init_pool_late(void)
>>> -{
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long addr, free_size;
>>> -
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 addr =3D kfence_init_pool();
>>> -
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!addr)
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 return true;
>>> -
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Same as above. */
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 free_size =3D KFENCE_POOL_SIZE - =
(addr - (unsigned=20
>>> long)__kfence_pool);
>>> -#ifdef CONFIG_CONTIG_ALLOC
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 free_contig_range(page_to_pfn(vir=
t_to_page((void *)addr)),=20
>>> free_size / PAGE_SIZE);
>>> -#else
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 free_pages_exact((void *)addr, fr=
ee_size);
>>> -#endif
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __kfence_pool =3D NULL;
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return false;
>>> -}
>>> -
>>> =C2=A0 /* =3D=3D=3D DebugFS Interface=20
>>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D */
>>>
>>> =C2=A0 static int stats_show(struct seq_file *seq, void *v)
>>> @@ -896,6 +921,10 @@ void __init kfence_init(void)
>>> =C2=A0 static int kfence_init_late(void)
>>> =C2=A0 {
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 const unsigned long nr=
_pages =3D KFENCE_POOL_SIZE / PAGE_SIZE;
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long addr =3D (unsigned =
long)__kfence_pool;
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long free_size =3D KFENC=
E_POOL_SIZE;
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int ret;
>>> +
>>> =C2=A0 #ifdef CONFIG_CONTIG_ALLOC
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct page *pages;
>>>
>>> @@ -913,15 +942,29 @@ static int kfence_init_late(void)
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -ENOMEM;
>>> =C2=A0 #endif
>>>
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!kfence_init_pool_late()) {
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 pr_err("%s failed\n", __func__);
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 return -EBUSY;
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ret =3D kfence_alloc_metadata();
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!ret)
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 goto free_pool;
>>> +
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 addr =3D kfence_init_pool();
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!addr) {
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 kfence_init_enable();
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 kfence_debugfs_init();
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 return 0;
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>>
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kfence_init_enable();
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kfence_debugfs_init();
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pr_err("%s failed\n", __func__);
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kfence_free_metadata();
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 free_size =3D KFENCE_POOL_SIZE - =
(addr - (unsigned=20
>>> long)__kfence_pool);
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ret =3D -EBUSY;
>>>
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>>> +free_pool:
>>> +#ifdef CONFIG_CONTIG_ALLOC
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 free_contig_range(page_to_pfn(vir=
t_to_page((void *)addr)),=20
>>> free_size / PAGE_SIZE);
>>> +#else
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 free_pages_exact((void *)addr, fr=
ee_size);
>>> +#endif
>>
>> You moved this from kfence_init_pool_late - that did "__kfence_pool =3D
>> NULL" which is missing now.
> Thanks for spotting this, I added it in v2.
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ed82e6b9-3d9f-259a-82bc-cc51f9131f29%40bytedance.com.
