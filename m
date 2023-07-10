Return-Path: <kasan-dev+bncBDGZTDNQ3ICBB4WFV6SQMGQE3W33JZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4645D74D3E6
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Jul 2023 12:52:36 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-1b9c60aa6e7sf35513125ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Jul 2023 03:52:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688986354; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ikp29vyORFzDbdFgITwfI+IlXgp/qHNVQkJROUqiRZYWc2456XZDkWgDn0UgRS9XNd
         JfegdSJvpZIINRA15B8ao3xb01eT8c2n8PgqMkwQmhOIaFmYhmHKCwDi48QpmBLdlE6C
         GlqB0640bH08IsZpwTWfNmz5hwl2+GID+LvM4x8fWyHRN9yTECAmxNZwLHXOWCy7ovSS
         obGJDpBMD4YNbGj+MB0WQp8qNL56whrA+n05AIptDZQBXDC7JTK0RWdle9TvehEwUnAR
         r8FH1Eck1s50cezBwFHO1S7TkLmNgs2Cp4GVIgHzy7q3ol/qJwypmaCdTGyod9EGCJ/a
         HVHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=j7nTDG+sE68CImCwk1neaAUgfhE52k0FQdWZO2uxmfU=;
        fh=kGmpU18qIeuWxWR6Tm14lWzk4/s/cNVjNtDaRv1CHks=;
        b=z6qGoP5gA5aICSbGl6xdu7SGZwiLKs05FaWk+GXdzrCIx/DI7B5iS6cjHNjOb7rWNs
         B9TjfBUPlrb7vm7HkBDUuzPyxu0hM9xN3MUJcCsmErtE7ZT6mr0N7vrSEdvqC1jyC5gj
         s3oce3lvx9QOsNrBbJAY9CP0aPcrT5ZEcpcMxiX4B+LcDMzkkBoTl6z2N5ya89Oz6uN7
         m900R2TcSj4kqOQFvQ8AUreLSSOUBXBJmxeEGQLnk8Q3pWJyuqSJhiJX/JcsOIyM9Xbp
         12M6HSksFkXnyAltDYq11LXBGnb/QpT2usJfut9itYUVsJmYo2fkdAPlFiOPFvPpsX8d
         xr2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=QgNE2wco;
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688986354; x=1691578354;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=j7nTDG+sE68CImCwk1neaAUgfhE52k0FQdWZO2uxmfU=;
        b=aBykY/7bZ6Tf4rzkwjJvr/ZjgJX/HbDonreoBvLPwNAUdG3EeCEcSA9Yxrl9nWFiBS
         jZ9o2vGNGMM5tUg9UdO7cXb6qRfXp3pqrkJQbfx7/5CFKubm6hDG400bLNFhCtVmk/t4
         /U90wGDYPyHjn6zTtfucvfJ8E7Qs2QHBlj4NM9OFKGFkjGcJYcqZyVlkEWjFrdC4ln76
         uZ6h0ZoOh9eJnfVZ+HxFjsin1hhMvwYgCobEMr5ijJdj+4Z/QAfd7h6z4f51kfwShgRU
         TyXVGelw0zTtl5c/Izq0/qfLz8PMsxHJIWrIcilo47ICUOShNtAsYr5XAy4g+gejvTBE
         JweA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688986354; x=1691578354;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=j7nTDG+sE68CImCwk1neaAUgfhE52k0FQdWZO2uxmfU=;
        b=XE7Sz6hc8PMtomxHU21u+JsQjCjbPflREZG2+gv46Fd+PQLQVB0qn8R3RAuv2ReDyZ
         dDMrEWSbHS1qbp4PbY5RQ/zAn9PgN0XGj3drI2/iRHPeey2pfAjZI8S/Dw7sXEyZfygf
         s6L2qDn2oGMTRE4yguh6hveQ9N1M+2R7hbUVIXTgnjU5eENvJoI3PwCcmblt9tijrpb+
         cUvAZGvAd4hZ5f4IBBEVIDyvtIRMprHocYY96g8Mh5En/CiFL40I7PPJr4R8hb4PZVUy
         ntKEfS5VH1SYgrb8kbHcsO31YaZnGEj56ULnBu8vimksbdDkMZqSz5Fo84B8Lpc4HsXM
         959w==
X-Gm-Message-State: ABy/qLZoqWVS/NWlG6D+Kq/Xt/PaQFcv0CxYtz6WQDHzLtl1u9+wKQtO
	PhehBRGhpYzc0Y6cBKE1EKw=
X-Google-Smtp-Source: APBJJlHJnU+ZQ025UDyapS1x5j2/7oBO0EAwsLCAMQl7eEsO00sY/cN0wUf9lFhpynjqFaUdiOxORQ==
X-Received: by 2002:a05:6a20:6a23:b0:119:5af7:7cef with SMTP id p35-20020a056a206a2300b001195af77cefmr12071010pzk.56.1688986354510;
        Mon, 10 Jul 2023 03:52:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:fa8f:b0:1b8:7812:7eab with SMTP id
 lc15-20020a170902fa8f00b001b878127eabls2343830plb.2.-pod-prod-07-us; Mon, 10
 Jul 2023 03:52:33 -0700 (PDT)
X-Received: by 2002:a17:902:e5c1:b0:1b8:3dec:48de with SMTP id u1-20020a170902e5c100b001b83dec48demr11147247plf.47.1688986353557;
        Mon, 10 Jul 2023 03:52:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688986353; cv=none;
        d=google.com; s=arc-20160816;
        b=BJGeqPeLa3qM0E/7m1g3Dk2K+ogv5ZIyDPhYLjyeyRp7GKi6EgquNkycrdGl9u/0LP
         n43R1xcptSBrwn6FQ3zJ3ySlGgBZVag3jrmC60H8CEyvGxk0/3p/HLOFCBVsvpc6yp2V
         OhxEkkctNvCIW1ub3oQAKpNImgUJvOhxWSFUEFMVZ1HTXeOjaPOjAyr/ncqOxqVWCdB2
         zWgo3qC0Q8Xs77xHRy0dOD6Ep/rakPKNHCTO5QGVRu9lUt1dEcYfRjqzyXwZ5tlp+fHs
         +eA+wfFgrdSe5weP3ax0Be7LyJ9Hvy3fVuiTpW4fVkO4rgDHx9NkCPvq7Cd9ImyJNcKf
         UMqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=1qWr+V3gYZrsNg0XRx3MW3g+BVG6UNjjUpqVndfuvns=;
        fh=RRQysK4pMbWEknOkJw26PKZ2ruZSr5AxDIz17Rud4U0=;
        b=KkFRwdsXWC9j/LQ33cvtwu9//B4tYkgblLbIN+e1tkV9SiZvVwlzpT7Gt4Vmcq7qsK
         c4TS+WSSmgoltPhADDq5HXgWEL61xG//rdgPPPkugEqisuqJL/gbPEsRxwIQ0vwLbcBx
         MKKLOmEC2pM/9dv5k6ZdCrKTBl7/B57sa+ksqK2jSJGa71nT6bOgmGKTc7U0dKrQf9Ih
         pjMLFN3IsBhcZRnV6Nuz1hvQvv02xQ2dS+Yh9o+BDqlgIrT1XZ4E9EHeofsYmEon2Ie7
         bPGokacaovyG3VW9WCndFzdtakCGBBU37uxueKHeBSaJKNUagq3hj5bZC90tOJbnoS0v
         i1Iw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=QgNE2wco;
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-oi1-x22b.google.com (mail-oi1-x22b.google.com. [2607:f8b0:4864:20::22b])
        by gmr-mx.google.com with ESMTPS id q17-20020a170902c75100b001b55934ae62si456744plq.2.2023.07.10.03.52.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Jul 2023 03:52:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::22b as permitted sender) client-ip=2607:f8b0:4864:20::22b;
Received: by mail-oi1-x22b.google.com with SMTP id 5614622812f47-3a337ddff16so3329109b6e.0
        for <kasan-dev@googlegroups.com>; Mon, 10 Jul 2023 03:52:33 -0700 (PDT)
X-Received: by 2002:a05:6808:3d3:b0:3a3:d4e9:7d18 with SMTP id o19-20020a05680803d300b003a3d4e97d18mr10935100oie.2.1688986353095;
        Mon, 10 Jul 2023 03:52:33 -0700 (PDT)
Received: from [10.90.35.114] ([203.208.167.147])
        by smtp.gmail.com with ESMTPSA id z2-20020a637e02000000b00553ad4ae5e5sm7065863pgc.22.2023.07.10.03.52.29
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Jul 2023 03:52:32 -0700 (PDT)
Message-ID: <96a737e5-5545-04ed-e533-e322ffe20fce@bytedance.com>
Date: Mon, 10 Jul 2023 18:52:27 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:102.0)
 Gecko/20100101 Thunderbird/102.12.0
Subject: Re: [PATCH] mm: kfence: allocate kfence_metadata at runtime
To: Marco Elver <elver@google.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, muchun.song@linux.dev,
 Peng Zhang <zhangpeng.00@bytedance.com>
References: <20230710032714.26200-1-zhangpeng.00@bytedance.com>
 <CANpmjNOHz+dRbJsAyg29nksPMcd2P6109iPxTem_-b2qfUvXtw@mail.gmail.com>
 <ZKvbqidp7s8a/17O@elver.google.com>
From: "'Peng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <ZKvbqidp7s8a/17O@elver.google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: zhangpeng.00@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=QgNE2wco;       spf=pass
 (google.com: domain of zhangpeng.00@bytedance.com designates
 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
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



=E5=9C=A8 2023/7/10 18:21, Marco Elver =E5=86=99=E9=81=93:
> On Mon, Jul 10, 2023 at 12:19PM +0200, Marco Elver wrote:
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
>=20
> Forgot to attach .config -- attached config.
>=20
> All I see is:
>=20
> [    0.303465] rcu: RCU calculated value of scheduler-enlistment delay is=
 100 jiffies.
> [    0.304783] rcu: Adjusting geometry for rcu_fanout_leaf=3D16, nr_cpu_i=
ds=3D8
> [    0.316800] NR_IRQS: 4352, nr_irqs: 488, preallocated irqs: 16
> [    0.318140] rcu: srcu_init: Setting srcu_struct sizes based on content=
ion.
> [    0.320001] kfence: kfence_init failed
> [    0.326880] Console: colour VGA+ 80x25
> [    0.327585] printk: console [ttyS0] enabled
> [    0.327585] printk: console [ttyS0] enabled
>=20
> around KFENCE initialization.
Thanks for your review and testing, I'll take a look at the issues later.
>=20
>>> ---
>>>   mm/kfence/core.c   | 102 ++++++++++++++++++++++++++++++++------------=
-
>>>   mm/kfence/kfence.h |   5 ++-
>>>   2 files changed, 78 insertions(+), 29 deletions(-)
>>>
>>> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
>>> index dad3c0eb70a0..b9fec1c46e3d 100644
>>> --- a/mm/kfence/core.c
>>> +++ b/mm/kfence/core.c
>>> @@ -116,7 +116,7 @@ EXPORT_SYMBOL(__kfence_pool); /* Export for test mo=
dules. */
>>>    * backing pages (in __kfence_pool).
>>>    */
>>>   static_assert(CONFIG_KFENCE_NUM_OBJECTS > 0);
>>> -struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];
>>> +struct kfence_metadata *kfence_metadata;
>>>
>>>   /* Freelist with available objects. */
>>>   static struct list_head kfence_freelist =3D LIST_HEAD_INIT(kfence_fre=
elist);
>>> @@ -643,13 +643,56 @@ static unsigned long kfence_init_pool(void)
>>>          return addr;
>>>   }
>>>
>>> +static int kfence_alloc_metadata(void)
>>> +{
>>> +       unsigned long nr_pages =3D KFENCE_METADATA_SIZE / PAGE_SIZE;
>>> +
>>> +#ifdef CONFIG_CONTIG_ALLOC
>>> +       struct page *pages;
>>> +
>>> +       pages =3D alloc_contig_pages(nr_pages, GFP_KERNEL, first_online=
_node,
>>> +                                  NULL);
>>> +       if (pages)
>>> +               kfence_metadata =3D page_to_virt(pages);
>>> +#else
>>> +       if (nr_pages > MAX_ORDER_NR_PAGES) {
>>> +               pr_warn("KFENCE_NUM_OBJECTS too large for buddy allocat=
or\n");
>>
>> Does this mean that KFENCE won't work at all if we can't allocate the
>> metadata? I.e. it won't work either in early nor late init modes?
>>
>> I know we already have this limitation for _late init_ of the KFENCE poo=
l.
>>
>> So I have one major question: when doing _early init_, what is the
>> maximum size of the KFENCE pool (#objects) with this change?
>>
>>> +               return -EINVAL;
>>> +       }
>>> +       kfence_metadata =3D alloc_pages_exact(KFENCE_METADATA_SIZE,
>>> +                                           GFP_KERNEL);
>>> +#endif
>>> +
>>> +       if (!kfence_metadata)
>>> +               return -ENOMEM;
>>> +
>>> +       memset(kfence_metadata, 0, KFENCE_METADATA_SIZE);
>>
>> memzero_explicit, or pass __GFP_ZERO to alloc_pages?
>>
>>> +       return 0;
>>> +}
>>> +
>>> +static void kfence_free_metadata(void)
>>> +{
>>> +       if (WARN_ON(!kfence_metadata))
>>> +               return;
>>> +#ifdef CONFIG_CONTIG_ALLOC
>>> +       free_contig_range(page_to_pfn(virt_to_page((void *)kfence_metad=
ata)),
>>> +                         KFENCE_METADATA_SIZE / PAGE_SIZE);
>>> +#else
>>> +       free_pages_exact((void *)kfence_metadata, KFENCE_METADATA_SIZE)=
;
>>> +#endif
>>> +       kfence_metadata =3D NULL;
>>> +}
>>> +
>>>   static bool __init kfence_init_pool_early(void)
>>>   {
>>> -       unsigned long addr;
>>> +       unsigned long addr =3D (unsigned long)__kfence_pool;
>>>
>>>          if (!__kfence_pool)
>>>                  return false;
>>>
>>> +       if (!kfence_alloc_metadata())
>>> +               goto free_pool;
>>> +
>>>          addr =3D kfence_init_pool();
>>>
>>>          if (!addr) {
>>> @@ -663,6 +706,7 @@ static bool __init kfence_init_pool_early(void)
>>>                  return true;
>>>          }
>>>
>>> +       kfence_free_metadata();
>>>          /*
>>>           * Only release unprotected pages, and do not try to go back a=
nd change
>>>           * page attributes due to risk of failing to do so as well. If=
 changing
>>> @@ -670,31 +714,12 @@ static bool __init kfence_init_pool_early(void)
>>>           * fails for the first page, and therefore expect addr=3D=3D__=
kfence_pool in
>>>           * most failure cases.
>>>           */
>>> +free_pool:
>>>          memblock_free_late(__pa(addr), KFENCE_POOL_SIZE - (addr - (uns=
igned long)__kfence_pool));
>>>          __kfence_pool =3D NULL;
>>>          return false;
>>>   }
>>>
>>> -static bool kfence_init_pool_late(void)
>>> -{
>>> -       unsigned long addr, free_size;
>>> -
>>> -       addr =3D kfence_init_pool();
>>> -
>>> -       if (!addr)
>>> -               return true;
>>> -
>>> -       /* Same as above. */
>>> -       free_size =3D KFENCE_POOL_SIZE - (addr - (unsigned long)__kfenc=
e_pool);
>>> -#ifdef CONFIG_CONTIG_ALLOC
>>> -       free_contig_range(page_to_pfn(virt_to_page((void *)addr)), free=
_size / PAGE_SIZE);
>>> -#else
>>> -       free_pages_exact((void *)addr, free_size);
>>> -#endif
>>> -       __kfence_pool =3D NULL;
>>> -       return false;
>>> -}
>>> -
>>>   /* =3D=3D=3D DebugFS Interface =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D */
>>>
>>>   static int stats_show(struct seq_file *seq, void *v)
>>> @@ -896,6 +921,10 @@ void __init kfence_init(void)
>>>   static int kfence_init_late(void)
>>>   {
>>>          const unsigned long nr_pages =3D KFENCE_POOL_SIZE / PAGE_SIZE;
>>> +       unsigned long addr =3D (unsigned long)__kfence_pool;
>>> +       unsigned long free_size =3D KFENCE_POOL_SIZE;
>>> +       int ret;
>>> +
>>>   #ifdef CONFIG_CONTIG_ALLOC
>>>          struct page *pages;
>>>
>>> @@ -913,15 +942,29 @@ static int kfence_init_late(void)
>>>                  return -ENOMEM;
>>>   #endif
>>>
>>> -       if (!kfence_init_pool_late()) {
>>> -               pr_err("%s failed\n", __func__);
>>> -               return -EBUSY;
>>> +       ret =3D kfence_alloc_metadata();
>>> +       if (!ret)
>>> +               goto free_pool;
>>> +
>>> +       addr =3D kfence_init_pool();
>>> +       if (!addr) {
>>> +               kfence_init_enable();
>>> +               kfence_debugfs_init();
>>> +               return 0;
>>>          }
>>>
>>> -       kfence_init_enable();
>>> -       kfence_debugfs_init();
>>> +       pr_err("%s failed\n", __func__);
>>> +       kfence_free_metadata();
>>> +       free_size =3D KFENCE_POOL_SIZE - (addr - (unsigned long)__kfenc=
e_pool);
>>> +       ret =3D -EBUSY;
>>>
>>> -       return 0;
>>> +free_pool:
>>> +#ifdef CONFIG_CONTIG_ALLOC
>>> +       free_contig_range(page_to_pfn(virt_to_page((void *)addr)), free=
_size / PAGE_SIZE);
>>> +#else
>>> +       free_pages_exact((void *)addr, free_size);
>>> +#endif
>>
>> You moved this from kfence_init_pool_late - that did "__kfence_pool =3D
>> NULL" which is missing now.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/96a737e5-5545-04ed-e533-e322ffe20fce%40bytedance.com.
