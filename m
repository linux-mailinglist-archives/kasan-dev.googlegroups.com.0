Return-Path: <kasan-dev+bncBDGZTDNQ3ICBBOGIXGSQMGQENKUFGJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id D4F6E75017B
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Jul 2023 10:28:41 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id af79cd13be357-76735d5eb86sf955369085a.3
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Jul 2023 01:28:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689150520; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZMNY62d8IJ0dtZ+CxXTheqhCeWlbiCNsPh6UonTDn1cvUNUgfvkKh6cgroT7/FU7lo
         kUMyzS5pb3HWNQ6FytgiTTjzqz18OuT14fiOvgX+5n7SGyx2PmTvdDEejNK6yzpxxYHd
         vdKKFkJgc+fT7jNPAzIB97ot7GiQuJCqIpCZO5kwRcOwV4wUjRzxzlejapPf1MK+qPHY
         NbAHFg/8TGGy5x1tJaG//vpclDPxuG2HubZ+SN08sKYw76xKgWcVXmNhptD1MLQFhq/z
         qBZRjKtIWPS6ULcf8/UrWMFBqlMBnjWuxeC+RoqFaUGQFWbAjiYRzwDEQrTBAurNlCFs
         492A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=XZVIYd8g/htTirGB/GJoswWBRhSqzuhIRkOPbjnfmCs=;
        fh=kGmpU18qIeuWxWR6Tm14lWzk4/s/cNVjNtDaRv1CHks=;
        b=0bPwmnzaijd9eGynI2e8WwnkORTMkXeVPYvLdP/vQXvFJXO6cqQKGD6/PNZN99YHnO
         sustNkEfEij8uqWDZDH2N/CfjPVr9oAYbMTs11r87vZVrkOL8tlWmIjLVT1kZv3u31gk
         Y5p16AGh3purPaWZ5+betnWwQ0iyShr+HERst48lxRobGhBdvz1yGYwUPjyt0FkR+lYY
         H+1zik711JeyF45PAVrprMETLNgo/PFqbXySiONNHAUbwrkz9joFvMHFXpxwlDpHFtKS
         wrIEbhjER6DBS5F0y5t4o8t2uU4aRkeDwV2dOGspNE1r8EsEun/fT55K/Q+5ruBf7Q9W
         wwOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b="D2i/AltB";
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689150520; x=1691742520;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XZVIYd8g/htTirGB/GJoswWBRhSqzuhIRkOPbjnfmCs=;
        b=gdDGK0LNBm3+PfU7jlH7n0BkCa/2UAEqU+XOdHsoBeLWl0VtiC4FFz1yTVIwnGsQqT
         Q7RqDSMRc9Ag9h1biKk6lnbGrE6++hlh8ZuW5E7ZD/ULplM+ETuGZbfcr+YjVuGnmKCV
         CNiekosmRkdJXiaduqdxips/tW9RYwnWCMGUdvH94SFb5r6D4k7KZI3we6t99CXE2UsU
         fCByyc7JXaGcZvopdaBP1d4nqCrMEEQEPzKj/IlAMyHWJpouFNTPqRQBmc+RcD5HFoR3
         tooFLvzVtcOzCQdri5cEKVsMUORE8oB94U2t4aFbCM074stgKeDKYUlzD99O1iR6bcJt
         8XLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689150520; x=1691742520;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=XZVIYd8g/htTirGB/GJoswWBRhSqzuhIRkOPbjnfmCs=;
        b=OIL5s3WnuD/GcXjTYs6nk4ZAlBSKTyi00smP9MDof2xRFnYssnEFS2DGNC84emng2z
         004sMbCvHW5jrUpwOHQhp0NGVSki6Q8/WN5az+Udk2NzQCqJd+XCC7jmb+/1fNPhnpKi
         7nOdt6QtuMDQyUSH1qlO48ujumdQ0MmHNXzFhqSxhzUpzBYE+v3Vd0q2KAntepR7JEPn
         jlSUnOKOrapqDmFEGv3gg6ysr9CMTbakW9pU9Rlm1N9aWWSSi7oDjHbxcLpVEw+2ax9V
         LcKNd+XdNQPuUD6gU5VWsexICw7Qw9BHjQHY+IUbnBAGY8K0ZHmctaF7gIYd7+K9p6uA
         Z9UQ==
X-Gm-Message-State: ABy/qLaiYzyt343rRy9QtH+FzLeR0gzJzPoO8YisxlHkRBk5SB/icVTk
	1vHy4FDGIgskjyzVWlaCpJQ=
X-Google-Smtp-Source: APBJJlEU/65ZAqP5YZcTAYMOYUYCq6+mtlqkF93sT0t75XetMIGuOxp6K4MgVlWnU6R8+34D2cuVYA==
X-Received: by 2002:a05:622a:1305:b0:3f8:58d:713 with SMTP id v5-20020a05622a130500b003f8058d0713mr22265367qtk.55.1689150520421;
        Wed, 12 Jul 2023 01:28:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:6a13:0:b0:403:ac2a:e862 with SMTP id t19-20020ac86a13000000b00403ac2ae862ls324484qtr.0.-pod-prod-04-us;
 Wed, 12 Jul 2023 01:28:39 -0700 (PDT)
X-Received: by 2002:ac8:7f94:0:b0:3f6:b7a3:8450 with SMTP id z20-20020ac87f94000000b003f6b7a38450mr22617095qtj.64.1689150519886;
        Wed, 12 Jul 2023 01:28:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689150519; cv=none;
        d=google.com; s=arc-20160816;
        b=ZwwDe/pwNubvKZZKVldlIZYf8lwfW+n/aELB6NyvlWmmuWBSfxJC+dde1YlGGyFZXn
         kJgmavFiHs7nYXNTYTuuOehUuhrJ3rybDI+YPbanUdXXm+lqG9cSBeDa8kuUigSdVu1p
         D2csIQxqy1fVBd4WVZJjqrAKIpZmwi5Fw3c+zrhc+Ek5nUYnv68oI6He29LluZ4ACyQG
         Z5QrYyhlW6UcTgQO43tOwX0BqwyX1SB+DCzl0m/wbkmoPadY1NIlym4SbaHkB+aVZyX3
         PRwz6VjbeCsNXQZXMhuNQrgm5QmeV1u/vwYP0W3TMW6tYs4KjnSpknchCgl078ihw/lD
         hkfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=MKOx3ji7cu7+toV6q7E7Pf07IRWv+R94CaV9atCugGs=;
        fh=RRQysK4pMbWEknOkJw26PKZ2ruZSr5AxDIz17Rud4U0=;
        b=FbA2hqFdDjia4BcVcSvgyJVf7FVE0S0nWypJiW02A+pWIxWMAUEBGzb5OlBXiMKl6F
         uvliTd8USlcgfXOT/sCSYUJ+pdc5uwMgQ6COmhAQcqcwVHUnPRDsq7c6lu6S8/pVCrmU
         osnkSAHllYEEgKwhCMGsV2hy3pVYEbMl7ARvDUbFWKrvMbqPxaVpt2wTQ8i1DVq461qV
         m59BF+A9KDM2+yJUUqwEbV9UzpoFfMxJwpKq0kC3o/pAtebLwoGzdHykWFkM4dUqdBM7
         Eey/Q36kCHICM1SeCVuppq75kgacWyH7LSavypm4oylxRYOuSAJZeiyQXeE7UKjZ1D7N
         9cPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b="D2i/AltB";
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-oi1-x234.google.com (mail-oi1-x234.google.com. [2607:f8b0:4864:20::234])
        by gmr-mx.google.com with ESMTPS id fz23-20020a05622a5a9700b00403beff66b3si163679qtb.0.2023.07.12.01.28.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Jul 2023 01:28:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::234 as permitted sender) client-ip=2607:f8b0:4864:20::234;
Received: by mail-oi1-x234.google.com with SMTP id 5614622812f47-3a412653335so1654888b6e.1
        for <kasan-dev@googlegroups.com>; Wed, 12 Jul 2023 01:28:39 -0700 (PDT)
X-Received: by 2002:a05:6808:152a:b0:3a3:ff72:14bf with SMTP id u42-20020a056808152a00b003a3ff7214bfmr9905777oiw.33.1689150518771;
        Wed, 12 Jul 2023 01:28:38 -0700 (PDT)
Received: from [10.254.22.102] ([139.177.225.243])
        by smtp.gmail.com with ESMTPSA id x16-20020a056a00271000b00672ea40b8a9sm3122098pfv.170.2023.07.12.01.28.35
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Jul 2023 01:28:38 -0700 (PDT)
Message-ID: <2a16a76c-506c-f325-6792-4fb58e8da531@bytedance.com>
Date: Wed, 12 Jul 2023 16:28:32 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:102.0)
 Gecko/20100101 Thunderbird/102.13.0
Subject: Re: [PATCH] mm: kfence: allocate kfence_metadata at runtime
To: Marco Elver <elver@google.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, muchun.song@linux.dev,
 Peng Zhang <zhangpeng.00@bytedance.com>
References: <20230710032714.26200-1-zhangpeng.00@bytedance.com>
 <CANpmjNOHz+dRbJsAyg29nksPMcd2P6109iPxTem_-b2qfUvXtw@mail.gmail.com>
From: "'Peng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CANpmjNOHz+dRbJsAyg29nksPMcd2P6109iPxTem_-b2qfUvXtw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: zhangpeng.00@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b="D2i/AltB";       spf=pass
 (google.com: domain of zhangpeng.00@bytedance.com designates
 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
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



=E5=9C=A8 2023/7/10 18:19, Marco Elver =E5=86=99=E9=81=93:
> On Mon, 10 Jul 2023 at 05:27, 'Peng Zhang' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
>>
>> kfence_metadata is currently a static array. For the purpose of
>> allocating scalable __kfence_pool, we first change it to runtime
>> allocation of metadata. Since the size of an object of kfence_metadata
>> is 1160 bytes, we can save at least 72 pages (with default 256 objects)
>> without enabling kfence.
>>
>> Below is the numbers obtained in qemu (with default 256 objects).
>> before: Memory: 8134692K/8388080K available (3668K bss)
>> after: Memory: 8136740K/8388080K available (1620K bss)
>> More than expected, it saves 2MB memory.
>>
>> Signed-off-by: Peng Zhang <zhangpeng.00@bytedance.com>
>=20
> Seems like a reasonable optimization, but see comments below.
>=20
> Also with this patch applied on top of v6.5-rc1, KFENCE just doesn't
> init at all anymore (early init). Please fix.
I'm very sorry because I made a slight modification before sending the
patch but it has not been tested, which caused it to not work properly.
I fixed some of the issues you mentioned in v2[1].

[1]=20
https://lore.kernel.org/lkml/20230712081616.45177-1-zhangpeng.00@bytedance.=
com/

>=20
>> ---
>>   mm/kfence/core.c   | 102 ++++++++++++++++++++++++++++++++-------------
>>   mm/kfence/kfence.h |   5 ++-
>>   2 files changed, 78 insertions(+), 29 deletions(-)
>>
>> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
>> index dad3c0eb70a0..b9fec1c46e3d 100644
>> --- a/mm/kfence/core.c
>> +++ b/mm/kfence/core.c
>> @@ -116,7 +116,7 @@ EXPORT_SYMBOL(__kfence_pool); /* Export for test mod=
ules. */
>>    * backing pages (in __kfence_pool).
>>    */
>>   static_assert(CONFIG_KFENCE_NUM_OBJECTS > 0);
>> -struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];
>> +struct kfence_metadata *kfence_metadata;
>>
>>   /* Freelist with available objects. */
>>   static struct list_head kfence_freelist =3D LIST_HEAD_INIT(kfence_free=
list);
>> @@ -643,13 +643,56 @@ static unsigned long kfence_init_pool(void)
>>          return addr;
>>   }
>>
>> +static int kfence_alloc_metadata(void)
>> +{
>> +       unsigned long nr_pages =3D KFENCE_METADATA_SIZE / PAGE_SIZE;
>> +
>> +#ifdef CONFIG_CONTIG_ALLOC
>> +       struct page *pages;
>> +
>> +       pages =3D alloc_contig_pages(nr_pages, GFP_KERNEL, first_online_=
node,
>> +                                  NULL);
>> +       if (pages)
>> +               kfence_metadata =3D page_to_virt(pages);
>> +#else
>> +       if (nr_pages > MAX_ORDER_NR_PAGES) {
>> +               pr_warn("KFENCE_NUM_OBJECTS too large for buddy allocato=
r\n");
>=20
> Does this mean that KFENCE won't work at all if we can't allocate the
> metadata? I.e. it won't work either in early nor late init modes?
>=20
> I know we already have this limitation for _late init_ of the KFENCE pool=
.
>=20
> So I have one major question: when doing _early init_, what is the
> maximum size of the KFENCE pool (#objects) with this change?
It will be limited to 2^10/sizeof(struct kfence_metadata) by buddy
system, so I used memblock to allocate kfence_metadata in v2.
>=20
>> +               return -EINVAL;
>> +       }
>> +       kfence_metadata =3D alloc_pages_exact(KFENCE_METADATA_SIZE,
>> +                                           GFP_KERNEL);
>> +#endif
>> +
>> +       if (!kfence_metadata)
>> +               return -ENOMEM;
>> +
>> +       memset(kfence_metadata, 0, KFENCE_METADATA_SIZE);
>=20
> memzero_explicit, or pass __GFP_ZERO to alloc_pages?
Unfortunately, __GFP_ZERO does not work successfully in
alloc_contig_pages(), so I used memzero_explicit() in v2.
Even though I don't know if memzero_explicit() is necessary
(it just uses the barrier).
>=20
>> +       return 0;
>> +}
>> +
>> +static void kfence_free_metadata(void)
>> +{
>> +       if (WARN_ON(!kfence_metadata))
>> +               return;
>> +#ifdef CONFIG_CONTIG_ALLOC
>> +       free_contig_range(page_to_pfn(virt_to_page((void *)kfence_metada=
ta)),
>> +                         KFENCE_METADATA_SIZE / PAGE_SIZE);
>> +#else
>> +       free_pages_exact((void *)kfence_metadata, KFENCE_METADATA_SIZE);
>> +#endif
>> +       kfence_metadata =3D NULL;
>> +}
>> +
>>   static bool __init kfence_init_pool_early(void)
>>   {
>> -       unsigned long addr;
>> +       unsigned long addr =3D (unsigned long)__kfence_pool;
>>
>>          if (!__kfence_pool)
>>                  return false;
>>
>> +       if (!kfence_alloc_metadata())
>> +               goto free_pool;
>> +
>>          addr =3D kfence_init_pool();
>>
>>          if (!addr) {
>> @@ -663,6 +706,7 @@ static bool __init kfence_init_pool_early(void)
>>                  return true;
>>          }
>>
>> +       kfence_free_metadata();
>>          /*
>>           * Only release unprotected pages, and do not try to go back an=
d change
>>           * page attributes due to risk of failing to do so as well. If =
changing
>> @@ -670,31 +714,12 @@ static bool __init kfence_init_pool_early(void)
>>           * fails for the first page, and therefore expect addr=3D=3D__k=
fence_pool in
>>           * most failure cases.
>>           */
>> +free_pool:
>>          memblock_free_late(__pa(addr), KFENCE_POOL_SIZE - (addr - (unsi=
gned long)__kfence_pool));
>>          __kfence_pool =3D NULL;
>>          return false;
>>   }
>>
>> -static bool kfence_init_pool_late(void)
>> -{
>> -       unsigned long addr, free_size;
>> -
>> -       addr =3D kfence_init_pool();
>> -
>> -       if (!addr)
>> -               return true;
>> -
>> -       /* Same as above. */
>> -       free_size =3D KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence=
_pool);
>> -#ifdef CONFIG_CONTIG_ALLOC
>> -       free_contig_range(page_to_pfn(virt_to_page((void *)addr)), free_=
size / PAGE_SIZE);
>> -#else
>> -       free_pages_exact((void *)addr, free_size);
>> -#endif
>> -       __kfence_pool =3D NULL;
>> -       return false;
>> -}
>> -
>>   /* =3D=3D=3D DebugFS Interface =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D */
>>
>>   static int stats_show(struct seq_file *seq, void *v)
>> @@ -896,6 +921,10 @@ void __init kfence_init(void)
>>   static int kfence_init_late(void)
>>   {
>>          const unsigned long nr_pages =3D KFENCE_POOL_SIZE / PAGE_SIZE;
>> +       unsigned long addr =3D (unsigned long)__kfence_pool;
>> +       unsigned long free_size =3D KFENCE_POOL_SIZE;
>> +       int ret;
>> +
>>   #ifdef CONFIG_CONTIG_ALLOC
>>          struct page *pages;
>>
>> @@ -913,15 +942,29 @@ static int kfence_init_late(void)
>>                  return -ENOMEM;
>>   #endif
>>
>> -       if (!kfence_init_pool_late()) {
>> -               pr_err("%s failed\n", __func__);
>> -               return -EBUSY;
>> +       ret =3D kfence_alloc_metadata();
>> +       if (!ret)
>> +               goto free_pool;
>> +
>> +       addr =3D kfence_init_pool();
>> +       if (!addr) {
>> +               kfence_init_enable();
>> +               kfence_debugfs_init();
>> +               return 0;
>>          }
>>
>> -       kfence_init_enable();
>> -       kfence_debugfs_init();
>> +       pr_err("%s failed\n", __func__);
>> +       kfence_free_metadata();
>> +       free_size =3D KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence=
_pool);
>> +       ret =3D -EBUSY;
>>
>> -       return 0;
>> +free_pool:
>> +#ifdef CONFIG_CONTIG_ALLOC
>> +       free_contig_range(page_to_pfn(virt_to_page((void *)addr)), free_=
size / PAGE_SIZE);
>> +#else
>> +       free_pages_exact((void *)addr, free_size);
>> +#endif
>=20
> You moved this from kfence_init_pool_late - that did "__kfence_pool =3D
> NULL" which is missing now.
Thanks for spotting this, I added it in v2.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/2a16a76c-506c-f325-6792-4fb58e8da531%40bytedance.com.
