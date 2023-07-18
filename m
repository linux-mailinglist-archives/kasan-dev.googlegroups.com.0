Return-Path: <kasan-dev+bncBDGZTDNQ3ICBBVFL3KSQMGQEU35V6LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id C94B2757DCE
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jul 2023 15:38:30 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-265826eef7fsf3886064a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jul 2023 06:38:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689687509; cv=pass;
        d=google.com; s=arc-20160816;
        b=bHdtv505pMBH9Kd1FHUQaUdMXeHEhEi2mEWm19s2ZP8pgX4eQuYYEuu17hAJmSMqlY
         f837s8EYdm+RS8YFoZi6Bj8XJ2dQKmkDWnrueCMBtv8ln0Q/yo2ip68h/3YjIpwI/plB
         CVFkdujbB28eIdMZLn7516hg6VONnAHUq+AvWIw67jwtZXq8CkRg2BeSp4hbeWzv6wRt
         n14MERX3XX3Ngd4qgpOUPxhvEFyU0FIKxLhBw5+mFLyju58VYmAbsU3HYobD8cYtCz+W
         kNkVpN9IU/VpH5w7zzis6JKmK6qQzIpJLtGxGqcCMt6hUuWb4xqBSuW12d4CijMaWlSC
         YuvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=bIC0WxJCwnUGe02eZTD7lsQm6KPf3VCibxYjed2cMOw=;
        fh=WYQUEj+XJIYambhA0zrnIsBaRBwjUqIa8w/vySQUdh0=;
        b=AHRNj1po0sYHuMfuEYzh11CRxW8++2AhhupLPgAM6pbuLuej6mKBoRLisFW2eJ7QFs
         i8i6OkVvparRdNrFz6aDOzSF0PT8qsuSAXS8DZwjV37HA5xwhKM+JRvj6N2pgrkHkcuq
         nH2jIre40GvuDqYY9ZPa/rG8meJHnXQrc/1/yJ4/XtQzgKYjpkg5+yVBbo30Vi+A1IHp
         BJY5iqC4gH2t5PVRrgkJ86SIrvtgAm5P71blWmskwXURDOZPgZPGemo/foBJ3p8LTJbw
         WhjFEdcEQxOSv7A7BQ4rHmza8nbjgfp7MeOup/Us1LizuSXsUgV3pFrwEEhrAbDFIGjG
         2ZOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=b1Umzpai;
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689687509; x=1692279509;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bIC0WxJCwnUGe02eZTD7lsQm6KPf3VCibxYjed2cMOw=;
        b=P60/kFbham38D0M5juT0kNIWL5qZHFn1C/5144rTl1dVftWefv6NJkMfcvJAQN2VUO
         GC69wg+9T8E5hbMk7j4kQEeI/c73nTGrsp7cR7J0JXn5zka+KdHks18KEJ+7oicze1zQ
         2PbzTQIVP7eNDC2Bf8lYbU/72hDZV2TCxSMRHsC45yVSqZpzmAzMoS7Fh1tumxEGT9Ev
         R7mrXR7me7+vGfIcSB0P38NgRTuwR+hzpyuqKzVwLdF506lklzjU7SIrcJn8EO/cJdsE
         9PqlBRNUsb6qAe5cPNhrpb5epbzun6N53z1u677CG/+hyECi7XZ5mjT2hfLPwtj0jq2c
         cDVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689687509; x=1692279509;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=bIC0WxJCwnUGe02eZTD7lsQm6KPf3VCibxYjed2cMOw=;
        b=CsUDJQQBLw+yFBlV2uuWvrQv28eTJJv3MRmskDFwF/f6xBCStCD0xRCNyD/TEKqK5X
         ezmHoOB421rMOBKlNiL4/M4KaLHndan9EnAtXTTpObtNys5HzSIbk/qWEGAA7eR0Ahqf
         qxKb22d/UmKYHx/+ilqUKS96mOy9Q9IgJrT6n06YuE+XWbxeZpmISXYhDJdro546pkTp
         9ZcqAcVjPiK3Fu0LIFAKeTbaaJsyWLVuuJmUdNVzkqbpLb6uPIx/uIDb53GrjMWfs5Lo
         O+ZYOjKYZDvGqPpCpCpHioSxnFv1osTRangkyXt5NLRh95uSt1Q8l7c8A1y3nHUXv4GV
         J8qA==
X-Gm-Message-State: ABy/qLY2OmWnu4E6XF5RZh2HJBrBEuEffWrudioA5xDALR2cwPfLXTtU
	9QwKsL8CThq2VT0Y6taRUo8=
X-Google-Smtp-Source: APBJJlGwNwVY/E+Y01gFIHRZLEhxe8eDxNAM56zw62UwCm0CW8oQ1Uvy4YQrCVqjBIlDoBPx0tFEqQ==
X-Received: by 2002:a17:90a:ca91:b0:263:e121:5440 with SMTP id y17-20020a17090aca9100b00263e1215440mr16588807pjt.1.1689687508708;
        Tue, 18 Jul 2023 06:38:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:344f:b0:262:dc9e:41ce with SMTP id
 lj15-20020a17090b344f00b00262dc9e41cels19442pjb.0.-pod-prod-00-us; Tue, 18
 Jul 2023 06:38:27 -0700 (PDT)
X-Received: by 2002:a17:90a:8a97:b0:262:fe4b:b45 with SMTP id x23-20020a17090a8a9700b00262fe4b0b45mr16403666pjn.19.1689687507760;
        Tue, 18 Jul 2023 06:38:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689687507; cv=none;
        d=google.com; s=arc-20160816;
        b=hH4+B2DiK+A6RFwPfAVYy4m2rD+MD3S7JWd6QiGjuaClkROuMwyxlFbsnVIyDkG8CD
         1jpFXssiINwycEyIuRfIkCASiU6yV6/gt7PUUzbXr4oKI0hd/L0WzRgcRR+9pRdV0Ltq
         iwiZb6dwdrDn1JZhYBME7OP1CTDNRBzUabrXp3lqzVphhJPujRHllrtG9+PV/ULBTFla
         sX1bjf6LCgQO+haSmKixobIjGOB4jZufpkf9pIA9Z41BF3J824BwNm9b73Z1x895zxYz
         ZyBh5EpRzjvoYrDKBVfk39X6EQOqQm7qm7rfpNcQyGHhm/d6+q5SG/V+2d2xOLN8lThC
         URMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=NziHoVfZFFhfuKFtxtt/vmey+LhNNI63Y5vIKiT5rkw=;
        fh=I9kWM26mfHVu9nbi8P/VHOd7MilrfsmfWHv7qnhuYiM=;
        b=pcuB7siQ0UZIFpuEB5kmn1WAzeVxpnNHI/iUf3Jyc/IfJKrUWRmPu8+FcdlY6Ouw3c
         OcFjBacBiRiHi8Dbp+z2Y4bCJwDgR8GDWWRsSvoM9Y3moFfueosmM9uLNgiIVHtrKQmC
         O4/ZtdvXaT81p3/CM4/nlgMXL5HtYjwRQeJa4jvsxUN465F5AGnmA3eg+kqDCSXY+j88
         z/IPa+CgvqoyjujfTK42P6zqgVuQEUtmsmMl1ZSLG5ICgP3/jWYQRMuwm0cOuE7fL1XA
         0FwUr13pZ8OgePztzrCAsPCUJ/QAubKXf39v6nfv4EnymrB36hHjtnkw0Oui3w/Gs7r9
         Hsyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=b1Umzpai;
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pf1-x42a.google.com (mail-pf1-x42a.google.com. [2607:f8b0:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id pv1-20020a17090b3c8100b002676622daeesi466240pjb.1.2023.07.18.06.38.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Jul 2023 06:38:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::42a as permitted sender) client-ip=2607:f8b0:4864:20::42a;
Received: by mail-pf1-x42a.google.com with SMTP id d2e1a72fcca58-668711086f4so3532172b3a.1
        for <kasan-dev@googlegroups.com>; Tue, 18 Jul 2023 06:38:27 -0700 (PDT)
X-Received: by 2002:a05:6a00:a1f:b0:676:8fac:37 with SMTP id p31-20020a056a000a1f00b006768fac0037mr16053323pfh.4.1689687507340;
        Tue, 18 Jul 2023 06:38:27 -0700 (PDT)
Received: from [10.254.163.13] ([139.177.225.229])
        by smtp.gmail.com with ESMTPSA id q16-20020a62e110000000b00682a908949bsm1592229pfh.92.2023.07.18.06.38.20
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Jul 2023 06:38:27 -0700 (PDT)
Message-ID: <62d96d1c-cca6-6837-cb66-3fc79990ce40@bytedance.com>
Date: Tue, 18 Jul 2023 21:38:15 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:102.0)
 Gecko/20100101 Thunderbird/102.13.0
Subject: Re: [PATCH v3] mm: kfence: allocate kfence_metadata at runtime
To: Marco Elver <elver@google.com>, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, muchun.song@linux.dev,
 Kefeng Wang <wangkefeng.wang@huawei.com>,
 Peng Zhang <zhangpeng.00@bytedance.com>
References: <20230718073019.52513-1-zhangpeng.00@bytedance.com>
 <CANpmjNNUr17dKfBYumm54aqB9J-FaeWOW-az9cpkwMS6sd6+3A@mail.gmail.com>
From: "'Peng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CANpmjNNUr17dKfBYumm54aqB9J-FaeWOW-az9cpkwMS6sd6+3A@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: zhangpeng.00@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=b1Umzpai;       spf=pass
 (google.com: domain of zhangpeng.00@bytedance.com designates
 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
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



=E5=9C=A8 2023/7/18 20:39, Marco Elver =E5=86=99=E9=81=93:
> On Tue, 18 Jul 2023 at 09:30, Peng Zhang <zhangpeng.00@bytedance.com> wro=
te:
>>
>> kfence_metadata is currently a static array. For the purpose of allocati=
ng
>> scalable __kfence_pool, we first change it to runtime allocation of
>> metadata. Since the size of an object of kfence_metadata is 1160 bytes, =
we
>> can save at least 72 pages (with default 256 objects) without enabling
>> kfence.
>>
>> Signed-off-by: Peng Zhang <zhangpeng.00@bytedance.com>
>=20
> This looks good (minor nit below).
Andrew, if there is no need to update, can you help to add the
deleted blank line below? Thanks.
>=20
> Reviewed-by: Marco Elver <elver@google.com>
Marco, Thank you for your review!
>=20
> Thanks!
>=20
>> ---
>> Changes since v2:
>>   - Fix missing renaming of kfence_alloc_pool.
>>   - Add __read_mostly for kfence_metadata and kfence_metadata_init.
>>   - Use smp_store_release() and smp_load_acquire() to access kfence_meta=
data.
>>   - Some tweaks to comments and git log.
>>
>> v1: https://lore.kernel.org/lkml/20230710032714.26200-1-zhangpeng.00@byt=
edance.com/
>> v2: https://lore.kernel.org/lkml/20230712081616.45177-1-zhangpeng.00@byt=
edance.com/
>>
>>   include/linux/kfence.h |  11 ++--
>>   mm/kfence/core.c       | 124 ++++++++++++++++++++++++++++-------------
>>   mm/kfence/kfence.h     |   5 +-
>>   mm/mm_init.c           |   2 +-
>>   4 files changed, 97 insertions(+), 45 deletions(-)
>>
>> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
>> index 726857a4b680..401af4757514 100644
>> --- a/include/linux/kfence.h
>> +++ b/include/linux/kfence.h
>> @@ -59,15 +59,16 @@ static __always_inline bool is_kfence_address(const =
void *addr)
>>   }
>>
>>   /**
>> - * kfence_alloc_pool() - allocate the KFENCE pool via memblock
>> + * kfence_alloc_pool_and_metadata() - allocate the KFENCE pool and KFEN=
CE
>> + * metadata via memblock
>>    */
>> -void __init kfence_alloc_pool(void);
>> +void __init kfence_alloc_pool_and_metadata(void);
>>
>>   /**
>>    * kfence_init() - perform KFENCE initialization at boot time
>>    *
>> - * Requires that kfence_alloc_pool() was called before. This sets up th=
e
>> - * allocation gate timer, and requires that workqueues are available.
>> + * Requires that kfence_alloc_pool_and_metadata() was called before. Th=
is sets
>> + * up the allocation gate timer, and requires that workqueues are avail=
able.
>>    */
>>   void __init kfence_init(void);
>>
>> @@ -223,7 +224,7 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp, vo=
id *object, struct slab *sla
>>   #else /* CONFIG_KFENCE */
>>
>>   static inline bool is_kfence_address(const void *addr) { return false;=
 }
>> -static inline void kfence_alloc_pool(void) { }
>> +static inline void kfence_alloc_pool_and_metadata(void) { }
>>   static inline void kfence_init(void) { }
>>   static inline void kfence_shutdown_cache(struct kmem_cache *s) { }
>>   static inline void *kfence_alloc(struct kmem_cache *s, size_t size, gf=
p_t flags) { return NULL; }
>> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
>> index dad3c0eb70a0..6b526435886c 100644
>> --- a/mm/kfence/core.c
>> +++ b/mm/kfence/core.c
>> @@ -116,7 +116,15 @@ EXPORT_SYMBOL(__kfence_pool); /* Export for test mo=
dules. */
>>    * backing pages (in __kfence_pool).
>>    */
>>   static_assert(CONFIG_KFENCE_NUM_OBJECTS > 0);
>> -struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];
>> +struct kfence_metadata *kfence_metadata __read_mostly;
>> +
>> +/*
>> + * If kfence_metadata is not NULL, it may be accessed by kfence_shutdow=
n_cache().
>> + * So introduce kfence_metadata_init to initialize metadata, and then m=
ake
>> + * kfence_metadata visible after initialization is successful. This pre=
vents
>> + * potential UAF or access to uninitialized metadata.
>> + */
>> +static struct kfence_metadata *kfence_metadata_init __read_mostly;
>>
>>   /* Freelist with available objects. */
>>   static struct list_head kfence_freelist =3D LIST_HEAD_INIT(kfence_free=
list);
>> @@ -591,7 +599,7 @@ static unsigned long kfence_init_pool(void)
>>
>>                  __folio_set_slab(slab_folio(slab));
>>   #ifdef CONFIG_MEMCG
>> -               slab->memcg_data =3D (unsigned long)&kfence_metadata[i /=
 2 - 1].objcg |
>> +               slab->memcg_data =3D (unsigned long)&kfence_metadata_ini=
t[i / 2 - 1].objcg |
>>                                     MEMCG_DATA_OBJCGS;
>>   #endif
>>          }
>> @@ -610,7 +618,7 @@ static unsigned long kfence_init_pool(void)
>>          }
>>
>>          for (i =3D 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
>> -               struct kfence_metadata *meta =3D &kfence_metadata[i];
>> +               struct kfence_metadata *meta =3D &kfence_metadata_init[i=
];
>>
>>                  /* Initialize metadata. */
>>                  INIT_LIST_HEAD(&meta->list);
>> @@ -626,6 +634,12 @@ static unsigned long kfence_init_pool(void)
>>                  addr +=3D 2 * PAGE_SIZE;
>>          }
>>
>> +       /*
>> +        * Make kfence_metadata visible only when initialization is succ=
essful.
>> +        * Otherwise, if the initialization fails and kfence_metadata is=
 freed,
>> +        * it may cause UAF in kfence_shutdown_cache().
>> +        */
>> +       smp_store_release(&kfence_metadata, kfence_metadata_init);
>>          return 0;
>>
>>   reset_slab:
>> @@ -672,26 +686,10 @@ static bool __init kfence_init_pool_early(void)
>>           */
>>          memblock_free_late(__pa(addr), KFENCE_POOL_SIZE - (addr - (unsi=
gned long)__kfence_pool));
>>          __kfence_pool =3D NULL;
>> -       return false;
>> -}
>> -
>> -static bool kfence_init_pool_late(void)
>> -{
>> -       unsigned long addr, free_size;
>>
>> -       addr =3D kfence_init_pool();
>> -
>> -       if (!addr)
>> -               return true;
>> +       memblock_free_late(__pa(kfence_metadata_init), KFENCE_METADATA_S=
IZE);
>> +       kfence_metadata_init =3D NULL;
>>
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
>>          return false;
>>   }
>>
>> @@ -841,19 +839,30 @@ static void toggle_allocation_gate(struct work_str=
uct *work)
>>
>>   /* =3D=3D=3D Public interface =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D */
>>
>> -void __init kfence_alloc_pool(void)
>> +void __init kfence_alloc_pool_and_metadata(void)
>>   {
>>          if (!kfence_sample_interval)
>>                  return;
>>
>> -       /* if the pool has already been initialized by arch, skip the be=
low. */
>> -       if (__kfence_pool)
>> -               return;
>> -
>> -       __kfence_pool =3D memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
>> -
>> +       /*
>> +        * If the pool has already been initialized by arch, there is no=
 need to
>> +        * re-allocate the memory pool.
>> +        */
>>          if (!__kfence_pool)
>> +               __kfence_pool =3D memblock_alloc(KFENCE_POOL_SIZE, PAGE_=
SIZE);
>> +
>> +       if (!__kfence_pool) {
>>                  pr_err("failed to allocate pool\n");
>> +               return;
>> +       }
>> +
>> +       /* The memory allocated by memblock has been zeroed out. */
>> +       kfence_metadata_init =3D memblock_alloc(KFENCE_METADATA_SIZE, PA=
GE_SIZE);
>> +       if (!kfence_metadata_init) {
>> +               pr_err("failed to allocate metadata\n");
>> +               memblock_free(__kfence_pool, KFENCE_POOL_SIZE);
>> +               __kfence_pool =3D NULL;
>> +       }
>>   }
>>
>>   static void kfence_init_enable(void)
>> @@ -895,33 +904,68 @@ void __init kfence_init(void)
>>
>>   static int kfence_init_late(void)
>>   {
>> -       const unsigned long nr_pages =3D KFENCE_POOL_SIZE / PAGE_SIZE;
>> +       const unsigned long nr_pages_pool =3D KFENCE_POOL_SIZE / PAGE_SI=
ZE;
>> +       const unsigned long nr_pages_meta =3D KFENCE_METADATA_SIZE / PAG=
E_SIZE;
>> +       unsigned long addr =3D (unsigned long)__kfence_pool;
>> +       unsigned long free_size =3D KFENCE_POOL_SIZE;
>> +       int err =3D -ENOMEM;
>> +
>>   #ifdef CONFIG_CONTIG_ALLOC
>>          struct page *pages;
>> -
>=20
> Unnecessary blank line removal (it looks worse now).
>=20
>=20
>> -       pages =3D alloc_contig_pages(nr_pages, GFP_KERNEL, first_online_=
node, NULL);
>> +       pages =3D alloc_contig_pages(nr_pages_pool, GFP_KERNEL, first_on=
line_node,
>> +                                  NULL);
>>          if (!pages)
>>                  return -ENOMEM;
>> +
>>          __kfence_pool =3D page_to_virt(pages);
>> +       pages =3D alloc_contig_pages(nr_pages_meta, GFP_KERNEL, first_on=
line_node,
>> +                                  NULL);
>> +       if (pages)
>> +               kfence_metadata_init =3D page_to_virt(pages);
>>   #else
>> -       if (nr_pages > MAX_ORDER_NR_PAGES) {
>> +       if (nr_pages_pool > MAX_ORDER_NR_PAGES ||
>> +           nr_pages_meta > MAX_ORDER_NR_PAGES) {
>>                  pr_warn("KFENCE_NUM_OBJECTS too large for buddy allocat=
or\n");
>>                  return -EINVAL;
>>          }
>> +
>>          __kfence_pool =3D alloc_pages_exact(KFENCE_POOL_SIZE, GFP_KERNE=
L);
>>          if (!__kfence_pool)
>>                  return -ENOMEM;
>> +
>> +       kfence_metadata_init =3D alloc_pages_exact(KFENCE_METADATA_SIZE,=
 GFP_KERNEL);
>>   #endif
>>
>> -       if (!kfence_init_pool_late()) {
>> -               pr_err("%s failed\n", __func__);
>> -               return -EBUSY;
>> +       if (!kfence_metadata_init)
>> +               goto free_pool;
>> +
>> +       memzero_explicit(kfence_metadata_init, KFENCE_METADATA_SIZE);
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
>> +       free_size =3D KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence=
_pool);
>> +       err =3D -EBUSY;
>>
>> -       return 0;
>> +#ifdef CONFIG_CONTIG_ALLOC
>> +       free_contig_range(page_to_pfn(virt_to_page((void *)kfence_metada=
ta_init)),
>> +                         nr_pages_meta);
>> +free_pool:
>> +       free_contig_range(page_to_pfn(virt_to_page((void *)addr)),
>> +                         free_size / PAGE_SIZE);
>> +#else
>> +       free_pages_exact((void *)kfence_metadata_init, KFENCE_METADATA_S=
IZE);
>> +free_pool:
>> +       free_pages_exact((void *)addr, free_size);
>> +#endif
>> +
>> +       kfence_metadata_init =3D NULL;
>> +       __kfence_pool =3D NULL;
>> +       return err;
>>   }
>>
>>   static int kfence_enable_late(void)
>> @@ -941,6 +985,10 @@ void kfence_shutdown_cache(struct kmem_cache *s)
>>          struct kfence_metadata *meta;
>>          int i;
>>
>> +       /* Pairs with release in kfence_init_pool(). */
>> +       if (!smp_load_acquire(&kfence_metadata))
>> +               return;
>> +
>>          for (i =3D 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
>>                  bool in_use;
>>
>> diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
>> index 392fb273e7bd..f46fbb03062b 100644
>> --- a/mm/kfence/kfence.h
>> +++ b/mm/kfence/kfence.h
>> @@ -102,7 +102,10 @@ struct kfence_metadata {
>>   #endif
>>   };
>>
>> -extern struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS=
];
>> +#define KFENCE_METADATA_SIZE PAGE_ALIGN(sizeof(struct kfence_metadata) =
* \
>> +                                       CONFIG_KFENCE_NUM_OBJECTS)
>> +
>> +extern struct kfence_metadata *kfence_metadata;
>>
>>   static inline struct kfence_metadata *addr_to_metadata(unsigned long a=
ddr)
>>   {
>> diff --git a/mm/mm_init.c b/mm/mm_init.c
>> index 7f7f9c677854..3d0a63c75829 100644
>> --- a/mm/mm_init.c
>> +++ b/mm/mm_init.c
>> @@ -2721,7 +2721,7 @@ void __init mm_core_init(void)
>>           */
>>          page_ext_init_flatmem();
>>          mem_debugging_and_hardening_init();
>> -       kfence_alloc_pool();
>> +       kfence_alloc_pool_and_metadata();
>>          report_meminit();
>>          kmsan_init_shadow();
>>          stack_depot_early_init();
>> --
>> 2.20.1
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/62d96d1c-cca6-6837-cb66-3fc79990ce40%40bytedance.com.
