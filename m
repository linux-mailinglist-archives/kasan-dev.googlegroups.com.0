Return-Path: <kasan-dev+bncBAABB4GLROQQMGQEI36SVMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2012E6CC01A
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 15:04:49 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id k4-20020a05651c10a400b0029a95d83debsf2641555ljn.23
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 06:04:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680008688; cv=pass;
        d=google.com; s=arc-20160816;
        b=fNo3PtCO3Q5iUu858BhrOTxCbfrFZVSWDi4daiQYmQwgkF4PwBl8jLsj2tFK/a1HyE
         FBPPVGDY1RrqeTem6TmzORwBoOPqk+znmH1YGyqGUeM+aqpUjHRENT3KxIGK+9LTy2Oi
         fckU88w/hrB71gwKPMG1AMpb8v2d2Wfij43+e4QyRfKrG0M4G3CqsJ8QnhSPXKjpPlFh
         0dnH66VW2KHgbSGZuAyjdqmQbf+nEjvfcWtDEQUQOUA7M3Y3OhHX4NQkRXE0tPn6fUTR
         kfdA5+12oIly++7muKTyMI1BgFMAVWeZn0S0gJfXF57UqkemeFl41i7nGFwHQTAAASgQ
         OoOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature;
        bh=xPZiZQVL2Lr/KFO5AA69N9gx4JOMpn9KrDEQpdblyOQ=;
        b=b7KUrJX44UW7Nk+WLvwf1ne4a6pXV2WHnxeFIKk0ZjeEY7yqlbC7cwx6hmJP65aQpj
         cq14SxCaAval38TS0tdfEKoPojBBK5563u2lUB4mNA4K7PO6SpMpWj19U/q3iornuP9/
         6hYHLnSDFbhuRBPaxb6nGaweysxN9m9SqyGAyEDoeY/KGIRFL/2MGbuzCNZv8dmFU1pl
         7iTJN4kbu8KnF6K35fADAhDc6v/3/4s1DNnZNAvNMyf1yEgUuuS/sHlVneMx1/0jgZQA
         1LaXrA/oZQl9T+dgUgXu29YwMFZONF91L3Xj+Xg95HoV/XZRiUm7HyGb8030ggYxgIRB
         1fng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=aPFwvaZd;
       spf=pass (google.com: domain of muchun.song@linux.dev designates 91.218.175.61 as permitted sender) smtp.mailfrom=muchun.song@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680008688;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xPZiZQVL2Lr/KFO5AA69N9gx4JOMpn9KrDEQpdblyOQ=;
        b=ZIU0pIUk8qkbi8rveHwImulqndlufnNHnapN6y9Gc1PxX+s4QDCDHGA6MyHTONvh+3
         EeJns1LRUBlXcMQauUD/poTX1sPPjaMem6B2c2W6ZEi4NTg2qNRutKBHupqu3rSXbppX
         d7VHezyGAHpX3QakDzC6J4hq93XyrhwVt3HT3YBD11pkco87gbEU/1id++7YT0qvRAO5
         /gSjMi3NzSDkcxqZzk2MI/LgeehMzZYFAQ+DzSpNl0m9Ezdl7/xxsGCsnyS1HLbCrlTr
         0ZfHqZp06729CX3j+9XgKhZp3BnMlzGUxCFzDGJdOIBZuYJP5wSxVY/x/eSDhiJVe7V2
         hg7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680008688;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:references
         :message-id:content-transfer-encoding:cc:date:in-reply-to:from
         :subject:mime-version:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=xPZiZQVL2Lr/KFO5AA69N9gx4JOMpn9KrDEQpdblyOQ=;
        b=3aM1Sqo8APlveAgK/1h15wVWw9gcYdYT0c+Kbb2P4oEw4TansiyitUIKM5c3QYqvvs
         9zWiIcNFRY5VVazWRBWJQbxLHq3ub9MTe/EWNjueaSPYvC+egD3MSEhV840s+/PfQgmA
         P2AYE6Pd3c/Swv+syzV9LEAECsBlGFjIu7J4qB3tpjgjrDkXV1a6Y2uXZghsijU+ZZjk
         zDdYpUAQLVX7cMdovJ6/WaYMjVpI88FdoBxZZknaM5syef458T9203dlAVkexuPa0kqM
         8/15v0sOq4arEOrtphat65ML//VN2ZVyiFlqmLGMWq+qgGFFjGTH1DJM6RxLZaeo+8k4
         AUJg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9cZwgVv8jfwhiQA7GiEajAz/yUdi78M9QGFTgX1TsLDunMMwXxq
	WKFjW1TR4yDsyig+H49I2o4=
X-Google-Smtp-Source: AKy350YodLM4yTsbp0UrimoaWq4jLX3F10TZtoRdXg2pI9FwoxMan8Rh2vp6vI4645lWIsiS2BWTOQ==
X-Received: by 2002:a2e:9887:0:b0:298:72a8:c6c4 with SMTP id b7-20020a2e9887000000b0029872a8c6c4mr4725328ljj.9.1680008688305;
        Tue, 28 Mar 2023 06:04:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2f1c:0:b0:295:b860:7804 with SMTP id v28-20020a2e2f1c000000b00295b8607804ls2131347ljv.5.-pod-prod-gmail;
 Tue, 28 Mar 2023 06:04:47 -0700 (PDT)
X-Received: by 2002:a2e:8e6f:0:b0:2a0:5a99:65d8 with SMTP id t15-20020a2e8e6f000000b002a05a9965d8mr6131912ljk.18.1680008687388;
        Tue, 28 Mar 2023 06:04:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680008687; cv=none;
        d=google.com; s=arc-20160816;
        b=uxui1oRK3zpAzr9iQdz+0vEWHfHckizNMecpCMWaGDfbuQYstmebkaNIs/sbVGWBS6
         5X4Y9UPUEDy37VnQTJy3SZZKm+vKOJtjaG+YbZaritE9rp9C8YXu4EKGqHHHTeCHBWh8
         lX6YpLowXVs+mT/flSa+KDgdHKC9MlNO50CYg7/flu/9q5ohFZA40AZSfnJ/0sNzDmuY
         8XxvEU4JNNfpXnUPBWH7NZO7LMvKDvwk84ajFL3ROWaCu+WHI15BZfbcZuL6LEw2wyLe
         aAjU4//x8masB46Mf27TV2uaoB6vcBYYljmj8ozlYKjShrDr+wm5kNnsn2kvyZImjwMY
         NAyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=Son+EeR8XyaKhlokwJs6j5Bs+OL8G7txoA1nBIX15Xk=;
        b=YgbQDFt7HcmdHjyTMPYGWqKYdTIm9zYZSFj0IeQTbHPFblG3SjbyhKZPa9SCD1Q3o+
         BBoFc8k7mMUYTD3P6z0+K3YwptgIry0m41glf8aAlRZkn8l1/T4QJ+vsTi1cxoIQlZv3
         Avll0jdsbnZuwxZsNUJDUQNxk6LGQRUAi0FxNlAZmWKiRJ1p5RGL6Lt7Dlfq9wZkxWB2
         qJveeWroIa10jguc7t1e2LnJNc1qbD8jSlYbgkPyFcqoSFEV1mlNykKCR15/b7ALnFOb
         eJyNt76H3BlaeuzkmTpAyl0kSNhXuYiTlC61L86j5NM4MIWX5wWGajRW8p8KZ5XrDC0n
         O/Mg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=aPFwvaZd;
       spf=pass (google.com: domain of muchun.song@linux.dev designates 91.218.175.61 as permitted sender) smtp.mailfrom=muchun.song@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-61.mta0.migadu.com (out-61.mta0.migadu.com. [91.218.175.61])
        by gmr-mx.google.com with ESMTPS id b9-20020a056512304900b004dbafe55d43si1219394lfb.13.2023.03.28.06.04.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 28 Mar 2023 06:04:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of muchun.song@linux.dev designates 91.218.175.61 as permitted sender) client-ip=91.218.175.61;
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
Subject: Re: [PATCH 3/6] mm: kfence: make kfence_protect_page() void
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Muchun Song <muchun.song@linux.dev>
In-Reply-To: <CANpmjNNry_OxZJFAKSFf9Cpb2SCWM-__AF25BpGwOXpa+DJBUQ@mail.gmail.com>
Date: Tue, 28 Mar 2023 21:04:11 +0800
Cc: Muchun Song <songmuchun@bytedance.com>,
 glider@google.com,
 dvyukov@google.com,
 akpm@linux-foundation.org,
 jannh@google.com,
 sjpark@amazon.de,
 kasan-dev@googlegroups.com,
 linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
Content-Transfer-Encoding: quoted-printable
Message-Id: <938ED660-4153-4F16-8115-E96BCAD51F35@linux.dev>
References: <20230328095807.7014-1-songmuchun@bytedance.com>
 <20230328095807.7014-4-songmuchun@bytedance.com>
 <CANpmjNNry_OxZJFAKSFf9Cpb2SCWM-__AF25BpGwOXpa+DJBUQ@mail.gmail.com>
To: Marco Elver <elver@google.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: muchun.song@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=aPFwvaZd;       spf=pass
 (google.com: domain of muchun.song@linux.dev designates 91.218.175.61 as
 permitted sender) smtp.mailfrom=muchun.song@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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



> On Mar 28, 2023, at 18:32, Marco Elver <elver@google.com> wrote:
>=20
> On Tue, 28 Mar 2023 at 11:58, Muchun Song <songmuchun@bytedance.com> wrot=
e:
>>=20
>> The arch_kfence_init_pool() make sure kfence pool is mapped with base pa=
ge
>> size (e.g. 4KB), so the following PTE lookup in kfence_protect_page() wi=
ll
>> always succeed. Then there is no way to stop kfence_protect_page() alway=
s
>> returning true, so make it void to simplify the code.
>>=20
>> Signed-off-by: Muchun Song <songmuchun@bytedance.com>
>> ---
>> arch/arm/include/asm/kfence.h     |   4 +-
>> arch/arm64/include/asm/kfence.h   |   4 +-
>> arch/parisc/include/asm/kfence.h  |   7 +-
>> arch/powerpc/include/asm/kfence.h |   8 +--
>> arch/riscv/include/asm/kfence.h   |   4 +-
>> arch/s390/include/asm/kfence.h    |   3 +-
>> arch/x86/include/asm/kfence.h     |   9 +--
>> mm/kfence/core.c                  | 142 +++++++++++++++++---------------=
------
>> 8 files changed, 73 insertions(+), 108 deletions(-)
>>=20
>> diff --git a/arch/arm/include/asm/kfence.h b/arch/arm/include/asm/kfence=
.h
>> index 7980d0f2271f..c30a5f8125e8 100644
>> --- a/arch/arm/include/asm/kfence.h
>> +++ b/arch/arm/include/asm/kfence.h
>> @@ -43,11 +43,9 @@ static inline bool arch_kfence_init_pool(void)
>>        return true;
>> }
>>=20
>> -static inline bool kfence_protect_page(unsigned long addr, bool protect=
)
>> +static inline void kfence_protect_page(unsigned long addr, bool protect=
)
>> {
>>        set_memory_valid(addr, 1, !protect);
>> -
>> -       return true;
>> }
>>=20
>> #endif /* __ASM_ARM_KFENCE_H */
>> diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kf=
ence.h
>> index a81937fae9f6..7717c6d98b6f 100644
>> --- a/arch/arm64/include/asm/kfence.h
>> +++ b/arch/arm64/include/asm/kfence.h
>> @@ -12,11 +12,9 @@
>>=20
>> static inline bool arch_kfence_init_pool(void) { return true; }
>>=20
>> -static inline bool kfence_protect_page(unsigned long addr, bool protect=
)
>> +static inline void kfence_protect_page(unsigned long addr, bool protect=
)
>> {
>>        set_memory_valid(addr, 1, !protect);
>> -
>> -       return true;
>> }
>>=20
>> #ifdef CONFIG_KFENCE
>> diff --git a/arch/parisc/include/asm/kfence.h b/arch/parisc/include/asm/=
kfence.h
>> index 6259e5ac1fea..290792009315 100644
>> --- a/arch/parisc/include/asm/kfence.h
>> +++ b/arch/parisc/include/asm/kfence.h
>> @@ -19,13 +19,10 @@ static inline bool arch_kfence_init_pool(void)
>> }
>>=20
>> /* Protect the given page and flush TLB. */
>> -static inline bool kfence_protect_page(unsigned long addr, bool protect=
)
>> +static inline void kfence_protect_page(unsigned long addr, bool protect=
)
>> {
>>        pte_t *pte =3D virt_to_kpte(addr);
>>=20
>> -       if (WARN_ON(!pte))
>> -               return false;
>> -
>>        /*
>>         * We need to avoid IPIs, as we may get KFENCE allocations or fau=
lts
>>         * with interrupts disabled.
>> @@ -37,8 +34,6 @@ static inline bool kfence_protect_page(unsigned long a=
ddr, bool protect)
>>                set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
>>=20
>>        flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
>> -
>> -       return true;
>> }
>>=20
>> #endif /* _ASM_PARISC_KFENCE_H */
>> diff --git a/arch/powerpc/include/asm/kfence.h b/arch/powerpc/include/as=
m/kfence.h
>> index 6fd2b4d486c5..9d8502a7d0a4 100644
>> --- a/arch/powerpc/include/asm/kfence.h
>> +++ b/arch/powerpc/include/asm/kfence.h
>> @@ -21,16 +21,14 @@ static inline bool arch_kfence_init_pool(void)
>> }
>>=20
>> #ifdef CONFIG_PPC64
>> -static inline bool kfence_protect_page(unsigned long addr, bool protect=
)
>> +static inline void kfence_protect_page(unsigned long addr, bool protect=
)
>> {
>>        struct page *page =3D virt_to_page(addr);
>>=20
>>        __kernel_map_pages(page, 1, !protect);
>> -
>> -       return true;
>> }
>> #else
>> -static inline bool kfence_protect_page(unsigned long addr, bool protect=
)
>> +static inline void kfence_protect_page(unsigned long addr, bool protect=
)
>> {
>>        pte_t *kpte =3D virt_to_kpte(addr);
>>=20
>> @@ -40,8 +38,6 @@ static inline bool kfence_protect_page(unsigned long a=
ddr, bool protect)
>>        } else {
>>                pte_update(&init_mm, addr, kpte, 0, _PAGE_PRESENT, 0);
>>        }
>> -
>> -       return true;
>> }
>> #endif
>>=20
>> diff --git a/arch/riscv/include/asm/kfence.h b/arch/riscv/include/asm/kf=
ence.h
>> index d887a54042aa..1299f47170b5 100644
>> --- a/arch/riscv/include/asm/kfence.h
>> +++ b/arch/riscv/include/asm/kfence.h
>> @@ -46,7 +46,7 @@ static inline bool arch_kfence_init_pool(void)
>>        return true;
>> }
>>=20
>> -static inline bool kfence_protect_page(unsigned long addr, bool protect=
)
>> +static inline void kfence_protect_page(unsigned long addr, bool protect=
)
>> {
>>        pte_t *pte =3D virt_to_kpte(addr);
>>=20
>> @@ -56,8 +56,6 @@ static inline bool kfence_protect_page(unsigned long a=
ddr, bool protect)
>>                set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
>>=20
>>        flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
>> -
>> -       return true;
>> }
>>=20
>> #endif /* _ASM_RISCV_KFENCE_H */
>> diff --git a/arch/s390/include/asm/kfence.h b/arch/s390/include/asm/kfen=
ce.h
>> index d55ba878378b..6d7b3632d79c 100644
>> --- a/arch/s390/include/asm/kfence.h
>> +++ b/arch/s390/include/asm/kfence.h
>> @@ -33,10 +33,9 @@ static __always_inline void kfence_split_mapping(void=
)
>> #endif
>> }
>>=20
>> -static inline bool kfence_protect_page(unsigned long addr, bool protect=
)
>> +static inline void kfence_protect_page(unsigned long addr, bool protect=
)
>> {
>>        __kernel_map_pages(virt_to_page(addr), 1, !protect);
>> -       return true;
>> }
>>=20
>> #endif /* _ASM_S390_KFENCE_H */
>> diff --git a/arch/x86/include/asm/kfence.h b/arch/x86/include/asm/kfence=
.h
>> index ff5c7134a37a..6ffd4a078a71 100644
>> --- a/arch/x86/include/asm/kfence.h
>> +++ b/arch/x86/include/asm/kfence.h
>> @@ -38,13 +38,9 @@ static inline bool arch_kfence_init_pool(void)
>> }
>>=20
>> /* Protect the given page and flush TLB. */
>> -static inline bool kfence_protect_page(unsigned long addr, bool protect=
)
>> +static inline void kfence_protect_page(unsigned long addr, bool protect=
)
>> {
>> -       unsigned int level;
>> -       pte_t *pte =3D lookup_address(addr, &level);
>> -
>> -       if (WARN_ON(!pte || level !=3D PG_LEVEL_4K))
>> -               return false;
>> +       pte_t *pte =3D virt_to_kpte(addr);
>=20
> This WARN and bailing here has helped us catch an issue early before
> [1] - and because KFENCE ought to be enabled as a debugging tool, the
> philosophy is to be failure tolerant and not crash the system here,
> hence the "return false".
>=20
> [1] https://lore.kernel.org/lkml/Y3bCV6VckVUEF7Pq@elver.google.com/

A good example.

>=20
> We're relying on the architecture doing the "right thing", but it's
> not entirely unlikely that the arch ends up doing the wrong thing due
> to some bug like above (i.e. arch_kfence_init_pool() is faulty).

Got it. I=E2=80=99ll drop this one next version.

Thanks

>=20
> Nack.


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/938ED660-4153-4F16-8115-E96BCAD51F35%40linux.dev.
