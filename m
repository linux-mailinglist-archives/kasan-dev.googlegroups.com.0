Return-Path: <kasan-dev+bncBAABBFGZROQQMGQEPYFKMOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id B0C2A6CC102
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 15:33:09 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id m5-20020a194345000000b004eae18274b7sf4749657lfj.19
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 06:33:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680010389; cv=pass;
        d=google.com; s=arc-20160816;
        b=0FE4gKqA+Fv2259MedNygWfD7+x5Hx8nh3ciCbPZupccQ2KylVRRbto5j48f/nz+EF
         X/+YehxFHTSQ4SzdrNukbk7V24QipA5+l5p3cXLNBkMNiLwg9p1qBimpa0iXxxX+bOvK
         7hsWYaaP2YXRDJ5h4QQUwz0CfNimRuTlG8PsfLkA6CEr6YSGHi5juqUG2zKFDUlMXqyq
         ToMP69YOlPKjwpgewl5lL7lyY0vZEFbsSbkOO63vEHnvaE2UQljj4gomejNzlIGYjRAY
         /5MHRwPYp0QFdj92WjT3c1RvNDXl6l6/UZcr1OqQqbRiF/okoZjhBj6KscqfSI6+uZmO
         cTMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id:cc:date
         :in-reply-to:from:subject:mime-version:sender:dkim-signature;
        bh=c8U5lpKOtKy/l+q86uUHfwlIW7hPg/BncPQMVTd9Y3k=;
        b=wtpMy7POuHOrscJ146ei61hGR2A/M+vTY3WpDQwe8GSUC9RoGpORVedX/lOkawIeCv
         mzlDqYElFzR7emPXsSzMKoiRaxNAZ7hpivhaRS1rt1t8bBrW27Lj7VIvZQ636CiacvH7
         zQ/UuR1HazH5SnD+3WK16WOeRAJpYF2SrtdZRpM4xo8BGNDUO8XThKltdMoVpErqYxIs
         /F2+GPIut+cTH4kWqhus9lTzDci9pq1+UBWf9an8mv6VF0T9YuTYfsZRc6lhMidMv+Px
         GyuF3V6frbcftxmTWXXKeLJgDmyaL1F3yTqWnhDKadmoOpIYKxQNY6vWTM6qgvriogV8
         ZA6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=h+3S9y6b;
       spf=pass (google.com: domain of muchun.song@linux.dev designates 2001:41d0:203:375::25 as permitted sender) smtp.mailfrom=muchun.song@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680010389;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:references:message-id:cc:date:in-reply-to:from
         :subject:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=c8U5lpKOtKy/l+q86uUHfwlIW7hPg/BncPQMVTd9Y3k=;
        b=ASCs3InZRSGu47UIz4FvSzoDxzGfA/IoWLsvBR3quWPl9GNt0XaMA5oC5nn8VHS9c2
         uPd/AEJ6Pusa7clD/2JYA6GHGfsl6R2Tu8xrcSGfTPRsMsIBKdiQF86BBmdNDer/Sby5
         OZux/rvxjZCxIXHU4vXJFhKuV/7RSoFDVmMha9v4ktgYVZXsP/B+NBBlLuQ8E8A0ZQq8
         gRD7XKMXF+dmwfP4js2dmMHlgKfpLESHSpTXYlGui5HZImfKBt5g2LZU2MnkCcO/DQqU
         qzHNsmgKixAd6+GXsdCdj0IutxF0ktrkWP4Cob0KrqerMKIfqshjlpVl/h7gNM1wIhEv
         +Nbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680010389;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:references
         :message-id:cc:date:in-reply-to:from:subject:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=c8U5lpKOtKy/l+q86uUHfwlIW7hPg/BncPQMVTd9Y3k=;
        b=X+VN+SFqmtZ7dqyspadU5Z8PYfTP8GS6PjDlifAWl9rnYSmJndg2pQd7MN8d8wMqmm
         2HcF4AaJJ9geSe2Cp8gLkp2XX04Jev9xO+7Ffuz36clZzrsTs9fHdaVuvVK6ocUKlRvn
         HhC8aC4pKN+KqBA4Mc03ARVDZCMFFastpGHvniLIaPZJZMtfcCHdBVfQaySaz7uMTu0B
         dZK1ioGdOTM6sv9V2bUiZdle1IYcQ5O2Lz+QyWPDu7QXTxCALImKxbLx2sgyoH+UcIip
         3+rMNrDyMVtRSutVB3IwYEs8HgE5pz5cN/gOaqdY4pbOPkzXfRTy7z8aKR0SROAaJZlK
         2eJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9dZ+VJQ4jk39yBDO3plVGcMQl1W1dw3OBYyTazKPlVrC1DaOyYB
	bbvyWLSFEsrO8cYpqoYi9UQ=
X-Google-Smtp-Source: AKy350aqI5aSiFi8gQU7qlYC9oIcHI2rI79NIdFEns9I3UO8HbAjBxQX9jkttqkYMfACeajjsldtew==
X-Received: by 2002:ac2:4473:0:b0:4eb:eaf:aa00 with SMTP id y19-20020ac24473000000b004eb0eafaa00mr2364555lfl.4.1680010388666;
        Tue, 28 Mar 2023 06:33:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1585:b0:4e9:c006:ce26 with SMTP id
 bp5-20020a056512158500b004e9c006ce26ls3889261lfb.3.-pod-prod-gmail; Tue, 28
 Mar 2023 06:33:07 -0700 (PDT)
X-Received: by 2002:a05:6512:7c:b0:4ea:e640:2a58 with SMTP id i28-20020a056512007c00b004eae6402a58mr5304348lfo.42.1680010387511;
        Tue, 28 Mar 2023 06:33:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680010387; cv=none;
        d=google.com; s=arc-20160816;
        b=ymHLr3QL9Xr9oxXarhtIYKvWN0ZoHa63frv13LgeGqbn7exVsXDAVtFE3XKn1Wp0DJ
         Zv1J/GbISBv7KlestH1edZ1yZRbWbRvXPBgFbZY8YW+GMZkH8xXgIHlPTBKdK4U4ZqrJ
         pDnGdxdDLS7KmDC7n1aGReeNHD9T3XdjxYebNr+twBh5hPqmiSAmizcskw+6A2IHkb3R
         L4zfPaGhhz+Zm2uxRa81HBM546phe/3bJjvcpFRWX4WfOd43vT+VAIc1YuMEDb5o77uZ
         nllt40pjQIsZRvtgR6zFlGCjj6CIgptCBFLefC8qCNn4wNt7xuaPAqH2mEk5SjoZgMcb
         JNEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=bApSM0pbQ1TIIJavw9zL4ET4YoxmQnS6zSB9mo2QPVs=;
        b=NzeG5sUamWtkea/OW0mc87TICR64av3dM6JaVCey9lAF2Fz1YqVK2WShzkd50AGN/O
         Gxj1CGr0EOXtcCk6ka5JjrZP4XpUEgKvHvKCiYqESoM9+CYQ0VG7R6D4OaPqNAFgzD/t
         skxXjc18eGABo0hA7kbwuQ3eWSqmXq1G4ygYIGU0QyRqmlEMLWfOFc8lp6xuzFPhK6wa
         AcQ+mBxtOquPEZQDXG7RrLYoHMk3K4ySfhD0fuh9bU6oeo4YoGj7hIAilwQvkryx9UWp
         QBCrAFwSWgv1OXM560Ljvp/w+r6QTivPjXdbZCVk3jBPEreRAZg8iTbTkaJWCAkof+M7
         cWEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=h+3S9y6b;
       spf=pass (google.com: domain of muchun.song@linux.dev designates 2001:41d0:203:375::25 as permitted sender) smtp.mailfrom=muchun.song@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-37.mta1.migadu.com (out-37.mta1.migadu.com. [2001:41d0:203:375::25])
        by gmr-mx.google.com with ESMTPS id w32-20020a0565120b2000b004dd8416c0d6si1428538lfu.0.2023.03.28.06.33.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 28 Mar 2023 06:33:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of muchun.song@linux.dev designates 2001:41d0:203:375::25 as permitted sender) client-ip=2001:41d0:203:375::25;
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
Subject: Re: [PATCH 5/6] mm: kfence: change kfence pool page layout
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Muchun Song <muchun.song@linux.dev>
In-Reply-To: <CANpmjNPZxDYPYzEjr55ONydwH1FZF_Eh_gu7XKg=4-+HK6vL9Q@mail.gmail.com>
Date: Tue, 28 Mar 2023 21:32:28 +0800
Cc: Muchun Song <songmuchun@bytedance.com>,
 glider@google.com,
 dvyukov@google.com,
 akpm@linux-foundation.org,
 jannh@google.com,
 sjpark@amazon.de,
 kasan-dev@googlegroups.com,
 linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
Message-Id: <291FB0BF-F824-4ED9-B836-DA7773BFDA48@linux.dev>
References: <20230328095807.7014-1-songmuchun@bytedance.com>
 <20230328095807.7014-6-songmuchun@bytedance.com>
 <CANpmjNPZxDYPYzEjr55ONydwH1FZF_Eh_gu7XKg=4-+HK6vL9Q@mail.gmail.com>
To: Marco Elver <elver@google.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: muchun.song@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=h+3S9y6b;       spf=pass
 (google.com: domain of muchun.song@linux.dev designates 2001:41d0:203:375::25
 as permitted sender) smtp.mailfrom=muchun.song@linux.dev;       dmarc=pass
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



> On Mar 28, 2023, at 20:59, Marco Elver <elver@google.com> wrote:
> 
> On Tue, 28 Mar 2023 at 11:58, 'Muchun Song' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
>> 
>> The original kfence pool layout (Given a layout with 2 objects):
>> 
>> +------------+------------+------------+------------+------------+------------+
>> | guard page | guard page |   object   | guard page |   object   | guard page |
>> +------------+------------+------------+------------+------------+------------+
>>                           |                         | |
>>                           +----kfence_metadata[0]---+----kfence_metadata[1]---+
>> 
>> The comment says "the additional page in the beginning gives us an even
>> number of pages, which simplifies the mapping of address to metadata index".
>> 
>> However, removing the additional page does not complicate any mapping
>> calculations. So changing it to the new layout to save a page. And remmove
>> the KFENCE_ERROR_INVALID test since we cannot test this case easily.
>> 
>> The new kfence pool layout (Given a layout with 2 objects):
>> 
>> +------------+------------+------------+------------+------------+
>> | guard page |   object   | guard page |   object   | guard page |
>> +------------+------------+------------+------------+------------+
>> |                         |                         |
>> +----kfence_metadata[0]---+----kfence_metadata[1]---+
>> 
>> Signed-off-by: Muchun Song <songmuchun@bytedance.com>
>> ---
>> include/linux/kfence.h  |  8 ++------
>> mm/kfence/core.c        | 40 ++++++++--------------------------------
>> mm/kfence/kfence.h      |  2 +-
>> mm/kfence/kfence_test.c | 14 --------------
>> 4 files changed, 11 insertions(+), 53 deletions(-)
>> 
>> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
>> index 726857a4b680..25b13a892717 100644
>> --- a/include/linux/kfence.h
>> +++ b/include/linux/kfence.h
>> @@ -19,12 +19,8 @@
>> 
>> extern unsigned long kfence_sample_interval;
>> 
>> -/*
>> - * We allocate an even number of pages, as it simplifies calculations to map
>> - * address to metadata indices; effectively, the very first page serves as an
>> - * extended guard page, but otherwise has no special purpose.
>> - */
>> -#define KFENCE_POOL_SIZE ((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZE)
>> +/* The last page serves as an extended guard page. */
> 
> The last page is just a normal guard page? I.e. the last 2 pages are:
> <object page> | <guard page>

Right.

The new kfence pool layout (Given a layout with 2 objects):

+------------+------------+------------+------------+------------+
| guard page |   object   | guard page |   object   | guard page |
+------------+------------+------------+------------+------------+
|                         |                         |     ^
+----kfence_metadata[0]---+----kfence_metadata[1]---+     |
                                                          |
                                                          |
                                                     the last page

> 
> Or did I misunderstand?
> 
>> +#define KFENCE_POOL_SIZE       ((CONFIG_KFENCE_NUM_OBJECTS * 2 + 1) * PAGE_SIZE)
>> extern char *__kfence_pool;
>> 
>> DECLARE_STATIC_KEY_FALSE(kfence_allocation_key);
>> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
>> index 41befcb3b069..f205b860f460 100644
>> --- a/mm/kfence/core.c
>> +++ b/mm/kfence/core.c
>> @@ -240,24 +240,7 @@ static inline void kfence_unprotect(unsigned long addr)
>> 
>> static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *meta)
>> {
>> -       unsigned long offset = (meta - kfence_metadata + 1) * PAGE_SIZE * 2;
>> -       unsigned long pageaddr = (unsigned long)&__kfence_pool[offset];
>> -
>> -       /* The checks do not affect performance; only called from slow-paths. */
>> -
>> -       /* Only call with a pointer into kfence_metadata. */
>> -       if (KFENCE_WARN_ON(meta < kfence_metadata ||
>> -                          meta >= kfence_metadata + CONFIG_KFENCE_NUM_OBJECTS))
>> -               return 0;
> 
> Could we retain this WARN_ON? Or just get rid of
> metadata_to_pageaddr() altogether, because there's only 1 use left and
> the function would now just be a simple ALIGN_DOWN() anyway.

I'll inline this function to its caller since the warning is unlikely.

> 
>> -       /*
>> -        * This metadata object only ever maps to 1 page; verify that the stored
>> -        * address is in the expected range.
>> -        */
>> -       if (KFENCE_WARN_ON(ALIGN_DOWN(meta->addr, PAGE_SIZE) != pageaddr))
>> -               return 0;
>> -
>> -       return pageaddr;
>> +       return ALIGN_DOWN(meta->addr, PAGE_SIZE);
>> }
>> 
>> /*
>> @@ -535,34 +518,27 @@ static void kfence_init_pool(void)
>>        unsigned long addr = (unsigned long)__kfence_pool;
>>        int i;
>> 
>> -       /*
>> -        * Protect the first 2 pages. The first page is mostly unnecessary, and
>> -        * merely serves as an extended guard page. However, adding one
>> -        * additional page in the beginning gives us an even number of pages,
>> -        * which simplifies the mapping of address to metadata index.
>> -        */
>> -       for (i = 0; i < 2; i++, addr += PAGE_SIZE)
>> -               kfence_protect(addr);
>> -
>>        for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++, addr += 2 * PAGE_SIZE) {
>>                struct kfence_metadata *meta = &kfence_metadata[i];
>> -               struct slab *slab = page_slab(virt_to_page(addr));
>> +               struct slab *slab = page_slab(virt_to_page(addr + PAGE_SIZE));
>> 
>>                /* Initialize metadata. */
>>                INIT_LIST_HEAD(&meta->list);
>>                raw_spin_lock_init(&meta->lock);
>>                meta->state = KFENCE_OBJECT_UNUSED;
>> -               meta->addr = addr; /* Initialize for validation in metadata_to_pageaddr(). */
>> +               meta->addr = addr + PAGE_SIZE;
>>                list_add_tail(&meta->list, &kfence_freelist);
>> 
>> -               /* Protect the right redzone. */
>> -               kfence_protect(addr + PAGE_SIZE);
>> +               /* Protect the left redzone. */
>> +               kfence_protect(addr);
>> 
>>                __folio_set_slab(slab_folio(slab));
>> #ifdef CONFIG_MEMCG
>>                slab->memcg_data = (unsigned long)&meta->objcg | MEMCG_DATA_OBJCGS;
>> #endif
>>        }
>> +
>> +       kfence_protect(addr);
>> }
>> 
>> static bool __init kfence_init_pool_early(void)
>> @@ -1043,7 +1019,7 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
>> 
>>        atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
>> 
>> -       if (page_index % 2) {
>> +       if (page_index % 2 == 0) {
>>                /* This is a redzone, report a buffer overflow. */
>>                struct kfence_metadata *meta;
>>                int distance = 0;
>> diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
>> index 600f2e2431d6..249d420100a7 100644
>> --- a/mm/kfence/kfence.h
>> +++ b/mm/kfence/kfence.h
>> @@ -110,7 +110,7 @@ static inline struct kfence_metadata *addr_to_metadata(unsigned long addr)
>>         * __kfence_pool, in which case we would report an "invalid access"
>>         * error.
>>         */
>> -       index = (addr - (unsigned long)__kfence_pool) / (PAGE_SIZE * 2) - 1;
>> +       index = (addr - (unsigned long)__kfence_pool) / (PAGE_SIZE * 2);
>>        if (index < 0 || index >= CONFIG_KFENCE_NUM_OBJECTS)
>>                return NULL;
> 
> Assume there is a right OOB that hit the last guard page. In this case
> 
>  addr >= __kfence_pool + (NUM_OBJECTS * 2 * PAGE_SIZE) && addr <
> __kfence_pool + POOL_SIZE
> 
> therefore
> 
>  index >= (NUM_OBJECTS * 2 * PAGE_SIZE) / (PAGE_SIZE * 2) && index <
> POOL_SIZE / (PAGE_SIZE * 2)
>  index == NUM_OBJECTS
> 
> And according to the above comparison, this will return NULL and
> report KFENCE_ERROR_INVALID, which is wrong.

Look at kfence_handle_page_fault(), which first look up "addr - PAGE_SIZE" (passed
to addr_to_metadata()) and then look up "addr + PAGE_SIZE", the former will not
return NULL, the latter will return NULL. So kfence will report KFENCE_ERROR_OOB
in this case, right? Or what I missed here?

> 
>> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
>> index b5d66a69200d..d479f9c8afb1 100644
>> --- a/mm/kfence/kfence_test.c
>> +++ b/mm/kfence/kfence_test.c
>> @@ -637,19 +637,6 @@ static void test_gfpzero(struct kunit *test)
>>        KUNIT_EXPECT_FALSE(test, report_available());
>> }
>> 
>> -static void test_invalid_access(struct kunit *test)
>> -{
>> -       const struct expect_report expect = {
>> -               .type = KFENCE_ERROR_INVALID,
>> -               .fn = test_invalid_access,
>> -               .addr = &__kfence_pool[10],
>> -               .is_write = false,
>> -       };
>> -
>> -       READ_ONCE(__kfence_pool[10]);
>> -       KUNIT_EXPECT_TRUE(test, report_matches(&expect));
>> -}
>> -
>> /* Test SLAB_TYPESAFE_BY_RCU works. */
>> static void test_memcache_typesafe_by_rcu(struct kunit *test)
>> {
>> @@ -787,7 +774,6 @@ static struct kunit_case kfence_test_cases[] = {
>>        KUNIT_CASE(test_kmalloc_aligned_oob_write),
>>        KUNIT_CASE(test_shrink_memcache),
>>        KUNIT_CASE(test_memcache_ctor),
>> -       KUNIT_CASE(test_invalid_access),
> 
> The test can be retained by doing an access to a guard page in between
> 2 unallocated objects. But it's probably not that easy to reliably set
> that up (could try to allocate 2 objects and see if they're next to
> each other, then free them).

Yes, it's not easy to trigger it 100%. So I removed the test.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/291FB0BF-F824-4ED9-B836-DA7773BFDA48%40linux.dev.
