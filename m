Return-Path: <kasan-dev+bncBAABBZ6GROQQMGQEHKKT5BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E0686CBFDE
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 14:54:00 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id a29-20020a194f5d000000b004e9b4f6387csf4658693lfk.0
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 05:54:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680008039; cv=pass;
        d=google.com; s=arc-20160816;
        b=YRgWmqYgIh/Dx66oWJ6TOdaAtvCbDmwVER8OlOtIiGBF3YEtCJdzBiK07TRZucbWBq
         AOip3tvl9YRw6j0DmE9QPbC8Gxkl0HFYUQHwyIQxG82ZYB7+AzN03VqEkjyD56Nk7RqK
         rib7yYpiEJZwH+kiodn0L2HcH4hiVeue4vZ5kMm4q59X2ZCrwc+CKPc6fKYt2hcx2s5f
         15Q3lgSvIF81O7evmf1GpjQaRyRYLqiPXxI/Yz1UHq29ULmCTLkDvcChECWIyI4r7SXC
         6zKLXTs4z+B20tgR/EAfl7J7/Dz1K6BVsMSbJW3RZgAeYWketMDfHNcl5MFv8ZMZ7TtQ
         Vprw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id:cc:date
         :in-reply-to:from:subject:mime-version:sender:dkim-signature;
        bh=MM8J1bRHCwCihfQEiwRSEOPM70okloFCCwLqwlB7was=;
        b=FJjI97LJz3juNYOPNATrGBgmU5ITCU1ID7AJ7QNnCKVYMU+7JK5khd0SwRrocGpYMO
         NS3USvj/hHRpz7FLPNnQ7ISYs5T8mM6vDvMLue82wDD8AyBykjdfW7syp5YhJR+wxo6O
         EkLakcEhbEaRFL1n2QCuh6KTN0razn9oPQ/vjYaYSPajL6aCEZhMjW596fdfLzK5E490
         1bQ9hmFan6oLerhxxTonZ/OHr3H7bNSfsD4C5EAngfR0Hir1LhzNmiHV1i6KbPlZSR7j
         UwxaxX6b3VmHc22V643kKOyJjwsv7mh3O4fKT52I6zVc6QvdmI9aMAJB8TXjfESaeN2p
         RLcg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=JcgQBtGA;
       spf=pass (google.com: domain of muchun.song@linux.dev designates 2001:41d0:1004:224b::e as permitted sender) smtp.mailfrom=muchun.song@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680008039;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:references:message-id:cc:date:in-reply-to:from
         :subject:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MM8J1bRHCwCihfQEiwRSEOPM70okloFCCwLqwlB7was=;
        b=YTYaZ9RFqWQkCGiIzqplBZvT0C92nfaIpk0sOz4/ruseyDbNEKiGLSKdN5E3YM/Fd4
         iTfwBf4c24YSr208LXtz89PKHsWK+oGMToVwB/onZ8diqNm7xnSneZ+aq8xBxeTKtvuU
         X8u7tTR3hT/oov4RCz7FT42HN2YCyQaGgzocuRpYktequVF1Fa3/aeq93rJ5ZCXnxihR
         hr1W3MzM3qvkp5Xqj/LPjeXBmg3pVnMSh32AQyxDFrgfSh3opmYVrpkvJ/UmPw6tgfzY
         NBS+f/47NNiInVBeia6PMh9VAxiOjMgkXXLaZf8oYU9JrGj6Gj2aihlnrErLSib+v8+W
         LkRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680008039;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:references
         :message-id:cc:date:in-reply-to:from:subject:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MM8J1bRHCwCihfQEiwRSEOPM70okloFCCwLqwlB7was=;
        b=EpdgQI5R9NJd9/n0H4NOPJeaYex5j+dIwLfVfxZvMg5Za8IsZm/524WmXPMTmrw6dP
         LbcONI7LvZwNOjw/I38jnwloCJR8Oxc05oobQHRevi+Vt3Q/vfdX4tFi2WMe6Lvc4JLe
         QMOF78Lgf02RnrPm6gv8b4DnwDb0Sex1Ygg+h2dGAygwt+HxVptrQo2DfyqO3aPLvXEB
         8IE8wgMXLjPjjAx+O6vyuXk4p9OXVmd6uW20QWNZ5V/HJ2ONcOzlJMZZG2H462QATI+A
         +ZQD1v+S/sB90mmkppdU9u++IbDJriobihfpJMvfaSYVtTAGaX0FKxVWU0TfsrFq8tAs
         BOYA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9ddza2/SJZiTELP8Y1rmY2eEOWBaL/UMCULLI65kMs5PCqDpu29
	bsD4Gmy9TsiKeq/s4LYdHNk=
X-Google-Smtp-Source: AKy350aJ5RIGODlsSRhJBSZMg2ZSdlwKMuBcNWOEobtwC+4qL8Gfg0P1QCEN4BzAxgV6XjaPQixGKA==
X-Received: by 2002:ac2:50d9:0:b0:4ea:fa15:5bce with SMTP id h25-20020ac250d9000000b004eafa155bcemr4579615lfm.7.1680008039349;
        Tue, 28 Mar 2023 05:53:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2f1c:0:b0:295:b860:7804 with SMTP id v28-20020a2e2f1c000000b00295b8607804ls2123700ljv.5.-pod-prod-gmail;
 Tue, 28 Mar 2023 05:53:58 -0700 (PDT)
X-Received: by 2002:a2e:99c6:0:b0:29b:d29d:c781 with SMTP id l6-20020a2e99c6000000b0029bd29dc781mr5450304ljj.19.1680008038275;
        Tue, 28 Mar 2023 05:53:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680008038; cv=none;
        d=google.com; s=arc-20160816;
        b=MzCWl/B3wsWds8IxyEzfYkIQA/hikW6U60ccksSflVNTGKOdRwtKRq3IlhjmDg3GwL
         nK8rbk0JjTIVWhwazWIShu/dojurTKyHoORVC0JK943MFQUaTmNEJW5+uYOYTBA/daMZ
         zUZLjc6QOVsBD6PGJwJaxzlvSLY2Wa0kEPvLzkyubf3SCqU7Y1vZe6eUoK0WnTvm95ay
         gL8WQUr1pM8/93Bhdci88i0O5uvEl+WlyI7R6LDgh/aZpJE2lsEGzKME8tvhqlnWK2mN
         9G1ke2HM7cZx2Zh/2A7juJgCc8vWqMDGtUrwm4vmfQCdPDXcNctBzoBuIjV/CdKAlCm3
         0G2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=lEBAyDbpcGWWtLv7yxB3dM0CQE6fBpZjwez5iEbApJM=;
        b=gSkiLaHjMhqkQbYTxBjeOnOoObT/kvweI2EaCHLHNhGi18a2gwRTy2wT/IYIpDrg+S
         vdFcJKsu5laOe+tK/hzpFcDZ1lxYey5uLGJWlyvXjhmXv+lKK/hzHKUcjysmv+zbjYNV
         zHga/tDYU5lVQXL7tU2b3Z+Q0Oyqc7pfMG1FuL1bWU9GgR7OCq92loJ6dcpWiQOeVjWX
         ckqR9pWj/D1ozJNFnQviJfO5N5Ju+rPlo/gVEmE75EV3PDTan3Yx5D67K4mjmRE0Vlw0
         5HfXbgU92rNpn5C1nGWLRoPuXG4NVtmJviKkHIjXRixKXyAgeNkMYZOrB5P7LIiJL6Gt
         fAdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=JcgQBtGA;
       spf=pass (google.com: domain of muchun.song@linux.dev designates 2001:41d0:1004:224b::e as permitted sender) smtp.mailfrom=muchun.song@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-14.mta0.migadu.com (out-14.mta0.migadu.com. [2001:41d0:1004:224b::e])
        by gmr-mx.google.com with ESMTPS id b7-20020a05651c0b0700b00298a76ba024si1371337ljr.3.2023.03.28.05.53.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 28 Mar 2023 05:53:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of muchun.song@linux.dev designates 2001:41d0:1004:224b::e as permitted sender) client-ip=2001:41d0:1004:224b::e;
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
Subject: Re: [PATCH 1/6] mm: kfence: simplify kfence pool initialization
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Muchun Song <muchun.song@linux.dev>
In-Reply-To: <CANpmjNNXDHZGr_r6aZi1bv5itc5KvGhRNnq_CSQRrmB6Wwx+Dg@mail.gmail.com>
Date: Tue, 28 Mar 2023 20:53:21 +0800
Cc: Muchun Song <songmuchun@bytedance.com>,
 glider@google.com,
 dvyukov@google.com,
 Andrew Morton <akpm@linux-foundation.org>,
 jannh@google.com,
 sjpark@amazon.de,
 kasan-dev@googlegroups.com,
 Linux Memory Management List <linux-mm@kvack.org>,
 linux-kernel@vger.kernel.org
Message-Id: <D04CBA99-3E17-4749-9144-34B6D9D3208E@linux.dev>
References: <20230328095807.7014-1-songmuchun@bytedance.com>
 <20230328095807.7014-2-songmuchun@bytedance.com>
 <CANpmjNP+nLfMKLj-4L4wXBfQpO5N0Y6q_TEkxjM+Z0WXxPvVxg@mail.gmail.com>
 <CANpmjNNXDHZGr_r6aZi1bv5itc5KvGhRNnq_CSQRrmB6Wwx+Dg@mail.gmail.com>
To: Marco Elver <elver@google.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: muchun.song@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=JcgQBtGA;       spf=pass
 (google.com: domain of muchun.song@linux.dev designates 2001:41d0:1004:224b::e
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



> On Mar 28, 2023, at 20:05, Marco Elver <elver@google.com> wrote:
> 
> On Tue, 28 Mar 2023 at 13:55, Marco Elver <elver@google.com> wrote:
>> 
>> On Tue, 28 Mar 2023 at 11:58, Muchun Song <songmuchun@bytedance.com> wrote:
>>> 
>>> There are three similar loops to initialize kfence pool, we could merge
>>> all of them into one loop to simplify the code and make code more
>>> efficient.
>>> 
>>> Signed-off-by: Muchun Song <songmuchun@bytedance.com>
>> 
>> Reviewed-by: Marco Elver <elver@google.com>
>> 
>>> ---
>>> mm/kfence/core.c | 47 ++++++-----------------------------------------
>>> 1 file changed, 6 insertions(+), 41 deletions(-)
>>> 
>>> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
>>> index 7d01a2c76e80..de62a84d4830 100644
>>> --- a/mm/kfence/core.c
>>> +++ b/mm/kfence/core.c
>>> @@ -539,35 +539,10 @@ static void rcu_guarded_free(struct rcu_head *h)
>>> static unsigned long kfence_init_pool(void)
>>> {
>>>        unsigned long addr = (unsigned long)__kfence_pool;
>>> -       struct page *pages;
>>>        int i;
>>> 
>>>        if (!arch_kfence_init_pool())
>>>                return addr;
>>> -
>>> -       pages = virt_to_page(__kfence_pool);
>>> -
>>> -       /*
>>> -        * Set up object pages: they must have PG_slab set, to avoid freeing
>>> -        * these as real pages.
>>> -        *
>>> -        * We also want to avoid inserting kfence_free() in the kfree()
>>> -        * fast-path in SLUB, and therefore need to ensure kfree() correctly
>>> -        * enters __slab_free() slow-path.
>>> -        */
> 
> Actually: can you retain this comment somewhere?

Sure, I'll move this to right place.

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/D04CBA99-3E17-4749-9144-34B6D9D3208E%40linux.dev.
