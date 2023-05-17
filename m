Return-Path: <kasan-dev+bncBC32535MUICBBWFBSKRQMGQEWMWHWEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id AA89B7062ED
	for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 10:31:21 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-3f41a04a297sf1755455e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 01:31:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684312281; cv=pass;
        d=google.com; s=arc-20160816;
        b=0W53q9g4ndNmz0IhAo5HuI7/4NnR42IQajDC1/LLpC9m5phb0aIdIpwhiMvGQdUi2X
         LQHc1sRE/lfum54domlrFrqjCayvX34kW+zG+/WJuYpgrkYKZhiH3OHotidu2Qvmqwwc
         LNE2VoxpmY3aKK+7+MsyDe1swFWf5vTMoL1EkZC0OIBrrkp190AZZTeY/6Jx0P0z4/96
         Zd89WWjrwaO1wUtM3zxM1/j63KK4zEwcJFw7jPCN99oSjPO4iVOJ7Vv/pMkRPhyG9NVu
         lJG7kS0+NnPGZWyoI3emNNS4X9fxCt0eHXG8LE4yXo5fyYKI0bx060WfDfx9jy/EIz0U
         czmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=saHZYxlikzx2RguUG28Cf/eA1CfXA9NgojiIwqc1pkg=;
        b=lw0fMix5Ysif4cL/3CQ06Kf+3t8XwUw16P2aV2luPGWsAd95hs7DQfs3gI414MXeex
         Z8QBKItY6t5Ad60ICtHunoOiZsvlnJzSXyXzrXI46trvmtnc6IrpBIQpdXNtPZp+HgjL
         12zV/lbrPUh4k3iCJ2DYMs7oqKIyKm9E/PupT87hzSLJjMNT9ZdU91SeAXEySSujNyai
         dVF1+HH+7VoVsfemhM/gCj72RDyd3IaIXK7rrnEdGrBbbpqBrA3vh1CuQva2wChDSGZA
         LtwKl2Jzeh477V8C9Ok7RuFw2PtEEJq13LDqIKaJNoKYfWs3/MnilvD2kkGEVTYM6q1w
         16Dg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=O6PMMZZ9;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684312281; x=1686904281;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=saHZYxlikzx2RguUG28Cf/eA1CfXA9NgojiIwqc1pkg=;
        b=a43+160Kgqren5AG7IbkSiZwRzDevCd8U+yJY4CDK9tw74y7A8qQWQALL1oORw2733
         875ZQIhzaQxGHVtZ8DDyiIMAiDorQo1pSf6N6Yw+a/0W9959B+3jOQ8X3FJ3v/j2f7qy
         80A2C5sh+SugTmY8r2BlSaivA66fQlKlXlh5E4y9dy27ZMfaB6Fnh91eTssDDCZzOMOm
         xpjBhoKDcu7EwzXJ4SlcHkrYozcU+05aYUNxNbU8IT5OuAcw3Tdee+PBMC5JGMQgVgkM
         te9uJmx3lf7lt5WsMbIakd0X+/22kzu9JHgruqbmTWMJhKbUwo8HnRVZzpNT3PJaTBNs
         MMoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684312281; x=1686904281;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=saHZYxlikzx2RguUG28Cf/eA1CfXA9NgojiIwqc1pkg=;
        b=ZUBiaOvo4Xxuuf2FkXxWGzd0Fg6AX3oQdIqi7dzL1rt4VSVnjDPRZzlgvURdoN0+uA
         RuPmN57MCSh0+yAkCKc5ELwkFxZnp1OW9pmJzTW540b/dEjXAFBTevoiM9Ea4wyynipj
         kyqK+DzYIFOVZFve+VPoCkXdIjuG18RPNbyi6LlzSsv7PpB0FWqhIaM422ruklDQHm3K
         skeQRWoHU/ljOe7JIqYtfeKBUkCh6A/VvMYMNDgK/ZG7zwFz63aGBh8U6LnTaLz1dIYR
         4NcfQvE85VObpiwiGjAdZRLK1IYqKX1QyKMAQB9tR6eUWnXSLVPccJkgkWuyW1P0aYdC
         Dnsw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwDnSqICWAD6Gv1FHuwNga6OPrk2T9SnUkE7UZvVzWG2IvMjLLc
	qv+1RFNBHmyQO3r62CogCf0=
X-Google-Smtp-Source: ACHHUZ4F+56L/HF0N+waenjM3bKoNUc2Bep4/IcECigLUJCPC+8jnzfzeOFk1zxr8fkEFMm6sbi8Kg==
X-Received: by 2002:a1c:f70d:0:b0:3f4:f205:fc6b with SMTP id v13-20020a1cf70d000000b003f4f205fc6bmr3202987wmh.8.1684312281001;
        Wed, 17 May 2023 01:31:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4445:b0:3f1:68f0:7451 with SMTP id
 v5-20020a05600c444500b003f168f07451ls985785wmn.3.-pod-canary-gmail; Wed, 17
 May 2023 01:31:19 -0700 (PDT)
X-Received: by 2002:a1c:7212:0:b0:3f4:e4f5:1f63 with SMTP id n18-20020a1c7212000000b003f4e4f51f63mr12656405wmc.41.1684312279375;
        Wed, 17 May 2023 01:31:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684312279; cv=none;
        d=google.com; s=arc-20160816;
        b=UPRnzCujc5rwFQHEnnrzw1qxFLRWBlBK2Nuz/qcBAPRMGOhmR+CYHlU3l8o7jn7zHC
         HucHLYGKsWTUM+nblI4ThLxt73AKigw6UZVUyq2jjJ5p/BqogDxsfo/oS4hmarFLAxCn
         fTMII40ynpZvbyoEcKVcQoBgZumc5N3So2cEz8CPib41tQnp3uM8BlA9QHnKSGWNzHA9
         CioaAnzy6DtUOLz7L+KIKgbJ3G3IXjqn5zpAHqXIjJum02AEBWxmotDqncCwFQZry1Us
         NG2HL7FFeQZWR414Cwl10JTyy8t2o8Fu8iLUEQC1evdQXshej4I1InqaiF8Idfjud1LU
         wQIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=+87hwHfuK6j4i/fuLrmFREP9Nl0u0nKS6+0RzbNzN84=;
        b=dZJB/0W4tYaoTbtLBzF6CJ0FkW0P3Qpf+OAz7glQLqiLrAOQWFhBiIv7RaVDpeLBG2
         yMfbJSXcT/7O5dRrI+xcXJBZIaWWrfprDM3x3LBy/F0NlVMoFpOzZVzTQZuYHGXPjYy9
         rRrp21L+YIRuGnWznS8zAbNU/dj1nWk7j+ikMQ5P0Kzw1vZSGudvbU7nW83n/832LBdj
         iaUGmO7lKlwjU5pqFR066mm3Z1ksCQM29dZPZWs74L+4V2rtR50/p6+CMRuYpM+RgYRf
         YVJzk/EMtZ6hKiTAJ1o7H7yUo81ABXNRLWuWj8tguw19goq5PCGSFxtX4Og6cpuc+ZMK
         9Pqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=O6PMMZZ9;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id k31-20020a05600c1c9f00b003f42c1b8171si62412wms.0.2023.05.17.01.31.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 May 2023 01:31:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wr1-f69.google.com (mail-wr1-f69.google.com
 [209.85.221.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-346-F1bG8vimOGW57M3ENkWH4w-1; Wed, 17 May 2023 04:31:17 -0400
X-MC-Unique: F1bG8vimOGW57M3ENkWH4w-1
Received: by mail-wr1-f69.google.com with SMTP id ffacd0b85a97d-30479b764f9so181749f8f.0
        for <kasan-dev@googlegroups.com>; Wed, 17 May 2023 01:31:16 -0700 (PDT)
X-Received: by 2002:a5d:5221:0:b0:2fb:703d:1915 with SMTP id i1-20020a5d5221000000b002fb703d1915mr26788402wra.43.1684312276040;
        Wed, 17 May 2023 01:31:16 -0700 (PDT)
X-Received: by 2002:a5d:5221:0:b0:2fb:703d:1915 with SMTP id i1-20020a5d5221000000b002fb703d1915mr26788385wra.43.1684312275770;
        Wed, 17 May 2023 01:31:15 -0700 (PDT)
Received: from ?IPV6:2003:cb:c707:3900:757e:83f8:a99d:41ae? (p200300cbc7073900757e83f8a99d41ae.dip0.t-ipconnect.de. [2003:cb:c707:3900:757e:83f8:a99d:41ae])
        by smtp.gmail.com with ESMTPSA id q28-20020a056000137c00b003078bb639bdsm1934194wrz.68.2023.05.17.01.31.14
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 May 2023 01:31:15 -0700 (PDT)
Message-ID: <86142559-f15c-938a-a0eb-1ea590cb5e91@redhat.com>
Date: Wed, 17 May 2023 10:31:14 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.11.0
Subject: Re: [PATCH 1/3] mm: Move arch_do_swap_page() call to before
 swap_free()
To: Peter Collingbourne <pcc@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
 =?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, "surenb@google.com" <surenb@google.com>,
 =?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?=
 <chinwen.chang@mediatek.com>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 =?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?=
 <Kuan-Ying.Lee@mediatek.com>, =?UTF-8?B?Q2FzcGVyIExpICjmnY7kuK3mpq4p?=
 <casper.li@mediatek.com>,
 "gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
 vincenzo.frascino@arm.com, Alexandru Elisei <alexandru.elisei@arm.com>,
 will@kernel.org, eugenis@google.com, Steven Price <steven.price@arm.com>,
 stable@vger.kernel.org
References: <20230512235755.1589034-1-pcc@google.com>
 <20230512235755.1589034-2-pcc@google.com>
 <7471013e-4afb-e445-5985-2441155fc82c@redhat.com> <ZGJtJobLrBg3PtHm@arm.com>
 <91246137-a3d2-689f-8ff6-eccc0e61c8fe@redhat.com>
 <CAMn1gO4cbEmpDzkdN10DyaGe=2Wg4Y19-v8gHRqgQoD4Bxd+cw@mail.gmail.com>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
In-Reply-To: <CAMn1gO4cbEmpDzkdN10DyaGe=2Wg4Y19-v8gHRqgQoD4Bxd+cw@mail.gmail.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=O6PMMZZ9;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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


>>> Is there any other way of handling this? E.g. not release the metadata
>>> in arch_swap_invalidate_page() but later in set_pte_at() once it was
>>> restored. But then we may leak this metadata if there's no set_pte_at()
>>> (the process mapping the swap entry died).
>>
>> That was my immediate thought: do we really have to hook into
>> swap_range_free() at all?
> 
> As I alluded to in another reply, without the hook in
> swap_range_free() I think we would either end up with a race or an
> effective memory leak in the arch code that maintains the metadata for
> swapped out pages, as there would be no way for the arch-specific code
> to know when it is safe to free it after swapin.

Agreed, hooking swap_range_free() is actually cleaner (also considering 
COW-shared pages).

> 
>> And I also wondered why we have to do this
>> from set_pte_at() and not do this explicitly (maybe that's the other
>> arch_* callback on the swapin path).
> 
> I don't think it's necessary, as the set_pte_at() call sites for
> swapped in pages are known. I'd much rather do this via an explicit
> hook at those call sites, as the existing approach of implicit
> restoring seems too subtle and easy to be overlooked when refactoring,
> as we have seen with this bug. In the end we only have 3 call sites
> for the hook and hopefully the comments that I'm adding are sufficient
> to ensure that any new swapin code should end up with a call to the
> hook in the right place.


Agreed, much cleaner, thanks!

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/86142559-f15c-938a-a0eb-1ea590cb5e91%40redhat.com.
