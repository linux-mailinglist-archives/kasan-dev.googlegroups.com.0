Return-Path: <kasan-dev+bncBDGZVRMH6UCRB7OFT23QMGQEN465QDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id CA70B979A0F
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Sep 2024 05:16:15 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id ca18e2360f4ac-82cfa70028fsf808404139f.1
        for <lists+kasan-dev@lfdr.de>; Sun, 15 Sep 2024 20:16:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726456574; cv=pass;
        d=google.com; s=arc-20240605;
        b=kYwe9EvcA+8ehKLSO2X1mLgzURQknfgs15zyd5uxNUKFIV9l1wvGgTeMrAVNxg9N7J
         DY22/8R6PxVrMc6e3aPCYLl41cHRGZJROHQwcpSA8RCFGFhyPSAedmRksQzU+m7d4YLZ
         +o5Nlo+qcb0fbS0EfsnIvKTBmpTSYcO3xboPWT4T7XhsS8dEUTngw2lStlxx7+tt7sy7
         3QkD3wG/sQClrZ5ASFnHNnl7UDJeyzWfWwgbVFbzpgutVNUAai5DRuYyYIl6K8CWCnuS
         wTe1AJHizKFID5se04asNt0HaAiawxGZm6bqGzaE2ElI5anv5SjAd5gLL8SEmGi1APBQ
         9roQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=xP92Ah/McrFKAry4hlWPnrww6o+nTvyBfcX4tJkADAQ=;
        fh=2O/Mzn/mOV07XGL2+Y0etGjBWnmmE0PFfnWjuEu8OYM=;
        b=ScWGJMVJsAbWaeM98fM9GcarAt6k5oOFB7wg0h5cyAeX4wtKbPVyIqqvR5TRE/Qti8
         5xvLRuCT4oySvEgUrf/o2yWchgA8Mlm9As12OlKRz4S4UiMuuM7v+t8ThPqpUUHBW5BX
         i1RwnNQ4tJKRcpFa/fGxL9kNyJM/ByDZBusmhxu/K/rQ36hLZ9sBLsf1oOAsTvhJlQYq
         p97hykXUhOuaDxmp3s0xUFYfR2r+dKd0hSv7NKbr5pw2wUMFBGRtFGWL0iBh9M4HrCNA
         SWdjny65kWG4/65J9XxQj+gNCiiuCjLGY7GkIIUQW7NuVfuqHBlFzDxsXy0Ihq7w1jgd
         Gw4A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726456574; x=1727061374; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=xP92Ah/McrFKAry4hlWPnrww6o+nTvyBfcX4tJkADAQ=;
        b=JWb4HUpb+FGxN5kSsa8xw8IEymy/zsbYPBBVpMc97H6PU3wh4FXCjXuBr+g0q0AfEP
         cQwquprh3Dvkfnm5fnZiW2GTAe/mUfpv3ENdW9sGrqxCVvKIBlFPht5HJaNg9jkr+1Kf
         2GOGuEgkzzaIipV5WFUnbNzKc/OxdO5k9b36E+ABcSjuKRzR+BhoZJ6UB+S0x9sCGirp
         LUHH0uMlRqvQReudaRrbMs75qpFiKYcSiIewvljXs4Tnw1vT943Jl11jHYjf82A3tSkI
         IEbv1uri+V0EQugWkYylm/ammvXkC582jycWaM40Rj8pXrY4GqbU+UvhOQrdaj/P9jx8
         IUzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726456574; x=1727061374;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xP92Ah/McrFKAry4hlWPnrww6o+nTvyBfcX4tJkADAQ=;
        b=XNBOhWKWr6fVDtB0lnyGDOeli0SDldKvWeBlIia2jwzJbOy6oZePLxrdriFNg95QKe
         wH1tBbRSvs9xuyB/v3YURMuFaLXbXUFCLKH+4Qh0YG/25bL5PK7G8wi9zSHd4K81g5Re
         dpsrGIjT1qn/q0Ba9JxI1FQKITQA3emBbNN6PiWaCtEGkPC220IH7GVOOchMIJxMiRW7
         B944MiBOfxn1hb2e/64mTWjLiQc/sfTsXdzvjTjYesYMf0LRBIuP27NjiJ/ZDO81zpZZ
         ko5UorSAQ/qQjK9ofvKb1pnjFo/z7trtI9KajJ+g+HPBBJM1F3FLiN4DwQpm6vZQ/1n/
         flmA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUQ5MvOD8cLiodNV5k+HEspB5j7vtPVmTtRMQRdttjpb4RyLCT7A7m797hgrPYFxLUCvidqbw==@lfdr.de
X-Gm-Message-State: AOJu0YyEZk61rRU4SM1K6N1Tey47KCwvwdJ6APs52T7gCSkKq+avPnVH
	4rBZOLmb3+HMcFFwn/vFCJYcRvCIhbkvxvI4hLnitNIWHybX/Nks
X-Google-Smtp-Source: AGHT+IFewDIR1Gi4GFhG/0gzFEgoQEhdmeluk1Gm/GanPs+AtIWTHfsIjnI+YFQFCp2qOR2aBny5tA==
X-Received: by 2002:a05:6e02:505:b0:3a0:9c04:8047 with SMTP id e9e14a558f8ab-3a09c048195mr29056405ab.6.1726456573951;
        Sun, 15 Sep 2024 20:16:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:b44:b0:3a0:a24b:e122 with SMTP id
 e9e14a558f8ab-3a0a24be265ls1697695ab.1.-pod-prod-00-us; Sun, 15 Sep 2024
 20:16:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVlEUjHAlXlD6gindkTjiIBQSqNPs8o9LDyV+9LoCuddQxKtmgwpLN2+nHIpV5c8PhwRjc1S0VwYDo=@googlegroups.com
X-Received: by 2002:a05:6602:6302:b0:82c:f7b1:a9fb with SMTP id ca18e2360f4ac-82d2071b7admr1016576139f.5.1726456573179;
        Sun, 15 Sep 2024 20:16:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726456573; cv=none;
        d=google.com; s=arc-20240605;
        b=C0m8ZbTDNVrTUyrTlvqLNMrlcVC4lxZtmqdcth4EATEjBfVFUQ0fNculOKT9F9uq5G
         ACIHs5jBA6x2wtyrWwwyTdjj7kDO+RFVlol2UDNAYInltElbUTKF1gw8x8DPBXScegUl
         0160Fn8dJRcABz1eEht/8g2o2UmY24eC/GFeiXZjtn6HWUTLaikzC7R4PbXBess93XA+
         ED9tEoOLFrsjijmA674wW6EOhy4BCOO3oF9nhhsRPFchSvW7/cpib+WxoClenfW//CMu
         mRHDC1wT12JmnZYQKEJfKEhEqCIqfEB7cpDEU7IAcJS8X2BHt/zEO9Fr6XpPp41uLNX3
         9Uxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=4VDOUWjrk1Z6cn8NNmyC0yp/VCOvweWW76Vz6loAdWQ=;
        fh=3FR20ap+9rzo84pHkiDyH+K7tojmPlPNibemmVti0b0=;
        b=BkX8RihrwInDx0oxR7VYNZ1ngccSrpB9tK2rQIJy03ObUZnD6+ko08aMVA0gBJzU5X
         Ewka6PQsJcgQ1KmV5kRdJs8QY9gRQTA57P9BEUU/UCPH6WeYpW/TRxS80dWHUHWS21bd
         Gx5aHdrM2dyLzRKjzBsOBwrk737hTtbanPUObII6xr/TBOe+ITeZzD15F58WccYx08QI
         VwIuW9wHf7Ni+Q/hpkloxRpG2jb7tsyHvxFWaSXMzqSXmpLFL0At5FLtdKmlaflGbPyH
         I0GYM+o5bPXXN7PWtQ6Ag8qHsulJ25XXy0JZck0Twiz6XI1n0p0mX/ohmWSx+i62Un2k
         4CTg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id ca18e2360f4ac-82d49268fc0si15376239f.1.2024.09.15.20.16.12
        for <kasan-dev@googlegroups.com>;
        Sun, 15 Sep 2024 20:16:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B1A6D1476;
	Sun, 15 Sep 2024 20:16:41 -0700 (PDT)
Received: from [10.162.16.84] (a077893.blr.arm.com [10.162.16.84])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E6B5E3F64C;
	Sun, 15 Sep 2024 20:16:08 -0700 (PDT)
Message-ID: <357931ba-d059-453b-a91d-1bed7fbe5914@arm.com>
Date: Mon, 16 Sep 2024 08:46:06 +0530
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 3/7] mm: Use ptep_get() for accessing PTE entries
To: Ryan Roberts <ryan.roberts@arm.com>, linux-mm@kvack.org
Cc: Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>, "Mike Rapoport (IBM)"
 <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>, x86@kernel.org,
 linux-m68k@lists.linux-m68k.org, linux-fsdevel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-perf-users@vger.kernel.org
References: <20240913084433.1016256-1-anshuman.khandual@arm.com>
 <20240913084433.1016256-4-anshuman.khandual@arm.com>
 <f7129bab-4def-4d64-8135-b5f0467bf739@arm.com>
Content-Language: en-US
From: Anshuman Khandual <anshuman.khandual@arm.com>
In-Reply-To: <f7129bab-4def-4d64-8135-b5f0467bf739@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anshuman.khandual@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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



On 9/13/24 15:57, Ryan Roberts wrote:
> On 13/09/2024 09:44, Anshuman Khandual wrote:
>> Convert PTE accesses via ptep_get() helper that defaults as READ_ONCE() but
>> also provides the platform an opportunity to override when required.
>>
>> Cc: Andrew Morton <akpm@linux-foundation.org>
>> Cc: David Hildenbrand <david@redhat.com>
>> Cc: Ryan Roberts <ryan.roberts@arm.com>
>> Cc: "Mike Rapoport (IBM)" <rppt@kernel.org>
>> Cc: linux-mm@kvack.org
>> Cc: linux-kernel@vger.kernel.org
>> Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>
>> ---
>>  include/linux/pgtable.h | 2 +-
>>  1 file changed, 1 insertion(+), 1 deletion(-)
>>
>> diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
>> index 2a6a3cccfc36..05e6995c1b93 100644
>> --- a/include/linux/pgtable.h
>> +++ b/include/linux/pgtable.h
>> @@ -1060,7 +1060,7 @@ static inline int pgd_same(pgd_t pgd_a, pgd_t pgd_b)
>>   */
>>  #define set_pte_safe(ptep, pte) \
>>  ({ \
>> -	WARN_ON_ONCE(pte_present(*ptep) && !pte_same(*ptep, pte)); \
>> +	WARN_ON_ONCE(pte_present(ptep_get(ptep)) && !pte_same(ptep_get(ptep), pte)); \
> 
> Suggest reading once into a temporary so that the pte can't change between the 2
> gets. In practice, it's not likely to be a huge problem for this instance since
> its under the PTL so can only be racing with HW update of access and dirty. But
> good practice IMHO:
> 
>     pte_t __old = ptep_get(ptep); \
>     WARN_ON_ONCE(pte_present(__old) && !pte_same(__old, pte)); \

Sure, will change as suggested.

> 
> Thanks,
> Ryan
> 
>>  	set_pte(ptep, pte); \
>>  })
>>  
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/357931ba-d059-453b-a91d-1bed7fbe5914%40arm.com.
