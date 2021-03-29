Return-Path: <kasan-dev+bncBAABBSUUQWBQMGQEZ7N74IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 98C9434C238
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 05:32:27 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id 13sf3503959pfx.21
        for <lists+kasan-dev@lfdr.de>; Sun, 28 Mar 2021 20:32:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616988746; cv=pass;
        d=google.com; s=arc-20160816;
        b=osM7NDLP31Ijtn6oSXdEGgNF2rEB+CUgHWbh8ICONtB/K0axPhNFIzGR48yB+BFh7y
         rhq+rMY8KJsiUIHltjzWwRkH73eBPoSjQsqpudy8yKqYaWSKREgbEp7SVsbwbPRVTdMd
         Lxug8WKt9/+OE/TK8yB6IvE4MHStuvzKk0jDGR7dsQ+Dv1gZzJQ+dl/pwj2NizRVHQJ9
         KlQ+Xvg7HkTru4qA23luvpNL737yxLteSjTyVFtHVJxkn0XMZ2My6XpZX8LOPNBN5Ngz
         U+jnKtN6Adc2GrOnw1HSyic5ZlJQpZTZcfsY0nG6AfgAxOT5g0OH21p/bJD+nV71ripk
         z6Cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:mime-version:user-agent
         :date:message-id:from:cc:references:to:subject:sender:dkim-signature;
        bh=GMkavHwU2+WqxDBGi9iQ/NYdZMYEfsDD/HKzmQ2X6VU=;
        b=codiikSIk7Ax9qHqWDetOZo8jSc6T3hBuARPYRpZNMXmKV43bWiDb7zCXguMiBh28o
         e1S+hzl1XhWx78Oqv62w4f3PxNmYWDS69DsmX5yypgcfv/5QrkN990WBFow49oRzZas+
         3zQmq5pXYsBliWlk28Nku3+zwe6PpU1nmQVr95Khb8W1ocV74ryg9zgnoGthTbgxcreF
         l4rHx6OdIrIwl3mxvTVWE/ix2v3aVfLIvqp1duS+zz/4T/jRjOlyv4X6uS1N2HKsEXT5
         35HF0fnyaEMn7FcfOptzpWj48PygqF/tVkWEZ6ojLJtOIh5Knmi2KWICn/3QOp5fiJal
         R+GQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.191 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:cc:from:message-id:date:user-agent
         :mime-version:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GMkavHwU2+WqxDBGi9iQ/NYdZMYEfsDD/HKzmQ2X6VU=;
        b=rTGgEoNpJtxrBAIi21UguDuuno0wdg4bV8A26mrGFmS5PqPVowN51T6SJpgg2qQNPr
         XfUFph890cEwUBDlQGZrEtPRCFD3uqekTRt2aWjBdNttqLEQqqOXoqV00vYbuMRcuSaH
         l2ELFLvTtrqwAQqc0oyLauYSW/RV3E3wQyh47YNVZ1uXlfCES0W1NvAOltpP3yKgzJ6w
         f7BA583Xi6U9sSJekkJgJ4uc5Uelzpub9ay9ZYQrk1D2POXtSwiuuTqXGeOzl8mBCQIx
         FJ7uN2bFLOT4//YjcB8HsSy28lHO5Na84p6s50chbWHRiVqAVI6kCSMxsOtaWn8uYFRa
         3j6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:cc:from:message-id
         :date:user-agent:mime-version:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GMkavHwU2+WqxDBGi9iQ/NYdZMYEfsDD/HKzmQ2X6VU=;
        b=rU7pkcCLUWMhGE8lunKRtyGArGY88awHZ3bXrVLBkJioAlpaoi0bQWaVfUoAPou+Ck
         o2218Z1l9rseXxYqWW3VDByIfAlnaE59iZnz0x33IGyIKcpzHSt5g8dHHmBqOy1CUns8
         reNKLXi8iZX2KY00bBL4oeor3aNcH1Oy86eQ3mYkbBQQZ612u701jSsVZE1G7AO5vDJk
         skRRX/PrFlHJeJd6YoZYlx/Iu2KoSLvH0mNEK3a+pa9jxHT+x6stjesMZ8y/Ro+zuG89
         ltapVmpk37a/kFeXTC94FNrScf7i8289EaA/urvMzIFDln3mZEmwVCkqP29hKirqr9mS
         K93w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532dnPFoUOxZL/Z66glJ7cNAkHyDj5iiICWVz3EGlPFEou50Gmr6
	cgDzRXBvEMOBqh50fsJANns=
X-Google-Smtp-Source: ABdhPJyYkA4vq1oQcOrEwuPwFDL2jbJtnMRm6BpMGvUzN7xpY83l1c5rWULANLVuvBwjz4kdB4J3qg==
X-Received: by 2002:a17:902:c20d:b029:e7:3266:6d4e with SMTP id 13-20020a170902c20db02900e732666d4emr14565440pll.54.1616988746373;
        Sun, 28 Mar 2021 20:32:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1057:: with SMTP id gq23ls7397336pjb.0.gmail; Sun,
 28 Mar 2021 20:32:25 -0700 (PDT)
X-Received: by 2002:a17:90a:c588:: with SMTP id l8mr24152641pjt.120.1616988745790;
        Sun, 28 Mar 2021 20:32:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616988745; cv=none;
        d=google.com; s=arc-20160816;
        b=c5rlmujBOE4oHyv/zxr/e/jjd8IwLd9AM58ksnSoqdjmzCZFiQ/bMIX+FFSeP2uz2W
         GcbFh9hejMRwaU2SCW+1qZv8tnLTqs0ch71oBQso+PelOPlQ/Ko5dkilpr5FtQ8xO32Y
         XxfCs/+j/cWLAapLb0HixHJ+eku43QDcy2lkS0A+IB5oXDhLDaAjqdEtNiar6IFzSVw9
         hfCPtUVv71WwtVu+BHW7IMxQ8eS2tJcqZwkqgW/DR1jzSkfpZex0X0dmrwVRHbfRsl2G
         KYInFUlyX/v1gmNc9DAyu3ATnMD91Hyyz9zQjUoDdBsVHdYvoHj8f7jeQ0IGjQ8idJym
         sz1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:from:cc:references:to:subject;
        bh=P3CpQYV6eiGEQuJfWfsgkjN8kjssxlj7g5c55rhh5xY=;
        b=Eb37SXE8HVFepgDfkaKIQ4wFocqvRULnMf01oZjeOHyR2fUrvDa9XDW8OiD1sT8miU
         H3e0HP1gb/Ul/6ANID979Zevk6X7g1JG0EEFZrn73OSLpIM361A+x0c8u6jynfg051qS
         tg4RhpQOybP3UtNjvTu1bs2nFy0mNsoyZBNLn8q12Kc42HXe+i0INILUywiwbp6xESmh
         0tmnowSOrdT1voPmJUwoRgkx+uW9WdjHdf/+blUv6g5+rLOSPrPxJKCgKmxqcpAhDeLk
         82fjwjvZ7IQexjoZfdHw6B0EqTJ5SJtC/ULeCJGA6pNectXO69YJWz54/L/sUlkmGaY+
         zxoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.191 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga05-in.huawei.com (szxga05-in.huawei.com. [45.249.212.191])
        by gmr-mx.google.com with ESMTPS id h7si1022412plr.3.2021.03.28.20.32.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 28 Mar 2021 20:32:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.191 as permitted sender) client-ip=45.249.212.191;
Received: from DGGEMS414-HUB.china.huawei.com (unknown [172.30.72.60])
	by szxga05-in.huawei.com (SkyGuard) with ESMTP id 4F7yjm0dqQzNr5m;
	Mon, 29 Mar 2021 11:29:16 +0800 (CST)
Received: from [10.174.177.208] (10.174.177.208) by
 DGGEMS414-HUB.china.huawei.com (10.3.19.214) with Microsoft SMTP Server id
 14.3.498.0; Mon, 29 Mar 2021 11:31:51 +0800
Subject: Re: [PATCH] arm: 9016/2: Make symbol 'tmp_pmd_table' static
To: Russell King - ARM Linux admin <linux@armlinux.org.uk>
References: <20210327083018.1922539-1-liushixin2@huawei.com>
 <20210327102012.GT1463@shell.armlinux.org.uk>
CC: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, <kasan-dev@googlegroups.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>
From: Liu Shixin <liushixin2@huawei.com>
Message-ID: <8578f96b-1a86-27a9-86a4-ed97c90b4892@huawei.com>
Date: Mon, 29 Mar 2021 11:31:51 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101
 Thunderbird/45.7.1
MIME-Version: 1.0
In-Reply-To: <20210327102012.GT1463@shell.armlinux.org.uk>
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.174.177.208]
X-CFilter-Loop: Reflected
X-Original-Sender: liushixin2@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liushixin2@huawei.com designates 45.249.212.191 as
 permitted sender) smtp.mailfrom=liushixin2@huawei.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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

I'm sorry for making such a stupid mistake. There was only one patch committed before(5615f69bc209 "ARM: 9016/2: Initialize the mapping of KASan shadow memory"), and I used the same subject by mistake.

Thanks for your correction, I will revise the subject and resend it. How about using "arm: mm: kasan_init" in the subject?


On 2021/3/27 18:20, Russell King - ARM Linux admin wrote:
> Why do you have 9016/2 in the subject line? That's an identifier from
> the patch system which shouldn't be in the subject line.
>
> If you want to refer to something already committed, please do so via
> the sha1 git hash and quote the first line of the commit description
> within ("...") in the body of your commit description.
>
> Thanks.
>
> On Sat, Mar 27, 2021 at 04:30:18PM +0800, Shixin Liu wrote:
>> Symbol 'tmp_pmd_table' is not used outside of kasan_init.c and only used
>> when CONFIG_ARM_LPAE enabled. So marks it static and add it into CONFIG_ARM_LPAE.
>>
>> Signed-off-by: Shixin Liu <liushixin2@huawei.com>
>> ---
>>  arch/arm/mm/kasan_init.c | 4 +++-
>>  1 file changed, 3 insertions(+), 1 deletion(-)
>>
>> diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
>> index 9c348042a724..3a06d3b51f97 100644
>> --- a/arch/arm/mm/kasan_init.c
>> +++ b/arch/arm/mm/kasan_init.c
>> @@ -27,7 +27,9 @@
>>  
>>  static pgd_t tmp_pgd_table[PTRS_PER_PGD] __initdata __aligned(PGD_SIZE);
>>  
>> -pmd_t tmp_pmd_table[PTRS_PER_PMD] __page_aligned_bss;
>> +#ifdef CONFIG_ARM_LPAE
>> +static pmd_t tmp_pmd_table[PTRS_PER_PMD] __page_aligned_bss;
>> +#endif
>>  
>>  static __init void *kasan_alloc_block(size_t size)
>>  {
>> -- 
>> 2.25.1
>>
>>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8578f96b-1a86-27a9-86a4-ed97c90b4892%40huawei.com.
