Return-Path: <kasan-dev+bncBCRKFI7J2AJRBVFITGEQMGQEJEO5RLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id F338E3F776C
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 16:31:49 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id i3-20020aa79083000000b003efb4fd360dsf850633pfa.8
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 07:31:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629901908; cv=pass;
        d=google.com; s=arc-20160816;
        b=o4jaRMuXoDU6fvQdfdJEBwf7OGusYZmfaKQJc9CcUrBK06SOCSrTekohDmyn0iMqgY
         vgycgbq9Jkc7Wi7SlVO0b0Tsn2cRzkd8x2zl9NWHOdrUIoZ7hdcBMaf4rAEAGPZrp5J/
         AAQvQVvAvkBPjDRlFOd8XE8pZNCu8mb/Pm0wEw71l4sjeg/+AFvKy23fAxeaml02yUUM
         edauvvma46BLuUvjXAEUjxE3vsOHtuBGpo/+ernm8fwbK6P/mdPvsYCsNqSlfxcHHIro
         o0S6M2TSDyO614iaQkkzRlN2vKtzx6leq3IurH2UP2+gy2D2YknvKDxiprCDxvrbh8uC
         gQNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=SJisDqDtz5iljXZfs5aewpaAJXy+LX4or2zwWE+dUs0=;
        b=z9SmWnCsNLyC/UtFmnSlFODYwVFJWbATCJaAkxt4OOAnTWE6ApTzuSCjtV2TiXKn4N
         9gCofeP5U3snP0jX1R9jFYX0m3aKtyvby2+qbBvHLUH7oDZFaBHq4UyjtOTA4ITN1m3+
         1bGUj8c+8LM0nrk0MZhirFpIKLCN0cigyO7m9x+3sR+kLAVsbrUoy0KEt8agd66ScbIy
         wQEOPAPYnsmx1HT2MAU07cPVpPtappnLVowI8Xmh7acsVuqLE5pHhTOkPqIkHvBorJYs
         VGD1KPE0Mxbpgq23Eh+IaiFeGrhafbgdvLm/AMcnsd2o4X6GWv9hWKpWz+wpHZSGCCi8
         XvLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SJisDqDtz5iljXZfs5aewpaAJXy+LX4or2zwWE+dUs0=;
        b=P0SsCaV++low0kjgcsaSqGqqNldIo94kcoaIOXGYOs5wmwojXRJnQ8aRtqpzNMCftC
         xqdTiv2NuXiCCNZBhkrf2t/qFNz8egR5lPdRVmqDaQcayWOGSeuU323jSkUgAVqJbMF9
         dRSTlg81xhZBtWiVSz5y+zHRW0IT5rDwnnrdr5WXvOIckAHXs4s+/5c9WU7eewJtpL2o
         CnbHoiyedIfvRgmgRnKRGoaAJej24rG9yF3EAuH+yqvue/vBcn+50cDlUNkQjsVJduFq
         OPgJGC6RkoVeYKA1Q76T+aIWieEgCct9OipTA5XzcBfAYFKZ3W++/BKuKO8IbV3/SilT
         TIAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=SJisDqDtz5iljXZfs5aewpaAJXy+LX4or2zwWE+dUs0=;
        b=pQIoyV990PW72IISnmXIDxTf4JeJ/tsjIbaYv2QoOHnpbQ0/DfBe8AKwNiD9ExXdfW
         URSKX0TMkJQZRmg7GOhwa3iIZ/AoPNI4zG3d3DA++6IDQnMuA4e2M9ZfzL4F4ubsau3M
         b+Fx1nNrghC9Vk6pVOSz3q/Y2FcLLGazEmkasElxlPVouM1iUpY/m6sL0rQcu4jMM4Zp
         0mCEFYeuVtmd3Rs50gQ6oWvjLhI/U9Lg3M180NZ9jIsgBrU9uPhSyRF3fpsxIzJh9L9l
         b46fJ1WMkb4n4Ru673hJ/Ei7UOEePjcWI9yJpcy7m69EsNhsEJVxQ4vrpwzsKr6R05XA
         l1lA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532T+jPz5j+B94fTV/BATlQqq1hrningzzlJEVec0dI1IDn8As7Q
	YnAXURU+Mbx85Pu32v8UPEY=
X-Google-Smtp-Source: ABdhPJxQSc3g/YlaXbdJ6bU1l81iUzUjQD9viijB08FMceXHCslvbBhkGTS5vaME7AFlMkSldaO60g==
X-Received: by 2002:a17:902:7b83:b029:12c:2758:1d2d with SMTP id w3-20020a1709027b83b029012c27581d2dmr38240940pll.80.1629901908674;
        Wed, 25 Aug 2021 07:31:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6487:: with SMTP id e7ls1038896pgv.7.gmail; Wed, 25 Aug
 2021 07:31:48 -0700 (PDT)
X-Received: by 2002:a62:1d0a:0:b0:3e2:7dd6:e4b0 with SMTP id d10-20020a621d0a000000b003e27dd6e4b0mr44593476pfd.27.1629901907997;
        Wed, 25 Aug 2021 07:31:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629901907; cv=none;
        d=google.com; s=arc-20160816;
        b=pfDAqalX2p3j35yYo8ldJDBbcKD0hw/nq+XsG8Vh5brk2Gz9isLdwlWVNp7LJEMafG
         76pK4Lnubf5r+HW7YhMkUUbB52OLx7RyGzT2bCbh9q9P6o6ENRj6JS0lb6RGmj+olzRJ
         jjGZUztlAFAuRfhf0AI4nMlnCNv6WEC7B2gLybFTONhoaUfoAiVWqmEAwXS8jAknXKIQ
         jkBwbpLNFgZWYX28cGEu5ELniZyo7mfoNWEmO2Oc/xTD3HcpjdWK40K65du0XienTLDq
         xuA0GTqz71Trtsak1p8OQsdfe8OtA5z7v6b71dUH7SNwd14JzOrFHSlXO5NUkKi6W01P
         Cj1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=2FtSV4zLxOd4l7AcsSSDp0Sw86frOrKqg60ZM45jlDM=;
        b=zqTvqVtDejCB02sBbRdLzPkZ4AW3f5pswhtNgfXaZhurb7C+OHGVBtkR+0t5zBK1U+
         6cC52akeEtLj7hFFnWnM8o3mW/pKxizW1PlKxdYGJyrJ2ZotEL9VLmFVtoBh0Ik+1z6E
         8GyX4n7j3nNJ5BN4gpHyBPLARgqjeJIznv8btzccm1QKXepe6WKaFd1JE561RNhAS9hO
         +yljilDrcbRBS4uVAz5yuK5HdgwSCa4VmRzKH4vBx77kjWZ7YFWDR+MogNVcBwemNpBW
         FBoZ0WcrsnmEQ70UfO+bk7wJvnen8XnmGQiqJZc2cCPhGch3yJPMJ3rVz7ZzcGD6fqQa
         jkbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id m1si455454pjv.1.2021.08.25.07.31.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Aug 2021 07:31:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggemv704-chm.china.huawei.com (unknown [172.30.72.56])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4GvpH001z6zbj5X;
	Wed, 25 Aug 2021 22:27:56 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv704-chm.china.huawei.com (10.3.19.47) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Wed, 25 Aug 2021 22:31:46 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Wed, 25 Aug 2021 22:31:45 +0800
Subject: Re: [PATCH 3/4] ARM: Support KFENCE for ARM
To: ownia <ownia.linux@gmail.com>
CC: Russell King <linux@armlinux.org.uk>, Alexander Potapenko
	<glider@google.com>, Marco Elver <elver@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<kasan-dev@googlegroups.com>
References: <20210825092116.149975-1-wangkefeng.wang@huawei.com>
 <20210825092116.149975-4-wangkefeng.wang@huawei.com>
 <51b02ecd-0f3d-99b0-c943-1d4da26174d0@gmail.com>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
Message-ID: <8531455d-3198-96cd-e26b-03156f95ac80@huawei.com>
Date: Wed, 25 Aug 2021 22:31:45 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <51b02ecd-0f3d-99b0-c943-1d4da26174d0@gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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


On 2021/8/25 21:18, ownia wrote:
> On 2021/8/25 17:21, Kefeng Wang wrote:
>> Add architecture specific implementation details for KFENCE and enable
>> KFENCE on ARM. In particular, this implements the required interface in
>>   <asm/kfence.h>.
>>
>> KFENCE requires that attributes for pages from its memory pool can
>> individually be set. Therefore, force the kfence pool to be mapped
>> at page granularity.
>>
>> Testing this patch using the testcases in kfence_test.c and all passed
>> with or without ARM_LPAE.
>>
>> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
...
>> +#endif /* __ASM_ARM_KFENCE_H */
>> diff --git a/arch/arm/mm/fault.c b/arch/arm/mm/fault.c
>> index f7ab6dabe89f..9fa221ffa1b9 100644
>> --- a/arch/arm/mm/fault.c
>> +++ b/arch/arm/mm/fault.c
>> @@ -17,6 +17,7 @@
>>   #include <linux/sched/debug.h>
>>   #include <linux/highmem.h>
>>   #include <linux/perf_event.h>
>> +#include <linux/kfence.h>
>>   
>>   #include <asm/system_misc.h>
>>   #include <asm/system_info.h>
>> @@ -131,10 +132,14 @@ __do_kernel_fault(struct mm_struct *mm, unsigned long addr, unsigned int fsr,
>>   	/*
>>   	 * No handler, we'll have to terminate things with extreme prejudice.
>>   	 */
>> -	if (addr < PAGE_SIZE)
>> +	if (addr < PAGE_SIZE) {
>>   		msg = "NULL pointer dereference";
>> -	else
>> +	} else {
>> +		if (kfence_handle_page_fault(addr, is_write_fault(fsr), regs))
>> +			return;
>> +
>>   		msg = "paging request";
>> +	}
>
> I think here should do some fixup to follow upstream mainline code.

Yes, the fixup is still there, as the cover-letter said,

NOTE:
The context of patch2/3 changes in arch/arm/mm/fault.c is based on link[1],
which make some refactor and cleanup about page fault.

...

[1]https://lore.kernel.org/linux-arm-kernel/20210610123556.171328-1-wangkefeng.wang@huawei.com/

>
>>   
>>   	die_kernel_fault(msg, mm, addr, fsr, regs);
>>   }
> .
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8531455d-3198-96cd-e26b-03156f95ac80%40huawei.com.
