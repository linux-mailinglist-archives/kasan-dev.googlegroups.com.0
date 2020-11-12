Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBO4EWT6QKGQEIBHCQPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3f.google.com (mail-vs1-xe3f.google.com [IPv6:2607:f8b0:4864:20::e3f])
	by mail.lfdr.de (Postfix) with ESMTPS id DF0A02B020D
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 10:37:00 +0100 (CET)
Received: by mail-vs1-xe3f.google.com with SMTP id l11sf1512275vso.12
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 01:37:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605173819; cv=pass;
        d=google.com; s=arc-20160816;
        b=jTnKjMsHrnV3A+tRGa7PIRRz0eZ2uWSv/4/xGunneFunKRX9IUzfIEyjbuzVU1jNL4
         Yt8D+VNbdE4EaaERI0jaZ0uqheCWFWiSz3Q/Au4azL32iSa0BQTYkfzeDwNmVctQRzSG
         BIo/XO5svTgHccZmjdpifiUhxAezajjlKMTJVyMq5OBndqgb+2CLzYfasjhDGBGzas+q
         Bql5gEz8mtpvi8IHml7PJ6ODWjdgdBcBEEyInh9EDtkmGHgzFr6PHOA44NV9crVsDDim
         QUrlTTaPDGj6rX62+MCN+VbGADscPa94bIZQ9espvD8wlGobimLbWL2b8vXhh5gAB6Ox
         QS7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=zT9WPDRFkrERzkcrQo8X2gHZH8xYrOQCvtDn+ZggZYE=;
        b=qL517yq6+jKJg39qKsG91lqpzoTGoMM1hQ+MWrPdXln5SUXk+94rafWElo9WOM+nSd
         ZNjl8pqVg3IVFTqWblBs3dg9kHKbXslgVo5do9Op1LwpHo/70YrXaN/Id6jBpqS4Ui1m
         aI/zzvcKZq4bRSjiHuLig6AgFTxmjuTjbHYlqHh40oz3jVnqcq6fa/yUJrgT/TFFNiLU
         xXX1Eqh1S0Ag/WNXia3BWpDfhNHHC6cCAmV0HwuvjcGBg81RpIN6ule5DCLSJs0k7xrI
         yX4chx/JxM9+g7Gc/iTjeIWQFW8bGyiDOPkqHqMY+NVeSy1X8tMwkEpWZf7OXe/X0poy
         wyzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zT9WPDRFkrERzkcrQo8X2gHZH8xYrOQCvtDn+ZggZYE=;
        b=h2aM/irHjS/IevoNFrIT91owvE8OmxnDVPdcFDRY3KJPAL6y9wI4ey6cKsrpW5XWPr
         eaBTfJf/aw9lkTArMHDt6kV+484x6gfcKnVSz0EM5hDv2ikhLEv5obY8/lJoUnrd7AH0
         0IGqfcDiFUuIumB+yKSDcgDsFmzG420tikMdQ3UFv6OSwN1J7palWgP50pvNYPr4QYN+
         rGxE8kKjwLLcSuSgek8c5vtWR+TIt6M7H1d8s+u0bk54zrp+BlBKe4/dI6ZX8IkGtKrE
         EJiRcVlw8hL3/7kYzYgA94yJtUyEp9/67gTQOv2eK2nWigzPvOrxEQmPdE1c5c/U7UTH
         EFPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zT9WPDRFkrERzkcrQo8X2gHZH8xYrOQCvtDn+ZggZYE=;
        b=AMAiwVxpG5MnOjznbppS9oq1ZdwjTilH8x2P+o+gOZ0sYrSHjttIdxK7K673Hr73qt
         k8Hl+ZH5czb+PncIeXcMcCxYFkinOo4hfCA8zBelC7wTxu+wxLo3KdY6kdX+ZSplqxvn
         zMzBDTDjIf8aSMihwI7wDsnokTQKhAky44bsnJYo1rj0Eo5yNb6l+0bxKQypBSW33v2i
         bDVFEGvXhrUSnpng486s1QwbhhS60xX230lle/jhG8mPOfij9Eybs85sg2xr+R9C03Zn
         tEtTD2iBtRkOs0GYjNov9u/u+VE+pWs/3zlnDIbEuhFeWCLbUtxj1KIf38TsSnPvHXu7
         0r4A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531BCz4+J9n5qUV1rVGDV8YC0yvukBeFZAJDJhyq9iWLtbyvgch9
	+fS2S2mwyz2qFrOAZfPwxrc=
X-Google-Smtp-Source: ABdhPJwHD/oJtfG25Vbpvd7CKuOAYTQDtghydD2Pv0NAuQPm06AntSXl2pjNSNQi7Iy4Nc7WrjNQXg==
X-Received: by 2002:a1f:9d04:: with SMTP id g4mr597225vke.10.1605173819824;
        Thu, 12 Nov 2020 01:36:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:ef8c:: with SMTP id r12ls337222vsp.7.gmail; Thu, 12 Nov
 2020 01:36:59 -0800 (PST)
X-Received: by 2002:a67:fa10:: with SMTP id i16mr19615484vsq.3.1605173819369;
        Thu, 12 Nov 2020 01:36:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605173819; cv=none;
        d=google.com; s=arc-20160816;
        b=BMQt9NdtoS1kVTJ+wt4z4c4spsdkMzzmKheBEJGP9XLn6nh4GITX/+TmsjxxxboIAR
         AHQoriHxW3SBcVRSoiOvEvPafRnmor/e0JEjvmTs9b1zdHJB0ejeoG8fI79IS7uPRNtB
         BXYwGECcSHpZfjzT03UXVFSZz2y8fh898NW6mw4hEDqgreDA+gOeeegPOx+Hj333fB84
         d6WjZz1m9G/VfEwlpuP9rPMZgqZxKVOXHQPD2ZePOoEiHO6Y6kvl/dqpITk0WugRIWch
         8YH8bRqlxnHk7nApa5oHhDDdH6YhLHkipqFaffVgZG9TXVmKJJJv59QN0E/kCfH3fFTK
         3YdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=LW28ULP7NLKewnHCptihvOevLt4Gcnr5qKI9uQR4Fxs=;
        b=Eul1AP73Kdu9RPrTGdH2PnIMNf5GG1o2O08lo6R9KJRJkOHh2mTRHFfStVu87Jh3Lf
         RxxdzSM5oy1208kMq+golkitdETEOPyOv1AEpJnEqjBCl2jA84yrY2xT5W4FNPBhfozB
         VOt6Oe2T3d+Z/VSf/GM3j3xJCFG5S7U+tEJ2Em5hl20TdAxA1mzCHesj3vrOkDtgcyTx
         WdLF0kZGyKvpmj3/zxSH22V7MSMdwaLpKR2t1d4gJKQ+P6SMVgGnEn0AuvO9GOI6OMN9
         PODERw5/Xrv9M3YkNwDRfsxhwiR48fyYjqcJ/uKysCcBpFyBN7Eo9DhOCgW2nqN2QUJl
         b1ZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id p17si366897vki.0.2020.11.12.01.36.59
        for <kasan-dev@googlegroups.com>;
        Thu, 12 Nov 2020 01:36:59 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 932FD139F;
	Thu, 12 Nov 2020 01:36:58 -0800 (PST)
Received: from [10.37.12.33] (unknown [10.37.12.33])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 7C3EF3F73C;
	Thu, 12 Nov 2020 01:36:55 -0800 (PST)
Subject: Re: [PATCH v9 28/44] arm64: mte: Reset the page tag in page->flags
To: Catalin Marinas <catalin.marinas@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <cover.1605046192.git.andreyknvl@google.com>
 <4a7819f8942922451e8075d7003f7df357919dfc.1605046192.git.andreyknvl@google.com>
 <20201112093130.GD29613@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <cbc140bf-a949-d9cb-3c9e-92304ee40c8e@arm.com>
Date: Thu, 12 Nov 2020 09:39:59 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20201112093130.GD29613@gaia>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
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

On 11/12/20 9:31 AM, Catalin Marinas wrote:
> On Tue, Nov 10, 2020 at 11:10:25PM +0100, Andrey Konovalov wrote:
>> diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
>> index 70a71f38b6a9..f0efa4847e2f 100644
>> --- a/arch/arm64/mm/copypage.c
>> +++ b/arch/arm64/mm/copypage.c
>> @@ -23,6 +23,7 @@ void copy_highpage(struct page *to, struct page *from)
>>  
>>  	if (system_supports_mte() && test_bit(PG_mte_tagged, &from->flags)) {
>>  		set_bit(PG_mte_tagged, &to->flags);
>> +		page_kasan_tag_reset(to);
>>  		mte_copy_page_tags(kto, kfrom);
> 
> Any reason why this doesn't have an smp_wmb() between resetting the tags
> and copying them into kto?
> 

Yes, the reason is I am not sure why it disappeared from the submitted patch ;)
I am going to respin the patch.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cbc140bf-a949-d9cb-3c9e-92304ee40c8e%40arm.com.
