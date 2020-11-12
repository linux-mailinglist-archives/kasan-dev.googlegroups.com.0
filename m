Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBFUHWT6QKGQEFO63CCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id C2A9E2B0224
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 10:42:47 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id 33sf3309377pgt.9
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 01:42:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605174166; cv=pass;
        d=google.com; s=arc-20160816;
        b=GUav/8yqlgmZtikj7VzIJz0scFTqOoXfFcgfXO7u04AnTpfZNDf9k6ZlhqwSXi/AXW
         vW6Qip54tVhQEpq8bEqCUayarlMgBWhhQIIbnfzGsz4C9+HFzg9D8DT1ZMw4QSdyGkGe
         aIxezxgf4e+m14v2AxB2wRbOs1ON9m5lB0j8G/aJobWjYuauzwzq/62z6BkVa8IAK7jc
         /s23bjxwjJLYIzvWbKaqTBPx2aXcJaibA/4+Ej12qIH9gL97WZr0UVnQoc8yjqCoNyeI
         yPBK+3dmUEckMD0JBafJedCHRrTyRxaZmWYXxxU8HlTd8fKTRsKwAX7JzR1oNuM3LrVf
         +P9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=tuKkcPMVIP3TXX4R87c5JUFUGmkZxUkBUEX9pEMqmdA=;
        b=cd7s9V3s5+2PkKS9BnZ2J8r+NWB5gAE1SuXxUZWPncf/bEdDtI3mjoIA/zIqOmi1Uf
         cy8DEBMA2aeMCGp/5VwuKSTYzz6hj+dlwD5vQoW9NYAYz2ApN3HTDoXJmhwL2ICBbXFd
         Gluc4fQQ6JPSJWEqscnl+4SSsxiFTiMqcnucNLLZVNiN9ZQRpJeXeOC03JR9aVoykOqq
         Uv3poEQbhVqWEnsWOCHtyERMMPTYuLLG1kP1SFDuhc0jZ0MSrSa+XFDv0F3S24241IQs
         GPp3AlkvfKyTOT/k/zm9Y4w7wVyZleRez+dvkY6UvvSNlYHLlc0ImJ3f5r/zbKc/X5Xp
         Jl5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tuKkcPMVIP3TXX4R87c5JUFUGmkZxUkBUEX9pEMqmdA=;
        b=YzyDATvycImx2593prOOXdr+CL/SN9gvW4y5OyUojmMQ8WB6FEiv/O5R5A9O+awtaR
         1MYG75croCO/HPb+lrbEDfVEnn5TlU/2rLMhATJGsUFP+O+gRisaDgNj/qSS0TT8mk0x
         1gL2C1L8hBAGwuCYGE7rZ2C/Z5Kau4HsjpZ0SN68ZlN+jaZ7y7C2d3//HORx8iu1Rqn+
         YyoSRPs735jBUQ0dFReGsZOeJGINO0p5O69M405OvsQm74+Ea2v5gMblxYti92mKipyQ
         MvGCjP+kstS/6RgGXD5K/bKuRepo12F47JEyxDxuHXsYZ/Q6alCBg4e36F4BZp6oIZMI
         e6iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tuKkcPMVIP3TXX4R87c5JUFUGmkZxUkBUEX9pEMqmdA=;
        b=RDLJL9z8hx8Qy7wLEwBmOu0wCDvQZkJFsn6QSSzixgdY2w4lVtwMefZEvp6ukuTlJN
         FT2XkfXgiipvswD0UbedQQO8HPAyHurctDSqrzlvvmn7ysjAYXtkh5QL7VFzZvJ+BMLX
         pjCqaID/QkuPilMq4x5f88uoQ7zLGf108SLWzyXYCH1ljN4LdLiUcM/R0rRVRo9hXFef
         Bql86sxvSAEUMhvR2ltzkPuTQOwxfkYYFf8tT/aw+ZJwjs1BDGvMp3TOFFugndMepi0O
         bVvzBXyhtkB6rWkUn+ZUk7TG95UIC+gdl0V3tTDMw1XHyiwwQB80dbVa9tIcLZQhGhqy
         y3ZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530VUb7aMfEfQ/H6vOdgLBk8J+hfRpnrQOG3yspYBN4Jr82vfqjT
	k0eQ0xZ4G8i2GoTq1dsbVxU=
X-Google-Smtp-Source: ABdhPJxl3537xTR27Tkx1vk2lWtXx7wK4K9H1qQw9xpDIQice6sNL65Do5YFXa3uqc5HWR8M8d5TsA==
X-Received: by 2002:aa7:9e4c:0:b029:18b:f89f:9e61 with SMTP id z12-20020aa79e4c0000b029018bf89f9e61mr19695539pfq.26.1605174166513;
        Thu, 12 Nov 2020 01:42:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:ea4d:: with SMTP id l13ls910507pgk.0.gmail; Thu, 12 Nov
 2020 01:42:46 -0800 (PST)
X-Received: by 2002:a63:4c5b:: with SMTP id m27mr26325692pgl.211.1605174165880;
        Thu, 12 Nov 2020 01:42:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605174165; cv=none;
        d=google.com; s=arc-20160816;
        b=QamVdPAhdee3hbrwoDz0qGfMYOsm/P4FKKbov7rWVrEL5CxbsgUnuItweNNTnJj7wu
         o6zoXiPs1h8a6hUCp242F5RUfbeWVPg85w5zQ6Buu17NqiZUWRwOdP9jLYD/xsTbqddE
         7JDllVHu5rLCYa6ZB9ifg0/V93jc6nMLvMdx+1AS6WVJdt6YZLBq9RJsWOdE7Cholnk9
         YeaNMpIlxk7v+Sl7Ul/tctJY5HYTg01Yz33gw2bVI8ea0vVyQlp9XnPPsdYCC3S/5M/x
         X4957E1chmkBT+l+Fx9SD6k7mBsN/7He96ygZ3vHxIKJqnALRkF8oKOccGGSzZDDcPMu
         kZBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=s3riNvjrDeCSp9nr8LuNzlAD5Z5+8WQqGLJM6PULAoI=;
        b=dYlhRxeazFvY/h6bwrlXUqZdd/K37PWOryNhoiBtqiqvlG0+4jjj/4105uqQwLcaxU
         0UW/goaVFGzr/2BcGYN85O6OhIsjdkx1H+UZ7wH8B39HtecqzFICjClQHcj92ktXsnrW
         LJIpiEzY8GqSOrhuGRXvG+Av34TmBM6uhJnwvBXCOXZ7YEkVa/e1Zyc9z9v6rHYA1RBC
         zC4faeyIV1IFWyPcSMZVsuJNbvb5HFhiEDMOpnfhI+osqNIfz4LuS0E4uHJlNJDu2QSR
         oWGFXujHhCHVSB5hC63WpPdCU5pf/ACPPUJOvwt/KaALlCDvcB6gJkM9RhSp6/XQXitU
         89ng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id t130si260815pfc.2.2020.11.12.01.42.45
        for <kasan-dev@googlegroups.com>;
        Thu, 12 Nov 2020 01:42:45 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B1806139F;
	Thu, 12 Nov 2020 01:42:44 -0800 (PST)
Received: from [10.37.12.33] (unknown [10.37.12.33])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 6C7CC3F73C;
	Thu, 12 Nov 2020 01:42:40 -0800 (PST)
Subject: Re: [PATCH v9 32/44] arm64: mte: Switch GCR_EL1 in kernel entry and
 exit
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
 <25401c15dc19c7b672771f5b49a208d6e77bfeb5.1605046192.git.andreyknvl@google.com>
 <20201112093908.GE29613@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <db6e3a5d-290f-d1b5-f130-503d7219b76b@arm.com>
Date: Thu, 12 Nov 2020 09:45:45 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20201112093908.GE29613@gaia>
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



On 11/12/20 9:39 AM, Catalin Marinas wrote:
> On Tue, Nov 10, 2020 at 11:10:29PM +0100, Andrey Konovalov wrote:
>> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
>> index 664c968dc43c..dbda6598c19d 100644
>> --- a/arch/arm64/kernel/mte.c
>> +++ b/arch/arm64/kernel/mte.c
>> @@ -129,6 +131,26 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>>  	return ptr;
>>  }
>>  
>> +void mte_init_tags(u64 max_tag)
>> +{
>> +	static bool gcr_kernel_excl_initialized = false;
>> +
>> +	if (!gcr_kernel_excl_initialized) {
>> +		/*
>> +		 * The format of the tags in KASAN is 0xFF and in MTE is 0xF.
>> +		 * This conversion extracts an MTE tag from a KASAN tag.
>> +		 */
>> +		u64 incl = GENMASK(FIELD_GET(MTE_TAG_MASK >> MTE_TAG_SHIFT,
>> +					     max_tag), 0);
>> +
>> +		gcr_kernel_excl = ~incl & SYS_GCR_EL1_EXCL_MASK;
>> +		gcr_kernel_excl_initialized = true;
>> +	}
>> +
>> +	/* Enable the kernel exclude mask for random tags generation. */
>> +	write_sysreg_s(SYS_GCR_EL1_RRND | gcr_kernel_excl, SYS_GCR_EL1);
>> +}
> 
> I don't think this function belongs to this patch. There is an earlier
> patch that talks about mte_init_tags() but no trace of it until this
> patch.
> 

Could you please point out to which patch are you referring to?

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/db6e3a5d-290f-d1b5-f130-503d7219b76b%40arm.com.
