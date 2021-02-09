Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB3PJRGAQMGQE3FJHE3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FD66314E4A
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Feb 2021 12:41:36 +0100 (CET)
Received: by mail-io1-xd39.google.com with SMTP id z8sf11252372iod.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 03:41:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612870893; cv=pass;
        d=google.com; s=arc-20160816;
        b=jZTLuFEPwsROuWHbxmFlUId95feBnPoHkwOxfaDl0nYQVCbkjd77lqNTYLMc5vT4xD
         ujGKoXayowQVh5BOu6/L+SLtPok29uxeGGACPwHpjy21H+U3L9uf+rI0pqb1TmkorxeU
         hxzq5JOpBKO1qBEU1CLbmbJR0MDWA6OCmmuruuVQBQF8oKMyYHAwoObdXPTeyksb8SOI
         gqV5IYpWu401h85Nfht943KXbS8KwV6iZJObqhn8kZNZCuv9yPd6UJD/gzENSS5aI5Kx
         kX/El4Wf6xDxoC46c3x+N1lIoj8FCNXKGH9wID1DdZ9tPWcXw3lQ7boW/ajJUS51RZr7
         u3AA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=XjXEShfqXFI8j9CmW2hVNafyqMXXqNIY7Z1CwjsYhYE=;
        b=fgnFu4uYd51of0g2RNeE6xfDZz5WH5gPkvVeiApYgNHe2PYYmhxcqLyI0zAL9F5tEX
         oR1mvCLoe+/cRe3cM8w0ncZ+Ehaz0ME7eSWdHPVz01d80ZK+7eXFwt5gRMfXKWuJpIzy
         f14+AVpzjuDXilD/qaenMCH4EMyX4XXGkEQpIWa90mh54B3h9ENGOuDtF2oaYBsQNnf2
         2G85ywl2pvpVL1bUuqmV5vsQgsZqpC70MSxqLsVddNvic7obrfxbeW7eEUxw4q5PsUck
         Nml9L4AefsEhqRNCeRpnvP/RDbkCXOS51qiD6yFK1t97sa9jPyib2SNIocAwSfh0SSbW
         smww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XjXEShfqXFI8j9CmW2hVNafyqMXXqNIY7Z1CwjsYhYE=;
        b=QCjeDit2knVqEGBiy/9PllKz/Ry4mmAPiPYgUmlglAkmAnsGVX+CawtZKx/LqalJ4c
         6usIh2WuvnW69yKzXbZSKTNYPUUYUvbINy2vrk+q3fg97m/KxlIodD5pNx0cc1SGO8vH
         nCWOJB33WECkq/HkZr+3QGxvU2gj3eLNbVghXSL4tsg2d9ENDhUsLvI1E0zSMliWwGkl
         veoVzpumudOEKGrXgtTgRknpP4kZGEHsVMZ/13UxEf9P8eDYDACee4hlOkQKIUkkGgqd
         oLVSPsXKrJyWKy0MzHjmmKERAJqbUQL4X1+RzZ+vJnkfSPESzmKE8xZA+pBlW7zGB0WA
         ZEPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XjXEShfqXFI8j9CmW2hVNafyqMXXqNIY7Z1CwjsYhYE=;
        b=OILBZWz5bOt7EDe9QSOASIHiqOEqYipDMl0dJjaxCdIQcKacL+XT78ZCvapWF2/Bjx
         Tgx4ok2pSSAerZPMgXtYwkLXOpfoDf2Y3x/FjEpDEci8G4ZkKif2rm7oDJ2GaBE9FpCj
         5U5NtHpo9qfH9+TArCe9jz0p9uoR0CjujbpczAy6tX0GNUgrEg86BbawH8p/293LI3mZ
         f3R0hZYSEwYXrOMWfRBfAsvlaIXjkDQFHTfjjPQquwDW4ViNd00d6cfFK/8BFNGX2SpS
         PJkGZEXq81aS6dzTBvH4IF4Aotrx1HP4rBm3NGCmtSAM3JojasHmYSXk4dlZR/kum+i1
         kE9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531QmZZkcL2F6geV7LvJmyxeUVdGs9wzPH3RPa5aKDzXENisDMWD
	xegB3esNVdGWBsHvT7KsscI=
X-Google-Smtp-Source: ABdhPJwKYUh23iuI4iymx2NeDAy0fKVAoiWwlQ1oC7SaCmeOb9VaZq4018ri0CjV8uWEYJw6QjoWHA==
X-Received: by 2002:a92:870d:: with SMTP id m13mr19280361ild.104.1612870893640;
        Tue, 09 Feb 2021 03:41:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:b44:: with SMTP id f4ls4767679ilu.6.gmail; Tue, 09
 Feb 2021 03:41:33 -0800 (PST)
X-Received: by 2002:a05:6e02:1a0f:: with SMTP id s15mr20008234ild.244.1612870893248;
        Tue, 09 Feb 2021 03:41:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612870893; cv=none;
        d=google.com; s=arc-20160816;
        b=FTLhBsBS5Z7+z4Vu/WyzcVqs3y71SPS4Yug7rkFUTthvGZvIFh/3sNsnLwZoMFQEk+
         mclcDwF83BsNtxfC21dalxOYB6kdq4gvTKuVaBkdm2GvU7/wdoWIsf/EvGA1usHVBqiP
         bvjJpIsoLirMHoe8ZeJ7WIbRLp5HnQ/s3lpLwh0Vqhx3BEl8N1eraiXyIMyqD3lcBGA+
         OGURwnhCYTDepYO307FIW1jkD7LJkYTM3M5DKM7cxK+NNIgZqtV0P60/rdqUYqxiCZJw
         Ur4NLjPeGiRaVAcWhs7SbioJPk5mACnrdjGX2aUxn1KKz/tQxElSTBwL+U0pkmFTTQ/I
         MFcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=Bb5yoERLfelmNtYPMhKYZh+X+ZFIHafVG9XaUqwdHDc=;
        b=pKCsz08K6Q4UoaJKXPZk85Hff3XbggvA4UZr/H1jcrXyial6QHEot5x39RFXz+pRNY
         8e3cCVxN1NnAtJAdO/VdMHypopJdF1d3Q92MOSTeVVRCA14Ka9sdEMFi7j5/nqhcabXB
         oHem2tH51UCYGAHbFUebna5Yfn6LKzZ5l2zdhYfURMb6dNt6MQc6XcB1ptV6QuS4eGwa
         z2dlSNRydOUXhJRiTJbMS86gDwzBJoWnlRZh2n0C7hz0Y7uM6kFq75TY7sXXnKwQdVIj
         +VKohD7uC+XXM2Qiaz6h+Z6ggeg2241fh51MCSEKOoVKpqsPs1NjcHT64ZsklTWP+if7
         35FA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d2si271988ila.5.2021.02.09.03.41.33
        for <kasan-dev@googlegroups.com>;
        Tue, 09 Feb 2021 03:41:33 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 7C5B1ED1;
	Tue,  9 Feb 2021 03:41:32 -0800 (PST)
Received: from [10.37.8.18] (unknown [10.37.8.18])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id A34EF3F73B;
	Tue,  9 Feb 2021 03:41:29 -0800 (PST)
Subject: Re: [PATCH v12 4/7] arm64: mte: Enable TCO in functions that can read
 beyond buffer limits
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Andrew Morton <akpm@linux-foundation.org>,
 Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
References: <20210208165617.9977-1-vincenzo.frascino@arm.com>
 <20210208165617.9977-5-vincenzo.frascino@arm.com>
 <20210209113505.GD1435@arm.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <1d8c98bc-2192-94c9-a383-d3e9cecc2eed@arm.com>
Date: Tue, 9 Feb 2021 11:45:32 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210209113505.GD1435@arm.com>
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



On 2/9/21 11:35 AM, Catalin Marinas wrote:
> On Mon, Feb 08, 2021 at 04:56:14PM +0000, Vincenzo Frascino wrote:
>> diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
>> index 0deb88467111..f43d78aee593 100644
>> --- a/arch/arm64/include/asm/uaccess.h
>> +++ b/arch/arm64/include/asm/uaccess.h
>> @@ -188,6 +188,21 @@ static inline void __uaccess_enable_tco(void)
>>  				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
>>  }
>>  
>> +/* Whether the MTE asynchronous mode is enabled. */
>> +DECLARE_STATIC_KEY_FALSE(mte_async_mode);
>> +
>> +static inline void __uaccess_disable_tco_async(void)
>> +{
>> +	if (static_branch_unlikely(&mte_async_mode))
>> +		 __uaccess_disable_tco();
>> +}
>> +
>> +static inline void __uaccess_enable_tco_async(void)
>> +{
>> +	if (static_branch_unlikely(&mte_async_mode))
>> +		__uaccess_enable_tco();
>> +}
> 
> I would add a comment here along the lines of what's in the commit log:
> these functions disable tag checking only if in MTE async mode since the
> sync mode generates exceptions synchronously and the nofault or
> load_unaligned_zeropad can handle them.
> 

Good point, increases clarity. I will add it in the next version.

>> +
>>  static inline void uaccess_disable_privileged(void)
>>  {
>>  	__uaccess_disable_tco();
>> @@ -307,8 +322,10 @@ do {									\
>>  do {									\
>>  	int __gkn_err = 0;						\
>>  									\
>> +	__uaccess_enable_tco_async();					\
>>  	__raw_get_mem("ldr", *((type *)(dst)),				\
>>  		      (__force type *)(src), __gkn_err);		\
>> +	__uaccess_disable_tco_async();					\
>>  	if (unlikely(__gkn_err))					\
>>  		goto err_label;						\
>>  } while (0)
>> @@ -379,9 +396,11 @@ do {									\
>>  #define __put_kernel_nofault(dst, src, type, err_label)			\
>>  do {									\
>>  	int __pkn_err = 0;						\
>> +	__uaccess_enable_tco_async();					\
>>  									\
> 
> Nitpick: for consistency with the __get_kernel_nofault() function,
> please move the empty line above __uaccess_enable_tco_async().
> 

Ok, will do in the next version.

>>  	__raw_put_mem("str", *((type *)(src)),				\
>>  		      (__force type *)(dst), __pkn_err);		\
>> +	__uaccess_disable_tco_async();					\
>>  	if (unlikely(__pkn_err))					\
>>  		goto err_label;						\
>>  } while(0)
> 
> [...]
> 
>> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
>> index 92078e1eb627..60531afc706e 100644
>> --- a/arch/arm64/kernel/mte.c
>> +++ b/arch/arm64/kernel/mte.c
>> @@ -27,6 +27,10 @@ u64 gcr_kernel_excl __ro_after_init;
>>  
>>  static bool report_fault_once = true;
>>  
>> +/* Whether the MTE asynchronous mode is enabled. */
>> +DEFINE_STATIC_KEY_FALSE(mte_async_mode);
>> +EXPORT_SYMBOL_GPL(mte_async_mode);
>> +
>>  static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
>>  {
>>  	pte_t old_pte = READ_ONCE(*ptep);
>> @@ -170,6 +174,12 @@ void mte_enable_kernel_sync(void)
>>  void mte_enable_kernel_async(void)
>>  {
>>  	__mte_enable_kernel("asynchronous", SCTLR_ELx_TCF_ASYNC);
>> +
>> +	/*
>> +	 * This function is called on each active smp core, we do not
>> +	 * to take cpu_hotplug_lock again.
>> +	 */
>> +	static_branch_enable_cpuslocked(&mte_async_mode);
>>  }
> 
> Do we need to disable mte_async_mode in mte_enable_kernel_sync()? I
> think currently that's only done at boot time but kasan may gain some
> run-time features and change the mode dynamically.
> 

Indeed, as you are saying at the moment is done at boot only but it is better to
make the code more future proof. Maybe with a note in the commit message.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1d8c98bc-2192-94c9-a383-d3e9cecc2eed%40arm.com.
