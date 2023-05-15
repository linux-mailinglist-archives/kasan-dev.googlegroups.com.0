Return-Path: <kasan-dev+bncBAABBGVBQ6RQMGQEBVL4K2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3BE7F70249C
	for <lists+kasan-dev@lfdr.de>; Mon, 15 May 2023 08:26:36 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-19297b852cfsf76565325fac.0
        for <lists+kasan-dev@lfdr.de>; Sun, 14 May 2023 23:26:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684131994; cv=pass;
        d=google.com; s=arc-20160816;
        b=W+u2zn/jmMxrcjaR2324CLq0DvilAFFNi1cV5xudcpUrSZ/HDZa17wSawJx4cHj6K5
         QBBvIAz6QNDkskdwIF+MZfC5AOF3Szte+LJCeKArW2VuwMAowE0+ft/tslnFr2Zl5NrI
         4IH9rTHcwHJYcthKjym0WsSk4n1rbqufBK1TKyNcesKwuO1ro8VSDElCvhnaKJmmiR0d
         U8hDG5djhBJIRhYtLVghWBXERdksMoez0ufLPYG/D5kCt+K0vEn4TKMFYNMqGqJgQpmM
         4UIe3QoXkIiHQVTBZFjp5pi25e9EbffPDEB7WwmfcbaGq/HnUiCWazj+uGMemPZTFBTa
         1iqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=AmSuR6OewzhW0zLpYfsQXCQ66nzPI/wabsP9CmiTx8I=;
        b=o5ZYtWNtdNpHqc5AfW6F4zB0PetsNdP76vKAVjD69gREATzKg+C6tJr3VnCrBOlw1k
         IYoYzHRFCm7YcgUwOMYzUeNraXjHJ8nN7bnX/wKpDMWc/3eXXlV24smzfAP3VATWgr4L
         hNDFv7i28TB60b8e0nkbHm4llOT6L3zdvQ1YY5eBQW5DdDSGNp/JykaRKnVcFt7l4bEz
         0uVEDNr99wQ+lpec16o+TDjgjeFm0DNQFvo7SVw7KlydscX/ThvXlJLzjUOl7mRSrRBS
         76P1duRTC1gfk5/2GUya6MWCLYV9VHWGSdjKxJCyGiRXr9ikPIAmQByXic/5K67tGJsu
         xtZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684131994; x=1686723994;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AmSuR6OewzhW0zLpYfsQXCQ66nzPI/wabsP9CmiTx8I=;
        b=DbSpMGqepNPZRoqZ6B/EmiCiQrf05lRxDTEuxGQn8uwhh2ye2It14P967SB9XovQAf
         ox4dcQEU60hicdREmYi5kzFodhxwuUjxbyZunNiMjtweQhTddDfX1hk7rbW0vINgSwIk
         HbJVmkjgPCajGF6CKrMgvXdofB1FQM981s+hg7CuTYiMDlYIX6j78w8bTgbYVuzgv3Ro
         +gSxE8EXoAr/EgW0D8PRHsPF5c/JLDt4/r2+ZT+sIsGIyj/RiUkH63Mb+5jTQjzjR8US
         hHVI5tFTzTrKqZS/DTh1WWWVGpLX2L+fzWwKFa73Yk6c1NRGvJFA514l4BZzhm+kRlHQ
         SsNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684131994; x=1686723994;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=AmSuR6OewzhW0zLpYfsQXCQ66nzPI/wabsP9CmiTx8I=;
        b=mGNSfZWsxsBPFYqAsQHmuFl1UsvjlydE+9z46Gz/ldilCm0m6LDRYtQG3CufnbwAVE
         49d31LLBEOuqwFp40K/qN9ANKowMRxTMgKIxpGhKKbV0SkKBFTFAGW/OP/qcg5hq3Hf2
         SCA0ivs/009R+ZwEe1lquYmcl9k/o7cw2Lnjlmc812mmv1TKHqkgf/fJ4YYayr80o2xE
         S+v2Do7IlhbpbWQL8e4A/mBTEwIamimwiTfmON8PkdnKb2zJj7LNbjLlwUCTL9Sv+gtf
         7QjrVq/K1PgEc3+BYG1Dxvx2qcadt94vrn+Iq3HJ5qWhLJ7GRSy8uAgRYL4tW6b5B7vU
         3K5A==
X-Gm-Message-State: AC+VfDzD+Nm27iwKENNBH4QrMBrsyegUw1byCsjZz4v7AlrfV1aYsxE9
	Lkkq1xXyxpGEvGdxehpOmVE=
X-Google-Smtp-Source: ACHHUZ71bh/oBuncnNiGdRG24c/hAhwnD3J3VPNs3zETwLrmyzJrUNqkYbXQDz36RS2prW182I7QaA==
X-Received: by 2002:a05:687c:18:b0:187:7f29:c1 with SMTP id yf24-20020a05687c001800b001877f2900c1mr11662346oab.0.1684131994745;
        Sun, 14 May 2023 23:26:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:5b12:b0:196:325a:cfce with SMTP id
 ds18-20020a0568705b1200b00196325acfcels1541917oab.1.-pod-prod-02-us; Sun, 14
 May 2023 23:26:34 -0700 (PDT)
X-Received: by 2002:a05:6830:39cf:b0:6ab:2abf:35ed with SMTP id bt15-20020a05683039cf00b006ab2abf35edmr9104330otb.0.1684131994360;
        Sun, 14 May 2023 23:26:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684131994; cv=none;
        d=google.com; s=arc-20160816;
        b=RVwWKEdd34rT1g7FS5LbmngzDDaYCOWB/b+h3E6YJfUDe9dPAXdS9QK02LDaD+FSz0
         n++teAyM3WzrVffzZ/bPFOKWuLm0r9V1ac7P/+WbvJ1mEfAJDFd34kz3rIsKoaranR+a
         dj/jGkfSQk5e+ifa+oA4kp3mxZtMRGF6McYJQHonD9ljVIqKuvpa6a7sGlTztCYnDQiA
         aNbwZckzz9C1Qrf/bJ6rLagPT8O9QDr3NqCYWxJrQOG/56r0WxBYC/Vzczv3FLMTIopS
         c6ERNZrykSHMoSv2vyxg6RhU2fuhSYTXLey4GEQqykeKkdnoKn2o/luxYmMMLKPrWV+J
         GRMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=nJnAtxh+M2dK8VZ1TLjKhd31KUufOlL/y9nDByIgcww=;
        b=LRotkBxoD6FtNPV0I8A5fP8qTk4xu83ifXSjzDD2Bs0ln25b2+ZMlQgCf6AQz8h6cc
         UwiuaxIHq6rr/2wjVg/i81o9GbSJicmhrmH7/kMmVL1sYDGkkAFs1u8krplyXshwTrY/
         4uuFb6XvLcNBoKkfMp4SF+X2eZTR5CDI3PmO9NjtdHcpC+u0GIYcJ218Y6PwtQ4XextX
         +mmuFziidlv73z7YpUYHbfZ7IANqqKASASZqrS8g0ejBpJDW1kANwD/dXEpxEksFL8G+
         s92G9SintGNMY1tQzSlBxaD518wQbYWkmEKQ5O07S40GUI6ZZ40nCQaxUrp93O8kRy/X
         /9zw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id j12-20020a056830270c00b006aad6752ce1si382361otu.4.2023.05.14.23.26.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 14 May 2023 23:26:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from dggpemm500016.china.huawei.com (unknown [172.30.72.53])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4QKTr91CXhzLmJB;
	Mon, 15 May 2023 14:25:13 +0800 (CST)
Received: from [10.67.110.48] (10.67.110.48) by dggpemm500016.china.huawei.com
 (7.185.36.25) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id 15.1.2507.23; Mon, 15 May
 2023 14:26:31 +0800
Message-ID: <fe79912f-3232-ffba-a191-477c80c703f4@huawei.com>
Date: Mon, 15 May 2023 14:26:31 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.10.0
Subject: Re: [PATCH RFC v2] Randomized slab caches for kmalloc()
Content-Language: en-US
To: Alexander Lobakin <aleksander.lobakin@intel.com>
CC: <linux-mm@kvack.org>, <linux-hardening@vger.kernel.org>,
	<linux-kernel@vger.kernel.org>, Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	<kasan-dev@googlegroups.com>, Wang Weiyang <wangweiyang2@huawei.com>, Xiu
 Jianfeng <xiujianfeng@huawei.com>, Pedro Falcato <pedro.falcato@gmail.com>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Vlastimil Babka <vbabka@suse.cz>,
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Roman
 Gushchin <roman.gushchin@linux.dev>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>, Pekka Enberg <penberg@kernel.org>,
	Kees Cook <keescook@chromium.org>, Paul Moore <paul@paul-moore.com>, James
 Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>, "Gustavo A.
 R. Silva" <gustavoars@kernel.org>
References: <20230508075507.1720950-1-gongruiqi1@huawei.com>
 <75179e0d-f62c-6d3c-9353-e97dd5c9d9ad@intel.com>
From: "'Gong Ruiqi' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <75179e0d-f62c-6d3c-9353-e97dd5c9d9ad@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.67.110.48]
X-ClientProxiedBy: dggems703-chm.china.huawei.com (10.3.19.180) To
 dggpemm500016.china.huawei.com (7.185.36.25)
X-CFilter-Loop: Reflected
X-Original-Sender: gongruiqi1@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.189 as
 permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Gong Ruiqi <gongruiqi1@huawei.com>
Reply-To: Gong Ruiqi <gongruiqi1@huawei.com>
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


On 2023/05/11 22:54, Alexander Lobakin wrote:

[...]

>> @@ -777,12 +783,44 @@ EXPORT_SYMBOL(kmalloc_size_roundup);
>>  #define KMALLOC_RCL_NAME(sz)
>>  #endif
>>  
>> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
>> +#define __KMALLOC_RANDOM_CONCAT(a, b, c) a ## b ## c
>> +#define KMALLOC_RANDOM_NAME(N, sz) __KMALLOC_RANDOM_CONCAT(KMALLOC_RANDOM_, N, _NAME)(sz)
>> +#if CONFIG_RANDOM_KMALLOC_CACHES_BITS >= 1
>> +#define KMALLOC_RANDOM_1_NAME(sz)                             .name[KMALLOC_RANDOM_START +  0] = "kmalloc-random-01-" #sz,
>> +#define KMALLOC_RANDOM_2_NAME(sz)  KMALLOC_RANDOM_1_NAME(sz)  .name[KMALLOC_RANDOM_START +  1] = "kmalloc-random-02-" #sz,
>> +#endif
>> +#if CONFIG_RANDOM_KMALLOC_CACHES_BITS >= 2
>> +#define KMALLOC_RANDOM_3_NAME(sz)  KMALLOC_RANDOM_2_NAME(sz)  .name[KMALLOC_RANDOM_START +  2] = "kmalloc-random-03-" #sz,
>> +#define KMALLOC_RANDOM_4_NAME(sz)  KMALLOC_RANDOM_3_NAME(sz)  .name[KMALLOC_RANDOM_START +  3] = "kmalloc-random-04-" #sz,
>> +#endif
>> +#if CONFIG_RANDOM_KMALLOC_CACHES_BITS >= 3
>> +#define KMALLOC_RANDOM_5_NAME(sz)  KMALLOC_RANDOM_4_NAME(sz)  .name[KMALLOC_RANDOM_START +  4] = "kmalloc-random-05-" #sz,
>> +#define KMALLOC_RANDOM_6_NAME(sz)  KMALLOC_RANDOM_5_NAME(sz)  .name[KMALLOC_RANDOM_START +  5] = "kmalloc-random-06-" #sz,
>> +#define KMALLOC_RANDOM_7_NAME(sz)  KMALLOC_RANDOM_6_NAME(sz)  .name[KMALLOC_RANDOM_START +  6] = "kmalloc-random-07-" #sz,
>> +#define KMALLOC_RANDOM_8_NAME(sz)  KMALLOC_RANDOM_7_NAME(sz)  .name[KMALLOC_RANDOM_START +  7] = "kmalloc-random-08-" #sz,
>> +#endif
>> +#if CONFIG_RANDOM_KMALLOC_CACHES_BITS >= 4
>> +#define KMALLOC_RANDOM_9_NAME(sz)  KMALLOC_RANDOM_8_NAME(sz)  .name[KMALLOC_RANDOM_START +  8] = "kmalloc-random-09-" #sz,
>> +#define KMALLOC_RANDOM_10_NAME(sz) KMALLOC_RANDOM_9_NAME(sz)  .name[KMALLOC_RANDOM_START +  9] = "kmalloc-random-10-" #sz,
>> +#define KMALLOC_RANDOM_11_NAME(sz) KMALLOC_RANDOM_10_NAME(sz) .name[KMALLOC_RANDOM_START + 10] = "kmalloc-random-11-" #sz,
>> +#define KMALLOC_RANDOM_12_NAME(sz) KMALLOC_RANDOM_11_NAME(sz) .name[KMALLOC_RANDOM_START + 11] = "kmalloc-random-12-" #sz,
>> +#define KMALLOC_RANDOM_13_NAME(sz) KMALLOC_RANDOM_12_NAME(sz) .name[KMALLOC_RANDOM_START + 12] = "kmalloc-random-13-" #sz,
>> +#define KMALLOC_RANDOM_14_NAME(sz) KMALLOC_RANDOM_13_NAME(sz) .name[KMALLOC_RANDOM_START + 13] = "kmalloc-random-14-" #sz,
>> +#define KMALLOC_RANDOM_15_NAME(sz) KMALLOC_RANDOM_14_NAME(sz) .name[KMALLOC_RANDOM_START + 14] = "kmalloc-random-15-" #sz,
>> +#define KMALLOC_RANDOM_16_NAME(sz) KMALLOC_RANDOM_15_NAME(sz) .name[KMALLOC_RANDOM_START + 15] = "kmalloc-random-16-" #sz,
> 
> This all can be compressed. Only two things are variables here, so
> 
> #define KMALLOC_RANDOM_N_NAME(cur, prev, sz)	\
> 	KMALLOC_RANDOM_##prev##_NAME(sz),	\	
> 	.name[KMALLOC_RANDOM_START + prev] =	\
> 		"kmalloc-random-##cur##-" #sz
> 
> #define KMALLOC_RANDOM_16_NAME(sz) KMALLOC_RANDOM_N_NAME(16, 15, sz)
> 

I tried this way of implementation but it didn't work: it did not
propagate from 16 to 1, but stopped in the middle. I think it's because
the macro is somehow (indirectly) self-referential and the preprocessor
won't expand it. Check this for more info:

https://gcc.gnu.org/onlinedocs/cpp/Self-Referential-Macros.html

> Also I'd rather not put commas ',' at the end of each macro, they're
> usually put outside where the macro is used.

It seems here we have to put commas at the end. Not only it's to align
with how KMALLOC_{RCL,CGROUP,DMA}_NAME are implemented, but also
otherwise the expansion of INIT_KMALLOC_INFO would in some cases be like:

{
	.name[KMALLOC_NORMAL]  = "kmalloc-" #__short_size,
	, // an empty entry with a comma
}

which would cause compilation error in kmalloc_info[]'s initialization.

>> +#endif
>> +#else // CONFIG_RANDOM_KMALLOC_CACHES
>> +#define KMALLOC_RANDOM_NAME(N, sz)
>> +#endif
>> +
>>  #define INIT_KMALLOC_INFO(__size, __short_size)			\
>>  {								\
>>  	.name[KMALLOC_NORMAL]  = "kmalloc-" #__short_size,	\
>>  	KMALLOC_RCL_NAME(__short_size)				\
>>  	KMALLOC_CGROUP_NAME(__short_size)			\
>>  	KMALLOC_DMA_NAME(__short_size)				\
>> +	KMALLOC_RANDOM_NAME(CONFIG_RANDOM_KMALLOC_CACHES_NR, __short_size)	\
> 
> Can't those names be __initconst and here you'd just do one loop from 1
> to KMALLOC_CACHES_NR, which would assign names? I'm not sure compilers
> will expand that one to a compile-time constant and assigning 69
> different string pointers per one kmalloc size is a bit of a waste to me.

I'm not sure if I understand the question correctly, but I believe these
names have been __initconst since kmalloc_info[] is already marked with
it. Please let me know if it doesn't answer your question.

>>  	.size = __size,						\
>>  }
>>  
>> @@ -878,6 +916,11 @@ new_kmalloc_cache(int idx, enum kmalloc_cache_type type, slab_flags_t flags)
>>  		flags |= SLAB_CACHE_DMA;
>>  	}
>>  
>> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
>> +	if (type >= KMALLOC_RANDOM_START && type <= KMALLOC_RANDOM_END)
>> +		flags |= SLAB_RANDOMSLAB;
>> +#endif
>> +
>>  	kmalloc_caches[type][idx] = create_kmalloc_cache(
>>  					kmalloc_info[idx].name[type],
>>  					kmalloc_info[idx].size, flags, 0,
>> @@ -904,7 +947,7 @@ void __init create_kmalloc_caches(slab_flags_t flags)
>>  	/*
>>  	 * Including KMALLOC_CGROUP if CONFIG_MEMCG_KMEM defined
>>  	 */
>> -	for (type = KMALLOC_NORMAL; type < NR_KMALLOC_TYPES; type++) {
>> +	for (type = KMALLOC_RANDOM_START; type < NR_KMALLOC_TYPES; type++) {
> 
> Can't we just define something like __KMALLOC_TYPE_START at the
> beginning of the enum to not search for all such places each time
> something new is added?

Yeah I'm okay with this. Before I apply this change I would like to know
more opinions (especially from the maintainers) about it.

> 
>>  		for (i = KMALLOC_SHIFT_LOW; i <= KMALLOC_SHIFT_HIGH; i++) {
>>  			if (!kmalloc_caches[type][i])
>>  				new_kmalloc_cache(i, type, flags);
>> @@ -922,6 +965,9 @@ void __init create_kmalloc_caches(slab_flags_t flags)
>>  				new_kmalloc_cache(2, type, flags);
>>  		}
>>  	}
>> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
>> +	random_kmalloc_seed = get_random_u64();
>> +#endif
>>  
>>  	/* Kmalloc array is now usable */
>>  	slab_state = UP;
>> @@ -957,7 +1003,7 @@ void *__do_kmalloc_node(size_t size, gfp_t flags, int node, unsigned long caller
>>  		return ret;
>>  	}
>>  
>> -	s = kmalloc_slab(size, flags);
>> +	s = kmalloc_slab(size, flags, caller);
>>  
>>  	if (unlikely(ZERO_OR_NULL_PTR(s)))
>>  		return s;
> 
> Thanks,
> Olek

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fe79912f-3232-ffba-a191-477c80c703f4%40huawei.com.
