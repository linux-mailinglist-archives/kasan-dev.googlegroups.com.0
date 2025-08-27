Return-Path: <kasan-dev+bncBCMIFTP47IJBBXVKXHCQMGQEJ3BKITY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 93913B37633
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 02:46:24 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-76e2ead79fesf268649b3a.2
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 17:46:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756255583; cv=pass;
        d=google.com; s=arc-20240605;
        b=aElRDnHfhI9cNG84BE+xk0wzsHcESuenVexkfwgMaMLPRPvj4Nt/ZtNiRUA3U6o83w
         kPwwjG8EPV+z9HUF9w5nIXrvZnpoybVJKh7PZHeF2yPwrDEBchiyV8Dz76OS7HZ455MF
         ojH7/a8qNejQUrCy8khgYuNu6nURrFiltpzudTg54HuODBUZOrTEk7eNEIBbMkuWXPva
         HgpExL2PVg5sWJPB3eq38oFo59oqXCTsv1xMd0nsIAyxXUj4zpXMT+qMWRjiW0iHMLT9
         UIaws/GTwfbKamMtzb5dNPVMvE31oq4HNv+liMpVYDx0OFKWWdS8ZYQwcnVWuuhSqNdm
         x0Gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=19xBZT5d25oVXGjySQVN80HRCNHzMJhqGm/co31hO+8=;
        fh=V2417PIkSWdXSyCU8NQGcp8vxxMurx3zch8GvhkrSJA=;
        b=bgti/bIOstR6ntRABX80/MAw5xWkTSXbjDkQyim83PX2u7Okk35U51ybltn4f5q6hM
         D1L0pLHCizsfhWvyTJUFItBykRiwpNE1QQQqDlESPOYNR7p6aWEa7wt+U69Eoo3xPyKQ
         UHOKvVQ+0NIGtTQwfOtAj5Q+J5mE0zN6gbMbXFROoSl5HfFvJXRkh3YAPRmFa4lei5ub
         ETMPNJ0nUfZVYSQRmUt3m+PBB8UApEOfrIqZV3JSwFIkl/T2UfEn5rblX/h5weocmheC
         +8AhV2dZjrKCHlsf/2WyVPudWAJcmmE3OUrl9JfqIVWtWvjdJQD+QAXQDK8Pm0OyKpVr
         riAg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=LW4aBRlO;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::12d as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756255583; x=1756860383; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=19xBZT5d25oVXGjySQVN80HRCNHzMJhqGm/co31hO+8=;
        b=aEZijgPA7oSEYvuLVcrrvt3NvMVD7cO6ADk10loT6WZK6TaUp8ndumguNbME2Jz8ip
         ic/Jf0FsDeZj/pA8tDk3dThP/K2kFbxnDDF81Hvuf47EoScV79SXtGltbqU56VH4Vnmn
         r7DxM96tYviYbchQlqq6n+pwNtMsX6t95XWvTsfu9ZoIzcpt+XXeLfDxF4mG0A4Os/A3
         VlsTb1olNditihp+tydrzPG3DnUcm11b8o5dljODfaQaMQ+MrWHI8OZQW1FjOiMoHBiL
         0XQsO2SZrrAEdPqoTpxuPRBQ/8duC+evqiK65zozgenDb6nSAKSFq4FUpe3FbukYgX8w
         Vylw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756255583; x=1756860383;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=19xBZT5d25oVXGjySQVN80HRCNHzMJhqGm/co31hO+8=;
        b=kHn7XENOzMjwgWgJs6Iy1uYDNe3Nn8wEDSpj9K7QS6X5NM7eAV5hKwVPjIPkxk0edU
         EA4yJk5WuYu8XS6ScSqBzxpGs+jK/oX5Dk/dn6SqujJlrxp9GvgM/zzCK2lawBdb7Csr
         ngOmid1JCpCIihdnX10N58T88FuU3vdnt7P0T0ZBx9+TKxwpm22yDjYizByPPuQTHlkq
         2glD0WkCETV+Y3et9ES7yPGfhEHjuqFeU2ZCF8pho8mUE2/CF+oSVaClDfRbx9sHqrut
         rmDaxaXoYYvXbgv6MBtI55wL42VY9YBv0Jd3uZ/r7xIOAJrxPEWIOZijcYqDIKOMmcdc
         Hn9w==
X-Forwarded-Encrypted: i=2; AJvYcCUojo/y7wPK5FQwloJYnLGPKalpqdadw34jtS5K3HMFcfqRZfwwkjUvshFwK4xSh5x6JjRO7Q==@lfdr.de
X-Gm-Message-State: AOJu0YyiPDufZt8R3pjaKyHfMGW8qzNBu1+b8zcaulaNhtl7djvi7n7r
	xSKKTD7oWpdvxMTkVjHdJyNwmvZwJS9Ap7Pal09cCV1CqNlIwcXA9Vzx
X-Google-Smtp-Source: AGHT+IEGL0EEUSnJfxjVu6HuCM/Z5MgrlO1qxZkI/vcgL5umJKuxHDG0uYdAhe6HQPK8Tr53iNl8EQ==
X-Received: by 2002:a05:6a00:13a6:b0:771:e3d7:431e with SMTP id d2e1a72fcca58-771e3d75581mr5514425b3a.6.1756255582822;
        Tue, 26 Aug 2025 17:46:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcbmItbYftuXh5c96tE78kpCgApNrGdtQDgjxe8FEdxBg==
Received: by 2002:a05:6a00:4507:b0:730:8472:3054 with SMTP id
 d2e1a72fcca58-771e1a96653ls2129870b3a.1.-pod-prod-03-us; Tue, 26 Aug 2025
 17:46:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVhVYlS8qs9VDMhH9hHJ5b7fxU4+h67eoiLVrjHctj7ajBDdlkf7wIKPzqXgbtIS7M278xZS/q/YKU=@googlegroups.com
X-Received: by 2002:a05:6a00:2d90:b0:772:3c9:ce3e with SMTP id d2e1a72fcca58-77203c9d114mr2403053b3a.7.1756255581140;
        Tue, 26 Aug 2025 17:46:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756255581; cv=none;
        d=google.com; s=arc-20240605;
        b=fAvtTGdyaUVg9HgsQHb1XHlQUjDexu4k5cIJcnVWL42uJn7aHY/DxLqxN9Nr26vcbT
         9qtWgackaroDhRdA9MAdsDB0jKPozQvhQyMfhXA3pKjDVNHXzFdxIc6z0j9D4zsyl9DL
         xGxOreMEkh9nwhsXIc3cm1lKqGaN+ySPcWFTXrB8d0s7RNPRS9IkGmqM0Q2DoX+UqFwY
         0BZLjShR8/pCMIUdgR+20z/xbo3z3iZEeNmMd7Cl9ttR5UdqrEiqYjz/65n4HJJRfUL+
         ZkNFUb3vKzt5aXA+iZAltVrhORE8NsuRX40bhyrGzlN/EoKBQMgx6NL1R9kb1KhnefQx
         aqOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=zclw1iBD4zpqjkUTKL/tBf6jKpfLRB4Ld2/pw8/YSMc=;
        fh=E/Iwxqb4M1AxEkdAEnhY1PQ0nHfw5bc+IySn+T7qKuY=;
        b=KOY9ZZOE2bRIIPs91mr2xO9T2+UwfFt3PX2cN/T6O78sZDCWhwUSNGlz+Mt4rG5XzI
         Kwn1Oa7GbDEn/bROG0ztSVL9FrKNuNQ0J/fLvMT8BN/LQmTX4P37ZYTSrAmc5roIJxFV
         HjwmuDYimNP5JL66WdMRM/lQ8YwZY453tNJRcId0AjYfc85Vzj5H4RARkgBLeOcZogiz
         T24MvI5+/QJ3mCjYf1BJgcH2QF9+VDeWdWbWEVGBe6lVbB/LBvqiS3V4R1odHrMGi8C+
         DKYD8EcFuHdc5eWHTHp4Pe2ison2hKrLIr1xM2Ybfqhjm0fNhTT4ZgU92TlFpoNxrtxo
         T55A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=LW4aBRlO;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::12d as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-il1-x12d.google.com (mail-il1-x12d.google.com. [2607:f8b0:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-77046a189f4si242362b3a.4.2025.08.26.17.46.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Aug 2025 17:46:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::12d as permitted sender) client-ip=2607:f8b0:4864:20::12d;
Received: by mail-il1-x12d.google.com with SMTP id e9e14a558f8ab-3ef6866cd99so4464105ab.3
        for <kasan-dev@googlegroups.com>; Tue, 26 Aug 2025 17:46:21 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXZztSM6CxajIdxEct1s+V8qoJVwuM/R++/FoeJsRtJ/oFL5A1cXzkPfAKf6GjpGVSG1buk9RSqB8A=@googlegroups.com
X-Gm-Gg: ASbGncuRgSxOYvI4Y/vJbHuEsjps9ZZloXhNZAAoI+dpUomGIFnxYA23l8Rh7aaCBrr
	o22jl60S9fgg3WXhcNp9XOe1L04Q9gNkD5Pck9AOIV/si3J6t8tDSS8KCDXlXoVKnkOcDoo4+wa
	MWV9UcJvvEBn/EZYN1edjj/jm0tgA6yRoqfE7TMrDsTDHUdXUCODsacIzNiR0RDemluYAQ7TSyK
	MisxpeL0qhBim0WQ1IPxObAumumicw0Gy3QE6+O7ZQBNzR5rC/pg/T/K1W7Pbrbk2z+NeyFNgXA
	TUDDWaC7vFcb/yikN8Td6fglXxPKBygpnj8rwesAS8CYAQSc7HQiRkej0mTP73T9yPll0MPpvmu
	QGwzSl5GB7PHXwie7PI0i1MH+pjtWxMUnEtrWBQ==
X-Received: by 2002:a05:6e02:1b0c:b0:3ef:1b56:c8ea with SMTP id e9e14a558f8ab-3ef1b56c9f9mr43866025ab.11.1756255580619;
        Tue, 26 Aug 2025 17:46:20 -0700 (PDT)
Received: from [100.64.0.1] ([170.85.11.2])
        by smtp.gmail.com with ESMTPSA id e9e14a558f8ab-3ef2ff2dd60sm14606295ab.9.2025.08.26.17.46.19
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Aug 2025 17:46:20 -0700 (PDT)
Message-ID: <2e9ee035-9a1d-4a7b-b380-6ea1985eb7be@sifive.com>
Date: Tue, 26 Aug 2025 19:46:19 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 10/19] x86: LAM compatible non-canonical definition
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>,
 Dave Hansen <dave.hansen@intel.com>
Cc: x86@kernel.org, linux-doc@vger.kernel.org, linux-mm@kvack.org,
 llvm@lists.linux.dev, linux-kbuild@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
 <c1902b7c161632681dac51bc04ab748853e616d0.1756151769.git.maciej.wieczor-retman@intel.com>
 <c68330de-c076-45be-beac-147286f2b628@intel.com>
 <4rkxgsa5zfrvjqtii7cxocdk6g2qel3hif4hcpeboos2exndoe@hp7bok5o2inx>
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: en-US
In-Reply-To: <4rkxgsa5zfrvjqtii7cxocdk6g2qel3hif4hcpeboos2exndoe@hp7bok5o2inx>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=LW4aBRlO;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::12d as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Samuel Holland <samuel.holland@sifive.com>
Reply-To: Samuel Holland <samuel.holland@sifive.com>
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

Hi Maciej,

On 2025-08-26 3:08 AM, Maciej Wieczor-Retman wrote:
> On 2025-08-25 at 14:36:35 -0700, Dave Hansen wrote:
>> On 8/25/25 13:24, Maciej Wieczor-Retman wrote:
>>> +/*
>>> + * CONFIG_KASAN_SW_TAGS requires LAM which changes the canonicality checks.
>>> + */
>>> +#ifdef CONFIG_KASAN_SW_TAGS
>>> +static __always_inline u64 __canonical_address(u64 vaddr, u8 vaddr_bits)
>>> +{
>>> +	return (vaddr | BIT_ULL(63) | BIT_ULL(vaddr_bits - 1));
>>> +}
>>> +#else
>>>  static __always_inline u64 __canonical_address(u64 vaddr, u8 vaddr_bits)
>>>  {
>>>  	return ((s64)vaddr << (64 - vaddr_bits)) >> (64 - vaddr_bits);
>>>  }
>>> +#endif
>>
>> This is the kind of thing that's bound to break. Could we distill it
>> down to something simpler, perhaps?
>>
>> In the end, the canonical enforcement mask is the thing that's changing.
>> So perhaps it should be all common code except for the mask definition:
>>
>> #ifdef CONFIG_KASAN_SW_TAGS
>> #define CANONICAL_MASK(vaddr_bits) (BIT_ULL(63) | BIT_ULL(vaddr_bits-1))
>> #else
>> #define CANONICAL_MASK(vaddr_bits) GENMASK_UL(63, vaddr_bits)
>> #endif
>>
>> (modulo off-by-one bugs ;)
>>
>> Then the canonical check itself becomes something like:
>>
>> 	unsigned long cmask = CANONICAL_MASK(vaddr_bits);
>> 	return (vaddr & mask) == mask;
>>
>> That, to me, is the most straightforward way to do it.
> 
> Thanks, I'll try something like this. I will also have to investigate what
> Samuel brought up that KVM possibly wants to pass user addresses to this
> function as well.
> 
>>
>> I don't see it addressed in the cover letter, but what happens when a
>> CONFIG_KASAN_SW_TAGS=y kernel is booted on non-LAM hardware?
> 
> That's a good point, I need to add it to the cover letter. On non-LAM hardware
> the kernel just doesn't boot. Disabling KASAN in runtime on unsupported hardware
> isn't that difficult in outline mode, but I'm not sure it can work in inline
> mode (where checks into shadow memory are just pasted into code by the
> compiler).

On RISC-V at least, I was able to run inline mode with missing hardware support.
The shadow memory is still allocated, so the inline tag checks do not fault. And
with a patch to make kasan_enabled() return false[1], all pointers remain
canonical (they match the MatchAllTag), so the inline tag checks all succeed.

[1]:
https://lore.kernel.org/linux-riscv/20241022015913.3524425-3-samuel.holland@sifive.com/

Regards,
Samuel

> Since for now there is no compiler support for the inline mode anyway, I'll try to
> disable KASAN on non-LAM hardware in runtime.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2e9ee035-9a1d-4a7b-b380-6ea1985eb7be%40sifive.com.
