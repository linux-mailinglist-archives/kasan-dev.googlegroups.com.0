Return-Path: <kasan-dev+bncBCMIFTP47IJBBS45WPCQMGQE2ZWAMQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D3DDB34D27
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 22:59:57 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-70dcd8b49easf2527746d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 13:59:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756155596; cv=pass;
        d=google.com; s=arc-20240605;
        b=HXor0RLH9TPO6rKzktJhsQyLZEoK9kaY+pbRtybys4/stOA8rLTfme4bArYMFFXy9Y
         1NLEpszpsylL2mxphaxnH9FzJuZs+LIMYlceIAS24ICjoGBRraWEWXrsLUjcYWbw5cIl
         IV9tikslTVAu3LBau+slHZTUn5me95rQTsa2eKcoRAtjhFZl2HwrwAR+MiwEU21CfWZg
         6Q1N5gRF+BfD8LOsi/Hlvzij/bFdrR9OdcY/+rVhD+/hQOiqaKH8QbD3hbTpEGVlu8vB
         bWcR8KmIi0zDTBqOlMPhneXFKFnbRQIZFXCY+Rk4PMX1T2lu2DREiw4E8eivHlX3mtsY
         uOxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=CmV3iPqfmK35Kr0Kz+Qu3WKjFuh2EEnN1/C7I8aRhYQ=;
        fh=3RQJrHkoJK+nkdazb7dMDCgXFOei+0tvh007Ho3xQ6s=;
        b=AbxErF8stIiHfEEbPrIR7dBpi61/e9MOp4JOOSkAB6bWeneiO3+taYUdrOkB2qOAN8
         igE2fNlyR3wEh9vpoKlzcj9V2phxOJO/vGVKdSrJQzdn63WgZghWfknqXjPpgaSpeQlM
         iH7t1HuYWxe8aZBri1iifWT9W7KZTYrrBx7KYVosQgFN4DEV5Qbsvc6prph6F4iwl7hX
         Ia6q8Kc8vx4yTrxSZ2TcWB7uuUldrBRbTDD+6MOVzIVFwRV/NOlWbdoLvgjaKHxGE/45
         BXAF2Pgnh2GBvZ9uBBSGa2JB64LiiTrSxzTfJqtjb/BP/2lD45V6eHfLz8nYFnn/NJOd
         g1Jg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=XfMEvQi4;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::12b as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756155596; x=1756760396; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CmV3iPqfmK35Kr0Kz+Qu3WKjFuh2EEnN1/C7I8aRhYQ=;
        b=rRp2t3POO5M3E3aZCf2bV4lJmIGN8tj4edRsemd9ijb14lycfMT6qLBdEsVuoMxENC
         6bbuXDfszmeZwIgqkh6sJxrvpWxtFwgZBwrEoZm/cVONb9WFt1xstNL3vJTDRG5MKUE4
         2UNM9I61wD5I/YDHIECp0PqIA5iQEkT4ZQm6LglL3uGzDN6VBziPY+lUtXn/DPYWD5Wy
         5HvPuID2+ewr6fMvHt91DoK8Lh6hnuMJdbZD8xZXleDbG2a4dRj4ZmgblyVyXu1GKzwq
         0twQh0+Lrwt71MArCa2nkQTq2RaChY2YtKKttJmdodR5BdnsYvxeUGmQ26cm9Pz7RP+P
         ZxiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756155596; x=1756760396;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=CmV3iPqfmK35Kr0Kz+Qu3WKjFuh2EEnN1/C7I8aRhYQ=;
        b=geb7iK3SoaJMwW3Yg8J+Tf3QScQFlBm6xiqqlrHV2fBMiOivF3BGRha8AXMIoCW4i9
         WRmMlLgRgEntyCumIgoSKdeCaLd0VHN64qq4eV1DDrHdWeXtB0njLtn8Ub6MBH8992l9
         CovcKEWyMZudBAR2c4jbVEkc1KnEN++g+ia7k3OyVl9+viyq4Z4NpWjWc/bQH4PiRpX6
         fHMyvCkzRJSywhj80jUz/2B7IgLDo3nXmxIReGrBAZf4sWXKLOudslUWg1XIFpfWKovj
         uPuFgSEIHjutsYcngCzj+6suL2pfOS5ba+8c8HYVTrM+rSdNdXlNkGe+k0Hi5HbSsVld
         pj9w==
X-Forwarded-Encrypted: i=2; AJvYcCWyhSjCmP4YaHOuwsNGMQz+sS6V+EQhR+U2nKvfnd6ZUuty5I2HkWyTEDuO+uFulQVyQp0Svw==@lfdr.de
X-Gm-Message-State: AOJu0YyuSb7zYbjVwlwo1zEfeyXBpE3SgSbLvQAKohy5lsK/Y+X0sBnc
	DipdTQSBzSdZCm+LOFZYeCEd4WzO9a9wZ+9niQX/bBawebQUYLBZr/ln
X-Google-Smtp-Source: AGHT+IFjJMgngnt+6txTQdDr8swm2NGMvaKyd1zPhQEJ2C6mjTQ7AXuGFjgav0Kb6DZo+CtHxvPOig==
X-Received: by 2002:a05:6214:1d2e:b0:70d:bfbe:abf8 with SMTP id 6a1803df08f44-70dbfbedfffmr61611456d6.2.1756155595863;
        Mon, 25 Aug 2025 13:59:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdmDuamk0WkppWOER0xiWhjiAoebMlvjEb9Yo0YlvpTTA==
Received: by 2002:a05:6214:20c6:b0:70d:bc98:89ea with SMTP id
 6a1803df08f44-70dbc988ca8ls26367116d6.2.-pod-prod-09-us; Mon, 25 Aug 2025
 13:59:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVbvsrVltySdeiLXifvPW4eeb279vX1chPikrB1b8FxyNLE5Ktl6ixRafJCfosqhx7lsl0AP8cBsro=@googlegroups.com
X-Received: by 2002:a05:6214:29c2:b0:70d:6df4:1b23 with SMTP id 6a1803df08f44-70d97245950mr136526946d6.64.1756155594698;
        Mon, 25 Aug 2025 13:59:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756155594; cv=none;
        d=google.com; s=arc-20240605;
        b=AEqaXUoaCluzX5sM39TvuUFcWl+E9XhO8z5pziIxJXwHg4ojC8egxhJ+xiI3RTqu8P
         YeKtAIYJOqSa1HgfmYBGEE+XMYc6tMfQQQYn0WVMF0wZDeR6lUbdrLuw9KdefvmFGVC0
         itGqwMtN8bc2XaI47f5KkepkWU0HGPk6+ArgaWKpG+I5oLIPSwbz5v8f+Fv4W/85yuaS
         VrLi1NCLG01SC7vuDYHYCS4/wXAdZf+lHCgEsVPrxLkv1z4aR5w+SScu0XNloB/rfUX2
         fwstf+SkmyClTcXH2XNTDgApNTnrUD8jW9bjXqXE16U23JIreCCymhwu0OSLoO3GeWhQ
         Z9ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=ZcPPbu+aYl9Xu1jLxey4/WhZ40S4z542awI5r/G6Sno=;
        fh=c810C3PLDs8z4dABpoPBDNfCMdiyiaq8wwB/lU4vMoM=;
        b=btSJQPoCxYgqtYV/Iahp1ZNgjMQnyPO85F9nmgTLzrofLMhQzSnWGbv36wjWVzol3J
         E7X6yBCFiEhIvsl5dsl9cPuaixqA96nCpLex1pEtJvWyH2c3s703gTIL81e4QvgVrnmd
         cO25ByAnWXwl3qMohu5cR+fReW0QJg42ULBxJtdDzx00eDp5KJSNKfp9QX3eXIqUAE6U
         z5xIRNLHYjQ4uBSUqvsu5SMt3xQpQmq6wrpnUVgoJdHSUHMq/jIjC3sF9dr5QrIBM9zC
         3fospU/ZLDsY9icG4ypt4hFNBmCnYJcP5Wk3S8Vy4haJu0Gn6pE30q7Miv7HlaGs2tFd
         kQhw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=XfMEvQi4;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::12b as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-il1-x12b.google.com (mail-il1-x12b.google.com. [2607:f8b0:4864:20::12b])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70dc547bfe2si1149706d6.1.2025.08.25.13.59.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 25 Aug 2025 13:59:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::12b as permitted sender) client-ip=2607:f8b0:4864:20::12b;
Received: by mail-il1-x12b.google.com with SMTP id e9e14a558f8ab-3ecbe06f849so8327345ab.2
        for <kasan-dev@googlegroups.com>; Mon, 25 Aug 2025 13:59:54 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU4VMrvkfanaRIUTjjk6CAjbA0wcZTMh5kCXEVnyGvVs6Pu974em0QWmPs08qHgVI3ZczgDipH4Jmw=@googlegroups.com
X-Gm-Gg: ASbGncvbkyji18XuAy/pDmDs6bsdHWelQKneBYSgyT5J5O0nN+6uLoCAWxbBZYGvh5X
	IOyIXEcNmg0c2BCXxrPedZ1SPWRt2HPf8eBxYP0wyRRPsXZ2pnoLY4Pnb6vesAhWgYrVdCgMDxV
	jkbKptKN/gUcAuJueCrVqf3ylTFZd/FRCPBLyygwJNwWBdRobnxHrhJ7a8xxWDe6cSHcqkWGkL7
	5973OelOrC1jBaGSxJ3+wVyu5DJ9C7R+MyON4TC0KiZJ+PydOOvONv33tXz8wFx6paezfXeFirV
	G1bL+u78eOu5bhc3w2NvzD+4YDj7UoKzmedSKjE8OQK5ArjHjrPXI4/EB0MQcmCKIT2lxK3xobY
	FERdoqnKhearhM1eacNVxXdcNjyRL7ObENiUD22GO+Ho=
X-Received: by 2002:a92:cdad:0:b0:3e9:eec4:9b5a with SMTP id e9e14a558f8ab-3e9eec49d85mr152368845ab.25.1756155593789;
        Mon, 25 Aug 2025 13:59:53 -0700 (PDT)
Received: from [100.64.0.1] ([136.226.102.202])
        by smtp.gmail.com with ESMTPSA id e9e14a558f8ab-3ea4ec1fa3dsm54724275ab.45.2025.08.25.13.59.47
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 25 Aug 2025 13:59:53 -0700 (PDT)
Message-ID: <9ae927d3-0a66-4354-910f-155ff9ba3e0f@sifive.com>
Date: Mon, 25 Aug 2025 15:59:46 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 10/19] x86: LAM compatible non-canonical definition
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: x86@kernel.org, linux-doc@vger.kernel.org, linux-mm@kvack.org,
 llvm@lists.linux.dev, linux-kbuild@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, sohil.mehta@intel.com,
 baohua@kernel.org, david@redhat.com, kbingham@kernel.org,
 weixugc@google.com, Liam.Howlett@oracle.com, alexandre.chartre@oracle.com,
 kas@kernel.org, mark.rutland@arm.com, trintaeoitogc@gmail.com,
 axelrasmussen@google.com, yuanchu@google.com, joey.gouly@arm.com,
 samitolvanen@google.com, joel.granados@kernel.org, graf@amazon.com,
 vincenzo.frascino@arm.com, kees@kernel.org, ardb@kernel.org,
 thiago.bauermann@linaro.org, glider@google.com, thuth@redhat.com,
 kuan-ying.lee@canonical.com, pasha.tatashin@soleen.com,
 nick.desaulniers+lkml@gmail.com, vbabka@suse.cz, kaleshsingh@google.com,
 justinstitt@google.com, catalin.marinas@arm.com,
 alexander.shishkin@linux.intel.com, dave.hansen@linux.intel.com,
 corbet@lwn.net, xin@zytor.com, dvyukov@google.com, tglx@linutronix.de,
 scott@os.amperecomputing.com, jason.andryuk@amd.com, morbo@google.com,
 nathan@kernel.org, lorenzo.stoakes@oracle.com, mingo@redhat.com,
 brgerst@gmail.com, kristina.martsenko@arm.com, bigeasy@linutronix.de,
 luto@kernel.org, jgross@suse.com, jpoimboe@kernel.org, urezki@gmail.com,
 mhocko@suse.com, ada.coupriediaz@arm.com, hpa@zytor.com, leitao@debian.org,
 peterz@infradead.org, wangkefeng.wang@huawei.com, surenb@google.com,
 ziy@nvidia.com, smostafa@google.com, ryabinin.a.a@gmail.com,
 ubizjak@gmail.com, jbohac@suse.cz, broonie@kernel.org,
 akpm@linux-foundation.org, guoweikang.kernel@gmail.com, rppt@kernel.org,
 pcc@google.com, jan.kiszka@siemens.com, nicolas.schier@linux.dev,
 will@kernel.org, andreyknvl@gmail.com, jhubbard@nvidia.com, bp@alien8.de
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
 <c1902b7c161632681dac51bc04ab748853e616d0.1756151769.git.maciej.wieczor-retman@intel.com>
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: en-US
In-Reply-To: <c1902b7c161632681dac51bc04ab748853e616d0.1756151769.git.maciej.wieczor-retman@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=XfMEvQi4;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::12b as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

On 2025-08-25 3:24 PM, Maciej Wieczor-Retman wrote:
> For an address to be canonical it has to have its top bits equal to each
> other. The number of bits depends on the paging level and whether
> they're supposed to be ones or zeroes depends on whether the address
> points to kernel or user space.
> 
> With Linear Address Masking (LAM) enabled, the definition of linear
> address canonicality is modified. Not all of the previously required
> bits need to be equal, only the first and last from the previously equal
> bitmask. So for example a 5-level paging kernel address needs to have
> bits [63] and [56] set.
> 
> Add separate __canonical_address() implementation for
> CONFIG_KASAN_SW_TAGS since it's the only thing right now that enables
> LAM for kernel addresses (LAM_SUP bit in CR4).
> 
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v4:
> - Add patch to the series.
> 
>  arch/x86/include/asm/page.h | 10 ++++++++++
>  1 file changed, 10 insertions(+)
> 
> diff --git a/arch/x86/include/asm/page.h b/arch/x86/include/asm/page.h
> index bcf5cad3da36..a83f23a71f35 100644
> --- a/arch/x86/include/asm/page.h
> +++ b/arch/x86/include/asm/page.h
> @@ -82,10 +82,20 @@ static __always_inline void *pfn_to_kaddr(unsigned long pfn)
>  	return __va(pfn << PAGE_SHIFT);
>  }
>  
> +/*
> + * CONFIG_KASAN_SW_TAGS requires LAM which changes the canonicality checks.
> + */
> +#ifdef CONFIG_KASAN_SW_TAGS
> +static __always_inline u64 __canonical_address(u64 vaddr, u8 vaddr_bits)
> +{
> +	return (vaddr | BIT_ULL(63) | BIT_ULL(vaddr_bits - 1));
> +}
> +#else
>  static __always_inline u64 __canonical_address(u64 vaddr, u8 vaddr_bits)
>  {
>  	return ((s64)vaddr << (64 - vaddr_bits)) >> (64 - vaddr_bits);
>  }
> +#endif

These two implementations have different semantics. The new function works only
on kernel addresses, whereas the existing one works on user addresses as well.
It looks like at least KVM's use of __is_canonical_address() expects the
function to work with user addresses.

Regards,
Samuel

>  
>  static __always_inline u64 __is_canonical_address(u64 vaddr, u8 vaddr_bits)
>  {

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9ae927d3-0a66-4354-910f-155ff9ba3e0f%40sifive.com.
