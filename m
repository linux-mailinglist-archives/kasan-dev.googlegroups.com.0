Return-Path: <kasan-dev+bncBCMIFTP47IJBBBXXSO3QMGQENH5LH6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id C7FD9978CE4
	for <lists+kasan-dev@lfdr.de>; Sat, 14 Sep 2024 04:57:12 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-2052a68430fsf31358965ad.2
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 19:57:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726282631; cv=pass;
        d=google.com; s=arc-20240605;
        b=Q4afN7702YgFRR8zmKhQawMXDO2qTkZcv6NGIqbqew81m/k8MS0RgTRl3E251Lzo8g
         mO7u7ru4AghUXtLeA0Q9grIWCg3jhYXJrPz8/FuB8tOfSoHnaTkfZvv5zt/ygrPkuIQA
         JJ9UlFFv19cttgESqwJNPVbsNvGvYIKtqUCSK8M7QBifGW9uRx+K3LLU+E+KSYNmKyML
         eiinnK4Qc77u7bQltzmr2z4Klhcp7WSDkTtq6WisO1WmBNNKstPa9ZflSwzyAKD63eP1
         I+LWu+/ZUdSbjNp2ODylZy8DvqT2KGpWIFofdGdHGcxU/mtSyE4MYU6rJvB5c1Wad6zV
         2EFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=St4zJFmBlRjqdw5m7U6VijjBY2kCsk0QCsarZhqyWiA=;
        fh=9mKddfsmaVDgPBWvn13cTqedhzNBrrUSYMtibCnch4M=;
        b=Fs58q7236Vb7drttKtsmpIZW2wxCPFrFxjsRWzPCy0AuA0e4BXrtwWiI+chJeIMpVZ
         NAjemNlmS+qsUtWh/JUuaxbR+K1D9ngEuSzw7EgftuuPhAotZk05RuEvcPltoGJCw522
         CRYVMUq24oU3i6QV8LaMX9F4Z51wib1kSCAIvNNCcwu+RpFL8FQxzzR8IbYBHFQn6U+5
         9IvnCKaycRXxofa9FFavq1ZdURh9ZT3T0eRsZFmyvn2XYLx5ainIKUS9iFMwIIXkqHwC
         27zpMXxduL5yF3LDFIElZRmrZqpAnfV2BMzvQmj+ILGGUqZNhh7PyN9KUXHudSPx+j1b
         IFbQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=ehk5jPfb;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::d33 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726282631; x=1726887431; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=St4zJFmBlRjqdw5m7U6VijjBY2kCsk0QCsarZhqyWiA=;
        b=SZqR6mECGbS3Uif3qCcO9wGLiNjAfWVT1JyIn/ueDjzE9QvX4nIE5e5xd1XqX6aU/2
         uhAMeQ7Pp9YY9+OONGy8yd+mn/xX+FN9r2KHf9mWtBCV5Rreu5KSzQ8jE77vRPVFjcff
         xosgdoNEedSPraW/RIx1vBEHJ5iQJaTRPx7u14Dkd4TYdRGWgxa0zpMQpxzK9Vf/VWzB
         SmPeor3UK2n8AyuVQp0FC5vYoF9Z0NCQxddPo4QzULpP6FkeaPsvZiz1dL47n+/n4Xzc
         ANk1RPxjQfq0BvpsfiUoFKqTXvroXri1wwICECydEhpMSgKtNrKDR2oTcVrRUNgyzAvG
         6YaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726282631; x=1726887431;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=St4zJFmBlRjqdw5m7U6VijjBY2kCsk0QCsarZhqyWiA=;
        b=YqGqq7YkLITlGtAzz5uC2+e5gQQQQ840ghWw7bIcLp/IyvjJGZU7VjjOE6iu98LQXu
         Mqg23gCPHnNWbfzHTHG66Wtw2BiIHzkB1C1tyXjuKpeaq2sL7emO/7L1dwI5XIeDVVkp
         aFPgxowLQmZSJq/7j3UsBCPJ9Mw1eeEH4XjH4bTdkYKGrfS/pd2AjH+Y0iwr5UeK2UD2
         IOjHiOV4dLEN0lSkpECVD4vqRE3YQ0rjNx0ZFL0JHCrKmol7QUHGIhi6TF7Pzo1KS3zs
         5gju+CvJbxeoMIpGdnvemVqwRS52TJJ+49eBBuLMQKdBuqo3hWz42EB16NEpKh6SwOlT
         CORA==
X-Forwarded-Encrypted: i=2; AJvYcCWj4LZmsUc3Ja5tdjx6xX1s1ofadp6auhMKSsh0DKfxD5aTCgprwNm0oQAv+g5XUVgCCerwjw==@lfdr.de
X-Gm-Message-State: AOJu0YzyF5j0b+K2hWCZECQKY2JYA7TpVQ14YGd7Vh7KAyic7LX4CJvc
	Fv4XOMDH5PqjXK92nOdeh4s6/OCdkD9WIUAfQRNw7Cw/SrOmIvLa
X-Google-Smtp-Source: AGHT+IGfjMkGgxKhoAI2PAjmyJDHNUY4MPG1CZTyNlPT9VJ7ydi+jpU+10115MKtdkQD2pxBUasVYw==
X-Received: by 2002:a17:903:40c7:b0:205:48c0:de8f with SMTP id d9443c01a7336-2076e476875mr85316365ad.60.1726282631113;
        Fri, 13 Sep 2024 19:57:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:db01:b0:207:6ea:6f7f with SMTP id
 d9443c01a7336-2076c8ab562ls18705795ad.0.-pod-prod-01-us; Fri, 13 Sep 2024
 19:57:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXpX8Y3g3o+NqPBVyF/B/krRH680jaPOnaAfYrZ0SZIW3IQUV8wDihEZ5g9yaId3qeuag1/FHndI64=@googlegroups.com
X-Received: by 2002:a17:902:db0b:b0:207:14e9:eb22 with SMTP id d9443c01a7336-2076e31f93bmr110625525ad.6.1726282629812;
        Fri, 13 Sep 2024 19:57:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726282629; cv=none;
        d=google.com; s=arc-20240605;
        b=kc2WGrWNgqy9tLDZPJH8GZRHuJ42hkAYgfHY0tHkUbDeyGK6I+rDzQW1MEI2YLgKZv
         DZCQnbKWzhXGp2BxT5G9vaTeI3PDMsdH3mtZr72FDhpbccmcfeC+OvpXp/wuARYPsMbf
         boT2yOYbpiPAzSBvWTH6Edm4e+4W4uB0rTFOgY42b1Dtt3mRcYTG2JArGV0loOxKgJyV
         i8B6bg3NuqaqoIqqNw5+o3Stnj6Z1+9PRVK8f03s+Lgnfp+QdY+ou+thBk91isgT2Cky
         BsJI3b1A+wtHM0VHl/DutyENhmyjIrTNZm4Q8s+kCwKltInsXpCUgDT6fZROOhTh7Ihf
         0sCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=pb+QdAWP89TAukwJGu2QJVdRrPw/zDWAXPkcoFz3eXo=;
        fh=e1LMyPfp8XiQQ8dahvc5otA6VE3yXJrLKTW886vQw4s=;
        b=a66PUNU8rzI/XUwWshTO97mBxsOnCuFMU3IfGNJb5T4UbY9Ku9dGEkwovglVI5YubS
         RfvtwRMXTXsJzH7kRCRPFxx4VTUTGNOtjiG+QePaGBc+JqiHBys9sj9ojOpKBTMdxPfw
         5FNSB3VGwcLY+sNCjwb/siUKpH/z7q9fqiEoEkVkVYvz9kYyE4ReTNHNqW9t+9IhtCWF
         eRMaTQvmDttd4vxb1xoNvmRlmQ4lJWosjFHIjO2PaO1KHxSaA6vwq3fPHh3Y0m20cYtF
         4a+iiCmYPiprPt+dFBhPJ1Lo/h9Z/XxrWGaukvVz/G4LGWGWVYonW39eb6R0y6D9vQiz
         ZD2A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=ehk5jPfb;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::d33 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-io1-xd33.google.com (mail-io1-xd33.google.com. [2607:f8b0:4864:20::d33])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-207946c2c05si256585ad.10.2024.09.13.19.57.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Sep 2024 19:57:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::d33 as permitted sender) client-ip=2607:f8b0:4864:20::d33;
Received: by mail-io1-xd33.google.com with SMTP id ca18e2360f4ac-82d24e18dfcso94881139f.3
        for <kasan-dev@googlegroups.com>; Fri, 13 Sep 2024 19:57:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXcIJwx94q9ZBo5NiRO55TYRfgo2lZclaIZlJu/N03fRNUvh2o6MIS33RnZsJy4U+M8bgyIZ2Xukxs=@googlegroups.com
X-Received: by 2002:a05:6602:3414:b0:82c:ed57:ebea with SMTP id ca18e2360f4ac-82d1f95f09amr1096525739f.13.1726282628881;
        Fri, 13 Sep 2024 19:57:08 -0700 (PDT)
Received: from [100.64.0.1] ([147.124.94.167])
        by smtp.gmail.com with ESMTPSA id ca18e2360f4ac-82d4928ac38sm16179039f.17.2024.09.13.19.57.06
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Sep 2024 19:57:08 -0700 (PDT)
Message-ID: <b5b1b654-b603-4e22-ae9c-b712e4d6babe@sifive.com>
Date: Fri, 13 Sep 2024 21:57:05 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 05/10] riscv: Add support for the tagged address ABI
To: Charlie Jenkins <charlie@rivosinc.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org,
 devicetree@vger.kernel.org, Catalin Marinas <catalin.marinas@arm.com>,
 linux-kernel@vger.kernel.org, Anup Patel <anup@brainfault.org>,
 Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com,
 Atish Patra <atishp@atishpatra.org>, Evgenii Stepanov <eugenis@google.com>,
 Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
 Rob Herring <robh+dt@kernel.org>,
 "Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
 <20240829010151.2813377-6-samuel.holland@sifive.com> <ZuOnTvgMv2b/ki9e@ghost>
Content-Language: en-US
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <ZuOnTvgMv2b/ki9e@ghost>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=ehk5jPfb;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::d33 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

Hi Charlie,

On 2024-09-12 9:45 PM, Charlie Jenkins wrote:
> On Wed, Aug 28, 2024 at 06:01:27PM -0700, Samuel Holland wrote:
>> When pointer masking is enabled for userspace, the kernel can accept
>> tagged pointers as arguments to some system calls. Allow this by
>> untagging the pointers in access_ok() and the uaccess routines. The
>> uaccess routines must peform untagging in software because U-mode and
>> S-mode have entirely separate pointer masking configurations. In fact,
>> hardware may not even implement pointer masking for S-mode.
>>
>> Since the number of tag bits is variable, untagged_addr_remote() needs
>> to know what PMLEN to use for the remote mm. Therefore, the pointer
>> masking mode must be the same for all threads sharing an mm. Enforce
>> this with a lock flag in the mm context, as x86 does for LAM. The flag
>> gets reset in init_new_context() during fork(), as the new mm is no
>> longer multithreaded.
>>
>> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
>> ---
> 
> Not necessary, but what do you think about adding riscv to include/uapi/linux/prctl.h:
> 
> /* Tagged user address controls for arm64 */
> #define PR_SET_TAGGED_ADDR_CTRL		55
> #define PR_GET_TAGGED_ADDR_CTRL		56
> # define PR_TAGGED_ADDR_ENABLE		(1UL << 0)

Yes, I'll add this in v5.

> Also looks like this last line should probably be under SET rather than
> GET.

The same bit fields are used for both prctl() functions, so I think the current
grouping is okay (compare PR_RISCV_V_GET_CONTROL).

Regards,
Samuel

> Reviewed-by: Charlie Jenkins <charlie@rivosinc.com>
> Tested-by: Charlie Jenkins <charlie@rivosinc.com>
> 
>>
>> Changes in v4:
>>  - Combine __untagged_addr() and __untagged_addr_remote()
>>
>> Changes in v3:
>>  - Use IS_ENABLED instead of #ifdef when possible
>>  - Implement mm_untag_mask()
>>  - Remove pmlen from struct thread_info (now only in mm_context_t)
>>
>> Changes in v2:
>>  - Implement untagged_addr_remote()
>>  - Restrict PMLEN changes once a process is multithreaded
>>
>>  arch/riscv/include/asm/mmu.h         |  7 +++
>>  arch/riscv/include/asm/mmu_context.h | 13 +++++
>>  arch/riscv/include/asm/uaccess.h     | 43 ++++++++++++++--
>>  arch/riscv/kernel/process.c          | 73 ++++++++++++++++++++++++++--
>>  4 files changed, 126 insertions(+), 10 deletions(-)
>>
>> diff --git a/arch/riscv/include/asm/mmu.h b/arch/riscv/include/asm/mmu.h
>> index c9e03e9da3dc..1cc90465d75b 100644
>> --- a/arch/riscv/include/asm/mmu.h
>> +++ b/arch/riscv/include/asm/mmu.h
>> @@ -25,9 +25,16 @@ typedef struct {
>>  #ifdef CONFIG_BINFMT_ELF_FDPIC
>>  	unsigned long exec_fdpic_loadmap;
>>  	unsigned long interp_fdpic_loadmap;
>> +#endif
>> +	unsigned long flags;
>> +#ifdef CONFIG_RISCV_ISA_SUPM
>> +	u8 pmlen;
>>  #endif
>>  } mm_context_t;
>>  
>> +/* Lock the pointer masking mode because this mm is multithreaded */
>> +#define MM_CONTEXT_LOCK_PMLEN	0
>> +
>>  #define cntx2asid(cntx)		((cntx) & SATP_ASID_MASK)
>>  #define cntx2version(cntx)	((cntx) & ~SATP_ASID_MASK)
>>  
>> diff --git a/arch/riscv/include/asm/mmu_context.h b/arch/riscv/include/asm/mmu_context.h
>> index 7030837adc1a..8c4bc49a3a0f 100644
>> --- a/arch/riscv/include/asm/mmu_context.h
>> +++ b/arch/riscv/include/asm/mmu_context.h
>> @@ -20,6 +20,9 @@ void switch_mm(struct mm_struct *prev, struct mm_struct *next,
>>  static inline void activate_mm(struct mm_struct *prev,
>>  			       struct mm_struct *next)
>>  {
>> +#ifdef CONFIG_RISCV_ISA_SUPM
>> +	next->context.pmlen = 0;
>> +#endif
>>  	switch_mm(prev, next, NULL);
>>  }
>>  
>> @@ -30,11 +33,21 @@ static inline int init_new_context(struct task_struct *tsk,
>>  #ifdef CONFIG_MMU
>>  	atomic_long_set(&mm->context.id, 0);
>>  #endif
>> +	if (IS_ENABLED(CONFIG_RISCV_ISA_SUPM))
>> +		clear_bit(MM_CONTEXT_LOCK_PMLEN, &mm->context.flags);
>>  	return 0;
>>  }
>>  
>>  DECLARE_STATIC_KEY_FALSE(use_asid_allocator);
>>  
>> +#ifdef CONFIG_RISCV_ISA_SUPM
>> +#define mm_untag_mask mm_untag_mask
>> +static inline unsigned long mm_untag_mask(struct mm_struct *mm)
>> +{
>> +	return -1UL >> mm->context.pmlen;
>> +}
>> +#endif
>> +
>>  #include <asm-generic/mmu_context.h>
>>  
>>  #endif /* _ASM_RISCV_MMU_CONTEXT_H */
>> diff --git a/arch/riscv/include/asm/uaccess.h b/arch/riscv/include/asm/uaccess.h
>> index 72ec1d9bd3f3..fee56b0c8058 100644
>> --- a/arch/riscv/include/asm/uaccess.h
>> +++ b/arch/riscv/include/asm/uaccess.h
>> @@ -9,8 +9,41 @@
>>  #define _ASM_RISCV_UACCESS_H
>>  
>>  #include <asm/asm-extable.h>
>> +#include <asm/cpufeature.h>
>>  #include <asm/pgtable.h>		/* for TASK_SIZE */
>>  
>> +#ifdef CONFIG_RISCV_ISA_SUPM
>> +static inline unsigned long __untagged_addr_remote(struct mm_struct *mm, unsigned long addr)
>> +{
>> +	if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM)) {
>> +		u8 pmlen = mm->context.pmlen;
>> +
>> +		/* Virtual addresses are sign-extended; physical addresses are zero-extended. */
>> +		if (IS_ENABLED(CONFIG_MMU))
>> +			return (long)(addr << pmlen) >> pmlen;
>> +		else
>> +			return (addr << pmlen) >> pmlen;
>> +	}
>> +
>> +	return addr;
>> +}
>> +
>> +#define untagged_addr(addr) ({							\
>> +	unsigned long __addr = (__force unsigned long)(addr);			\
>> +	(__force __typeof__(addr))__untagged_addr_remote(current->mm, __addr);	\
>> +})
>> +
>> +#define untagged_addr_remote(mm, addr) ({					\
>> +	unsigned long __addr = (__force unsigned long)(addr);			\
>> +	mmap_assert_locked(mm);							\
>> +	(__force __typeof__(addr))__untagged_addr_remote(mm, __addr);		\
>> +})
>> +
>> +#define access_ok(addr, size) likely(__access_ok(untagged_addr(addr), size))
>> +#else
>> +#define untagged_addr(addr) (addr)
>> +#endif
>> +
>>  /*
>>   * User space memory access functions
>>   */
>> @@ -130,7 +163,7 @@ do {								\
>>   */
>>  #define __get_user(x, ptr)					\
>>  ({								\
>> -	const __typeof__(*(ptr)) __user *__gu_ptr = (ptr);	\
>> +	const __typeof__(*(ptr)) __user *__gu_ptr = untagged_addr(ptr); \
>>  	long __gu_err = 0;					\
>>  								\
>>  	__chk_user_ptr(__gu_ptr);				\
>> @@ -246,7 +279,7 @@ do {								\
>>   */
>>  #define __put_user(x, ptr)					\
>>  ({								\
>> -	__typeof__(*(ptr)) __user *__gu_ptr = (ptr);		\
>> +	__typeof__(*(ptr)) __user *__gu_ptr = untagged_addr(ptr); \
>>  	__typeof__(*__gu_ptr) __val = (x);			\
>>  	long __pu_err = 0;					\
>>  								\
>> @@ -293,13 +326,13 @@ unsigned long __must_check __asm_copy_from_user(void *to,
>>  static inline unsigned long
>>  raw_copy_from_user(void *to, const void __user *from, unsigned long n)
>>  {
>> -	return __asm_copy_from_user(to, from, n);
>> +	return __asm_copy_from_user(to, untagged_addr(from), n);
>>  }
>>  
>>  static inline unsigned long
>>  raw_copy_to_user(void __user *to, const void *from, unsigned long n)
>>  {
>> -	return __asm_copy_to_user(to, from, n);
>> +	return __asm_copy_to_user(untagged_addr(to), from, n);
>>  }
>>  
>>  extern long strncpy_from_user(char *dest, const char __user *src, long count);
>> @@ -314,7 +347,7 @@ unsigned long __must_check clear_user(void __user *to, unsigned long n)
>>  {
>>  	might_fault();
>>  	return access_ok(to, n) ?
>> -		__clear_user(to, n) : n;
>> +		__clear_user(untagged_addr(to), n) : n;
>>  }
>>  
>>  #define __get_kernel_nofault(dst, src, type, err_label)			\
>> diff --git a/arch/riscv/kernel/process.c b/arch/riscv/kernel/process.c
>> index f39221ab5ddd..6e9c84a41c29 100644
>> --- a/arch/riscv/kernel/process.c
>> +++ b/arch/riscv/kernel/process.c
>> @@ -204,6 +204,10 @@ int copy_thread(struct task_struct *p, const struct kernel_clone_args *args)
>>  	unsigned long tls = args->tls;
>>  	struct pt_regs *childregs = task_pt_regs(p);
>>  
>> +	/* Ensure all threads in this mm have the same pointer masking mode. */
>> +	if (IS_ENABLED(CONFIG_RISCV_ISA_SUPM) && p->mm && (clone_flags & CLONE_VM))
>> +		set_bit(MM_CONTEXT_LOCK_PMLEN, &p->mm->context.flags);
>> +
>>  	memset(&p->thread.s, 0, sizeof(p->thread.s));
>>  
>>  	/* p->thread holds context to be restored by __switch_to() */
>> @@ -249,10 +253,16 @@ enum {
>>  static bool have_user_pmlen_7;
>>  static bool have_user_pmlen_16;
>>  
>> +/*
>> + * Control the relaxed ABI allowing tagged user addresses into the kernel.
>> + */
>> +static unsigned int tagged_addr_disabled;
>> +
>>  long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg)
>>  {
>> -	unsigned long valid_mask = PR_PMLEN_MASK;
>> +	unsigned long valid_mask = PR_PMLEN_MASK | PR_TAGGED_ADDR_ENABLE;
>>  	struct thread_info *ti = task_thread_info(task);
>> +	struct mm_struct *mm = task->mm;
>>  	unsigned long pmm;
>>  	u8 pmlen;
>>  
>> @@ -267,16 +277,41 @@ long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg)
>>  	 * in case choosing a larger PMLEN has a performance impact.
>>  	 */
>>  	pmlen = FIELD_GET(PR_PMLEN_MASK, arg);
>> -	if (pmlen == PMLEN_0)
>> +	if (pmlen == PMLEN_0) {
>>  		pmm = ENVCFG_PMM_PMLEN_0;
>> -	else if (pmlen <= PMLEN_7 && have_user_pmlen_7)
>> +	} else if (pmlen <= PMLEN_7 && have_user_pmlen_7) {
>> +		pmlen = PMLEN_7;
>>  		pmm = ENVCFG_PMM_PMLEN_7;
>> -	else if (pmlen <= PMLEN_16 && have_user_pmlen_16)
>> +	} else if (pmlen <= PMLEN_16 && have_user_pmlen_16) {
>> +		pmlen = PMLEN_16;
>>  		pmm = ENVCFG_PMM_PMLEN_16;
>> -	else
>> +	} else {
>>  		return -EINVAL;
>> +	}
>> +
>> +	/*
>> +	 * Do not allow the enabling of the tagged address ABI if globally
>> +	 * disabled via sysctl abi.tagged_addr_disabled, if pointer masking
>> +	 * is disabled for userspace.
>> +	 */
>> +	if (arg & PR_TAGGED_ADDR_ENABLE && (tagged_addr_disabled || !pmlen))
>> +		return -EINVAL;
>> +
>> +	if (!(arg & PR_TAGGED_ADDR_ENABLE))
>> +		pmlen = PMLEN_0;
>> +
>> +	if (mmap_write_lock_killable(mm))
>> +		return -EINTR;
>> +
>> +	if (test_bit(MM_CONTEXT_LOCK_PMLEN, &mm->context.flags) && mm->context.pmlen != pmlen) {
>> +		mmap_write_unlock(mm);
>> +		return -EBUSY;
>> +	}
>>  
>>  	envcfg_update_bits(task, ENVCFG_PMM, pmm);
>> +	mm->context.pmlen = pmlen;
>> +
>> +	mmap_write_unlock(mm);
>>  
>>  	return 0;
>>  }
>> @@ -289,6 +324,10 @@ long get_tagged_addr_ctrl(struct task_struct *task)
>>  	if (is_compat_thread(ti))
>>  		return -EINVAL;
>>  
>> +	/*
>> +	 * The mm context's pmlen is set only when the tagged address ABI is
>> +	 * enabled, so the effective PMLEN must be extracted from envcfg.PMM.
>> +	 */
>>  	switch (task->thread.envcfg & ENVCFG_PMM) {
>>  	case ENVCFG_PMM_PMLEN_7:
>>  		ret = FIELD_PREP(PR_PMLEN_MASK, PMLEN_7);
>> @@ -298,6 +337,9 @@ long get_tagged_addr_ctrl(struct task_struct *task)
>>  		break;
>>  	}
>>  
>> +	if (task->mm->context.pmlen)
>> +		ret |= PR_TAGGED_ADDR_ENABLE;
>> +
>>  	return ret;
>>  }
>>  
>> @@ -307,6 +349,24 @@ static bool try_to_set_pmm(unsigned long value)
>>  	return (csr_read_clear(CSR_ENVCFG, ENVCFG_PMM) & ENVCFG_PMM) == value;
>>  }
>>  
>> +/*
>> + * Global sysctl to disable the tagged user addresses support. This control
>> + * only prevents the tagged address ABI enabling via prctl() and does not
>> + * disable it for tasks that already opted in to the relaxed ABI.
>> + */
>> +
>> +static struct ctl_table tagged_addr_sysctl_table[] = {
>> +	{
>> +		.procname	= "tagged_addr_disabled",
>> +		.mode		= 0644,
>> +		.data		= &tagged_addr_disabled,
>> +		.maxlen		= sizeof(int),
>> +		.proc_handler	= proc_dointvec_minmax,
>> +		.extra1		= SYSCTL_ZERO,
>> +		.extra2		= SYSCTL_ONE,
>> +	},
>> +};
>> +
>>  static int __init tagged_addr_init(void)
>>  {
>>  	if (!riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM))
>> @@ -320,6 +380,9 @@ static int __init tagged_addr_init(void)
>>  	have_user_pmlen_7 = try_to_set_pmm(ENVCFG_PMM_PMLEN_7);
>>  	have_user_pmlen_16 = try_to_set_pmm(ENVCFG_PMM_PMLEN_16);
>>  
>> +	if (!register_sysctl("abi", tagged_addr_sysctl_table))
>> +		return -EINVAL;
>> +
>>  	return 0;
>>  }
>>  core_initcall(tagged_addr_init);
>> -- 
>> 2.45.1
>>
>>
>> _______________________________________________
>> linux-riscv mailing list
>> linux-riscv@lists.infradead.org
>> http://lists.infradead.org/mailman/listinfo/linux-riscv

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b5b1b654-b603-4e22-ae9c-b712e4d6babe%40sifive.com.
