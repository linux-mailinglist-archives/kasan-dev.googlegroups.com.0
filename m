Return-Path: <kasan-dev+bncBCMIFTP47IJBB37ZX64AMGQEVABNLCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 648EC9A10EF
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 19:50:41 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-286fa354e34sf46452fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 10:50:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729101040; cv=pass;
        d=google.com; s=arc-20240605;
        b=iTGkl86SPJsvpdK/6jJlT0UCd1w+5L0PvRfLCJDB6N2dXbjtYMfAPxhhXiCV7mXBEa
         oN65ZQ9keGUOZNv/lVud+TzWu1MciFOoOp50wuL/so3e58lfEtvozrM7bAidWDyOTGEE
         aSN2uCDTkGytysjgsHhTJYA/msVx+p/1RZAoW0P3tg1A+jqe8OojXAD6L/9GMXKl2S5q
         QhnSoZDHT/EruVExeRE2fCe7HQj3zOdxpaTYwWGapXCyhsTKfOKdv4gvIDHqOjj+1J0I
         LJlxdYqY5XduD30P1B03rjA0Q/iP+jkTUlL0RonjtQ9BZ8OI9pDutoMSBrB2Ljhn6CuV
         r82Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=0Oiy0lmE0nnoay/rA02LIcXKAl/SUuVZHGGncY45eGo=;
        fh=IHPPjD31lI6kEcRDcVoEMfXjme5wbgI3y5teYfR8B1k=;
        b=cfYkADy8uB+5SZsVI6qhOummRpqoFZZ0HEpEOtb7XOrEydKgmDxgS7737/B/EPdxY1
         c6FykAUmU32qLOsUBRQ+d1x+m+PkddH2cNkMqxX76aRj3Ggp4TBI+RCiWCpvSBl2gw2m
         ZAAyITpbieVoaVrvkAbY1oua/lcM/4rNjuwCb0XJHVP3vIKJzM9tQUuasSwvyaryqRxq
         krtHfxVB2gZq/0LuiE+X1lynWUeT1hi26UCekykE70QnynOrxBCZ4+V0Qq46qS5dsioz
         Vmpue9+EpBjuQhoPGexEfLu3BW5FDRsffxnD3xdhU9RbkAK9gzCPz44DA66lX2Dllot4
         irhg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=mLE84pIE;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::c43 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729101040; x=1729705840; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0Oiy0lmE0nnoay/rA02LIcXKAl/SUuVZHGGncY45eGo=;
        b=mB464znDwMLCi9qJxo/lUA2ViTMl7bx5U7K2UiRBLa7JdrjWUeIBr7eRrqCw3X3+sW
         OR/xNdAs+x8zB4OCu699cuMKWKqOjv98qi/aCROSU+/t9NqthsgKGArlXm2S0eF4KPJD
         P9pDrG0uIeCvdwUZ2Pleboos1qVGYc4zQo17g7NHB3rCS26bRYPCyblmapatlZqXgeAG
         CRDRaILCQxTy6WADczFHQYxvuuVpWqd5zV2y6mFAUPtuw/n2BNfT5Q0cmLuHJJbM48ce
         ui2mC97VuuPHLRiCyxk92dtz/KCuky2rjgINtsg9yHykiCXBneePErOK1IqaWlYGuIi1
         l/sA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729101040; x=1729705840;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=0Oiy0lmE0nnoay/rA02LIcXKAl/SUuVZHGGncY45eGo=;
        b=YRLGdLbewRus0ZkBGX1quR+R7ryTK7tc8im4+vH4h6j+urQvMdXddleLab0qF3m45L
         ReguxFekCgaFz7L0U7kD84hLBaUMV3auO+Ke5/DzKmSBIf6cQBmylW6i9karxNjb5Mi1
         2aSwgdLDezRqj+Sn+4n9OF4aET/dLMmq3T0rbM/7XElW91DxYQUqy/PxYpWZ8x3aEYWw
         M4lqR8XkeTZ6dtZFpdNISV68E84E9PjE2y3OSSgAAhtB91U0cwkkyj7KNvomb+eziMqU
         xJKkCORuNH+bmTPwV2yPj46vU8vm430UBhYPLQgvKoWvrLcX1JZj16m/9z2JqZDKWreb
         wJMA==
X-Forwarded-Encrypted: i=2; AJvYcCVf5pXjQwarxLrIlVPlAV0/o4rXJTOxeEh6Bq7/OmcTgup5+ti59DX3YETYKKNFlRKAz+URMA==@lfdr.de
X-Gm-Message-State: AOJu0YwYXCPuhGj/1TX5Dx2jBf6nlqZme8DZzwRodg/JNNMtxNBJq+1n
	odDwLii9ogT4+D/Ey8esGU+GXRVHJbHP9as9m5KYMstGddxpW6EP
X-Google-Smtp-Source: AGHT+IEFl90Ae9JTseHCcNkNjYDH0VyElis2m09qqrEYd5DoGz/bJOwWkcx7D5qOwLKH5FAVG4V8SA==
X-Received: by 2002:a05:6870:d10f:b0:27b:5890:bd38 with SMTP id 586e51a60fabf-2886dd50b6fmr14392119fac.7.1729101039412;
        Wed, 16 Oct 2024 10:50:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:9f15:b0:288:93de:9ec9 with SMTP id
 586e51a60fabf-2890ccfe813ls121649fac.2.-pod-prod-03-us; Wed, 16 Oct 2024
 10:50:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXVFna/xGPG3UQ8+GYKdJubaFPCIsZG3/M3m+7aNtmgcAKrmHY/A8vqCXXXL8/HDNHXINNnfvnFGfo=@googlegroups.com
X-Received: by 2002:a05:6358:2486:b0:1c2:f4e9:6789 with SMTP id e5c5f4694b2df-1c32bd0bd81mr1245170855d.27.1729101038216;
        Wed, 16 Oct 2024 10:50:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729101038; cv=none;
        d=google.com; s=arc-20240605;
        b=OatShmRXTqnU/pi4HoYe4/1qHcond1JlYIKGzkWi6gjGDrZz8z53ssmnGHcAi5pzWv
         m4NpZeAkr3jCrC72crYkq4tHr35Ed7GsmJ4r1K9LQfaTUtGINhqN8pDP81otV8sO4wKE
         6Ity5oMftadDvfdeVcDO1oU48/wKSwsdDOjh2A7a+Y0QMbNJLM6rbzQou8ByhoNi3X+7
         Knc/Yv7VRaTJUtuJZ9/x5kr3oXTEkADeS7UG9Cwbct9pWCPrOd5YKYlRPz1Djs9ZGyUA
         KHBEiGxn0UnDP6qlOv/d9bMHto7bk5KAVC7mNegj4MpHTvSQvDFxNosvS5bTS46Knrxz
         EIRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=lCcgXYhcr1eYAzXAtgbojySY9FznxIOauj/4HQBvgNM=;
        fh=go60R332LJFp9pfKD//d6MxfxJUpgLIsTp2PIxgZZEo=;
        b=Hhuf0bDKtFoAef6rsf+U+P8pvWrc91ZW+FYzRirYRVovl7cRISdsHbwlzoJMPfZRQq
         Il6Dbl1L/Ce7Rb0nVPmu1pwp+C3as9zu9Rc8D/o089QW9ajuUXbUL/xTT806RlvcB+ru
         qaY6bheIjB8ITxNinclhkcb4WTFsdEHPYWJRlZAl7rKhL9NpHsNywD8pb2cJsadavt3C
         89rkBS+GULsDkW2zLu76OZG/AjruV1xuh0KJGYhpYdTE7YDUyFeyS3vovA6j+2wWMYNF
         zQepcBo4FdciYoHo/pFj7wb5ruvrp1uWmaepNWmPpMxcN9QGd/F838ZBl1CDG+6hu8py
         Crxw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=mLE84pIE;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::c43 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-oo1-xc43.google.com (mail-oo1-xc43.google.com. [2607:f8b0:4864:20::c43])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7ea9c7a6e76si192444a12.5.2024.10.16.10.50.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2024 10:50:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::c43 as permitted sender) client-ip=2607:f8b0:4864:20::c43;
Received: by mail-oo1-xc43.google.com with SMTP id 006d021491bc7-5e98bfea0ceso91672eaf.0
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2024 10:50:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWG8H4Ixmcq8LO2HecB7ghgAmjOUtLh1GqFx9SBocWwPeVZ2Qysay2FfYGrlsk+HQGkPyV051dGKYQ=@googlegroups.com
X-Received: by 2002:a05:6820:2212:b0:5e7:cb2e:e01c with SMTP id 006d021491bc7-5eb1a2da0f0mr11488027eaf.7.1729101036963;
        Wed, 16 Oct 2024 10:50:36 -0700 (PDT)
Received: from [100.64.0.1] ([147.124.94.167])
        by smtp.gmail.com with ESMTPSA id 006d021491bc7-5eb4edbcf06sm802586eaf.2.2024.10.16.10.50.33
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2024 10:50:36 -0700 (PDT)
Message-ID: <2e25597c-6278-4bc6-a0c2-3826841c2ac0@sifive.com>
Date: Wed, 16 Oct 2024 12:50:32 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 06/10] riscv: Allow ptrace control of the tagged
 address ABI
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
 <20240829010151.2813377-7-samuel.holland@sifive.com> <ZuOoqTfKs/7G075O@ghost>
Content-Language: en-US
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <ZuOoqTfKs/7G075O@ghost>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=mLE84pIE;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::c43 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

On 2024-09-12 9:51 PM, Charlie Jenkins wrote:
> On Wed, Aug 28, 2024 at 06:01:28PM -0700, Samuel Holland wrote:
>> This allows a tracer to control the ABI of the tracee, as on arm64.
>>
>> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
>> ---
> 
> Since this code is identical to the arm64 port, could it be extracted
> out into the generic ptrace.c and ifdef on either CONFIG_RISCV_ISA_SUPM
> or CONFIG_ARM64_TAGGED_ADDR_ABI by adding some generic flag like
> CONFIG_HAVE_ARCH_TAGGED_ADDR_ABI?

Yes, it could be factored out, though I don't know if it is worth the overhead
for these two trivial functions. I don't see any other code like this outside of
arch/.

Regards,
Samuel

>>
>> (no changes since v1)
>>
>>  arch/riscv/kernel/ptrace.c | 42 ++++++++++++++++++++++++++++++++++++++
>>  include/uapi/linux/elf.h   |  1 +
>>  2 files changed, 43 insertions(+)
>>
>> diff --git a/arch/riscv/kernel/ptrace.c b/arch/riscv/kernel/ptrace.c
>> index 92731ff8c79a..ea67e9fb7a58 100644
>> --- a/arch/riscv/kernel/ptrace.c
>> +++ b/arch/riscv/kernel/ptrace.c
>> @@ -28,6 +28,9 @@ enum riscv_regset {
>>  #ifdef CONFIG_RISCV_ISA_V
>>  	REGSET_V,
>>  #endif
>> +#ifdef CONFIG_RISCV_ISA_SUPM
>> +	REGSET_TAGGED_ADDR_CTRL,
>> +#endif
>>  };
>>  
>>  static int riscv_gpr_get(struct task_struct *target,
>> @@ -152,6 +155,35 @@ static int riscv_vr_set(struct task_struct *target,
>>  }
>>  #endif
>>  
>> +#ifdef CONFIG_RISCV_ISA_SUPM
>> +static int tagged_addr_ctrl_get(struct task_struct *target,
>> +				const struct user_regset *regset,
>> +				struct membuf to)
>> +{
>> +	long ctrl = get_tagged_addr_ctrl(target);
>> +
>> +	if (IS_ERR_VALUE(ctrl))
>> +		return ctrl;
>> +
>> +	return membuf_write(&to, &ctrl, sizeof(ctrl));
>> +}
>> +
>> +static int tagged_addr_ctrl_set(struct task_struct *target,
>> +				const struct user_regset *regset,
>> +				unsigned int pos, unsigned int count,
>> +				const void *kbuf, const void __user *ubuf)
>> +{
>> +	int ret;
>> +	long ctrl;
>> +
>> +	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &ctrl, 0, -1);
>> +	if (ret)
>> +		return ret;
>> +
>> +	return set_tagged_addr_ctrl(target, ctrl);
>> +}
>> +#endif
>> +
>>  static const struct user_regset riscv_user_regset[] = {
>>  	[REGSET_X] = {
>>  		.core_note_type = NT_PRSTATUS,
>> @@ -182,6 +214,16 @@ static const struct user_regset riscv_user_regset[] = {
>>  		.set = riscv_vr_set,
>>  	},
>>  #endif
>> +#ifdef CONFIG_RISCV_ISA_SUPM
>> +	[REGSET_TAGGED_ADDR_CTRL] = {
>> +		.core_note_type = NT_RISCV_TAGGED_ADDR_CTRL,
>> +		.n = 1,
>> +		.size = sizeof(long),
>> +		.align = sizeof(long),
>> +		.regset_get = tagged_addr_ctrl_get,
>> +		.set = tagged_addr_ctrl_set,
>> +	},
>> +#endif
>>  };
>>  
>>  static const struct user_regset_view riscv_user_native_view = {
>> diff --git a/include/uapi/linux/elf.h b/include/uapi/linux/elf.h
>> index b54b313bcf07..9a32532d7264 100644
>> --- a/include/uapi/linux/elf.h
>> +++ b/include/uapi/linux/elf.h
>> @@ -448,6 +448,7 @@ typedef struct elf64_shdr {
>>  #define NT_MIPS_MSA	0x802		/* MIPS SIMD registers */
>>  #define NT_RISCV_CSR	0x900		/* RISC-V Control and Status Registers */
>>  #define NT_RISCV_VECTOR	0x901		/* RISC-V vector registers */
>> +#define NT_RISCV_TAGGED_ADDR_CTRL 0x902	/* RISC-V tagged address control (prctl()) */
>>  #define NT_LOONGARCH_CPUCFG	0xa00	/* LoongArch CPU config registers */
>>  #define NT_LOONGARCH_CSR	0xa01	/* LoongArch control and status registers */
>>  #define NT_LOONGARCH_LSX	0xa02	/* LoongArch Loongson SIMD Extension registers */
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2e25597c-6278-4bc6-a0c2-3826841c2ac0%40sifive.com.
