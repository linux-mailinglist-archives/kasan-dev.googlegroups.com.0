Return-Path: <kasan-dev+bncBDHJX64K2UNBBLWRR23QMGQEC733DIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 34C78977713
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 04:51:28 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-6c528f34ca1sf10135506d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Sep 2024 19:51:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726195886; cv=pass;
        d=google.com; s=arc-20240605;
        b=XUsiRqGv0jfb6zHSgsRBzDqzoUqzTBjAhoTmpLg1hxTCE92dS0ZvFCMCIbalgt5HhO
         aj9iF5g7PTvPMpkcC1GNh4Egl6iFQf3/PMu+Z7bhAMjdKkiEnapYDgwnO0GItLbA1aEc
         LJs54HNpPGZtJguHqLTAW/aHPqTvTJrbFzILV8j+b7uHvaV4PHPhv0MpSkFCSAF124XG
         hwcS+cj+BNbZPqw4tWGOf3SzX5/u/U4UPkvWQ8AHqcXd661P9sskhSf+6v7tFxCH2KyD
         vndyJ7vinM1mKrCNeebAHEoWhQWU7bfvEW+IK3SBJT6E4VzIXjTaRPfzCpp6GBzbMs2Q
         asTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=aWurfZsf8FUm4rnFUsKHlwVC7sIDKxHd6Er87Ko5vgk=;
        fh=30QPWxlH+Kh3oTzS/RUjj2DkpD0UJYzB132qOnEOhVU=;
        b=Sttz2aT/Ru/rHdxScPA2WEDxex8q0FAJIdBCfm+qr4Qmf0R7Cxh1NuVyF6kXyZd3Sk
         2/Jo2DbMQ8LslEP/pNjn+0NRyfusFJVrnaum7B9Qvore5ph5cOJRa16UbTGjDQ0b4Gm7
         HX91heldFdkEAi26JvoYlzS3hLb/IgoFPYe6TOKEtn3jvIF4VrqUDFdfbYLOtSejVtgM
         fEgdCTaLFrYpZrCLDl8Mw6Y3koUEGSsFLZmenXocnEAcfzm0ExynllMxX4W896cO+imK
         P8QuLmD7KhSjgbc001xjm3L4yo7Pm20WHQfXCufs7t2ZhLeIlWYT/LAFO3zbOSOeP256
         ARVw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=Qp9rEqqo;
       spf=pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726195886; x=1726800686; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=aWurfZsf8FUm4rnFUsKHlwVC7sIDKxHd6Er87Ko5vgk=;
        b=PXUhSMiW2QZzzlY+/EZRYFsFwwffcdMTYRLASZlAuyb3LSAdcj7WN6QdaYhpc4tuLB
         7tIcQ9gA8SHMQVPruVpZ/3Uy/awkgJg8eQbk5JqTIvFPkH8vrskfl9sDSPqeVzJiL3Rs
         Tr6prowT0ToKUgV4TPpIz3PJT4voS3H/SSFvsrLhPD+mjCnkNc6m0+TsNRs3AYMdTvMM
         PClLSjeHnIQTnnTGHqporAd0FL45EX3z1CZh8xDw6NJD25w/mJP2f7686qljXuaFwbak
         W8nMuy3jgdYc0jI3AJNSG6Bp9VlGwUQgr4ysUCNtobHab8Fqne78Bx5a1qxF7Zb4P4Lt
         JBHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726195886; x=1726800686;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=aWurfZsf8FUm4rnFUsKHlwVC7sIDKxHd6Er87Ko5vgk=;
        b=PSRxeiLYcJcaFiWwOZQRNEjnS5fkNQzPRK7/iliGSNVVaeLq1UgkN50cm+aimfnDBv
         kSKS3GjdPX0hrYu75w6GbOvr3dwJ4EEeRKaixFGIYR4pOAwKYUP/mHkqeCNgz48ljeyL
         0lj0Kij1eB1XaD9HY2T/KRtX/LjkG5MMqOPYNG3/qjo9bUyG6SLITqeQPDOkqB7DVkOa
         glssz62eV9itVFgmKpEAOs7PR+v7OpLOqAvDRsBxc8S628D9HO0B/dqh5g0BU+cNsAp+
         oyY92KrIGJFAlG/JQL9j7UanjUrpDHXu0w58609Wxs9XSEeIGsSGjYO4GkcjCstM/J4U
         obQw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVeJBoYFCJJ9kVRg1tWhJpo60KjjZtM40SWyHgonO5UyriPDV4qA1dihl8vQhwovP5TpudQWg==@lfdr.de
X-Gm-Message-State: AOJu0YzHj2yfmbMGXs6AGEAkFOuEEwWK2uAz1jAxc7bFrmo2UNJHlDg7
	mimkkk/4OFxjVbynuznCNwfy7YPhpr1lr5oYCH67VOu6whEZ6+8d
X-Google-Smtp-Source: AGHT+IGId08ZuMWN9SjZCK4DDP2vkJha5z5/XS0/wmpMUkLrOZveq+1qP03X9/dVJeJlueN9U1EVCg==
X-Received: by 2002:a0c:f411:0:b0:6c3:5c75:d2bc with SMTP id 6a1803df08f44-6c57e0d6734mr22786826d6.47.1726195886533;
        Thu, 12 Sep 2024 19:51:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:407:b0:6bd:9552:bc87 with SMTP id
 6a1803df08f44-6c573507413ls28135886d6.2.-pod-prod-04-us; Thu, 12 Sep 2024
 19:51:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVDiQaDJuaCqkyL0UPqsNhMiJCP+irt234CIkN5uC7ZXJdBX9XARq8n6jvhHsRf4btvZ8MNmRHF/BU=@googlegroups.com
X-Received: by 2002:a05:6122:1d15:b0:4ec:f996:5d84 with SMTP id 71dfb90a1353d-50344b4b1c5mr1079379e0c.2.1726195884943;
        Thu, 12 Sep 2024 19:51:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726195884; cv=none;
        d=google.com; s=arc-20240605;
        b=IlQwNA1yjPkGczMI/sygXsw/oArC18Dxc8EWJns0peL7eyikZ3+l+zdJ0anzTrftt+
         6P/WzWgchsYWPUae/cWivbhT1OjqcZIc3afdIKwfFWl28Si14tXcMACpqJsmgIQ7wPjj
         5NPAm46HyxdA/1vzod2xDG9lVwhpWGKhIA1oJ32ugkmQoOkpxO9i9OHRijH2lzd5bU4H
         4FqiZJzf5u5lO4HzMlOhvB7A2QrDJt5Rr1wW1f4De3lJZv7MTMTu2b2LATsbyuhIkmrI
         xmWYDeCGTiMaJys+fP+CoVWDgv6fePPs8TCXwyKDtb/sIpeYyz94PJ57/aR0S2h+uLj1
         LsJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=7lucKHZRD1F8sNhQoF0GbULdmAnhRsrGT0LLKCZjQ8Q=;
        fh=rrWUoToD1jcYe/LjX7j9EN7Ggmx+alB2rOCs1cYlFP0=;
        b=HcbiSCFhYAmmeeaFxbs3q2rCRxYzFHmp8YiKALnamlQFL7Bf1bulW1bGxSI9bLUjyB
         uowJKMB3ZBt/hFBoEdf/98qkPdxYJk8SUhwo5rku/YM8MkFaG/XKM0hY4/FeV3M/iBYq
         pGsW6YPnK6yGPDtUXKk7t8I2dlQw2rXmeevaNb4JNNUaGNZyOM+5g4eoFHZZqC53TPK3
         BH+5/3MfE1oSaDTBjtFD2ImPowfz2hZwwWHnOk946+04Vu/UtX7YAA18t6S5LlOND9z+
         KcyIi4s1CSiDMMBRxxThdX+REdFH+8XnwiTBs3xvgpfQXNTyex/dSNQjNpJpINNZRCT6
         FTUQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=Qp9rEqqo;
       spf=pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-502f9fa6969si635712e0c.5.2024.09.12.19.51.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Sep 2024 19:51:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id d2e1a72fcca58-7179802b8fcso370860b3a.1
        for <kasan-dev@googlegroups.com>; Thu, 12 Sep 2024 19:51:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVcGYGpmY1oAsF+C5+ed4MJbfF4C2Ix22w4IdbhjhbN73KcHHeicKmtJ6Bu+I2v+RWoMDdNIJ/owWE=@googlegroups.com
X-Received: by 2002:a05:6300:668a:b0:1cc:cdb6:c116 with SMTP id adf61e73a8af0-1d112db1368mr1881160637.24.1726195883833;
        Thu, 12 Sep 2024 19:51:23 -0700 (PDT)
Received: from ghost ([50.145.13.30])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71908fc8febsm5398290b3a.19.2024.09.12.19.51.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Sep 2024 19:51:23 -0700 (PDT)
Date: Thu, 12 Sep 2024 19:51:21 -0700
From: Charlie Jenkins <charlie@rivosinc.com>
To: Samuel Holland <samuel.holland@sifive.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org,
	devicetree@vger.kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org, Anup Patel <anup@brainfault.org>,
	Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com,
	Atish Patra <atishp@atishpatra.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Rob Herring <robh+dt@kernel.org>,
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
Subject: Re: [PATCH v4 06/10] riscv: Allow ptrace control of the tagged
 address ABI
Message-ID: <ZuOoqTfKs/7G075O@ghost>
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
 <20240829010151.2813377-7-samuel.holland@sifive.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240829010151.2813377-7-samuel.holland@sifive.com>
X-Original-Sender: charlie@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=Qp9rEqqo;       spf=pass (google.com: domain of charlie@rivosinc.com
 designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
       dara=pass header.i=@googlegroups.com
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

On Wed, Aug 28, 2024 at 06:01:28PM -0700, Samuel Holland wrote:
> This allows a tracer to control the ABI of the tracee, as on arm64.
> 
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> ---

Since this code is identical to the arm64 port, could it be extracted
out into the generic ptrace.c and ifdef on either CONFIG_RISCV_ISA_SUPM
or CONFIG_ARM64_TAGGED_ADDR_ABI by adding some generic flag like
CONFIG_HAVE_ARCH_TAGGED_ADDR_ABI?

- Charlie

>
> (no changes since v1)
> 
>  arch/riscv/kernel/ptrace.c | 42 ++++++++++++++++++++++++++++++++++++++
>  include/uapi/linux/elf.h   |  1 +
>  2 files changed, 43 insertions(+)
> 
> diff --git a/arch/riscv/kernel/ptrace.c b/arch/riscv/kernel/ptrace.c
> index 92731ff8c79a..ea67e9fb7a58 100644
> --- a/arch/riscv/kernel/ptrace.c
> +++ b/arch/riscv/kernel/ptrace.c
> @@ -28,6 +28,9 @@ enum riscv_regset {
>  #ifdef CONFIG_RISCV_ISA_V
>  	REGSET_V,
>  #endif
> +#ifdef CONFIG_RISCV_ISA_SUPM
> +	REGSET_TAGGED_ADDR_CTRL,
> +#endif
>  };
>  
>  static int riscv_gpr_get(struct task_struct *target,
> @@ -152,6 +155,35 @@ static int riscv_vr_set(struct task_struct *target,
>  }
>  #endif
>  
> +#ifdef CONFIG_RISCV_ISA_SUPM
> +static int tagged_addr_ctrl_get(struct task_struct *target,
> +				const struct user_regset *regset,
> +				struct membuf to)
> +{
> +	long ctrl = get_tagged_addr_ctrl(target);
> +
> +	if (IS_ERR_VALUE(ctrl))
> +		return ctrl;
> +
> +	return membuf_write(&to, &ctrl, sizeof(ctrl));
> +}
> +
> +static int tagged_addr_ctrl_set(struct task_struct *target,
> +				const struct user_regset *regset,
> +				unsigned int pos, unsigned int count,
> +				const void *kbuf, const void __user *ubuf)
> +{
> +	int ret;
> +	long ctrl;
> +
> +	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &ctrl, 0, -1);
> +	if (ret)
> +		return ret;
> +
> +	return set_tagged_addr_ctrl(target, ctrl);
> +}
> +#endif
> +
>  static const struct user_regset riscv_user_regset[] = {
>  	[REGSET_X] = {
>  		.core_note_type = NT_PRSTATUS,
> @@ -182,6 +214,16 @@ static const struct user_regset riscv_user_regset[] = {
>  		.set = riscv_vr_set,
>  	},
>  #endif
> +#ifdef CONFIG_RISCV_ISA_SUPM
> +	[REGSET_TAGGED_ADDR_CTRL] = {
> +		.core_note_type = NT_RISCV_TAGGED_ADDR_CTRL,
> +		.n = 1,
> +		.size = sizeof(long),
> +		.align = sizeof(long),
> +		.regset_get = tagged_addr_ctrl_get,
> +		.set = tagged_addr_ctrl_set,
> +	},
> +#endif
>  };
>  
>  static const struct user_regset_view riscv_user_native_view = {
> diff --git a/include/uapi/linux/elf.h b/include/uapi/linux/elf.h
> index b54b313bcf07..9a32532d7264 100644
> --- a/include/uapi/linux/elf.h
> +++ b/include/uapi/linux/elf.h
> @@ -448,6 +448,7 @@ typedef struct elf64_shdr {
>  #define NT_MIPS_MSA	0x802		/* MIPS SIMD registers */
>  #define NT_RISCV_CSR	0x900		/* RISC-V Control and Status Registers */
>  #define NT_RISCV_VECTOR	0x901		/* RISC-V vector registers */
> +#define NT_RISCV_TAGGED_ADDR_CTRL 0x902	/* RISC-V tagged address control (prctl()) */
>  #define NT_LOONGARCH_CPUCFG	0xa00	/* LoongArch CPU config registers */
>  #define NT_LOONGARCH_CSR	0xa01	/* LoongArch control and status registers */
>  #define NT_LOONGARCH_LSX	0xa02	/* LoongArch Loongson SIMD Extension registers */
> -- 
> 2.45.1
> 
> 
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZuOoqTfKs/7G075O%40ghost.
