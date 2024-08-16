Return-Path: <kasan-dev+bncBCMIFTP47IJBBY7R7W2QMGQEZP3PQRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 27731954E6C
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Aug 2024 18:05:57 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-44fefc0296esf38242671cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Aug 2024 09:05:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723824356; cv=pass;
        d=google.com; s=arc-20160816;
        b=SMPieS8TE5WysyREI3Kgm8xzD9xyHtXdU6ypcoKUG5BM8V20V/yTwRSl04wMJkgCS/
         FRXU3IFr8bqXretr+6Ww3GzaW42Cupzavex76S0WKLXsjuhBsf4nov+xRdwRKm+MCoCw
         Y3D88W4H09gcNnRbxTMx0zILCCc/d81OO7NZQltBdJQsSJ7VAeRHr5qtcmqw1vqVPzWt
         0xAIiMBOtC7u2A3unNXKYiamRAxU93IqhiNN23ZEtTWCU0Ef0Xqi3KA1HaKtVVUF/m1X
         8kJ8RX9oxOK2xuybeQSUv1Igfq+1g3wXzR40mmQMdkcwQ8TK69MGcuafd5ilJy+Bxxt/
         m/nQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=iCLrpDrEQKjodPPyPOQorEjzI83SP3/OEF3PDhEtiUE=;
        fh=2mFl/7uKJRSmZK5Y0M9PGbzOsLIpqpcK5rOaL2D6BUw=;
        b=M7j9n0TEmkpypi+FOvCQo+rqckaIK2lU3zL60X/KEfLf25vMATpFHoGyvEsM+Hrt9F
         hnT0XFk3U5/pzkmx4LWIpxcTkjDyY2ZzWe7dGjxG7aGQEMa8pnvcmZGMchXTgKWl+J6x
         QkYrEmWS6+YKUCGA5ZqNViMHE7kzGDxpVOprWYCk6Oh3DMDH+vMGd0kQ/gKRqakqdNwd
         eAoTqNgwoga8w6R7/nqa4gxbhKCfEySmhDhKeCqQzcgHsmtX40l/gHeJGYX7pWImhooA
         MkXHSZBDQK7mXqOJdOhxbstnUutsBDMiR4uMk+CkvvLhoembEyj8ULpNFmHVVbwIRNk7
         Jbew==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=UF4mMsKo;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::130 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723824356; x=1724429156; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=iCLrpDrEQKjodPPyPOQorEjzI83SP3/OEF3PDhEtiUE=;
        b=vf9YIm9cQlfsq1986BtnZwjMEiq0TWLQlaaeQT4lOHbpmsPjwdCle8qv7RHttveYvI
         CnHArX4WE3Al3za8Ntgsn++dNvdabRzMK6rBLnK+SNGZVEyC87RP3NKwKjw3UAz/Jnby
         fWSLgQMR2ZSDPbyqIrT87QY3j4pYPHsD1Jo8vf/DG0/yXmB/3HOIrNSF8EaIB3OAWGun
         IXzhrFLH3KZGqYOxk0hm2oDZqKlLuRkDK134/OPIPCzusx2sLM9uF4BzBOUo65kCjQKP
         lzaSNBdBNUGjv2LOsoobvBBQd2rUzo9YiMGy9NQvVqTDg0zzm+ApDVHEZcFqLVDWhROL
         AeTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723824356; x=1724429156;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iCLrpDrEQKjodPPyPOQorEjzI83SP3/OEF3PDhEtiUE=;
        b=MR6QYHa8h0VAsJws14X2qR3dB2YYfj7iM11zj/qoPNaGh7sKP2oC7wndJBotan5mFt
         qKZ3271RazDl9pYu9suL9Kwsuw9/a+Lz4nqZ1M9veBxos2XtnFPgr12F5nGZwg1aIU8Z
         wzLtQBhSghFwiqcRihvwHAg37HsV9oPGLWUGyIX11zZpquCZJ4wAq1CGYSScEAVrAZLV
         y6eNFPlyj0pQRw8sW+OCPhwVE4Jey+YppjVE+m/njZcgJaZyn9yPpioiCB/CFxD5wVY0
         pty/yUS7jKq2G/bxaq3bfWzuiRU0cLIAuYgmXrG6ZeiMRekXfik+enjEFD4CRNY1ouLq
         UZiQ==
X-Forwarded-Encrypted: i=2; AJvYcCUYGkZQEl7lRd4399jmfOYId+0Xg9RK8euX53E6cSBc01ih4UwO2jt3cvRC/zYT5NBs21YYMCIK8lktHL7R2HwPoRF7IXcLKQ==
X-Gm-Message-State: AOJu0YzZvKxKOUu8gpof43qNJCbeM1205j0TTkW98VRjEodC74EDDGDk
	6uZDd/YjFt7qoFCFcm3kf0eFJyBxtk3N3+k0WpBLZuTYx0HK+NB1
X-Google-Smtp-Source: AGHT+IEjps1jHN/OydQAeuPh1bUIQ4Kw7eQiCm+NKWFm8oilaz4zDGALkEOL9GqG7n8r4O3Mibk0+A==
X-Received: by 2002:a05:622a:1356:b0:444:d08d:6202 with SMTP id d75a77b69052e-4536784f913mr133204781cf.12.1723824355395;
        Fri, 16 Aug 2024 09:05:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:20b:b0:440:38e6:c194 with SMTP id
 d75a77b69052e-453674758f0ls11526841cf.2.-pod-prod-00-us; Fri, 16 Aug 2024
 09:05:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVFDzWDj8UHL7QTCl1y5JFvVCt7TDabADwjyi9XnZqObXMkuGNeYLoEXium7fgRtW9BmZujFQ7cQ4CEi8CsM6RSj+UT4/BRfnsSMQ==
X-Received: by 2002:a05:620a:24d4:b0:7a1:df6f:3632 with SMTP id af79cd13be357-7a4fd24f419mr1237365085a.32.1723824354426;
        Fri, 16 Aug 2024 09:05:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723824354; cv=none;
        d=google.com; s=arc-20160816;
        b=Bn+NgPzU3+umpVUpSGcrccZo4wR1AaL5AArqyCDg+RHZYXFV0uXkoW/DalTCbt4yWR
         kcPkw5TS19KjTvD/rnKqvkPcm7Dav5dBmEykCNROEW15LT34w55CmcZEldEqnGO1svI/
         iPtgRev+ZT/KG7aUhlYpOpiTRY73AbM5vDcTY+vaPZpw9te1PFCnr8QpN7gW3buwyORt
         bCn7s4lTSopPoSyN0HbntfUxBgR+U4xDy7KAKscSX1+ZBiX+yVAZCx7mqYGyFrTIJ//9
         aWCEHzkylXf5y+zak648LysO14b7QdyLghgkzcM78oiAU7ym2+Yo1nJBf0lFilICRTog
         E+rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=o84N4ouk6Dkhcje+6ztzZIHY0vWe2YxL+gh1TxT0Vmk=;
        fh=TtMZJX99Rxq6yDrRbnP0FP2llRlNq77VypQeoWQld4U=;
        b=MkfWmwFZLIEn6Zd4gPJa/BOBZoQDfG0rbaOUWC/hCNzpF4KkgnAQqU+NnB6MvGDg6w
         vKJLpvLBPBvQcaC5yK1mK+XHSMOfCjpxb7Cm5tqcsNg0cOhz3XoOtB3dVrsECtfo7JuA
         VldvlbepH4F2FxuhfyEC1FAHb+i73yLFDX4C65rlII+jkIfmEzRsQFwlfspFmvSvY2IP
         r6NuEzd6KClBWW2+oZDbi0H3V9c/XcmMM2jOU2u86yq4jVB+loJNmhkwBkJxattTdg6S
         eEPVJyEJRM+dVfWxMViK/FOCZNhfAaoCrVnFskjSXLYWe82kKvfM7D7L8OkSLLTHlxer
         YC7Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=UF4mMsKo;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::130 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-il1-x130.google.com (mail-il1-x130.google.com. [2607:f8b0:4864:20::130])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-842fb9ce792si153620241.2.2024.08.16.09.05.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Aug 2024 09:05:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::130 as permitted sender) client-ip=2607:f8b0:4864:20::130;
Received: by mail-il1-x130.google.com with SMTP id e9e14a558f8ab-39d24ec79feso5168215ab.0
        for <kasan-dev@googlegroups.com>; Fri, 16 Aug 2024 09:05:54 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU9cpWVHRNQkpeLsfOol03/YfXAmWc6NC6Dr6Doqn+VtzsVUOYdqpCrDW3VbLsmyhp/CJb6u9lJCvhn1euz8Xl2xzPWscQ/ry+0Ng==
X-Received: by 2002:a05:6e02:1c49:b0:39a:e9b8:cdae with SMTP id e9e14a558f8ab-39d1bc97b4emr73110195ab.0.1723824353392;
        Fri, 16 Aug 2024 09:05:53 -0700 (PDT)
Received: from [100.64.0.1] ([147.124.94.167])
        by smtp.gmail.com with ESMTPSA id e9e14a558f8ab-39d247324afsm11366425ab.13.2024.08.16.09.05.51
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Aug 2024 09:05:52 -0700 (PDT)
Message-ID: <7d741701-8966-45f1-8404-4b3618d44ea4@sifive.com>
Date: Fri, 16 Aug 2024 11:05:50 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 04/10] riscv: Add support for userspace pointer masking
To: Anup Patel <apatel@ventanamicro.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org,
 devicetree@vger.kernel.org, Catalin Marinas <catalin.marinas@arm.com>,
 linux-kernel@vger.kernel.org, Anup Patel <anup@brainfault.org>,
 Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com,
 Atish Patra <atishp@atishpatra.org>, Evgenii Stepanov <eugenis@google.com>,
 Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
 Rob Herring <robh+dt@kernel.org>,
 "Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
References: <20240814081437.956855-1-samuel.holland@sifive.com>
 <20240814081437.956855-5-samuel.holland@sifive.com>
 <CAK9=C2XOktu5kPXEWKMY4Wsf0D9kwh3rZNXricWqLQaiaqWnnQ@mail.gmail.com>
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: en-US
In-Reply-To: <CAK9=C2XOktu5kPXEWKMY4Wsf0D9kwh3rZNXricWqLQaiaqWnnQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=UF4mMsKo;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::130 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

Hi Anup,

On 2024-08-16 8:21 AM, Anup Patel wrote:
> On Wed, Aug 14, 2024 at 1:45=E2=80=AFPM Samuel Holland
> <samuel.holland@sifive.com> wrote:
>>
>> RISC-V supports pointer masking with a variable number of tag bits
>> (which is called "PMLEN" in the specification) and which is configured
>> at the next higher privilege level.
>>
>> Wire up the PR_SET_TAGGED_ADDR_CTRL and PR_GET_TAGGED_ADDR_CTRL prctls
>> so userspace can request a lower bound on the number of tag bits and
>> determine the actual number of tag bits. As with arm64's
>> PR_TAGGED_ADDR_ENABLE, the pointer masking configuration is
>> thread-scoped, inherited on clone() and fork() and cleared on execve().
>>
>> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
>> ---
>>
>> Changes in v3:
>>  - Rename CONFIG_RISCV_ISA_POINTER_MASKING to CONFIG_RISCV_ISA_SUPM,
>>    since it only controls the userspace part of pointer masking
>>  - Use IS_ENABLED instead of #ifdef when possible
>>  - Use an enum for the supported PMLEN values
>>  - Simplify the logic in set_tagged_addr_ctrl()
>>
>> Changes in v2:
>>  - Rebase on riscv/linux.git for-next
>>  - Add and use the envcfg_update_bits() helper function
>>  - Inline flush_tagged_addr_state()
>>
>>  arch/riscv/Kconfig                 | 11 ++++
>>  arch/riscv/include/asm/processor.h |  8 +++
>>  arch/riscv/include/asm/switch_to.h | 11 ++++
>>  arch/riscv/kernel/process.c        | 90 ++++++++++++++++++++++++++++++
>>  include/uapi/linux/prctl.h         |  3 +
>>  5 files changed, 123 insertions(+)
>>
>> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
>> index 0f3cd7c3a436..817437157138 100644
>> --- a/arch/riscv/Kconfig
>> +++ b/arch/riscv/Kconfig
>> @@ -512,6 +512,17 @@ config RISCV_ISA_C
>>
>>           If you don't know what to do here, say Y.
>>
>> +config RISCV_ISA_SUPM
>> +       bool "Supm extension for userspace pointer masking"
>> +       depends on 64BIT
>> +       default y
>> +       help
>> +         Add support for pointer masking in userspace (Supm) when the
>> +         underlying hardware extension (Smnpm or Ssnpm) is detected at =
boot.
>> +
>> +         If this option is disabled, userspace will be unable to use
>> +         the prctl(PR_{SET,GET}_TAGGED_ADDR_CTRL) API.
>> +
>>  config RISCV_ISA_SVNAPOT
>>         bool "Svnapot extension support for supervisor mode NAPOT pages"
>>         depends on 64BIT && MMU
>> diff --git a/arch/riscv/include/asm/processor.h b/arch/riscv/include/asm=
/processor.h
>> index 586e4ab701c4..5c4d4fb97314 100644
>> --- a/arch/riscv/include/asm/processor.h
>> +++ b/arch/riscv/include/asm/processor.h
>> @@ -200,6 +200,14 @@ extern int set_unalign_ctl(struct task_struct *tsk,=
 unsigned int val);
>>  #define RISCV_SET_ICACHE_FLUSH_CTX(arg1, arg2) riscv_set_icache_flush_c=
tx(arg1, arg2)
>>  extern int riscv_set_icache_flush_ctx(unsigned long ctx, unsigned long =
per_thread);
>>
>> +#ifdef CONFIG_RISCV_ISA_SUPM
>> +/* PR_{SET,GET}_TAGGED_ADDR_CTRL prctl */
>> +long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg);
>> +long get_tagged_addr_ctrl(struct task_struct *task);
>> +#define SET_TAGGED_ADDR_CTRL(arg)      set_tagged_addr_ctrl(current, ar=
g)
>> +#define GET_TAGGED_ADDR_CTRL()         get_tagged_addr_ctrl(current)
>> +#endif
>> +
>>  #endif /* __ASSEMBLY__ */
>>
>>  #endif /* _ASM_RISCV_PROCESSOR_H */
>> diff --git a/arch/riscv/include/asm/switch_to.h b/arch/riscv/include/asm=
/switch_to.h
>> index 9685cd85e57c..94e33216b2d9 100644
>> --- a/arch/riscv/include/asm/switch_to.h
>> +++ b/arch/riscv/include/asm/switch_to.h
>> @@ -70,6 +70,17 @@ static __always_inline bool has_fpu(void) { return fa=
lse; }
>>  #define __switch_to_fpu(__prev, __next) do { } while (0)
>>  #endif
>>
>> +static inline void envcfg_update_bits(struct task_struct *task,
>> +                                     unsigned long mask, unsigned long =
val)
>> +{
>> +       unsigned long envcfg;
>> +
>> +       envcfg =3D (task->thread.envcfg & ~mask) | val;
>> +       task->thread.envcfg =3D envcfg;
>> +       if (task =3D=3D current)
>> +               csr_write(CSR_ENVCFG, envcfg);
>> +}
>> +
>>  static inline void __switch_to_envcfg(struct task_struct *next)
>>  {
>>         asm volatile (ALTERNATIVE("nop", "csrw " __stringify(CSR_ENVCFG)=
 ", %0",
>> diff --git a/arch/riscv/kernel/process.c b/arch/riscv/kernel/process.c
>> index e4bc61c4e58a..1280a7c4a412 100644
>> --- a/arch/riscv/kernel/process.c
>> +++ b/arch/riscv/kernel/process.c
>> @@ -7,6 +7,7 @@
>>   * Copyright (C) 2017 SiFive
>>   */
>>
>> +#include <linux/bitfield.h>
>>  #include <linux/cpu.h>
>>  #include <linux/kernel.h>
>>  #include <linux/sched.h>
>> @@ -171,6 +172,9 @@ void flush_thread(void)
>>         memset(&current->thread.vstate, 0, sizeof(struct __riscv_v_ext_s=
tate));
>>         clear_tsk_thread_flag(current, TIF_RISCV_V_DEFER_RESTORE);
>>  #endif
>> +       if (IS_ENABLED(CONFIG_RISCV_ISA_SUPM) &&
>> +           riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM))
>> +               envcfg_update_bits(current, ENVCFG_PMM, ENVCFG_PMM_PMLEN=
_0);
>=20
> Seeing a compile warning with this patch on RV32.
>=20
> linux/arch/riscv/kernel/process.c: In function 'flush_thread':
> linux/arch/riscv/include/asm/csr.h:202:41: warning: conversion from
> 'long long unsigned int' to 'long unsigned int' changes value from
> '12884901888' to '0' [-Woverflow]
>   202 | #define ENVCFG_PMM                      (_AC(0x3, ULL) << 32)
>       |                                         ^~~~~~~~~~~~~~~~~~~~~
> linux/arch/riscv/kernel/process.c:179:45: note: in expansion of macro
> 'ENVCFG_PMM'
>   179 |                 envcfg_update_bits(current, ENVCFG_PMM,
> ENVCFG_PMM_PMLEN_0);
>       |                                             ^~~~~~~~~~

Right, thanks, that's why I needed to use #ifdef here before. I'll switch t=
his
instance back for v4.

Regards,
Samuel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/7d741701-8966-45f1-8404-4b3618d44ea4%40sifive.com.
