Return-Path: <kasan-dev+bncBC7PZX4C3UKBB4EJ6O2QMGQE3AUBXQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 968A3951DC8
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 16:53:38 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-530db30008esf6429351e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 07:53:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723647218; cv=pass;
        d=google.com; s=arc-20160816;
        b=W3Y2jSOI1C14rrlOnX4m07MaaloCL63m7wCXmKgn3t7k9Xq6WMFWPARpx81XP2StSK
         EZuHO2Vz+a+DRRH0KvMOXOASgGz6txNR8diboOKeA/PiCIUsyGgDCbCXjZVgiYHd2Ye9
         gE6Boawnpe/4S0OKgZQZAx9UDUrRfV8qhzP6k/r0v2O1BuudHbZ/MYRhsAH2Y63Kv+Ic
         NL00CcUIfc5VBXJVH6S2SH8T+/vSL/R0hxLm25SuXscuf/SSTezsMp1NfP9qvldM+T6Y
         ag4NI1RpzBdiq0mjYSXb7bnpbYGVr7n9mGZ9ukc5cF/RBTNM0ymivXSeC7O8+EE6W957
         JAIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=LAHnXd/xGxDEywoe1bJSbS/e6p56kfRwpPxhzA5qxJQ=;
        fh=XXA8r2vnNRH6nY3eTAgvkMjb0p/t9CpdJM8dTRKzL2A=;
        b=VMKTuYHUKVwlXUDeH9IxJjfaHT4TYD2BQVjNNKki6UnJfbAIeQV8cONkxa/VZl1jbL
         ZXpua+Gs2W12otLOuv42UyoRrGSJY4lqEu/v0oS7vqxhJi060iwB/bohHpxwDe3ilAEI
         AOrXHoyDu9nsXVblC6v5T340u3CI+2XcyW1qPCrNOQMd3IrZhc6gW2rvhPNuaXzNVkCJ
         i3Hv3aPz2tEdDsH254V72KMXyO0wfcFx0caMsIQbZcPsvwjg74ZMLMO1FFEQrjGlwlE5
         CNXlS09kY2VbpTw5pFk0eEfCWQ2oASRLW7X5AUHrZISV70hZYaq/s51Drc4wGR5XKvUC
         m+iQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::226 as permitted sender) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723647218; x=1724252018; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LAHnXd/xGxDEywoe1bJSbS/e6p56kfRwpPxhzA5qxJQ=;
        b=nZ8HkHhIb2QzYBzYE5CD1uYBUdCB5sqcVTLGHj9BCHvxNp7V8L8lEzodJ5fdCJMEwu
         T6H3xQ7E9YS0NZZ88/oemMubXql3gs8smzkiBieQXG5RB5/nUtQYqbyofYhCKgNcOF2X
         YiTkRSiDkY8bQnqD5ozgcISZP0w2lVR5jbXUr28XCf7HTS2H5t1us4ld9OVyXlmRh5J6
         8DiHLKi8vFvnF7t8edY6BEPYIJou5OzrOWF/JT5+PLHp6pWcsHfB0O7/oKk3/i8XTYdn
         rYp+jcvkZUrHOM9eRXkPPYKhmijENE/Ig9eYnmwrglMEy8CrhPueoMJGXU344RopVJfN
         dyvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723647218; x=1724252018;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LAHnXd/xGxDEywoe1bJSbS/e6p56kfRwpPxhzA5qxJQ=;
        b=QcooIgd1r98JGMxnrOzCTHV0jmFksJXX0df0DsM+6qceIK0N3p1L/hUIA60+a8bvks
         5ojFaFxszHwFay3Vr/TppXPVZJGCNnG2crBBxWDrtzgD3DM6ItrZfxPIDF+5xWph5ht+
         FTCRIsj/EsueOhQE+mBO8L9tcsINcQ/qcAw7c/S4PDQFoRA1R+BdcNSksUph6zb4OPRn
         38pxb7sv50o9MVKokgAy6Dfv5Amek88CXtpRVIy6oCLVmYRf7WhIgeD5QpxjtMmaeo/8
         T8zJRhpiQ8+FdvCP1Sf7YQTNfwg3IC5M8kP+P9qtRc4G7yUDauyBVS8GaD/CjNxBZAN/
         PNJg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVUio7IqHUIGrlnIxz2Yc1z1jXjpFxRmH1ElJc34vCObohUv+NyaiQniJAl8ZgabU/xlfhlhF6kCWa7E3Eon0LpaxeY02SoKw==
X-Gm-Message-State: AOJu0YzUI/CzEFgLfniOW0QPFzWxF4Sf7ZtkEGZRN3tiqB94fvN4TXiB
	pI0U2nW8QqSmfC6w8JxilhPKbKssMGYusy/ExwCKNb+iKaHR59hj
X-Google-Smtp-Source: AGHT+IGsR54SiTi8AfSWuZN0leIXTxOZzdh8QdxICDfvkyv9knrHWkva06Fa3UK1DpxWv5RMkMRqpQ==
X-Received: by 2002:a05:6512:104d:b0:52c:8df9:2e6f with SMTP id 2adb3069b0e04-532edba899cmr2278237e87.42.1723647216588;
        Wed, 14 Aug 2024 07:53:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3c9a:b0:52f:317:fe07 with SMTP id
 2adb3069b0e04-530e3a15267ls288265e87.2.-pod-prod-03-eu; Wed, 14 Aug 2024
 07:53:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVy+0PbaBazzYpAXh9lW9FkyxNgdacLDBHL8qHD96CKLfFh4JA6dSxo9lh9qnRSk/Aok/FFozQ6Ckjbz0C+i73EPkhyurKnNVO3kA==
X-Received: by 2002:a05:6512:3b94:b0:52e:9b68:d2da with SMTP id 2adb3069b0e04-532eda5ac24mr2178808e87.9.1723647214085;
        Wed, 14 Aug 2024 07:53:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723647214; cv=none;
        d=google.com; s=arc-20240605;
        b=VhHXpC7SKhQAFVNduGgRuv8PqiLkaXpaun0+P6Bt7uWdkVggKbZzrvfMcfHogffr6u
         kNxxNX4Z5RvCyKxV8QXgi+hwEkydsryWFQervT50oQdp/+JnZYpH46p9R9jVrw+jKgFp
         Oa+7g04oU+OlgtILIRaF1hvH0TZ0CDkA7vdAu6jFidH6bgeKpUfw5JccfWHlBFJ1D+xb
         Dn1+q8ersE1K7ZujUYh9xbMNdFDJMYa69wiNek/mXGkqMi3tXg+xIVcVNpFAni0Mqzoi
         WHoBSApyofzQhkcWFJSGk5z38hQxwVJAjxs5GMJfmaKZZ7R1qORJ6IaBxz0yBw+dx81R
         RFoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=flnJFrccAR7sM+gtYaU9F8pTMTBNOijB2p/d/989Omw=;
        fh=PlrXXiljIqn5FFku5uz3XLLiXAFcGGd/MpVQIupLlEU=;
        b=OfueYlVGGXJgYERmAQv4mlEyPtJIIjU27T/xA5/r8FEIbRz9w7O6zzX77SQLlbM0mQ
         hBvPyAmLxf8T6HZkzYMHwKPKcOD73cGVm36RLUArNuO8zRO4qT/NfCc5SRp+Nu4KY/X7
         nfXfV8bvyWhH5AR7eM7w912BR80gvFoU1BSWj7F+VYHVbaMCGq6QkpaKaoxb1tA0WvKY
         ersXCGGnTjVTXJgIYlQU1aTXdnu6PO8ZwumkvU1fyaA5Ff9bJhhtlL2aSqRCg/3K/7mk
         rVbNv6qYzz93XkxFEA9S6D7HEA/7JzjxakfZlHCjg/Z8YviZZC19AHwbZ6Pkycewamb8
         dgRg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::226 as permitted sender) smtp.mailfrom=alex@ghiti.fr
Received: from relay6-d.mail.gandi.net (relay6-d.mail.gandi.net. [2001:4b98:dc4:8::226])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-429d780b745si2812495e9.0.2024.08.14.07.53.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 14 Aug 2024 07:53:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::226 as permitted sender) client-ip=2001:4b98:dc4:8::226;
Received: by mail.gandi.net (Postfix) with ESMTPSA id 34763C0003;
	Wed, 14 Aug 2024 14:53:32 +0000 (UTC)
Message-ID: <02718edd-e061-4f2d-9a29-cdc7931727b3@ghiti.fr>
Date: Wed, 14 Aug 2024 16:53:31 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 04/10] riscv: Add support for userspace pointer masking
Content-Language: en-US
To: Samuel Holland <samuel.holland@sifive.com>,
 Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org
Cc: devicetree@vger.kernel.org, Catalin Marinas <catalin.marinas@arm.com>,
 linux-kernel@vger.kernel.org, Anup Patel <anup@brainfault.org>,
 Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com,
 Atish Patra <atishp@atishpatra.org>, Evgenii Stepanov <eugenis@google.com>,
 Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
 Rob Herring <robh+dt@kernel.org>,
 "Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
References: <20240625210933.1620802-1-samuel.holland@sifive.com>
 <20240625210933.1620802-5-samuel.holland@sifive.com>
 <440ca2a7-9dfb-45cd-8331-a8d0afff47d0@ghiti.fr>
 <dc8da1d4-435a-4786-b4bc-7f89590c2269@sifive.com>
From: Alexandre Ghiti <alex@ghiti.fr>
In-Reply-To: <dc8da1d4-435a-4786-b4bc-7f89590c2269@sifive.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-GND-Sasl: alex@ghiti.fr
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::226 as
 permitted sender) smtp.mailfrom=alex@ghiti.fr
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

Hi Samuel,

On 14/08/2024 03:54, Samuel Holland wrote:
> Hi Alex,
>
> Thanks for the review!
>
> On 2024-08-13 3:58 AM, Alexandre Ghiti wrote:
>> Hi Samuel,
>>
>> On 25/06/2024 23:09, Samuel Holland wrote:
>>> RISC-V supports pointer masking with a variable number of tag bits
>>> (which is called "PMLEN" in the specification) and which is configured
>>> at the next higher privilege level.
>>>
>>> Wire up the PR_SET_TAGGED_ADDR_CTRL and PR_GET_TAGGED_ADDR_CTRL prctls
>>> so userspace can request a lower bound on the=C2=A0 number of tag bits =
and
>>> determine the actual number of tag bits. As with arm64's
>>> PR_TAGGED_ADDR_ENABLE, the pointer masking configuration is
>>> thread-scoped, inherited on clone() and fork() and cleared on execve().
>>>
>>> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
>>> ---
>>>
>>> Changes in v2:
>>>  =C2=A0 - Rebase on riscv/linux.git for-next
>>>  =C2=A0 - Add and use the envcfg_update_bits() helper function
>>>  =C2=A0 - Inline flush_tagged_addr_state()
>>>
>>>  =C2=A0 arch/riscv/Kconfig=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 11 ++++
>>>  =C2=A0 arch/riscv/include/asm/processor.h |=C2=A0 8 +++
>>>  =C2=A0 arch/riscv/include/asm/switch_to.h | 11 ++++
>>>  =C2=A0 arch/riscv/kernel/process.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 99 ++++++++++++++++++++++++++++++
>>>  =C2=A0 include/uapi/linux/prctl.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 |=C2=A0 3 +
>>>  =C2=A0 5 files changed, 132 insertions(+)
>>>
>>> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
>>> index b94176e25be1..8f9980f81ea5 100644
>>> --- a/arch/riscv/Kconfig
>>> +++ b/arch/riscv/Kconfig
>>> @@ -505,6 +505,17 @@ config RISCV_ISA_C
>>>  =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 If you don't know wh=
at to do here, say Y.
>>>  =C2=A0 +config RISCV_ISA_POINTER_MASKING
>>> +=C2=A0=C2=A0=C2=A0 bool "Smmpm, Smnpm, and Ssnpm extensions for pointe=
r masking"
>>> +=C2=A0=C2=A0=C2=A0 depends on 64BIT
>>> +=C2=A0=C2=A0=C2=A0 default y
>>> +=C2=A0=C2=A0=C2=A0 help
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 Add support for the pointer masking ext=
ensions (Smmpm, Smnpm,
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 and Ssnpm) when they are detected at bo=
ot.
>>> +
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 If this option is disabled, userspace w=
ill be unable to use
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 the prctl(PR_{SET,GET}_TAGGED_ADDR_CTRL=
) API.
>>> +
>>>  =C2=A0 config RISCV_ISA_SVNAPOT
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 bool "Svnapot extension support for sup=
ervisor mode NAPOT pages"
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 depends on 64BIT && MMU
>>> diff --git a/arch/riscv/include/asm/processor.h
>>> b/arch/riscv/include/asm/processor.h
>>> index 0838922bd1c8..4f99c85d29ae 100644
>>> --- a/arch/riscv/include/asm/processor.h
>>> +++ b/arch/riscv/include/asm/processor.h
>>> @@ -194,6 +194,14 @@ extern int set_unalign_ctl(struct task_struct *tsk=
,
>>> unsigned int val);
>>>  =C2=A0 #define RISCV_SET_ICACHE_FLUSH_CTX(arg1, arg2)
>>> riscv_set_icache_flush_ctx(arg1, arg2)
>>>  =C2=A0 extern int riscv_set_icache_flush_ctx(unsigned long ctx, unsign=
ed long
>>> per_thread);
>>>  =C2=A0 +#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
>>> +/* PR_{SET,GET}_TAGGED_ADDR_CTRL prctl */
>>> +long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg)=
;
>>> +long get_tagged_addr_ctrl(struct task_struct *task);
>>> +#define SET_TAGGED_ADDR_CTRL(arg)=C2=A0=C2=A0=C2=A0 set_tagged_addr_ct=
rl(current, arg)
>>> +#define GET_TAGGED_ADDR_CTRL()=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 get_tagged_addr_ctrl(current)
>>> +#endif
>>> +
>>>  =C2=A0 #endif /* __ASSEMBLY__ */
>>>  =C2=A0 =C2=A0 #endif /* _ASM_RISCV_PROCESSOR_H */
>>> diff --git a/arch/riscv/include/asm/switch_to.h
>>> b/arch/riscv/include/asm/switch_to.h
>>> index 9685cd85e57c..94e33216b2d9 100644
>>> --- a/arch/riscv/include/asm/switch_to.h
>>> +++ b/arch/riscv/include/asm/switch_to.h
>>> @@ -70,6 +70,17 @@ static __always_inline bool has_fpu(void) { return f=
alse; }
>>>  =C2=A0 #define __switch_to_fpu(__prev, __next) do { } while (0)
>>>  =C2=A0 #endif
>>>  =C2=A0 +static inline void envcfg_update_bits(struct task_struct *task=
,
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long mas=
k, unsigned long val)
>>> +{
>>> +=C2=A0=C2=A0=C2=A0 unsigned long envcfg;
>>> +
>>> +=C2=A0=C2=A0=C2=A0 envcfg =3D (task->thread.envcfg & ~mask) | val;
>>> +=C2=A0=C2=A0=C2=A0 task->thread.envcfg =3D envcfg;
>>> +=C2=A0=C2=A0=C2=A0 if (task =3D=3D current)
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 csr_write(CSR_ENVCFG, envcf=
g);
>>> +}
>>> +
>>>  =C2=A0 static inline void __switch_to_envcfg(struct task_struct *next)
>>>  =C2=A0 {
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 asm volatile (ALTERNATIVE("nop", "csrw =
" __stringify(CSR_ENVCFG) ", %0",
>>> diff --git a/arch/riscv/kernel/process.c b/arch/riscv/kernel/process.c
>>> index e4bc61c4e58a..dec5ccc44697 100644
>>> --- a/arch/riscv/kernel/process.c
>>> +++ b/arch/riscv/kernel/process.c
>>> @@ -7,6 +7,7 @@
>>>  =C2=A0=C2=A0 * Copyright (C) 2017 SiFive
>>>  =C2=A0=C2=A0 */
>>>  =C2=A0 +#include <linux/bitfield.h>
>>>  =C2=A0 #include <linux/cpu.h>
>>>  =C2=A0 #include <linux/kernel.h>
>>>  =C2=A0 #include <linux/sched.h>
>>> @@ -171,6 +172,10 @@ void flush_thread(void)
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memset(&current->thread.vstate, 0, size=
of(struct __riscv_v_ext_state));
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 clear_tsk_thread_flag(current, TIF_RISC=
V_V_DEFER_RESTORE);
>>>  =C2=A0 #endif
>>> +#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
>>> +=C2=A0=C2=A0=C2=A0 if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM=
))
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 envcfg_update_bits(current,=
 ENVCFG_PMM, ENVCFG_PMM_PMLEN_0);
>>> +#endif
>> if (IS_ENABLED(CONFIG_RISCV_ISA_POINTER_MASKING) &&
>> riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM))
> I will update this.
>
>>>  =C2=A0 }
>>>  =C2=A0 =C2=A0 void arch_release_task_struct(struct task_struct *tsk)
>>> @@ -233,3 +238,97 @@ void __init arch_task_cache_init(void)
>>>  =C2=A0 {
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 riscv_v_setup_ctx_cache();
>>>  =C2=A0 }
>>> +
>>> +#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
>>> +static bool have_user_pmlen_7;
>>> +static bool have_user_pmlen_16;
>>> +
>>> +long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg)
>>> +{
>>> +=C2=A0=C2=A0=C2=A0 unsigned long valid_mask =3D PR_PMLEN_MASK;
>>> +=C2=A0=C2=A0=C2=A0 struct thread_info *ti =3D task_thread_info(task);
>>> +=C2=A0=C2=A0=C2=A0 unsigned long pmm;
>>> +=C2=A0=C2=A0=C2=A0 u8 pmlen;
>>> +
>>> +=C2=A0=C2=A0=C2=A0 if (is_compat_thread(ti))
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINVAL;
>>> +
>>> +=C2=A0=C2=A0=C2=A0 if (arg & ~valid_mask)
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINVAL;
>>> +
>>> +=C2=A0=C2=A0=C2=A0 pmlen =3D FIELD_GET(PR_PMLEN_MASK, arg);
>>> +=C2=A0=C2=A0=C2=A0 if (pmlen > 16) {
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINVAL;
>>> +=C2=A0=C2=A0=C2=A0 } else if (pmlen > 7) {
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (have_user_pmlen_16)
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pml=
en =3D 16;
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 else
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ret=
urn -EINVAL;
>>> +=C2=A0=C2=A0=C2=A0 } else if (pmlen > 0) {
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * Prefer the smallest=
 PMLEN that satisfies the user's request,
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * in case choosing a =
larger PMLEN has a performance impact.
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (have_user_pmlen_7)
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pml=
en =3D 7;
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 else if (have_user_pmlen_16=
)
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pml=
en =3D 16;
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 else
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ret=
urn -EINVAL;
>>> +=C2=A0=C2=A0=C2=A0 }
>>> +
>>> +=C2=A0=C2=A0=C2=A0 if (pmlen =3D=3D 7)
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmm =3D ENVCFG_PMM_PMLEN_7;
>>> +=C2=A0=C2=A0=C2=A0 else if (pmlen =3D=3D 16)
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmm =3D ENVCFG_PMM_PMLEN_16=
;
>>> +=C2=A0=C2=A0=C2=A0 else
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmm =3D ENVCFG_PMM_PMLEN_0;
>>> +
>>> +=C2=A0=C2=A0=C2=A0 envcfg_update_bits(task, ENVCFG_PMM, pmm);
>>> +
>>> +=C2=A0=C2=A0=C2=A0 return 0;
>>> +}
>>> +
>>> +long get_tagged_addr_ctrl(struct task_struct *task)
>>> +{
>>> +=C2=A0=C2=A0=C2=A0 struct thread_info *ti =3D task_thread_info(task);
>>> +=C2=A0=C2=A0=C2=A0 long ret =3D 0;
>>> +
>>> +=C2=A0=C2=A0=C2=A0 if (is_compat_thread(ti))
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINVAL;
>>> +
>>> +=C2=A0=C2=A0=C2=A0 switch (task->thread.envcfg & ENVCFG_PMM) {
>>> +=C2=A0=C2=A0=C2=A0 case ENVCFG_PMM_PMLEN_7:
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ret |=3D FIELD_PREP(PR_PMLE=
N_MASK, 7);
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 break;
>>> +=C2=A0=C2=A0=C2=A0 case ENVCFG_PMM_PMLEN_16:
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ret |=3D FIELD_PREP(PR_PMLE=
N_MASK, 16);
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 break;
>>> +=C2=A0=C2=A0=C2=A0 }
>>
>> No need for the |=3D
> This is used in the next patch since the returned value may include
> PR_TAGGED_ADDR_ENABLE as well, but it's not needed here, so I will make t=
his change.
>
>>> +
>>> +=C2=A0=C2=A0=C2=A0 return ret;
>>> +}
>>
>> In all the code above, I'd use a macro for 7 and 16, something like PMLE=
N[7|16]?
> I've done this using an enum in v4. Please let me know if it looks good t=
o you.


Great, thanks!


>
>>> +
>>> +static bool try_to_set_pmm(unsigned long value)
>>> +{
>>> +=C2=A0=C2=A0=C2=A0 csr_set(CSR_ENVCFG, value);
>>> +=C2=A0=C2=A0=C2=A0 return (csr_read_clear(CSR_ENVCFG, ENVCFG_PMM) & EN=
VCFG_PMM) =3D=3D value;
>>> +}
>>> +
>>> +static int __init tagged_addr_init(void)
>>> +{
>>> +=C2=A0=C2=A0=C2=A0 if (!riscv_has_extension_unlikely(RISCV_ISA_EXT_SUP=
M))
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>>> +
>>> +=C2=A0=C2=A0=C2=A0 /*
>>> +=C2=A0=C2=A0=C2=A0=C2=A0 * envcfg.PMM is a WARL field. Detect which va=
lues are supported.
>>> +=C2=A0=C2=A0=C2=A0=C2=A0 * Assume the supported PMLEN values are the s=
ame on all harts.
>>> +=C2=A0=C2=A0=C2=A0=C2=A0 */
>>> +=C2=A0=C2=A0=C2=A0 csr_clear(CSR_ENVCFG, ENVCFG_PMM);
>>> +=C2=A0=C2=A0=C2=A0 have_user_pmlen_7 =3D try_to_set_pmm(ENVCFG_PMM_PML=
EN_7);
>>> +=C2=A0=C2=A0=C2=A0 have_user_pmlen_16 =3D try_to_set_pmm(ENVCFG_PMM_PM=
LEN_16);
>>
>> Shouldn't this depend on the satp mode? sv57 does not allow 16bits for t=
he tag.
> No, late last year the pointer masking spec was changed so that the valid=
 values
> for PMM can no longer dynamically depend on satp.MODE. If an implementati=
on
> chooses to support both Sv57 and PMLEN=3D=3D16, then it does so by maskin=
g off some
> of the valid bits in the virtual address. (This is a valid if unusual use=
 case
> considering that pointer masking does not apply to instruction fetches, s=
o an
> application could place code at addresses above 2^47-1 and use the whole =
masked
> virtual address space for data. Or it could enable pointer masking for on=
ly
> certain threads, and those threads would be limited to a subset of data.)


I had forgotten that by default, we restrict sv57 user address space to=20
sv48, so that will work *unless* someone tries to map memory from above.=20
I'd say that if a user asks for sv57 and at the same time asks for=20
pointer masking with a tag of length 16, that's her fault :)


>
>>> +
>>> +=C2=A0=C2=A0=C2=A0 return 0;
>>> +}
>>> +core_initcall(tagged_addr_init);
>>
>> Any reason it's not called from setup_arch()? I see the vector extension=
 does
>> the same; just wondering if we should not centralize all this early exte=
nsions
>> decisions in setup_arch() (in my Zacas series, I choose the spinlock
>> implementation in setup_arch()).
>>
>>
>>> +#endif=C2=A0=C2=A0=C2=A0 /* CONFIG_RISCV_ISA_POINTER_MASKING */
>>> diff --git a/include/uapi/linux/prctl.h b/include/uapi/linux/prctl.h
>>> index 35791791a879..6e84c827869b 100644
>>> --- a/include/uapi/linux/prctl.h
>>> +++ b/include/uapi/linux/prctl.h
>>> @@ -244,6 +244,9 @@ struct prctl_mm_map {
>>>  =C2=A0 # define PR_MTE_TAG_MASK=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 (0xffffUL << PR_MTE_TAG_SHIFT)
>>>  =C2=A0 /* Unused; kept only for source compatibility */
>>>  =C2=A0 # define PR_MTE_TCF_SHIFT=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 1
>>> +/* RISC-V pointer masking tag length */
>>> +# define PR_PMLEN_SHIFT=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 24
>>> +# define PR_PMLEN_MASK=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 (0x7fUL << PR_PMLEN_SHIFT)
>>
>> I don't understand the need for this shift, can't userspace pass the pml=
en value
>> directly without worrying about this?
> No, because the PR_TAGGED_ADDR_ENABLE flag (bit 0, defined just a few lin=
es
> above) is part of the the same argument word. It's just not used until th=
e next
> patch.


Ok, I had missed that we use an already existing prctl. If you spin a=20
v4, can you "riscv" to this comment then=20
https://elixir.bootlin.com/linux/v6.11-rc3/source/include/uapi/linux/prctl.=
h#L233?

And did you add that to the man pages too?

Thanks,

Alex


>
> Regards,
> Samuel
>
>
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/02718edd-e061-4f2d-9a29-cdc7931727b3%40ghiti.fr.
