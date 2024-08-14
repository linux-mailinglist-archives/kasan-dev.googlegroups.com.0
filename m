Return-Path: <kasan-dev+bncBCMIFTP47IJBBUE46C2QMGQEZGQVUZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 640349511BD
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 03:54:26 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id 3f1490d57ef6-e0be1808a36sf9101173276.1
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2024 18:54:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723600465; cv=pass;
        d=google.com; s=arc-20160816;
        b=AM3JTvkBtu4OWDK+cHh7JcPmcpGpgu/Il16FQBAPTwvXYjzBrdPvZrkZaS0pIlN4PE
         pQOEut1dQZms2VDkDd8pQ/kBN8BSZUIkHV7F9HHHncXGAnUB10kj5odwUotqOTREPSvf
         aXmcZ8CpyvcJZMM9MvWYbmYSz1N4svDQSOHLtG8JRIvkLXZwSvsUaVLlHLDPlgtkjxD3
         UdAMJoyfNiXPmIqcHnK94UwTvd2cohOSxZGCH52gZ/HiLjW0yYBq8ppth+inWSAGGkuo
         JGNklwbg0NrEG6gORUZXpCINkYxI8VQv/w2/OINtlRjoAxg8uqQCubE2pGdO+WdiD04Q
         /pFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=tVXGnXDgjOiMEH5y6QyjzOyEym4zvese+QlMcHKsyRI=;
        fh=QRnyVOwu3wS4tbnxAPdrgumvm0cPUA7sW8z88b42968=;
        b=NLkhlUUJxxp1vIhyrvBXViyoQoHcUCD/3RqvWdMy1AIa9oOeszHD+eOe5Am3bUFC37
         8eyud1BeDyGIUZlDTQ0hOt87VP0c1/mVBasHPxBVgCULhtvTSpoPkEqeYDbqOp1unveQ
         lK+6ze6mnmfjmlBo3tD6j3hh8oEg8faLHEua3a7buKNZTpgbOALex6qsfE/RYGSogD6X
         9k3hW2SnvpKJOX01wFRDl239z59t9uL70/U8QavXBLegYuoHTnohP88aardrq1WnYToq
         ZfnFXVVfzUTBc2JlOD0SFIemzURZZvqQhmOoNCyRKlEl2+PNDbcju65J7++l6eKDqDaa
         WS3Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=Hkx3Io6N;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723600465; x=1724205265; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tVXGnXDgjOiMEH5y6QyjzOyEym4zvese+QlMcHKsyRI=;
        b=aZCT+MX9v5FXrC3HUfS3oahYDltXFOVIiiy3Mr/h6CFmXscLHOhycWzefzLjrZzgxx
         twIpdq++J12NRiShgJ0/8hQPrweSsl23HWLfSxVML92ZRdE74sp9h5OXB4FDRZacDMfp
         pen969gJFMvDzEv57WPsSFNqlqJR/cMtMqplAjmLFQwQtu09bW/dyO4zXT/yLZ9qsG8l
         KFS9FNcZfVJdjGc8j2psxGYm827s1HSjqQpL2KsVuwxKzDjp4xm2Lmjv84QIp5w13Jrb
         p0bPFM54GnOCucRG8Pg9jMRXZavSEIaoc8YGqhJum5kBF/pB7py/0xMcWireF71s2o7x
         tqQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723600465; x=1724205265;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tVXGnXDgjOiMEH5y6QyjzOyEym4zvese+QlMcHKsyRI=;
        b=fGYJCzOyYvnAZdFd6uj2QLTE0oduiO+PBJSWfc6q7YdJL5ktTBJ2YVH6nJ42jDI+z8
         srXMKt6zVzEcJlkZivya/jEAYqqdqYfwiZEx9dvaNJYUdTty6jZO0O0ItEJXiw3IK1nr
         +zqhDFlqSoeb/NJTM6AGuEidXtFTfBgGcZn1LhpaLe1t0gNd+jUQNACbliH1oCBceLAk
         ycX4p9YllPwUYVGn3trimBtpwlReLMaRwrhvUFNOa5WQwY/cgY9uXra5Jg5XJ3M//qRN
         RvJgxyNm7k4eG/BS9AdGZ/CKYGY2Vehvskk6uRPu5XlKcy3bD3joi3UpEaE8aJl8VpuN
         9mlA==
X-Forwarded-Encrypted: i=2; AJvYcCUG++jJngdiquz+WWAn2MnijmTnWcJ4CjWVzjTmO7MPRdES/bFUIV2drhnke3Ue1FjMeDCzqlXDAdkhMxjAdPIqZV/WxSI8TA==
X-Gm-Message-State: AOJu0YwA/PmKs7FRuJaxiVKZpYgcSFJZfcMZbVkidw8SuDnBSwnIsI9G
	ie4LzXYAh8L6Fwt6UqHgnsUlON6VYrkbYPP4A+YHWFjEIYbJ4Avi
X-Google-Smtp-Source: AGHT+IEn2FOuPVWyJgXZ5hIVXi93B1VR9YeSl59cel9sxrQ6MUh6gCsyFGn/L/lUYn7IPsMwgr8+gw==
X-Received: by 2002:a05:6902:1007:b0:e08:5554:b2cd with SMTP id 3f1490d57ef6-e1155a42df8mr1417069276.4.1723600464913;
        Tue, 13 Aug 2024 18:54:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ad56:0:b0:e0e:af58:f006 with SMTP id 3f1490d57ef6-e0eaf58f40els1131129276.1.-pod-prod-05-us;
 Tue, 13 Aug 2024 18:54:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVEdz8XLiyptMTYhxOxoYn3mRGiWaMNMgMDA4ML6jJYbMAUH7cUu/mJgaaFVMFajRmfvckCf+qhrMUw5c34T5WE5CPS5TsXWhGtVw==
X-Received: by 2002:a05:6902:1896:b0:e0b:2c11:bc4 with SMTP id 3f1490d57ef6-e1155a41fcamr1724124276.6.1723600464071;
        Tue, 13 Aug 2024 18:54:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723600464; cv=none;
        d=google.com; s=arc-20160816;
        b=aUcxhVfpwHyAesYv4GsUQf7puM8+ZiEQoy/NIuiH4E/+YsnbBeZFUnvNUKdwBDFzjM
         PcQHh/j3ptRp15ZT47jQniARnsDh4RqA+q0q6gvgXZV2Y1FtaW5tyKHimnA7AfX3SSho
         p5gNtABd6M2jlNyUTgsuT9Q+nCuvskPvZ1b6jPkjFq/rXYIVyDwdOYBTwG0s9CraJlar
         oT1vRHE5ddPKKQZrmmFlgZas3ilxgUFQBRhBlFdw4+MSXy/pNBMIirfsiVTFXoyIA/ZD
         CRizWJEAlywSEMe1jpxY07mCAHt0+CDj1k1Ze8HfL2aD2xqNJ+cxc3s5eWwUUgmseDLw
         hGww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=p6pmULMAGWWHjRqkutdIwNmS0SAJKLB9nOZJ5sh6Gzk=;
        fh=rtxA2ja0m8rd0KpgJfgPyrTmfRGrN/qKOm4k4Xn/cBg=;
        b=pE4lYnPzpSfE9hExThxU3GmN3nAduX/79D4Goq3PkXmmBqdWpWHUZ+RpCWxT2IN/pZ
         CCeOB+v4kFg249QL7ZCcFdmfqhNnv4C7FFmedioGAC1luxqzC3c1cSmAVlTkbkMk7Prk
         MbIVTlXqrXAumZj78IRQicAyUExgSYrI7P32D6/1W99gQTeuqcuwe+DJz2mjtA+jJkK/
         rEj4N+PIXfUTL7PYWmYFJnihHHDlrgXVEu9fTdmO0AawJcaMQvrYJll99HDKhsOKPG/+
         zWYbqGbkR5NkrUYarEijz8T13nhEM15bUcVQ3xbBagdPcAVfClLtb35YS9Or2twSQwJb
         VQ8w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=Hkx3Io6N;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-io1-xd2a.google.com (mail-io1-xd2a.google.com. [2607:f8b0:4864:20::d2a])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e1158f9f31asi23313276.0.2024.08.13.18.54.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Aug 2024 18:54:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::d2a as permitted sender) client-ip=2607:f8b0:4864:20::d2a;
Received: by mail-io1-xd2a.google.com with SMTP id ca18e2360f4ac-81f86fd9305so328609339f.0
        for <kasan-dev@googlegroups.com>; Tue, 13 Aug 2024 18:54:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWywg1XhVUXU5IjHeME9oXj5ml/AYFGeClNuMdwnpS799D3DQXrh9oj8E7NiRUKbOHFf1dWEcpKlvJttYFVtMsm6UCkaUus9s9Q6w==
X-Received: by 2002:a05:6602:3f91:b0:822:3d11:107a with SMTP id ca18e2360f4ac-824dacda2ecmr182325039f.4.1723600463386;
        Tue, 13 Aug 2024 18:54:23 -0700 (PDT)
Received: from [100.64.0.1] ([147.124.94.167])
        by smtp.gmail.com with ESMTPSA id 8926c6da1cb9f-4ca7695d26csm2890726173.84.2024.08.13.18.54.22
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Aug 2024 18:54:22 -0700 (PDT)
Message-ID: <dc8da1d4-435a-4786-b4bc-7f89590c2269@sifive.com>
Date: Tue, 13 Aug 2024 20:54:21 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 04/10] riscv: Add support for userspace pointer masking
To: Alexandre Ghiti <alex@ghiti.fr>, Palmer Dabbelt <palmer@dabbelt.com>,
 linux-riscv@lists.infradead.org
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
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: en-US
In-Reply-To: <440ca2a7-9dfb-45cd-8331-a8d0afff47d0@ghiti.fr>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=Hkx3Io6N;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

Hi Alex,

Thanks for the review!

On 2024-08-13 3:58 AM, Alexandre Ghiti wrote:
> Hi Samuel,
>=20
> On 25/06/2024 23:09, Samuel Holland wrote:
>> RISC-V supports pointer masking with a variable number of tag bits
>> (which is called "PMLEN" in the specification) and which is configured
>> at the next higher privilege level.
>>
>> Wire up the PR_SET_TAGGED_ADDR_CTRL and PR_GET_TAGGED_ADDR_CTRL prctls
>> so userspace can request a lower bound on the=C2=A0 number of tag bits a=
nd
>> determine the actual number of tag bits. As with arm64's
>> PR_TAGGED_ADDR_ENABLE, the pointer masking configuration is
>> thread-scoped, inherited on clone() and fork() and cleared on execve().
>>
>> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
>> ---
>>
>> Changes in v2:
>> =C2=A0 - Rebase on riscv/linux.git for-next
>> =C2=A0 - Add and use the envcfg_update_bits() helper function
>> =C2=A0 - Inline flush_tagged_addr_state()
>>
>> =C2=A0 arch/riscv/Kconfig=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 11 ++++
>> =C2=A0 arch/riscv/include/asm/processor.h |=C2=A0 8 +++
>> =C2=A0 arch/riscv/include/asm/switch_to.h | 11 ++++
>> =C2=A0 arch/riscv/kernel/process.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 99 ++++++++++++++++++++++++++++++
>> =C2=A0 include/uapi/linux/prctl.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0 |=C2=A0 3 +
>> =C2=A0 5 files changed, 132 insertions(+)
>>
>> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
>> index b94176e25be1..8f9980f81ea5 100644
>> --- a/arch/riscv/Kconfig
>> +++ b/arch/riscv/Kconfig
>> @@ -505,6 +505,17 @@ config RISCV_ISA_C
>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 If you don't know what=
 to do here, say Y.
>> =C2=A0 +config RISCV_ISA_POINTER_MASKING
>> +=C2=A0=C2=A0=C2=A0 bool "Smmpm, Smnpm, and Ssnpm extensions for pointer=
 masking"
>> +=C2=A0=C2=A0=C2=A0 depends on 64BIT
>> +=C2=A0=C2=A0=C2=A0 default y
>> +=C2=A0=C2=A0=C2=A0 help
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 Add support for the pointer masking exte=
nsions (Smmpm, Smnpm,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 and Ssnpm) when they are detected at boo=
t.
>> +
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 If this option is disabled, userspace wi=
ll be unable to use
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 the prctl(PR_{SET,GET}_TAGGED_ADDR_CTRL)=
 API.
>> +
>> =C2=A0 config RISCV_ISA_SVNAPOT
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 bool "Svnapot extension support for super=
visor mode NAPOT pages"
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 depends on 64BIT && MMU
>> diff --git a/arch/riscv/include/asm/processor.h
>> b/arch/riscv/include/asm/processor.h
>> index 0838922bd1c8..4f99c85d29ae 100644
>> --- a/arch/riscv/include/asm/processor.h
>> +++ b/arch/riscv/include/asm/processor.h
>> @@ -194,6 +194,14 @@ extern int set_unalign_ctl(struct task_struct *tsk,
>> unsigned int val);
>> =C2=A0 #define RISCV_SET_ICACHE_FLUSH_CTX(arg1, arg2)=C2=A0=C2=A0=C2=A0
>> riscv_set_icache_flush_ctx(arg1, arg2)
>> =C2=A0 extern int riscv_set_icache_flush_ctx(unsigned long ctx, unsigned=
 long
>> per_thread);
>> =C2=A0 +#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
>> +/* PR_{SET,GET}_TAGGED_ADDR_CTRL prctl */
>> +long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg);
>> +long get_tagged_addr_ctrl(struct task_struct *task);
>> +#define SET_TAGGED_ADDR_CTRL(arg)=C2=A0=C2=A0=C2=A0 set_tagged_addr_ctr=
l(current, arg)
>> +#define GET_TAGGED_ADDR_CTRL()=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 get_tagged_addr_ctrl(current)
>> +#endif
>> +
>> =C2=A0 #endif /* __ASSEMBLY__ */
>> =C2=A0 =C2=A0 #endif /* _ASM_RISCV_PROCESSOR_H */
>> diff --git a/arch/riscv/include/asm/switch_to.h
>> b/arch/riscv/include/asm/switch_to.h
>> index 9685cd85e57c..94e33216b2d9 100644
>> --- a/arch/riscv/include/asm/switch_to.h
>> +++ b/arch/riscv/include/asm/switch_to.h
>> @@ -70,6 +70,17 @@ static __always_inline bool has_fpu(void) { return fa=
lse; }
>> =C2=A0 #define __switch_to_fpu(__prev, __next) do { } while (0)
>> =C2=A0 #endif
>> =C2=A0 +static inline void envcfg_update_bits(struct task_struct *task,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long mas=
k, unsigned long val)
>> +{
>> +=C2=A0=C2=A0=C2=A0 unsigned long envcfg;
>> +
>> +=C2=A0=C2=A0=C2=A0 envcfg =3D (task->thread.envcfg & ~mask) | val;
>> +=C2=A0=C2=A0=C2=A0 task->thread.envcfg =3D envcfg;
>> +=C2=A0=C2=A0=C2=A0 if (task =3D=3D current)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 csr_write(CSR_ENVCFG, envcfg=
);
>> +}
>> +
>> =C2=A0 static inline void __switch_to_envcfg(struct task_struct *next)
>> =C2=A0 {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 asm volatile (ALTERNATIVE("nop", "csrw " =
__stringify(CSR_ENVCFG) ", %0",
>> diff --git a/arch/riscv/kernel/process.c b/arch/riscv/kernel/process.c
>> index e4bc61c4e58a..dec5ccc44697 100644
>> --- a/arch/riscv/kernel/process.c
>> +++ b/arch/riscv/kernel/process.c
>> @@ -7,6 +7,7 @@
>> =C2=A0=C2=A0 * Copyright (C) 2017 SiFive
>> =C2=A0=C2=A0 */
>> =C2=A0 +#include <linux/bitfield.h>
>> =C2=A0 #include <linux/cpu.h>
>> =C2=A0 #include <linux/kernel.h>
>> =C2=A0 #include <linux/sched.h>
>> @@ -171,6 +172,10 @@ void flush_thread(void)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memset(&current->thread.vstate, 0, sizeof=
(struct __riscv_v_ext_state));
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 clear_tsk_thread_flag(current, TIF_RISCV_=
V_DEFER_RESTORE);
>> =C2=A0 #endif
>> +#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
>> +=C2=A0=C2=A0=C2=A0 if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM)=
)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 envcfg_update_bits(current, =
ENVCFG_PMM, ENVCFG_PMM_PMLEN_0);
>> +#endif
>=20
> if (IS_ENABLED(CONFIG_RISCV_ISA_POINTER_MASKING) &&
> riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM))

I will update this.

>> =C2=A0 }
>> =C2=A0 =C2=A0 void arch_release_task_struct(struct task_struct *tsk)
>> @@ -233,3 +238,97 @@ void __init arch_task_cache_init(void)
>> =C2=A0 {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 riscv_v_setup_ctx_cache();
>> =C2=A0 }
>> +
>> +#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
>> +static bool have_user_pmlen_7;
>> +static bool have_user_pmlen_16;
>> +
>> +long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg)
>> +{
>> +=C2=A0=C2=A0=C2=A0 unsigned long valid_mask =3D PR_PMLEN_MASK;
>> +=C2=A0=C2=A0=C2=A0 struct thread_info *ti =3D task_thread_info(task);
>> +=C2=A0=C2=A0=C2=A0 unsigned long pmm;
>> +=C2=A0=C2=A0=C2=A0 u8 pmlen;
>> +
>> +=C2=A0=C2=A0=C2=A0 if (is_compat_thread(ti))
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINVAL;
>> +
>> +=C2=A0=C2=A0=C2=A0 if (arg & ~valid_mask)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINVAL;
>> +
>> +=C2=A0=C2=A0=C2=A0 pmlen =3D FIELD_GET(PR_PMLEN_MASK, arg);
>> +=C2=A0=C2=A0=C2=A0 if (pmlen > 16) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINVAL;
>> +=C2=A0=C2=A0=C2=A0 } else if (pmlen > 7) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (have_user_pmlen_16)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmle=
n =3D 16;
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 else
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 retu=
rn -EINVAL;
>> +=C2=A0=C2=A0=C2=A0 } else if (pmlen > 0) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * Prefer the smallest =
PMLEN that satisfies the user's request,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * in case choosing a l=
arger PMLEN has a performance impact.
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (have_user_pmlen_7)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmle=
n =3D 7;
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 else if (have_user_pmlen_16)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmle=
n =3D 16;
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 else
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 retu=
rn -EINVAL;
>> +=C2=A0=C2=A0=C2=A0 }
>> +
>> +=C2=A0=C2=A0=C2=A0 if (pmlen =3D=3D 7)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmm =3D ENVCFG_PMM_PMLEN_7;
>> +=C2=A0=C2=A0=C2=A0 else if (pmlen =3D=3D 16)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmm =3D ENVCFG_PMM_PMLEN_16;
>> +=C2=A0=C2=A0=C2=A0 else
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmm =3D ENVCFG_PMM_PMLEN_0;
>> +
>> +=C2=A0=C2=A0=C2=A0 envcfg_update_bits(task, ENVCFG_PMM, pmm);
>> +
>> +=C2=A0=C2=A0=C2=A0 return 0;
>> +}
>> +
>> +long get_tagged_addr_ctrl(struct task_struct *task)
>> +{
>> +=C2=A0=C2=A0=C2=A0 struct thread_info *ti =3D task_thread_info(task);
>> +=C2=A0=C2=A0=C2=A0 long ret =3D 0;
>> +
>> +=C2=A0=C2=A0=C2=A0 if (is_compat_thread(ti))
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINVAL;
>> +
>> +=C2=A0=C2=A0=C2=A0 switch (task->thread.envcfg & ENVCFG_PMM) {
>> +=C2=A0=C2=A0=C2=A0 case ENVCFG_PMM_PMLEN_7:
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ret |=3D FIELD_PREP(PR_PMLEN=
_MASK, 7);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 break;
>> +=C2=A0=C2=A0=C2=A0 case ENVCFG_PMM_PMLEN_16:
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ret |=3D FIELD_PREP(PR_PMLEN=
_MASK, 16);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 break;
>> +=C2=A0=C2=A0=C2=A0 }
>=20
>=20
> No need for the |=3D

This is used in the next patch since the returned value may include
PR_TAGGED_ADDR_ENABLE as well, but it's not needed here, so I will make thi=
s change.

>> +
>> +=C2=A0=C2=A0=C2=A0 return ret;
>> +}
>=20
>=20
> In all the code above, I'd use a macro for 7 and 16, something like PMLEN=
[7|16]?

I've done this using an enum in v4. Please let me know if it looks good to =
you.

>> +
>> +static bool try_to_set_pmm(unsigned long value)
>> +{
>> +=C2=A0=C2=A0=C2=A0 csr_set(CSR_ENVCFG, value);
>> +=C2=A0=C2=A0=C2=A0 return (csr_read_clear(CSR_ENVCFG, ENVCFG_PMM) & ENV=
CFG_PMM) =3D=3D value;
>> +}
>> +
>> +static int __init tagged_addr_init(void)
>> +{
>> +=C2=A0=C2=A0=C2=A0 if (!riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM=
))
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>> +
>> +=C2=A0=C2=A0=C2=A0 /*
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * envcfg.PMM is a WARL field. Detect which val=
ues are supported.
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * Assume the supported PMLEN values are the sa=
me on all harts.
>> +=C2=A0=C2=A0=C2=A0=C2=A0 */
>> +=C2=A0=C2=A0=C2=A0 csr_clear(CSR_ENVCFG, ENVCFG_PMM);
>> +=C2=A0=C2=A0=C2=A0 have_user_pmlen_7 =3D try_to_set_pmm(ENVCFG_PMM_PMLE=
N_7);
>> +=C2=A0=C2=A0=C2=A0 have_user_pmlen_16 =3D try_to_set_pmm(ENVCFG_PMM_PML=
EN_16);
>=20
>=20
> Shouldn't this depend on the satp mode? sv57 does not allow 16bits for th=
e tag.

No, late last year the pointer masking spec was changed so that the valid v=
alues
for PMM can no longer dynamically depend on satp.MODE. If an implementation
chooses to support both Sv57 and PMLEN=3D=3D16, then it does so by masking =
off some
of the valid bits in the virtual address. (This is a valid if unusual use c=
ase
considering that pointer masking does not apply to instruction fetches, so =
an
application could place code at addresses above 2^47-1 and use the whole ma=
sked
virtual address space for data. Or it could enable pointer masking for only
certain threads, and those threads would be limited to a subset of data.)

>> +
>> +=C2=A0=C2=A0=C2=A0 return 0;
>> +}
>> +core_initcall(tagged_addr_init);
>=20
>=20
> Any reason it's not called from setup_arch()? I see the vector extension =
does
> the same; just wondering if we should not centralize all this early exten=
sions
> decisions in setup_arch() (in my Zacas series, I choose the spinlock
> implementation in setup_arch()).
>=20
>=20
>> +#endif=C2=A0=C2=A0=C2=A0 /* CONFIG_RISCV_ISA_POINTER_MASKING */
>> diff --git a/include/uapi/linux/prctl.h b/include/uapi/linux/prctl.h
>> index 35791791a879..6e84c827869b 100644
>> --- a/include/uapi/linux/prctl.h
>> +++ b/include/uapi/linux/prctl.h
>> @@ -244,6 +244,9 @@ struct prctl_mm_map {
>> =C2=A0 # define PR_MTE_TAG_MASK=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 (0xffffUL << PR_MTE_TAG_SHIFT)
>> =C2=A0 /* Unused; kept only for source compatibility */
>> =C2=A0 # define PR_MTE_TCF_SHIFT=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 1
>> +/* RISC-V pointer masking tag length */
>> +# define PR_PMLEN_SHIFT=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 24
>> +# define PR_PMLEN_MASK=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 (0x7fUL << PR_PMLEN_SHIFT)
>=20
>=20
> I don't understand the need for this shift, can't userspace pass the pmle=
n value
> directly without worrying about this?

No, because the PR_TAGGED_ADDR_ENABLE flag (bit 0, defined just a few lines
above) is part of the the same argument word. It's just not used until the =
next
patch.

Regards,
Samuel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/dc8da1d4-435a-4786-b4bc-7f89590c2269%40sifive.com.
