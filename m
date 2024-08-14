Return-Path: <kasan-dev+bncBCMIFTP47IJBBB5P6G2QMGQEVGC7IFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 288499514F5
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 09:06:50 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-2cb6b642c49sf553619a91.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 00:06:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723619208; cv=pass;
        d=google.com; s=arc-20160816;
        b=B0FvmSkEM65R4gghO6DFyfABGgUJLI1LN/lNxiDPfVG/m/ZZ//FzIlUstpT67K6mRk
         t9d0jo/vnQh+16Hp3M/3s/zDOKC+yqwUq74d7Ao0CSTDDArK3IvUgOPAqlJHJvO2H/1C
         Fcu00Xi+VYkLVFtums7r4RCkwasZJI3MUUzbBvM1G6qKt5lRIsKgk/pwLLxQnyYDPjio
         3CdU23WXZ6QgqQg07MIonvPVS++jh8djTb63K4lNA+1wfJBTWcKZSN9He8J8KKd/Xia2
         PZZAWLaa8HPwwtAmvDn5uptRUaHV9OO0CQ2lgYYCX6nHMXNe7YkEhtZqwJZakZux9BK9
         E/2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:content-language:references:cc:to:from:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=5uTkKBd44cf5KzqVQ3lzy1OMXiRtCazj8C4mpzkWsQo=;
        fh=c2HYNmtSNM4I37vVOEyvO0HDnt6YzIYm1w8OjFNBJAU=;
        b=wAHL2OZIsTgXuMIhfkJdq98BPx9lcJqJAPm762j9OITX4xVVU2x4CoivGYkK9jbGDQ
         9ZsPrIzzuSzcUuqlBJp99Z0oQ4QWdoa5/s94wRWJdM2F0Lv+ByDl0i7q+sYTCXe1UfoN
         tioK0xqJOIuUjdjlWglPpFKDh3qCS8f0uzaPDSJ+k9z+kiM2yQC0E14QaHXiPLDo6idQ
         i8r1U+zYcjKYx/sjC350wEhcElRAZrx+aIUBG3LPgnF2gfpC/oGSJ9qPc9XXAznOj4jx
         /lJObCRfyGyLFHSeoJ0vPzhGm0KglQJ3JAbzdZCQMj2Yjy59n/XcMxmEy8f9tnpsWHET
         WJ9w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=FfzdnPoc;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723619208; x=1724224008; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:references
         :cc:to:from:subject:user-agent:mime-version:date:message-id:from:to
         :cc:subject:date:message-id:reply-to;
        bh=5uTkKBd44cf5KzqVQ3lzy1OMXiRtCazj8C4mpzkWsQo=;
        b=nPI3NcWrBd20pzOhCE4qN2CLfMusny2biriuF9Ht2j26LTfgiaw2P46iYErUoIWkuD
         IkEd56r1uTO4zS/j9GjPBpkRF536XLkDj61Qnqv7YeNH7Qq9LYEKxSwVUN7RltfWR2sm
         8BOAjRU9WakLDIc2L7PawU4ALVoiYfykNgDQj51nh08QwRJyl70tA0O7M3VrxrYgTdAB
         IllgLYVKz8xumvIgySKHwHVfIr29NWUUiHPVhwHY5Pqkt4c/mxa+vQL1+8znpnDWQ7vY
         tf8yTcQb/ZxDVXeyA/YosGF9QjKBHCrAkSplklmi8aDnaR5mr77xq80Nii+niqZl0GLU
         rtFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723619208; x=1724224008;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:references
         :cc:to:from:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5uTkKBd44cf5KzqVQ3lzy1OMXiRtCazj8C4mpzkWsQo=;
        b=dHsIOn5e1dm6/4GVB1lOmGh4GZAtSSA9dOxqJit3b6lHmKdybDi8ievQ83fDGBjde5
         TO40wzcIO1hz8f6WRNnnWhBCiIo7pMGT1SxMci1h58JAe05tDpt9XY/uOPd+V4L57aH9
         0OKhWlvqYR/ng+ebuySzlODUlSLjI9nIUUBAC8fJi2f5L6K4Qan8tEIMnoDnizwJpiGL
         Arfvq1eh+KYANA1RYA5eIrbv8dWsI2mt3wKTylNm2MJaFkCfVIrGDzlPBmrnTes/ivUx
         z5yyYEDDFRoOQKMMF/Nv6+2R01oMyh3BYq1fxubE90WSlojQOlZJtBGTSemEQtuW9jMy
         ucvg==
X-Forwarded-Encrypted: i=2; AJvYcCVbkF4F/azfdjY3HxgQqbG3htyNmWmG0dWbNyywSN3A0mWbZ7Ew21fRB9UMp3oMFhhW+kqmJTkp0bs/1saS/LnRgsD2a+TIDQ==
X-Gm-Message-State: AOJu0Yx4jo92hb/YhsMeuhjE4jWVifaz9vQkbMwC9pGIS1q7nzxB+MS9
	OLYR+z1Zrw5Hmsomfekw0mbMQWvHvvpdX4u3c/6dR5YAoaJJuTMo
X-Google-Smtp-Source: AGHT+IEbJ1RXlBsYR/P6Kv7PvzrcPZjAyIcOpShgMr5p7Hm0c9IX9544b7spb5pY6CIQ3uwu4fmpaw==
X-Received: by 2002:a17:90a:f2d4:b0:2c8:f3b5:7dd1 with SMTP id 98e67ed59e1d1-2d3ace552eamr1994089a91.16.1723619208070;
        Wed, 14 Aug 2024 00:06:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ca12:b0:2c7:50ae:5c1b with SMTP id
 98e67ed59e1d1-2d3aa8f735fls359973a91.2.-pod-prod-00-us; Wed, 14 Aug 2024
 00:06:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUP5IZPsiAzI0+IQorMd33rlFrm+SWMm7GS5OLsvyw83hvegudXq80BQO+tefPZWALQU0Cx3dkPPdZ8MWv+GiHCW6lBpQ7VWoLWTA==
X-Received: by 2002:a17:90a:d586:b0:2c9:6abd:ca64 with SMTP id 98e67ed59e1d1-2d3acbf5253mr1906920a91.9.1723619206615;
        Wed, 14 Aug 2024 00:06:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723619206; cv=none;
        d=google.com; s=arc-20240605;
        b=TTw1GQ+DDKCfTeabL/azNOmqbvgqMqOSJnOKQDEUIRC3dGc9Dq0vBH05KPAoZQY1HF
         FDKpsPbPHvuvmidiGzYJ+vI1CL7fH4xd24HUI3F7fkMwAUF8U9eW0A39fXqCq7cDMEEB
         mkIEoi74ksM+fP8NXw0+jx0but52wBZM9h0ooF1zY6zVYCXACl/50/cLT3suwwT9oSn8
         PzPuo7T2PIR05OJlni3D/xV89D1vM3LANRZYfA0qX0Ea4wiXf4dVVAbtgcs9pNm9Dknh
         WUuvnNz+hglGFHpcrPDi8P4gd3gpCcfAv24Rz3dsXueKALdQhyee+ZHEP3R0Eo0mx9G7
         RifQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:references
         :cc:to:from:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=sTHU8iXlEqUwgCimuhc001HOr+meABY+UioHyXt5kKk=;
        fh=9FOAVLSLYH0tZu2a/cYw+ya4kKVeMam7dvip+iyUKjk=;
        b=lQiIO7fDmZCExFuCCaIjeyb2HMgkROFnn9QY8YTY2lIH/JV6eLee973ca4b41ZTGBl
         LER7iEeA4lF/xSamb0pZo+0aPP27OFl2/JNvr9NQ033ycjGTmY74mVfp9yy4naOdIyr9
         XIppt57F9AbZMmMQq5p72rNOwgVjUbWM1zrLyX5uofgFzaJOqokaaqAvAWKYPMbTb0tc
         uVrait5t2j30Jjd6ouxGdH7LlXpnD57qe5ZNfE6J1QFxFZiVdIXMGe67PYU7WjIAlCNj
         uLkqCgVEA7QapoyuK5X4DFE0wzncBexUsAIoX4cNIb4Hy/JQA/jF0TOqi0agJ9uf6oOf
         jnAw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=FfzdnPoc;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-io1-xd2b.google.com (mail-io1-xd2b.google.com. [2607:f8b0:4864:20::d2b])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2d3ac852da9si33242a91.3.2024.08.14.00.06.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 00:06:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::d2b as permitted sender) client-ip=2607:f8b0:4864:20::d2b;
Received: by mail-io1-xd2b.google.com with SMTP id ca18e2360f4ac-81f86fd93acso24191939f.1
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 00:06:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVey2tJ6QTyfWTMuHDNrQTlszf6qkcy1KP8DNi0hz3LlSf5bulBM07b5FKuZ0JvMigyVrW4WpSxrZteg7eaXxp1q1GFCMXn/YBn/g==
X-Received: by 2002:a05:6e02:154d:b0:39d:184c:19b0 with SMTP id e9e14a558f8ab-39d184c1b38mr1818145ab.10.1723619205757;
        Wed, 14 Aug 2024 00:06:45 -0700 (PDT)
Received: from [100.64.0.1] ([147.124.94.167])
        by smtp.gmail.com with ESMTPSA id 8926c6da1cb9f-4ca76a367e2sm3019621173.150.2024.08.14.00.06.44
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 00:06:45 -0700 (PDT)
Message-ID: <fc65fc29-4cd8-4e41-93e4-a35e3c8998d8@sifive.com>
Date: Wed, 14 Aug 2024 02:06:43 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 04/10] riscv: Add support for userspace pointer masking
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
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
 <dc8da1d4-435a-4786-b4bc-7f89590c2269@sifive.com>
Content-Language: en-US
In-Reply-To: <dc8da1d4-435a-4786-b4bc-7f89590c2269@sifive.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=FfzdnPoc;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

On 2024-08-13 8:54 PM, Samuel Holland wrote:
> Hi Alex,
>=20
> Thanks for the review!
>=20
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
>>> =C2=A0 - Rebase on riscv/linux.git for-next
>>> =C2=A0 - Add and use the envcfg_update_bits() helper function
>>> =C2=A0 - Inline flush_tagged_addr_state()
>>>
>>> =C2=A0 arch/riscv/Kconfig=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 11 ++++
>>> =C2=A0 arch/riscv/include/asm/processor.h |=C2=A0 8 +++
>>> =C2=A0 arch/riscv/include/asm/switch_to.h | 11 ++++
>>> =C2=A0 arch/riscv/kernel/process.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 99 ++++++++++++++++++++++++++++++
>>> =C2=A0 include/uapi/linux/prctl.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 |=C2=A0 3 +
>>> =C2=A0 5 files changed, 132 insertions(+)
>>>
>>> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
>>> index b94176e25be1..8f9980f81ea5 100644
>>> --- a/arch/riscv/Kconfig
>>> +++ b/arch/riscv/Kconfig
>>> @@ -505,6 +505,17 @@ config RISCV_ISA_C
>>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 If you don't know wha=
t to do here, say Y.
>>> =C2=A0 +config RISCV_ISA_POINTER_MASKING
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
>>> =C2=A0 config RISCV_ISA_SVNAPOT
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 bool "Svnapot extension support for supe=
rvisor mode NAPOT pages"
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 depends on 64BIT && MMU
>>> diff --git a/arch/riscv/include/asm/processor.h
>>> b/arch/riscv/include/asm/processor.h
>>> index 0838922bd1c8..4f99c85d29ae 100644
>>> --- a/arch/riscv/include/asm/processor.h
>>> +++ b/arch/riscv/include/asm/processor.h
>>> @@ -194,6 +194,14 @@ extern int set_unalign_ctl(struct task_struct *tsk=
,
>>> unsigned int val);
>>> =C2=A0 #define RISCV_SET_ICACHE_FLUSH_CTX(arg1, arg2)=C2=A0=C2=A0=C2=A0
>>> riscv_set_icache_flush_ctx(arg1, arg2)
>>> =C2=A0 extern int riscv_set_icache_flush_ctx(unsigned long ctx, unsigne=
d long
>>> per_thread);
>>> =C2=A0 +#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
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
>>> =C2=A0 #endif /* __ASSEMBLY__ */
>>> =C2=A0 =C2=A0 #endif /* _ASM_RISCV_PROCESSOR_H */
>>> diff --git a/arch/riscv/include/asm/switch_to.h
>>> b/arch/riscv/include/asm/switch_to.h
>>> index 9685cd85e57c..94e33216b2d9 100644
>>> --- a/arch/riscv/include/asm/switch_to.h
>>> +++ b/arch/riscv/include/asm/switch_to.h
>>> @@ -70,6 +70,17 @@ static __always_inline bool has_fpu(void) { return f=
alse; }
>>> =C2=A0 #define __switch_to_fpu(__prev, __next) do { } while (0)
>>> =C2=A0 #endif
>>> =C2=A0 +static inline void envcfg_update_bits(struct task_struct *task,
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
>>> =C2=A0 static inline void __switch_to_envcfg(struct task_struct *next)
>>> =C2=A0 {
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 asm volatile (ALTERNATIVE("nop", "csrw "=
 __stringify(CSR_ENVCFG) ", %0",
>>> diff --git a/arch/riscv/kernel/process.c b/arch/riscv/kernel/process.c
>>> index e4bc61c4e58a..dec5ccc44697 100644
>>> --- a/arch/riscv/kernel/process.c
>>> +++ b/arch/riscv/kernel/process.c
>>> @@ -7,6 +7,7 @@
>>> =C2=A0=C2=A0 * Copyright (C) 2017 SiFive
>>> =C2=A0=C2=A0 */
>>> =C2=A0 +#include <linux/bitfield.h>
>>> =C2=A0 #include <linux/cpu.h>
>>> =C2=A0 #include <linux/kernel.h>
>>> =C2=A0 #include <linux/sched.h>
>>> @@ -171,6 +172,10 @@ void flush_thread(void)
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memset(&current->thread.vstate, 0, sizeo=
f(struct __riscv_v_ext_state));
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 clear_tsk_thread_flag(current, TIF_RISCV=
_V_DEFER_RESTORE);
>>> =C2=A0 #endif
>>> +#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
>>> +=C2=A0=C2=A0=C2=A0 if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM=
))
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 envcfg_update_bits(current,=
 ENVCFG_PMM, ENVCFG_PMM_PMLEN_0);
>>> +#endif
>>
>> if (IS_ENABLED(CONFIG_RISCV_ISA_POINTER_MASKING) &&
>> riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM))
>=20
> I will update this.
>=20
>>> =C2=A0 }
>>> =C2=A0 =C2=A0 void arch_release_task_struct(struct task_struct *tsk)
>>> @@ -233,3 +238,97 @@ void __init arch_task_cache_init(void)
>>> =C2=A0 {
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 riscv_v_setup_ctx_cache();
>>> =C2=A0 }
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
>>
>> No need for the |=3D
>=20
> This is used in the next patch since the returned value may include
> PR_TAGGED_ADDR_ENABLE as well, but it's not needed here, so I will make t=
his change.
>=20
>>> +
>>> +=C2=A0=C2=A0=C2=A0 return ret;
>>> +}
>>
>>
>> In all the code above, I'd use a macro for 7 and 16, something like PMLE=
N[7|16]?
>=20
> I've done this using an enum in v4. Please let me know if it looks good t=
o you.

Obviously I meant to say v3 here.

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
>>
>> Shouldn't this depend on the satp mode? sv57 does not allow 16bits for t=
he tag.
>=20
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
>=20
>>> +
>>> +=C2=A0=C2=A0=C2=A0 return 0;
>>> +}
>>> +core_initcall(tagged_addr_init);
>>
>>
>> Any reason it's not called from setup_arch()? I see the vector extension=
 does
>> the same; just wondering if we should not centralize all this early exte=
nsions
>> decisions in setup_arch() (in my Zacas series, I choose the spinlock
>> implementation in setup_arch()).

Forgot to reply: no special reason, I copied this part of the code from arm=
64.
This code doesn't need to be called especially early; the only requirement =
is
that it runs before userspace starts. One advantage of core_initcall() is t=
hat
it happens after SMP bringup, so this way will have less impact on boot tim=
e.

Regards,
Samuel

>>> +#endif=C2=A0=C2=A0=C2=A0 /* CONFIG_RISCV_ISA_POINTER_MASKING */
>>> diff --git a/include/uapi/linux/prctl.h b/include/uapi/linux/prctl.h
>>> index 35791791a879..6e84c827869b 100644
>>> --- a/include/uapi/linux/prctl.h
>>> +++ b/include/uapi/linux/prctl.h
>>> @@ -244,6 +244,9 @@ struct prctl_mm_map {
>>> =C2=A0 # define PR_MTE_TAG_MASK=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 (0xffffUL << PR_MTE_TAG_SHIFT)
>>> =C2=A0 /* Unused; kept only for source compatibility */
>>> =C2=A0 # define PR_MTE_TCF_SHIFT=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 1
>>> +/* RISC-V pointer masking tag length */
>>> +# define PR_PMLEN_SHIFT=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 24
>>> +# define PR_PMLEN_MASK=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 (0x7fUL << PR_PMLEN_SHIFT)
>>
>>
>> I don't understand the need for this shift, can't userspace pass the pml=
en value
>> directly without worrying about this?
>=20
> No, because the PR_TAGGED_ADDR_ENABLE flag (bit 0, defined just a few lin=
es
> above) is part of the the same argument word. It's just not used until th=
e next
> patch.
>=20
> Regards,
> Samuel
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/fc65fc29-4cd8-4e41-93e4-a35e3c8998d8%40sifive.com.
