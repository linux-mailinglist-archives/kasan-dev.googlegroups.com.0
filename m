Return-Path: <kasan-dev+bncBCMIFTP47IJBBTPK4G3AMGQEYPKPJUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 923A696C169
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Sep 2024 16:57:19 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-71434a51126sf7433376b3a.0
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Sep 2024 07:57:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725461838; cv=pass;
        d=google.com; s=arc-20240605;
        b=L16yJuybJMl67Znh6mr4PLm3UD5Tk+7AV66KQHV+MNwBUUc6jy4VD77eHbGjRQMppz
         WXWaVMZvVNKoyFp9zxHFChJO7QA129lB0lpVleb2VZn42IZIOXoGOqrRMQkP3P0glUv7
         9NApxHDB69Yly0Iqq2gfzs4VzYbtXTiybkSRSxKaa7abj4uRY6TqPazFzED/IyM5TSlQ
         Y9QxxAQJUALaKM79bmdfoIXjv/fF5dpLzQusAgv3y34GVDAidSK1p2JJEDPE2XlzHQpl
         3bra8c3tnmiowTLIeE+wXOLsVK6d3Y+iCC1x+X0iFkRvQErp64cwIfILnz+jO89WcMtn
         HUuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=Y3gla00ttvCQT5tUuGSna2DvTc1gKE2CSjqLIVHISTo=;
        fh=9rw8di/Fu5kznF7sHGVqy6ZDIOKtSkWyn/WWb1sYbow=;
        b=UIXwtuBO17BBWSphZJ0iiZY0qPehxudYUQePTDpmZ5X7LMOQd4QzSYa10vvgdf15HX
         43vNqGSL3OH1Trd1p0y+2lD8byFfFU3tIQmoF2cFwKW1ZcRCiBaq/RB2bWmn2JD0lCaw
         loQkxW5wmls0d4eXawSiAM7pdxqa6p0U83kjIiaGw4S00N2Rr4EMsJFTEeUx/FMa0ETo
         RTyWmufRCFstEZkoB/Glny41zaKaWDoDMQdTXmtqzXyVkfcVxrXJeJtASqwt/BXcW5oC
         WQ99/WaN7QDz7dJSzg6pPJ9rIHNMxfOvfh8IOgFEcd7u1SQx1mC6JVnC0ZOHjtmdG/3H
         iYew==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=jRjJre8n;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::132 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725461838; x=1726066638; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Y3gla00ttvCQT5tUuGSna2DvTc1gKE2CSjqLIVHISTo=;
        b=uRECG5ibgDeWaGbrr8laLv6vsIw4FpoCcr0jzXFB5lEP8MBcpl5BylhsGB6rX+TQVC
         eDZafJ06fS7sKgm87WI4ATSlTnYPIUjlQaYnDXgK7hhEH4QiJqmM1Px0VZsxKI6jWhfZ
         Sfp8OriwOnMgfZ10GDDtFNbWHNO+/gmrolFAS6XsL+69v9SE0o6PCsVvRvnfgB4Kw6CC
         f4nbn9aNi1vaTJnDvU8DmRfiHzbT40CQGwmqcjdabxHOFuecgPY0DwJYPhBezkOmkDRA
         hlZulqO0YydvVtqtP9+iX8ntcS0aaE3iFV+pwZccLLzRNRiHNNThTOkX8QM4J7hIB0dq
         uiaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725461838; x=1726066638;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Y3gla00ttvCQT5tUuGSna2DvTc1gKE2CSjqLIVHISTo=;
        b=LrwP6u54XMzYAO1PvYbScmmMmNupBCF3/cBJOzegBd2ADyzQwNx/lCu4vz/GtfP0SB
         y9Ngj9oTANuqbj6oCvqTv0rAmFU9YUcH61wdvagTWeh7HM+pl/Fv6Yy/RVgbp62Z2d/l
         4FSmEx0FPnINnrteFnmsST5eT3b1lPLWcYcezGyF6vemCTA5OB7oJFRiekdSXiXaloAg
         qHAagR8g5CLba18b6htfhmw661hA2rytbE7pifdDCUCYq9TrA5uBoNVBbszjLvarr26Z
         JLnWokfUw3cR9ktVksUWaQqppFewIkpWC76cpQ6giYrzwGJwA2BnF+tOKzPCtCI2EUl0
         yDpg==
X-Forwarded-Encrypted: i=2; AJvYcCWDiFMY+xdamPVNswbEvr4XN6W/O03vjPifLNB62x+yGKpge/EtwTR54iRfo3+luWG+dfhgWA==@lfdr.de
X-Gm-Message-State: AOJu0YwhFGBe1yw0mccTAwDX3OAlMamS556idgHwMkFk4kE7Mo2NFAz8
	xXaX/tWsEqFLYSVq92XqT/4hhH7Q9v/4mKDVuQiEWmprzDa7SyGA
X-Google-Smtp-Source: AGHT+IGlQGG7DO/tzNRoqQawazFgINknVb8GcbX1rmun+ZmI/fv5+bhKygPePUAnuSVleCYaPgZmiQ==
X-Received: by 2002:a05:6a21:9206:b0:1cc:ddd7:b091 with SMTP id adf61e73a8af0-1ced617dc46mr13550725637.20.1725461837803;
        Wed, 04 Sep 2024 07:57:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:b018:b0:2d8:d2c6:e0b8 with SMTP id
 98e67ed59e1d1-2d8d2c6ebccls1802227a91.2.-pod-prod-04-us; Wed, 04 Sep 2024
 07:57:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXKM03j+AWHamv5JD+2QZ9cGjplyifa6J/gmK8meL+YZuqD34bZUmuANGZQ/R0VExVIujc1Rk9Hxmc=@googlegroups.com
X-Received: by 2002:a05:6a21:918c:b0:1c6:ba9c:5d7b with SMTP id adf61e73a8af0-1ced619532dmr10942646637.23.1725461836527;
        Wed, 04 Sep 2024 07:57:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725461836; cv=none;
        d=google.com; s=arc-20240605;
        b=Gh29PTZKuoR/mUZc0fPHRhWfFVAVRMGeRYR2xiA2OPwJ9uYo1XxEeKQq2wMNDEfxHK
         fiRYw9o7Dt5WsDpnfzQHNoVuvxzyxq450ixCvBmOrWLxzEmTQdAIk/bOT/b4jYL6viX3
         JbAn/MZlSQqIhHFwnJqlv94hGdFcziqjLQu/LWgv9T9tyi8rZw6NO/DIW7nnNMgzSWs8
         QDuLBb7uSlwo0rP0MtKM0iolZeaa6+dM5Aqbt/n77hEieoqKDkpIC3pIamMpNrhHPGHm
         Kf+Dh/lrmHnCel8R+FWCdyRMZTtHmP/9sSdJJwA4GUxtitxGJliFTp7gVYITWmdEIrS8
         a5Uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=F0ZQXgyDP6PEcKiBn5OcVA7Fwl0wFC8E7Z3K9IfpZ0M=;
        fh=3ieC3SSj3VsrxylJtBcPvDlmNdBxA/8Tk+wOEFOB1+k=;
        b=lRUxs7ojjWexaXCuyQzriFseVUe4Mo8Zextd5dsMLYvCOS5ijq8zTVA00MmCZNd88c
         46ld8zMHoAv8iaxBBzPOelQ91boklc4d7nVaZBMI9ptkca7wGIt91SfYMqTV4/kG5J+r
         Q2enAEsVFp+k+2RRtSgr0kcAJqZgOsSSpKZF9D6Ulmbb/eUiEoyKRH2CCfK8gBLrR8bN
         wY6EgZbp77+XBYUvi+P5BlwnH8GGlb177EH/bITN1mBE9XTL1ou6FRST5vzl55Emj9/j
         iJVUdHMQtNg2alkggwE6tD/OSgiRDBDDjxf/s/JWEq2iDJ2n1rjc7iLZmxeBxlVRFgCV
         ybLw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=jRjJre8n;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::132 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-il1-x132.google.com (mail-il1-x132.google.com. [2607:f8b0:4864:20::132])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-206ae8bcecesi861635ad.1.2024.09.04.07.57.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Sep 2024 07:57:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::132 as permitted sender) client-ip=2607:f8b0:4864:20::132;
Received: by mail-il1-x132.google.com with SMTP id e9e14a558f8ab-39fd6a9acb6so2500335ab.0
        for <kasan-dev@googlegroups.com>; Wed, 04 Sep 2024 07:57:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXdVadT3OQYF61FAfPBob2zuXOUsaPLglE39HZ1xQjxSQZ6pgNDiV0px6nGVXzuajzpg7lPPUgJSOg=@googlegroups.com
X-Received: by 2002:a05:6e02:1fed:b0:39e:78d9:ebfc with SMTP id e9e14a558f8ab-39f6a9f5455mr82847405ab.17.1725461835688;
        Wed, 04 Sep 2024 07:57:15 -0700 (PDT)
Received: from [100.64.0.1] ([147.124.94.167])
        by smtp.gmail.com with ESMTPSA id 8926c6da1cb9f-4ced2e17ba7sm3122962173.77.2024.09.04.07.57.14
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Sep 2024 07:57:15 -0700 (PDT)
Message-ID: <20ab0fa2-d5dd-446d-9fff-a3ef82e8db35@sifive.com>
Date: Wed, 4 Sep 2024 09:57:13 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 09/10] RISC-V: KVM: Allow Smnpm and Ssnpm extensions
 for guests
To: Anup Patel <anup@brainfault.org>
Cc: Anup Patel <apatel@ventanamicro.com>, Palmer Dabbelt
 <palmer@dabbelt.com>, linux-riscv@lists.infradead.org,
 devicetree@vger.kernel.org, Catalin Marinas <catalin.marinas@arm.com>,
 linux-kernel@vger.kernel.org, Conor Dooley <conor@kernel.org>,
 kasan-dev@googlegroups.com, Atish Patra <atishp@atishpatra.org>,
 Evgenii Stepanov <eugenis@google.com>,
 Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
 Rob Herring <robh+dt@kernel.org>,
 "Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>,
 kvm-riscv@lists.infradead.org
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
 <20240829010151.2813377-10-samuel.holland@sifive.com>
 <CAK9=C2WjraWjuQCeU2Y4Jhr-gKkOcP42Sza7wVp0FgeGaD923g@mail.gmail.com>
 <b6de8769-7e4e-4a19-b239-a39fd424e0c8@sifive.com>
 <CAAhSdy08SoDoZCii9R--BK7_NKLnRciW7V3mo2aQRKW1dbOgNg@mail.gmail.com>
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: en-US
In-Reply-To: <CAAhSdy08SoDoZCii9R--BK7_NKLnRciW7V3mo2aQRKW1dbOgNg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=jRjJre8n;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::132 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

On 2024-09-04 9:45 AM, Anup Patel wrote:
> On Wed, Sep 4, 2024 at 8:01=E2=80=AFPM Samuel Holland <samuel.holland@sif=
ive.com> wrote:
>> On 2024-09-04 7:17 AM, Anup Patel wrote:
>>> On Thu, Aug 29, 2024 at 6:32=E2=80=AFAM Samuel Holland
>>> <samuel.holland@sifive.com> wrote:
>>>>
>>>> The interface for controlling pointer masking in VS-mode is henvcfg.PM=
M,
>>>> which is part of the Ssnpm extension, even though pointer masking in
>>>> HS-mode is provided by the Smnpm extension. As a result, emulating Smn=
pm
>>>> in the guest requires (only) Ssnpm on the host.
>>>>
>>>> Since the guest configures Smnpm through the SBI Firmware Features
>>>> interface, the extension can be disabled by failing the SBI call. Ssnp=
m
>>>> cannot be disabled without intercepting writes to the senvcfg CSR.
>>>>
>>>> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
>>>> ---
>>>>
>>>> (no changes since v2)
>>>>
>>>> Changes in v2:
>>>>  - New patch for v2
>>>>
>>>>  arch/riscv/include/uapi/asm/kvm.h | 2 ++
>>>>  arch/riscv/kvm/vcpu_onereg.c      | 3 +++
>>>>  2 files changed, 5 insertions(+)
>>>>
>>>> diff --git a/arch/riscv/include/uapi/asm/kvm.h b/arch/riscv/include/ua=
pi/asm/kvm.h
>>>> index e97db3296456..4f24201376b1 100644
>>>> --- a/arch/riscv/include/uapi/asm/kvm.h
>>>> +++ b/arch/riscv/include/uapi/asm/kvm.h
>>>> @@ -175,6 +175,8 @@ enum KVM_RISCV_ISA_EXT_ID {
>>>>         KVM_RISCV_ISA_EXT_ZCF,
>>>>         KVM_RISCV_ISA_EXT_ZCMOP,
>>>>         KVM_RISCV_ISA_EXT_ZAWRS,
>>>> +       KVM_RISCV_ISA_EXT_SMNPM,
>>>> +       KVM_RISCV_ISA_EXT_SSNPM,
>>>>         KVM_RISCV_ISA_EXT_MAX,
>>>>  };
>>>>
>>>> diff --git a/arch/riscv/kvm/vcpu_onereg.c b/arch/riscv/kvm/vcpu_onereg=
.c
>>>> index b319c4c13c54..6f833ec2344a 100644
>>>> --- a/arch/riscv/kvm/vcpu_onereg.c
>>>> +++ b/arch/riscv/kvm/vcpu_onereg.c
>>>> @@ -34,9 +34,11 @@ static const unsigned long kvm_isa_ext_arr[] =3D {
>>>>         [KVM_RISCV_ISA_EXT_M] =3D RISCV_ISA_EXT_m,
>>>>         [KVM_RISCV_ISA_EXT_V] =3D RISCV_ISA_EXT_v,
>>>>         /* Multi letter extensions (alphabetically sorted) */
>>>> +       [KVM_RISCV_ISA_EXT_SMNPM] =3D RISCV_ISA_EXT_SSNPM,
>>>
>>> Why not use KVM_ISA_EXT_ARR() macro here ?
>>
>> Because the extension name in the host does not match the extension name=
 in the
>> guest. Pointer masking for HS mode is provided by Smnpm. Pointer masking=
 for VS
>> mode is provided by Ssnpm at the hardware level, but this needs to appea=
r to the
>> guest as if Smnpm was implemented, since the guest thinks it is running =
on bare
>> metal.
>=20
> Okay, makes sense.
>=20
>>
>>>>         KVM_ISA_EXT_ARR(SMSTATEEN),
>>>>         KVM_ISA_EXT_ARR(SSAIA),
>>>>         KVM_ISA_EXT_ARR(SSCOFPMF),
>>>> +       KVM_ISA_EXT_ARR(SSNPM),
>>>>         KVM_ISA_EXT_ARR(SSTC),
>>>>         KVM_ISA_EXT_ARR(SVINVAL),
>>>>         KVM_ISA_EXT_ARR(SVNAPOT),
>>>> @@ -129,6 +131,7 @@ static bool kvm_riscv_vcpu_isa_disable_allowed(uns=
igned long ext)
>>>>         case KVM_RISCV_ISA_EXT_M:
>>>>         /* There is not architectural config bit to disable sscofpmf c=
ompletely */
>>>>         case KVM_RISCV_ISA_EXT_SSCOFPMF:
>>>> +       case KVM_RISCV_ISA_EXT_SSNPM:
>>>
>>> Why not add KVM_RISCV_ISA_EXT_SMNPM here ?
>>>
>>> Disabling Smnpm from KVM user space is very different from
>>> disabling Smnpm from Guest using SBI FWFT extension.
>>
>> Until a successful SBI FWFT call to KVM to enable pointer masking for VS=
 mode,
>> the existence of Smnpm has no visible effect on the guest. So failing th=
e SBI
>> call is sufficient to pretend that the hardware does not support Smnpm.
>>
>>> The KVM user space should always add Smnpm in the
>>> Guest ISA string whenever the Host ISA string has it.
>>
>> I disagree. Allowing userspace to disable extensions is useful for testi=
ng and
>> to support migration to hosts which do not support those extensions. So =
I would
>> only add extensions to this list if there is no possible way to disable =
them.
>=20
> I am not saying to disallow KVM user space disabling Smnpm.

Then I'm confused. This is the "return false;" switch case inside
kvm_riscv_vcpu_isa_disable_allowed(). If I add KVM_RISCV_ISA_EXT_SMNPM here=
,
then (unless I am misreading the code) I am disallowing KVM userspace from
disabling Smnpm in the guest (i.e. preventing KVM userspace from removing S=
mnpm
from the guest ISA string). If that is not desired, then why do you suggest=
 I
add KVM_RISCV_ISA_EXT_SMNPM here?

> The presence of Smnpm in ISA only means that it is present in HW
> but it needs to be explicitly configured/enabled using SBI FWFT.
>=20
> KVM user space can certainly disable extensions by not adding it to
> ISA string based on the KVMTOOL/QEMU-KVM command line option.
> Additionally, when SBI FWFT is added to KVM RISC-V. It will have its
> own way to explicitly disable firmware features from KVM user space.

I think we agree on this, but your explanation here appears to conflict wit=
h
your suggested code change. Apologies if I'm missing something.

Regards,
Samuel

>>> The Guest must explicitly use SBI FWFT to enable
>>> Smnpm only after it sees Smnpm in ISA string.
>>
>> Yes, exactly, and the purpose of not including Smnpm in the switch case =
here is
>> so that KVM user space can control whether or not it appears in the ISA =
string.
>>
>> Regards,
>> Samuel
>>
>>>>         case KVM_RISCV_ISA_EXT_SSTC:
>>>>         case KVM_RISCV_ISA_EXT_SVINVAL:
>>>>         case KVM_RISCV_ISA_EXT_SVNAPOT:
>>>> --
>>>> 2.45.1
>>>>
>>>>
>>>> _______________________________________________
>>>> linux-riscv mailing list
>>>> linux-riscv@lists.infradead.org
>>>> http://lists.infradead.org/mailman/listinfo/linux-riscv
>>>
>>> Regards,
>>> Anup
>>
>=20
> Regards,
> Anup

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20ab0fa2-d5dd-446d-9fff-a3ef82e8db35%40sifive.com.
