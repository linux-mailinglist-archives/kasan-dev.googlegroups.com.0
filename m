Return-Path: <kasan-dev+bncBCMIFTP47IJBBXHUSO3QMGQEFQJV7MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FD19978CD7
	for <lists+kasan-dev@lfdr.de>; Sat, 14 Sep 2024 04:52:14 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-2d87b7618d3sf3818931a91.3
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 19:52:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726282332; cv=pass;
        d=google.com; s=arc-20240605;
        b=SMcdqWu9SmyRnVw6hNWye1U/x7ZfT7NSm5aitUgTRDvbIktnj5KhGRfQj3RIsc5Ve3
         sONVWPNa44gQb5Uewa80YVM3ngCoND7d+qm7kPqyN3a6UTNHnIrW/KHtJy0Y9/tsVDLF
         FovbbZHCi1zKzVB1Dt19UG9mRBmHQKoEYwNZvYwFVWsIavVdEBtO4ixVHQC92KzBQpiL
         GqSkLUAzagBPprdFHH8LjkMYL2fXJBcwxlsnvryhi7dzY4ADiN8i/WU0FvXDCXS6XA5N
         HyVbn8KBxi7He4wZmyd4pBorE2V49wkdpNyE2SUwhesoVl2LjjGHny4wbUuQb5H9q2IL
         JUYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=1BkraBjf9mNy3NspCtulzgqzw/NxOnfoiZZsGUgO9a4=;
        fh=+5sk5VtcDcShjJ1wxkaMdmKoWvrvh5m9qeqAKG+2K+4=;
        b=Tc7pMGqbwS2wjRIOuzOFTqAGAwqiWvyXu9KpVjnPX/mJc2wF7QfLQ0phLfnKwsR0ST
         QMCSiaefqeKZ5hjZHfwf2OGqihxPsz4oLNHUDTIyhhm77pTSeLwpt/D7/7pRD8xitF8p
         FJE+FVy6K9XMrHKLFX0aHs5Dy1J0hnp+MfSYkLT2Bcc6FNGzjl0a2m2UCxf/JQbq6U0D
         PfQh4ErzHWdQXAKw2zNQsLy00hlG/RCO3VjRMwivJF9umFasdC7sETW7sd41rGz0smfK
         j8f91DY3pC8d5gg4Oj90/s4AuRzs6vRHz0xLuI32ve7n46SSU/lR2cgaz5UYap+17V9a
         kbdQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=Q08QFNtU;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726282332; x=1726887132; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1BkraBjf9mNy3NspCtulzgqzw/NxOnfoiZZsGUgO9a4=;
        b=jmVx8+LE3o/q0BbELLrv4oNHC8hR7+fbwYO7LD5CSDsjZpUgtPULB5Fc0QIK5ixjui
         xUZdDzHn4df0K+vJlVeIB/BUrhCT+D/JRvdRzkxndKe7ZS7wC10fQccqo+wuhukwnoCq
         qQ7EcRON4SfnR7uKzxSU4ryI2a4HJXHvWeERzwovYvXCphUvJdUpfTpYnPJYaAwe7cfl
         SV5AjjLib37YZmaPvl2OQ4YvcA5LPMCQo0sh0/bsYDHd5T7YV/+c4G6ZIWf2b6Izqq97
         zvxQjkW3zauzc6jqnwU77bJaLAIqR34GBcBOY/9QYZ74UX0oqzhN2zMNaRSSBuKhDxXL
         qc/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726282332; x=1726887132;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1BkraBjf9mNy3NspCtulzgqzw/NxOnfoiZZsGUgO9a4=;
        b=k0sUXaaG6kToQvtCwEOu7AUZBIXlsZ4WEe94Kmj/hLX9eafeEsD4s+2csFF7Sj3KsB
         /muJid8RI/QOTc9UfsKFVq91SoDYdBZtzQDKa2TUhpaZj/duFLWA6H8TWiOmh1d9C6Ke
         al/8bFCClp/fdATE0kWdPvM78wfb5RA4UqLmc0zfgyij5k8kibiWMXtU4la/hh8xSDn7
         uC3JO2wtp1qLQVLmvnd000kNtB2Kt5hQusAqITy7JfcTNURTztzC8tYqsyrPNoxPQCBf
         bTrO4XaNnFSWXI+OTz2sSbeURv4BJ0qdwFIF5m+WmwhGjjQQR4OmsgbiFgd+3noPfF22
         l6Ag==
X-Forwarded-Encrypted: i=2; AJvYcCXGN8rBpx1rwYIShe4fua/EuRhFO+rjmmN9YWRb91ztJ0FibSOBf9WIaKFNMTZszFzB+sSI+Q==@lfdr.de
X-Gm-Message-State: AOJu0YwfqN2EYnoDsHiHqMrFvSVqf3OdJPEOrijbDTTfhLmcpmGismz9
	4SJ/X6e1V3WHBL9OU0yK6YytLHI1J7LvbzqRq+l7eU+ahx4NsWYp
X-Google-Smtp-Source: AGHT+IFqKLAnuklNVMpMSnhAwYVeAZttPSxOspLYNXTH+ryo1n+aap5QpgO1vwLzXYZzAE1cOROJ+Q==
X-Received: by 2002:a17:90a:9303:b0:2cb:e429:f525 with SMTP id 98e67ed59e1d1-2dba0082f0bmr11507204a91.33.1726282332504;
        Fri, 13 Sep 2024 19:52:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1c12:b0:2d1:e21f:8543 with SMTP id
 98e67ed59e1d1-2db9f66406els1317686a91.2.-pod-prod-03-us; Fri, 13 Sep 2024
 19:52:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXo018BtxC+fn0uDOnLy98KFwM28iZt7kYAgQvEi/qrNixaEZ7w3CiJgPjXZwxgvhF4gVEbUcuJraA=@googlegroups.com
X-Received: by 2002:a17:90a:a781:b0:2d8:b43b:6ecc with SMTP id 98e67ed59e1d1-2db9ffb11c3mr11611664a91.4.1726282331081;
        Fri, 13 Sep 2024 19:52:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726282331; cv=none;
        d=google.com; s=arc-20240605;
        b=cUCsNMGjlBXp7efYWUrY07HbWqIKfxhL0+LlNlwTqnMU4bNAOznp05CqEYEGz2btGo
         2tQZKP5dNB7WN66PstlfCPB0l18ULdCHnIFLABBYVwCGhMD2X9ktVbDm9sdmXbFUJBDl
         YCn7CnLmFJW4327i96K3YC+HbBcIAjYcR15UM5a7ORFv4xUB3Ase18eb7+m1KF1CM/WH
         rKi6Q+j/UQBC3pNyL0mMx3npmetVI8netNX7VgTWBLxg5wTtB8eSkshbYaASxFz6wzea
         10JX0Kpjvl+r/8AlkjL/ihV9efxulsABlnsXA+c1jwjN8t4Epk3ldR8P9pppqLop78WE
         ug4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=PcgocvC07KwdgYkvDV/qMfScM5+LqmPejCCEAA1uMJI=;
        fh=bqdFTTlhK6f4XOIgoTFnrQZ4eOabIbhr9dNIJyFlEPQ=;
        b=DzRDxgn6k8Eu53YlIFSSrYjd9IkqkQ9566qLUo5oXwqJDeTea6Urvnfoag0IFxZaCp
         hTDiupWvw/3rtI1Z6euJA2KZ7+wvPpeHQDCsZERMH5MRk1MEHb5zGucyyFY/YP+QcYs4
         mWsTZxvBsmaGEPRbD3qivTEONVLo6xwLQL0dAoXRBV/bRNf1x5ChYYKFiOWS4Y/wW+4U
         TtQwYqUx//6XfMn1/4vYw2mKe8FP/yLl3PDJ4cN+MhOt0PSHYzQAK3v43ZI+T1dk5car
         xHoDsbtRF7VGvANLmJR2v0IIBxjggnQYaKO4it/KY/Cki3okzE/n/51HuhDMLqrjptKE
         o4dg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=Q08QFNtU;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-io1-xd2b.google.com (mail-io1-xd2b.google.com. [2607:f8b0:4864:20::d2b])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2db6dc9977asi703989a91.1.2024.09.13.19.52.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Sep 2024 19:52:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::d2b as permitted sender) client-ip=2607:f8b0:4864:20::d2b;
Received: by mail-io1-xd2b.google.com with SMTP id ca18e2360f4ac-82ce603d8daso100138639f.0
        for <kasan-dev@googlegroups.com>; Fri, 13 Sep 2024 19:52:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUwexrQFh1E9FxBq5OIHVe0T44/x16KbjdODvblJV3ffjvAmx3s7B+2dD7YnVJKUgcIicnpCsCWjHc=@googlegroups.com
X-Received: by 2002:a05:6e02:5ad:b0:3a0:8dae:8b06 with SMTP id e9e14a558f8ab-3a08dae8c99mr24837465ab.9.1726282330175;
        Fri, 13 Sep 2024 19:52:10 -0700 (PDT)
Received: from [100.64.0.1] ([147.124.94.167])
        by smtp.gmail.com with ESMTPSA id e9e14a558f8ab-3a092dfe1d8sm1609685ab.13.2024.09.13.19.52.08
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Sep 2024 19:52:09 -0700 (PDT)
Message-ID: <8e474b14-e963-4d3e-8240-37f662e7bd8a@sifive.com>
Date: Fri, 13 Sep 2024 21:52:07 -0500
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
 <20ab0fa2-d5dd-446d-9fff-a3ef82e8db35@sifive.com>
 <CAAhSdy1pZcEfajg3OZUCaFf9JMYcMzpRVogCT5VL2FHx__vDdA@mail.gmail.com>
 <4c010cb1-b57c-427e-a241-1dd3ab15f2ce@sifive.com>
 <CAAhSdy0kYUdgX8NUKuOdQa-69ET=cscduJvyz3z31kVeB-JaNw@mail.gmail.com>
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: en-US
In-Reply-To: <CAAhSdy0kYUdgX8NUKuOdQa-69ET=cscduJvyz3z31kVeB-JaNw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=Q08QFNtU;       spf=pass
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

Hi Anup,

On 2024-09-05 12:18 AM, Anup Patel wrote:
> On Wed, Sep 4, 2024 at 9:25=E2=80=AFPM Samuel Holland <samuel.holland@sif=
ive.com> wrote:
>>
>> On 2024-09-04 10:20 AM, Anup Patel wrote:
>>> On Wed, Sep 4, 2024 at 8:27=E2=80=AFPM Samuel Holland <samuel.holland@s=
ifive.com> wrote:
>>>>
>>>> Hi Anup,
>>>>
>>>> On 2024-09-04 9:45 AM, Anup Patel wrote:
>>>>> On Wed, Sep 4, 2024 at 8:01=E2=80=AFPM Samuel Holland <samuel.holland=
@sifive.com> wrote:
>>>>>> On 2024-09-04 7:17 AM, Anup Patel wrote:
>>>>>>> On Thu, Aug 29, 2024 at 6:32=E2=80=AFAM Samuel Holland
>>>>>>> <samuel.holland@sifive.com> wrote:
>>>>>>>>
>>>>>>>> The interface for controlling pointer masking in VS-mode is henvcf=
g.PMM,
>>>>>>>> which is part of the Ssnpm extension, even though pointer masking =
in
>>>>>>>> HS-mode is provided by the Smnpm extension. As a result, emulating=
 Smnpm
>>>>>>>> in the guest requires (only) Ssnpm on the host.
>>>>>>>>
>>>>>>>> Since the guest configures Smnpm through the SBI Firmware Features
>>>>>>>> interface, the extension can be disabled by failing the SBI call. =
Ssnpm
>>>>>>>> cannot be disabled without intercepting writes to the senvcfg CSR.
>>>>>>>>
>>>>>>>> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
>>>>>>>> ---
>>>>>>>>
>>>>>>>> (no changes since v2)
>>>>>>>>
>>>>>>>> Changes in v2:
>>>>>>>>  - New patch for v2
>>>>>>>>
>>>>>>>>  arch/riscv/include/uapi/asm/kvm.h | 2 ++
>>>>>>>>  arch/riscv/kvm/vcpu_onereg.c      | 3 +++
>>>>>>>>  2 files changed, 5 insertions(+)
>>>>>>>>
>>>>>>>> diff --git a/arch/riscv/include/uapi/asm/kvm.h b/arch/riscv/includ=
e/uapi/asm/kvm.h
>>>>>>>> index e97db3296456..4f24201376b1 100644
>>>>>>>> --- a/arch/riscv/include/uapi/asm/kvm.h
>>>>>>>> +++ b/arch/riscv/include/uapi/asm/kvm.h
>>>>>>>> @@ -175,6 +175,8 @@ enum KVM_RISCV_ISA_EXT_ID {
>>>>>>>>         KVM_RISCV_ISA_EXT_ZCF,
>>>>>>>>         KVM_RISCV_ISA_EXT_ZCMOP,
>>>>>>>>         KVM_RISCV_ISA_EXT_ZAWRS,
>>>>>>>> +       KVM_RISCV_ISA_EXT_SMNPM,
>>>>>>>> +       KVM_RISCV_ISA_EXT_SSNPM,
>>>>>>>>         KVM_RISCV_ISA_EXT_MAX,
>>>>>>>>  };
>>>>>>>>
>>>>>>>> diff --git a/arch/riscv/kvm/vcpu_onereg.c b/arch/riscv/kvm/vcpu_on=
ereg.c
>>>>>>>> index b319c4c13c54..6f833ec2344a 100644
>>>>>>>> --- a/arch/riscv/kvm/vcpu_onereg.c
>>>>>>>> +++ b/arch/riscv/kvm/vcpu_onereg.c
>>>>>>>> @@ -34,9 +34,11 @@ static const unsigned long kvm_isa_ext_arr[] =
=3D {
>>>>>>>>         [KVM_RISCV_ISA_EXT_M] =3D RISCV_ISA_EXT_m,
>>>>>>>>         [KVM_RISCV_ISA_EXT_V] =3D RISCV_ISA_EXT_v,
>>>>>>>>         /* Multi letter extensions (alphabetically sorted) */
>>>>>>>> +       [KVM_RISCV_ISA_EXT_SMNPM] =3D RISCV_ISA_EXT_SSNPM,
>>>>>>>
>>>>>>> Why not use KVM_ISA_EXT_ARR() macro here ?
>>>>>>
>>>>>> Because the extension name in the host does not match the extension =
name in the
>>>>>> guest. Pointer masking for HS mode is provided by Smnpm. Pointer mas=
king for VS
>>>>>> mode is provided by Ssnpm at the hardware level, but this needs to a=
ppear to the
>>>>>> guest as if Smnpm was implemented, since the guest thinks it is runn=
ing on bare
>>>>>> metal.
>>>>>
>>>>> Okay, makes sense.
>>>>>
>>>>>>
>>>>>>>>         KVM_ISA_EXT_ARR(SMSTATEEN),
>>>>>>>>         KVM_ISA_EXT_ARR(SSAIA),
>>>>>>>>         KVM_ISA_EXT_ARR(SSCOFPMF),
>>>>>>>> +       KVM_ISA_EXT_ARR(SSNPM),
>>>>>>>>         KVM_ISA_EXT_ARR(SSTC),
>>>>>>>>         KVM_ISA_EXT_ARR(SVINVAL),
>>>>>>>>         KVM_ISA_EXT_ARR(SVNAPOT),
>>>>>>>> @@ -129,6 +131,7 @@ static bool kvm_riscv_vcpu_isa_disable_allowed=
(unsigned long ext)
>>>>>>>>         case KVM_RISCV_ISA_EXT_M:
>>>>>>>>         /* There is not architectural config bit to disable sscofp=
mf completely */
>>>>>>>>         case KVM_RISCV_ISA_EXT_SSCOFPMF:
>>>>>>>> +       case KVM_RISCV_ISA_EXT_SSNPM:
>>>>>>>
>>>>>>> Why not add KVM_RISCV_ISA_EXT_SMNPM here ?
>>>>>>>
>>>>>>> Disabling Smnpm from KVM user space is very different from
>>>>>>> disabling Smnpm from Guest using SBI FWFT extension.
>>>>>>
>>>>>> Until a successful SBI FWFT call to KVM to enable pointer masking fo=
r VS mode,
>>>>>> the existence of Smnpm has no visible effect on the guest. So failin=
g the SBI
>>>>>> call is sufficient to pretend that the hardware does not support Smn=
pm.
>>>>>>
>>>>>>> The KVM user space should always add Smnpm in the
>>>>>>> Guest ISA string whenever the Host ISA string has it.
>>>>>>
>>>>>> I disagree. Allowing userspace to disable extensions is useful for t=
esting and
>>>>>> to support migration to hosts which do not support those extensions.=
 So I would
>>>>>> only add extensions to this list if there is no possible way to disa=
ble them.
>>>>>
>>>>> I am not saying to disallow KVM user space disabling Smnpm.
>>>>
>>>> Then I'm confused. This is the "return false;" switch case inside
>>>> kvm_riscv_vcpu_isa_disable_allowed(). If I add KVM_RISCV_ISA_EXT_SMNPM=
 here,
>>>> then (unless I am misreading the code) I am disallowing KVM userspace =
from
>>>> disabling Smnpm in the guest (i.e. preventing KVM userspace from remov=
ing Smnpm
>>>> from the guest ISA string). If that is not desired, then why do you su=
ggest I
>>>> add KVM_RISCV_ISA_EXT_SMNPM here?
>>>
>>> Yes, adding KVM_RISCV_ISA_EXT_SMNPM here means KVM
>>> user space can't disable it using ONE_REG interface but KVM user
>>> space can certainly not add it in the Guest ISA string.
>>
>> Is there a problem with allowing KVM userspace to disable the ISA extens=
ion with
>> the ONE_REG interface?
>>
>> If KVM userspace removes Smnpm from the ISA string without the host kern=
el's
>> knowledge, that doesn't actually prevent the guest from successfully cal=
ling
>> sbi_fwft_set(POINTER_MASKING_PMLEN, ...), so it doesn't guarantee that t=
he VM
>> can be migrated to a host without pointer masking support. So the ONE_RE=
G
>> interface still has value. (And that's my answer to your original questi=
on "Why
>> not add KVM_RISCV_ISA_EXT_SMNPM here ?")
>=20
> Currently, disabling KVM_RISCV_ISA_EXT_SMNPM via ONE_REG
> will only clear the corresponding bit in VCPU isa bitmap. Basically, the
> KVM user space disabling KVM_RISCV_ISA_EXT_SMNPM for Guest
> changes nothing for the Guest/VM.
>=20
> On other hand, disabling KVM_RISCV_ISA_EXT_SVPBMT via
> ONE_REG will not only clear it from VCPU isa bitmap but also
> disable Svpmbt from henvcfg CSR for the Guest/VM.
>=20
> In other words, if disabling an ISA extension is allowed by the
> kvm_riscv_vcpu_isa_disable_allowed() then the Guest/VM must
> see a different behaviour when the ISA extension is disabled by
> KVM user space.
>=20
>>
>>>>> The presence of Smnpm in ISA only means that it is present in HW
>>>>> but it needs to be explicitly configured/enabled using SBI FWFT.
>>>>>
>>>>> KVM user space can certainly disable extensions by not adding it to
>>>>> ISA string based on the KVMTOOL/QEMU-KVM command line option.
>>>>> Additionally, when SBI FWFT is added to KVM RISC-V. It will have its
>>>>> own way to explicitly disable firmware features from KVM user space.
>>>>
>>>> I think we agree on this, but your explanation here appears to conflic=
t with
>>>> your suggested code change. Apologies if I'm missing something.
>>>
>>> I think the confusion is about what does it mean when Smnpm is present
>>> in the ISA string. We have two approaches:
>>>
>>> 1) Presence of Smnpm in ISA string only means it is present in HW but
>>>     says nothing about its enable/disable state. To configure/enable
>>>     Smnpm, the supervisor must use SBI FWFT.
>>>
>>> 2) Presence of Smnpm in ISA string means it is present in HW and
>>>     enabled at boot-time. To re-configure/disable Smnpm, the supervisor
>>>     must use SBI FWFT.
>>>
>>> I am suggesting approach #1 but I am guessing you are leaning towards
>>> approach #2 ?
>>>
>>> For approach #2, additional hencfg.PMM configuration is required in
>>> this patch based on the state of KVM_RISCV_ISA_EXT_SMNPM.
>>
>> No, I am definitely suggesting only approach #1. My proposal for adding =
pointer
>> masking to the SBI FWFT extension[1] specifies the feature as disabled b=
y
>> default, and this would apply both inside and ouside a VM.
>>
>> But I am also suggesting that the ONE_REG interface is a useful way to
>> completely hide the extension from the guest, like we do for other exten=
sions
>> such as Svpbmt. The only difference between something like Svpbmt and Sm=
npm is
>> that instead of clearing a bit in henvcfg to hide the extension from the=
 guest,
>> we reject calls to sbi_fwft_set(POINTER_MASKING_PMLEN, ...) when the ISA
>> extension is hidden from the guest.
>=20
> I think we are converging towards the same thing.
>=20
> How about this ?
>=20
> For this series, lets add KVM_RISCV_ISA_EXT_SMNPM to
> kvm_riscv_vcpu_isa_disable_allowed() so that for the time
> being KVM user space can't disable Smnpm.
>=20
> In the future, a separate series which adds SBI FWFT to
> KVM RISC-V will remove KVM_RISCV_ISA_EXT_SMNPM
> from the kvm_riscv_vcpu_isa_disable_allowed() because
> disabling Smnpm from KVM user space would mean that
> the POINTER_MASKING_PMLEN firmware feature is
> not available to the Guest/VM.
>=20
> This means in the future (after SBI FWFT is implemented in
> KVM RISC-V), Guest with Smnpm disabled can be migrated
> to a host without pointer masking.

OK, that is a reasonable compromise. I'll do that for v5.

Regards,
Samuel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/8e474b14-e963-4d3e-8240-37f662e7bd8a%40sifive.com.
