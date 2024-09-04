Return-Path: <kasan-dev+bncBCMIFTP47IJBBAMG4K3AMGQEMIKJTUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 30CB696C313
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Sep 2024 17:55:47 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-39d55a00bd7sf81797905ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Sep 2024 08:55:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725465346; cv=pass;
        d=google.com; s=arc-20240605;
        b=P7oDxRR+Rg1T3AFB0IEoc3O8m0nYL5S1j5M6LaQljRK6HDZI3Jkv80UoJgH2w/RVCW
         sq69HyLagtmWlpZu/IrJLB8VmcZjPn7kWBX4J/YIE6NfQ8ksur3IZENX6qnM+lxupA5H
         KPyv5tNfhGy8FIGJVvT1Oa3u2KU8FaZ9yUy0wlNEliJKOqgBqghmz9I5vmiLwUzsTU74
         RHa5b8949RLymIIwTieSj9ug9su3uWgXAEaQwpyntlVE15V/QV+lFJQd0N85JWzEEuth
         /CU8Q+mj6Q/1c0M8pGfU5miKEAPwUo28JOAIAUJFI6cRJdelhN2MoTbpQ4uMRdHd+tr5
         IUfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=Kod3Xxn7nrrZ5wQqTTm6HwEYjzlOTfKhtZWNTYgs3vM=;
        fh=xZzcCR6pA0bN9taxhBdJmcw1If+j62OG74zDDNFwIg0=;
        b=BwDWTcYhao8eX0JQUS5ZG0Q/HQGo5bKi+GKIliAIS93lO+Vle3Lzc6qkE3SsJKQwGD
         +m0T1BcqCibJV2Munin1MwANLYMhpOGewrOV4u7h06iNMj4oSZaz6MAbNsmTb5ThLByI
         AH14QuQSdKaxZaFilwy6ExB2PHWJifRq3l2fuIjafURH3eSAw4sg4LXgIUQiHtPrJiAA
         M/bI9aySo3T/grp61eYZ8Zj55bVyc0EWcTbXle6jj794LPndI4kYm/WJ4TLRLbOs0wcy
         ewRu6x4ivjNAPwyyzQj6ybkhtPoOfbFKZQhXUhA13/yVkrszJpp0cIkBCPktOfW2yNa4
         VrcQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=N9MThlEH;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725465346; x=1726070146; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Kod3Xxn7nrrZ5wQqTTm6HwEYjzlOTfKhtZWNTYgs3vM=;
        b=Cmz/Mi6opOyDVnQZ9a+U59pv+0gsEDsQ6MNegspC0rDaUBM7s6eYOndVuNENOp2J4y
         blDb/GG6DQx44a0zSTuSTFLFBKq8a79vbGuzdtpc1pLWiJkIF+Wacb6YwJPRs9l9uoFs
         p314uo9Z/XgXgQSepN4zjsPY6K3wCcMbF4PvTjy5lCVgJzmLuo/sd3s5E8AzMlEXlGp0
         /hsCRnq6y/S8jV7UIg+j/IlF2REcaoqUpV5x7uNoyPYW7l/k91H9h+gU/r/mfsUzWG67
         /nIhNWXp4waaCCSp4TSYNgepx7+u0qvlIfMQw9qQYfFeSIR2UKiNuBccbJQ6DeGocXPU
         Loag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725465346; x=1726070146;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Kod3Xxn7nrrZ5wQqTTm6HwEYjzlOTfKhtZWNTYgs3vM=;
        b=MSwHAcjnI5CxwrGiFSv/2RyNQyscAYcQVd6RrzTCWBTIUfvHGAcpjZfJShlSj8wXZ0
         12VQ89mLQ6or6x2GTTXyko5Q5QR41DIvgEMLI8Om08YsgLvPpwK2oJ45O7dYvMXHIz3u
         pCaZhoMkUD91ixFjLVtAKTXbn6FMZXMDj5xnrvQprSS5yYrMgE/2MeZGvMZGrlBP2nKq
         0F3RgaIcqO5HOWsKK4j16PQvdq5xxNGKKVo394YcTweEDEJvA8SqvZo1p6Ixd87Fkpf3
         DvffUx5yY+Wh+hQbQG5QZhTHSTnCzp64yNNK6S0suJLZi4RI9qwIYVRe4JHCs14/kqI+
         0MBw==
X-Forwarded-Encrypted: i=2; AJvYcCV1MaVufQgu9nOc4+L9zqHDiNvxwB0hXwZy7VLSFtZkX+MmnNY7B2o/tl9egjEBrIFFqpZ2eg==@lfdr.de
X-Gm-Message-State: AOJu0YzUl06UihZvajI8XF4qJ9oSGMGT+vfSlfSyHxuNnmRj+xuDBy3o
	0FlAIGrMEky/MighrXvaafoYTS+CcswSGMKjPTZoj7NIO+nfvCup
X-Google-Smtp-Source: AGHT+IFQ7Pzdh0NiLcTb/d/Mf/y5XPkrpoYqvMH7XneBpSXKUAdu1GJd9ElbzM2czlNigYpDUY3nNQ==
X-Received: by 2002:a05:6e02:1c23:b0:39b:25dc:7bd6 with SMTP id e9e14a558f8ab-39f49a1fc8cmr186054945ab.4.1725465345687;
        Wed, 04 Sep 2024 08:55:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d85:b0:39d:50e8:d14 with SMTP id
 e9e14a558f8ab-3a0463a327fls411395ab.2.-pod-prod-06-us; Wed, 04 Sep 2024
 08:55:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVLcsKkILiGQbWgOBfhK7HXlkzJxj2ABjNmjBE7C+UwIhytkBm6q+HpPPwr8hjXrvIBArD2ovz3RHg=@googlegroups.com
X-Received: by 2002:a92:c241:0:b0:39d:484e:b316 with SMTP id e9e14a558f8ab-39f4e128344mr171600745ab.24.1725465344790;
        Wed, 04 Sep 2024 08:55:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725465344; cv=none;
        d=google.com; s=arc-20240605;
        b=SifvkmzFd0L8aOgfLQD184YVFSyt+z+tVhcP1rDXG6dxzdA4p0FkqCmTTlKrzrsDMt
         d3+CG/S4Wl+qP+5U3SJSoOf2zxmMKrSL7rvFA+giPZ+EUUF/elhvWsWJGqzZR6Ba88Sm
         3mUPifQtO7XLuydt7uG0grY2lr5gFEL+cE8K1tlbGV0gBX78yznDsV4J6H1pldCAcT2E
         XlDV3Xnlc6EkoO32RzHsxvAvItKpKhA4+7vDU4aiC4IT9SmIMhXW/KAD+s7n3Ltl30wt
         oYJvGYvmfPs0LB8kTSsVk5rBIHRFohb1GHdRudjXA9tBDes1nL6LJ8/LGt0LKFAiZzhM
         SFNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=IJfJhTqoZula3HvRr4vB1EKIVpNv9UMUTRfayiacVI8=;
        fh=uknbB6dxVSVtjIAx8hohAFN6Es2v0EW4Y3lXofQgvQY=;
        b=O2yK/HWRAloXzc3HktcUFg7iuSXHumbhtNhCPCdhhtqECveUIbWE0FqF/MMMZMtCQ6
         kdGwqyZqdRat6MefcejrrMQbk0PYHj7U097c7UnohWwRwJPvpm+vt1wUicoQpB+KwVFA
         XuCDyUP/FdCon9qSI21JTw+EvbwkBZmxj3rK/A2Xa1JWnGWJBf+bLZhQgCp4o+DsG6MA
         BEhad9h+BetsFTayOXmnnSOE9S/ORhAY8dpbefggiAhLXstAe1jtQetn/J/Kp6jietOD
         56drht1MRFzYXqN7BJsauQF2FxDv2uooybhoSxcdIsDl6n5y+JHsThKMg1CWYJcmtEu2
         6aqA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=N9MThlEH;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-oi1-x230.google.com (mail-oi1-x230.google.com. [2607:f8b0:4864:20::230])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4ced2e8c6a1si533059173.3.2024.09.04.08.55.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Sep 2024 08:55:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::230 as permitted sender) client-ip=2607:f8b0:4864:20::230;
Received: by mail-oi1-x230.google.com with SMTP id 5614622812f47-3df13906bcdso3227265b6e.0
        for <kasan-dev@googlegroups.com>; Wed, 04 Sep 2024 08:55:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXH4BQTIJm6krSJbXCv5AqO4U63lSXBfYaU3UJwQQB58OQ183q1xQa8cB+7evxwR6pRbzHKUF8Zj7o=@googlegroups.com
X-Received: by 2002:a05:6808:1687:b0:3dc:15b9:334a with SMTP id 5614622812f47-3df1b6f43f7mr14003462b6e.6.1725465344248;
        Wed, 04 Sep 2024 08:55:44 -0700 (PDT)
Received: from [100.64.0.1] ([147.124.94.167])
        by smtp.gmail.com with ESMTPSA id 5614622812f47-3df117a63a5sm2850495b6e.1.2024.09.04.08.55.42
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Sep 2024 08:55:43 -0700 (PDT)
Message-ID: <4c010cb1-b57c-427e-a241-1dd3ab15f2ce@sifive.com>
Date: Wed, 4 Sep 2024 10:55:41 -0500
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
Content-Language: en-US
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CAAhSdy1pZcEfajg3OZUCaFf9JMYcMzpRVogCT5VL2FHx__vDdA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=N9MThlEH;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

On 2024-09-04 10:20 AM, Anup Patel wrote:
> On Wed, Sep 4, 2024 at 8:27=E2=80=AFPM Samuel Holland <samuel.holland@sif=
ive.com> wrote:
>>
>> Hi Anup,
>>
>> On 2024-09-04 9:45 AM, Anup Patel wrote:
>>> On Wed, Sep 4, 2024 at 8:01=E2=80=AFPM Samuel Holland <samuel.holland@s=
ifive.com> wrote:
>>>> On 2024-09-04 7:17 AM, Anup Patel wrote:
>>>>> On Thu, Aug 29, 2024 at 6:32=E2=80=AFAM Samuel Holland
>>>>> <samuel.holland@sifive.com> wrote:
>>>>>>
>>>>>> The interface for controlling pointer masking in VS-mode is henvcfg.=
PMM,
>>>>>> which is part of the Ssnpm extension, even though pointer masking in
>>>>>> HS-mode is provided by the Smnpm extension. As a result, emulating S=
mnpm
>>>>>> in the guest requires (only) Ssnpm on the host.
>>>>>>
>>>>>> Since the guest configures Smnpm through the SBI Firmware Features
>>>>>> interface, the extension can be disabled by failing the SBI call. Ss=
npm
>>>>>> cannot be disabled without intercepting writes to the senvcfg CSR.
>>>>>>
>>>>>> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
>>>>>> ---
>>>>>>
>>>>>> (no changes since v2)
>>>>>>
>>>>>> Changes in v2:
>>>>>>  - New patch for v2
>>>>>>
>>>>>>  arch/riscv/include/uapi/asm/kvm.h | 2 ++
>>>>>>  arch/riscv/kvm/vcpu_onereg.c      | 3 +++
>>>>>>  2 files changed, 5 insertions(+)
>>>>>>
>>>>>> diff --git a/arch/riscv/include/uapi/asm/kvm.h b/arch/riscv/include/=
uapi/asm/kvm.h
>>>>>> index e97db3296456..4f24201376b1 100644
>>>>>> --- a/arch/riscv/include/uapi/asm/kvm.h
>>>>>> +++ b/arch/riscv/include/uapi/asm/kvm.h
>>>>>> @@ -175,6 +175,8 @@ enum KVM_RISCV_ISA_EXT_ID {
>>>>>>         KVM_RISCV_ISA_EXT_ZCF,
>>>>>>         KVM_RISCV_ISA_EXT_ZCMOP,
>>>>>>         KVM_RISCV_ISA_EXT_ZAWRS,
>>>>>> +       KVM_RISCV_ISA_EXT_SMNPM,
>>>>>> +       KVM_RISCV_ISA_EXT_SSNPM,
>>>>>>         KVM_RISCV_ISA_EXT_MAX,
>>>>>>  };
>>>>>>
>>>>>> diff --git a/arch/riscv/kvm/vcpu_onereg.c b/arch/riscv/kvm/vcpu_oner=
eg.c
>>>>>> index b319c4c13c54..6f833ec2344a 100644
>>>>>> --- a/arch/riscv/kvm/vcpu_onereg.c
>>>>>> +++ b/arch/riscv/kvm/vcpu_onereg.c
>>>>>> @@ -34,9 +34,11 @@ static const unsigned long kvm_isa_ext_arr[] =3D =
{
>>>>>>         [KVM_RISCV_ISA_EXT_M] =3D RISCV_ISA_EXT_m,
>>>>>>         [KVM_RISCV_ISA_EXT_V] =3D RISCV_ISA_EXT_v,
>>>>>>         /* Multi letter extensions (alphabetically sorted) */
>>>>>> +       [KVM_RISCV_ISA_EXT_SMNPM] =3D RISCV_ISA_EXT_SSNPM,
>>>>>
>>>>> Why not use KVM_ISA_EXT_ARR() macro here ?
>>>>
>>>> Because the extension name in the host does not match the extension na=
me in the
>>>> guest. Pointer masking for HS mode is provided by Smnpm. Pointer maski=
ng for VS
>>>> mode is provided by Ssnpm at the hardware level, but this needs to app=
ear to the
>>>> guest as if Smnpm was implemented, since the guest thinks it is runnin=
g on bare
>>>> metal.
>>>
>>> Okay, makes sense.
>>>
>>>>
>>>>>>         KVM_ISA_EXT_ARR(SMSTATEEN),
>>>>>>         KVM_ISA_EXT_ARR(SSAIA),
>>>>>>         KVM_ISA_EXT_ARR(SSCOFPMF),
>>>>>> +       KVM_ISA_EXT_ARR(SSNPM),
>>>>>>         KVM_ISA_EXT_ARR(SSTC),
>>>>>>         KVM_ISA_EXT_ARR(SVINVAL),
>>>>>>         KVM_ISA_EXT_ARR(SVNAPOT),
>>>>>> @@ -129,6 +131,7 @@ static bool kvm_riscv_vcpu_isa_disable_allowed(u=
nsigned long ext)
>>>>>>         case KVM_RISCV_ISA_EXT_M:
>>>>>>         /* There is not architectural config bit to disable sscofpmf=
 completely */
>>>>>>         case KVM_RISCV_ISA_EXT_SSCOFPMF:
>>>>>> +       case KVM_RISCV_ISA_EXT_SSNPM:
>>>>>
>>>>> Why not add KVM_RISCV_ISA_EXT_SMNPM here ?
>>>>>
>>>>> Disabling Smnpm from KVM user space is very different from
>>>>> disabling Smnpm from Guest using SBI FWFT extension.
>>>>
>>>> Until a successful SBI FWFT call to KVM to enable pointer masking for =
VS mode,
>>>> the existence of Smnpm has no visible effect on the guest. So failing =
the SBI
>>>> call is sufficient to pretend that the hardware does not support Smnpm=
.
>>>>
>>>>> The KVM user space should always add Smnpm in the
>>>>> Guest ISA string whenever the Host ISA string has it.
>>>>
>>>> I disagree. Allowing userspace to disable extensions is useful for tes=
ting and
>>>> to support migration to hosts which do not support those extensions. S=
o I would
>>>> only add extensions to this list if there is no possible way to disabl=
e them.
>>>
>>> I am not saying to disallow KVM user space disabling Smnpm.
>>
>> Then I'm confused. This is the "return false;" switch case inside
>> kvm_riscv_vcpu_isa_disable_allowed(). If I add KVM_RISCV_ISA_EXT_SMNPM h=
ere,
>> then (unless I am misreading the code) I am disallowing KVM userspace fr=
om
>> disabling Smnpm in the guest (i.e. preventing KVM userspace from removin=
g Smnpm
>> from the guest ISA string). If that is not desired, then why do you sugg=
est I
>> add KVM_RISCV_ISA_EXT_SMNPM here?
>=20
> Yes, adding KVM_RISCV_ISA_EXT_SMNPM here means KVM
> user space can't disable it using ONE_REG interface but KVM user
> space can certainly not add it in the Guest ISA string.

Is there a problem with allowing KVM userspace to disable the ISA extension=
 with
the ONE_REG interface?

If KVM userspace removes Smnpm from the ISA string without the host kernel'=
s
knowledge, that doesn't actually prevent the guest from successfully callin=
g
sbi_fwft_set(POINTER_MASKING_PMLEN, ...), so it doesn't guarantee that the =
VM
can be migrated to a host without pointer masking support. So the ONE_REG
interface still has value. (And that's my answer to your original question =
"Why
not add KVM_RISCV_ISA_EXT_SMNPM here ?")

>>> The presence of Smnpm in ISA only means that it is present in HW
>>> but it needs to be explicitly configured/enabled using SBI FWFT.
>>>
>>> KVM user space can certainly disable extensions by not adding it to
>>> ISA string based on the KVMTOOL/QEMU-KVM command line option.
>>> Additionally, when SBI FWFT is added to KVM RISC-V. It will have its
>>> own way to explicitly disable firmware features from KVM user space.
>>
>> I think we agree on this, but your explanation here appears to conflict =
with
>> your suggested code change. Apologies if I'm missing something.
>=20
> I think the confusion is about what does it mean when Smnpm is present
> in the ISA string. We have two approaches:
>=20
> 1) Presence of Smnpm in ISA string only means it is present in HW but
>     says nothing about its enable/disable state. To configure/enable
>     Smnpm, the supervisor must use SBI FWFT.
>=20
> 2) Presence of Smnpm in ISA string means it is present in HW and
>     enabled at boot-time. To re-configure/disable Smnpm, the supervisor
>     must use SBI FWFT.
>=20
> I am suggesting approach #1 but I am guessing you are leaning towards
> approach #2 ?
>=20
> For approach #2, additional hencfg.PMM configuration is required in
> this patch based on the state of KVM_RISCV_ISA_EXT_SMNPM.

No, I am definitely suggesting only approach #1. My proposal for adding poi=
nter
masking to the SBI FWFT extension[1] specifies the feature as disabled by
default, and this would apply both inside and ouside a VM.

But I am also suggesting that the ONE_REG interface is a useful way to
completely hide the extension from the guest, like we do for other extensio=
ns
such as Svpbmt. The only difference between something like Svpbmt and Smnpm=
 is
that instead of clearing a bit in henvcfg to hide the extension from the gu=
est,
we reject calls to sbi_fwft_set(POINTER_MASKING_PMLEN, ...) when the ISA
extension is hidden from the guest.

Regards,
Samuel

[1]: https://github.com/riscv-non-isa/riscv-sbi-doc/pull/161

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/4c010cb1-b57c-427e-a241-1dd3ab15f2ce%40sifive.com.
