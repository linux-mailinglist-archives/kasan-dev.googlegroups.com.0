Return-Path: <kasan-dev+bncBCMIFTP47IJBBX664G3AMGQERB7G7OQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FBE396C093
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Sep 2024 16:32:01 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id 41be03b00d2f7-778702b9f8fsf752599a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Sep 2024 07:32:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725460320; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZChdgeuM+XgmENBUA00zeUxzRFiGrJQQzwkXEzsCcfXGxg/6dI4e9ARgHs1ZMeSmL+
         TzhUu7oltBn0CzmK/zxQOqzscAH6ShydS/ycHACWLWluZa4xwSNhOcg+bN0kdE97X8p+
         KtfECk83XlN3PdaZ+sU3jMQkTaVTVGtKp9DFUt+hXivV61UAlvJ5j4xT+Te/+8CYTWcV
         6v2L5mmTQmSl+v304SVLdEQcrvymYoKhjJ7v5P459/a1DfUudUebJEpK2/g0TUuzL8Wy
         K95XpdHfH20w+m6wjMb3RXwDS14jqo9Kju35+7SqkUp0S8chhvdf0abnLagPqqvuc2GX
         u+nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=v6lxApWpst8o4xktJO8NNGrFhn2P61lfB90VW9VYeaM=;
        fh=3DNY/Huopir2EfXk29rYoMLzkTYiuM8cNc/OqcWZgHI=;
        b=A3YCiiKzdHvt2aFZMHRjjlv0Xdgv/BUg6AAXgc5EyAZN9mfHq8SSo1TFK0AGIAhJHX
         0ndR5JD/KK0tf9hPXKXIk3GPJxiO7SqEEk+3ktNeQumXlRfhLTXJsxtE/GG5xjLsWIcP
         gouPV2UxOxvi943r9vQqZ2FKzcYgy8yFceYBG14yvJBn3LDG1gl+TwGEbDrbeyFsHVIi
         YHhAwknjc9Oz/+OFV2UCLUJJeZlPpiZ+onTqmbflFV8V1FDmOT68wRBmfAmJsiELjpYF
         TNMehp5n2AjI+W+h/BUcPPezAtyWVZHlrBjQhSEL31fhcOfBd3BYBoAoFjtxNHS5ouEM
         Pwfg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=B2avQAbF;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725460320; x=1726065120; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=v6lxApWpst8o4xktJO8NNGrFhn2P61lfB90VW9VYeaM=;
        b=wu9YwVZzL7lYGrL/F0Uf7JxcI+IScmXM871sKOH4P1i9lqGMIQYupbqq0l7pQ1Bess
         1e5YUZb7V76b9BU8KKIiFNS15xAnqlYbkUjT6Fv7CIOj/i46u/bDOMMa2WZvNjTiH8h3
         k8cUzszP+GTtem27vMmR25nFreXdcYshd8nvno82NoUEElBClulrup2jyIHo51/XczIf
         B59esRZ4cdbMksYbdMyfdibCNnIMqRnMFfVZQ5nVEwaYFy7QSa8QsyT31HutFxnx8I6e
         Qz42X+b3TRTvA3cES4lbSfmWT9IWmjMe2bg2j1+rV+ZYiDGvI1mBHUuFCr3WM3holZze
         FVgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725460320; x=1726065120;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=v6lxApWpst8o4xktJO8NNGrFhn2P61lfB90VW9VYeaM=;
        b=jJeRX8MV0xzsPG6xrz7JyDCfpF7jHaqsS03Hc4g99M9mVtZ2OM4WUZPUVnYzdN+/7l
         GuCyKsVV7RPF3/1fOSUnJZAQ3zkZVhrpQPlfFgGICvoJZWZQogRGiEpfOo0rwJkjTHfR
         cb+blPwoce6d04SGEtD9KLm0+laCQ0h3NXU/W/KgHqbyBxXm9bSJex7xoM20Wm+RsY3y
         VBVUMx0Imx290hJQXW482akmmnHbTh6ZftJEAKrmYM0+GWTb2aJrXZCyPe7gChNy1sYp
         OpqdU3wHC0mzvjgCox4mKOP3y3er5bScVfXc5pvcL4I0wlMaH9g01kid2+11PII/6YWe
         JFBw==
X-Forwarded-Encrypted: i=2; AJvYcCUzHuaZlAYSDMlM6dtwK1cftrfHZWoMdGo7627vLGSf680jxtW33JrV5IekdNYoL/Tqq3b8Ww==@lfdr.de
X-Gm-Message-State: AOJu0YzgmVBke1VzM0PBmOyq7gELLvVr3WO2fgLq0SX/S5f5d5PYDglp
	IGMHpa5YCKH16UxIjP5ho4ihaSGiYVMncBNx5lNOgs0jmuKJjptf
X-Google-Smtp-Source: AGHT+IGMtxzwqrW9+P65c46rjZv2CRlfLEVDPCrIucXVwTHozTuNmwQWPluZYzarowPJHOlulXe9Kw==
X-Received: by 2002:a17:90b:1d82:b0:2d8:7445:7ab2 with SMTP id 98e67ed59e1d1-2da8f2f7058mr3247650a91.20.1725460319960;
        Wed, 04 Sep 2024 07:31:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:17c9:b0:2c7:50ae:5c1b with SMTP id
 98e67ed59e1d1-2da849bf6cbls758344a91.2.-pod-prod-00-us; Wed, 04 Sep 2024
 07:31:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUtrmysOYZTKZKzE/4vcHQre7NOXgCqStPmiz7h+iuP5Inb6jx9jQwCO+vdRLdzxP0ETYIKlgP+eCI=@googlegroups.com
X-Received: by 2002:a17:90a:bc95:b0:2d8:8381:c68e with SMTP id 98e67ed59e1d1-2da8ebd420fmr3873051a91.8.1725460318746;
        Wed, 04 Sep 2024 07:31:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725460318; cv=none;
        d=google.com; s=arc-20240605;
        b=ifqaOElms20lGiNIawbG7E7iUOKYGouFIM6mxMqvqJNUgPV2rVQWTzi7UO2aNeCtm1
         AWl+d9YwJ3PX9WkFm71f9lv4ATdc2egYIACS98unuA0yAO5tTbxgf3anWiUrnAERKUyu
         ebgBXU3wAIBw7/mNC9xDsSGxeT1fjHOKDpRXfc4JOXyjyYXWnUDFLK+lg8QTzbp42tZh
         s60qrvTAWBU8YxxPJ3XropA9kYWIi8WyAnhVuRW7TevejmKAyJRQCGRatNw8nd6HrTT4
         WikUVEjssdVQWK4kegeK97SmtJjElpNPco3EXuThiRgDkgpGa6Xu2rUlkaYaTWtixzEY
         xAfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=7zATIwTHrXGiuEASzCytr2UxxMjPOWVj85mDZ7xtUWY=;
        fh=3Mqi6rrKDzjzOJW6cGZ01ufmCH05c2sxunDTLKFB3H0=;
        b=SxuTfup1x6fXg4i82J3X38iRt/LVWeDyrOajsRVrDBQOZgef3ryeAxladUJ8JXNWse
         5UBAkm2Z7++jv67VEyJvfmrdwM5dkuWuWvVHk1IuFvKEAWtPPuo9q+CEryYxwyz460Kj
         arcAY3FY57rX8mmEHchqTuyDbi2vMYAQFy/v5YWMf4tTj9Su5g3/JyDLMC3Q2do/XQop
         +YAdo3Y3c9Iflcep+Wa8L10X2M0G/Mc2IKZkfa8g27h91rY1j15U7+W/H3W19SpldslL
         27ijLFl6VU8NSJWH11ya/QRHY9dwu1pM0vvPwXZM47mfML8QQMPd7O0FMdqOvrF5PkRR
         iZqg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=B2avQAbF;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-io1-xd32.google.com (mail-io1-xd32.google.com. [2607:f8b0:4864:20::d32])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2da82d71c63si105161a91.2.2024.09.04.07.31.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Sep 2024 07:31:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::d32 as permitted sender) client-ip=2607:f8b0:4864:20::d32;
Received: by mail-io1-xd32.google.com with SMTP id ca18e2360f4ac-82a24dec9cbso29163639f.1
        for <kasan-dev@googlegroups.com>; Wed, 04 Sep 2024 07:31:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX/xBaHvBXSSw2OFkBXaFQ0MUVknD7Y59Q5fFWjH+Dmp/vMTyLGoe23ZwYH6OBOhCRw3j/TY51JtcA=@googlegroups.com
X-Received: by 2002:a6b:7e0c:0:b0:806:3dac:5081 with SMTP id ca18e2360f4ac-82a7920d595mr183512639f.7.1725460317814;
        Wed, 04 Sep 2024 07:31:57 -0700 (PDT)
Received: from [100.64.0.1] ([147.124.94.167])
        by smtp.gmail.com with ESMTPSA id 8926c6da1cb9f-4ced2ee8559sm3114240173.174.2024.09.04.07.31.56
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Sep 2024 07:31:57 -0700 (PDT)
Message-ID: <b6de8769-7e4e-4a19-b239-a39fd424e0c8@sifive.com>
Date: Wed, 4 Sep 2024 09:31:55 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 09/10] RISC-V: KVM: Allow Smnpm and Ssnpm extensions
 for guests
To: Anup Patel <apatel@ventanamicro.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org,
 devicetree@vger.kernel.org, Catalin Marinas <catalin.marinas@arm.com>,
 linux-kernel@vger.kernel.org, Anup Patel <anup@brainfault.org>,
 Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com,
 Atish Patra <atishp@atishpatra.org>, Evgenii Stepanov <eugenis@google.com>,
 Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
 Rob Herring <robh+dt@kernel.org>,
 "Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>,
 kvm-riscv@lists.infradead.org
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
 <20240829010151.2813377-10-samuel.holland@sifive.com>
 <CAK9=C2WjraWjuQCeU2Y4Jhr-gKkOcP42Sza7wVp0FgeGaD923g@mail.gmail.com>
Content-Language: en-US
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CAK9=C2WjraWjuQCeU2Y4Jhr-gKkOcP42Sza7wVp0FgeGaD923g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=B2avQAbF;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

On 2024-09-04 7:17 AM, Anup Patel wrote:
> On Thu, Aug 29, 2024 at 6:32=E2=80=AFAM Samuel Holland
> <samuel.holland@sifive.com> wrote:
>>
>> The interface for controlling pointer masking in VS-mode is henvcfg.PMM,
>> which is part of the Ssnpm extension, even though pointer masking in
>> HS-mode is provided by the Smnpm extension. As a result, emulating Smnpm
>> in the guest requires (only) Ssnpm on the host.
>>
>> Since the guest configures Smnpm through the SBI Firmware Features
>> interface, the extension can be disabled by failing the SBI call. Ssnpm
>> cannot be disabled without intercepting writes to the senvcfg CSR.
>>
>> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
>> ---
>>
>> (no changes since v2)
>>
>> Changes in v2:
>>  - New patch for v2
>>
>>  arch/riscv/include/uapi/asm/kvm.h | 2 ++
>>  arch/riscv/kvm/vcpu_onereg.c      | 3 +++
>>  2 files changed, 5 insertions(+)
>>
>> diff --git a/arch/riscv/include/uapi/asm/kvm.h b/arch/riscv/include/uapi=
/asm/kvm.h
>> index e97db3296456..4f24201376b1 100644
>> --- a/arch/riscv/include/uapi/asm/kvm.h
>> +++ b/arch/riscv/include/uapi/asm/kvm.h
>> @@ -175,6 +175,8 @@ enum KVM_RISCV_ISA_EXT_ID {
>>         KVM_RISCV_ISA_EXT_ZCF,
>>         KVM_RISCV_ISA_EXT_ZCMOP,
>>         KVM_RISCV_ISA_EXT_ZAWRS,
>> +       KVM_RISCV_ISA_EXT_SMNPM,
>> +       KVM_RISCV_ISA_EXT_SSNPM,
>>         KVM_RISCV_ISA_EXT_MAX,
>>  };
>>
>> diff --git a/arch/riscv/kvm/vcpu_onereg.c b/arch/riscv/kvm/vcpu_onereg.c
>> index b319c4c13c54..6f833ec2344a 100644
>> --- a/arch/riscv/kvm/vcpu_onereg.c
>> +++ b/arch/riscv/kvm/vcpu_onereg.c
>> @@ -34,9 +34,11 @@ static const unsigned long kvm_isa_ext_arr[] =3D {
>>         [KVM_RISCV_ISA_EXT_M] =3D RISCV_ISA_EXT_m,
>>         [KVM_RISCV_ISA_EXT_V] =3D RISCV_ISA_EXT_v,
>>         /* Multi letter extensions (alphabetically sorted) */
>> +       [KVM_RISCV_ISA_EXT_SMNPM] =3D RISCV_ISA_EXT_SSNPM,
>=20
> Why not use KVM_ISA_EXT_ARR() macro here ?

Because the extension name in the host does not match the extension name in=
 the
guest. Pointer masking for HS mode is provided by Smnpm. Pointer masking fo=
r VS
mode is provided by Ssnpm at the hardware level, but this needs to appear t=
o the
guest as if Smnpm was implemented, since the guest thinks it is running on =
bare
metal.

>>         KVM_ISA_EXT_ARR(SMSTATEEN),
>>         KVM_ISA_EXT_ARR(SSAIA),
>>         KVM_ISA_EXT_ARR(SSCOFPMF),
>> +       KVM_ISA_EXT_ARR(SSNPM),
>>         KVM_ISA_EXT_ARR(SSTC),
>>         KVM_ISA_EXT_ARR(SVINVAL),
>>         KVM_ISA_EXT_ARR(SVNAPOT),
>> @@ -129,6 +131,7 @@ static bool kvm_riscv_vcpu_isa_disable_allowed(unsig=
ned long ext)
>>         case KVM_RISCV_ISA_EXT_M:
>>         /* There is not architectural config bit to disable sscofpmf com=
pletely */
>>         case KVM_RISCV_ISA_EXT_SSCOFPMF:
>> +       case KVM_RISCV_ISA_EXT_SSNPM:
>=20
> Why not add KVM_RISCV_ISA_EXT_SMNPM here ?
>=20
> Disabling Smnpm from KVM user space is very different from
> disabling Smnpm from Guest using SBI FWFT extension.

Until a successful SBI FWFT call to KVM to enable pointer masking for VS mo=
de,
the existence of Smnpm has no visible effect on the guest. So failing the S=
BI
call is sufficient to pretend that the hardware does not support Smnpm.

> The KVM user space should always add Smnpm in the
> Guest ISA string whenever the Host ISA string has it.

I disagree. Allowing userspace to disable extensions is useful for testing =
and
to support migration to hosts which do not support those extensions. So I w=
ould
only add extensions to this list if there is no possible way to disable the=
m.

> The Guest must explicitly use SBI FWFT to enable
> Smnpm only after it sees Smnpm in ISA string.

Yes, exactly, and the purpose of not including Smnpm in the switch case her=
e is
so that KVM user space can control whether or not it appears in the ISA str=
ing.

Regards,
Samuel

>>         case KVM_RISCV_ISA_EXT_SSTC:
>>         case KVM_RISCV_ISA_EXT_SVINVAL:
>>         case KVM_RISCV_ISA_EXT_SVNAPOT:
>> --
>> 2.45.1
>>
>>
>> _______________________________________________
>> linux-riscv mailing list
>> linux-riscv@lists.infradead.org
>> http://lists.infradead.org/mailman/listinfo/linux-riscv
>=20
> Regards,
> Anup

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/b6de8769-7e4e-4a19-b239-a39fd424e0c8%40sifive.com.
