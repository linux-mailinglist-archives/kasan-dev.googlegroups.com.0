Return-Path: <kasan-dev+bncBDFJHU6GRMBBBFHF4G3AMGQEYQWF4HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2042A96C111
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Sep 2024 16:45:42 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-277e5e84a54sf4396819fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Sep 2024 07:45:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725461141; cv=pass;
        d=google.com; s=arc-20240605;
        b=QY9NEOXcHOqxwDDJAbmsJ8X+NQtIXJFNdEyWIb+l126otFbWAMJYcDsYZaDTg7GtTH
         JnSFMARs6AHZD9gYwPCiWXjKzmKCa7uLbH/mqgh2wNqzHVIGd3DBc03qVml+Uy/2baSJ
         c0n8HQIlBs4BjjNYrT55hL/+JYQIRyp+9yMv6g7wrOSosQYf88Gw080DyL3/+JY1t43n
         /8a3ATblM597Sj9UJrO5qL7e9UqAKWBLJFbjbmLMHdQi1/NZtryYYrLgtaVeZbZIxG8F
         ynenCrTuy/kDyawiH/OK1GC4aDm4Rb6TVNvUqUHZL1TuCzA+mdWtZmMHMSP2lWAmQJY4
         4Wcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=fSTJMmdimGE6L5XGLevDPuc9ruMAXDp18SuQwwvuySw=;
        fh=rYMv7UmDoTwZHLonxEac8RF7jq2GXQTJl1/Rky5p7J0=;
        b=SlRicF8pZXAwYrbzBnTN5coAvnT23oH7HWOXcj/GvxlPiKPy+0fCdYVqyAWWBHUDec
         oaeY7T65753A472I5LbxcKPqRNSSpWOyXqfAVcqOf4svLorkwi6i4QRfE+P9Cw0N9o6Q
         pW200e80vz9hMtrIokSMXzmv82ftPA/C1TybZcOPQPC/lg74G2yWtQNX/giTDMztEou6
         tmHVK/GsE6JC9xhOvhvALGBo8UsUN0IPvaLBFptRZSNo5JJsR7Z6n+rOR9Fs2VxU1xWm
         1odf/jptJTuqmEBUGB9eBJjqdFkllLn2UFqsIDG90x7OF5rCxV0ThdxSW5/Rme+ttADr
         ZreA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20230601.gappssmtp.com header.s=20230601 header.b=evIOXXLV;
       spf=neutral (google.com: 2607:f8b0:4864:20::136 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725461141; x=1726065941; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=fSTJMmdimGE6L5XGLevDPuc9ruMAXDp18SuQwwvuySw=;
        b=izPqw3o6IrSMFCCNFR2Ho5aDj46aMGsfVYIN3zVUpE5FMfPIKx5OH5mzp+J4x7/LOQ
         mERkRTkJNk//isxo0lQvMtZgEt50aY21ih/OI9/V3AqMrmaG2i4zJhLcMqpnFRL/ZKw1
         nEOoUJP+sag00R8wtGwXxvD2qEchh5wOmyrfz0GxVZqBvjHr6ASXqHxh9/NxARc2EKnj
         Ch7phG3N6kuN/7SkKjBZMeoAQAMlzQxTgPp0ymMORRECl1bG0w0hTxcaEuhkGjIGy18w
         Xc/ls69XViTCRgSbndQdd0X+R7B62m/GqyQhAou2XaoJ5LDhv3UQ90id1lrWo6WifPLj
         m7tw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725461141; x=1726065941;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=fSTJMmdimGE6L5XGLevDPuc9ruMAXDp18SuQwwvuySw=;
        b=bBxKxnorBMf8m6yaLF7a23+FWiIfVFHvKtkYhldcoUWg2/D9BVy7lum7Wl1G/8j8++
         aa2SN1xyHQyvtcf0ic5DPKm3yK2rYMNDGhG7bqfxS/qCWMEa+hyWkRs1iN+mfDXlducL
         CHP1nEZpCsDVjJBE8cFPcGAO82snsrzo6z8EZRjY+ajQ80IJ0x/SKEehlH+iITiCef/q
         BGBFo/YgvraKXR6M11G7tX46dGAIjAe85t1NyxUgXZ/7G7r94xvag6MAKTLNZYl6pyRe
         xVxU2fX028ANLkVXaL73eUKR0CsKPCQB+Igl2+WPHv7bgd79F70D35opWP/tAgrSicT7
         I/8Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWgAuMGZOiwf5tQd/g/u2UyLoG//a8CezuycVg70ovSK/5AKjIhNDk/EfnS/pkx03HpMEnjuA==@lfdr.de
X-Gm-Message-State: AOJu0YzGDwacdVuIVI870IEOTzDpMClQ771H0v/SHU8RhXkhMd6OJSez
	iS4oanXy2YKTvTTQycPE2vdz7Eh4x/gEHLCH9JI3TKNYCxfvvl/E
X-Google-Smtp-Source: AGHT+IEB8ajY3SZSfYaZw+hKC+HkSJzTv1CWac5ERdID4NwVEH0WjhyUZwixeCTUitjjpNDDVdwe1w==
X-Received: by 2002:a05:6871:e40f:b0:277:eb15:5c60 with SMTP id 586e51a60fabf-277fffbef9dmr10287252fac.10.1725461140630;
        Wed, 04 Sep 2024 07:45:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:ff91:b0:25e:160c:c90 with SMTP id
 586e51a60fabf-2778f53fcbcls4119319fac.2.-pod-prod-08-us; Wed, 04 Sep 2024
 07:45:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWzjWq64QT8sIQVtIbUib+SB/iNAha0wUdQ+ZFrZOTD3BL1RuOKJf5IEDd2x176PpeZqeC1nXzJE4g=@googlegroups.com
X-Received: by 2002:a05:6871:5813:b0:270:c1e:41ad with SMTP id 586e51a60fabf-27800506b9bmr10574672fac.35.1725461139005;
        Wed, 04 Sep 2024 07:45:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725461138; cv=none;
        d=google.com; s=arc-20240605;
        b=A2uz/+YHVOpnMSY9ui2kpGQSq0JtkBY7wj8oj0o55OPgog78N52PzhlMtLTnGkomrD
         4kltK3i21rlpBJHCUM2MPahowsoDmPoGTc6WekJZ/EWwlnVQ3UlYUcbLTwGs63rvAffx
         1T69QkNp/C5jqmdNMJFiQld2VvDSlP8cEeHFn92kyqm+XT3Upl2/AFnMFN5RqZ342wi2
         AUNOEyPbaUmuuqKUS3FsBl2gg6L5nI9YW6a6vvid/CqaVNgGdIU9eRP9c+uxSO8bdbkw
         4+irVkmH7zHS8Ksiz1DtYyz9nKTCPpZHFP2/jM2isBRengafmYvxUhVcPMs5iHPtK518
         Bdiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=51nJ3+dnXamTe1z0PXS6eJAv/Sucabjt3mu+GvHMgUs=;
        fh=hgzjmYvyUDl+6yICHMC1u9IukIlSheTBocuUs1T59EA=;
        b=LmlnzQdeflRZB+g95Fk7Jr1STLJb2HH9guZ9IFDQGWnYBRsQHlGjWRXWwFpCYuMXqx
         VoZNszIf3oAXoE/U2L+SmWapzwhb0Hwd6eUjAIX0KnqGcMVI66prafYeBes6A5E+9uRl
         gCmiwVCYN4ppEVbYOKcL/OgyLf4mMxIjXvRQaZCTOfgL/YJXSeDuIvbULY9xpj82t11a
         eWEhFlFO1gIdmxsvNHGsqwo20rJDIeqCg7YBS4JDmw9uekf17lgOv4yK1yI7sqgo4i2O
         nQOeSunwChdMCLUuhVjVVbkWg48kImropD0tJih/pgsf2kx0jCfDKMxSL49s+V/OKfP4
         JaMA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20230601.gappssmtp.com header.s=20230601 header.b=evIOXXLV;
       spf=neutral (google.com: 2607:f8b0:4864:20::136 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-il1-x136.google.com (mail-il1-x136.google.com. [2607:f8b0:4864:20::136])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-71778627fd1si108147b3a.5.2024.09.04.07.45.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Sep 2024 07:45:38 -0700 (PDT)
Received-SPF: neutral (google.com: 2607:f8b0:4864:20::136 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) client-ip=2607:f8b0:4864:20::136;
Received: by mail-il1-x136.google.com with SMTP id e9e14a558f8ab-39f4ff22a49so17176375ab.1
        for <kasan-dev@googlegroups.com>; Wed, 04 Sep 2024 07:45:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUE7oTtIjKhKw3MezPR0yCO7hrJQsra3pFHOI9Mf7HaWUgQ6gw4l9aFeFFzgWZ3w66xyStLNbdq7lc=@googlegroups.com
X-Received: by 2002:a05:6e02:52c:b0:39f:558a:e404 with SMTP id
 e9e14a558f8ab-39f558ae637mr120606115ab.4.1725461138110; Wed, 04 Sep 2024
 07:45:38 -0700 (PDT)
MIME-Version: 1.0
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
 <20240829010151.2813377-10-samuel.holland@sifive.com> <CAK9=C2WjraWjuQCeU2Y4Jhr-gKkOcP42Sza7wVp0FgeGaD923g@mail.gmail.com>
 <b6de8769-7e4e-4a19-b239-a39fd424e0c8@sifive.com>
In-Reply-To: <b6de8769-7e4e-4a19-b239-a39fd424e0c8@sifive.com>
From: Anup Patel <anup@brainfault.org>
Date: Wed, 4 Sep 2024 20:15:27 +0530
Message-ID: <CAAhSdy08SoDoZCii9R--BK7_NKLnRciW7V3mo2aQRKW1dbOgNg@mail.gmail.com>
Subject: Re: [PATCH v4 09/10] RISC-V: KVM: Allow Smnpm and Ssnpm extensions
 for guests
To: Samuel Holland <samuel.holland@sifive.com>
Cc: Anup Patel <apatel@ventanamicro.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	linux-riscv@lists.infradead.org, devicetree@vger.kernel.org, 
	Catalin Marinas <catalin.marinas@arm.com>, linux-kernel@vger.kernel.org, 
	Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com, 
	Atish Patra <atishp@atishpatra.org>, Evgenii Stepanov <eugenis@google.com>, 
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>, Rob Herring <robh+dt@kernel.org>, 
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>, kvm-riscv@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: anup@brainfault.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@brainfault-org.20230601.gappssmtp.com header.s=20230601
 header.b=evIOXXLV;       spf=neutral (google.com: 2607:f8b0:4864:20::136 is
 neither permitted nor denied by best guess record for domain of
 anup@brainfault.org) smtp.mailfrom=anup@brainfault.org;       dara=pass header.i=@googlegroups.com
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

On Wed, Sep 4, 2024 at 8:01=E2=80=AFPM Samuel Holland <samuel.holland@sifiv=
e.com> wrote:
>
> Hi Anup,
>
> On 2024-09-04 7:17 AM, Anup Patel wrote:
> > On Thu, Aug 29, 2024 at 6:32=E2=80=AFAM Samuel Holland
> > <samuel.holland@sifive.com> wrote:
> >>
> >> The interface for controlling pointer masking in VS-mode is henvcfg.PM=
M,
> >> which is part of the Ssnpm extension, even though pointer masking in
> >> HS-mode is provided by the Smnpm extension. As a result, emulating Smn=
pm
> >> in the guest requires (only) Ssnpm on the host.
> >>
> >> Since the guest configures Smnpm through the SBI Firmware Features
> >> interface, the extension can be disabled by failing the SBI call. Ssnp=
m
> >> cannot be disabled without intercepting writes to the senvcfg CSR.
> >>
> >> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> >> ---
> >>
> >> (no changes since v2)
> >>
> >> Changes in v2:
> >>  - New patch for v2
> >>
> >>  arch/riscv/include/uapi/asm/kvm.h | 2 ++
> >>  arch/riscv/kvm/vcpu_onereg.c      | 3 +++
> >>  2 files changed, 5 insertions(+)
> >>
> >> diff --git a/arch/riscv/include/uapi/asm/kvm.h b/arch/riscv/include/ua=
pi/asm/kvm.h
> >> index e97db3296456..4f24201376b1 100644
> >> --- a/arch/riscv/include/uapi/asm/kvm.h
> >> +++ b/arch/riscv/include/uapi/asm/kvm.h
> >> @@ -175,6 +175,8 @@ enum KVM_RISCV_ISA_EXT_ID {
> >>         KVM_RISCV_ISA_EXT_ZCF,
> >>         KVM_RISCV_ISA_EXT_ZCMOP,
> >>         KVM_RISCV_ISA_EXT_ZAWRS,
> >> +       KVM_RISCV_ISA_EXT_SMNPM,
> >> +       KVM_RISCV_ISA_EXT_SSNPM,
> >>         KVM_RISCV_ISA_EXT_MAX,
> >>  };
> >>
> >> diff --git a/arch/riscv/kvm/vcpu_onereg.c b/arch/riscv/kvm/vcpu_onereg=
.c
> >> index b319c4c13c54..6f833ec2344a 100644
> >> --- a/arch/riscv/kvm/vcpu_onereg.c
> >> +++ b/arch/riscv/kvm/vcpu_onereg.c
> >> @@ -34,9 +34,11 @@ static const unsigned long kvm_isa_ext_arr[] =3D {
> >>         [KVM_RISCV_ISA_EXT_M] =3D RISCV_ISA_EXT_m,
> >>         [KVM_RISCV_ISA_EXT_V] =3D RISCV_ISA_EXT_v,
> >>         /* Multi letter extensions (alphabetically sorted) */
> >> +       [KVM_RISCV_ISA_EXT_SMNPM] =3D RISCV_ISA_EXT_SSNPM,
> >
> > Why not use KVM_ISA_EXT_ARR() macro here ?
>
> Because the extension name in the host does not match the extension name =
in the
> guest. Pointer masking for HS mode is provided by Smnpm. Pointer masking =
for VS
> mode is provided by Ssnpm at the hardware level, but this needs to appear=
 to the
> guest as if Smnpm was implemented, since the guest thinks it is running o=
n bare
> metal.

Okay, makes sense.

>
> >>         KVM_ISA_EXT_ARR(SMSTATEEN),
> >>         KVM_ISA_EXT_ARR(SSAIA),
> >>         KVM_ISA_EXT_ARR(SSCOFPMF),
> >> +       KVM_ISA_EXT_ARR(SSNPM),
> >>         KVM_ISA_EXT_ARR(SSTC),
> >>         KVM_ISA_EXT_ARR(SVINVAL),
> >>         KVM_ISA_EXT_ARR(SVNAPOT),
> >> @@ -129,6 +131,7 @@ static bool kvm_riscv_vcpu_isa_disable_allowed(uns=
igned long ext)
> >>         case KVM_RISCV_ISA_EXT_M:
> >>         /* There is not architectural config bit to disable sscofpmf c=
ompletely */
> >>         case KVM_RISCV_ISA_EXT_SSCOFPMF:
> >> +       case KVM_RISCV_ISA_EXT_SSNPM:
> >
> > Why not add KVM_RISCV_ISA_EXT_SMNPM here ?
> >
> > Disabling Smnpm from KVM user space is very different from
> > disabling Smnpm from Guest using SBI FWFT extension.
>
> Until a successful SBI FWFT call to KVM to enable pointer masking for VS =
mode,
> the existence of Smnpm has no visible effect on the guest. So failing the=
 SBI
> call is sufficient to pretend that the hardware does not support Smnpm.
>
> > The KVM user space should always add Smnpm in the
> > Guest ISA string whenever the Host ISA string has it.
>
> I disagree. Allowing userspace to disable extensions is useful for testin=
g and
> to support migration to hosts which do not support those extensions. So I=
 would
> only add extensions to this list if there is no possible way to disable t=
hem.

I am not saying to disallow KVM user space disabling Smnpm.

The presence of Smnpm in ISA only means that it is present in HW
but it needs to be explicitly configured/enabled using SBI FWFT.

KVM user space can certainly disable extensions by not adding it to
ISA string based on the KVMTOOL/QEMU-KVM command line option.
Additionally, when SBI FWFT is added to KVM RISC-V. It will have its
own way to explicitly disable firmware features from KVM user space.

>
> > The Guest must explicitly use SBI FWFT to enable
> > Smnpm only after it sees Smnpm in ISA string.
>
> Yes, exactly, and the purpose of not including Smnpm in the switch case h=
ere is
> so that KVM user space can control whether or not it appears in the ISA s=
tring.
>
> Regards,
> Samuel
>
> >>         case KVM_RISCV_ISA_EXT_SSTC:
> >>         case KVM_RISCV_ISA_EXT_SVINVAL:
> >>         case KVM_RISCV_ISA_EXT_SVNAPOT:
> >> --
> >> 2.45.1
> >>
> >>
> >> _______________________________________________
> >> linux-riscv mailing list
> >> linux-riscv@lists.infradead.org
> >> http://lists.infradead.org/mailman/listinfo/linux-riscv
> >
> > Regards,
> > Anup
>

Regards,
Anup

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhSdy08SoDoZCii9R--BK7_NKLnRciW7V3mo2aQRKW1dbOgNg%40mail.gmail.=
com.
