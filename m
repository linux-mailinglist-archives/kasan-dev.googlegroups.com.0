Return-Path: <kasan-dev+bncBDFJHU6GRMBBBT7V4G3AMGQEFVT2TKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 78A8996C21C
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Sep 2024 17:20:49 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-2d8a1a63f3dsf4173010a91.2
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Sep 2024 08:20:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725463248; cv=pass;
        d=google.com; s=arc-20240605;
        b=FJ91OzRXJ0WEUATuf/DkJSRRQbPRxrqkAw8PHBkBhdf/TwT4rA7yBCxCuuzwT20LFI
         bZ63SdbLL3uKKFJlPQhl+QPvgNoh2xkFfVWjHJKubH2V0BGXDtRq9M9pxM6aP66Gv2mm
         FDpQq9iPDm3eHZNejrGO0EoCiRjFUGaE1Rk9auHWnDPeebCQUDr07Sgi+5ksaiJ/3B3K
         Ob7X7mbFwXGHogftIUI0FveIrTfePYO/SsKpxtg7m2Oa1+AkLq27FbEuyE7asvv9pO+4
         78qRjiDhap2ZlQ7aEZ3yCBrDuSuSBDOqnuAoHS0Gty+oVKkSyKFt/AfhSvzAXacqqUQf
         tfJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=buG179o5RMjGaMhH7KASrKvjiDdN+K1ObT66KeQO71o=;
        fh=3GgkscNZkr84jfLAtnqhbUeQ4sEgd8a6KGGmn8gl9SI=;
        b=lxTq8TM1J+8ALh33qrciZXrjf0VUu3QQiJNCnrY9PTSjHR2B3As7iEQg9qpRzho2gV
         q9d2bRhVuxDIpCtU7CILc99u8JqvNhsj2xgReERkgiUceZaaE8DD2yiKo/QRy3eEvhsI
         IibosuQFT2NsoH36qyKncfhGZiVRWJ0pcuT2G6vzeND3ViO7xxazlMufk6WmeYUsCHzS
         m9FmuLGTLuFrpkz0RYP370Zdq4+DLvvOAUsJ7hkaCs6BRgGXwobotcVpdF56kfFKS//v
         FS3Hr3K0hjKz9gFkJ3l3nuY9dwiIGoeJVgsqhOI+9nTpFMMQCbAKBoa2Bov0cnOngCdC
         E1DA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20230601.gappssmtp.com header.s=20230601 header.b=cZITtIIn;
       spf=neutral (google.com: 2607:f8b0:4864:20::12f is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725463248; x=1726068048; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=buG179o5RMjGaMhH7KASrKvjiDdN+K1ObT66KeQO71o=;
        b=ZQWItIifN/858w5UW4yevmiyJgC804vdlFctu8jtIAQ9wYnZN7XZoDBt3A1cdY8wE9
         0slObPkTCLb8ztvnfhQmbuYCkEuprBG8oAVZhraBECKcyv1fhQhYi4TFtkiuPUtc7Df5
         sQyHlkbuDMVsJpyi79lGIncT9TcynxzYEpUXePRUBZlwgAGl5+Hlb3z0BV8S3fO1VQ4c
         bez9a2Tn+p9d6yX8cPuuPFuSGLJZlRFjpYEMwKbKyMa9NCPlzVrieA0v38s7L+uyKuoI
         7QMNdRB5IQOoE4oiaHOw/RRSAc056nkRPNgMy/nTF+g0DPJipoi70fet3d2S/bU07NqM
         zOtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725463248; x=1726068048;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=buG179o5RMjGaMhH7KASrKvjiDdN+K1ObT66KeQO71o=;
        b=hx0SJsLtXeAsXu8j/d3gVh7n+vChESg+HVrBfrbYW4ssCi40vnfPzEj4vNq6yKJJcJ
         +DvHC84RN9Ya6/AqWatrZQ/6JPFLUhfrEULRZtJ+7hBzs0/XC9jSfXuXuKueIaRw8t9D
         xzB+q9WdD5vaN5buExOTPeCSXz0cCuQffmFJ2F5Tw30CEIoY44V4VBgVQMHYKPvm1TCb
         q2HqeQq7UC68WNHOR5d/wsE9cwgzDMk4sXoy+52LsyD+iskJz87QmN6qMwL0LwYAerBc
         DrNXmyrtgPXRmxLxB6XH1wwvyc4klrZkGIz2m2Bmw/7S9QFJ9Ck7FjdQVgMhsdBXldsO
         Hneg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWfGBZs6iLpLrR91iopaTJUP8TJvfJkLge4qPZ5zvShRhUXYtNJGS6SUvtRE/JfNbj3tq8V/A==@lfdr.de
X-Gm-Message-State: AOJu0YwtUOm6xGl+nQeOU8LpmOEOmKotVyzW4zhC+JNYexdDdWcVwASd
	fLe+qAaMAEstyUJszWXkUhGddWF3CgtoiC/I2ox6B2BzeHxO4Hd/
X-Google-Smtp-Source: AGHT+IHXphph/HiJLVeoKz6kaYt85De9W3ZY+U45pirWvAudI0YoDaS6aBdLFtHQ2yd7Sdhb3fEeYA==
X-Received: by 2002:a17:90b:33cb:b0:2d8:94f1:b572 with SMTP id 98e67ed59e1d1-2da5597aa17mr8114522a91.18.1725463247872;
        Wed, 04 Sep 2024 08:20:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:b018:b0:2d8:d2c6:e0b8 with SMTP id
 98e67ed59e1d1-2d8d2c6ebccls1820840a91.2.-pod-prod-04-us; Wed, 04 Sep 2024
 08:20:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUT9uHrHx0MktL4xGW9kcawcNFaEdQK2PlX9wMUrLOyDhhfuuU0IRWbervn1IQiL2VIe0QREb34/Fs=@googlegroups.com
X-Received: by 2002:a17:90b:17cd:b0:2d8:d081:e8ee with SMTP id 98e67ed59e1d1-2da5597b1ddmr7792590a91.20.1725463246677;
        Wed, 04 Sep 2024 08:20:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725463246; cv=none;
        d=google.com; s=arc-20240605;
        b=I4MwXcgn0U9LZNCmhuJgC614S4dyDEXzCYCmsOwj0/chge5GIoFXCs7ISeWPc/crhi
         GdY7JeKrxITvQoVZ3sSoFG5Kh4Y3vEUKnLWPg52QXgziSzjTDAP+RPsADaCXqNLyApjn
         tGHZQZLY0Y+1qHMKVpcpvnk2zj+ioxULBmuHWcRsXWwUVK5kFkYokWu5BnpGEm+Zkc48
         jcekUp5eIaDURO8D4wAhut9NY13v2woLkreMy0ESPcUD3Lx/tGZWfPV63g3y22+xEHHb
         hGWd0WmnOxhrTDLsC9rqZVz9C8z9c99A/sitT/+UIsxO3VWsZvT0LhfyvE7uxEv/eQQz
         kYhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=FhDF0SQeiM2A3Xk/DMuv3JXuwNqZLtLOCwSo8gz5fyA=;
        fh=M6vE5siJ3BTc4byhE0oQpfY7nVMh7zh+RXsWnrSfL7k=;
        b=JAWJE26UFLmu09sO1Gb4bVmqQTnt5FsU8dq98pa1uIVxxtOCdUtFsTyRXdGGEyH69Y
         3LpE29wR0DfmpuNpNuOleTVqRUpCiLqE9ojVvzHNYGEDXvw9v5dOD2y/Qz2k7Evml0c5
         AWNI/FaWniF7HhIDveRfCOgKjvHQRojTaFhXhUeNwkihRIyEUTjGJo9lRCtqwL4yvlBG
         pgBSjFw6HiqzgotrrJSQT1KSAE0Caz3FY4bZD4z35pdP0VCVSqn9u2A01/Ht8OSY2j9g
         jeX8Eduv78BJ7OxbBLVLItHgJbchzHaSgjXKhyn8OGg7so0DVT2WZQfBM4pRrYyWEOvt
         xoag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20230601.gappssmtp.com header.s=20230601 header.b=cZITtIIn;
       spf=neutral (google.com: 2607:f8b0:4864:20::12f is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-il1-x12f.google.com (mail-il1-x12f.google.com. [2607:f8b0:4864:20::12f])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2d8b68d3d22si386240a91.1.2024.09.04.08.20.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Sep 2024 08:20:46 -0700 (PDT)
Received-SPF: neutral (google.com: 2607:f8b0:4864:20::12f is neither permitted nor denied by best guess record for domain of anup@brainfault.org) client-ip=2607:f8b0:4864:20::12f;
Received: by mail-il1-x12f.google.com with SMTP id e9e14a558f8ab-39fd6a9acb6so2629175ab.0
        for <kasan-dev@googlegroups.com>; Wed, 04 Sep 2024 08:20:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU/I5o0iCISx02qp3P20lVLrgylSdM576ZeLpdbNe78R0PASG6I3A/+bDbYgj8wZYIWXQf4VEPksqs=@googlegroups.com
X-Received: by 2002:a05:6e02:2181:b0:39d:376b:20cb with SMTP id
 e9e14a558f8ab-39f6aa30e14mr79570475ab.25.1725463245792; Wed, 04 Sep 2024
 08:20:45 -0700 (PDT)
MIME-Version: 1.0
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
 <20240829010151.2813377-10-samuel.holland@sifive.com> <CAK9=C2WjraWjuQCeU2Y4Jhr-gKkOcP42Sza7wVp0FgeGaD923g@mail.gmail.com>
 <b6de8769-7e4e-4a19-b239-a39fd424e0c8@sifive.com> <CAAhSdy08SoDoZCii9R--BK7_NKLnRciW7V3mo2aQRKW1dbOgNg@mail.gmail.com>
 <20ab0fa2-d5dd-446d-9fff-a3ef82e8db35@sifive.com>
In-Reply-To: <20ab0fa2-d5dd-446d-9fff-a3ef82e8db35@sifive.com>
From: Anup Patel <anup@brainfault.org>
Date: Wed, 4 Sep 2024 20:50:35 +0530
Message-ID: <CAAhSdy1pZcEfajg3OZUCaFf9JMYcMzpRVogCT5VL2FHx__vDdA@mail.gmail.com>
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
 header.b=cZITtIIn;       spf=neutral (google.com: 2607:f8b0:4864:20::12f is
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

On Wed, Sep 4, 2024 at 8:27=E2=80=AFPM Samuel Holland <samuel.holland@sifiv=
e.com> wrote:
>
> Hi Anup,
>
> On 2024-09-04 9:45 AM, Anup Patel wrote:
> > On Wed, Sep 4, 2024 at 8:01=E2=80=AFPM Samuel Holland <samuel.holland@s=
ifive.com> wrote:
> >> On 2024-09-04 7:17 AM, Anup Patel wrote:
> >>> On Thu, Aug 29, 2024 at 6:32=E2=80=AFAM Samuel Holland
> >>> <samuel.holland@sifive.com> wrote:
> >>>>
> >>>> The interface for controlling pointer masking in VS-mode is henvcfg.=
PMM,
> >>>> which is part of the Ssnpm extension, even though pointer masking in
> >>>> HS-mode is provided by the Smnpm extension. As a result, emulating S=
mnpm
> >>>> in the guest requires (only) Ssnpm on the host.
> >>>>
> >>>> Since the guest configures Smnpm through the SBI Firmware Features
> >>>> interface, the extension can be disabled by failing the SBI call. Ss=
npm
> >>>> cannot be disabled without intercepting writes to the senvcfg CSR.
> >>>>
> >>>> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> >>>> ---
> >>>>
> >>>> (no changes since v2)
> >>>>
> >>>> Changes in v2:
> >>>>  - New patch for v2
> >>>>
> >>>>  arch/riscv/include/uapi/asm/kvm.h | 2 ++
> >>>>  arch/riscv/kvm/vcpu_onereg.c      | 3 +++
> >>>>  2 files changed, 5 insertions(+)
> >>>>
> >>>> diff --git a/arch/riscv/include/uapi/asm/kvm.h b/arch/riscv/include/=
uapi/asm/kvm.h
> >>>> index e97db3296456..4f24201376b1 100644
> >>>> --- a/arch/riscv/include/uapi/asm/kvm.h
> >>>> +++ b/arch/riscv/include/uapi/asm/kvm.h
> >>>> @@ -175,6 +175,8 @@ enum KVM_RISCV_ISA_EXT_ID {
> >>>>         KVM_RISCV_ISA_EXT_ZCF,
> >>>>         KVM_RISCV_ISA_EXT_ZCMOP,
> >>>>         KVM_RISCV_ISA_EXT_ZAWRS,
> >>>> +       KVM_RISCV_ISA_EXT_SMNPM,
> >>>> +       KVM_RISCV_ISA_EXT_SSNPM,
> >>>>         KVM_RISCV_ISA_EXT_MAX,
> >>>>  };
> >>>>
> >>>> diff --git a/arch/riscv/kvm/vcpu_onereg.c b/arch/riscv/kvm/vcpu_oner=
eg.c
> >>>> index b319c4c13c54..6f833ec2344a 100644
> >>>> --- a/arch/riscv/kvm/vcpu_onereg.c
> >>>> +++ b/arch/riscv/kvm/vcpu_onereg.c
> >>>> @@ -34,9 +34,11 @@ static const unsigned long kvm_isa_ext_arr[] =3D =
{
> >>>>         [KVM_RISCV_ISA_EXT_M] =3D RISCV_ISA_EXT_m,
> >>>>         [KVM_RISCV_ISA_EXT_V] =3D RISCV_ISA_EXT_v,
> >>>>         /* Multi letter extensions (alphabetically sorted) */
> >>>> +       [KVM_RISCV_ISA_EXT_SMNPM] =3D RISCV_ISA_EXT_SSNPM,
> >>>
> >>> Why not use KVM_ISA_EXT_ARR() macro here ?
> >>
> >> Because the extension name in the host does not match the extension na=
me in the
> >> guest. Pointer masking for HS mode is provided by Smnpm. Pointer maski=
ng for VS
> >> mode is provided by Ssnpm at the hardware level, but this needs to app=
ear to the
> >> guest as if Smnpm was implemented, since the guest thinks it is runnin=
g on bare
> >> metal.
> >
> > Okay, makes sense.
> >
> >>
> >>>>         KVM_ISA_EXT_ARR(SMSTATEEN),
> >>>>         KVM_ISA_EXT_ARR(SSAIA),
> >>>>         KVM_ISA_EXT_ARR(SSCOFPMF),
> >>>> +       KVM_ISA_EXT_ARR(SSNPM),
> >>>>         KVM_ISA_EXT_ARR(SSTC),
> >>>>         KVM_ISA_EXT_ARR(SVINVAL),
> >>>>         KVM_ISA_EXT_ARR(SVNAPOT),
> >>>> @@ -129,6 +131,7 @@ static bool kvm_riscv_vcpu_isa_disable_allowed(u=
nsigned long ext)
> >>>>         case KVM_RISCV_ISA_EXT_M:
> >>>>         /* There is not architectural config bit to disable sscofpmf=
 completely */
> >>>>         case KVM_RISCV_ISA_EXT_SSCOFPMF:
> >>>> +       case KVM_RISCV_ISA_EXT_SSNPM:
> >>>
> >>> Why not add KVM_RISCV_ISA_EXT_SMNPM here ?
> >>>
> >>> Disabling Smnpm from KVM user space is very different from
> >>> disabling Smnpm from Guest using SBI FWFT extension.
> >>
> >> Until a successful SBI FWFT call to KVM to enable pointer masking for =
VS mode,
> >> the existence of Smnpm has no visible effect on the guest. So failing =
the SBI
> >> call is sufficient to pretend that the hardware does not support Smnpm=
.
> >>
> >>> The KVM user space should always add Smnpm in the
> >>> Guest ISA string whenever the Host ISA string has it.
> >>
> >> I disagree. Allowing userspace to disable extensions is useful for tes=
ting and
> >> to support migration to hosts which do not support those extensions. S=
o I would
> >> only add extensions to this list if there is no possible way to disabl=
e them.
> >
> > I am not saying to disallow KVM user space disabling Smnpm.
>
> Then I'm confused. This is the "return false;" switch case inside
> kvm_riscv_vcpu_isa_disable_allowed(). If I add KVM_RISCV_ISA_EXT_SMNPM he=
re,
> then (unless I am misreading the code) I am disallowing KVM userspace fro=
m
> disabling Smnpm in the guest (i.e. preventing KVM userspace from removing=
 Smnpm
> from the guest ISA string). If that is not desired, then why do you sugge=
st I
> add KVM_RISCV_ISA_EXT_SMNPM here?

Yes, adding KVM_RISCV_ISA_EXT_SMNPM here means KVM
user space can't disable it using ONE_REG interface but KVM user
space can certainly not add it in the Guest ISA string.

>
> > The presence of Smnpm in ISA only means that it is present in HW
> > but it needs to be explicitly configured/enabled using SBI FWFT.
> >
> > KVM user space can certainly disable extensions by not adding it to
> > ISA string based on the KVMTOOL/QEMU-KVM command line option.
> > Additionally, when SBI FWFT is added to KVM RISC-V. It will have its
> > own way to explicitly disable firmware features from KVM user space.
>
> I think we agree on this, but your explanation here appears to conflict w=
ith
> your suggested code change. Apologies if I'm missing something.

I think the confusion is about what does it mean when Smnpm is present
in the ISA string. We have two approaches:

1) Presence of Smnpm in ISA string only means it is present in HW but
    says nothing about its enable/disable state. To configure/enable
    Smnpm, the supervisor must use SBI FWFT.

2) Presence of Smnpm in ISA string means it is present in HW and
    enabled at boot-time. To re-configure/disable Smnpm, the supervisor
    must use SBI FWFT.

I am suggesting approach #1 but I am guessing you are leaning towards
approach #2 ?

For approach #2, additional hencfg.PMM configuration is required in
this patch based on the state of KVM_RISCV_ISA_EXT_SMNPM.

Regards,
Anup

>
> Regards,
> Samuel
>
> >>> The Guest must explicitly use SBI FWFT to enable
> >>> Smnpm only after it sees Smnpm in ISA string.
> >>
> >> Yes, exactly, and the purpose of not including Smnpm in the switch cas=
e here is
> >> so that KVM user space can control whether or not it appears in the IS=
A string.
> >>
> >> Regards,
> >> Samuel
> >>
> >>>>         case KVM_RISCV_ISA_EXT_SSTC:
> >>>>         case KVM_RISCV_ISA_EXT_SVINVAL:
> >>>>         case KVM_RISCV_ISA_EXT_SVNAPOT:
> >>>> --
> >>>> 2.45.1
> >>>>
> >>>>
> >>>> _______________________________________________
> >>>> linux-riscv mailing list
> >>>> linux-riscv@lists.infradead.org
> >>>> http://lists.infradead.org/mailman/listinfo/linux-riscv
> >>>
> >>> Regards,
> >>> Anup
> >>
> >
> > Regards,
> > Anup
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhSdy1pZcEfajg3OZUCaFf9JMYcMzpRVogCT5VL2FHx__vDdA%40mail.gmail.=
com.
