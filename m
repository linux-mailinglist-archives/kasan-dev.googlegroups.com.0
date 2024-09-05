Return-Path: <kasan-dev+bncBDFJHU6GRMBBBOP64S3AMGQE7MREL6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 237D896CE5D
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Sep 2024 07:18:52 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id 5614622812f47-3df0559f3adsf419700b6e.3
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Sep 2024 22:18:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725513530; cv=pass;
        d=google.com; s=arc-20240605;
        b=SrfaIj6E5hAnuzQUwz2UD16YHRaRn7WQ/61vcoJuJz9PFpRU62nwMyexy5Lq7YE3bT
         c8ogXn80zwtF+yNgCVv+Hn/r/Fii/89s8+CAAr5HPhdiGaO75ieeWGtbFOSz/+ZgO47j
         QI1Dijln74eP83fukfvEoRra06ZRR2AKQe5VRfGqK0ivF9UJs9XPghwDjP7Z+0o6UDa0
         llgPsVwH6FXWdZZWtIuTaa4+MdMgj2sZYZOVh3DZnlgttjB7sZtEm6vt9Zb25fYLwXE8
         g5dM9zA4uxAJQGPsR1Jer7WK7JjXCwm+L3EHsQJCfYyyrnGoEQWfgOgPDHRELUjsPGSr
         1eUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=b4rhRehj4sPa88Kp1qBvWjG0MWqPcopSpGNEuHRMWgM=;
        fh=hOLuodyofQyWxKlf1InHtnAlInJBs+kQ5U33FF770E0=;
        b=T8nwApqqNE7REF0bS47LyUEqo7gpAC4U0FuKTsqzooWowNKQhDpOnUluNyLrBktnIK
         jb/sP/Pmsam9i0R2myE2HGbdVKlI2uCejLpKb4L3sdx4aKW/Vdvn/3G4QYPdQuv1q3mc
         E11uziQvae+s4QCZ5F2MB95VNL7mlgaNCujgNewjjC3E9f5tqpQUNj8DIH+1pY7MyROA
         nm6gsUG42ctbVnGUk/H5YbkYGKuFUkDcJ1G2A2aIif2pdBdfnNokcA2389z8r99XGKER
         szD5w7b0CKrXSdFziqze0F5tgX3wKRSB8qvDWb4f48QeMURrEs3GTP0bpeeeQ49ZMItF
         AKMw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20230601.gappssmtp.com header.s=20230601 header.b=mzis7ZRB;
       spf=neutral (google.com: 2607:f8b0:4864:20::129 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725513530; x=1726118330; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=b4rhRehj4sPa88Kp1qBvWjG0MWqPcopSpGNEuHRMWgM=;
        b=ZQtmPPhPTCdhUHykMd3UbJjIaNpfBOS6FjJhHJoiYfhE0PAmMCpAkJmYF/ucKi57sG
         C536IsIHt8VFRzI37xfRuZu0+T3RECfc4CQDnoyLu3f6jnayBTXUdf6b5ZpppiSvFrls
         3MA0xY3N+FefRVXrIOgkr9H3lg8yFnvw2ltEFleBuNBJnSNpNDJKP++EHkl8JuBecGVE
         RhNNi2r3IApIGDaANPKE1DHmZ80uVwLW3kdR3Gz+kOOj1WeX4GS7IQZq3Mu4A2AY1x7Z
         bRM15OFVbY1Zx5pjIkq7gke3nWGccivKgRsT92u0kLIaDGE44smfaWy2l6B6M1mBt1Nd
         CNfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725513530; x=1726118330;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=b4rhRehj4sPa88Kp1qBvWjG0MWqPcopSpGNEuHRMWgM=;
        b=J+WdYkHetb7nHeXrk5NbOMXHooz4izGShCjTJPCtvi+M9Kgu53ltbSKNgaqJ/bdhnH
         JoEHMUzGy61COnaMCxE5I/lVCq0oXKeU83EeTl6/fcycttva5fHH7LKjXLEEPgr9uHbf
         2xV6dBib3er33t4WjkKlaiB7JAYUGO6TDFq5vLAs23qflLrk1T3vNTTGqPAT2CAHRyS/
         bNMhYrdLgquf93EJEvcwoe/mkw9gLpzxyrZPKov+OA/ZoM6o+esYz1qwUpjd24eKSQ6+
         Q850O6O7pYNqG/xbqHzEHu1LAzkQtnvC+2TAmb7AJ0uE0L3v0MSihAEBkIbZolyUWHiX
         FIrw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXH3yNNuQAk5TW4jY0eZttdqe20YY+eBEW+BfGTS17TfRo5+e+lyvE8ANdmnEiGxHGCsokOnw==@lfdr.de
X-Gm-Message-State: AOJu0YyQCpBqon0hCJJxvhW+/nC9i6nprsfL/vyiB4I0eP+uInu7An4z
	JtuNtbpnLMS2jOZwWFmuODSfIs0qjGY5ndnUIrbr0j1PPxQ62oQ6
X-Google-Smtp-Source: AGHT+IHmfTZpwCNOx1sgcstfLqJzxN8bXrxJbijaRopeNEQpBjTwU+7dQpGjBhIDA1WChBUhXTSXuw==
X-Received: by 2002:a05:6870:568f:b0:270:184b:ccd9 with SMTP id 586e51a60fabf-27800506b63mr12504280fac.39.1725513530162;
        Wed, 04 Sep 2024 22:18:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:988:b0:717:85a0:1de2 with SMTP id
 d2e1a72fcca58-717890008e5ls517218b3a.0.-pod-prod-08-us; Wed, 04 Sep 2024
 22:18:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXkBG0ubSylly2XBtsPa0AURcEWNbrbjpGP3BlDlKmGLMjgAWli8RBV6iVGhnUO/bVstLLgDN7NtrM=@googlegroups.com
X-Received: by 2002:a05:6a21:3510:b0:1c2:8d49:dc33 with SMTP id adf61e73a8af0-1cecf757e95mr20818109637.40.1725513528961;
        Wed, 04 Sep 2024 22:18:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725513528; cv=none;
        d=google.com; s=arc-20240605;
        b=SVVrzIszKZuOPBSxgHJPrXJ7k3EFzv3nirF7Lam8/a4W41+eIKK5YAoEjAMtS/BXU9
         CHR8neAQz/kbkdpq3uJyyTMLTOrhvNQMPAL2Takl3oq79QrgFsknuhmyT1he/jUJEAM2
         4sF4LMd1XZ41FbOG1TC4p9DwvYQXyXC+VoBvVVcZo9i22I9Pau3NgdrR3ZSQ4On/HlO9
         h5RsRqy2bF9XF1kQhztsWHPzeMFBMR0mEgTwYDiV80LLrzWFTFvJ88wXrwnRu5QCNqZU
         Mg9eB7zJSj8gFyTdqzxw1S0nIUoq08vD3JuwTPtWKwUnmudKdKn4+X8ofQxgEuCrbS8T
         wuGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=lgy+KzMNuhYLUyLUNPHVh2erq8NnTHGx1LflMF38P4o=;
        fh=rjX/3Y6UoeMPjWhEBoIjBd08s7Thr10Z57sfBGKijcU=;
        b=Els9jTnGjOi90HrHLhRG5QNk2L1JOzoUYHE69cZTfXy27WakZ3NyNkXYrMP2ZMzWg8
         bZ27Il1Vke1DuHuXwlrLRsnjKnw03Jw25xgpw3QyHI6YZWH4RHyHbHBUfuQHIEy5D0GT
         +QcUQJglTyy4SRzgdYR2kEKgI9NwtIie7QN5j2fyfCdltYbKfsdRcxrFKfBgKbE3Zzs0
         znNrF7w1Hirh6NGsZjd24+bYSd95V4bvsfVxUmfQVqmNJCFc40AsZZzShnOcxCcOKQVE
         dsYQTtC0oWzJr2Qu7mLOikPghbeSpr2M02DbHvRV0cWDRI8uVjmpj80njZOT/0Vs/11/
         a+Pw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20230601.gappssmtp.com header.s=20230601 header.b=mzis7ZRB;
       spf=neutral (google.com: 2607:f8b0:4864:20::129 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-il1-x129.google.com (mail-il1-x129.google.com. [2607:f8b0:4864:20::129])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2dab6e52153si51241a91.1.2024.09.04.22.18.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Sep 2024 22:18:48 -0700 (PDT)
Received-SPF: neutral (google.com: 2607:f8b0:4864:20::129 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) client-ip=2607:f8b0:4864:20::129;
Received: by mail-il1-x129.google.com with SMTP id e9e14a558f8ab-39f52e60a19so1475575ab.3
        for <kasan-dev@googlegroups.com>; Wed, 04 Sep 2024 22:18:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXcIjrx3l9B+R7GHOp4HrdD/lCQQ0Q0q8mEOXVSAxlVUSGB3zcPMd+pInhg6w6FZP3AzRzERXTyjtk=@googlegroups.com
X-Received: by 2002:a05:6e02:12e4:b0:39d:2524:ece6 with SMTP id
 e9e14a558f8ab-39f3783810emr305003055ab.17.1725513528004; Wed, 04 Sep 2024
 22:18:48 -0700 (PDT)
MIME-Version: 1.0
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
 <20240829010151.2813377-10-samuel.holland@sifive.com> <CAK9=C2WjraWjuQCeU2Y4Jhr-gKkOcP42Sza7wVp0FgeGaD923g@mail.gmail.com>
 <b6de8769-7e4e-4a19-b239-a39fd424e0c8@sifive.com> <CAAhSdy08SoDoZCii9R--BK7_NKLnRciW7V3mo2aQRKW1dbOgNg@mail.gmail.com>
 <20ab0fa2-d5dd-446d-9fff-a3ef82e8db35@sifive.com> <CAAhSdy1pZcEfajg3OZUCaFf9JMYcMzpRVogCT5VL2FHx__vDdA@mail.gmail.com>
 <4c010cb1-b57c-427e-a241-1dd3ab15f2ce@sifive.com>
In-Reply-To: <4c010cb1-b57c-427e-a241-1dd3ab15f2ce@sifive.com>
From: Anup Patel <anup@brainfault.org>
Date: Thu, 5 Sep 2024 10:48:36 +0530
Message-ID: <CAAhSdy0kYUdgX8NUKuOdQa-69ET=cscduJvyz3z31kVeB-JaNw@mail.gmail.com>
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
 header.b=mzis7ZRB;       spf=neutral (google.com: 2607:f8b0:4864:20::129 is
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

On Wed, Sep 4, 2024 at 9:25=E2=80=AFPM Samuel Holland <samuel.holland@sifiv=
e.com> wrote:
>
> On 2024-09-04 10:20 AM, Anup Patel wrote:
> > On Wed, Sep 4, 2024 at 8:27=E2=80=AFPM Samuel Holland <samuel.holland@s=
ifive.com> wrote:
> >>
> >> Hi Anup,
> >>
> >> On 2024-09-04 9:45 AM, Anup Patel wrote:
> >>> On Wed, Sep 4, 2024 at 8:01=E2=80=AFPM Samuel Holland <samuel.holland=
@sifive.com> wrote:
> >>>> On 2024-09-04 7:17 AM, Anup Patel wrote:
> >>>>> On Thu, Aug 29, 2024 at 6:32=E2=80=AFAM Samuel Holland
> >>>>> <samuel.holland@sifive.com> wrote:
> >>>>>>
> >>>>>> The interface for controlling pointer masking in VS-mode is henvcf=
g.PMM,
> >>>>>> which is part of the Ssnpm extension, even though pointer masking =
in
> >>>>>> HS-mode is provided by the Smnpm extension. As a result, emulating=
 Smnpm
> >>>>>> in the guest requires (only) Ssnpm on the host.
> >>>>>>
> >>>>>> Since the guest configures Smnpm through the SBI Firmware Features
> >>>>>> interface, the extension can be disabled by failing the SBI call. =
Ssnpm
> >>>>>> cannot be disabled without intercepting writes to the senvcfg CSR.
> >>>>>>
> >>>>>> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> >>>>>> ---
> >>>>>>
> >>>>>> (no changes since v2)
> >>>>>>
> >>>>>> Changes in v2:
> >>>>>>  - New patch for v2
> >>>>>>
> >>>>>>  arch/riscv/include/uapi/asm/kvm.h | 2 ++
> >>>>>>  arch/riscv/kvm/vcpu_onereg.c      | 3 +++
> >>>>>>  2 files changed, 5 insertions(+)
> >>>>>>
> >>>>>> diff --git a/arch/riscv/include/uapi/asm/kvm.h b/arch/riscv/includ=
e/uapi/asm/kvm.h
> >>>>>> index e97db3296456..4f24201376b1 100644
> >>>>>> --- a/arch/riscv/include/uapi/asm/kvm.h
> >>>>>> +++ b/arch/riscv/include/uapi/asm/kvm.h
> >>>>>> @@ -175,6 +175,8 @@ enum KVM_RISCV_ISA_EXT_ID {
> >>>>>>         KVM_RISCV_ISA_EXT_ZCF,
> >>>>>>         KVM_RISCV_ISA_EXT_ZCMOP,
> >>>>>>         KVM_RISCV_ISA_EXT_ZAWRS,
> >>>>>> +       KVM_RISCV_ISA_EXT_SMNPM,
> >>>>>> +       KVM_RISCV_ISA_EXT_SSNPM,
> >>>>>>         KVM_RISCV_ISA_EXT_MAX,
> >>>>>>  };
> >>>>>>
> >>>>>> diff --git a/arch/riscv/kvm/vcpu_onereg.c b/arch/riscv/kvm/vcpu_on=
ereg.c
> >>>>>> index b319c4c13c54..6f833ec2344a 100644
> >>>>>> --- a/arch/riscv/kvm/vcpu_onereg.c
> >>>>>> +++ b/arch/riscv/kvm/vcpu_onereg.c
> >>>>>> @@ -34,9 +34,11 @@ static const unsigned long kvm_isa_ext_arr[] =
=3D {
> >>>>>>         [KVM_RISCV_ISA_EXT_M] =3D RISCV_ISA_EXT_m,
> >>>>>>         [KVM_RISCV_ISA_EXT_V] =3D RISCV_ISA_EXT_v,
> >>>>>>         /* Multi letter extensions (alphabetically sorted) */
> >>>>>> +       [KVM_RISCV_ISA_EXT_SMNPM] =3D RISCV_ISA_EXT_SSNPM,
> >>>>>
> >>>>> Why not use KVM_ISA_EXT_ARR() macro here ?
> >>>>
> >>>> Because the extension name in the host does not match the extension =
name in the
> >>>> guest. Pointer masking for HS mode is provided by Smnpm. Pointer mas=
king for VS
> >>>> mode is provided by Ssnpm at the hardware level, but this needs to a=
ppear to the
> >>>> guest as if Smnpm was implemented, since the guest thinks it is runn=
ing on bare
> >>>> metal.
> >>>
> >>> Okay, makes sense.
> >>>
> >>>>
> >>>>>>         KVM_ISA_EXT_ARR(SMSTATEEN),
> >>>>>>         KVM_ISA_EXT_ARR(SSAIA),
> >>>>>>         KVM_ISA_EXT_ARR(SSCOFPMF),
> >>>>>> +       KVM_ISA_EXT_ARR(SSNPM),
> >>>>>>         KVM_ISA_EXT_ARR(SSTC),
> >>>>>>         KVM_ISA_EXT_ARR(SVINVAL),
> >>>>>>         KVM_ISA_EXT_ARR(SVNAPOT),
> >>>>>> @@ -129,6 +131,7 @@ static bool kvm_riscv_vcpu_isa_disable_allowed=
(unsigned long ext)
> >>>>>>         case KVM_RISCV_ISA_EXT_M:
> >>>>>>         /* There is not architectural config bit to disable sscofp=
mf completely */
> >>>>>>         case KVM_RISCV_ISA_EXT_SSCOFPMF:
> >>>>>> +       case KVM_RISCV_ISA_EXT_SSNPM:
> >>>>>
> >>>>> Why not add KVM_RISCV_ISA_EXT_SMNPM here ?
> >>>>>
> >>>>> Disabling Smnpm from KVM user space is very different from
> >>>>> disabling Smnpm from Guest using SBI FWFT extension.
> >>>>
> >>>> Until a successful SBI FWFT call to KVM to enable pointer masking fo=
r VS mode,
> >>>> the existence of Smnpm has no visible effect on the guest. So failin=
g the SBI
> >>>> call is sufficient to pretend that the hardware does not support Smn=
pm.
> >>>>
> >>>>> The KVM user space should always add Smnpm in the
> >>>>> Guest ISA string whenever the Host ISA string has it.
> >>>>
> >>>> I disagree. Allowing userspace to disable extensions is useful for t=
esting and
> >>>> to support migration to hosts which do not support those extensions.=
 So I would
> >>>> only add extensions to this list if there is no possible way to disa=
ble them.
> >>>
> >>> I am not saying to disallow KVM user space disabling Smnpm.
> >>
> >> Then I'm confused. This is the "return false;" switch case inside
> >> kvm_riscv_vcpu_isa_disable_allowed(). If I add KVM_RISCV_ISA_EXT_SMNPM=
 here,
> >> then (unless I am misreading the code) I am disallowing KVM userspace =
from
> >> disabling Smnpm in the guest (i.e. preventing KVM userspace from remov=
ing Smnpm
> >> from the guest ISA string). If that is not desired, then why do you su=
ggest I
> >> add KVM_RISCV_ISA_EXT_SMNPM here?
> >
> > Yes, adding KVM_RISCV_ISA_EXT_SMNPM here means KVM
> > user space can't disable it using ONE_REG interface but KVM user
> > space can certainly not add it in the Guest ISA string.
>
> Is there a problem with allowing KVM userspace to disable the ISA extensi=
on with
> the ONE_REG interface?
>
> If KVM userspace removes Smnpm from the ISA string without the host kerne=
l's
> knowledge, that doesn't actually prevent the guest from successfully call=
ing
> sbi_fwft_set(POINTER_MASKING_PMLEN, ...), so it doesn't guarantee that th=
e VM
> can be migrated to a host without pointer masking support. So the ONE_REG
> interface still has value. (And that's my answer to your original questio=
n "Why
> not add KVM_RISCV_ISA_EXT_SMNPM here ?")

Currently, disabling KVM_RISCV_ISA_EXT_SMNPM via ONE_REG
will only clear the corresponding bit in VCPU isa bitmap. Basically, the
KVM user space disabling KVM_RISCV_ISA_EXT_SMNPM for Guest
changes nothing for the Guest/VM.

On other hand, disabling KVM_RISCV_ISA_EXT_SVPBMT via
ONE_REG will not only clear it from VCPU isa bitmap but also
disable Svpmbt from henvcfg CSR for the Guest/VM.

In other words, if disabling an ISA extension is allowed by the
kvm_riscv_vcpu_isa_disable_allowed() then the Guest/VM must
see a different behaviour when the ISA extension is disabled by
KVM user space.

>
> >>> The presence of Smnpm in ISA only means that it is present in HW
> >>> but it needs to be explicitly configured/enabled using SBI FWFT.
> >>>
> >>> KVM user space can certainly disable extensions by not adding it to
> >>> ISA string based on the KVMTOOL/QEMU-KVM command line option.
> >>> Additionally, when SBI FWFT is added to KVM RISC-V. It will have its
> >>> own way to explicitly disable firmware features from KVM user space.
> >>
> >> I think we agree on this, but your explanation here appears to conflic=
t with
> >> your suggested code change. Apologies if I'm missing something.
> >
> > I think the confusion is about what does it mean when Smnpm is present
> > in the ISA string. We have two approaches:
> >
> > 1) Presence of Smnpm in ISA string only means it is present in HW but
> >     says nothing about its enable/disable state. To configure/enable
> >     Smnpm, the supervisor must use SBI FWFT.
> >
> > 2) Presence of Smnpm in ISA string means it is present in HW and
> >     enabled at boot-time. To re-configure/disable Smnpm, the supervisor
> >     must use SBI FWFT.
> >
> > I am suggesting approach #1 but I am guessing you are leaning towards
> > approach #2 ?
> >
> > For approach #2, additional hencfg.PMM configuration is required in
> > this patch based on the state of KVM_RISCV_ISA_EXT_SMNPM.
>
> No, I am definitely suggesting only approach #1. My proposal for adding p=
ointer
> masking to the SBI FWFT extension[1] specifies the feature as disabled by
> default, and this would apply both inside and ouside a VM.
>
> But I am also suggesting that the ONE_REG interface is a useful way to
> completely hide the extension from the guest, like we do for other extens=
ions
> such as Svpbmt. The only difference between something like Svpbmt and Smn=
pm is
> that instead of clearing a bit in henvcfg to hide the extension from the =
guest,
> we reject calls to sbi_fwft_set(POINTER_MASKING_PMLEN, ...) when the ISA
> extension is hidden from the guest.

I think we are converging towards the same thing.

How about this ?

For this series, lets add KVM_RISCV_ISA_EXT_SMNPM to
kvm_riscv_vcpu_isa_disable_allowed() so that for the time
being KVM user space can't disable Smnpm.

In the future, a separate series which adds SBI FWFT to
KVM RISC-V will remove KVM_RISCV_ISA_EXT_SMNPM
from the kvm_riscv_vcpu_isa_disable_allowed() because
disabling Smnpm from KVM user space would mean that
the POINTER_MASKING_PMLEN firmware feature is
not available to the Guest/VM.

This means in the future (after SBI FWFT is implemented in
KVM RISC-V), Guest with Smnpm disabled can be migrated
to a host without pointer masking.

Regards,
Anup

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhSdy0kYUdgX8NUKuOdQa-69ET%3DcscduJvyz3z31kVeB-JaNw%40mail.gmai=
l.com.
