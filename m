Return-Path: <kasan-dev+bncBCMIFTP47IJBBD4Q5GXQMGQEYHHCYJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 1271988098A
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 03:21:06 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-1deed404fd7sf452085ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 19:21:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710901264; cv=pass;
        d=google.com; s=arc-20160816;
        b=h/SL/u7rNf0+/px1n2GiJueXs1fo7y8KSLBF/G2WMHRfNR1xavFp6ImeECvyYFS8sT
         iZ5MNHe2ZnLbiI2q+gNXSA0m13g8B+Ntbu7isD6TUThWjZoGnX2Jk7c7sPGaCj07R9D7
         VLCzTxf9PxQAtFo2oMXY/zwXVR0L+f3d9D282LhDLE+N5HaK7vSEqe3wMc06ssTEovBm
         iLWDov9o7XjRZvXu5hOMHMK3Bil77Vks8/39EEcb5W2odpBb7YbZP9eoUND0NbFGC3+q
         qVoTwXuaBVl3WFnsI0dgen9U9Pen7d9uKvbHLEOyev34/tPUtlUe8PwT+iqZiYS5a+0T
         Hj4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=wN98xGgar58/o+1tlG1LeA77BB2ek9fgpXgrPETA2O8=;
        fh=ETv+dVM/ki1+I7E+NOvqkdoK8B+Vie6rpjLHoJfRXoQ=;
        b=f8TPLE3enIn/H4kNFTDDjitU3GKyBRPx1ejNRt0nd1NLfn2BRMtnDFAzebB4Dprg7m
         t9r2LdyoXInw6HxCgaHhPCjWQxhkT5+/HvlP5c25pUiH3H0di2oyfl3KnvVwcXL4NKbA
         XFhgDT/R7KUy9HrXPFjvW4LFIUjoHq0CTKD6HshWNrhlvgoXrgJHzPnz5NtguwFzSX/w
         ZfQ2Rkkp4flIbScpK9BqHPFUSMEyBenPhC4mWiAK6rU6i/fo7Mwf0KpkYiQfF1+O0InD
         Z66ZkRZVQH4cZ/bpSBrOImd0XAFeoFhgtkKAau5lvk7WDMvu+APOdFFvvRVwqyREC7mF
         +2aw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=cw1dNUBo;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710901264; x=1711506064; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=wN98xGgar58/o+1tlG1LeA77BB2ek9fgpXgrPETA2O8=;
        b=wOjczH+AOb1oO/J5Rt1GKH96wBP22f2pskUqBNgUUs+tGm2XZcCMnoX8XQ6qR6g4Dk
         jd1bdyD2O8rCHEcxOWgBwnr+SZ9JF6/7ZuwabKImRDLPDeyLIGuIP4RMelFahL+gRqfu
         mD577KlZTPOaO8jiQdnmHy3ovFDFXkoCa8E5nRQhBhGKvIGd9q9+LG/nd7aCY7XTm0Pd
         gKT9lmAgmfhcAdFtRTrNlsXU27A144rn86LdZ/qLEwiuhLhta3tv0byOjpDyqSBi6VzH
         lFZ5xdFQqljI2BZkt7BS7BY6D8eBh8nrAr9b4UZ4to4X0zEdQyLfJ2fS/9EA3+VC6Mu9
         g1hA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710901264; x=1711506064;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wN98xGgar58/o+1tlG1LeA77BB2ek9fgpXgrPETA2O8=;
        b=V3UOs0g2G0lcxxJ29dQuv6VvCg2ImyQbNEYcyVnv72I/NbbLq64N3qfpnuO31yhWnK
         p2KFndGdYes8ns9jdpJxttzEqFaqZzXwCQ+yRbrmFOKXWe+FBKW1YfQO0x9PodU14O9J
         RYKfjh4fj9A1yYXbYRNRY6kEXWLQI114/z86qGD/ezv/aMMkH6jHEkiAmwoN4P7pw22a
         hWwLmD0djYJ53kSjTol60/86GBWjHm+7j1l2YGMVK98dOWAaLxN08vTO6Dg16Elfzvxm
         opLR6WZk6bwkGw0V+NaqZy6UmMlF7vpcRa1qBEXbOGJ2RNFhRUDV9zOkosL24zyB8+NH
         7XIQ==
X-Forwarded-Encrypted: i=2; AJvYcCUlaLDm5lpKf7eTNaZp6xGxV0SZt7DgT66QLAwOH/3XOu2epxLJpjboUXFnwi/Mgy9L8xgr81GP8YxXNs3FOKj9LNNdFRfPyQ==
X-Gm-Message-State: AOJu0YwuqdVFQndl/e3wbQnazJHFlDyNKimFcrHjQp1uHbBHhhYrINEc
	+xa5a53hceEMs/97ruY0DKOY58JrUkJRAGJ8hLEDK/2Tp0KudwFU
X-Google-Smtp-Source: AGHT+IF254W74buz/Bf8dSDT4sF/PqdANZxnMHwGIKal20cYiiTQSJr1TkzSAIc3Lwf8+qGVIb+DsQ==
X-Received: by 2002:a17:902:e80a:b0:1de:f0c7:108 with SMTP id u10-20020a170902e80a00b001def0c70108mr153886plg.6.1710901263898;
        Tue, 19 Mar 2024 19:21:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:18a:b0:1db:969c:f2f with SMTP id z10-20020a170903018a00b001db969c0f2fls1364722plg.2.-pod-prod-05-us;
 Tue, 19 Mar 2024 19:21:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWtrpXuvbTUhV6u2Qa/OBHCPPl9+/C3KD1MPZ1r+AVlR5osZX/CIlpBf2buj3l/U40xdQqkmOYZOcdARKd9bqBlTf28J2pHAAMVgg==
X-Received: by 2002:a17:903:248:b0:1dc:b73b:ec35 with SMTP id j8-20020a170903024800b001dcb73bec35mr19564764plh.4.1710901262643;
        Tue, 19 Mar 2024 19:21:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710901262; cv=none;
        d=google.com; s=arc-20160816;
        b=y9cXzPmzTPKeDZ2BsooZd5VmwGq5pjO6s1bDDHakj2iAFEAJHInN3D3df1UdIoed3i
         i2/L5ll1cd4e30nnWppDeq4FGWKmDe1/oYWMmyBUXcVtjULMQG6ipAbIj+Cj/iiUAznY
         /gZK2M11WoBX8mVj28yrXbpq0HPDz1sRtZEcUl9qxy/268qrPhj9g5ZCIJ5Flif0BgkF
         l7+UXc1Wl6tAWFrXvGsKjOIwTkF0tWm20Mpy63Sr/SOEF12zxGE/V4E0k92BL7DIr1dh
         qCqiesuh33u3JICrANkq+/k3tVCGpHMAprfwHlZiq9g+r0tUFRQ+Rk/LOJ+lH+youEJg
         sfgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=20q06/6oGIfjPCtmqOWMDp2L8ubG1IZix8+eCUbt12w=;
        fh=REQqtHy+PKkn9XKLyb0pUeNKmcTHQaYwnjXTPD7oWoI=;
        b=eEEXnHnrM/7Kir5BSTwb/5rqQ4mhRuhyrzqmLF/jnxgQzU2t3seMjb9h7odod+dHmO
         mm+YKGucqYA810kP8lEO4fYhz83MyOgE7+fOT4NmUfFs7IMmHuldWBC5AgYaAd+mAMqx
         eBZP4vtL03/IFzew4mhzq0b9y1ouY9enB5/SU049j0+9iyG8YEeugroRb6kDN8X0imVO
         6aqZBh56AwTYZPDM1U79xoIsA1anJ8OU6Kl9IiTTDshxb4G68u+tMWaAwA2drAVoFoo2
         9HMF4LOSEjcvdwqKwaP1dc2GiYvH0fl3JLbEgBP77HO+IR1lukRjN97qeE7O8pJ9fWMm
         03HQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=cw1dNUBo;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
Received: from mail-io1-xd30.google.com (mail-io1-xd30.google.com. [2607:f8b0:4864:20::d30])
        by gmr-mx.google.com with ESMTPS id jb13-20020a170903258d00b001dd6f638c0bsi974762plb.2.2024.03.19.19.21.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Mar 2024 19:21:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::d30 as permitted sender) client-ip=2607:f8b0:4864:20::d30;
Received: by mail-io1-xd30.google.com with SMTP id ca18e2360f4ac-7cbf307213fso189391839f.0
        for <kasan-dev@googlegroups.com>; Tue, 19 Mar 2024 19:21:02 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWpEhQb3T9UpMmJ/NzAMnZ+Jiq6nYv/k5H7CFX6cYqD0IhyztdadZEegg4/7aoOHu+9Fhir5IGl5CqE0loAG7VzK9HRuVNO2M1Mjw==
X-Received: by 2002:a05:6602:340d:b0:7cc:10da:ac1a with SMTP id n13-20020a056602340d00b007cc10daac1amr13941502ioz.8.1710901261875;
        Tue, 19 Mar 2024 19:21:01 -0700 (PDT)
Received: from [100.64.0.1] ([136.226.86.189])
        by smtp.gmail.com with ESMTPSA id fm39-20020a0566382b2700b0047730eb5bebsm3174773jab.60.2024.03.19.19.21.00
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Mar 2024 19:21:01 -0700 (PDT)
Message-ID: <40ab1ce5-8700-4a63-b182-1e864f6c9225@sifive.com>
Date: Tue, 19 Mar 2024 21:20:59 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [RISC-V] [tech-j-ext] [RFC PATCH 5/9] riscv: Split per-CPU and
 per-thread envcfg bits
To: Deepak Gupta <debug@rivosinc.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org,
 devicetree@vger.kernel.org, Catalin Marinas <catalin.marinas@arm.com>,
 linux-kernel@vger.kernel.org, tech-j-ext@lists.risc-v.org,
 Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com,
 Evgenii Stepanov <eugenis@google.com>,
 Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
 Rob Herring <robh+dt@kernel.org>, Andrew Jones <ajones@ventanamicro.com>,
 Guo Ren <guoren@kernel.org>, Heiko Stuebner <heiko@sntech.de>,
 Paul Walmsley <paul.walmsley@sifive.com>
References: <20240319215915.832127-1-samuel.holland@sifive.com>
 <20240319215915.832127-6-samuel.holland@sifive.com>
 <CAKC1njSg9-hJo6hibcM9a-=FUmMWyR39QUYqQ1uwiWhpBZQb9A@mail.gmail.com>
Content-Language: en-US
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CAKC1njSg9-hJo6hibcM9a-=FUmMWyR39QUYqQ1uwiWhpBZQb9A@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=cw1dNUBo;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
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

Hi Deepak,

On 2024-03-19 6:55 PM, Deepak Gupta wrote:
> On Tue, Mar 19, 2024 at 2:59=E2=80=AFPM Samuel Holland via lists.riscv.or=
g
> <samuel.holland=3Dsifive.com@lists.riscv.org> wrote:
>>
>> Some envcfg bits need to be controlled on a per-thread basis, such as
>> the pointer masking mode. However, the envcfg CSR value cannot simply be
>> stored in struct thread_struct, because some hardware may implement a
>> different subset of envcfg CSR bits is across CPUs. As a result, we need
>> to combine the per-CPU and per-thread bits whenever we switch threads.
>>
>=20
> Why not do something like this
>=20
> diff --git a/arch/riscv/include/asm/csr.h b/arch/riscv/include/asm/csr.h
> index b3400517b0a9..01ba87954da2 100644
> --- a/arch/riscv/include/asm/csr.h
> +++ b/arch/riscv/include/asm/csr.h
> @@ -202,6 +202,8 @@
>  #define ENVCFG_CBIE_FLUSH              _AC(0x1, UL)
>  #define ENVCFG_CBIE_INV                        _AC(0x3, UL)
>  #define ENVCFG_FIOM                    _AC(0x1, UL)
> +/* by default all threads should be able to zero cache */
> +#define ENVCFG_BASE                    ENVCFG_CBZE

Linux does not assume Sstrict, so without Zicboz being present in DT/ACPI, =
we
have no idea what the CBZE bit does--there's no guarantee it has the standa=
rd
meaning--so it's not safe to set the bit unconditionally. If that policy
changes, we could definitely simplify the code.

>  /* Smstateen bits */
>  #define SMSTATEEN0_AIA_IMSIC_SHIFT     58
> diff --git a/arch/riscv/kernel/process.c b/arch/riscv/kernel/process.c
> index 4f21d970a129..2420123444c4 100644
> --- a/arch/riscv/kernel/process.c
> +++ b/arch/riscv/kernel/process.c
> @@ -152,6 +152,7 @@ void start_thread(struct pt_regs *regs, unsigned long=
 pc,
>         else
>                 regs->status |=3D SR_UXL_64;
>  #endif
> +       current->thread_info.envcfg =3D ENVCFG_BASE;
>  }
>=20
> And instead of context switching in `_switch_to`,
> In `entry.S` pick up `envcfg` from `thread_info` and write it into CSR.

The immediate reason is that writing envcfg in ret_from_exception() adds cy=
cles
to every IRQ and system call exit, even though most of them will not change=
 the
envcfg value. This is especially the case when returning from an IRQ/except=
ion
back to S-mode, since envcfg has zero effect there.

The CSRs that are read/written in entry.S are generally those where the val=
ue
can be updated by hardware, as part of taking an exception. But envcfg neve=
r
changes on its own. The kernel knows exactly when its value will change, an=
d
those places are:

 1) Task switch, i.e. switch_to()
 2) execve(), i.e. start_thread() or flush_thread()
 3) A system call that specifically affects a feature controlled by envcfg

So that's where this series writes it. There are a couple of minor tradeoff=
s
about when exactly to do the write:

- We could drop the sync_envcfg() calls outside of switch_to() by reading t=
he
  current CSR value when scheduling out a thread, but again that adds overh=
ead
  to the fast path to remove a tiny bit of code in the prctl() handlers.
- We don't need to write envcfg when switching to a kernel thread, only whe=
n
  switching to a user thread, because kernel threads never leave S-mode, so
  envcfg doesn't affect them. But checking the thread type takes many more
  instructions than just writing the CSR.

Overall, the optimal implementation will approximate the rule of only writi=
ng
envcfg when its value changes.

> This construction avoids
> - declaring per cpu riscv_cpu_envcfg

This is really a separate concern than when we write envcfg. The per-CPU
variable is only necessary to support hardware where a subset of harts supp=
ort
Zicboz. Since the riscv_cpu_has_extension_[un]likely() helpers were added
specifically for Zicboz, I assume this is an important use case, and droppi=
ng
support for this hardware would be a regression. After all, hwprobe() allow=
s
userspace to see that Zicboz is implemented at a per-CPU level. Maybe Andre=
w can
weigh in on that.

If we decide to enable Zicboz only when all harts support it, or we decide =
it's
safe to attempt to set the envcfg.CBZE bit on harts that do not declare sup=
port
for Zicboz, then we could drop the percpu variable.

> - syncing up
> - collection of *envcfg bits.
>=20
>=20
>> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
>> ---
>>
>>  arch/riscv/include/asm/cpufeature.h |  2 ++
>>  arch/riscv/include/asm/processor.h  |  1 +
>>  arch/riscv/include/asm/switch_to.h  | 12 ++++++++++++
>>  arch/riscv/kernel/cpufeature.c      |  4 +++-
>>  4 files changed, 18 insertions(+), 1 deletion(-)
>>
>> diff --git a/arch/riscv/include/asm/cpufeature.h b/arch/riscv/include/as=
m/cpufeature.h
>> index 0bd11862b760..b1ad8d0b4599 100644
>> --- a/arch/riscv/include/asm/cpufeature.h
>> +++ b/arch/riscv/include/asm/cpufeature.h
>> @@ -33,6 +33,8 @@ DECLARE_PER_CPU(long, misaligned_access_speed);
>>  /* Per-cpu ISA extensions. */
>>  extern struct riscv_isainfo hart_isa[NR_CPUS];
>>
>> +DECLARE_PER_CPU(unsigned long, riscv_cpu_envcfg);
>> +
>>  void riscv_user_isa_enable(void);
>>
>>  #ifdef CONFIG_RISCV_MISALIGNED
>> diff --git a/arch/riscv/include/asm/processor.h b/arch/riscv/include/asm=
/processor.h
>> index a8509cc31ab2..06b87402a4d8 100644
>> --- a/arch/riscv/include/asm/processor.h
>> +++ b/arch/riscv/include/asm/processor.h
>> @@ -118,6 +118,7 @@ struct thread_struct {
>>         unsigned long s[12];    /* s[0]: frame pointer */
>>         struct __riscv_d_ext_state fstate;
>>         unsigned long bad_cause;
>> +       unsigned long envcfg;
>>         u32 riscv_v_flags;
>>         u32 vstate_ctrl;
>>         struct __riscv_v_ext_state vstate;
>> diff --git a/arch/riscv/include/asm/switch_to.h b/arch/riscv/include/asm=
/switch_to.h
>> index 7efdb0584d47..256a354a5c4a 100644
>> --- a/arch/riscv/include/asm/switch_to.h
>> +++ b/arch/riscv/include/asm/switch_to.h
>> @@ -69,6 +69,17 @@ static __always_inline bool has_fpu(void) { return fa=
lse; }
>>  #define __switch_to_fpu(__prev, __next) do { } while (0)
>>  #endif
>>
>> +static inline void sync_envcfg(struct task_struct *task)
>> +{
>> +       csr_write(CSR_ENVCFG, this_cpu_read(riscv_cpu_envcfg) | task->th=
read.envcfg);
>> +}
>> +
>> +static inline void __switch_to_envcfg(struct task_struct *next)
>> +{
>> +       if (riscv_cpu_has_extension_unlikely(smp_processor_id(), RISCV_I=
SA_EXT_XLINUXENVCFG))
>=20
> I've seen `riscv_cpu_has_extension_unlikely` generating branchy code
> even if ALTERNATIVES was turned on.
> Can you check disasm on your end as well.  IMHO, `entry.S` is a better
> place to pick up *envcfg.

The branchiness is sort of expected, since that function is implemented by
switching on/off a branch instruction, so the alternate code is necessarily=
 a
separate basic block. It's a tradeoff so we don't have to write assembly co=
de
for every bit of code that depends on an extension. However, the cost shoul=
d be
somewhat lowered since the branch is unconditional and so entirely predicta=
ble.

If the branch turns out to be problematic for performance, then we could us=
e
ALTERNATIVE directly in sync_envcfg() to NOP out the CSR write.

>> +               sync_envcfg(next);
>> +}
>> +
>>  extern struct task_struct *__switch_to(struct task_struct *,
>>                                        struct task_struct *);
>>
>> @@ -80,6 +91,7 @@ do {                                                  =
\
>>                 __switch_to_fpu(__prev, __next);        \
>>         if (has_vector())                                       \
>>                 __switch_to_vector(__prev, __next);     \
>> +       __switch_to_envcfg(__next);                     \
>>         ((last) =3D __switch_to(__prev, __next));         \
>>  } while (0)
>>
>> diff --git a/arch/riscv/kernel/cpufeature.c b/arch/riscv/kernel/cpufeatu=
re.c
>> index d1846aab1f78..32aaaf41f8a8 100644
>> --- a/arch/riscv/kernel/cpufeature.c
>> +++ b/arch/riscv/kernel/cpufeature.c
>> @@ -44,6 +44,8 @@ static DECLARE_BITMAP(riscv_isa, RISCV_ISA_EXT_MAX) __=
read_mostly;
>>  /* Per-cpu ISA extensions. */
>>  struct riscv_isainfo hart_isa[NR_CPUS];
>>
>> +DEFINE_PER_CPU(unsigned long, riscv_cpu_envcfg);
>> +
>>  /* Performance information */
>>  DEFINE_PER_CPU(long, misaligned_access_speed);
>>
>> @@ -978,7 +980,7 @@ arch_initcall(check_unaligned_access_all_cpus);
>>  void riscv_user_isa_enable(void)
>>  {
>>         if (riscv_cpu_has_extension_unlikely(smp_processor_id(), RISCV_I=
SA_EXT_ZICBOZ))
>> -               csr_set(CSR_ENVCFG, ENVCFG_CBZE);
>> +               this_cpu_or(riscv_cpu_envcfg, ENVCFG_CBZE);

If we drop the percpu variable, this becomes

	if (riscv_has_extension_unlikely(RISCV_ISA_EXT_ZICBOZ))
		current->thread.envcfg |=3D ENVCFG_CBZE;

since the init thread's envcfg gets copied to all other threads via fork(),=
 and
we can drop the call to riscv_user_isa_enable() from smp_callin(). Or if we
decide CBZE is always safe to set, then the function is even simpler:

	current->thread.envcfg =3D ENVCFG_CBZE;

Regards,
Samuel

>>  }
>>
>>  #ifdef CONFIG_RISCV_ALTERNATIVE
>> --
>> 2.43.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/40ab1ce5-8700-4a63-b182-1e864f6c9225%40sifive.com.
