Return-Path: <kasan-dev+bncBC76RJVVRQPRBJGR5GXQMGQEFIKOHQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D7F0880A66
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 05:40:06 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-69181af8ceasf80655236d6.2
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 21:40:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710909605; cv=pass;
        d=google.com; s=arc-20160816;
        b=xysvY1gPqCJCi8n4VR46f9x2aSB7B/kqM5WP1j82q0mTDE//5wmeEQY/J7TXS5e4yQ
         cyJ2mC+bAlW0+dU+ttg0vacGhj9lDcjJNk6ChFuVNne9acwQhLkOqO7D6XNb4jZDnHSr
         KRzVNU42TMh1obZNIG4I+OcWJ0sjGAZuFzUdizee9+Cw+5FoY+XE3n5nqIYJbxzeaDjX
         UvwOmQmnsiyisuqb6poEV50d27aPLLPu2QCsZHx0x5FysjQSLtVRRF0PfLnau6zbghYf
         lNqjndsOy/8f99VxVWVIgReKxb1tUwDDcuwlFQr46wi1HJGDdppL2FimqNsKEye4/qcx
         3efQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=fCNtfJ5topHDekXuHR+JH5/wEjupzv1PyRMN16QDvn4=;
        fh=iy/JY/EHkmhSQXoT4UoXHaNU0Mly6IvY6jNgWnmU8ns=;
        b=mAudJN7w9lZBC6Y6KKvhadOUJMhXttxN5kk1KyQtmv2Fy4bO3W0xd9TKkdXJNIIlO2
         bO6anOHJnJA4ywleMmgy9B12rucBUaxaJksiYUZrRokhmT8a6Jy+JSJBwprzTzsMEg3y
         pEr6HKtg77+tKg3k5m9RVcGC68VpnHwrC4TpIidN5P10Yw3Fvz8u8MEuABpaNfY3tfX3
         P46S9jFF0QYAOXr1SzbU1/SSllIuAAerLNR67VBL1TzPbnYPGgtQ/Gmjh1EbOKaTpMe4
         I/sCb9AsXpGCjmbGk+mZPsTZrPzFuuYDSZJxFNFAOr6p67YYuP0frrYcVXiond9cwnSc
         aabw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=vOHvuwKt;
       spf=pass (google.com: domain of debug@rivosinc.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=debug@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710909605; x=1711514405; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=fCNtfJ5topHDekXuHR+JH5/wEjupzv1PyRMN16QDvn4=;
        b=fHkjAr2/sQPSAc7mqRD08IOwCi4sF8RpYItmxrSIeJJvX4BHXOMM7/326kdIhCqzbp
         LHDr72woNBSx3lQN7Yjgdl0W6p5bPzYOeQP76cYLBGC+JZqnWxCUEyeDTYKaLUnGN+ka
         09OkL/vbmToBw8uGsXaW40EEvLd4wCAEgvRyG9icea8kUJ3QdPctvfcdpFBG6ZUP7u87
         pI7OBaBvN5Nneh8h9uS5oGy2M99ZlJ9lnwbZhkhnqiIYznonvfr6GedaUvd5QnY6GQA6
         MeHJdQg2/4Mumeo5SSj4jBeY8rzCfyZ13ipocDeqBrZ15WSYxBP1Rqx/0RK1rm8WOXzO
         AITQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710909605; x=1711514405;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=fCNtfJ5topHDekXuHR+JH5/wEjupzv1PyRMN16QDvn4=;
        b=VjHjTaOpJNB3IorXqGXvWbLJnb8n0UwPDD2dkV7KI7bc4iEJFo5rf4UuqqrEs0qCBX
         z/W2mn8Tl/jYGekXxhlAq1CB3SAYLd69+03KWPErJSmVVhnrSjtMGh7KqRl6g1i4zhkG
         28kBh9CH78W0YSUJNn/qtOziTCFmfcWChQbWzW/4iEdu/C+203UJAK71nYKvwXnBy84B
         ASvUiGSjCpgK/eP7CIudaAk5AK2BYW4AyuG//CFdx1dcFnSA1/cZ1AFY1AACfsrYZ0XW
         4UbqRc+i1l7MG0liLNklG+QuLV2a+9fwgAeg6Oo0IVQJDdqJC9urEXNqJd71wZS9Xnml
         vOJQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWBhEztO0WrSE/tvsiPu6FJnIczuEm9TlsL98ldbTDUSJD8GXFVjU72ixlVv5r93Xw7NCbWzGbthRbLM2hf7PPT10Oj80U3Kg==
X-Gm-Message-State: AOJu0YylAEXYwx8c+AGMc5MxQjbPCBhe8KF9LGJJYpD7XwtKhNvAH00g
	FbgGqifZt53mq0Bm6wiA6vd+R6YnuGkpun62u7eoCoBZDk4GZ0YL
X-Google-Smtp-Source: AGHT+IH6fzWLAueAflaj9qKjmReHJNVpwp29WhlHMYOwzJQlim/U5fNSIsvAKqJxE8CA2GZNjfJPvA==
X-Received: by 2002:a0c:da85:0:b0:690:b563:879 with SMTP id z5-20020a0cda85000000b00690b5630879mr15524484qvj.58.1710909605061;
        Tue, 19 Mar 2024 21:40:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:ac2:b0:690:ee1f:cfe3 with SMTP id
 g2-20020a0562140ac200b00690ee1fcfe3ls10070536qvi.0.-pod-prod-01-us; Tue, 19
 Mar 2024 21:40:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXNf9JfcQt//TFzzqrf0S3TerpHKiSq7QH0S94lKmPKaQQ9WAk/T70uA3kAENbzyoRa7gR83yvlid7Js7jBiO647Ng4QRRqBpSvZg==
X-Received: by 2002:ac5:cdf3:0:b0:4d3:3f2b:dc63 with SMTP id v19-20020ac5cdf3000000b004d33f2bdc63mr10943660vkn.5.1710909604151;
        Tue, 19 Mar 2024 21:40:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710909604; cv=none;
        d=google.com; s=arc-20160816;
        b=smPGzggupI4GOGwO6tMtdWpwN86agFbs5wqvu3Zov4MQ/0lUxe/f3PifuANxgzCc8I
         h9bIyhgyygDyM7cA3+7Xpxl1iP6WAJDA2PGK3pTHu4SDItNqFVg5/82rQIoLFrtOKEO6
         Gb6Xr0uAk6RqfdgYEfqp2BJRwvaYN92ec5TaEqrU0L+FHJ3TJhBO5crIFkjvaGJOdvQv
         eBJQI5i+bbGKA+bh4gMJEmbdqlGPfxtgzuBTWYlkEJGPQJB9i6lzkEtcRVzCd3HKcxXj
         Rm98kFRt2dc7gyi8l8fx+TTBj6SQbzINbttrqbF1PBhH3BjVvW8LyOpLSadtIoTLnrO5
         n5SA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=HOcEqvOqLiRgD+vxwVroLkV65fGdVjagF231/Ug6vZ0=;
        fh=tH6D3BRRT8Bht/e1Km+4OEf7NiNVC2UdnMMdmKLJ7kg=;
        b=aVgiwDyrSGLtfDGCRpC0EwV/OooZIRaO4tIgAIOGtyCzKn+fUOXmQwVIImQdH9LLPW
         w2vxzezFXSKM8v36yw180afaF/blk16NIbqN6SgQ/iEG9p5slofdNcTpsA8U6PuMyX2x
         NV5WkmYxmL+0fC8s1lhJKWcXrET+1H5h/jchaMkbp/KioE5fzXhoNcF8ppcTLDGjxowK
         Oe7dJKHDukC8paYxmi9+HWozonzK39qc5jwkJapb5BRSsmZbDbMCUOp3iJCMg9YYr6uT
         8i20dzKqcZMygedd9sBeDbSIPCJ6t3zpQMVX3kKfJvHI4eGXnGhgWSmmSmjYCQgxLKW8
         Ay0w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=vOHvuwKt;
       spf=pass (google.com: domain of debug@rivosinc.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=debug@rivosinc.com
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id de29-20020a056122459d00b004d42270619dsi1143691vkb.1.2024.03.19.21.40.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Mar 2024 21:40:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of debug@rivosinc.com designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id 3f1490d57ef6-dd14d8e7026so5182341276.2
        for <kasan-dev@googlegroups.com>; Tue, 19 Mar 2024 21:40:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV+lQ8Po/SMFlN7/icLX8bgweaNOJcbiamKhiRzeDGsTdqyHyI8LE96hfYViPyAkjA2Ve/Kj++blN58bZ6vJwt5T5oOu5vIBLlozQ==
X-Received: by 2002:a25:ad46:0:b0:dc2:2f4f:757 with SMTP id
 l6-20020a25ad46000000b00dc22f4f0757mr14257691ybe.7.1710909603558; Tue, 19 Mar
 2024 21:40:03 -0700 (PDT)
MIME-Version: 1.0
References: <20240319215915.832127-1-samuel.holland@sifive.com>
 <20240319215915.832127-6-samuel.holland@sifive.com> <CAKC1njSg9-hJo6hibcM9a-=FUmMWyR39QUYqQ1uwiWhpBZQb9A@mail.gmail.com>
 <40ab1ce5-8700-4a63-b182-1e864f6c9225@sifive.com>
In-Reply-To: <40ab1ce5-8700-4a63-b182-1e864f6c9225@sifive.com>
From: Deepak Gupta <debug@rivosinc.com>
Date: Tue, 19 Mar 2024 21:39:52 -0700
Message-ID: <CAKC1njQYZHbQJ71mapeG1DEw=A+aGx77xsuQGecsNFpoJ=tzGQ@mail.gmail.com>
Subject: Re: [RISC-V] [tech-j-ext] [RFC PATCH 5/9] riscv: Split per-CPU and
 per-thread envcfg bits
To: Samuel Holland <samuel.holland@sifive.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org, 
	devicetree@vger.kernel.org, Catalin Marinas <catalin.marinas@arm.com>, 
	linux-kernel@vger.kernel.org, tech-j-ext@lists.risc-v.org, 
	Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, 
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>, Rob Herring <robh+dt@kernel.org>, 
	Andrew Jones <ajones@ventanamicro.com>, Guo Ren <guoren@kernel.org>, 
	Heiko Stuebner <heiko@sntech.de>, Paul Walmsley <paul.walmsley@sifive.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: debug@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=vOHvuwKt;       spf=pass (google.com: domain of debug@rivosinc.com
 designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=debug@rivosinc.com
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

Hi Samuel,

Thanks for your response.

On Tue, Mar 19, 2024 at 7:21=E2=80=AFPM Samuel Holland
<samuel.holland@sifive.com> wrote:
>
> Hi Deepak,
>
> On 2024-03-19 6:55 PM, Deepak Gupta wrote:
> > On Tue, Mar 19, 2024 at 2:59=E2=80=AFPM Samuel Holland via lists.riscv.=
org
> > <samuel.holland=3Dsifive.com@lists.riscv.org> wrote:
> >>
> >> Some envcfg bits need to be controlled on a per-thread basis, such as
> >> the pointer masking mode. However, the envcfg CSR value cannot simply =
be
> >> stored in struct thread_struct, because some hardware may implement a
> >> different subset of envcfg CSR bits is across CPUs. As a result, we ne=
ed
> >> to combine the per-CPU and per-thread bits whenever we switch threads.
> >>
> >
> > Why not do something like this
> >
> > diff --git a/arch/riscv/include/asm/csr.h b/arch/riscv/include/asm/csr.=
h
> > index b3400517b0a9..01ba87954da2 100644
> > --- a/arch/riscv/include/asm/csr.h
> > +++ b/arch/riscv/include/asm/csr.h
> > @@ -202,6 +202,8 @@
> >  #define ENVCFG_CBIE_FLUSH              _AC(0x1, UL)
> >  #define ENVCFG_CBIE_INV                        _AC(0x3, UL)
> >  #define ENVCFG_FIOM                    _AC(0x1, UL)
> > +/* by default all threads should be able to zero cache */
> > +#define ENVCFG_BASE                    ENVCFG_CBZE
>
> Linux does not assume Sstrict, so without Zicboz being present in DT/ACPI=
, we
> have no idea what the CBZE bit does--there's no guarantee it has the stan=
dard
> meaning--so it's not safe to set the bit unconditionally. If that policy
> changes, we could definitely simplify the code.
>

Yeah, it makes sense.

> >  /* Smstateen bits */
> >  #define SMSTATEEN0_AIA_IMSIC_SHIFT     58
> > diff --git a/arch/riscv/kernel/process.c b/arch/riscv/kernel/process.c
> > index 4f21d970a129..2420123444c4 100644
> > --- a/arch/riscv/kernel/process.c
> > +++ b/arch/riscv/kernel/process.c
> > @@ -152,6 +152,7 @@ void start_thread(struct pt_regs *regs, unsigned lo=
ng pc,
> >         else
> >                 regs->status |=3D SR_UXL_64;
> >  #endif
> > +       current->thread_info.envcfg =3D ENVCFG_BASE;
> >  }
> >
> > And instead of context switching in `_switch_to`,
> > In `entry.S` pick up `envcfg` from `thread_info` and write it into CSR.
>
> The immediate reason is that writing envcfg in ret_from_exception() adds =
cycles
> to every IRQ and system call exit, even though most of them will not chan=
ge the
> envcfg value. This is especially the case when returning from an IRQ/exce=
ption
> back to S-mode, since envcfg has zero effect there.
>
> The CSRs that are read/written in entry.S are generally those where the v=
alue
> can be updated by hardware, as part of taking an exception. But envcfg ne=
ver
> changes on its own. The kernel knows exactly when its value will change, =
and
> those places are:
>
>  1) Task switch, i.e. switch_to()
>  2) execve(), i.e. start_thread() or flush_thread()
>  3) A system call that specifically affects a feature controlled by envcf=
g

Yeah I was optimizing for a single place to write instead of
sprinkling at multiple places.
But I see your argument. That's fine.

>
> So that's where this series writes it. There are a couple of minor tradeo=
ffs
> about when exactly to do the write:
>
> - We could drop the sync_envcfg() calls outside of switch_to() by reading=
 the
>   current CSR value when scheduling out a thread, but again that adds ove=
rhead
>   to the fast path to remove a tiny bit of code in the prctl() handlers.
> - We don't need to write envcfg when switching to a kernel thread, only w=
hen
>   switching to a user thread, because kernel threads never leave S-mode, =
so
>   envcfg doesn't affect them. But checking the thread type takes many mor=
e
>   instructions than just writing the CSR.
>
> Overall, the optimal implementation will approximate the rule of only wri=
ting
> envcfg when its value changes.
>
> > This construction avoids
> > - declaring per cpu riscv_cpu_envcfg
>
> This is really a separate concern than when we write envcfg. The per-CPU
> variable is only necessary to support hardware where a subset of harts su=
pport
> Zicboz. Since the riscv_cpu_has_extension_[un]likely() helpers were added
> specifically for Zicboz, I assume this is an important use case, and drop=
ping
> support for this hardware would be a regression. After all, hwprobe() all=
ows
> userspace to see that Zicboz is implemented at a per-CPU level. Maybe And=
rew can
> weigh in on that.

I am not sure of the practicality of this heterogeneity for Zicboz and
for that matter any of the upcoming
features that'll be enabled via senvcfg (control flow integrity,
pointer masking, etc).

As an example if cache zeroing instructions are used by app binary, I
expect it to be used in following
manner

 - Explicitly inserting cbo.zero by application developer
 - Some compiler flag which ensures that structures larger than cache
line gets zeroed by cbo.zero

In either of the cases, the developer is not expecting to target it to
a specific hart on SoC and instead expect it to work.
There might be libraries (installed via sudo apt get) with cache zero
support in them which may run in different address spaces.
Should the library be aware of the CPU on which it's running. Now
whoever is running these binaries should be aware which CPUs
they get assigned to in order to avoid faults?

That seems excessive, doesn't it?

>
> If we decide to enable Zicboz only when all harts support it, or we decid=
e it's
> safe to attempt to set the envcfg.CBZE bit on harts that do not declare s=
upport
> for Zicboz, then we could drop the percpu variable.
>
> > - syncing up
> > - collection of *envcfg bits.
> >
> >
> >> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> >> ---
> >>
> >>  arch/riscv/include/asm/cpufeature.h |  2 ++
> >>  arch/riscv/include/asm/processor.h  |  1 +
> >>  arch/riscv/include/asm/switch_to.h  | 12 ++++++++++++
> >>  arch/riscv/kernel/cpufeature.c      |  4 +++-
> >>  4 files changed, 18 insertions(+), 1 deletion(-)
> >>
> >> diff --git a/arch/riscv/include/asm/cpufeature.h b/arch/riscv/include/=
asm/cpufeature.h
> >> index 0bd11862b760..b1ad8d0b4599 100644
> >> --- a/arch/riscv/include/asm/cpufeature.h
> >> +++ b/arch/riscv/include/asm/cpufeature.h
> >> @@ -33,6 +33,8 @@ DECLARE_PER_CPU(long, misaligned_access_speed);
> >>  /* Per-cpu ISA extensions. */
> >>  extern struct riscv_isainfo hart_isa[NR_CPUS];
> >>
> >> +DECLARE_PER_CPU(unsigned long, riscv_cpu_envcfg);
> >> +
> >>  void riscv_user_isa_enable(void);
> >>
> >>  #ifdef CONFIG_RISCV_MISALIGNED
> >> diff --git a/arch/riscv/include/asm/processor.h b/arch/riscv/include/a=
sm/processor.h
> >> index a8509cc31ab2..06b87402a4d8 100644
> >> --- a/arch/riscv/include/asm/processor.h
> >> +++ b/arch/riscv/include/asm/processor.h
> >> @@ -118,6 +118,7 @@ struct thread_struct {
> >>         unsigned long s[12];    /* s[0]: frame pointer */
> >>         struct __riscv_d_ext_state fstate;
> >>         unsigned long bad_cause;
> >> +       unsigned long envcfg;
> >>         u32 riscv_v_flags;
> >>         u32 vstate_ctrl;
> >>         struct __riscv_v_ext_state vstate;
> >> diff --git a/arch/riscv/include/asm/switch_to.h b/arch/riscv/include/a=
sm/switch_to.h
> >> index 7efdb0584d47..256a354a5c4a 100644
> >> --- a/arch/riscv/include/asm/switch_to.h
> >> +++ b/arch/riscv/include/asm/switch_to.h
> >> @@ -69,6 +69,17 @@ static __always_inline bool has_fpu(void) { return =
false; }
> >>  #define __switch_to_fpu(__prev, __next) do { } while (0)
> >>  #endif
> >>
> >> +static inline void sync_envcfg(struct task_struct *task)
> >> +{
> >> +       csr_write(CSR_ENVCFG, this_cpu_read(riscv_cpu_envcfg) | task->=
thread.envcfg);
> >> +}
> >> +
> >> +static inline void __switch_to_envcfg(struct task_struct *next)
> >> +{
> >> +       if (riscv_cpu_has_extension_unlikely(smp_processor_id(), RISCV=
_ISA_EXT_XLINUXENVCFG))
> >
> > I've seen `riscv_cpu_has_extension_unlikely` generating branchy code
> > even if ALTERNATIVES was turned on.
> > Can you check disasm on your end as well.  IMHO, `entry.S` is a better
> > place to pick up *envcfg.
>
> The branchiness is sort of expected, since that function is implemented b=
y
> switching on/off a branch instruction, so the alternate code is necessari=
ly a
> separate basic block. It's a tradeoff so we don't have to write assembly =
code
> for every bit of code that depends on an extension. However, the cost sho=
uld be
> somewhat lowered since the branch is unconditional and so entirely predic=
table.
>
> If the branch turns out to be problematic for performance, then we could =
use
> ALTERNATIVE directly in sync_envcfg() to NOP out the CSR write.

Yeah I lean towards using alternatives directly.

>
> >> +               sync_envcfg(next);
> >> +}

>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAKC1njQYZHbQJ71mapeG1DEw%3DA%2BaGx77xsuQGecsNFpoJ%3DtzGQ%40mail.=
gmail.com.
