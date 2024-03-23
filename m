Return-Path: <kasan-dev+bncBCOJLJOJ7AARB4GE7KXQMGQEKW7CEXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 32FC38877CD
	for <lists+kasan-dev@lfdr.de>; Sat, 23 Mar 2024 10:35:46 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-56be4021c51sf13527a12.0
        for <lists+kasan-dev@lfdr.de>; Sat, 23 Mar 2024 02:35:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711186545; cv=pass;
        d=google.com; s=arc-20160816;
        b=L6VJWGCesQIcc9xRzEe9kzlq4TNdTZcp1jkWQZTstk22Oj/pY7pCFL8doenYu41I6l
         xW+sz1tiFZAihtcZ8Sb54O294Y6OGpLvqf+9kEcegQk6TmNN4nYk0Ao0L9R8OngESDmO
         ew8aRZqaVfzK7goK+ijpdKsB25kvBkWS/hppsb6alTbtmdbiFbrU1RjI1fm+SNKqNMc8
         p8CtFWrYaL2S/SIbCKFN6mNv4FIMxbUYMaiCJXjpgsAa1ay8Hl4r9aMpxMcJKSQgFnzU
         /QSElD7DCsvpmkVx5fDBe63j18KkrDBA3Gokk6Gk/+ooZGCmKBh0y38KnT/FiVsqSy3X
         1Gxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=lFbnuzgbjUMsauS5YKHFIKfgMhohE/PctKMac2ECYHU=;
        fh=RNUs/d3unNM+g+8MtvtoYEdKd5AxX7zOPRcv2Sv8jxs=;
        b=kqQpQvkBPJcVP8kHE9SbMQSrabkLWxa7OFnnrlE3jpubTDdEKIAn1MKth/J+//ANZp
         hRUTS2C1B2fusrOThWdkvC0Ejj/r6wqa9riVlRc8/sRzOqCX6CCtvv+BD982yedK6uiZ
         ZwllTDw6+hnF28Yf4Z690GbLCLjj0q1RmTplX9CQ9t4wPWaXm2dhMjFFRIee+MFmNYMX
         XHbdKavzRAweJn+2QiSzU8KGuI1p+YBDm0XpRd0yDPiD/CJOuDW5jZ0ygbQhQBKjt2oM
         BaxwxG5kdwvmkvfmk4Igws1nchE81asBIa1iJyzg7BVf+KJ4FsnUpgmjtUKochEG2PcE
         kZUQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ventanamicro.com header.s=google header.b=BCvgz6eI;
       spf=pass (google.com: domain of ajones@ventanamicro.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=ajones@ventanamicro.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711186545; x=1711791345; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=lFbnuzgbjUMsauS5YKHFIKfgMhohE/PctKMac2ECYHU=;
        b=qb746By6Wk2Ao68th85MxTqUzuRNBKo7ifndjTtDNPS/7zKrIg/dCewTowlqdOEpud
         /hhBkzxV3aw1rAImBUCwhpaOkr8e8liBa0ANJz7vUz/v5F72P/EmvzA6ghAyHpm55gDA
         K1s+qFPq3mNb/X2N2UiTytAn/7259Qn6rgdK5SBZQSgeQSAOy7c0BrUK8sJyYUnckeju
         NUbJNEF89ZqimpOOhr+q8OljagKfaWO5EaDBz4HKxCBawfafQCBKnxTBL/FQlVjNLMHZ
         f1YZaPbMThvebg+STAy0c5pzuBFOuFSAlJSgQoUMlSJ0KbXmuIdbpbdz06O3rXEU0ndK
         TlIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711186545; x=1711791345;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lFbnuzgbjUMsauS5YKHFIKfgMhohE/PctKMac2ECYHU=;
        b=LO78uZcsN378fo1B9YdrNQOxdG2mgGEmdBUBtkTdYcLjJ0qtzVPa98LgHGuKztWjVi
         wXTs3sTZbnQhMowjYzROBXBvsix+ZMYzygxulDJO4DMxCyUNKUYBKlAKUYMu8TXvIIm+
         ND8axm9JfMRhXXPUQ9T8RU1ejjshdWEmKb5gQmtQb7znSF9lT96vXZmICscdRudzL82C
         edg285F1qc0c0j5jq3FBZYPRA9HtgcL8nqgRNyGNVJ38qrEYuwYSF9pfu8vjeKMlvsNF
         oFMg0X4FENzkSaMZcYe2bklZr2AZGbx0DsEN/qLXppUyST78OxAp3Ma/ZemtJdM64I9V
         qCuQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUm4MAtRe0oQ7KlCUj96NGv4dubf93JrSUxoa9yr1x2+QVKnfUnUJA9aim5TFsD1TlWNy7jOAS8QD2XCdeFKcHPFJrwwxzXzw==
X-Gm-Message-State: AOJu0Yy8aRzGD6YiWti8x786N1RmUFhBD5IT6kKc0SVrlVQym88OF1zs
	NvsQv2OV6GscK0FNEgqwhA3X/oS9V792Km7Y6HT2bQgk5mfhosau
X-Google-Smtp-Source: AGHT+IEuDnZx1oW9DN0dn/oQb1ksvHBzYgKdLPfgajfoW6X7ECRY7BWD/83LanUrLr/rEoWoxYX9Pw==
X-Received: by 2002:a05:6402:3483:b0:56b:d1c8:a276 with SMTP id v3-20020a056402348300b0056bd1c8a276mr517645edc.6.1711186544274;
        Sat, 23 Mar 2024 02:35:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:4023:b0:513:b057:b104 with SMTP id
 br35-20020a056512402300b00513b057b104ls1599505lfb.1.-pod-prod-03-eu; Sat, 23
 Mar 2024 02:35:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXyxbPuwUdzfIaEQ7D8OZ1sCS6UVBXcbEXH1q7cy2HYDhlVFIb3YCx3djl2hryx4xbyWb7zCZulMwee0VeS8eOsHrRbNzdoTRXtpA==
X-Received: by 2002:a19:8c16:0:b0:513:d104:f5c7 with SMTP id o22-20020a198c16000000b00513d104f5c7mr1165582lfd.5.1711186541883;
        Sat, 23 Mar 2024 02:35:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711186541; cv=none;
        d=google.com; s=arc-20160816;
        b=ohdS/0+u/8KNxHTJ6MYbJ6OxCGAoyOGi/ZP6v480Y7SXfqw5EFxDJkqLBBhp7KwkFv
         +5WPKpZ+ks6fRghCSuKeQLpvBGzJ/FXhROiqs+2lI6pNgy0xcBQApfAAWanZHJ5xBH71
         IlaBUHWC0cs0FZOqHAWVWnxgHGRSRcI+UxAWuKFSEKYoWpVuA8s3bXGkrgLOwWtxUti2
         fsf6YBcibpPsjHJclIWvPNFxAuYaedqnUvpsWHWUoipFWPDD9zXFo94dMRCW+WkiVSeS
         37Eeh+MQQicvOckxWfZbyrp1vfs7C188oQnAYhzGmkuSxGYpcACC3up4fm/s/9WX2Wfv
         AFfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=gifRQ1PeHTOYVEFwRFqeQ4RDDqpypI+PitbwyUwiMWU=;
        fh=I0N7CHi0wAtk4hPgYMTJXgSYb0ngf71bnG9ZUFcIyss=;
        b=wXV1IQJ63xthQJ6QrbKpJUEZeNOuSBxbFKPxoITcb6xBSff4mrdrVLJoPT7YhSc6xL
         gKjMVohF3LK2PQVRFcP1/fiyXsdDlBkCvjhXJaL2Qdmu4ccO1bvDLHnC11KLj9+atbXR
         YV2xq6nZUGu/TMpSVELvR/Q7wT0nIEuBsViGGkA4FAPLBofGL+YeFwXxXAT2EzEaUkbv
         3WbFr/KNz2TSI1Iy6AiEN2Krmecb8BUz2GKFqZRH8BU2A9l3wECCs0z5TkOSFB9slsW4
         5hb2yIJ+/FKV6CdSFOoFS24dYcG6DFKwNO+sM2QCatQrlwT6zvoY+KO4WunqOFlHUDb0
         rQRg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ventanamicro.com header.s=google header.b=BCvgz6eI;
       spf=pass (google.com: domain of ajones@ventanamicro.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=ajones@ventanamicro.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id o21-20020ac25e35000000b00513d22b003bsi37866lfg.11.2024.03.23.02.35.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 23 Mar 2024 02:35:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of ajones@ventanamicro.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id ffacd0b85a97d-33fd8a2a407so1672721f8f.2
        for <kasan-dev@googlegroups.com>; Sat, 23 Mar 2024 02:35:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVufiIDQpiF2EiKZHb5Z4D1Z0ZrgfQ13oVo6gBxHPCsEEOOPEiBSO1Q0evCnaVZR3rS+nTLeJ2K0XDuvdKGp6LgW0F9KKJOrCdkUA==
X-Received: by 2002:a5d:40d2:0:b0:33e:78d5:848e with SMTP id b18-20020a5d40d2000000b0033e78d5848emr1084783wrq.12.1711186540910;
        Sat, 23 Mar 2024 02:35:40 -0700 (PDT)
Received: from localhost ([2a00:11b1:10c0:1192:d048:e3e1:1749:7466])
        by smtp.gmail.com with ESMTPSA id cl1-20020a5d5f01000000b0033e72e104c5sm3007561wrb.34.2024.03.23.02.35.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 23 Mar 2024 02:35:40 -0700 (PDT)
Date: Sat, 23 Mar 2024 10:35:38 +0100
From: Andrew Jones <ajones@ventanamicro.com>
To: Deepak Gupta <debug@rivosinc.com>
Cc: Samuel Holland <samuel.holland@sifive.com>, 
	Conor Dooley <conor@kernel.org>, Palmer Dabbelt <palmer@dabbelt.com>, 
	linux-riscv@lists.infradead.org, devicetree@vger.kernel.org, 
	Catalin Marinas <catalin.marinas@arm.com>, linux-kernel@vger.kernel.org, tech-j-ext@lists.risc-v.org, 
	kasan-dev@googlegroups.com, Evgenii Stepanov <eugenis@google.com>, 
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>, Rob Herring <robh+dt@kernel.org>, Guo Ren <guoren@kernel.org>, 
	Heiko Stuebner <heiko@sntech.de>, Paul Walmsley <paul.walmsley@sifive.com>
Subject: Re: [RISC-V] [tech-j-ext] [RFC PATCH 5/9] riscv: Split per-CPU and
 per-thread envcfg bits
Message-ID: <20240323-28943722feb57a41fb0ff488@orel>
References: <20240319215915.832127-1-samuel.holland@sifive.com>
 <20240319215915.832127-6-samuel.holland@sifive.com>
 <CAKC1njSg9-hJo6hibcM9a-=FUmMWyR39QUYqQ1uwiWhpBZQb9A@mail.gmail.com>
 <40ab1ce5-8700-4a63-b182-1e864f6c9225@sifive.com>
 <CAKC1njQYZHbQJ71mapeG1DEw=A+aGx77xsuQGecsNFpoJ=tzGQ@mail.gmail.com>
 <d9452ab4-a783-4bcf-ac25-40baa4f31fac@sifive.com>
 <CAKC1njRBbzM+gWowg1LOjq5GzVn4q+vJP9JUswVYfWmEw+yHSg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAKC1njRBbzM+gWowg1LOjq5GzVn4q+vJP9JUswVYfWmEw+yHSg@mail.gmail.com>
X-Original-Sender: ajones@ventanamicro.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ventanamicro.com header.s=google header.b=BCvgz6eI;       spf=pass
 (google.com: domain of ajones@ventanamicro.com designates 2a00:1450:4864:20::42c
 as permitted sender) smtp.mailfrom=ajones@ventanamicro.com
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

On Fri, Mar 22, 2024 at 10:13:48AM -0700, Deepak Gupta wrote:
> On Thu, Mar 21, 2024 at 5:13=E2=80=AFPM Samuel Holland
> <samuel.holland@sifive.com> wrote:
> >
> > On 2024-03-19 11:39 PM, Deepak Gupta wrote:
> > >>>> --- a/arch/riscv/include/asm/switch_to.h
> > >>>> +++ b/arch/riscv/include/asm/switch_to.h
> > >>>> @@ -69,6 +69,17 @@ static __always_inline bool has_fpu(void) { ret=
urn false; }
> > >>>>  #define __switch_to_fpu(__prev, __next) do { } while (0)
> > >>>>  #endif
> > >>>>
> > >>>> +static inline void sync_envcfg(struct task_struct *task)
> > >>>> +{
> > >>>> +       csr_write(CSR_ENVCFG, this_cpu_read(riscv_cpu_envcfg) | ta=
sk->thread.envcfg);
> > >>>> +}
> > >>>> +
> > >>>> +static inline void __switch_to_envcfg(struct task_struct *next)
> > >>>> +{
> > >>>> +       if (riscv_cpu_has_extension_unlikely(smp_processor_id(), R=
ISCV_ISA_EXT_XLINUXENVCFG))
> > >>>
> > >>> I've seen `riscv_cpu_has_extension_unlikely` generating branchy cod=
e
> > >>> even if ALTERNATIVES was turned on.
> > >>> Can you check disasm on your end as well.  IMHO, `entry.S` is a bet=
ter
> > >>> place to pick up *envcfg.
> > >>
> > >> The branchiness is sort of expected, since that function is implemen=
ted by
> > >> switching on/off a branch instruction, so the alternate code is nece=
ssarily a
> > >> separate basic block. It's a tradeoff so we don't have to write asse=
mbly code
> > >> for every bit of code that depends on an extension. However, the cos=
t should be
> > >> somewhat lowered since the branch is unconditional and so entirely p=
redictable.
> > >>
> > >> If the branch turns out to be problematic for performance, then we c=
ould use
> > >> ALTERNATIVE directly in sync_envcfg() to NOP out the CSR write.
> > >
> > > Yeah I lean towards using alternatives directly.
> >
> > One thing to note here: we can't use alternatives directly if the behav=
ior needs
> > to be different on different harts (i.e. a subset of harts implement th=
e envcfg
> > CSR). I think we need some policy about which ISA extensions are allowe=
d to be
> > asymmetric across harts, or else we add too much complexity.
>=20
> As I've responded on the same thread . We are adding too much
> complexity by assuming
> that heterogeneous ISA exists (which it doesn't today). And even if it
> exists, it wouldn't work.
> Nobody wants to spend a lot of time figuring out which harts have
> which ISA and which
> packages are compiled with which ISA. Most of the end users do `sudo
> apt get install blah blah`
> And then expect it to just work.

That will still work if the applications and libraries installed are
heterogeneous-platform aware, i.e. they do the figuring out which harts
have which extensions themselves. Applications/libraries should already
be probing for ISA extensions before using them. It's not a huge leap to
also check which harts support those extensions and then ensure affinity
is set appropriately.

> It doesn't work for other
> architectures and even when someone
> tried, they had to disable certain ISA features to make sure that all
> cores have the same ISA feature
> (search AVX12 Intel Alder Lake Disable).

The RISC-V software ecosystem is still being developed. We have an
opportunity to drop assumptions made by other architectures.


As I said in a different reply, it's reasonable for Linux to not add the
complexity until a use case comes along that Linux would like to support,
but I think it would be premature for Linux to put a stake in the sand.

So, how about we add code that confirms Zicboz is on all harts. If any
hart does not have it, then we complain loudly and disable it on all
the other harts. If it was just a hardware description bug, then it'll
get fixed. If there's actually a platform which doesn't have Zicboz
on all harts, then, when the issue is reported, we can decide to not
support it, support it with defconfig, or support it under a Kconfig
guard which must be enabled by the user.

Thanks,
drew

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240323-28943722feb57a41fb0ff488%40orel.
