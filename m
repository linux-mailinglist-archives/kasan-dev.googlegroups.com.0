Return-Path: <kasan-dev+bncBC76RJVVRQPRBV7Y62XQMGQE3H32FHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id AA8758871C6
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Mar 2024 18:14:00 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4313a5ecc8dsf9531cf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Mar 2024 10:14:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711127639; cv=pass;
        d=google.com; s=arc-20160816;
        b=pIFgIZ95fBuy8vVpo7QqbP/lWGHiY8BTXDjJqW7mR/fT2CiWYD/mangGMFd7wNTMEo
         fAzmHVbgU2U/GZn7ZbDmIicgfnZ2LhFyUCsZgqVnP9Bfu4JN+69rbjJzp9wPzFhhVg9F
         YmpRKOGd0ubaHVL7jhOwuyqYOMTC80QPq0PYuWNMwUm6KURdzJKbs2ZrqA0fmPg5Dpn/
         zKKcmlhTsNeFBPmHMAeMO/dplHrlvBU37oH/nlXf2bFvnvjO+VnBZDPytKy055TUvxH9
         7DURD3s/++nnZya15+I5ZSgEdi+1cuws0sD2W+Q1DCKDgT+FjptfKrwQ2sRqNJ+zak/D
         0Daw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=Lk7A10RY2VRlZ8Qo6884ETabHgfHckq+J3+0X2H1rws=;
        fh=YLBx57nvbsp/gsPuaT+0ay7nU7pYRszBgObTukYVaQ8=;
        b=b5wvE5VGbTCKKVLLpAyvtK8TvP/gem4yJAWYgTEsmtDmmYJqf6IQ+OaofdwX70vMaH
         CpfwQrvJ57TAEaI8yV308ODP4Twr6vw/rrbkkSBmo5DkV42LRNljrtPgsVwIR9eSFhKQ
         o4QxcLEBxe4kKNhK0FtL9NLCJzC9JRANoyWRDbQ0MBWALMLfOy9vU1J7+m4/+t7yjRO/
         kSREdnJVKBzdzPRINs2A97qbogeYHexiaCoq2B78I7VTe7pGZ0Qc8M+gTmr1ujKQPRlX
         TDVnnnis3/vu77RD7lFtC0cj7DePNy3Y4fn88MsgMMVZ/7mIfHex80ZzV55hZjU4Ibeg
         MFNw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=IxhfOwnQ;
       spf=pass (google.com: domain of debug@rivosinc.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=debug@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711127639; x=1711732439; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Lk7A10RY2VRlZ8Qo6884ETabHgfHckq+J3+0X2H1rws=;
        b=UbKTbj15FfPQQ2fF7M5k4t3IzszKwmZp3W9r3CgY6V0f3ff3CMFK2wyLYWsl/JkhLX
         NRZJgY+V+thz5gak3fRINrbuIqWFFdCeZkqecdI2+3TvEnmWPWr+2K2JBw6jPOw7D5t/
         O323cbOp9lCJg1zgACMW9GK7L7rubG1PkNooW2iXdoDgyr5gO66C6o6Jacph3/73FUwJ
         ws5l47u3tB4jZdqVeS2/Bf2mJCqT9iGLNnHStaeaXcjA1CbfQDhijxXa76O+6fdgecGY
         AczgoeDAbkU7kA1/UqKI/h0M0AmDVgfH0UNQykjoX3rMTMDRf9EVtQT/fh+x8EVh8DI+
         PNXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711127639; x=1711732439;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Lk7A10RY2VRlZ8Qo6884ETabHgfHckq+J3+0X2H1rws=;
        b=XjuufNv+KuDv89BNiPYhNLAsPj/Wcr4cgaJbl4YWvX+C7dIFX0fokI4VJx2t7FgX17
         5c1SXm4hkYsVBBPZ+nOW8xCtXbJbayz5J9GGeZk5QaJzdbtPUy8J++/HwjYSpEFY4CXF
         SnseEVmg4Mzfm48uKsooSdv2dKLEXoS3gF+qrtSb95esExaM3sTs5wzvmN126+maMr+p
         K1+dw+2lxDFulfyo+hU1Qpq3D5U4Yh3r1Fh79R3rc8tGZeCFj6I8D7beh3fdc5bwRtYp
         v85qpsMTarhdTR/T4ERQe1RTGvHFeeTFvMy1r2iWhYCXiKst11mws3FwplTcO0p2MSK3
         9T+Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVIGeD4f1QjivXKETusqHbT31n3caq/Z32SGqIpXNBKaLzQbKo9/9k+lKEzd/Tiauhr0la01a4XjDuHweHpjlN/L5uyj3/RiQ==
X-Gm-Message-State: AOJu0Yx3xAhNQb0nOTEWhONPb/uEnFf6fWV/Vf2ri2Yv4q85VePyUCB3
	Zn55qUXqUm26BxSNtYDZOt00ysK/AHQ9V27RAkHPsnUYPIjbLb3L
X-Google-Smtp-Source: AGHT+IGBAZGykeZwn5QPaZ0I1qIqAvI0kVhPXAbaDRRlwAl90oaTB5pKaw6/K6V4C0ZiKd66vFzCLg==
X-Received: by 2002:ac8:5ad4:0:b0:431:2a26:2121 with SMTP id d20-20020ac85ad4000000b004312a262121mr420074qtd.25.1711127639349;
        Fri, 22 Mar 2024 10:13:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7542:0:b0:dcd:a08f:c83e with SMTP id q63-20020a257542000000b00dcda08fc83els456208ybc.2.-pod-prod-07-us;
 Fri, 22 Mar 2024 10:13:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUa4CJYbtXXpQ1tWJPyTmhbFCXAu/IsCxFW3RrwvRQjHDeuRukSgREgaL64aRDagv/WWGfRQvHnHvRNtm3zSzuiwssPEndBOtkkHg==
X-Received: by 2002:a25:ef48:0:b0:dd1:5c7c:f262 with SMTP id w8-20020a25ef48000000b00dd15c7cf262mr2578487ybm.48.1711127638620;
        Fri, 22 Mar 2024 10:13:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711127638; cv=none;
        d=google.com; s=arc-20160816;
        b=BUzHQgu5IlXIuIsX7pWM6DsYjIGZGLL5C9ON+41/64CLb91+QsGYP3J0UaXuq9BOCT
         QmBR6tEcsYx1mAvuP6GiGpvY+qNFoA/WATHtDsVA5oR4Vy8XrV2vejz4q/UUHexrobJa
         WhIGPFUniGwr0CwnS0dtjGlnIJ3+Y/fTor6YAORjB5zWHLX8CQbLhqjD3UY657zBooOc
         tbPyDtOrJ/un5F42EOUlq4DiDAEIaJgVcVtM7vMtZTlWfS+pY3FmDErwheBq988msxPX
         XNo2S5dHHjFzDRSglHLQ2Teg9bN3rHMZBjigNqIZVqY9ecBLLg7QFno+UKRJGvdmcHGJ
         A+Ng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=JrCZcezSHtMHgCYV9eTeglWhzn7+4jU5szarE8AAqMc=;
        fh=tsfWqkL2E5Zq5uTXGB8KPmzdFpg1ZVyu3VArM/4HR+o=;
        b=OqJEIxFEuYqHi8+GCAQN0R8P6gLnxTusjiiOO3iOtvUDaz6NOusA4qEgS9x1JO19ss
         IxNDXrgp3ZFxYig7kwlz7FtrkiARH07b2E/KX9DAQFNozxeQn4SbT2dvCAWz219NzjaL
         3NvPPzVhLTJV7Yac3C3UktsUZXvoMrPmE3ZJVKjemn0RsKtaJXMFtL1sFVSPuf22pcH8
         n8iAITEGaSvnwKp8pcG3vzjbARl+4i319CkzrmaeimbdOvm/SEYJTBQRBC7+t7lbeV1h
         I0rP+rvZ0iYOGaG40qwnVYKamN5p13zTzcwDi6VULELcEoeY+kpyzd32YEUGDL7Xeh6p
         9sUg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=IxhfOwnQ;
       spf=pass (google.com: domain of debug@rivosinc.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=debug@rivosinc.com
Received: from mail-yb1-xb2a.google.com (mail-yb1-xb2a.google.com. [2607:f8b0:4864:20::b2a])
        by gmr-mx.google.com with ESMTPS id g193-20020a25dbca000000b00dcd162eec7esi146309ybf.2.2024.03.22.10.13.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Mar 2024 10:13:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of debug@rivosinc.com designates 2607:f8b0:4864:20::b2a as permitted sender) client-ip=2607:f8b0:4864:20::b2a;
Received: by mail-yb1-xb2a.google.com with SMTP id 3f1490d57ef6-dcbd1d4904dso2523874276.3
        for <kasan-dev@googlegroups.com>; Fri, 22 Mar 2024 10:13:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV36O3XRwH4XClt+d5LmrxOE3cDYNxnCqIQxeq4yJeE7O5vwv75IZ29tcOqHEpsqlWhMdovio8eoklagUNAlSw8qDnZKcY0VKj4NQ==
X-Received: by 2002:a25:b121:0:b0:dc6:d2d3:a57c with SMTP id
 g33-20020a25b121000000b00dc6d2d3a57cmr2856379ybj.59.1711127638274; Fri, 22
 Mar 2024 10:13:58 -0700 (PDT)
MIME-Version: 1.0
References: <20240319215915.832127-1-samuel.holland@sifive.com>
 <20240319215915.832127-6-samuel.holland@sifive.com> <CAKC1njSg9-hJo6hibcM9a-=FUmMWyR39QUYqQ1uwiWhpBZQb9A@mail.gmail.com>
 <40ab1ce5-8700-4a63-b182-1e864f6c9225@sifive.com> <CAKC1njQYZHbQJ71mapeG1DEw=A+aGx77xsuQGecsNFpoJ=tzGQ@mail.gmail.com>
 <d9452ab4-a783-4bcf-ac25-40baa4f31fac@sifive.com>
In-Reply-To: <d9452ab4-a783-4bcf-ac25-40baa4f31fac@sifive.com>
From: Deepak Gupta <debug@rivosinc.com>
Date: Fri, 22 Mar 2024 10:13:48 -0700
Message-ID: <CAKC1njRBbzM+gWowg1LOjq5GzVn4q+vJP9JUswVYfWmEw+yHSg@mail.gmail.com>
Subject: Re: [RISC-V] [tech-j-ext] [RFC PATCH 5/9] riscv: Split per-CPU and
 per-thread envcfg bits
To: Samuel Holland <samuel.holland@sifive.com>
Cc: Conor Dooley <conor@kernel.org>, Palmer Dabbelt <palmer@dabbelt.com>, 
	linux-riscv@lists.infradead.org, devicetree@vger.kernel.org, 
	Catalin Marinas <catalin.marinas@arm.com>, linux-kernel@vger.kernel.org, 
	tech-j-ext@lists.risc-v.org, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, 
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>, Rob Herring <robh+dt@kernel.org>, 
	Andrew Jones <ajones@ventanamicro.com>, Guo Ren <guoren@kernel.org>, 
	Heiko Stuebner <heiko@sntech.de>, Paul Walmsley <paul.walmsley@sifive.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: debug@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=IxhfOwnQ;       spf=pass (google.com: domain of debug@rivosinc.com
 designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=debug@rivosinc.com
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

On Thu, Mar 21, 2024 at 5:13=E2=80=AFPM Samuel Holland
<samuel.holland@sifive.com> wrote:
>
> On 2024-03-19 11:39 PM, Deepak Gupta wrote:
> >>>> --- a/arch/riscv/include/asm/switch_to.h
> >>>> +++ b/arch/riscv/include/asm/switch_to.h
> >>>> @@ -69,6 +69,17 @@ static __always_inline bool has_fpu(void) { retur=
n false; }
> >>>>  #define __switch_to_fpu(__prev, __next) do { } while (0)
> >>>>  #endif
> >>>>
> >>>> +static inline void sync_envcfg(struct task_struct *task)
> >>>> +{
> >>>> +       csr_write(CSR_ENVCFG, this_cpu_read(riscv_cpu_envcfg) | task=
->thread.envcfg);
> >>>> +}
> >>>> +
> >>>> +static inline void __switch_to_envcfg(struct task_struct *next)
> >>>> +{
> >>>> +       if (riscv_cpu_has_extension_unlikely(smp_processor_id(), RIS=
CV_ISA_EXT_XLINUXENVCFG))
> >>>
> >>> I've seen `riscv_cpu_has_extension_unlikely` generating branchy code
> >>> even if ALTERNATIVES was turned on.
> >>> Can you check disasm on your end as well.  IMHO, `entry.S` is a bette=
r
> >>> place to pick up *envcfg.
> >>
> >> The branchiness is sort of expected, since that function is implemente=
d by
> >> switching on/off a branch instruction, so the alternate code is necess=
arily a
> >> separate basic block. It's a tradeoff so we don't have to write assemb=
ly code
> >> for every bit of code that depends on an extension. However, the cost =
should be
> >> somewhat lowered since the branch is unconditional and so entirely pre=
dictable.
> >>
> >> If the branch turns out to be problematic for performance, then we cou=
ld use
> >> ALTERNATIVE directly in sync_envcfg() to NOP out the CSR write.
> >
> > Yeah I lean towards using alternatives directly.
>
> One thing to note here: we can't use alternatives directly if the behavio=
r needs
> to be different on different harts (i.e. a subset of harts implement the =
envcfg
> CSR). I think we need some policy about which ISA extensions are allowed =
to be
> asymmetric across harts, or else we add too much complexity.

As I've responded on the same thread . We are adding too much
complexity by assuming
that heterogeneous ISA exists (which it doesn't today). And even if it
exists, it wouldn't work.
Nobody wants to spend a lot of time figuring out which harts have
which ISA and which
packages are compiled with which ISA. Most of the end users do `sudo
apt get install blah blah`
And then expect it to just work. It doesn't work for other
architectures and even when someone
tried, they had to disable certain ISA features to make sure that all
cores have the same ISA feature
(search AVX12 Intel Alder Lake Disable).

>
> Regards,
> Samuel
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAKC1njRBbzM%2BgWowg1LOjq5GzVn4q%2BvJP9JUswVYfWmEw%2ByHSg%40mail.=
gmail.com.
