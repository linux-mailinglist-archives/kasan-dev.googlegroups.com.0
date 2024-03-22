Return-Path: <kasan-dev+bncBC76RJVVRQPRB2XO62XQMGQE755ZOMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id B6A74887146
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Mar 2024 17:53:00 +0100 (CET)
Received: by mail-io1-xd3b.google.com with SMTP id ca18e2360f4ac-7cbf0ebfda8sf215108839f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Mar 2024 09:53:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711126379; cv=pass;
        d=google.com; s=arc-20160816;
        b=DYurzO0s3F7LXyKgLA2Ze7uh1oN0Svk2dKqU28IafLOofQEJHogW4vUM31OrBy4jSn
         sxkzLTbgaPahvM46lfgN/YdI1T9rNCotvPOO/nrlCecZxntf/ZcT1Y3V6vYljxEHplew
         j03suZgz14UyiCwMOqRsCCK3rGvjEQDzYHCIuIQPGAu8eR8k3ozF8evi8b0jPx3EZf+J
         j9TIUdXKL06cJA1+pvCXkBgVo/UDg8JXK1C0XaNHnkRnNO+wrRt+xohj3fqxTJL9zXDc
         ZNul+5gQy68lFyzolNmlyMZdrnl13WyeWtE2psBNazSK2fvCs9deYyyglYiOLNy84TWJ
         fjVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=+SMKUqkuWweTUV3plO0lkvujyTWGLX18vq8/kulz3qU=;
        fh=ytqt8MoBVLiVOF1m9VzrEkh5zvw0ywjWlXl2WdXQm2M=;
        b=iRXYPZKWn9mP7NW2Kcj95TXFlGMhdiEaeEzij277XZqjD0hJVuwmZ/aMemTLUWSif2
         UaSmfjsBNmGZgb26QFSrrFfolxQTeoU+shbpf9m5oizzR7P71HMeuVsN5yi1DdtAO8gj
         pT0AqLyXoqM999/Gzotb7omt70wiI+k6j7v5+AJyxl92RMtLoLtRaWAIn8WvUA13Rf4t
         WW5v5Yj4Y4Evpb7f/Q+L3a3Hg4OyyBhmYp/MCdoy/5X4hdB9kxHsLsvHkiU4BnVaymwo
         M2b07TdLqya8edZPJ46kI7sZnrA9TTX2T77Bbtzotj1VFnFpDd9WAY0JncFx4Z7smGp+
         +V5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=UofxCdhB;
       spf=pass (google.com: domain of debug@rivosinc.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=debug@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711126379; x=1711731179; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+SMKUqkuWweTUV3plO0lkvujyTWGLX18vq8/kulz3qU=;
        b=G8oy87znsOoIHTMRW+ojMsT38pgsqaoQHtBv0zhQdBThWeYoWKQPByp0r/b3cGse/H
         daYQtZOc3Ien9PuGdidfpYgXDos2N5YZ+Rj5MKoUzWe0HIB0mq5FHd588r7lBiGtGBME
         Ao0MGn5w13NXzM8MRxn/xGON0/sBuNlGjpgaba8xj7/WsvK8/62wFAc15y40IGWQBdro
         iejLIl6YMgAbzCxAK5At9zFnp7ovPw2T+DEh8FLTy1lsqs4AOW5JHSvMe2E8CDDspOwq
         yOn4rusu2QlQkWD3J4SDem6+NrFH/FkzR38YBm/Xs1yfGAfq2fimCie03+La1uYiBzBm
         UARg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711126379; x=1711731179;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+SMKUqkuWweTUV3plO0lkvujyTWGLX18vq8/kulz3qU=;
        b=wiycVN97s4v9LczmrznW5OVXyoSHnpeupIgk118N71IQXFv/LeuCNdexEXFvpms4mj
         J0Clz3adLeVAEbvXubr2Sicy7iyIm3asFHb37uJ4sYvj3bk3SnUjIdn5cV+NNLFxwEfW
         xOseyiu5V2n9Vla7m9TnMfgWBJBJMoiDEc5hyW7UweyuvPBYr2SBTDaFQlxAxzaJMXih
         v99yr7UvYfXvBaBiY0yna3FPj4W0oySUfc63dkGuLOcpIFCfDtTFmVAkpAWP7NukdYUS
         39rSUKbROyGbBi/vacddnA1ZlokCXwEXD8IEsU4iQjqicJ/xOe62A+V8/Ra/udKQHw3C
         +aRw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWl9FK+hZ64OsQ+6NFPRx6tmp300NSBLZWKU7me0rghQdyc1P3efs6sR7KrBRmxFGXF0M4Bqn4URrP0Ir+t7TtbwrIIo1YUnw==
X-Gm-Message-State: AOJu0YztA3ZATciWjkxnW+AW/Aa8F0E8cgICyHs8GCGmWzHdAWnG3W3s
	dXAwV7z+Zgnyc76zPMRESap9sGsBGyPUC5jUCYZAiT5GEcIP34Wg
X-Google-Smtp-Source: AGHT+IGUXHqK6Je7f/HRuOzpkjBGclQNpa8qymuBJPy1JXrbTx8/9i4TADpu/85YpTEHAxLyvPzvRQ==
X-Received: by 2002:a05:6e02:174d:b0:368:6187:e19a with SMTP id y13-20020a056e02174d00b003686187e19amr63222ill.3.1711126379010;
        Fri, 22 Mar 2024 09:52:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a0a:b0:368:589a:3ea0 with SMTP id
 s10-20020a056e021a0a00b00368589a3ea0ls1296408ild.1.-pod-prod-04-us; Fri, 22
 Mar 2024 09:52:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX2d3FyEfHhYi49FNyv6r4PGM4mv0mRtIFno/y/5ljxkaSwstRZcunb+Dd8UVtRIbWWu0FT74iBObZ94x3RsrxYu0TtI9Te5uZKlA==
X-Received: by 2002:a6b:6d01:0:b0:7cd:6bb:c52 with SMTP id a1-20020a6b6d01000000b007cd06bb0c52mr18057iod.10.1711126378111;
        Fri, 22 Mar 2024 09:52:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711126378; cv=none;
        d=google.com; s=arc-20160816;
        b=T1bwUYkn4oPZZMbPEOF4BcYzeUuuwgsN6ZidQ09OStPiiADBNsT/eEzuZgM3auanf3
         5ArEKY4XOr7qUu/hXGdLHtz+TC4Iq20PDHBPWMIGI1F7OJjByAaTs/3Zer8GJd6VRzMr
         ik/YEUZTde7wijy+D9VFJblqxJkgcBnlJf9CcZ3yDcu0I+3LL72hq5qtbCkKcuXyiV62
         NWwXAHagF7EEFlZPQM+WuYKdJUGAvbPUVg6XKqWr3WOxahrh5Dp0Uqc51HxTTHTxo1V4
         peD8XJUZsNRt+R+hKBzchRy6OhwT6wq5wmV4IrvJwLqLbi64Vo/HHvrMbuRS+R6L8sLF
         9LBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=y51uEGJ03D6pw21uRms6OLbBjZsNY8YSRn9RWNKVb+8=;
        fh=who1j43LmY0yIMKkJNwvaXu+7eLbYkvmE6/PPjkTlx0=;
        b=y/0L5LkrrhPDXfdTOERLGgCQI4eiIejbwk6N/C0kDnAPqhePaYv/SRYvq0/gLBw8QB
         PbmazUQAXTsBcsksvlGDtPBfpw8meFyj327zFaj0IDZoo2n+pwEniLMdreCFFQrXsbp8
         gIkL/pYOdP3+1YidZDBxdHo+eZlP8OFJTl+r3SJ0eGveY3bh8mJ0Bm08xsUNE6bwOg9D
         fq5aJqXzrjmknCW0Cv2txn8ApP0uQ0/SejBhzVI33uEMQYT41qf1BPZJ4bZniiuSUN6f
         pRRiwctRTUmSGvJDl2M4Z59gm6KfYj1VedPfEcale2iV/nKi2hfOqxv6Dq9UwoNPAAfY
         xhWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=UofxCdhB;
       spf=pass (google.com: domain of debug@rivosinc.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=debug@rivosinc.com
Received: from mail-yw1-x112c.google.com (mail-yw1-x112c.google.com. [2607:f8b0:4864:20::112c])
        by gmr-mx.google.com with ESMTPS id k19-20020a5d8b13000000b007cf1ca72eeesi111875ion.3.2024.03.22.09.52.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Mar 2024 09:52:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of debug@rivosinc.com designates 2607:f8b0:4864:20::112c as permitted sender) client-ip=2607:f8b0:4864:20::112c;
Received: by mail-yw1-x112c.google.com with SMTP id 00721157ae682-60a0579a931so25447617b3.0
        for <kasan-dev@googlegroups.com>; Fri, 22 Mar 2024 09:52:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU6+uBk2hWEZHkX6FVGrHFgn6fbD4rX+07PwuZAf1w/iTquG0NtMKHxximYTwSKmiE5T/rXvfl376qRs23hobVrJcN07b0IF8VuGA==
X-Received: by 2002:a81:710a:0:b0:60f:d6fc:74f3 with SMTP id
 m10-20020a81710a000000b0060fd6fc74f3mr228823ywc.7.1711126377529; Fri, 22 Mar
 2024 09:52:57 -0700 (PDT)
MIME-Version: 1.0
References: <20240319215915.832127-1-samuel.holland@sifive.com>
 <20240319215915.832127-6-samuel.holland@sifive.com> <CAKC1njSg9-hJo6hibcM9a-=FUmMWyR39QUYqQ1uwiWhpBZQb9A@mail.gmail.com>
 <40ab1ce5-8700-4a63-b182-1e864f6c9225@sifive.com> <CAKC1njQYZHbQJ71mapeG1DEw=A+aGx77xsuQGecsNFpoJ=tzGQ@mail.gmail.com>
 <20240322-3c32873c4021477383a15f7d@orel>
In-Reply-To: <20240322-3c32873c4021477383a15f7d@orel>
From: Deepak Gupta <debug@rivosinc.com>
Date: Fri, 22 Mar 2024 09:52:48 -0700
Message-ID: <CAKC1njTGSMPekhvyRW0gz6+mY2S_==voCcspoLAyp38X-BcWcw@mail.gmail.com>
Subject: Re: [RISC-V] [tech-j-ext] [RFC PATCH 5/9] riscv: Split per-CPU and
 per-thread envcfg bits
To: Andrew Jones <ajones@ventanamicro.com>
Cc: Samuel Holland <samuel.holland@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	linux-riscv@lists.infradead.org, devicetree@vger.kernel.org, 
	Catalin Marinas <catalin.marinas@arm.com>, linux-kernel@vger.kernel.org, 
	tech-j-ext@lists.risc-v.org, Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, 
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>, Rob Herring <robh+dt@kernel.org>, 
	Guo Ren <guoren@kernel.org>, Heiko Stuebner <heiko@sntech.de>, 
	Paul Walmsley <paul.walmsley@sifive.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: debug@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=UofxCdhB;       spf=pass (google.com: domain of debug@rivosinc.com
 designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=debug@rivosinc.com
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

On Fri, Mar 22, 2024 at 1:09=E2=80=AFAM Andrew Jones <ajones@ventanamicro.c=
om> wrote:
>
> On Tue, Mar 19, 2024 at 09:39:52PM -0700, Deepak Gupta wrote:
> ...
> > I am not sure of the practicality of this heterogeneity for Zicboz and
> > for that matter any of the upcoming
> > features that'll be enabled via senvcfg (control flow integrity,
> > pointer masking, etc).
> >
> > As an example if cache zeroing instructions are used by app binary, I
> > expect it to be used in following
> > manner
> >
> >  - Explicitly inserting cbo.zero by application developer
> >  - Some compiler flag which ensures that structures larger than cache
> > line gets zeroed by cbo.zero
> >
> > In either of the cases, the developer is not expecting to target it to
> > a specific hart on SoC and instead expect it to work.
> > There might be libraries (installed via sudo apt get) with cache zero
> > support in them which may run in different address spaces.
> > Should the library be aware of the CPU on which it's running. Now
> > whoever is running these binaries should be aware which CPUs
> > they get assigned to in order to avoid faults?
> >
> > That seems excessive, doesn't it?
> >
>
> It might be safe to assume extensions like Zicboz will be on all harts if
> any, but I wouldn't expect all extensions in the future to be present on
> all available harts. For example, some Arm big.LITTLE boards only have
> virt extensions on big CPUs. When a VMM wants to launch a guest it must
> be aware of which CPUs it will use for the VCPU threads. For riscv, we
> have the which-cpus variant of the hwprobe syscall to try and make this
> type of thing easier to manage, but I agree it will still be a pain for
> software since it will need to make that query and then set its affinity,
> which is something it hasn't needed to do before.
>

Sure, the future may be a world where heterogeneous ISA is a thing. But
that's not the present. Let's not try to build for something which
doesn't exist.
It has been (heterogeneous ISA) tried earlier many times and mostly have
fallen flat (remember on Intel alder lake, Intel had to ship a ucode patch =
to
disable AVX512 exactly for same reason)
https://www.anandtech.com/show/17047/the-intel-12th-gen-core-i912900k-revie=
w-hybrid-performance-brings-hybrid-complexity/2

As and when ISA features get enabled, they get compiled into libraries/bina=
ries
and end user many times use things like `taskset` to set affinity
without even realizing
there is some weirdness going on under the hood. For majority of use
cases -- heterogeneous
ISA doesn't make sense. Sure if someone is willing to build a custom
SoC with heterogeneous
ISA for their strict usecase, they control their software and hardware
and thus they can do that.
But littering linux kernel to support wierd usecases and putting a
burden of that on majority of
usecases and software is not wise.

If something like this has to be done, I expect first that it doesn't
force end users to learn
about ISA differences between harts on their system and then figure
out which installed
packages have which ISA features compiled in. This is like walking on
eggshells from the end
user perspective. Sure, end user can be extremely intelligent / smart
and figure it all out but
that population is rare and that rare population can develop their
custom kernel and libc
patches to do something like this.

This is a good science project to support heterogeneous ISA but
practically not viable unless
there is a high level end user use case.

> Thanks,
> drew

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAKC1njTGSMPekhvyRW0gz6%2BmY2S_%3D%3DvoCcspoLAyp38X-BcWcw%40mail.=
gmail.com.
