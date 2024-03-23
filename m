Return-Path: <kasan-dev+bncBC76RJVVRQPRBFP37SXQMGQEOWHETYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 828BC887A49
	for <lists+kasan-dev@lfdr.de>; Sat, 23 Mar 2024 21:37:43 +0100 (CET)
Received: by mail-io1-xd3e.google.com with SMTP id ca18e2360f4ac-7cc044e7456sf307753939f.1
        for <lists+kasan-dev@lfdr.de>; Sat, 23 Mar 2024 13:37:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711226262; cv=pass;
        d=google.com; s=arc-20160816;
        b=V9Uawmjrd9rkVO67YfV48+R2gw9r30UEE6uyJZ2XBMsw1W9YxoU+Oz3NRSpeOeRuTH
         R6aH1klhkUTa0NdIGXHmvz3vNApcEGgED0hJVk7I/KeB34h71MYRzsVHyrjA4pGy1RW5
         +r6z+VaybLlgOcnhbxDcSPJmHHh+AxDetXSPh4oXZ1/ZeNq3ej2oZ5Zcr9VyVy+1Xzdi
         0D9krvHaiFHRu5iqtY7oEZ8KwwW1bdT6pTQ7tA469QxYDMJoUEPL0JiCUCPncpGS13nh
         uQydKnto+LfaepHDffhGlHY89PB+3NnDae6n3Ng0t5JG3bqHWqvhVdkOwym5GhLQYV5/
         2l1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=eExk2rIJ/CWVyqfKoeFhvOUt3SlkF6STSCqoj5gUvFQ=;
        fh=XhckbTfl8n7ZkGcqXKQbEV4fKgwBH5S4PlX/q3xF4bM=;
        b=J3+9GST4L2yS+NyIrwzvVgKr+kALmAs3yzgWobW40spQQSkSWWk561v1R1sia3ETst
         uaALdGC/ljAPnWaYK8SQjxh+WaQZIxRWM69HNnif+c5ROoNTwhmzj8GZvCTl3JBQFIAE
         S6duJxqb5jOHZmfn1V/VXtMLUpsFu4zbtKbySXiNSfXvlUn65etnveoRpD6gDHiqYKTY
         iaYkTnfN02iDA9fqp3jv0JhmuTNBhnux0AqcEB5whkO9PXidNRpKR3xl6n6Eswt/ZC8l
         t4c1cK2ZIgKndHsfAL12LKmZy7XTUye1hizjbdgWQea3kpp/Sk/jOfbzrc7q72YAFPph
         OsDw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=PcutTWlq;
       spf=pass (google.com: domain of debug@rivosinc.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=debug@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711226262; x=1711831062; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=eExk2rIJ/CWVyqfKoeFhvOUt3SlkF6STSCqoj5gUvFQ=;
        b=HTZgcSuqoc9N84Vq8ZULPJCuoLIo0x+LSt1TBZEfxb6KM4N/eFNgaKGXYJjdWB6nT3
         0HkByxv9Vff0MOJgVCyCmYP8EgjT7IPiYHdNWWy2DrD/fjh9YXqizpPPNhtVnJky0KYK
         FxaE7AG1HwK+HI/9v1jWeZ45x01tOSNkVEwXNfM9Yira2FReCSHuK3CjMInpugjdhjnL
         tRyK6NqKs2OO76qXdoKhErZnat44jZ3Mv+YRNJkpVXndDwoEgPCN8095SeRRfooh0oZx
         DRnXWa/IOTXiGQ9oUMhBeMuRTtz1HcCAFE8EGRpnqKwVt4Fsy19yJNoF6FDC/a0PTGky
         aE3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711226262; x=1711831062;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=eExk2rIJ/CWVyqfKoeFhvOUt3SlkF6STSCqoj5gUvFQ=;
        b=b8Dac9ZcDXxI0o5vDWWDbMf5woKEH1RQgQ32j8nw6CpotVL9dKeytcejjyK+vo8R9p
         qUkmot7wD/hu2XCUKGZTIXAtZ00h4eDADWM9agBRvM1Vevd8GUzjHZ6VYizAz91zVzDn
         VdtW+oAUU721suADtqMouRS6G1DI96trxGFgXbgmUFTo7MTn70+5rmDtwiRszr1xTki1
         slwMyWE6V+dMdHgMUvlcUj41v1kalE6XoTRmmWqRbs6jubnxDdhF1nPvM/tr3ZDxfgmM
         1uD8hsBcy9cuZe371LdGAvv6UUQOWglVDd7ebnUNJWE12SGt5bemQ3s33ZSz40FVBrnv
         ZBPQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW/wfjfLY1P3zZRy8OW7VNl5x2IgsWVlZNLDfJE3hCPhdJ1HV8HAEQsw6bLbnma5mu7eAZugnurpHsipBUVQKzcvuazH+QAxg==
X-Gm-Message-State: AOJu0Ywd5aMabCrtxI2CO5nGMwIf1ausnzkNGf8g+gcpjg4dyj0R3fE8
	v+yrJ8chDKmPsEbZ+u5uEjainXr+XDJ5LRD8ZB9HAhqyBcE0ShTZ
X-Google-Smtp-Source: AGHT+IG1CS0baJi/yAKwtLH1WEfTavrEWhgKjOh/3ioiB3+GBQNqf/t0Odm/28cui9pu9NQ2vL0KgQ==
X-Received: by 2002:a05:6e02:df4:b0:366:9511:dece with SMTP id m20-20020a056e020df400b003669511decemr3207173ilj.17.1711226261674;
        Sat, 23 Mar 2024 13:37:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2185:b0:368:7fc8:d73f with SMTP id
 j5-20020a056e02218500b003687fc8d73fls361958ila.2.-pod-prod-03-us; Sat, 23 Mar
 2024 13:37:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWEcxvPXnZSlsELQbqqRA7u0VELne+BNSYvNLSMAytJw6q/IQ9/LA2Eagh3cS3ltzrCG80NHhkLYNiOOTpFGmqNadMiEUFEp9t3zQ==
X-Received: by 2002:a05:6e02:109:b0:366:468b:3e26 with SMTP id t9-20020a056e02010900b00366468b3e26mr3323889ilm.28.1711226260690;
        Sat, 23 Mar 2024 13:37:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711226260; cv=none;
        d=google.com; s=arc-20160816;
        b=WEYRp15IARJ/RL0Hb6eHf5GzlAbNT80p4E8Nyo+4tdQOiS7tt82d4ut+HJ1Fl5WepG
         YVvw4ibj0ZE0X91nK3R+2oIy9pYgsQwktlz/XVgmlRWvJ7EN4cFXvuZ1oO8UhF9E/H6b
         zv4AVXIHMQPgBmef/MRZI2dNb3JZU8WYqKt8ZgWTkDgANg/1obG+fZOHo0ycEt27q2Mo
         56PX4XsuNaU/VU1BRumz0qkDxl4Dr13Om2Auu3eSos/4DVWy9FDa1vtcHzeHJG1e/7zD
         injQhgjhbojb0SHT9fZFy8lRmydoKKshytDi/WH+3OmMdJaCm+Msvg6ju4+OSIOpqwqE
         S+EQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=24wJWvfMNNR4rY9ZJ72kq+zMk5fkM7haArePsqOnmfc=;
        fh=awkqtMGLgd2cZIvc+ZZN/b0gH8yjPm4bs3HDYIp+8wE=;
        b=cQF9T1HS22KoOATUlx/3cu8VoBbuN2wJ+W4fYyf58EgKDGrgEpLN7ypiatfFIUtPn9
         48fXUdC34vyFW/pblgUJ6U4B0umHcgMwhUjqw4ItQUAyRFT0nglL1wlzYUF9xSESx0sW
         Bm4g/2HuVV8CGWgwWP2BQhmbilLP/Xh8+hZ5TVivnCNgFWF2CjBoukeDedNScncGMYMz
         tXwx1gr27BZLyCtkykcSiW6yOrPvaTxd4fQcomCC3PP/qzMSHuXcROTNiI5IYO4RebGJ
         t5kCdQCDaqRw591R20Wa4hKc62toZ79FdapQ9uS5QYzaDRlKXjDIPbvASiBxb3oyYB67
         POjA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=PcutTWlq;
       spf=pass (google.com: domain of debug@rivosinc.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=debug@rivosinc.com
Received: from mail-yw1-x1129.google.com (mail-yw1-x1129.google.com. [2607:f8b0:4864:20::1129])
        by gmr-mx.google.com with ESMTPS id x14-20020a92b00e000000b00366b2bf4066si284845ilh.1.2024.03.23.13.37.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 23 Mar 2024 13:37:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of debug@rivosinc.com designates 2607:f8b0:4864:20::1129 as permitted sender) client-ip=2607:f8b0:4864:20::1129;
Received: by mail-yw1-x1129.google.com with SMTP id 00721157ae682-6114c9b4d83so2453737b3.3
        for <kasan-dev@googlegroups.com>; Sat, 23 Mar 2024 13:37:40 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXyDbaCpkLIRMIHbDtvEoO2lK1aoRFehOA7e+reJkgylY5G0dbIfkJ+0IgTdnPzQYpXgEcwTQuuykVvnkgVR32GhQA9yJg+/EJn1w==
X-Received: by 2002:a0d:d981:0:b0:609:6eb0:4714 with SMTP id
 b123-20020a0dd981000000b006096eb04714mr2781546ywe.34.1711226259384; Sat, 23
 Mar 2024 13:37:39 -0700 (PDT)
MIME-Version: 1.0
References: <20240319215915.832127-1-samuel.holland@sifive.com>
 <20240319215915.832127-6-samuel.holland@sifive.com> <CAKC1njSg9-hJo6hibcM9a-=FUmMWyR39QUYqQ1uwiWhpBZQb9A@mail.gmail.com>
 <40ab1ce5-8700-4a63-b182-1e864f6c9225@sifive.com> <CAKC1njQYZHbQJ71mapeG1DEw=A+aGx77xsuQGecsNFpoJ=tzGQ@mail.gmail.com>
 <d9452ab4-a783-4bcf-ac25-40baa4f31fac@sifive.com> <CAKC1njRBbzM+gWowg1LOjq5GzVn4q+vJP9JUswVYfWmEw+yHSg@mail.gmail.com>
 <20240323-28943722feb57a41fb0ff488@orel>
In-Reply-To: <20240323-28943722feb57a41fb0ff488@orel>
From: Deepak Gupta <debug@rivosinc.com>
Date: Sat, 23 Mar 2024 13:37:28 -0700
Message-ID: <CAKC1njRqWYOsF9bQvWX99DhP8Ji_wDUc8J8N41=N6J_tncM3=A@mail.gmail.com>
Subject: Re: [RISC-V] [tech-j-ext] [RFC PATCH 5/9] riscv: Split per-CPU and
 per-thread envcfg bits
To: Andrew Jones <ajones@ventanamicro.com>
Cc: Samuel Holland <samuel.holland@sifive.com>, Conor Dooley <conor@kernel.org>, 
	Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org, 
	devicetree@vger.kernel.org, Catalin Marinas <catalin.marinas@arm.com>, 
	linux-kernel@vger.kernel.org, tech-j-ext@lists.risc-v.org, 
	kasan-dev@googlegroups.com, Evgenii Stepanov <eugenis@google.com>, 
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>, Rob Herring <robh+dt@kernel.org>, 
	Guo Ren <guoren@kernel.org>, Heiko Stuebner <heiko@sntech.de>, 
	Paul Walmsley <paul.walmsley@sifive.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: debug@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=PcutTWlq;       spf=pass (google.com: domain of debug@rivosinc.com
 designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=debug@rivosinc.com
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

On Sat, Mar 23, 2024 at 2:35=E2=80=AFAM Andrew Jones <ajones@ventanamicro.c=
om> wrote:
>
> On Fri, Mar 22, 2024 at 10:13:48AM -0700, Deepak Gupta wrote:

> > > > Yeah I lean towards using alternatives directly.
> > >
> > > One thing to note here: we can't use alternatives directly if the beh=
avior needs
> > > to be different on different harts (i.e. a subset of harts implement =
the envcfg
> > > CSR). I think we need some policy about which ISA extensions are allo=
wed to be
> > > asymmetric across harts, or else we add too much complexity.
> >
> > As I've responded on the same thread . We are adding too much
> > complexity by assuming
> > that heterogeneous ISA exists (which it doesn't today). And even if it
> > exists, it wouldn't work.
> > Nobody wants to spend a lot of time figuring out which harts have
> > which ISA and which
> > packages are compiled with which ISA. Most of the end users do `sudo
> > apt get install blah blah`
> > And then expect it to just work.
>
> That will still work if the applications and libraries installed are
> heterogeneous-platform aware, i.e. they do the figuring out which harts
> have which extensions themselves. Applications/libraries should already
> be probing for ISA extensions before using them. It's not a huge leap to
> also check which harts support those extensions and then ensure affinity
> is set appropriately.

How ?
It's a single image of a library that will be loaded in multiple address sp=
aces.
You expect all code pages to do COW for multiple address spaces or
expect to have
per task variables to choose different code paths in the library based
on address space its
running in ?
On top of that, the library/application developer doesn't know how the
end user is going to use them.
End users (sysadmin, etc)  just might use taskset to put affinity on
tasks without being aware.
I just don't see the motivation in an application developer/library
developer to do something
like this. No application/library developer has time for this. Putting
a lot of burden on application
developers is mostly a nuisance considering they don't have to think
about these nuisance
when they expect the same code to be deployed on non-riscv architectures.

One good example of putting unnecessary burden on app/library
developer is Intel SGX
This is exactly the reason Intel SGX failed. Application developers
don't have time to develop
confidential compute version of the application for a specific CPU
while on other CPUs carry
a different version of application. But at the same time virtual
machine confidential compute is
better approach where all complicated decision making is delegated to
operating system
developer and application/library developers are empowered to only
think about their stuff.

>
> > It doesn't work for other
> > architectures and even when someone
> > tried, they had to disable certain ISA features to make sure that all
> > cores have the same ISA feature
> > (search AVX12 Intel Alder Lake Disable).
>
> The RISC-V software ecosystem is still being developed. We have an
> opportunity to drop assumptions made by other architectures.

It doesn't mean that it should try to make the same mistakes which
others have done.

If there is a motivation and use case from end user perspective, please pro=
vide.
Otherwise no point doing something which is just a science thought
exercise and no concrete use case.

Please note that these arguments are against Heterogeneous ISA on cores.
From power and efficiency perspective cores can still be heterogeneous.

>
>
> As I said in a different reply, it's reasonable for Linux to not add the
> complexity until a use case comes along that Linux would like to support,
> but I think it would be premature for Linux to put a stake in the sand.
>
> So, how about we add code that confirms Zicboz is on all harts. If any
> hart does not have it, then we complain loudly and disable it on all
> the other harts. If it was just a hardware description bug, then it'll
> get fixed. If there's actually a platform which doesn't have Zicboz
> on all harts, then, when the issue is reported, we can decide to not
> support it, support it with defconfig, or support it under a Kconfig
> guard which must be enabled by the user.
>
> Thanks,
> drew

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAKC1njRqWYOsF9bQvWX99DhP8Ji_wDUc8J8N41%3DN6J_tncM3%3DA%40mail.gm=
ail.com.
