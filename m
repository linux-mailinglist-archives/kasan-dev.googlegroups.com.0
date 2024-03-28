Return-Path: <kasan-dev+bncBC76RJVVRQPRBYM5SOYAMGQEE7MOZSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 656DC88F4FF
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Mar 2024 02:58:59 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-42f521e0680sf3978721cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Mar 2024 18:58:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711591138; cv=pass;
        d=google.com; s=arc-20160816;
        b=KkeKsBNEpUiU/nc1EhU8/+JCYP+uDEGq4i+rDq+CdC2NHqXy+RBz4aIdlr1vmpbADB
         3GApV+6YdpMYsezNxse/psqCMZLwQGq06vU4bc4gUMzBdCMT+hp2wReX2hOab2cg4tXV
         SReyDIdDOh+HueIoYk96QwnBK7AOr0klLTFkfQ19C/sQj+3+kTAh/ZhlCWfN1b4QfHqc
         V2lGK/AEts86YRi4P0D5bd66qX1fLWM0mQy+RTBL7mWzxdGokbkjECFPKhgaNra5MWFp
         aI9XzWPv+4OlzX6tImS8G5p84uXnLBbBWzMVv3Hoatb8tyXbdmkviieaX3Ek5HVcIQ80
         zQXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=d0ZOZyfJwc1JPIP6Cejn897TGrUS57tfOhZlMkQoc30=;
        fh=etvif8y/ldKf4qxVbuQV50rY4+vQMfOEO7qr89EyYJs=;
        b=XIQTCJC6EMzlw6DT+J233Wtf3BBeOfXt8GibzEi+FuHseQeQYVOcosNKhnqPCjnS1q
         8obRp2k+G1JDQmmQkx57UKmvsetqLAdEJe6uJHuG0V1AIze49ScD999uUkP2gUTwjoQy
         QslQcvipdO3WyV+XVa6JY7vhNohZ3Ifas4/zVqZs3cq2qZso+WA7ylgYfMFxSzlB5T5j
         qrMsDud92txtY6XyAMrk63TyJybc9YIVqvoiTn6tcDgINfbOpRKXBoOnZpon432JjuWv
         GtFafcmsAJBxcjDi4D4NbVyZmMWCkLHi9/oiuoVjs5rlBc9TBcdM+xuc6cgWvWuaCkvO
         mvAg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b="cBtd/1ZH";
       spf=pass (google.com: domain of debug@rivosinc.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=debug@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711591138; x=1712195938; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=d0ZOZyfJwc1JPIP6Cejn897TGrUS57tfOhZlMkQoc30=;
        b=JDoFdQCHoF5WkDoIPGIeDCEh6Slue1DKf5qmT+l34VdncrC0Bf9QtAueIntZuvNmy1
         JyESjEEwyIwAL2odzaGpvNSaSOht2xL5n106k/bFWXMb8TfknfD39s1XSobfePEYqnZV
         B4nSchVvUimnL8++yihwRIfp547PzBE44V6zAdwmOa1vqMKzeKuaFOU3gkwQAyZUUyPp
         txD7Ps4JKm0iZNakZQRlY+2NvFxsqxqaLgpimz/Cv1X0NdCQ/EwD8DWMMhZE0FFo7ztl
         XoYbhOxbLDs47vDxTSEYpf5BGHV4pP42o/D2f5kbOLiyK3GU7AWlqsaCYlhmt9ai0HGg
         nNWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711591138; x=1712195938;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=d0ZOZyfJwc1JPIP6Cejn897TGrUS57tfOhZlMkQoc30=;
        b=CTsitbXAj7sQViQD7GAydDB3in4uyJM+Tbq8cskbPgRtF35yWggLQI4cy9DzUbPKes
         hPGDjge5v7jDiCjk6z6JgR+FwN8b61eWideiPLgV9UJ5CNQiX3M77aKPvYsfbT3VAac4
         Dg7suq8NgM8jQXdaYZzubQQbZZ3VYq60nEPPcBZ5pQ1zE9Whsi/9N7ZEQQJLCz7/5lzk
         1XeQYRHeZ72I9FF1fmZjfSwIV2xJH/AbB0egV3B/9WeY3bR1vDaxF89nBj7SaJe9FRMN
         I0QyW7NvADXBw2k4CJxMEL6iERRVinJa7y3b9nPEcSLrqRDO2ryAYbJkHJNIosPvS8yF
         fsFg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV/R9sxex7Fsi+AepKezZJldIHc1pHawvjcTKsBQDTq9EdDmGytxlrUs7Cli4GIJfOTkhaLMc2goAmN3/iLIYtrwQwi57lsYA==
X-Gm-Message-State: AOJu0Yw0RFuG0ouffMvc1+dk1LyHTYSSjeLZeFseVaLggTt0Fo5VxFL2
	Tvm0frHQ4M3DAAiuLx/miVJoTYlH8a/EI3kKWFR1iSsE9MCwRuhS
X-Google-Smtp-Source: AGHT+IFVfJf8JL/liPGZUKnbJZX41RQgau5jf2AXs4wWg8agFP0X0UORVgdiWSdM8+N9cnFDd9dMcg==
X-Received: by 2002:a05:622a:4e98:b0:432:7ae9:73e2 with SMTP id dj24-20020a05622a4e9800b004327ae973e2mr1212806qtb.23.1711591138027;
        Wed, 27 Mar 2024 18:58:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:34a:b0:431:74f9:979c with SMTP id
 r10-20020a05622a034a00b0043174f9979cls627262qtw.2.-pod-prod-07-us; Wed, 27
 Mar 2024 18:58:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU8XUOqS9e1+aP9vesh2Af+qAnmq9UZojSf9tsAsGyK8tl4DVJdz7L7+OClF1Xt7ACdlEJ2P/B9JB+LQCDDILIfZZVWscstuae2UA==
X-Received: by 2002:a05:620a:1709:b0:78a:3e97:4114 with SMTP id az9-20020a05620a170900b0078a3e974114mr1750232qkb.5.1711591136317;
        Wed, 27 Mar 2024 18:58:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711591136; cv=none;
        d=google.com; s=arc-20160816;
        b=a31WzqxTyisJti5kcpCY0aLyzZw0s9zEteQh8mmTpRWCgtPXppIBCeFFZP65dVlKm9
         vVvM2lgwPVo9ek+WWpZl32wwA9LMLI6Mx69x5RJR6nISlYLrVgL0Ngf5m4+vjrbQ8HGM
         ubIQDPPGiv+5MXyza57I98HKFFgJhZe7X8b6Ay5KuzcNnAjrGPJJCtACKWT8LBbDevpx
         FANUUsmb0UlFzUX8LHEKHY7eu3NkT9vs5nyy3cPKAMhOrifRGCRV3A0/elSOpTVghXT+
         tFn41I7jJ2VlRDg0EPC8U/0gQIpqU85lLyTozxeK3JAoPSFemYrtPyVpp+oXLTqo8DAC
         N0Zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ixVd6sHhRte5be07PDHwpHq0YTAzRJfXqkR9VbnbXt0=;
        fh=a8vGBhGArCmA9ZnE2ht7OEebg+8KEmOdO53YU+XDaN4=;
        b=KHc3eMTiQFSf5If2md1OfsCfJXM7mwhhPXncjDCqYcSAlHQouGaFq54mP1bQSDGvF5
         +sT6XC4sWxZmKm6DJwd2d1q2AjaikoOQ3wOaRrPp9X5NyOZtyahcMT3BhHEiBX5VgOZu
         U0Ym9ioiBQMKsfwmyn4Hw8yp906ffS1pTLdyXhlJunzq0oOlgy1eZG2Gih26l2HMBRtj
         pTrB8O0xY+R9sYS/k+TX8DURPptNX9JV9gpEWInBA3nBvQtiG/Rc45Fhq8fZY/Qjo0Y4
         6mWP0/ljux8XyJSu8jndLeESU0siLItvGD0Wb7O9VIUWefqXQmyaNCrlV0Lxs0huet1Q
         JDDQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b="cBtd/1ZH";
       spf=pass (google.com: domain of debug@rivosinc.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=debug@rivosinc.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id s17-20020a05620a081100b0078a678f2394si27415qks.5.2024.03.27.18.58.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Mar 2024 18:58:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of debug@rivosinc.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id 3f1490d57ef6-dcc4de7d901so433478276.0
        for <kasan-dev@googlegroups.com>; Wed, 27 Mar 2024 18:58:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXWqBwJEe+dGOPoVM/PerD7lDPu13wXLiLAQSqvFv3O60NnBGASRAtoDhfIPFEzsSEdB9Exnm1s9j0Qw0TBDIeJ8Q96m8tc+2JQWQ==
X-Received: by 2002:a25:860b:0:b0:dc6:9c51:760f with SMTP id
 y11-20020a25860b000000b00dc69c51760fmr1468859ybk.56.1711591135824; Wed, 27
 Mar 2024 18:58:55 -0700 (PDT)
MIME-Version: 1.0
References: <20240319215915.832127-1-samuel.holland@sifive.com>
 <20240319215915.832127-6-samuel.holland@sifive.com> <CAKC1njSg9-hJo6hibcM9a-=FUmMWyR39QUYqQ1uwiWhpBZQb9A@mail.gmail.com>
 <40ab1ce5-8700-4a63-b182-1e864f6c9225@sifive.com>
In-Reply-To: <40ab1ce5-8700-4a63-b182-1e864f6c9225@sifive.com>
From: Deepak Gupta <debug@rivosinc.com>
Date: Wed, 27 Mar 2024 18:58:45 -0700
Message-ID: <CAKC1njTOgsOCpLMCch_YBE+qDoewADhzWwjjfX9nhWCS9hs0mQ@mail.gmail.com>
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
 header.b="cBtd/1ZH";       spf=pass (google.com: domain of debug@rivosinc.com
 designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=debug@rivosinc.com
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

On Tue, Mar 19, 2024 at 7:21=E2=80=AFPM Samuel Holland
<samuel.holland@sifive.com> wrote:
>
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

A quick observation:
So I tried this on my setup. When I put `senvcfg` writes in
`__switch_to ` path, qemu suddenly
just tanks and takes a lot of time to boot up as opposed to when
`senvcfg` was in trap return path.
In my case entire userspace (all processes) have cfi enabled for them
via `senvcfg` and it gets
context switched. Not sure it's specific to my setup. I don't think it
should be an issue on actual
hardware.

Still debugging why it slows down my qemu drastically when same writes
to same CSR
are moved from `ret_from_exception` to `switch_to`

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAKC1njTOgsOCpLMCch_YBE%2BqDoewADhzWwjjfX9nhWCS9hs0mQ%40mail.gmai=
l.com.
