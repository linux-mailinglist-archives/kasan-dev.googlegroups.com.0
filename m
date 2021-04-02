Return-Path: <kasan-dev+bncBDFJHU6GRMBBBK5UTKBQMGQERTF4X6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id A09D4352603
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Apr 2021 06:14:35 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id q17sf2948305lfd.19
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Apr 2021 21:14:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617336875; cv=pass;
        d=google.com; s=arc-20160816;
        b=WpmAntykosAvWbmFVoOF++kXdFUvMX6JtRK2MdFzcNq3eebeI729G7Rhok4GxGY2Fn
         56EK63LtbrkIv2qPyKBXFY4h5fR4hInUDzwiS3z151pMtvi5nokttcQyoTiFjoOLeFKN
         egrp1XmuahbS4BqnhrKexCMybeLjhoX+GlpeV70KVzNyUGznvIFlvseYLyc6wydr211o
         galih8eeu7UXXnaZcMfEorj5M0Cq9EKC9nLB+KuHXcq+NA79iO4odgW2u2O1cZacyo3U
         pBoNW8ckancIbVP6ViaV8Kd3YqV1AqSLeuKZs+WtwO1iU/Z/4G2MLa8C/wQY2AIVxfn/
         yP9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=jBNRCEpIRCWROaMi1FIkSNPpWqXFe1AhIaaM4Shfaog=;
        b=rDwGYBK7rO9ZmpqAieYq3yHinzaflWjD1mL0ZkA8L8dgXwqCIlt6SCWLhX9ERaycXJ
         EwMv6ZaK8EWjycU4azAH4lK7Fc4RhgHzEr5x81orOZo8GrDvlEEK8Lr1oU/RI7zyNrrq
         /T8jMbtPiGbINeqU+C6d4vxy2LETXqKNEOeLTJz4ZjitJ+Ss8jmJ8ZgLE6eJ7jkDDAUi
         VDfjEvkLFhBD7+xkN3O3PhEEq6wV02TmPNUjvRols35rknNz6n9Ox1SiN0FvoU5XIy+Y
         hFXE/YX9TsVORykbaLJWNrZDbpDXLndd7a0+DFw+DWPHTyEDhZI4vR2iYODATaj8V8Fx
         EfmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623 header.b=IOwAv1pJ;
       spf=neutral (google.com: 2a00:1450:4864:20::431 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jBNRCEpIRCWROaMi1FIkSNPpWqXFe1AhIaaM4Shfaog=;
        b=CDTpkYdysxFN/SP861+2XyawZKlkXxf2aef2E3xGt2rlAQs6/zGpj8llH1+qy1YvOH
         s5iv0YoNCQkovndU0cYoZvBQwUdGPn26t3+MNEi8MK5C/hnJkLOa31I4H5ewjx5qNL8b
         pbwVjWlFkeCi7WJCm1kzFYOEyn+AkIzbkZkd2FII/NMTSouPSh7Dwp2/7Gz02/8bn0fR
         ru1HBqasb7VhfAZec2kAoe8pl66YV8S5GuEM5ISWv4DBQuHiRqT5Kn3qqWkR2W4sZeZs
         g+63Qjz2xdt13kdyLWkeBp+NeqKvd+iG0/5/lv+5JUtRF3Vv7mKhLEVEM2Lx9DG4dB4V
         kHNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jBNRCEpIRCWROaMi1FIkSNPpWqXFe1AhIaaM4Shfaog=;
        b=YRVX9Hr83bE9o2Wmp0vq2f7lfbAxu8/fSZmd4NYC1Txg9akw5fw7Ax6VO6D+Cz5zDD
         tvi0wrK+yKx6Q2GJOLKrRh0ytG0uhu2MkZu+VMBlpA3bTrSqztz6cynDoJtUOgPJG3G8
         dbUj+rLUdBzTsRGZP6NWbcblF+BgxOpQm7dErEHyVOSrhlKVGcd7VwG5Aee0h3N9e7Bb
         yw7lulL3O1Az7/p+4Oq5/sdGFG7HVa2hBPtBrW9AzK+z7EjX7qORoAlsxLKlMPJRp+zD
         fD2I/acDUYU8kFQRcH7LdewgfzqpgPwL7n/yR26sneYpqxOo/9jwYoGXH4YQrCxMcFr/
         wX8g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533tjV8tLRZSs4OWMrd4eKf7p4Y6eTduR3P8v1Hw6weC+G54hqw+
	3jHqND3I1aPkuhl6/LJ/myo=
X-Google-Smtp-Source: ABdhPJxdE2tlYm2JaCOSKXOwn5dmVaMwsq7d2b0tW4MicNAdru1hVbypnvuVXxvSdKBU/fRGdw6n+A==
X-Received: by 2002:a2e:b555:: with SMTP id a21mr7210652ljn.69.1617336875262;
        Thu, 01 Apr 2021 21:14:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b603:: with SMTP id r3ls1761779ljn.5.gmail; Thu, 01 Apr
 2021 21:14:34 -0700 (PDT)
X-Received: by 2002:a2e:8084:: with SMTP id i4mr7424253ljg.122.1617336874266;
        Thu, 01 Apr 2021 21:14:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617336874; cv=none;
        d=google.com; s=arc-20160816;
        b=Nu5sl+ZNsykUluImUQ7+yR4amX4X5EYbdycCgtm2+ATE7cOxfM8PBgaJA8gr2qGHWi
         cWS5W9TFtvd9G5AZZj4ARGAIJQHckq8N0XR3g3k1hrkKSg75U4A9VoGvCrqLA6X2lwxi
         oUJ+cG2aikCAbJhDs+xImEsNDatkRCDSUb2jCzgeotARAlRx0GT39lZzZUUzibeizRVf
         ke96umI9JzyVusgarRBW2ygfWfbdYC5ewtjkuBAbpYRqgtyt9dOCuF5yhrWXlUj97nlT
         jXLKu+uheO1EIFYT8gXGUogY9FI6G+Fb/AlUDADwmCWHcwWn2N2RxZJr9M0warDlgaap
         /GkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aTF4DSgy0PHbD8hdS+0qJlLOgVDSXpSKNN+yUg9A0Hs=;
        b=zfJtihRM9Qm863cJWf5vHtAz45tV6R0S1xJkTHAdCppiumR8AA9qqZjDl6jCcQ6Rjr
         XftCI2oOfNFGnl1R7Sv2SWRIm8UT5drBTgXtMgpjfg95FIDmUTtNzCt025MyFHX9DBzW
         b9KJfqzGPNf3Qx4WpPvkvneNjSAx5ClY/mFkhlFYx8hTUQUX3p8QC9XT4H3fSYgKFiTf
         3hwUfyj8fFlj3vOA6U0d0liKgnCdgIvxTm/1/Dt82tnzuIcN2jXxOZ3iO6i1rbRvdyOA
         Ol9KVTV4nQwikDgCB6dO7SSzF+mfU6ke9XZx6XWdVGQo7gzkAACf2ZNnJxs4DR/n0CTF
         Ickw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623 header.b=IOwAv1pJ;
       spf=neutral (google.com: 2a00:1450:4864:20::431 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id h2si687112lja.3.2021.04.01.21.14.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Apr 2021 21:14:34 -0700 (PDT)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::431 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id b9so3669305wrt.8
        for <kasan-dev@googlegroups.com>; Thu, 01 Apr 2021 21:14:34 -0700 (PDT)
X-Received: by 2002:a05:6000:c7:: with SMTP id q7mr13176764wrx.356.1617336873672;
 Thu, 01 Apr 2021 21:14:33 -0700 (PDT)
MIME-Version: 1.0
References: <20210401002442.2fe56b88@xhacker> <20210401002949.2d501560@xhacker>
In-Reply-To: <20210401002949.2d501560@xhacker>
From: Anup Patel <anup@brainfault.org>
Date: Fri, 2 Apr 2021 09:44:22 +0530
Message-ID: <CAAhSdy0p4g1o2xLbHXzMer7P=DgLjYfbiO4nYTU1gqPbLgLUKg@mail.gmail.com>
Subject: Re: [PATCH v2 9/9] riscv: Set ARCH_HAS_STRICT_MODULE_RWX if MMU
To: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, =?UTF-8?B?QmrDtnJuIFTDtnBlbA==?= <bjorn@kernel.org>, 
	Alexei Starovoitov <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>, 
	Andrii Nakryiko <andrii@kernel.org>, Song Liu <songliubraving@fb.com>, Yonghong Song <yhs@fb.com>, 
	John Fastabend <john.fastabend@gmail.com>, KP Singh <kpsingh@kernel.org>, 
	Luke Nelson <luke.r.nels@gmail.com>, Xi Wang <xi.wang@gmail.com>, 
	linux-riscv <linux-riscv@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com, 
	netdev@vger.kernel.org, bpf@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anup@brainfault.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623
 header.b=IOwAv1pJ;       spf=neutral (google.com: 2a00:1450:4864:20::431 is
 neither permitted nor denied by best guess record for domain of
 anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
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

On Wed, Mar 31, 2021 at 10:05 PM Jisheng Zhang
<jszhang3@mail.ustc.edu.cn> wrote:
>
> From: Jisheng Zhang <jszhang@kernel.org>
>
> Now we can set ARCH_HAS_STRICT_MODULE_RWX for MMU riscv platforms, this
> is good from security perspective.
>
> Signed-off-by: Jisheng Zhang <jszhang@kernel.org>

Looks good to me.

Reviewed-by: Anup Patel <anup@brainfault.org>

Regards,
Anup

> ---
>  arch/riscv/Kconfig | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
> index 87d7b52f278f..9716be3674a2 100644
> --- a/arch/riscv/Kconfig
> +++ b/arch/riscv/Kconfig
> @@ -28,6 +28,7 @@ config RISCV
>         select ARCH_HAS_SET_DIRECT_MAP
>         select ARCH_HAS_SET_MEMORY
>         select ARCH_HAS_STRICT_KERNEL_RWX if MMU
> +       select ARCH_HAS_STRICT_MODULE_RWX if MMU
>         select ARCH_OPTIONAL_KERNEL_RWX if ARCH_HAS_STRICT_KERNEL_RWX
>         select ARCH_OPTIONAL_KERNEL_RWX_DEFAULT
>         select ARCH_WANT_DEFAULT_TOPDOWN_MMAP_LAYOUT if MMU
> --
> 2.31.0
>
>
>
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAhSdy0p4g1o2xLbHXzMer7P%3DDgLjYfbiO4nYTU1gqPbLgLUKg%40mail.gmail.com.
