Return-Path: <kasan-dev+bncBDE6RCFOWIARBGPL473QKGQE4KA572Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F7EB20CF04
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jun 2020 16:07:22 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id j16sf11261835wrw.3
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jun 2020 07:07:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593439641; cv=pass;
        d=google.com; s=arc-20160816;
        b=tFfznyL4A0fikYrQPi+MpeyTzlOaS2PpJAQT7+tzBzYPT8Ya8TmS0q0YT99TGu87C0
         lYrZq2N0sgjtrGMj9lC5F/P/7revwaVKyueaMQLPF4vdOPW7q3qTqxo4UIOkhNecMBy5
         HR4NkaPMmRfP+IcbMz+uCBF2Ru5EthTWKmhIfrzIx/PdtcxqKwjqQlvpxcNGlWh3mxIN
         wpiVizFc5IdCAuHWuAdfMjHz4SJSr/G7XglBf5JtqwSLLaq5fdMtlp0HkVGOMmsivboR
         fz7GC1RPLTXi3GsTgawRFMSw8mtVcbn03F9n4CjYE6qy7+8tZTONSMs3w8gAUCgx3gf9
         /Kig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=Wz46zv7TFMDk6efFmBLOjgDFqGNoklg1cZe5RhJR93s=;
        b=k/l0fcA3+lzAQ9dh5sEmTHqjaJXw7JgrcBQMqIj1qN+mztCM79ZY5iEobn5FrjF02W
         /sIylnhFuWEzs6Qot3EmvNTGqiy2skKR+uzWj4ciyq+Uhguil8PrgLZ1sM8T0eoC3Ji2
         v/T4ZFgvTsNqiEG8YoHCu21umM+4Orj23lfN5Y+S9X9FjkxtIl2WOo6oUkzo2lVSNLa0
         iCytzgUaC14zlxuuak/0zdRSzBShTjNHP1l9BVlIfApYayBNbZ0ccMonQdxFEfXEb2z6
         +FQi6LzDlmaYAyt/XWQPyZ6Ud7Z+S1FG3NqSWHCzge7oP5UPhh3TKiKIYkFhPLJKn4gn
         4oYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=YsMQszVm;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Wz46zv7TFMDk6efFmBLOjgDFqGNoklg1cZe5RhJR93s=;
        b=HfMc/1AiMmftt9l8BXMWE1uLuIClGczZsVKOp35mYemZVMF5xdJvfC3uaSvMu6v9wy
         +o7nox9LqXkt04wbTunNFHoPWxXUFAi+PwkrY/i93OKwjS1Ude5H91aKTmMO+YIvX0ms
         neefqKgwUR/KdwmLCIMeYgIe+GdlLKitxM/Wpyo+dC5blux4zQVLin9GTwwZ7WJH7/tJ
         0L3YeshswM5cctzy89pd9uMaJ1fTp0hoXUZddTW6cmeHaowJ03TG7L/y4NzuQPTd/n6j
         nw8xUU36tgqiEZHMaVH9aDRV2Lbw1TOXCDYVKrNBajdSECD5+05+8ZC6ihpvptyvllSu
         QpsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Wz46zv7TFMDk6efFmBLOjgDFqGNoklg1cZe5RhJR93s=;
        b=Ar6wH010UaZ+LtvaUZkIA8WsyePQuut+YIWGWXJi2YuIhiwxSuyeKBdpEFFYvj4no6
         GRmvV8N05Cpi0aZsOyITD1uxuiAE6LoQ9B5KKeVEnf6vHMXg29oNBrz4m65pm264+Chz
         HizOU14eIL6ogJAwkBtL8a5hyJJZgUYxqaZ6qbYIR2DHoTepPs+DYJGu3G6QdrDiTQ3E
         q0FOOoiAq0zvPM95CTc6c6DlbBGzrcZ2mkSUa5YbvsiNpocFt5hu2dzqRV00oP0ypqrA
         y5LqQtoQ8SjgjLypwiscVSVfAvbtLjGbgV0F/0eNpMYZ7Lmy4hzmjrWUidc1HgZolI5p
         y1Qg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531BaCR2JcA/2bwaMFFj70+7419XBg+ca/2z9Oi7ayOYzibEPiHc
	deerIEjrgauO3nVZQkeRSrM=
X-Google-Smtp-Source: ABdhPJyQI9/hNZGMnXAep36ig7cFSVJdjL7NDi/Qw0Jpk96AtHNJrRUO+/FVmQwzqb6k0xXRVDTvEQ==
X-Received: by 2002:adf:ef89:: with SMTP id d9mr18313378wro.124.1593439641761;
        Mon, 29 Jun 2020 07:07:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:cc0a:: with SMTP id h10ls8108046wmb.3.gmail; Mon, 29 Jun
 2020 07:07:21 -0700 (PDT)
X-Received: by 2002:a1c:24c6:: with SMTP id k189mr17717323wmk.9.1593439641294;
        Mon, 29 Jun 2020 07:07:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593439641; cv=none;
        d=google.com; s=arc-20160816;
        b=IGwLsvNPbWA7CUyvPhRWmLQZ+eIcUPa5nibu80zI+N/eg4nZSvtm8J60J8MKht/zKc
         rOu3VuS86WViRTPxOpEExr8gAYC6yroi6Ar3e3UEIm2ltQu0ACK7nPOdLUHm4Q1D9rdX
         legerinvYRhuoqkIr3DhuFYoN9xNiaW7h6fGokvo1s4LM4twST64K1XmXCeeqZ+bR6Oo
         TXaN1IUT1vXFuAM1xMfn/zf08uYSIPn0trntqVdOujgGxDjstNKA0Bv1vIptKcXH5/5H
         rzu2MDmAb7MWpBjknAw7+dGQGLfFq9pXQGLGAOSpHyvt6bGJ06dk2EzI/QX0MgZqYPdm
         s8tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IfVRXuWvv5izTVufgDwQsSRq62OKZ7f3B+ri7x5olzc=;
        b=IN67TdfIUPazDihs6tZPiZZAwf8VC7I70F+R5uNYeRblpK30S0NviPVPit0NaCa0fy
         01PtafNp464Ca+nDYtKx7mE10RRG15+zNfxM55Nal+owbP6M2hoPWCanIiu+zwkTtiSJ
         Va2724LGAMhI0hPu9WeYYdeLr+30GK1CARH2QtLYrSYPUHfq4OTqaFn+HQ7sUfsoGIZv
         IDk2plD+NACDyOc8whensWMkQiQ4xR83St1lFdUHHTvve3Iu1pLlkTpTGb9OZvTgtctk
         qmplNS2TYfWeJWytB4G2BYw7h2nYdzINFhQBRNiUCzSnVh4DciInaWkbte+hhw0Ah4dE
         4htw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=YsMQszVm;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id t16si3817wri.3.2020.06.29.07.07.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Jun 2020 07:07:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id f5so2282798ljj.10
        for <kasan-dev@googlegroups.com>; Mon, 29 Jun 2020 07:07:21 -0700 (PDT)
X-Received: by 2002:a05:651c:1291:: with SMTP id 17mr5726600ljc.286.1593439640668;
 Mon, 29 Jun 2020 07:07:20 -0700 (PDT)
MIME-Version: 1.0
References: <20200615090247.5218-1-linus.walleij@linaro.org> <20200615090247.5218-5-linus.walleij@linaro.org>
In-Reply-To: <20200615090247.5218-5-linus.walleij@linaro.org>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Mon, 29 Jun 2020 16:07:06 +0200
Message-ID: <CACRpkdbuRCXvnaKvAcqQPCWBWmJYQ9orVhWNrOdhUVJUD2Zbbw@mail.gmail.com>
Subject: Re: [PATCH 4/5 v10] ARM: Initialize the mapping of KASan shadow memory
To: Florian Fainelli <f.fainelli@gmail.com>, Abbott Liu <liuwenliang@huawei.com>, 
	Russell King <linux@armlinux.org.uk>, Ard Biesheuvel <ardb@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Mike Rapoport <rppt@linux.ibm.com>, 
	Will Deacon <will@kernel.org>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, Arnd Bergmann <arnd@arndb.de>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=YsMQszVm;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

Asking for help here!

I have a problem with populating PTEs for the LPAE usecase using
Versatile Express Cortex A15 (TC1) in QEMU.

In this loop of the patch:

On Mon, Jun 15, 2020 at 11:05 AM Linus Walleij <linus.walleij@linaro.org> wrote:

> +static void __init kasan_pte_populate(pmd_t *pmdp, unsigned long addr,
> +                                     unsigned long end, int node, bool early)
> +{
> +       unsigned long next;
> +       pte_t *ptep = pte_offset_kernel(pmdp, addr);

(...)

> +       do {
> +               next = pmd_addr_end(addr, end);
> +               kasan_pte_populate(pmdp, addr, next, node, early);
> +       } while (pmdp++, addr = next, addr != end && pmd_none(READ_ONCE(*pmdp)));

I first populate the PMD for 0x6ee00000 .. 0x6f000000
and this works fine, and the PTEs are all initialized.
pte_offset_kernel() returns something reasonable.
(0x815F5000).

Next the kernel processes the PMD for
0x6f000000 .. 0x6f200000 and now I run into trouble,
because pte_offset_kernel() suddenly returns a NULL
pointer 0x00000000.

Naturally dereferencing the pointer when checking
if (pte_none(*ptep)) hangs the machine since this
is in early init.

Does anyone have hints on why this happens, and why it
only happens on LPAE? non-LPAE on the Versatile Express
QEMU A15 works fine.

I'm debugging, but any hints are very welcome.

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdbuRCXvnaKvAcqQPCWBWmJYQ9orVhWNrOdhUVJUD2Zbbw%40mail.gmail.com.
