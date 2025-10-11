Return-Path: <kasan-dev+bncBAABBGFLVDDQMGQEUO2CHBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BE09BCF24B
	for <lists+kasan-dev@lfdr.de>; Sat, 11 Oct 2025 10:30:18 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-30ccebab467sf6230624fac.2
        for <lists+kasan-dev@lfdr.de>; Sat, 11 Oct 2025 01:30:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760171416; cv=pass;
        d=google.com; s=arc-20240605;
        b=FWzrI/HvQRFD1dI1ihTdecycQqzo3ME/VVNIdNTqWTgDE6RTW89bf9bX35uTurbJJ8
         at5WHWa4IsYG+gnQ+9EgtGTLarcoMdTGRL/Aik5QI9nZd6/+lRAhlNheGW6C+pxkKrWA
         /TYreDeCXSiUEHuKnXnDWmQPmg6+CQscrGvBGwcLzebIg44NCupRXlRbtFnlRoqcJbYn
         pNcstfyTw2lAeiDCPb6MtusIbPbmJ1l5a42RPU40gwZ+CFMQt9ykj9mAn8Mg/tptIC+n
         e2nOo1kH4eJch1Vaz/yHtdy5lAPpuju7haSvtXpZ6qi6Xfl+WpnCsFE2BnX2naxspoJT
         PKJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=8MbcO2vQlz6km5iVr5WQJwtR7KXLLB8N73HR4D7iVrs=;
        fh=gF3qnAErokqNRHzwcGe1oB2KVQiQw7+QF72OsoO3K9s=;
        b=bCKVxScAJ053PAMquf6IxajKZ0HSchhBLTWvX9XmWnegwN2psIcClEcvJzWZ6PTaWT
         6KRNV1e54K2QMvLBR7y+lTttXa03Fz4wDFLuARnnGcrpINS+6ttpJnTB7ms0SKLZna9J
         /k9h1U6mLy0xpEZMR9mVa27hWSxCzNFpY4x1nF+Sto4zCZFVDfH00GcztL9/X/ZqBEvj
         awo25npWeZvjYtAEtv2SeKx2jde1aZ2MBw0dAnXGxPhEC0bsIQLrORZvb3BfyPQMHuW2
         xdgY9vs1TxDjxnpM5HUzgZf8iG57A+9nVGir51afwr+BcDls3w0aPLyaJ0HY0vv0aKmE
         zcUw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lliM7r31;
       spf=pass (google.com: domain of nsc@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=nsc@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760171416; x=1760776216; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=8MbcO2vQlz6km5iVr5WQJwtR7KXLLB8N73HR4D7iVrs=;
        b=tPLey21gC6pxDGRLG2qej4DiqL5L0SRW/PXwSN8S0Jit1OJ3xIn5xO5fjJ2O5WGtij
         p42GXqjuiJtlrmKSLcze0G9ec+WhXcbVjFRf/A+yDwK72LYgSWAYyoMBetdtkaof4qIp
         qmSz9MZQjBH2susCCUKsSzj6CQkGvOqFblQXpefKBozpZ+d6g8uSwABmX9wu/MENpIH/
         rfrbfwZtUdztaCxxyrqeMmALPL8hsc8q2mdtvsSZIJQ/d8bwt1eWcajR3QUHGCmq6Zu9
         OoCs7zCHCPBTz5a++OX+1s/oyb7ECoBqLB4rQORzocRh1mBjBeLZLCd8jFRwhYUV5OlM
         DKKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760171416; x=1760776216;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8MbcO2vQlz6km5iVr5WQJwtR7KXLLB8N73HR4D7iVrs=;
        b=dSIWgK63kCenH5s5fKDxffaSfFZQm9erIR3x2yZ+ja/jUGD1HbGswOsRDJANOjeKmt
         nVbjPLplO1jNd0ceZG1ZUiwe0iBP9G0yiNFigblSU8S127jk4wW8jWMgaZEoZXDvg/ey
         McNXRe/cjL4llckjvgFJk5sZI0GIq7XL/Y5ApWOpDTPZ0RK3s6kX4MgO0hSe6K7FyzHh
         Nr3ZzEAQxkL1iVzt7N4rdMOEkLWEzm6aIwY+BRWKGQPgRvGXqwoNXqPfvkN/+MKsaIKI
         TQO1aVC1jbeNXlXsl+sVGo3A2SEFh4qYHcgWlxhdPmHwqONAIKaJbaZ5Nbzvzwn6aAPu
         D3CQ==
X-Forwarded-Encrypted: i=2; AJvYcCWYXDasPEa5us1jB5e03ftY/ubwrMPqaMqj4dW03T9DGr6t9Oen1YP/DKluTk5xKWOqoiXMjA==@lfdr.de
X-Gm-Message-State: AOJu0YxV7VfO3GqK7Dcip5Yksq+7bQxyMOZTIwN6EXQ8TgPQKCN99Ovb
	6N7ejze+BMWGBYHn13E+qSKBwJlZk/natGoJxUCJlVrjZQDDJ93FbJFN
X-Google-Smtp-Source: AGHT+IGo65ZO2lYFEU5be8H4srlbPYBDiHjULPYECFwlezRSk6I4Smwuz/6gCiBK3921IWxeqXbIXw==
X-Received: by 2002:a05:6870:348b:b0:3ae:f15:5de1 with SMTP id 586e51a60fabf-3c0fa754b53mr7093517fac.41.1760171416569;
        Sat, 11 Oct 2025 01:30:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6vAj3uk4rYQWHdhbpuhUxE8P3Y5LJIZI8wt06lzjTRDQ=="
Received: by 2002:a05:6870:638b:b0:31d:71b5:3ff8 with SMTP id
 586e51a60fabf-3c7211c9f3els1670175fac.0.-pod-prod-09-us; Sat, 11 Oct 2025
 01:30:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXv96KALdwHupFR6zKtZcNAYJ/+PyK7YHdFmnOUq1aLvEheoDgNKPbj7DpVpyXAI99cjIVLKWR/F84=@googlegroups.com
X-Received: by 2002:a05:6870:8112:b0:2b8:fab0:33c with SMTP id 586e51a60fabf-3c0f92a84f6mr7070558fac.23.1760171415255;
        Sat, 11 Oct 2025 01:30:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760171415; cv=none;
        d=google.com; s=arc-20240605;
        b=bu6dfW5IZ0t+TATZqOBgkaw1hlCRIKLK7IUXGiZ3LVb9EnxsmnphBvsnJiVBxuZIyL
         mLut3reJdhRU6Y8srgB1m/C0tFDezVoM5t+sx6Ztxdrgm0ilm6YkOW/3DmywkYPDTS6q
         /rPzzisvizr0Ndqi2pahPt8FtwPvA/ZZaBmCRsqLx+hQU+CVv2Th0bq9hReUwb4OUI+l
         fu3Cdm7uO4WgARNoVs7GyDCk0GVm16jwsI3nL+eFTZdSoeSL7K+1TNY4vL4zZwCcKF9n
         p6//YZIYX5nfCtKtlXdAbengb60zOhA3AP+SxWcSguzyY+OKGYOrBqbSy7RjWEZtn49/
         hZXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=K3AqDx6D164IDyWQvKYlwd86aInkzNyOofX9sCIGXUY=;
        fh=0dWTvpt6AhZl8smnAJNSDCY0WxN5vWgbNW+Mx7EUBPM=;
        b=Ae+jWF6NAQR6zqvn5rZ9IATeqhfewoSJKVqOVx0Pg49pMhrFnihDSqQFRSpqYFvxB8
         7R3maXRGHnI7of+mBL9ocWaJ2WZ+ylfALYiuS/YyuvESgOJxe1yWZ132d80OZAk5QW0E
         ooI2lJAo/5rX8dtzZ6sfdw/g6HTAMe+GuowDhHgHwIVK5qH0NHBtcUxPUrD9AS+mD5OO
         X+1iYK0UTB1GEHNwXrKa83delPtFB+hEQS9iF2DAoAbdmQmx6E6/aG1gms4Nd4CXrWJR
         R51JOQrgjrIcvp8Hsehrg0F5lGjYjTPZj8Bc5jIwtDO8d/TRTqpbEvQqsVWBFUpXDZq0
         hi6g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lliM7r31;
       spf=pass (google.com: domain of nsc@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=nsc@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-3c8e7a94889si175713fac.0.2025.10.11.01.30.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 11 Oct 2025 01:30:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of nsc@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 644F543220;
	Sat, 11 Oct 2025 08:30:14 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E7A57C4CEF4;
	Sat, 11 Oct 2025 08:30:13 +0000 (UTC)
Date: Sat, 11 Oct 2025 10:12:54 +0200
From: "'Nicolas Schier' via kasan-dev" <kasan-dev@googlegroups.com>
To: Nathan Chancellor <nathan@kernel.org>
Cc: Alexey Gladkov <legion@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Charles Mirabile <cmirabil@redhat.com>
Subject: Re: [PATCH] kbuild: Use '--strip-unneeded-symbol' for removing
 module device table symbols
Message-ID: <aOoRhgzntzk2YKYP@levanger>
References: <20251010-kbuild-fix-mod-device-syms-reloc-err-v1-1-6dc88143af25@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251010-kbuild-fix-mod-device-syms-reloc-err-v1-1-6dc88143af25@kernel.org>
X-Original-Sender: nsc@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=lliM7r31;       spf=pass
 (google.com: domain of nsc@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=nsc@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Nicolas Schier <nsc@kernel.org>
Reply-To: Nicolas Schier <nsc@kernel.org>
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

On Fri, Oct 10, 2025 at 02:49:27PM -0700, Nathan Chancellor wrote:
> After commit 5ab23c7923a1 ("modpost: Create modalias for builtin
> modules"), relocatable RISC-V kernels with CONFIG_KASAN=y start failing
> when attempting to strip the module device table symbols:
> 
>   riscv64-linux-objcopy: not stripping symbol `__mod_device_table__kmod_irq_starfive_jh8100_intc__of__starfive_intc_irqchip_match_table' because it is named in a relocation
>   make[4]: *** [scripts/Makefile.vmlinux:97: vmlinux] Error 1
> 
> The relocation appears to come from .LASANLOC5 in .data.rel.local:
> 
>   $ llvm-objdump --disassemble-symbols=.LASANLOC5 --disassemble-all -r drivers/irqchip/irq-starfive-jh8100-intc.o
> 
>   drivers/irqchip/irq-starfive-jh8100-intc.o:   file format elf64-littleriscv
> 
>   Disassembly of section .data.rel.local:
> 
>   0000000000000180 <.LASANLOC5>:
>   ...
>        1d0: 0000          unimp
>                   00000000000001d0:  R_RISCV_64   __mod_device_table__kmod_irq_starfive_jh8100_intc__of__starfive_intc_irqchip_match_table
>   ...
> 
> This section appears to come from GCC for including additional
> information about global variables that may be protected by KASAN.
> 
> There appears to be no way to opt out of the generation of these symbols
> through either a flag or attribute. Attempting to remove '.LASANLOC*'
> with '--strip-symbol' results in the same error as above because these
> symbols may refer to (thus have relocation between) each other.
> 
> Avoid this build breakage by switching to '--strip-unneeded-symbol' for
> removing __mod_device_table__ symbols, as it will only remove the symbol
> when there is no relocation pointing to it. While this may result in a
> little more bloat in the symbol table in certain configurations, it is
> not as bad as outright build failures.
> 
> Fixes: 5ab23c7923a1 ("modpost: Create modalias for builtin modules")
> Reported-by: Charles Mirabile <cmirabil@redhat.com>
> Closes: https://lore.kernel.org/20251007011637.2512413-1-cmirabil@redhat.com/
> Suggested-by: Alexey Gladkov <legion@kernel.org>
> Signed-off-by: Nathan Chancellor <nathan@kernel.org>
> ---
> I am Cc'ing KASAN folks in case they have any additional knowledge
> around .LASANLOC symbols or how to remove/avoid them.
> 
> I plan to send this to Linus tomorrow.
> ---
>  scripts/Makefile.vmlinux | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 

Thanks!

Tested-by: Nicolas Schier <nsc@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aOoRhgzntzk2YKYP%40levanger.
