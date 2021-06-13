Return-Path: <kasan-dev+bncBD6MT7EH5AARBJODTGDAMGQE5KDD7SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AEED3A5A3A
	for <lists+kasan-dev@lfdr.de>; Sun, 13 Jun 2021 21:51:02 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id u7-20020a0565120407b02902ff43b1e7f4sf4323901lfk.5
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Jun 2021 12:51:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623613861; cv=pass;
        d=google.com; s=arc-20160816;
        b=zYORLEg0cyyp30gVmXRMivLnVN2dVAWVrqjeDBWK+FI6+xoTTggGzFfvuJRN/agZHP
         v5CSkanF9a4icbUyAmlscoJwfpwBJq5lFdCDkhCCfnspt8PUu4EwBOfGEb2y8TD+av4s
         pKYU99zW6Jft9HMYWdx4VgkgZgkE42nzdZT/Uwf/AJikcIi8xsuDOJ4zoHbPxiTToJ3R
         tCGS0xoVPrV019EMbdzDEfdzr9mP8nrFHM8eCjnYz5kaET1vOCKXQntbZkDGFXIi7P7w
         KVscVI1q8QILXUM0z1U9OTASlhxKIQZA1IzJ2fc9lhCfToKYNL/BMj1haXVxsAYHgV+4
         wwSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from:sender
         :dkim-signature;
        bh=DCLnBmI2iCf3EaSJgFIgkXyCFqFmK6D8hMJYrJCF8Q4=;
        b=EZz+bnaxNZztkCn2PHk0cyq5pnTl5zKWgRgPpUdh8Xe5+BhYNbYs1GrtIHbErrg1ks
         9RCUD9GmMsZ1xQPoY0EYaizyKvyHjoeTFD5SYTcLhtjEiUtzA+mamwGU8nr9tHfkQnyO
         GsgVbYAw4ms09cGiWYUUe9baA2wKxo8X99zRG9oUira0j4qqTiBP0FSpOoasafjtQt2K
         nGfIwRO93T4yrSCGvjtQHyARxbDh87mSV/QBIeoTzCPEDWWhsQBxj0K3fY/Fj9FzK8nq
         DZSvTciI2UIZNblrzUKj9XfwBv6GSZBM9lI1/ZtIqgNDshvBlUSFBccGzOY//Yuz7W4M
         WGmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of whitebox@nefkom.net designates 212.18.0.9 as permitted sender) smtp.mailfrom=whitebox@nefkom.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:references:date:in-reply-to:message-id
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DCLnBmI2iCf3EaSJgFIgkXyCFqFmK6D8hMJYrJCF8Q4=;
        b=TjhsGd26Lj2r+XteN/Vd9ag1z6qHfYyM2EPg69JYXpAvBS0gHfEJA/jFNN0UiMfbYZ
         FS68QjDsZQoETJkntsBo4gI3P1A/HxzCH6vCLyeoFOD6POJkzWF+tMJLDsIGeN+h9iVw
         ecP+DNfl6ifd1qyIo0deVuxxaRX3BtW73PkYeq1RKJiRmG/j/JPVlGRFG73pBXth/War
         PdNPlKazKTPDThzM5J4WJFitgJjwHGdqIfkHmWCEwWJLTCb8UV4ER/42cLo/5p+zP+qE
         sD/4BauNUygcN85rNN5+x479kVTxIiF0T8j2EA3VsmTTDn6qLB4ZDUMjn1gNy/ginxT8
         1erw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:references:date
         :in-reply-to:message-id:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DCLnBmI2iCf3EaSJgFIgkXyCFqFmK6D8hMJYrJCF8Q4=;
        b=FQBBsDItlErHkkh4IqAQpMz0UWAlDIwGuffZlnhMQ+OPcJGwWz3PY/h5KszVYMn6FK
         +QQEJIkAbVVJ6qDrdbszm2Ntit8tled2I4esyAm2AIEH31SAJnn9MRlVJiDijGHbFZ7y
         gq66QISoxkaRWVckluasJmQofxuph00/sPr6rHXbwxDxPiJDY0Mf+/hFYHCr57o24v4G
         WhWD/NXRIVsf6XNxtxwgHi98rplXnsQQeobZcTqVBeovZmPCpZpixGaTHPADk+F/XOGC
         ydjvKDJaY3OKEBk9qj2nKCtof40OLFoFlNkl1ni/UQk8PF1+UD0xTr3nnFoZICY2HIQm
         xpDg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530rnahgIwuPxVpmGoB9JxwCgmsfvufwjLDK+OIM8HL2BXYCdqoc
	Q+W50RP8Ps8agVl4LkF1PAU=
X-Google-Smtp-Source: ABdhPJyi6hV8MyKYVuMet2sliGY/qINgYK9w5a0zrVW2oEv1C/EmmrlbSpq+3Rblpu4wsx1gHvueJg==
X-Received: by 2002:a19:ed16:: with SMTP id y22mr10039835lfy.384.1623613861652;
        Sun, 13 Jun 2021 12:51:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b99:: with SMTP id g25ls1424855lfv.2.gmail; Sun,
 13 Jun 2021 12:51:00 -0700 (PDT)
X-Received: by 2002:ac2:4c8f:: with SMTP id d15mr9429411lfl.157.1623613860578;
        Sun, 13 Jun 2021 12:51:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623613860; cv=none;
        d=google.com; s=arc-20160816;
        b=cbZN5NGjngqWYlGTsEaSav7ltV1XbWI60fLBfRHlqEhvHFAMfgGdzzflyhUjya20dc
         Vf/6mH/ywXOHCb1NhNOay25TQUDrOAoD1QOo/bV6YPRMh28TbyX6z8byIrPW3MCeHOdv
         UQb3bYp+UtG6QrG2Tqz05xMSWrh6zoXypcFHLLyuv1u0AekxBor0l01wITPte8h8QaGD
         S3oZtoxd+X9e4Jj2AMd1CQTsYdKdShB6z06bqY2w5xh0w5tV0MsWYPJruXcJMZpkw/m6
         DTCM2ymD5+QMhEBGPW1Bh3rJE1m65bu/3BCUOx8V70eC17O2Sm2TsRsHYiu28ugfQ5VJ
         pi8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:message-id:in-reply-to:date:references
         :subject:cc:to:from;
        bh=U/+kaBvJqt2y4czUHyrEKSj7NVUmriWqKkfTzUlQrEY=;
        b=MBTjvb98C9cjzezZOl57gn63VRp65pQRzCYKeSdGhVEXdSPyZnYFXkHyYFL3F/chOZ
         wi63qyHbGmqtj448ZKfXOHnePYx9ba/Qpwut0ipFecwJlCFrL7obcvMgJHLb1Scj9Ivs
         E7/UVlUKxTsSToYO1y5ekbZMrS7A2q3rT5RhsOhmBi7V7qYaVjxViKa8hzbpsPupin91
         nkt+i5QAFS6F6Mn+VY1BiQTJisfdBKVxoOhyC2FgCHoT+k/7fjaUG1ZX1B0v08PTRolw
         mTYFlIYxVfwjIwYvisCjrzGHoQ6vtLDCjS7Ja4xt6ihnRsdfrACia9EgoKTyw/qne1Yz
         +e3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of whitebox@nefkom.net designates 212.18.0.9 as permitted sender) smtp.mailfrom=whitebox@nefkom.net
Received: from mail-out.m-online.net (mail-out.m-online.net. [212.18.0.9])
        by gmr-mx.google.com with ESMTPS id bn2si385878ljb.7.2021.06.13.12.51.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 13 Jun 2021 12:51:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of whitebox@nefkom.net designates 212.18.0.9 as permitted sender) client-ip=212.18.0.9;
Received: from frontend01.mail.m-online.net (unknown [192.168.8.182])
	by mail-out.m-online.net (Postfix) with ESMTP id 4G34vN64Cwz1qtQV;
	Sun, 13 Jun 2021 21:50:56 +0200 (CEST)
Received: from localhost (dynscan1.mnet-online.de [192.168.6.70])
	by mail.m-online.net (Postfix) with ESMTP id 4G34vN363qz1qsYj;
	Sun, 13 Jun 2021 21:50:56 +0200 (CEST)
X-Virus-Scanned: amavisd-new at mnet-online.de
Received: from mail.mnet-online.de ([192.168.8.182])
	by localhost (dynscan1.mail.m-online.net [192.168.6.70]) (amavisd-new, port 10024)
	with ESMTP id HJAVNxtJklRu; Sun, 13 Jun 2021 21:50:54 +0200 (CEST)
X-Auth-Info: LElrgumow5j7MizGUQKNpWrnXWIF9Qr7mZEEQCIJzLKJl+b0lrS27gPvl8MTWt4G
Received: from igel.home (ppp-46-244-177-185.dynamic.mnet-online.de [46.244.177.185])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.mnet-online.de (Postfix) with ESMTPSA;
	Sun, 13 Jun 2021 21:50:54 +0200 (CEST)
Received: by igel.home (Postfix, from userid 1000)
	id D34602C369D; Sun, 13 Jun 2021 21:50:53 +0200 (CEST)
From: Andreas Schwab <schwab@linux-m68k.org>
To: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>
Cc: Paul Walmsley <paul.walmsley@sifive.com>,  Palmer Dabbelt
 <palmer@dabbelt.com>,  Albert Ou <aou@eecs.berkeley.edu>,  Andrey Ryabinin
 <ryabinin.a.a@gmail.com>,  Alexander Potapenko <glider@google.com>,
  Andrey Konovalov <andreyknvl@gmail.com>,  Dmitry Vyukov
 <dvyukov@google.com>,  =?utf-8?B?QmrDtnJuIFTDtnBlbA==?= <bjorn@kernel.org>,
  Alexei Starovoitov
 <ast@kernel.org>,  Daniel Borkmann <daniel@iogearbox.net>,  Andrii
 Nakryiko <andrii@kernel.org>,  Martin KaFai Lau <kafai@fb.com>,  Song Liu
 <songliubraving@fb.com>,  Yonghong Song <yhs@fb.com>,  John Fastabend
 <john.fastabend@gmail.com>,  KP Singh <kpsingh@kernel.org>,  Luke Nelson
 <luke.r.nels@gmail.com>,  Xi Wang <xi.wang@gmail.com>,
  linux-riscv@lists.infradead.org,  linux-kernel@vger.kernel.org,
  kasan-dev@googlegroups.com,  netdev@vger.kernel.org,  bpf@vger.kernel.org
Subject: Re: [PATCH 7/9] riscv: bpf: Avoid breaking W^X
References: <20210330022144.150edc6e@xhacker>
	<20210330022521.2a904a8c@xhacker> <87o8ccqypw.fsf@igel.home>
	<20210612002334.6af72545@xhacker> <87bl8cqrpv.fsf@igel.home>
	<20210614010546.7a0d5584@xhacker>
X-Yow: ..  Once upon a time, four AMPHIBIOUS HOG CALLERS attacked a family
 of DEFENSELESS, SENSITIVE COIN COLLECTORS and brought DOWN their
 PROPERTY VALUES!!
Date: Sun, 13 Jun 2021 21:50:53 +0200
In-Reply-To: <20210614010546.7a0d5584@xhacker> (Jisheng Zhang's message of
	"Mon, 14 Jun 2021 01:05:46 +0800")
Message-ID: <87im2hsfvm.fsf@igel.home>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/27.2 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: schwab@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of whitebox@nefkom.net designates 212.18.0.9 as permitted
 sender) smtp.mailfrom=whitebox@nefkom.net
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

On Jun 14 2021, Jisheng Zhang wrote:

> I think I found the root cause: commit 2bfc6cd81bd ("move kernel mapping
> outside of linear mapping") moves BPF JIT region after the kernel:
>
> #define BPF_JIT_REGION_START   PFN_ALIGN((unsigned long)&_end)
>
> The &_end is unlikely aligned with PMD SIZE, so the front bpf jit region
> sits with kernel .data section in one PMD. But kenrel is mapped in PMD SIZE,
> so when bpf_jit_binary_lock_ro() is called to make the first bpf jit prog
> ROX, we will make part of kernel .data section RO too, so when we write, for example
> memset the .data section, MMU will trigger store page fault.
>
> To fix the issue, we need to make the bpf jit region PMD size aligned by either
> patch BPF_JIT_REGION_START to align on PMD size rather than PAGE SIZE, or
> something as below patch to move the BPF region before modules region:
>
> diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
> index 9469f464e71a..997b894edbc2 100644
> --- a/arch/riscv/include/asm/pgtable.h
> +++ b/arch/riscv/include/asm/pgtable.h
> @@ -31,8 +31,8 @@
>  #define BPF_JIT_REGION_SIZE	(SZ_128M)
>  #ifdef CONFIG_64BIT
>  /* KASLR should leave at least 128MB for BPF after the kernel */
> -#define BPF_JIT_REGION_START	PFN_ALIGN((unsigned long)&_end)
> -#define BPF_JIT_REGION_END	(BPF_JIT_REGION_START + BPF_JIT_REGION_SIZE)
> +#define BPF_JIT_REGION_START	(BPF_JIT_REGION_END - BPF_JIT_REGION_SIZE)
> +#define BPF_JIT_REGION_END	(MODULES_VADDR)
>  #else
>  #define BPF_JIT_REGION_START	(PAGE_OFFSET - BPF_JIT_REGION_SIZE)
>  #define BPF_JIT_REGION_END	(VMALLOC_END)
> @@ -40,8 +40,8 @@
>  
>  /* Modules always live before the kernel */
>  #ifdef CONFIG_64BIT
> -#define MODULES_VADDR	(PFN_ALIGN((unsigned long)&_end) - SZ_2G)
>  #define MODULES_END	(PFN_ALIGN((unsigned long)&_start))
> +#define MODULES_VADDR	(MODULES_END - SZ_128M)
>  #endif
>  
>  
> can you please try it? Per my test, the issue is fixed.

I can confirm that this fixes the issue.

Andreas.

-- 
Andreas Schwab, schwab@linux-m68k.org
GPG Key fingerprint = 7578 EB47 D4E5 4D69 2510  2552 DF73 E780 A9DA AEC1
"And now for something completely different."

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87im2hsfvm.fsf%40igel.home.
