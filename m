Return-Path: <kasan-dev+bncBAABBDNG5C5AMGQEN27WQPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 681FE9ED9C5
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Dec 2024 23:32:49 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id 41be03b00d2f7-7f712829f05sf15475a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Dec 2024 14:32:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1733956366; cv=pass;
        d=google.com; s=arc-20240605;
        b=PNW983cJ4z2PAKoH/vkMxQP+MPi8J615Spvm8snZMWVdJFm1H1p5FgbDxIqjCYcY3c
         0zJdY49I5/jzx9J1Zg5JjOEgUfYt9cj2NAyeqMWxtO24ZIclfGHXhqAfryvLCh8QmVw4
         48mJp4HPDq9TAu01WX4+2UCYhyifDEwTFsox2RRZgbXhRPnMOthSvH5Np4MU+hQDUeJh
         G5F02BpklsvxUBEfaWSwJ/V5r7SXqR1rWuP8MAT/hEGsuQnOadAHGR9L1zXu0MYRwDuf
         IIIJo9A+aMO/l7JZiggkpe92Rp6CPbWGjdmkjubSnP7cz4bgj9EwTGAoPudz/ry2H8Lw
         KvGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:date:message-id:from:subject:mime-version:dkim-signature;
        bh=ECT+c1LbP3X0XRgLEGA0xN0272klMWEmVXThGinVZOw=;
        fh=SR19ZzbnnkRehZjQDF4uoDPn1ir/vtRclv/b7N7AHaM=;
        b=L4LBCq41CDU+Du8kQ/oIf+yBnIL3bnFyg3XrKI+m2/BAFzHVibBD56MkOsz0tiQx8G
         ZIQzIn2pfWPHv+Q+SdVDu2LX3XXrGa9UqKVlhXSNyaJ4D5ywkphHcACIbHvgL7ETtqO9
         9fBOMAH1XdqKZ3wQUxLnmt+EXIyEAvxySM1SD4CxyvbCIC3o7YZgnxDV2uT544O4O308
         0qckiMuWWJSjkfUlLAet7BFMOL3sURBFsaYOgki5neKyiYW2q01qtcy5wiuIc/8EyaCs
         uktaC40+LXGb/dGlGntnzARaFXwXUshV5q9qYJ668/F/PXN4XoZM98ET358hAa/stZiC
         8Gcw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NUls12FN;
       spf=pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1733956366; x=1734561166; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:date:message-id:from:subject:mime-version
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ECT+c1LbP3X0XRgLEGA0xN0272klMWEmVXThGinVZOw=;
        b=iR2UwU20N7uqjI3UhM6DCQ0oEczFzRaFuJoXASpNrkwYXuIp5JZUY+sBto9Br27uIK
         Zpju9P4EvMM+ifDdLbDhNDdT+f1P6aKl2dVZ/EaFoTq89NRd9oEU86RltTJXAAPRa79i
         yOQD1ZQU9brjMxD812go/1Weq0LjW4TPMAcRByDF6l6dluirXJ9/E+OuflMm1a8iVhi8
         lgPTmIGRS/LVB812fluix3ZfrxCmeE3sJ793ahIxsNfhRqueUJzfuSSMXiLqZLk1TYJj
         swok0C7nQufl9W9VSCqRre/Wm72PtveF8d7hz4rZOWRToniZW2r9JCUgtbxCUePeDbH3
         A1Kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1733956366; x=1734561166;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:date:message-id:from:subject:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ECT+c1LbP3X0XRgLEGA0xN0272klMWEmVXThGinVZOw=;
        b=Ck0TfHcGPgOEBa0wj66sZZ4vNJ0a1+rJ65PT599C+89IDGs/6FRM9KPiKkXtOEdbhF
         9Rt0kXSkUq393urZlMROLOOGctQfCauZDoC13KlGjLdFsFbpCyHk+u8YhN6T/GbRICn4
         8SQql54AgkWOO3HypfbB/kEpnVnpJrEDxlyLtcHtMtQElmptUtNk6LekwENqFs2XCZz7
         iUGDi/KcbEWlCmLq8yz6XSoFib+nObRmgu5rM1UBiDEr7ncRvPu1IibTT4/JIeb6Fig5
         URbKHs97J1s6EW70kR1tfwt9jk6GmFVJ3UD+fYp9T0w5EaqKKxtKi5RTr5/1Nq7bwUOu
         UKJA==
X-Forwarded-Encrypted: i=2; AJvYcCW1RrlLFsBuxXQU0NYD8/aGYN0+HLuCTzt3YgP/KPvkpCOrFhdviO+1t5CRrzZ82xyXLtoa7A==@lfdr.de
X-Gm-Message-State: AOJu0Yz0/UhNdi7y1YzufZrdTZ/SbET7OMbL8vePwaaVt5+qS3h4FRCL
	QV+PTSmCRkwO8zZBMUkAwBEEi5uwlKH/P9LAtKT1j+vV1NjDkQHw
X-Google-Smtp-Source: AGHT+IFcG5+FgUG4CFpPTOKkNL1AJBrZubP6oyMQNVN1fEnfElCssunJIWlXX2U33W2pIVc5J9BFLA==
X-Received: by 2002:a05:6a21:99aa:b0:1e1:aab8:3887 with SMTP id adf61e73a8af0-1e1cec1c1f6mr1409415637.39.1733956365378;
        Wed, 11 Dec 2024 14:32:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:e08:b0:725:db2c:c4a8 with SMTP id
 d2e1a72fcca58-728fa91b5c7ls257059b3a.2.-pod-prod-09-us; Wed, 11 Dec 2024
 14:32:44 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUd9+wPOaBivRt2kBvoumLwEyElRNhLWfEIM92fTNsuD7aaGRxW8882cp1Y7zug/8PdV/dgXk3e13s=@googlegroups.com
X-Received: by 2002:a05:6a20:d50c:b0:1d9:3b81:cdd3 with SMTP id adf61e73a8af0-1e1cea71c61mr1350681637.1.1733956364176;
        Wed, 11 Dec 2024 14:32:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1733956364; cv=none;
        d=google.com; s=arc-20240605;
        b=UipJhy5i8ol2RfK/t84gvfOZcD/N1Lp7f5LNOOmMEMei9lxB+hmnIFT1orIC0AKV+8
         PPbZkUPig+MnSXDm/t0A6rWrrJwVdw/CfaRli5ywUbQEZ9Nvq+mkn/CxphXH9/+QxapO
         on9F+7VdYzoFfX3vak3TlGvFxJepzHX0Rsi8eYGlXqmcwb4OJroKK6zakAiPtvZuNAjM
         1mLONZsPuera/tXTm6HFyr/14hlblmt/hfwGwHKwPfgMODGqDCwH933hTfgF+CMcPEER
         Aoc/Cbtgh+sLW25QhfUjs6YER9Eb5g1Dh4BmWdd2haXMAJ4Hbgr3cvKZbqINpF655lHv
         hVPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:date:message-id:from:subject
         :content-transfer-encoding:mime-version:dkim-signature;
        bh=b0xtmU2Mtgx2NjqxdXyaxmD4I6YrdvDLU6HOsqxl83s=;
        fh=uwj4OSAKx1ixVM9Pa+BrSfPbGlyF4r5QBTVR53I1aBI=;
        b=QOsRKxKHtFgQ6+sYoDKKEViVLguDWyeds1toTRLVJ/F5PbdQ1egg50GxSyDngXkpAa
         SqFLblVMwPub3VcbEWR2iEsfgY0Fd+/Pn1I9sDJHynApGVeVbZlg49m7vzpMtljF6ZCm
         uxenRW6nGV5DgJf3Sl0BrMCMNzSmvP3Jp+sacKbpEcy3WHvsmCXtGVKIAeGfqAShnQIX
         JJVZLvZOGT2lVJ/Pf4FC+ZcYBaFMMWfNpjdnaodIRWRc9G2PFSayHvyZc/dqfBFLLU6D
         M2SdAH6HoNnDp3SWaL4Omf/VAK1SIKT4Xo2e5cEj/4uIeQMQOAYXwH/yT7EJ4gxMDiC4
         TLrw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NUls12FN;
       spf=pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-725a2a8f5d2si621246b3a.2.2024.12.11.14.32.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Dec 2024 14:32:44 -0800 (PST)
Received-SPF: pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 0A1325C67EF;
	Wed, 11 Dec 2024 22:32:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2C1B8C4CED3;
	Wed, 11 Dec 2024 22:32:43 +0000 (UTC)
Received: from [10.30.226.235] (localhost [IPv6:::1])
	by aws-us-west-2-korg-oddjob-rhel9-1.codeaurora.org (Postfix) with ESMTP id 70A87380A965;
	Wed, 11 Dec 2024 22:33:00 +0000 (UTC)
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
Subject: Re: [PATCH -fixes] riscv: Fix IPIs usage in kfence_protect_page()
From: "patchwork-bot+linux-riscv via kasan-dev" <kasan-dev@googlegroups.com>
Message-Id: <173395637899.1729195.4700524807900643783.git-patchwork-notify@kernel.org>
Date: Wed, 11 Dec 2024 22:32:58 +0000
References: <20241209074125.52322-1-alexghiti@rivosinc.com>
In-Reply-To: <20241209074125.52322-1-alexghiti@rivosinc.com>
To: Alexandre Ghiti <alexghiti@rivosinc.com>
Cc: linux-riscv@lists.infradead.org, glider@google.com, elver@google.com,
 dvyukov@google.com, paul.walmsley@sifive.com, palmer@dabbelt.com,
 aou@eecs.berkeley.edu, liushixin2@huawei.com, wangkefeng.wang@huawei.com,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
X-Original-Sender: patchwork-bot+linux-riscv@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NUls12FN;       spf=pass
 (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: patchwork-bot+linux-riscv@kernel.org
Reply-To: patchwork-bot+linux-riscv@kernel.org
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

Hello:

This patch was applied to riscv/linux.git (fixes)
by Palmer Dabbelt <palmer@rivosinc.com>:

On Mon,  9 Dec 2024 08:41:25 +0100 you wrote:
> flush_tlb_kernel_range() may use IPIs to flush the TLBs of all the
> cores, which triggers the following warning when the irqs are disabled:
> 
> [    3.455330] WARNING: CPU: 1 PID: 0 at kernel/smp.c:815 smp_call_function_many_cond+0x452/0x520
> [    3.456647] Modules linked in:
> [    3.457218] CPU: 1 UID: 0 PID: 0 Comm: swapper/1 Not tainted 6.12.0-rc7-00010-g91d3de7240b8 #1
> [    3.457416] Hardware name: QEMU QEMU Virtual Machine, BIOS
> [    3.457633] epc : smp_call_function_many_cond+0x452/0x520
> [    3.457736]  ra : on_each_cpu_cond_mask+0x1e/0x30
> [    3.457786] epc : ffffffff800b669a ra : ffffffff800b67c2 sp : ff2000000000bb50
> [    3.457824]  gp : ffffffff815212b8 tp : ff6000008014f080 t0 : 000000000000003f
> [    3.457859]  t1 : ffffffff815221e0 t2 : 000000000000000f s0 : ff2000000000bc10
> [    3.457920]  s1 : 0000000000000040 a0 : ffffffff815221e0 a1 : 0000000000000001
> [    3.457953]  a2 : 0000000000010000 a3 : 0000000000000003 a4 : 0000000000000000
> [    3.458006]  a5 : 0000000000000000 a6 : ffffffffffffffff a7 : 0000000000000000
> [    3.458042]  s2 : ffffffff815223be s3 : 00fffffffffff000 s4 : ff600001ffe38fc0
> [    3.458076]  s5 : ff600001ff950d00 s6 : 0000000200000120 s7 : 0000000000000001
> [    3.458109]  s8 : 0000000000000001 s9 : ff60000080841ef0 s10: 0000000000000001
> [    3.458141]  s11: ffffffff81524812 t3 : 0000000000000001 t4 : ff60000080092bc0
> [    3.458172]  t5 : 0000000000000000 t6 : ff200000000236d0
> [    3.458203] status: 0000000200000100 badaddr: ffffffff800b669a cause: 0000000000000003
> [    3.458373] [<ffffffff800b669a>] smp_call_function_many_cond+0x452/0x520
> [    3.458593] [<ffffffff800b67c2>] on_each_cpu_cond_mask+0x1e/0x30
> [    3.458625] [<ffffffff8000e4ca>] __flush_tlb_range+0x118/0x1ca
> [    3.458656] [<ffffffff8000e6b2>] flush_tlb_kernel_range+0x1e/0x26
> [    3.458683] [<ffffffff801ea56a>] kfence_protect+0xc0/0xce
> [    3.458717] [<ffffffff801e9456>] kfence_guarded_free+0xc6/0x1c0
> [    3.458742] [<ffffffff801e9d6c>] __kfence_free+0x62/0xc6
> [    3.458764] [<ffffffff801c57d8>] kfree+0x106/0x32c
> [    3.458786] [<ffffffff80588cf2>] detach_buf_split+0x188/0x1a8
> [    3.458816] [<ffffffff8058708c>] virtqueue_get_buf_ctx+0xb6/0x1f6
> [    3.458839] [<ffffffff805871da>] virtqueue_get_buf+0xe/0x16
> [    3.458880] [<ffffffff80613d6a>] virtblk_done+0x5c/0xe2
> [    3.458908] [<ffffffff8058766e>] vring_interrupt+0x6a/0x74
> [    3.458930] [<ffffffff800747d8>] __handle_irq_event_percpu+0x7c/0xe2
> [    3.458956] [<ffffffff800748f0>] handle_irq_event+0x3c/0x86
> [    3.458978] [<ffffffff800786cc>] handle_simple_irq+0x9e/0xbe
> [    3.459004] [<ffffffff80073934>] generic_handle_domain_irq+0x1c/0x2a
> [    3.459027] [<ffffffff804bf87c>] imsic_handle_irq+0xba/0x120
> [    3.459056] [<ffffffff80073934>] generic_handle_domain_irq+0x1c/0x2a
> [    3.459080] [<ffffffff804bdb76>] riscv_intc_aia_irq+0x24/0x34
> [    3.459103] [<ffffffff809d0452>] handle_riscv_irq+0x2e/0x4c
> [    3.459133] [<ffffffff809d923e>] call_on_irq_stack+0x32/0x40
> 
> [...]

Here is the summary with links:
  - [-fixes] riscv: Fix IPIs usage in kfence_protect_page()
    https://git.kernel.org/riscv/c/b3431a8bb336

You are awesome, thank you!
-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/patchwork/pwbot.html


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/173395637899.1729195.4700524807900643783.git-patchwork-notify%40kernel.org.
