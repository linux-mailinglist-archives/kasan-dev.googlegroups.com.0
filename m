Return-Path: <kasan-dev+bncBCRKNY4WZECBB4GORCCAMGQEPZ7FWSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id AA94A368A88
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Apr 2021 03:48:33 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id y20-20020a6bd8140000b02903e6787c4986sf14434221iob.23
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 18:48:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619142512; cv=pass;
        d=google.com; s=arc-20160816;
        b=NgH5c5DibGwrqZafA76/7F8KtiizyYUlUbz2ie4WGk6f6MKeWX0SSqrnFExbqfyUwh
         8D9VcqSnuRI9TgVgvG6419QAxsUH6eJEdcAYQSWWjit14R3iVoOrOUsHzxCi8oRfmzob
         bSiL8xeooNWRaaUvIMKLLAUvwF0rYhr1ywewU8Lyk4RNXuUYjYXJ85MPCuB4L0+jDbUi
         subwTISCCLcr701027VnFDiOt5hBmmpMbcwBjCaSUQZh9n0mNuonAZZCa78PEBGH3b9l
         sLFqZHmN8vbB6icXkQbGS0XMai0g4sIiqiT3VQPfzAvS4VS6yY94ejLHRXg1LGXRahYb
         DAtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=b23zj7hlZCRMt9xCKwUc+nZHSWnVCpamWmyt5WLGJzw=;
        b=QE5hBnqMBvzv/p2ZdHhAyoJzioV7zapzgtMtkYTv4WvgHQ3Hr6Pk/s5HXOVISkYgfw
         4G48sV1ff2jdpYPmT3QIpAjUbvzXevlGDHmKHGVAna8FcyfT7L9Kt5caok7/NH/oIl1R
         3HlN0udGzbOgKW7j3EldPRO9slMcQlamaWVIOSEzZWTTnx812aU48WlIp8RW1ZYGpPRC
         JDDsaHFwl4tjY8hDtDc3PNSCWQ/p58+0k0xavP8XTvw+4dtj6veVmBb5JQAOb97F31M2
         skDOc543Gz3L96nWxp+fjaV5HeBR1OBZclIWEtByP8mTzIHmf+ebLW9+VcG0dPzRsO9f
         qx1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=16Qh8D3Z;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b23zj7hlZCRMt9xCKwUc+nZHSWnVCpamWmyt5WLGJzw=;
        b=d/UdIhJQE+hdfwAE8UV267IluVn00Sr2B9L4O3dO1A9w5jXLEdYkXLu+MXujPLnAKp
         ZEvdsvhBBQeXo1VIDs6migbG3Zw3qMf9zzsg6Z4fImJnUEeBpjYt3No58FVLlDLwTEYz
         tKyQVS3JGClUe/3t9K7EdD1HIEzIhrtdvhi0JF0vOAgPf0nHPQfZK6rc22kWGLQmSwWB
         X/uvUeeiqU2JcpRQXQM7TFdlj4Hcgb0cXPBXTsB2PzVEPxVJtLN/uzLHiqSvNwFWBvjy
         XNBQSnQ4rdtpEMqzcdyZBYCA/grLj+vedJNMzsFmOpvxurnn6SJJo+O6ahSu1Q2tJOHj
         unhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b23zj7hlZCRMt9xCKwUc+nZHSWnVCpamWmyt5WLGJzw=;
        b=bVN7fhg+slUC7IsJ9lS7vde4ae4ofN0xBb4NkII8yzmXot9YD0vDSP3Lb/g2V2rO7y
         k2PrPA1jGdpxnZU5sl84EOCNNUobFxTuFd7rw8NDt3ZRTy/536dEojg6tXRnUht7XR84
         0pnB2YqTvJ6AoWioaxKKPxihcp69pdkn2w8asybIazoVYbUF1nflj2K2DE/vfxVMpeYs
         IGmgy3u4tzBF10pxVf/qHA1N51dwvNSftfj3Y3JsXnCuhpcKpnZkRzjfn/pXwwfqL+rI
         TS+4mp/R5quwxlt/Bc8Rc+Y1vI9LQsEfw/52L2TFeP8cQnASOYuLddErCD+JePLArq5I
         3uEw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532xSVzhgNnaupJVceC2EAUOL7R98OgteZwHBbFJ2+qW4x7ejpfM
	gjmxYpHKk7GhlFLfjn5IoxM=
X-Google-Smtp-Source: ABdhPJxL+GVC505XjfoM51IaF5pGp9k1m3wtr5fa77bmDs1aav55u9W47IqGEagRBaSt30pFEVKVZw==
X-Received: by 2002:a5d:8b09:: with SMTP id k9mr1461555ion.185.1619142512731;
        Thu, 22 Apr 2021 18:48:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:924:: with SMTP id o4ls1912948ilt.9.gmail; Thu, 22
 Apr 2021 18:48:32 -0700 (PDT)
X-Received: by 2002:a92:ddc6:: with SMTP id d6mr1036395ilr.33.1619142512371;
        Thu, 22 Apr 2021 18:48:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619142512; cv=none;
        d=google.com; s=arc-20160816;
        b=B5SeZTjKqdi+ZT0nX8kG8xrs/UdVMgpAbSVjpVCghqdWEDcVG0rtgZibshr5PYv4j1
         TAfTrWw90/yAB4M6/4vZc2mwO69bAkEeeefPl86Y6CYd2hf/wjMh942+t+ly12GSm6OH
         pnKcRCQDvCp/uSIOzcUkJ1vVUE4Nmo7pWOvFnje+Mu8eC6zDdjERkQa8FzdPJT/MwE+j
         hxrEChgYWu6GPXvih4KDjRJ3/NKMCNW5CJXqk1BCTMhEoRsgMsgaRVx9w+4Wo/LY6mue
         vPoo7Ai+zaF380V7FnOjCAHHn1xmHE310M44wCP/c4tPFxT7Yh69Z8tPjTWSrE3ngUtE
         D2tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=XajKNy6aoIfR9fbxhkyLjiEoAllUlrFjsDiP5vSV8KI=;
        b=AKSKb/e6QAaFyfRx9e4zy/e1Vp/S/jQf+ZWLi8SMDx5x/8qnBS9ffw587x1IASStTJ
         Fk5ner5zDoF9jNU2ruc45J7chTbORSm9RE2hk4qFLEKe94e8yMyVviz9PyX0RQYSIJJZ
         fs+s+oMCemGV+Gq45BCoNg9Sk1jUxRSVLg/JsIByldfPVLTadfBcPVzpRoW7KZOsKarB
         ejOEQB0nFI9jijQvRIF5vb5sijs8uJPGfVheyIOpjkPJPAk9/5OTfrpcSPo2JLmLf/iN
         2eWUgZajKtd4sIRegZDWE20CAzb0JYqr8zx8f8eYsbluLLWIOn6ijRguhC3fSNRvzl37
         4vbA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=16Qh8D3Z;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id o3si542696ilt.5.2021.04.22.18.48.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Apr 2021 18:48:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id y1so8819991plg.11
        for <kasan-dev@googlegroups.com>; Thu, 22 Apr 2021 18:48:32 -0700 (PDT)
X-Received: by 2002:a17:90a:c3:: with SMTP id v3mr3158756pjd.55.1619142511541;
        Thu, 22 Apr 2021 18:48:31 -0700 (PDT)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id w123sm3004405pfb.109.2021.04.22.18.48.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Apr 2021 18:48:30 -0700 (PDT)
Date: Thu, 22 Apr 2021 18:48:30 -0700 (PDT)
Subject: Re: [PATCH 0/9] riscv: improve self-protection
In-Reply-To: <20210330022144.150edc6e@xhacker>
CC: Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
  ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, dvyukov@google.com, bjorn@kernel.org,
  linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
  netdev@vger.kernel.org, bpf@vger.kernel.org
From: Palmer Dabbelt <palmer@dabbelt.com>
To: jszhang3@mail.ustc.edu.cn
Message-ID: <mhng-c1b60b87-7dd7-43e7-91eb-1f54528384f8@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b=16Qh8D3Z;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Mon, 29 Mar 2021 11:21:44 PDT (-0700), jszhang3@mail.ustc.edu.cn wrote:
> From: Jisheng Zhang <jszhang@kernel.org>
>
> patch1 is a trivial improvement patch to move some functions to .init
> section
>
> Then following patches improve self-protection by:
>
> Marking some variables __ro_after_init
> Constifing some variables
> Enabling ARCH_HAS_STRICT_MODULE_RWX
>
> Jisheng Zhang (9):
>   riscv: add __init section marker to some functions
>   riscv: Mark some global variables __ro_after_init
>   riscv: Constify sys_call_table
>   riscv: Constify sbi_ipi_ops
>   riscv: kprobes: Implement alloc_insn_page()
>   riscv: bpf: Move bpf_jit_alloc_exec() and bpf_jit_free_exec() to core
>   riscv: bpf: Avoid breaking W^X
>   riscv: module: Create module allocations without exec permissions
>   riscv: Set ARCH_HAS_STRICT_MODULE_RWX if MMU
>
>  arch/riscv/Kconfig                 |  1 +
>  arch/riscv/include/asm/smp.h       |  4 ++--
>  arch/riscv/include/asm/syscall.h   |  2 +-
>  arch/riscv/kernel/module.c         |  2 +-
>  arch/riscv/kernel/probes/kprobes.c |  8 ++++++++
>  arch/riscv/kernel/sbi.c            | 10 +++++-----
>  arch/riscv/kernel/smp.c            |  6 +++---
>  arch/riscv/kernel/syscall_table.c  |  2 +-
>  arch/riscv/kernel/time.c           |  2 +-
>  arch/riscv/kernel/traps.c          |  2 +-
>  arch/riscv/kernel/vdso.c           |  4 ++--
>  arch/riscv/mm/init.c               | 12 ++++++------
>  arch/riscv/mm/kasan_init.c         |  6 +++---
>  arch/riscv/mm/ptdump.c             |  2 +-
>  arch/riscv/net/bpf_jit_comp64.c    | 13 -------------
>  arch/riscv/net/bpf_jit_core.c      | 14 ++++++++++++++
>  16 files changed, 50 insertions(+), 40 deletions(-)

Thanks.  These are on for-next.  I had to fix up a handful of merge 
conflicts, so LMK if I made any mistakes.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-c1b60b87-7dd7-43e7-91eb-1f54528384f8%40palmerdabbelt-glaptop.
