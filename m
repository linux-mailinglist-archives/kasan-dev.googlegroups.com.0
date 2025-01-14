Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYP7TC6AMGQE6P6W5BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id BCF2CA10482
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2025 11:43:46 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-467a0a6c846sf107540421cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2025 02:43:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736851425; cv=pass;
        d=google.com; s=arc-20240605;
        b=XWGRZkp+DkgpEs7p9LUWGEeyal2pD09xuKfnCAuvO+iSjt9O9fc6XdAYjE1tpuGnqS
         TfhnJGEDal88YIHmwnGMTxDq1DBG3/GKJrJgb+w+06OcgOxyUAJvbV7SET/2lIpLhpzv
         AtEH34YaY4iriLhQ7dodJYVo65v6FJJb2+Ge3DESY44jZByGwVeKZxadQqDI5bfTz8GU
         rNJIm7nwJPBUoIoUMp+UbspJT1pvWENuyizHVq11OEcW9i//SXqoqn7dOsn4B4QJAkqy
         VFE/EnodkYUVxtp1gmUaaRop0c58GcUfP8tT0RzHpyzIWfDg3ywVBj3YyOrSbzGXpoEB
         WPxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=AUpmYxAF7bGlvWQsHuoDtUWXaJ4fjrvJ7+p+jIAOSnU=;
        fh=sfG92E05E7DZXuF1S7nuHoOZ3mB+n68mzKGBsGanFq0=;
        b=De47Dw8H/SNfTlsWHhnbsiZw6f+ycADJedOHa6IiUYRSIkoQ3HYwtf85UC/l/5Qn72
         NreNzs6UtV8K7xX+RGqv4E+RPqQuJpqS+bKB7b3TLdhudbDf3ZhvrOn87PkRTi+xEs41
         kszpBLye5hwi780zxa8iJ2ZB0l0hMbwRpcFsPKvg4sfimObGHTw00g4trbCZo9VKLNOl
         XmcVK1k2uwVgqXbwvZCdZ+0Huu6THrnHH/5fF+f7w8I37Slt0DSCAgEQGZ1D81NAT6n6
         YW2SXi3XcN+3+y9kDgZ3TxABsqHXrbpExcqMTob8VSau8km2Cvkn+rcciIrIrcbQZLy4
         jzBQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ZmonYZdh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736851425; x=1737456225; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AUpmYxAF7bGlvWQsHuoDtUWXaJ4fjrvJ7+p+jIAOSnU=;
        b=KeXTqzkFnjMDOJbIJBpVxjasBp2HtTu3uKmREmCTuTdMp/YlOalSnx4dpwrWe47qor
         vRjaTYZ0Tn73blLnX6XhZi86272vtqZSaMQ7NW/VlsJlDv0YsTJhV5j+6VkqhV4N/TRz
         chf23jVLY17Ac5KO+KMcWj0mAWeEQ/a4dsBxta/Lq3A4FJXU0zkUZLLB6FxNqdqKqoC6
         6mCsX3fPY6RjNKDnSveFXDUgV8yb2PGT6+BHUynnJ2o28ugE99N3jIkMwBVzEI9aDa2q
         oPgr8xPQajYvdB51v2wi0KhUnyBfwwKrp2M5AzlrFlWjQgBIHwW7mASqtxUfPO+vbU3/
         sxpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736851425; x=1737456225;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AUpmYxAF7bGlvWQsHuoDtUWXaJ4fjrvJ7+p+jIAOSnU=;
        b=OB67egWMHZdfbnngwkgQf6XH+S+VT998QQIuTu+H907aGkzi5K0N+o9fKasFJZZrqo
         +N4VOXgUvDmn2diAWiV/sEg8SsZh69u8gc4TZ+0JYQutvIjLQ7+uv09r20pjp1++W4cv
         2o1fupd+ELsIJyFSkngCtPelikizy2gBWhpd1Cz0DHwXJz6V205DryOGAOOZQOwNNUyC
         ObkiN6h6gddY+zAMGTDHWuX+QHrUtmt0QDaY7LuhdCXEN1NUsxYZL3P79FrYcwfl5808
         GEHuW5UhczefUk9ieLOyQ+2W/sronTSS4tM8R50yjwLHQjHIrg4FMwPhR167gZ388oG/
         d1pA==
X-Forwarded-Encrypted: i=2; AJvYcCU6L42PQkv3wezJxunD4IpgkpVHtNsvRrSIbv1j0My4Mp1fNsAXgDMRVblcw4hS9rsDSPA/pA==@lfdr.de
X-Gm-Message-State: AOJu0YzyuYJcvSiN2bcQ9h+RW2TFeEcYCDKoN6MfZq1zwScwXnzf7ZC7
	j/u4SRBCdM9hC+K+SlWbGofuekjicjQ7+PYqJ13WeHhHa9PeUMsN
X-Google-Smtp-Source: AGHT+IFaCBSKmzWEdCmiaraxf3or7AUpjEeZc6RoMTkkIwR2siv22ckJNqXpT/tKmi/HBWSIXnGZ2Q==
X-Received: by 2002:ac8:7f8e:0:b0:467:6b96:dc5a with SMTP id d75a77b69052e-46c7109e5d9mr417295581cf.47.1736851425759;
        Tue, 14 Jan 2025 02:43:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:6104:b0:466:8f66:abeb with SMTP id
 d75a77b69052e-46c7ab39266ls63132021cf.1.-pod-prod-09-us; Tue, 14 Jan 2025
 02:43:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCViLuf6n7QdRiZOZcpTA4pNPolB4z5ZhggRMniao9qKRmN4hZpu6x6MwqrofehUzXXjCb2wuukMinc=@googlegroups.com
X-Received: by 2002:ac8:5705:0:b0:467:7513:3d8 with SMTP id d75a77b69052e-46c71003a9bmr266656081cf.21.1736851425121;
        Tue, 14 Jan 2025 02:43:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736851425; cv=none;
        d=google.com; s=arc-20240605;
        b=WZFglB52Nqql8Hb+kBdOz44+HK16Z37zxOdhVum8lsXj3tii2rAxigl5CpX8JKmFmA
         kinb8qU/tANIMwCeN3JnK50OCks6CYeWp4/JcubqRV0HaJJtCvyf5dVQOjvtuC1VJqHx
         9adHiv6U/KMXI93J8QBjnRdDT+B6rTGSd69kd2UvhdwgVk8f31p1sZWq8+rmzKd6eO5s
         FOkJQr2HWsAj/59cgS5l7/phv7UDIwVvxJmQa+tjaIali6UXni7jdEEwXtKFZB53ngX/
         nY84OxTtR6uBu/HBfrbNOVolIkDeOsA6D9d3wQqcADpmkrtSPYenPuATcHsazYPYxziP
         VjRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=U+iFfCSA0esMLhZDHY92zW4RJncb7ADni12U1qFlLKc=;
        fh=sA7inDDLeDRi87s4QxH6AadHyLR1vI3E00MQOqE1B5U=;
        b=OsJEZLC4NBekrs5doGFidhETUCKW2VtW/g8bpmO8d4dGM4nyKKaXyQVjpRpDSMlUPi
         YvM8obnT87ZoWj4igk3lUEgEHShVtVGDo/tuD3DAqyfEWIlbpbTemHi1YBTjAOU4xlzv
         KQpUYoov0iTp/pehJ3wF7qnpTfdv/2bAY+h/zlERpNl7zUOshBAMiY4LbzQc5lW1WQwB
         htxGppEwzx8LlSizm670MYtcqTU6aqOU02tuAuCcdoF+EJ1go8xxWTZ00PYeXlPCGKNO
         q6BGQ9Xkg+H14nxphiwkqSF7ASt9Cqsaytcq64X2OwB9ekQLFGIizRI48aKeCtkbCrZr
         EJaw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ZmonYZdh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6dfadc28922si4133236d6.5.2025.01.14.02.43.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Jan 2025 02:43:45 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id 98e67ed59e1d1-2ef748105deso6668536a91.1
        for <kasan-dev@googlegroups.com>; Tue, 14 Jan 2025 02:43:45 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUDSeJ+0FuO4MmhgdrsfGgi50App/5CaRuVMhOmCe8PACCBndhqPZdq0uWaCAnzWa3jmrxf2meAm2k=@googlegroups.com
X-Gm-Gg: ASbGncur3Q+gVZ8a2S7+Rkgr0X+XBZEXV2z1+mbaGoxwBejk2dSjPpiS5DqN4QW+HIZ
	m2kH+w0+AOW9RX5A7KVXNJZLXRzu8rFS7l6wGV80Cd+XF+usTGrhpRjwjMCPUJEjEI9O0
X-Received: by 2002:a17:90b:540f:b0:2ee:48bf:7dc3 with SMTP id
 98e67ed59e1d1-2f548eb321emr37372999a91.15.1736851424249; Tue, 14 Jan 2025
 02:43:44 -0800 (PST)
MIME-Version: 1.0
References: <20250114-kcov-v1-0-004294b931a2@quicinc.com>
In-Reply-To: <20250114-kcov-v1-0-004294b931a2@quicinc.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 14 Jan 2025 11:43:08 +0100
X-Gm-Features: AbW1kvaVa5-9nPmDbOZJ9N5LtR4pKYs5_Kxyb15S0vct137T7GGOlb18swg2wtM
Message-ID: <CANpmjNPUFnxvY-dnEAv09-qB5d0LY_vmyxhb3ZPJV-T9V9Q6fg@mail.gmail.com>
Subject: Re: [PATCH 0/7] kcov: Introduce New Unique PC|EDGE|CMP Modes
To: "Jiao, Joey" <quic_jiangenj@quicinc.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Jonathan Corbet <corbet@lwn.net>, Andrew Morton <akpm@linux-foundation.org>, 
	Dennis Zhou <dennis@kernel.org>, Tejun Heo <tj@kernel.org>, Christoph Lameter <cl@linux.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, workflows@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, kernel@quicinc.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ZmonYZdh;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1030 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, 14 Jan 2025 at 06:35, Jiao, Joey <quic_jiangenj@quicinc.com> wrote:
>
> Hi,
>
> This patch series introduces new kcov unique modes:
> `KCOV_TRACE_UNIQ_[PC|EDGE|CMP]`, which are used to collect unique PC, EDGE,
> CMP information.
>
> Background
> ----------
>
> In the current kcov implementation, when `__sanitizer_cov_trace_pc` is hit,
> the instruction pointer (IP) is stored sequentially in an area. Userspace
> programs then read this area to record covered PCs and calculate covered
> edges.  However, recent syzkaller runs show that many syscalls likely have
> `pos > t->kcov_size`, leading to kcov overflow. To address this issue, we
> introduce new kcov unique modes.

Overflow by how much? How much space is missing?

> Solution Overview
> -----------------
>
> 1. [P 1] Introduce `KCOV_TRACE_UNIQ_PC` Mode:
>    - Export `KCOV_TRACE_UNIQ_PC` to userspace.
>    - Add `kcov_map` struct to manage memory during the KCOV lifecycle.
>      - `kcov_entry` struct as a hashtable entry containing unique PCs.
>      - Use hashtable buckets to link `kcov_entry`.
>      - Preallocate memory using genpool during KCOV initialization.
>      - Move `area` inside `kcov_map` for easier management.
>    - Use `jhash` for hash key calculation to support `KCOV_TRACE_UNIQ_CMP`
>      mode.
>
> 2. [P 2-3] Introduce `KCOV_TRACE_UNIQ_EDGE` Mode:
>    - Save `prev_pc` to calculate edges with the current IP.
>    - Add unique edges to the hashmap.
>    - Use a lower 12-bit mask to make hash independent of module offsets.
>    - Distinguish areas for `KCOV_TRACE_UNIQ_PC` and `KCOV_TRACE_UNIQ_EDGE`
>      modes using `offset` during mmap.
>    - Support enabling `KCOV_TRACE_UNIQ_PC` and `KCOV_TRACE_UNIQ_EDGE`
>      together.
>
> 3. [P 4] Introduce `KCOV_TRACE_UNIQ_CMP` Mode:
>    - Shares the area with `KCOV_TRACE_UNIQ_PC`, making these modes
>      exclusive.
>
> 4. [P 5] Add Example Code Documentation:
>    - Provide examples for testing different modes:
>      - `KCOV_TRACE_PC`: `./kcov` or `./kcov 0`
>      - `KCOV_TRACE_CMP`: `./kcov 1`
>      - `KCOV_TRACE_UNIQ_PC`: `./kcov 2`
>      - `KCOV_TRACE_UNIQ_EDGE`: `./kcov 4`
>      - `KCOV_TRACE_UNIQ_PC|KCOV_TRACE_UNIQ_EDGE`: `./kcov 6`
>      - `KCOV_TRACE_UNIQ_CMP`: `./kcov 8`
>
> 5. [P 6-7] Disable KCOV Instrumentation:
>    - Disable instrumentation like genpool to prevent recursive calls.
>
> Caveats
> -------
>
> The userspace program has been tested on Qemu x86_64 and two real Android
> phones with different ARM64 chips. More syzkaller-compatible tests have
> been conducted. However, due to limited knowledge of other platforms,
> assistance from those with access to other systems is needed.
>
> Results and Analysis
> --------------------
>
> 1. KMEMLEAK Test on Qemu x86_64:
>    - No memory leaks found during the `kcov` program run.
>
> 2. KCSAN Test on Qemu x86_64:
>    - No KCSAN issues found during the `kcov` program run.
>
> 3. Existing Syzkaller on Qemu x86_64 and Real ARM64 Device:
>    - Syzkaller can fuzz, show coverage, and find bugs. Adjusting `procs`
>      and `vm mem` settings can avoid OOM issues caused by genpool in the
>      patches, so `procs:4 + vm:2GB` or `procs:4 + vm:2GB` are used for
>      Qemu x86_64.
>    - `procs:8` is kept on Real ARM64 Device with 12GB/16GB mem.
>
> 4. Modified Syzkaller to Support New KCOV Unique Modes:
>    - Syzkaller runs fine on both Qemu x86_64 and ARM64 real devices.
>      Limited `Cover overflows` and `Comps overflows` observed.
>
> 5. Modified Syzkaller + Upstream Kernel Without Patch Series:
>    - Not tested. The modified syzkaller will fall back to `KCOV_TRACE_PC`
>      or `KCOV_TRACE_CMP` if `ioctl` fails for Unique mode.
>
> Possible Further Enhancements
> -----------------------------
>
> 1. Test more cases and setups, including those in syzbot.
> 2. Ensure `hash_for_each_possible_rcu` is protected for reentrance
>    and atomicity.
> 3. Find a simpler and more efficient way to store unique coverage.
>
> Conclusion
> ----------
>
> These patches add new kcov unique modes to mitigate the kcov overflow
> issue, compatible with both existing and new syzkaller versions.

Thanks for the analysis, it's clearer now.

However, the new design you introduce here adds lots of complexity.
Answering the question of how much overflow is happening, might give
better clues if this is the best design or not. Because if the
overflow amount is relatively small, a better design (IMHO) might be
simply implementing a compression scheme, e.g. a simple delta
encoding.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPUFnxvY-dnEAv09-qB5d0LY_vmyxhb3ZPJV-T9V9Q6fg%40mail.gmail.com.
