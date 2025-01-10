Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCOOQO6AMGQETFJAF7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id EF751A08B7A
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2025 10:23:23 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-2ef909597d9sf5415022a91.3
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2025 01:23:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736501002; cv=pass;
        d=google.com; s=arc-20240605;
        b=bi6KGMUuz/zsE6+NInlqTdbvnY25VcUB4lfgpzFyISP8SKpuXCDlGFaZOswxbeRL53
         Xlr4DzOQK+UzfDj86GeK2TTIrEUB54dGBg8+GvIv5gSCl7gYfcAh7t9v4659fCR1OyiR
         mw1xP1+vqRi55VA7paBawgJAEdkpF/CvqCAW16K5Qb28U9jRx4ha5Z8F5xEPpZW+k0+j
         +ppR20XtO8OF71SwI8HNbIsy2SnD4F/MgMeS3I8PxdKEP4DvHNhAYuHbZ4KnJoNSqSoJ
         7mKV4zDWM50tG56bIb2wbH7BgJZnEQPI0zdE9LVQsjBOybp6xI+ZxxTOMyczNVG/1jz/
         sQSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4YSLnIZuW0pLXdlVsN1xp9ouZbWvQcP4LJTA1OhjFkA=;
        fh=RFGT4QvKQgFblFqBoovOroOtqgb/trt6lc3WcKWDkl4=;
        b=IeJrwHQ0KJneWKupMPS29mQgZKcACK8+d5WzRgOd8UQCu3w2dWV/C6WcPCbAr6wdPG
         598QtsUqe2fuBnspTPEcvkt6SddeE7ve726SFl2gBfLw5QfAy9cgYPt2LjcCN2S6Ceij
         PqPE6mwRL70xmtpMv44Wj7ofksAB94ylDcgJMxOJs0Bgruzw9qP2F759DC3zGpkedKzw
         SAcABLv+tfEhl+oOpslGCeLpPYzfThmk3kQceDIPS8+12q/Wt97xVQPVzqu/GlZBSPvk
         nhW2ZiKvQPLgewhmKADcIy+kcgOJED4OJtCebPdLzgQkDXykbxNMlgwJSOuFCPYeW4nm
         Ap0g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ypKDnNCq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736501002; x=1737105802; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4YSLnIZuW0pLXdlVsN1xp9ouZbWvQcP4LJTA1OhjFkA=;
        b=XffHz4rXao0CLg6Y5iBBJ0lbqyRKECi1YuirILBEuYoC59LZKZSrx/IAcuofDmA1zQ
         CbtU4Ipp8beRUTOn7isTcyuEV6MEDLx20oMQrJ/Tnc4CD7yeBwkV6Jryd/xnVo7jtx5m
         0shFNUHdxDR2t0ucl3V3J9b+YBsazb5zNy16DV6RY7S1azyu7jAB5ssnrs2ONX1cQh9d
         qOh0wsEq+0TdBfHdNKW7bRdJgElG+0MwQ7QeJvXZtEMUOjlEsgu3+5SYz95xlNDaaYmK
         UpaxY8CRDT8O68grqMhcQ8r2vO5Wxlf6R1vP0YWDB2CHLQiQ4my+tU4zgHG6xcR2N4nQ
         2y7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736501002; x=1737105802;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4YSLnIZuW0pLXdlVsN1xp9ouZbWvQcP4LJTA1OhjFkA=;
        b=DWRIH+9J+wf0LvxK4uJz2TLDpbMBDBc9YHLA0ihjOV+pcqdZSIuBPTcAQhutIP8auE
         PmTp385LQzPg4cXMXK6B7SVquFcUpwjKRHULN0sSSOqlJDswfm0Y1lnUCj5oz84FsTyt
         LDQ3T4N0vNiAvADPPjp9xCvHAkHAsETJ/qHeJsMbCwlSCWoRx3NYTREvfkVxF4WRh6E5
         Yfx2nyYQ9AU4JfCTpBm+hGC4T8MIlcq4ReoB8LdavyIp/sofvWxRkegSUZeXfv0MsS2Y
         iEwfT+BaiU24CXyNKMMoQTcvyfJX1pTnw+JFG+AYT1fUaD6gHYu5H+A7Xi5xKiYrOue1
         kCQg==
X-Forwarded-Encrypted: i=2; AJvYcCVUedxDZ4XnYdDrcOmUIGTzbMTXnDT94YsYi+2AL15jpuJfTT6OuHt6BU/5jBTrKvp5L5NRAg==@lfdr.de
X-Gm-Message-State: AOJu0YzxMsIlDb70BdQPk61BpPUi0fzG3AQXAnZtNSU4OYUYG/pj8enL
	wTH83DGVimKo4Qk7S4GGBmk+oraQip/SBDQzlpv0/x0Z60aySIIb
X-Google-Smtp-Source: AGHT+IEY5TVweZ/azrHKQ8W87Gy+rrCC6YuOAoXSHmUYWhNcVyuHS1QpKY7k4bfglt+Nrr/f6S/MtA==
X-Received: by 2002:a17:90b:2e86:b0:2ee:b26c:10a0 with SMTP id 98e67ed59e1d1-2f5490abf24mr15957912a91.24.1736501002189;
        Fri, 10 Jan 2025 01:23:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:2cc5:b0:2ef:288a:b248 with SMTP id
 98e67ed59e1d1-2f553f2ff4als1581911a91.2.-pod-prod-03-us; Fri, 10 Jan 2025
 01:23:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW9t4cwfyeI1ggq9jW8alWfRiNQjmwWBV0xggqc7IRiqdImFbeRJY0tWnYTg0EuCyLE7WtZbcj7e9E=@googlegroups.com
X-Received: by 2002:a17:90b:6c6:b0:2ea:8d1e:a85f with SMTP id 98e67ed59e1d1-2f548f44771mr16576335a91.17.1736501000708;
        Fri, 10 Jan 2025 01:23:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736501000; cv=none;
        d=google.com; s=arc-20240605;
        b=LLruhOsfad5JSPiVE6k+4ftpmM209kAfMDDo5UIH1kO826H0g/XoiR90sj87HIXRq+
         CGX6wVdqXIc0Hj1EdpYv0xvWuThow+xW0vf7KYz6mBjapG9/qKpfPmBirSYZIBQV8Qwj
         Q9SfMAg09D3wK3bVZbMeLB/6zWW4Y7ZhkiykYmTaQ/K1LvqUxX2BM7b0OfGj/wdU3PZE
         apBwfsI7dQRuNuZiMJIrpzgFbodEXq8k0Q3jQQJBC5uogram0z9il6P9eK1rF342fGRt
         AOOUX721V8xZFAdzYd+TrrwCdGnSSfczWKVSioOYx3E8lKWe5MI6CkKVXxv+dFKGPW2d
         fYKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/8n2ma/ziuKr5ZfTxLhXrZB/sBg/b3H77RWqJjKv6Y0=;
        fh=9zDf4Dh6wlmwKk1RA+u5pinFEHXiFAy1o7liGka5wac=;
        b=MonWpPiA5OUzEh/lpM2dZ9CgYsVjMQc84RUKbdTM+CUMduqI4R1hjBkyP0kDaD6zfU
         7OtkY5CVfhTTiRR5PnCbH87ppClYAhDyMhJHLrWPr5C6AgYMIzqTJnhOpb1dWojzEGwp
         /PyMKp/UqxW5PLLd7ymXjhZDvWCNEfd7i3zbaAShotA2WON5FigTpliYxbMC1ZKk8ks4
         v5fDGQ5ilp73qYTGEFC/Bjjwg9rdWanEdAR4XCUkwbTYJwTPF0FR419fpcGSxn9lyOYg
         2PPLV5uzrT6zwzfWjnbLgWbX5dLuwAMTMWXnAS3sf1ca3+/3A2RtAJGFBeylSDvJbKbc
         hT7A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ypKDnNCq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2f54a33aea9si276005a91.3.2025.01.10.01.23.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Jan 2025 01:23:20 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id 98e67ed59e1d1-2ee989553c1so2968837a91.3
        for <kasan-dev@googlegroups.com>; Fri, 10 Jan 2025 01:23:20 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWBwWLLJcUnpuVXHGAinyq1LC7G7nzcD1oWKq7NwM6m1xCVET4N6P1lA7bNhH/ogb7+dNEx90ZaKEo=@googlegroups.com
X-Gm-Gg: ASbGncsm77YJiUq/ucONP8dahdPwwYik34cMuXXeVSD6Z4TSLPIPUj69zloDMDphBog
	YH67sQG39jX1I1DD6SB0KDjFXIWNWpibGcBQZ3/QvdKuy8WxqFChdygVPTCpZeaFdyBwcng==
X-Received: by 2002:a17:90b:5483:b0:2ea:3d2e:a0d7 with SMTP id
 98e67ed59e1d1-2f548f2a897mr15945376a91.15.1736501000183; Fri, 10 Jan 2025
 01:23:20 -0800 (PST)
MIME-Version: 1.0
References: <20250110073056.2594638-1-quic_jiangenj@quicinc.com>
In-Reply-To: <20250110073056.2594638-1-quic_jiangenj@quicinc.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 10 Jan 2025 10:22:44 +0100
X-Gm-Features: AbW1kvbwJdd-Q4HHGj93BJhXupMaNDNojdpH0KA2V7DRnVCIXbRzJRAefX-Qlpc
Message-ID: <CANpmjNOg9=WbFpJQFQBOo1z_KuV7DKQTZB7=GfiYyvoam5Dm=w@mail.gmail.com>
Subject: Re: [PATCH] kcov: add unique cover, edge, and cmp modes
To: Joey Jiao <quic_jiangenj@quicinc.com>
Cc: dvyukov@google.com, andreyknvl@gmail.com, corbet@lwn.net, 
	akpm@linux-foundation.org, gregkh@linuxfoundation.org, nogikh@google.com, 
	pierre.gondois@arm.com, cmllamas@google.com, quic_zijuhu@quicinc.com, 
	richard.weiyang@gmail.com, tglx@linutronix.de, arnd@arndb.de, 
	catalin.marinas@arm.com, will@kernel.org, dennis@kernel.org, tj@kernel.org, 
	cl@linux.com, ruanjinjie@huawei.com, colyli@suse.de, 
	andriy.shevchenko@linux.intel.com, kernel@quicinc.com, 
	quic_likaid@quicinc.com, kasan-dev@googlegroups.com, 
	workflows@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ypKDnNCq;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1034 as
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

On Fri, 10 Jan 2025 at 08:33, Joey Jiao <quic_jiangenj@quicinc.com> wrote:
>
> From: "Jiao, Joey" <quic_jiangenj@quicinc.com>
>
> The current design of KCOV risks frequent buffer overflows. To mitigate
> this, new modes are introduced: KCOV_TRACE_UNIQ_PC, KCOV_TRACE_UNIQ_EDGE,
> and KCOV_TRACE_UNIQ_CMP. These modes allow for the recording of unique
> PCs, edges, and comparison operands (CMP).

There ought to be a cover letter explaining the motivation for this,
and explaining why the new modes would help. Ultimately, what are you
using KCOV for where you encountered this problem?

> Key changes include:
> - KCOV_TRACE_UNIQ_[PC|EDGE] can be used together to replace KCOV_TRACE_PC.
> - KCOV_TRACE_UNIQ_CMP can be used to replace KCOV_TRACE_CMP mode.
> - Introduction of hashmaps to store unique coverage data.
> - Pre-allocated entries in kcov_map_init during KCOV_INIT_TRACE to avoid
>   performance issues with kmalloc.
> - New structs and functions for managing memory and unique coverage data.
> - Example program demonstrating the usage of the new modes.

This should be a patch series, carefully splitting each change into a
separate patch.
https://docs.kernel.org/process/submitting-patches.html#split-changes

> With the new hashmap and pre-alloced memory pool added, cover size can't
> be set to higher value like 1MB in KCOV_TRACE_PC or KCOV_TRACE_CMP modes
> in 2GB device with 8 procs, otherwise it causes frequent oom.
>
> For KCOV_TRACE_UNIQ_[PC|EDGE|CMP] modes, smaller cover size like 8KB can
> be used.
>
> Signed-off-by: Jiao, Joey <quic_jiangenj@quicinc.com>

As-is it's hard to review, and the motivation is unclear. A lot of
code was moved and changed, and reviewers need to understand why that
was done besides your brief explanation above.

Generally, KCOV has very tricky constraints, due to being callable
from any context, including NMI. This means adding new dependencies
need to be carefully reviewed. For one, we can see this in genalloc's
header:

> * The lockless operation only works if there is enough memory
> * available.  If new memory is added to the pool a lock has to be
> * still taken.  So any user relying on locklessness has to ensure
> * that sufficient memory is preallocated.
> *
> * The basic atomic operation of this allocator is cmpxchg on long.
> * On architectures that don't have NMI-safe cmpxchg implementation,
> * the allocator can NOT be used in NMI handler.  So code uses the
> * allocator in NMI handler should depend on
> * CONFIG_ARCH_HAVE_NMI_SAFE_CMPXCHG.

And you are calling gen_pool_alloc() from __sanitizer_cov_trace_pc.
Which means this implementation is likely broken on
!CONFIG_ARCH_HAVE_NMI_SAFE_CMPXCHG architectures (do we have
architectures like that, that support KCOV?).

There are probably other sharp corners due to the contexts KCOV can
run in, but would simply ask you to carefully reason about why each
new dependency is safe.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOg9%3DWbFpJQFQBOo1z_KuV7DKQTZB7%3DGfiYyvoam5Dm%3Dw%40mail.gmail.com.
