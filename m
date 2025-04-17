Return-Path: <kasan-dev+bncBCCMH5WKTMGRBY7QQLAAMGQEUKCYCJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id A5ABEA91643
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Apr 2025 10:14:29 +0200 (CEST)
Received: by mail-oi1-x23f.google.com with SMTP id 5614622812f47-3f6a7cba17bsf380806b6e.1
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Apr 2025 01:14:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744877668; cv=pass;
        d=google.com; s=arc-20240605;
        b=CMC31KgXdCAGAJTQEJujj43J1CdY8RWe32VuVRAzXC+EE+gcLcKfzHP95JA5rDa+8M
         WhtPkP2deIp0kFtlvEVmjalOaXZ0DKbSLOo2kr96fZkbhh5nFeQX9xgZGKGMWLEzf1j3
         fQzLCTPvMFrGinkX9faTskrzuD/90caiYauqD+RO4INa4zrBwj+3pLtabcSLe7n0OpkM
         ohN/O1nq4W78//G1zl9QU7SYeddWBQS/ZXYrZlv4Fdy6QsMfJmRRPA/A2yValSoJ3IGF
         +FIHGDWgCO9c0awiMxBtU+NXMeJpsBx7zNXARUN8OENcEQLoHMW/mfbU9Rdppd8oBPEq
         9xkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Tbr52+MfLXdwADguTrl+ITxz5tunAx4us/csNtMAvw0=;
        fh=4P9XH0psIlE/mBiJOplJYtE2Mxmt3RpEWHBnfmA15y4=;
        b=KKNCbCent+mxJJq6RQZhXcGCodUiRD8e0l1hG7uZxpweddcydAsz7+rWByPx34uHcg
         wUgzPH0WBiNvs+pSy6D3q5DbDXYSyN/QQZenh9KOB00mxZISAVVdIIQqecKjsX7qdpa1
         G2Q4UhGaizQYragS1TTeDPFw/k8QtIgUYBc6bmlF5sPJwCMEWNzG+iJD3v6QHgabqsui
         ZI91LD82i4v785OaZtq7SBhDUAbEGd/ZZlacWf5t5wKbZ2wnKpEqZQvcVWNnBvGXJcLv
         JJA2/Z/KgYYSqMePFv4Gz9Gb9dtk13glHSYItAdYPVh+65LKkvExhMALaayLiw0ArhGh
         k7RA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=cKGfXDcU;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744877668; x=1745482468; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Tbr52+MfLXdwADguTrl+ITxz5tunAx4us/csNtMAvw0=;
        b=b0DaFkYTnsF6Xatk870bV8GLdAyNoXDoGyee0zmFzHXpdVfxcO0/EAJ+SCdGmHEgr2
         /4WWcl/lrmfKkEa9jEz+5aIhDmGC2AJZCudFHUtATlCzkyqkjgO8Q5aSTS2N4xNi0DHG
         DpqYLdMrsAFHVSPzMyhX3pQHyKVRDg6YHpmHLZ3u9jUAVw9kClEgEuYDYmgEByXIZs+I
         A4qbgCNuZuBHZRUAxlZ2Gi1zMI3BwpWPXCa8FDQdWDdCp6JuwzIVXiOTovebnauxTvZq
         JcpEcQ134rc9oVGsLYssM+e53Ji6ah8PXc80dNOvJhaFi6I7Xh/wULNGq3n98ffhTCNP
         Qfbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744877668; x=1745482468;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Tbr52+MfLXdwADguTrl+ITxz5tunAx4us/csNtMAvw0=;
        b=S1ztUsZ/s6a5g28vGnTYxf51869LpeqoyHCwj7AEhjCSc0cwE7FbvZXjhpaC5v5NSh
         0s0MSRa9EvjUzxYCzICo/R+iE67KxIGbLD97Ec53YA2GpR3Ny5RBGt5zwY49mQiVlET8
         gUfq/Zlx9y+OugMocNRMGfzHa5hwqbTlSHYZDLjUbYHoEksu8hPYYchTQs44SQOE15br
         Rq3pRspm8c4qvBo/f8H0YPmceV9ZRq3ch87rOpjxTy0qYArolAivdwidmfxgxJyY8u6g
         ARCVk14gtC+D7Ypq6t7UoVpLeqRIpZh2NfvGz9WJJX6D+pTCXMEao4RvdpxTm5OLKdMd
         Vwrg==
X-Forwarded-Encrypted: i=2; AJvYcCWMRyuA6dTHwZUk3PVbKhuJJo5hZ70hUNwMAP4kn9P3w1ecQks1rWup9FXyYyJFEwXA53qTQw==@lfdr.de
X-Gm-Message-State: AOJu0Yz+NhZ/xd69qT2bC6WMTCYNovOVIl3hFdDlnFdD8K5xb/HxxXjO
	OtnsnJAtOWV09aNuXuwp9V2CZFymApnBc2YKeENGOA6lrAN7ANOc
X-Google-Smtp-Source: AGHT+IEWbS6znITuA8D5vB/rDHdI/qHvQ32vtzGLXpjw0wFYzbu8k6AlZgqwwaNRW2siuyrIg87/uA==
X-Received: by 2002:a05:6808:18aa:b0:3f6:6d32:bdb4 with SMTP id 5614622812f47-400b021886fmr2749856b6e.24.1744877668094;
        Thu, 17 Apr 2025 01:14:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALgbVogx21n0985OGYyEn6+vlT5cMjiSPGVIaBGyhFJiw==
Received: by 2002:a05:6820:150b:b0:602:1ea2:b1d9 with SMTP id
 006d021491bc7-604d07c557als341382eaf.1.-pod-prod-01-us; Thu, 17 Apr 2025
 01:14:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUEODaTPE+4LVAD6tDIRHoL7fEgW4P671mNNx0i/zjkKXbBXIQmj7AJof0hXLjgPmgSLUN+WoCrRbc=@googlegroups.com
X-Received: by 2002:a05:6808:15a6:b0:3f6:65fe:2672 with SMTP id 5614622812f47-400b01bfb7fmr2790817b6e.2.1744877667356;
        Thu, 17 Apr 2025 01:14:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744877667; cv=none;
        d=google.com; s=arc-20240605;
        b=YFV2TFoE0DGQiyG4qho2exAwLx32iutQEZSXvgo62EaE6NsY1TO/MmTgE6sehDnuPj
         5yR2B6+VeuSD1dDuwpPdVt788nole5N42VPt9gv2uFOUtaUFzSFBnYmthIo62I/JV1R3
         eoYCSQ2OSwMQocVcbv380N9Ged65u23AkM+aU+8Gp3f+YcavX3FQNrjuvmb0LN9K+inr
         ihGn3U1Ovx3eB51Gw40iumpDQSEga5urPtIiFW3zkhNDQGw82mIHplNHoGNv1iseYs9x
         nUEd6J5DgxSjCX8urGO3FUbkJd2zHV8nCtMp6O22pJSG80Fskc6HvQ7yD7C3h+R5MlYJ
         ISiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=OaiHtoNBz7N5DFvLSjtxO2fIGN8TT/ntEXFFU/tTPXw=;
        fh=egHYLH2MF7qdelussU2ocMpWwgPcr0CQz6A5jEIT0cU=;
        b=hNi8+XTi+v0jxGecEJ3lKQmhXGEyozlI0ooy7vU51Yplnt5saBj5RQ73nH7lwc2n4n
         dP3VpU6NH87QxtyLYuqnDjHHsbRYRqzZswwXImiSEYqvoQ8HKDrOhTUI+j3Kn2pZPrEx
         ipI6TiGa5b3eOYalVqvEwHmWtUkz1a4r+64oxvjPwifgJHoI10xpFSoDqj6PCOIdIai9
         hVzKL568dL2lQrr1n4MXPEpqOF7YfGrSr+3rLqjkkkHO2DdRtchtECF8FkUx/wHZW+bA
         URBBPNMMliV9BBCSgohLGx5hA6ibAQarAGGa5oGTExbVrN1yek7SRKegtUK+XpDRnt7M
         Htvw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=cKGfXDcU;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2e.google.com (mail-qv1-xf2e.google.com. [2607:f8b0:4864:20::f2e])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-604a5bf9621si74783eaf.2.2025.04.17.01.14.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Apr 2025 01:14:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) client-ip=2607:f8b0:4864:20::f2e;
Received: by mail-qv1-xf2e.google.com with SMTP id 6a1803df08f44-6e8fc176825so4519136d6.0
        for <kasan-dev@googlegroups.com>; Thu, 17 Apr 2025 01:14:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVKyJz3cP89cI71jll5CgkR7CMkduxcmMrLf9s9lYnZSB5r4aZh3bOCLTDMsf2ly4qpKXiJ5+wr0NE=@googlegroups.com
X-Gm-Gg: ASbGncuiuBLeH9NH2gb+IuNrSNdjmVkbD9XGwX9zLCHKUUPcsxFTwVm2dzm9pd5DdCB
	OrARrWzKLWDLhgR9irHsF+WntPq8/lNnI4zkfMkjtSpx3PvhTxRfQQxQeAL4Y+844gbTHGXI15i
	n/1dBzcPTxYFhDPWbjcAHZTsQsXYyE4yruPYvA7IpWaovHLak84Hfb
X-Received: by 2002:a05:6214:4001:b0:6d4:1425:6d2d with SMTP id
 6a1803df08f44-6f2b307e7femr67265446d6.43.1744877666833; Thu, 17 Apr 2025
 01:14:26 -0700 (PDT)
MIME-Version: 1.0
References: <20250416085446.480069-1-glider@google.com>
In-Reply-To: <20250416085446.480069-1-glider@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Apr 2025 10:13:49 +0200
X-Gm-Features: ATxdqUE8zseXJA43ZAhAMTdI6D4ruJXnW0e3Yc0OVf1KYUbilqiiH3jBvVsIOQE
Message-ID: <CAG_fn=WNMWFXND0BZMyydUtxzet-mdG3dCiETCw0sH1YK65NAQ@mail.gmail.com>
Subject: Re: [PATCH 0/7] RFC: coverage deduplication for KCOV
To: glider@google.com
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=cKGfXDcU;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

> We've conducted an experiment running syz-testbed [3] on 10 syzkaller
> instances for 24 hours.  Out of those 10 instances, 5 were enabling the
> kcov_deduplicate flag from [4], which makes use of the KCOV_UNIQUE_ENABLE
> ioctl, reserving 4096 words (262144 bits) for the bitmap and leaving 5201=
92
> words for the trace collection.
>
> Below are the average stats from the runs.
>
> kcov_deduplicate=3Dfalse:
>   corpus: 52176
>   coverage: 302658
>   cover overflows: 225288
>   comps overflows: 491
>   exec total: 1417829
>   max signal: 318894
>
> kcov_deduplicate=3Dtrue:
>   corpus: 52581
>   coverage: 304344
>   cover overflows: 986
>   comps overflows: 626
>   exec total: 1484841
>   max signal: 322455
>
> [1] https://lore.kernel.org/linux-arm-kernel/20250114-kcov-v1-5-004294b93=
1a2@quicinc.com/T/
> [2] https://clang.llvm.org/docs/SanitizerCoverage.html
> [3] https://github.com/google/syzkaller/tree/master/tools/syz-testbed
> [4] https://github.com/ramosian-glider/linux/pull/7
Ouch, this should have been:
  [4] https://github.com/ramosian-glider/syzkaller/tree/kcov_dedup-new

I will update the link in v2.
>
>
> Alexander Potapenko (7):
>   kcov: apply clang-format to kcov code
>   kcov: factor out struct kcov_state
>   kcov: x86: introduce CONFIG_KCOV_ENABLE_GUARDS
>   kcov: add `trace` and `trace_size` to `struct kcov_state`
>   kcov: add ioctl(KCOV_UNIQUE_ENABLE)
>   x86: objtool: add support for R_X86_64_REX_GOTPCRELX
>   mm/kasan: define __asan_before_dynamic_init, __asan_after_dynamic_init
>
>  Documentation/dev-tools/kcov.rst  |  43 +++
>  MAINTAINERS                       |   1 +
>  arch/x86/include/asm/elf.h        |   1 +
>  arch/x86/kernel/module.c          |   8 +
>  arch/x86/kernel/vmlinux.lds.S     |   1 +
>  arch/x86/um/asm/elf.h             |   1 +
>  include/asm-generic/vmlinux.lds.h |  14 +-
>  include/linux/kcov-state.h        |  46 +++
>  include/linux/kcov.h              |  60 ++--
>  include/linux/sched.h             |  16 +-
>  include/uapi/linux/kcov.h         |   1 +
>  kernel/kcov.c                     | 453 +++++++++++++++++++-----------
>  lib/Kconfig.debug                 |  16 ++
>  mm/kasan/generic.c                |  18 ++
>  mm/kasan/kasan.h                  |   2 +
>  scripts/Makefile.kcov             |   4 +
>  scripts/module.lds.S              |  23 ++
>  tools/objtool/arch/x86/decode.c   |   1 +
>  tools/objtool/check.c             |   1 +
>  19 files changed, 508 insertions(+), 202 deletions(-)
>  create mode 100644 include/linux/kcov-state.h
>
> --
> 2.49.0.604.gff1f9ca942-goog
>


--
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DWNMWFXND0BZMyydUtxzet-mdG3dCiETCw0sH1YK65NAQ%40mail.gmail.com.
