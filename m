Return-Path: <kasan-dev+bncBC7OBJGL2MHBBP5LZOCAMGQECJJNBNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id B23EB37437D
	for <lists+kasan-dev@lfdr.de>; Wed,  5 May 2021 19:28:32 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id b16-20020a5ea7100000b02904037ac1756fsf1734365iod.13
        for <lists+kasan-dev@lfdr.de>; Wed, 05 May 2021 10:28:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620235711; cv=pass;
        d=google.com; s=arc-20160816;
        b=v/OHPzswp5vB9y+ExbRoXyTIErtCNmKKxP4/Nec5k4pKpmEDsEa4o8VVeLnhdK5WqM
         84fNmaXV4wYAnu8m1tGPmbaHel23mXA1PZba8y/GvS57+kPNRfCq7ieo2H2CMiDJj7V2
         t3OCNPf0tVouTQ6zMY4nVl1QVajZI28kaAG7xBpv+C4WeEU/41URVM9X6eKalkHNJ0sm
         9HZ2ztfJjriW2qWSTLkvTDJDe/XpwdNR2dhc8ft77vl4ERFNSQULelLLXykGG93mUCT7
         8KWcnExMd8HvBclYFRjiSZ28GO+xTMXaCYRj9JzMKYc7cmmyuI4czkacl5Q+cRqVNhhW
         S0yA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=80XOlxpXmEUgheiXPbzMerhLBTrafrfvqkECvzqEuMs=;
        b=QxFdiCHhmAqS3DD99co7uEQm6DRPJOwsfmgUFWXkaJ0DnBeFt2xUMpJ7vxvZ9ZDSv0
         ir0LiyYGpmFkEpp5WCnT74Wa1hNjmvjtiXaZvliMEW+vh5bb7XrHZd6JKOrp9kantJa7
         mjR39oN4dkS80aDs9gY9cD78/fuvYe3HFO8lqgBVz80CLumydb2LeXcLs0FMhCQM/bVu
         3tyrB259YMiUUfhU2PQQOY9imvwziHwMOPUOSevt1ToIoOc2BaMP92t8x3rw2K2yTVUx
         zBjekiGJUDmt2iowYBvKJm71X1KEBFvnZZqmAiXKB1OLvrzrHQXKs9LagOU4eKDThKsl
         c7Pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EXvGc2UU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=80XOlxpXmEUgheiXPbzMerhLBTrafrfvqkECvzqEuMs=;
        b=WeOeoNDwBiyJiUslkHbuvZp8eJB4hPe8uzP5z3J0W+8k4bRA/pn43LtCkrYVzUpHLH
         ds082I/bjWyewj+ZRVyaGrF/BQQVPczZ79kYlxFTSfmDYK6oRdLppLTMKnVwh+HWgxIN
         AVTszerClaVfDNcixahAfnWdZHfXoGpBwFYrhzWD3iLK1zwokRU5k5LDHvMHnbh7aN32
         IVvXFjd+2c1vEONKjyRzgX1tZ0GxAbWns6O7Uu/zt9jEoP8CZOelrgKCVvgen8p6oml5
         SDF7xTCYcEZsvQt4r1b6yN+GaecJpphMAsv6YLlk2ukjNPG53mzW+h7yxj1WhW/eKWOF
         7Omw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=80XOlxpXmEUgheiXPbzMerhLBTrafrfvqkECvzqEuMs=;
        b=YJVjRuOGPSiHI/ErHa4Vg2uL1yX2RVJm6LVPxNhGIW5AWLi52k4Jm9Kegl9pbDENj5
         GH6HU4b12HiLAWvyoQBX2SRm1piaDffOSJaiNaaPTImDpGi/Y8JUjFYbkWt9d/L3QdZe
         CRraMH8ZJjr/fSumXrywvVeQF/dpu7DU1sspejCbC8B3wb+bMGovqHS/jAA33JPxmskb
         O3njevmR7plxSLY5xX3Qknx0oTJ1I2VqzZoB+MhSE2mvV8K8loim/WTK6z/gq4IhWS28
         q1GehuOVwqWAW2Pk40Dy5KqdMkuqAnGNwTJJ3WPJWS1KIQ2F4sSJJ9HGw8s07fiSUUiQ
         F1nw==
X-Gm-Message-State: AOAM533n2wFQ0c2cEiuEOUmHT1aOtsDL2TsGOyJlh7VM5Whi5rWn6wci
	fdVEYSULfHYkegr5Gjg9eXg=
X-Google-Smtp-Source: ABdhPJwA7P7VXNgueDzDuDCfhOSPoL/k6NMkN4qDCUzSJxH5a7Vh5Txxl9p1QmXjo8YlKVnxcXZ2MA==
X-Received: by 2002:a92:c8c6:: with SMTP id c6mr15152ilq.109.1620235711695;
        Wed, 05 May 2021 10:28:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:25c3:: with SMTP id u3ls2765797jat.9.gmail; Wed, 05
 May 2021 10:28:31 -0700 (PDT)
X-Received: by 2002:a05:6638:1390:: with SMTP id w16mr29854224jad.83.1620235711304;
        Wed, 05 May 2021 10:28:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620235711; cv=none;
        d=google.com; s=arc-20160816;
        b=PKLnwN/fsZivGedXUoXXQ1hlRNhGJY1sf4zLgeifO7s0GAsevlFfmzLa3yae5E0I45
         xaAZVdWz3AhiyPgF854qUzbPLGbAKyucmBjcBLbgvgxRYdo1dE70W4kpyHxsfZK0+1lx
         5dnlCP7v/jicQximPMo0+dmDQCT3b9lRYwujnjmfZ4pY9gtvca3Y3x1fau8ByeRN7DQ3
         +Lhkj45bcNvl12xMLAQyA/jYL3wXd7LZ/CpNL4z6bamPKRiC/eCQYlwpQlf7kMV2s/6e
         /nEQIwq2hRrREH1kOntxcX95iJstCDdT6n1DZRiPmqPfomzBZp0l3i217hDPbCPxQwN9
         qQpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=J8AaP/lvxUNB3rrLU595zuxT9OqLnp3Rqgcgif6hwNc=;
        b=P/nocBnd3g6HxsKaTqi/6YezX0miAS0po9+e/WG49HPSk9MPWV36Fg+ZUgBq38tnpn
         LzWyZ/QS3YxMPb564Pc6oyfmhTRBzMKDjgpvNI6hlQhJPPIc6LSKoN/6gjiYRm5cV4b/
         N2og9d9tUJFNHEgR3SAqzNmjfkh6ZUBXwKJrS2B4HrXaQrSvvHrWQ5bJNgYyF0tm74mX
         U6Ia/VP7dAj0N6qOnaWbsydiVRWP1PmgZbxWHiICfupM/Z3yMCjALO/BVo1cLB+e5liB
         R8eAx5ntdOG1M6zbr/43jYFQnwXIOyA6T4degdgrZdlc20HwVJiwOXniAxZAJ0BqxpKG
         rTcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EXvGc2UU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32c.google.com (mail-ot1-x32c.google.com. [2607:f8b0:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id o3si918198ilt.5.2021.05.05.10.28.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 May 2021 10:28:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) client-ip=2607:f8b0:4864:20::32c;
Received: by mail-ot1-x32c.google.com with SMTP id u25-20020a0568302319b02902ac3d54c25eso2424237ote.1
        for <kasan-dev@googlegroups.com>; Wed, 05 May 2021 10:28:31 -0700 (PDT)
X-Received: by 2002:a05:6830:410e:: with SMTP id w14mr23875287ott.251.1620235710813;
 Wed, 05 May 2021 10:28:30 -0700 (PDT)
MIME-Version: 1.0
References: <m1tuni8ano.fsf_-_@fess.ebiederm.org> <20210505141101.11519-1-ebiederm@xmission.com>
 <20210505141101.11519-11-ebiederm@xmission.com>
In-Reply-To: <20210505141101.11519-11-ebiederm@xmission.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 5 May 2021 19:27:00 +0200
Message-ID: <CANpmjNOBtpMad-mn1JE1LmkEURtc0RJX-9LNXvJPMfDpSC3ASw@mail.gmail.com>
Subject: Re: [PATCH v3 11/12] signal: Deliver all of the siginfo perf data in _perf
To: "Eric W. Beiderman" <ebiederm@xmission.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Florian Weimer <fweimer@redhat.com>, 
	"David S. Miller" <davem@davemloft.net>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, sparclinux <sparclinux@vger.kernel.org>, 
	linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux API <linux-api@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=EXvGc2UU;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Wed, 5 May 2021 at 16:11, Eric W. Beiderman <ebiederm@xmission.com> wrote:
> From: "Eric W. Biederman" <ebiederm@xmission.com>
>
> Don't abuse si_errno and deliver all of the perf data in _perf member
> of siginfo_t.
>
> The data field in the perf data structures in a u64 to allow a pointer
> to be encoded without needed to implement a 32bit and 64bit version of
> the same structure.  There already exists a 32bit and 64bit versions
> siginfo_t, and the 32bit version can not include a 64bit member as it
> only has 32bit alignment.  So unsigned long is used in siginfo_t
> instead of a u64 as unsigned long can encode a pointer on all
> architectures linux supports.

Since there is no functional change (we already had the unsigned long
here), the explanation made me think there was a change in that area
(but there wasn't). (Can leave as-is, but a "Note: " or similar if you
deem it appropriate.)

> v1: https://lkml.kernel.org/r/m11rarqqx2.fsf_-_@fess.ebiederm.org
> v2: https://lkml.kernel.org/r/20210503203814.25487-10-ebiederm@xmission.com
> Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>

Reviewed-by: Marco Elver <elver@google.com>

Thank you!


> ---
>  arch/arm/kernel/signal.c                      |  3 ++-
>  arch/arm64/kernel/signal.c                    |  3 ++-
>  arch/arm64/kernel/signal32.c                  |  3 ++-
>  arch/sparc/kernel/signal32.c                  |  3 ++-
>  arch/sparc/kernel/signal_64.c                 |  3 ++-
>  arch/x86/kernel/signal_compat.c               |  6 ++++--
>  fs/signalfd.c                                 |  3 ++-
>  include/linux/compat.h                        |  5 ++++-
>  include/uapi/asm-generic/siginfo.h            |  8 +++++--
>  include/uapi/linux/signalfd.h                 |  4 ++--
>  kernel/signal.c                               | 21 ++++++++++++-------
>  .../selftests/perf_events/sigtrap_threads.c   | 12 +++++------
>  12 files changed, 47 insertions(+), 27 deletions(-)
>
> diff --git a/arch/arm/kernel/signal.c b/arch/arm/kernel/signal.c
> index 643bcb0f091b..f3800c0f428b 100644
> --- a/arch/arm/kernel/signal.c
> +++ b/arch/arm/kernel/signal.c
> @@ -757,7 +757,8 @@ static_assert(offsetof(siginfo_t, si_addr_lsb)      == 0x10);
>  static_assert(offsetof(siginfo_t, si_lower)    == 0x14);
>  static_assert(offsetof(siginfo_t, si_upper)    == 0x18);
>  static_assert(offsetof(siginfo_t, si_pkey)     == 0x14);
> -static_assert(offsetof(siginfo_t, si_perf)     == 0x10);
> +static_assert(offsetof(siginfo_t, si_perf_data)        == 0x10);
> +static_assert(offsetof(siginfo_t, si_perf_type)        == 0x14);
>  static_assert(offsetof(siginfo_t, si_band)     == 0x0c);
>  static_assert(offsetof(siginfo_t, si_fd)       == 0x10);
>  static_assert(offsetof(siginfo_t, si_call_addr)        == 0x0c);
> diff --git a/arch/arm64/kernel/signal.c b/arch/arm64/kernel/signal.c
> index ad4bd27fc044..b3978b468bd4 100644
> --- a/arch/arm64/kernel/signal.c
> +++ b/arch/arm64/kernel/signal.c
> @@ -1005,7 +1005,8 @@ static_assert(offsetof(siginfo_t, si_addr_lsb)    == 0x18);
>  static_assert(offsetof(siginfo_t, si_lower)    == 0x20);
>  static_assert(offsetof(siginfo_t, si_upper)    == 0x28);
>  static_assert(offsetof(siginfo_t, si_pkey)     == 0x20);
> -static_assert(offsetof(siginfo_t, si_perf)     == 0x18);
> +static_assert(offsetof(siginfo_t, si_perf_data)        == 0x18);
> +static_assert(offsetof(siginfo_t, si_perf_type)        == 0x20);
>  static_assert(offsetof(siginfo_t, si_band)     == 0x10);
>  static_assert(offsetof(siginfo_t, si_fd)       == 0x18);
>  static_assert(offsetof(siginfo_t, si_call_addr)        == 0x10);
> diff --git a/arch/arm64/kernel/signal32.c b/arch/arm64/kernel/signal32.c
> index ee6c7484e130..d3be01c46bec 100644
> --- a/arch/arm64/kernel/signal32.c
> +++ b/arch/arm64/kernel/signal32.c
> @@ -489,7 +489,8 @@ static_assert(offsetof(compat_siginfo_t, si_addr_lsb)       == 0x10);
>  static_assert(offsetof(compat_siginfo_t, si_lower)     == 0x14);
>  static_assert(offsetof(compat_siginfo_t, si_upper)     == 0x18);
>  static_assert(offsetof(compat_siginfo_t, si_pkey)      == 0x14);
> -static_assert(offsetof(compat_siginfo_t, si_perf)      == 0x10);
> +static_assert(offsetof(compat_siginfo_t, si_perf_data) == 0x10);
> +static_assert(offsetof(compat_siginfo_t, si_perf_type) == 0x14);
>  static_assert(offsetof(compat_siginfo_t, si_band)      == 0x0c);
>  static_assert(offsetof(compat_siginfo_t, si_fd)                == 0x10);
>  static_assert(offsetof(compat_siginfo_t, si_call_addr) == 0x0c);
> diff --git a/arch/sparc/kernel/signal32.c b/arch/sparc/kernel/signal32.c
> index 5573722e34ad..4276b9e003ca 100644
> --- a/arch/sparc/kernel/signal32.c
> +++ b/arch/sparc/kernel/signal32.c
> @@ -778,6 +778,7 @@ static_assert(offsetof(compat_siginfo_t, si_addr_lsb)       == 0x10);
>  static_assert(offsetof(compat_siginfo_t, si_lower)     == 0x14);
>  static_assert(offsetof(compat_siginfo_t, si_upper)     == 0x18);
>  static_assert(offsetof(compat_siginfo_t, si_pkey)      == 0x14);
> -static_assert(offsetof(compat_siginfo_t, si_perf)      == 0x10);
> +static_assert(offsetof(compat_siginfo_t, si_perf_data) == 0x10);
> +static_assert(offsetof(compat_siginfo_t, si_perf_type) == 0x14);
>  static_assert(offsetof(compat_siginfo_t, si_band)      == 0x0c);
>  static_assert(offsetof(compat_siginfo_t, si_fd)                == 0x10);
> diff --git a/arch/sparc/kernel/signal_64.c b/arch/sparc/kernel/signal_64.c
> index a69a78984c36..cea23cf95600 100644
> --- a/arch/sparc/kernel/signal_64.c
> +++ b/arch/sparc/kernel/signal_64.c
> @@ -588,6 +588,7 @@ static_assert(offsetof(siginfo_t, si_addr_lsb)      == 0x18);
>  static_assert(offsetof(siginfo_t, si_lower)    == 0x20);
>  static_assert(offsetof(siginfo_t, si_upper)    == 0x28);
>  static_assert(offsetof(siginfo_t, si_pkey)     == 0x20);
> -static_assert(offsetof(siginfo_t, si_perf)     == 0x18);
> +static_assert(offsetof(siginfo_t, si_perf_data)        == 0x18);
> +static_assert(offsetof(siginfo_t, si_perf_type)        == 0x20);
>  static_assert(offsetof(siginfo_t, si_band)     == 0x10);
>  static_assert(offsetof(siginfo_t, si_fd)       == 0x14);
> diff --git a/arch/x86/kernel/signal_compat.c b/arch/x86/kernel/signal_compat.c
> index c9601f092a1e..b52407c56000 100644
> --- a/arch/x86/kernel/signal_compat.c
> +++ b/arch/x86/kernel/signal_compat.c
> @@ -147,8 +147,10 @@ static inline void signal_compat_build_tests(void)
>         BUILD_BUG_ON(offsetof(siginfo_t, si_pkey) != 0x20);
>         BUILD_BUG_ON(offsetof(compat_siginfo_t, si_pkey) != 0x14);
>
> -       BUILD_BUG_ON(offsetof(siginfo_t, si_perf) != 0x18);
> -       BUILD_BUG_ON(offsetof(compat_siginfo_t, si_perf) != 0x10);
> +       BUILD_BUG_ON(offsetof(siginfo_t, si_perf_data) != 0x18);
> +       BUILD_BUG_ON(offsetof(siginfo_t, si_perf_type) != 0x20);
> +       BUILD_BUG_ON(offsetof(compat_siginfo_t, si_perf_data) != 0x10);
> +       BUILD_BUG_ON(offsetof(compat_siginfo_t, si_perf_type) != 0x14);
>
>         CHECK_CSI_OFFSET(_sigpoll);
>         CHECK_CSI_SIZE  (_sigpoll, 2*sizeof(int));
> diff --git a/fs/signalfd.c b/fs/signalfd.c
> index 83130244f653..335ad39f3900 100644
> --- a/fs/signalfd.c
> +++ b/fs/signalfd.c
> @@ -134,7 +134,8 @@ static int signalfd_copyinfo(struct signalfd_siginfo __user *uinfo,
>                 break;
>         case SIL_FAULT_PERF_EVENT:
>                 new.ssi_addr = (long) kinfo->si_addr;
> -               new.ssi_perf = kinfo->si_perf;
> +               new.ssi_perf_type = kinfo->si_perf_type;
> +               new.ssi_perf_data = kinfo->si_perf_data;
>                 break;
>         case SIL_CHLD:
>                 new.ssi_pid    = kinfo->si_pid;
> diff --git a/include/linux/compat.h b/include/linux/compat.h
> index 6af7bef15e94..a27fffaae121 100644
> --- a/include/linux/compat.h
> +++ b/include/linux/compat.h
> @@ -236,7 +236,10 @@ typedef struct compat_siginfo {
>                                         u32 _pkey;
>                                 } _addr_pkey;
>                                 /* used when si_code=TRAP_PERF */
> -                               compat_ulong_t _perf;
> +                               struct {
> +                                       compat_ulong_t _data;
> +                                       u32 _type;
> +                               } _perf;
>                         };
>                 } _sigfault;
>
> diff --git a/include/uapi/asm-generic/siginfo.h b/include/uapi/asm-generic/siginfo.h
> index 3503282021aa..3ba180f550d7 100644
> --- a/include/uapi/asm-generic/siginfo.h
> +++ b/include/uapi/asm-generic/siginfo.h
> @@ -96,7 +96,10 @@ union __sifields {
>                                 __u32 _pkey;
>                         } _addr_pkey;
>                         /* used when si_code=TRAP_PERF */
> -                       unsigned long _perf;
> +                       struct {
> +                               unsigned long _data;
> +                               __u32 _type;
> +                       } _perf;
>                 };
>         } _sigfault;
>
> @@ -159,7 +162,8 @@ typedef struct siginfo {
>  #define si_lower       _sifields._sigfault._addr_bnd._lower
>  #define si_upper       _sifields._sigfault._addr_bnd._upper
>  #define si_pkey                _sifields._sigfault._addr_pkey._pkey
> -#define si_perf                _sifields._sigfault._perf
> +#define si_perf_data   _sifields._sigfault._perf._data
> +#define si_perf_type   _sifields._sigfault._perf._type
>  #define si_band                _sifields._sigpoll._band
>  #define si_fd          _sifields._sigpoll._fd
>  #define si_call_addr   _sifields._sigsys._call_addr
> diff --git a/include/uapi/linux/signalfd.h b/include/uapi/linux/signalfd.h
> index 7e333042c7e3..e78dddf433fc 100644
> --- a/include/uapi/linux/signalfd.h
> +++ b/include/uapi/linux/signalfd.h
> @@ -39,8 +39,8 @@ struct signalfd_siginfo {
>         __s32 ssi_syscall;
>         __u64 ssi_call_addr;
>         __u32 ssi_arch;
> -       __u32 __pad3;
> -       __u64 ssi_perf;
> +       __u32 ssi_perf_type;
> +       __u64 ssi_perf_data;
>
>         /*
>          * Pad strcture to 128 bytes. Remember to update the
> diff --git a/kernel/signal.c b/kernel/signal.c
> index 49560ceac048..7fec9d1c5b11 100644
> --- a/kernel/signal.c
> +++ b/kernel/signal.c
> @@ -1758,11 +1758,13 @@ int force_sig_perf(void __user *addr, u32 type, u64 sig_data)
>         struct kernel_siginfo info;
>
>         clear_siginfo(&info);
> -       info.si_signo = SIGTRAP;
> -       info.si_errno = type;
> -       info.si_code  = TRAP_PERF;
> -       info.si_addr  = addr;
> -       info.si_perf  = sig_data;
> +       info.si_signo     = SIGTRAP;
> +       info.si_errno     = 0;
> +       info.si_code      = TRAP_PERF;
> +       info.si_addr      = addr;
> +       info.si_perf_data = sig_data;
> +       info.si_perf_type = type;
> +
>         return force_sig_info(&info);
>  }
>
> @@ -3380,7 +3382,8 @@ void copy_siginfo_to_external32(struct compat_siginfo *to,
>                 break;
>         case SIL_FAULT_PERF_EVENT:
>                 to->si_addr = ptr_to_compat(from->si_addr);
> -               to->si_perf = from->si_perf;
> +               to->si_perf_data = from->si_perf_data;
> +               to->si_perf_type = from->si_perf_type;
>                 break;
>         case SIL_CHLD:
>                 to->si_pid = from->si_pid;
> @@ -3456,7 +3459,8 @@ static int post_copy_siginfo_from_user32(kernel_siginfo_t *to,
>                 break;
>         case SIL_FAULT_PERF_EVENT:
>                 to->si_addr = compat_ptr(from->si_addr);
> -               to->si_perf = from->si_perf;
> +               to->si_perf_data = from->si_perf_data;
> +               to->si_perf_type = from->si_perf_type;
>                 break;
>         case SIL_CHLD:
>                 to->si_pid    = from->si_pid;
> @@ -4639,7 +4643,8 @@ static inline void siginfo_buildtime_checks(void)
>         CHECK_OFFSET(si_lower);
>         CHECK_OFFSET(si_upper);
>         CHECK_OFFSET(si_pkey);
> -       CHECK_OFFSET(si_perf);
> +       CHECK_OFFSET(si_perf_data);
> +       CHECK_OFFSET(si_perf_type);
>
>         /* sigpoll */
>         CHECK_OFFSET(si_band);
> diff --git a/tools/testing/selftests/perf_events/sigtrap_threads.c b/tools/testing/selftests/perf_events/sigtrap_threads.c
> index 78ddf5e11625..fde123066a8c 100644
> --- a/tools/testing/selftests/perf_events/sigtrap_threads.c
> +++ b/tools/testing/selftests/perf_events/sigtrap_threads.c
> @@ -164,8 +164,8 @@ TEST_F(sigtrap_threads, enable_event)
>         EXPECT_EQ(ctx.signal_count, NUM_THREADS);
>         EXPECT_EQ(ctx.tids_want_signal, 0);
>         EXPECT_EQ(ctx.first_siginfo.si_addr, &ctx.iterate_on);
> -       EXPECT_EQ(ctx.first_siginfo.si_errno, PERF_TYPE_BREAKPOINT);
> -       EXPECT_EQ(ctx.first_siginfo.si_perf, TEST_SIG_DATA(&ctx.iterate_on));
> +       EXPECT_EQ(ctx.first_siginfo.si_perf_type, PERF_TYPE_BREAKPOINT);
> +       EXPECT_EQ(ctx.first_siginfo.si_perf_data, TEST_SIG_DATA(&ctx.iterate_on));
>
>         /* Check enabled for parent. */
>         ctx.iterate_on = 0;
> @@ -183,8 +183,8 @@ TEST_F(sigtrap_threads, modify_and_enable_event)
>         EXPECT_EQ(ctx.signal_count, NUM_THREADS);
>         EXPECT_EQ(ctx.tids_want_signal, 0);
>         EXPECT_EQ(ctx.first_siginfo.si_addr, &ctx.iterate_on);
> -       EXPECT_EQ(ctx.first_siginfo.si_errno, PERF_TYPE_BREAKPOINT);
> -       EXPECT_EQ(ctx.first_siginfo.si_perf, TEST_SIG_DATA(&ctx.iterate_on));
> +       EXPECT_EQ(ctx.first_siginfo.si_perf_type, PERF_TYPE_BREAKPOINT);
> +       EXPECT_EQ(ctx.first_siginfo.si_perf_data, TEST_SIG_DATA(&ctx.iterate_on));
>
>         /* Check enabled for parent. */
>         ctx.iterate_on = 0;
> @@ -203,8 +203,8 @@ TEST_F(sigtrap_threads, signal_stress)
>         EXPECT_EQ(ctx.signal_count, NUM_THREADS * ctx.iterate_on);
>         EXPECT_EQ(ctx.tids_want_signal, 0);
>         EXPECT_EQ(ctx.first_siginfo.si_addr, &ctx.iterate_on);
> -       EXPECT_EQ(ctx.first_siginfo.si_errno, PERF_TYPE_BREAKPOINT);
> -       EXPECT_EQ(ctx.first_siginfo.si_perf, TEST_SIG_DATA(&ctx.iterate_on));
> +       EXPECT_EQ(ctx.first_siginfo.si_perf_type, PERF_TYPE_BREAKPOINT);
> +       EXPECT_EQ(ctx.first_siginfo.si_perf_data, TEST_SIG_DATA(&ctx.iterate_on));
>  }
>
>  TEST_HARNESS_MAIN
> --
> 2.30.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOBtpMad-mn1JE1LmkEURtc0RJX-9LNXvJPMfDpSC3ASw%40mail.gmail.com.
