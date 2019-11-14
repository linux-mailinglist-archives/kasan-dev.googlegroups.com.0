Return-Path: <kasan-dev+bncBAABBGHAW3XAKGQEMAQP7II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id D30F1FCEF0
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 20:50:49 +0100 (CET)
Received: by mail-ua1-x937.google.com with SMTP id d22sf1727737ual.1
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 11:50:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573761048; cv=pass;
        d=google.com; s=arc-20160816;
        b=bkTbLvRobh6KY+4P5Ku7lJxPZ/Tl8yfTYJ+FE10pDCm1g3Yw2HWcEZRTwGU0S1X4dl
         CIkw647G3sPPl82pr1ZxhWgTBbBNqfgyRwEpU+Kfrf9p+IqkIlvYtwN9yuv7uo98O/f4
         xxss5gN9sRUmlPBC4OOeuPELlJW5LjbEWneWsJELzyUlt+HGezSYb0psC78JHD9ICR/A
         /BejaB2boUIgzbGU7xsYG2ON7/aW1HJT6TNywlxyVdhNv1ZURQmzQu9wsAjKz4Z1kZdS
         XgY2swibbnVupaJDC7TcVL26b7vM5xblslfrGgGGW9KrN9HjAqyPrOKvBqRiHXh2KCLr
         2O6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=G1SSPM5flF4dSc8D3Y7JnsoLtSBM4use0XZTvLtF5Mg=;
        b=rKhdSUZwB3D4lNUsInxq+XPw7bZY0y/4b429Xs8qG0GUlnDNJjB3x0m/plcpEbd5BI
         kZ13j+z0CRsxj87kBXtXRPnYIYkeoqWi9hVfvXpAiTMTtIohC36hk3uuuG3Ef/XnpkIQ
         VG5EG/CX1obF0Scs6+b4NGTlAd6wSTPKwm27uGfFrCVV6G35qoHV9jK6tHS//T5yaBjS
         EM8AgxqsqX9eZOHadV28cavcriIB7G3qmmCXNN1zdVKYhrfknBwotHGONmdmE0NRSUTh
         ZzXdAeizTUPO2IX+vI+i/OEcflP5JZBxbsvr3DwlH2/aR4dctNT5CfNVQcnTwujpJZY9
         0sOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=C2AGRCgt;
       spf=pass (google.com: domain of srs0=h8vx=zg=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=H8VX=ZG=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G1SSPM5flF4dSc8D3Y7JnsoLtSBM4use0XZTvLtF5Mg=;
        b=FsAvVabYM0aXgDgJCwik/iz8c9JiY+hQoMNsny9E/ox5kTaalvRF6SZoQMV4O6XMSa
         5dMe/I0U/hM+O2MN8/He8MPX3ttWXcz3+l87OKWejegfGzPsPJGmOJ3UCCTCgB+Fr9KU
         3Zgi1HRIuNyHEWj5c9kovZ2B9IC9OifJMG9GtGGLOS6IC94Irywkks7rrQgBuW2C/SPF
         pyH5ZZDsKoR7ZCRdt9UDAmZPUS6Z+vYq9AKghNG/voKG8DmQxjQGYnMIbJ5QNHQqUQ8u
         NbPgJlQKa/HUyGMmdptKudfXRRcw3w5Uwgsv8PS8yVrQA5ixM7i/cXi5cVBrJhyLDZaE
         Wcag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=G1SSPM5flF4dSc8D3Y7JnsoLtSBM4use0XZTvLtF5Mg=;
        b=OtJKfat29B2uOdQWzAdtYcZYA0DDe8LtI/sfNSxtL9UrDhnmx+aC1309ws9YLxOOxT
         3ZqwGYZ8bymriFCyQp4KZdNkHhRIHSbaLVnGHV7hD62LTf9Q0rRWAQA0Lf7XZktLrGGy
         EJYDjDehVg0HM/58HjWROplbpaMyJvsCgoCdmPyX/yqycHS6Y0k5s14eT9TJx85dYEya
         3XSd6iwIa8oD/uxVxWr0OsuxD1VyW9CL6qG/ToWjNlAXv24+KPVYj4F7a2xjcf4RtBwS
         D8RzSex6oTF9+1QhpcOO8lFQELB4EyPMQQBq26CYqsaDrfBDYXpGAGDrcmKs3M90dg4j
         c3kg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAULqA50D1ah59E/MMKizSfRpjfrum1GGHWNUdpAGb1HQJuvuX5I
	JHtsNHnH391k6QgwkLAsYz8=
X-Google-Smtp-Source: APXvYqymD1zFOfjXwLKyiJFES4VvsPUsMXix0Mo0oYawWtnGW6oTLlsVDYSeGx/SC5IALs87/oQoqQ==
X-Received: by 2002:a1f:38d4:: with SMTP id f203mr6256488vka.44.1573761048530;
        Thu, 14 Nov 2019 11:50:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:2c0e:: with SMTP id l14ls193367uar.7.gmail; Thu, 14 Nov
 2019 11:50:48 -0800 (PST)
X-Received: by 2002:ab0:4587:: with SMTP id u7mr6918805uau.67.1573761048157;
        Thu, 14 Nov 2019 11:50:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573761048; cv=none;
        d=google.com; s=arc-20160816;
        b=mcRqe4wLcD5VcfXGzGQVmR4BhoxqIOhmKfNAlf7e8q1PDlelI3oHNJNct6YaVF26Qa
         HDFDU7QqZPflPG2W757jg0C2WJGzeZHhtnlmPon+2lmwXwKZ7XXPftEk2l2x4E/BwFS+
         MzwBGjbZoOPrkt/nHoVxf3bITjv3eu5mSErTDp2t/w3WQv2lM3vSF4fTW/xWeOb6zORm
         +iR3e4TbelI3Jh3ZDtnW7WIR9lXSVaUL/vfJAC2LfM8c+DikymD7d//dKPzRqRL99va+
         JRWCWMQmSq/1K4We/PfbdSpFRiBXA2B9Tl7GNZB+IYCYjpAPTol1lRnlrauExnHMR9pZ
         jjIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=30m7lcwXD2wFsGdxqlAtJ1Cv/fiWDWB40r3qK5+qmus=;
        b=pWvUyX5N/0ICBWzLe4Tddu9hcuqoAC6Yi6OBuHKdDqd6si/a58+exkO+ix/GsHJ8Vd
         oBu96lU1ukC5JiLkzLkmTMAx7yzwc6hq1NlwL5penmlpHfsRxx+zdy/6RSgtB5NtXAjC
         Gqa5sKgIHUI93u8KRtI8o09MzTCKeRaeTgaJEapz6zW6uwZ9/QHnjrQJm0G8zDiKaINN
         sGy9sbjbT7bxY0D0tDsJ86T4GLM6XTTk1FraI7ixzWSFXM0hH8ygQFY3BPYILY6ikMpO
         y8kniKUBFREJev4fGjwY4fGDlPUkhJzHvLPwzuKR9neuOMLmkYqbXRaYJA/+qToO9QP9
         Tpnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=C2AGRCgt;
       spf=pass (google.com: domain of srs0=h8vx=zg=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=H8VX=ZG=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p78si458859vkf.0.2019.11.14.11.50.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Nov 2019 11:50:48 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=h8vx=zg=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [199.201.64.141])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id C8BF420724;
	Thu, 14 Nov 2019 19:50:46 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 7365535227FC; Thu, 14 Nov 2019 11:50:46 -0800 (PST)
Date: Thu, 14 Nov 2019 11:50:46 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com,
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org,
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com,
	bp@alien8.de, dja@axtens.net, dlustig@nvidia.com,
	dave.hansen@linux.intel.com, dhowells@redhat.com,
	dvyukov@google.com, hpa@zytor.com, mingo@redhat.com,
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net,
	jpoimboe@redhat.com, luc.maranget@inria.fr, mark.rutland@arm.com,
	npiggin@gmail.com, peterz@infradead.org, tglx@linutronix.de,
	will@kernel.org, edumazet@google.com, kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH v4 00/10] Add Kernel Concurrency Sanitizer (KCSAN)
Message-ID: <20191114195046.GP2865@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20191114180303.66955-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191114180303.66955-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=C2AGRCgt;       spf=pass
 (google.com: domain of srs0=h8vx=zg=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=H8VX=ZG=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Thu, Nov 14, 2019 at 07:02:53PM +0100, Marco Elver wrote:
> This is the patch-series for the Kernel Concurrency Sanitizer (KCSAN).
> KCSAN is a sampling watchpoint-based *data race detector*. More details
> are included in **Documentation/dev-tools/kcsan.rst**. This patch-series
> only enables KCSAN for x86, but we expect adding support for other
> architectures is relatively straightforward (we are aware of
> experimental ARM64 and POWER support).
> 
> To gather early feedback, we announced KCSAN back in September, and have
> integrated the feedback where possible:
> http://lkml.kernel.org/r/CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com
> 
> The current list of known upstream fixes for data races found by KCSAN
> can be found here:
> https://github.com/google/ktsan/wiki/KCSAN#upstream-fixes-of-data-races-found-by-kcsan
> 
> We want to point out and acknowledge the work surrounding the LKMM,
> including several articles that motivate why data races are dangerous
> [1, 2], justifying a data race detector such as KCSAN.
> 
> [1] https://lwn.net/Articles/793253/
> [2] https://lwn.net/Articles/799218/

I queued this and ran a quick rcutorture on it, which completed
successfully with quite a few reports.

							Thanx, Paul

> Race conditions vs. data races
> ------------------------------
> 
> Race conditions are logic bugs, where unexpected interleaving of racing
> concurrent operations result in an erroneous state.
> 
> Data races on the other hand are defined at the *memory model/language
> level*.  Many data races are also harmful race conditions, which a tool
> like KCSAN reports!  However, not all data races are race conditions and
> vice-versa.  KCSAN's intent is to report data races according to the
> LKMM. A data race detector can only work at the memory model/language
> level.
> 
> Deeper analysis, to find high-level race conditions only, requires
> conveying the intended kernel logic to a tool. This requires (1) the
> developer writing a specification or model of their code, and then (2)
> the tool verifying that the implementation matches. This has been done
> for small bits of code using model checkers and other formal methods,
> but does not scale to the level of what can be covered with a dynamic
> analysis based data race detector such as KCSAN.
> 
> For reasons outlined in [1, 2], data races can be much more subtle, but
> can cause no less harm than high-level race conditions.
> 
> Changelog
> ---------
> v4:
> * Major changes:
>  - Optimizations resulting in performance improvement of 33% (on
>    microbenchmark).
>  - Deal with nested interrupts for atomic_next.
>  - Simplify report.c (removing double-locking as well), in preparation
>    for KCSAN_REPORT_VALUE_CHANGE_ONLY.
>  - Add patch to introduce "data_race(expr)" macro.
>  - Introduce KCSAN_REPORT_VALUE_CHANGE_ONLY option for further filtering of data
>    races: if a conflicting write was observed via a watchpoint, only report the
>    data race if a value change was observed as well. The option will be enabled
>    by default on syzbot. (rcu-functions will be excluded from this filter at
>    request of Paul McKenney.) Context:
>    http://lkml.kernel.org/r/CANpmjNOepvb6+zJmDePxj21n2rctM4Sp4rJ66x_J-L1UmNK54A@mail.gmail.com
> 
> v3: http://lkml.kernel.org/r/20191104142745.14722-1-elver@google.com
> * Major changes:
>  - Add microbenchmark.
>  - Add instruction watchpoint skip randomization.
>  - Refactor API and core runtime fast-path and slow-path. Compared to
>    the previous version, with a default config and benchmarked using the
>    added microbenchmark, this version is 3.8x faster.
>  - Make __tsan_unaligned __alias of generic accesses.
>  - Rename kcsan_{begin,end}_atomic ->
>    kcsan_{nestable,flat}_atomic_{begin,end}
>  - For filter list in debugfs.c use kmalloc+krealloc instead of
>    kvmalloc.
>  - Split Documentation into separate patch.
> 
> v2: http://lkml.kernel.org/r/20191017141305.146193-1-elver@google.com
> * Major changes:
>  - Replace kcsan_check_access(.., {true, false}) with
>    kcsan_check_{read,write}.
>  - Change atomic-instrumented.h to use __atomic_check_{read,write}.
>  - Use common struct kcsan_ctx in task_struct and for per-CPU interrupt
>    contexts.
> 
> v1: http://lkml.kernel.org/r/20191016083959.186860-1-elver@google.com
> 
> Marco Elver (10):
>   kcsan: Add Kernel Concurrency Sanitizer infrastructure
>   include/linux/compiler.h: Introduce data_race(expr) macro
>   kcsan: Add Documentation entry in dev-tools
>   objtool, kcsan: Add KCSAN runtime functions to whitelist
>   build, kcsan: Add KCSAN build exceptions
>   seqlock, kcsan: Add annotations for KCSAN
>   seqlock: Require WRITE_ONCE surrounding raw_seqcount_barrier
>   asm-generic, kcsan: Add KCSAN instrumentation for bitops
>   locking/atomics, kcsan: Add KCSAN instrumentation
>   x86, kcsan: Enable KCSAN for x86
> 
>  Documentation/dev-tools/index.rst         |   1 +
>  Documentation/dev-tools/kcsan.rst         | 256 +++++++++
>  MAINTAINERS                               |  11 +
>  Makefile                                  |   3 +-
>  arch/x86/Kconfig                          |   1 +
>  arch/x86/boot/Makefile                    |   2 +
>  arch/x86/boot/compressed/Makefile         |   2 +
>  arch/x86/entry/vdso/Makefile              |   3 +
>  arch/x86/include/asm/bitops.h             |   6 +-
>  arch/x86/kernel/Makefile                  |   4 +
>  arch/x86/kernel/cpu/Makefile              |   3 +
>  arch/x86/lib/Makefile                     |   4 +
>  arch/x86/mm/Makefile                      |   4 +
>  arch/x86/purgatory/Makefile               |   2 +
>  arch/x86/realmode/Makefile                |   3 +
>  arch/x86/realmode/rm/Makefile             |   3 +
>  drivers/firmware/efi/libstub/Makefile     |   2 +
>  include/asm-generic/atomic-instrumented.h | 393 +++++++-------
>  include/asm-generic/bitops-instrumented.h |  18 +
>  include/linux/compiler-clang.h            |   9 +
>  include/linux/compiler-gcc.h              |   7 +
>  include/linux/compiler.h                  |  57 +-
>  include/linux/kcsan-checks.h              |  97 ++++
>  include/linux/kcsan.h                     | 115 ++++
>  include/linux/sched.h                     |   4 +
>  include/linux/seqlock.h                   |  51 +-
>  init/init_task.c                          |   8 +
>  init/main.c                               |   2 +
>  kernel/Makefile                           |   6 +
>  kernel/kcsan/Makefile                     |  11 +
>  kernel/kcsan/atomic.h                     |  27 +
>  kernel/kcsan/core.c                       | 626 ++++++++++++++++++++++
>  kernel/kcsan/debugfs.c                    | 275 ++++++++++
>  kernel/kcsan/encoding.h                   |  94 ++++
>  kernel/kcsan/kcsan.h                      | 108 ++++
>  kernel/kcsan/report.c                     | 320 +++++++++++
>  kernel/kcsan/test.c                       | 121 +++++
>  kernel/sched/Makefile                     |   6 +
>  lib/Kconfig.debug                         |   2 +
>  lib/Kconfig.kcsan                         | 118 ++++
>  lib/Makefile                              |   3 +
>  mm/Makefile                               |   8 +
>  scripts/Makefile.kcsan                    |   6 +
>  scripts/Makefile.lib                      |  10 +
>  scripts/atomic/gen-atomic-instrumented.sh |  17 +-
>  tools/objtool/check.c                     |  18 +
>  46 files changed, 2641 insertions(+), 206 deletions(-)
>  create mode 100644 Documentation/dev-tools/kcsan.rst
>  create mode 100644 include/linux/kcsan-checks.h
>  create mode 100644 include/linux/kcsan.h
>  create mode 100644 kernel/kcsan/Makefile
>  create mode 100644 kernel/kcsan/atomic.h
>  create mode 100644 kernel/kcsan/core.c
>  create mode 100644 kernel/kcsan/debugfs.c
>  create mode 100644 kernel/kcsan/encoding.h
>  create mode 100644 kernel/kcsan/kcsan.h
>  create mode 100644 kernel/kcsan/report.c
>  create mode 100644 kernel/kcsan/test.c
>  create mode 100644 lib/Kconfig.kcsan
>  create mode 100644 scripts/Makefile.kcsan
> 
> -- 
> 2.24.0.rc1.363.gb1bccd3e3d-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191114195046.GP2865%40paulmck-ThinkPad-P72.
