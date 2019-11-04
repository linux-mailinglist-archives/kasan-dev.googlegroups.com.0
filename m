Return-Path: <kasan-dev+bncBAABBGFMQHXAKGQEEAW3SBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id D2F96EE50B
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2019 17:47:21 +0100 (CET)
Received: by mail-qk1-x73b.google.com with SMTP id a16sf6712630qka.10
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Nov 2019 08:47:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1572886041; cv=pass;
        d=google.com; s=arc-20160816;
        b=tPGxEeCaedGGMrlsHY9LmwpT9BcjyC2wrUDJn9sv7wuBuCwHAZSuVBLfdQNFibKAxT
         284nJnKvfkXNNRi6mV7IMvYjo84x+MQE7q/WQyZfr7vOQO40+htdMuHCLoXViaNgu9ZN
         I9LJ0UulgTDhOKU7q3kR4MzfVYghsbDcg5JoxPkmgxqUj9QO6+VaeCGrKEZDXHypoVhe
         d9wQ2uhOZeF9ATQWvdCcW2mcZGGcfZU3cnzoLLLVal+LINmKf34RvQQo/MU5zo/hjsMq
         SuSFGbLjUFmYtK/0hR7Dpd1wAOT1mdaaXhQTF9tx059aHvq0P3ET5Xdgrwy4NJaHXJp/
         CLwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=LJN4KiD7cKnszDxf6etfMFCvVfzrUPOj5E5BauUj7p4=;
        b=Dn5j3ksZ4cYazsM4XnUSkVuEgC9uVze24xqZAqv6iOTwXZXkki6KyR0iX7bTklOeUo
         HrPYwFiCS2c4y6yUgdeBaJOf6wPGU+KThMUWdMHIRaf2e33OSN9pyNlyHKWlH8ThC2mX
         1G4k0FMoAzxwrVczFg5ChsQxd9aQ7Mf9aRrerj7BWU5bT4eheJxrXhnDy3YHRTROZZRA
         mij+WS7c5KCtUkv1l72LqH+G/4vsJy/cETmQNIxCSkbmfXVojj7lOTpxgU+fRixWprW2
         4jTLgWvtp4jWUxYyQNfCOBYzR6ebJtguagLu5/S/QQ+U0SwuIJIRLIJwSwL6wicZk8Kt
         evHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=RBlzKtfO;
       spf=pass (google.com: domain of srs0=hufz=y4=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=hufz=Y4=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LJN4KiD7cKnszDxf6etfMFCvVfzrUPOj5E5BauUj7p4=;
        b=Gf2JNhRKuTNSxJciW9u0lBjOpbDMw6m1Oa6UufCYh0QOMcaAvj5oLCUxGLxT/pXEIl
         0cVhkEdR4YE2/tva+TGQ5FjRSwOfenwIofJS/HcnlpeGOmyb5Y7nF70K9+i0oZSF203f
         +278IcDgzza6M7px0wBqst8+XLUay19kPK0ZWY6YcOLYTR2xwP6hebQS/H55YKDv3oD3
         buq3m3DB+jlhaPkAIEuln0JFrVZ/17GekyjXFX8qSKLELumFZ8udDSsvehZOsbNK0ehZ
         UACsDITutEbaPwYrdV+XOJdG+MZCQkCDmaYpJKk1kdvKTx0YMT7TCjFg4XdHobnWKCWe
         VsHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LJN4KiD7cKnszDxf6etfMFCvVfzrUPOj5E5BauUj7p4=;
        b=dJgg4PuBL6pcZ3yP3Tirk3kJX/1Mlh8fXnJtS5/a3NrbSW0IjAcBaLoc2pbNPX+KQH
         4ZUcWR0O+x0zL2lrLKapdcRpFeFI4Tn4IQr2VUt1ru6ZjBQF/HMI/UnoSM/+zAq4nfw3
         QgyzmfIlGa7fJnkcXTOkE98/kuILZMRnNhFu/v/gTn/LFuLltTKN4f1g2F0rMwfg8YXC
         Ox1ydC0G5wsUDe7RlWvTCM2ayDLafpkgAxEY0wukSvK9wvyVMMTrEQBrPGWXC1XWUgWG
         +Bd/KmVwsYwaie1D9bcruqqqqFESAXqw6Y8q2skg/Uz7yC1AaBuJ+KsPk0J7TvkoIvRO
         0Byw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXeUKqzHzIfZSdbgPpiHx6YY5BiBK7uBDJgtQsvhohUPyj0aAt+
	eEWQCZ2jC/8mxKaFCFUXGTM=
X-Google-Smtp-Source: APXvYqzNywhsseiwJ6noTdIVTFgFmA5Pka7EgXrYXdfojsfGjt+vXUcmD8qjSqAklYysg5/N8iAzEg==
X-Received: by 2002:ae9:c30f:: with SMTP id n15mr24073808qkg.202.1572886040849;
        Mon, 04 Nov 2019 08:47:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:8051:: with SMTP id 75ls2578541qva.3.gmail; Mon, 04 Nov
 2019 08:47:20 -0800 (PST)
X-Received: by 2002:ad4:4e4a:: with SMTP id eb10mr22257106qvb.228.1572886040552;
        Mon, 04 Nov 2019 08:47:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1572886040; cv=none;
        d=google.com; s=arc-20160816;
        b=HxFW1j6cqNDNmKRSsbuOriUR8Q+MP4XXypWhI+72x7TfqeQtWgMRSjq29IP1ka8s8W
         1RtzTZKJfio66OIxNIo+VH6jH7WKAPJdnmVEYs/PTWZzUsHkAckT7VkWYVQcsSqsl8k7
         ZaV7g2DShcQRDFnFX1CvONpwEyuM6Ghw99l+Qp6UGg1/wlvu+4Piii6ZgP5Nj5UoRv6l
         23viUNgNRJLi4J/XV70jiRTLKeq6zrq3SAdhz69oYVvU6ehFGo4psU/ikfwpWi0pxr0b
         KuOUl6/n+dFbId5gsd49HgPvBbVTDyI39xgLczcVuXGEFOlCzu/1jaANnnF5Enee70mq
         S5aQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=WK5DnJ7czg0qMDqz/UrQ1A3xAtVuW/eb8vedj6RQkZ8=;
        b=0Y0FgRdbEOrd3HBj4QLPOn71cp+1L2O2+qsl5pWFKjKwHtPKXmXA3yJXif/OAV2XkI
         GB9NzV3n0BvYOVZrYzC8wVlXw2dEzcNx9QDRTnKAOiI9q1DAawL8yLSEz5YivZJ4dl+M
         yfc4B94jXH0AzfWB0SHbqvy/Q6VBEMITyvCWOm2FGx14KBQq374qQzIDOcfmsq2A9V/Y
         DgbVxMA2mkejYGACOimxxGnRiDXPo7Bs0aNbYHaTU0eJMhFpSw3fIfkJNnx05SI34dmR
         iNAW62hICNfxTMFTQID2BTADn78h/f5cY4WruKNAi9gv/woMJfwqCWH7g3nWxjqaDa8y
         a3Mg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=RBlzKtfO;
       spf=pass (google.com: domain of srs0=hufz=y4=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=hufz=Y4=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w140si1060686qka.6.2019.11.04.08.47.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 04 Nov 2019 08:47:20 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=hufz=y4=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [109.144.216.141])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 205412084D;
	Mon,  4 Nov 2019 16:47:19 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 3F5003520B56; Mon,  4 Nov 2019 08:47:17 -0800 (PST)
Date: Mon, 4 Nov 2019 08:47:17 -0800
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
	will@kernel.org, kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH v3 0/9] Add Kernel Concurrency Sanitizer (KCSAN)
Message-ID: <20191104164717.GE20975@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20191104142745.14722-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191104142745.14722-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=RBlzKtfO;       spf=pass
 (google.com: domain of srs0=hufz=y4=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=hufz=Y4=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Mon, Nov 04, 2019 at 03:27:36PM +0100, Marco Elver wrote:
> This is the patch-series for the Kernel Concurrency Sanitizer (KCSAN).
> KCSAN is a sampling watchpoint-based data-race detector. More details
> are included in Documentation/dev-tools/kcsan.rst. This patch-series
> only enables KCSAN for x86, but we expect adding support for other
> architectures is relatively straightforward (we are aware of
> experimental ARM64 and POWER support).
> 
> To gather early feedback, we announced KCSAN back in September, and
> have integrated the feedback where possible:
> http://lkml.kernel.org/r/CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com
> 
> We want to point out and acknowledge the work surrounding the LKMM,
> including several articles that motivate why data-races are dangerous
> [1, 2], justifying a data-race detector such as KCSAN.
> [1] https://lwn.net/Articles/793253/
> [2] https://lwn.net/Articles/799218/
> 
> The current list of known upstream fixes for data-races found by KCSAN
> can be found here:
> https://github.com/google/ktsan/wiki/KCSAN#upstream-fixes-of-data-races-found-by-kcsan

Making this more accessible to more people seems like a good thing.
So, for the series:

Acked-by: Paul E. McKenney <paulmck@kernel.org>

> Changelog
> ---------
> v3:
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
> Marco Elver (9):
>   kcsan: Add Kernel Concurrency Sanitizer infrastructure
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
>  Documentation/dev-tools/kcsan.rst         | 217 +++++++++
>  MAINTAINERS                               |  11 +
>  Makefile                                  |   3 +-
>  arch/x86/Kconfig                          |   1 +
>  arch/x86/boot/Makefile                    |   2 +
>  arch/x86/boot/compressed/Makefile         |   2 +
>  arch/x86/entry/vdso/Makefile              |   3 +
>  arch/x86/include/asm/bitops.h             |   6 +-
>  arch/x86/kernel/Makefile                  |   7 +
>  arch/x86/kernel/cpu/Makefile              |   3 +
>  arch/x86/lib/Makefile                     |   4 +
>  arch/x86/mm/Makefile                      |   3 +
>  arch/x86/purgatory/Makefile               |   2 +
>  arch/x86/realmode/Makefile                |   3 +
>  arch/x86/realmode/rm/Makefile             |   3 +
>  drivers/firmware/efi/libstub/Makefile     |   2 +
>  include/asm-generic/atomic-instrumented.h | 393 +++++++--------
>  include/asm-generic/bitops-instrumented.h |  18 +
>  include/linux/compiler-clang.h            |   9 +
>  include/linux/compiler-gcc.h              |   7 +
>  include/linux/compiler.h                  |  35 +-
>  include/linux/kcsan-checks.h              |  97 ++++
>  include/linux/kcsan.h                     | 115 +++++
>  include/linux/sched.h                     |   4 +
>  include/linux/seqlock.h                   |  51 +-
>  init/init_task.c                          |   8 +
>  init/main.c                               |   2 +
>  kernel/Makefile                           |   6 +
>  kernel/kcsan/Makefile                     |  11 +
>  kernel/kcsan/atomic.h                     |  27 ++
>  kernel/kcsan/core.c                       | 560 ++++++++++++++++++++++
>  kernel/kcsan/debugfs.c                    | 275 +++++++++++
>  kernel/kcsan/encoding.h                   |  94 ++++
>  kernel/kcsan/kcsan.h                      | 131 +++++
>  kernel/kcsan/report.c                     | 306 ++++++++++++
>  kernel/kcsan/test.c                       | 121 +++++
>  kernel/sched/Makefile                     |   6 +
>  lib/Kconfig.debug                         |   2 +
>  lib/Kconfig.kcsan                         | 119 +++++
>  lib/Makefile                              |   3 +
>  mm/Makefile                               |   8 +
>  scripts/Makefile.kcsan                    |   6 +
>  scripts/Makefile.lib                      |  10 +
>  scripts/atomic/gen-atomic-instrumented.sh |  17 +-
>  tools/objtool/check.c                     |  18 +
>  46 files changed, 2526 insertions(+), 206 deletions(-)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191104164717.GE20975%40paulmck-ThinkPad-P72.
