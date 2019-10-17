Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBXPUHWQKGQERNW5ASI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1AB4ADAF93
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 16:15:35 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id b67sf2306484qkc.1
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 07:15:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571321734; cv=pass;
        d=google.com; s=arc-20160816;
        b=BHmS00FgsL2b79BEH+CTIgGfMF8MvtQ48ohu+ccNOEusblXGmS5x4m5cLgfQ1QbcLZ
         ZJz1gKd5iJKCiKYJkBfv6P8EYWyvXs4f6fLE+DOcOmBjHnsG19Gmkmie8nA9WGCa9zzx
         PFHqAuPyMdW3F3nzZMSuDsvphuuWFCqq5yQFvYiiOcuTCF1vg/ra4EUJvDLscfcvyy4E
         puxA2kIa4e7VGq5WeOaLuFW/c7IgeCb5rKxKQPQy18j31CkMOp8OGydNfjVzrEeT+Auu
         j2mBtYyc5y8DMUwmRhaD/yPqTSVpl1RUwxwrHzkBPLDtLEJdGmOnVQUK4w+ADR7AtC2u
         ohYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=nHyY+gMyGZZeAwiD3QVX9sC11x7eu0F4aU4ToUtgqD4=;
        b=ceaAlp2Q+aNb4wbuazQFZmnjvJagrQRCDG/AdKY7ZmxgsKwqXyUP0OsA0jx6B8UgUx
         /m4/Vzrk46y+/nYCmGBGfOMVwwh2+cObI8tssmrIT8hbHcCkG3vF4ymt7Ry8e5cfoteh
         mjWOfQawQb+SiebiZxCagwzYhDQ9Ku2i+1FXpO++yFahAEpBPLKPpQOiQ3b5TZxCos8D
         mEr3iukWK+eH3tlD4qlff4Pamka410PxtMUCASRlBuwsCteDCSqWfoOzLKQTgGRRhzF8
         gCZsf4j/IpKQadVvsb+e0iCpBNPh1NAKvKeXCZRCkEIAPd2ipO+Jl/M6awOd1u5lVFBV
         UxAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Kv2dqE7D;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nHyY+gMyGZZeAwiD3QVX9sC11x7eu0F4aU4ToUtgqD4=;
        b=Vnblg0kiaG3PkOPFNBTGaVxustEX9J8R9J7DnrI2VLmxBTsNmd3Ynmg+3AlGwaNcqk
         MKGW7OK8Vtk2KR6s/JRt84XWEvMxK9reFbn5q+WN4pXLJEjaeGcWjZgwk/UXLpVhEGfj
         JPcUCsRjoHzW3Pcx4pEiC25vn5HvUOLMEmEpjBItxJ+NVGnJYjJWuhNvp/QFyzb7x1az
         xoc6blffVJ87n7sEkGHSUJ5QiqcWVNau608fRxYLbFJnbPCurXp53KhG8T+Fr22BWsSp
         zVG/b4IQWAq50sh7nPLjmfANUEjqmibwe5/oMNB4nNDfVApkvcQx7FSUqkKrFHo8UNAe
         d3xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nHyY+gMyGZZeAwiD3QVX9sC11x7eu0F4aU4ToUtgqD4=;
        b=Q+560oBTodF1CP5aCacOoyP0ryX/twovk2kOoLs9XnQ5aDK9HbeEyiM3WeaBZbjqg1
         doCItJ0zzYjMRHgBa/+Y6ylothXDr34HgjT7IlGunak5LxzsqX+vIPM2SLUsVTuI3dJh
         DI3OtMrDpxbvNQCGk320NDrKLs57ZUS0+dFfgVtPqyhgCdwn3nX2nmeqrD2tFRWdFPBb
         Okf5zDvC+fbcUbgOpwhNo29fTgwPmOm8q3hc1aCMRN05VLEQXv8r2d083jXlG7O23t/a
         gvLJ0p1UnjZFZv3YvjXFn5FHKOToHvKpQGhgoBEK8gw16xDtZqPQH9v/70VRGiYag3zg
         b0tg==
X-Gm-Message-State: APjAAAVMBKF+90OISUIZ3itCAVZvfq8ORozpGkH9hU/fMaPgVBhNcYO8
	d6VWmtEwgwy034ejq+MMvZM=
X-Google-Smtp-Source: APXvYqzAQ2A2AaSoUw9FuRZ59YEmCezExvDEm2+WdNHP6pHhwARm1v04//PDfQyPUnHVVPL/rlDALw==
X-Received: by 2002:a05:620a:1328:: with SMTP id p8mr3263855qkj.461.1571321734094;
        Thu, 17 Oct 2019 07:15:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:34fd:: with SMTP id x58ls808881qtb.8.gmail; Thu, 17 Oct
 2019 07:15:33 -0700 (PDT)
X-Received: by 2002:ac8:740b:: with SMTP id p11mr3929649qtq.75.1571321733771;
        Thu, 17 Oct 2019 07:15:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571321733; cv=none;
        d=google.com; s=arc-20160816;
        b=U3faWK8cfDhc3H2SCEFPGdd2AYHWbdJZLyfbwhVBuKwxh+j21FwlVleK4zY/SiKHKg
         CfjP97eQvSVzw5NCDqj/W9oVZHCc6dbCBUypteAARUDaaFsd4d0QdSfaNNtE83dpj+CW
         Ml4jQznaAII2/rHHO0x04RuAuRtSKeOhjnih4EdLKLH+1bpFoIhPQ5k6Qm4/LPzLAQbL
         aFXNq+BhBGReJlklErcv835m26QB3HeFO6Rq27NL/JE3kRlQaXCNefBK6fNP81Gj2zUD
         RDL2JYoZ9ldw5+gZlx6NFiD24bWaEy57c4VxoXABBA4UEjglFlPs7py26HJNEE45iuzE
         IFEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gNom0VFlbRYX78r4OKfXRzBJyj1ZzMem6+U6GRAPZGs=;
        b=tytAKBPvfr3k/PZRb2d+8yP6HDkTzNTTv4zCli+jeoELIlYDDGOsfcvto4hWK/TkUS
         6GpVQivRVv4x3+xqIoXTVttaeGeRMjkMC/IORJC1gqXhOzaISeJpJkRhjH6IDRAnJrf3
         4SDHd8v9OMHzIo4dsMJfiGOO76XVkH9ARdgv0RGsKzIu6BfmTRSAk4gU+BKr4ZxnakfV
         coihLc1fX6C4hJ0SGfBobdNFyJuxoUzf6J9gk5Y6uyyzsFniHuj/miabLl9ILOZboAW6
         5tOUwEcKnH5x4h2W5m3oYOAIIV6XZ5QKwB8AE0DLAGxwSLgnOhxw4hpxzA4nsFPoNdSz
         5L9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Kv2dqE7D;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id t187si57308qkd.0.2019.10.17.07.15.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Oct 2019 07:15:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id w144so2275225oia.6
        for <kasan-dev@googlegroups.com>; Thu, 17 Oct 2019 07:15:33 -0700 (PDT)
X-Received: by 2002:aca:5015:: with SMTP id e21mr3502104oib.121.1571321732803;
 Thu, 17 Oct 2019 07:15:32 -0700 (PDT)
MIME-Version: 1.0
References: <20191016083959.186860-1-elver@google.com>
In-Reply-To: <20191016083959.186860-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Oct 2019 16:15:20 +0200
Message-ID: <CANpmjNPB8mFso7=WpUQ8Nbxon3kKTEGRUFMCVhjLNkfzey+TJg@mail.gmail.com>
Subject: Re: [PATCH 0/8] Add Kernel Concurrency Sanitizer (KCSAN)
To: Marco Elver <elver@google.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, dave.hansen@linux.intel.com, 
	David Howells <dhowells@redhat.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Luc Maranget <luc.maranget@inria.fr>, 
	Mark Rutland <mark.rutland@arm.com>, Nicholas Piggin <npiggin@gmail.com>, 
	"Paul E. McKenney" <paulmck@linux.ibm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Kv2dqE7D;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
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

On Wed, 16 Oct 2019 at 10:41, Marco Elver <elver@google.com> wrote:
>
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

Sent v2: http://lkml.kernel.org/r/20191017141305.146193-1-elver@google.com

Many thanks,
-- Marco

> Marco Elver (8):
>   kcsan: Add Kernel Concurrency Sanitizer infrastructure
>   objtool, kcsan: Add KCSAN runtime functions to whitelist
>   build, kcsan: Add KCSAN build exceptions
>   seqlock, kcsan: Add annotations for KCSAN
>   seqlock: Require WRITE_ONCE surrounding raw_seqcount_barrier
>   asm-generic, kcsan: Add KCSAN instrumentation for bitops
>   locking/atomics, kcsan: Add KCSAN instrumentation
>   x86, kcsan: Enable KCSAN for x86
>
>  Documentation/dev-tools/kcsan.rst         | 202 ++++++++++
>  MAINTAINERS                               |  11 +
>  Makefile                                  |   3 +-
>  arch/x86/Kconfig                          |   1 +
>  arch/x86/boot/Makefile                    |   1 +
>  arch/x86/boot/compressed/Makefile         |   1 +
>  arch/x86/entry/vdso/Makefile              |   1 +
>  arch/x86/include/asm/bitops.h             |   2 +-
>  arch/x86/kernel/Makefile                  |   6 +
>  arch/x86/kernel/cpu/Makefile              |   3 +
>  arch/x86/lib/Makefile                     |   2 +
>  arch/x86/mm/Makefile                      |   3 +
>  arch/x86/purgatory/Makefile               |   1 +
>  arch/x86/realmode/Makefile                |   1 +
>  arch/x86/realmode/rm/Makefile             |   1 +
>  drivers/firmware/efi/libstub/Makefile     |   1 +
>  include/asm-generic/atomic-instrumented.h | 192 ++++++++-
>  include/asm-generic/bitops-instrumented.h |  18 +
>  include/linux/compiler-clang.h            |   9 +
>  include/linux/compiler-gcc.h              |   7 +
>  include/linux/compiler.h                  |  35 +-
>  include/linux/kcsan-checks.h              | 116 ++++++
>  include/linux/kcsan.h                     |  85 ++++
>  include/linux/sched.h                     |   7 +
>  include/linux/seqlock.h                   |  51 ++-
>  init/init_task.c                          |   6 +
>  init/main.c                               |   2 +
>  kernel/Makefile                           |   6 +
>  kernel/kcsan/Makefile                     |  14 +
>  kernel/kcsan/atomic.c                     |  21 +
>  kernel/kcsan/core.c                       | 458 ++++++++++++++++++++++
>  kernel/kcsan/debugfs.c                    | 225 +++++++++++
>  kernel/kcsan/encoding.h                   |  94 +++++
>  kernel/kcsan/kcsan.c                      |  81 ++++
>  kernel/kcsan/kcsan.h                      | 140 +++++++
>  kernel/kcsan/report.c                     | 307 +++++++++++++++
>  kernel/kcsan/test.c                       | 117 ++++++
>  kernel/sched/Makefile                     |   6 +
>  lib/Kconfig.debug                         |   2 +
>  lib/Kconfig.kcsan                         |  88 +++++
>  lib/Makefile                              |   3 +
>  mm/Makefile                               |   8 +
>  scripts/Makefile.kcsan                    |   6 +
>  scripts/Makefile.lib                      |  10 +
>  scripts/atomic/gen-atomic-instrumented.sh |   9 +-
>  tools/objtool/check.c                     |  17 +
>  46 files changed, 2364 insertions(+), 16 deletions(-)
>  create mode 100644 Documentation/dev-tools/kcsan.rst
>  create mode 100644 include/linux/kcsan-checks.h
>  create mode 100644 include/linux/kcsan.h
>  create mode 100644 kernel/kcsan/Makefile
>  create mode 100644 kernel/kcsan/atomic.c
>  create mode 100644 kernel/kcsan/core.c
>  create mode 100644 kernel/kcsan/debugfs.c
>  create mode 100644 kernel/kcsan/encoding.h
>  create mode 100644 kernel/kcsan/kcsan.c
>  create mode 100644 kernel/kcsan/kcsan.h
>  create mode 100644 kernel/kcsan/report.c
>  create mode 100644 kernel/kcsan/test.c
>  create mode 100644 lib/Kconfig.kcsan
>  create mode 100644 scripts/Makefile.kcsan
>
> --
> 2.23.0.700.g56cf767bdb-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPB8mFso7%3DWpUQ8Nbxon3kKTEGRUFMCVhjLNkfzey%2BTJg%40mail.gmail.com.
