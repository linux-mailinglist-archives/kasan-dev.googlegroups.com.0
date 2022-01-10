Return-Path: <kasan-dev+bncBCS4VDMYRUNBBY5F6KHAMGQE3O5JMNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 613A148A0B2
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Jan 2022 21:11:16 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id l29-20020a19495d000000b0042d1e9c46f3sf2025984lfj.22
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Jan 2022 12:11:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1641845476; cv=pass;
        d=google.com; s=arc-20160816;
        b=P+KknfBCTnjEST7Y1Bw3fjQPGLKdFdsOAmbACYqRE3pMYzmzIjQjp6YerOlmAvNfVZ
         rArwyp8YhlEtVRRwSeD4v+FpeKJKQ/P8P26r6z83GCui1qTlw+3VyTQi1d1wN4oOFWvl
         uMfCQ5OpoeJiGEAVCxSGnE2mcBjENOUfYjOSt2pOurnC/EPpkRS/qgt0qzQXeIxMjjcB
         nVB1hbyFFVdi8D9JvRJSUeAXZ2GcgRliZWWRMKeyQX0SUWtvssKV/ooHsYtRhffsFD5j
         MWk8EyEugYheAj1SkNf4K/eULrRnpP9nfp2o1I5HSDOb3uxVabVD/Xlrin1qhbDAZjp8
         jiRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=JzQ0jReOgJ443Ks/WRmICZKrkofg893k0Az3vlwrevA=;
        b=qcnJYicjodIAf1aimMdSwRzY9qhWezK+eNh41Ec5mHPWdvhHvJKtAGGPXuNNTLd54Q
         8vwguP1c3/4lSw+6zcZNzR36JaLB9XhVUVhPjiWA2nzkvHeQu1Suzd8z+njNxTLkgPmw
         W4ue4WsQt7gC3CflOezg+8uHPOE3rUvGRYPE+KkWiIXb/wj2gcgZ9DxOnn0gHeuJCCw2
         Vu5ZxVR229D2tIWEA2f26WFBs/UsJceoto+SDdwx9e2HdBRvwVOA3yusSVIVJNNpUNiG
         ol3DXVT5TJVTwh/hKuHdimtfcEm7dws+cc1Up1tDvboDVNw9InXgYC/K0r3Y/Kkc5sx1
         3eHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=agy857BB;
       spf=pass (google.com: domain of srs0=rut/=r2=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=rUt/=R2=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:mime-version
         :content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JzQ0jReOgJ443Ks/WRmICZKrkofg893k0Az3vlwrevA=;
        b=WbK34RNtUcPhMysZMstkj3N23BJCWHjMgZT+la1rKJqykzhw43bo6NjhU5GfV4cXQh
         D1ET69hcjHLuj2WiY5pA7FRV8ttZtYXfpibKQJKUaFshNWn3vjSHwNcU6rcA1TZFxHgH
         mATgi3RzoBuoOiX9zERe7zb84J4cmP9seGUK7+PRGtCngnpguhb24uUaMTJFB9DRf5Ia
         tq4tDEq0gQzdjn/2bweaoJRqiBf3lIDE9F7vXPPnXkjyh8pzE/2APqJDGbmdO8sCNKiI
         T2cWTFOlqZY9D4mDfZEc5qgNDbSdbwJ0zmU64KlV8+HCLXPg2IiM5fIlBXF3VH6aU/eL
         VACg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:mime-version:content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JzQ0jReOgJ443Ks/WRmICZKrkofg893k0Az3vlwrevA=;
        b=6wq4l77fJkE9qeo/7Tvn+VYI8sfzDiDXNSko4OpMT5Z7ODCMvWCf3Z4jbIbZF5zz5H
         V+kID0qESKxkZmICn4mU9aXmYlswEaz/rQfDyY9VnQHle2P7fUDaBZJLJziFRZpML5rJ
         ikIy4KG58zLkgG9ad8/uaAE+XLpz78uBkO1QZSFWb/HpohtTRabvhKcRy37tr1GElPLV
         ++BiieipIQb5bDdMKk4VOpf8o4/pvQOuoWwnhazUSfuIUmejL7ANzvVYFvSU7wAZziUP
         YyYcqbhhmyPzp/HOw3wX5BFdJ0FiSPgb/sjyru68arw4SVFGuqDt84C6U67Pg5WMCF6G
         +GfQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530QTrBs73N0if9/3TUhEzYQEkZm4FWfClxzOx7rK9RzcOkdLTDD
	fAY3NpC/mGEE/FqyhMo5r0U=
X-Google-Smtp-Source: ABdhPJwtmmg61erdpPmlyWI7zR0IVpNNiYUvEKHez9rcGu4z6xd9cyjqDT83vtz6qOVNxCeaHAaElQ==
X-Received: by 2002:a05:6512:a8f:: with SMTP id m15mr998697lfu.435.1641845475820;
        Mon, 10 Jan 2022 12:11:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:81c6:: with SMTP id s6ls1912154ljg.4.gmail; Mon, 10 Jan
 2022 12:11:14 -0800 (PST)
X-Received: by 2002:a2e:7015:: with SMTP id l21mr720450ljc.375.1641845474622;
        Mon, 10 Jan 2022 12:11:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1641845474; cv=none;
        d=google.com; s=arc-20160816;
        b=xBMVmOl+PRlc6q5ih9/iQVBD0+4bLMbr4Aqt25H9xDsxWI4/BiM1vZ9RzYMVappvyl
         89xltHT28++net/7w2T9XHick0P0igSe7Wr3s2dvdAB20HU25NBrWZfyZ8NwmPLSIvo9
         c9J3fFSGg9EAxy9Wg/3R5hqbdCWtfLtpmBzWFgpPvz9MRodDP5eIWldLcp43OsjPtT+e
         07M50RBjX1bCceUXTgoMqZ4oVRjPQAeQKg0OyYqdKVeoJ6aTd8dc0t5XRNfHiWDH4ylg
         /3rwF67mVK8SHrZgebxw3RTgU9ENegR6nISiNYJx4OlDLMH3emyW5GN3fkT3qNoTxiX+
         AhKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=l2UrhKsZxwCa36Ol6JoTPKEGQbhRYi6fS9zlyunOKfA=;
        b=GILRPqo6MsWgWQ84kZdSLQyhJDQ9TpN7wDZvixKubyxFNtDqvq6yXPxQR6hXCj0wQY
         oi6vG4+Q4ux69iVFPI/wcO3o/QEHuwBil7Bh+Zx5dXPkPfy7+vVQefbposUNMcDMiTS7
         y313D+FryNa0b02RnuweKgfZjovts+pBX5WB2ZL77TnS6PcdAA+3aKTKl/tffomVwjNP
         zp+HpcinGa2wmqvIMdUrrfhg8vwvGoojUwF1JdhC/grq6DeiK1EDPLzkZaBR0RSXtXU9
         ivU/o6OdLsJ+HnrsX3b6Pi/zfxV4Et94nVJWilLnoE9T0hqRmTrHmzB1Zhh2azzVxA++
         91nQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=agy857BB;
       spf=pass (google.com: domain of srs0=rut/=r2=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=rUt/=R2=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id g42si391828lfv.2.2022.01.10.12.11.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 10 Jan 2022 12:11:14 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=rut/=r2=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id DB33AB817D3;
	Mon, 10 Jan 2022 20:11:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A6513C36AE9;
	Mon, 10 Jan 2022 20:11:12 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 3A4BC5C03AE; Mon, 10 Jan 2022 12:11:12 -0800 (PST)
Date: Mon, 10 Jan 2022 12:11:12 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: torvalds@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, mingo@kernel.org, elver@google.com,
	andreyknvl@google.com, glider@google.com, dvyukov@google.com
Subject: [GIT PULL] KCSAN changes for v5.17
Message-ID: <20220110201112.GA1013244@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=agy857BB;       spf=pass
 (google.com: domain of srs0=rut/=r2=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=rUt/=R2=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

Hello, Linus,

Please pull the latest KCSAN git tree from:

  git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git tags/kcsan.2022.01.09a
  # HEAD: b473a3891c46393e9c4ccb4e3197d7fb259c7100: kcsan: Only test clear_bit_unlock_is_negative_byte if arch defines it

KCSAN changes for this cycle provide KCSAN fixes and also the ability to
take memory barriers into account for weakly-ordered systems.  This last
can increase the probability of detecting certain types of data races.

----------------------------------------------------------------
Alexander Potapenko (1):
      compiler_attributes.h: Add __disable_sanitizer_instrumentation

Marco Elver (28):
      kcsan: Refactor reading of instrumented memory
      kcsan: Remove redundant zero-initialization of globals
      kcsan: Avoid checking scoped accesses from nested contexts
      kcsan: Add core support for a subset of weak memory modeling
      kcsan: Add core memory barrier instrumentation functions
      kcsan, kbuild: Add option for barrier instrumentation only
      kcsan: Call scoped accesses reordered in reports
      kcsan: Show location access was reordered to
      kcsan: Document modeling of weak memory
      kcsan: test: Match reordered or normal accesses
      kcsan: test: Add test cases for memory barrier instrumentation
      kcsan: Ignore GCC 11+ warnings about TSan runtime support
      kcsan: selftest: Add test case to check memory barrier instrumentation
      locking/barriers, kcsan: Add instrumentation for barriers
      locking/barriers, kcsan: Support generic instrumentation
      locking/atomics, kcsan: Add instrumentation for barriers
      asm-generic/bitops, kcsan: Add instrumentation for barriers
      x86/barriers, kcsan: Use generic instrumentation for non-smp barriers
      x86/qspinlock, kcsan: Instrument barrier of pv_queued_spin_unlock()
      mm, kcsan: Enable barrier instrumentation
      sched, kcsan: Enable memory barrier instrumentation
      objtool, kcsan: Add memory barrier instrumentation to whitelist
      objtool, kcsan: Remove memory barrier instrumentation from noinstr
      kcsan: Support WEAK_MEMORY with Clang where no objtool support exists
      kcsan: Make barrier tests compatible with lockdep
      kcsan: Turn barrier instrumentation into macros
      kcsan: Avoid nested contexts reading inconsistent reorder_access
      kcsan: Only test clear_bit_unlock_is_negative_byte if arch defines it

 Documentation/dev-tools/kcsan.rst                |  76 +++-
 arch/x86/include/asm/barrier.h                   |  10 +-
 arch/x86/include/asm/qspinlock.h                 |   1 +
 include/asm-generic/barrier.h                    |  54 ++-
 include/asm-generic/bitops/instrumented-atomic.h |   3 +
 include/asm-generic/bitops/instrumented-lock.h   |   3 +
 include/linux/atomic/atomic-instrumented.h       | 135 ++++++-
 include/linux/compiler_attributes.h              |  18 +
 include/linux/compiler_types.h                   |  13 +-
 include/linux/kcsan-checks.h                     |  83 ++++-
 include/linux/kcsan.h                            |  11 +-
 include/linux/sched.h                            |   3 +
 include/linux/spinlock.h                         |   2 +-
 init/init_task.c                                 |   5 -
 kernel/kcsan/Makefile                            |   2 +
 kernel/kcsan/core.c                              | 347 +++++++++++++++---
 kernel/kcsan/kcsan_test.c                        | 426 +++++++++++++++++++++--
 kernel/kcsan/report.c                            |  51 +--
 kernel/kcsan/selftest.c                          | 143 ++++++++
 kernel/sched/Makefile                            |   7 +-
 lib/Kconfig.kcsan                                |  20 ++
 mm/Makefile                                      |   2 +
 scripts/Makefile.kcsan                           |  15 +-
 scripts/Makefile.lib                             |   5 +
 scripts/atomic/gen-atomic-instrumented.sh        |  41 ++-
 tools/objtool/check.c                            |  41 ++-
 tools/objtool/include/objtool/elf.h              |   2 +-
 27 files changed, 1347 insertions(+), 172 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220110201112.GA1013244%40paulmck-ThinkPad-P17-Gen-1.
