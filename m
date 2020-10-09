Return-Path: <kasan-dev+bncBD7LZ45K3ECBBKUOQD6AKGQES4D62AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D3B32882EA
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Oct 2020 08:46:03 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id e13sf4820412wrj.8
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Oct 2020 23:46:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602225963; cv=pass;
        d=google.com; s=arc-20160816;
        b=W3z75XQmmQ3lGctGp85Zc2azYEkWIDWkN06TLqJhrX4HNQ/7jx/TyZq+4cuvdXtMyY
         g9kD83UBoMHndsrFMnOfRH9e/oCDhBix1iYfKmkFBzRwnOCR/ETZz16c3VkYASoPpJXy
         09C8d7ISBmqF2p2b5uqWYh9XWsr32LjRGQ80Nh2P01wjfmE7mG2Ao1u0732KN4ogevoG
         6SpFTCeRxrJMlrb2oXlvGB5c3Ehec9sH8Hb0jRyzsrlGUHIqvuhh05A12l1DA28M4J64
         +S2ytVw8/zQ3G9yw659MojKbmpd1t4YoX3QWiK0ofCGAGgYefQvPxATRuLEjyjc6IFw6
         c57A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Bjkrvqy21Et1qClQODxaFvziDg6CHU2WCI4FOpuZ38g=;
        b=vaAPk+3jESVjF+kwA9mZDvmvfO5RVxjXa6LqYWfjihhrllyHN9rBSEBL51dqV1EbK3
         j6a7zA8JeMlkHUaRvU513YEwlwXFDT2/9j7fc0ITclYN3khU6b9IF28Jrb6lbWnjLfZk
         ZTTXJ3v4W9won32prqKl01fUqt1FK7ZTE9WqfiBhFtRk/HhijaZ/NP4fxKwpEyp+kaZ4
         e38dPufS3aLGmIrfce1K97TRQ05sxvX1HX/ale6XeGlI1u3IxSffz//vN1Pw2Da1dMYD
         v6vf6HXThKkCzqDLM+89NatNvdygerRGOm4yQukquQZfarP4YUmnIXmpAUmP078PLZvG
         U33A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=fsQxbAzy;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::642 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Bjkrvqy21Et1qClQODxaFvziDg6CHU2WCI4FOpuZ38g=;
        b=tvpJ/SLqq3/J2btH89DqzMYMh4DZC9w7XF5KC2+e7dLaPdgCX7azHGjIbcV9gu9Ycp
         CPPe69HZrbinjH/geVE9U7PBRdeRFKZVU4DnZxn+oqOPHOgeK0dhrVvtGtf55AswxAob
         J+UapoSKtcymyOI1GFgoOGkCi95o5EaT8SsfMYiKUdHChP/HqhUQWmiaDx5FKndwJeTP
         r10fuQjjrTqHZc5dYpFwcJKED7NhzIeODL4ELd8Kh/J27szyCAcu77qeMmwkm7XWRc49
         S7/ziCVYZ7dlHrxZ3OM/8nDRtUzQXzzhT/pkAyfbbRSwJxVCbo6A8VvAZCHfyPFvEmiD
         NYtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Bjkrvqy21Et1qClQODxaFvziDg6CHU2WCI4FOpuZ38g=;
        b=j0Jw4PUULr2Jel/+g3Ha48+vOXaDGNrXcA7ThuUQ87MITAfluHb77e/DrucOlnTuY8
         sjgtJLtGsDyhk1nc0nDjn55eBUvk54Bj7lkEZQihbpAfzdurme1aE3dwvOsD1594nBqG
         i42snGfxLtp0yM1L5IGfqjtlSqBdkg6GC/yHhWCdRbCScWqfEUXe8tDUbxV0sxFjrlNZ
         qL5/rm/bH/fLZWfu/3jmwMM2MoD5W774s9tr7s5epqIoNlByqKY3UQ0PH8/oXDV/UONE
         g/K/jIzbmKWxa9yUSUgMU0HCsHfJGApiySTAEAZDJYWib/w1q4957BDE22C/ghoKs8Nm
         Efug==
X-Gm-Message-State: AOAM533loWyZjZHdwZTz807c21539mFwTC65GKUoiOoe18U+mcxA798b
	x0O5hBdIC6jxQj/LDYcHisc=
X-Google-Smtp-Source: ABdhPJzxTHBKlehuZQUtsrpBkXro5ESbSmYuxnm+0Lp3aEVJLL/+L364neadsNSGe8MmhwPM7BlzPA==
X-Received: by 2002:adf:c3c2:: with SMTP id d2mr13631652wrg.191.1602225963159;
        Thu, 08 Oct 2020 23:46:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a456:: with SMTP id e22ls2613426wra.3.gmail; Thu, 08 Oct
 2020 23:46:02 -0700 (PDT)
X-Received: by 2002:adf:e6c4:: with SMTP id y4mr13230016wrm.423.1602225962069;
        Thu, 08 Oct 2020 23:46:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602225962; cv=none;
        d=google.com; s=arc-20160816;
        b=z3i3LpOAyw/0/CtGUSt2hiwpvKXf4A2mp/kJdSvIlGkkMzj631kO0qdfbnUUCrtW17
         BXAuSEww7e1454KpYjtszN5ouTwe9pXixN4G6OAwCvB+OGrz9izVQO0qzAtS/4l4IZ4q
         4Bt8NyE6k8gd1fDL9s+4JCoLrjlcRFoeVqZsRm1St5BQfW73AfVbqE5g/TsWt8lzQX54
         yjsokIqS2DAHCk69k6ugUpLEMapjmapTrAyKRnvsd/BemNPxvI+lrwE6xrakYpS7x8Nc
         JtTNw5XuH+JZvwsZ+3/069QIkKK12qqZOeWeoudKp41dqv3YM+u59a7dxCBT98GVDod/
         v3Pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=70XPomHxMoYYRMOMdOG6A/Tz50BhoxBCD92mGRCZip4=;
        b=JaPI6I6PUJKyOAwdmDYSe/PXBxrDzRKZSMWiVZi2ycCnzeeHAtV518rmzqBVgwxqCU
         Rag+Ac80Iqx/RKCHOJG/At2JIuc9D6JfGfFobVTFy3HDmIs87CXCXomKMm45zYZWokj7
         O+d5HAsH0m6CQLDhuk56OI1XTKl0sRhehlAAoeDJKQQxYqdOoPR++c+OH5r2TtYFiDb0
         PMYaEGq3fqBnHBbdrcl/gB3SKu6M3c5r3sT3NpzE1z0T8RGFXayZ55Okdv3MNldLDSD7
         G2bStQItT/i7R3cCeFqR3lFxHRqraxI4xsYNy7lrIxkA1duy6KjyYymTA9Cg9CfcvbVr
         zBMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=fsQxbAzy;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::642 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-ej1-x642.google.com (mail-ej1-x642.google.com. [2a00:1450:4864:20::642])
        by gmr-mx.google.com with ESMTPS id 63si177860wrc.0.2020.10.08.23.46.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Oct 2020 23:46:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::642 as permitted sender) client-ip=2a00:1450:4864:20::642;
Received: by mail-ej1-x642.google.com with SMTP id qp15so11536064ejb.3
        for <kasan-dev@googlegroups.com>; Thu, 08 Oct 2020 23:46:02 -0700 (PDT)
X-Received: by 2002:a17:906:8295:: with SMTP id h21mr4648133ejx.278.1602225961802;
        Thu, 08 Oct 2020 23:46:01 -0700 (PDT)
Received: from gmail.com (563BAB65.dsl.pool.telekom.hu. [86.59.171.101])
        by smtp.gmail.com with ESMTPSA id o13sm5769383ejr.120.2020.10.08.23.46.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 Oct 2020 23:46:00 -0700 (PDT)
Sender: Ingo Molnar <mingo.kernel.org@gmail.com>
Date: Fri, 9 Oct 2020 08:45:58 +0200
From: Ingo Molnar <mingo@kernel.org>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, elver@google.com,
	Peter Zijlstra <a.p.zijlstra@chello.nl>,
	Thomas Gleixner <tglx@linutronix.de>
Subject: Re: [GIT PULL kcsan] KCSAN commits for v5.10
Message-ID: <20201009064558.GC9972@gmail.com>
References: <20200914175133.GA14094@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200914175133.GA14094@paulmck-ThinkPad-P72>
X-Original-Sender: mingo@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=fsQxbAzy;       spf=pass
 (google.com: domain of mingo.kernel.org@gmail.com designates
 2a00:1450:4864:20::642 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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


* Paul E. McKenney <paulmck@kernel.org> wrote:

> Hello, Ingo!
> 
> This pull request contains KCSAN updates for v5.10.  These have been
> subjected to LKML review, most recently here:
> 
> 	https://lore.kernel.org/lkml/20200831181715.GA1530@paulmck-ThinkPad-P72
> 
> All of these have also been subjected to the kbuild test robot and
> -next testing.  The following changes since v5.9-rc1 are available in
> the git repository at:
> 
>   git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git kcsan
> 
> for you to fetch changes up to cd290ec24633f51029dab0d25505fae7da0e1eda:
> 
>   kcsan: Use tracing-safe version of prandom (2020-08-30 21:50:13 -0700)
> 
> ----------------------------------------------------------------
> Marco Elver (19):
>       kcsan: Add support for atomic builtins
>       objtool: Add atomic builtin TSAN instrumentation to uaccess whitelist
>       kcsan: Add atomic builtin test case
>       kcsan: Support compounded read-write instrumentation
>       objtool, kcsan: Add __tsan_read_write to uaccess whitelist
>       kcsan: Skew delay to be longer for certain access types
>       kcsan: Add missing CONFIG_KCSAN_IGNORE_ATOMICS checks
>       kcsan: Test support for compound instrumentation
>       instrumented.h: Introduce read-write instrumentation hooks
>       asm-generic/bitops: Use instrument_read_write() where appropriate
>       locking/atomics: Use read-write instrumentation for atomic RMWs
>       kcsan: Simplify debugfs counter to name mapping
>       kcsan: Simplify constant string handling
>       kcsan: Remove debugfs test command
>       kcsan: Show message if enabled early
>       kcsan: Use pr_fmt for consistency
>       kcsan: Optimize debugfs stats counters
>       bitops, kcsan: Partially revert instrumentation for non-atomic bitops
>       kcsan: Use tracing-safe version of prandom
> 
>  include/asm-generic/atomic-instrumented.h          | 330 ++++++++++-----------
>  include/asm-generic/bitops/instrumented-atomic.h   |   6 +-
>  include/asm-generic/bitops/instrumented-lock.h     |   2 +-
>  .../asm-generic/bitops/instrumented-non-atomic.h   |  30 +-
>  include/linux/instrumented.h                       |  30 ++
>  include/linux/kcsan-checks.h                       |  45 ++-
>  kernel/kcsan/core.c                                | 210 +++++++++++--
>  kernel/kcsan/debugfs.c                             | 130 ++------
>  kernel/kcsan/kcsan-test.c                          | 128 +++++++-
>  kernel/kcsan/kcsan.h                               |  12 +-
>  kernel/kcsan/report.c                              |  10 +-
>  kernel/kcsan/selftest.c                            |   8 +-
>  lib/Kconfig.kcsan                                  |   5 +
>  scripts/Makefile.kcsan                             |   2 +-
>  scripts/atomic/gen-atomic-instrumented.sh          |  21 +-
>  tools/objtool/check.c                              |  55 ++++
>  16 files changed, 677 insertions(+), 347 deletions(-)

Pulled into tip:locking/core, thanks a lot Paul!

	Ingo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201009064558.GC9972%40gmail.com.
