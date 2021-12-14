Return-Path: <kasan-dev+bncBCS4VDMYRUNBBT5J4SGQMGQEUCXFRSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 49149474D7A
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:00 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id t9-20020aa7d709000000b003e83403a5cbsf18245434edq.19
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519440; cv=pass;
        d=google.com; s=arc-20160816;
        b=ldDWrxZnMYq4DxigSYaTGZ1+kjpIWRHrAnt9mIKBhBxLjM/kNEVEH64bj9eOZeMWyN
         OEtb8+w7ww2/W3dDJAoiwpYFUHQLLm1JkY0RJkYns6ptfay84FIDcUVMFETMvx/pMkXK
         Mo3zsEXd168lCFJygRkFNeL+n+ofRIgQMZk35VfPJHSdko5vX8HTLSJqxImCDKlN2rdi
         AVE5Mh79KzZY3E7KjHuuf6v4oj1Gd1XbdaDcQbhl6CyYwWvsiTfGu/PHF5LrmzpGyLki
         0JEfy9egTfqBLRlDCT3L5uAo1Rsou79WlRc3l49MaRTvzXnqyjkcqgStODb+lBPey18L
         F7rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=GfjKDZ5abh3CHR/C814lOZl3wWnzUnY551iUxc1aeC0=;
        b=pq2Zppoa20VjDr+aBSQbIB6TP4Z5rss5oNa7WnWohyQfIkBeWlCqezTAVSh997Y1sw
         8jqURLfj75zYs6zDnk0a/i2PyUvnO4R1pcrVX7466V8iswlHfslIPmSPMpENF0mhbfQP
         Si0iZu4IktfMkUMw1pVuK+Rb11wqdcJGsrC/naCRVrYSLv871Zy1bOLZAy4y2HAUvcKj
         xDXSEJ16s/9/PS4I7San59GmJp2CEZRZvmgXYHpDNqzIzDVEl9/NalwsZRP0NPRQzDXE
         MpLwtVqKj7IZ2b4+q0EeHMh1yqTNqFzkdnfb0BoLyldzCq7+52bSVo/EYL6s2RbdQjf1
         DuoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qE8zVxAD;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:mime-version
         :content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GfjKDZ5abh3CHR/C814lOZl3wWnzUnY551iUxc1aeC0=;
        b=ady4Cc88l4uAmRJVIrcI4mziQwvhfiCPaabacYaO2A3hBcVFGSkuEKZ+X65Z88rSeW
         yS0GtvYwdGN2ARoSbckDNPC+dXfpZ9DE2cGBryL/xI3mR3OKw0X9b6Ogd5Xz8szMZQTW
         LGf0/CXiLDqsIY/bm2Z50rqHU1dTaAeF5854mXJ3hBm4mhsoEjHCSCJpKCBicgr6fKgv
         RxKKf15G7C/dMfs6wY/skuBdJ0CGc3Ys97MmnktRxTYwY0dyV7I1MU8iGKDSbVA7kGmV
         JpGPIda20O2O/hPgd7WFG1xFUVcsHAkRoeipcNt2PYl9IL6np5B/Vdsy5JFFu0+W1d2O
         QvXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:mime-version:content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GfjKDZ5abh3CHR/C814lOZl3wWnzUnY551iUxc1aeC0=;
        b=5ipWnKou3qP7iJZYoVW+2OzxquqX1mkH8mGoEba+d3vu+y+EqlYGzdIzzWq3nADrCT
         OGlNm21iQXqSNR6S1Y0hYaU3zj5l9Zl6szcZJ1LdEd+qMeAq48b6CL50z9yKaBckUK/w
         61dO5MokxwryhEKuQKDVCauS+omeY1CERHoiZWmpGGdLi7TGllwS6XZim68xBn+VsU87
         gCImeAr8zQlL3Oe2sI1lo3QR04F5DyKDco/9ZJKsbI7xUtnI0e3uB1yLBqvQYj5D9tcm
         z7cUMthd/URss2pwI91OSR0j3gFubEUxMVqjVBgLHGsHbicDKY83n8iTj4frj5rGsl9c
         zXqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531BqRIup/G4HJ5wBeJv4LTaGwp0QNbK0rYueeVRi+cn5Ci9w9fE
	4Sf1/aBOeujCIpZdKOGUXKY=
X-Google-Smtp-Source: ABdhPJzvJ1QOUfuueu3B+XSohAMw4p8i0SspmFw25UlOWL2KS7Dr7Vr/SqlqJ8z1MrVS6IYhhoe8Xg==
X-Received: by 2002:a17:906:955:: with SMTP id j21mr1865675ejd.221.1639519439879;
        Tue, 14 Dec 2021 14:03:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:6283:: with SMTP id nd3ls32674ejc.0.gmail; Tue, 14
 Dec 2021 14:03:58 -0800 (PST)
X-Received: by 2002:a17:906:b011:: with SMTP id v17mr360703ejy.495.1639519438751;
        Tue, 14 Dec 2021 14:03:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519438; cv=none;
        d=google.com; s=arc-20160816;
        b=fYKyksdDrmoXTcCEPWWSaDY18K8kue5iJyJ6f7N4TqUvBdF41dO7Sxdv+kpJmgMIM4
         f/Onn55qsMcoR4cyU4LqzY7Fh3j/hSRjV+wN0eiSME6XfKHrGYsZhMka/WvNcxnWNRJQ
         9pyFrQttGFqQ+/JR0YtSoVzfvrqJcb04UsIAWK1uwGoUpzTv4CHF31bj4Uqbh1ce8Ypg
         wp1uXz9y/U3iFs5StzstDV22/M3+NEkIM7JhxNnDvhkrNT1GcuZLEKLW2AeF6C7YBXTg
         WNSXNbIJFxGa+Tm3g82kq7NZUOD0cEpCBsH/6W3YeFCabfSkVZmKyj8H7UaWuFoqv1fG
         KI+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=VXYF/oIWEURZagCykfhgrRzqP4pH/2T/pXVQJ1ZHwoE=;
        b=lkH1odQNdvdhdIsWs6CFBc+MfMIk3Jp3B4vWgRsQVxAAXkxvIqMCZkRfG0aEEiJYoq
         R0i4EFmTfffSQiceMd3d/gh6XUC1LRwVCUzYJvy6/eMM1plXX9O2NHFFrmJHwJcnSI3+
         PC63ein7ChGJOHku97q3f8JLsizuquHVqTvGgxJtZnIEH5++fTqXx1/COUjk3HRg4lgG
         k4se8bLSmrwA49ca0Ji34eZw31I6nIci+ZlSIOX6z0MnPBTEvI+kPIWWUf3O+f0bBLic
         SLz4sWXg4TnwfXYxk7/0XoqFQwNRg9FCT+ScDMRorjCBUkQRTEC/zyNdqqTfnJDvL5Cv
         gYUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qE8zVxAD;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id dk14si8053edb.4.2021.12.14.14.03.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:03:58 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 7F10A6171C;
	Tue, 14 Dec 2021 22:03:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E1A42C34600;
	Tue, 14 Dec 2021 22:03:56 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 84BFF5C03AE; Tue, 14 Dec 2021 14:03:56 -0800 (PST)
Date: Tue, 14 Dec 2021 14:03:56 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, mingo@kernel.org
Cc: elver@google.com, andreyknvl@google.com, glider@google.com,
	dvyukov@google.com, cai@lca.pw, boqun.feng@gmail.com
Subject: [PATCH kcsan 0/29] Kernel Concurrency Sanitizer (KCSAN) updates for
 v5.17
Message-ID: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=qE8zVxAD;       spf=pass
 (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

Hello!

This series provides KCSAN updates, courtesy of Marco Elver and Alexander
Potapenko:

1.	Refactor reading of instrumented memory, courtesy of Marco Elver.

2.	Remove redundant zero-initialization of globals, courtesy of
	Marco Elver.

3.	Avoid checking scoped accesses from nested contexts, courtesy
	of Marco Elver.

4.	Add core support for a subset of weak memory modeling, courtesy
	of Marco Elver.

5.	Add core memory barrier instrumentation functions, courtesy of
	Marco Elver.

6.	kcsan, kbuild: Add option for barrier instrumentation only,
	courtesy of Marco Elver.

7.	Call scoped accesses reordered in reports, courtesy of Marco
	Elver.

8.	Show location access was reordered to, courtesy of Marco Elver.

9.	Document modeling of weak memory, courtesy of Marco Elver.

10.	test: Match reordered or normal accesses, courtesy of Marco Elver.

11.	test: Add test cases for memory barrier instrumentation, courtesy
	of Marco Elver.

12.	Ignore GCC 11+ warnings about TSan runtime support, courtesy of
	Marco Elver.

13.	selftest: Add test case to check memory barrier instrumentation,
	courtesy of Marco Elver.

14.	locking/barriers, kcsan: Add instrumentation for barriers,
	courtesy of Marco Elver.

15.	locking/barriers, kcsan: Support generic instrumentation,
	courtesy of Marco Elver.

16.	locking/atomics, kcsan: Add instrumentation for barriers,
	courtesy of Marco Elver.

17.	asm-generic/bitops, kcsan: Add instrumentation for barriers,
	courtesy of Marco Elver.

18.	x86/barriers, kcsan: Use generic instrumentation for non-smp
	barriers, courtesy of Marco Elver.

19.	x86/qspinlock, kcsan: Instrument barrier of
	pv_queued_spin_unlock(), courtesy of Marco Elver.

20.	mm, kcsan: Enable barrier instrumentation, courtesy of Marco
	Elver.

21.	sched, kcsan: Enable memory barrier instrumentation, courtesy
	of Marco Elver.

22.	objtool, kcsan: Add memory barrier instrumentation to whitelist,
	courtesy of Marco Elver.

23.	objtool, kcsan: Remove memory barrier instrumentation from
	noinstr, courtesy of Marco Elver.

24.	compiler_attributes.h: Add __disable_sanitizer_instrumentation,
	courtesy of Alexander Potapenko.

25.	Support WEAK_MEMORY with Clang where no objtool support exists,
	courtesy of Marco Elver.

26.	Make barrier tests compatible with lockdep, courtesy of Marco
	Elver.

27.	Turn barrier instrumentation into macros, courtesy of Marco Elver.

28.	Avoid nested contexts reading inconsistent reorder_access,
	courtesy of Marco Elver.

29.	Only test clear_bit_unlock_is_negative_byte if arch defines it,
	courtesy of Marco Elver.

						Thanx, Paul

------------------------------------------------------------------------

 b/Documentation/dev-tools/kcsan.rst                |   76 ++-
 b/arch/x86/include/asm/barrier.h                   |   10 
 b/arch/x86/include/asm/qspinlock.h                 |    1 
 b/include/asm-generic/barrier.h                    |   29 -
 b/include/asm-generic/bitops/instrumented-atomic.h |    3 
 b/include/asm-generic/bitops/instrumented-lock.h   |    3 
 b/include/linux/atomic/atomic-instrumented.h       |  135 ++++++
 b/include/linux/compiler_attributes.h              |   18 
 b/include/linux/compiler_types.h                   |   13 
 b/include/linux/kcsan-checks.h                     |   10 
 b/include/linux/kcsan.h                            |    1 
 b/include/linux/sched.h                            |    3 
 b/include/linux/spinlock.h                         |    2 
 b/init/init_task.c                                 |    5 
 b/kernel/kcsan/Makefile                            |    2 
 b/kernel/kcsan/core.c                              |   51 --
 b/kernel/kcsan/kcsan_test.c                        |    4 
 b/kernel/kcsan/report.c                            |   16 
 b/kernel/kcsan/selftest.c                          |  141 ++++++
 b/kernel/sched/Makefile                            |    7 
 b/lib/Kconfig.kcsan                                |   20 
 b/mm/Makefile                                      |    2 
 b/scripts/Makefile.kcsan                           |    9 
 b/scripts/Makefile.lib                             |    5 
 b/scripts/atomic/gen-atomic-instrumented.sh        |   41 +
 b/tools/objtool/check.c                            |    4 
 b/tools/objtool/include/objtool/elf.h              |    2 
 include/asm-generic/barrier.h                      |   25 +
 include/linux/kcsan-checks.h                       |   95 +++-
 include/linux/kcsan.h                              |   10 
 kernel/kcsan/core.c                                |  302 ++++++++++++-
 kernel/kcsan/kcsan_test.c                          |  456 ++++++++++++++++++---
 kernel/kcsan/report.c                              |   35 +
 kernel/kcsan/selftest.c                            |   22 -
 lib/Kconfig.kcsan                                  |    2 
 scripts/Makefile.kcsan                             |    6 
 tools/objtool/check.c                              |   37 +
 37 files changed, 1389 insertions(+), 214 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220356.GA2236323%40paulmck-ThinkPad-P17-Gen-1.
