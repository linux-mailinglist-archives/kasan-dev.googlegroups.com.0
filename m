Return-Path: <kasan-dev+bncBAABBWGZ36JQMGQEG2PA2DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 65BFB51EEE2
	for <lists+kasan-dev@lfdr.de>; Sun,  8 May 2022 18:16:26 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id z34-20020a056a001da200b0050e057fdd7esf3756860pfw.12
        for <lists+kasan-dev@lfdr.de>; Sun, 08 May 2022 09:16:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652026585; cv=pass;
        d=google.com; s=arc-20160816;
        b=qA1cEhf2FoQ4BpvspetVlAtRdFdFcz3qDRiPlECKh3czIcOF0WIPUCkxJiStZSLoUc
         0Wx2k+tY+Zw5en45feQ08jiPEjj3+484kuKv5Ylmd/VLglBfhJWN8+VLQR5uMR0zWfZg
         vhrgzSILVvaiBQnVI9D0qb9zG/1bWjFL1s/waxdb+dPF7Dl49WXKgcs8GgYchQMnblFv
         aSw/9ZuAJomsquUd9Pal8p6fRhq7Xpciniz+sCApjzMd2rrRlHXmjJIs6IJCXJenEdXK
         hqVNhjcxcSmkWQKAG4UpoxtP9GI93eY2+3x5K+cOCQoR3dKUOLcUpTanb/O02q3uUBRz
         D6AA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Z0wfZ+wS9IatD8pIw+SSjd/HIlnpwlZHYhqMLu4LTEg=;
        b=YgFmzAzQLwOaw35481E98Urmq3zL593/XZhUSu1fRLAvLBisxV3k+3t02ECDYpqHzQ
         ooDfYqJSf+NsLYNqtUeNyw3/azwuABN44Y0NYjS/lds6q4sweWro/1gdP+hUBZsYVUhj
         L5WM7Aq6Ua1uhJ7Te+vXNQZ4G38AiRf/vWPjot8LGd2UEvA9et/llThwPsV0IQ0FteHI
         ORbKjEHgApiuI4K5upbFupJu7X0lJ1KdnmYBxiPVwA4MzqIe91m7gmr8yKtxOq+dUZmj
         iBFDRsMIt20uxaprOMQ/YypY0yAuCz3Mpe/mHd3nHSFHukO1eCE2qR5MheRZz+BvsKIB
         Fz7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JGdlu0gL;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z0wfZ+wS9IatD8pIw+SSjd/HIlnpwlZHYhqMLu4LTEg=;
        b=KA86UDgmRtppboH2BH5UqH7J43hRhtX5ryE1JFaxsWXNdJJ3YfNei9lkUqP8MKOaNA
         ahFBsZccpe4eUwQhYRSm+6ajGrFDwKMDibV+1d4pna5TKCp3+wWnMg5zyHE2WhPcQhfz
         1DoC0salU7fKMGCZ912N6ZPJtrEN9IkUApHzMSJMrJNVtfsGaPLh1SRnl3l4+MN/I1vs
         ZehF9zAKHcSn5tPa6DAwLk9qrZjMsLWkPaY3tbIkcSMwKG+nSU6SJyN0d/04jHW2WZts
         KujbZb7BbVyt9GY9ql1f1rZC/nMK9lbvlgH4NXBMWzqMjheqo94LSVAzrgUiaWWer8ag
         HITA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Z0wfZ+wS9IatD8pIw+SSjd/HIlnpwlZHYhqMLu4LTEg=;
        b=kQggD9lh+DNnEO4Kggb8a/TEJ+M9fU1Gds1KNipl3wh4Jgq+UFEZeGNYHSMjTIXpzo
         cfo/E3yK/6XWZoSoPIm5vOluAX07e6Qxfu1mh/KO7AhRDgNBm0sDY5YNbPGou4xLCsjO
         U7vj7AZtjUroge7LtUx2cVxVeR5q/lr/mFm8+Jri6oxmbZ+sifnojfSbCWHoG3KzwCMQ
         iQPu0YzAxL2RDQJvbmSGANfzGYL7z6/1TGX0I2iAMpsegcg9JODjeEPzEHff9pGATmzs
         nw3fkO+yhBGDAvYJCTuWfSMAsTi4VHOxYmNQIuoph1K6eHCXjYS9NHfaa3+vvL5/LQi0
         /E/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531PHp6ci0Kdgy0aq5aY9zQXU6wYcMUHEAR/JRPESxr5KarjqQ73
	iJkDT4enQ8GI6C55/+kw5Y4=
X-Google-Smtp-Source: ABdhPJy0UK7LAcrWAkocSbG+Ne6cQ0/DcabDi0IOHUhIFSVCABPiK9Ko475Ag9FDlLs9M13S6ZM9Bw==
X-Received: by 2002:aa7:84cf:0:b0:50d:d25a:5d37 with SMTP id x15-20020aa784cf000000b0050dd25a5d37mr12524642pfn.84.1652026584849;
        Sun, 08 May 2022 09:16:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:b90:b0:510:7b21:1280 with SMTP id
 g16-20020a056a000b9000b005107b211280ls3310205pfj.7.gmail; Sun, 08 May 2022
 09:16:24 -0700 (PDT)
X-Received: by 2002:a63:5551:0:b0:3ab:84c3:1a0 with SMTP id f17-20020a635551000000b003ab84c301a0mr10279332pgm.604.1652026584392;
        Sun, 08 May 2022 09:16:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652026584; cv=none;
        d=google.com; s=arc-20160816;
        b=MJYZYpNiDXug9+ctaP7E8AI8Ehk14go+QvyjYLKS/k6+Ba0OBGhJr8pFSihAwEwgqa
         OVaUBbu+ssBdAP/tPgU++79eLgKNCYbzGLrdg8MAa9d6JgWTKktWhxmSPSd4Y7nSptBj
         Xig6qYH6WTfvoMHQAqew2uQzMvjQwdFiK0yRWr15UPDsj9fV4Wa00pPXewLY/8uJl5fw
         H7oi/9HIJMf0u5ABKGssbAXmVBIMZGPCjHsFV/5IgsxbKXWB91CoFkQTYyJyxAyDkmqX
         S4P+fU4pCwV7CrOclXoyoYtvNVkeZfUMow1YBfYRWoK2LHAJh82uv+dvr6/oQ5gEmsVU
         D3xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=B19DiMbLsCNNTRla+mHgo37faAgif0bXsP1qBO+fYf8=;
        b=sMeM3dV01koMHQIxJCHYRql5bErh8HeDY5KQNH4VuSHW5+AtrHsS6YLzr9O10MzsOu
         J7M91cbftLVGxA28D5JuG+lVUSNR8ToHZ+c0VAw7cVYwkhmZ+8Wblfctt/PaFLLtaml6
         j0OHH39/72W1V7SKNdzeES7m66xSKHhNwvis+KqUvnXmOoKUbZt86hODuhAo0G+1EPem
         DgjAQJJ4KAu5N2KjwkcEEZipLVILR7FJDMop/3lkUpy2ObqiKpCaftnH/RJD9i3HOqxn
         5WwzbZeBjZV2tzANNDGuNcsJup4paUO+oz7/KEJwdih46DGa6RDbWWftrZseOeBOiOWc
         tcKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JGdlu0gL;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id m1-20020a17090aab0100b001cb5c591f9asi966723pjq.1.2022.05.08.09.16.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 08 May 2022 09:16:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id CB41E611F3;
	Sun,  8 May 2022 16:16:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D21AFC385AC;
	Sun,  8 May 2022 16:16:15 +0000 (UTC)
From: Jisheng Zhang <jszhang@kernel.org>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH v2 0/4] unified way to use static key and optimize pgtable_l4_enabled
Date: Mon,  9 May 2022 00:07:45 +0800
Message-Id: <20220508160749.984-1-jszhang@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=JGdlu0gL;       spf=pass
 (google.com: domain of jszhang@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=jszhang@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Content-Type: text/plain; charset="UTF-8"
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

Currently, riscv has several features which may not be supported on all
riscv platforms, for example, FPU, SV48, SV57 and so on. To support
unified kernel Image style, we need to check whether the feature is
suportted or not. If the check sits at hot code path, then performance
will be impacted a lot. static key can be used to solve the issue. In
the past, FPU support has been converted to use static key mechanism.
I believe we will have similar cases in the future. For example, the
SV48 support can take advantage of static key[1].

patch1 is a simple W=1 warning fix.
patch2 introduces an unified mechanism to use static key for riscv cpu
features.
patch3 converts has_cpu() to use the mechanism.
patch4 uses the mechanism to optimize pgtable_l4|[l5]_enabled.

[1] http://lists.infradead.org/pipermail/linux-riscv/2021-December/011164.html

Since v1:
 - Add a W=1 warning fix
 - Fix W=1 error
 - Based on v5.18-rcN, since SV57 support is added, so convert
   pgtable_l5_enabled as well.

Jisheng Zhang (4):
  riscv: mm: init: make pt_ops_set_[early|late|fixmap] static
  riscv: introduce unified static key mechanism for CPU features
  riscv: replace has_fpu() with system_supports_fpu()
  riscv: convert pgtable_l4|[l5]_enabled to static key

 arch/riscv/Makefile                 |   3 +
 arch/riscv/include/asm/cpufeature.h | 110 ++++++++++++++++++++++++++++
 arch/riscv/include/asm/pgalloc.h    |  16 ++--
 arch/riscv/include/asm/pgtable-64.h |  40 +++++-----
 arch/riscv/include/asm/pgtable.h    |   5 +-
 arch/riscv/include/asm/switch_to.h  |   9 +--
 arch/riscv/kernel/cpu.c             |   4 +-
 arch/riscv/kernel/cpufeature.c      |  29 ++++++--
 arch/riscv/kernel/process.c         |   2 +-
 arch/riscv/kernel/signal.c          |   4 +-
 arch/riscv/mm/init.c                |  52 ++++++-------
 arch/riscv/mm/kasan_init.c          |  16 ++--
 arch/riscv/tools/Makefile           |  22 ++++++
 arch/riscv/tools/cpucaps            |   7 ++
 arch/riscv/tools/gen-cpucaps.awk    |  40 ++++++++++
 15 files changed, 274 insertions(+), 85 deletions(-)
 create mode 100644 arch/riscv/include/asm/cpufeature.h
 create mode 100644 arch/riscv/tools/Makefile
 create mode 100644 arch/riscv/tools/cpucaps
 create mode 100755 arch/riscv/tools/gen-cpucaps.awk

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220508160749.984-1-jszhang%40kernel.org.
