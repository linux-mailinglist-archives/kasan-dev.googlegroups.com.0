Return-Path: <kasan-dev+bncBDAOBFVI5MIBB4HPXKGAMGQEVHZSDTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 778C044ECD5
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Nov 2021 19:52:32 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id v10-20020a1cf70a000000b00318203a6bd1sf4705461wmh.6
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Nov 2021 10:52:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636743152; cv=pass;
        d=google.com; s=arc-20160816;
        b=vdYCJZoIByDtYAHGYuPNdqqyhOFc9dPyqE65EyZ7yOFz9Ox5N0Q9L/1XJEih22Pqwq
         wK/wJVmZBhxnv8ZZwELZeUwh8lmOfp7oJ6jMka2+d0Tvjmb2SQ610nN3Ih95qRb49Jmj
         T5aFuJlvgguGBOW1KAtcY3gmoM4teNv65jXxwIAF1H6qGgw8DFU//vNLOURn5t3SG3yj
         +iFY1WPtce5x4WXCOq7fq+Fx8E5QgEbTotR4h2PN0CWGj1JYaSNuSmgS2a50daY8u8pg
         PIQwjsilucTznMNcLoS2PTpBktaCV3hnhOcocCPS0WXTkM9jwYYmCigKGpdKtL6k/uZY
         91rQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=GD8WIHAjmpkFCv+zK6eMoKTuBv/e8ynClF0cxJg7Z/k=;
        b=cXohTIdzuWwm5esgSFuAk+/d/fFY6G1hFNQEfB9hlyQVGhYh7cPxg7gVTvDTC0x4Ey
         VBqldeg1FvjfuqIbmfYBtmlnWY99MeoZMg4TFA/lxETo1ZO3G2eDBG96IgJIgLlqJj1E
         H03TJz5gAZ3paNFuK4QCTRhQ2Xkiq5hG1BvOmcZzhF1W2HINx9sBvW4DU04bA8+88A0w
         8SNKZq2L+T+UI15JA1yyA7HhqVgzIM2e/2WBWfVVrPBXr1Mcj1j+y3q98C5k7ZMLnaWH
         OqZiMSyRfZnHFfD+95+5Y4U9tCacJHM8sX3ogLiBrgIdkOb/32h7LJa3LqVyyYyYgmDJ
         VUZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GD8WIHAjmpkFCv+zK6eMoKTuBv/e8ynClF0cxJg7Z/k=;
        b=tnx6dkQByp75d8wX75jQ24K/foP2eZ4NIZ92qtRwH6cfVr3gZtsh6pVVdJo/SUBc3R
         QJqDYNtssf8gtLeVRnYdKNB0EDbvEYWCC34hX08DAVTzu+lTwbpNlNP2bUvjMWXfgt2O
         ovSZg1iugZCFbzpGmk0SGY3+u/XH4OPZLTRu5NJ98LqPtbUKamd31HnYBIufyB1ceRGw
         nkLUPXR2FWnxibVsKo+ilKbBlfLtR2WZa2lF2IYGpVQYJnYC3nmrw+PeK1JWb5y18D8m
         zjARpgrLr1pHWZYFqTANl/WloPlTNYtu7A7+sV50ubZpxL08qUtxYGK6QLWRA+ulBLAG
         iUTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GD8WIHAjmpkFCv+zK6eMoKTuBv/e8ynClF0cxJg7Z/k=;
        b=PzV1URSsBFmnTvOxj6Irr6VRIqwHifYl9hWOZvNckHj/klf7QrtwgZH2vmgrGYzDf0
         0ioHgpUFrP/QMqxCw9O/ttb4gvO99e/aMUv+trVKHGpr9R6mX2yjZyUvMv3zEwGIQci8
         XcBMbSCmAJQAwTuoI+KxBlVTCaVc6jOoKJVcgZEWgRqqCxfPVsaK+i5u5pTlD75QjooT
         nYtw1Jtgl/cCswLR0q/UiCkKFY9PG9IN6wrlVQuIuJCqTKgrltQ8nEZTm1GcRS/6UFal
         1KQ2x1I/hZDNRXKVcEzkscOZ6F2soiLmeRLBfivG8YEORfeWC/hspWCoCl8458TpHWpM
         loJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533KoHivwAJXSKccfdLuCPxownfBh2OiqwiroVG7gW1hpc7tjGB0
	Dtvqihnj+S8ge1xixNg0d0s=
X-Google-Smtp-Source: ABdhPJwUKobDE0G+QmEgXLickHaaiES6LC0udUyilRiznrpcjnTxlpLvpAnE7iEfZmJoKg7EXIAutA==
X-Received: by 2002:a1c:4681:: with SMTP id t123mr36657283wma.83.1636743152199;
        Fri, 12 Nov 2021 10:52:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4092:: with SMTP id o18ls2127612wrp.1.gmail; Fri, 12 Nov
 2021 10:52:31 -0800 (PST)
X-Received: by 2002:a05:6000:4b:: with SMTP id k11mr20462979wrx.86.1636743151300;
        Fri, 12 Nov 2021 10:52:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636743151; cv=none;
        d=google.com; s=arc-20160816;
        b=lM18PLi1POejf7ZGlEN5adFERry4mQ7jg22i9w79HkiO5XCJRIDXhUFHCu84OW17LC
         YaLi5eeLL7ZElGMrQxXh1D+N1/6yzB3r7TjF9jrEmN4b0ib9XoHkPKCDJWb+yByUTPIH
         JPv1A+I/E7EYDk9V6eQgKK6Evrs+xP2LKUdxIOj2OCJDchbFkJrqEa+c0Cs0Q7aKRySX
         CYfTSYlqMgy3JRwCGNX7T4rJOEqzmE32btvs3kWJRBm3+TgQvIdhXv4kxw147yGV8ip3
         b6UYQV85/Z+BF4M5pAGhVEgbAj+angXDqQKaagwkEraUStPsJ6gTZ/9Tjd2FNJA4ZCZi
         KtKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=ADWtBgES1GvSXGDQNEhvTkVdCVo4IRreKqFg/ZxjYNM=;
        b=aS3sfNJupvLLnsRG6UDdQAds5EY84/N/jlpPCX9uWYGhkwD4cQhXKWbWddc/AC5DRK
         H5KBGxFxpUCS73yNU0bDZhFgWBCeVTVrJ9PROFuaT2dykt85NvsGy0Agj9l6qH6YmX5Y
         uQTlCfO44apyq+Rek5W81lkssbgE1pxKRzsvWZ1BBsMWd4e6e919sEuvqSvQIITNHKyq
         10688bfaQ0TWq8CM44m7DqTprkr2tEd5xc1lwqcn2Uzy2NvhRJ37YFN5DePrYDRIQjNI
         wVbzHHCJTBVCZILRMEXHPJWrQKLfbrQx4Sji12Jidky9G8i7hBVHpgJOM35Uu4EvNkEP
         mPOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id o19si445654wme.2.2021.11.12.10.52.31
        for <kasan-dev@googlegroups.com>;
        Fri, 12 Nov 2021 10:52:31 -0800 (PST)
Received-SPF: pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 6A2F3101E;
	Fri, 12 Nov 2021 10:52:30 -0800 (PST)
Received: from e113632-lin.cambridge.arm.com (e113632-lin.cambridge.arm.com [10.1.196.57])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 9DB3E3F70D;
	Fri, 12 Nov 2021 10:52:28 -0800 (PST)
From: Valentin Schneider <valentin.schneider@arm.com>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kbuild@vger.kernel.org
Cc: Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Mike Galbraith <efault@gmx.de>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Michal Marek <michal.lkml@markovi.net>,
	Nick Desaulniers <ndesaulniers@google.com>
Subject: [PATCH v3 0/4] preempt: PREEMPT vs PREEMPT_DYNAMIC configs fixup
Date: Fri, 12 Nov 2021 18:51:59 +0000
Message-Id: <20211112185203.280040-1-valentin.schneider@arm.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: valentin.schneider@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi folks,

This v3 is mostly about the naming problem - get your paintbrushes ready!

Patches
=======

o Patch 1 is the meat of the topic - note that it's now in tip/sched/urgent
o Patch 2 introduces helpers for the dynamic preempt state
o Patches 3-4 make use of said accessors where relevant.

Testing
=======

Briefly tested the dynamic part on an x86 kernel + QEMU.
Compile-tested the kcsan test thingie as a module.

Revisions
=========

v1: http://lore.kernel.org/r/20211105104035.3112162-1-valentin.schneider@arm.com
v1.5: http://lore.kernel.org/r/20211109151057.3489223-1-valentin.schneider@arm.com

v2 -> v3
++++++++

o Turned is_preempt_*() into preempt_model_*() (Frederic)
  It breaks my rule of "booleans must answer a yes/no question" but is the best
  I could come with using a "preempt_" prefix
  
o Added preempt_model_preemptible() (Marco)
  Now used in kcsan_test.c
  
o Dropped powerpc changes

Cheers,
Valentin


Valentin Schneider (4):
  preempt: Restore preemption model selection configs
  preempt/dynamic: Introduce preemption model accessors
  kcsan: Use preemption model accessors
  ftrace: Use preemption model accessors for trace header printout

 include/linux/kernel.h    |  2 +-
 include/linux/sched.h     | 41 ++++++++++++++++++++++++++++++++++++++
 include/linux/vermagic.h  |  2 +-
 init/Makefile             |  2 +-
 kernel/Kconfig.preempt    | 42 +++++++++++++++++++--------------------
 kernel/kcsan/kcsan_test.c |  5 +++--
 kernel/sched/core.c       | 18 ++++++++++++++---
 kernel/trace/trace.c      | 14 ++++---------
 8 files changed, 87 insertions(+), 39 deletions(-)

--
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211112185203.280040-1-valentin.schneider%40arm.com.
