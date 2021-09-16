Return-Path: <kasan-dev+bncBCJZRXGY5YJBBX5ARKFAMGQERL3W3TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0071240D0DD
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 02:31:29 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id r3-20020a0cc403000000b00377a3318261sf23027093qvi.11
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Sep 2021 17:31:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631752288; cv=pass;
        d=google.com; s=arc-20160816;
        b=gYy2x7oq66xCFPkvwhrpHqXN0YhjH4knYqtjN6n0HSAMx+nyHA/CwJGcABG0rXU/SO
         dq7x/FaQMTL30pWpTujGNU6tw9EzISMB75tbzjp/dZO1WiazNX+Kk2ht69WpB9GIM7eU
         SFdzHggMMoHqb4dINRoJeaF7VomTVe87KLwTplmWD6lJ0L0XZBYsGqhIe5Oknd0t01t3
         WRAvCapYWZVf0JCy6UgTkMG642eAO85WZnrrX1phCV8BLwTmbVqxQnuJNUQkBW+vcyc1
         wVrQ2Aj6vQ//JwPhtOw2LywUalduVhffRDtdF6m4pD1mzxR2hrNdyVUMwkf7Y3muUSU4
         e8Jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=U/lYda0PkNT6We1A4htWVEnycPd2qwC9O8g3TgHqEA4=;
        b=gJ6jpiEi0G+OtkUS62AOY/ew/XmdkIkOJnf/md4PvgyDPC7cV56/TAY2ZpV0Ii2YcQ
         sjWDYhxPPcFtDf934AN5h3a0mpFKicRAASoV0bPl4EQIknPAHdRyuM4sAWAyvicVsYXI
         +6nGXUVm9U3JZJDCx5mXjP4nIpExkX9gTxMZdeSCy9qOYEcw/meVAQINVQO6RsB8f6eZ
         Uz34B8n+ozfb2dSwhifSPj1RsmTh0dwlXEdPRUtHJ7KpBoISfK4fm7ysCIOLaKyGZnTd
         uxt8SB5xmhTNjOUd4muYrbbz0sGDLF/nF/xqj66ee+QY/bhfkSfGrB1EIUmUiE9q9Ofq
         v/bw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hghhs7SM;
       spf=pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:mime-version
         :content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=U/lYda0PkNT6We1A4htWVEnycPd2qwC9O8g3TgHqEA4=;
        b=QNgs6WQnDozKL2XBHmsMIrV+QKlLhHx1ZMIub2HArbnmTTD7nCUhigoz+MjRqa8YRL
         Ik3BvGYRFIU0jBfBIVy5A/hbf/uwKFdSepKhTrgQ5DXTC/ncYdgPF49xTnjf8aHiYEEz
         GLo3f6OXf0RdzQKRBQ8vtLKn/ICFl8+YNdRQjMyxXovqcACDXtbpJ3U5ZxPYOzZ+Mn2t
         CUOOdc9cWD3L2Wi6z53n0nEbftBZ0DwaAgwYUbtEQi7r4iQ1CBHifQqrIFSaWOUJI594
         BxE8lP9MkcVsumZdpDjlTH3aJgWOUNPyxgaD3qdHPI5IRrMTR6Y02O384GtN5iiNHwpf
         6h9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:mime-version:content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U/lYda0PkNT6We1A4htWVEnycPd2qwC9O8g3TgHqEA4=;
        b=B23UVGZ8Pi9+idyykuuEmJNJPVHWmlsVXY+81d4Qg/GW/J69OhvC7+BwdiyDxdlstm
         Xy/nmzPwa+FCVIj/X6PUc4Z4MVB8A/g3nW/cu63XcF7xF0h8b1n1o2oY3TsioNy9+ICK
         ryxqd8Q1oPKUAg+qstJ7UCfWyk9OqOoLGvLfzhaQD6ezuNhgz/MHNY/feoif69Pe8kW7
         cGHhif+a0baIcJ4fkzzyKCs/cnO5fDZkFizOtFoS0W/yDrYn6aUe074+LFB+yvVj/7LI
         rHLdZJlvq1rqOtnLuRay6TOu7uqYcCTDAFMFekNv5ADtLfUoeKQg4pSgNnGCai0MqVHA
         34qQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Rx+NgwWzYxMEWISWHwGC7uyI8ufKTsrxxCgZtzyj4MNHYjZeW
	S7hTK8q/EB2/zl/k1Mkrxz8=
X-Google-Smtp-Source: ABdhPJzKt7yf2sYNzBnHtd+b7UsV4diy3bLgLyuF9ZoeFjFvYvYzGOoFc6zTW0B8jpY02Jy/diOf4Q==
X-Received: by 2002:ad4:5554:: with SMTP id v20mr2651710qvy.16.1631752287891;
        Wed, 15 Sep 2021 17:31:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e014:: with SMTP id j20ls812981qvk.0.gmail; Wed, 15 Sep
 2021 17:31:27 -0700 (PDT)
X-Received: by 2002:a0c:8064:: with SMTP id 91mr2832970qva.66.1631752287453;
        Wed, 15 Sep 2021 17:31:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631752287; cv=none;
        d=google.com; s=arc-20160816;
        b=qVIdilPMsxcOsTJrj55Cn6rgIW34+A5jmAVHEtj7UOlLvCx1Qd/BF7LmgCdsSdB3Ih
         virMx+bZC3sYnjejrrRH5xDeVfjWasTyhnDuSNT7ZLxaZSSD2q47kvj0VVbSDD0/EKf7
         NrfOS2wEe6SmehhFroO1Pz+dVUsclaY94UM772yzutaYNO+ktjpin80oCot3NE/bEObY
         RS81H6WT8rjwXK/ThujwrJESUwFhL5lU2dg4ouWm5L6wKmrarQNefLlROko5amFJIUIX
         D/9dqEwlrKHarxSzdMBrd0wbXh2q34aSB7ejI/QAjeCi/Kmwky5g11lZxRfpaGphmWPa
         lS0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=3jcAJRf5e942OxCdJBbR8wtn+421NBAbIs5/nETyxgY=;
        b=FDk2bgNp492I83Xsk/mpkYWMW9WORKn4jkwbF6b51AVm+/n1h4r0ARbDl4NRDwHmvX
         zenDITy7kqcW6bV8xt9ocX5WIo15Wp1zDUpOoKFI9kzei1ye2MEyYV1Zu2Imu64Xm/f3
         F2EYYxEYKYtyOqqx/7Nms9fr5QCxPaKp0TPv2N3fH2zcLAVo1V30P4ncR3CH4onjj9q3
         3nviyObvkaFTGvMG8l0gesiNoeGgqvKIt9o7vXrNCpzkGjeYA0UbYsIeybOmrdZI6Ace
         /PXoWcqhar+kESZKpGmCppN7o7NlXjY7Vbn0jLzcJFhjdXe8t3uL0DXzmHjNb8vqnRBn
         9HLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hghhs7SM;
       spf=pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g18si284741qto.2.2021.09.15.17.31.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Sep 2021 17:31:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 90D70610A6;
	Thu, 16 Sep 2021 00:31:26 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 6325F5C054E; Wed, 15 Sep 2021 17:31:26 -0700 (PDT)
Date: Wed, 15 Sep 2021 17:31:26 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, mingo@kernel.org
Cc: elver@google.com, andreyknvl@google.com, glider@google.com,
	dvyukov@google.com, cai@lca.pw, boqun.feng@gmail.com
Subject: [PATCH kcsan 0/9] Kernel Concurrency Sanitizer (KCSAN) updates for
 v5.16
Message-ID: <20210916003126.GA3910257@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=hghhs7SM;       spf=pass
 (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

This series provides KCSAN updates, all courtesy of Marco Elver:

1.	test: Defer kcsan_test_init() after kunit initialization.

2.	test: Use kunit_skip() to skip tests.

3.	test: Fix flaky test case.

4.	Add ability to pass instruction pointer of access to reporting.

5.	Save instruction pointer for scoped accesses.

6.	Start stack trace with explicit location if provided.

7.	Support reporting scoped read-write access type.

8.	Move ctx to start of argument list.

9.	selftest: Cleanup and add missing __init.

						Thanx, Paul

------------------------------------------------------------------------

 b/include/linux/kcsan-checks.h |    3 +
 b/kernel/kcsan/core.c          |   55 +++++++++++++++++--------------
 b/kernel/kcsan/kcsan.h         |    8 ++--
 b/kernel/kcsan/kcsan_test.c    |    2 -
 b/kernel/kcsan/report.c        |   20 ++++++-----
 b/kernel/kcsan/selftest.c      |   72 +++++++++++++++++------------------------
 kernel/kcsan/core.c            |   20 +++++++----
 kernel/kcsan/kcsan_test.c      |   60 +++++++++++++++++++++++-----------
 kernel/kcsan/report.c          |   59 ++++++++++++++++++++++++++++++---
 9 files changed, 187 insertions(+), 112 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210916003126.GA3910257%40paulmck-ThinkPad-P17-Gen-1.
