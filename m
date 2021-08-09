Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMFBYSEAMGQE2E3QDSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id F15BC3E44B9
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Aug 2021 13:25:37 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id z14-20020a92d18e0000b029022418b34bc9sf199045ilz.9
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Aug 2021 04:25:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628508336; cv=pass;
        d=google.com; s=arc-20160816;
        b=NRDVBtW9Dij1eoA8j3fPVSN/8TP7F2LMroAzIYysnlrDRtfJUDU6/70ncnjcLC/Wfx
         WjxIO3GADjO9riG+Ev8yLMObRi4dRPcB7LHfOM/FVdbEVBCM78D7xgBBFgqr2cWTB9Tu
         /MnfYC/wEzfCfMZh0uQML0JVm3xEQ2k8+nf+9CxBxM0wmq5bEyU2kdPBAg2kdzZf1qhG
         b1fOn+5hBjqKwNpTmg52AcQmXTa6JH17ZY/wOgV7twQ/zObBKSUycaF2UA6k8CezXwUK
         CbQ8YJ6MVj2ojbA5Vr4X/fdKQ081O/VauoaZoNpXtcpxZF5Wo80hyWpxnBFYwBxfD5I8
         MQHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=uifk5U8k21ts2EsN5i6JePoeIFeG4rZmhtMYOL5X7qQ=;
        b=KWLfQHwEViAqg2/PPGfaGdaoYP/ip2bsWDsg1v6KDns6y8+vrevOUDUsEt5r3sKTfb
         h2qBKXhZtDhef0Gr+5J7V4zwC4HKAMq1quqC/bfsanSwm/A7aakLtYMGvvML8TrpeaKV
         EwFg9YbLU+bOUhn8qd0OfWZx5OUpzuyf9hCzL1z0zEoNaeHfPt9xYuXAiMiduJSOIJUT
         NihjDyMjhoR3H/ti56t0H/rmNUiGpNVW1Ajx4fMFd8Z8NEQxqwk31NEw/CHcx8MBExmq
         CNhVKwMrE1d+duykcFUbpEWJMcx7JVm5nk5PbSl6O3VXSQ5lwLOcWqkdOfVyAf3UG2WU
         cdsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OEtXS1km;
       spf=pass (google.com: domain of 3rxaryqukcsqelvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3rxARYQUKCSQELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=uifk5U8k21ts2EsN5i6JePoeIFeG4rZmhtMYOL5X7qQ=;
        b=rgjQ9rg9fKHx2tkWdHTXROcNWwYEhV1sO3HbW/N1tYObsJJviMNLcMWnWfk+sYXMbI
         kLIVZJsg8ZA0tkn6AZ25f3Z21OFJrbX10yFjx7Y2sjD1TweXzyY7fdpHN+lA+8c6X+FC
         v7LlUD/1Ggn9dwtJO62O7YG0m/0tug3Mq0NbNVoHHbPEnEBW4oe9CvECD3qpPMFTOzha
         YQWO2ZFjdwlg+RKS9kFdPrx8WKRmIkJ80iqXQ9mVI4xun55GhgiH2Ha7rMGiAkPx08NA
         BPjZkgR5sL8Kjohk5qav1662UNb5QP92IpvwFUorAmM3dw+3tGT0+/lLUrPdYEuxwEwd
         xfgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uifk5U8k21ts2EsN5i6JePoeIFeG4rZmhtMYOL5X7qQ=;
        b=U6mOnl9mX0xbj01B+yWFZNCatb32NHVYIWbwLPPodJlJIwxPECyVikjqz1Qj8zpsQa
         xI0lVywK4uFIPE+eeSqDsr8KrEWyVmoLrXWOiQ2LQbX5NI1XRsKvZT+WOcPGCl6cLsI3
         A7fJPOrcm2mNAm9EOU+JC6nQhnexcPt0apwO0G/f/iiEonM5KkvfBzEB5tsLore4mktT
         1UUUusD2y+rjitnJmlsTOxuyOz/rIoke3ddF6aJosRg7b5Dzc7BoD+cmr4F74x+qDi2c
         pYQSZGl5ru+rynrtm8rsq1YiYUVz5TPiWfHiWZNjY9ocYNFo9UKH1cqPt4MXoT367i8M
         icLA==
X-Gm-Message-State: AOAM533NmgrBhQga6zCu5a4T0h4p7HNMfOC2nhd3ETrJWVoo7XYlw3CQ
	YZWWBrQLtxnuWMGDZWRFL24=
X-Google-Smtp-Source: ABdhPJzDNuTHFRQzYroQroZCKw/gyosdxthCFpGFMm9zRdvzadlZOUtG7tFcucf0sC34JRvPlAVf9w==
X-Received: by 2002:a05:6638:358b:: with SMTP id v11mr9874438jal.128.1628508336807;
        Mon, 09 Aug 2021 04:25:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:329c:: with SMTP id f28ls658456jav.1.gmail; Mon, 09
 Aug 2021 04:25:36 -0700 (PDT)
X-Received: by 2002:a05:6638:624:: with SMTP id h4mr22750832jar.73.1628508336422;
        Mon, 09 Aug 2021 04:25:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628508336; cv=none;
        d=google.com; s=arc-20160816;
        b=vhpsDriBJPDdRFYQ0F+ETQ1cMEUq5twKFuSaBgZgicpThCBo/kG7Bya8pYGZCEt2kX
         Pe7pn9Thj39iQFf6h7c7cck3f+0LD5w8fDdUAiVjBrk5FCysnnYcoNctZh4rkjcsKUQ8
         o6jUJ8Ct4LjnTYlirRBKODW78ikZmjCI4lyW0rLzXx0VV3Jum572QcEl3FQsAZsgYCJn
         JadCoNGCy2XFtSs3UGb9fhARAFgwECHFfPKR8EjjYQSSDhVnW9x5SqzEBBiGmTEsAqBa
         txbGDqQ3GvOJv/oknLPg4VgyRLWS4eXlk7l1WbFWpNsBbID8R0bZRggNJvV2AhTmKZdq
         h0VA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=pk34E2M+ZiZK0Nfsu3ClbxlgUD+rETQhezjkayYFVhg=;
        b=udwSCiOLryPRA/KHfd2S0l5dPXl7YeelGFGMZCIrBqG2VMENxye4w/a5S9SCl1rdGp
         Oibul12XmFV7ow7SHoYxBXP1SSAH1Zh07YeEJKZ4vMpfNE02O21LXgy7Chjt+54d/oM0
         lufB42xL5hWwMvSJfB7/dkf13bXJ667OAV6IvxX8vNbGfdRZPOEzbtWV4Hil5/AYGNdN
         hcCmVw7idOr5Jb5Qs+uXacdwFi6iWVgNDkMUZDuawasPy6yJK2P4y0/euuZEGBMWUxZ3
         d3ykrvwQYGVl3/6ZHZfoUlQweHNJD+YuYLtOj9VGGhdtA9xSPoWQJ3S7RC5isUJ+0m0U
         zmsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OEtXS1km;
       spf=pass (google.com: domain of 3rxaryqukcsqelvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3rxARYQUKCSQELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id e16si772662ilm.3.2021.08.09.04.25.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Aug 2021 04:25:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rxaryqukcsqelvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id b19-20020ac84f130000b0290291372a1d17so2852342qte.9
        for <kasan-dev@googlegroups.com>; Mon, 09 Aug 2021 04:25:36 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e5a3:e652:2b8b:ef12])
 (user=elver job=sendgmr) by 2002:a05:6214:76d:: with SMTP id
 f13mr22832309qvz.53.1628508335890; Mon, 09 Aug 2021 04:25:35 -0700 (PDT)
Date: Mon,  9 Aug 2021 13:25:08 +0200
Message-Id: <20210809112516.682816-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.32.0.605.g8dce9f2422-goog
Subject: [PATCH 0/8] kcsan: Cleanups and fix reporting for scoped accesses
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: mark.rutland@arm.com, dvyukov@google.com, glider@google.com, 
	boqun.feng@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OEtXS1km;       spf=pass
 (google.com: domain of 3rxaryqukcsqelvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3rxARYQUKCSQELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

This series contains several test fixes and cleanups, as well as fixing
reporting for scoped accesses.

Thus far, scoped accesses' stack traces could point anywhere in the
scope, and can be quite confusing when searching for the relevant access
scope several stack frames down. This is fixed by using the original
instruction pointer of the location where the scoped access was set up.

There are more changes coming that depend on the fixed reporting, but it
made more sense to detach the changes in this series as they are useful
on their own and only touch core KCSAN code.

Marco Elver (8):
  kcsan: test: Defer kcsan_test_init() after kunit initialization
  kcsan: test: Use kunit_skip() to skip tests
  kcsan: test: Fix flaky test case
  kcsan: Add ability to pass instruction pointer of access to reporting
  kcsan: Save instruction pointer for scoped accesses
  kcsan: Start stack trace with explicit location if provided
  kcsan: Support reporting scoped read-write access type
  kcsan: Move ctx to start of argument list

 include/linux/kcsan-checks.h |  3 ++
 kernel/kcsan/core.c          | 75 ++++++++++++++++++++---------------
 kernel/kcsan/kcsan.h         |  8 ++--
 kernel/kcsan/kcsan_test.c    | 62 +++++++++++++++++++----------
 kernel/kcsan/report.c        | 77 ++++++++++++++++++++++++++++++------
 5 files changed, 156 insertions(+), 69 deletions(-)

-- 
2.32.0.605.g8dce9f2422-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210809112516.682816-1-elver%40google.com.
