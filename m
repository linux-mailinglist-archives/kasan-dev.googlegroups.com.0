Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMVS7WAQMGQEDQOQANQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 78F9432B63D
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Mar 2021 10:39:00 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id a18sf1304788pfi.17
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Mar 2021 01:39:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614764339; cv=pass;
        d=google.com; s=arc-20160816;
        b=p1heKciUeEGEmUDXtWYt6DQhg8mI95tsG9NXQudsYBlhGEW9VqdZaBFvHEGCS/Njdi
         qMaiMgKtSIuib6nyVlcWm+f5PyS0N5P0Hmc0zgkaBu39hG3yULmnsZGfDmZdAnNb4Jho
         I59v3eD9JDgBUToD8joLvUkKIybdqRjvMDWK3CihVt49j9m3SbPS7+rlD6Ypb8zqUFGR
         /KBjnDPl77p/2Jt8LFkMEoRL4IgAbH0MUULE69GEs+6gT35ZVJYbaEAttiv6iFYbrJoC
         pz3DM0kyn0HMO/eZKgo44poKXLIuqWYa2+SNXp4gVq4rwaWXlmG3B7SIaMw95zHklGWK
         ikBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=5LifBtlFje7Ob0b7t9JwgVTmZkyuWJGbn68celka0ZY=;
        b=aWmaiGsZvt4U/qshJuHvxzdpchA+12wo2he1WpboVpQrEo1KSz6nRpE1PXyzox/1gz
         tScG20J6kjdpb6rDXtX1xFjLswHPNMqcEbq4iVtoYcrJ4E4i61aGmCv/XXgwhw43ehFW
         TmfwgAbAai3XwbMmVv824f/2LSNG4TONAy/D02Pi37GcVj5r25phiz1BcDuNoDrLu7qV
         B55mpGR4OZBsBlSmhJY7WFYglcwUUzI8cR+u/ZUT/1Y9Td2gWhxUGO0uvpIoun9VsjQz
         vDHm9F1NTbKoOkQaoWE5ERBLaDLvXTB30Xe+liUnvzR3mpdrh7zjct3t5R1OS5TbJZCs
         2+cQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BABNwRFo;
       spf=pass (google.com: domain of 3mvk_yaukcegovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3MVk_YAUKCegOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5LifBtlFje7Ob0b7t9JwgVTmZkyuWJGbn68celka0ZY=;
        b=re+HCZ46f/wx05rkxkl4hH/ZIwTvd1Lt6T35zUnyfCSUm1aqftVl9UhBgWSZExSguz
         pLvvJV8xBViuR3FpPmRb5dAfMo4SMwQekIrcvhup0BKGck22E8axuL+Ads9aHmpWKBtt
         MMeC2qDLBMGynHvv02oiOOl8lSB9X58c8CoTHHW67M4rAdNAGc1CpI9BA5gg7JfqTVrJ
         vaYYAndWb9nUKZwhdMtrLunrs8T4syLLYFxtdQecRKFcW+NNYDnAWbKXvpJl6FeQGVwA
         6oLPQSv5hEMqJBJDfcRlbRSVxPYKosVGuySQ7ZDUnpSpqjtcsXc9Clz5NeWxToRlJy7A
         vFMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5LifBtlFje7Ob0b7t9JwgVTmZkyuWJGbn68celka0ZY=;
        b=bUWLPhtcw4L7vid86E3VnHimm6SyyYY00YopbGHQVlNouPViGyCPLmhuzGQhO4wxV2
         QkV21qcN4pq8Oy2aurWP1mtQOm0f5OSA86sroJ3bl334dtutNAkJ+oeYG67u3wghqA7S
         yyKSaOyjTFpi6I684ZFOoc9xR2aevTarMQTkxawGglDHPmwR9tQHCURsFflatjvjiAXz
         lp7aRMtJ34ZDsN1hNv09MXwrhCBDlliaHst23WezOFYhsOOxWBMWORrbnQ2+G95sQo5n
         4b3OyX/32j3ORPz08g94yLhKdv3P9umETtOEkNs7jWs/UwYf/bwZDUh1/K5Os2PwTquE
         Xscg==
X-Gm-Message-State: AOAM530up5X1VGfIN6Y7uv3NRGrnlK31xIQt0PWHu3CGhu4qAjmJZ5l4
	S7ThY1LgrMxqL3FI3PJf0z8=
X-Google-Smtp-Source: ABdhPJyM+mH+EXwBoWe1pb8skuNrtFbcKGAuS17Ar3K4Z2VW6B8/v/o6Bnc37rQOzOt6bwhBlMiOOA==
X-Received: by 2002:a63:7885:: with SMTP id t127mr7277933pgc.237.1614764338857;
        Wed, 03 Mar 2021 01:38:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8a52:: with SMTP id n18ls711774pfa.9.gmail; Wed, 03 Mar
 2021 01:38:58 -0800 (PST)
X-Received: by 2002:a63:f921:: with SMTP id h33mr21861010pgi.419.1614764338316;
        Wed, 03 Mar 2021 01:38:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614764338; cv=none;
        d=google.com; s=arc-20160816;
        b=mItg8iuiKIqabZdRwvOyDWtud7a7IY+oZeY8YktxKkz9mgCj+1INAnbi12UVQTTp7I
         8nUWGSW8errsJTLLHOnJtCjfoaCTS8CSQtURwjGq0noxtMP/dOzyTVxl/d7HnYRL2uVZ
         kLEUkbTZUeycL8xHd+9f5gJzM4Nj/QxUvECfszzvqdTspNU8bYwx/8KQOYw7kHiT/1lq
         C2D/KXYxjSKc2hanhK+KfZz2ES+E8rDTpM1RcLoJ0zrC7y+9m4v0crlOwDOXOfwh2Lfj
         5E1aOd4KcteWW4l7d6oQ5WfjjqoePj2uYfARHaaXOTEBgB5VDIwUZ2GObKqDE9HVCioY
         y24g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=06CCmBMLbXxMNmm2C3sV6HK1skcr37rdo4zP3bjD240=;
        b=BC2rJ02lXDzOBzWZ8TNDSZfil9npHV5L2AGXGMkYFLa22rCJs8yR4UvGc2t88eIJ9/
         LPErcvR48U2rYOXPiHH8OyDRzOk1C4KOBTHBsliLnD5vPyQCj6xrIJZ6oBaqTowRCvpK
         XUwFFQZO5mTAn+yG/btS6Y6gLecaITw6Wv+gPEbWaH6QrfyiwPs15FpgA6EEAegIc7po
         dA0s1D2Pt2pNuQg4O/6zt5j0aN5Ac+lYSd/Z+onAyGUt8Str6+1fKQEaxNX7lOHQTbP+
         0v5p8GWsZ0980MFoEzWDf5011txnaVDy3Bmg2yad8g27PMCUuygUOOhMMjWeZ33HcmEY
         kKLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BABNwRFo;
       spf=pass (google.com: domain of 3mvk_yaukcegovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3MVk_YAUKCegOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id l8si1395353pgi.0.2021.03.03.01.38.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Mar 2021 01:38:58 -0800 (PST)
Received-SPF: pass (google.com: domain of 3mvk_yaukcegovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id i188so2484822qkd.7
        for <kasan-dev@googlegroups.com>; Wed, 03 Mar 2021 01:38:58 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:811:228c:e84:3381])
 (user=elver job=sendgmr) by 2002:a05:6214:6f1:: with SMTP id
 bk17mr7605939qvb.53.1614764337502; Wed, 03 Mar 2021 01:38:57 -0800 (PST)
Date: Wed,  3 Mar 2021 10:38:45 +0100
Message-Id: <20210303093845.2743309-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH] kcsan, debugfs: Move debugfs file creation out of early init
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: gregkh@linuxfoundation.org, rafael@kernel.org
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Marco Elver <elver@google.com>, 
	stable <stable@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BABNwRFo;       spf=pass
 (google.com: domain of 3mvk_yaukcegovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3MVk_YAUKCegOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
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

Commit 56348560d495 ("debugfs: do not attempt to create a new file
before the filesystem is initalized") forbids creating new debugfs files
until debugfs is fully initialized. This breaks KCSAN's debugfs file
creation, which happened at the end of __init().

There is no reason to create the debugfs file during early
initialization. Therefore, move it into a late_initcall() callback.

Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: "Rafael J. Wysocki" <rafael@kernel.org>
Cc: stable <stable@vger.kernel.org>
Fixes: 56348560d495 ("debugfs: do not attempt to create a new file before the filesystem is initalized")
Signed-off-by: Marco Elver <elver@google.com>
---
I've marked this for 'stable', since 56348560d495 is also intended for
stable, and would subsequently break KCSAN in all stable kernels where
KCSAN is available (since 5.8).
---
 kernel/kcsan/core.c    | 2 --
 kernel/kcsan/debugfs.c | 4 +++-
 kernel/kcsan/kcsan.h   | 5 -----
 3 files changed, 3 insertions(+), 8 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 8c3867640c21..45c821d4e8bd 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -644,8 +644,6 @@ void __init kcsan_init(void)
 
 	BUG_ON(!in_task());
 
-	kcsan_debugfs_init();
-
 	for_each_possible_cpu(cpu)
 		per_cpu(kcsan_rand_state, cpu) = (u32)get_cycles();
 
diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index c837ce6c52e6..c1dd02f3be8b 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -266,7 +266,9 @@ static const struct file_operations debugfs_ops =
 	.release = single_release
 };
 
-void __init kcsan_debugfs_init(void)
+static void __init kcsan_debugfs_init(void)
 {
 	debugfs_create_file("kcsan", 0644, NULL, NULL, &debugfs_ops);
 }
+
+late_initcall(kcsan_debugfs_init);
diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
index 594a5dd4842a..9881099d4179 100644
--- a/kernel/kcsan/kcsan.h
+++ b/kernel/kcsan/kcsan.h
@@ -31,11 +31,6 @@ extern bool kcsan_enabled;
 void kcsan_save_irqtrace(struct task_struct *task);
 void kcsan_restore_irqtrace(struct task_struct *task);
 
-/*
- * Initialize debugfs file.
- */
-void kcsan_debugfs_init(void);
-
 /*
  * Statistics counters displayed via debugfs; should only be modified in
  * slow-paths.
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210303093845.2743309-1-elver%40google.com.
