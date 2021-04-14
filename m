Return-Path: <kasan-dev+bncBC7OBJGL2MHBBANE3OBQMGQE3NGIILA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 2696235F272
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 13:29:06 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id i10-20020a2e808a0000b02900bdf90c5ca7sf899210ljg.10
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 04:29:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618399745; cv=pass;
        d=google.com; s=arc-20160816;
        b=iOMdV9jpzpIEX1CTN+5D5ri+/DmtoOVxZ9xvX72k1gd4oeQORwnPxjS1VNMLyIfwNW
         15zuyrBoy+g8PpwSUNnB4Q1wv09BAn5EfFQejTToP3SbCNl5mgdco86C87z1E9VwHyMw
         tTjIj7HJqNIFQLtomYTfxR3Gl9/XlYdtf4NCZxl+YIsnGSZ9fFPV1L4MXIkAHJhrdd2O
         5wN1sFSGMdwR1gacwr0QyhzcDQqAvrriI8CPQqRyZL6DWja7MIqLLjN4dqi+ADLnOJnc
         KEGFjXmkOiSDbdX7Q0N27PN4AcZLO8LO06c5kYkr417nrG0kSsQX+aNzQx2Gqia5F8tl
         jQ9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=dVJLHuuWSvV+Z9N/rZUZzMoe5HDg9jYRoceZ0fSz1Zo=;
        b=Esum6KElcwv1hSvsrdqrR5pNDM9dV0aUeP7ayI/YpIypdiu14itORsDGJD/MMQz/ox
         vTW2ObULdIgeV35QMB+fAj3uL5LUY4JSHnMDOwNWe5bosDGhAf6/MkVwD8vNUPiPPXwA
         +rompiKDAL4o8O3SEUwrGv4PvWvBBUWRIQ2jQof2zy0/bR++pGVMZNVa2euGvTxvj4cA
         K9GzjtdTIgUliukvBCbkSsigJABklg8jNkphDI+1pu9fWCHRcZ0LSynxa8AhrMRpbyJd
         /RYmDM7O5jGS2l4Y1e7SwjN93KRYzcerqcDJB79zbKVZ6+AL4bZerrJlPYjGVo1kpgSa
         4Mxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Mrg9DeYb;
       spf=pass (google.com: domain of 3anj2yaukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ANJ2YAUKCYkry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dVJLHuuWSvV+Z9N/rZUZzMoe5HDg9jYRoceZ0fSz1Zo=;
        b=X2iabfrK9iJ6c8WeH6ptBYkmZmxVNyiezcpH6tJvEvUm+a7elv4xgR5eRNXjMKtoY2
         6J+LDcobZei0H8Jq0miTA+qvaO67uDsDy5yvrCYn/bFfIXdbIl7JdvEreGhJPSuAkFV9
         yb5b7D6vX8Tl9vSb3CSa5FCF8t0KKHok+umnJWytdPQUFQj5QfFRCrS4T0kp7WRjBQxl
         VlzCGmpJbgrp4RhwX7ljgejBNYze92ewYWc6mWf04bTbdCS4hAjUFwohknIBBifsd/ji
         fUowV+zRWxeIg9YROd3giyRqecm2niMbw17h6mocsVLjiT5SCgqEuyDiecWea2U0EgId
         sOPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dVJLHuuWSvV+Z9N/rZUZzMoe5HDg9jYRoceZ0fSz1Zo=;
        b=MyJ2LQzkAamL2BhS2g7uNeUz6gZmb4h479GwTv4BnPScMUDpXrt0GKzyAg0mJwVc6c
         kP4FdI7O8ns5RxOHXflbeOB911iZNa8rbTj2mwsndnWq4FdRVgQ9ZT5Ml6Gj5TvS/R7F
         a06Lv8VetowB74J6W6LqdgqdeCgUgVi0mEh4tKaaViM3VmFL8yaqoLT4b6+qWA+Ziqfh
         bvt5BEiKyTUg/S+frXW/GFCRny5c53ONkIT9216OuLEuPp83m7RnrDM2hI4QjdgfEFrU
         Zon94J7uaBkqy2/w2b8ncaxUDD2+/XzqkVAy1BwQnY0fbStfcNflOYZMFZBvW/F0mLBO
         7zoA==
X-Gm-Message-State: AOAM532E9+1O3vARJGscWbSDy4/uEKsbzUNS6UwjHSG3Bv8W9Qj/PxpW
	sR/YSpmS5IAlvPN8uW5A7Sc=
X-Google-Smtp-Source: ABdhPJw0Hhqz/t3A2L49mw4JeqV+kRu9rn/GGONE5s3Co2yhF3LcOWda8cg1GErpZHGn5zAUbQqX1w==
X-Received: by 2002:a2e:8182:: with SMTP id e2mr21716908ljg.238.1618399745725;
        Wed, 14 Apr 2021 04:29:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3c10:: with SMTP id j16ls315005lja.2.gmail; Wed, 14 Apr
 2021 04:29:04 -0700 (PDT)
X-Received: by 2002:a2e:9707:: with SMTP id r7mr24703749lji.181.1618399744581;
        Wed, 14 Apr 2021 04:29:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618399744; cv=none;
        d=google.com; s=arc-20160816;
        b=rMF+m6tVmQxEmgr0cDF4r+PkykSsi+xnuilxi3C6sJPiVfKwDJG/slGqj8YSMahmqp
         wZzudskOzS6up3SmNrCKyvdsXFSKPi2QefDe23ytvlnYR18d+4HFlYM0Dom8JrEpna4O
         n4WfG10zVrMH7pMbOsXPtNz++UhEKYkWGH31F6Vr3gK2JLJTcT5pw85n01wcGEyyDX0C
         5aL42jKzjTsnyAYvHIiEr16kaqjItiM0eFecFp07uTaWZlByCxKxK/eYmnizzLSV6K6J
         wYZiG489EnYoZuI4FgRPaWVfKpUO0cgl/OaJI623AHrNntWgVek9Zx0DUAn3bdLkXSrW
         jO4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=sgGFXp+rNeY0o6f3MUrh3kWdEuk4SzRpLTB8DWBZoJA=;
        b=AFJp0ClkrreNaRjw/MEspq58iq+VSfR/sckWTMMmqsRjoQt9m3mCoso9TIgqUFnCPM
         RBxrVSE0n4qrAqQESNzRAM6p9X5JlaG4TenQLpr68Srh8ws+JiICKbqy6gxAw1r9zGve
         PV+z2JBUQQ6g4oQODShcVbRHZH069j6ZD5znVk5zyoxPyHjSs1q7KPrGGk3/LeU9Th3y
         a5ya626tmEbgHGSCQSbK4mVcGvH0J35JUwg05iu6GqfE7Ml8JwAUhAw5Yp0sR7o3dCgI
         ZTZ5a6llRFLDL5a9dmEay7G8z917a70wtkhaqTqMEbDlf9tlX2ckG6nDyea4gNUUH5yH
         IWKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Mrg9DeYb;
       spf=pass (google.com: domain of 3anj2yaukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ANJ2YAUKCYkry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id u11si967267lfi.6.2021.04.14.04.29.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Apr 2021 04:29:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3anj2yaukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id i5-20020a05600c3545b029010c8bb11782so1973681wmq.7
        for <kasan-dev@googlegroups.com>; Wed, 14 Apr 2021 04:29:04 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:4051:8ddb:9de4:c1bb])
 (user=elver job=sendgmr) by 2002:a1c:f618:: with SMTP id w24mr2517462wmc.93.1618399744094;
 Wed, 14 Apr 2021 04:29:04 -0700 (PDT)
Date: Wed, 14 Apr 2021 13:28:25 +0200
In-Reply-To: <20210414112825.3008667-1-elver@google.com>
Message-Id: <20210414112825.3008667-10-elver@google.com>
Mime-Version: 1.0
References: <20210414112825.3008667-1-elver@google.com>
X-Mailer: git-send-email 2.31.1.295.g9ea45b61b8-goog
Subject: [PATCH 9/9] kcsan: Document "value changed" line
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: mark.rutland@arm.com, will@kernel.org, dvyukov@google.com, 
	glider@google.com, boqun.feng@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Mrg9DeYb;       spf=pass
 (google.com: domain of 3anj2yaukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ANJ2YAUKCYkry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
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

Update the example reports based on the latest reports generated by
kcsan_test module, which now include the "value changed" line. Add a
brief description of the "value changed" line.

Signed-off-by: Marco Elver <elver@google.com>
---
 Documentation/dev-tools/kcsan.rst | 88 ++++++++++++-------------------
 1 file changed, 35 insertions(+), 53 deletions(-)

diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index d85ce238ace7..ba059df10b7d 100644
--- a/Documentation/dev-tools/kcsan.rst
+++ b/Documentation/dev-tools/kcsan.rst
@@ -27,75 +27,57 @@ Error reports
 A typical data race report looks like this::
 
     ==================================================================
-    BUG: KCSAN: data-race in generic_permission / kernfs_refresh_inode
-
-    write to 0xffff8fee4c40700c of 4 bytes by task 175 on cpu 4:
-     kernfs_refresh_inode+0x70/0x170
-     kernfs_iop_permission+0x4f/0x90
-     inode_permission+0x190/0x200
-     link_path_walk.part.0+0x503/0x8e0
-     path_lookupat.isra.0+0x69/0x4d0
-     filename_lookup+0x136/0x280
-     user_path_at_empty+0x47/0x60
-     vfs_statx+0x9b/0x130
-     __do_sys_newlstat+0x50/0xb0
-     __x64_sys_newlstat+0x37/0x50
-     do_syscall_64+0x85/0x260
-     entry_SYSCALL_64_after_hwframe+0x44/0xa9
-
-    read to 0xffff8fee4c40700c of 4 bytes by task 166 on cpu 6:
-     generic_permission+0x5b/0x2a0
-     kernfs_iop_permission+0x66/0x90
-     inode_permission+0x190/0x200
-     link_path_walk.part.0+0x503/0x8e0
-     path_lookupat.isra.0+0x69/0x4d0
-     filename_lookup+0x136/0x280
-     user_path_at_empty+0x47/0x60
-     do_faccessat+0x11a/0x390
-     __x64_sys_access+0x3c/0x50
-     do_syscall_64+0x85/0x260
-     entry_SYSCALL_64_after_hwframe+0x44/0xa9
+    BUG: KCSAN: data-race in test_kernel_read / test_kernel_write
+
+    write to 0xffffffffc009a628 of 8 bytes by task 487 on cpu 0:
+     test_kernel_write+0x1d/0x30
+     access_thread+0x89/0xd0
+     kthread+0x23e/0x260
+     ret_from_fork+0x22/0x30
+
+    read to 0xffffffffc009a628 of 8 bytes by task 488 on cpu 6:
+     test_kernel_read+0x10/0x20
+     access_thread+0x89/0xd0
+     kthread+0x23e/0x260
+     ret_from_fork+0x22/0x30
+
+    value changed: 0x00000000000009a6 -> 0x00000000000009b2
 
     Reported by Kernel Concurrency Sanitizer on:
-    CPU: 6 PID: 166 Comm: systemd-journal Not tainted 5.3.0-rc7+ #1
-    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.12.0-1 04/01/2014
+    CPU: 6 PID: 488 Comm: access_thread Not tainted 5.12.0-rc2+ #1
+    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
     ==================================================================
 
 The header of the report provides a short summary of the functions involved in
 the race. It is followed by the access types and stack traces of the 2 threads
-involved in the data race.
+involved in the data race. If KCSAN also observed a value change, the observed
+old value and new value are shown on the "value changed" line respectively.
 
 The other less common type of data race report looks like this::
 
     ==================================================================
-    BUG: KCSAN: data-race in e1000_clean_rx_irq+0x551/0xb10
-
-    race at unknown origin, with read to 0xffff933db8a2ae6c of 1 bytes by interrupt on cpu 0:
-     e1000_clean_rx_irq+0x551/0xb10
-     e1000_clean+0x533/0xda0
-     net_rx_action+0x329/0x900
-     __do_softirq+0xdb/0x2db
-     irq_exit+0x9b/0xa0
-     do_IRQ+0x9c/0xf0
-     ret_from_intr+0x0/0x18
-     default_idle+0x3f/0x220
-     arch_cpu_idle+0x21/0x30
-     do_idle+0x1df/0x230
-     cpu_startup_entry+0x14/0x20
-     rest_init+0xc5/0xcb
-     arch_call_rest_init+0x13/0x2b
-     start_kernel+0x6db/0x700
+    BUG: KCSAN: data-race in test_kernel_rmw_array+0x71/0xd0
+
+    race at unknown origin, with read to 0xffffffffc009bdb0 of 8 bytes by task 515 on cpu 2:
+     test_kernel_rmw_array+0x71/0xd0
+     access_thread+0x89/0xd0
+     kthread+0x23e/0x260
+     ret_from_fork+0x22/0x30
+
+    value changed: 0x0000000000002328 -> 0x0000000000002329
 
     Reported by Kernel Concurrency Sanitizer on:
-    CPU: 0 PID: 0 Comm: swapper/0 Not tainted 5.3.0-rc7+ #2
-    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.12.0-1 04/01/2014
+    CPU: 2 PID: 515 Comm: access_thread Not tainted 5.12.0-rc2+ #1
+    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
     ==================================================================
 
 This report is generated where it was not possible to determine the other
 racing thread, but a race was inferred due to the data value of the watched
-memory location having changed. These can occur either due to missing
-instrumentation or e.g. DMA accesses. These reports will only be generated if
-``CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN=y`` (selected by default).
+memory location having changed. These reports always show a "value changed"
+line. A common reason for reports of this type are missing instrumentation in
+the racing thread, but could also occur due to e.g. DMA accesses. Such reports
+are shown only if ``CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN=y``, which is
+enabled by default.
 
 Selective analysis
 ~~~~~~~~~~~~~~~~~~
-- 
2.31.1.295.g9ea45b61b8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210414112825.3008667-10-elver%40google.com.
