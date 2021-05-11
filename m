Return-Path: <kasan-dev+bncBCJZRXGY5YJBBGFE5SCAMGQE3XAFTEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 97CC737B277
	for <lists+kasan-dev@lfdr.de>; Wed, 12 May 2021 01:24:09 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id h8-20020a92c2680000b02901646ecac1e5sf17972383ild.20
        for <lists+kasan-dev@lfdr.de>; Tue, 11 May 2021 16:24:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620775448; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fd5f85iANS0Uf2KA/vFuilVFMsru0BVS/zGfzHO8Rm14wiyKMppNjRy8ENcE3AGuEP
         nKn0j+ohhVGbNzXr5B71+GTb+874Wjj4NljeaOUzOqv+mApdMX3PcLePIgitFVQdhh44
         gO4e38OFkYajt+/xkB2lpvrBBm4udiSrjdj2ENjpBFmPP7XorYHyB9BxRlWzTfV7+j7q
         iNI3i0Jah/+NUdk/GLBme1fmXNZ6/LR0wLlLOfrSaJbKzWjT96Nm7/IgPvKJTD9FtB9P
         KEbcg3QnkXXk6/UCG3T8VYZw6b0qp5Ltq2JiwiT49wmdkG7ipB2DnNrwAVU504YO4wS9
         ZiKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=B6RdrMg2RlSYnQNqVIcWPINIbrMjKy0veE9nIF5Vl8E=;
        b=E3QUQS2LzZdztjjEiiVZfbQHgon/yL4qx6gz4FmrE817LxZyRFMBfhsMH9w0hW+b0S
         EoJYlkQFZEa1v2wsijxYlLzvOHD3GHmqIuw+31p/nnsG1YRuHvxAde71MciKXoJctPuK
         qSI2b5ixsbI+ZBFccawg3aAk+7Efpfn7/rjFZ06BFR0F7mJAJFWXh4dZ+lu4WvieYyY+
         kVlLsOIoGAFDeaZMAuaahp/XZONzZ7qlqn8KzpBB2dALfBosVyOuW5kkxtg4+2iX/PDx
         Cd4yisFtpZlxEKlmDQXb9ZPyb8y7LDx/ngcOl4JIUxnyuN9c9TbpIxL6ofm/6PBzeiW6
         LLrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tDIr4JWH;
       spf=pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B6RdrMg2RlSYnQNqVIcWPINIbrMjKy0veE9nIF5Vl8E=;
        b=djO6u9Ygp6z4M0UInce2EFumjGdbyx5uyXkbTc/zqj/ADYjXDIfac3lNuNTXBXJvYx
         TFsXaibcfX8lyLxKIxdh5SP+Y7aJG/T770npJmOQJeFfEC9vuqYBoUKPVoMEFVUu37QZ
         mlAuZ/CaqIMr7gPRylXyX7iRQzkLs1iV/fNbev/So9/eSoRbDqYKbJz+7NQfK7OJjxxF
         ZknE5cORWl2rO2R/N3l87y7bJAzd4NbmpJq/DkO8I6s5LHKnmjsYHYHXcL3o6CNTBGrY
         yDv+7nGuVl0TcggXk+HQT7WkOxV1IjmxU5rTEX4onzTCkifVUqRLqAQ66wsAymcWfet7
         bdVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B6RdrMg2RlSYnQNqVIcWPINIbrMjKy0veE9nIF5Vl8E=;
        b=Mny/ruNCERVR96BZnb/TrMeZS8cmGONk+UvaZ/h36fZ2qCFkb8HdeoFKR5g4lZ0BBW
         tgWbJEEtMi28wrYxBoBfFdsCi5qFKc19sgZDWL2rlA9ar7OsypMTCzKfjvqvVowVFuRa
         W9sgu5rfoSNw7xCNdJAxwWr01SNnEQcLjX5s5ODhcxAgLm4n8W/whRHdFPPZklSNeBL4
         y2JaZLOqG0bfqwWxQsMmPELvA9Vf/B6OA60rXzIREJbk7SJC37a7MkwcrF/dQZ4IwPBN
         zjDDVoiFf1mDPZF9htTfvl+/tyVLontlqMIwAlFI84AQFx6S2dW16bU80bIZ+c3O1w3q
         xyaA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533lBXbHvE0DKxLL5ZplITbmsFHfhcgmWiB4zYfGAR0nDZWwgwiP
	iaV2pz9k/9IgrF15fnwEyMI=
X-Google-Smtp-Source: ABdhPJxbAiHXmmjSJTQMFY/Ja3D47rppEfkqAgnBAE6zozdcVtCtoTzU+ZMsQjDk2dKHMo6XFBlaMw==
X-Received: by 2002:a92:de05:: with SMTP id x5mr28593744ilm.156.1620775448651;
        Tue, 11 May 2021 16:24:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:7303:: with SMTP id y3ls55355jab.9.gmail; Tue, 11 May
 2021 16:24:08 -0700 (PDT)
X-Received: by 2002:a02:878c:: with SMTP id t12mr28602963jai.59.1620775448383;
        Tue, 11 May 2021 16:24:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620775448; cv=none;
        d=google.com; s=arc-20160816;
        b=tmLkx26HGjZhdu4Xcv0nJ8w7y8XX5KDA0qsNmTS+kAqXrGNP1eVIK+UOUdUDyEMNuG
         vCYpFIx1Lr6IExq3WAlVLm+9eS/YmUF+suUObr5D0piiw2DTWyiXu10tev5n5hXtCM4F
         j5wQp8XOzHXHW7a+1+E13J4XjqNuIFTKExtBJfI5mNNKJB5mJmv1P4aZHk352SiUv/C4
         38URtKg30F8mNyOM3sQ/1rxj9CZ3xGO1zju5o30OAGVqgyGqmhqfW2GL56xIFgKvUYjW
         Q46LTilSrXv8zfI45wUvQHNjg07sg31//kDWnTgOPGHTCCNDp3TtEM8YDwi9Rnl4jjBa
         jPKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lr1xxAMohpXDjBZCP9VjhU21lShEPNCBRmlKff5WngQ=;
        b=zKZi5crE2wStLSa+Qhmm1gcUh1kKiZEeTJhRBOkzn/27RB/9GnQQiFaPXNN8Otk/ra
         hBRHni7cI3Ph71as+Uh5Nymg5kDEHxVIR2UFqxoIWZ6OIq7NzPM260GN1b/B2p7ihUPT
         SBhRYBHXjBhvaW7ASCosR/fLHdsPK3/FhDLMUJ2gD859diz8/JjEa20dvJMd6HrvAABB
         BLS/M+JNdBCUqGGo8P7Y57xtL+EaUgV2myJz0e2uE4zNH+l2leJOYOByBjPfQJY+gJfc
         eVe2iYp2nNqu+/pFhPvWZj7Puu9Md8j6MW3qb3yvsPJcKZwzA11lEqiTDOEKUq6Ghq6q
         In4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tDIr4JWH;
       spf=pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h2si303082ila.4.2021.05.11.16.24.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 May 2021 16:24:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 53DAA61937;
	Tue, 11 May 2021 23:24:07 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id ABD925C0DEA; Tue, 11 May 2021 16:24:06 -0700 (PDT)
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH tip/core/rcu 10/10] kcsan: Document "value changed" line
Date: Tue, 11 May 2021 16:24:01 -0700
Message-Id: <20210511232401.2896217-10-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210511231149.GA2895263@paulmck-ThinkPad-P17-Gen-1>
References: <20210511231149.GA2895263@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=tDIr4JWH;       spf=pass
 (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

Update the example reports based on the latest reports generated by
kcsan_test module, which now include the "value changed" line. Add a
brief description of the "value changed" line.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 Documentation/dev-tools/kcsan.rst | 88 ++++++++++++-------------------
 1 file changed, 35 insertions(+), 53 deletions(-)

diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index 80894664a44c..d1efd9cef6a2 100644
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
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210511232401.2896217-10-paulmck%40kernel.org.
