Return-Path: <kasan-dev+bncBC24VNFHTMIBBEO3ZD3QKGQEB6FTDUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2CA46205731
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 18:28:03 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id z187sf13070518pgd.11
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 09:28:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592929681; cv=pass;
        d=google.com; s=arc-20160816;
        b=jkOfEZT9Q6LZ9ySp5wwWaVh+r/iYPRxk0ZZb9X6rfypAgbsu4aSJIA6NATRtJpBrtv
         8/qxWgAfBd5b+BDvDh7RyIQiPHg8KRV2FpMN9hqZM6JEntXR7gKeSw2WtYsSTuOprlpF
         ff4nUu9afOCksAeWfzoxJkbCmkZKeLm29dZasCrUxdzzllHfmqmjDJz+DHdVT/ZYeVGw
         OZMjYyILfrlbX27FGaUjq+rASyoT3qXt1YtdMAgbKxr7AMhEakAvzkLEFSHZKnVChz3C
         iSAmfisD15nyOP53Ycohs4W+5JnHulzCdJfVGvThWVCHlp7U/IUQW4KPmbxqqPE4sTDI
         mYKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=0lk1Hj6eeSE20G/iG/sDiK4n8V6tXuaNugbSieS5cYI=;
        b=iKLSgDBoFY42y5krV1flK7W1Mk4c9FfnYC/qRhECo8MeANthntes2KanGNm/kGjBQn
         tVMmH95eHAh6DuA+2cL/8mcId72X5rP3UeParyBvw20ebkp5AwSza7R5TiqQoxoi7opC
         zAQGijma4lDDQAUL/2CMoPNG6i2tBXiWveYh4bw2w2gC0dIeb5t0SFew612B2PUx9rxH
         rUpr6wCdP+mhRB0x8yu61jls/c34An9jVV6KSyrZsm1hmdwqPxyiOytSgu1kJ1sfTXci
         g8HV+FphvTLBwIEa+SNJb7L4QVXXlkGcJtmz0wx3EjSiGQfZz9kQj6E5WyBjpXzHjuRL
         Kzig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=00lz=ae=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=00LZ=AE=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0lk1Hj6eeSE20G/iG/sDiK4n8V6tXuaNugbSieS5cYI=;
        b=Va0mNMqIl61KbGYR6VE2VDPkUSX9VBHeMm8WyBA9SxzFbsOFra67Ky6tq3i4kS3aVl
         e/oUNdkC0vbpnXTYQCCRA6oCCIzS093KOD3t+R6J4xATgysVtQjjfNwW615nmfyUnHFR
         50SKhF6XWgu8JHhwxVqVC8BgJomA3zZY1FvUhT75B82f4g1+eRJ4W0tO0pxJ+kjD7zMJ
         oohDAQ/Y2bMie6qulNNEazT4dnkAStamnC83qmIvXsUcAZYmwmhwDZdet3ulIm2E9hvZ
         +bGizLKx6a0fHtRZqPea4LCb+vTcw8DkyyIuaQVIzkIHfY2LlKoxIriPoEakhreD5iL0
         SUOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0lk1Hj6eeSE20G/iG/sDiK4n8V6tXuaNugbSieS5cYI=;
        b=b7UlEXuYWunQifJLKxJ4xbAfMCjWGibzxkPsdNlRCCLGc407M9Epfum10VpLMUBG3j
         ku2+4KX7aEBk+f7Vta/HiuQmFSld9Vs7cwqfGowKXS2jBaZ7AW1zRBke2PRo3zGxR/7d
         ZAjF+DmFk6pMf3Uj26jvhQarB8fyyfUQGE2LrEfME7Cyt1QwqDb+O1hiCCecoZPnkAaJ
         QhcvYIbm1HfN/ClJyQpUXDoTkNR8/84z8fh2CcA72U0sG39zHRNAKFAyGjcPy9l06hx7
         qZoz5uC93RvklsLFK0zX4ZFcff1h28cG2bO3ekZYAqx3wCRQuJmO2sK8PI6QHy8viRHH
         k03w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Y645vNohNCeb4S+OPhMNOyP/Exc1uGQhiwxsczn9hBg5jDqcg
	zesVEB3c8pbaIDEZdY11wh8=
X-Google-Smtp-Source: ABdhPJxuFqbmYGOeREO+K3bheItNi81eRifYcy2ltQHmtToE/TZANb6WsmAFogyqWXY0S6CG+bWpDw==
X-Received: by 2002:aa7:9ae3:: with SMTP id y3mr25843149pfp.224.1592929681477;
        Tue, 23 Jun 2020 09:28:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9007:: with SMTP id a7ls7862647plp.3.gmail; Tue, 23
 Jun 2020 09:28:01 -0700 (PDT)
X-Received: by 2002:a17:90a:3b06:: with SMTP id d6mr26320718pjc.67.1592929681062;
        Tue, 23 Jun 2020 09:28:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592929681; cv=none;
        d=google.com; s=arc-20160816;
        b=c4PSIE3cljQoMgCFpWzyTvZorsOnnQSMne1aOinoy59SxeT8fMG7X9acihmF3rN1jC
         AKpSE2k7eOXHX3Hb7yw8XbWDYnS8gyCiDb5Dlm9FRW88rsUpKnWbpB8ri6/ls0aGURTY
         PuQ/GlxpfLGwvC56KNVSmzE8z6/706O0zM5TLtYQLCdYV1LUtjha90FBCCODfGV3eO22
         WSzfK2Bq2yeBDrz+YOHvp5nz0HsyVoc0OAggJdku0nwcbc5Z+F4SdbybaF8BtH59WJ/d
         yJc/r23oVpiEJ9Qvc4StY5tpD6DE5GcWhJtUZP5xAMsbaQ8z14mCRRmArbIpg/gJzY3j
         QAZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=V/YWZMbBwpVhJcsUSv4Yc4pEns6rwiY0x598CvEacxY=;
        b=UC1vA33xGQosZkIgO5F673ObGoHU/rWX6TcXCnsxlC+Ib1SEXbcf6uEbPFi2/rusag
         qhvs5VIyUS61dfdWLloV2+oXfGNM3OCY/A9PiZWyPx+guyO/sEXHStSVWuCz8D26YCg0
         rKBSe3ksNVY97ugO5znn14Q0/OBuSF5kFCT2vlO2bBS+QrtARthTmu68vthkED30L9nR
         sS7JFv4YaXvq2auRixJAQjGq77oRrv4uPInY1JWavHg5cf2k3PTyHaOQVS6hcz/3M1gC
         M0XYo8A7d+ST4apwJaixDD9rEUfsySz0E0iTIRSFAGWByFyWNcjT/YDYnt9wUtfTx2ib
         EvyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=00lz=ae=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=00LZ=AE=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u2si964162plq.0.2020.06.23.09.28.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Jun 2020 09:28:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=00lz=ae=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 208299] New: Add fuzzing-optimized RCU mode that invokes RCU
 callbacks ASAP
Date: Tue, 23 Jun 2020 16:28:00 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: jannh@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-208299-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=00lz=ae=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=00LZ=AE=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=208299

            Bug ID: 208299
           Summary: Add fuzzing-optimized RCU mode that invokes RCU
                    callbacks ASAP
           Product: Memory Management
           Version: 2.5
    Kernel Version: 5.7
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: normal
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: jannh@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

At the moment, use-after-free issues in RCU allocations are hard to discover
with KASAN at runtime because the RCU subsystem heavily optimizes for
throughput and doesn't care much about the latency between e.g. kfree_rcu() and
the actual freeing; therefore, KASAN is only informed that the object is no
longer accessible long after the RCU grace period has already ended.

It would be helpful to have an RCU mode where the kernel essentially maintains
an ordered list of active grace periods, allowing it to synchronously discover
items with expired grace period on kfree_rcu()/call_rcu() (if no grace periods
are active) or rcu_read_unlock() (when the last relevant grace period ended).

This will necessarily cause cache contention linear in either the number of RCU
read-side critical sections (if a global sequence number model is used) or the
number of kfree_rcu()/call_rcu() calls (if global timestamps or a set of local
sequence numbers are used for figuring out the ordering of grace periods).
Since RCU read-side critical sections are much more common than
kfree_rcu()/call_rcu(), it may be worth thinking about how to implement this on
top of instructions like RDTSCP, so that cacheline-bouncing global
synchronization only happens on kfree_rcu()/call_rcu() and when grace periods
exit while kfree_rcu()/call_rcu() work items are waiting to be executed.

Development of this should probably be coordinated with Paul McKenney.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-208299-199747%40https.bugzilla.kernel.org/.
