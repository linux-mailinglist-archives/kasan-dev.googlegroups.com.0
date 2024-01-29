Return-Path: <kasan-dev+bncBAABBWNH4CWQMGQEAGWWOTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id BB4078414F2
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 22:08:42 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id 3f1490d57ef6-dc64b659a9csf5707290276.3
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 13:08:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706562521; cv=pass;
        d=google.com; s=arc-20160816;
        b=clC11d8KgpS8l0SPmbhCmPixmIlGDy0bqCSBZWp5DflpPBr3C0xfg2cEUWMSdRUzci
         W1YIHc8091Dm8i2jb1Kth3vZW9gZ/1s2VmrK/QMV7u3oKiTGF2mkhm9ClayYbZwHk72T
         Igj5X7nrIG8o/68iVN61c0TZqbu1xK1R2NsVbAI1VXEvgVvq5w91XY2XpxatAKP/m3Lc
         C67Gp/arkvPzy3UGM3YX5qF0PnYPTURNzeWgGTe74yDUS026wgfq9qklm9AY+xt57aWm
         953sbncYasY5W0lA8SGtAn33lRK5VWAhoK1P/OAZLHXWzKSU6jUGWo9GIOYyD2YatZDs
         3IPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=W30JczA8QqO9oaNWGMQjYNwgpYGI9e6k0hZbaefcbyQ=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=jhi4FpaDoUMr8mXgww1DbRFoy5AgegNmbxbWso/lfW+CMqquEySx8sqWSdPEPNUNg4
         C+Qetx3fvxhNStkKl9A6BcPCwgiCkAUxfW2k8Wiov++RYiieuV49w5EpgHggm4jlD9R1
         U2z8/PWXH+buYU/xEu404tEUv0H6QZ2sVB0Q9ZNsKL0F3sGL9qNGeuA4igMnShE1BuGG
         0wWnxEF887UixbudXhjQGFxIBC0e+klIBtqFp3/0Dzy7aJA7QizS1VdGhQwc0ODaxiD7
         3W4QaaUXFS1o1P0jE32+1KqGXcQgyEFJ0p8/YJWPvv9f4dt/tSI9+d6LxcBJmsEDLtyb
         9pjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=W0LfH3wT;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706562521; x=1707167321; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=W30JczA8QqO9oaNWGMQjYNwgpYGI9e6k0hZbaefcbyQ=;
        b=wI3qGwxph5koIumipy09fdA9PXHewsYSPp87vKI6mKRjo6zNZuEgad84M5nl8dLia+
         9/0OGdquX5cy94YvoiBO7KgRnCGM29NzPagUnAbG/aNY+qJU/JgqDaPII6Y8Gm2+3g6a
         NJleVfCbtvFdchtPzvi4ARRFFOafAWz4E6H1lO1QpHpIzrPoHd3cgl3kADPtib3QhpHZ
         djx3nsBeYHJExrH9RREpkugo8s0Uw7p/oEnoUdvXVSXKIoZkcio4kP2M4F8OU9EbAJRz
         x1Bz5x3yrQnlH/UpgBAyjTD2nPiH3RH5XA1G1DUa4zo+bg1df0/r7aqrJLG4l8RpFAXK
         IjzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706562521; x=1707167321;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=W30JczA8QqO9oaNWGMQjYNwgpYGI9e6k0hZbaefcbyQ=;
        b=EOw00ws0iETHeelPze0u9TgCBQSf0JV2sNFV+Fus+IbFKsUvhtm/n3hLwEtKnxz2Ge
         A5hoRzZyaHTzwIbz3fQuexUFKJU58n0A79huDQNLAndsj0jQxqYmsbFhLkcLG+ksnms9
         +umtvaYf4Bge4u+XhpEiwLjJ6H0UXNMhtdOVMcUnThYXG5HpZkL7N0oRnczJrmUcOCmx
         M3PKbTd6I4o25G5XvnJOL+gKpkZpMAjA80NSpHAAB+dcupAoaRFx6AK5c8XMc/ducfOO
         scMYXZUmB6br56nzDPv27aR68scL01IrB6DPXeHgxYP1XEbIUeoYo21QVY2b07sZUBrA
         3tWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw6DtnQfnltqJ6XRAEywcOb2kKuzEy3h9MVMripgLVS3gKrJdxD
	R1/eccuU7WNGrj6fQ2pbjlDks57CoppBHxLZjoC+LNXrYKGScwrU
X-Google-Smtp-Source: AGHT+IEw4EFZBZoa9ZTLnaZXaAvPRruIio4gS03RZ+pcuaSnEO7slm9QWOQSngj5dOgs3N5Bk0Aq9A==
X-Received: by 2002:a25:5805:0:b0:dbc:ce5c:1939 with SMTP id m5-20020a255805000000b00dbcce5c1939mr3102480ybb.120.1706562521453;
        Mon, 29 Jan 2024 13:08:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:704:b0:dc2:1b5a:3ea4 with SMTP id
 k4-20020a056902070400b00dc21b5a3ea4ls336782ybt.0.-pod-prod-08-us; Mon, 29 Jan
 2024 13:08:40 -0800 (PST)
X-Received: by 2002:a25:6408:0:b0:dbd:2b6:6cfd with SMTP id y8-20020a256408000000b00dbd02b66cfdmr3257387ybb.2.1706562520057;
        Mon, 29 Jan 2024 13:08:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706562520; cv=none;
        d=google.com; s=arc-20160816;
        b=cIQA988CajWEvggFekn7WKRjYFW7eX3zz4GShEdLfb5Ur4wD6yAVoV24tqn7e3C8nF
         EeIdJoFdZ6vna9GrVkbC6UiylZScAXpy7dMgyS0ajB2BvwokNjxfcvajg6oTZuEItVlb
         orXBwL+UZ/T+79OzrvHMnJHeYJOsU2IY3+Zua5jteS6RgH1hmrnxIO+mOGZ1Ak84u0ui
         i79HLo/5moJpv0xomWgwYbZYp4acO+sPu45du0UkTgM1w37yoYVkidKDPPxTJOgmDVDR
         /rup89XuxiR5mbRhOBOR1NZnOzb4x2O42hqCYhAnkE9YU7XA91VmJTAPmOyPCAxdV6lt
         SZNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=3SSAJzR6GjdwbO3gc1qFO5xO8gvVxoeJDuiai5u2Al0=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=YIWG+3OeaIdq95GKD0FlOOGb79C9V2tTNt+K+tEFIAHwej0L9+aIx9K+41sZachr1O
         6Lvlr6/wusMof89l+LxRHJH88DntgWkpDqFbBrP56jURrAwbbfFv5vISgHbBrbGIQNAW
         1MkauSPQlOTvNi1J2r+L8m+HigVy9j+/QqIdY3ThsvLWGHfhFoMIeB8BrUsUp4LsLgm9
         xJ2UlGKDtEY0XFWSOWlPUNj49F8szOqnBOQmH4PySbO2pX/DA+6ZDDy0Re/AQ48AzFU/
         3z5yrqfoK0hxxbpTRr8TJdLA0elF0Pti3OIk28ZGOIuJHvrmwYpUCbL4wip52g/6Nz5N
         o/vQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=W0LfH3wT;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id u204-20020a0debd5000000b005ff5d5ae22bsi859588ywe.4.2024.01.29.13.08.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Jan 2024 13:08:40 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id A72AF624BC
	for <kasan-dev@googlegroups.com>; Mon, 29 Jan 2024 21:08:39 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 56C75C43390
	for <kasan-dev@googlegroups.com>; Mon, 29 Jan 2024 21:08:39 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 40F19C53BC6; Mon, 29 Jan 2024 21:08:39 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218433] New: KASAN (generic): avoid init_on_free zeroing
 metadata
Date: Mon, 29 Jan 2024 21:08:38 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version rep_platform
 op_sys bug_status bug_severity priority component assigned_to reporter cc
 cf_regression
Message-ID: <bug-218433-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=W0LfH3wT;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=218433

            Bug ID: 218433
           Summary: KASAN (generic): avoid init_on_free zeroing metadata
           Product: Memory Management
           Version: 2.5
          Hardware: All
                OS: Linux
            Status: NEW
          Severity: normal
          Priority: P3
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: andreyknvl@gmail.com
                CC: kasan-dev@googlegroups.com
        Regression: No

When init_on_free is enabled, slab_free_hook memsets everything past s->inuse,
including Generic KASAN metadata (free meta for small objects and alloc meta
for all object). This happens before KASAN puts the object into quarantine.

As a result, with init_on_free, use-after-free reports are always missing the
alloc stack trace and sometimes the free stack trace. E.g. all kmalloc_uaf
tests are missing the alloc stack trace.

We should teach init_on_free to not memset Generic KASAN metadata.

Reported-by: Brad Spengler <@spendergrsec>

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218433-199747%40https.bugzilla.kernel.org/.
