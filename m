Return-Path: <kasan-dev+bncBAABBFGRXWMQMGQEDIE5VBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A0FE5E8FAC
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Sep 2022 22:29:10 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id n18-20020a056a000d5200b0053e16046751sf1697369pfv.7
        for <lists+kasan-dev@lfdr.de>; Sat, 24 Sep 2022 13:29:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664051348; cv=pass;
        d=google.com; s=arc-20160816;
        b=lBWI9cndh4xmZR/C/fKjUyLoong9YkdAut1UisagoEcI/UtVDBKbarhfknE8BqH43Y
         XpFUUERxveGBXnmC/4WFH9VIHFbrQdFwAL4mISS3zlY3t+7VBWtr0yCPqtmU5uNeTenI
         328IjYRCywoe7nKIaKHdb/WGssrvK5qLlAt3WlDByihU+K8tJ2yIheJf4EjG4XeN41DF
         o6gYXDYnnQi9lrXvHPa1QIlh2muRTXiLu1qkOJMcKO3Cr0ihgpbtQq8cmZMRQEQS0CKH
         tfRwfVqckDWfwZs2INt+jn96sU1JvPQW7Xc6xs++EX1HqrxuY+Hr7xCWcqeTd1bUPP9d
         53Jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=woKZsGv1q1r/hAvM9PTWjqWt1iuoTIwXlsfcd42HGUI=;
        b=QAqFAK30jaqSjT4ottRWOgJLgA+7yrZkgMnd93pwqubScojmzklGgHeFQ25UJrsBVE
         BT4PeCIcjugr5bcm87F7qtQQG5XebrjcpVT1X9pYeuspFzjNFH8Qh9GXnWNMUwqYbvU4
         b171bAXbfNZKuPznDO/2f9aPIU9YK/6fdWAO5DTtypQcNfU/tZ0QgXR3fNCVeoUHM/vQ
         wJlanLEjxT33fWWQcio4abaw0Wut9XJgJgZG/uXNRyKkp0f34PurgE+VTyzoi7nKkwTO
         MM+OCGBEqnA0zrCvIGSYGK/WgceD86+AFh2623W+MiDCnalDrExx8DqXGzEeRXVgHtM8
         SY8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OdcR6fCS;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date;
        bh=woKZsGv1q1r/hAvM9PTWjqWt1iuoTIwXlsfcd42HGUI=;
        b=PES7Dn0AIHLmEBv9WrfxjDG1zp9DhxrXCXszRux5fbshVQgZpi47wCTVSIJcqCgzy4
         +uMJXuygZ6RSqs7qVOtedZVG4+bmSbXK/vELI0GAQBuirmwTrSxO4rr1KMSUFD9fB+8r
         Hz2UYFgvlqLgH8NRyy/840LvFBTMYAKDkB3MvEGDLDxKJlnBVe+SJ1CU7+XYw2TZ4ap3
         0+tWzOlGPq9F2yc4OQF/qEEswbCt6wmn7xKmpWt1gQd1OgblH3y/K29HQVN2CicTSH/A
         Do5kVccQ7KkrNGabon1vNbST9niBY6HV89i/bfpcJW2ajfdU8gkLFDD9SR5tPOJXfMln
         sB7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=woKZsGv1q1r/hAvM9PTWjqWt1iuoTIwXlsfcd42HGUI=;
        b=FOr80yZJT5yddJkEPy19K7LXW1/39PbIMOXQ0HbwTSkwsWAhOgTxaI1p6X9ECjwp/z
         WIKcwsFixLi38rSa7A+NsCPHquU/CoWt6QiHBa4PauoM8GXRQE7XHPiQUpGD04bfrXOr
         wRBNJdu2NKR/pzXeENbMB8Y6uIhdLRhIEih0Lmg9bImEjaudhFWyBdwa8+XPV+QBnbXp
         LYLL/g1d6pNkEaxKrn7/aqld0MfNsBwAvwaquw9FazW1hzPFGhCYWzHDj3WzqvmY1njT
         Q39GhhDR/rlvwW2aDsRUdl6LpOG4tngU0uy8XnGED5mzRe8aaATxWtuGRzY0tr3T3s0S
         dmSg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1UkZtZUe7iUPwhsU7PApvBMdlT/R4FQooLBE8rUcE2kx9eKmvj
	mYMplBlwEM9Q3nLh7A4qAKY=
X-Google-Smtp-Source: AMsMyM5D3MmY1YWW+TZF4OHjZki1oPGtJXBtZoqF4szLadq80fC+UnRimmQVwdJu5lI9RwcOxTVkUQ==
X-Received: by 2002:a05:6a02:309:b0:434:d151:639e with SMTP id bn9-20020a056a02030900b00434d151639emr12846710pgb.124.1664051348265;
        Sat, 24 Sep 2022 13:29:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:286:b0:178:29a3:df47 with SMTP id
 j6-20020a170903028600b0017829a3df47ls13740738plr.7.-pod-prod-gmail; Sat, 24
 Sep 2022 13:29:07 -0700 (PDT)
X-Received: by 2002:a17:90a:4607:b0:202:d8b7:2c1b with SMTP id w7-20020a17090a460700b00202d8b72c1bmr4417873pjg.64.1664051347666;
        Sat, 24 Sep 2022 13:29:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664051347; cv=none;
        d=google.com; s=arc-20160816;
        b=Bcz86kOV3Kc+SwkNMBDrL0/TeduawvzsDISkVAyzQJgdd1qjtoOqwRLKYn1Z5JUrnc
         SiwDyChvXN1L/JxBNoSfszqAZ3l2vLGkawqTpKvipaPpyK0CFpqNR9Rc2zhRZueSlMvA
         VfMAKk55YOSEBaslBG6pwz/6tLwHLaK1R9Il6lxIxGo4jO5DY0b9SIlGm/RBZ8JhQJ8S
         n2XXg23AMF6HEhvBZfhs7NU6E1Y4fPou44SuD812UF9cm9HeFWWcTjI9ENziTr3q0CML
         vDbSoPs1YZQy2cNxj/r4hJOU1wUivfQmL/GUg025e/ZCPWj4iakZltBEcHvOrYInxr0C
         eikA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=SJcg386OCrpYg1LDp2XteU2+Hp2b1/Zp1h3rAhuvv2g=;
        b=NHH2utqPhCDZzPt1dvBazBg8ZuUjk5tmJLbN2hWgFfpuNPemOmiIttpzQFWztiOWLY
         189hEf3AZL/eU6qrEyTIOvFf9Lcynp5IY1Uxob+8+KKz127fRGz+npTMUZuXnuTmdFQK
         dV0QcZWaW7nyMdnl+09C327bVMzMrwyrhlOqtYxn0wp5jWPVwUEcAtGNQHW/ghVMQtWx
         9ucnf7sSONXCAJn45Ie/2KFJKBLJG1LDb62pTQ8TO/FPQv/y70nL9V4dvu3MoAAz7bqI
         3c6xzaMqL0fH1P52IfiO8cbEvFXJdkKn/PzQkB+d1Jdxf06rVdGDz0rv0evMO/evsbu2
         NtQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OdcR6fCS;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id i9-20020a17090332c900b0016bf0148e25si419034plr.9.2022.09.24.13.29.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 24 Sep 2022 13:29:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 2299D6143F
	for <kasan-dev@googlegroups.com>; Sat, 24 Sep 2022 20:29:07 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 8391CC433D7
	for <kasan-dev@googlegroups.com>; Sat, 24 Sep 2022 20:29:06 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 4D516C433E7; Sat, 24 Sep 2022 20:29:06 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212203] KASAN: use console tracepoints for tests
Date: Sat, 24 Sep 2022 20:29:05 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-212203-199747-SS7v7XqxtF@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212203-199747@https.bugzilla.kernel.org/>
References: <bug-212203-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=OdcR6fCS;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=212203

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Mailed a patch series that makes KASAN tests use console tracepoints to check
whether a report has been printed and makes two more tests KUnit-compatible
[1]. Checking reports' contents for correctness is not implemented is this
series.

[1]
https://lore.kernel.org/linux-mm/653d43e9a6d9aad2ae148a941dab048cb8e765a8.1664044241.git.andreyknvl@google.com/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212203-199747-SS7v7XqxtF%40https.bugzilla.kernel.org/.
