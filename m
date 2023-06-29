Return-Path: <kasan-dev+bncBAABB2PG66SAMGQEVY2BSJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 22B68742F53
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jun 2023 23:11:07 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-34593333548sf5244815ab.3
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jun 2023 14:11:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688073065; cv=pass;
        d=google.com; s=arc-20160816;
        b=gHmgDAXTpapIqRseKDl17ydHg4cQVP6Wg+oiy9LD7a3HPsH8/fFyXx51gFdyOZf55V
         LCUo2vA0at1FR4t0L7ApFHBZzso9ttfoBt0+qAnN4TTxlDc1ub9jHaU7EwyBMpKY9JHB
         Sx6Ni0nRvJthrbS6c2xcvP7sXC9G4/ImJ+1Sebn2hUR1B3so2T+Dz5ubcpZBSne9aWH1
         2bKr8kRp0g76Cljt4uPsEMjbS2LZPM6wd48VgDqWLdiMxDl9oS95KCisSgDP83wJxKNq
         cm1AdKNi0bSDfnlqUoa1cV7wM4eC56r1aiKSF74wsrk3zzArlB/EiukeiG86yTTN0US9
         NyiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=WGF17NgHcRnpHTuD3+yq8x6RF5KI1VrFgIrmFtHjKOY=;
        fh=DKBepnc4MQU5iECICp0yzPMRbEkFfxKQwwgklF3yzXQ=;
        b=QvfwDGU9V5OshDaPg3G/asdajRaBcApP+ioP/tXxiS04TBw9RZvkFaDKBZxUqAw4Fk
         5UXhzK3NiZlA1ACNrWHFB7iSGqJ21w8EXelaMT5q8uda0UAMnU0P6461SsNDUUgWHl/R
         gu1dKzSZ5ytGkg2NNPdn/FeR07Vak4foC0u8hL4v3r2asg35tuYtYw4aOuSpCu9kYqP7
         l5WLgdfgUn8BompQV2QHkBhmyjU+F8kaIfa9MGpJ1M6zooe40b/ra2JADShSiVEFdK97
         7sqjxyhMeCaN6eurTrGtD2x/7Kkv9iN+BcrhJQs+ls7qGiplKlLktCVp3byJs8d6rtC9
         Ajig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YbdhzTCb;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688073065; x=1690665065;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=WGF17NgHcRnpHTuD3+yq8x6RF5KI1VrFgIrmFtHjKOY=;
        b=CuX60EyNHNoLw3TAHs77etoM6V8/YMSYjwOp9vmxHuBygqccwTMf8jAv6q0NCq1hZ+
         araAWA3T+Vrn1n9jVEta7oieNe+dL8xobClKAUkCcOPDa4+ttE9H4kaQeT435ZKvMgTI
         gbmqHB09lyJWLucY6hiR0pq3ivDrUyHQBEbnPPQsexA9VSgs3df6JM4IeRc4P1ifo2as
         sXgpjN7RMvPRGszG1vvb8jmSk8uO9eu28x30PALccfNCjl9lka3xj6Ob4NBcGYtWLL2Z
         KCX8kLXlxg5GNgjTIxQdNnIQzoJ4VoFRtVbKV+YVdgxxq8ccj1eGbX4ve9aDl5apbQlo
         CqgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688073065; x=1690665065;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WGF17NgHcRnpHTuD3+yq8x6RF5KI1VrFgIrmFtHjKOY=;
        b=MfEMJoqRBC4meW4Bo8EqxG3F3EhaQItHB7yuYUjHMjZYh08vEEDyGGhOXT+tbhjNkg
         LRijoN5h5Ea7FijBmCKy3KH81GDk/ktJlsgjcFtUYBwrCq/sOWaptBnFG5jOatJUSdlo
         CmEgPHLNwiqulSBi0MJqC57eBO6de+aNvuEkwcr2nPu7FfuHOk2ygFXhRkuKkzN7+y5u
         tSNOcDDE+I4lSpVKFDZD0Wek6G2i9vPojwb2g3ZEjXbXLjSL6ZanGAI0BWIlkEsIU0/R
         E8sgLgcdVUzb4v6L1cbloGs8BStK/REieZuyFeAZQp19f5CYUnqS4i/4R7WjX64gpHg8
         KQgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLbNCdNCJ4cBv9//Sx0AX/GKxPYv9mV9RaViMLCuSpCnrerw1Lol
	+n+/a0sXBKextSgtElTD+KE=
X-Google-Smtp-Source: APBJJlEPWxOjUvgalisMFS8JDlz4GoXF1WvtzDEcNcTfBRKSRzagOG9Z+xrsYou1082EKYCpZWci/A==
X-Received: by 2002:a92:d6c3:0:b0:345:ac15:68f with SMTP id z3-20020a92d6c3000000b00345ac15068fmr309775ilp.30.1688073065733;
        Thu, 29 Jun 2023 14:11:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c642:0:b0:342:ff1:3d84 with SMTP id 2-20020a92c642000000b003420ff13d84ls555366ill.0.-pod-prod-04-us;
 Thu, 29 Jun 2023 14:11:05 -0700 (PDT)
X-Received: by 2002:a92:d6c3:0:b0:345:ac15:68f with SMTP id z3-20020a92d6c3000000b00345ac15068fmr309758ilp.30.1688073065272;
        Thu, 29 Jun 2023 14:11:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688073065; cv=none;
        d=google.com; s=arc-20160816;
        b=DoX36+Ae2VWr80OMHhmNRGv6Kf643iI1tgwMAYHXEdLXrFJY2N5ojA98mKt7vCqGhg
         Jr3DH/vRAHnlECT2BuiXWWoVp8aRZbySeRhnj0xUmjfjE1WzWcQGFeXN+NA2VfPz6JYz
         moIyyjFmpsWEcw1oB3E+mXVpT89TIti1QO80nVEWkFIKKEVGODWv7JkXHMGmGU2Xv81l
         9L9tny8k+F44t7wsI/RwjcteL/hThY9KKc+e5DKmHgE+vUOZQtCAgVIzJ0xTnV6iC2zc
         rMn3cfhWBjE6+KlGvqnqgojjeneP9DMSrR3BPr5/JCNy35p7muLEXcx4r4o1hGlbueTd
         vPwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=aF633VqpJnp9I95px8MTdC8QXWP5RB7lqyf1M4t4GCo=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=NWyIou9SheD3k/G9lXeU5cWT4HOgE76/m8EgwotOeDklxd6NRYyOIzeYMcTAzWVHLc
         /+RonSXlRk920RUlg5qCVpYjIG95mBdmK/Fr5KG93yLc69VAM3D7s4JojDpUtiYKGsNR
         m03COle6Gt80lyewc7Qq0kiXuYNk6/xNQvtrK+n44sesM8Ej7HTZMjTdKDg1GS703+Sp
         nC9LkfNgOiPE04E0qJvettruodzfAkvCFcN+Wz23vwJB/g0vuAgp7vddhAJUt/rZ3bcZ
         w+fk372e05sp2hzGeTq4eQTBlOT5CQzsIZL8UhiEEFwK7Muh3RHKtPaMwuPrZvqZBEBL
         pkuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YbdhzTCb;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id dj8-20020a0566384b8800b0042681c2d789si833507jab.5.2023.06.29.14.11.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 29 Jun 2023 14:11:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id DF3F1615C3
	for <kasan-dev@googlegroups.com>; Thu, 29 Jun 2023 21:11:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 51947C433C8
	for <kasan-dev@googlegroups.com>; Thu, 29 Jun 2023 21:11:04 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 367B4C53BC6; Thu, 29 Jun 2023 21:11:04 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 217612] New: KASAN: consider checking container_of
Date: Thu, 29 Jun 2023 21:11:03 +0000
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
Message-ID: <bug-217612-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=YbdhzTCb;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=217612

            Bug ID: 217612
           Summary: KASAN: consider checking container_of
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

Consider adding checks that the start of the container is accessible on
container_of invocations. The idea is inspired by the "UNCONTAINED: Uncovering
Container Confusion in the Linux Kernel" paper [1, 2].

As mentioned in the "Time-of-use Checking" section in the paper, using
container_of with wrong types might not immediately lead to a memory
corruption. But arguably such uses are bugs on their own, and it's worth
reporting them.

Note that the approach used in the paper goes beyond the mentioned simple
checks and also checks container_of for nested container, see the "Container
Nesting" section.

[1] https://www.vusec.net/projects/uncontained/
[2] https://download.vusec.net/papers/uncontained_sec23.pdf

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-217612-199747%40https.bugzilla.kernel.org/.
