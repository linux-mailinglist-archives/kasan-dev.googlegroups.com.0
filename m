Return-Path: <kasan-dev+bncBAABBEPBU6WAMGQEYWJPBRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 5016A81E26A
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 22:13:55 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-554c8ec6b04sf883646a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 13:13:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703538835; cv=pass;
        d=google.com; s=arc-20160816;
        b=UJryT+qeWRr3q8dEie+xMTOQrFnU5PxwTOIJYE+Wuy4yRvVBadyubS8qaK7HQThjry
         LS4MrRIG24dohGfKwV4v0NgRWvVR0sZGGwhEiLtAgTZKXRVew/nQYvfmXso6PF36k3ey
         i5xxgjeM3apMY2CTIgtWED+/GwlGapZ8jAlqRwaCBrKQxmXA+SDj/zmWzUBWMLT49zB8
         M69tM3cFw6DZ3sRnk+npr9FeUoJZ3tScn834QSfLsMwaQ3d7+KDtEH+yCs82L7Phe0oS
         GWv1PHq1fcZfG9MAoPbphLHBOamUHIxvBXNz6kMJzlttPod7U2Ygys+ar5SikLUIK215
         VuUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=pA+B2RznzrMej0F9Ga68yLdqQBOwezHtYT5/WoWoxUY=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=EMf2olF8LR3KZMM4pyo2W7CEdJP5Me8+bc1Q3tG4B+VGI1nygetAIjCqLHEVuVbetO
         q3hkZS9al7DUSrWkaNYnYkJkM1Qfq+c8PaUtGHgyjtJYwIKCFsi2zn4hPUJkAcBq7/yw
         0yyc7CjUiytX7wkALh3Pa4msa2ox0A9esFpmqnlBUJinGA0oggwYGc9l8bcVIdBcLcJu
         oW8TjqLqq/2LCZp9vuli99461I42OiafMpAIA0pTbOACK9HU18Zvgk1pUPnhPSGhNICw
         Ggx5f865DharB1EMb0FSEIV4jo1ktm5Lan+ntRFX4/0A8CDG8ziii1ln4L872Psuz881
         +qDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GbKhsSOc;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703538835; x=1704143635; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pA+B2RznzrMej0F9Ga68yLdqQBOwezHtYT5/WoWoxUY=;
        b=rDteZkERMJS7AgSif+nsZxJowyqN3YwMs/Nnb33MxQtDJcnjqtsMMUnCoO5itbojLP
         AvQ0CZ9/T73/meixYlMi31ihp8d7yv7k/rWTMcEM+scQXybozR5vmLgqAI5Q6JvRSBhl
         W4ksuxHB7Xt1nXePtvcqzLJMpGgfbw0xYGBAqDO5bLSXiWrpJfntNtJKJXR8kx/jD7Pb
         heX77Z5Z6q83FcQIwK+6xhw/xG8Qg6OBKiPwXWAnr6jxNPazu72/Syk5ap72yg8KJvq3
         H8Rvxz+xNbFg3FDsvAQ5Fc6h9nLaP4zJPR/bEfK2PxinZ+vHE2es4EtTnUqj/tuO02ZO
         EXOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703538835; x=1704143635;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pA+B2RznzrMej0F9Ga68yLdqQBOwezHtYT5/WoWoxUY=;
        b=aRxHbbSHzcfIFl2H/4cedhYm+31Uxk0ryLV1DFl9jKHEIIoFcrILfYeuQoxBu9Najd
         OLmWvyHnPwRlsqCnWqqW9Ok65ALVSRAaZVizD+0NXYqdmcWIVixRZWFXj5nBXmTa7w7a
         6gzCXQQVFKR3SDRrhjrz1c7C49j1HdpypJRwkY19PQNVQ4/XRJy3xO1DAMOm5oRbP1qS
         Ld6IOLhahZjE+owBeBdp3xWKsVCmK9Lg5e903NA8D4uJERuARmCZe46OaNUQTYoxhrJK
         FW8zBmMMzP5dYdSYm5gfeEbRwJNm2VuOm1sIYErTIONNMNc7YUqV6j32n9KxE50+qsbS
         yNWQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YznQW7alubMfmGtUvZSET2/5cgQdigalEakf3IU7GE94wmf/onf
	wqPg2RKOh/WpA5meXTAs5CQ=
X-Google-Smtp-Source: AGHT+IHvorLUhI+rWytbtEpTd4t15h7dUNPXcsXqip7RYlii5L50ByVOBpmMBZwK2qn6tcCWSkjdmw==
X-Received: by 2002:a50:9b5e:0:b0:54a:f1db:c290 with SMTP id a30-20020a509b5e000000b0054af1dbc290mr5112355edj.9.1703538834174;
        Mon, 25 Dec 2023 13:13:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:210a:b0:552:aa11:a5c9 with SMTP id
 bl10-20020a056402210a00b00552aa11a5c9ls257939edb.0.-pod-prod-04-eu; Mon, 25
 Dec 2023 13:13:52 -0800 (PST)
X-Received: by 2002:a05:6402:b29:b0:553:2da2:897b with SMTP id bo9-20020a0564020b2900b005532da2897bmr4439131edb.58.1703538832471;
        Mon, 25 Dec 2023 13:13:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703538832; cv=none;
        d=google.com; s=arc-20160816;
        b=gUQFY2MywwOm1TIjEYCt8H2ak8ghpZD+LQetfExBQqR4ZReJhi9EcgqwJqNzOMZeDa
         kfzHrB84J8df0oYKRkXNw2A+rNy+kSxDPhaICmhkgqMUt/si258drstd7G6zQ2EoYW+p
         xXD4vIQ7STsM1rsCeTAx7LL15EaVtM4qxdZKMP83NZZsL+MjTLR8ZcpizZzcK1Fj1bSY
         pow+HhOSkcaWKewWcrwIi7yHHO1bzWEwwiS3ArllDnfiV4Vq6q9A0WSBJC0JfsBFqSCj
         YdDTLblXhdSfFsEQM/FNMlBXBDbdCOASYL1F8bud2feM8gJouL/Z87HEw6JiknOTmPzS
         rO5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=T3JxT9poZNhwbSrerCQbCHAJcSK2yNW32vzz3Bp9mZg=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=B2aV9crFcAAQN6a5fMVCGOKrdKOmLFtbY+XF0ewXKSss/AHUau7JtdaZUr3qgzBDkq
         0NFoIelJ5uR54nF6Uncpp/SAdo0PoOlo1S3IINEgngp4XoybSnNYK2Z1EjAdFszls5ZF
         INv+XggezlKeYqVuxr5MGfXuLQD11ty/EiSpIa9K2qyoCUjNUSwAn9pd9xE1muEHzGvL
         bphZavRrtuYf0WKB2gn8E11DaimnvNoAZU9F4iIsTQqwWmjwyPpC1d3gFWSUQAgbFuUZ
         8nKInUTvG4oDxAkI1wZu2haaPqnQXRnPoTOtL4QeB9NuilVMdAhTBc+906F9T3Z/I3lb
         tILg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GbKhsSOc;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id b16-20020a2e8950000000b002cca9236a6csi242863ljk.4.2023.12.25.13.13.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Dec 2023 13:13:52 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id C5D69B80B0A
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 21:13:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 811D9C433C9
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 21:13:50 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 6CB62C53BCD; Mon, 25 Dec 2023 21:13:50 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218318] New: KASAN (generic): tests for kasan_cache_create
Date: Mon, 25 Dec 2023 21:13:50 +0000
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
Message-ID: <bug-218318-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GbKhsSOc;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=218318

            Bug ID: 218318
           Summary: KASAN (generic): tests for kasan_cache_create
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

kasan_cache_create is the function that assigns the location and alloc and free
metadata for the Generic mode. This function performs quite a few checks and
calculations.

It makes sense to add tests that kasan_cache_create assigns the metadata
locations properly for various test caches.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218318-199747%40https.bugzilla.kernel.org/.
