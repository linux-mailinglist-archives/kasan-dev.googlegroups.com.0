Return-Path: <kasan-dev+bncBAABBCON3G6QMGQEZHNQD4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113e.google.com (mail-yw1-x113e.google.com [IPv6:2607:f8b0:4864:20::113e])
	by mail.lfdr.de (Postfix) with ESMTPS id B15DEA3CD3E
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2025 00:17:31 +0100 (CET)
Received: by mail-yw1-x113e.google.com with SMTP id 00721157ae682-6fb91a99b18sf4165187b3.3
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Feb 2025 15:17:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740007050; cv=pass;
        d=google.com; s=arc-20240605;
        b=ErdluXlQp/ztPx1alQOPVur7SWPGxxaj4A5C9OcRRRH03WFxg44TCwBpX8twk79utI
         6yikK3AqkWn6fp6ivjHL24GvwkBBh2coWZPIeeHP61C7SKQ4S25UP1vz7F62AOgu3NKw
         jwVjMfVLkM0QiXeqsabzom8tXXYGzRNT8JMbJGGaBSqtrqrtHONsFPmg+NFml8Ykllfc
         JlEYrLAerzYYP9A8AQ31x3+rDOTuqHY5bICYkwxLL+wWmX41o0/RF9PAs94rSAndZmrM
         tZBAbCQ4JsTqg0tqyHRLS4VkEFz8II8eHOZIKL6osFfFOcGf15Hq6uI8DeSbJs9LN0yf
         pBKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:message-id:date:subject:to:from:dkim-signature;
        bh=Axwt+7MrYK1Bqh0JBiv2yJc5C8k9puvmcxRDsMf0miE=;
        fh=RZ/S1H54XlAFMRaaaiEa7zLlOcQdDjDmGl+ryrw5pNQ=;
        b=buraM4ovLrL+Vwhus7DzOUeMgV/BOjV5JHaAYktRI2XkA0bhc02mYwE3dlJrFWEKWs
         dYlzwB7EuAi+Y9HkB3vV/SGEHF3EO3nR1fTSkD6JjJJGpbrpR92FkhRhu7nKSEdHT64F
         S8HJqCsanybhESJQlvdF6lsijBbPRVE+0ivtbxysu7XHjV6DQHPhk0klOFM/CrwQA/4P
         g+N2Y0vHHFaYcmms4c7EEk/u2g3MFfdksUQw1PdD8YkLJbr/IVFWPtwfl+ZhCMcHM7NH
         CO55TJ+SYl6+3mv1GgvRvK9K41c0XrQDaTgmOnMSuMBOX0FHxqxroHJPMnjdG+GdwFHb
         gNjA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ToxfO8hk;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740007050; x=1740611850; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Axwt+7MrYK1Bqh0JBiv2yJc5C8k9puvmcxRDsMf0miE=;
        b=KwCiSeBzbuO9jkFWnBFyRgM6iYcuGQe7uTLAafu+OJhM98xqGQmVwIkNKKLh3k6sDk
         qu3D5MPA3Ns1KT2fy6390STfoA+2uIOK6sUJZ8aw39Sh16qGwGPCuebH3m8vmHjwBDdF
         O58vdzunhRlpak0YEVDbWGVAQsrfiyBISkG+XrZN2DdjXxWe556wEosNnR5E+Y03FNpq
         ZFdToRBGv+EZInahg5DZ4pApZSWZMDfKG7TXE4JJDTect8LRL7Z8QbM1DTv6MbYwc0gH
         rXaS1AJoltrUSlSwn7wtlSoNShxcWtPc8yqSEp59GLoZLF0no3YJ1mkAqoFOZ1DNEpvm
         KkOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740007050; x=1740611850;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Axwt+7MrYK1Bqh0JBiv2yJc5C8k9puvmcxRDsMf0miE=;
        b=g/2zUrlh+0vVuoH8rvmLYpQa+ntCya6iFrXXZum8jKCt8UhF1AEguAXrtFZsbyLfI5
         8SUov69QWTV6CptbABN2SsakxLd4XLUJAliEpgDnz4PmSRmTB6mh4IF4t7qVK3pgGQi9
         Qmww4o2ePIM9XzL/jKX44GOmBH1+oW5mMXCa5fuQc3d/5zy8RNG3jpqhyK+xaUKkbIxN
         F5uhsqzL7phKfmAt9+UhEi+7HGrSplMZUxU/uInWZtB0HkoJvA3Jv/iop0r1BhVPqvdT
         L5Ea1SLUxZV//IaOZ2CNdLV10pdH9pJN9YxDX1eHMlTyNew4UhvBDtylqfThOL98gSUT
         fO4A==
X-Forwarded-Encrypted: i=2; AJvYcCUvmrFIavA6vICtQxo23VRCkG+CUxhjGPHST7GjdOIPNlSk6Fbx6t8+qzpjQwjW5lcX8XqcVA==@lfdr.de
X-Gm-Message-State: AOJu0Yy7FKk2MbVmRjVcKRQxoGxL18CQPh8A7O3/s6GH9IIQZNwtHueV
	yMeTjjqInUNaT9m8JkORfab9IBpRRD2mo1E6XOpSBFfIfNOqbu3C
X-Google-Smtp-Source: AGHT+IErtISypjlDtYAFkB3KBZE22pMwudtVnW3FSva3lJJg1j9iNbMHqaEWL4RdvRyD+rnkAVy/PA==
X-Received: by 2002:a05:6902:2187:b0:e5d:c1b9:4a4 with SMTP id 3f1490d57ef6-e5dc930fa31mr16434594276.46.1740007050144;
        Wed, 19 Feb 2025 15:17:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEMTlyun2PRy1QQN4gJoz/eAZVxmaBHljmbKXxSkoe4fw==
Received: by 2002:a25:b223:0:b0:e5d:bf60:53db with SMTP id 3f1490d57ef6-e5e18c993a8ls339642276.0.-pod-prod-04-us;
 Wed, 19 Feb 2025 15:17:29 -0800 (PST)
X-Received: by 2002:a05:6902:1544:b0:e39:6e4d:32fb with SMTP id 3f1490d57ef6-e5dc930fa51mr16786379276.45.1740007049318;
        Wed, 19 Feb 2025 15:17:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740007049; cv=none;
        d=google.com; s=arc-20240605;
        b=AwUj74q813WtrKUpy3amlSQKQIj6BRvWheQoRBVl/+i57dnoEMlzaMIy+CyeFeQXba
         Q9Rn3r2HStViN9X04SKmZXtOgK7j5Z6mbCuCrkDzieK0AQI/jvqo3aKP4/j1VL1okffo
         nyRbqeU2XKYZJ7OnIZwWpmRTZhGhllsDxJUdfJ510feuPRfTBCPE8aJ/tEt/X1kLjuAZ
         cX4qTaUhvquLUZQ76UP+HOCmd4BjLd8beJRhBhIhBKAssZHM4+1dduSv7UYPdE0YVr+y
         Fj96Qn37iHQmqAgi81d+5lE2Y9FWAK5MsHXscpJeDWFT1QAmlgmYdHdhccm8C4AVqbqM
         kL1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=MCZmqE5XfYBGvh8hep76Jc4HPMUuMlpmJCCG8V5NGY8=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=ihcESe0+CBt4a78Ru5cEZ653NDj6Wgki4IP+WeC29XK7uYsyAU0HjfY6ZzPbn7lsb2
         um4qcWvnR7PomO9RnKUpxQaTG43EKYL34pG49BUPYOeQDFXUs0d7IguQPq3rlYwakiuC
         lxSXygpEBFnDrn1YdCcUr+3xeHMES+WWXSppZPyJpKbW7Kif4dDlIXUmeUldZRZZ9u0n
         qiNhqs0qlsOktt1eEcqcCXeI94cxK3UEea5ODk51fAPCi9UjvPCX2kQPBH0QCvtCspc5
         OCxW5ORKlq9cGCnVKlhaLgsgqDMuIkGnthJl5uoBxoOgpaYWqFr9kL920bbSyd1sXmmO
         JEow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ToxfO8hk;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e5db9c278d6si1080323276.0.2025.02.19.15.17.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Feb 2025 15:17:29 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id BAD6B5C5C47
	for <kasan-dev@googlegroups.com>; Wed, 19 Feb 2025 23:16:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 9A717C4CEE0
	for <kasan-dev@googlegroups.com>; Wed, 19 Feb 2025 23:17:28 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 8C6CFC41606; Wed, 19 Feb 2025 23:17:28 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 219800] New: KASAN (hw-tags): set KASAN_TAG_WIDTH to 4
Date: Wed, 19 Feb 2025 23:17:28 +0000
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
Message-ID: <bug-219800-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ToxfO8hk;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: bugzilla-daemon@kernel.org
Reply-To: bugzilla-daemon@kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=219800

            Bug ID: 219800
           Summary: KASAN (hw-tags): set KASAN_TAG_WIDTH to 4
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

KASAN_TAG_WIDTH defines the number of bits used in page->flags to store a tag.
Currently, KASAN_TAG_WIDTH is 8 for both SW_TAGS and HW_TAGS. However, for
HW_TAGS, we can change it to 4 and to spare 4 bits in page->flags.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-219800-199747%40https.bugzilla.kernel.org/.
