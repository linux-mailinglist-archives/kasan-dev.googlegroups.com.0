Return-Path: <kasan-dev+bncBAABBTOU3TAQMGQECPLEOOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 1032CAC6CC1
	for <lists+kasan-dev@lfdr.de>; Wed, 28 May 2025 17:22:55 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-60b79e21d8bsf3775471eaf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 28 May 2025 08:22:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1748445773; cv=pass;
        d=google.com; s=arc-20240605;
        b=V17LK4YosnPrUi5ROE7bCFKX4ZNKRe3JIhgxjBCGFVZbxRnKX1nLCaVQZmDdkenaZ/
         MKLNWRAltxSKBRm+zWpitCHp3g7Ctr8mcF/gcdoqqUtVfKDYejywQb4Pnmi+KjCl/ZKS
         blB9dmG7UrBmNA3uRzIZZ/Qo5BRIkCvprPaL9Yyga6yBINrA1okO4DsZFX/j3zLsQpCc
         IK+1FXuFxVSQ5AIjyC8XCDgfv+v8dYY2S5siT1G7b8vMWo3yUNctIIPT3Qy8j+IARJtk
         ygOq1MtS4NHpezyqzk+veuoOyYxGt4X4uHIAw7H+5nb3UnDf7OaZbWL4Mt5vHwMvhvpx
         B1zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:message-id:date:subject:to:from:dkim-signature;
        bh=ijTJOIjndNgmGcnUp+Fm3cHPWH/gQdbJMhU4xtpIov4=;
        fh=AcEDus8c6lJxgdS1KmE7HEoz98MNEEELhyEjp2tyS30=;
        b=NtvX/E2F2jOBbQ+kskoVqIYgj2nr5PQ2xf0+RT+cN8gXyScpQFHi5dDKnnlXATSOdN
         EI0hIVHut5RUGaCnyU2Cj6Yd1Qa281qV8wxSYTab1M/32dC0To5ZenzMOmHURq5/ngCW
         FVOZP4utd8RglLMktgIPNwW/9qJGeLp9FjIsjdWyg9EjBNadarJO0JDQG6BiOGnQP3R3
         fWsBFmajy2w59Aywb4YfZfs9M1Fo8O2TscNadHqcan+0JpX9vCtvDsvPi6HJIJnTqDjS
         HS1gZLNHu9Ivmpg1iGkTPBPbJeVXEeYrr267A75GWsyblPrh+KqeHhpaYZji2aTdDZcW
         7ubw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KI68kvvJ;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1748445773; x=1749050573; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=ijTJOIjndNgmGcnUp+Fm3cHPWH/gQdbJMhU4xtpIov4=;
        b=Ri/lJQPhzzl6zoJKFxlvrazzz6tFz3vWDfM3R6mhbf5gi0o93/n306ZuzKgfBz3lPg
         FxMRHo5URuIBIbmtAskBDA2a19bB8z8RSMI9O1c5mKrJsiab2bT/sEa6fR4Hm2DJ+7ll
         QRXVZU1KnP2Z151E7JhCiCJQTpEjRIujBH3n0uGsEzXY9tNQc9C9WT1E9MN14DjaNlEn
         lCpLG+VG+WnNEgw3j0VWA3IZ8a4oJnx9uMHOYtZZfhnH1IDOF6FdeGeXJYsDcSR3p07c
         AOatsW/BABgoZlCkSIhNH1dq5kdeY0y0If4gKgsVlVwQOyr1XwSLKYR3a0FmcywgHpCt
         iHPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1748445773; x=1749050573;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=ijTJOIjndNgmGcnUp+Fm3cHPWH/gQdbJMhU4xtpIov4=;
        b=OCjPBZBz2Xtv72XcaFvPCbywXGecFubjoEeEuYI3ke0J6Jild4puP47a7SURrGASsa
         osrCr3ML+3Q+HI+pbTDmdugyHwLUY/ruKFzQPf9+hXZ1Ex/F1sad34aD31WTwKGwtXjV
         uqzizomEnafittKoyRlMHWHVwGrnMn/HP7JCtmniKm9q0NBRx0Vg/e7M5C1ri1/7dax5
         f/0LEajrlnXN9e1ssUTmG3Rt8G/Ntls75zt2z5UmgKKwjYaYUHbgKTTiiUx6V9O8eM3W
         6jFPY8jtbdYpqRQ1I+4vqCJ4215glc+g3n256seyLLDS7/R5FqxMzsVzTehecs8C+hUo
         8J8Q==
X-Forwarded-Encrypted: i=2; AJvYcCWfbPJt+7hZ3ORo+BfxhjJEVnd6q61tt4HRxB86R+wlJRcHx1HvpF1R5d6AoBPMXICAq8fq/w==@lfdr.de
X-Gm-Message-State: AOJu0YwJGs+QlWZ4ZjqDhL2xZsxpR4SqUiSViHCi6YYEbHolsT1xZYFO
	Nhrs6uUe6lPGU0YV5EjtN8VKiG0YpE29yFy2qR0dohw3rwO0CsBZg8C1
X-Google-Smtp-Source: AGHT+IGXzkGg6UzbNuCRpmn8SCOpzwm8pyqiSRmrMM8sDNGPPrg6daGcHSpNu438iJDhPZMWrRGKAw==
X-Received: by 2002:a05:6820:2903:b0:60b:aeb2:988c with SMTP id 006d021491bc7-60baeb29a2fmr7900787eaf.1.1748445773447;
        Wed, 28 May 2025 08:22:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdQjNT1oWtP8EmZAzKHGpnRpD0qt/mKkEVWIPCIdhzQGA==
Received: by 2002:a4a:e51a:0:b0:607:dc9f:dc28 with SMTP id 006d021491bc7-60b9f6ecb5dls1572282eaf.1.-pod-prod-05-us;
 Wed, 28 May 2025 08:22:52 -0700 (PDT)
X-Received: by 2002:a05:6122:d9a:b0:526:19e6:fa34 with SMTP id 71dfb90a1353d-52f2c4fe87bmr10866254e0c.1.1748445772521;
        Wed, 28 May 2025 08:22:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1748445772; cv=none;
        d=google.com; s=arc-20240605;
        b=KofZaTgzizB7B0//NiFT9gswjojLWnp9TEPfIk9GBjoL5fbgsBAOpjb2jMwwJiEZf8
         qStmzFjCV+KUItILef4REuSylQRTNH/jm7NsfqdG4zCwJDQrZf59lj08unqi9pW2Q+kE
         J/y1idt4vuc2Z5F5dWZzsXgwozO3tbxFHyUraxFHNYvR5eQxtdkyg29XqKTEAX0tFAzC
         p4oLLwyvCYd3SzBrZEDXOpW+4vPoaZ9AHQbpNl63SX4ICHC/0iSQYfEGEBQxGipPSboX
         MYrjyQy5ESlCE5Px+iyLbFuj8DfgSWpSKDYJO3NTWNS7Ymj2lg4keBVEyOOnf3tRy5hz
         jPrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=iG39liHofLYao4G9SLwTwSKu1N0UEbuajeBfgLUjlR4=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=NmRcLxwSsxKAZMTBp47lPy7Qw76bEOKSPTa5ld/7qSqpicdQOsUiAKl3FV4ruWFLRG
         F1sEHud92TtLcwUrNVz5qYjZikSO6jqrWJ59trZZXXdzcBLHPwdKhN9rJj82DZzjbRKw
         WT/A1UF17l111K7gIEuhLOQZlka3+Lb48FWhRJrx20TjZ8USppmO4+RQOKPz48HScQ32
         rUqBS+sw8QhqaY3IJo0vU1cgRCzcwvqF5QIdGwgoFyz+qs5Xsvc/xXndjglMQiMCmBXG
         KMZevm+xDYFjdZr4ZSC8oMjOK7gJgSeKq6nKDORgUFOXHq8qSxRHftru5sxWvTSQlueP
         4Wgw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KI68kvvJ;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-53066938df0si66095e0c.4.2025.05.28.08.22.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 28 May 2025 08:22:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 6E382434A9
	for <kasan-dev@googlegroups.com>; Wed, 28 May 2025 15:22:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 4C65EC4CEEE
	for <kasan-dev@googlegroups.com>; Wed, 28 May 2025 15:22:51 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 2999EC41614; Wed, 28 May 2025 15:22:51 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 220169] New: KASAN: detect mapping of freed pages to userspace
Date: Wed, 28 May 2025 15:22:49 +0000
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
Message-ID: <bug-220169-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=KI68kvvJ;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=220169

            Bug ID: 220169
           Summary: KASAN: detect mapping of freed pages to userspace
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

Add KASAN checks to the routines that map kernel memory to userspace that
checks that the memory being mmapped is allocated. Possibly relevant for all
KASAN modes (unless there are other debug configs that do this) but likely a
nice hardening for the HW_TAGS KASAN specifically.

This could help to detect side-effects of logical vulnerabilities similar to
the one in [1].

(AFAIK, this won't help with the vulnerability from [1] specifically, as there,
the kernel pages are freed only after having been mapped to userspace. In
addition to the pages not being freed to page_alloc but to the Mali-internal
allocator instead.)

(Another thing kernel/KASAN could do is to try detecting the freeing of kernel
pages that are still mapped to userspace, but I don't know whether this is
feasible.)

[1]
https://github.blog/security/vulnerability-research/bypassing-mte-with-cve-2025-0072/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-220169-199747%40https.bugzilla.kernel.org/.
