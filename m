Return-Path: <kasan-dev+bncBAABBXU3YHEQMGQEKZNQJGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 0242FC9F57C
	for <lists+kasan-dev@lfdr.de>; Wed, 03 Dec 2025 15:49:05 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-88820c4d039sf6393546d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Dec 2025 06:49:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764773343; cv=pass;
        d=google.com; s=arc-20240605;
        b=T4QRWgFPPwmVoB/k2AigsFdgBmgGRCvo9Az7Rh0gOo+dxKQxFmjF5CzAyiCRilwKbO
         xtmgecW8jy732rW+e7pYDaO7FRAY/95VdBOE1fwl5o5X3C+Ju7A+vCNSsV5BDhy0CM9V
         EQAwN6hmfSCTY2c87Fg2XHxNtTBbu8qEvfzGbFLCPV9WpmzzGvxHRB7TA24h+GKFnGOc
         pRhI4lbXfyCmCe2x9VIKC7VxqVuVUs8amIsFfF5UQ5xjYMISflk3fLPzSsE7NCSLBmaE
         HDFw0rWBBVbVGJOzc/X5tcvBmZgdlkn6nH4LH5t9Ay4jdReNe6bvND8f/Xn57a9FrU9G
         RYkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:message-id:date:subject:to:from:dkim-signature;
        bh=cWsihhJgyh2mrXt5C2wH2yjzycQbsOoLfvhkVa79n9o=;
        fh=2wzW8wTdqHhMqignBpSfGnWiyypaX6ss2sH2z+Z6WFw=;
        b=R962YqL2MLwadLo3gkYKZQae4jJKjFlbCJBBElUzYlx7vUy3IJ0VO+asYNVGv72Xec
         2K8enewZhVS2bfHzNWgew1oVoT2VGzzIsUHVKeICvPE0W8gvlvDXlpSbD7udPDrUVscg
         cOY2360oisb4AXAScc7TMFqQSNQ977i2BMKhS5yyilJtthMCXmh3FgvfF5VHorQ2eqqu
         ftp/vSSvbwSlUGGjN9R1X46XGoDtTzsspkT1nY6GVh8MlKDhlor/XCRqZr5DnMujjjIy
         JqW9fB0QyAIgRp0t6M1p5EcL8QGB+2RjJy2RizLpC3Cos8Tbwpgz3CS7R6mxnLadhPHx
         6wqA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=l2LrFrga;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764773343; x=1765378143; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=cWsihhJgyh2mrXt5C2wH2yjzycQbsOoLfvhkVa79n9o=;
        b=mws9sdVdcQgYOfgyVKrKrm2h2SRQpEfXuM0zdcKTknLA4QYCXtyR8xfsm+vOAX3ufy
         1CFYNbM//KjsJh1IpTcYNQ4lBKWG9Jvre+yNNMRGHGnOaENOj+RLpc9Y8ndNjatBaNqd
         jXzyMy3JLNHzCOb21PBT5lKlHmnQSYUFql1rfzZnwvgvT5C6jpE3Bqy7wICBL+BcTNqI
         UYMPrT2/4NYzukwZRas8rPvgudL0L1AtJxUTWNVMg7+m/P+uM25EHSTwaGTDUuKbdWNp
         cqR2gXsBbtAvKrUcumyI4xlirkieAxC92/Iofhy/qys3dQk5s2k9mHl2wpKKGJxIiBjU
         ANMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764773343; x=1765378143;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=cWsihhJgyh2mrXt5C2wH2yjzycQbsOoLfvhkVa79n9o=;
        b=CLP2uUPwXAmSBEYO6INuWWMKOXpc12BjaqTXmrReIaoLvhTgV0P5TXFIQ2y028fSXS
         jNPBqGeESi0/RGQ6u/id2S+SUJM7MEWXObJW7uT6Jlo1XFoVCMAnHpRDu/Atyx2slSqr
         1LryqvZqd0Un9Q2E7XVyiC99YC4bOtqqtUHWDPPKfOkch0JIBNR0iFrU0e00ovq+gGhy
         +aWVjkg1FJzPfEo2WTj7gBEwhBqPA0PuCB+qCqsdiPk8De9YTR/ngsCMl7zYNmZdKgSk
         qf2wZoYKv/ZaDVkgvksC7ECY5tFQRJYdJmiYViilXem2sxVboTcvGYruHv1yhFgBktaE
         WJxw==
X-Forwarded-Encrypted: i=2; AJvYcCXHBSKKb0isROcSHlK4lIXBlZ/8cSAe7wmsqn7S3ZVWU4vmeBhDU1sVrvpXNYaI9GhVVA4Qcw==@lfdr.de
X-Gm-Message-State: AOJu0Ywuqd+0pHsgvJIp/vr/beaXG6L0KSPNnSGVlYFU+1wxpqKX+ONg
	thd4qi1HMcngi/Dkcdkip89BzRSld23E1ZuvE0IMczKnacQvb0RY0mbY
X-Google-Smtp-Source: AGHT+IE2fh6YwL9XNnITvw6J/i2STB2KxLulgw+20XRInT68jlJBNK9bnSqCKPudjxjxlR4KubClsA==
X-Received: by 2002:a05:6214:194a:b0:880:1f14:e086 with SMTP id 6a1803df08f44-8881959b7e1mr35031726d6.64.1764773343614;
        Wed, 03 Dec 2025 06:49:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bVQu6sQmCBgJXO60SXFthHUODEvMmYZfYHvqgFUiDf0Q=="
Received: by 2002:ac8:7d8e:0:b0:4ee:217f:a9d9 with SMTP id d75a77b69052e-4efd043e2eels147530751cf.0.-pod-prod-03-us;
 Wed, 03 Dec 2025 06:49:02 -0800 (PST)
X-Received: by 2002:ac8:598b:0:b0:4ec:f1a4:5511 with SMTP id d75a77b69052e-4f017656b7dmr37413111cf.65.1764773342471;
        Wed, 03 Dec 2025 06:49:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764773342; cv=none;
        d=google.com; s=arc-20240605;
        b=C3Stpk1EvJX1+lAb0qR16/YGqGTD5KJos9U2MRzXHc+eLES4a9E+1qGadIqrRmW1cY
         l0raYjqvpU2ZZCJLEWXwc505ayW8xYqnzwJxJ99z8aGZQOFLl3pEYLdR2yYbj1DaBZJ5
         sTGyXxWnB+XeUEXWyEnJKC2dnPWe4yqJIM1Vx/rIfwQKRq6I4D+11gTg5weLbu+o5IOQ
         rHd8xX0EEngD2/tiKFC33XH+02Sn8qzQuFvMuQMpE10+zBvJNkzk+FmyvX1yXOSpnPYC
         ph/6CXbKmJkXRcRVCgDgadDQeEYV/Oq13N8ocEw+9uFynSzqBL8bRxTJjToPjhlwZ7+u
         j1fw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=KuvjueXjbOIELD5D5dpoYwr8TQMeLvE4feC/5lYL5rg=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=O+QkiSYoZDumEKjuK2s1Bd+fTx8gEJTvKkcj4zJykuXlj64oUiqc4hQm+OSyjcUzXZ
         lbMQGHp0EchOxkxUDonAV4bvGyhoJgvb4SclqTiUjc4v3w77/axVIegxnBgHsgVgl4Ny
         5LtEi2DUaHP3GDz3bPk/Z6V4l0ef6OVRCKtLHxNp2A3iMyi8ouiD3pb1zkPAfWYzue3B
         JxedMk4LhtQ1Mo0M60MQm/ORJSvWCb2dcTzY6/fVytASJDfw+eBYwRiiOQOFdu2C2G1Z
         Cf53ukplWnzGkXJ1jgKnWSt3dWJrHTlzjkAMmjiXd56V4A5vkZUHUcpRxYIhaBbWVIMQ
         dK4g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=l2LrFrga;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4efd2fbb8e8si4228681cf.2.2025.12.03.06.49.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Dec 2025 06:49:02 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 8A03C43386
	for <kasan-dev@googlegroups.com>; Wed,  3 Dec 2025 14:49:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 6C5C1C116C6
	for <kasan-dev@googlegroups.com>; Wed,  3 Dec 2025 14:49:01 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 60FB2C41614; Wed,  3 Dec 2025 14:49:01 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 220829] New: KASAN (tags): always assign new tag on
 krealloc/vrealloc
Date: Wed, 03 Dec 2025 14:49:01 +0000
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
Message-ID: <bug-220829-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=l2LrFrga;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=220829

            Bug ID: 220829
           Summary: KASAN (tags): always assign new tag on
                    krealloc/vrealloc
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

Currently, tag-based KASAN modes keep the allocation/pointer tag on
krealloc()/vrealloc() when the old memory region is large enough to contain the
requested amount of data.

We could likely assign a new tag in this case to detect accesses through the
old memory pointer.

And a test to check this detection.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-220829-199747%40https.bugzilla.kernel.org/.
