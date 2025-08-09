Return-Path: <kasan-dev+bncBAABBAFH3TCAMGQEYQEHL4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id F25ACB1F3B4
	for <lists+kasan-dev@lfdr.de>; Sat,  9 Aug 2025 11:23:13 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id 3f1490d57ef6-e8e0f10c3dasf3460273276.2
        for <lists+kasan-dev@lfdr.de>; Sat, 09 Aug 2025 02:23:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754731392; cv=pass;
        d=google.com; s=arc-20240605;
        b=dLUdKFN7LKMwi06b/jomWoPirbDwlF6bGRdcW68J34QZjsFfGq33BJ8Lf+6z5BUdxr
         9EeBLeDN4Bb7LIMapa9V+Dzei+KnFc6/iIHdYuay910RS+pzqEJRoEYvCAxK+M76DPS8
         y3fT1RL103FqXb3yynnvqVgm5ZCYladOOgkgxjdugD/UwZ4q9XjRm2teZPQbnfh1NQhD
         Kt9awL5zC3lBe85i6jSx3efefRcOiH3cY+s5AaYGcrt14t9sOmcZmIk0S9/iCG9lZCLe
         DH0fjWDMoKm/V0EAieUg/+r0t54R713B6G66yIy7Er9o2lS5i6uwiwLsi/mqgcv4+n3R
         SBlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=Rkn027BVAvMBvJXMk89/sXBMTLFXaUAOae5YFX7hNZs=;
        fh=CMhxPmMSVu5nEdrf6PMZ8AdavqyHiX9kNmoVzgq3mrM=;
        b=ZJQAfDVeIWH9I9EspTS8hHF0AfdNSwKVvac82iLl6x9DLjVMNlovbpPB4u07h57jiq
         E5xYv1DKJYle6u40cK+pmfGQ1UJEKh0TxHzlTTnYwJugBi+OvrYCFGa6T8UcZz49+opj
         kYhej899FJx8DY01t8OXUIeEp5+d9wr1TamEbZVGBigoHPusheYGFYLZr7Duw7XXVhPG
         zROWk444I71WI6FzWXOFPQiNlEzKr+KqRyz76QkGwuMg+uWl2f/4os5qPxo/aWHPbIdH
         p3Yf/6mudupA2n+OGDm9NPWg0Az3IZdAlekwGNgCnXEvIXdZqd+fr6NxOsbg8jDjnv+w
         Qs6Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nvlVFxYJ;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754731392; x=1755336192; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=Rkn027BVAvMBvJXMk89/sXBMTLFXaUAOae5YFX7hNZs=;
        b=TnsKt6zqEpXOx1n7NDps6nVKskkkiiIizKkDCSpwa6VRIgN4lEVXlWNHh/6a7mF2Eq
         OMLGrYc9/r2AVXCuPiYefpfKP79r+Fq4ytfx0fhbqIqJpji9MF6MzofAk92c2CIJAW+N
         FAN1WQVc2y1CchcAI+bxFYrBYL5sDKLe6GWT8fUdtHUsT8q5O4NhH9iyN+OG4dVFINJZ
         x8wnAFBmqclNJn0D4L1MsznWrUuBm5SsK+iJKvMmd0onFLHBBaAJfIvrU/MvnctYo4qK
         jXb6f0jLesPz7hcRGVShVkvKibKwuoofwQxbSh4GmfbEf05hzccXG92n10Rj2tGFWSz9
         R4yQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754731392; x=1755336192;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Rkn027BVAvMBvJXMk89/sXBMTLFXaUAOae5YFX7hNZs=;
        b=c46O9WXalvUDVmyOJ99srFs6+jMaJ8Oscjqq8K9A5oVJ35UPS2eFbwBiKsGkJxC42w
         HWCyqLdCxuWQGYbLsWSHh6fTQxOq4RVvYc5f5F1lFccHM9oSzP4ozwkh81mLk1UXh0u0
         XvzeNjjrIHEVrst39QOKs/oX27cLRYYXjQ2H8ztqN049g1RvB4vqdJ/7I9N/ED1vryb4
         8PFiNURHbwXVyjjNDq0yrmH6/z3g/kfH5JPp3J9diT7e8KbsZhi0Xl5hp3vn6eFXnMLm
         JmZLdHqPNs+mUHirXXOBrDWEly88Hj8fuR7rsLXiPALPRbEqufxCX9jo4zyFIv1bfN9s
         kbuw==
X-Forwarded-Encrypted: i=2; AJvYcCUESlfaTBlRlvimz7NRic0HbAtZ6/ZeNg1qOlIovCwHZX3lcEasQmfYXSM1ulVMzP0Zsd3pjA==@lfdr.de
X-Gm-Message-State: AOJu0YwVMt21I+pXm2daamMxeKtUwWonN5fmefHNUdrAVWaVoBY3n82E
	PDsnC8YYEFG7pdmf2EplbZJJKdHOsbEijCgDnl6iul1AolnhYsWnGXvU
X-Google-Smtp-Source: AGHT+IHu5Rk9/GE8NChdBzLg3JV4+q/0G7X4HCCM6rQv1jBwKw86BM3Z7U3U4iizEN9bDiInzk/lxw==
X-Received: by 2002:a05:6902:3302:b0:e8e:1f55:c2a2 with SMTP id 3f1490d57ef6-e904b65b97fmr6216148276.36.1754731392521;
        Sat, 09 Aug 2025 02:23:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc32BRfVx5jm6m/7T/TLIPLseDUgMeW0M9tPWDxmIRtew==
Received: by 2002:a05:6902:218d:b0:e7d:cee1:1ba9 with SMTP id
 3f1490d57ef6-e9064fe62dals67080276.2.-pod-prod-08-us; Sat, 09 Aug 2025
 02:23:11 -0700 (PDT)
X-Received: by 2002:a05:690c:7092:b0:71b:fe47:a1de with SMTP id 00721157ae682-71bfe47a7abmr54913997b3.24.1754731391576;
        Sat, 09 Aug 2025 02:23:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754731391; cv=none;
        d=google.com; s=arc-20240605;
        b=cEAek+iYa16NM0iU2GQg4UbXQEVN0qnsEnIKSsnRmOQu/CWx26KoD28i33qB8wfPT2
         xg9rbudmKZL1rvfxy9PzF2hLxDAMPNwsCuMDcx/iwm858F9ay/cV4PoeEoqZ0hbvBHQW
         HET2EQ716pzSceQ1Dk2YnSC8eBZXFNrhu0/kT3ISUTbcWPqhSSLo+WWGuKEGpvIT67nj
         DunupFICv51STf/k1XhBWdM3d25/pP8I0v+hhvJpfRiR8Odqo/Rf4ZPxE6XnY2e7QLnw
         pF/fatRGoedRqJVPP802GFiMRCf/PYjBV7aU+lU1TSbxsiv7iD+D054p8VlnO8JVUwJQ
         AKIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=ucH8DFczIuRtvEwP7kUmk1CFPQtaVjFJyVZ5mdaJTrI=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=G2s45Sr8S6UBpaB6JBXNEjSHMwZ/hWEHhnSN/FBnq8c2n0cTRU5Ta3OxJAJuYQmaK2
         hTLoPUxc/KdRMHN3WrGV/EvlZ9waX28VoXvcV40E6Kubkpy6YVGlFzSqWAu4Pi7/VUJr
         LoU/2bCIRumaEScvQooYss2/EKefp/OZk1C0VrW50Ne/nZ0Q6/rGqQNcir2V5v4PMrHS
         9usX0R+d6K5iSGrSSkn252IsXP6ouySJAxIhst5ZYBgSAq8TAOxBVaIEEJypn8OVpnWk
         ruZOHvfy/OqnUt+pUAMJRIwPL9xNS0J020jhXuJ3zlEcKYHaxglg3DHVJwzX8NsVCjDA
         gt6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nvlVFxYJ;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-71bfaf977b6si1052667b3.2.2025.08.09.02.23.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 09 Aug 2025 02:23:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id ACD7A601EC
	for <kasan-dev@googlegroups.com>; Sat,  9 Aug 2025 09:23:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 64E52C4CEF7
	for <kasan-dev@googlegroups.com>; Sat,  9 Aug 2025 09:23:10 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 568BFC41613; Sat,  9 Aug 2025 09:23:10 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 220169] KASAN: detect mapping of freed pages to userspace
Date: Sat, 09 Aug 2025 09:23:10 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: ujwal.kundur@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-220169-199747-hPqE2rW3KA@https.bugzilla.kernel.org/>
In-Reply-To: <bug-220169-199747@https.bugzilla.kernel.org/>
References: <bug-220169-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=nvlVFxYJ;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 172.105.4.254 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

Ujwal Kundur (ujwal.kundur@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |ujwal.kundur@gmail.com

--- Comment #1 from Ujwal Kundur (ujwal.kundur@gmail.com) ---
I'd like to try my hand at this, seems pretty interesting to me.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-220169-199747-hPqE2rW3KA%40https.bugzilla.kernel.org/.
