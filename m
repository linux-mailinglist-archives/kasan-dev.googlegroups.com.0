Return-Path: <kasan-dev+bncBAABBXUVXCWQMGQEDTWJEGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 291AC835AFF
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Jan 2024 07:27:44 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-598e0a8a456sf3352494eaf.2
        for <lists+kasan-dev@lfdr.de>; Sun, 21 Jan 2024 22:27:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705904863; cv=pass;
        d=google.com; s=arc-20160816;
        b=aGQD5FzyxBR6XrtH+d/SYQsw8Bl60GeWPNO46YPofZAidJ/d1On34bBU2QcSTtsbFu
         c4oMO1/uKWSVa5sLmFJ0p/4lSGMCrTasEDClF+k6DGTPJWOTW4HD+IY8ZCFfbSq8QqGK
         ztgAN4BSY74jV+6xUQ8iAMMYqthwPlaPM6vQ+PY/cOGf2/LXSeqn3leC1vglMsMrtciX
         XyMw8xnM9Qec976wsw8hK6mHu5unSKo9Gqu1JZjZEvQS4WFRySUpKMVz5j35m2QvIxd2
         PrseI2Rkvj5Fb/U4EXlTdyervqx0BIW6XYCa831TRZMaTvkQ7jE+gpvlQt52StjH4WIl
         J1wQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=DZJHktVGzu5p//NOqVL2gp+1ZCqzqLyh02agI5xKUZE=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=jZM6TaJyrS0MASypFaptwcHuy1wbW1qX0z/javc9ezNJH7SAzD37S3Tuac7PYCW7ZW
         rCqnAZWv3nj9v8CNDnGU8wHpZxIztBeF6AUGq+t/O0RpSXU+11nyEJRe9S7QA01Ezqqb
         lt7T65jo8AHmG8MWwleaXAPd8gH1Pn97wT69k/O/Knf/g1C2AswZRBbGx6rTOMks47z7
         waRJwfVnFaqBG3ZF1+fT3MLP2HOOE79hFzHRHyS4Ttc4SxYlDSYkRpnqAvPHG8EtG9bd
         oPIHhS3vXsknYO0K7si7EIi4a59F6/5Jb8My2+J0Lci7vvhLShe75AJep7LSc2fgfhFo
         hk+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ehw9Ur1N;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705904863; x=1706509663; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DZJHktVGzu5p//NOqVL2gp+1ZCqzqLyh02agI5xKUZE=;
        b=rtTLHiZ56GKXcCFZeTEVmlwh8Il9mkWSCMSPukKQKVTpDHFInhpIIMZXjk5Y9r+aY1
         zSECAbYLiYYD0bnaYs3wS/p7+r8xEYdZ6foHEO6OLJfhpwabS/Gpwmk1axI77VdqOlO9
         l3tDxm1eJ03n0861pi9Vlf361HOP0p7EHYvUmGhKd0oxTZqVeI5X8z3M1hTk6gd6qH0Q
         Wxj03JtVxGIKT1oLUDqCvYtimg/Bc5ZIq6UwfcfN+GtHfN2Oe4YCW4Hl+yG68pk7WYxA
         kFSsKQbTtNd+82hAH6DExZg3vBB1YpLrqIPF2Ky6fxgs/hJcE3krD66ndjNuwSB9Jb5H
         c7wg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705904863; x=1706509663;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DZJHktVGzu5p//NOqVL2gp+1ZCqzqLyh02agI5xKUZE=;
        b=qBJB+xScNr8tPm7249WFpY/d0fceT/UXL/+KwRvO1UGxxFc5jzTlvCMSlW/9zRmX0a
         6DF6Rb1rms6OHI1ZIdKJw4wGlkOHXznTWAzg5LzZMGYfM4MPvJUZRKfLAgoGGTdVWJxl
         XzEOJUJdjHI0aWPtjG1ol9K1UvbSowc/YKxDqSmudXp52zdDObIQsP0SuQJRXY7GApJl
         JOe5Narz1qBTHp5g+qLQTMw2UUZyJbvgnyo6aaKw8jO8TUZpV2R9n7stDPKSdXPw/071
         fxbQbmbl6EewfkMVjYmzxa1Q8StLxONmRQ3fEbKTYJnIAaSr36BegAhf/djXNMpVIMBf
         9n2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwgMMg6l8hsH3rEzxY+G/y5iufJs7F3PwEF3vu6KclG4PQ4UhTh
	pZY25C4l2P7HZx8pM6YWAd6XW1PVrelZQn2THAGqSt266NutSs+3
X-Google-Smtp-Source: AGHT+IHKqkYEMRebp9wku8M+NRwEru6+hCt/49aP6lPzftP/z+5YPLDCUOAeZMhqTpcJDjWk0jl1hg==
X-Received: by 2002:a4a:ba18:0:b0:598:e2ae:2d9c with SMTP id b24-20020a4aba18000000b00598e2ae2d9cmr1922241oop.15.1705904862883;
        Sun, 21 Jan 2024 22:27:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:558d:0:b0:598:cad2:8227 with SMTP id e135-20020a4a558d000000b00598cad28227ls920861oob.1.-pod-prod-01-us;
 Sun, 21 Jan 2024 22:27:42 -0800 (PST)
X-Received: by 2002:a9d:6189:0:b0:6e0:ef80:c526 with SMTP id g9-20020a9d6189000000b006e0ef80c526mr982193otk.3.1705904862312;
        Sun, 21 Jan 2024 22:27:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705904862; cv=none;
        d=google.com; s=arc-20160816;
        b=e3GaaDHMjMRCyiSe8S1mYhUPnl6HiXxjwh7fG5tmhaDIAWYosZsFtDI+pE6TCFH49e
         y3599iw9xejiI4Ix8C40ySAv26UquFRLBqDZSoRMNlDXJXB862idBRHLRd0mNEIE1M5e
         JYvFeBFQqHx70ARH/7Yhaf+hNBZv7aZ69Q0QZ5aF+5uTM8FYNdjq1d2eZSe0IPhAAG9p
         tWr+3+fBn9g/vO7Z71VU0dnZOAgluPEt50RxY7U/m4UiT1ta/o/fUKugVe/7H7XyqJni
         LYAJ5oYi3B5xpmtt/tvnUWs/Poy7zq5VthyfKifjFE6ybWJzQnMMythzmtrpBme5USXN
         p/NA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=ee5zXN/XuIV58Xg5i99HM7nJQmLiYYOav7fCNlM0S6Y=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=choSbd+nX9XuGXkX7Zf+MujH1kUk4OUfJIH9wyqLp1rEWROUFHIDN4DR/S43up6kCP
         alkT+qC11mne5Jkmnt3NK95RuuxGfAjboashcUQ4xQNm24S7zIjYaaAIq4qZ7ckfkAie
         MjPhZgAu3ms45aLvgNB2Dln+k4Xwj6+6k+1Y5ZZNsPLMYl7JIr0WCUs/HHi6wvuYgCf4
         +/LLkYhuywb7RitBoJcKdbO0jsNlBh2eOriNypUktDGMLLooEPDkYhOV5e+S8OZnE1qI
         JgjnMFIdi2J7Fgp3CSq12fXff1Cmwh8F+o/adlc2wOj+j1O5zPOQW16FqKPpgPiK15Hy
         xTUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ehw9Ur1N;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id dm7-20020a0568303b8700b006dbb6f37f29si629035otb.2.2024.01.21.22.27.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 21 Jan 2024 22:27:42 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 0297761084
	for <kasan-dev@googlegroups.com>; Mon, 22 Jan 2024 06:27:42 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id A8C6FC43399
	for <kasan-dev@googlegroups.com>; Mon, 22 Jan 2024 06:27:41 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 9414DC53BD1; Mon, 22 Jan 2024 06:27:41 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218313] stackdepot: reduce memory usage for storing stack
 traces
Date: Mon, 22 Jan 2024 06:27:41 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-218313-199747-gq08xmqcNg@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218313-199747@https.bugzilla.kernel.org/>
References: <bug-218313-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Ehw9Ur1N;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=218313

--- Comment #1 from Dmitry Vyukov (dvyukov@google.com) ---
What are the intended use cases for eviction?
It's not needed for testing/fuzzing scenarios (worked fine before eviction),
and the locking/refcounting overhead may be too high for any production uses.
At the same time eviction is not guaranteed to bound memory consumption (if
lots of stacks are used, they will all stay in memory).
It looks like use cases are pretty narrow, but we pay a high price to support
eviction both in terms of memory and speed.
I think eviction should be optional and shouldn't have overhead if not enabled
at build time.
If we don't have eviction, we don't need size classes, we can simply allocate
exact amount of frames as before. We can also remove refcount_t from
stack_record, define STACK_DEPOT_FLAG_GET to 0 to remove branches, etc.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218313-199747-gq08xmqcNg%40https.bugzilla.kernel.org/.
