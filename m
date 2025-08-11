Return-Path: <kasan-dev+bncBAABBHXE47CAMGQEWUNO5II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id A5A9EB20A72
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 15:37:36 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-4b085852fb8sf178622231cf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 06:37:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754919455; cv=pass;
        d=google.com; s=arc-20240605;
        b=PAqZgFNWrhetffdJ26V1vavAgqHw3AZ2FkkAFDhtMlMw80uZr+FRuBnLwow9e+PMoT
         kA05E01+wQHTZN1baXpdgRdDl5xuO/pdRciHga0qZyUEseTykfo7dOpmyA+GXfJZ3C13
         8SaYfq7uYWhe3hpnWJGqVKHNrscT4Q1S5MDaIewmhRR1vKHC52/mFro2AhMZVsfVXvyo
         WNjI5rZ9HzDgveNSnLEd+I1nVY8BY0MGXaLV6BeGWzrzz7Y6B2Grt9zyqbrxI3D3XYKy
         +1pbj52X3WboZRq5eBWpkY0r/DGoqo0PvWul+9zbTqJ/J/kFUdB5GF1DjlTFYsJb8jYH
         ghtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:message-id:date:subject:to:from:dkim-signature;
        bh=a4JPmZbP+QUi99UG4qGzsWd78tGaBiL3HVlGp5FsASs=;
        fh=FanNI13HBGKCgYUBA/AtkEcOWZWNXYp19+u3D7x25ms=;
        b=c+YZP0inT9XqYW0sScHuXdmL3ZUfFhUy7g0hFJ7cTtxuH6Ln9z/9EoeNpAjWvOF2ul
         9z4VGBCtvOvDsYzIJbpQ8DV8MzST3TpafKQzVJwpVz7Mw2V9gLI/0pklIFXnP6NU8Pn/
         +n9SeIKpzfRYMYc0xFpJMV2XSct0+qaWCVXqNfarB3Z6ycDStzcmUXMPhAOeNcOtZ1q8
         PSieOOxy61n8jCTB5X1ue7PIbAC7M58rx6hOhNMTl9U/WnrUzeItw45VoKheVZ2/Vx4G
         5Yjm17f4oS2mtKDKNnl3zI3B7FEcEuZWO3Gd+RYZua2dWyE7YDARro/q45iNsUvQRJx1
         ALrw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BJSqeL7Q;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754919455; x=1755524255; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=a4JPmZbP+QUi99UG4qGzsWd78tGaBiL3HVlGp5FsASs=;
        b=JNZ9aPd5f5CrMW1k4AtpbCs4eaM7jKUA+UFAtVKySjfjnEBbATmRTVxCLzD5mtssGR
         vHnHuXwhyCdrEpnP01H8sBzSSc9ffokTWIus19atDMpnj9Onl7Kse6QUzpD2HtNna8BD
         4w5uzuXEZaieWHNVmaxAorMP66uL1k2tEDIteXON91rmglHUhrHc2ySTQqKZjljjumi2
         6I1r4vbN+I6cuimNF6la+tq/2bSvjuAgEh8X3qUqIwN0lXHrJytM0pScFKGnib58VDys
         PCSbN+dpTmw0EJ3LkUdnctYJhdj1WZk7eYffWaZsCUImoH5PmBpWegjK0uy+lK/BDFG+
         9oUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754919455; x=1755524255;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=a4JPmZbP+QUi99UG4qGzsWd78tGaBiL3HVlGp5FsASs=;
        b=soe2ouKapGgMXIkgvDEwh8jGpptGltnidyvnEzNCcx+D9wkaYCTsJCr3QwIrDZ+BIK
         qtgmtrRlBHwa/5vEa5GygYNjqZ+xDQYq39BtIvGxMMCTenVBz/q7yqhKnMP6zjbnbqoo
         7jAiSH4+C1WYwlei6OQSQVVx0LHkIaZiolFjKpadcgLgqA0vCCs3xeDL/jqGZ2jrCyHS
         2wrS2WlL3kxwmFdlnQS/QMeNJrCAH+TptPFGOJ/1heTBjibGXj9eca9seBaJrNRY1sEJ
         LiXgiYxM2zSSOyLBJdEtsU4WpnJJicJ5+0fF/Kb14HOgcSZrmWMEL8B5IwTwR45xYmKr
         D1Dg==
X-Forwarded-Encrypted: i=2; AJvYcCVOay3sPVpma0NFqJLl+YVL2foSHc8SlM/XaJ6qHnmVnoW/g0UXwmLtDKkj8txxLMvhPlU2fQ==@lfdr.de
X-Gm-Message-State: AOJu0YyWzT3GszpeRa7ANa33twlLAfMSM3wXSz5joNyuGXq+6O/phdaQ
	OK55eM5xsLBh5R5BBE1eGjmAAkl7bdxBVu/qm99N5ZnaSr3wN/ssneer
X-Google-Smtp-Source: AGHT+IGD0LK5tvZuXlYICTgH04yj7ex0xOWxiCxcHG+loonbP71pZMznSQHQIDjihNGEAptKdChNYQ==
X-Received: by 2002:a05:622a:5509:b0:4b0:851c:538a with SMTP id d75a77b69052e-4b0aed0aecbmr158542031cf.8.1754919455154;
        Mon, 11 Aug 2025 06:37:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe32l/mRt69Liq/pzz7sDSx1opi3zRAEm41jadmsTMDRw==
Received: by 2002:ac8:5891:0:b0:4ab:9462:5bc0 with SMTP id d75a77b69052e-4b0a061729als71419771cf.2.-pod-prod-06-us;
 Mon, 11 Aug 2025 06:37:34 -0700 (PDT)
X-Received: by 2002:ac8:7fca:0:b0:4b0:a1e7:902c with SMTP id d75a77b69052e-4b0aed405f6mr179787741cf.16.1754919454426;
        Mon, 11 Aug 2025 06:37:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754919454; cv=none;
        d=google.com; s=arc-20240605;
        b=AxbLl7HNx2rlU3plcvDNR7tWWNC37znXETBMu+LyjkwZEIaDW1WP/m5KsRiHbvHMs9
         kdLy6UniNHhZYSCby31sU4bdTTS77TDMgukBvYkHoLmHHxvakE5BVizGwKiEaWsP7+Tl
         iMiBpuIojUIiITLWJYuah6rgHRZRKCP49ct7/zdrClPjr/jkmpHuKi1ScD4aa3sCVsdP
         QvrtbAjIfW1awU501Q6+bA7PvNWIPK1HuyL7tY5q/8dLwr2gZVXWVxHtO82vxMlmbbRs
         QwRRIXzrMtm1aeNETISy00VFsHH3HecALSW/l4WdcXgVNPxpPokogB1enV3Z3LKUY/xk
         dESQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=eYqCCxaXQd+a7uEggVIAK8V5S4qnvQeaj365ipgiWyI=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=fgjL6j1Zx7cn4QvsUXXhz0eE7o720Cm4JeLSG5F38sWyYL9IhQzIQcqGutbQSOerXC
         pk1TqGCGNP1CLGBfvZ+LYyI0uWmmVFLEQm+Vy3BPf7r38MqASx+9gHoEAkhXLXUIU5O0
         fUNqQpwFh2O6AMym5T9lR8lBCbBnbQFzPI8juJDPVm7cree89lfu1QsXmN6+KL4Onkt0
         EnFW+Zmx7ABcerrXkSCtmmhslZHDjffyxpQjwdGYlDkXg1jGYogc5Reh6sBdIIEbgCUZ
         6ZlMoLRZKwr6AJ1RyzM/J2DQj8496l/L6MIbh4PwVCfZGtWo7mjxlGJavhGZVfDB/r4z
         d1pg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BJSqeL7Q;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b096b6d8e0si1069181cf.5.2025.08.11.06.37.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Aug 2025 06:37:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 1F181A56EA3
	for <kasan-dev@googlegroups.com>; Mon, 11 Aug 2025 13:37:34 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id BA998C4CEF4
	for <kasan-dev@googlegroups.com>; Mon, 11 Aug 2025 13:37:33 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id AD19AC41614; Mon, 11 Aug 2025 13:37:33 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 220434] New: KASAN: respect GFP context flags for vmalloc
 allocations
Date: Mon, 11 Aug 2025 13:37:33 +0000
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
Message-ID: <bug-220434-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=BJSqeL7Q;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=220434

            Bug ID: 220434
           Summary: KASAN: respect GFP context flags for vmalloc
                    allocations
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

From [1]:

> KASAN is still failing to pass through __GFP_NOLOCKDEP allocation
> context flags. It's also failing to pass through other important
> context restrictions like GFP_NOFS, GFP_NOIO, __GFP_NOFAIL, etc.
>
> Fundamentally, it's a bug to be doing nested GFP_KERNEL allocations
> inside an allocation context that has a more restricted allocation
> context...

See [2] and [3] that fixed a similar issue in stack depot [4].

[1] https://lore.kernel.org/all/686ea951.050a0220.385921.0016.GAE@google.com/T/
[2]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6fe60465e1d53ea321ee909be26d97529e8f746c
[3]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=70c435ca8dcb64e3d7983a30a14484aa163bb2d2
[4] https://bugzilla.kernel.org/show_bug.cgi?id=216973

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-220434-199747%40https.bugzilla.kernel.org/.
