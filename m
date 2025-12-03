Return-Path: <kasan-dev+bncBAABBY45YHEQMGQE6WCNXIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 27B87C9F5C7
	for <lists+kasan-dev@lfdr.de>; Wed, 03 Dec 2025 15:53:25 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-88820c4d039sf6479856d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Dec 2025 06:53:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764773604; cv=pass;
        d=google.com; s=arc-20240605;
        b=clTR3CFiuubTmNtq/K9sr3oeFA2uzY0bHpg3Wvw1SkOWxrwiHuIv/P71ERilkAo7Bp
         pITR3wR9egi+N8pCUVdNxYB9105Hzgz0CU5q77vesUnDITMaUKb1iBxcBaQioHf9JR0E
         MUKnlwt8tmnOcmTf1NjXcc1GGE2JUeOuT32crOjSt2T9OShn0ZYtjTC1Ym1zx4+jyDSh
         fuHTcVESmedox8hRxhGsLkgXfT5HUR9aMtEgejQi2fDks442nkBY32TWLkE2Kxdcgbx5
         wNuy8HHih42lX+GY7S38GqlpF5MBIpyKRM86z19FUXkKNxnUkR5kYXq7QczUFRzLAgNg
         yY+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:message-id:date:subject:to:from:dkim-signature;
        bh=YrlSlGO4uHh+AxMg1uzNeMfVVOPXF++kTjJlqUpXp/s=;
        fh=ghxDGLlgiiI+LbN41vkIxlOmFWtAszTo1dltG7q1wjU=;
        b=RAc5GYUMWnm7oTAafolqS30CNc/qKKj6wpom3FVKZPIsXqwYHkimI2pO7EBCUcmdNl
         FGvm3JANCqCnA7EhoiBVEPhCV5QIUwbLWvPcvKEMzH57wsHDnlvzwbSd5zOAjnw6CrZU
         YYKDW0OzZVautgJx0BKYVoX0o148yQax9PEFw/fLM6iviUH1rt7UHbUGQPQURQZKeMxV
         TxO4/Nbe3kCMM8Rh0XXppEnAmRfKaLjxKSGcuvY/rMyKHWQMaIpDDY8KQLp3saUK5YjS
         JlMwXoJBqu9flq7AiQLdQoEzeLROiSatD3G4CXzc0daHGDl42TyAtp8r8ZLXOdaX3zuD
         FSEA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OeMeDsp+;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764773604; x=1765378404; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=YrlSlGO4uHh+AxMg1uzNeMfVVOPXF++kTjJlqUpXp/s=;
        b=PWAGG7bnvmmzqvMT+Y1Y0/O5hohGcoOkFowpwzd+BkO68T5wm05K8SlUr+f93npAKU
         NDQLXlG/pgPuXPeCrOrOpCNHPLq/5Lq2snifw8nUMO+mv0ZLkokXy545+OLoZqwJaNVo
         ud4XK8wdSrMMXZTC0CjV0ZnHlmfJDdRFGxO/Z6TDVXyZVPQ78bxIBC6VcdjHPZ1V5FH5
         xAW2ZeoK/7tNdESC9AqVU518XCtLFg66oFZOKi9wj0IXlciA3b1Y6ytdv7p0wmzqkuII
         sFfWsnJpPhvpWrKT+9dFUJwW15zBF7C4Yq1/Jp5RcccEbZcxvha8VYJl2ejpTm5J9jB1
         57/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764773604; x=1765378404;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=YrlSlGO4uHh+AxMg1uzNeMfVVOPXF++kTjJlqUpXp/s=;
        b=iHbhY2GVjW7JcKavqLuFuHTSordm8m495IClnhcTKZb6mm9zy79Qo2znqN99Ijr9fD
         kOCqcsDUB3z2SpR8uQ7klbe5w74E+ZMoRNOOMV49K/c5d3CY7FyeLBKnD2EvCBnz1RxV
         CWj4PXjDWOAR0b2E9zldeGFfNXBGLvkW8/X4tu18ioMq7yghAgS2T6YNvooSWynB+NC6
         4I64oxNAUY+XrnbHa56sPnDYxh3yLdYZTGpdqHafkWuv4Ljag4SE8YQhWws5M3FgY4WS
         6jy1V4aB+lB4THg5AFzptm6VNwexBt3yYNS92xXkYe1oAH2vspUnLpy8fvA1W21nTjW+
         ZzGw==
X-Forwarded-Encrypted: i=2; AJvYcCWx54Xr+AE9dZ8ewWBiRjkbBlzZF/VnYpP+zZhiMHpa2wkOUrUHArZ0CZYkjkvrb0uRXqUlpA==@lfdr.de
X-Gm-Message-State: AOJu0YyuAA2R1A1b5Jke5dYRhv2cDuIyL15DXW7UwbWuwxtZYF8pE7ix
	t6uMv7zoR+ku13ZCBWDTttAVbpef+wVlvjREVH/+Wqu96UkbGQuMr/km
X-Google-Smtp-Source: AGHT+IHyEKOV3VAGzryo2RekAIA9crNBuZ6ruZxjYVYsnSZmuiVeVNgFSRHgtb170jiTgWzzmfHQ+g==
X-Received: by 2002:ad4:5f0c:0:b0:880:501f:5fa with SMTP id 6a1803df08f44-888194b9f7emr34549096d6.11.1764773603904;
        Wed, 03 Dec 2025 06:53:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YKRnnpQQSSHpLsTe0Mgy+7Hru4aj7aEGulS2hb4ylKIg=="
Received: by 2002:a05:6214:226:b0:880:57b3:cd12 with SMTP id
 6a1803df08f44-8864f8c39fels96779626d6.1.-pod-prod-03-us; Wed, 03 Dec 2025
 06:53:23 -0800 (PST)
X-Received: by 2002:a05:6214:3004:b0:880:88fa:d74f with SMTP id 6a1803df08f44-88819587a6cmr40979106d6.49.1764773603165;
        Wed, 03 Dec 2025 06:53:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764773603; cv=none;
        d=google.com; s=arc-20240605;
        b=MBMtWKCduLbcWm8UcRf9zt7QYdY89NZFt1WEbPs5fJK78YKPCctAH4d4czV6VmE3/r
         Ww4H14GsExmJwipTIaV4PMX7S3+7+gVdfjqu5gluFiwjhXC8ufAAC4x8n6Lm0t3HAWeq
         gkx+4p5h3yMhUl8FaKswnQYiAhbTaQEju4HqtMA53/pMKOZmkXX56SgSu7OJIfkIHqwd
         C9Wz5IhNlCaOwARu0ABwR3qKDYurdKz25vVGeQDaBSrDVRxHuCoDwH1QAz2FD+1mHu6M
         qvT9tIAn+6bBkL9IkAs0PYpjBGqzNFzT+Jov2UX32SxvvWbo4cTbDxGmEt3udUBe0f1J
         38Kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=nxJyAFpCBG3qNlRs7QRHbh4ftOzl4xNknXyKBgj2Q/o=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=fMGPryW9K+Dp4evNZAtnef8MzTLo2wtM/Xc2R+Ci6ORnKvtdt5e7oWjzgjjIVO8GmA
         h3elmP2kNr8edB69wp0vrv9pbFZXYaHw3gNTXSdWQZFsD8EEDKMoGwQ6smfr1ZPYQjzh
         S4SWMgyychDLsAG+GvdQtiSM3/c7mGUXDRPZ5q58iKO1CGpdQJanzfUfgN8UssANv++S
         o8wEzjYdS8pBZjK8yP/F/hJv4KqDq2TwmDJubsuzXLBJ2qeV/BPiHoZ6C3fR76T/6zgL
         9NpxxicchcXE04MBfnKlnTEofWt5uq+DRWV4alr86ee1+ZbdKntBbLTXZJoCCy93lNFb
         jhaw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OeMeDsp+;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-88652aeada9si6575616d6.9.2025.12.03.06.53.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Dec 2025 06:53:23 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 99844442D4
	for <kasan-dev@googlegroups.com>; Wed,  3 Dec 2025 14:53:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 7B5D0C116C6
	for <kasan-dev@googlegroups.com>; Wed,  3 Dec 2025 14:53:22 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 6D8A1C4160E; Wed,  3 Dec 2025 14:53:22 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 220830] New: KASAN: add vrealloc tests
Date: Wed, 03 Dec 2025 14:53:22 +0000
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
Message-ID: <bug-220830-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=OeMeDsp+;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=220830

            Bug ID: 220830
           Summary: KASAN: add vrealloc tests
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

We need tests for vrealloc(), similar to the ones we have for krealloc().

Would have allowed to catch [1].

[1]
https://lore.kernel.org/linux-mm/xfqnzil2oiidogd2drvjrzg4dymydywkge4zws2dildgqvcr2v@ns45a6frntpf/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-220830-199747%40https.bugzilla.kernel.org/.
