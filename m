Return-Path: <kasan-dev+bncBAABBG6PU2WAMGQEJY7MZ5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A50C81E17D
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 17:02:36 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-40d307e1d4csf3692525e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 08:02:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703520156; cv=pass;
        d=google.com; s=arc-20160816;
        b=p2CMZ5zMrt687sat3WcbF2OLNy9c6ttP69pf9TphvPjJe09uGIagb6R8bH98TVxGav
         0SCn1lj47H2jTOpuzmvb/zbcr7mhGAxJ0PgadALINP2GuaO9f106UP8a5rzX7KLyHzl1
         uZpSgKMINvYH8ovSjpPDGAMH/tAxLpcNPXipnaVCuj7f0duCIx3DOe0lCkMleWIgeIBH
         xwwUer6ikC5BUbSKvzN1PKNWMjkfJ2sNhw18IBErHq2z4JvsJErsgerB7w8ZpCgpaXd7
         38OmZ/IUgCVWXC7lGnnHvmKjd5dO6IogY8WjROcF/DS0q3HPjv6GmtFZyzOTIax+N0Cn
         /jOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=kK462pZcf7qYrNSwjIcaJ/xxYMwBvn70wyfd0pc0fjw=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=cE0Id3Q06/+XxYa9mVHhEgWVoqQpKzrPLh1UPo2uYFp1jxkgVQelOoCYZf6GtChtpO
         Q4x5EuZwqjUgdfncSqYG7AGMIRCakN0jVOPPIki4/AWztSr9GrzK/4x4uWSZiLnpwUKv
         di2+qnHJsSpFQUuUQPzdHtyjSnMJAmEjqF6Z3KINHrIFdoNxVUg5ztoIBKaSJ2h7efIB
         kWyZ4wYx4OQKeJM6xLIB9jDq+XcYYfD/PXC2rT5/GtnthMVgUcYhJXtWsdUR9ghz5pma
         CcK2/WEKhcOLlSA4+1fLPx/IKiii0mhgYGHnd3V0zT5h6i0WudSYKXlb0GA3jMS2ekOz
         /daA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="LmZK/YiR";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703520156; x=1704124956; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=kK462pZcf7qYrNSwjIcaJ/xxYMwBvn70wyfd0pc0fjw=;
        b=bpmtGE8tDRoW31hzfHZqjXnee+AnUKfsmYBEaiKFOrzrY78ci5CoXLi61Xw89kcawT
         kl7F6EmKLcS/YMwA1RtNCbziKpCZknv4ZMdt75/QCa49GsDHk+auqOoUX73TJE4eSMQi
         RW1F6uQSZ/r1ytFLRXWEsOXTCe+PwhJHdslnk6Dwq+RQPGJHRn57k63DnUbW35eq9VBy
         UKaHXnzQstw3S3MrSVBHlj/Zfzkbvs37R6QYyDdH4lDiee1BqYzCsDuEyTLBI9QR3l2t
         W3Nztn6CTdM29R43/MEA9vZSmZrw86kPs+L520V5rJ70kRKuaMzZ9qc75iZkwcrBNZER
         L2dA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703520156; x=1704124956;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kK462pZcf7qYrNSwjIcaJ/xxYMwBvn70wyfd0pc0fjw=;
        b=iXMshM/JVgl71ATLnBCMFj1Nnug2FclEYQpZadzs/AEjFRN2nUOM9grWxXzUJeI4a4
         ueG/tdwktdnjmAVb3TfDjm6HLhLloT1HLAusNxuJdBuaIU5knltIq65NsFXVntAuzLac
         Ei/H+rrJz1BOCB2EFDdTYOl3VR0tRJXrFxe6NlY8MQG4ryQgd6JfxIxcTGJMXT5Ti5GD
         goeT5Ku+QCL+Kvw9w0KUYJOnhCqkwhBGPqbe4DM9TkAKVcB85/CqcW1rnZKGD0m7AUZQ
         2r3WhG8uUhg1C9Yj8yeBNmfQOmai2XxPq2V9gnryW+2kobV1GX6ZeBjSYDiHyZsja9Fd
         nhVw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwgG0VoMD2AbsNqP+kAh4c/gqGOM6+IHeL1n6Kb8MkvG1UI38j4
	cj6rLE8B+gB64ZW6/luev08=
X-Google-Smtp-Source: AGHT+IG8Njst8g4Mi26XHNv2aP0CPAc9kK5CSgzWpnflxF0ifiJ/D+COPUG3t6RS6Au1x7IVpPEjxw==
X-Received: by 2002:a05:600c:4fc1:b0:40d:53b7:82ca with SMTP id o1-20020a05600c4fc100b0040d53b782camr158626wmq.1.1703520155509;
        Mon, 25 Dec 2023 08:02:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1695:b0:40c:39ea:db6a with SMTP id
 k21-20020a05600c169500b0040c39eadb6als49816wmn.2.-pod-prod-00-eu-canary; Mon,
 25 Dec 2023 08:02:34 -0800 (PST)
X-Received: by 2002:a05:600c:4e87:b0:40d:3084:a9e8 with SMTP id f7-20020a05600c4e8700b0040d3084a9e8mr2552445wmq.21.1703520153987;
        Mon, 25 Dec 2023 08:02:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703520153; cv=none;
        d=google.com; s=arc-20160816;
        b=WR3ckxjhIsRHf6lcqnQ8zHOBVDwWXqV6ysfVVqJeGIiYRA7Ck4eePx4tteR9ZyZcPG
         pQGjsWgjfiraAhgSj+km8LUG7QDa1CcfrqCCKwH6slUucxD6HTYvDQV3Xh6sEgfFKH+m
         OfreCyHCzCUUvBh/niQKdMiGg7w7/Hwk8naj0IXjDgxofStbCq+g2nVeOEZ2KB4SOLUp
         p9+k+hnN1ocKYOExLRbBgt+MroPAMQSJSdqxvJKS/+nNj7l0fIpbMQPRb+VAWcvkEl1Z
         gn6rKf9LVroh/j0Bcc/1qp/XSwftakGfGZbFzDtHHwJsaGa4oKb3gruK3LlztjNZFmIU
         rzDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=2rJ2Iy/PRGvnzzn+4Sshtkmww7BInxznMxiG33cSAc8=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=tIffVPMQ7TbHkME8vsFwg3pJbvlu9PGeSNO1KWAvhF/upj+q3LekMoHQYvQ+AuM5b9
         2UHpMuBRRTSSPciednsn0PBF2bTjD8kMEhCCmrmfO3Mnj+ZsD5Lbe3vnt0z6dhuLfVlh
         gyT9rodoXn/Qk6oSgVxELDux5sG6orc48YtTLNXcWl0hxZGswDDE8Apa55SztpNVQCG/
         YJUxXq432CvlMJA/YxFIew8BtaQNFs0YoROtUuQ6j9VL8ASgP0qgeihv/0djsxikZDo+
         H+FWPqGrDLEBsW2n84yiDlXVDvFk6gw+rNqGsIckLDL/TGsnTgOsEOTPy7Z1K8nab+kc
         SGdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="LmZK/YiR";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id t15-20020adfe44f000000b003368d5d1fcbsi270106wrm.0.2023.12.25.08.02.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Dec 2023 08:02:33 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id 8B173B80B37
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 16:02:33 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 43E80C433C8
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 16:02:32 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 1545CC53BC6; Mon, 25 Dec 2023 16:02:32 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218313] New: stackdepot: reduce the memory usage for storing
 stack traces
Date: Mon, 25 Dec 2023 16:02:31 +0000
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
Message-ID: <bug-218313-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="LmZK/YiR";       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=218313

            Bug ID: 218313
           Summary: stackdepot: reduce the memory usage for storing stack
                    traces
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

With the "stackdepot: allow evicting stack traces" series (will likely be
merged into 6.8), the stack depot starts using fixed-sized slots for storing
stack traces. As the result, some memory gets wasted.

This is partially mitigated by using the stack_depot_put API (used by KASAN),
which removes unneeded stack traces from the stack depot. However, not all
users can use this API (e.g. KMSAN cannot).

We can improve the memory usage by either:

- Introducing size classes for storing stack traces. I.e. store
4/8/16/32/...-sized traces in separate pages.

or

- Allowing each user to dynamically create a stack depot instance with the slot
size of their choice. E.g. KMSAN can create a separate instance for storing its
3-frame linking records.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218313-199747%40https.bugzilla.kernel.org/.
