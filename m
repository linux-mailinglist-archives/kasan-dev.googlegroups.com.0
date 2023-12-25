Return-Path: <kasan-dev+bncBAABBKGEU2WAMGQE5FRUVGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id F04C081E16D
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 16:39:22 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-40d4a29dca7sf25543885e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 07:39:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703518762; cv=pass;
        d=google.com; s=arc-20160816;
        b=pFBrnsOrC5+hLU5FnTjdiPyX0lt8PI4l1LzUoFNQjqoJXpIrShMsCnR/z4pTzQjtuL
         Tr6XNJPAXu0CgFYdBOO9dX+kdpLc2+vNP7YuBTrHlIdgUL8s5Ef0aq+KXpmuAqI3ntwe
         YIEiIK9gcVoJRdhnUIMpT+oR+UWEpLzE2kSTFdmrj3IXlgdJWVjoxoAhf4GSBlvfsZrq
         lAISzQw0Q04MEOi2EwpLY64btbQKihDJDEv+ItpF06Thji/6juG39TGXUhCYviHQGSy7
         JGR47dFhQnLgE2FiHh8Py8veuGy2n8Yim9g/8mfP+21hznaWZ/gtRdhtbSZRyUF05mVa
         0DPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=a2cRUMOHVnVyDK9EDw0v1lj+PEQJNwLJMZGr+bx8y8o=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=fjCue7SRMx3CNwYxUHfiyO5OyWtQC6MqeTQoMCcF1QNDK81TfV6Ryzu0kiOWfnXNZn
         bAlUaiT7+YW13+Jnnq1Zl2xawMHIzvQMTzqcFUMr0ck954chqEOhTAt6dtg//bsLoEhO
         JwKv9ntAihzPS637PE1RB1xy1u5n9bkwC1H+jE1jg9npJ8zi6JI23RuPpoWpFRH6qksp
         8ZGjch1/II0rmrAkpQMaugkZtZxQydqm43J8jP4U6koQMwaRhGL7Jet3iJChfVZEYRm1
         +/YOQQJqk776U7uwOAeeuzJvaPozASn+sODjQ2pFBOfDB/seIkm03JT8OgCimmqp8Sc8
         fe3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DeqtS7Mu;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703518762; x=1704123562; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=a2cRUMOHVnVyDK9EDw0v1lj+PEQJNwLJMZGr+bx8y8o=;
        b=uiQRS9o4y5/D6w4MyFFdaC6PUhK3fGoj+C73sf4Jy9k1DsO8OPYdtC8hzpkviv7TY0
         UjgZQX+J93YECffA7KWqG/MOpUVnRPtfjElYDBYoiGQDFFlEaNCm865bWf75efrycUsa
         U0bc/EZydji6icwLNCLJJw4/mQj4foly0Xvma/4FO2RsudtL/raWTVF5HmQgFzeRNvDd
         dSyk9ozNZ/wjpzUQnByVjOpAjL8+5xn2w3dKaAHySoRlwK6K7pPTU2pmIaedLfCHVKSe
         DRQUAe2BWYu+vlItLKMDw5OZd/dLk9Hs8LSIr9j8KxEi0hu+Uww/xg77zvb6jRrgiSL2
         3rBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703518762; x=1704123562;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=a2cRUMOHVnVyDK9EDw0v1lj+PEQJNwLJMZGr+bx8y8o=;
        b=G6ORXO2eYFUANUm0LeORrwRBVeV6GZCrZwKLVc9qvXEHn7LisYzMbuXcskbMgP7qeE
         zNl3qTG3CKDhCPrZzrLhxKKY3T10W72V8QKgVi3b85asMrDk8cTk8DS2H7RyJyQjEyha
         mdE2pUfULhP6iJ+HEEQlNxygqnwN71XCeBSAlvufaIITvOHZNouHDW8DbBQ7kxnzc5SW
         WfzWEGcTWbt+P6NPxQUqbHUp6SbLrDQZUSry6HDtpaM8IrZXvc5M/yBKv30PXwLIrMTQ
         4hIPBHRgwbVZddy0tOMc5lirEY0Q4XtiFrtT5PrRoFWYfTnvdDHDScY1GmHXZg/Otm2W
         VcRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywjvw/n3SemPEVaFUdj0e37aRBe8cuGhgkcEQvWmv3TMMRWW8Hi
	HRZKRi+Ggi7yVZfMtn9qpGE=
X-Google-Smtp-Source: AGHT+IFSWV42EZ5/8XvgiWzl6aHcfiI/75MR57gekCc09APiWk4PPHcDeh935ELaLPTbSaqkEwrkhA==
X-Received: by 2002:a05:600c:538f:b0:40c:2dad:d394 with SMTP id hg15-20020a05600c538f00b0040c2dadd394mr3387185wmb.149.1703518761161;
        Mon, 25 Dec 2023 07:39:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:468e:b0:40d:2bc7:eb4 with SMTP id
 p14-20020a05600c468e00b0040d2bc70eb4ls22974wmo.1.-pod-prod-06-eu; Mon, 25 Dec
 2023 07:39:20 -0800 (PST)
X-Received: by 2002:a7b:c8d2:0:b0:40d:415c:611b with SMTP id f18-20020a7bc8d2000000b0040d415c611bmr3264726wml.122.1703518759794;
        Mon, 25 Dec 2023 07:39:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703518759; cv=none;
        d=google.com; s=arc-20160816;
        b=mpd43UmiARYVZr4kNYn5Im0HcNObhf3rkVGAxT2FHCTHMSL+DWSkBRjtNYStAaPEnb
         nbTRenetcnwjH1YCQbAXVRd9WrQZc/XjPRLK+MGVkBqbrIlhCwgCRSdIhYUATL5UoQhy
         nQ5z42Of6JcAKq/hdDSKs4zrmrMjBNOg9nsQu2t0PVDbYafVM+dTYDTGm4A25aiQfREK
         F6f7iHywdcSkfF8ba95H/vs+HuoudRHX++0ma85uDs5xqNrS7/ZU9JbeBkML5AogFu69
         PHzzMtqBc/aQYX10c4mEZnzyA/NefNKaP602MbbRE90ZbgAYa9qLE5gV1d4N/GRJzB1S
         2Zgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=tB6k2DTkv1lEO4bX2RIqdsmTIh19mBSgkICmPvk94tE=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=r5N3+Fy+bpCBUAsE8duAqgBwgLrpPwJGdmwZRpoBJaNZxJ1uOxDlGj+6HKJfw/0aDR
         8aNvCJrLtJYSzsPt0wXas+wgMO3lnlRwt3Y5ltrlCCjGEhHawwTElmVT/6Rt5B3uBwxP
         rSAerrYONAm24dYLOF+OV8xMjWHcu0RD0L1R7Coj6UzYgsFRklfY1b/vesCRcU+H7gzY
         TnMlzo2qwa4caRUQuMdlR6DL1rH0wwHll8KHxVthK38L6q1S1jpBwdBB28VpRNc897Tc
         dbYhIl2p4Y4mHKyUzDxd4un17aJlxk0oBURbq30G2mbm6K/78uMvRSZuoSPfad6DNSyE
         W4Lg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DeqtS7Mu;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id t3-20020a195f03000000b0050e6b19b855si369121lfb.11.2023.12.25.07.39.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Dec 2023 07:39:19 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 90CEBCE0EE1
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 15:39:16 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 12522C433C9
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 15:39:15 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id DED4BC53BCD; Mon, 25 Dec 2023 15:39:14 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218310] New: stackdepot: from zeroing GFP_ZONEMASK from
 stack_depot_save
Date: Mon, 25 Dec 2023 15:39:14 +0000
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
Message-ID: <bug-218310-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=DeqtS7Mu;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as
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

https://bugzilla.kernel.org/show_bug.cgi?id=218310

            Bug ID: 218310
           Summary: stackdepot: from zeroing GFP_ZONEMASK from
                    stack_depot_save
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

From
https://lore.kernel.org/all/CAG_fn=XBBVBj9VcFkirMNj9sQOHvx2Q12o9esDkgPB0BP33DKg@mail.gmail.com/:

>   Currently, __stack_depot_save() has "alloc_flags &= ~GFP_ZONEMASK;" line
>   which is pointless because "alloc_flags &= (GFP_ATOMIC | GFP_KERNEL);"
>   line will also zero out zone modifiers.

Another related issue: https://bugzilla.kernel.org/show_bug.cgi?id=216973

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218310-199747%40https.bugzilla.kernel.org/.
