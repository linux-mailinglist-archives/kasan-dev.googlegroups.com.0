Return-Path: <kasan-dev+bncBC24VNFHTMIBBD75TWBAMGQEIWP5OQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 731B23327DF
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 14:56:32 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id e6sf10465721qte.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 05:56:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615298191; cv=pass;
        d=google.com; s=arc-20160816;
        b=cqwQZkIubqXtOKoKKW0BH/3Et5iaBdXrFRmF7oAJMfmUt8+N4Sp/McnuULg4md7hUW
         MAVj3rCnDkomTyV/oz1R1MYoW5567R0MlUZOS098oDa039pWeKuWyFHh534rVoG/2joD
         lWeZiR1pzG8GMkx9LMNCbFg54k+Ubi/Cisf5dCrEj0z/nx4IK2Zg5qmRp3MJqvvjH5B6
         8JAiMmTfl/aZAivJ6r2lvIeKDInbBjDmJwgsvZi8q0ucJVRmSDIdSlDN7+WsNSJ2hiD0
         8ZGVzsdyc0pZRt2XB1NVkFoq5ZuYUZJRk8pBvU0Zx3Lm3g6KXZU7m7F5JmlMlBy8KmRn
         6azA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=eVFx4B9Hk6bs88JmET1TeHjMFZlZGxTe+v3YwQvsnO8=;
        b=ZtlTABcmpfszH+NLY5i9zmodVmQLU/jswGw5pf3QoefKFhpHd5EpTnZpCD3IzJM3nw
         JLRw53vo9jZYtl5IGhsL+rc9G3Cb10xSH9jcCYsb5WvJ9KGC9xHYLvMVP/VKZGvnH9eF
         iW36AwNgOMeLIVtDFrL6QvmevNRW5q4qoGvG3fDVHSL+w9VEIPQKQHd0Tj4KM8XD9HkV
         N9NBi4+Avlw6T1R4xP3jopdss/XsI/I7cbmIcCEVyQvn+O0cICP+ULF9LKvxPg7bv1kF
         bbV6XtsrN+4e1RuMWVhZjCRFTrUJ0LYJuwdqJZ+kqp7x43LVHCCSb1zDAUr50CW1B90m
         o73A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VL6V7U2u;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eVFx4B9Hk6bs88JmET1TeHjMFZlZGxTe+v3YwQvsnO8=;
        b=hPx9aJRl4zgBlSk3pPS5Sp8sTIp6eeivCrjZdw7zNOfPjl+gQIma4P4tBXDO7lqhOR
         MxUdWBC8KSifUQKSLzmQwjhVqgG0/i4YIgX3KUaH/w4I85qkxmYFvYs/3VBAM+QyPbL+
         xN71n5Jt9M+ypvd8pNPdyid/bESP4MXIzohOqhnfFZ8jcMSioe9XEPfYEcuK8tM81ySB
         zsfpZBWdQwwBkGST0HZ/oFGRSFqgA+cnbCBcReXfZP7BN6dvL1iD6lWwqLYf6yLrCdog
         T37nlrt1FULtcM3dMuSVxb5NFN0cfzmnEoNmVMS5t1wKf2dU0L+n6/ZMARPqftMQiClY
         BfbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eVFx4B9Hk6bs88JmET1TeHjMFZlZGxTe+v3YwQvsnO8=;
        b=LAl2REfH/ZX+Kfj0v9C6L4vRhmLMFv/ILdLnd6Z38sC/ysZZ0x4wtifE1pXiNPhQVc
         pfRkl48ZzxHn5EI6qJ152g1nCzofUcxE+ynEvw0bl/aKol+ERI8PDG/foeoa78jvtxo2
         1HgztYh8MmVB+AVajzhaACN5O73RGykWxn4Jk/VddJau953wuLLNWigjPh7e1hxxwFUg
         sBK0RCIuZYs+CQlJBKkjArLrhVa7/+p2gBz4JJPMWKxrsycyP1pQvCcjaU0xJ+9HcR19
         VSHNvHZgdBXnYXoDNbDX9Vmg2ES89Y8i4mvyQx6U79tJvdBMUHypsiqhl953DXvPRg6C
         S8TA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531J9j2dtcTANnuOlF2UUtRHei5ZLu0iyrkJCznmaMq10syiEZgn
	RDaohacOqojPkQLdWBpH06U=
X-Google-Smtp-Source: ABdhPJwk1IWCjvEBlVc9FwR/wggZdvnOnpKERCieMBhtx+iCy4g3Bz7qFpbmcasKOOxA69Aw5vWgvA==
X-Received: by 2002:a0c:fecd:: with SMTP id z13mr22677091qvs.43.1615298191404;
        Tue, 09 Mar 2021 05:56:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:d53:: with SMTP id o19ls10637870qkl.3.gmail; Tue,
 09 Mar 2021 05:56:31 -0800 (PST)
X-Received: by 2002:a05:620a:2116:: with SMTP id l22mr25598990qkl.377.1615298190955;
        Tue, 09 Mar 2021 05:56:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615298190; cv=none;
        d=google.com; s=arc-20160816;
        b=qZpvPG3ehNBdmBYWEoRkl5pAE3CRSHr+BEpSIzdJumqDmt7e7NW/2cg/LWqHy3fAOx
         QNpaszRMRhPi3D0gIem1Xugsm71J4L8DdgIzxk7qZ8oy7Z7xapWmndDAWCnyHNI7VwuR
         ALxaTy08YExuIAN/awD7aGU5awhGnssK4Pdb0MbnlkPbbwSew58TN4lNjUcagHpI94gm
         Lhqrbu/QDhoqEQJ2/QfbvIDO6vdouD0j0ktjEQi1muW6uYmPOzyZVLSssXKYOlIABxeu
         P5QbHRzQw6QH+HNB91yhorgCRUVacZYauLjJexJ36EHJ4j9R6kfQ56WK7MG6cgNC8zfX
         a5vw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=LeuGqnycQJV52n7CMe1SQ8PR7QaDY2oax17qBhZe6LY=;
        b=i8hnSFE0t1qrLKoJv1IHtzPgtSP+RISaRzqKLx4CGcS2GskfpJ+H2ZtRdsR2oznvcX
         4U843jmOQQiE0FycsQ95bxe/RSBHxAnI3olWYRlMtUGDVyiZ+XoP5s9NLwbG4LVjkdtR
         qCT/N4fB+Jpg/qUUCaDj/yFNBu0Q8wEARPDzRAoh//DXzINTqTshpQuWScxUuKyZS3yj
         pjyY3U0KxvPX2avO5MPP+630Ou4Qd0GtcXi0YY8OQq1UcCG/e8ve7FJWSwASf1aW0602
         Kv8WJOe5s142Ff21qodUZZnevYhK9HxHsastaVdtEfLJ41GUPhVBi+GyOtOywY3RBtQd
         I2vg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VL6V7U2u;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w19si1058398qto.4.2021.03.09.05.56.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 05:56:30 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id A3F0D6518C
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 13:56:29 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 90D8265368; Tue,  9 Mar 2021 13:56:29 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212175] New: KASAN (hw-tags): harden against code reuse
Date: Tue, 09 Mar 2021 13:56:29 +0000
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
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-212175-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VL6V7U2u;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=212175

            Bug ID: 212175
           Summary: KASAN (hw-tags): harden against code reuse
           Product: Memory Management
           Version: 2.5
    Kernel Version: upstream
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: normal
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: andreyknvl@gmail.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Ideally, a kernel with HW_TAGS KASAN enabled shouldn't contain instruction
sequences to:

- disable MTE
- read memory tags (meaning that we can't show memory tags in a report)

This makes sense for kernel configurations that panic on the first tag fault.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212175-199747%40https.bugzilla.kernel.org/.
