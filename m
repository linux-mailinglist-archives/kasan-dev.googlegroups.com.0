Return-Path: <kasan-dev+bncBC24VNFHTMIBBBVSV77AKGQETYK5ZWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id D639C2CFDFB
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Dec 2020 20:01:30 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id a17sf4688849pls.2
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Dec 2020 11:01:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607194887; cv=pass;
        d=google.com; s=arc-20160816;
        b=u1rWcrmmoA0tjR6iVa1943E5kCE6zNyl22wRBhOWpxI/VX8lcO3moBObDNPzeGOEd6
         /bPmHtHaqqXSt7h30QI1aOO4QcLcbQ5NJtzNqFnl0xgEZtAowe5xKlA1wDL73m/yzxut
         xbhZss+7N1u8K75xTvJqpsvQxQiFF7xTWxWrajSBinuop5x6hUyp/n3GQZTzePSNIeLQ
         e5+ycj4rlxIQtB+mbGWToiDL3I37p+MbTxAtToRl1+nwIXR8ijETAISTpZyWc8sR80mh
         kTDMdS618clPW96zxPvBzXlsb0bhApxCDR4RyovAvOQ/FStLPPomjnV0dO/hQqdc+Pbm
         pbLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=2C0GOi36l3xxSlHyL2tKgnSJ6AweVEqsW3QHHNf6kDo=;
        b=r7/o0W0FTo/wBahyreFeH7xon4KcFWhqWX+x3Q84AcZnCVlozfR/jfbbLESUnHZhAw
         AzQFFsziXoluSpLCUVp6qPHwoZv/B+yLFB6IKakyrtGUcft0PYbY2Fd9rf3puv6RxQuj
         ajreutFXZx+r5lZiy67/WSU5tw3AmjNeQLCryZv+0e8vSG/oO0yT6Eqr7r/3wW9bZh7X
         tr6ThDnRXEjoITtDAUua2YnYu5lDEMJDWvehEEIY5p2yNzc61I6oCiW1shBmnMUvsZj9
         JnU2+zC0GXLfWSW3YJ7jyr9mO4MHC/qVV7syIuFUNZoKyXd9r28epVDNT+XwdJwlUG3D
         I+UQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2C0GOi36l3xxSlHyL2tKgnSJ6AweVEqsW3QHHNf6kDo=;
        b=PbaFrVbOsSu3JP1Hqv8IjfNWXXzsxohV2evJADM7O9/4HaEgSaMxjezFuF5aPjIiie
         Mfdspp3cH+gwjesKHDzNsg/XdSs0VRAwvAtDKCViTZrmaLarehkahFn54nDiTSB1I6eO
         0FlIHoVm/7a4UPK7mjW+5nO1ERExGyT9U56Ga6PwZXSwJvSNh4jy2kCeyWWgIYNT+c3N
         MqSdu2uvPb+wGRphluYP0MHKH656pvAlCgEAIvXay5k2woA+nEQg/VX3x+a4KF2ScdqR
         KEo7Xv2lM8l1CCHsRfKERweoCh2eH/wSamwmix8Z1Nb/d0MdQaz9ZAfGWGtzJ+yKoqB/
         Gxpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2C0GOi36l3xxSlHyL2tKgnSJ6AweVEqsW3QHHNf6kDo=;
        b=A/1aL8yKJdQwA1rMkEpo6MHrlr3Ta8eLXOYN3lwkMiZmK8l6uo3ARpYL2g54x8fSo0
         1vm9pa5347mnF1QbZIM4bIlelxr5LYF4sdMnGEMjaX0J+q8ADoBN8/R6PUuLB7L5BWTe
         WcX6n0bTsSjZx41UwgXnEBBeVrHbGjlx8/DIpwjGoSyWffmVW1/PUwo26RGq3LjwXQMx
         vp9Mz3WZToPAle7ztdjbXBGHWYu4CuvRGRbx1Gyt5/bv+bF7SSkQBflL6LjGAmiRoXrK
         DegPHmqyrnGJhys33Xl1HQHu+7MG82rkR1Yi/B3lzJQXxBgImd3udS8Zq5vBAlIAqdkP
         XOIw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530DnRGmZrOf37upC6BvJAIsdDTWn/6u/I+lFuoEFo9nZn+9So/n
	anEGcgdCJpbmuFRCjvYVWAA=
X-Google-Smtp-Source: ABdhPJxGKPV0hjZCsHNZzpvymXtrknXwY+4oiELzaCLCEkY3r/Khqu7Bw6X+qxqfwCHbXpLyAAG8KA==
X-Received: by 2002:a65:614c:: with SMTP id o12mr12198314pgv.111.1607194886824;
        Sat, 05 Dec 2020 11:01:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bb95:: with SMTP id v21ls4337013pjr.0.canary-gmail;
 Sat, 05 Dec 2020 11:01:26 -0800 (PST)
X-Received: by 2002:a17:90b:46d2:: with SMTP id jx18mr9744884pjb.106.1607194886280;
        Sat, 05 Dec 2020 11:01:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607194886; cv=none;
        d=google.com; s=arc-20160816;
        b=jlA7Tn+iUfvF3/pUC5cdmfDt9qpRBH8hECcvos1bUpnG360p53s0+rwcUf8aRgoQQq
         2X3Ctc387RrSiMtpk6rec25Ra3Qg+gV8fUj459N5oXRSRNC+4eLletfiPpEdtZnjYu1q
         cccYVq3c0MW19+K5DF7QipNZxaMQfncinjSDQMMzVtlvRu+4TwNPXZbN/3tkQWxlZ7UB
         feUBTAc9YetgMO00sDZBq6fk46fLwnTJCAnoJzaYWoijt4ZKL+GSZ3emHzs51buG9mgR
         4rNNZf5dQ/tQwWaKuolzGj6Kx0pFKEEL2q8o5DQoOlc99a3KJVlEsOaZLDCHmGiy4lrQ
         QKjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=56+BdeeHhlfpvKev6VmanfhxFREw8sTPy1Y0g/PoNlc=;
        b=Nsz/niim3bqgtyhd3T/rsDB6UYxM8u/6nkmAQg9IdnDnlnoAcqR7jvnHc4Qc/kyXjq
         AArKb4ow5VOLUcI+mc8BFGRxlqxLoCDaa9tomt59ABH2P1mUztpyce7i1KDFDvod9Hbx
         M6Jvf1r+Km58d0uImYNp4Wlq9YFd7IpZ0SETtQdaeThyAb8+JdclrUb6ijZ85IW4dhAU
         zfRQ1Y8AwqPWmZHzwfuWkNQ3YoB5IKLy4VDiuulvQnbzILVVL4yjJtXQQpkQNE0iEuYW
         cl9wCIe7cGiI5qOn55EMsZfTPEDzS3xsVC+wbbUw1calWPDsE/shr0JXa3e80rNF3LQV
         s5OQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f128si763654pfb.0.2020.12.05.11.01.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 05 Dec 2020 11:01:26 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210503] New: KASAN: no redzones for page allocations
Date: Sat, 05 Dec 2020 19:01:25 +0000
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
Message-ID: <bug-210503-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=210503

            Bug ID: 210503
           Summary: KASAN: no redzones for page allocations
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

Page allocations have no redzones, therefore detecting even linear
out-of-bounds bugs on those with the generic KASAN is impossible, unless the
accessed memory is freed.

Related issue: https://bugzilla.kernel.org/show_bug.cgi?id=203967

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210503-199747%40https.bugzilla.kernel.org/.
