Return-Path: <kasan-dev+bncBC24VNFHTMIBBUMFXWFQMGQETQNBY6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E649434136
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Oct 2021 00:12:35 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id x5-20020a1709028ec500b0013a347b89e4sf8535193plo.3
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Oct 2021 15:12:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634681553; cv=pass;
        d=google.com; s=arc-20160816;
        b=UwJXqEuS6+AxKYa+iPf/K3nZ6Vq54rT6HII1xyTG48xoAC7SrVNryg/jd70jEUfkVp
         QMcFk08z5V+YpPBBhUA0X/sDkl6uTHRacPvpYENdmNJGqKO4EvnjAMqeqZ+Fue/bnC90
         Pb+ITuH0bmqdX7/CWWiJnw3Zwaw06A2FwtbT7N0795GnHDcxZWIKWL9k/9sW5LLkVdfF
         BYWzGHxFzixTPcuf6KpQoNxjDGJe6DjBEN4ZGd/VX/P54kmUDu6MaZWuU9p/5FgFMDDM
         p91ttjG1L4S3sNKSZxQqzqcsDV3A6xFdm4OSSn2fHTFyoodryHXhalLgPQecgYef7osk
         L6BA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=q/l2ri8PI5Q8KJacFVXn7vgUAcO4qxUXo/zjS6n8fis=;
        b=PGCOEmOQ7Qj46ad+QyKP/XAkSFiYzl+V8vbZa/UwVaVJi+iJryWm7vCkdIbkUtRX22
         zCY0Si1UDJY/scQ4bEQp1mGWA5HBzJRCVoJy13aJFY86Qp3cjkZNwn6nCG78e6Zuv00Z
         O1d/CcIy5n478VBbyoJTq+7GopgaheVOOt87ZiemXt4feFceKpY4+XlcG6C3AzrljFkO
         XWUz7CeFztSV2uhChYU3T6BS5PKQXqOdpxgqcyQCJMWwJPyrM+z+3hmnSPcCIfUlRgus
         lmiMHlAfp8m01hDaNDXWOLQMw/kbisJbnb4LDQG5sg7ZZU1ks9+gjnwoh85nhjCnlvBR
         VSqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Da46obal;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q/l2ri8PI5Q8KJacFVXn7vgUAcO4qxUXo/zjS6n8fis=;
        b=cQHlRzcuDREQEuKT/VM+MEEkRfYU6KE40KB7V1SXifvHuHNLypmLfXje9fg0J8HR7n
         Rc6d86KdKf7NWHAAD7CTLAdm/WmTU6A3ziK/cgujfuZ+pDSD4XnKXniGUTbJSL4T/g/t
         DU/m2AAB5xbxtl9PBVScl4ywspz/Cpo2ZAbYheg5gZz1Zrw3vv8daeRcM3ccbKtCIO89
         mCtnqbDQZsIseGL6DFyzMvGr0m+EqQdF/CeWwpvcytbucxCZNuBdCGFUUqKtzIs1DPn+
         r5JZlrOoD/6VqeEulaxitEX2NWAVkcdYiw6r81iDhfRuO+ptxspzDJ5djOp0Wvt53Nr2
         qLkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q/l2ri8PI5Q8KJacFVXn7vgUAcO4qxUXo/zjS6n8fis=;
        b=VPjk7XMQPNUFSrESQBGoIiMjzmvcHT6VUHOobGPuXLNbxna07btLneeabTSXuCx/yl
         yRLUUeONYHXzt17XvZAPIX2wORnLz9f3rr0R4HMOUbbekPw6IAGPcanAYx0aOPKdO5NS
         iq8o4gLbUrU077hUnIa25E0FpzFIAc9n7ohARL5RRHiN9TGZYt88qpBEzs21EXUTQiY5
         pL0UePUY4NpshzpDCCRQf7hg7+5I+5rGCK4eVh85VgRccPdlstmrjZh2bYqCbzCN0YxB
         zsW1nTGdIJ5FWfcNMoTwyNxs8gS1RvqGIolhVZOKJ/W4xBrJ19Sk4wQ7x/EPYCvJbkJI
         rbAQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531eGAl2ZC6zvzr3i0iZhO8Ae/rRHH6vp0VzAhXM4w3zzz3HOdbU
	GOA/k/lEOCRj+BN9X6zZbl4=
X-Google-Smtp-Source: ABdhPJytxBbajqel98TBMTQZrzRIczCjHCA+ZCaoMnu5Zo+yA9M4QIvQuEHkAXw80pRhZVahcnQwBg==
X-Received: by 2002:a63:dc13:: with SMTP id s19mr30406784pgg.233.1634681553767;
        Tue, 19 Oct 2021 15:12:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:6401:: with SMTP id y1ls95444pfb.10.gmail; Tue, 19 Oct
 2021 15:12:33 -0700 (PDT)
X-Received: by 2002:a63:7047:: with SMTP id a7mr12332069pgn.458.1634681553200;
        Tue, 19 Oct 2021 15:12:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634681553; cv=none;
        d=google.com; s=arc-20160816;
        b=XjqLYSaBolHSjP0otXe25e38iQ18+C1OQhojLjopd6s6y9HcRHCApT7fvtpUoFmSV9
         WC7PeQ7cONl6CvQwzoNfb5kDxfVoFTTkwx0/s2/htHougzLtHpQJRvPxucYy7iAzx/Lz
         VAFgPxGRwv53ZPjQGUDX67IhiKS5cqfuYRSl4oYcHSn5gCarffMPv6MCg7PsUl93CCOw
         DKEDX8iUlevE/th9S63ibmYc5HyUQjiPxsVgQmQ409mpaczqH/Vdl58stTvic15xyE4M
         SX60cQgiWkmOkV7RXyDvWDDEfl5YU8X/ECC3mizLcT0SmIy3vM4vu/2Mcx7VbCPOaNyE
         6fyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=tlypq3T9gzzci76O7hC806Sye2do6liyDD3AqOmCxYs=;
        b=eZ4uLsEQ6pnXqtpzrJgjeiwp4FiCrZqVEf8MetDog2HWn3A3OMZQ0KBT1Ul4N2FoV8
         1BTw0SJQuL/cgRKHAMy3HA4nTO/m6B9W/SXsKdi2TDafE0ZpwS2uTbTyRMnllRYcMl5/
         8YnJNZCiuFgVJFzbwDc5MIGZXUNR5sJHwSWoW5uA1z3z27qV4G6Oycev8ilt7XYrRZBx
         WnheHjIq7Gnv+qdigm4LFG0wU1IdMMGrHWZk9SwNniKzBziPmS23h2DFiZxpOgWe2eXy
         lfXyZWK4BMoULzWyR9CwzhjDG9ekldBqGU2p2mi+jSyIsKDS/+5rRGLxnfYVRRg6clY8
         +Pog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Da46obal;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b1si21054pgs.2.2021.10.19.15.12.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 Oct 2021 15:12:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id E033960ED5
	for <kasan-dev@googlegroups.com>; Tue, 19 Oct 2021 22:12:32 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id D1A46610E8; Tue, 19 Oct 2021 22:12:32 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 214761] New: KASAN (tags): consider stripping pointer tags in
 kcmp and FUSE
Date: Tue, 19 Oct 2021 22:12:32 +0000
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
Message-ID: <bug-214761-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Da46obal;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=214761

            Bug ID: 214761
           Summary: KASAN (tags): consider stripping pointer tags in kcmp
                    and FUSE
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

The kcmp syscall and fuse_lock_owner_id() might allow bypassing Tag-Based KASAN
mode in use-after-free exploits. See the "Against UAF access: Probabilistic UAF
mitigation; pointer leaks" section of [1] for details. This needs to be
investigated.

[1]
https://googleprojectzero.blogspot.com/2021/10/how-simple-linux-kernel-memory.html

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-214761-199747%40https.bugzilla.kernel.org/.
