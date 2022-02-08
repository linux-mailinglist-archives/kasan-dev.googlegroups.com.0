Return-Path: <kasan-dev+bncBAABBS5VROIAMGQEZ4AUK2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id E606A4AE2C0
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 22:04:11 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id c9-20020adfa709000000b001dde29c3202sf108046wrd.22
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Feb 2022 13:04:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644354251; cv=pass;
        d=google.com; s=arc-20160816;
        b=utFvqrpMsmCHC/KbXAGpFBFa41+4U6gAA8h65K/VYXlCdODOYigb+HFzRx9iXye++w
         /LLtsD5o+3dZPlAVYUv8GVpANH27aoZJzVQYiII8yZI8nyklGtFSy9GYCnpZSulPAmVg
         HQC+kMepFTnTE2jOGX4RVK4wh4XTRR/IRX3GFEPPEOseMThUPrCL7Q5918OA9xVRgcgr
         ooa9dBG8O2jwXl09OvFuRuFljBebUEhpTWyey5im3JodbgE71mUyAwkbGxOruv4TD/np
         ftQ5wTJOLUT3zkeCT2tDuR3WClgVG4mgYSxs4G5u1W7ZHk07i0bvLq672gYBSxSBEZiZ
         ojMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=0g2OdOv/Od1GDJEJ3Cbq/+wYDktuGwddCHQiiNxLMyw=;
        b=ON/6U+DiR1WAwAW5sb0XFDTg4D38fwqUQpHexWXBz0GngccNDwoi5P0o51KzJmNuGu
         qAdtgmPnbaxs4sXriPCYGnS5f2cpClKPP1RkJtMP4x6WtdNrlcb+8G5GYEvyA8ljGBNV
         CBjE94d5Ap/5DgZE4OAQpO/W8Zq9v6In4DmJue4302IYpqWH1sOORBwxteIoOnGPScsa
         PfzizNT99hoZ7LZkXDfAvPUp38QCqNR1ATAHhpsae7yajFUUyp2Ow4eM/Nlm/0AcqICY
         jG5l4WjoJwWPAQy5GHoYxToCujfV7R5Ak6Q4bDbPep25Tgflx6j7xdWQ1fiXidLckg1p
         /b9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rrN+ZKr1;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0g2OdOv/Od1GDJEJ3Cbq/+wYDktuGwddCHQiiNxLMyw=;
        b=Ilz74WXkgwz+Y6BX36oM3EDpezPBzZY/XIGMFZNsf1wKXjNExA3AIpPEHiBb93qyau
         jHqC/vA/u7eUKs9l3QJMFcCG8WLakVy5PZpH9n7lIcPBFihMudp00EKcvR3HicgCpSJw
         5FLMympQdYj6eh8w24b8T77tyqDKBR0RPRSkEpIWqvCLHAFHw/00+6rB/tQbHrvpl60q
         qK7c6Q+6jU08FH9vt5fyWG3W/WXotV2DrsPT8E/LLEGA0tWHXqsFGc7nlgHq57WEUvL5
         LazQBGrvi6ANQtA4ZrHWJCvTKr8E+oMyjdLJWarS1a9na9YIt+cg9vSAvB7/o7cCJikM
         UsqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0g2OdOv/Od1GDJEJ3Cbq/+wYDktuGwddCHQiiNxLMyw=;
        b=tYp0ztIyaBsj5kXuD2yaVJXWgtsg4DyEy3AMp73Pb3SEFLeSvYusoN0+UhHUhdUXgR
         9G6fVtK2bSurNWOvoGOPrvwJobKz0isz0LC9dGDOAQUMIXhun6+d7Pfnkr3QZ3P8fqcA
         cjaOvwKzqlW5v049/8HN/AmS9Hnl0jsliL13p8ckOMkvMaOYTh7YM5xEtIN7L3g7pkAk
         xrd4xGVPNJbTkRl67Eoe2Gk+O6DWZn8ru5pAozyN33+6bhgucUlLjGsc/QLlbVmdO8NE
         6Dhz/jca9AspVmoWTibMXynXlJ6KaLewR1wWHgNA38m8CN8DI3XDwqAaLN55EbTDjGRd
         65mA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531G7Z/ushcOTx9zkqNU1SR9+FTY/o3OT/++p/PqurN7wyQSMs/Y
	7/1gDzniqypZHQo64CMorpk=
X-Google-Smtp-Source: ABdhPJzo50FwyeIPyV3qvli4FAblnsBsxH1k2d6PeEVN8sWs2NjERGBcAHQ3CFrIFD4EWHdNATpbEQ==
X-Received: by 2002:a7b:c3d4:: with SMTP id t20mr2629442wmj.110.1644354251567;
        Tue, 08 Feb 2022 13:04:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:3c8:: with SMTP id b8ls88107wrg.0.gmail; Tue, 08
 Feb 2022 13:04:10 -0800 (PST)
X-Received: by 2002:a05:6000:1b85:: with SMTP id r5mr4901189wru.453.1644354250901;
        Tue, 08 Feb 2022 13:04:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644354250; cv=none;
        d=google.com; s=arc-20160816;
        b=sHsVHLr7+Ur3W9UG8pyyIVfpTpCTLWSThQJFZbfjqHcxVNc3mv7kubkz2gH5OiI92F
         Fm//1v3GUpA5GWUKXcTFrYC37fJ11YyPRkV169lfH9cIX1AX69Ds0RNFVa9n8n3zG6y7
         8r5LO6675sJbc92DPE4FX8jKl1k+ZHYSSgWFvnGmSDG+WTBtW5J8OlaGrYZsitwanzQZ
         /iY0iHKxIT46qOsnUlJKqbNu7FjwhCNHXdQNKxCllFafPquFV2APJSjo6vSkOKH22411
         tJM3e6C4L7xDB63C75H1YvMlvHr4MVEHn5VwttEvdW2NFcb7E9rQKcQaoIXfU9Fw6Zpl
         xpXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=RzEzRmjiAf4RmzCV07MkUwTd6YuV9WjkxUwUyAmF6BA=;
        b=rHpWuvmUOqwOvACRkrQSn/wt7K+tCQLAqENZQ1AOZHPfnG+wEjW9KIsY6aUIk6em36
         GX/WkUqDoCbV4vjI5bWoa6J/OsogYKjk8E6l9hHC3KHHhzYks/f0+irXxErXvZvCkYxV
         ZsAOcMtmGhKpyF6xv+5ClDMgYXVpgGW+5xSVxqtp3ltEPgJ0rTvTdZyMG+mPGDIx4eHJ
         uxtsKvjdt8uuX/8jrMmqgJMUURa3Zw2WCkLwLYEEh2PYXlLId+s7BmzHFbYwLC09+rA5
         qbOcXYf5O8qLKYN+bGazYsseqJC9hls4Akch8YFnD5O5tEnCvn9bm3gkZqqI8y8jZrna
         xzxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rrN+ZKr1;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id v5si165238wme.4.2022.02.08.13.04.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Feb 2022 13:04:10 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 85FC4B81D09
	for <kasan-dev@googlegroups.com>; Tue,  8 Feb 2022 21:04:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 39D80C340EE
	for <kasan-dev@googlegroups.com>; Tue,  8 Feb 2022 21:04:09 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 20FD1C05FD4; Tue,  8 Feb 2022 21:04:09 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 215583] New: KASAN (hw-tags): retry tests when tags
 accidentally match
Date: Tue, 08 Feb 2022 21:04:08 +0000
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
Message-ID: <bug-215583-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=rrN+ZKr1;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=215583

            Bug ID: 215583
           Summary: KASAN (hw-tags): retry tests when tags accidentally
                    match
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

With HW_TAGS KASAN, there's a noticeable probability of neighboring
pages/objects getting the same tag, which might lead to test failures. I only
observed this with the pagealloc_oob_right() test, but others might be affected
as well.

We need to retry running the affected tests if tags happened to match.
Currently, only the kmalloc_uaf2() does this.

Or, alternatively, addressing [1] and [2] should fix this as well.

[1] https://bugzilla.kernel.org/show_bug.cgi?id=203505
[2] https://bugzilla.kernel.org/show_bug.cgi?id=212177

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-215583-199747%40https.bugzilla.kernel.org/.
