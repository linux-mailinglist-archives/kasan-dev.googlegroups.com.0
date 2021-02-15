Return-Path: <kasan-dev+bncBC24VNFHTMIBBOU5VOAQMGQEQMJJMWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 42FB131C28D
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Feb 2021 20:42:51 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id h10sf3715987oih.9
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Feb 2021 11:42:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613418170; cv=pass;
        d=google.com; s=arc-20160816;
        b=RLtlHd4dWk46XDakdrUHyJKs3IplVyBCgJ5R5FLoMSAxCtksWwu1s+LUI0MtiEcwZH
         OF0drtVay09uTxDiGYB4YVFDmj09GdB8bX1QobMd5pdbwy1Cxa09l+r4peWOntK7+XBx
         ltqrflonZgUgKL4f1cLAT4KPM09kp4No5uvI//cWivLprlYRyisu0OMrJXHgkBaSfL7o
         ZKw7PShDH1uXvUlRHEHUgOOoUuFo4K38DHzbalRwipKNf4G1DELFcIDlKsMo6kSf0xcD
         wS7lFdhiE5gGHwJCT4CbPrlQV9CyaSewRXntKTVHMCZ55pwLXJm/WNjppt4wWxnLOi9r
         Q24Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=bqcOzUMgG5WAYR1vxIVzAb6+Gb7Y2g+1A4PYVC57G+0=;
        b=nejoWfRubDfHJYps/GZFZCHV0d4TGwRO43bTFk/i0xIsqrTvwzBbN0hqmGiumLzqow
         C2Iu/2Fv6oan9iXyqN/uCkSk2QrZTNpqK9oQC8433/DgvU8TMebT/EzGAd3ErxzyCz9u
         lA82mZwgckJF1kGDBIxMCsLbfLd0n0ckBh8UWg41FiBQQ/SPhSlEXyBetYuYXw5kwzB5
         7au4KZF3TDX/WJIMgT1PBt5msLu+sO1YGxSafz8tE9IRoJZksgSkZQ7i/TjU/pZpb9kk
         IIfuUze01mF89sm2w+FDKW0WjEyGK3eTw4kZSCALd6rsQtBW8kxN5FGQ9lbrNB42ZhW0
         jiqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pO3v19es;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bqcOzUMgG5WAYR1vxIVzAb6+Gb7Y2g+1A4PYVC57G+0=;
        b=LL5DmmZRU3oBWHA8pEDypEuhAj2Fz++v6HkGfTcHbb4A1Y6/TeQ5i+1lpPUwtipGsY
         ymmRO9CIp6WFirh9GZpRhdl3B3j1K+x+n+RSG8akBmuVdfgxaAKTxtT2xSgW5Lryv4dJ
         gx/YRVraqXevvDZKxlT5omFd3gYGbFI7DXFAHdlye1QEajEKJX3UnrPdBuGp/4xeZo+b
         d+RcjdDVDTCsUEU7LsyoFTMCJGNgUJ4VlOkjSKss4rWYblqbDk0/S95oT57SEbnuxZW3
         3qgJPTHN1rPXb/srKjciWhIU9yd6606TEwXaqAiZoHX83WN5TK8eEjdyzKe37MPO6jx4
         1Jxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bqcOzUMgG5WAYR1vxIVzAb6+Gb7Y2g+1A4PYVC57G+0=;
        b=ipNccdTwmseiQD6kuPjHvbJVchnWbEdrqAVsCd9CsqEmdT0F11XOb689FtFW63pyOd
         IjcLFURpg600M0HKVjOqbj+8DDywEQ5gKJhOp91zoG/Zako2x4DICGYEoGWgVmcTnMP0
         qNpvlI8PrUptL4E3csBFeHQbBTMY6pkPZCdsx0/yhhWyLatza6kn91HWAzr9cQZTJxEz
         5q3Wn15+vhtTYQDiMbugJ3wUrcXrNL9rZK2XP/H0e0UvonxbWnGCcFJX4GnyTboBjxf5
         keWZPRqw3ieS0KRuLnASC6lY/2nGj/2jiEQ058aDtGV4u0taHPNrJGYAObWAJ2/8EpMP
         thDQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530S4JY9oro2iD6k5Sx6Q23efObfpwEJNIvZEhQvC90H8KfnIQDR
	wYG+wBlt5Aqf2oLYClPpxzw=
X-Google-Smtp-Source: ABdhPJwARNneGdkre1DSQGgsLeR9qso3SQ1o1LbZWqJBQBCkPVhH4hj2FCWGOT84rCLGPkzZJ3zPOg==
X-Received: by 2002:aca:c345:: with SMTP id t66mr304414oif.139.1613418170177;
        Mon, 15 Feb 2021 11:42:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:bd88:: with SMTP id k8ls994086oop.0.gmail; Mon, 15 Feb
 2021 11:42:49 -0800 (PST)
X-Received: by 2002:a4a:c44d:: with SMTP id h13mr11916677ooq.65.1613418169855;
        Mon, 15 Feb 2021 11:42:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613418169; cv=none;
        d=google.com; s=arc-20160816;
        b=JzIwaVMKUIVapV2qP6cbKzwpc+yWJu4k6fKP9fC02zL5Pe/1DJLWWIkSFCi97m2eVy
         sistsO4AIM+yW3j4aEbxYIIu7iwx0BWGHZiqottdGq7RQ7/v49jmnFmq4UXLf95faaEr
         uP8V40Shh257t5mAtskVvz25osMQ5AQXjQGuCFPdBm0mqgyAbEuJe0TRtW+KCt/f8wuN
         f7ypLDoyDVPxQFV9Avw9JsrO87GEb5Uu8y1Pr9jIGw1Ux0wzfsq7z5ELbZZsoNjlPIRk
         pYu3a1q6DaPm2PjnlWcmqiy7eEqOHPVUs2nRwr42/dFP93Cs8mCnihQc4K9B+R6kt/Xm
         dOhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=Cxmx/dUWxd22FJkU0XkVB38lUcn2Eohm5nc6KDbZj8s=;
        b=TsQvoJmnzDAGidvcsxqjea6N/pCum9JMSnbimUx6fF0g3A7CrCk9gjTKzetFDqAXJQ
         jHzl87Trc/YwpbydFIzbvnbfwLWMczklsLLx/TqsoCOfqj1Z6q3aDmqbqAU6jBN8a0k3
         X96dQj/ByA3nc9G7ksXzQZX56JH8ptzHqb9fRBGELrZ1H6dIbb6DcH9zp9Z4ZOUmE0K8
         JBCMZ+CdJqMAC1At+sqRRpkUmT3HKH5uTJ/1M476luAAzvu+VURGvHIeQx0EKHMmq/ay
         azq8hqGriMVaSRi6FoEggkz65AkzL7odM7h/F00tUtzRIAWguTSIlKOP174y5e2UotUq
         Bw1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pO3v19es;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m1si84973otk.1.2021.02.15.11.42.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Feb 2021 11:42:49 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id EF5A764E20
	for <kasan-dev@googlegroups.com>; Mon, 15 Feb 2021 19:42:48 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id DF97B653BA; Mon, 15 Feb 2021 19:42:48 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211783] New: KASAN (hw-tags): integrate with init_on_alloc/free
Date: Mon, 15 Feb 2021 19:42:48 +0000
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
Message-ID: <bug-211783-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=pO3v19es;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=211783

            Bug ID: 211783
           Summary: KASAN (hw-tags): integrate with init_on_alloc/free
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

When init_on_alloc/free are enabled, HW_TAGS KASAN should initialize memory at
the same time when the memory tags are set. This should significantly reduce
the performance impact caused by setting the tags.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211783-199747%40https.bugzilla.kernel.org/.
