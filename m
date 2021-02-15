Return-Path: <kasan-dev+bncBC24VNFHTMIBBZ4IVOAQMGQEYYLFGFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 402DB31C209
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Feb 2021 19:58:48 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id z18sf5909792qtq.10
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Feb 2021 10:58:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613415527; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZMIk3BTG94T2MfCfaeBmw3odjoKWOeU89HyXkQl9cWZ8stuRuPui8MBEsz1Om+dkn9
         3FT4tmxQ5xL93qTyCtGlC6RZAib3lc5eQ6gPVHYU5kxhkltsNtXYt1tBermxg3pUp1tv
         k1HSGPI67G38fRQzD8vvO4p2QPgkMvyNQBCRehUIHdIa479TyCiaiPXDbuiuLosaXKxB
         zRXX+2lHUUhUkyRSh1utnkyG/Vff9fsWtUb/d5UKEbJw4yvhNmxPTA6hTsjP887xdhFf
         zTci9hTor+IieekKLTqNCebkIW2wl2K6n8fLcRFrBYGdowQJTl/s+yOVz89VFStSk4w+
         lCXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=/s9053ldGJCPbUE0SZiB5Un4r9EFa9gWZRJPFMqQsIk=;
        b=UR7xVOiZWVT+2s4Ymny7RWrUaVNHmzlmjiqac4ihMU7UG9SJ5jrkPjNFAW+SXOqip2
         F3UL5BIiHgq20GZEK9u2wgrK/xJ/5lNEDRKv/h/dyehEl0Z3ePlMyXKTD6h2kRPg4uBM
         7Tazz9rh/kDE2od4IihFW8ymG1aiGDJ0+RkM4X8yIG1eOW4a8LrQe7HApAXLjfH0TIrE
         2oR7xToQTOIyefsb088t1FQxSOwt+sHoBy1gRyaFLHlhLwVZt+mArlf6ByGiiHUwYe4B
         0RU1AcCU0Dbvw0TG2k1ibUHTIpSZhAd4wpgj88AKQuFYZ5eY1OJlA9SnU75uM9MSMnUD
         NtXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kr4hagCR;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/s9053ldGJCPbUE0SZiB5Un4r9EFa9gWZRJPFMqQsIk=;
        b=a73zGWXMYosmZstu12raITEYHiu5Tr3wuH7QOoFMI2vSwUWPkP6+1vnv4RmJFQaqME
         pP4vhdk5JdXNgsrHLV0/ywjVxJGCdDZbahxXZ4y6DxF++ze3JDKQ0UlVUp2wJn15yXqR
         xWTfxmUbKexpVmKXK6zpY1iHXVIgFRdYuD+lACfBzSCpsx6SQfu9K/bSzIazj3ndy0Q8
         s7AzWzBMgytiywW70m+KR727VUonFWuuWdU3VFcI3Q5yOSAlabuVYWwy3JraQhljXl1A
         KvmlZJo8mdd8UYJMbeozNxbUE7ViTvkW7uIhDogV/d9WatN6ALPgvcT6yjMtWPbjAPaL
         gOOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/s9053ldGJCPbUE0SZiB5Un4r9EFa9gWZRJPFMqQsIk=;
        b=GopcsHkbeYzXcxEbiUMlVedViKOtoTXlntwd6eaYN9St7+tgbw4r62XLPymaSJSIxZ
         yL40bFX6TuCC5d+WFJSehvdkjX9oBZvweWa9vEinJ7fODedEBIm1jqAhSEEX3GKqKyf4
         gCBH9ryA2XO+0Bs6qMo6B0pmAZajU75d9Zyb8at+vPFusLkxbeWan/dKQyIEoNnV8GNQ
         LKRhheUqbbtRrMTeuUE2woP2B9tyAWmVPYrJOTvdNE0f4uGBpeZnRUF/4fSSPMfPTaHU
         QfUh8YQfHudVbOiH6MLNS+PjPPCwiUYbDtmLwpMDEvwT1sNVjJ94LPX5fM2Y0BOG1I9l
         qMDg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530LbESutH1IR594R8EUqbudaY495ywPWkZjumKfmjQ4rZOcmEbq
	AFBh+VLC7xpSjwP6SctSzn0=
X-Google-Smtp-Source: ABdhPJygj3c+ipOJOuuSnwmD4d2e/jBK9RhUUP0WAvqI+Xgi6Us0iOQdvXrZIZcAue7p4/7VksiZoQ==
X-Received: by 2002:a37:38f:: with SMTP id 137mr17202585qkd.284.1613415527209;
        Mon, 15 Feb 2021 10:58:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:9d01:: with SMTP id g1ls8790326qke.6.gmail; Mon, 15 Feb
 2021 10:58:46 -0800 (PST)
X-Received: by 2002:a37:ae02:: with SMTP id x2mr1332128qke.176.1613415526855;
        Mon, 15 Feb 2021 10:58:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613415526; cv=none;
        d=google.com; s=arc-20160816;
        b=IqWUu0oSvQzbRPLnE8Xh/TD3ZqnhcPXbC1EojVBUpBHsXh3GRET6BmpdsOj5qwgS9r
         krsItfrgDaEBS0IG8wsc+dSYh0dKc/5XGSNx4a7oItfyk8OscE3ui0zNCWM+o9y+oc2x
         6h0e8eENzhHWleKJmbozROPtRhWrBYSK7HAb95MBfklUBEfBtDOsFFWiYKHyFWnwZEJn
         xAXKcP+WM8DgF0TQBhcScd8rlVKPm3EnT2b003mvUI3DoXQj4F8KmZE1GWPwC32ax03j
         MzR5CxHErRCaSkl87qLzdT7tN7QT8GZUJrf807F+l/Wrl1kNicjjmOyTYyIY55zZFPJe
         qFjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=EFIUuEapq6mIS6/mTyijd/s93HqoqIKZTBhtR8DzW5E=;
        b=KF3Xpb7CLJ256kzt/E/svt59qimmxs16u8O7RJ1q0T1POY5LC8/P8XP772xubDyhWB
         dhqwtQI3jYvQqGlQmsckBg4LWODKvsJcnjzN8X1aJG0ydgT6Wq0Syfxqqwb9r/eAbNrv
         tBFRnrWLX9CBUrtWY7ctt0ABKVxCRxnYIsH/krz0QanfnScbU5BylGhP+38eZ/VtmRqR
         cov613W0+/8zn/AM80tKXLht6yslywWRBnfEqVrCdfk460hmpN9C0HuHcJFfZeBH1y1Y
         ariwz/e1Fdj2KTBOcYn5AokT3h70PRXPpEz0tCJDmYjRTD47zU6j8FPdsDXl0whDAsbx
         AABw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kr4hagCR;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p21si142572qkh.6.2021.02.15.10.58.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Feb 2021 10:58:46 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id B353564E0F
	for <kasan-dev@googlegroups.com>; Mon, 15 Feb 2021 18:58:45 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 99C8E653BA; Mon, 15 Feb 2021 18:58:45 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211779] New: KASAN (hw-tags): support stack tagging
Date: Mon, 15 Feb 2021 18:58:45 +0000
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
Message-ID: <bug-211779-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=kr4hagCR;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=211779

            Bug ID: 211779
           Summary: KASAN (hw-tags): support stack tagging
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

Add HW_TAGS support for tagging and checking stack variables.

Both generic and SW_TAGS KASAN modes already support that.

The implementation of stack tagging support has to work with a single kernel
image on devices with and without MTE support. This is demanded by Android
Generic Kernel Image.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211779-199747%40https.bugzilla.kernel.org/.
