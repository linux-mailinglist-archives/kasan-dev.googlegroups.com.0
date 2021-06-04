Return-Path: <kasan-dev+bncBC24VNFHTMIBB7HY42CQMGQEVGN7OPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6572739B215
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Jun 2021 07:39:09 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id o11-20020a9d5c0b0000b029035b9aaeeccbsf4548141otk.10
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Jun 2021 22:39:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622785148; cv=pass;
        d=google.com; s=arc-20160816;
        b=bGx/p9VaFcZugDi9pOKRnabaVHFEkUkaOAbWYE3cSRN5B7zepNlXDsjBTtTGlrfxLe
         P9KBEguDZF9MpGkBFILC2M0HcOfrvg52smHkXlE9iDRVTlvDa/Uez592oPTaJ8wh0FBL
         D7ATNIVh3Zr/bEb9rjxCAp/s1vaNrcWE4W4nwQB+T+OjdYUDqDRBNXB9fTzh4j/NyaZa
         1+unFU7qNM08UZZvC9MrjrsKGWi348ue4EorTZdA1ErOBbV78PW5hZe1H2ZXp3DzQhLn
         Hc1gaYxfih0Nwv1onbr/Z0D1s++axNkSBHHtS9TnKpMPxXWoUDuYPRwuzyXP0DS979xa
         gHIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=Bgvb5UG5TNwwmaS3UYN4vLhOEkdWkVu6/cbMV0mkbrY=;
        b=DQhGr6ZjqkkzmtV+WnlceAd9OwjvQ5W19h/89PGrq6Dn/zhAC5nvG8h23QpeWfnHVe
         +7XKwQOQ7KoXLv2SQBmkKPpRdyqdRhrC6aU8hur04wfufQ7TIhSr07tMgDr49Ibi+3jH
         IAH3CmzSUSfFWmAgnO5+kaD56DuQXw3aWisspDKsB4q860jhTdtgKAshkF5Ya3YYR2Tv
         TFOZJU3zWrOE5qCYkOQDBxmSJZJYUDqQBlHv6wCaO5dbybi+T3uKWJhXf/DGYeGeGTrI
         Igl9sdXwLXgduoRSwSCQaWsJ6WCOEYhmWxLpi+XfxEnarUrl/7iyUx2+oiI5kqPDkBDq
         7Kog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="N/3jebSL";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Bgvb5UG5TNwwmaS3UYN4vLhOEkdWkVu6/cbMV0mkbrY=;
        b=j4iZWyaUdootSaXPk1TduGxGY8j5d3WXPWPMfeSCEKIBPu/s3+rmjrTobK4peKuWen
         Sg1NhIjwClWyCnOkQFyw9orEpCB4De1Vf1qiKqn1f5UVT6xxWxcN+RdiAIZsBiK9cK0F
         /XH540dT2ZMqX/Xg561UQUGCdkTihXFlKoggcEXIRr51x7sOMuh5QaqCpeAFy/ddFFDj
         1XqiYiYdhi4s3dNiDGLPQcLbW5Cxc2QEz/j+Gs4AawHP41XdVportmN2N1RhsKSL1aws
         kiyKVmFhxat9y5BNz5lsboe+ORj+vJ7dJfCqBh0pVuQGbFDAu9zA6+MvHd8xvOZs5w7i
         JzKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Bgvb5UG5TNwwmaS3UYN4vLhOEkdWkVu6/cbMV0mkbrY=;
        b=fgLoCu3uT5VjvHphJd/oBXvJloz3HYcgXMPQJNoBeQXJbpzm8TAZ93qVoakooFflaz
         lE+DeUQ8fjlZ67gos+nnV5XYGma56veA9GwGQJw6RLI1dEdDXt+Dchg3dv6jeuCjxaqW
         3fIHV+sAc5c1/3YqmvOBxIgAlFKgA6YR8OwF+w2eOWnhPUtaYK5OVWsrfkAv7A7sDhX2
         NdqRLXeyNRjiYSKktgupvlUuEIj7QHmjGVTYLDJVFjroMSd+96UOf3WpIF7R5JeDvDsK
         kDstxGkt+zpIG6IAyADDEJwzvVaPLj4W6H6nUbRXujRHYNwOxAT8O6HWwlCDqi3zsf6j
         g9HQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532yYcjlfQ2mC0VPs0v7BG0eGB/Hc6FksGupBxGFVTj9n+C3f2Iw
	GcKElWcEwVbfHU4etrVRA8U=
X-Google-Smtp-Source: ABdhPJxKKlwVwJBNBf6OQG43YfENXEG83AVxHgbi/2HxfMJXm7Ep1Uaj/FPrWS5TcVDQq2/RsIrEug==
X-Received: by 2002:a4a:d69a:: with SMTP id i26mr2284415oot.27.1622785148146;
        Thu, 03 Jun 2021 22:39:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6959:: with SMTP id p25ls1917055oto.3.gmail; Thu, 03 Jun
 2021 22:39:07 -0700 (PDT)
X-Received: by 2002:a9d:69da:: with SMTP id v26mr2424060oto.338.1622785147814;
        Thu, 03 Jun 2021 22:39:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622785147; cv=none;
        d=google.com; s=arc-20160816;
        b=OnjxmvrtfFvXr66dpVeqSIX4OKriwFBDN7W1sZ6rVHI0XP0uLIQ9Ck042a/kKzTiva
         OM6Y2r/9G4vmYek95MKLPoqphQ2kBZ3l2Ng6k2gV0i/kh3v2D+qkek1amC2G+5q9B3Bz
         5ouPouL569w+Q0xeihIf9DZa5T9WYU8RXjRXZZ/lzZFur/+wCHX+w05dXNPNnhW0koKZ
         /MVRXm7YvEgVsae+H00hbHcK23wxseQRHuYGNZocvGhQUFw+ji+Gvkrt3VZhOiUNZmIB
         1IZkM0etVSvpiGZtRrzkixeJz99jtP14MJVbtKCfdu/+waq0LwtyFbS/KrfjzXJdGkGy
         +LAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=dynUOk9Nhb+17OEFm2cnaIU7SW2pNnXtfe60//JvLuM=;
        b=P6V3yYUERvDdaEyHwUhPIsGJaeNcJz8r9sPvP/KcMvRIw1VjVkvL/as7I7ESP4C94C
         O2nBd8vMCDJQmkaQUuvHjU4QOjjK7agzYqmPPfFflnLTgN1p2p7Wno4SKItESQICgDB+
         BBnGFBXM4Kevts7D/zOZssNIkwMBZfKLUpHReytwRI15n3yQInWkXYVyxgvVGs7a7BMU
         ZyBzYmiE7ugF1cINd83jWuGITQgl1ysdAFqgfLMhdAgRJ0fyeqn2Fri8pd90qjWugo9M
         hNX9ETc0eFKQr6buXCeiPTW+K1sS2KR2Mtcna579ZWTj07/iRoMeQ1af59DcqaQhiYyA
         W5Vg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="N/3jebSL";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f4si171538otc.2.2021.06.03.22.39.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 03 Jun 2021 22:39:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id E51EA61412
	for <kasan-dev@googlegroups.com>; Fri,  4 Jun 2021 05:39:06 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id DB6FF61206; Fri,  4 Jun 2021 05:39:06 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 213335] New: KASAN: vmalloc_oob KUnit test fails
Date: Fri, 04 Jun 2021 05:39:06 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: davidgow@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-213335-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="N/3jebSL";       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=213335

            Bug ID: 213335
           Summary: KASAN: vmalloc_oob KUnit test fails
           Product: Memory Management
           Version: 2.5
    Kernel Version: git master (5.13-rc4+, commit
                    f88cd3fb9df228e5ce4e13ec3dbad671ddb2146e)
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: normal
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: davidgow@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

The 'vmalloc_oob' test is failing.

The "KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)area)[3100]);" line is not
triggering a KASAN error.

I reproduced this using the qemu patchset[1] for KUnit, but it also showed up
when compiling and running the kernel manually under qemu, with the test
built-in.


The failure message (once [2] has been applied to make it useful) is:
[22:04:04] [FAILED] vmalloc_oob
[22:04:04]     # vmalloc_oob: EXPECTATION FAILED at lib/test_kasan.c:993
[22:04:04]     KASAN failure expected in "((volatile char *)area)[3100]", but
none occurred
[22:04:04]     not ok 45 - vmalloc_oob

I did try randomly changing the 3100 to other values just outside the 3000-byte
array, but wasn't able to get a KASAN failure.

I'm yet to try bisecting this properly, though...


[1]: https://patchwork.kernel.org/project/linux-kselftest/list/?series=489179
[2]: https://groups.google.com/g/kasan-dev/c/CbabdwoXGlE

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-213335-199747%40https.bugzilla.kernel.org/.
