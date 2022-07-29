Return-Path: <kasan-dev+bncBAABBBVJR6LQMGQEJ2BNYYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id E4E8158501F
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jul 2022 14:37:28 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id s129-20020a632c87000000b00411564fe1fesf2233809pgs.7
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Jul 2022 05:37:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659098247; cv=pass;
        d=google.com; s=arc-20160816;
        b=cWm5i1rVhPFFvodjw4lAEozqpPVMRs08kkjV4seyBH3/34dVFycVobHH5V9G6o5K7H
         jTFpoktMjk3NaFXQaoxdrvXjkFzTq2hyG3BE2wUZ0VWz77QCPWaaUoK0djfhav7JlQN1
         MlySsrzXLCjXy9zX9iuSF/ygiabc0XP9agf227FFDG9iF/uttDcz54FfNbd8jBV3Zgds
         26BmfomDZxeirPNOTdA2TPZeDZLteNIigg9fTYr27nPwEHnAOxVA9w345XJiOrSdwfEN
         rIpg/Z0uvMNuKrLRePWR1p7rbmgll/peLcdxjYo/KI9B8zLUTV3FjsFJSbmW6Yib16gE
         V0QQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=T8hOINzigMZoH6DLGNxr3nJ7ceowJM3F2Dx0TPqij+E=;
        b=r16C6roKBu0eikinZcF1XIQgsbZaT1yoOMKxEG1x29nW8/a2uKGmfPOc4rGgi+yGGn
         ilsLk/pPxK5Av20K5N2gBllOOmNnE/ICcLVA8JzWnYKdcjGCcA3tiPcEMw7ugZ/qtTHx
         +hpGPC18RGau6BLYsXnHzll53Oe8wCUn3lyH2Aj5BzEtbyUeYWwP36mgT3wBVwhyUz8E
         tRGne22KiJhsxzke86/gP0qSZxTO0XkqRMB5riWGY4EkWXt+aBZEbH9ewuqADlbxMlDB
         QFKW+ssgCTf4F6HK37O+suBtZtw6Lbp60HNspOAp5UaovAd+bjdeViFZ5F2v3ruSZAYP
         vWbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=op1kfuZc;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T8hOINzigMZoH6DLGNxr3nJ7ceowJM3F2Dx0TPqij+E=;
        b=HsXi1ZPh2VOwo8uULTXUkzunkUch/6tRLV+dUhKKQ8HIUJWLMI/bQmBhMnl1T/6BqS
         hXYGLu/tpdnfr/SmKjin4kPiuxYGQfNNV8ylG/zNKZ+gBMdb+ob0NXlpIyjmYIuUHMaL
         9K3c12qAAHXcDBxSM8iP+yThh827tOkIn7MfE5hqpbnrN78fTwkIX+gFJbmDRcGRdk93
         TH+aTlYB9ixW5suuTrg23oqoKgNsLpNCDHxl3ZSV3sd9Z096SWX99l5wWXB5V/gfX/W8
         gMRV6j5VypcEnHXBIA2KocFPgFe/fgnbp7AxehW+bd9tZgD21I5Hi48zjOfUgWmLiAbn
         6edA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T8hOINzigMZoH6DLGNxr3nJ7ceowJM3F2Dx0TPqij+E=;
        b=1G2SyOfAnZJHyBDnQy7tEHRl48BLHDIoylchBvDqdSyaSr7c/OmqwSvmiBC5uGQV67
         5X4kwmFX9i8aU192bmULc0js2/GsqC4+/suDZ9LJSMl5sFUfKt6wNw8KKl0S3HdGRpfa
         8I/gg4ZBEIvDXT0ns9PoA5J87prSDpzMAHHFbl2XQ/1kLYllw+VSZae0HcVgJWIwVf1N
         LQoz4jhMJ22ZP8+gfPufSQcdZhX7/U1kv1/yaUsw8xHvlc366tj1CGAC7gfeBXR7PfIw
         v6foiD1d+qZ9+fnTNy8d0BATu12HJlvpeFlSsevT66EujAUnsBoZEDvrp9ElR55uvotd
         2InQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2eY4BwOvOUXHbF19T7AkCYM18eS+UmWpf2zYg9PqOj/0Mbh1sx
	8UgBnOIU2mJMP68ohD/o5jg=
X-Google-Smtp-Source: AA6agR62IDglUak498yLwdFyYyNpGr7yVLeQTQ+EouDqm/J0liI5Kz/mCW1llB0jk+ozXx6FY6uHcw==
X-Received: by 2002:a17:902:f542:b0:16d:5a3d:a529 with SMTP id h2-20020a170902f54200b0016d5a3da529mr3769646plf.170.1659098247106;
        Fri, 29 Jul 2022 05:37:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:54c7:0:b0:52c:e9ef:c7b8 with SMTP id i190-20020a6254c7000000b0052ce9efc7b8ls34340pfb.11.-pod-prod-gmail;
 Fri, 29 Jul 2022 05:37:26 -0700 (PDT)
X-Received: by 2002:a63:4d0e:0:b0:412:1877:9820 with SMTP id a14-20020a634d0e000000b0041218779820mr2824468pgb.177.1659098246583;
        Fri, 29 Jul 2022 05:37:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659098246; cv=none;
        d=google.com; s=arc-20160816;
        b=rg+Y5egz6QFF9COMiddP0cXKrpIJtYVtEr6RLSiExekR6AxwsUApLcMg77/qiS9ikB
         l2Ro7EjfjENYOcv9chSItFLiDFlSQWCD4gyp8L6dtQZnfhZk7BYZ+q5M4UA/HPubRNHw
         KMKQ9C/LJvebAQmSJkAfvV/u8VbZ7xGW+g86YTt+qicyqe6cfTDpja84q9nb8MskfugH
         K1J4oXDB1XiWJEK56CwtOESflQxpmgWUYUBxKz/z+lO8sycVb8h4/v+qjuCleDvLTF+9
         WA1jji6vRCc8ipkx6ODIDRRPKdK6pRCJrQetMA/rUVAGbb+OTvrdFPp1O1aR43lRZork
         obOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=9ydZnbbcsZzo/aVI4LIgt50w0O9ZyO1CdKlZdQZ5iG0=;
        b=0w0Xie5NzTEEZPHdn1II/o+6x7rW/JWlmuH4gEAtcFOinLEszhHBQpjxtBIwpNbyEh
         d8BldsyI/R/Ivyk+Diocj5wxfQS05URUirXjQ1aZaS44SD4SWcKul2zYVyTQ2m7yHWWR
         5A7QZgHZ5upi06hRFnbhfCisxmIZLkZ4x31rWY9nnVBW3T+lMTeqszrh7h7YVjAxOoc7
         XytwK9lDDrWT4bGRdkz2dJ+3+rjawDDJvbnhY+ecYrqZwXPCnc4z4ZsGBTUNzz9wfPq2
         kKTRYUn5Frnq1yux1cGvy9LTJ9czxHJvl711wO4bKD2QLgtNxYwguBDT1qV7z9kJ9AcU
         jJ3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=op1kfuZc;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id i12-20020a639d0c000000b0041a4cf95551si191546pgd.3.2022.07.29.05.37.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 29 Jul 2022 05:37:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 03DFE61EE7
	for <kasan-dev@googlegroups.com>; Fri, 29 Jul 2022 12:37:26 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 655D9C433D6
	for <kasan-dev@googlegroups.com>; Fri, 29 Jul 2022 12:37:25 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 4ADDDC433E6; Fri, 29 Jul 2022 12:37:25 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216307] New: KASAN: check memory on kfree() before
 DEBUG_OBJECTS
Date: Fri, 29 Jul 2022 12:37:25 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-216307-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=op1kfuZc;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=216307

            Bug ID: 216307
           Summary: KASAN: check memory on kfree() before DEBUG_OBJECTS
           Product: Memory Management
           Version: 2.5
    Kernel Version: ALL
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: enhancement
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: dvyukov@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

We've got the following report on kernel commit 4a57a8400075:

BUG: unable to handle page fault for address: ffffed11035786bc
#PF: supervisor read access in kernel mode
#PF: error_code(0x0000) - not-present page
PGD 7ffcd067 P4D 7ffcd067 PUD 0 
Oops: 0000 [#1] PREEMPT SMP KASAN
CPU: 2 PID: 12575 Comm: syz-executor.3 Not tainted
5.19.0-rc6-syzkaller-00115-g4a57a8400075 #0
Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.14.0-2 04/01/2014
RIP: 0010:__debug_check_no_obj_freed lib/debugobjects.c:978 [inline]
RIP: 0010:debug_check_no_obj_freed+0x101/0x420 lib/debugobjects.c:1020
Call Trace:
 <TASK>
 kfree+0xd6/0x310 mm/slab.c:3795
 mi_clear fs/ntfs3/ntfs_fs.h:1105 [inline]

The freed object is presumably invalid (double-free, uninit pointer, etc).
kfree() is doing DEBUG_OBJECTS check before doing KASAN checks:

https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/mm/slab.c?id=4a57a8400075bc5287c5c877702c68aeae2a033d#n3795

It may be better to do KASAN check first to ensure the address is valid.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216307-199747%40https.bugzilla.kernel.org/.
