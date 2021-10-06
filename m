Return-Path: <kasan-dev+bncBC24VNFHTMIBB6U562FAMGQEN5GM6KY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 7146A423D5B
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Oct 2021 13:56:43 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d9-20020ac86149000000b002a6d33107c5sf2080470qtm.8
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Oct 2021 04:56:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633521402; cv=pass;
        d=google.com; s=arc-20160816;
        b=CdXQGh6XVJg9cWtp4irDBFg1C43VOsv2oGE5hHriM4RAHjqgvx5gixr0pnWA67KU6A
         74GVDUaN3mzBwBUH/LaZB8fdQ3JQIABF1oNm9HH8Xl0neyUWgzplOfJl0TZ2ZRPh4Ejd
         /UP5EaDzsKPJLAgrepfSjKFDVQdG239VO0s1PNp5F0YOm9jH53TPKTy+I44tJ3KLqnRC
         tnJhE0fwZBwH/mSZdZZh9fudCKH/19jRl55Ck4R2YAoIDCaMVo7UCNxyKIV71tbWgl7x
         ffQCasBiTmPz9gc+gSJeNYqBLc/PS4ogxuN5F4soHQpHp3V216YXGqKjR+2hWvpq1C7+
         B7Sw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=23D8yElFvkL6AQtE6F5WwuZxHqjYlIVnRLopaqObnMg=;
        b=nZ9CCB7WC35elowKDg87PDJQJucMRtGcgvF9S1FInHAhEWLdE9sEICC9hDLmNCDp99
         AF1Lbei2Xzv1rPwH1MvZ8QZUzOqsdm/qNqfxPqZNiD5qZ0hruiczRmIlwVBg0vBx6WD8
         Du1boB+w9Hlev0QzeK+R804Je1Lo83iELq/r7ZCcEIh6EyUVHSAd/u335RP/zGUqBbR1
         Jw7oSEUq1BzXar5TCs5944BksyLaorWRB1RBh0EbQBvKCyCDM+VXniy/0gdfMV9BjhwD
         M+KfQbWIU9yzKhO0kpjVK0qG+LJrUxbMyMJBcLhKbwfcbY9vRx/uz76L55suZ/7iqJVw
         hgww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QeKWHo+i;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=23D8yElFvkL6AQtE6F5WwuZxHqjYlIVnRLopaqObnMg=;
        b=T0F0RrYMKnrZUDAe24CCijKiMEvD8Mq93zEHnuQ739q4gI0Xz1u7/tgLvWGeXTkwKa
         Aj34CfGKowaH1DhdaHFOB7cfjd7N6kAOJTktUq+va3GGM9Do/4Wf/azSPd1qymEtRZ/Z
         6iT5DE9SlJT6PR1YuEk3LLxGh1HU7ZBA+BI2x9xfVxtGBZGU3CYB18ATr+0ONx2WSTIr
         mie3CcTZNihiKUo8x1bxY1mheKlx6m3j9W2rPz3fDvs6Nv5DjkgCDlzdZcAfBWUQvOhw
         8RQ5q3slsoa4B5M7QmFK95walZF1fcMuoLCV4Nmr5hdv1YnyOILSl3d4ZiX6r6nPRxjb
         XNrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=23D8yElFvkL6AQtE6F5WwuZxHqjYlIVnRLopaqObnMg=;
        b=mM7ruULPGd6rkJnuYASsbfjU39ErtCaPQc/GTKrRFNR06THB06IDte/fF0wne3sWD8
         ltm3kO+G+7s8zfdmQbwoeZUof5aSbWRYrfplFk6qVqYc+Sakx4QgcxKPMBEzxuJOKzAw
         BOw2jANwxYhfGwjrMHWIlMLCwJzwBsSMHWjUhNV4dXPZHIQpAQljqQdhI/iadFnGerKq
         GG1k5B8jJ+lPoSi7SLYRGsaViRx7QApxHA/Scl4jQC6nryyd4JCA8C9iYoXkxCqRJLva
         OfnDbG49L8yNabgzlvbnFA9NryoDDLsFy8h6l+k75zCasXJKVxL/klirj2r93efD+65t
         KiYA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533lolVm2R6TT3n5layoZAJ/5sJNl1xVffQODt9b2WkHW4WI8x74
	FcAGK453Scm9PzI59zti8Js=
X-Google-Smtp-Source: ABdhPJw4lcuOE+XwNkmO3+A6u1oET252pMhHblNuCvJtd/Vfk/1JlkK85JP4dJ9YVUVfM32wlA80JA==
X-Received: by 2002:a37:94c1:: with SMTP id w184mr4826998qkd.103.1633521402607;
        Wed, 06 Oct 2021 04:56:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:24b:: with SMTP id o11ls14292786qtg.0.gmail; Wed, 06 Oct
 2021 04:56:42 -0700 (PDT)
X-Received: by 2002:a05:622a:1a92:: with SMTP id s18mr27345641qtc.76.1633521402178;
        Wed, 06 Oct 2021 04:56:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633521402; cv=none;
        d=google.com; s=arc-20160816;
        b=bDZzsVAYDn+TXaaRYiK7uEZX7ufPzIplEUrDAfh/FnPCqwyyb3rM5QPW5JOAJ4ZwJe
         o6mmVubEToIQA7h29sFRLW0eUBpO+Vun46m4tV2GNVkG6uap99joO9YHly32LPa6W4Iu
         NSpSq/H2H4wYELEvPcw0xwhRe/qE+BVwBBXrHhG9i5pWjhlONzO+hoeoSL2cmRa5Lmsy
         p8DrR77k3Ri4F4fkkg9KWUibpFE9PC0PMQM/TiyVyw44Ru0uCrVREahCXa5l1dVRPGOG
         HjkSXugwQfXpzWF8vbVeksgnUQXZSsUTGMMlyuxqwtYISzzbARmTvi8sjYaYxikqpPqA
         jxbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=chl7Px0kt6OYlApe2my7EuuZmqjqdW6eJNeZAwRw8Rc=;
        b=yAxqOjObbJzd5HW7nInE9wJc547h7IDEULh4xLPRYUQlp7zQO0Iq2QW1JJzD67qQ6g
         WO+rE1BFr7lxNyR4sAOLwqAW6XDvWdnUOxZqcCQlvNVVNOolwpvA86ZcJOM29ndCLz/F
         ODESpqhx1SwF00gO/1XT4P8j3B88PZqwhKET8vtkr7CZy1b8jY3t7A1sDEYrfdu0jWr6
         9kR0uKfreD6L2iXlemoTij6B/aQ7otrGNDae/BXEnaUQQjSrVDI5CgP5sQI5GhcZei2/
         4yYw1mX1YBXOJLdu1ApcVVE+VHM5U83qUm6MQ8PmcahD2UXylGkEIC/aWNoczSH0zx+5
         SrRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QeKWHo+i;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 4si213238qtu.1.2021.10.06.04.56.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 06 Oct 2021 04:56:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 0C45A60FE3
	for <kasan-dev@googlegroups.com>; Wed,  6 Oct 2021 11:56:41 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 01EAD60F3A; Wed,  6 Oct 2021 11:56:41 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 214629] New: kasan: organize cc-param calls in Makefile
Date: Wed, 06 Oct 2021 11:56:40 +0000
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
Message-ID: <bug-214629-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=QeKWHo+i;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=214629

            Bug ID: 214629
           Summary: kasan: organize cc-param calls in Makefile
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

It should be possible to pull all cc-param calls out of the else section of the
CFLAGS_KASAN_SHADOW check.

Then, the code structure would make sense: first, try applying
KASAN_SHADOW_OFFSET; if failed, use CFLAGS_KASAN_MINIMAL; and then try
applying all these options one by one.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-214629-199747%40https.bugzilla.kernel.org/.
