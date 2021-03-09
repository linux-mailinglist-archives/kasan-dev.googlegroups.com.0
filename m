Return-Path: <kasan-dev+bncBC24VNFHTMIBBDORT2BAMGQEKPTUZ7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id DDCAD332CA9
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 17:55:42 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id e11sf10715313ioh.11
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 08:55:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615308942; cv=pass;
        d=google.com; s=arc-20160816;
        b=QZLjH2Ku21k9IQhD5NBete6zDHKxwU5FK6CqyxqCn0/hCVNc6jkUp616oQ7an0LXrV
         gh4R30mKKowzeeUTidgM4OIFuZHdGCJhk2ZpUAPBKcHPCAwH8ww035Qw1UCA8eoOkEBP
         +K/vWK0Dobfv8J7NJoWygXkHGf/JZ1f8XsxhJUlw2HOJYtc7Y97f8cwgauSntAvBZ1JC
         vfYn4WFWbnpLkFS6iT12RXa3C4W9AOQ4K7TTgAOhjccWyneOyGQllH2tEx9gWnX5h3TO
         A9Z8S+qfP9586Xm0elcvSMg7yprDOJIRzLMHiTNP1rE06CBtVgXXyQ9FRv1B13fTU/uJ
         yIgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=VVyCkyuOUjnMy0eRIS7vYPPZo7o0SRVtbJ7cwc1NohI=;
        b=vQ/ow11GhotpMOQN/YxTLMdGyOCTdSXvPwoY9P2CSrHrXWrfzjJooAd8ttt/8lT1bd
         L61o9FWSMYWAF7HxMl8Btqkex+XiCgQtB3utf+vzRzhEJEeXPr3aB0W/MMr4yy2Y9lmt
         aT67A73rYA+96uJQnh0N1gUCiuleeB064zoGMzAKXpGpCbWyB5ljxwndhgc4dBxf/exm
         aWDES4DwVN34kcYoAk/i2bdpDWp0hIFWvPx0e55zRfwizzpHzeapG3cZ0l1JGgsROPMW
         +C8QgHvfV/evaRsLuPL+IP2EpoSFQyekZEzasblMKdZRXhC3ZHjqubFslvJR317rDHTO
         lIaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="kgj9I38/";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VVyCkyuOUjnMy0eRIS7vYPPZo7o0SRVtbJ7cwc1NohI=;
        b=H3KVzlabM5TqsnL+pAVQIw50QDJbQDo1GkTP8W6RtRc7fKSwQAlyKdfeqOaZ4Nxkh+
         W6gjq1lpcBgRlzp0U/M0b4GVAmq6/Brg8T/Zdg86N4izdPbZTqQDMAq6e8d2DZILywJq
         H7/7BYMI8CkJU2gSO3Nr+oBtP5yInF6AyvofQfOfkWv/7gHw0rkl3WkGgmViGlnV8i8T
         YHmkBGGTLZrqt7vgqPglW/uzk9MM0ZspWhpk0KphM4Ns0uDbMqHrXQmqozSa57BRQagO
         3dL9jetqiaa2k33sb85UNPh1pe3FH6S248iXd0YZ0ogD9grJpigF4WlTXrnVtrBLh8zZ
         zLHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VVyCkyuOUjnMy0eRIS7vYPPZo7o0SRVtbJ7cwc1NohI=;
        b=jYlIvn2f8Krbe8Vcqave69yrspW2aZFQFhLZYLiDKTr6cqlxaVi/qu2RJlPbzqIilF
         84WHCzbfx2GQmYlUgZiEwq0LMk4EFWzG2qyJkQwOEzVk+BJajmW8MaPmiXeM83R/mkm7
         EM/hSWVKKUVYXnVm77Luqvek7nCj4zc8rNDmdWADPWcbMlRitiml0Vfnufq1RRmduMMQ
         FOo9XxoVHYGZDp6Go/UOonnM7QJZ305/jR5udAGPpc4NDNl2sMG/EDkMmCJLGBS6oibM
         tk7HrYNykI7pA3Iyy/jxOX+aMxM5bX6QYYEbSvWHWoE6Cez5H4uaEUA+z1w4BzvB3mGG
         4gKg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533dYPLNu/HgHhTIqiKWRjZuBROEWYnz9QXjRkfmeSb7A1C/wVYV
	PsQTuPKnpq/u5gm3+tK0xQ8=
X-Google-Smtp-Source: ABdhPJwyIhdjnrB1WUoScoGyMPO9GzC4M5dQZ67lZZ9yxcPj8MADwuKTRlPyW4E+n8GFi7EzrphuKg==
X-Received: by 2002:a05:6638:2bb:: with SMTP id d27mr29053829jaq.98.1615308941879;
        Tue, 09 Mar 2021 08:55:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:26c6:: with SMTP id g6ls3443224ioo.5.gmail; Tue, 09
 Mar 2021 08:55:41 -0800 (PST)
X-Received: by 2002:a5e:9513:: with SMTP id r19mr24212523ioj.35.1615308941516;
        Tue, 09 Mar 2021 08:55:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615308941; cv=none;
        d=google.com; s=arc-20160816;
        b=ILlofxiKSINXAGnlx74T0tNAs+kPJhkqOB0sNCOxLzAWeG2rl4iSeY6NeJlKAQQoy0
         DLCv5E28nvYYoHH5BIgdgshn7FWe4rjf+FxO442DTz3Mt8I8SntDYziJon0g/02RKqhv
         Ueh0YMuWtaJ6/bsmGSBvfFLy0vna7bxg1NdQ4TqcXtOxlur14wOp2iLAAhwdM6RhdFy7
         6dXW9o684K+RSTvS7tHATIdFOPZbbXPoOa462WEZrn/+VaEeNccf6EaMPcnFCpd4S7wW
         GDadiluUgEvqhgLcL1Qf2qhpBZoD0LlJa8zk5z9bvH1q7yRNqNzsfPLxQUU+PolW2UST
         tPcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=pmL1D1hAs4JaKzPIShkRofdxTjj6YkGARHZZW4Knu00=;
        b=eP+DPzdO51sgH6XuDvYwy7IMcX9zXm4o16rfC15ccVbq0w+vE05nDq+gvqaLs8NBx4
         5O7bYk6tAJ4dhcvFslm2PbwMksDa/qWJ6iiqSN06Ng847Wgpa4tI52YUq+cpl9FloAKk
         KQVUnNi5smFzvuIN92mQQIgeFpyQc9jbjc6idG7bDzN5YdqDUXBlHOveX1ULGsVa5ie/
         qncU8rtoYW0GE4nNJzyINj5OMq65Np0bJURIbba4Fr1nb82Niq/KpaWXS5GMaR4DUr7+
         W/5zw4Pck+e1EpjOIddLU3+ytQGPe3TxuxrecS+UG9NX0ViNmXDTn0LWTIXxhdpA7vW5
         X5ow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="kgj9I38/";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c2si1034794ilj.4.2021.03.09.08.55.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 08:55:41 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id C7DC965237
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 16:55:40 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id BB72765349; Tue,  9 Mar 2021 16:55:40 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212209] New: KASAN: clean up multi_shot implementation
Date: Tue, 09 Mar 2021 16:55:40 +0000
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
Message-ID: <bug-212209-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="kgj9I38/";       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212209

            Bug ID: 212209
           Summary: KASAN: clean up multi_shot implementation
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

- Drop multi_shot declarations from include/linux/kasan.h.
- Only export (or define) multi_shot functions when KASAN tests are enabled.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212209-199747%40https.bugzilla.kernel.org/.
