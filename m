Return-Path: <kasan-dev+bncBC24VNFHTMIBBX64ZGAQMGQECTFCBVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 30424320AED
	for <lists+kasan-dev@lfdr.de>; Sun, 21 Feb 2021 15:29:52 +0100 (CET)
Received: by mail-ua1-x93d.google.com with SMTP id c8sf5157200uac.11
        for <lists+kasan-dev@lfdr.de>; Sun, 21 Feb 2021 06:29:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613917791; cv=pass;
        d=google.com; s=arc-20160816;
        b=d6jWz8tI7+JE9609NKZ3DI5uD51dRtauVttTt20gM6gHp1hLOX2HgRNWlOpdcwIr74
         +sNfzxKTMYCo5vQmXpW33iuafHXcqSNbmJey571KpZVc4yYyqni/RvHNvyVTzVLcbQ+w
         +JmwopkJOJwgq+FEY2PjMuWtIVoj9Y9oyft8eMxI7OyZsKXiBsJXG7xdgp+84qzhe2Zu
         kRrXBrtEP7jGCfinct/uBQmiNMUtXEMjEs7bzDbKM7HIorVjJWnSuI1i/Psp5u5CrX9Q
         JQrFNf69r8ud3f3cETr/lNW8NAm/CuV5UcYebZsRwxYI0A3gh0ODxNt2SSXqF4yOYBEB
         X1AA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=F+y46XkRikSLd5K9Bh7/CBu+Id09XLhsXYlecW1Tpgk=;
        b=ww0JwOv7536KmlAICdPutztgPF+udEzfuq7Rv7akmh0KAj08tLL/FKaM5Z9lkF+KbU
         0k8GdFzn5ZSE8AzKaMHjgVf0QZaXsJKWpYYRZR6b7i0SEMdympxknqxPBQXr/EgBTOfZ
         T6BlNZFNnIKZy2AUYmtasAKzvX/Sj2R8gvw5Fji/zWgbmMt8ie61jQPywrqyEcTtQdDS
         kd8uvr3JRFpqsE/9hnNEDA9qM2fGoHmmk5orQgug3CEW7vnO8sbWvdqkPoORGDd0PU1O
         He/iZas0Ru+22M0v+UD4c0Cu9zy9dnsANYp/fZdqnQWkAD2qOKM0rWIE/iTSklWhteEL
         alkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bzyozIDm;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F+y46XkRikSLd5K9Bh7/CBu+Id09XLhsXYlecW1Tpgk=;
        b=YerWYN5NZer2mzcTW/TJMfdES2/1JwnTNXPJ0oFH2F9LvM495Vj18rbnfo52473bfB
         A19b+OEKmsQllGc682Pp8KMoFo+LyKX1hwasDV9JKae9SVYfpOhWZ+8Uc1FsD81UwW2u
         PO+DDlivwqFKAXep6AKcZ2TWwHsxDU59mQNyzb7xDT8bjkwUll1RYxRCd6UZ49wncuO+
         iWSu0+1XE336Y9PwNl/sADiVodJqFK+XtRy1QLhIuMwQrW3KF7gnO3fL1MpgrdmSSP2a
         p8w3W1AlCqBrZ6S3zGGHhkS+jFgIuLFuoaZRsLHE6Ls0b3OR4VY1iDcCdJqdy9XCMAts
         iHAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F+y46XkRikSLd5K9Bh7/CBu+Id09XLhsXYlecW1Tpgk=;
        b=aWWzCevhMosrxSid/1ZlpeRt/9ZVre2Xky31gC3lM6TrpZ21XLnGI1lW83Rn4KgFyA
         QAcjqrEi5inqGjcc9Xpk2xn5lksF4rqI3C+gBomyMkJ2y81NU2qq22G4RkKp4dbDVlaz
         JIg8NFgqgUtLY7A/gyXJrqmJfDcawVF75nvPZ3MAemCvKdsCSejo6p0EGoocBJuL+G20
         4bQdVgcMTGkrLLRapglwS593h0D0Ffjdr+SIUy8KT5jiSnvN+SeJPO2H9ciykAY6zHDS
         18TaMFyMi5h5XBRJ1naI/lkj/BV9EmdPbwfSllgp7+PCyojNxegMWRrPkRbsrgeycf5A
         XYRg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Da5WLtgzaLxg+uFkvPwT/UKcJcH3lHZm5fQtQHhLFT3a0MBSw
	Aj/2AHVT6AW5XNhxzLyLKZ0=
X-Google-Smtp-Source: ABdhPJzW8MkovSPlz5Kx9ovyxKTLXnfvjdmwbTlSHs4SjsTNVUa5HDziHiF/mmh8a6H5SY4NxV1kpg==
X-Received: by 2002:ab0:498c:: with SMTP id e12mr10010744uad.10.1613917791274;
        Sun, 21 Feb 2021 06:29:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:ce91:: with SMTP id c17ls1655465vse.1.gmail; Sun, 21 Feb
 2021 06:29:50 -0800 (PST)
X-Received: by 2002:a67:8b05:: with SMTP id n5mr11424835vsd.32.1613917790877;
        Sun, 21 Feb 2021 06:29:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613917790; cv=none;
        d=google.com; s=arc-20160816;
        b=xiqlQC1Ebg9UGqKBOUWGN/IP7SinQ/8VE4PBMhwyP1nZKUHMAQQk6DOVll3hxJpRkQ
         Ha/AUojMM7l9aCZpE4Ww9q0b7x6XKSfcHMqwKDgGpVQxS68yyHW48QwJO+TYD9MpkvPr
         VVgQhJ5ypcKIiEwn7mBhk21/OqsBptjeeiU5BO+ZzXcMFhySqJsCC+5Mjnn9txkL/tuu
         JChg7gXjMlkWy1P4wjZzVrrxnmnRZbK491bMhFtKZnPMA64YzOkcYJbgBDYCPw2W+iIE
         E5eR1DdzLfJEoa9MxfdWPKOdalf1OIn3O1o3b1xJimTwOs7+srTYEyUydL8NYh8UEhPE
         StLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=/rVNoWbhENiNHYnmA4s+cb0WEjYp/Y0GjFIyzaoI3G4=;
        b=oeWnj9FcW/A52JGaIBd4BzmU3+RdkS1SxrL0TxgqJrYISsNBqKlrwbM/mM3YaM36mJ
         PdfZ+aGyNqRicgNR+Mrhm9goO0iyWqFGfNFNu7znx8GxY/FYLoZCwtHqMMoSJuY6RQ/M
         5CCK66vYlMRtxgvKsLSjTNONCilkwP5Qg+t+kMlD1YewhmeqXr1IyV+acAjseQKGgEtN
         8NNNMPLKZNBHVlpO5Xid3RvbhV6SY84kWgCFKKtuQdblirPS8NB7hVatxt+8MVic1JKt
         3z3tO/oWtdRFZ69+lUQDr6p/lbR4DPy6JCBbIC66rOvwpHkehCjPP7/X8i4gYYpjQOb6
         fQqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bzyozIDm;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i20si89909uan.1.2021.02.21.06.29.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 21 Feb 2021 06:29:50 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 9EC9764E86
	for <kasan-dev@googlegroups.com>; Sun, 21 Feb 2021 14:29:48 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 879BA65368; Sun, 21 Feb 2021 14:29:48 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211877] New: Make "unregister_netdevice: waiting for dev to
 become free" diagnostic useful
Date: Sun, 21 Feb 2021 14:29:48 +0000
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
Message-ID: <bug-211877-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=bzyozIDm;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=211877

            Bug ID: 211877
           Summary: Make "unregister_netdevice: waiting for dev to become
                    free" diagnostic useful
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

syzkaller triggers tremendous amounts of "unregister_netdevice: waiting for dev
to become free" warnings:
https://syzkaller.appspot.com/bug?id=949ecf93b67ab1df8f890571d24ef9db50872c96
The warning comes from:
https://elixir.bootlin.com/linux/v5.11/source/net/core/dev.c#L10261
The warning is triggered after 10 seconds of waiting for the device to become
free (all references are dropped). While 10 second wait generally should not
happen in normal life (NETDEV_UNREGISTER notification should make everybody
drop references), it seems to fire falsely very often during fuzzing. At least
it's not possible to understand if it's really a false positive or not. All
messages the same, so we can't e.g. detect only 10-th such message. We raise
other stall/hang timeouts to 100-140 seconds and in qemu 3x more. 10 seconds is
really too unreliable timeout.
We used to ignore these messages entirely, but then real hangs are detected as
unuseful "no output".
We need to make this timeout configurable and/or fire a real WARNING after some
timeout.
If we keep "unregister_netdevice: waiting for dev to become free" message and
add a WARNING, then we need to somehow change the message text, so that
syzkaller does not consider it as bug anymore (while still considers the old
message as bug on older kernels).

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211877-199747%40https.bugzilla.kernel.org/.
