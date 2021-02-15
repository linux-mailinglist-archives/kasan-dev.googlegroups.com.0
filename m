Return-Path: <kasan-dev+bncBC24VNFHTMIBBHMFVOAQMGQEWTWTJTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B49931C1EF
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Feb 2021 19:51:10 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id e9sf4522728oiw.4
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Feb 2021 10:51:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613415069; cv=pass;
        d=google.com; s=arc-20160816;
        b=QqeKFqh9C6kdc1Uj9eOSonxBVQZHIuBLrL1NGX51e9ZH44KzFk6ywrA+TbzxamUYw+
         4r7+4g1yYFy/WpRrNQlYJidoRRZYGig3NFN1+T7yTTRKm0sJjSx51iVFf43yvgvmSXtz
         1koVkNEFw4fkHmHEznMYldkanqBL6Ef1NfNKofzF+vsVZvHyB4+s0EPoTaThbbTq3qM8
         +X4yZZyQs20BbLG7Z2/BCLvU7LWvF+KhaME6BicuUdcgg2pjCvxPjAurxwqVfQMPVT7k
         zZFGqJl8GQFNfeESFGRFrcBqhHBIp40xeW8Ripohaf+MwIqELbTigAQs7HG6Exy6un7h
         6IFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=9OQN0sXNwtaDDI5zpyH+26E4/PuDGsWCBilLtNxJBvc=;
        b=rbhSXiBVe8873P/kyjkWC4YLNoCzXFk7DfeuwkLQllcWY8IPRkc8BR+1yFwjSmZM/3
         /5Uxu6UCVqZX4erYzgh9wqJDDbp/htiW2qecGr50i0zXovFK/KT0SOVkal8I9KaJDFg9
         tQWgBhXvRW2kl44fLfFriaH190hK5oRbfcDs5G25kuZLZtmKTiNt+eFApd/vtdCZwios
         DRtQHUkGvnnJF9rQ8X5kpMO6+xtnreZX8L/MLttxIsrpgmNUAS4EO+2sLzPoPghZTUjE
         wEPk26e4fW2Q/VzBoqQKOMK7bbtLQToNpiZmeK0Za/3tu6B0baLuJ+LBAYOYLe3tiNcC
         5hTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=k4KACTLA;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9OQN0sXNwtaDDI5zpyH+26E4/PuDGsWCBilLtNxJBvc=;
        b=iXqtTdjNvaOOodwEOZxI3TXdpnFfkYdYuQ6byxBtELzMseQdsZ8WUN7GTecuW6kf0s
         X14DklSWOLBECM0xO4Vw8dGt6IcRB05V/O4BdKkDz4uST4nKD1jc3lPkd0Q6XWSGpL+B
         azc+w+TJTxU/JTb//9cVUGWVyIpmO8Ccjh5sx9muLUVqK9y/7N5l9/qWEHamUe1a1ExF
         M+j7R8v3H5EeWksj5GK9+UJeeTgLAx3/MEVbjpFVNmT38wFg3GVMqCTAPiDNzVLfed1H
         eA7+6KUQgRUtHPpwnA8CiOR9+Wk8DI6EwpE+jg1CoVvwn7XYq5kzQOb1FLmF85/JExzP
         75XA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9OQN0sXNwtaDDI5zpyH+26E4/PuDGsWCBilLtNxJBvc=;
        b=A3XPRVbRr1IEteIFe87Qv+AHZiv/epiHBIfrGbK3nTPg5+26myA5QMfc+bYPhaa5tp
         XAv0xvQxbOEEw0x2y0KDKNrsNa43Yrv80wrKJMriNuVa/QOJ9mXsqnio+d7S2g7Sy7hj
         Ovx5Xh5aWuf506YVWZJGuxEDRoDk8XNdU4/qi/XjCBIeCGGhZ9gINW+GoaFpLxym5kcE
         SyAl2r2xZ3NUcuZ6jQs7m5PA60aT/08Q5BIVfCbEe61pdngKUxSoYcVun62JQqX7Lh/A
         kSAKqArmSFCNo+gKn7b3CQSW464bcH9bGGYysJBILol54JBxGJ/A6dLk5TFhTlfTu79C
         oRdQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533srphCaYJub8xmzLfAgkQH0t6S4nCD9oYDw3uFsiWaLOeNI2aJ
	Dcb4uSROsGnqSPLuG1LOgfU=
X-Google-Smtp-Source: ABdhPJya2dVywTibf/aeaSBxn2JRcQjB9OBySFHY8VJQ1fi2+OV8FfFKCBJdDpnSABIrL1aC2YWdwQ==
X-Received: by 2002:a4a:aa8b:: with SMTP id d11mr11731983oon.36.1613415069276;
        Mon, 15 Feb 2021 10:51:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:19f8:: with SMTP id t24ls3997890ott.11.gmail; Mon,
 15 Feb 2021 10:51:09 -0800 (PST)
X-Received: by 2002:a9d:8ef:: with SMTP id 102mr12774965otf.75.1613415068967;
        Mon, 15 Feb 2021 10:51:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613415068; cv=none;
        d=google.com; s=arc-20160816;
        b=P1nPBPT14RtEaH9De8MGVlFsRGxFC3p1rF5eJ/kSwvZKre1BmFsVk8Eo/I2sjiGVL3
         jjduy4jWkCrU5ewcyhhpwoJG1fMC/+ubPSMc5pkPUDta/U97UwNkDsakSnv3IieJnODq
         k4m3MKqoknd717AvawgQ12LIsXzgiDNQvCo2EYB4XhrSHjA8RE7hTomkfNEmEtuW0wo2
         F22+a5HcKxbVwvI5+VmwaYs/ijrbKIFc8UDpmPbIV6QSA+6NyjES1D/dmp6rUQNNityi
         Qnsbie0DvPj1Y0GnXoCV/38zwZtEkrDLVCfUUN3+l0RtUMmVpPyohM0AtDCw/OQBei5J
         k+9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=dVdumF5uFMEHuNcvT3lJyhQHzSK+9LCRqmDWUttHy3k=;
        b=lf9rydF0lctUeQy+Ch5W1AXQw/Ybs930wMolcfWwZwIWWdTT0vOccTav3TWc9Qvt+k
         9eInNkvF/Lsj5ovVItXMUO1P8kHn1glesXvO1fzDSlh/PIR6PQ0nU8Gw+UpidRdnHQet
         LSpLusSxm5aX2MzmKHtL9DD4VZrgapeJCr/Pv35h5yWoXCUkys3bqVTndiXj83Oc6kPs
         UHTCL1nuwOdbCWANs3e0k85iRg4zqtIgqvenn579nFU84lRMj8Bw93EZJChGZQu2rg2e
         p24D5o2pv8MQhgINKHbGf5n+0rl3yJPpUU7WhUP0ppzlf7Atg5LCWj4JWOit7PuvFJJN
         4BqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=k4KACTLA;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y192si1029090ooa.1.2021.02.15.10.51.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Feb 2021 10:51:08 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 2F62164E2B
	for <kasan-dev@googlegroups.com>; Mon, 15 Feb 2021 18:51:08 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 22010653BA; Mon, 15 Feb 2021 18:51:08 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211775] New: KASAN (sw-tags): support CONFIG_KASAN_VMALLOC
Date: Mon, 15 Feb 2021 18:51:07 +0000
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
Message-ID: <bug-211775-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=k4KACTLA;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=211775

            Bug ID: 211775
           Summary: KASAN (sw-tags): support CONFIG_KASAN_VMALLOC
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

Before working on this, it makes sense to add CONFIG_KASAN_VMALLOC support to
the generic mode first [1]. This will allow to only focus on the interaction
between tagging and vmalloc internals, without having to deal with the shadow
memory.

[1] https://bugzilla.kernel.org/show_bug.cgi?id=208515

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211775-199747%40https.bugzilla.kernel.org/.
