Return-Path: <kasan-dev+bncBC24VNFHTMIBBVPQTPYQKGQER4SU4ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2631E143DAE
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 14:10:47 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id c8sf1504242pgl.15
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 05:10:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579612246; cv=pass;
        d=google.com; s=arc-20160816;
        b=zG1sBTisn2cpY652s1Sxe6T7dDLYqwIrv4Lt5G6pFOQCYR+lT0I/6p/rQ9k2caBeaR
         kB7wNQUyasiZEkEaIItB8+KB++wNAxSmCJvVTYyhuKvcofFdR1aYtBrDlkxq+Hysw3vq
         4dzFe26mVSb8VVUPZAw3CBJbXQAfUmxHDzJ7KEh8mRbrZXhL31y8XY3a5nvPqqGgypkF
         vw+x0W/llDaaGsutrXJtjRxt+KV/PZyNhukux5H6X2bpApRigjUgznl1qayKlAEGtHWP
         9GVEzhNp7mYSu64aUDrko82Ll9mKPXxv63oe0xwj/jTKy8Q2dvrqt4u3jxdzXiKnIh6m
         mvOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=pBS08v6K8lurFrZkzs3+J93JFAfvOp8UbQ73Ea2jFK4=;
        b=v+FQDEd1MXrSv4EPYD4/LM7gxlQKsduqSbuGfiTSj3ZfBq1REtVJFZlMWGvEsrTd3g
         zG1JWDLMXOk1w3m0ERg4Ll+WT0MM38h9TixfoH3+tcV4o11L/meVOU1ilcaUwtr7L2S6
         qNFfuQedGKiXHJkTrFRaBMQpUKQpYdJITS82cl45VAtWZQPU5gS1EZVGZkUS4p9nXAhm
         SQuFpqewfF6KncdW+gmtfQJ254wjCPHsd86P2muAeKhiXTvs/yyKU2o7eXsjiPY+13Yb
         pwGkbWNCVsIfCvALtYgMYIpoE31MszzXiaU7+AbV6wamYiL3F133zYdzSTnAdpgba8zo
         h/Eg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=dqi7=3k=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=DqI7=3K=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pBS08v6K8lurFrZkzs3+J93JFAfvOp8UbQ73Ea2jFK4=;
        b=YubcE1ARNNG1mGk6+9rr9a5PWzBsw3dM6FCf3tkRd3IHau6liq0O81MAKBSwr8CrO2
         nqLI2sQxn90bWEpTAFeY3jffdAY4tlPPq6QZtKH4O7mhoMFlTwAN75c+XMMJCmmsWe0y
         F4h05sOPWRSQATNFcap7o+wcoRR+bOumtirZ/gvG+7NMAWAFMctG9wwDXUDMfwV0ad09
         Tuvg/TRAQrFDhWA13uNy/xCUfJhacOxbt4ssurvzUXxdjPakSSxw0zeffpVRuxVe+RlV
         D/Z7cdqEf/+aVD4LVk/j5LxmKcCsTdgitznRLKZ506nCcrTXjEQDEjj2nA0hRJhY7S2A
         yShg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pBS08v6K8lurFrZkzs3+J93JFAfvOp8UbQ73Ea2jFK4=;
        b=ScwsNfwqNSbge0WnBlQxMJRPBn2jaoCCqX7MI5ge7oqajWH3yvNJbHK4X6C/W+ChQx
         3xdqaP9HeOwY3x9PQJ2L8AbVtFS8d66onL/ckk/oNVLNDK6XinUBHJLZH9ced2KHfFCE
         CN8NLqBZAF/96y9zaBBmN6twsTb6xXm5Q6/9CRdXqMfrsBh2YQtKNFpC0B6EuLO2P9nJ
         WbF9QS+UNz5YTg/skIWte3jHeqg1Ptfjfi0iZ1o5Hlsflx/xvDzX3HUVl9K/Ea4R3hKE
         lqEcbq49ZQOpIfsyF1dlRCWC5/dsrD41Uf1Bbq4/WTxIaDfg6sdwSajqvMqBJT8ghDbe
         y15A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVksJVU9cP9BA10xGqHofA0gziAEyqoao3vTvBiQM9cZBGVd6uD
	GfPaddAUp6kU54jR/XV9ixo=
X-Google-Smtp-Source: APXvYqyY1cB60l9SoJWsJ7mQLoXz6p/y/BhJPC1tmVjMVYyDQKHvgQzYk5TREzf5QDSVOfQS6rR9ig==
X-Received: by 2002:a17:90b:2286:: with SMTP id kx6mr5313374pjb.95.1579612245965;
        Tue, 21 Jan 2020 05:10:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:791:: with SMTP id 139ls10816783pgh.4.gmail; Tue, 21 Jan
 2020 05:10:45 -0800 (PST)
X-Received: by 2002:a65:4c8b:: with SMTP id m11mr5525292pgt.208.1579612245538;
        Tue, 21 Jan 2020 05:10:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579612245; cv=none;
        d=google.com; s=arc-20160816;
        b=tOR3P++ItttueG8fBZUNLmhJc+ZpGXd0DxrW9o0Pps+ZxzcGpdlSOAmflHJx5H751G
         Udb7IJz7zz55AfP6YTBWCKsDbk1gbsOKuGPfSrgUc71Ogk2teuB3aYYTN1HYI2HcL+Vf
         PCbK7F6KHl6rXgOS4g/pXVUpcpL49XZbJ9Z5k02GcVmGD8ih8hY4bNn8scTci65hK0/s
         IjdYIzSTMZW6Pzu079FwCPH1B0caHplHs2xaSzUUQ6jlkoIHR+/iZb6SyCs14epMs/VM
         4hRxdDOocP6RkifxSN6Np2XdTUfUxSmnMQo+Wmxm+YEVsFbKjvwUF0nNYznRwqOo5eZe
         cqDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=Hp24QLy1Wx7kmh2/VyDEr0cNo0OCoVA0rJLivFHed84=;
        b=kP0ZH8a8o94ACIK2/9ZJBru/l16LsVhu1tqdhwqQxK7GgzQNhZn2YzF8ZqlaXqLHFz
         arh92NZyIq0IbGv8EonMhP1GmHqTk7Phl8tFsOlJmQw0QqLLEY3klmfNjz7DWye5/xR0
         UxzpYWAddFjzGrfAlqr3ZZBASpTgzg1D0PyqkHMV8qwTiyGDb+XhAF7NkGLcKn8ia0Pz
         IDsw3RW3449ewiTbK3Jv6E6gxBiJ9ViSNX/qbiCsTQxA/yk5+XZg+1XKPLqPMJaq815W
         Kp+gEFvP3BQYarsHwoEKRRrLvbmNn5+vQ1eMyAvf5HXoOYDK9kbshdWci6nv1IO3PNVm
         AifA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=dqi7=3k=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=DqI7=3K=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f8si422061plr.2.2020.01.21.05.10.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Jan 2020 05:10:45 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=dqi7=3k=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 206267] New: KASAN: missed checks in copy_to/from_user
Date: Tue, 21 Jan 2020 13:10:45 +0000
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
Message-ID: <bug-206267-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=dqi7=3k=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=DqI7=3K=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=206267

            Bug ID: 206267
           Summary: KASAN: missed checks in copy_to/from_user
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

copy_to_user may actually copy to kernel addresses (in compat syscall
wrappers). In such case we need to check validity of the _to_ buffer as well.
Similarly for copy_from_user, if it copied from kernel space, we need to check
the _from_ buffer.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-206267-199747%40https.bugzilla.kernel.org/.
