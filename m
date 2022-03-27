Return-Path: <kasan-dev+bncBAABB5PQQGJAMGQEIG5RJ4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id 66AC34E8839
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 16:45:10 +0200 (CEST)
Received: by mail-ua1-x93f.google.com with SMTP id x9-20020ab05789000000b002fa60bdf012sf3757272uaa.1
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 07:45:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648392309; cv=pass;
        d=google.com; s=arc-20160816;
        b=f69yUupWQEcecmZBuV5/rvn4Avpkm+3HYBXnOBSDGHoh3cl7pCmDN4lnTalETzREod
         1mZwztNEwmwVQue8IoTKWa6p28dQKzsKPukjzG3mZTJYgEorBFUYU/tNmiDF4rI/G2c1
         gcjVzKurVIocCxVsw7mF4Zjh27cLrdpUo7hK8RgfuqPIrmg1RSs5UYxibZjXKWi6eW8C
         kW7eaImWmUvj1Jm0LbikVhzuIQGAKCNzoDOaYT+6qajPBsqr+Zt9/gSNuUCQyXZbvWFH
         hBG2Ypv9Uhuvy9JZQTjPmfZgA2U6WkthIlXooktov0vj8lOO0oxDW38W2H4FtELhp+ch
         qvMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=CNHvOQ8Tz2IO+qgQiGslqW6z7y5zIeWtmMw4p2YwGW8=;
        b=bahyqM393/9AwMy05iX6fi19ITT98qy4l49u0ZOX/sfMnvlLm7o4o2HQvyOXgFcz9n
         GypBSgvI+5w3sx1jXP8GL0Pssuyup0YBT942rp9LklC1JhtYeJ67/HQrfVKn9SeIkXy5
         t81sfW0+7b0+V7YAhMMPbO5GmugATeDv02DOs6gxsl5225n1HjCTJKVrDZZ7WRUHmr0X
         PQYhBkq41vx0iTXblNu7YuW+UC4dj3Fd2wlJKxsn+O7N3cjvCzGS1Dx42uK3fgPYUYdy
         cPDly/eCuq9ZeWOVkPWPWIZI08bE5HojJoJLOJMx0Su7QbGYKadWbftKyv+LoCcs2Mby
         LYqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=p9KowqTP;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CNHvOQ8Tz2IO+qgQiGslqW6z7y5zIeWtmMw4p2YwGW8=;
        b=cAGRaM6+btAj9WfCrMV11GPo+nDGrhDPxa6FV6CNqBvf8sIdknkmCWaqfK7sdTBz8y
         FqgXzRY+Di0xO832KdSZYo1EJHnxgS0a8jwrX8zO6EC0KdKW1WQ0YR2H93PgcxzG9g84
         I/lVaOWYWL3lmt1xz0E1e6hnCjLjBz169ejTVXZANevzRMz4n/giPQR/Ck3SSfIWQgiu
         q4NLhKbpSbOyAi/LjcsU8eWv4hI7n18XAqBikiVHnFw9+qw6lM1HlABT4dvDBYjNvQIJ
         j3gpIkvH5pW/nWWI/eIcHvvtHvaZz8+uAc7+/Hv3eoWzs07aDGwJKB7vTQ8yPMI87d0g
         L9gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CNHvOQ8Tz2IO+qgQiGslqW6z7y5zIeWtmMw4p2YwGW8=;
        b=niUIbMsiNxYGAdTb00HLTHFXtkIopYcvoTXueE/G1qzGJtbV4g1Bgth36+27+4mB14
         byWu0OV7fPLx9+fqt+Q3dFq6YBaYlPdNtKFwb6H69cFej1Q6ziBkHSmcWIoFrsSBdG0G
         Ez94dqS9eXr6nc6SPyGKQ6sVmzH0IoMRJ4aPdNiqC9J1rAzGD+07OlWpCGH1uQeM1h3I
         A2ky2khYXOlTSc09S9AlYXsBcSpNXPxyi3sVnEPaligdGgmZC/Rd84d/s53LcM5WRpKd
         qkc9eibddQk7YZjEY9XblxaxAqpuMGV4nGtCoBO4anE6TLJji/akxlBj1alL1CaYCjsp
         8S2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532B2mw5B4gUuvRZLqed2kdId6r89glzW9cE/t/wvy6XtsHdMHG0
	QJhT0ul4jyDP0+HKJ1Jjy40=
X-Google-Smtp-Source: ABdhPJxU0tV0ejqx5OYxjerknI2AH/75hqaCT4RcrqgxH0WNfq/UPjX9tYEpZWK3rrsCdQZDdFz2fQ==
X-Received: by 2002:a67:ee87:0:b0:324:ed5b:68fa with SMTP id n7-20020a67ee87000000b00324ed5b68famr8600873vsp.76.1648392309487;
        Sun, 27 Mar 2022 07:45:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:6054:0:b0:32d:23b1:3d8e with SMTP id u81-20020a1f6054000000b0032d23b13d8els1073323vkb.2.gmail;
 Sun, 27 Mar 2022 07:45:09 -0700 (PDT)
X-Received: by 2002:a05:6122:20ab:b0:343:411:49f with SMTP id i43-20020a05612220ab00b003430411049fmr1793190vkd.4.1648392308972;
        Sun, 27 Mar 2022 07:45:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648392308; cv=none;
        d=google.com; s=arc-20160816;
        b=AbCJoMlyBKchOz6aVPk4Q2vAfsp7vi7ue7qbf/bdoWaloc1UC6FZnQL7TwFXHzIsM/
         MnkUGwtfgx2zMYEP4Ua3PiLiJHzhWyPAx6cGrCiY6D/YAN8VeUgtHU8iBAHAkxJbEKPo
         8ssFZd1j1qX6FwNp/M22jX9Nkzmhbd0IDzmXHz4V+cXwVZ8mZ91t117gxZb+CGFBI4Rn
         ut8AGkceL0SbuV0WMjcW1LZ40ZG+iz7dFun2qniUH8wfiCtXfybl95uUlgP0CwA+tn0w
         YQj0vx+Ft/D+qzfIkYnr1Da3JkpTvEmlviXg40n223gZIUACSJm08EW37Jr/pYxplqjV
         FR2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=PwD53NQM7a7eNlp4PtUakvNDA2xUhl5u+7RJepUUXAk=;
        b=JSV1FFDreYBmAuuNSsCopqwD0azNTOLN54ILtenYTrJSI6hAZVYFki9pJMDQJH0Hlu
         nLAkIn/4iBDZLk2QJBFvu0B9tUeZfb3i7iGsQn6pD3QceTqRzvat28r8dOi6rtVvia4C
         9tF8WuzNmrW1Jk54wEib9Ot7Ry0Wm9TmqYLVAQvnvusJZNzLrF0n7v4bnvN9cn40vhbi
         C8hYxmPjSar2cyOpnxkGvRedGH5BNaLUCOy6+0yMOKdFfzwnsvAoSI/g5ldAHBW0Ype5
         Tu10XlHkJjuNhLjq43v08c12hf/Mv/GC2srSqel5OOraAMh0XBRzLp+MI3FjNnqetBAo
         0MPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=p9KowqTP;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id d13-20020ab0378d000000b0035971916a9dsi744612uav.1.2022.03.27.07.45.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Mar 2022 07:45:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id 859E9CE0DBC
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:45:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id E7FDEC340EC
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:45:04 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id D4C1DC05FD4; Sun, 27 Mar 2022 14:45:04 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 215754] New: KASAN (sw-tags): tag pointers to vmapped stacks
Date: Sun, 27 Mar 2022 14:45:04 +0000
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
Message-ID: <bug-215754-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=p9KowqTP;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as
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

https://bugzilla.kernel.org/show_bug.cgi?id=215754

            Bug ID: 215754
           Summary: KASAN (sw-tags): tag pointers to vmapped stacks
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

Currently, pointers to vmapped stacks are not tagged with the SW_TAGS mode.
(The memory itself is tagged.). Compiler instrumentation cannot handle the SP
register being tagged when KASAN_STACK is enabled.

Fix the compiler and start tagging the pointers.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-215754-199747%40https.bugzilla.kernel.org/.
