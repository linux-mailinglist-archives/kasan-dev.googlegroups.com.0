Return-Path: <kasan-dev+bncBC24VNFHTMIBBT7VTWBAMGQEV6BEBKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0219733275B
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 14:40:33 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id q23sf6960905oot.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 05:40:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615297232; cv=pass;
        d=google.com; s=arc-20160816;
        b=CsclBuFQJfc/r0F4PQtPGBOjmTWaJopAkutaq3zba3PgUKY/lW9QReizoltkrWekHy
         mTXlavkrSMm6eWL/fC3guABxRpmRHoDQUyF+Bz6nFIZ6lBH9zeTEKFNmSG5j87b494uZ
         Sjdb9N2hFSEeWY1XZFNgiFkDtSjPy1yev1Ye1Z88gnRKHIQOVrcrA64m5wMceFotDq5v
         14yafaA+rx/op1G6yIgMhIQbDQTHpDzDetFfEfbQ8nWNycuWmyNmXHbBcemm7Mdv/XO8
         lJHnWVV2d0LM+RDo92P3vRO/JJTHcBjsckPVdLOLDVQZbbYsNvryLHM3dU3lsuiu9tAD
         4nXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=tjit0E0h2oJwmyq94wbBznqH5A5kT/Ne5LDNiNONXUo=;
        b=n+5j85AkJK8X02eFEFAVeuuQqYnLmQ5AkFY+sDWgHuK5mc2JRw9/xv+XcY6VFGzUU5
         tZSOj65EuuCUifNAF+1EOVy09dSTF9th6aUzMbU6oKwTFOLPFkXuq4+MWyMEjf1AgK+7
         G1QYYIeGFdWA7oWJvLvmNE1sA4vOJRxAPu49PcNOjLnuQ+HjnBkiGlXCIAibJYPMzAs3
         Rzkb4efxpLsq5gkZPylXyd4gvuMApVGMOwpD7NkYV4Hu16F4xtSGmFnmQzwMPnVsP58q
         Gw132kwOTCLWjwO9boDrVk+iW6+TvmyZYumr5IyqMKE40eQNSv0ayUX11X3H4xzIyIrv
         hNuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=agq3dIPP;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tjit0E0h2oJwmyq94wbBznqH5A5kT/Ne5LDNiNONXUo=;
        b=e5wuwVcQcBKCw9r9tRf5ILvkK4LchvK/7Fx6pRoCNvU2MiHKTFBwBndfj4sfr6KBnV
         w96Gvv1izuRgybuSX6YHzxmRIPLVjhZ/N5J2GYUJD7Catet/X7q/TCezydzF/D4vlbZB
         RrjIX8rYoaM2iinkR12WW83t1FoniXRENwzRlSl3jYeMNyy14vMZ4t/N9XrNrWMPluwN
         QNcdwXHWRutczvXJ7NcC/855Ad/KUGLeMZcNdE3V5CzHnGT73Xj45ot/NH2jghNC+hm6
         4fXj9WWsEVVCExaNZ2JmzDn4hK2PoWZdqIR/smud8Bc43vUqE6lm3mge/j2PTKFL07gG
         JUHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tjit0E0h2oJwmyq94wbBznqH5A5kT/Ne5LDNiNONXUo=;
        b=JMtz7gV0EtYa3nGNYARo/krVzP5TlWTL5SLFP8j0jXUfoGI7FKXhIr6yMevJU4yvAu
         sZyD2YLAM95KVTdZAyvRwwG1ecZjawTYFoeV291mo/23TMCzO0ksSvnC6Pp/FLq1WzlV
         5bnyTtfX8bhsCEqQhRN1UjKOOAZsZnN8TM3NWMmt8wRBS8CAJprFnBi7kkRlmc1upDx2
         Jqe1hmBQ47g6k9qD9atekoHr/td5Ai6FDZsEwUotCoEgyKGej6FNOgLPn9Z6QU1si8T+
         SFEUd0ymDCwnmpbBtapDN9CRMV8AQdfqg2sVqs6PdIFL8XhpXk4jVAkR2B3ZmcF2FAN6
         ZHZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530+AzjYJC7p0Biq9gie2KJ2n6F/ycKfmuEEAN1EVG7+nk/muROS
	bMjLQedX9nFy2IBRIfvM5jM=
X-Google-Smtp-Source: ABdhPJyzGx6YWsJe9XVHxTKDKkLnXmU+AQEoOOKFMcUpCX+DMnLMxV7C8lee3VjtHzhH5g+uWhqlTw==
X-Received: by 2002:a9d:1b49:: with SMTP id l67mr14635502otl.83.1615297231996;
        Tue, 09 Mar 2021 05:40:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:f11:: with SMTP id m17ls5313036oiw.0.gmail; Tue, 09
 Mar 2021 05:40:31 -0800 (PST)
X-Received: by 2002:aca:358a:: with SMTP id c132mr3039249oia.142.1615297231676;
        Tue, 09 Mar 2021 05:40:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615297231; cv=none;
        d=google.com; s=arc-20160816;
        b=QpouXSRFKuu/1j8NSMj3IzKvdV6qX0zI409u86B3i/6s813uaJoZ5LsZft9WTJzMUZ
         Z4E0QYvVbrDNfbKEYuZp+4FeZiXMfSfWF4fJ8z94vnKge9jmsq6hH2Zu7NWLU1mcI1KF
         JBRyUxMS5YAQJdraRQuG7gVv9IhMjSFPcI5UjjPT4fOBPafugfyIt+krYkmc2nEGrTbm
         e0EM2vSWs2SRv2DoJgBg2L84mLCe13PgpHXKD/Ef7Vb4QDmJVbn+ZlQhkMpUQp6YbpIZ
         gln+c8sUdA/yUPY6UH2zGH2BJC0TUMW369mstqdju4CdhJt6JEu9mvTmwlXhnThAK1Dv
         FXJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=8S1ITgDV60ONdE3dkZL4Z5FsBN3gatrn0sCOdaTh1/w=;
        b=NZQSGOug8i1q7CokztTSqHMtF+5MhOFcITb6cHPs+TpV0Lni6qvJYbgKkBAX0cx9a5
         2ngz9IcRE+ueyfZbys43505n+urWuaVmeI5j2G+Dyh2GoU44rGe3icyGD0x/hbxX1Jva
         dFS3yVjtD8jdjGhvxmNwcROeRVIRg77iqG7iNAcJN3HalRll6Wy9ZY6k9+NJu4p8zjYu
         WSnZB/80Wt42BD8x3uKmIkOdraE3S5h89IXQKsJkHtjVOCgQh0xGyQh/QQNfMFTJLo4u
         ZAZNjsp82PaDJI6aNCxPnJKRjyBwYFEhcJfRWnUsuFBp7aWmbHJC365WiSOJAsYhr1oO
         RBLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=agq3dIPP;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f20si513752oiw.1.2021.03.09.05.40.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 05:40:31 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 9C53C600CD
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 13:40:30 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 8D07165368; Tue,  9 Mar 2021 13:40:30 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212167] New: KASAN: don't proceed with invalid page_alloc frees
Date: Tue, 09 Mar 2021 13:40:30 +0000
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
Message-ID: <bug-212167-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=agq3dIPP;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212167

            Bug ID: 212167
           Summary: KASAN: don't proceed with invalid page_alloc frees
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

For slab allocations, if a double-free/invalid-free is detected, KASAN doesn't
proceed with freeing the object. It might be a good idea to do the same for
page_alloc.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212167-199747%40https.bugzilla.kernel.org/.
