Return-Path: <kasan-dev+bncBAABB3XZQGJAMGQEABYFONI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id CA9334E8852
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 17:04:15 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id z15-20020a25bb0f000000b00613388c7d99sf9477264ybg.8
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 08:04:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648393454; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vfo5Z2MzUcF7r1x92iaYtWXTfEpwoS9B6cqrrX/qr3ATO0DGZUvieyYIClwWMGMlii
         /x0nC6I7rhaI2BEKjaxROjcGERTiRbsax8vptF8MCLpm3W0oCzx37vbQkTuKZK+bHivj
         jIyBfxW8Whw7SmmJMAtDqGzRD2RzPWY9+daOwBITdUCuDZoAv44YuqwQGoWRez5vE+cq
         8045T6TkMNRAdHo6xEA710xeXHAfionpx7eOfqVkDNUI0OsqzAa9psqFJEH5NIeOkqEA
         eLU1lO72N1bgrYWaoefiv6YNWoFK2tNu/XNFfCezPSm6K13Oto28gswRD9S0fiHwiTaT
         t+qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=HsN+uUMBjr5ifzn0Khu+mH0IrxItYIPXy+GM5Y7fBNA=;
        b=aUwvGcFbwQXrQp+ut3UnsD7uN+w97fc6PZbsjEZk1XOW+cHWw5UDZybaPJjh7fftcH
         F/G1a2iLPTh5K13cuvxDKCrClveyCkIgl5VxV+Li7yPVvoZoJ+D+umWaV8r95aBFgPuw
         dBE4DswTcHzA7i/BH8wSRkEKL7fVyVwezCk0vkORWoMWWaxL0riYk5vw9jyu7q3KTqbm
         MfgoVHb1wly0wb8sb5qoAzPjOJ+VSxv5R4NtctVuiUuDONJnrfYsp82gh0CYJx+sL/Gj
         yMZDPuB5O51+T1gKWWms6DeTGqqv+by8d5CO7EPCcsLHNzNJdrvvQmDDl3AzLfPSGw3J
         X7Fw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Vvtpgi8+;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HsN+uUMBjr5ifzn0Khu+mH0IrxItYIPXy+GM5Y7fBNA=;
        b=HlKMVc6gIR2um6jqgSAEXJhBRc9qXT/odqczTcU4gBfB017hUYEQsp/fJWIoSAy8oy
         oMdDOVDb2wLdNzGr29FY5z5JxEBcyP8w7WpJbw6ITnF7BvFfO0eVfcaQfpPHOAuOqdZR
         hT/GVgoQIBrx1MvkdLFNj7PrB9x3C/vMEAnAOJiMlF2LQdj0B39PnqMNlEDT+Px2BbQK
         Y8cYndbaQaAsAQY9aXpn2RqR7r4G71/mqi/gf9kEw37RguzB4HWBaIe9OBKBcLf9ga7C
         4u6cKRYTBAB/XK4zLbalfy24C2s2sgfuRbKg1hlRzMBe0Okt97hwPvpjRQdq5C6tlNd5
         V+dQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HsN+uUMBjr5ifzn0Khu+mH0IrxItYIPXy+GM5Y7fBNA=;
        b=an67FbVgBRIPndarGD5P0yAgVddye9B+rqOXb21seBZIzrN8Gv7t+Ue2Rey/43bbQ/
         wAuzKn72taQ4zVZf1G3v5bnfEOmJdyixyE53fwVHsHMnT22tix/urgQwJVVsQwcDp4eU
         azDxEA2ApjrvPdr2e9gICuS8gPoyr0HIwOiB862m3Q/iF/nR1LYpsc8gNrUWlmaU8Fye
         JFUhV/9cN0zTeEAIUWwaX4Fk8EAKrPU8jaqLOK9lgV2qeXvDDKtaJmqlkG2PItg43531
         2D8WlyH0ELHqKM2OXRfQXeeZtRsQAr31IBQtuaGGaXsP0iiPCqUzWFQhUiz6buTBAjtn
         n8mQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530/EOfaExZ4plc2yoQc34Po/OSGCCAxBJ2D7GoB0feWvKtPYnrX
	FSy23La4CN832OZ5eaWwBZM=
X-Google-Smtp-Source: ABdhPJxIFGu9RvG6A/H/chMaNboh49qojruNzteI3EcLhuZ/el9TnuacFt6mtnZl9fIYwFEE+PJWoA==
X-Received: by 2002:a05:6902:706:b0:638:c954:756c with SMTP id k6-20020a056902070600b00638c954756cmr16417299ybt.245.1648393454702;
        Sun, 27 Mar 2022 08:04:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:82e:b0:2e9:d5df:8003 with SMTP id
 by14-20020a05690c082e00b002e9d5df8003ls2334932ywb.10.gmail; Sun, 27 Mar 2022
 08:04:14 -0700 (PDT)
X-Received: by 2002:a0d:cb4f:0:b0:2e5:c4dd:c0cb with SMTP id n76-20020a0dcb4f000000b002e5c4ddc0cbmr21402464ywd.194.1648393454303;
        Sun, 27 Mar 2022 08:04:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648393454; cv=none;
        d=google.com; s=arc-20160816;
        b=rHgI2Y3C6umLeSbtpGa5afskysihQT1lbpCekbsJEeHp7F8jwwjdTQJR1gbDjYXkY3
         C+tPXpdSJShfNaZMuiUOqNmaIJbPY+ENJZM1azgYF8ZzdpDMRkCFHgDkJJjjtq66564U
         uWULxQE3Sskw5pJid2UZumSPErQeY2rj7nEC3Hp6s3eClUabsae8EgRgM/yC+rhGKlXX
         lHEd5+14p+xS07SHaSqRKXL4HitT7Dcm4E6AKConEBCoT0tkfzeWq8y8eJ14l1npSuCh
         z6GwegdLkZJINDOukchdxKkopfqoyWmceESGz1QJBEB4Njw4o8T3+tmJ+nmTBE3S6Iua
         U4pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=or+bjQx66OoHGS1f4zZvJCHu7sWcJq6XSbfZyTkepRc=;
        b=J+TcXh44uNlvTwaZELIwsgFOlFbuo6qokE2nbXUPpUC9ZBr8K0cYT7VX2tEfPrS2tE
         G512BQR/54ZR3yubk2qSVROZY6efvPrTP22fJhapc2IaEnedc92MKPlPk56XOX9bljsy
         Q5s2KIMdpFlaixcMymFbL1cQilbNk4swW6cO7wF9goW+nT88vISj2wx2FeLRyNvQJN/R
         NMK9PEWF0gSsfIZ9OUDzOs2kIlLp2uT6zgTxn3B/OJ5wLEehCKgVqPYdVYnOk9PuocSg
         Ew6KUCAMFeEz91iYGfV7gSLmBG0i3yWxjfLzVE5vayPOy4a7ku+hW70mT0FJ6K7hhAuE
         M/SQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Vvtpgi8+;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id r13-20020a255d0d000000b006332ac9b1ecsi792952ybb.1.2022.03.27.08.04.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Mar 2022 08:04:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id CFAC461032
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 15:04:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 41680C340EE
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 15:04:13 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 248F9C05F98; Sun, 27 Mar 2022 15:04:13 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 215758] New: KASAN (hw-tags): tag vmalloced per-cpu areas
Date: Sun, 27 Mar 2022 15:04:12 +0000
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
Message-ID: <bug-215758-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Vvtpgi8+;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=215758

            Bug ID: 215758
           Summary: KASAN (hw-tags): tag vmalloced per-cpu areas
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

Currently, HW_TAGS KASAN does not tag the per-CPU areas allocated by
pcpu_get_vm_areas(). The problem with these is that they are not mapped in
mm/vmalloc.c but in percpu-vm.c, and the HW_TAGS mode cannot tag memory before
it is mapped.

Add custom annotations to percpu-vm.c to tag these per-CPU areas.

The implementation should be in sync with the SW_TAGS mode.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-215758-199747%40https.bugzilla.kernel.org/.
