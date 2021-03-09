Return-Path: <kasan-dev+bncBC24VNFHTMIBB6OMT2BAMGQE3G3VRUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6CDFA332C7B
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 17:46:50 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id p136sf17869325ybc.21
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 08:46:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615308409; cv=pass;
        d=google.com; s=arc-20160816;
        b=omQ8Yu5oJH3BJycYR4FkTOA1XK6jXGAfJtx34elyjkYNpZca45wgY4FE9wGKwxBJz+
         bxEzqF5quGSddAgQr/VPopr9vDlAlepIFKkLLTCIadeocl3nGXLuLiPtywW99zXDGD4g
         9NfIFFdjjGyf0F69qPOoenfuyZvguQ5gWvfX7EDI0WKsnHrgSrhgL7rd+ER6NIuQJQ7O
         0LL8PEAIZpw0mv8opmsm+ouCDTrsztuNC46S+CwroAw/AoqzT+ShiA50MI554cipldHb
         l12G7ePuLNMCB3BqZXKeZ7LYGizkQmAbj/9VY3MZQAm6y6Dk2CjbqU3SL1Rey91OsXaq
         QTAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=iZGCiQfE3KACLtX6zsY7tSUj8QZStCF26jUGASlZahE=;
        b=uF15ZYf0mAkF4ang7Kx9VkiIvA2CgxBgep6nDFSQJWwYZSaqH3zshIaykrAXrWjNAL
         gQuocpgPQQipzaz5mh2QZg3PS9pCK0lrljT4MVQshdDJ9j07AvpJZtkhKqPGPZgvu2WR
         a/rJ7lZvO/cc2gOSZ/zOd1xr4aIA2273T9YYMTiouk52Bgv25xLT2HD0Jr8lOQsonguw
         dN/H11qdCqAjC/Kj/UkAQ2aCuA7Pzfo2viKZ4herLR5qj/qdYkGq6Qy+/Cxx0tfWJTxQ
         XUTx2gzXRJrf4i6Qx2G6LiVy4k4nPFbP3IUoD1WW5pUz6gZATdAs0mVZgkWEczlaiZJs
         qAag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XQTFTI6m;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iZGCiQfE3KACLtX6zsY7tSUj8QZStCF26jUGASlZahE=;
        b=TkXwc6bWHkGDV//CpQpAUUzv8z1Wxze0WOPmOM4GtXPA96tn6lFsGUyT8CJd5JWafB
         3iEKnwbUJHUTMneP/0SaPyVM25O424t8gtKmVlq11NFxYMKmZxlzz0bDqZqeYNABO7rb
         LMCC50PwDFcKc1IUvnCgH/UEojquSdEayySyGGragQGsGIIgL4IlkAvSatzwVN74N5+l
         WjFSXLtVAxNtZ11+G8Rojy+PeQHoC1rW5ebnm0CyYdRoWzcqwVFF/P1UX67zfPfBCc2B
         xt/vKmf8sTdYCo6tfefbnqdE4+ClTI1ZG32TdnKlfZqDdFcpgvQeZIj+qjWoc2j+q6A3
         nHww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iZGCiQfE3KACLtX6zsY7tSUj8QZStCF26jUGASlZahE=;
        b=E6Nfq1K1uU2X+X4p5yIBi4K7WT3JmP/6u2zUEB48ZE+9fWAXWIDZUG3yWpIywdbsuB
         IdV/fjV62eZt64ZdEIvjP797j2GGgH1oS333+oMyaGTzRJaTl2EUvaR/6JgPcpjJhWQK
         7svdmAldYOEw2VrbPoL7/nllXtDTKo/Gq7l6VhEge26EpY2Au5LcJaV0+roEcqhPK2hJ
         yNlBte/2hDrlDwyjQzkiZvpOaCQJ0AbdB6OaBw/wm4jznja8FFU/izN/uxGaSYZJXWMz
         8RzOTUU/9VYpeI3dzxaXf5gUjdtrirFh/PwVz/aZU/ls0mqFngPSOpAC2mvLaZnRHhRj
         nXWQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530fnNP5lTt7uhJt9o5zVRzstc6wBgn/Bz9oORQVAEEg07xnu8de
	WpYILWvmPSy5P+jSbxKNjzE=
X-Google-Smtp-Source: ABdhPJyYNKdYKmKMTJbL8JL8HfCNTveHs0oVgbP+kIYaBME8NTrttGNYZvvvcNXKVez/lkEgiqJRvQ==
X-Received: by 2002:a25:ab0a:: with SMTP id u10mr39589418ybi.312.1615308409352;
        Tue, 09 Mar 2021 08:46:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:dc49:: with SMTP id y70ls10647138ybe.4.gmail; Tue, 09
 Mar 2021 08:46:48 -0800 (PST)
X-Received: by 2002:a25:67d6:: with SMTP id b205mr38702216ybc.394.1615308408831;
        Tue, 09 Mar 2021 08:46:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615308408; cv=none;
        d=google.com; s=arc-20160816;
        b=xpBHV4GZSiWUZ4O/uA61ThBZEGtDcNiKqRdjeaANRTh1BjR/fF+kTxq88E8Cd7DOzw
         lffVbHA6ePqtzI5ubqxFxUgYOT35sylCSepZ4GMeQkK653dmDTu+TBMnRLsKfJpoLT4S
         iUiOWj7vdaTJmUYe3DO+ujxxXuE+4rP9WPk+m0xMkoNHMdfejdmyi8lIwrF8Mq1EoaJT
         tzZwSP8d1eRqXpioIyhyl6iR0WLONfWB8MwFZJVYjuS1yGmQQrL/5WJewsXqKLjLSaky
         yOSJTBl+REZFB2r8nX/501+nkipaHR3YSXYqRtbKqiuB8wYmrdIuj5zG/BQyjwxp+yyv
         unLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=/HqzNwPptsaypN9LfSLs/O+c3roeFZwTkBsPPiezM70=;
        b=osFOlc7Us5ko6XBO1eprJTlf9FYf5ioP4yEczeDTKT+Y3UzkBYj73Nab2n3eJRhNKC
         /wqvI7YSnZfrmDxwe9pNodzwxqCrD3Ra+1t5WhNxGQA3daicV2Vbixgv3IaUddBwpS/f
         Kt4xM7TpNRZRIj3mVsWJUFG95Yoh7IgAnUjciBiw9JFSWGkVhUmi8dwFYVuF2spi3Lcz
         NQyNrHS/Da6MUCQgDDtoOm/J7w/UB3Qwao+55sVLsqgNesNv0YxOQS7IOMllrApUIVKt
         Pix7SzgyxQv2wfRqt/zRx65mvGH0qhXZS1HRg3kY0PdY5drFWu98dN4bTMsCXhgoY3IK
         eKDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XQTFTI6m;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s44si906751ybi.3.2021.03.09.08.46.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 08:46:48 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id CEC9B6523A
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 16:46:47 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id C853965368; Tue,  9 Mar 2021 16:46:47 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212207] New: KASAN: precise redzone checks in tests
Date: Tue, 09 Mar 2021 16:46:47 +0000
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
Message-ID: <bug-212207-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=XQTFTI6m;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212207

            Bug ID: 212207
           Summary: KASAN: precise redzone checks in tests
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

It makes sense to add precise checks for redzones in kmalloc() KASAN tests.
I.e. make sure that the first and last byte of allocated memory are accessible,
and that the first and the last bytes of the attached redzone is inaccessible.

Currently, this is only implemented for krealloc() tests.

The implementation needs to account that tag-based KASAN modes round up
allocation size to KASAN_GRANULE_SIZE.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212207-199747%40https.bugzilla.kernel.org/.
