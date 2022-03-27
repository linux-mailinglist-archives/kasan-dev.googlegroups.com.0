Return-Path: <kasan-dev+bncBAABBUXIQGJAMGQET6SNBCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id F37674E8815
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 16:27:31 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id k20-20020a5e9314000000b00649d55ffa67sf8769505iom.20
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 07:27:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648391250; cv=pass;
        d=google.com; s=arc-20160816;
        b=IGtYjz2xAXzpheecCF5USRWbKOSItQMsH7+E490bPpxZr7abFM3hQcvytAshaWuwkE
         7Gkibwle+/9qxOZpAFoL/uPdQIdkxOzixBOVyYiPZI+8Bmp8YUm9lYZGEEwIjjXa4zPB
         cJ3+mzZtCH7v6pCHLNaw+v3wBLdzD2PVChUBIwUIMzZonhqPzvCfvfUmzukFNlHiEwuN
         sW7VjfmY2jKENgRJj0T8oKaJ3cKLHYMzVczJ5O0aG2+cqDAl9MKGWFvzvuJmDTwQ6mdE
         sHHtonCyVJJEaplMvRtcOzkmDTqK32UfIBPdcLEQlCcFLEl97w4kOCi/xThd9bcNsysQ
         3VgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=8mNrqazQhirxTnh/NhjdMz3CHAUB9qGrsR/jM50zVb0=;
        b=cBGKCLnX/FCOSYIenEypMcoNRe/cno2qqKC2ovFzUsPpblSa7auw5JMNUjcLEL6fhr
         TZDH9P24ZjVe+BunLd4KglGtTz1Uv3FT0pLmQGsW02BhjRIaKO11l6uZ3+5QepDgoIV+
         /LWT3srUSaCp/4DMb/a2VOiqCc5iIDit92IVJ+t4dhqRZVRCBMgvFlJ7xCU5tkOcQdUj
         sdYKxaZEUweuJdBOYyxspzPJcNX0GCYtQCj9cav5maRBouFNcUoCiMsjAv/F+Bn5AkQ7
         cX5mCP/3zfDAw+g+MV9waeBb4KuL81kMqYOo6y8Uu8g8ziT/eVV2VR6R1L0gXYB4UtCQ
         oL4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Enr4uWo1;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8mNrqazQhirxTnh/NhjdMz3CHAUB9qGrsR/jM50zVb0=;
        b=Gi+jmlPZNqhL36CrTS50M8NtJFz7C/3m0fhq2pCUoMz2xROgSyD6RzbCSsFtQpTfkH
         ctvzcafI0aEkmCC12HPT8fB3JkTPK5N6r6EalHmT8O8AgTt62MSiYi06G1Gnh/5Sru55
         +Z17ECwQsinaAq1YvASjTtzBmrIvXW6Uz8mURCfoeeLrwp2zeCEsPZwt1XVtffNGNS49
         k2WIBbRHNDqHDjMkyj3NPTQY0A22ENwluVzjd9CttBFSCD30vZ1t0sAa83n1IMgsVMUr
         bAw63JDqbD7IJPBaSV7HcxFDvfPMAMeqAMcbil5m83iChJ1bE3ItG8ZB5+l9QcsFmtTP
         uP1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8mNrqazQhirxTnh/NhjdMz3CHAUB9qGrsR/jM50zVb0=;
        b=ROJGxEOiIYQWSzDQprk870Rpn+eE01BQ4DoCa+AARvnwFlv357EPcw2z/+KJfNwQkc
         HuTyp2HVDgTmmHMKoa4l1tywvBpaO9ApDYdH+zImMNIwlrPW4AC2tSGo+DKJj91swM90
         ePkaqUX1mL/bLJQzWbLqngoYuEv8ZpYuq7b3GM2KwcztZYuW2xOUCs2xZSuIC3BxkS3T
         5s/kVi0prvtk9M3P5ih9mHD81e0Yfs7nTZ4N7cOIDwXUsN/F65aNHBrPch5dSz1Rs3md
         t5oYco/Gv/QQ6NC+/Pnngkqz4CXazue6+fe4BmAKaSZyC2eO+ftt7wcKBfRA7HIPDQVq
         DfSg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532zqpDfVbnZhnRs2qIKCJGKM4cR7Iq+mgEQ/fJGpUPArUhuYRZI
	ccVlxnwJhKHvd78VMm5tCCM=
X-Google-Smtp-Source: ABdhPJxgxj5kXsESr1hLkyKf2qofMCsAwoLlR16Fix2j0GUgOgKJXT73EzUfKi75Ht444o9rgRLMfA==
X-Received: by 2002:a92:874b:0:b0:2c7:b987:4ed2 with SMTP id d11-20020a92874b000000b002c7b9874ed2mr3487912ilm.318.1648391250666;
        Sun, 27 Mar 2022 07:27:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c24b:0:b0:2c9:a63b:a899 with SMTP id k11-20020a92c24b000000b002c9a63ba899ls446522ilo.9.gmail;
 Sun, 27 Mar 2022 07:27:30 -0700 (PDT)
X-Received: by 2002:a05:6e02:164e:b0:2c9:9849:dd5b with SMTP id v14-20020a056e02164e00b002c99849dd5bmr2887580ilu.81.1648391250312;
        Sun, 27 Mar 2022 07:27:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648391250; cv=none;
        d=google.com; s=arc-20160816;
        b=m2l7maxf1w2wws9QKWYq7T8pdzPKR0BuljdD4fLA+W/3N2QBq4BJOyrLQrb8Wjk/0X
         N2bdELaH5UYjgxb306pcGFIWAELPXQcaZLHqdozFVN2Sta0ehFPYodwRnT0nJ6fmUh5N
         qq26SQlUMTiOQAvUIwB2/XD4eibAZ7gzYsiQ48hDNuGh8QzCNWQHiXvPC/c/e9D69H6j
         WoO5LKc3irKmrIjEMco8KwRtMH/Y3D3+4vYl/X5jexwZId1EMvLZTvuiKEFCY2v1hTzd
         nv3oL4aIRldMzU/erQbami6Z8ji9wXSs8coGsttHiJhCFiJWXELjxvVB45kTdO73axbD
         QveA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=twV8JFoFJx5HG+NZuuWeqaoUFBSVS3hJC76GD+6jSqE=;
        b=n5TMEzcQGi2ptdjzoqsW4T8F1itSNTwXFmwCFrnPb0CjtORaVkmVx97CcekVoHKUY/
         H3LCHsukRQrGgpWcAmdTTVAmMUEEuRlzlc2ToN/lIKt83lU4QupKrtZ2wkSH2MgtRM5u
         +2IJnK6l/fFWXSGsoJ+TIJEqCv52YICqAQIC84zGaQOSuwReOfV8fyvUQKhhN0xaJYgl
         xTOU4j8zpjPzbWkLWm/GEA5p1hoVMkGMWbkA1NtFfnHS6vwh2W1FPMx8nIU38jDAI72/
         3lF4Lw1WahdODSs3RNZmpfno+V992fXoDkn2Se9zBHqOwkjMJf68f63SxST/+8i8FaWq
         uCPQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Enr4uWo1;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id l1-20020a056638144100b003215ae2bd87si893694jad.6.2022.03.27.07.27.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Mar 2022 07:27:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id D245061029
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:27:29 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 4492DC34100
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:27:29 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 1FF6AC05FD4; Sun, 27 Mar 2022 14:27:29 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 215752] New: KASAN: describe dynamic allocas in reports
Date: Sun, 27 Mar 2022 14:27:28 +0000
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
Message-ID: <bug-215752-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Enr4uWo1;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=215752

            Bug ID: 215752
           Summary: KASAN: describe dynamic allocas in reports
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

KASAN does not describe dynamic allocas in reports like it does with fixed-size
stack variables.

Currently, this only applies to the Generic mode, as it's the only mode that
handles dynamic allocas.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-215752-199747%40https.bugzilla.kernel.org/.
