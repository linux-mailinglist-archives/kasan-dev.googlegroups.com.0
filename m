Return-Path: <kasan-dev+bncBC24VNFHTMIBB4GIWHTAKGQEXM3Y27Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id D839A13192
	for <lists+kasan-dev@lfdr.de>; Fri,  3 May 2019 17:55:29 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id v9sf3216550pgg.8
        for <lists+kasan-dev@lfdr.de>; Fri, 03 May 2019 08:55:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1556898928; cv=pass;
        d=google.com; s=arc-20160816;
        b=n/dXZ4RbWaUt6FD/qk8tCI54SRITZfYR6DDuTyiGOX6v2s5LK2EcKKOEbOsUNd6Mfl
         mml5xQXMX1gB5XfxX2OCPbpSQSiHSGqVJvd35Iz0cm0zUx2Bad/IvBqXrHfviI+AdvDa
         Mkfc/SfxGNuYKQzkFjkhe4dO0/F4bHXcTDplTiMzC5vc/hthL27rn/A5OhTqmJAaiPZV
         t0dVwRk5Xb/VljFeQxi6yY+UbN/XR1Mz96Pt/kQgRWVFtYTx/VHcADP2xUcfEIR+rUV3
         wsR+un9CqTI/oWmuiZQsJiP3SmslZMq3We8Wq4FhFi6VU9UPgN4MBcSQvK9xP0PD9OWc
         cw6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=EHSuBuQUFhVIDFqCunhouhyQps2cUsN3BWyADU7AqS4=;
        b=YmzRQQJ7zfkLBIC2fGP2pNDLu3GjAN4cvCIrfBEv+gqlr8Y4KydM4Ee/QZJFEKtaEw
         uKoORbsDIS36I62G0DElEhC8ruhJTClpTsvzaL+ppX44J/ufncLh+optitthwvCJn0c4
         V6K1igDocktIvEV3G9yyUT703asJXbXQMkwdrElBj5oS1qPqHPtFKXcXrBEUBlqTCVER
         /2wayzwMwwrDAGqNQ2uUibJBnG8jTRK5nnfJfK1Ep5H8UN9AAq+tA16MZ6a7nKqZSUVr
         ojbt0X17yKFkdzPLWZvdu+Sf8wajfDc6QqMjMT9NQQhXa48/R2llCrBYDE+IKEFv/eJ5
         LTFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EHSuBuQUFhVIDFqCunhouhyQps2cUsN3BWyADU7AqS4=;
        b=Kbj7GoMv4nVud0qPl4dEMcsnXQZVCt5fyUOzq2Kr9bsbWrvrvRB8gMRCUDR48uyvOM
         u8vwm2A0aP87cRJ22/qMm2RtcmZAPyfWPdqNPBJXWAuxZFYacTAYtg4iUYEKI1I8xgIk
         XwdpgHW0UZiPdxWnMtv2hsNastHu82koHAbVUUHgfTsBB6gAmnFQweru8vTjNoQa4g2I
         KvT5wBN+kxgH+wWyAuqJ2Kjx0NuEb/9yn6n/KRvxyQ9Pn4SYJ8zA+B5qxMqopr4PEinX
         l7g7CtEsba2EZaT2Z87W/bAo4iIRNzJ9zVhaxt1QM7C9n/tz0mSHM79cJq7jQDP0tOup
         ygcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EHSuBuQUFhVIDFqCunhouhyQps2cUsN3BWyADU7AqS4=;
        b=SqDa5yRPOY0KJyRmYyz0Tmg0qxk6ELgRSXO439ZZsRNNXb0BTqoyFkAZXdf/wREHXQ
         mIrYdcivqHdteX2f5gTtsNSE/YOZZfTKTLZQXlLzZ+/vVJ98pyrMzQEhtrEOyJ/Q09I8
         ML9RXmra/kFUjbs6CdqlcnHVrzh33havlbBD5SvH/Q2lOfcYhPqWbInNvpcDa0F0PRE/
         FSQVy3oVnYZ1Q7pF/9/TnqvkUGsi2uTUA2rNWzDUwFSHhE/c41zeCKxJciFUcVI+EOXT
         7wqUHTgrcA1njWgfYBs03QGHlSMGNOLDkxhBPIHDbeHHEtsiW5IVlHeH5SdKD66r7S3n
         TTPw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVRrnCVNl27yde4cxHSCe8SMX6wJeveQW7r4QGvH/vwO7bp79yY
	rbCtMbDWn9xiUEa55Zupuu8=
X-Google-Smtp-Source: APXvYqx/TgjkOB9HwW3Su6r3Oil2TRYTQoQLBvWjKW6yPLXMUTjPhLMW9awjaM13gkNtsPLImOHH+g==
X-Received: by 2002:a65:5086:: with SMTP id r6mr11470504pgp.301.1556898928484;
        Fri, 03 May 2019 08:55:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:2010:: with SMTP id g16ls425402pfg.0.gmail; Fri, 03 May
 2019 08:55:28 -0700 (PDT)
X-Received: by 2002:aa7:9116:: with SMTP id 22mr11787183pfh.165.1556898928119;
        Fri, 03 May 2019 08:55:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1556898928; cv=none;
        d=google.com; s=arc-20160816;
        b=o88x6TAcpm2xGCVLbE04XNMtiXqYidpQtCOrAtvC3XKPyUUYYLrdc9FaopZxEteDWR
         OX8xx2TUPnL5gWngV9eWMSWC4hTvgRlkjAPEpMxGvP9FR/5Rtfqz4ObqnNVJX6l/FVfj
         gDRl7TRwmh3vffW+DLqQ5ue0VL8AqSkVjd9z+uVcGtcd4Kl6zY3vuan+zDhju5iFTSlw
         ZIIjfjQiKsKqUMOZ3x7J9vClIeSk2n9yo/MqwDXVmUuQ/gp7txJqztHYFMB+VCp/U2NI
         bblx0+MPZHMnc+lPh5+9UbWrpYAqcrwyTa/zBzQbz4+18dB/A2c2WXNQPXk5gf5WX96J
         gV+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=ajPxYBbhLgBnSOWQCLhHn/SCKbwykdBX12sqagn3hrE=;
        b=ASaLIc6BJnsXwxHLeefqjTDMOL7vx+3rpSaG2BWJfK5D4U1cUtUA/frCvcULfxVwMF
         GCsxhQEf3hHUhmqIelzareICJ6aJSB3P7YbfBHgrLwkbyUphho4SBvAvDKXdUJlWB/6C
         PVTRQkocOO56K77FUQrC6hDGEeJZY0Ndo27rXx4xo4zQKlz05iqOGQC23xOXHTbam2Qa
         7tGn9euG8T0Atu/jdBNpGhCg/Nr0GkiE++y3ECBs5WWtImBkt2e6dgQxmH4p3T6d474/
         18TTrATg9PoJgyAYMXrKVGuPWwSEazJ4BWogdrGSt3wfAvtdGj13joNVgGyyBfRglJd5
         Z7UA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id q203si121201pgq.4.2019.05.03.08.55.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 03 May 2019 08:55:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id D3D2E28613
	for <kasan-dev@googlegroups.com>; Fri,  3 May 2019 15:55:27 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id C6FB82862D; Fri,  3 May 2019 15:55:27 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=ham version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203493] New: KASAN: add global variables support for clang
Date: Fri, 03 May 2019 15:55:26 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-203493-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Virus-Scanned: ClamAV using ClamSMTP
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=203493

            Bug ID: 203493
           Summary: KASAN: add global variables support for clang
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
          Reporter: andreyknvl@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Global variables are only supported in GCC right now.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203493-199747%40https.bugzilla.kernel.org/.
For more options, visit https://groups.google.com/d/optout.
