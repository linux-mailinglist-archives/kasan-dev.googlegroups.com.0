Return-Path: <kasan-dev+bncBC24VNFHTMIBBDXZ6H7QKGQELMMP3VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id EB6812F1AE5
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 17:27:59 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id c1sf12430585pjo.6
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 08:27:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610382478; cv=pass;
        d=google.com; s=arc-20160816;
        b=OevqT9fcrp037OQrBYpYNAnMLpbrJ/2/RxU87jxAm4BCKHWcc1ob/HNAAz/2pkjavE
         aiPKzAAH3zuz78lA8bgApJr/Ae1m8ZFrjrXp3rwp6kQnR4Hz36I4LMBA1yJiUkC3Tprd
         Dab/kFaKkYhdVZ5NJ7dff0Izud4oS3pidzDt5H+3FBPmOrc3GvohaxBmd9Y5PPO4Y/oH
         4hhMY3QfOW1b3tQE2xw1q8YCd7siUZy3zHybC9b59h2y2KqxQrgIkL2w7j4p/me1QGS8
         JMp+O5x3imWiMQE+QfKnymDElc19xgutB+cOSxH2xGaowK7BIfkw01hbWvqf21KMgeZX
         LrgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=yqoIUoxd7r5Kt2T3q0n96pvRRRUp1XYhFnIFpr6VDik=;
        b=gD2gWoPBIe7mGNDbwaSojwHOW5BMjc7glImGDLc+lbCqnJghMui1gsAS7AfxwXQq/w
         KC6rU7CoY34mVzTZ+ZMuAhufoIY7lirToQUvZPZyBTwcXuR1MlmE/bxfg+8M2Cs28xfD
         4GUvZdmHtf6Gw+ron5epGJqxKZVonl6THrzTzb2DBdbXRY5IcOX9SmRwW8Xko7Ks9eh+
         nmSfn50V6PaCwnS3LAEGgWE5szZvrmB9txxCq/8vbpY5UAq0u/b1qAZ8z64BF8IN3KWe
         FPKEZ5F8QBV/T2FesjnuzRIsVS2Kzfbtc5dXoRsIK5CPpVNJbPHDMDdNkIIDNHul01dk
         IV+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yqoIUoxd7r5Kt2T3q0n96pvRRRUp1XYhFnIFpr6VDik=;
        b=GTC7ZVxDSNJUSSIH3WyhbDqDxwKeF1AUobHrdvV2G1xV5YGBySqCo9+ozO5kYANl4p
         wfw9G4qkVp3DInb65ZwGmI1RDWWF0s54UVmjScJjuHYrp8jNnxzInlUPJXjrzI/rg0UX
         RYu+9DOWSK8pOEQztLNgZCB5J+Un/b5YmU4YOcwMSI4BCoiJJnLgWJZS7wW++4VelSzY
         STVZPzRVYENLo0cwQKmLVvO0P3NT/Z+egM2K6/7l3hq7MtbJN51dytdiRtNoNgXOQSVm
         Hk9hXHqZfzc7cNn/Nb7/zXfB98jT1b2hxQjCH9WbtuseNJZOjb0J9AWl3b2JgllTx7VI
         UzKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yqoIUoxd7r5Kt2T3q0n96pvRRRUp1XYhFnIFpr6VDik=;
        b=qAPpKYrhFm8KiHfwur2Ny3cvUuuGPJV2Gotq3dxexHfvSLEKPzReJg8vsEhE0kpSS5
         XiAiXWidV60c0zfLeZlY31di0I6aDejaDj8LPyBJEBXCSqZ1SDA14DOm/P1mCKE//CQV
         yDi3he2+iojjIo+rF7TtS8ZMl0QgIbXR8LsTCXhTJkKfmBVYaWPZ6zoKZJzjfaydb4r/
         oL30ESkwK7n6XDVkukoBK+zSKGQW3PoBb3t6MVWjeXqOrVgeSxzcCPNhxjoDOha6Hf8U
         alFDqFj3OVIMHN9/+bukeVwjQLPvH1WoheIW+Lnw1Z/Rwtt9Ro2mwwqwdqqR/fBpu9c8
         7lEw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532R6p0pA+lNAhgeg6tsnZEd/67nvdrYj8VrfF5v7ZFZ3EEvbynv
	kOSJpG+cQaOaxNLgLk9vuN0=
X-Google-Smtp-Source: ABdhPJyXzx/V5RjOBeSWia7XgRSkTRwL6/Wbaqd8ApxEhss/zyAzEwrC+A1SvNQ9C9pYfyTFz48haQ==
X-Received: by 2002:aa7:8749:0:b029:1a5:63e6:56fe with SMTP id g9-20020aa787490000b02901a563e656femr193554pfo.32.1610382478232;
        Mon, 11 Jan 2021 08:27:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bb95:: with SMTP id v21ls90775pjr.0.canary-gmail;
 Mon, 11 Jan 2021 08:27:57 -0800 (PST)
X-Received: by 2002:a17:90b:4014:: with SMTP id ie20mr28021pjb.95.1610382477711;
        Mon, 11 Jan 2021 08:27:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610382477; cv=none;
        d=google.com; s=arc-20160816;
        b=sBy9Rb+TEPh/sV24C7MWhtCK1LWJ/54t083agUQq9d9OtgrbtmJ46PQhtJZXcW4j4+
         yeR385j7OQ4ebPAZrT/ctPBYO1o1sAwIWmz16ZRSgCbWYOLNc/xmD0O9Xms+YWqklxcy
         uKM+UGUZqcQft6smiVz57RYOKiUGzLP/2Grdb2V3JC2Hsg4VTwtpti3+5HesujqvODNN
         5H8GD+b9ZYZTqdtmvd5cvjNuat+MCkfiqUZK4nLYLQd88osu9zvXDWEVoxPVI2ByWtFO
         /X3iTMaQ+8PPpcdELFnPaflAcnxWqVEW+yGgUp3j0xSM1xdsHNZjrWeWDiStDmN6J0iL
         NHTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=Uo8B4W1xj9PXT6UlS293bIshE2IehpHfMGygznTix38=;
        b=HfnmdH+UeG2jvd/AHD9Bbs8uRqQoYCjLhnS70a+wlAj4QjWv3MvsIAu0ry0FSvOwra
         IuAzXJw+8mWgQqvJ4yQW6w4+ifuDj6ScXnW6th0zeOH+nOWCbH8+bE0NJgJm56KrpwCi
         e/DpkPcS+kIyyJsb4IkositcIqqdPRnfX495prfEWJk5eZ6IrtqIU8XdK5FDaDBiptMY
         9YkwJinJynhTWg3HBoWwkxYHxOmw/Ikkk5lGDGflPt1Ocq6XxnZtuptV1Dx1lI7rni1V
         lzkW+JDBGZV/zMg6mdQomAfV+JbC488KYo1Y2mw4kacy+sDOwYE4DGkVL8ZfEgGwQdp0
         zZiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f204si5818pfa.5.2021.01.11.08.27.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 Jan 2021 08:27:57 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 3B852223E4
	for <kasan-dev@googlegroups.com>; Mon, 11 Jan 2021 16:27:57 +0000 (UTC)
Received: by pdx-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 332E7863B9; Mon, 11 Jan 2021 16:27:57 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211139] New: KASAN: excessive stack usage with Clang
Date: Mon, 11 Jan 2021 16:27:56 +0000
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
Message-ID: <bug-211139-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=211139

            Bug ID: 211139
           Summary: KASAN: excessive stack usage with Clang
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

Building the kernel with Clang with stack instrumentation enabled results in
many warnings about possible stack overflows.

Details here: https://bugs.llvm.org/show_bug.cgi?id=38809

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211139-199747%40https.bugzilla.kernel.org/.
