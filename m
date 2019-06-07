Return-Path: <kasan-dev+bncBC24VNFHTMIBBSXJ5DTQKGQECTXBOTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id C89ED38771
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Jun 2019 11:56:27 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id x17sf1062895iog.8
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Jun 2019 02:56:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559901386; cv=pass;
        d=google.com; s=arc-20160816;
        b=qU3DmV1Gs6PzvLvh6tGLevoqmJV5UywPJviHDSGCuPejQBWQ9ZAdANo9QlxlP/hBEI
         r50Uv4Tuv18rrTq4aDHcy/67s0CoZbxui4N2aNxOSEr2whQ6ELeBt5U1qeoXh866JcKI
         +vUqABIffY1dTNdYDvYD4uZvF19193i9qmlIWPOzvMplqAk4JE4pbVPJPcO4Sad5Wpxd
         47NPIKL+90AC//vvlkLQpQ+M4GESl9AYqHt+ANTnCDF1vU3vH2YMW/qGryoHB6M1BKQ9
         r/TOx7Jeo0quvdsXPMK93Lm/2zjaLfbGAjsoq4boVwSXrGxj/u19vHnSTLs7+kWoPBSw
         qo7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=M4i1nFfJiRJImkQ+1aZwirYDFoe/+bvtQ5Jg+Bb//EE=;
        b=Ni58lEkXlbmFOKrG0wqrQ1/Uu7WRiKOnEeUxXqJT90yoqC1IZsa5A62ykE4PIW11gT
         qdgzRYNpwdcemxOGvUv8irpwwN6i8jf5BZg2F+Sbz5qC1ilZCxjLI0vgV524hcZP97Vg
         6lXghcNDyJf922GEjgCMKuRKTUtraTq88yGCRI6XdjvboTiojMJXTnB3A/uHd2/4PiGU
         dlVp4RQWtuo4ieAKBPR8F6KsZbrlQHBsrXgU1BT7Gwm9bHTA0uZyITlBbjDgi1Tr9UJC
         s6nMFo4XIesbztoxVKt6PDqxPBf5f4YHmdkGaftRqj/0UF7eDwGPs77iUPJmnE8+lcLI
         Ymag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=M4i1nFfJiRJImkQ+1aZwirYDFoe/+bvtQ5Jg+Bb//EE=;
        b=laU/SA50xoVXgs+SYALF7pqNM7WfSz8mRE7g9dzYA9BcQhOYgjBu2SqYR4xHKMRBxb
         zkw4yl10Q8owOlW0J6l00fFQqimaQbdes0A9bSIceh8kCFceFXhZTF6K6sEnoqozZeod
         Js1g7w6XSWyCNfsFgegp4sib68oQPwd/j6cLH0w5Z3XYs4tenLqDmnUQa2lr7uC2EZes
         8hGSpOicdvm98i1MyXDWHAlzY2wmUgT3oXh6zBbVHL4/KkbljjIjO28NcHhyA2vfDlQ4
         0F+4vBMoPxtA25VrMvc4GcYgS7qFjWTrSG1BY6T9dDtUlqWPXJ9IB0oI3LUAxB4ynJPo
         1pfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=M4i1nFfJiRJImkQ+1aZwirYDFoe/+bvtQ5Jg+Bb//EE=;
        b=PIu+K7P4mabwDa2AKBCGMNuTZzQEE5EHQnxW0xZL4ArmfDT0+VvGkoelMYxKpL+yNv
         K47UUmyk744fWfADzp+64BH1VSv+5QTQHjTuyPqj06f6VGnguvUF2PSMQydcm+0Uds5G
         IO1w73PVXXCMhdGrCdIHiqDMBYVgyTSxoBbimSPvNH7p1tihNnQD6iRK+Or48r9SA/9g
         p74qlcl4JvyoZ/iSQIPLlKXUF1XFFdyW0/51AqRKV3uGeDSs6Sf8ZjCD3QF78qbmuLMy
         MAHvshiOkFpc/lNv/eoRxGikiBV/BmEOvj3Ip5aK81IOQBPqKiKcQ5K05SGNGybT6hJm
         UaBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXthDVLtMMAJM0/fXfs+hswtgKRXCGc0k+LK0hHi4Ta8dbYZVNQ
	/r4mE3LAS+flcF62STpnM6Y=
X-Google-Smtp-Source: APXvYqyygLjJhEUSnBnrZisQW+vHaNWnRQgycRJHhc5zS4/fritR79vjck0HTMC+un+w9vGfT6f+iA==
X-Received: by 2002:a6b:6217:: with SMTP id f23mr31630512iog.110.1559901386584;
        Fri, 07 Jun 2019 02:56:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a24:6744:: with SMTP id u65ls2468277itc.5.gmail; Fri, 07 Jun
 2019 02:56:26 -0700 (PDT)
X-Received: by 2002:a05:660c:1cf:: with SMTP id s15mr3390626itk.78.1559901386277;
        Fri, 07 Jun 2019 02:56:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559901386; cv=none;
        d=google.com; s=arc-20160816;
        b=hlepxfAGgYgseIpAVUsu4yHK+2VxYd1m4eA1DcR21Va/q64O6Uq4sifG8++iSqn+s6
         BIuQZe09wout8FK4h9u4m7mFOkyZuFuttRLI4VToDFDn0r+1k4fNz7fJ5oBRQ1adx4HO
         zQDhxWWE/PAzAp1/l9BO5xJ4jB4QYNxU1ZPc5Jtk2Bv4NXjJoYFvXcJ8Z9nKneJ9EZAL
         kxskvLqmAs/VPgiRPskFWCM9OZFF5+v/L+dhN/I8Qy05ftD30xEcU+GDkvGkb3KDFH95
         68/3YBkJDFPnNgBK4OM3eSCuBfbx98OngU8KMAEtonLFN6vYhu6FI70g2rTLVswRxFVB
         hRDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=/tZpaO2wNYP+22IW9CC3fQZiK7Ht9dUG3g3MhfaUNyc=;
        b=R624imcCxpOFgcGmXlQwAKWU3XXHJjlFT+b1WU8ew5fgAw7oAQHnDQjWQuzl3802GY
         rSers8TxKlnUVWnZcEXj7wi4HBpxaiXkLqKQB8LK2lVRSEYJ0W/e5dvqEz3vvhfUlNpp
         DYUzZwKO1BT0CFT0rvpZmPekpmuEa5YwlPvrbUTEkZuCDTFD5zUXXo5/FSSpRL5ttj9d
         OT1xBXiPMZNgexsw70hZZF+ynIGJ7mFSHA3t4oKZZBhFkMR9BwgKz1vKmzeY5cxkgRlZ
         PYnRG5ch1aWV8wldeoGqTNXRLqUGp7GaUdveWwMRLlGt3ynBc3BCo3ePKihN+Iw1qfnx
         1Imw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id y15si44987iof.5.2019.06.07.02.56.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Jun 2019 02:56:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id 542CD28B35
	for <kasan-dev@googlegroups.com>; Fri,  7 Jun 2019 09:56:25 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id 486D828B3E; Fri,  7 Jun 2019 09:56:25 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=unavailable version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 198435] KASAN: print frame description for stack bugs
Date: Fri, 07 Jun 2019 09:56:24 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-198435-199747-tGeMrgkmwX@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198435-199747@https.bugzilla.kernel.org/>
References: <bug-198435-199747@https.bugzilla.kernel.org/>
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

https://bugzilla.kernel.org/show_bug.cgi?id=198435

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198435-199747-tGeMrgkmwX%40https.bugzilla.kernel.org/.
For more options, visit https://groups.google.com/d/optout.
