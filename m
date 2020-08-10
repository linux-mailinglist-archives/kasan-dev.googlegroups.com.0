Return-Path: <kasan-dev+bncBC24VNFHTMIBBLFMYX4QKGQERE7JR7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id E3BC924074B
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 16:14:05 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id a19sf5601009oic.7
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 07:14:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597068844; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ud09ErkoevmdEp9+3NMUdD0vQFhrr1bl1sWl0aByXlK8lskhLKVaYBCIa4FDbhOO6T
         ry9Gvj8cn9EXuJ5p5y/BYlTUgFBRjzoHXKKQjooqW2q1BURFjEqCYNUyOjR/e1odZWzy
         UfbPcPFMuJJ76g6qddElJDNsMwCk5jpKObXzeYQLs8P0GOTLUjtZws4Y7/oKjQ05MTdR
         frhhNz6jsYlqHpyIFLZdQgnWZZsGzoLl+QA6crvR/zVco/zy8MzuyU49oiLSWm3jJzjf
         N4DWmUCWSKpQh577NKcvrBXF89dt/m7KN/6H3U4X23wUCNEDH0qlpR4dyGsrcdU+ancN
         sISA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=nmw9TAu1ZchSa3T9dseSquPII4PctXK0JhqdoTveodc=;
        b=LtwvH7n4t1RzDOcQbwhWdBs3os+CK7onaRhU2qs/ZJfUF7FUUcPHq/TI3H3q6IUSgN
         1rrFbHwrSD2wOgNP1T0yY2yboyUDXkAty9MlIemXctdZ9bRaFln5SL58CK39Ymj/G1j3
         BV5s2uiL5ZUZiTJfGyZ1b/11pF5z1SYpAKuxny5Ri1cLNosEyXdzjO4tNMMSx7zTK0Pa
         Ovw4U5ZaNcCc5M/Wf6QfSBRzMyAzopaEQU0Eu1YQ1gegWz2qX0WoEpDY9Qc9cew4yMDx
         FbSe47rmmbgd1G+sHBULeJLA35FB99NhZxIIZRnNj+UwfkKNNhOjV/yB3jubjut+wDe+
         Acsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=lle8=bu=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=lLe8=BU=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nmw9TAu1ZchSa3T9dseSquPII4PctXK0JhqdoTveodc=;
        b=MTqBg+j5KnUcVKEx5FdPfKm78b4M5etbD+cWoKM6so0MSUKiHuXAePCVAQRq24dAqu
         L5CsPIMBydnwnfclxKdFzazpTOGLyGDBnDCaADdXGB5BR5wVVAvg+FzGddLrROYOLRRI
         gZc4gpqu+mOa9Atie+dYpTvIAR7MYMnfqIhLrl+kGZDz+zqUyE8qi39FKSH4f5qno6ux
         ozhbKZc0Y9oTFmR1jiA9o1fE0c6pdoLstmLd3eSbSzBW9XS6qphy5GJ+LyPJLZZXoPqB
         7pvfOFVzOLoloIifcq5HO0jpVLwcIZyFOAAjJKd+8mG9jsMShmIbc0pG8t6HTsytxJI+
         NCzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nmw9TAu1ZchSa3T9dseSquPII4PctXK0JhqdoTveodc=;
        b=KgIC8DnP3QnGv+XNyBlpbnsZAuPL2+nXtfMqsmP5ieo3iOOydVCUAWsjpYKnTDk3WX
         tPnk0qJzhDxhDMWp746gzxJIaE18Rp8QCJilBMV6YMMU1Ivgs/XF1Ndt1T3KO5bdGbvC
         fZ6Mn7Sl4xAXq7Jugy4wH9otLhUJqTzEj77jo7Fbca0n0UIGUEmmSN3nXNLlc0avAb3p
         Oq9aTGx5IkbGFh8ITvPCMx6hXjjZenSymBcO16683x9CXs9cDTppUnDoaVih2Pjqk2Sl
         KeRlh2j6YebQeNI3GIzE2fNENAaCDdASIGYf/NYsDcRvCGX9QlOCK3bAHM0Uv3t+oQbq
         kqsA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532kmdqw8Ad9s81KHSFp3EKN1jt4QWJXSs0CPv69kbr+lMjdI9mU
	4T/Urt5gFrCr62dZ5eE6Di0=
X-Google-Smtp-Source: ABdhPJx655G2v2XAqkPvuOlY+dlWRiVosAlkVT3Du1gG03MmiacQtOGA2lu/BuVJEj+b13aCQT2pvA==
X-Received: by 2002:a05:6830:148f:: with SMTP id s15mr969668otq.323.1597068844776;
        Mon, 10 Aug 2020 07:14:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:42c5:: with SMTP id p188ls3600384oia.3.gmail; Mon, 10
 Aug 2020 07:14:04 -0700 (PDT)
X-Received: by 2002:aca:7583:: with SMTP id q125mr889277oic.142.1597068844438;
        Mon, 10 Aug 2020 07:14:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597068844; cv=none;
        d=google.com; s=arc-20160816;
        b=lgLHlTnFcz+3XtngLMDhSe+TDmjabgJmzjPXsP/V1WEMDVCj9PP4EAoFCBWPE5Q/z9
         M5R/A7H+Zya1uPwZNlQqNwqwxBEa1wwYJfGmp9CdJ+kjy9tH4EM7pUhCes7XLqLD+b7z
         bhRfRohxEMQHIgPs3j59CvqHQSywGG/v2Gt7yAizEDsdjP5GKY5bpL6w4dUAMCMPnfoj
         yLnvWiwWqine9+5G1I5F+Qphj14FaXcH9JOxB0tGjFQpeno8fEWdaPARZoryTR0E/7pj
         E6ANtW7ugs9H1ajFx1zhEpiNgMpfIsU+zea6cS9NItTLqBRrb95XoXyRP0kCGEmoZxkO
         BbNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=RxY1oC8OH+XafYHXpb01z7SmYgZuOHtMGXPWx0heFUQ=;
        b=yXDSaaa6sowA9OGtFuwTsEQ5hkUneCiGAtorOcmmIJ1ICRdCMTEU9zCXZe2LUxHHOR
         tiBH/H12lH3kybXNgIUBamuKW3Unlevh7zPIAfh6F0/+3I0rP3LJ+GwYp1fPFmlDhoeW
         veirZvtQMRW1tDkbrdKXWdt4nkNGj2g+XQTwvC83PfPcR4cEqG3EkSYnZCTg+wQpYKM1
         Q563oiUbQrzkEOovIzJGaXCaXjAGt1pen7jnPNg0WdxxHlXRuWXOmOPA0SaslpkW85I4
         KTzpwwI2v/nz18EUTYLkqpL7Lo49K+5RRbrpQrGmBCdUiESRgxBwhUkekzAEa6rl7sRO
         aTQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=lle8=bu=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=lLe8=BU=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v18si15446oor.0.2020.08.10.07.14.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 10 Aug 2020 07:14:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=lle8=bu=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 208865] New: KASAN (sw-tags): support short granules
Date: Mon, 10 Aug 2020 14:14:03 +0000
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
Message-ID: <bug-208865-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=lle8=bu=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=lLe8=BU=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=208865

            Bug ID: 208865
           Summary: KASAN (sw-tags): support short granules
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

Software tag-based KASAN currently doesn't support short granules [1] (not for
slab nor for stack). Slab support can be implemented purely in runtime. Stack
support requires both enabling -hwasan-use-short-granules and runtime changes.

[1] https://clang.llvm.org/docs/HardwareAssistedAddressSanitizerDesign.html

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-208865-199747%40https.bugzilla.kernel.org/.
