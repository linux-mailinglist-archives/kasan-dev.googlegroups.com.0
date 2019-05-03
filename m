Return-Path: <kasan-dev+bncBC24VNFHTMIBB3OFWHTAKGQESH67HGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-it1-x139.google.com (mail-it1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 3FE291316E
	for <lists+kasan-dev@lfdr.de>; Fri,  3 May 2019 17:49:03 +0200 (CEST)
Received: by mail-it1-x139.google.com with SMTP id p23sf5029428itc.7
        for <lists+kasan-dev@lfdr.de>; Fri, 03 May 2019 08:49:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1556898542; cv=pass;
        d=google.com; s=arc-20160816;
        b=Psjg4alqDGXkLN8lOaUwqQaU3kYuyEsj8XpBXsqnuKwFBdKAsdJ6RXyxAb8t5ch8Rg
         GCEhVzwhxh//VpR+K6gcDB6TMYvSva6PWvoM67EG2zV8SujpOg3xBbzs8Jyoi2efClkm
         ymrO7Dn7h6Dx3rz56NXGtXfAya1BWgO7SII7qUWCkNSHPSc91XgrFNVlCHzaUvnMK3k8
         mYAaE2WM98XrbqTmVkznp4uSyf3WrHRsKGRoagF75/Q/l3FK+hj79SS5XBj5QEOQy8G4
         6ZyOwhZLLsjkIe6SMJMUr3j7LCn0Al6X+6d/POGID7eE+b11SYHH3OLdtKcy/9LrJ0xt
         RUXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=TcA155AmmGX3Ht2gxD+qVCxbMshVEU6iPSKWy9EuGXs=;
        b=nrqWoQmfpIx9ILd2FDw3mwErOIUiLcfbSd+Vbkw2GzPPL/7YMXq0G2w2MFNpZrwmQ9
         au1brhaES+hS24DDblWqQN+o710Fm/hfK6PYe3MStzVF5zKqIC/G8sPLgFc3BVtIUZZP
         3vmSjPIExC2jIHMAMT5DwHC7bkC7FAA81olVTLr7b76HgDKHt7w7qq2AZ/LL1fgyQsTy
         nTG/kKOpxiXKE48Q027xILn7zyy7KOeKj6h+AiyGHUQ6mvAB5SGJhPt4duZojnUpAplo
         IFmlhuFHPO7cXTdjHCyCNo7940ZxQp6Syq8at70F0yiwKGMchQA9R/QIVQGdHIIYv6qH
         K7OA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TcA155AmmGX3Ht2gxD+qVCxbMshVEU6iPSKWy9EuGXs=;
        b=bPT2tZCMHY8/llE4gM0dNGplmwoq9qRzSmFabGXSmQKWvpEVsp2PjF1YSQn1tlNqxz
         YLrdbChiQrtmvYcMkJaxbG6zxDYU3kaIEVoUIoUyxZR850NIlpAuBhulNxCJ6qH0Jtji
         WDI/ZpqkwfUIW7tdFcGBW419kBLN/vjkvn5TqeGajeKkvBfRQgQnnHvM6s1l/64iXj7o
         wecxJuxClTa7Dt/+2+um2pvvy6LAJvPfT+l1IuXAkYd37GZwKoY8XyqWZpR2vnizsv8n
         7qif7YJlSq4f2ncYP2jhJYNTiMnWpKrNbkX3m+x9FgoVZt5I3WN0qGuBZSKdiAptoIZ+
         7hWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TcA155AmmGX3Ht2gxD+qVCxbMshVEU6iPSKWy9EuGXs=;
        b=e8arcz9mcl3vTfRr72Gnbyhwtt+tSG1Pw5pGETbCcSh368gfz/UKaKgeiG0z1XcGT2
         /wtyKw6lZ0qDQTS8kU3WcS6s2u/TaT9st3zH4GxRTeXGIGvDTG5f0h4vKi04SqefYS90
         nYaeSDligH5wTC+5S04KTRKtCbM6dfbTtLCPbnVzYpOO6Z9JwZsRWmdIhavSEgxAzoL1
         ctSWP5qN9LhPMZ6RDkkcmkwBLL8JaZLQw0qvLFXA4BPiZCOZRI8nHitBctZLukFJfGgz
         BMV+833lMQRfkeX58qQC+f/RFtJy7G3QPjJEm1rIuE9Uz1Efus1jsiFTwhnMT1XuYVga
         v7kA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU0v7nI7+/vcWDGECwcYQFtZ9ztt7xN7QRbxISdohLv56od3y3s
	twfN5zfRZKaTYtsNdQOMncQ=
X-Google-Smtp-Source: APXvYqxTL4lKVmg9uTeOzTQ1aws/SYqiiRrGhvM0EVzbg8nuZjHGKR7hlZxWZutecL2JoLcxZbFTzw==
X-Received: by 2002:a24:7c8c:: with SMTP id a134mr6731507itd.144.1556898541994;
        Fri, 03 May 2019 08:49:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a24:47d0:: with SMTP id t199ls1923637itb.4.canary-gmail;
 Fri, 03 May 2019 08:49:01 -0700 (PDT)
X-Received: by 2002:a24:1052:: with SMTP id 79mr8245950ity.158.1556898541655;
        Fri, 03 May 2019 08:49:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1556898541; cv=none;
        d=google.com; s=arc-20160816;
        b=S5J4UG2UE0GWvdrWs/z8qvPLaw693Sc+H5hn1bL1ugl7j6SKYE2M5DMd+FOKMgG9WK
         OtrMgfxX/NNxzRkNbhKAyu8ovqAn17NzCsn7welPVIqqurmu1p42MCt5tO5X5osmm/nu
         uXWtnv024sDX7Jkpys3DCbW4GXTCrc+4iJ9IPzYEbwjIaqIyJ8DwnPKH2KpB98n+726s
         OHkzbm4O6l7m4gBXcfV9izDSXG90OKpoV61iYaTGSuOULkPJG0kAZvE9IZGM+YCHhZyp
         W93h01LRTjPF8SIyAU9H3l2IJxkHPfjCXrQnigoBbP2FNJVAEC3mR3mpphyo7LHw3ETz
         mD+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=6GtNHj0HsxqchQ5yutOnbnVHMYk+57muJ/MRoLTQ8wk=;
        b=j9MxaNUwTApiBCkHf8HIRxGU37x7973b5/EcT7LiBMJ+s+iDr7qXeWuwJkLkHfEZmk
         MDC7tn7uaSzcyd62m3NrlCdC7WGJAAewwdt2D6xB6T03GAHk6JIkOvYMVb3+g6dtow/b
         BVHsIYUUGbTAl4d7HtU5btsxFoxoLNF4ACDRlGb++2EHHzzmSL3CkyBE3ERpGvf/OasY
         hhRA7kK2/uFiqTXMUmxZztxoel6vn6tJNvUxjPEwWg/nSLE16Mz9v9PRlyH0OiHc1yrk
         7oEZgbBWgjO25hcdP8SmZPqsEKzOuelKxKDnCATxUfkwmz9KQVouNa4RpFXuzeAZqhzv
         IuQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id u1si779834itj.2.2019.05.03.08.49.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 03 May 2019 08:49:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id D411A28662
	for <kasan-dev@googlegroups.com>; Fri,  3 May 2019 15:49:00 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id C8C042866C; Fri,  3 May 2019 15:49:00 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=ham version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203491] New: Double unpoisoning in kmalloc()
Date: Fri, 03 May 2019 15:48:59 +0000
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
Message-ID: <bug-203491-199747@https.bugzilla.kernel.org/>
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

https://bugzilla.kernel.org/show_bug.cgi?id=203491

            Bug ID: 203491
           Summary: Double unpoisoning in kmalloc()
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

For an object that is allocated via kmalloc(), both kasan hooks
kasan_slab_alloc and kasan_kmalloc are called. Each of them poisons/unpoisons
the memory, the first one according to the slab object size, the second one
according to the size that is passed to kmalloc(). This can be optimized to do
the poisoning/unpoisoning only once.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203491-199747%40https.bugzilla.kernel.org/.
For more options, visit https://groups.google.com/d/optout.
