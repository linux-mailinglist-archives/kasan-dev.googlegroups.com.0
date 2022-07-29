Return-Path: <kasan-dev+bncBAABB35FR6LQMGQEZY4WHHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 23379585015
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jul 2022 14:30:40 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id b15-20020a056402278f00b0043acaf76f8dsf2883882ede.21
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Jul 2022 05:30:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659097839; cv=pass;
        d=google.com; s=arc-20160816;
        b=nq/RPeDWayXcbDEd7BMuPcPK9IAb/mFCZ7X3uFmx3yihYZcACEpcqiFhRhPcRJ1Ohz
         5rgmkuEvCW97VWoYM2u9s6V3ViesesyhtLsB6Rbm9P9X+W0rL22uXkifl/ruTHjlyrla
         NpJz4aZCNZEbS0iMSEQJClXvBN5W+thu3LJ4rFs/1x1nVS89Rf9bVy2d+bO+y4h6wwXz
         +R99OALVIkqTfVSP7NK5n32/7SlPC9aVjF8F8eyxrfc23b3vFonyvGgK+eAprHOq3NZp
         PChjMFTJW/YHexLuhOWOhF1M+uQOjOrywMatlMM9qUoVdzCqwHYOS5SkK4/aAusToEUo
         KM4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=cCYxVQ51eOUqLmqRFXJ9X+oxF8NSf6theS89fMOi57Y=;
        b=ouWIk7+/UzwDqgiXN/g1JUF1yn5SvobZA7YMiZUhNw+USMiug1NgFnkFU9iTeVaWxS
         016isS6moN4nYhfWWLTcbbMBShPeyMgQUYM8PSOlcS6VDksU6MTnbPzEmbutOFr+aKV5
         fNJM+/1wcHek9A7BBKKkDPuiAqrsiG1g0cCfwsnO61i9ZCxDlxXImocGqRmr9HjTTHCx
         HGfDdxc1plSgEEeLqIHJOWwdTK+YJUhu5sz6wi10f3em/gUIJev2ZjWC7AXfvik9WCdb
         YE1ivS9/Hs21QCP3+4KfRCWox7MLDaZxgNpUsHtZ+LV+ue2xyIOs0fBhEQAHXT3dZeh7
         TTKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GeQaN1kS;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cCYxVQ51eOUqLmqRFXJ9X+oxF8NSf6theS89fMOi57Y=;
        b=rcP5SloITBU+E2DUqFQ4nfGUDcflGbknMBEoQjcCuTQUev01YU8R9Ps+JVPlv/kTSa
         H+NPxCu6LJsWnULXLfc7pP5MU+LWLnaPW9JoDQja0uJct0Edu1Zrw8E23hve3a6miuAr
         HnkvYt60snj5AERx1APe8sECf1cP0kLFLamU1H7UpMzOAdgqae87NVYacx7JcR6eKV3Z
         Hrcby8IUUDIEHjHhov3PJy1/yu6y8OfyRv6y2D+0/65NfvMs07xaod1tFzJecXxbc0g8
         3RuF9y99itZuz2jVkdXzzbMMIroa9l2Rd8P+ZdZsjQ2OY+DuzYIbZ9BQhDT+I7nR2L0p
         vkow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cCYxVQ51eOUqLmqRFXJ9X+oxF8NSf6theS89fMOi57Y=;
        b=AevpP+1kXCX82R8NpcxWE+YSmrQ5jAU5hRIc7ZkhJfdXbHTC8spTuxYVtUFeHlPQZ4
         qFHEsB3OKtXnUhnEzA8Xv9e0d4edipcwvjqcWk54kX2Rh35tWkr7ayGS9+juypIeUoRJ
         c7JlV1YX+q/TM1qMt1YxfVtfZCE0Vuh3Cx8+beAyzxfO2Ki5wVHYVkjU4ygDOBCtOroR
         TlWhV/WJmNJwXJP2aap6EB8xf4UAb2lOROi10XFkLpql9Wc1BUjEBBEyMXEEwcLwOTHx
         am+0LNGn796a0i+dfnYRWvrZlqbXggZ7xarYUZLUclniNcuCAQ/7+spKfBtb/esd/VEP
         y6vQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora86ww+ZUgtrxzEhEL2LI/CwtoRkxD4m88aMjkhDaG7Jp/xTbHTQ
	+ZuEadSDDfePKX3/Yn+4hxk=
X-Google-Smtp-Source: AGRyM1uvl7MfZnPvdWBPmQGOJZ4/eeNh4r0WsCh/Zs6s8Ghvg+CBAclViPpP+BXDGjl9ChKMh4JnYw==
X-Received: by 2002:a17:907:75ce:b0:72b:305f:5985 with SMTP id jl14-20020a17090775ce00b0072b305f5985mr2708297ejc.527.1659097839522;
        Fri, 29 Jul 2022 05:30:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:e0d4:b0:6fe:b664:4b5f with SMTP id
 gl20-20020a170906e0d400b006feb6644b5fls2416898ejb.2.-pod-prod-gmail; Fri, 29
 Jul 2022 05:30:38 -0700 (PDT)
X-Received: by 2002:a17:907:6e89:b0:72b:68d6:c9d6 with SMTP id sh9-20020a1709076e8900b0072b68d6c9d6mr2690155ejc.711.1659097838756;
        Fri, 29 Jul 2022 05:30:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659097838; cv=none;
        d=google.com; s=arc-20160816;
        b=hMt2Y5L8Keq1QZ2V2gBoi70SMm76FegvVVNv8MZiwZyDLNSRrddsgoyj+4DiYt5OOO
         EU1wLpqkpPTlHeXYvCZRZJNkwPfKPMLTRcb3wRbOXwTTi8wId9GyXcyigd8z/ryxi24Q
         pINcG8zMkL0WZzqmAeZh9tMgNM4leBGS//AGJ4z9VNCh6+10MuGGKb+xbSbaL1uOYg2p
         oGoCAXE0iAQsb3n1DuTpDSRZBI3402Zdq0c88eLLLeXlRPEhCMcy8AF6r1WggIANNzvG
         eMK3QhIgd0gvjpx0Tz1Ct0KrY6kxghIbtAW4Z2Zog2B9ztuoNR6zHry9p8ocr2aqWctJ
         JUEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=j423SM9zQEfijWfgmwFICSAuaMbNO6ktDq9Oy2vVs5A=;
        b=MXH9rZ84Qf48QZv3OZ5mo+jPIeA8zXqq6A7DhEzObTGOSyOQuoeUXLUGG+UfcuJ2dE
         7u0kGa4hA40FdJEnpCvL7pjI+OGTyFyEgHKRr9jpz8e4SLdsB1OqC4jaRICEK9sX2csc
         xkWe0n+Iyi8/bE+g8CqR73cnL91hyb8aftSHwqbzLMXij6YRgF2Fbt1fViMhfIBkOGbi
         BGaWYa0ja2FJZ3XpEWb10pGGNonmvosRWCnqCkbn4WRGKR98YUrv18fAXV0x/a4XTEtp
         NGMKGLddLDy6Zz8RgoaFZFh74iLJ2R7aLMnZ+4hNujY4EXr1Salrye1Zc1o4Tqxg154O
         3OBQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GeQaN1kS;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id r8-20020aa7d588000000b0043c90c086d5si157521edq.3.2022.07.29.05.30.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 29 Jul 2022 05:30:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 8262DB82745
	for <kasan-dev@googlegroups.com>; Fri, 29 Jul 2022 12:30:38 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 3440EC433C1
	for <kasan-dev@googlegroups.com>; Fri, 29 Jul 2022 12:30:37 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 179EBC433E4; Fri, 29 Jul 2022 12:30:37 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216306] New: KASAN: print alloc stacks in kmem_cache_destroy()
 for leaked objects
Date: Fri, 29 Jul 2022 12:30:36 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-216306-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GeQaN1kS;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=216306

            Bug ID: 216306
           Summary: KASAN: print alloc stacks in kmem_cache_destroy() for
                    leaked objects
           Product: Memory Management
           Version: 2.5
    Kernel Version: ALL
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: enhancement
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: dvyukov@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

There is a WARNING in kmem_cache_destroy() for the cases when a cache is
destroyed with live objects:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/mm/slab_common.c?id=e0dccc3b76fb35bb257b4118367a883073d7390e#n506

When KASAN is enabled we could print allocation stacks for all leaked objects
to give more useful info for debugging.

For context see:
https://lore.kernel.org/all/2916828.W3qMjvkFlE@silver/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216306-199747%40https.bugzilla.kernel.org/.
