Return-Path: <kasan-dev+bncBAABBTMYQKJAMGQECPCXQTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 71E9E4E88AE
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 18:09:50 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id j15-20020a4a888f000000b00321764d8f14sf7713773ooa.14
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 09:09:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648397389; cv=pass;
        d=google.com; s=arc-20160816;
        b=VtAVgkJ5zQrE86yEhcgRqeTVxMR6V2+7Jt3g8PTNtM89VWuJxTk2TYzvq8rCD3bryy
         8gy7BfQKzMgK+LGXJvNA7jprbTq5fV/BHdfKCdPGSWNmgMxGM3WpV95JnrKK9871dR+D
         4jV0J5i8Evf3PMNdmb0+Ta6BaVtxFsMTz4eKwUNKzkETQzXt5l4KcN9UuA/vShxW68sn
         CsmuDYBlkeWa+dqT2uEDbeBOYHt2JsrgxGKrPAwwHoc2BEkapaCbafED3mhuknLkqSHp
         nmeRrxE3bPiYluOg9+9sf9U0VUg0YaQdxSpEAYwtCLBsKzhcqrwPaRTcQVMMNiU+8/tT
         vDFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=s/Lfr78LNQlfDJWIgKL2eqviGRy0vNK7DMDlGN0Wu3g=;
        b=uXy6tgkaV3rF6MkGvzMLYdAAGGZWIXtuq2Tu4+Ieb4SwAKHh9A6484gugX012HpBqW
         f1cqm66YX2is48DrKrOkbD8tiLtbf5i/SmdfJ6ioVhU4qEd2lzQxTes3a/mrPXqPZP+f
         TiB40iJ1mmNnfUaxuG4xQpOTOG1qsIB8dKDNy5EZKdiaj2GSpYwOvg/+folzWIWPnjmS
         qDkcduPI8NCteLIjroOz8NaXq3rsF7LtHTnaJMC3adVdELhM/7p3KGVn604JkoHLKfbf
         +E8pviy8ryjVaS485JiCvaeKlEvrvWdJ8XQGNyNdgksKDMviqVIhayXo700O0k3oXUdT
         /T/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Q5JxOir6;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s/Lfr78LNQlfDJWIgKL2eqviGRy0vNK7DMDlGN0Wu3g=;
        b=cWr7C2OjI8D2Ks3paWB1/6LiaC6158afBtGelgVw93Ht4gOnSD14Sijt87Dzge9acH
         LbeTS1LRhyT8ey/Glm0zRqGANjEvwrdhQWz6HI2kpq0ePPMGpxkYo+VFDGgyIxnl4Own
         SWd6VULt+1Lj4WmezbIa47m3YMFZifwf8EaAtdDlIa8sFnyXWZj7YVCMyK2c5YpfYLdI
         eU/KajSrGt9J+GQ9v7HzzVxd5H4MSQNPr2b63lNVX/y3FyQ0C7OPlBZ2fsYmHKQmO+AU
         zXo+M3P7ii8vCXiIX2nrbsx2C+DBMrtd4aGFv4P98TXdUohCizyPhswcv4TL7cqEKZA0
         iC/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s/Lfr78LNQlfDJWIgKL2eqviGRy0vNK7DMDlGN0Wu3g=;
        b=YJRP8V7apZZQtGnMCb4WA5IGDsN3NBQY6FA2IafOxTEOVk3/3T1/OvhRLw2duf3DzU
         NRokwK27EdzLknPjKTMMvULXmwhMKpbedcpNFXVYsS2tSw1ti5WpSIpKUm/qWS4YeSjy
         dMc8/DVmNxsoJ7BqUAe2ifkRg99Tl12fZN9/rBznjlUJ5oo+KLbD9RZt8VuUTIlNNKY2
         uJR0o9ig/X70wdnMMHbRSa+Gk94DswjJSHVSwm2OjpOrK6fmk4rVgY7pkIKLZRW0100c
         pQQxASQ+T7PLYD9SM3rj28TzY/RzhWZDQz8Tj0SyyB023w+akRGzo7m2qcY9lv6Wj5yN
         BrcQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533C4OaZ4XkHr61G2cBRaKTJJFWaHmbda9+cJkLnKLuznXKoWxXJ
	4wX0/TWmXLFDkyAVNC8i4eY=
X-Google-Smtp-Source: ABdhPJyPmoC8+1YWoextbHg/HFs2N7BopFXwCLABcumGhvKYvZ7c9SOKkWschkQnN1+Ityj55tAAvA==
X-Received: by 2002:a05:6871:613:b0:dd:b444:9889 with SMTP id w19-20020a056871061300b000ddb4449889mr12871350oan.185.1648397389438;
        Sun, 27 Mar 2022 09:09:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:240b:0:b0:324:b23f:3c07 with SMTP id m11-20020a4a240b000000b00324b23f3c07ls598395oof.0.gmail;
 Sun, 27 Mar 2022 09:09:49 -0700 (PDT)
X-Received: by 2002:a4a:c894:0:b0:321:1b7e:f130 with SMTP id t20-20020a4ac894000000b003211b7ef130mr7479672ooq.56.1648397389113;
        Sun, 27 Mar 2022 09:09:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648397389; cv=none;
        d=google.com; s=arc-20160816;
        b=Iur/nAeAcypPP6xjqt2iXYvmpRJCyHLeRUU+iAL/QlAwQjl2GhyM0QSmX0q4XjP4S7
         G10lAAnKW6UXtr2m1PQRdyT3gBRjZ5LeAejK8THekamXfqVkMvRmrjiEyXw2K/KjmLN1
         q5DGptn2i4cwf1T13Vhv42EHfQyjTDTEZ0ZV99TE8y4K7DpfsH4oi5xN0rKtjeQ3OeFO
         x8gstLEWamZTv84l9gic+sPEM7umpjuEnzV/h6hrifjNw9T7Ab4hJsnNdYRUGY0kmyrY
         75YNULkAD5mPHpapFkOuNxFMM9KoV94RxHNOxuIm40nyGE0GmHwAjQBXRUWE3pQBevFw
         0iqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=L9FxIGPZ5Sw0gXmpVPKKhgUG4uPVD7gpohqnLYy9c3M=;
        b=o3BZORFSwTci7NRPQwDwOC+XzEZZ787PH4Y2hT/hCs3a84ztuXZeZvT1Fw2F0d7fYe
         cwZPZGV1lXtN40IgaIl3GzwgJLNYw4OnMenKEK/s5U+/8nhaa5UAhhADUx0guAVdSUbG
         lweDItBMM0TC2i7mWAsSBJKPE3dV8L9EyGp6aHKYAXBLd5GYh11Ecm4Akxte2qU0psSo
         yHZ9QBPgNVrIvH0G1Dg92/sEOmdxR87iAjlG5TRLVqGXNMRCaxfjsMfotrWar0F5iJZ9
         qccZ7rXSDTBCh7gmI3DpIw5IHuRSY1ci0H4d3KGwnpSDoUMSmgYi3EShQvA3IBMC+efR
         s5cg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Q5JxOir6;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 22-20020a05687010d600b000de1ab63670si768218oar.2.2022.03.27.09.09.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Mar 2022 09:09:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id D5AC561024
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 16:09:48 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 45540C340EC
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 16:09:48 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 1D7BEC05FCE; Sun, 27 Mar 2022 16:09:48 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 215759] New: KASAN: more OPTIMIZER_HIDE_VAR annotations in
 tests
Date: Sun, 27 Mar 2022 16:09:47 +0000
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
Message-ID: <bug-215759-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Q5JxOir6;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=215759

            Bug ID: 215759
           Summary: KASAN: more OPTIMIZER_HIDE_VAR annotations in tests
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

UBSAN, -Wstringop-overflow=, and other compiler features detect the issues
deliberately present in KASAN tests. We need more OPTIMIZER_HIDE_VAR()
annotations.

For example, as reported-by Gustavo A. R. Silva [1]:

lib/test_kasan.c:274:49: warning: writing 1 byte into a region of size 0
[-Wstringop-overflow=]
lib/test_kasan.c:194:63: warning: writing 1 byte into a region of size 0
[-Wstringop-overflow=]
lib/test_kasan.c:139:57: warning: writing 1 byte into a region of size 0
lib/test_kasan.c:145:53: warning: writing 1 byte into a region of size 0
[-Wstringop-overflow=]
lib/test_kasan.c:760:19: warning: writing 1 byte into a region of size 0
[-Wstringop-overflow=]

Peter and Kees also encountered similar issues and sent patches [2, 3], but
looks like those have not been picked up.

[1] https://twitter.com/embeddedgus/status/1507546690160664579
[2]
https://patchwork.kernel.org/project/linux-hardening/patch/20220213183232.4038718-1-keescook@chromium.org/
[3]
https://patchwork.kernel.org/project/linux-mm/patch/20220224002024.429707-1-pcc@google.com/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-215759-199747%40https.bugzilla.kernel.org/.
