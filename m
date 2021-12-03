Return-Path: <kasan-dev+bncBC24VNFHTMIBBGNUVGGQMGQE2GKSMYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id A2549467CE1
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Dec 2021 18:55:38 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id s16-20020a2ea710000000b0021b674e9347sf1444433lje.8
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Dec 2021 09:55:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638554138; cv=pass;
        d=google.com; s=arc-20160816;
        b=UuyDCcc69zLXmqW7bQG4moXAfT/erbcguhowSWzQzyGZR+ABeSk24RHTObx61oKmqM
         bnsILeMHV8bMOjPazRE2xV0YnwulxbX1cd+/+p/Rdu4O07QCGwk6WZweWidTlgVAcU9g
         Key5w0grGwlKlaDwQuFQilDJcomazryA0zduPt52RXFyOVtJHDmK4R4Nx3/sWEDEgULD
         T5Dx42UaNR4r9QJV6NdunQvXj0egdWO4yqH/Qt3hoEaOfltVWNkHqlBx1gjX2AW4C75k
         MfhEBpe9PrpGDbjxG10gyjdLql0z/2S2anwyaXRM0O2/oDe/D6GWHrJ8Xwiow3Z2nn7z
         bxjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=1NRcyUwnOy3umQ1z0p10ykcJSXmzYbHREymn/kmpH6U=;
        b=Snbc8nG2wbF87Muv/jlDLvuKY6abnMKFGQbGqMo7FR9sQgmbXsDqetANdbSJEH+jvX
         KOyxeVPqmeeKnKcZ1G8mA+DB2dDy60WnuHLjs7n9wP2dLielWd3NmRLyJRGPzEmX0hmY
         5waY+EqBF86dtE8sv2uwEB0JE1Wl/jf/l9ZAkOPXNl35P48kb+7/abiA01Q+5mNy8XV7
         rLcnsGt/gMNpxJdt1Y+ysgc6gWGqbtj+JT+YK2gmLNQH+QegQYRsHQTKYj1IyH50qZd+
         9M3/Ied7v0RWNttwJOIecJ/Z0uZ8RQohR2dactYzayWWOeIDLhl497iPjzB6LbJD8tPO
         TGtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="rS6/O9DK";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1NRcyUwnOy3umQ1z0p10ykcJSXmzYbHREymn/kmpH6U=;
        b=ed3gn8wVT03a/fK/grPupFwqzB3Xj7Av5QRWr4bu2EvL3UYSG0EgiZas+DWQ8wNmpA
         fC9rqoifGwcNBFhUP5W625SocjBI4QmWKqub3Ir8OvZ/DWClunTpr/Edk45yn1mbImKx
         AaNUBlsz3b0/3FZKzVumQOMUuJ4uHvuge4Ev59QWWxhs0VmGWP3sD+w2uqG6X8HYcT64
         pGMqQJFnv40w+ZMIuUalNzHqsaajq6lhQkokj6HGvpJIWlpIwcfkquFoWye5MThRUOv2
         e4c1wLVvR395itDLBCct+DZQRjgnh85jyii+4aGQSw3kaTNfaR4vIZx3uQgYqIaA9vXU
         getA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1NRcyUwnOy3umQ1z0p10ykcJSXmzYbHREymn/kmpH6U=;
        b=v/2OPs63+LN1ausUvACqzQudDIBdOef2IJXfYZI/s8d5xDWVn1PyVNBaMVUewawvt0
         7g97BWJPuRbVyvU/FVqS3+HcPoGoCHFBqXAPXErTWv6pVTKu2KxwLIDIdigw8Y/tHr70
         YoMHqzVtHBA/7Tho9uYWYhlh33kpH2SQZ0nWNoEScFZsPj6z5VFGmoUpyGmKL9uwL7X4
         5447000PzRz7e3ZQmT7e/1CAvLaAg/QiNwVVaegSF3zCdEQ/q9py9iFjjEaLeh4OzObJ
         Ijmph6jwdLm7sXda6YikCwz7tVGzcudmWXLN6lUOtgPAb9QJyAeL+i/9LNbP2IAKfIMT
         rf6A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5317QdDzPe84JqOjWd2xbdT34V1KQMIVSWF7aYcU4CD8rSPxGnJs
	hdDgyaBIypuGNeRmkJsG0AM=
X-Google-Smtp-Source: ABdhPJzBt9jxqc5slRNgA6NswfWPJyS2kHvcwo2+N61Ie5RravE5ZZSooXevIWjJvwVIC+A8tlu3rA==
X-Received: by 2002:a05:6512:230b:: with SMTP id o11mr20797500lfu.488.1638554138140;
        Fri, 03 Dec 2021 09:55:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234c:: with SMTP id p12ls730738lfu.0.gmail; Fri, 03
 Dec 2021 09:55:37 -0800 (PST)
X-Received: by 2002:a05:6512:b9e:: with SMTP id b30mr19760493lfv.301.1638554137165;
        Fri, 03 Dec 2021 09:55:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638554137; cv=none;
        d=google.com; s=arc-20160816;
        b=AC/KP4ggbpDuIYOzulOkv9FzOJedO6WGe/NBPPrXlx2f00CQ3Zueud3QdjpWgDoH3P
         re/UcoNHqa4T2mOjI7lqcVPrro7EFBc0V3oQyQk/AOi2CiKTX9scS5mH1W5ONEjcXLC5
         shAcHJfa52Vgb1DaiQaCkeztboMzfiWIe2bMC9qxttF1V6nLkyiEUfOf+WSvH8gMtAom
         8gcrAfj+m/iylwiY8mg4BJU2MsqEqwufapn4NdxKtr8tqsK6pMBRYioxj3veFcn55ZOL
         zI9Zmp2cPpwprCMCoRQ7EC+EeX1gOPxGqg6fu2wkXu/MOXbUeCQRPRJUjaf4osyRIsPI
         I7NQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=89iW1LA0VNqpUju5MMCrpr/QZs0w9pbQ27axNWviiqM=;
        b=TjLQ3ThZjW8u8jPOPY3FxX8PI2uX1hTSPQx4L0GToQzZ6tNiGt0ckzKf7VKaJ+zaSV
         Fffg468cUcP6amU3NdRPRkz/CTood1VZ60cxGWyOIrd14gJ0qYGlSbwmLzyfB/Rq3Fty
         8fA36Iy+h4qH/dB2DCogq102x40yGwEyWfVbtj9EdP1hjIeWaTu2RnJ3T+Nmu4jAXMnP
         F7UjVIk2HnLQKZZ4MIxlrRMvCSpvLWdbZCWgVfbyQrtpRaNcFpUrFA1csS4Eb9LnyX+g
         nXeICPMkuTkXUwCznNDwwDPM3jzZjKeUI6gwBpLFlHvWzqTpsuEBsyKtFHocZL3lo4Zj
         Qzrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="rS6/O9DK";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id h12si209987lfv.4.2021.12.03.09.55.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 03 Dec 2021 09:55:36 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 20A16B828E8
	for <kasan-dev@googlegroups.com>; Fri,  3 Dec 2021 17:55:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id CF2B3C53FAD
	for <kasan-dev@googlegroups.com>; Fri,  3 Dec 2021 17:55:34 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id B7612611CB; Fri,  3 Dec 2021 17:55:34 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 214861] UBSAN_OBJECT_SIZE=y results in a non-booting kernel (32
 bit, i686)
Date: Fri, 03 Dec 2021 17:55:34 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: erhard_f@mailbox.org
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-214861-199747-jYHKc4rAbI@https.bugzilla.kernel.org/>
In-Reply-To: <bug-214861-199747@https.bugzilla.kernel.org/>
References: <bug-214861-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="rS6/O9DK";       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=214861

--- Comment #5 from Erhard F. (erhard_f@mailbox.org) ---
Thanks for the insight! I did realize that using clang for building the kernel
entrails a few specificities but I didn't know UBSAN_OBJECT_SIZE was one of
them.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-214861-199747-jYHKc4rAbI%40https.bugzilla.kernel.org/.
