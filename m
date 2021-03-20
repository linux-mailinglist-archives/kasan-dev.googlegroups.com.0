Return-Path: <kasan-dev+bncBC24VNFHTMIBBNMT3CBAMGQE23YJ5XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B5D7342D6A
	for <lists+kasan-dev@lfdr.de>; Sat, 20 Mar 2021 15:41:59 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id y16sf23870507oou.0
        for <lists+kasan-dev@lfdr.de>; Sat, 20 Mar 2021 07:41:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616251317; cv=pass;
        d=google.com; s=arc-20160816;
        b=dH9DGeyozzl8gJrlJh4Qg0UmTbQan4j+3u0Z2K8yvu4ja3I6vVI0kzYFX6jMh78X/p
         ZhZJIy+zz2EQON5V4ag+NXTf6vrlv9EIKDIFsKDPRDq9BWWgAXTZrgqYayi9H+Krj7tk
         xUZz3PfurvCGa0z+loA6juD0Rpwj2Oy+GMckLMJJDfbyAaETCoqh2Z/m4H3MDodRIoZY
         mRZwX5+CvIMIatNCjBSHrwdNDxV+6mvccpqsJw2U0abcnydBdXQzxuaVY7T9cdHaHYvD
         JzM/i+yLQ2Q3pbFejsd/wtEAK1M4Hx2NkqXhM95KMfsdXoMlMLIYbYrRndY8eMfy+ijK
         QMhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=vRD460rxiuiTkXlN3xQ9PM76mkEBRr2rjwT67ceQdZ0=;
        b=Ow8dUj9KSGlqm41Nz5MASK22G7wZG6hg2NyYib1xe9zxYjmB+uWSej64jTadMIaILv
         dfyleFQfNIp0rb+5gVNBMMXidWxTM3SYv8tu21F1sCIQbQ+3tnV2yvXJ8LLSZRL3xine
         vjX5/RXJgoFn1tW+YqDhm+Pzgt3rFYK6c4qE/htWZ0j2xIpz2lkiqgo5VR/9a1E/uDbT
         NlbChrU5XHIdf7yrQCAeih4IoCWyt+2znOwn2IemFa4BcXKDswrvoGO6oucx69Qs3ebt
         KPip/klkDzYaTMrp2qsQNP6mx1lgUWdG9lOA9MuWcb1RB1YWSR1acTqm9wlVzdh4ntFq
         QARg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=aplPp3GE;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vRD460rxiuiTkXlN3xQ9PM76mkEBRr2rjwT67ceQdZ0=;
        b=pNNnPP/WOa1Sy1v5Z8ilrOY21VlBNnBwPC7dA664rGA4188ANsBlg2psJP73b0CFVd
         tW8SHaziXDs3XCW62dLBML/E65IOuRpxS4zcrtgCvuc7msNnKp8q9Otz1IzJ2hTI55tc
         UtxOZFsJTnC48wBvUnxM5d9g+UVkEKmzaX11Ee/hagYDDHinQX5MoggAbobfidKrHkfI
         J+60lmWjQtvOJwgp35OIn1mNCaOlORiEP30C70uPoycZ66e1At2AHdxos/0CDI43LR7r
         OcmWzH9yxXPnA9UYDxP6L6JoTb4tL+r++/VrH9ErPI5JeM/D/7FunArcq7HF+brwVr5g
         6AOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vRD460rxiuiTkXlN3xQ9PM76mkEBRr2rjwT67ceQdZ0=;
        b=qTKs6zhzwYV8S8c+WiNIx/idBIFabZKBv+J40kV+Tq8WTtkaqwIhBoMHUb0i6HIix1
         uGg1WO8rs9JnuRkUbHwAcyoCS1XP0CbRPl6J2IG14TJn3h6xYzDy1akbZP81sKAiax4u
         qBUPshcOGxccPwv5eid1W88IgCuZUlhqFFocQM0XsUHWxN9y0CjpXAww2j3ZG9AAEalh
         Ksz5dHH+vr/K9biP+BwLtfUlicF8qMCqZaKWBPC6BoB3+KpkJlO8GtnFIhot9FJJ4ZKA
         sDAby5bKE1JJh94mfJk5sz9QzFR5zZq4jD3IbyaaBylsodPJa3/3GmQX0Ee8K4ctWuKy
         dHvw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531CS+eLjmxM4dmhaSq3QHWLdFd++GE0tgAl67t7m0DxZromAYuQ
	qW2Bxae0Xl+EsMkdhXRu2Xs=
X-Google-Smtp-Source: ABdhPJzTzzi+E/roC6cPas9UIrTmyWhi2/XTKZ3/74ysW5y3orsRvREl678LEfH7J3KJO/oZpz6Dvg==
X-Received: by 2002:a9d:bd6:: with SMTP id 80mr5339545oth.98.1616251317639;
        Sat, 20 Mar 2021 07:41:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:3113:: with SMTP id b19ls2013511ots.5.gmail; Sat,
 20 Mar 2021 07:41:57 -0700 (PDT)
X-Received: by 2002:a9d:740a:: with SMTP id n10mr5080201otk.27.1616251317344;
        Sat, 20 Mar 2021 07:41:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616251317; cv=none;
        d=google.com; s=arc-20160816;
        b=A2wc4wE8jPM8k2dMGj9opro2YyR5It9W377nd++sESNawy3gX8eQltaLYhavw4GU2o
         OYu38FejQ7yCCXj2TTy05xmg9KxO0+uVjuJ2iD1gL2dsczHUN0GT/CTgJVaq5rhDveuC
         eSBFBcEC226UFuyIFL/Bqzs8oyVeolqYVhdHJS4jo+20QbwiRceaYE9P2/ksI6dZGsVc
         9E7f9+0PRjOKGyXvpkIJfLc1Y42ThXjmoArTn5e5LwR/ww87PwkSPjn4Z7wVNUJG0ub2
         VlsIIw+7XMQLrwtDsIl9THHa1gjunXoemu6SmzwL5uZ7tiwkwsxdnh6vFrk3A8hwbc06
         bWZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=8MvvEzcCl5t6tqIN8UTK80JxOraijaBjnX7tBElT8KY=;
        b=Mpm12Dx0mRtO25T2n2sDTseYPSY4giu8F4974m6IqQA4DfOWUwCfO3Wln259+ELLlA
         qe9dS7PweRRugfBnFqt/ZYqUUlYDLwR/kdZr9aI36Wp1DGrCOO1UCau8fDAorEtgERtT
         Kca/w4Ce+DFxjCWak0k0IQOg7yfw6hHPnbkTWUj5d11Fx0y6K+CgYeFs2FLcjx/y6zPi
         5dr8gtLBMKAUdrRgnKFLETOWig+GYR9mODQe2EKhG7fomADr9i/uJVyXjKzUt6e+30bb
         MAjI4s/3luk8XTBx5wnMVgJvFJN6ZyJrE8iv+e0FmetDtiHkak3rY5YxeO6LySmNQmXN
         ytHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=aplPp3GE;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w16si825200oov.0.2021.03.20.07.41.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 20 Mar 2021 07:41:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 6D48B6196B
	for <kasan-dev@googlegroups.com>; Sat, 20 Mar 2021 14:41:56 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 6266662A5F; Sat, 20 Mar 2021 14:41:56 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211877] Make "unregister_netdevice: waiting for dev to become
 free" diagnostic useful
Date: Sat, 20 Mar 2021 14:41:56 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
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
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-211877-199747-KeAUcAY0Bo@https.bugzilla.kernel.org/>
In-Reply-To: <bug-211877-199747@https.bugzilla.kernel.org/>
References: <bug-211877-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=aplPp3GE;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=211877

--- Comment #1 from Dmitry Vyukov (dvyukov@google.com) ---
FTR mailed "net: make unregister netdev warning timeout configurable".

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211877-199747-KeAUcAY0Bo%40https.bugzilla.kernel.org/.
