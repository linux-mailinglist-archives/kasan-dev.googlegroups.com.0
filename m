Return-Path: <kasan-dev+bncBAABBCOIUSVAMGQE6U4AMPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id B92447E2B07
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Nov 2023 18:36:10 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-581f38fe82csf6630674eaf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Nov 2023 09:36:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699292169; cv=pass;
        d=google.com; s=arc-20160816;
        b=jqzXBafC5FvzRczvmIDSaUlppwRECQZ23WlU0IPdRzXxw1cvLOd7p8Bf4B10vR+Gpk
         NPUPOpW0IVoYhBbEuO5dhio3ZLR0vh4fqHPwoeMmKk3Rn1I/+1r3Uh7r/hV1vk55Z2WT
         FATXFupVsuYeGQwyPY/mM5dCKEdww4RmmhOp2fdk+a+T5XhFmTPHoYxEi8tPb+6QuRgv
         4moD0deYvwmtKWkFDz+rX5NrabuZEwKidDBZlnqWy9FIoH+hhUUyEIxdCdmUPxOoSiQI
         bEXB4o20jO/lQsoBgCJiR6jwaAZNoKUJJhbFjvUGDGJ923/bOy5pvjtB79GRv3KwITGB
         rzjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=gZBmkax/r8iix7IwrzKd0yS+GN4HhZ2uwGVSUi/neGU=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=Qo2apagzPWLOw93jwdE6CL50PcQ7yZDOLBYJ1CVm6tEUTG1H246BKprYdsZGL38+qS
         M+hJm6yT2hltqyy8qoxfxR/m0uJTsc0Tm743JlWrxkYskTq8G6X5n5W88fKDoGumQpw5
         Rl6yY75gBIkUPE24Q+EN1h2F3d88czQVrn8OcOXnI+L9dIuAP77+SqkXNg00NP8BBh+8
         HcUvqturV1ZbNnd4yBqaliJXexK1x55XioFzD1IkA/EZZSxkNn9Cn9KjYsbOuHwS6tZn
         ekGjsmlUkb6/Qt8X++ayIL6mns1HQejX61OlU3krDJ5nuqgjIfG9HyeN80019Vopar5T
         2KlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kB7eESg2;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699292169; x=1699896969; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gZBmkax/r8iix7IwrzKd0yS+GN4HhZ2uwGVSUi/neGU=;
        b=B73ggBSM3NiU6xs3vjezCu8qd9sBqbqpzJWQr+LgwFj/oTCYcWBHFwINPx8bHzFTbm
         KUeFyQTBGMzYrP++pfQnTIY/dXr64Lb7XkyLJI/chsczSSBGZ5vWmtVIZ5ZKEcsG7mrh
         aYL1mcqmj0Vk3uriM22y3aNItoWqEfc3AnwowkYMmcM2CNYFMiHW3TCSlA1IkOcpx+zn
         KN1jXRIswIiyGK30utJS4HYkRstJSeVKNr7ygDgndtlnP8RaLH6vPluwHD1aXF1s36n2
         KDVVgmON24NMWQpZVjME3hJ3P0C88WcIAuPI5CbXoId83HirucDpgfw3BcxRloEIFxNT
         92Eg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699292169; x=1699896969;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gZBmkax/r8iix7IwrzKd0yS+GN4HhZ2uwGVSUi/neGU=;
        b=X6XJ9bdO0MukDP5JMwQZPdhVW92fmh7gxpLgs2+LngZDp9I9Z0CrDa3q+8n9m1/qpW
         BiagWY9U74/jqnrji1YuqaAB8PR+vDl5+lL/qwSxyjpG7X3gX2SJMySTk72ncsF4Vv0C
         /T9BYpIpGDCzOoqdlWINDZojaYOyN6+hTl5rn85BoOzHh7vcVw8kWg2+XlSw50mUVDAX
         4TTLMXgbya3b5ZFZ2jb4YEoYBgvzpQrz2OSiNNllNbZxJBnrSjm9niKTxHi2tXO6g9AW
         ASrzXPE+kdZW/4pd0yOFWmKF1vUXQcQg+nm6WXyMcb55ZMpONHXHEZlCqIalj05FxuId
         5c+g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxrUBTNco3DUaFTJdsacAn9Yr1g9CdL2GtdqMHl1eDE0xfQBCyW
	ZTXzFxMa7p0Qr0+uspWJNQM=
X-Google-Smtp-Source: AGHT+IF9ykKeluzYKKy4BjDcV9atcn5mUH8Uf9vOjaYBTy7VnJf0VSO0LfqYq7f92pAWBHSViS7hMw==
X-Received: by 2002:a4a:a88d:0:b0:57b:eee7:4a40 with SMTP id q13-20020a4aa88d000000b0057beee74a40mr30841126oom.7.1699292169561;
        Mon, 06 Nov 2023 09:36:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:580c:0:b0:586:ac7a:39b4 with SMTP id f12-20020a4a580c000000b00586ac7a39b4ls212185oob.1.-pod-prod-02-us;
 Mon, 06 Nov 2023 09:36:08 -0800 (PST)
X-Received: by 2002:a05:6830:22db:b0:6c0:abdd:a875 with SMTP id q27-20020a05683022db00b006c0abdda875mr31785282otc.18.1699292168789;
        Mon, 06 Nov 2023 09:36:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699292168; cv=none;
        d=google.com; s=arc-20160816;
        b=pGRqitpImU7edmJzp5HI3WYOEiOijFtPDpK3pSHPa8L45PuDDn6cdBN9z6iFeYUbEd
         jwHuGVUdPBDoOxi/lHHRDYqdZbS2r1Z5HMnST3FpyeSg9LUGnGqN4CI+X9Aj3pWCa1az
         8w7lv4HvHxjuLyt7Ma5AafRhyGdlAZGZA25U0T7uEc77N+E6w+rK+dNf6ukn0u/Te7Bg
         ee7mynBPuxbSNMNQdtn/ChyqUoTx/YEyCK0cscd+2FqEQavsYNRSNEZYcDIPM9EXX4Yz
         kS8cUQv6mCtCfAT3/kroMl3yg4jLZeR3kB6hufIswaI9NPA4CZOFV2WKMyVUeOmW4N+D
         IALg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=/A2AqvPWQVGouYq71OWjdED0/LwIlFPdheKkvvyDqqk=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=DxvO1/uLW8xChBvn4Q3KTeI0VJkw6vR9j5sRmnMcJ5LEGcVlH8hC2Xhd5xbwB6C96T
         N5OFK6yCWldNu8bCYXYNKo90rEW38P6Q7Srz1NWqlqPpcRcf7USFlND857RB/BprbpP1
         zb9pIwu8cxrjESpfiYQey7gMTWBaVVyyWteL1UY0qRJYz9zzagTP3JNz7Q79qE0IyFoI
         JEEFK89LSwbKxxCmAg0EU3s3kKhpczwKHxsHaMV0DSm/8er1BEVKbFsvqzHc1Vj4cJLz
         Q9PWnMTRb2MRz+fqNYiGZhbjTvwgAZTd/0/SLz7Cr1Rhr65TDOmj8NR6NBLtlziqdJUQ
         7f1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kB7eESg2;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id y9-20020ac85249000000b0041790471199si646029qtn.4.2023.11.06.09.36.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Nov 2023 09:36:08 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 35FE6CE0B49
	for <kasan-dev@googlegroups.com>; Mon,  6 Nov 2023 17:36:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 7415AC433C9
	for <kasan-dev@googlegroups.com>; Mon,  6 Nov 2023 17:36:05 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 5B8ADC53BD0; Mon,  6 Nov 2023 17:36:05 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216762] KASAN: more reliably detect page OOBs
Date: Mon, 06 Nov 2023 17:36:05 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
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
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-216762-199747-BUSqFQe2Of@https.bugzilla.kernel.org/>
In-Reply-To: <bug-216762-199747@https.bugzilla.kernel.org/>
References: <bug-216762-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=kB7eESg2;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=216762

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |andreyknvl@gmail.com

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
This is a partial duplicate of
https://bugzilla.kernel.org/show_bug.cgi?id=203967.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216762-199747-BUSqFQe2Of%40https.bugzilla.kernel.org/.
