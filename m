Return-Path: <kasan-dev+bncBAABBCGQU2WAMGQEITEDC4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 533BA81E17E
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 17:04:26 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-3367e2bd8b0sf2865022f8f.1
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 08:04:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703520266; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q2WQP12RqyC0WRUFXPP0SRVygUbK6xgogOsLgFw07E+n5qDZPgZx3YzMjLt2dIup25
         B3lnyJApEblQj0xwOdq6K6OsrpGczraopzG8MHszCqivGU8rakajO9S5vqya4IKt3B8k
         0Cp940HmMT42NHKdQtFWyw/8rQ7tZfqDeheoI/rs1dktOOJLe8xed/rxUgegcpIFzxK7
         SY/DxCDhQLpvtOYqOuBT0eYYxykR+FPSjd3CKBP6zjzHIgNnBFuzXN/UE7OsLFw1zBK4
         dV4CfjN9c16nvupbyRo1keXJOO9ZdU+dj3R/q582uiGpMbkQWvEWjr03twwXnYQwdPaP
         p+4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=+wjkPdUGyfKnDotTGqaj4iF95wrPG6Xuua6S6mLYs3U=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=sGwrY5zcKUltmdGQp9wUUxIKc6hc6c19bSMO4jBQAiG8i18IcaLFF74a3Y/L2tVhlW
         0Wgd0cUJQ3BSjphbHFxZ1/zmI4B/VLJT8QjGKvZ3WCNgoxoQL/zos7ghCKJW9ZmbF6gs
         xYHtGzM23tftWaCqWsleO1w57gXKRT6MyXcYCBLcM35bnSLT/HVhkjei4Cs6PA80B6ea
         0R/6qMexLfA/zPPryRcEZSYcrVtXVZ4Bzmdp3nwUBcO071VrJ+p3t+YnnK7nq/kiiknO
         tIav22KrArs5LyBiPkcpdvYBhU9XteYf+5KgoLtta+VPv7wAxZHnKxuF0xMU0M94UHoW
         LrNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="ZL/Sjt7y";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703520266; x=1704125066; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+wjkPdUGyfKnDotTGqaj4iF95wrPG6Xuua6S6mLYs3U=;
        b=MI1nL7K58/9oKa353fAYgXrsauXeYaoC9HG5BJYb4nKRdrd6xFR32pCvP05A1a8xqh
         H7gKHTDh1+XvCr56E0LGtm5Ilx9VkwwlXypgwslatOmT+L+D4CusXDsHjBUY9RqQXrev
         N0HKDyH/qCucMlUmtARku403XxniINaqeaWFvI6+nBKAdZzEOlEI+1/sIZkEKmRH0xHc
         HUMB7Y1EpuOlaClXLqGyZ/T9W2Jlyw4UosxY4n/gF3PT74Zve5D2Je/4JctdHSqI2awN
         g5BOeRD1LRI8QhX2mTs2BNqtV9SsTazn04h/ZmC8G5dxTRmabvcS0cUE2d2o5mbOwGG2
         sHjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703520266; x=1704125066;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+wjkPdUGyfKnDotTGqaj4iF95wrPG6Xuua6S6mLYs3U=;
        b=KQSbdmK/wt+dgtJEPKz9quvY3xUlo+GnJxl+lq0LlGJwVdKFfhw/eqCABF+eaqJF6v
         qMyJpuxOiORLECGGTFneGMWHZWeP1ssBksWk5qECmaVQ6Td1ZWNEbJOhy1ipflXfBBma
         hHaWTDiHNy6DSYX2TKsvUYws4/L/MtUochBseyDggvlGLCMDABLBBwh2u8jIKknM1+Te
         tdcP/yvgqMaynuUr+nZHuAnkH+VGBY5pOr5dOVTCY97nb2LZ0RTKOV+mLMYd/umeiSFW
         37+UNnp+kVRPOHUShaaqv0HzlEo5FZ95p4xjWBQ61MNWAsLcFtsE+Q7wOHEvB+YBqhwQ
         FDQw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzASOjt7/SzCrMTs9WkN9VhVgKGLDIv61TW6JoDnD/f7e2nN127
	Lok9lMNgSUlRpaqg5pCkkv4=
X-Google-Smtp-Source: AGHT+IG0XWp0AUfi+Q4YV8KFuuOo8/qBLtgwRfPJHugGS0Ig4cXvCgx0byxcc2YL7exh9yYuuHv5Lw==
X-Received: by 2002:a05:600c:4587:b0:40c:330b:d447 with SMTP id r7-20020a05600c458700b0040c330bd447mr3379643wmo.16.1703520264722;
        Mon, 25 Dec 2023 08:04:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b0e:b0:40d:3abd:bd06 with SMTP id
 m14-20020a05600c3b0e00b0040d3abdbd06ls967538wms.0.-pod-prod-07-eu; Mon, 25
 Dec 2023 08:04:23 -0800 (PST)
X-Received: by 2002:a1c:6a0a:0:b0:40d:4181:4d23 with SMTP id f10-20020a1c6a0a000000b0040d41814d23mr3239736wmc.105.1703520263308;
        Mon, 25 Dec 2023 08:04:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703520263; cv=none;
        d=google.com; s=arc-20160816;
        b=YMRi9cvufXFwI+MxdoFQbDwh5zp9ZhKQLFcFofkbCbiYI5/aGzAEssmuZP9zT6pjm7
         rW5K1el1liVm1+0ZnhRn8d2Lma5hsSc4/nhaLX7lyJcsWCAY0T3ennFBQ7Fh4sFSMFZE
         Dus2sZZhiUS8EO39PD4AjqUR9Z9rawcqBDCaUQInKXlKRVuzPTfNnlhBF/VA6+Q8t5gC
         0AtOgrEjvinHSqQ6FGDOtRJV6FwhJHJ4W3s/jo71jubuJAtR1PMP+Gg6WPKp7hG9g0O5
         dBLtjh+IichweqrsqXFmhEimPcihzB23RPKGm5moar1SPPpk5IO8s5RKYNLFNfZFj/k8
         XG+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=uQi12bK/4O9WkM9KpyaYIM6KbfCK9oCX3PNF4p8lvyo=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=tJWyKD0VhVAqkVl5DS35RG9PwITNL3Hi6y9KMQ1Lbf7hr2T21g1KnipAvMQn9HkLt7
         YhpDBrhD5eaAKtW+0xt8btqf/Xq1ouPNmvN0bMxvT1BAX3129bYoAbHLb2jA2Yn0F06O
         NmxVgnXxbW7id6IQ7ywHvhyySeZpcFnhyHJAjHnE2t+/UAXoXhY7Yqk5PmyZmmJZul5u
         u8qLnuwUxpWa9v87nO1f5Yx1tJbYPLs7+O41bNwT5Zdf/9trGxlJIobGKuGqhJLdG/uR
         4fenb87dvPlW0+dwIW/l6+GAhIFsqSYDenS0yUi+VwNCgzFp9TLwwe81NOZoOrtdOut6
         MIzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="ZL/Sjt7y";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id o17-20020a05600c379100b0040d2cb644e3si365300wmr.1.2023.12.25.08.04.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Dec 2023 08:04:23 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id EDF84CE0E80
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 16:04:19 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id C3455C433C9
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 16:04:18 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id AB904C53BCD; Mon, 25 Dec 2023 16:04:18 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218310] stackdepot: drop zeroing GFP_ZONEMASK from
 stack_depot_save
Date: Mon, 25 Dec 2023 16:04:18 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: short_desc
Message-ID: <bug-218310-199747-6EYina1I5h@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218310-199747@https.bugzilla.kernel.org/>
References: <bug-218310-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="ZL/Sjt7y";       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=218310

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
            Summary|stackdepot: from zeroing    |stackdepot: drop zeroing
                   |GFP_ZONEMASK from           |GFP_ZONEMASK from
                   |stack_depot_save            |stack_depot_save

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218310-199747-6EYina1I5h%40https.bugzilla.kernel.org/.
