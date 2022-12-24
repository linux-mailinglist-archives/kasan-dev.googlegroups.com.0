Return-Path: <kasan-dev+bncBAABBYVNTGOQMGQEQ4O645I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id C0C2C65573D
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Dec 2022 02:33:23 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id k42-20020a05600c1caa00b003d971135cd5sf1196851wms.4
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Dec 2022 17:33:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671845603; cv=pass;
        d=google.com; s=arc-20160816;
        b=vwC4kQGK7e3/Riw62Vahsh83doF2V+qVlFs/NA0u0mYy6B3i4YjdHTUQILUqNsoKHL
         ZMC0Xt2cI7Bv4pGS6cZgAzcdmBSNZiZcN950k9zuSaCMr2x/wLKzmlkNICpmMgWTHWWn
         /Tu087WR3pLGxKbDSTwG+Ozcb9XafvhROLOqWD4mK9qM8jE2FqUyK/GISwm9qF5oSbFO
         GJNl6PDzGq1QeeeqMlSn51r4WoZp36heh2361fyZefLIrvBkzsACOTiyB7Zr6ocE3sYr
         THC5E0lbXRQatlVgFO8iXS7UZm2SIDdCm0IHXfArh4W0SBUZUNOmoSMq/aWMckApfZtv
         7R0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=utjSMybnc3iTLRxuBCyyu8AIFi6NZU4CjGkCbrW1z+A=;
        b=clkbt4ZgA4f8NyVniCoOb9A8uQbzHuNU1qqA1sTDuaaPUL94OaeGmQoubX7/XgNgwB
         4gSbn18YxeagLpME8DevI+lfj4MZ9qbmN2SyHv04DuEo33KFbnlauZZ/+Ca8iHBORR0f
         yZfsvsyLaKnRkFmEG00ch0rKUTCDewQwWcxoW7LDSqum1audD05QfdcT0MyyRMl31QaM
         Z4U1daegPQxfBfG7kg+nOh40varpoxYRiN3Kf9CoUp+pLa7uSdIiou/YRvd6wVzYh5yh
         IkfMB5HzlORO1ctyyfnuGx67AbeFPpZbzI1G3tuiXjXTlEXmRvaN6Bh+9Z5Ihg54hnXw
         AaFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NFG+xgX0;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=utjSMybnc3iTLRxuBCyyu8AIFi6NZU4CjGkCbrW1z+A=;
        b=lWgZZfov/8oYqy/JGVCfXhcnMp5JAwRYSFG9GfZglqRDcbGy/uRTOV4Hj5MsvtfTh3
         83rP1JAbFEqTmu8S3AAR9DRC7ejVdNGxA/BOjDjmMq+xgX4+7tKraoCxhrORlrPJGgm+
         EAWG+y1nRYHMQshLqYAnebwIuJOcdNHYnkxoy83EzHb27mfbF2rUX0KkKoOUuVfylyjY
         T4S4V7Hm99xjcC7MldwL6XR3ekgSCzrhzLHox0v9SmmivUJ8XJ/r3FkspuIEKYl5tmCI
         BQQAQbl8ChjJuH2G+7Z45k5qYq+1vDhjbvT0ElHYtT3qa1NQ6tHq3eYykn1jw0/F0ouf
         56Zw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=utjSMybnc3iTLRxuBCyyu8AIFi6NZU4CjGkCbrW1z+A=;
        b=DrS3risZAQlVGuGtL6GvmrYKiadPXtI+ag/tLRThQOFpP1C6Y85BQBmvPOZWc708HF
         728SOadj4My2N9eqOgqEa9wJ847uLxFuAkIQWv9E1yziPjaL8c1V6ymFnCQop7IKdZwN
         9azTktkXfEhkeLP9G6aCUEgl0fCb8OPDkqQLKLeWy8om8sMz3GjpUJ+RWxXGwDZiT62q
         4qNBY5F1MyVNsYHCTNKwsNRtoDwQCnnkXoe89cYA8V5HEi1UY3Jo4E4xZMDoaoP9LXen
         jKmoGq4+EFnxSWGIlJmhJjrOq5WJwv9v1S6WaRW3UIYFVZ+4Kn9G7UqANoq8qp91PsXe
         GYUg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqNsqw+ue4xqozcuG/R6ovfeC3/h9XW/xYCy++guyXfcDEL0RTW
	iC8CJml4vDeYhVEiiCTXJsg=
X-Google-Smtp-Source: AMrXdXt0w78tJSWNcNPfMc0HbvPTQZKFtxRqdx7eBiK6kFbbUwARQGRmxt8Olp8s+gKFrHU6N9KZTA==
X-Received: by 2002:a5d:4524:0:b0:278:29ac:f8a2 with SMTP id j4-20020a5d4524000000b0027829acf8a2mr5082wra.274.1671845603110;
        Fri, 23 Dec 2022 17:33:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:f706:0:b0:3d2:2f88:9ec7 with SMTP id v6-20020a1cf706000000b003d22f889ec7ls3241885wmh.3.-pod-control-gmail;
 Fri, 23 Dec 2022 17:33:22 -0800 (PST)
X-Received: by 2002:a05:600c:19c7:b0:3d9:7096:262a with SMTP id u7-20020a05600c19c700b003d97096262amr2430837wmq.27.1671845602413;
        Fri, 23 Dec 2022 17:33:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671845602; cv=none;
        d=google.com; s=arc-20160816;
        b=HVgqplFvc0VtrEfViyh72mW9C9tyNDiINXaW5wT3/c7rbsJBOw5EBwCO2R0WxArae1
         ezvpP8BH6MybllCQK0cpuAxVD00zZS1EaloVLhrVuqvScd+1obfdGQjx4ckJNGrSP4wX
         aM0x4fb7/nVdxts/jRw+MfDSrmBDmlr8awpNNB4/FX/w0tDmT05tS/nk6usMbHX8xKZy
         uVgH6RJAIJ8uxTDhGyRlNFNnU/h4mDRshOKV14ZQHQUh6vRP49U4IiNVzveRmBN5Z9Bn
         DiXDYofIPNMj/a3TwdqYGI5abcaHM17BeDvMz3ioxC/l0wky4bCkJpNweOgcdFmLtJLU
         xjpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=3/Esj6fo8SpdTPbuZjZHp8AzPxH3mJNyitnGKCwxMDE=;
        b=mHvUSg3fzjAy2qlSH7vLr9AvK0RpmSIIHzq040kfy1hEGmu+fFEYiuwsaarPWq2y3p
         /CiwJrM9q6BKNIPSKc+bu02qJiZWJ24kVP28LvJih7L/OpHzIumKsT0+7tR6W34kNPR5
         8DIvTVuDwX2d18NmT2flZVegQPzaAHh2hlzmy1Q6jsK4S6L6vs1shvObU+i2M4w4zdZW
         SNKn2BLwac+ncsn1oYUslcJQDC1+UcJsH7oN2SAGGfv2U+RRtFzLm/KHkZkrmNBo2lBr
         b8LYRxMyZBen7NysVip5JtyEevRxQuriWTOZlD7O3ohR+m5PkZRltmu4XvJQqreD5aUq
         yaig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NFG+xgX0;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id z24-20020a1cf418000000b003cffb3cf5a0si267552wma.2.2022.12.23.17.33.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 23 Dec 2022 17:33:22 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 23621B821B4
	for <kasan-dev@googlegroups.com>; Sat, 24 Dec 2022 01:33:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id E04A1C433D2
	for <kasan-dev@googlegroups.com>; Sat, 24 Dec 2022 01:33:20 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id CF0AEC43143; Sat, 24 Dec 2022 01:33:20 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212203] KASAN: use console tracepoints for tests
Date: Sat, 24 Dec 2022 01:33:20 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-212203-199747-pPkfrJyP1a@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212203-199747@https.bugzilla.kernel.org/>
References: <bug-212203-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NFG+xgX0;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as
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

https://bugzilla.kernel.org/show_bug.cgi?id=212203

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
Resolved with [1].

Checking reports' contents is tracked in [2].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=7ce0ea19d50e4e97a8da69f616ffa8afbb532a93
[2] https://bugzilla.kernel.org/show_bug.cgi?id=198441

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212203-199747-pPkfrJyP1a%40https.bugzilla.kernel.org/.
