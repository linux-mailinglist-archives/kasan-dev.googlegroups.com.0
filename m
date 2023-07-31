Return-Path: <kasan-dev+bncBAABBHEYTSTAMGQELH7CCNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1139.google.com (mail-yw1-x1139.google.com [IPv6:2607:f8b0:4864:20::1139])
	by mail.lfdr.de (Postfix) with ESMTPS id 60ECC76898A
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Jul 2023 03:19:26 +0200 (CEST)
Received: by mail-yw1-x1139.google.com with SMTP id 00721157ae682-5704970148dsf49424287b3.3
        for <lists+kasan-dev@lfdr.de>; Sun, 30 Jul 2023 18:19:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690766365; cv=pass;
        d=google.com; s=arc-20160816;
        b=nkfsqQ0PE4N+UAMHBQhhxp1nf7Jk26ZR+LuQEikIuXeq3nUwOURql/bGeT+RGKOc3Q
         g/J2+Gh2iUHeFOyqgIvczNKSDj9XM3oX0FyYj29U9RCbhVzJfW+9kJALvU+T3LfkbeyA
         IZKWN9yF2oxjC+34n6q6B0MVQAk6sO3rXuA8qAqLRETqgQgIkEIeIIAr9/Hhh50jD7A+
         EjR86UnKhL8GHCw1UHCZy++xNVsFYiUGgmoBbD5u0rxVtb+8BQX6EkABsHUHDgU6MowW
         60g/bVQQENFmMOLGnTpkYuqeMZeU8G9jXk/nogaV0wopMlVtYAR9dJ7itvVSEHM9EEqe
         nyPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=gTzdTmYv3zFkFpHeZ0c3er7pmCF9Zt/79N9h3NapwWQ=;
        fh=DKBepnc4MQU5iECICp0yzPMRbEkFfxKQwwgklF3yzXQ=;
        b=DA1b0sBx89MqYeh54R14TesOzs3ncjfaiVgHVxSDIf9cwlArwOV7lClTP89FBy6FM5
         WHJ5fuLPtX6BDrtp7W8d3dcSlhCBXi1Za3SLj2zcrc2zolHo73qcVDjw/appxf6PVAHm
         g4LfYejMvD9jaTy/ZHWszkgefbVShgSrXX3phGO8aIcdwVf7sPyAtGHLp3h3pWixzKvZ
         sLnMXnp6803EapnDVXtKstMLc9SLw/zlCuubgig7bvsBXgxDiAteiNxtkLQxTet4ME4Y
         u7HXm+2WVm2Nj+nXkHUJ61FY0rOG4R0vs277kz342dID+hp4xds7agY4baI2b+eyGj/y
         X5ow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pVRnQ75w;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690766365; x=1691371165;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gTzdTmYv3zFkFpHeZ0c3er7pmCF9Zt/79N9h3NapwWQ=;
        b=LGKiRRLAHdO5/P4d4uv+vvGaokLlijC4rrYaqDfwlGwU4rDdqp9pqn/GgN0xpYrptV
         J3hiSNDSwWn1KkRdLBysJFNalBH1L9wy4/SAqCdHaOkd/PTtIGRSYHct50fuWVmiN40u
         Ph1yUkPR9RyfTfLx+MhHYLLq+453R0c7a4QqlIMfBd5rJt9wF4x06MkZt1AFDrfRBpDh
         WGRhGaFCYWzXIBUBB1wh2T/p5mYQ6rQQ80XaFn5PV3X4wWu4zvv1J17npSfe2ShUXJAE
         neE/xEWQzyvl5RnLQR6XnGIlR5QBJahRI4bGFAvdGMf1MwE5IZOl1dX8WLuXdkqwHGVv
         u4ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690766365; x=1691371165;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gTzdTmYv3zFkFpHeZ0c3er7pmCF9Zt/79N9h3NapwWQ=;
        b=QuszKDH8f7xZtwXOweWhHLoK3BJVdIZpBDg7Fb83fkoZOmriwgUKa0yKLOkGKAqTAq
         GtXtVX6OJ7ddzaQ8j4t6tmQZd6vsNnSID8t3PVBRisGOPflhZrC+5DmfM7gTdoW9VC63
         boUUwfTQC5L24/rZkBAM6DM7NXsk3R3w27B+EHPtAulq6q1aZW0pDRNYWuAwCQNO0tnY
         fslgE4XZovB2efGR+1acerU8mH2hWxK0XHhS5lvJgo7cBQls7ano2Yz8VplCeT6NPRg9
         Y0h3CLvQz12ll4dMQU+nLpCjkajutyPciMSVSWQIpKZk+mzuLOMcbMx0BwkIaJrLwH/7
         O9GQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLZ1++NCaLWtSor9ywvxubSdWyujU0mi0N222OezVrGHJTAL7YDx
	TJGvBajHpHs7xpzoPMKSITk=
X-Google-Smtp-Source: APBJJlGonINO4VojmAoqxkBdjeZOSgYR6Y1aL9hJXR9rkISKT6bHmsxQEwSI0Z/PRrQt5MJGnfjLHA==
X-Received: by 2002:a25:344c:0:b0:d32:bacd:50a0 with SMTP id b73-20020a25344c000000b00d32bacd50a0mr1016261yba.3.1690766364964;
        Sun, 30 Jul 2023 18:19:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1894:b0:cdb:efa9:9aa8 with SMTP id
 cj20-20020a056902189400b00cdbefa99aa8ls511064ybb.1.-pod-prod-07-us; Sun, 30
 Jul 2023 18:19:24 -0700 (PDT)
X-Received: by 2002:a5b:910:0:b0:cfe:49a5:5aed with SMTP id a16-20020a5b0910000000b00cfe49a55aedmr7043018ybq.7.1690766364114;
        Sun, 30 Jul 2023 18:19:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690766364; cv=none;
        d=google.com; s=arc-20160816;
        b=lrgvNDagdUbOe1qwIb+wAK3iHXNs5ZUNoJzYwUOQVzqjM/7B2dnAOymqSYwic2Un9H
         6IDPJiLX5LuafyzcmoxLtN603pf0iqS1EuplP0iEachJb50VL9fph7vR45zLvVv0EiDA
         8sFiScekO/7AwVGBinyNBBxp4vGnQgQ7/zYiZCstxURGSvEtNu/XGQitvs7Djdzs7UR1
         rnOJb4jJT6F0hFLgkazdl9expGCsZWjiWgB+UiDTTpvAo6A3Fl5vIu8lIetMuyZkVX16
         rBJjypM3V9XX3BJ27oA6YwHSLZOGOXMzoX0La5sSzRV6Ri9lZ/dfdgrKA10574xH6ERt
         K9qQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=SI2ZUv9m4vSvGuQ/DX5JO9KyZJYYmMEyPS5GyJ0Dw2o=;
        fh=DKBepnc4MQU5iECICp0yzPMRbEkFfxKQwwgklF3yzXQ=;
        b=XPqGkQOx3L9xqfsoCjGJ7NiHLsxFqSj2S9+7T94v3UhCu5eZFEITwQA5bX8zd9GpGN
         PXqzlwEs2ValjudY+eLWaFXcX9BdlUXxzRUAmstxZwPABZ9DomZD/PkQDsz/h39dQF8m
         8eyT6hhUlfmiTRN+97Yp4pV4tR0BiUxlyAkk1xc3sQ34t5Pl1eyq7b1O2iWJMNTq2PVL
         6rqHmtICtyfvPHYbt7yeJwInRe/9V6SYM/1r5V6N9WB5DgVWIvodYpc2nIVOQIL3v8c1
         YFczVGaJDY+Q9j7+MRAdvUVfjD3RGWjgQl+AR6I4HisfQMYUNUAoOPjHHW/cICg4CgWj
         y2bw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pVRnQ75w;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id a188-20020a25cac5000000b00c6e58f4a4d8si757857ybg.0.2023.07.30.18.19.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 30 Jul 2023 18:19:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id AAC1160DFF
	for <kasan-dev@googlegroups.com>; Mon, 31 Jul 2023 01:19:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 200F7C433C9
	for <kasan-dev@googlegroups.com>; Mon, 31 Jul 2023 01:19:23 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id F0D62C53BC6; Mon, 31 Jul 2023 01:19:22 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 217049] KASAN: unify kasan_arch_is_ready with kasan_enabled
Date: Mon, 31 Jul 2023 01:19:22 +0000
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
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-217049-199747-xEoKC4yZwB@https.bugzilla.kernel.org/>
In-Reply-To: <bug-217049-199747@https.bugzilla.kernel.org/>
References: <bug-217049-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=pVRnQ75w;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=217049

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
While at it, also fix [1].

[1] https://lore.kernel.org/all/202307310656.h1Bdon57-lkp@intel.com/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-217049-199747-xEoKC4yZwB%40https.bugzilla.kernel.org/.
