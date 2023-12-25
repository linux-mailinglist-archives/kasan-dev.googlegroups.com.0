Return-Path: <kasan-dev+bncBAABBH67U6WAMGQEVLWQO4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id E09FD81E266
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 22:09:52 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-40d3eabab1esf34274075e9.2
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 13:09:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703538592; cv=pass;
        d=google.com; s=arc-20160816;
        b=lkK2iwHxQu2POAqCD9gb5azqRejyQ+isuOkYtPd5vfBbJLSahJDkXVZS/1tkCwxubZ
         3gIenJpaaxf/srrJhrK4zmBMpML90PLacwP3bbSHs4NbIeagr9A7wNlx4tx2x5d3YLlM
         WNAmWsJ4X8iYbd9+h6liMVfV8S0iutZBEH4fAryC8+K/k4OdtFUsaKJl7bo+JXzCribV
         V2q8ZZUJopgmEHnwG8JiNlaYNwdQnUJSlGiV69PYmGIQLMrZcb6bBpE4+/ZbmoS5zUWs
         LlfqAOkzuByc4UDlCfaF6A3RJNRazOTWosrzo+A3djyU5kJpLPn1PsdPo6pRJseVmiAt
         DK0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=0rwz0Bn9klgpana1Wxub/XvPVjA34u1uXhU5PpyeBuw=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=R5H46vYW2UxybW/bUitmnV7kRaALoOhtAI6eSwxBxDwN4jbqpFQNB/ZlW5BvZEW0lC
         /EDVBuyENIsizbECl6s30TU5462ydH6Hul61w23UfdtQBpNOKG+9vVLJWnGXFUrE8Mdg
         PPmMQKqRfJRr2lGIgPCHmj8B8L/zPMotmP0x7ZAuCillQ3lt7QKOooWMJmRUI5L25qgt
         QIoOA67g3O6sr+8BCRcPwd4oz+BPs1lI+718CX04P0yNIFMq8UKrKkwb+g/Rfw0HAy5Z
         eYKFmT+l2jAKwcyCi1oT5kDuqpi5HLRBY2mKmOhacnBjJ/C/w/bBFowobhHH9cCtpyUz
         EChg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="dsx/ENTN";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703538592; x=1704143392; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0rwz0Bn9klgpana1Wxub/XvPVjA34u1uXhU5PpyeBuw=;
        b=Bmm6KBzf2sZDc2nIkYUuRsrcLDySPMmyZhx+ajE6gOFF0wNF/YK6aeyfresxmy6F3x
         6t95jXKPs+Cwn5uJuwVaPzYMYYr+ZO18yneSmGODoRJUofEx5x4fHWza+WBC4KsGBwqj
         7+KWxilXuNevhpmU0ZIRAoeEHseeN4aV7V35BZqpvilwYFrtRZBviopdpCTGbNVVTcfp
         RQtEekubpol7Z1JWAZlvEzTlWGkGBa35MRHZqmXspYKniSRXT24vKqRG5jcyfdYBrGxS
         K7kqYEAtDWU64Ze/EKBOEBOuuskzG+yCc+62WJsLNQiRgH1hKi34NRDNia/1/ikymzBj
         h7pA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703538592; x=1704143392;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0rwz0Bn9klgpana1Wxub/XvPVjA34u1uXhU5PpyeBuw=;
        b=Yz6M5m8RxfxZSwjCF2Q/UII2It+5tG1lpktvAKxgbLfB/N5rwKHZhQWaH9eTQAP2IU
         FLYTMDEezbInYcQ3B+OYtrwiKctfryaxJ09OAHY92JvSn3qQTnhrFYaTGuYgZv9i+qej
         fa1L44x01/NEC0JVQOjL6axM11EBH2tuAtYtV9jOIhdSmWWF+0VEEbqYBTX+ScXiGZXo
         5/SruvhCU29v5zzKTW6qPrxXX2vo3Qye4hWH/mI0JaZRRjf2X8XxyQ4g0bf+UaAiSUZN
         R6OZCt0n2R9MHwkFKw1HcPn8crnbNkHJOFMmnkvt5+HilgLrZwJ+8msVUC1gtUcGCweh
         a1Hg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyywMttvBKuo1kqmeSuiDwq8sWsu2ci25gA9UDrvDs3O/lVRW3f
	U464hnFRsact6I6SHNRI2+o=
X-Google-Smtp-Source: AGHT+IF5Y7/2nQxQmnRhT2MZxPIVwhxbDFMIJrgG956sN416Do70yBnDpboUEJYbaMvCXagVR5u8FA==
X-Received: by 2002:a7b:c3c7:0:b0:40d:3c48:519d with SMTP id t7-20020a7bc3c7000000b0040d3c48519dmr3566470wmj.56.1703538591932;
        Mon, 25 Dec 2023 13:09:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f4cc:0:b0:336:8b8e:5eb8 with SMTP id h12-20020adff4cc000000b003368b8e5eb8ls1814823wrp.0.-pod-prod-07-eu;
 Mon, 25 Dec 2023 13:09:50 -0800 (PST)
X-Received: by 2002:a5d:5605:0:b0:336:7434:193a with SMTP id l5-20020a5d5605000000b003367434193amr3260303wrv.124.1703538590313;
        Mon, 25 Dec 2023 13:09:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703538590; cv=none;
        d=google.com; s=arc-20160816;
        b=TIyxqk6GiEgftTr49f2xbMESFyI7YItVUnwmYIrAXgHMV1A73zsg82FAlvdkHIt6Zp
         ZvJF1eMsGvtUUSpuHm/NXpLKnviTewG0//iqcIWalaw5suxZa2Dij+qikkASee/Iz7tK
         dSDr7pjO0IkeWifhpcfKNRy9veDjG6Wahwyo4B2uvixTMWyHtnQdYmzkuYti1rPpjtx0
         1jTFuwEZ3u5lt6mL5dsMhvgyXlBGEZFUPrRNH62qebJD8LlQCOatrd+FiGkejkd1Rpy/
         En6ZsNxD9TXACvKHUMQKrzDNLjcMzz7jm+wPVObYhXspRIm0chHF+YtrGjwVF+DcBYRg
         Eu6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=lwWPDGxdL741nGu9l82f4ZpqYdF7Lksp6SWNzH+CNoE=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=mn745opICt81h2sWJk+W2//WHv6dREQoZcs69jjZeejEWXiCiS0BhSDKb1XrYMQ+Ox
         aZ72DTLgZqU5t8FZXRE5PRYymDyodxsgXdnUfStF78siIAYiq3MwjAB7GdNbPgziPwKj
         00qk06AJwKcMRkR1tjIjNIpg1POJ2zV82g7lGXpvKHtKNY92WaKIJa44BheOgUu2gmNa
         5pAgDybYksJ8CEEG3QdmmC+zYCAxYq8V677i1qAp1bHAHv+Mam9A6eAByNaCvFu7uo0q
         ak6XIGVfgxG3mft/fN2yN9IVOSJhQUUcyD+Y39pYgxHqwHJW1EVITBL3lutaYv54N/x8
         2fLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="dsx/ENTN";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id l14-20020a5d560e000000b00336c518da12si62072wrv.5.2023.12.25.13.09.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Dec 2023 13:09:50 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id E5E56B80B0B
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 21:09:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 4A850C433C9
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 21:09:49 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 16D91C53BCD; Mon, 25 Dec 2023 21:09:49 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218317] New: KASAN: tests for RCU caches and caches with
 constructors
Date: Mon, 25 Dec 2023 21:09:48 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version rep_platform
 op_sys bug_status bug_severity priority component assigned_to reporter cc
 cf_regression
Message-ID: <bug-218317-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="dsx/ENTN";       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=218317

            Bug ID: 218317
           Summary: KASAN: tests for RCU caches and caches with
                    constructors
           Product: Memory Management
           Version: 2.5
          Hardware: All
                OS: Linux
            Status: NEW
          Severity: normal
          Priority: P3
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: andreyknvl@gmail.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Add tests that check KASAN's ability to detect out-of-bounds and use-after-free
bugs (whenever it can detect them) for RCU caches and caches with constructors.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218317-199747%40https.bugzilla.kernel.org/.
