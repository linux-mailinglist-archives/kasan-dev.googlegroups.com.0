Return-Path: <kasan-dev+bncBAABBLXCQGJAMGQEYVHPTTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id CF1814E8800
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 16:14:06 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id a23-20020a05651c031700b00247fd91c2b5sf4696716ljp.21
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 07:14:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648390446; cv=pass;
        d=google.com; s=arc-20160816;
        b=s0y++5THUCeeFoZQgoHSokmJOBRBTsRHkqZbZfWZW47z7+wqAy+RXwqkUbgAWXy01M
         Y76j18nWfdCROy1ac+YFBlKt9Gst2JsRUdZ03ov7Kq+N8Bu1kLm+WXoXoDwfI9srSwdb
         5L63nYz6zim1pTDvhwyTiB1cz1zWC7UtLOfJahOG9VYkA6u6Q3hNwJ5V6uCRNoQ4L3am
         88xiayf4wp3JvX+okvMuKQRlYPfU62f6vb2taH9L0X1cCeptnh++M149sKCD8802Bf2o
         VpKT81DbTmfGsD2cg1CVAROKf8P3NsI74IhAtgMeebd78pJwzDrpWKy9LUzt+ynV14NZ
         f2VA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=taGKBDrTf5eBIgCCXgZj3RW6rTNIbFATlA2iIlnJgoE=;
        b=DJLyLeaDF9KYUAEDj8g3iF3TnENNkf21Eq54ECGo8OwIeyg/b3EFLjxufoeDsjUm06
         bOLfKwSKX7U+kJoz0Zzn/GDV/m1hNHOKXmIzpVf6Uu4TDhs65HoK77D5A+r5mw+Ab3Dg
         JMd707vBEPUMaLC4PGUhBNsmdBLDwCSYlo4i4FXr8WjxOHi3dNmwawXj7dWIFWjY7jCn
         eKN3RmQ6aO7ije+xmcr7zb82+RF61+WkDSQi1zYFWpvnaxwR/dvYm76ATtj9ZE7UCfV9
         cjDw+XRltxBqtiahgNz/tIU2QaowLdFTSZR5FM3eftYoYrSVblW4sFvQcVM5y1jKyJZ2
         I8fQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=b6tYfPv4;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=taGKBDrTf5eBIgCCXgZj3RW6rTNIbFATlA2iIlnJgoE=;
        b=J3pElesIzaD2OK45Kg8/nJ0OyfNZxo5tWecKL4wB3WngPOhs6rqaM8DX/zEOHEjc0t
         Bcydi6k8CfyrSjIkLrEQ1awuMVJFw5aO58t59jVi185CaaE47LvjFRZyq65L4peu2DoI
         cCy/PolxMPZkguPLRSJtSinpy1Q5uj7I/Ta0PFCyR+B/Ncy16Nv2k8TPBYJNGklykrlT
         D7eRNmVZ0vJOpaXAVh14f9AZsQ8U0nLcYBmqs4ep/Omqy6g0bwf13Y+n1vJWbsKTs59w
         DqGj5DfkkuQ+fCEAoZrS6CVVGVa2uMmPacfcGlVbSrIRYtXcNcfBNxN+f9VkYf22GSVt
         8qUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=taGKBDrTf5eBIgCCXgZj3RW6rTNIbFATlA2iIlnJgoE=;
        b=VGpMcBATMOFSkHX1ODXbURTKKcWs9A9voNZc5oiiiQaCybWqlP7O4A4xcFhqMzhhzK
         AGP/xYYGQ2wqnp3aPFXElJSJ87TUz9B+sOSdOZl/4dsa3510ISlHWJokJJaU5ddXJGk0
         7dyblXZjNptE4e9yMz5UJliqz2ikHmfEP5h1YvnEi2lqAah1ZHdnXBGJQ5vrk5R8Gikp
         txZ4xiyhVWk99CiGiPhUmQjH8+RTclSzl786DQpFR1k/uHA7huAlpCC8u6l+/n10h8wK
         E8CXz64V49oM0qTqL9cg1O2Q7Yhb7/KKEYH0y1+6pe/XCIvIgUKXO7QJ2lk4umYcVnjp
         h7Qw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533xYFnqU9DYvxK22s/6AcEUAIlLrwMCMArfeBtBuqACItFuNThj
	V7nQIQjSIWLId1Td2yUvtEQ=
X-Google-Smtp-Source: ABdhPJwXmf7n5QVDbZsJsLkpbqoFTSuyTQsbGVpF3X2jRtXmhhsfbwgw2QH4nq1SHD3wYhAGPultVA==
X-Received: by 2002:a05:6512:1510:b0:445:cbc3:a51f with SMTP id bq16-20020a056512151000b00445cbc3a51fmr16052330lfb.116.1648390446378;
        Sun, 27 Mar 2022 07:14:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls2008212lfb.1.gmail; Sun, 27 Mar 2022
 07:14:05 -0700 (PDT)
X-Received: by 2002:a05:6512:2614:b0:445:777d:3530 with SMTP id bt20-20020a056512261400b00445777d3530mr15745247lfb.647.1648390445564;
        Sun, 27 Mar 2022 07:14:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648390445; cv=none;
        d=google.com; s=arc-20160816;
        b=hvCgPAeCBRUmCKUEwupIQW836W+ZGmo4Nls+qIX0tFoqwizjg9BrpcKO+Q5Wo9cMUk
         SQzJGaFhhv3sFu7TFugnKCfHBgv4WvfmQu/ug8E0Eq2lpStTZh1+/F+PGV3rfRW2F6bJ
         SONPb4YXu8Xam0fceOWEEpoHHQVVqdfiqbakqfLxGGUDm7zERx9WJQC6egi4jFL3hLlN
         UgYtKK1SDTez96sYoZyOY3QYDk+SxM50Cl2ACsrsdzW56gtMBd7FR8kKDyFCxVTwWhcz
         J+jjskY0ZIJNNfWSb/kgWEsHgGxi04QIfFkeyTO6Y7dtkRrz4Rn+xjZNEQshlapBMz7n
         mEDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=UpcnjVUIoAF4H1BpQ9O1ur8JB8yrs8DgKcNgRYQUkuo=;
        b=zI7pnoWq4Y3Vg01f/KwbXY0McGdqGwQiInR9PyXLHP3uZH031Piz6oKgteS+Szy602
         nPMAwvzy89kiJwz7hEWcf+pDO48Oyz9LbPoJjw3A2oietDKsbPK4lIAHRdjDKYhwMEnU
         /v9dgdbAuGrpIBH7UfjrC6hxb1AaiEgd8Jjel3r+sb77XP3bxxstd27RHTdPfhxlLu2z
         dcN+MNy6LwZJgAkk42vamM6Blk+mNqRVHluVeR14jRrLj1hm4Qg9/5FRiOrIyJLLFVUZ
         SCF2OfUp2nYYfOOn+EGWKVegU3JHP0hk5GpTLuOY1wUBcjfiI0A/ipIacNF4CmBO7TGi
         sLHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=b6tYfPv4;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id i3-20020a056512340300b0044a2d961b74si717683lfr.4.2022.03.27.07.14.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Mar 2022 07:14:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id EF78AB80C6A
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:14:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id BED0CC340EE
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:14:03 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id AE969C05F98; Sun, 27 Mar 2022 14:14:03 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212209] KASAN: clean up multi_shot implementation
Date: Sun, 27 Mar 2022 14:14:03 +0000
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
Message-ID: <bug-212209-199747-7GhAyjGCLJ@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212209-199747@https.bugzilla.kernel.org/>
References: <bug-212209-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=b6tYfPv4;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212209

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212209-199747-7GhAyjGCLJ%40https.bugzilla.kernel.org/.
