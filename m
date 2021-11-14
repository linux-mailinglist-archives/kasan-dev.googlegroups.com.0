Return-Path: <kasan-dev+bncBC24VNFHTMIBBD74YWGAMGQEDXXBGSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 65A0244FBCA
	for <lists+kasan-dev@lfdr.de>; Sun, 14 Nov 2021 22:22:24 +0100 (CET)
Received: by mail-pg1-x53f.google.com with SMTP id k22-20020a635a56000000b002df9863aa74sf6610631pgm.19
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Nov 2021 13:22:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636924943; cv=pass;
        d=google.com; s=arc-20160816;
        b=zyQZcBO/tN0ELPKELtFZs2jeIDEkYfYQazJ1G37wyek2gH6lKnQvMyq40FyctzJ1Ir
         SXj48dH1dcA4mYZKsyJ4HF4cTCyj1VpxocAxE9VhD0u7fLHpTAiZB0aNclTUYOLfDH8w
         zkRZAIurm+15m3qgY6s3P7FJ1EuS0OcOFRU1aE2WatPfcamrJCdSh0DCceX2kYU6VEil
         Lrs6qDU0SCTKJSnV71JqObb4g55odwQfFsd057LdHDsMgpNZVOdtJYTkpAvhXRO9vWzB
         ouCKTcq5s9jEz97v8nMIOlLSmckKbPNYkJNCs2DdxHfPXYh7Y7ZKlaKblutRPwchssSf
         Witg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=wvP77JSWso1MppyhzPN1/pUrLxMKma/djPY/AQcjuRc=;
        b=Y3Bn4U0H21tXV0AEbB2jaZ1xKQn8+ZvN5rirDVt41naLfU8sbYssdyMqUVriMY5aeN
         7WOmuimLI9BhSdWuSH6hmCJW+bgibCNsp1sl2QlVjsXfuWpWs2g++TkPWur4cX39JnrM
         Wr1qANRDnq49Xpg7jUlEYOaH3IyaIXuM20yKtLjXb50WXLLAiWLmoDs/Ib+2PdB32EVu
         lFTZuIRooSCATWadD0Gs+tbF3d4I/VHJpL4lrvQ4br0/ltssO4EqSFPadrBTIY72uRXh
         BgeQOJgtk6RbrBgIc3Gg2klX5kt3MgM2gqVMhAwwsjp+EHxHzI1cMYaLAWExVQn5X8HX
         rwnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="SHj9/QQS";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wvP77JSWso1MppyhzPN1/pUrLxMKma/djPY/AQcjuRc=;
        b=sthCS2o8dMRMgF/o2Tm9sSMwK7XhR/+Xtt/m2pABQTyOCZ8N0xE5GR9Rv6FLfmrdoQ
         4eTlzAd+vFMgZiQO4elxNWbdy/yg2wOSQRoqK8cl4pahBuOlaT4eLF2WjwrRSMO1YaPa
         K2XCTLjlgzkT/UEAam56OuC5d0+AxuhpXXC3wZR4FZHj3jlE/aAFmWAQDa1eD53/9aJ/
         l79bMtuCglqKzY5PSItu6MjIAA/T3BuSXkgZopyHS1eN+Sv24t7meRMWYJiYEApbWAM2
         ABwCrGTD5j9TzVRpX24BnuVh9zWt/vhGdhXAY7MQQAr5wMj8Go1OLGA+4lyCtlEqSczv
         X+7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wvP77JSWso1MppyhzPN1/pUrLxMKma/djPY/AQcjuRc=;
        b=xrJy6ujkUpLKoxqzP/NGLcsRp1o0D87SuB3rsVbpKN+lYga9IkQen6b1HRR9mZ+1jJ
         CSmZBS2bpG8DQ6iXEde512dVbiNBM9GJy55vPDoGQYalOGy8mWUYm0LVA3qZc37aU2nM
         LJXBAI8yqYepCKl0DGuVUpGvmvIaPTrEEwzK9rBrdXuyj4D1wiYdz2XD/TEOLWHgBbai
         wdUSvmYrqYbHwhDz3Oyt09YzAa+4mUMEfGNlm5RU4Hbh9k4MLP3PeL+I9xR3+1xVC11P
         GfJxY++nMtv2ZLJmP15db/QCWYuJI367AGRVSP2YPouEUzSNxzyIodA4orFhmhJY78cH
         l9jQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533+5GSn03rl1Fm5DWdDCIfuE0bxNireo/k3lfnuIiaKJF9tgx+Y
	nQEf6BqQ05TUXxGIA5jAe3w=
X-Google-Smtp-Source: ABdhPJx7s/zG81t0KRoJYeH8kbRN4fKwTUTuY6N1C/gbjLFs3koHBLkj7esaczaGJIRK6l9VHi/Aog==
X-Received: by 2002:a05:6a00:170d:b0:4a0:c6a9:622b with SMTP id h13-20020a056a00170d00b004a0c6a9622bmr25663375pfc.41.1636924943169;
        Sun, 14 Nov 2021 13:22:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:181e:: with SMTP id y30ls4323173pfa.8.gmail; Sun,
 14 Nov 2021 13:22:22 -0800 (PST)
X-Received: by 2002:a63:80c6:: with SMTP id j189mr12344319pgd.200.1636924942573;
        Sun, 14 Nov 2021 13:22:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636924942; cv=none;
        d=google.com; s=arc-20160816;
        b=MnQkG54rEm1Zpi0SGZQFy13ULwhnS8m8XrKKAkNQlxWZSeDbz4uCe1f+jqI5Z9c7k4
         cNg4XqIGO3dKm1AyYPgrS1y8jXOttgXHYxLUFLLLeQcMgIe/sTTeDS4JbVllcW56+uqT
         b6ZCqPAzcqotDjyl0LsdGmGuNPMnhe8V5cw1HyaV9VP09Xp9yReI8NkhN2OBMZULuZyc
         Q6EYT5x6fn0vCQvE1RKpp+q7ONr6HtFYsrvlVH5FWNFdcW5w+zJXCXyE/zfDsqI45Zhh
         1t4Eu7NyEW+os48E4mumtYKZ9JHHn+eA4xgj1ZxS5cWuhme8qXL1o4yN1HJ/Z8ftv8wu
         mYUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=11DJ+3EGRwY+zjHlX1ktluNpPLhcUguE0HO0BXXaTHI=;
        b=wvo8nWjWCoosWJafL/34Jhr+wUMfaQSMP49T50qY62jsOYCvwJXZ6VIm8ncjJe8glh
         cZYSoG9QCbvfBZ3ITO2BtNC/Ydz4MCOKowuqeEIjUFxLANZSxGNFFAR8RfCxaXAO/YUj
         ur4wAMBLe4UDzmg4zocoECb0kFuZQDaB9ymc5meLakVjrv6T7w58yhEsk+UcKWEPtDeO
         JNyC3B2+U5BFZCyA6Hdy/SS29ULmwwVVXbzVL8HGhtCdJXZEzmYHVWBmtLJxdbnb+rSU
         9Cytk93DjkIp4Tus54u9OlnQ79hE/W3rroZsMsTh5uFIpjbwPHUA4iPvGchRu5A7FUyq
         F8Dg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="SHj9/QQS";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id ls15si394940pjb.1.2021.11.14.13.22.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 14 Nov 2021 13:22:22 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 4688060FD7
	for <kasan-dev@googlegroups.com>; Sun, 14 Nov 2021 21:22:22 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 3A01160F51; Sun, 14 Nov 2021 21:22:22 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 208515] KASAN: support CONFIG_KASAN_VMALLOC for arm64
Date: Sun, 14 Nov 2021 21:22:22 +0000
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
Message-ID: <bug-208515-199747-oXrkbp0ivh@https.bugzilla.kernel.org/>
In-Reply-To: <bug-208515-199747@https.bugzilla.kernel.org/>
References: <bug-208515-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="SHj9/QQS";       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=208515

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
GENERIC mode supports CONFIG_KASAN_VMALLOC as of [1] and related commits.

SW/HW_TAGS mode have their own bug tracker items [2, 3].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=acc3042d62cb92c3776767f09f665511c903ef2d
[2] https://bugzilla.kernel.org/show_bug.cgi?id=211775
[3] https://bugzilla.kernel.org/show_bug.cgi?id=211777

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-208515-199747-oXrkbp0ivh%40https.bugzilla.kernel.org/.
