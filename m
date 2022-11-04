Return-Path: <kasan-dev+bncBAABBE5ZSWNQMGQEWBONF6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id BD57F61A029
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Nov 2022 19:40:19 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id v188-20020a1cacc5000000b003cf76c4ae66sf4638713wme.7
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Nov 2022 11:40:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667587219; cv=pass;
        d=google.com; s=arc-20160816;
        b=0F44hW88Nn+zg/Mbn8R7yABlWb0ncLiYcoWjJoNSu+duC7I+uSTa04G96agBUtDp+9
         xOWhMEpdNzov7sIf5NEw0IS8U/Sh6q028htn49FUcyISZxXEG9G9UfT0XAVNK/hVZGTW
         U/MZRUK0ZFRnc0RTxBDHS9q/Av5avnImrlcnsbhzr+TDA95OtmMWV9IfsBp+tRxTA5PM
         vDmRfuKGtb4c/ji95/1SJMFyx4oIBuCShvUY+1MGaBl+EuZJ8jydfb5K4OAQVUfYQojg
         VptgIxajcmUp4MvdSEL8g/GIwxDot8/xLphKb9gOjgitIySSyjq4k+UsXrTSGEU6C4o3
         H2Kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=c0UdeciogRDWdV/LzLn4Kcko4n1FyVqwdVmoecCNQV4=;
        b=w/0KWTNLk7ACaXs1AopWFvagNWhF4rFPng24N2lKzRjjdsh3/qs4OUuMPD1UGGlV/A
         rYJpoKAloO7zIG0W37wAeJHwM8IzQkR2H8HM+jyG5xM9kNJM4Kww1YmkSnAsqZXNKAf8
         uhuMKuCCBsa5G4HOq4socbTjWWJqAIK1R0RMt2gaAxWerF83uVW+GCU4PKtJF6yUvJCT
         p6VAIN0uG+jYRB27MClriYpLjrmkPeEt/kzLq5xY0uVN58lQr49dZkvNnqQqoJhrLtm8
         7M+OY+BlaWADhZRiO6BBlSvCELobEVpl2mLDeyXM6oFNkwfzwAVlHm2kMyIsLt4resqZ
         bvrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IpwjcOO6;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=c0UdeciogRDWdV/LzLn4Kcko4n1FyVqwdVmoecCNQV4=;
        b=duPq835kii1NpGv/BOWsEEw+q911mKbdF6NRgrTBqWb1GOAZK+Zsfe0wrqQ0WCKtcp
         Ka8RbXSbLXKFElZuO6xY096P3SbpmABUZiwItt36gfjFr4uPh4GReSJJXjjSFG/E/0SX
         j/T9Oh77o0pntfgUIgMdQBIm8Lt8LcNm5eD3bf+xsir6xVIi1ZxYcslZqYVeX0D55s3q
         xl8u3NsE+Ej64Q5up/vDHmBZAf6pOi6DaTsB08zDOGF712PivvhbhY2Up2e9HlveZFAk
         KBGJGrcAdauCBoOXn8/HsvYQdVw/mEXCMUgVXEE0Y8+QvOaom9U3ZwX9s8zId7zQNEQm
         DZJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=c0UdeciogRDWdV/LzLn4Kcko4n1FyVqwdVmoecCNQV4=;
        b=GpsBLjpqVH4dtkOIfNNZprqUmv8DbcswHw1iO3Zl27O5LXiomBVMB9cLKZe6zoYpii
         Ze8aNjL5NZ5El5AI3FQyQI8hPLd7dJnwQJbf3c9Huls3fyEw3JzVTxvWAxS3XvbaP9ye
         Amf/eD9VTAgD2Fl+ksSOY4e7nV13MfX7ko2g0lHVVWfxcE0oGSfxdFBauTLBrnTXmYzD
         zoHdfzprzfWa9RSI+DyIUcsbIUa+IJ+/LyYuWAmUWPP71LuUam99Vletat85OdvMlF5O
         OHMAHylijpWr0ArN5unLm8I0OYq1OEfrDUA9H+oIWEGW5s8CWJDW3zuiT600IWmPnwiN
         Ec2w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3kRCdRnTwyxFRDhAn38qOSWaiGJ7FRFv7mqKEwTu/6+BtiSdpX
	YBxeHj31mqO1ZYpJK4/w2kI=
X-Google-Smtp-Source: AMsMyM5O3XJHTntF4CcEJIP7Uv1ujG8eW8vzsmG2RIaTmk+Z2oE3Fceh0fkGCpZrYguJMgdRuGyZSA==
X-Received: by 2002:adf:fc07:0:b0:236:6f04:2010 with SMTP id i7-20020adffc07000000b002366f042010mr23325692wrr.227.1667587219374;
        Fri, 04 Nov 2022 11:40:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:70d:b0:225:6559:3374 with SMTP id
 bs13-20020a056000070d00b0022565593374ls6524664wrb.2.-pod-prod-gmail; Fri, 04
 Nov 2022 11:40:18 -0700 (PDT)
X-Received: by 2002:a5d:6dc3:0:b0:22a:bcc3:21c6 with SMTP id d3-20020a5d6dc3000000b0022abcc321c6mr24413431wrz.450.1667587218579;
        Fri, 04 Nov 2022 11:40:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667587218; cv=none;
        d=google.com; s=arc-20160816;
        b=naBB4Dw61Hd27MGIH1fvBnH6/VMS/AXpyFPP9o/RFW5Jw0bnrzo1okrmPgiaTNMhGA
         mOCcyE/aBMfNnU41pUrYJkPZc+G/SNgnXAt6hCXrLcVHNOaxJbxsVLzzhzEwbSDJUIiF
         Mp+EknIa8a8yORvtyNwtSrlrfonHBPA8gueqoVREs/wC6SKyRLl+PCz6/4ORR//IaUy6
         EKjogtY68vu02JxW60pvHgIf0Omh8KZgkpGL+pG+dwApNAD1TUM0VWu+7YxqkfEMKobt
         nlNyVF/9++N7ZfFvWxb9rCDwJYxo+LY996/RzMywyPHHElmmY+dUQsx/aHxyKRxYdiFg
         yuTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=qYJwOczrdrco49wItn3AeTkai6S4gQs5fzcTP6TVrvA=;
        b=XpKD8wfyG4EcL0LDJTqe8i3OuxZ9NIPf+ruw2JsPMfRjF3L7p1F1rYK//XGoZ6ApRq
         1+WL/HbRsPBr5rawU0yn6ax9LFziWkxSOvREHZv/6A36xCbZv4i/BaVPdTWrsNCFPEsR
         oZpv337MYe3L9DLTQoGQ4OWCheUAEXJtb+V3Usc1hd/DuK++lmaNb2vMeSVXXZA2URHJ
         eP1F4C1vncNV+7hkTz4clPjOFuy1c8rHyj25NjLzoOq5unyfGRWXy1RFXCryzqP+Ijpo
         L07tmjvsr0zfUxD5uhIQkBB7TL3enQFmshvj8KFLcUNIpAlSEyZcNyfDaxbYGDUWLZcN
         VoyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IpwjcOO6;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id bi5-20020a05600c3d8500b003cf567af88esi141937wmb.0.2022.11.04.11.40.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 04 Nov 2022 11:40:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 2FFD2B82F0E
	for <kasan-dev@googlegroups.com>; Fri,  4 Nov 2022 18:40:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id D5CF6C433C1
	for <kasan-dev@googlegroups.com>; Fri,  4 Nov 2022 18:40:16 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id BD471C433E4; Fri,  4 Nov 2022 18:40:16 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216660] fail-nth: don't fail own copy_to/from_user
Date: Fri, 04 Nov 2022 18:40:16 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: short_desc
Message-ID: <bug-216660-199747-z2Advep9H8@https.bugzilla.kernel.org/>
In-Reply-To: <bug-216660-199747@https.bugzilla.kernel.org/>
References: <bug-216660-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=IpwjcOO6;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=216660

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
            Summary|KCOV: don't fail own        |fail-nth: don't fail own
                   |copy_to/from_user           |copy_to/from_user

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216660-199747-z2Advep9H8%40https.bugzilla.kernel.org/.
