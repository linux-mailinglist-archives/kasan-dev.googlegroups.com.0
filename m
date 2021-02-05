Return-Path: <kasan-dev+bncBC24VNFHTMIBB5W662AAMGQEFMXWWAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 561803112C9
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 21:49:59 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id c16sf7444085ile.1
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 12:49:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612558198; cv=pass;
        d=google.com; s=arc-20160816;
        b=cNy0NMbPV8Tk810zKQLkeV57g0IcbCLc3oCzbgjxMCP2+gvk5ym78nKdDSY1AbP8ho
         37hHOGXXSPZAggaIMxLiQgKnhTAqk4Iebq4xcIshEMwua9EtdAS3HIK6aOgp8A2YAWhV
         00Lfx25RpLXHY5mSVRb/Cv75Q99XkYjb67uH5MvNSnjlMre4IC0vxJ1dnB8rDTdWz6Ym
         Zs6moJkJ4NlFakrJN8LIYjU4NBO8ZdSrn+eKFYHRpPsoKm1pwlnPwr5pXT5kn3uzXCkJ
         qGvkZ02o5CoKSguy9XDsNeHem3m7kGDQmmpbArO+x8W3AJChiu5Y97sHtiqohQKsPxnX
         P2uA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=9exekqi+eK2ebJzI1mYpgKj2miD1JsnHOVI3IWo2UnE=;
        b=jKG+8CxVAqV+uWZMxJ0Djmj5HIkbHz/TE7p2BFLyQDgSXZZ6eSGWx1XrKZFRWDqUZ+
         0d80sZemD1dUDxQlG5AELeAKuEWhuOiDkAnY2IJ8OVhNq3DioZy/RoASWv8j1xdTJkOq
         61fUP3NmOel/+IERYFvZFYpSS+Ghe8m84UCQ+cRmrS8FHN6p5LEqpBPEV2NBP9DIInnh
         kghsXMZauBtV/v85xwS5rmRIH1qUvDVKLMZJ8whpOJ5JiIkYa4Yr+i/2bgP12NrAhY5w
         Wg3fRHhp1NJHwiBzC8i5UiHF2OWU3JbSJ5/vkNaTO6dJuMu6xDrU1TgtdVUi4+Lduaxv
         9J6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TzoYg3+z;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9exekqi+eK2ebJzI1mYpgKj2miD1JsnHOVI3IWo2UnE=;
        b=UkK1RDIUxtanYEELYzT124pwQBNshZ8y2QaYVq+D5fbr1Q7Yiw+C0En87KpNwJdUzI
         gsZzYqTGORf14b3UtGJSGhfzFrW9UDf1ZadRfY7yAHj0efsoe04DjwdZa+cu9ljfdG8B
         KlOlJ7oeSydvTAgjfSoIJ5BLtfeLhvFEzLt6Gef4oGw7YVId6emG8yy+Edr5knMBCtxd
         naAKZJgBilLuBpxQZfv2y1tPZPhf72NA+ReKooVsT3HHfVUTVPVELlE5TsIKmcjnhDQn
         Y9J5K/UN5nWuhVmb6Yvxz7yrnU0KA42k9w0frPEjQJAz2ZEowKM3/tl1+C7DW4yXPdVq
         DkdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9exekqi+eK2ebJzI1mYpgKj2miD1JsnHOVI3IWo2UnE=;
        b=Oi8AXh6jYEX/yZCye3xnuQvea85LE57X2I5teTK+T2U18tDTcI1iWf6kHg6ym6ig3A
         uv800aDi5d6Du2XndqVjX6a8WRZS0J+RijUeztvpNqCB0L9BcdYeZiYauKh1IDs008NJ
         CY5auSEHtYdUfasZDxLjf3Lhn+Gyet01KWYKCg/szCxha0o56cP1iAxkm0A3y5928U1r
         fHnTN9M2BxYQaS5VpHF6IX1ctinSvrUtlW9vDsIC0rXSWp2PW05lsvziq5E2Xd4O3nXM
         UtyoIOvWbexNq7sFQrY7gW3GgYoGSZy7Tp1LiiAuBr/Fb0u6UYi4A4j00hVzIOunJZrl
         1+Bg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531inrRJDU63sqDl1RfKDTBIPTnHIG+D1cm1PIvxIhSLqKIga18H
	Piz1OwmrHEXWAlo/iIJ8q3Q=
X-Google-Smtp-Source: ABdhPJy7GKWoUzL0RS8eVv71RXsSZM+vXA+ZUzus7U+7lIKm6RqD2S4OvjxDRcqeJA4+/Ie8mSW8Xg==
X-Received: by 2002:a6b:ed02:: with SMTP id n2mr5868064iog.80.1612558198140;
        Fri, 05 Feb 2021 12:49:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1385:: with SMTP id d5ls2577723ilo.5.gmail; Fri, 05
 Feb 2021 12:49:57 -0800 (PST)
X-Received: by 2002:a05:6e02:1a0f:: with SMTP id s15mr5737766ild.244.1612558197713;
        Fri, 05 Feb 2021 12:49:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612558197; cv=none;
        d=google.com; s=arc-20160816;
        b=SOf+bOCBa4WVFgAED47eM60nLlY8Q1mwHgR0N/PJDzvCBxxfJrtLaeFpa3z2Vd+UPq
         2mnyDSNEySBlzfDeKB/IqlRT29KU0rQSNiPxoTD+A+aw6vAh6/Uyo74g0T+vYeuGeCaF
         f4c3/4Ox+zKCpi5j6D+2NIlkq65cpQj3wHal9T3rWoNz+cD4aRLYakAM6rk6aCS43a/h
         B2JChsT57WLTPbvLNC8XpkMSsNlgUWLUxKakYzuyIpk786XIIlR3BrFQ+HGSFuS6/BRx
         x6xhScErdX+Y+5zdxyp7a3CqnIaVxnpY8VqMzZ9eplEeJ3Ix8veJuMT60w9fMKdQLgky
         lcSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=SCxKlXqxP3J38hNWKItmbkyh1tPwRshvorWgxuTclKI=;
        b=VMO5ZolDC23QDnArrXrVXY4BgokelLJNzwNxT3ou56nn6SkP73FdAOZDpJj0pwdxUn
         W7F92h9+LInymAkq2nYvoCFVAKdwhovxqOSwLZYkqfXIURTjA10gkb90K2EoRJQs/SFY
         KgL4ya4H9/unPDuXfB5grgjLRdT0XX+bDkxlyl0mTdwkMttrxLMTe9SexLkhQotR9HBX
         JhOLyHxDZf+cV2/igxVLqrtpTxExHdEV5ssOYOjjfS0DVvsbfaE67y3RKyc+4cvcgGWL
         SO2CIkBnGp3XzLPCamYr3aufDGakchVwG9aPugD1Y+EzO8X0ESv36lPiLzheu8HPLwXG
         uOMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TzoYg3+z;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f11si588219iov.1.2021.02.05.12.49.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 05 Feb 2021 12:49:57 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id DF96A64F95
	for <kasan-dev@googlegroups.com>; Fri,  5 Feb 2021 20:49:56 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id D06466533E; Fri,  5 Feb 2021 20:49:56 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211581] New: KASAN: invert VMAP_STACK dependency
Date: Fri, 05 Feb 2021 20:49:56 +0000
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
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-211581-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=TzoYg3+z;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=211581

            Bug ID: 211581
           Summary: KASAN: invert VMAP_STACK dependency
           Product: Memory Management
           Version: 2.5
    Kernel Version: upstream
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: normal
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: andreyknvl@gmail.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Currently, if a KASAN configuration doesn't support vmalloc, VMAP_STACK will be
silently turned off. Instead, we should make such configurations depend on
!VMAP_STACK.

Reported-by: Will Deacon <will@kernel.org>

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211581-199747%40https.bugzilla.kernel.org/.
