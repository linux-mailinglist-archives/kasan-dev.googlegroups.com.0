Return-Path: <kasan-dev+bncBAABBO6LS3FQMGQENUM3YOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FB52D163BB
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 02:54:05 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-65b37e173fasf15932349eaf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 17:54:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768269244; cv=pass;
        d=google.com; s=arc-20240605;
        b=WUo9g24VEgc8/KUhZbOEGDS3C0lUz2mHMjgWZlPLJh6SSopbfliYmx6SGr5tK+rgkh
         lT/YSEjasKWmDTYxJBfkUZLGtLDmBPk5KV4VC29lwrLX3OWFci7IhiW3+wmOFG41Y6jj
         58qia5brfHgyAtV2QjAlPPUwp17jYW3gzU0boMQA5O28+8oAzEFd9AmGCT3hK+2GR+OG
         ux2rbZ8vgopBYbG4lZj8wTQwPNZBlzGBT/cZ4dmJ0HoTeq6Az566wI1WwKBIZizdaSB+
         xL+VAfXsYIhj9P927LpNcCHNXNn+gOuN/riy5VxrazF0Nut+k0mQX8lpSPXOxNfpdhQ9
         +Gww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=cspEK8PNCkCriMjpFAUbe1u+UM4LHO/Ub8DSt9YVEFI=;
        fh=JdAYlUc4QvNL0JGEBLDF6a7/1mbMoL4/8EjW2WBwVWc=;
        b=KUrHOrpJEsMbBH1f6PymrpPrz0uxf5gbRo4J/8UROEWMBYNYhjIVAGPDeJDCqNoBFY
         W8eKmMLrUQ48LP0tNw51Y0VBhPdGMaa1RTuTv1xLDYXRxoU1qxSdTrKyX9PrbD4bUKw6
         0eNgpBWW1edNSWYh4HKsKeLi1L090CIrUkfiziHz2RDcoos1HuA4IHmZXHbWOIssrW9/
         Xxk2vYrxOIE6uQxs9YgEmsT1NtsJWpScpbR9JFVX/zU2Xv7nobxOoTftDs35WyEKOfI+
         MR/XJigO98cmncGGFzo95kb5H/3AGLao9B4ywOiz8GNKyUgj5L8NbjfPDBum+hxN33LP
         I/SA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SM7+R7tK;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768269244; x=1768874044; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=cspEK8PNCkCriMjpFAUbe1u+UM4LHO/Ub8DSt9YVEFI=;
        b=uR7T+lJWSL7/xnVsqM9yvJoAaEzUCkR9IuT1Fty5TyZPD3pgNIx2vcQDc1ElriiYVU
         7n+NPJoXXoyWMPxS+vj5yMv8xmcnA9H3QM1fiKf0UoAMd21q3tmbJjPE1/jyU0BVMzEK
         +iwP/y9yesX6215U4R8aFHxVE5qVEWMzgIZz94zJiVyVXHinYRbf5UBYP1H1oTokZLON
         JUX1niTcEU4212uSEvLepFgxtbGgC/VmmLBbqGBnWngjlSOCHDPA/GEHmGhgbXonsBnE
         K8K83r1J6tZOKbmUs3DPid+Yme6uwnU4MxMOHJpsO5LEprq5d7wISf/fXU7vsBJaMwHy
         MLYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768269244; x=1768874044;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cspEK8PNCkCriMjpFAUbe1u+UM4LHO/Ub8DSt9YVEFI=;
        b=rDr3ZZ5d+raJhc3B6TFKOG5Za8iJTLE/P4cA3f0/JQz8ivmzd07ZyoXVgUukYchWEz
         S3NFv2Vj7RFKpCbWMhrFsltTmfY9CNuY7t7L+hVVjDpPlrbpeleU45K2v5sQEkrOAaOO
         KNsw+CrrxNZnXSa8/8TDQyZuo7PSYZPnAzglf3JzFXuUYXAnzb5w2eY+ynEX7KQWSyfo
         KkZ4W7X2MRSVIdg3xxvJ3k4xEBNjN6oEhqJdXtagT+Fj8QCmAuFy9POApM4vZ1mF8Xs7
         Mwl8LUPMuT8ygPBdGZrkVgIX+fOwUOybAMnCShwR4hLWTYJFwlPLaLfMPIbzhdcur/4S
         UWwg==
X-Forwarded-Encrypted: i=2; AJvYcCXUb7qoemGdiG5Jgni3JF3i6IVfe2T68h7p5kutmbECNFDXUs4ETREflFIoohzcPq+N9/nTCQ==@lfdr.de
X-Gm-Message-State: AOJu0YyPmUdzSsV5TEZ7vkSjd0UBmX2403GucLr7JI0wjqZM2lsEJ5VN
	PBwNSg6D5xWBCkcYCda570JtAIMwWzwZMyCJcT+44kEoiD0t9IS6CX9Q
X-Google-Smtp-Source: AGHT+IFD0r3NRtoKdGa2vv193Vwe0SxYgLHfE2foNd+Iv8/UljOxRJ21fjL4TjHwzlVqNnLv6CBsRw==
X-Received: by 2002:a4a:d4d1:0:b0:65d:dc8:416a with SMTP id 006d021491bc7-65f54f5e819mr7424297eaf.46.1768269243692;
        Mon, 12 Jan 2026 17:54:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HpFFvFGqWQp970t+co/Cr+3phy6jxVdRyNFisn6NEKYg=="
Received: by 2002:a4a:ea94:0:b0:657:906e:22a3 with SMTP id 006d021491bc7-65f473ce18els4226900eaf.1.-pod-prod-01-us;
 Mon, 12 Jan 2026 17:54:03 -0800 (PST)
X-Received: by 2002:a4a:ea44:0:b0:65f:6759:991e with SMTP id 006d021491bc7-65f67599c1cmr4643725eaf.79.1768269242892;
        Mon, 12 Jan 2026 17:54:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768269242; cv=none;
        d=google.com; s=arc-20240605;
        b=W4gsIYuIyAaojc8uqeSMHUt+okABOIjZZP9EmZuxuHNHa8jANoZAqJZlSqvk32Qr3L
         VMHfDiVDfTI7tYI8EVnM7c9M2UkSZNlsJroHxDWBdFp8PVpUCs0DTtWpGY/Bdx/rfFsz
         mNmkUSt0JaltxfSbn5fzZJN5f9uAYbE/nkljDMugMYJY63BljwIRvJvakKM0/O6ZB69W
         D0XsT4IRRnZqzrzb55pOrfgXyMapzIJB8KxHVI3Kbmd+445mkrMqWWs9pX+n8vmMuy/Q
         hQSvmnnJ7Oq7oDndXBnXvEqfF5B7uBgZYWWm2rc9RZu2H2yA7VRWNYB/SylnT8RP32XM
         pMYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=bnPMwSSogByQHlf5Jph/Wu1mfrQMoYOUyiu8qf4p5y0=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=iiEeHMzStP1QySFv0Bc6ITCPFtij4z2+CKqKJmuTs8fu6YtTPiLJL7a87nwgUV6ZOv
         UPpESWKf2GilwtSbblVVWdaj8mN51gWOql9UzSpCwsQQONi5tAfyn7bcJem+XsLsBxLt
         FLPQ0zJE4NJczlqw4Mfm0q63wi5RJi3PzCk3ausIAJ5ZMxoYzD0J/j8NS/TdQuX50eMm
         3ne7p7fhsG9SzH8vQw6vn+1Z8BTKD5x2ONs49Ywb0tF5FOsMS+HTi7cUoSnrXKsFOOqc
         0pdspdIK3x+AUIQ/Vx34Suo8mQzTwxRwbg7MK8oF0kCXk9ct+fKvXEpKfhTnpiheZLAs
         JUTQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SM7+R7tK;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-65f495913fasi655656eaf.0.2026.01.12.17.54.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 17:54:02 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 3260D6001D
	for <kasan-dev@googlegroups.com>; Tue, 13 Jan 2026 01:54:02 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id DF05DC2BC86
	for <kasan-dev@googlegroups.com>; Tue, 13 Jan 2026 01:54:01 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id BD7F1C4160E; Tue, 13 Jan 2026 01:54:01 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 220889] KASAN: invalid-access in
 bpf_patch_insn_data+0x22c/0x2f0
Date: Tue, 13 Jan 2026 01:54:01 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: joonki.min@samsung.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-220889-199747-KqeYjxKOiE@https.bugzilla.kernel.org/>
In-Reply-To: <bug-220889-199747@https.bugzilla.kernel.org/>
References: <bug-220889-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=SM7+R7tK;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 172.105.4.254 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: bugzilla-daemon@kernel.org
Reply-To: bugzilla-daemon@kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=220889

--- Comment #6 from joonki.min@samsung.com ---
This issue is followd by  https://lkml.org/lkml/2026/1/6/779

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-220889-199747-KqeYjxKOiE%40https.bugzilla.kernel.org/.
