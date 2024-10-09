Return-Path: <kasan-dev+bncBAABB6H6TO4AMGQEPQ64SRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E217997846
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2024 00:11:12 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-6c5984bc3fdsf3782646d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Oct 2024 15:11:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728511864; cv=pass;
        d=google.com; s=arc-20240605;
        b=CHsdddRAGzHysgGc3Fmeaxy8Nvf23j0Gp0xf36z/YXSMFJYpTWD0lIWnttCvZ4gpL2
         TpTHkcGIpl6M0j8lK8E4TaAHHAwJKSuHql8gCRY0K+VBG7z8L0PwJzU6GO8PmTbRoiJt
         98XdfurNEug5UBRFd8JJyYOdZBpkx+OgVw9DkEhYp8lx0Cq0lE3ji6GSMQGMciIkwkcq
         M2ermiJ6Hm/Nd3vBGhw4ZzC7yIb1kdgSz35MReDDkoMwB6w3lJYQHSIORWs1Urmxd3/x
         nlEYhJl+ad6zIt36+0Sw0BWseT/Dbgix48Jb+49AnDt1TARDR3dugMEqnXbZiAndi2Ex
         +nYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=+fUW0LscagwPbxEBh/PGTRm6hPVCOzsq970p0hFTSfc=;
        fh=eYUxCVVY+jq2VKZF8TgxMFYqyJH/9DVkcVlnHuLTFPw=;
        b=cwTIT/libr4uR9TTBD9B4amoHbp2a2FufHH8gxQIegG9bFvl7Imhn/C92LgN9b2SBS
         ve3pIDUXQsG+jzFI+fY0wIzEzdkC/uXiT00xzkG5O4v4VU1OXG1RD2CKndRP/pzaVA6n
         0cG/1cXZOUMJJXdpVgP09vjnuzwV6KPLZ6TMVesDZ3R8f/7y/taHAs3HeILjgL74MDs9
         0bsvVJThbCUI472JSN7IFmCmtbeyA7r8/7lxYZ6YKBXFVIku5ASOontgPd4hPy0aAFGj
         2tAYiUzkFJ7V/Di/y3CqWQv0O3XUFOTCTSpc+gS5SFR0ZJwuzNZv39eNZSGfoZDHDkEV
         mADQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rBMXU9r4;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728511864; x=1729116664; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=+fUW0LscagwPbxEBh/PGTRm6hPVCOzsq970p0hFTSfc=;
        b=nB2+Pgr4U2KQGbUZiLXyzHYBltzjy497b6Ku0i/KPBNQCd+TejtXnYM/iFg+f4SVk+
         DR8N1v38FAl92vxckSgSG69QEyMDwW0tQCCfOQHOHwrSylEe2ntNHVhH1efXYpZOr8Ie
         zqtyik7BLTA1cRs/u22rr/oehBQ7kfXdr+jEHJKvQTjK6p0gMLFH/xMcp740taQdSP3Y
         bd9J+Ri6cM3/sVGuLREFrWpxCq+RUrDYeV9Id4w4KSDBPlKZZ4xni1KGZqkS0qinlQfj
         vrh+zOH1cFrfABPIo67DYt6n5UstvLzrcJf5/lPJCg8AdSCVWtMDsPCk5Fdtuo4mYSsI
         jevA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728511864; x=1729116664;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+fUW0LscagwPbxEBh/PGTRm6hPVCOzsq970p0hFTSfc=;
        b=hsaCxUrWVg6c6gKYpk/6TAXar54EdGkvl/Yj+uyQXzM++C2/78tSKuGxe1cXTz92/N
         7F7h9D70wdeWCSYgtLGzrUCKXtShRkYCmkE2EHHkc/TDu3vcKrAObHiO/lGwhbtE5NWm
         p+Yolpf18nIdq67koVHXOvCKyOA1QDRn5Yx5NORkpyEQQQ/Y+XOp/5wL2+wfwnj65cYO
         SnAmMXZD4U1M+D0caf25hohz1FCtESNmi2PRMFe73grVHUyKz9zji1IMMLXiHh3gdPVJ
         3cxW5Khso3ZVnZYjKKJ4yFFWik8gQ0MrEijVixn/l0l6/5qMhSYdo+uIpCph6iv4p+2E
         UZpg==
X-Forwarded-Encrypted: i=2; AJvYcCXkZF9O4Tvt9W50KCKZhPtk1wCNKT3w7e1sPjUPlkZbzD7Hi4I2gcCWXvanz+HyDEvAlWKVLg==@lfdr.de
X-Gm-Message-State: AOJu0Yw4kOOj4P/zSuHmUq76yNgppBUYJdj2Myr5SbBneFmfK/lStA9V
	TQVNqS0lgtKONVnhENfsuvvA3mXj3c+F3FP4svI76hdaTDB+BgCV
X-Google-Smtp-Source: AGHT+IEGn3no+ViLvdOAhE9A1aMo/2HsGlVcD+bVdl6aPr60h7du+Ie7RJ/8kBNsnO8MSe/NpRG1sw==
X-Received: by 2002:a05:6214:5b82:b0:6cb:e6cd:82fb with SMTP id 6a1803df08f44-6cbe6cd999fmr5111766d6.22.1728511864129;
        Wed, 09 Oct 2024 15:11:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5c44:0:b0:6cb:d466:e169 with SMTP id 6a1803df08f44-6cbe566e9ccls3743586d6.2.-pod-prod-08-us;
 Wed, 09 Oct 2024 15:11:03 -0700 (PDT)
X-Received: by 2002:a05:620a:4611:b0:7ac:a0a5:9bf4 with SMTP id af79cd13be357-7b0874b2ecdmr510637285a.40.1728511863370;
        Wed, 09 Oct 2024 15:11:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728511863; cv=none;
        d=google.com; s=arc-20240605;
        b=kJqnDi2WdE/wWyYYY5CuVLIoS+ZRmgCtUuGno8b4sktQ53XVjWXAnsCpi7TEr9qK88
         /vzpB459h44/BWtnwUhSGOo6lm2EIsG6Q4EK6JZwxAp4UWrhTh6HRg/HH4i1btqJbBtd
         d3CveZXjEEZooolvVzDfMlYrotNzxALejGzaLp20tccQWJFAJsSDccOlb87Cxuiwq6QI
         J/p5z7Vt0xfSjrRskuTrPcbA5nmWYGz7jKIF0tWDbHV6OJR5RU3w5xtQfVcOMk+n46r0
         G5AtTDaKsswvt7QZ8m32Ae1A3tbEn/tVjyn4WbK3GWKbkAU6z65BnrPqWOyjUYByijPd
         n3mw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=aQm7eP7NdqkfjTupCIy24FfMcZtxg26owCrzBa8O2p8=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=lkHx+FEFywBJee5rDM8vHOMicuMMd0fRD5z6F/XG2CBdXmyRViTI4QB12keMkOs8LH
         1KiLOiONf1atlDbag+yYrrI7MVbYSdyjyDBCfRi0xpSPtKLrsqvelJ99AOofvWl9XeIi
         CLwOTWIsp1em+jvwFBeiUGv71W2cpaGDBBCHm8tPtWvFgW24y9zN2pLUtCmvVwNefFef
         upWn7pykwYt1FGVquJCT3ffDqvXNDtCn4qYVqc7l0c4NsKQgG+zb7/7VWMiGoL4lEZlC
         VUiVQWEvwxSEfjfeXqodyjbMd86LZbZ04A2Y5uMCKmROH+7oUnRNfBsRiXAm8vkr4jXf
         rraA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rBMXU9r4;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7ae75669910si43177585a.6.2024.10.09.15.11.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Oct 2024 15:11:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 4792AA438BC
	for <kasan-dev@googlegroups.com>; Wed,  9 Oct 2024 22:10:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 879BDC4CEC3
	for <kasan-dev@googlegroups.com>; Wed,  9 Oct 2024 22:11:02 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 7905CC53BCB; Wed,  9 Oct 2024 22:11:02 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 208295] Normalize ->ctor slabs and TYPESAFE_BY_RCU slabs
Date: Wed, 09 Oct 2024 22:11:02 +0000
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
Message-ID: <bug-208295-199747-zrf9u0QCqK@https.bugzilla.kernel.org/>
In-Reply-To: <bug-208295-199747@https.bugzilla.kernel.org/>
References: <bug-208295-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=rBMXU9r4;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as
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

https://bugzilla.kernel.org/show_bug.cgi?id=208295

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
Update: Jann added support for KASAN checking of RCU slabs in [1] via
CONFIG_SLUB_RCU_DEBUG.

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b8c8ba73c68bb3c3e9dad22f488b86c540c839f9

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-208295-199747-zrf9u0QCqK%40https.bugzilla.kernel.org/.
