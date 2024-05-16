Return-Path: <kasan-dev+bncBAABBLXITGZAMGQEO3BEL7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 073C88C7DDF
	for <lists+kasan-dev@lfdr.de>; Thu, 16 May 2024 23:01:36 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-43dea131affsf42321cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 16 May 2024 14:01:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715893294; cv=pass;
        d=google.com; s=arc-20160816;
        b=B4GhRUp+kB++f+XcIjC/cahC9HUYy8olwB/mIitw1O2zlMTT0HDYSQIlaf9B1cs8lk
         P9o5cdBymaNjzySu2DPW79v4+GA8Hico7YN5lQkYmCETOuUSqzareHjpwp8OhIlQDX0Z
         2oroqOpQpii6ArPRasmO5367ZQ8qLjlBlC4XKjvbCl6fJNB03+PK62new1Q+eaEg5w1j
         1xayS6+1AblR4whLZpQMal79RfQo6XHSEPcnJIdlUzksWrd/ymbEEkdm8+tX0iSDxNiD
         Sv4YD8dCHvmRYL+dzPNxbElaYoNlfIiEc6EHNLSR1pX/KBSNYPIIY+CtGUoFiPkvi2D9
         fToA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=dvb7rd/+pu8zGzBLxP8inWqrr27v47ArqE7QT/Nl2ic=;
        fh=YTbBzGxj7xbcVCW99xZb6/79fvgAItgyA1SAXkP0P5k=;
        b=Qr+WkKcHNtqv+EbO9eaXAhVuSOHmqjsnOhRwfLJYigw18KXdeZNXLBQ7wbuL6zfPK6
         g3EL4dgSKZxF1V6ZMXh8td+oZ7cdMdaY1chV1RvPgcbGcERY9ua5R5s+/QtO5yI1XWX7
         vLk8NeYjeoQSinB2T1liBuYG0pkQREv3VmfYwNGbbtQxU9WDbsPXnHCipR10kOLC4aBI
         dxdIguuiyoLPjBLhh+1RJmy0c/yVtzaLCe27YJtJ+h3ILrgzjPauDa5zkU6T1Fx9irCr
         11VM3kp+GR82IoNyyC0t4sIzcEJ6nmvF2a9GCY9Trmz2xxuLuZBJovzRaAquiWwAKoLs
         y7dg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jz5xZrbl;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715893294; x=1716498094; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dvb7rd/+pu8zGzBLxP8inWqrr27v47ArqE7QT/Nl2ic=;
        b=IQ4HRlx0A1LyD50mMpPwRF/YSe/ukBmV5f4+2Xd6airtoIwbaVllkSQu2veAGtLOyl
         gkQiuAHGOJL2x0xKqO/yQIutQ9KBnlyWyKwMWHPQxDo7Ap7Q4VcKnGEx/SO7n7a65jpK
         HqRJatXoJWM55KClE5Ujllo6x1fPzWnzIbvZzpvkAU7eh4vcDxPOv85UoboQSvxUDy2G
         yc3e9p0S2d6b4qixpBU+4WuTdydDZ0cOczbnduuOUOCPJGWRebP0celmVPDtfjLc9ACe
         FQhZMvmSKIJp3Rs36yxvW7ypucmPArxhQc5JA0jbw3PJB+ZuvtEy8mpG4CVMUTclVZe7
         qwQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715893294; x=1716498094;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dvb7rd/+pu8zGzBLxP8inWqrr27v47ArqE7QT/Nl2ic=;
        b=NKbccAEQomROH1ApvkCtLSAObU+oD5ZZrl2Zk3O4nlL+KVD9CBWhJCDUvO8AhM21pN
         sL6nYRtUNHkm3zTcGVFiZ6uOibDpVO1F8N0t87/5OwrQb4246cvZAM/dmjbqJV4yvgvC
         6KjdotpMkhjMLk3Q9nemejt5dRf1DBtB8aCnEZLkMK+Ui4BLjoXvz9d8c7CzfFkwdhlL
         ZGgx+iQnWBs0XPKFNP9J73BQ2OBFpYwpCL+GG/3wN4xLPVNVJxEol7h1BYjhluWHkpmW
         4Gmsbg4EAD220SDDQ12DegiCGpN4d8+ctwDzdBEV5aoGOEMHc245OxDZYv1EJBaRa4ZF
         58Dg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU7D26IPksAAAPVXrfC7vasUbLZPcmkYPomHIfMo0RUv7TgFZWNKgXDPXUyg6jdyKs4ysNgetUhDtpzOfRkl5KvPs2oLjFYfw==
X-Gm-Message-State: AOJu0YxtQBqJzl4n4FdhI5lYYprVbcIlPH+PlEBzykaBj2kNrQEDYGd/
	6bdEHehBL5L/kq/OzY9XJRjtnKUvDZd7CkZQuO62E7WuAjGhf8SL
X-Google-Smtp-Source: AGHT+IE/CW/bhd3U6VlzGt4fpMve6A/ve9qt3+lp2GtAOW4tKWYwkA7iXSyvuL800XpRoFSvd3at2Q==
X-Received: by 2002:a05:622a:428c:b0:43e:295:f160 with SMTP id d75a77b69052e-43e4418b350mr690121cf.24.1715893294510;
        Thu, 16 May 2024 14:01:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:d47:0:b0:5a1:2a2c:9ec with SMTP id 006d021491bc7-5b26a79f8d2ls46377eaf.1.-pod-prod-09-us;
 Thu, 16 May 2024 14:01:33 -0700 (PDT)
X-Received: by 2002:a54:4818:0:b0:3c9:63d1:6fde with SMTP id 5614622812f47-3c9970cc5c2mr21367598b6e.37.1715893293714;
        Thu, 16 May 2024 14:01:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715893293; cv=none;
        d=google.com; s=arc-20160816;
        b=PKmOO+3Pa1H4VRT6PyX8K5810w5nwhB0D9cRusB9DPFbkBKlruSwDWbKxtfICSOo2I
         fehmMoJOKxZvHt5KQ/XpLuKjzasHAnmD9V7F2WdhtguGE3GT301wv7xqI/Ho8LtQw6h9
         RrLfzezFTOWWHtAmoK1fp7jCHCXWS4c0uDkRj+ZtmiIVB75kaTsXKpzANzUl7kbUNBgV
         Omr8up9kh/v7Y1zG2P5CgEl2ihzRQ2XgImYbFhAyWQqGE+G5oNoJaDd2p+O+Khc+dqzD
         +z0MSFaHuzIgRHfvZKTwaWrns7QF2XfwXCI6xbvboBXAd6O3Orn+VKJx10M/S0xM9PHn
         Cxkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=kGxOqjDRDSVgmPiwPYBfzeHVkx1e8yHz3a4/lt4a30E=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=qRRqy6FHnlici4/VK9mTcBk+Jy6M7DUJJifqYOHaBDXs1dIURo62QKja8CTW4nVmZp
         l41CgdzjQMY2rJ2z85qsv28JuewjNzaOmtQ4AvODUOtRxLOu0bdHJ/7WjT5c/Y+/HgBX
         YX5AYuwKIz1erLPGq3i8BrWRxwO1OK7RgLngiCatIv72zKwtARdh4uEqfQPu+XDnHnE/
         yK7q8OUSfS5J2w5062wzO1WfQuzzMMbrDla1sfBeP+d/XjhtBDQX5PxnM/PGmZBoTZQH
         WKHHYfEIjSUWuFpTqUPs2iMe58oPXlKwXZtPn3tE0g8kKDDTZ1eZHkTgK8j7mErR1BPe
         Perw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jz5xZrbl;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3c9a41b82c1si820778b6e.4.2024.05.16.14.01.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 16 May 2024 14:01:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 742FD61775
	for <kasan-dev@googlegroups.com>; Thu, 16 May 2024 21:01:33 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 28D17C32782
	for <kasan-dev@googlegroups.com>; Thu, 16 May 2024 21:01:33 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 1C33DC53BA7; Thu, 16 May 2024 21:01:33 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216973] stackdepot: do not drop __GFP_NOLOCKDEP
Date: Thu, 16 May 2024 21:01:32 +0000
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
Message-ID: <bug-216973-199747-LafNKeCm30@https.bugzilla.kernel.org/>
In-Reply-To: <bug-216973-199747@https.bugzilla.kernel.org/>
References: <bug-216973-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jz5xZrbl;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=216973

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Fixed by [1].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6fe60465e1d53ea321ee909be26d97529e8f746c

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216973-199747-LafNKeCm30%40https.bugzilla.kernel.org/.
