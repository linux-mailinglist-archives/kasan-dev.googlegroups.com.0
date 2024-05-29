Return-Path: <kasan-dev+bncBAABBG7B32ZAMGQEL25PDRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 46EB68D4185
	for <lists+kasan-dev@lfdr.de>; Thu, 30 May 2024 00:47:57 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-2bf5bb2a414sf199501a91.1
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2024 15:47:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717022875; cv=pass;
        d=google.com; s=arc-20160816;
        b=TjQQbgzYShXcIeCSrGOdeOAi6acKQ5jYxgFzAQNu7mdA9Fy9g/IDdreifcZVsx3nhk
         X+5V3as6JoIOINIIJaD7q6OJ/B1zKm8WwPJo7oXf9aoqx2V/9zSpWe9MOAhI9S4mwQLd
         lLy0Bs0ecdZ3W9hUI6Kf96NklcjpBnAsT8xCu0cPf1mXvr4Wp/cyo8IAEP1UjliK7i5O
         oXdn62+PfmKjHMUX6MC8lCxN1cnVvYbTixUBlZdLaGhr+Mr5SSNhxIFl2gPOdAuOn39O
         RxW9YY+Zba+Bqo5vAJS3jAViLsPE8LxAZfgxb/lfMv+I6kdGIv4ID0k1cc6ccBihX6IC
         2Peg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=Mvm0nepNKNmy+a+n6/1t9z39MOG7eeGuqx3dmRDdGiw=;
        fh=nJK+uORpzT77nbZqqnd0SEuduE+n407CF+slnn2yCOM=;
        b=MCi2TLQClBl0UWSmdF/IksWcbSNPem0gA1UDgmC6zy8mQM5dXFqn6Gdxo7PEbn4qhb
         dsHcBif/fp9nxllyMZOEFB5b+nUcjdSDTkyvxn7cFXZHPEQD9dp0BhianpTpNBqN9khH
         y6ZfU/TL72xrc4WdvcxM8RElARdb1yA8H1/DRwVuz+Zr/6qgd3cr2a0GYrR/tpcYT06z
         X+GhTwPeQWPVcfVuEWInzUWhoUkv1wZav83q+DpjwnmGWi8Mt3xlZ2h661bCDCTgMVCi
         dZQsuWNqeMDne3BDQGrghTxcqrZPdafDLDwfw5zq82vjFPxBRTVCFUatpphkpEUiqYUb
         4MvQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RV8B5f0K;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717022875; x=1717627675; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Mvm0nepNKNmy+a+n6/1t9z39MOG7eeGuqx3dmRDdGiw=;
        b=O+N5Z77xgFCqXceoFBqyUadQdnrx9JMaXsrZEml2OrGFQj0Loqr/NwiO8XXswv9vSa
         VUWSihXx0t9fJ5Y/X9lLNnZlQg//3az1bXCyh+j5K1+2uJErahin68d9lJBmozuRSbHQ
         eOQFLhXtL3MFOJSivEEtfFlWUO871QU2GgPAAc4LsDjdL7jaO5fh/9faBExZKgWYlXpv
         S/Gi9a9bAUYEJ0eSdwdVeRww4VxO3sV4/6SHflA2+SVUo5/pKa92pEs7W130xLBlODFl
         9X1kPnYKgbGDu393bBzjYpBSZ+vpkz6AfdKiXM+b+Op/tTfNlwDeHkGMTIVv2iMdfrWM
         aw7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717022875; x=1717627675;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Mvm0nepNKNmy+a+n6/1t9z39MOG7eeGuqx3dmRDdGiw=;
        b=MEvr21X9utzhPxus/SzMD/xS/LoVrh40mH9rjRftL5trXMVeMRoheaUaOsBDF7md72
         ad9WL4uzqbZg+csLSn/I3c1q6tx4Cv3l0B//Ht456PZc5rKEghA04Hpz6LMeCOy+ZClm
         IcSIRxMPzdpSjZQS6bLYA4NjdjPvwfC7SBgA3jtpZsbepqu50UuN/fgipPOrBO8Awwz4
         Lul3h9cYISnwNwF4+F/JNNXMjn5m49gUakd6OfkkBPWeZNJigUkRpEdunhhSngis7tqn
         ZDuRFJ/0scbXHpR8Zw0uKW6woznOMsVVKDlO2xKAmDoI0D/FpSaLCF+KeA2ADokklHlp
         3AIw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUDo5J7CJP0v/34N099FrGPGxMxCG7oxwMcXOc1k9pctLTV+OSHEkO2VcmZ2YgBsx7/lspzHNrLeWv3sawTdwlKucK4exSQZg==
X-Gm-Message-State: AOJu0YziRyC11SppYlTmk9z32GwE/LkxUN4/anW6cdQpnoHdhAp89TqZ
	3qxSscMQIpXVy7LvJAcHMBa4FTWf+qrjzTQynij45+srvQSDDsog
X-Google-Smtp-Source: AGHT+IEXflihwphToGu5b7pUR2hC7GVtki/4VAiR0PWUV6zXFiaY3PXn77VBRg2r4qDRQMfSiPkCrQ==
X-Received: by 2002:a17:90b:a13:b0:2ae:6cc7:23d8 with SMTP id 98e67ed59e1d1-2c1abd7090dmr439129a91.41.1717022875499;
        Wed, 29 May 2024 15:47:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:9c2:b0:2bf:757a:5efc with SMTP id
 98e67ed59e1d1-2c1a7e5c107ls140544a91.0.-pod-prod-05-us; Wed, 29 May 2024
 15:47:54 -0700 (PDT)
X-Received: by 2002:a17:90a:e2cf:b0:2bf:7d98:77e7 with SMTP id 98e67ed59e1d1-2c1abd715f5mr417150a91.44.1717022873904;
        Wed, 29 May 2024 15:47:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717022873; cv=none;
        d=google.com; s=arc-20160816;
        b=efaCN7LN9nrRoUiaEBs3cUYbeZ/Upjg5tCkgc09Yd0wj7lTfcHq5UQPfBEaB32O/mE
         Dfo6042DhVh7BW1V/9w9gu4krksmyFL0VCj3g7ci+nXzuyN0MFKOzZDjoWSVIAxKegR+
         ix/kUGQxBJziJ3mf74vyAf+kuAecxwLi1a+jc35mjXZ00fkAFr8niRNA91QH4H3ywYmL
         ktlbclK7UajLH1Wzjdh9RApaT7H99gCOkT/5iG70AhqLRT9/sdimxqD2ZRVpLdzm/s73
         JW2vkaWXGmpX6T+HCXzsXXin72fdbkZn/gZyvjZW8hJYWURySsRTA/ssIbf6IJepQlgW
         kfQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=NVPGLBsn+y2TUwpwGODfi6N2jD3+e87xYKmAoPWCgP4=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=M1KGXcHgHDkiPU8oTeZP4H8yPp22XmN0FeXsZgOLfTC72jBzuUErzYAguSDqbr/5zM
         nTZ6D3l2Fv0bsoTq+os7IqRh8v25V7X2hPxudOFxOIKC5BhMfkTg5UYLc9g7SLqpf0Me
         Oxa3A4kFg/ppf20obiV/PbETvNWfftL4WXJ+ZsxWWG2OD5rN8RGVi1sB0nwTORfFKjHI
         lifV4O1WZLy5+VSuGG89igj2/GL0O+YsxrT/74D2Knlay9Mre4EpyCQTjziGwSi6jya1
         +fnqYK0xcEY9kwoLIK+7V78yrMTYKIz85znJjAdvcn6npNDDWlMRWWgc+jbydg2Qd/pq
         zcLw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RV8B5f0K;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c02df5386asi226163a91.0.2024.05.29.15.47.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 May 2024 15:47:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 3638D61F9B
	for <kasan-dev@googlegroups.com>; Wed, 29 May 2024 22:47:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id DDD05C32781
	for <kasan-dev@googlegroups.com>; Wed, 29 May 2024 22:47:52 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id D5664C53B7E; Wed, 29 May 2024 22:47:52 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218887] RISCV kernel build fails with CONFIG_KASAN_INLINE=y
Date: Wed, 29 May 2024 22:47:52 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: jason@montleon.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: PATCH_ALREADY_AVAILABLE
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-218887-199747-WeJMVJCNJX@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218887-199747@https.bugzilla.kernel.org/>
References: <bug-218887-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=RV8B5f0K;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=218887

Jason M. (jason@montleon.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |PATCH_ALREADY_AVAILABLE

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218887-199747-WeJMVJCNJX%40https.bugzilla.kernel.org/.
