Return-Path: <kasan-dev+bncBAABBC7O3GYAMGQELFV46II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 954BF89F094
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Apr 2024 13:25:01 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-2a4b48d7a19sf2824586a91.1
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Apr 2024 04:25:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712748300; cv=pass;
        d=google.com; s=arc-20160816;
        b=xFtnl7liR9lHf1qnIDtz+j0UDiqqf2XBi5iDFux0toTw+fZCyeHHLeddTxvle/7s/o
         uSCYrjS1lZV3/rREUGL7qLt54Niscs6QXYsfcEEDBhvClxRlsf6ZzQVDZWA5VxEj12Ko
         p6U6/Ky1tHXuR4fuTm8Gxu9iiAQVWY/zZK71H2CyMeFixixTO8Y24iJFdMHZPCBCG//a
         +Yreyhny7aCwpvkHRfIOffMUHukvSqsACv5u6pBoTOIbWLTxZEgJ/SXSPMMyNjAxo64l
         XfBduMsyHu1J2gyDw1Z/AbuLZ6rKj6GMRTJWPqlMdqaL1JpBjpGP3WCn1CuC0bc2+17b
         0whA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=BQF06S7w+cYdIGvyoO2kjccRM09G+M7YQgYJSXn75xk=;
        fh=qy0np7W+64kmYqNpVpTc6kjZ7U8in11/D2p+6q6swYo=;
        b=WHdfYoU+cNNQBVK3tFHvEiyG1kflT4sm0o6JF+GUIRv2ZfVFLCrZHVFja2as/fd80F
         r54B6SD9SciUk/7udklDNJZquCEosQXCwM5otXVzbGaJcTT8jbw1CW3S42vaS7nFp3YD
         MPVt3VgFZ8OTAbZ7LUvmRbKgNrKtFYVKGyxrkSklXKuY99qYMnh5uCMtGrCs+Zc2WiKh
         310crbR7tJZk1jlvkhulFSfMKfVk3o2Jyh7hMVtENp6PH/l9hJljz9r7rDa0rdFPbpQ5
         eGVZZkaQvCH9AeCc0pCLos06gXMQ21x71CMe/+WupQ87r1zjsrsvhpFFpRc8ri5OMfBt
         8RZQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UIorwFQJ;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712748300; x=1713353100; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BQF06S7w+cYdIGvyoO2kjccRM09G+M7YQgYJSXn75xk=;
        b=TchnTKpQq0gUKB11PRmkaCbjdxAjnmY7xkPLaDR1oHa0qcuXpZhtbaLXXOMUszQ82i
         oaemWDmspluUVdWNK42J4QCKXUVfEyWjlXKZT7T2J7QbBOtZPzJ1rXPTj5dAdJwxMNcI
         rP0BIvPbENWzy6DocKmwBCvYLKncfWPXynq49PAAoi7xQYqmUqF2LOe+3tE442xkRBKM
         R90nwE4DU/2HSr0f/Z/YCNqfwEUaV0BRZfe0MHBmYAJPKeNjVOicmQy+AwjzC8koDc3W
         WhcoJCehWsypNijMe377TInSzgxZnMREHsVqrzhKbvEfc1xtJO6vP1+e7LTOeItVCf15
         V7Cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712748300; x=1713353100;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BQF06S7w+cYdIGvyoO2kjccRM09G+M7YQgYJSXn75xk=;
        b=uQde5Pb+5t8dNSPfVWNp2i2avUvbxzwNq4NjP6sImwxuYjUp6g3ld19RMjSYz0FeK0
         DCxaaWPD4+kGZvymLGecqeYic5mTUNTS31zC9ajZWIjYirOcgq8abeGa/wzoYfKiMAo2
         4UgOsVqyPKPFdD6V686pjeU9o1TemgYGwlon6H11ZAQxoRfajwgN26jm4dJ71llkb0kK
         lQ4wLqqGI2UDy7L7m4plCCZgcEPZhIam0L0LHAF1YTEKoBWGf9KZK5g4mFVpzc4UJNM7
         KNYfXlGnc06N5Ow3m53XEpEXDve59BpzBLF9zfWwUeEvZM//e39aX9xu2IjB7jdJa8k3
         o/mw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVTRToHdHIsvCBtmqVZ1vvSC/mBdrDaXzcjCv0i3gvz9/9sUSZC4JsbjTLYKiYp2xAuabzNt05YzNPX0FlpDkxuAJT/gAJTsA==
X-Gm-Message-State: AOJu0YyACmWcL+zTBWBbCw3Zh528U4H6s9ndPd3ZboFSIJ+HiC+42+ew
	Uh6p2HRinfpEogTPt0Pvi6iQeKSZa3HU0x7C2/rbUZHorsQYUnmJ
X-Google-Smtp-Source: AGHT+IFLBRBgksKAH7GNgKkFULR47oq0IUteDvIuVe65gS6pTcNrBwEUQ77O2kpB7Q13GyZoYvrKdg==
X-Received: by 2002:a17:90a:702:b0:2a5:be1a:6831 with SMTP id l2-20020a17090a070200b002a5be1a6831mr3020912pjl.19.1712748299963;
        Wed, 10 Apr 2024 04:24:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:fb8e:b0:2a4:ed93:1d82 with SMTP id
 cp14-20020a17090afb8e00b002a4ed931d82ls1800745pjb.0.-pod-prod-00-us-canary;
 Wed, 10 Apr 2024 04:24:59 -0700 (PDT)
X-Received: by 2002:a17:90b:3592:b0:2a5:6e51:f009 with SMTP id mm18-20020a17090b359200b002a56e51f009mr6780235pjb.3.1712748298907;
        Wed, 10 Apr 2024 04:24:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712748298; cv=none;
        d=google.com; s=arc-20160816;
        b=zYYw3rMEYks804rDoanYUxPgjlKX1nGBDJtZIGYCIt0nFXLDjNypIPNGxcc4uYIpAK
         YhH3g49TOmLCazW/R9H0twQVOZccizFhpU4GeVdnSrpAvdmQ89sYPNzYr7k4RlZlToDE
         Wpi0AOfvL4rBbOUbJqeutWXm4PzU0qSmuCCtDY+Ba+VWBz2qwPJPPpRQPfmwfpsUj3Ec
         tXSLCtALbROAEosJK5iPd8UWnPHtGklIcif+06NePyBcl8QiC8OaMSpSDpWZX72iDuDn
         IxOClodpKdZpZrviOBmtXNck5A16kl5jxgWWTefw6yJhVVm9aSVN8FoHBDiffrnUrgs6
         OFCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=Xq1D/RtG9N+Y/kinRk0i4tU9OpCj7dOpOFDfVy0H8lw=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=xxGK/4kOLOpVu1zPEplZgZjiLMrxaJuTZSfXt9db0Bmb1xwLEQcffgbGv4CW8kNhYS
         IMFkfiZMHBmL+rz5TQ588mybHbp70NUCt0gL1XnOUchke2yynKYgsg4/omqYqi9lYP0M
         bMSHwvkiWS5SHJhADb2+GzDO9i0ddhbxlivoOTWarFSaWAUP+Ze24dGRk6njg3G7uXoJ
         EsFJy6FQ501Vl9XXLZ+1sQdlW36kAP4hGZU+KpQ0+MzZvO1pos60xja1k7xioH2zUee8
         nsiELZCjegLS+IkFi0zqmsi6WggpxhcVgfTha5J+sx/pSPHUkfMqZmjzozmAz7POyDCT
         NaTg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UIorwFQJ;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id k35-20020a17090a4ca600b002a499886dcbsi512687pjh.1.2024.04.10.04.24.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Apr 2024 04:24:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 35343619FD
	for <kasan-dev@googlegroups.com>; Wed, 10 Apr 2024 11:24:58 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id EC694C433C7
	for <kasan-dev@googlegroups.com>; Wed, 10 Apr 2024 11:24:56 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id E7401C53BD9; Wed, 10 Apr 2024 11:24:56 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218703] KASAN: make compatible with USE_X86_SEG_SUPPORT
Date: Wed, 10 Apr 2024 11:24:56 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-218703-199747-neKfgGWWpN@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218703-199747@https.bugzilla.kernel.org/>
References: <bug-218703-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=UIorwFQJ;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=218703

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
About to be resolved with [1].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git/commit/?h=x86/percpu&id=9ebe5500d4b25ee4cde04eec59a6764361a60709

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218703-199747-neKfgGWWpN%40https.bugzilla.kernel.org/.
