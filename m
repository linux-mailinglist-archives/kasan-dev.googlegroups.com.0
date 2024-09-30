Return-Path: <kasan-dev+bncBAABB7OO5C3QMGQEW4IZB3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 611F69899BB
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2024 06:22:23 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3a1a969fabfsf49677305ab.0
        for <lists+kasan-dev@lfdr.de>; Sun, 29 Sep 2024 21:22:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727670142; cv=pass;
        d=google.com; s=arc-20240605;
        b=i17Z9kX2giwdQx5Oo+5rldYX85FBOwD0vBh9muB9yAXuF13fA8jLSz0k+7ZhvYYiLs
         TEGAIquSkA1Mvo0K4aN9wqPwSwR5jNKTXKZOuCSvsN2GJGKkpCW4Ah9nvt90cpr6y1p+
         /qLkObYSwF6R0MGZNbbMeyYnBcKepCuHFNHoO2FNOXtkp31YvdBdtZIUtNNlceOUsMgx
         bYVkK/6DgcOczXAMbFd2uh4ACUHevyACvpBgxkygpPro3SgsXDedmmBH0SaMENKEaDWF
         4Z6KA/I+IlIvmAUapBKg8U/guHSf0b9Dt9rZZUE7rDyCWbuYv5VE+xRH+ZOKvPZP2n5l
         S3jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=StPjItw8d8i5k3soRLDYQ/NkNM/TquMpBKLv+t5SB1Q=;
        fh=KtwnCYTw9iB8KE6rB0gMwSuq4AwlCqzTRqffhvnE71k=;
        b=jOdKxmq8f7iMms0prfFHYFyRIbNZmUsW/BxF1qZE99yfzOk8taa75apE24pwPuHedJ
         Yfn5SXtMrhkwoI9P7j2q/punZMorQvwbPmGERcDGBzWySafdHMJH5UrgvnVRPjgBKj7n
         x3RebU7qQAwczSUIhEwUzZIEMm0G4lt0G2CTHpxh4JVQMXvBBOWiL62hCDX/3VGH0Xwu
         1OEoOJVgf557rqPDoaVjVH+1Q7gH2jqL+ACQQ/bE+H1O3on1BQdoGXJO+D4TnWR+6sdX
         igFAwVa6RIoGFvhYPW3Ca+wxfFCm6oZ+0SleYmZO2rmTvHM1DMmX/p7CzVXrwNs76OLB
         LtXA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QNdnR8Fp;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727670142; x=1728274942; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=StPjItw8d8i5k3soRLDYQ/NkNM/TquMpBKLv+t5SB1Q=;
        b=sJl3OsxRy2LKLcRuhkXgzQiJ22MG7I99zby06lpkoE04A4bSiCtNhybugAUhglc02h
         QmmBMireYb5Va0uWhu3ocRoOiEcJJirjrOkY+2Z8A5t/mpFejIMg4k7KILB+77rg+3Mh
         C4nVCJKjfjZar5CxM9fDDtySIGmMhXyW+xAD0GJUVZ3DCvSRGlnfoGHuwZM1g1IWuJ3F
         MQjnohVgXjOy4PzEETbTki8U2WT4qOmHtNK7JWd16O257nle7+n9qMm0uI4ldlwkl1iG
         p61o+tbob+6cZmOaw3CI2QTyjF7FoHwGxXMwU9nYVPx6/vdGYsj+ZyVjrO0FNCZlph0N
         5jkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727670142; x=1728274942;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=StPjItw8d8i5k3soRLDYQ/NkNM/TquMpBKLv+t5SB1Q=;
        b=nojFyZ8SmpoN5f+H6xcWG8BzKem85+dpQkV4w2S2q780HFDfKgIWJfDomunwihSXdq
         euENZIqw8Xx8EdR55x8V5cfLqf3IBhUbydA1KghigoiOFa49EEnXr3KLQCXgkGCoPYYx
         FzRjxbuoz/9yqfQVwjbPyrEfnJkH4d0yPxJ6L/PL/zgI3fhsBTYTFfOnCRSzKDiMNFls
         CEZKq+I7fo9jrANRbzotOAzJwbmlQeZiqBTODttVrknAPfmQc7IjVTA6B7hsVtE2nO/x
         mkRJMNeMZ7TdgKNEcgcK4daJsTzNZSysNU8M38wUFnjEaAr8N/M6mwNHpoV4n7mqCFB3
         fmrw==
X-Forwarded-Encrypted: i=2; AJvYcCUeb1SY+26cRiMoF/98XqYDQrIcg3MfqL2Yw7vszZvP53J7WNaXD7bg26C51z+HC2+ZnwSTMw==@lfdr.de
X-Gm-Message-State: AOJu0Yz8F+KMGTlrt5VBihWIshIaTwdmNsnIdp3uid6ynjowi/NWai6J
	xmk0l6PLzsBXCIYxAmTvTvRiphRL2rQ7cZSkq7axGoxtTAysYnw4
X-Google-Smtp-Source: AGHT+IHgL6MOM7qhJcmfj+CZ2M1bXTson0R/M2x8RULoTE2FTJv89Um0spUMRbaHf8Xt14VUz/bq7Q==
X-Received: by 2002:a05:6e02:20ea:b0:3a0:8f20:36e7 with SMTP id e9e14a558f8ab-3a3451af12amr92426925ab.19.1727670141852;
        Sun, 29 Sep 2024 21:22:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1546:b0:3a0:9043:59b0 with SMTP id
 e9e14a558f8ab-3a2768e9043ls24935715ab.1.-pod-prod-01-us; Sun, 29 Sep 2024
 21:22:21 -0700 (PDT)
X-Received: by 2002:a05:6602:150c:b0:82c:ed57:ebea with SMTP id ca18e2360f4ac-8349326f4a4mr865677439f.13.1727670141148;
        Sun, 29 Sep 2024 21:22:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727670141; cv=none;
        d=google.com; s=arc-20240605;
        b=IGD+HLjZWzWAt/FAcTh25WRQHQWGxUYj/5fR6Y0yVPH8af8Kl/ayPgnc5RzHRJfvlu
         x6klUcAAUSC2LCHZqXWAVHV4KejvcOU1WPoC29t4fRmpMovHIC+bBiIAewkxyMwf6Ub9
         of1oFfFOsWttVJPY82EVdphCc+KIK3kP586MU62V0u9rrvmsA/tv2fddf/ozfAOWAckZ
         DqEQjTLusGoQD9FsU8cNg2W4yrqsNP3PwPJm/YJ+DMkQ86kVBAMW11KFtUX88XFtkoCn
         MZfPxRfmCCWrT0pYuGmTSywFaFLe1ZNLv3ill3IFZ4gWkyb/vRjWe+r63XCqOWKfwz2O
         0D2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=3Or1VxBIA0xkUkaNWorQ3BLYCRaoxWua4C07dijfPnk=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=Fw3AgCWORQbMSuTSPIRQjzWwotX4qRf4FRF6BLouBATFm1QIB5q19diG263ZUdqnA0
         IXoc3NDUeBmspm5763xpizgvyjZrS2Tc/pTX5LK4W3Tj6i524w4F6XeGQ1OxdgkCyfLL
         BYMcyWU1MfhuX8cSAvV3bVrwmzRQFqLGXuKMCTIbvnmm8wZ9EsKrP4lRlNSvDE9ZQxNj
         7fe7Qg1dAn0UNq/aUxeqZqSERiYSMZVl4mB1/XFbp7yUIGgdpO8gwWY0T/9tkG8+R0QD
         hDMc418LRNnTG4Mi/IN1GQiLw2uEiyHNqd608yjBvHffcp5ria4WMFzzt1SCSUjiWA0/
         ephQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QNdnR8Fp;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4d8888af650si249662173.5.2024.09.29.21.22.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 29 Sep 2024 21:22:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 8FFCD5C4B06
	for <kasan-dev@googlegroups.com>; Mon, 30 Sep 2024 04:22:16 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 458D4C4CED1
	for <kasan-dev@googlegroups.com>; Mon, 30 Sep 2024 04:22:20 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 33CE2C53BBF; Mon, 30 Sep 2024 04:22:20 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 210505] KASAN: handle copy_from/to_kernel_nofault
Date: Mon, 30 Sep 2024 04:22:19 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: snovitoll@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-210505-199747-rAcw1LbwGy@https.bugzilla.kernel.org/>
In-Reply-To: <bug-210505-199747@https.bugzilla.kernel.org/>
References: <bug-210505-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=QNdnR8Fp;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=210505

--- Comment #2 from Sabyrzhan Tasbolatov (snovitoll@gmail.com) ---
Patch for this, has been merged in commit 88ad9dc30bbf("
mm, kasan: instrument copy_from/to_kernel_nofault")
in linux-next tree. Though currently, for arm64 HW_TAGS
the new copy_from_to_kernel_nofault_oob()
kunit test is disabled:

KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_HW_TAGS);

Need further investigation on kunit test arm64 HW_TAGS issue.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210505-199747-rAcw1LbwGy%40https.bugzilla.kernel.org/.
