Return-Path: <kasan-dev+bncBAABBTONTO5AMGQEGF5KRJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id C67EC9DA4C6
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Nov 2024 10:30:55 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-212617bf5easf77405715ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Nov 2024 01:30:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732699854; cv=pass;
        d=google.com; s=arc-20240605;
        b=cpPIfD7tAw628S52bluouGzAvjw6dfsBxC+vsZUVGjweRSnNyhmcMnDgXCyhFojDzK
         zjBgk4xgDFCtL/YxoH1Gnrww9VrPRwZwlJ2jV3PF2hHOBy4Rq+TbBDG5vwVnWiGCZJpe
         s1J8sTOfFHS0FofeVHanEDrwBiEiB8CeSaih8TM0uAu+iUEm7PePyt+Kr9yufR9fB9/Y
         0MqJQE2o1TTMyLQalNdIpQ0HL1pcQ5i198dAHiLw9N6nwUdKsBCMsRMWKe5QylLVT9Zu
         nyEDKEWGKnktjd8Vlu+2IjEa3uiyPV7rNldTl4p9R7tEXM/SP1SM0FJiptMAeM8fbFny
         AjGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=2pP3xrIr9GttanPLO+EMEqJkpvjY6qO9hcvqd3XUnJ8=;
        fh=8afkPsFgFMC3YqgtBsK7MXw0c/WJRMneehWChyu7QOM=;
        b=lpzDyiIIyX8Y2AfJMCUG1S8DKNU5kfPJ1FEKfcfLegKdTM8cXWgtgLN4hlhqx5cse7
         VcED76zrW3uxPX976TZlkQT55hdO4p/RWGq4oCQ+HKYYubJ2pQz8kziBBg54Y57cLgrw
         Lh93OFXUNNJkKNX0zqBEPHvaJWvVNAWr2fbRa+mWPgD3HguFowiYDT/j+xpCeewYT1St
         pu/0rMP2ZHyzC8PTmc45XKAGVd29sKedOl4F7qmeQdHiCrJe6iYYd7lE/N4RsMfUi6zr
         VxeOW+7Y2LR1u60s+uqVEEXhe8MPqPYSLH/TBlTkzP7iAh002fhK3L4JEECQedLMNzMF
         ZFrw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=EqI9WtCB;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732699854; x=1733304654; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=2pP3xrIr9GttanPLO+EMEqJkpvjY6qO9hcvqd3XUnJ8=;
        b=cGVspLRCnq4rzIiHPmaUfsG6+nrA2KIkDR1EDjidpVwnTb2SE9TJbaZcOAkM0t5gEe
         +5j509Q7Xh8gRn2eJY07BQskI9grE6uFjfKvYiM3wozcPHYMcdJGRQDVKk3b7aXx9T/k
         Ay+tVlQwFJ2aIdEtpcDvg1XdV1+Z+d8nSiceCdz3Psv6gGui03zWUcucQGiqfmfCxgaw
         24qUxWrMF9EcpFnFv+cJVYcegup6Iu3A9f16O4gHFw3dBna+qvKuOI4tOc7l2Cc8qh52
         bCxht1gUBLZamva9GjrKcZZVB5u7gQCmz6uMF+GZBayf5csnM3VgCJXqO/ZyF/Ib/uix
         KM6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732699854; x=1733304654;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2pP3xrIr9GttanPLO+EMEqJkpvjY6qO9hcvqd3XUnJ8=;
        b=AqYTo6qiUA7T4CshSPXw3Ex9QuwkVZO/15ZTgg56eCOS8LymVxiVD+cSyuycgcw4Mm
         qB+EB5DS6QYqtXJ9T2xjmWloKgfVZzQxAIFSEQMzQCwWH4hTM4HtvNScRl584GFtbsAb
         Kpc7dsYSjprLru2exqLxYopDWgZn62lxbrB9cJEuDKoXueJuEXDzsREnOMvVkXu7Db8/
         VV8+qfojJGzoIg4GuiPoYyGaeSieHI2EQd03/QwfeN4pRqZptaNzMNuC8WeMDLubHxIT
         pSPgQBhJ60vmrTGe/KE9eTN5DaMC5wnK/4Gxr7OF2i56SAsmKLIj3h0tTSkuv9yb3O90
         j9RQ==
X-Forwarded-Encrypted: i=2; AJvYcCUWLVcERWzCpxJRJhsqTLtJbqCIpFf87zOyAkprHSyyEi/23MPT0ahObpu6FUwTV32CTzgXFA==@lfdr.de
X-Gm-Message-State: AOJu0YzpTJbASqtz5yHgk8jU53oKZVsABkC9uDCEwaFPKraIJv3GmUEK
	UuPw9b76TRaCRSuOOWf+BFofFR5QWJ/N5A+EKVoywms/yaSjHdKU
X-Google-Smtp-Source: AGHT+IFathLrG801K3Q+IjrIT8qEWp5p2E+wfljlFspjXNLUhqrc932GsOcEFMhSk6X9VjoRMNytHw==
X-Received: by 2002:a17:903:2b0e:b0:211:ebd:e370 with SMTP id d9443c01a7336-21501385f12mr31129575ad.25.1732699853802;
        Wed, 27 Nov 2024 01:30:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:23c4:b0:1f7:38a2:f1eb with SMTP id
 d9443c01a7336-21283bdca11ls38317585ad.1.-pod-prod-03-us; Wed, 27 Nov 2024
 01:30:52 -0800 (PST)
X-Received: by 2002:a17:903:1c2:b0:212:5b57:80de with SMTP id d9443c01a7336-21501f63200mr25460985ad.49.1732699851707;
        Wed, 27 Nov 2024 01:30:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732699851; cv=none;
        d=google.com; s=arc-20240605;
        b=gaYTI5thL65/qGTy1v2su6W0rml8ZqvFFFtvjUBdrSYzXUSeI8LFnx5H1a8j9OILnZ
         I7/Wk+908ffGqgJA/5fjxtWI62n7i/grRDcfby9V867nWWtGHqSubwgu52pGv/2mPzdR
         8//iLLENqtsoJR7XkI8gz+yvtcBu7zhmoEUWaxRHXNZ1E/A/rnOUg00oDTHkvNxTXT5T
         zQbbSCBrXLymz0SCqVLKx5aGaXz9n2quiYtAN17RpuB18zQMMG1BiPnSUIWHz0vYUbdY
         xBWpDpNOWUeZbAfCw7zm13ev/15i5yLg9H91lIrk3a8mfBE7It4i1TofntPbiTOqc6TT
         p+Lw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=mAY1JJU/nToIId8wRzT4q89thn67fZUcr0dgy9A42H4=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=YoV5/JCHFgw2D0cbvwIbw/qgbvvA9A+P55rzu/WWLdU8f6/9vriJIZOD22RhZsIQDW
         vKnsqhB6ocWOgSY6v8avb6b+qMsokvCTOHtDZbqXqsP0zC80SotKZ0D2bQjwJ1paE6XL
         5ThXarGRxMyufMUzo/qYcAz5SZliaaOghqU3/13JW3wjwJoAu7ZuL8ZjZ3129iGGngXv
         YPogpPSvhxxiIiRLhZbn7BFGqdDb2xONSDF5aflCRTpqmD3QnMBBWiLDg4AGyHTVdSkz
         8Ga4jVsosTeYDswNTEHiZg6z7NFcQ8/E3Z2Dfh72PAXamaTQuUoP0o6K0dFZahPTRKJB
         G0EA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=EqI9WtCB;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-214f87bc260si793605ad.9.2024.11.27.01.30.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Nov 2024 01:30:51 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id BEDD85C5E46
	for <kasan-dev@googlegroups.com>; Wed, 27 Nov 2024 09:30:07 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id CE87FC4CED2
	for <kasan-dev@googlegroups.com>; Wed, 27 Nov 2024 09:30:50 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id BC7DEC53BC9; Wed, 27 Nov 2024 09:30:50 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 201177] KCOV: intercept strcmp/memcmp operands
Date: Wed, 27 Nov 2024 09:30:50 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-201177-199747-9NmIDYjBno@https.bugzilla.kernel.org/>
In-Reply-To: <bug-201177-199747@https.bugzilla.kernel.org/>
References: <bug-201177-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=EqI9WtCB;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=201177

--- Comment #2 from Dmitry Vyukov (dvyukov@google.com) ---
Yes, I think it may be useful in some cases. But if you want to work on it, it
requires prototyping the syzkaller part to use this info as well. Once we know
it's indeed useful and we shake out all interface details, we can upstream
this.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-201177-199747-9NmIDYjBno%40https.bugzilla.kernel.org/.
