Return-Path: <kasan-dev+bncBAABBL7N4K4AMGQEFGX3ZZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 45B719AC1F2
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2024 10:41:21 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-3a3c5a6c5e1sf68309115ab.2
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2024 01:41:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729672880; cv=pass;
        d=google.com; s=arc-20240605;
        b=g9jErPKLOAohYDkiFfZFl2kXGfB9OlrJlRDa4pHlhOJmK2GxaCnFnUVjFixcyzERiO
         Bx6jROjdPMWzg3ax6Wq8GfRYQz4BTRfIeUeuF4UE4VPbqIHIXbf8RWmojWxwwPMQ21MJ
         BYzjJs/rB5RRMu6+/+HpPzSoLfs0KM4qfAutyzwwcvgj8GsMFLTMmVh7QLWL2mOdPKjM
         CRq5tnU5OEI24Tmb1rbdSSud7WLPYYQZ0RhMeR0sGM5BJpvk7EvcqvkhYmTBjV0UpVoR
         QL0Uypxlq9XYnc1TcxkyoHBbv1MxArt3gEAdLd0p1FGj8hw1tnnSQqsZMvY9o/dKa8vL
         Zu5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=3ZL/PWbhKnKi5oe5gyMD0AslsLU49Yxzhj69vSu9REE=;
        fh=wOdWEVPtKadZ8MiTzV8vhyyPNh0tGYh6tr/H/oi2D4g=;
        b=gsHNb+RrOaU3omjFMcRePEKC0TKLPWYIH/1LgRSyZlLpL3Q+M0KEMSKD3jsKJqUKcf
         fByK50uOsIWIJo1qtUyhHQII6Kbid27gSZKrDTnDBIS4JceTw0wz/B1Jnw9DeyV6gK/w
         ldNTfo2bJXDXxzaUXV5/u6ZhICQtXEiZAfFhxv0rawp6/CVkMG/GEYVfrBGEgSGVuYUx
         W8D2bbiEnas4lnIUEAtUliiRgm6HKEzB/WjgJIX1u2L/gz0jDnFUEwUOk25T4wKc7Jnp
         jGbJ7v7eTDgzNr3JVMcyQjKTnPuZSBa8LCutN4EdwDgWD4k8XOKKn02lZ9Pj1LTaPI2J
         Kiaw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=R2JWjCmm;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729672880; x=1730277680; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=3ZL/PWbhKnKi5oe5gyMD0AslsLU49Yxzhj69vSu9REE=;
        b=AndV1qboYTmdLbJ05hOuVEE+lmUP0Qmg5DePLmAFSiqOr6Tf1NWadOlLWw3Psh7l6I
         9CMVi9P85Bh9jG1nAtWMEqzmWghnB3j/XfzgwVMRlnM6rB8rjDhMJHqMw0cC/UNBZS91
         E3AOT6wsvLXwpxxYVcL3xPnSFEMYQbkGEHGCawua8tDs+nQj+kQ1qNrdgrNnKDTEu7AM
         PBFNMknqXcVBqWLydZM2N8GYbvWW5V+TrSiP80kqHsWaMNT2R1jdTqn3MeopeIELlPND
         6Rjf4KbeTni5rQXVeqzx4cEeD56epRqB6g94uM7aTzkhqpqdQwZBVAKuE1xj5zlyR/Al
         xSCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729672880; x=1730277680;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3ZL/PWbhKnKi5oe5gyMD0AslsLU49Yxzhj69vSu9REE=;
        b=sfrQAC8dr30u3jSnazLa6mt4OMRTRGpu7pb/iLgZ18LzwxKqgXpZXDUd6rN4LvRBfp
         9AilcjGHDhzJerTR9s0oukpT3P2wViKy9FD5f5Xur/mZ8EAqgw9T40c/lAi8M8wcaKwW
         vbecmV0FiPp3LdKvn49XC4B54L082dGHjamWej5IXnVlNKvQ7qMV305FmOIH/VGM1MB4
         TI62rGOt8jp3HZ4u841hHsWpr/HGJmmZCpQuvmcPh8CeWPJcwJURYdSDhWvZEDDECd9e
         1YI8F7Mc6wGC0NuD9PpghtrOCabBC86bfzt9TIJqS+/lVjgG7PvGkKV1foLeA5I2BK65
         yUIw==
X-Forwarded-Encrypted: i=2; AJvYcCVnJ13G/I3QTfqpQL8fgzbGHzKZ1MHcVIoRgnTsUzVPlBEDxRh/buBl0WQuanwIdDUX590w3g==@lfdr.de
X-Gm-Message-State: AOJu0YzSCc3b3jL1ljSv+g4KW1Ub4OfQZNWc1cwbg5MvmPdCXDam0Tqr
	tTsmedn8PTI+9teuoaBlUiFgCgE73BpKVZHj/l3ILVJFz942bkA+
X-Google-Smtp-Source: AGHT+IH6rijTBpLMm6Iq+dkRMgSfwPJz7tvdrtzf9S6NlWfk+v03d9L4bvlguam/Zsk/qcj+893aXg==
X-Received: by 2002:a92:cda2:0:b0:3a3:41cf:f594 with SMTP id e9e14a558f8ab-3a4d598fcaamr18550385ab.12.1729672879723;
        Wed, 23 Oct 2024 01:41:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1485:b0:3a3:daaf:d989 with SMTP id
 e9e14a558f8ab-3a3e49b776fls11515235ab.0.-pod-prod-01-us; Wed, 23 Oct 2024
 01:41:19 -0700 (PDT)
X-Received: by 2002:a05:6e02:1fed:b0:3a1:a619:203c with SMTP id e9e14a558f8ab-3a4d5a11e27mr20067085ab.23.1729672878991;
        Wed, 23 Oct 2024 01:41:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729672878; cv=none;
        d=google.com; s=arc-20240605;
        b=Icd+yi7ZD4RQfpv4m04ZoDbUxoxtiHXJEkgVnhZtIrnM3qE+Uo8G/nN5WPdKflzn+R
         QD7pIQDOS2DsaBw7F5S3J9UFInyuxbAV2PLYXLKHAjVzUtXkZJCbOKn2wlxTGD+2MxB3
         saZm4OBtP4c4f4gUejSurtz2t5ylBwHBIZAKoolkl3Hiih6lE8i4O6R/UWUL1ffeqAJG
         Mh+Ekrf2tyBki+BR6Np7YWKA76FS+zl45bhcDNM5kyrYmyN3Cmc4LqT+c8BvaYLEDENM
         vFPI5CF7+sNYZXm04zkDdlD+Za4QmMrRUcj1q0gVyHXXddMP1Kyr4jZQqZTEWStQNbJW
         NKAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=7ZNyguhpnRjgCz01V99IV+K390VJCcWdIUhLSrXtl9M=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=PKIrCqlIweWY5fcPBZu/CzjO0HdY8eturmARPOQlnVJskueZ4p9TyZN3+On4pP2jxg
         ufVufHaoJpr8F3qD9zl0dcMHsQY3uZ+teKTa0GmpqtZLLqfuaaVmvFVHzW8tTTrv8Wgw
         hQBxCB+9qgdtgLiRQvlSwYoh8qEww/uAkGmOU3x1pnHTSpLanFm8Y/qQ+lqFa7RW0pGF
         lDR7wqh8EYPtEfelzYlSQvff7K4NOU707a0QkCGxaJ5zPO0lTZli7AvyjqpeJTtaTXtp
         RnQTQxlhMVmuON7sJIlTVbaWgTL/ivRUOdKtTelSnw2GVIl6p3a8nb2QyP6dAMdfm52e
         ACrw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=R2JWjCmm;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3a400aa829asi2801925ab.2.2024.10.23.01.41.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Oct 2024 01:41:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 181B7A44C16
	for <kasan-dev@googlegroups.com>; Wed, 23 Oct 2024 08:41:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id E018AC4CEC6
	for <kasan-dev@googlegroups.com>; Wed, 23 Oct 2024 08:41:17 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id D3C89C53BC8; Wed, 23 Oct 2024 08:41:17 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 218315] KASAN: use EXPORT_SYMBOL_NS to export symbols for tests
Date: Wed, 23 Oct 2024 08:41:17 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-218315-199747-UIrHKR5XDs@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218315-199747@https.bugzilla.kernel.org/>
References: <bug-218315-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=R2JWjCmm;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=218315

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Instead of creating a separate namespace, we can reuse EXPORT_SYMBOL_IF_KUNIT.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218315-199747-UIrHKR5XDs%40https.bugzilla.kernel.org/.
