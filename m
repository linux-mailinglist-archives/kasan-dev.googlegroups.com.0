Return-Path: <kasan-dev+bncBAABBQWNXHAAMGQE6L6ZCOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0446FA9E40E
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Apr 2025 19:17:57 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-3011bee1751sf3490165a91.1
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Apr 2025 10:17:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745774275; cv=pass;
        d=google.com; s=arc-20240605;
        b=jDvNbq9mvfpe3hPmeZSjtI1hC8r7KHIJVbUszRUZQxvAPPYT4IpBbXNquAX8H7V/xZ
         j1RlZq+DoS/lMggcKEsJC37amarPQVlb5QnHRhjkYCUmVIn2RwIvFkCM2S+yx//pKt45
         QBdx9hSdsp91YWX86g1TaNSjN9MemlUD/VmLFqmbxYbeFT299xvqgX34pS+3efQrG247
         kZ5Xch+9/ueaC0wsCNzRuibCI/+wsOFRlgl9NejCrV3m7IsWKKH4oKlCQ5zju/XT70G6
         1vM1TReMVZM16Hzf06fd+Ga3i7O5kYBTtjPjZNMIlBhOdyEMkgpjwq+rZ+DSyqaJEHF5
         l2Sw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=H5PjRUbOJ429nykuNOQNpsY9pVNk6jXNhSUVHUamaqU=;
        fh=9n3f7f4pe/5rIs3+miT0kGeRr/ubuSZ8tFBy1o2UojA=;
        b=HBV8uNTggvgLbzQGaJ33batOOoH3g5Pjr3KghS7dNGZmfqCEI74qM6xNwdySGTMP/j
         BW2XCdsVLZ3HkjDCuHiRVNYGqnNfulnE76muYB/rwXatEQsjDwNIQBSeGIGMMfVMBK4r
         Babf2HvBh9d+CkahINMIdUQK8pmqnwXPYoOyHi9MPx+rwDS9DhnaYNDjVih/+JO0oeEb
         ESpkmKbdD/3i5RtohBhq9nafiSeRBSUa3AzuP9PK52tlKM1Dg0gJbTpTw3wmeEKLUljY
         eJyuVWrlTYli0WcWS3yEWpXCahPbYeo4eczcLSnNxWK0EM6okyxpZkBDyTNiBtQek8Dh
         dP0Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Isz6dX9U;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745774275; x=1746379075; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=H5PjRUbOJ429nykuNOQNpsY9pVNk6jXNhSUVHUamaqU=;
        b=SjIy4+LMUnwCgkJqrYgL60C6s54d28uDGYQ8oOBbBKaIudbW4H46W8a9bE01Ku96ug
         +2NHtbb7MeKPCuaeq4bG+4xqXUj5lijKLzI2Vt1Z21UTeNEwNI8kvWkCXxCL4ctx4fDt
         maE1WR/9rwVe9GH86BNjW0zI/eFq6L8/i0Dcdnt5CCie3B0bXKbIWKQRavEn3RvQkopm
         WWujH3/37VjJeWpOjSoOJnI+Qg6QpsswilFOlwVL3kTztUBFbeHo3ecm4R+x6YHNGd0Z
         aTseNpAWrFft+zGMVCTXCRKOYudfG56pAFjS7fHM52986Mlwp8AL5F/GnGOmNv4DsA7c
         vEfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745774275; x=1746379075;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=H5PjRUbOJ429nykuNOQNpsY9pVNk6jXNhSUVHUamaqU=;
        b=RgyUTyfsoeSr+bpM+15jL6cfJ8qDjn4G+ikBfeM7YmBxFQ6KFKMXRNihuPnHvwcLM9
         wqCIjZ5zrom1qqm3b8PvMsnCMpP96FrIEZz6JKVt865BuesgbUNQiDk9gdQDQoJTTu7u
         ezz/l5GNma7cJHc7yIwjloJ4Gi/o6KSAV2OgDjdRYJ572duguK/J/URhr2Q3Vbqf8nHR
         RdJ8qR0I1+MlFLvCr+cF1w6s/hrdTMq9RXQX/VPi1a2DahPX9wPy74Hpv0d6wkNpc8em
         3/JTNcivl3fSkBszPuLaKqPO0KeBurUT7V3fZmCP5/LXDj7NC1v3ztoZlZBzG0waOa9u
         avRw==
X-Forwarded-Encrypted: i=2; AJvYcCXLpGqvz8FkznVxbadEjC9/015RWPxzVjSJL3K18O1ilRXL+ASpdcwYLJI/mXmDKtdPIy0+Yg==@lfdr.de
X-Gm-Message-State: AOJu0Yy6wNsshAAHXkGGzE8ZK7djwnCV1WW85oYjkavtrOzmf4m+KAmF
	qVh9nFR4MJMpqfJzyHMxjQGSdMzx5I2FCaWiAvM2LZyO/DxMITDL
X-Google-Smtp-Source: AGHT+IGAjh0zOddvbkTyU2fUKq6ZXQPlq3WJacF2F/fmZX5QodL9wFsM6cHgza3lcOpiE6OdahbUNg==
X-Received: by 2002:a17:90b:1d51:b0:308:539d:7577 with SMTP id 98e67ed59e1d1-30a01033a09mr11174104a91.0.1745774275093;
        Sun, 27 Apr 2025 10:17:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGa8GK0oez0/0F3on2pR/UsZUCqbMBJ0R+rRUJfL8O6rQ==
Received: by 2002:a17:90b:2804:b0:2f9:b384:bcb8 with SMTP id
 98e67ed59e1d1-309ebd15696ls287344a91.0.-pod-prod-05-us; Sun, 27 Apr 2025
 10:17:54 -0700 (PDT)
X-Received: by 2002:a17:903:1252:b0:223:88af:2c30 with SMTP id d9443c01a7336-22dc6a000dfmr88823915ad.16.1745774274206;
        Sun, 27 Apr 2025 10:17:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745774274; cv=none;
        d=google.com; s=arc-20240605;
        b=lQJkJHJnUwW49/S6b3z0tDxKQd7AB3BtcfwkryyqqnVPCaMBbkqsnIukIr0qsaaM1Z
         6s9xhix5S6A64cYRqCg0Vi8epu/rK3IvvIl1I1S21WCtsqhrG+CNOqmILUR9lDLH94q2
         rE9MMCTt3ihNkz1bWen/dPIG8THCDXD6x7bHJ80NcVUbdE89TUsBSqc3fMOhmmYXI8ZA
         aqTb7TGbia/0XAZQOgQZNnvEoSrZ5HwvSolLQ2lRTKXBX4i8qr9jNY+EwVGS8TAn9PGa
         COAZtoabmkLqJ5ObpVqmkGiEfDIOEy9ZQMLIsbpPntgNjeCCS8V1s+QSo8xPsgqNOtNV
         3hFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=n7PUZMp0WoRzGZDjogh+ZGTSMyJtcr7W5TUETQPP1S0=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=cO1gY0KDufgEre3R3qFc9M+0wtGkJIM6Vr4yP75ZjjCMvq+gdFWnUtkgcsvPsQnkzV
         cV6GNjyRu9KV+FatG5yensiID0g5+o25jWWKORTVc1eokkIm5tQ3n6+ecZB2+KBOsHJp
         7L0yvHG+w0bPws/0H6j7zQ3C2P0X/FZo7m8CWtzumu5snS6bVZiOFArDWzKmcADpb3F8
         JdYp8IB9tDolP4XZP6qcitdrTLtAYTosQq4R/KhKEJH5/DLnIVMQMDpGSEaRpRAW4QYI
         OEtedM98a0YAIXLuQxmb/xSoaUsmVUZXUuNTBrGRlm2Ch/eq973ak7n6kmsXXKN7OF64
         9Cig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Isz6dX9U;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-309d3b9dfbcsi939519a91.1.2025.04.27.10.17.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 27 Apr 2025 10:17:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 54B5DA4256B
	for <kasan-dev@googlegroups.com>; Sun, 27 Apr 2025 17:12:25 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id B360EC4CEEE
	for <kasan-dev@googlegroups.com>; Sun, 27 Apr 2025 17:17:52 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id A7879C41613; Sun, 27 Apr 2025 17:17:52 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 219800] KASAN (hw-tags): set KASAN_TAG_WIDTH to 4
Date: Sun, 27 Apr 2025 17:17:52 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: trintaeoitogc@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-219800-199747-DGEnwS5Vjb@https.bugzilla.kernel.org/>
In-Reply-To: <bug-219800-199747@https.bugzilla.kernel.org/>
References: <bug-219800-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Isz6dX9U;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=219800

--- Comment #5 from Guilherme (trintaeoitogc@gmail.com) ---
Patch sended

https://lore.kernel.org/all/20250426180837.82025-1-trintaeoitogc@gmail.com/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-219800-199747-DGEnwS5Vjb%40https.bugzilla.kernel.org/.
