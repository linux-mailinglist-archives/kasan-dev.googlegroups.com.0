Return-Path: <kasan-dev+bncBAABB24BX25AMGQEUG7K5MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F9449E2EA0
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Dec 2024 23:06:37 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-46686a1565bsf94748111cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Dec 2024 14:06:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1733263596; cv=pass;
        d=google.com; s=arc-20240605;
        b=VK8NDLFGujP2mTFeiktkHfboWPyBFvboc360+gLQWm1QVIImZtMLt+8aJhi8OMaFzL
         h0alxSmBHt1AuJ68GhDul8plHc6B8gCdC1rP7OqSrQ9RROo3ktr7gJuyXHltHZbnFY96
         KWNzLzV0dGl+IeZ55YBVxeuBxCvPyBAJ0nBvj+OOrG5QJSRYs3Fxsr4CGol5CgtY9+zf
         heGadagtDmzaSmL62UjhVFNa30f7lAAouqEc34lAr1RhN3q54ygI6Kl/2E6J8elBFqug
         RpaG2x77RrcKXwsE2TZAqoBybYxhUGyO8xs8uHD5Hp6F6XzxndjbZs8wdodqA47w52I6
         Somg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=VA9IAg6iUFtfPFWa9VLYKA3f1Ez5KafuEnWw+tfYk4g=;
        fh=xBLQ7IzB8B671wxC2YpMwx3+YtfX64DCWjeSXFZIx+I=;
        b=iPhy6HRHvim361jfiPbhwml6RWnKnG/VagZR4KIWK4Pz9LSEAGUyBSze1Cih4NPnJd
         /dbHqZID/as6kodKUymj2dQBaOzPh4U748Xuvu/Z6T4/W96bNDXkjuI5ytw3+WHHVNV9
         l3hr0HGeaWlUrmarc1/wIz5BnHC0Y0wL6gEkeYcIQfXvdqBaFhXNd055ajqnle6L54ir
         nmlYFRLNDgl7LH+5FG3WEzbYXPHcBm8T6dHOeUgfPw7tLow8K9cRZ/fCMqi/cThQseVY
         kie9mrfFW/zIbs/Im7sLKc40jBPAG2ir+0vh+IqfmwHd1kOGOrwJZ9TIlJqCNRZcIfHx
         0kDA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=M6vqYWYe;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1733263596; x=1733868396; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=VA9IAg6iUFtfPFWa9VLYKA3f1Ez5KafuEnWw+tfYk4g=;
        b=caRXBRupvcQM1HLBhvzu4stWJXZHl3o0QHPCaWJzwn+MGCJqgZ6Vb2x0oxCSRMjhqV
         qyM9HppDRuyG6oQoYRuKEgqAie4obQWtzISJaCvXQjLRQp3LTjscbPhmRnnRcseMISHf
         B+YSXmexoeB0qoZfyCtCxXJIg7zNPOI4HyXZ2jKLx5L9Dvo0xWm+afkK6W7xIhnEmKT1
         keOPfg0hae1PgOD3SdkfMv3+6pMZr5stqn0w6WlBbCm2e9AAJIJ4anlr8VDr94taBVts
         3XCbuOAnfcu9qzse9QDC0tWGaTFVPAMeH9kyKUy3585n6+iggBCwMdWHnOr4vwXmP/md
         2FXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1733263596; x=1733868396;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VA9IAg6iUFtfPFWa9VLYKA3f1Ez5KafuEnWw+tfYk4g=;
        b=pBfih9yk/dlxNPLHrsAM+EBy2sAfz9+t3+JOFQTeR/2ztsFb2Lr3MqH0CdTH6JCXfA
         DhuV4MHWMzbqgOWXLBATPOHHwzo1RI96eM2Q2ta/VfK/eNtQQODQ5z8+K31yNePKogmy
         o5Q0X+KRWyO9RmkPhYLfZgl9WqYnQGCtrvSWZDABgBBxuMnd/1mCRnMa+/wZIrojD3FP
         nhcfKNOE6MtaVQ18I3cjW3WFBAYf/L4eHDumQQAffI506FsM0jrWQec/dsM1TIKS66Hs
         exs89vilfAVpn8Y1L4kT4lOssK2MFe3k362OxmBjCsDP2dWaCiHhVvsYMpjSeSbNBMCA
         7KbQ==
X-Forwarded-Encrypted: i=2; AJvYcCVcm5xO+i+ZdMk4WuuesClRhyauBey3hzRZGhocKddsHcLpnCLNfLUZeNKBlfTDWLpucXvEPQ==@lfdr.de
X-Gm-Message-State: AOJu0YyKn31HdVQAd4+zcHvz1fYJvejTa+7j8y7iyp8aWs508m18Clxd
	Ly58ejD4MTirUm8a9mhTjJyom4xGfYq6x+JZ3niIzGcpnmVRjU5e
X-Google-Smtp-Source: AGHT+IEYOXkucsbv6/jqRxZxHYpbBehdaFoQe5FLnesrw4wr5oKznZodF2pAAP2ka+rwlXOcxqw5yg==
X-Received: by 2002:a05:622a:190c:b0:466:9f89:3d72 with SMTP id d75a77b69052e-4670c38f557mr49124861cf.36.1733263596421;
        Tue, 03 Dec 2024 14:06:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1806:b0:465:2fdd:88a5 with SMTP id
 d75a77b69052e-466c1d21248ls93167791cf.0.-pod-prod-09-us; Tue, 03 Dec 2024
 14:06:35 -0800 (PST)
X-Received: by 2002:ac8:5846:0:b0:463:59f2:1835 with SMTP id d75a77b69052e-4670c3d2bfdmr44780891cf.54.1733263595450;
        Tue, 03 Dec 2024 14:06:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1733263595; cv=none;
        d=google.com; s=arc-20240605;
        b=Yu/GgYLm0Rz9dGDj8fRQgJ89sszkesgAs4DeVCPYnuOCJxCMEoHPommJgg4ipv7cAa
         +1pEsZLD10c5V7RabJVq4dcksfTKTravscyFB68AULaK3Eup8LNcqX9zJVIoPGaCWsxF
         Od1ZHy+t0JAKayu4NfQPIcfyFtXRTI8cS0SnYKLMjuR3G1y8C8MGLKsgvPsx6eseTn3D
         LtbKy9L04nmYZay+uMmZA/J05cYPzoMBM4DRRlzkfHnV57dRuXeU+DB4IsqApZz3xxs1
         wzm4sXnGJU1j5GuMeOpDL5Au9wdpMi0upKrTqSxbcOWOVYUE3TfWqKaFdhvy5SMjEr/U
         Ac8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=JqUwdVMoy3aleD81ElXVNUBtlQI7rHa7ww34AaBN8PE=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=C0OylYfeIXGhhlVhQVibluijb75xBh2en8kYBiLVygxtHVQWqNYm92+LWx2noD34eM
         vngB/q5+8wVUG7mRGDDJrJ61DCvNQ0xwjM4VfNdpppjWfoY0BQpdl7U8FbpovccTb0w/
         K7X10e20eEg1pOt7/KyNqis/hqsqXxh80Bn1mfo2GZ1GYaFyRDsgIxr1emtD+isKO46+
         yUSGh7K97U2VoLBzQV09TTPILvmgVOC2Czj9aQzxgih31+U7ly5Eid4eJFjhtQyCuUBr
         hSod2kIU4+dWbtsKF38iAOX6rlhbhiuqUjQpQIzij/z37IYn+PH2guXg81KaJ50aGYHF
         E6/g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=M6vqYWYe;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-466c421c82bsi5013311cf.3.2024.12.03.14.06.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 03 Dec 2024 14:06:35 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id DC00FA41993
	for <kasan-dev@googlegroups.com>; Tue,  3 Dec 2024 22:04:42 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id C5A62C4CEDF
	for <kasan-dev@googlegroups.com>; Tue,  3 Dec 2024 22:06:34 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id B4D07C4160E; Tue,  3 Dec 2024 22:06:34 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 215756] KASAN: filter unnecessary stack frames in reports
Date: Tue, 03 Dec 2024 22:06:34 +0000
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
Message-ID: <bug-215756-199747-z1MUCNEaXp@https.bugzilla.kernel.org/>
In-Reply-To: <bug-215756-199747@https.bugzilla.kernel.org/>
References: <bug-215756-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=M6vqYWYe;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=215756

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
There's a proof-of-concept patch for this issue sent by Nihar Chaithanya [1].
The patch still needs work and testing as pointed by Marco in the thread. Also
see my comments for the previous versions of the same patch (search
lore.kernel.org).

[1]
https://lore.kernel.org/all/20241026161413.222898-1-niharchaithanya@gmail.com/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-215756-199747-z1MUCNEaXp%40https.bugzilla.kernel.org/.
