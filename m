Return-Path: <kasan-dev+bncBAABBJHGQGJAMGQEEQ3XVQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 2434C4E880C
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 16:22:29 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id l14-20020aa7cace000000b003f7f8e1cbbdsf7583155edt.20
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 07:22:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648390948; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gh9s/IqnPeWQVOSOdlBxdNy6qG+g818F402tOPVWLaY7E2bVice/zGY3WUGBgyNFvY
         XSXOXG8Os58kTw6JVsZ1qFkORpq5a+9ik+sItaDF4Q73BFQ/5pmGT/+rBvO+5hp9rPEh
         3ml7WdkLW19tZTSO4UoZhVDCuPiRnOZSiQY475oeuvLg0YxnK5Y5sZCVZJSZUMjDwMro
         mUBSHDoGhgj6u6tA8P8xBoYEsn3j17rcuJPALbb7AbdnLU43vK1ZVOUoqitlIi/PXVms
         XyQqlaY37KloTBMz+Urp3ahTZ5b1HPGO6Prt09oCm76xj1A9CE0UXvciUt9odQTImb4f
         Q0Ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=s8WXCkz28DZuwOWVDwGYt7MroKlRwJkNMAvrH1uwQpA=;
        b=uX7Nt5JjhxdoYKB6Ty/rWFf13K4SNSscA5Qj0eCBQwE3x1k0HZPFAtoEIr8qBHXZK2
         t9OGyBIcX1ku4LKztXu/QRLKmt5p/llZHkxQ+letoOC3y5kY1kQObzVOFuXsGaN6m6LW
         jkgW/loomXhaHOibaqJo8AqW/OXxs3tS6COAC/j5h0cvXuQue14QEtYHcD7Vz+BlovGP
         esbtMwpySE5F2bErVNvi1rS1yYXAi/RqPGhNbRQqmJlpoRsvFfKSUgjDOfxd3eRfZYpN
         7bIJb2XvVOL+nAKCS77BjOy1t+OYIuCsG1aAc19mp3ZOiCjSHbu+BuyIDYUquRVCI8ZF
         LcQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ptKRayKd;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=s8WXCkz28DZuwOWVDwGYt7MroKlRwJkNMAvrH1uwQpA=;
        b=HEawTEnahjLSwlH7ZIKbDR2lZj+SAKQHFuHm0ApAlM/NzJlEsJSxERR5Pf2MlB1uK+
         dJMEE7vQwqDNwhzARmkmQFEwegoJUuksmJH5rsKVLgSbebnVe4+nlXy3CGkwjSwo8wgI
         GETZiyKgWcDnfPeC/bzIWgwc7r6IT0mwioRC4kqlFYjzK0wsxpXwJfHZ1AR/Q/+i6jgp
         DdwQ+fZ5jjXfljWngW7QX8kWb8reV8X0MeS8FcI8Xf0zxUgP29SojbVaxkLX1xMQpj2H
         6CTDrECI8DNDE0vYgAO1Fido3L/kUnDYFxK90D+MVYpHGu3vz1n8+5u8Z7Av2lp4vnS+
         uK1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=s8WXCkz28DZuwOWVDwGYt7MroKlRwJkNMAvrH1uwQpA=;
        b=Wb1SmV/W+zoSRYsXIeKQ0NP2DVUYbEwNwJc+CzqcMjhSDJdI6bTiRctA66syLCUobm
         qvgnd3JKuk3PiyeHAvAi6rr6D0U+A3tT7gRa5f8Krr50r9jVNaMCrihn05c4w6GrDKRZ
         EjvyxPlxTcWfPQ0sH6/CktCQLwvS07ij27St1jv2jtGgk6SlFLLf9wW04eZEKX8sZuED
         ZECjZEU9g0/aOjrSMYrBs7YwS6wKfaWeSBhafPqcZOKDJ95iDEcMmjiDo2ub5shW8zfM
         6IcZcX2dBnq6XUM7F2OTBSca5mSvVjoVL/BZ0QbSF3pEQCv7zzeCElPLB/KOfLPot0Rb
         rM5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531RL7klQH9jwttMnT7I9WFvei5zWslTC146/plHA1DZVZgAqsJz
	KAgPJHYd4d2qQQsK5qCneQ4=
X-Google-Smtp-Source: ABdhPJyvHXcOS4MD5Q99eT1oMmnyXDjc8A4AYah0U06YMI39aSkvHMDWwnW/d0RkpKPD8WQ/Oxh1aA==
X-Received: by 2002:a17:907:2d07:b0:6e0:13e2:841b with SMTP id gs7-20020a1709072d0700b006e013e2841bmr22621486ejc.502.1648390948744;
        Sun, 27 Mar 2022 07:22:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:7e8a:b0:6e0:47c8:10dd with SMTP id
 qb10-20020a1709077e8a00b006e047c810ddls1841363ejc.7.gmail; Sun, 27 Mar 2022
 07:22:28 -0700 (PDT)
X-Received: by 2002:a17:907:6289:b0:6e0:eb0c:8ee7 with SMTP id nd9-20020a170907628900b006e0eb0c8ee7mr5235620ejc.245.1648390947934;
        Sun, 27 Mar 2022 07:22:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648390947; cv=none;
        d=google.com; s=arc-20160816;
        b=Jy8gVhzUSMQbzN2uFDrIs51JrjfWyxi7mPqSziMmplWvryRtBYmrAwBf5huZuc+cdc
         5QRHKC5SMU43x3vmzwbDlaARpUwELXcFZnRHn3bNgfv2tRphYE5aNJMp9P/YRqH6G3nb
         yA6H0rieUA0ZtBs8KDU5ovjIEp7DfStspphMF5s1e/SLdQyuPVCTxvly75epYir+77YB
         poN5sOnlQeklmR/cb9zJAA7RnuD6M3VjeFUHVmpcDK8kpaY7zGoMw9dEZ7AUDuu+9wLz
         vputax4HPDgt7rfRCLAtc/FHBgakHRLCe0c58D33EfE02i4WJSE6FYuMvZVu5pFlawtw
         fCgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=OeFYnAkSY2kIq1VtF7wStyaMjYtKyPN/IdvAsMu8924=;
        b=AGOgecMb+w0A2e0Btx1V0iu9OGCtoL+EABCyMKoRj5hpu3PVxad80tdr14BQlvwXOR
         tFS1nCGaZTRlXP6Ko9GOXWGArn+zVOyRRuo1dyAtwqa1zEEiLPkZkDkXi8szd4x3L9Zs
         nCZ/YviOb0Y88eUBPyAp4WaCrNKRD3039u6bRsil8Hl7SWzeWG1Kv1NvCqP5OurSA9m1
         ZLxvzNGWWaM2tj8oleKm2ArxcN62V2waWhy3ioYhoKnII7noSrBPSxoyTYx5I8+98X98
         2ERr2ij3A2o0X1u8bo38TxxBb+alN8qcV8oEFWqXn2r2r5GozJMGk9YpT7Cykg4qU8JT
         JRqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ptKRayKd;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id r16-20020aa7cb90000000b00410871504d8si646560edt.0.2022.03.27.07.22.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Mar 2022 07:22:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 9E997B80D0F
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:22:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 6F21BC34100
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:22:26 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 5D3FAC05FD4; Sun, 27 Mar 2022 14:22:26 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211777] KASAN (hw-tags): support CONFIG_KASAN_VMALLOC
Date: Sun, 27 Mar 2022 14:22:26 +0000
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
Message-ID: <bug-211777-199747-4pAWW4CEDS@https.bugzilla.kernel.org/>
In-Reply-To: <bug-211777-199747@https.bugzilla.kernel.org/>
References: <bug-211777-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ptKRayKd;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=211777

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211777-199747-4pAWW4CEDS%40https.bugzilla.kernel.org/.
