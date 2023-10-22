Return-Path: <kasan-dev+bncBAABBM6H2SUQMGQEF5R3ZRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id AF39F7D232F
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Oct 2023 15:29:24 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-1e9a324c12fsf3943822fac.2
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Oct 2023 06:29:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697981363; cv=pass;
        d=google.com; s=arc-20160816;
        b=uPnk0pyabZmRiqkJ06u5rocsiF50PDqIiPVoYIgbtXv/p/82Yw/7lJEGBGqslTBR+d
         svP9JbPNPk7jNJTiPt0U6A9D7YO3UmmsBJP0290UpS+cMjqs3R4NhZW+f8pbxvE52xPJ
         1Nxg7ay89lLuCK2d7C8Ds6a6RJ8cMpP48E9OZXny8sk2B3N9tBGTcQPSLdEE7taknQL9
         oJCf7ggH7qeOXMOFQHPvGUNSIg01BCGW9dpuCIvAW8we5nY4vMF7IVVYZ4rb//HcGZH0
         RIn2qYkJbm141awQ4R4JoZqTehpQqwcaBekqsLpNRfTAdknK6w0WccPRBuNx2kb6gQwU
         dnpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=I2BL2d+U2ZtLnOjvXfvxtgsXEd1HiRldfSrnOLLHYMM=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=DWzAmAEiaQdLpe/bF/V85INM8NVLKSb5H/MRM7rZxzBhwboeVPcTXaG37YN2DBUnBu
         uDBwcdIL0FHIc0nOq0VDsqOeKVv+9df0gnHPN7pHHETWNWXetACRhc4OiyiW2fQRsD0x
         anJUIIIGDwEoHNAIaQG/vTLJh0GmMTsl86wLmEf+4598/nn74Rdm2mlSjUPDWX9EDygT
         hRHNuHVVTgyKT9cuy09vRmOub4zieQImiTGAIuAFbq35mS2SyQL9VR9A4zUsnJ5QpiyJ
         mpH1ivZbsoKEbfXeWoM16yqbEr7hw07ayV9/Ngxuefv4RP57ft7M1WPYxjMcQwPafnRD
         RmvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MGvwNt6N;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697981363; x=1698586163; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=I2BL2d+U2ZtLnOjvXfvxtgsXEd1HiRldfSrnOLLHYMM=;
        b=gn6ZZ6DNSy4I+Rr4phNqg2dXtA5cppEJvDDVmPsLS9M3eULwhZwrDfPx0lza3j0SVt
         OeyTo0sgxbV0bH6i7LXN1P+Fa7oPKzrR2A1cDC4qPCiPg1HQubVZhQ5dBU4lSttfV9af
         9cS1vAgvLJI8tRc9Co7XR6OwvbP6lnDCsgAntKZfodr7JN+sYirJyMDpHj+wc16QoASM
         a1V/ohwtGjgL4Qus8jtdWI/TWru28s3dWgp7mHC+shMYzhi/YRJK2wUey2KKodxKmeDP
         9CcmbTokV6NSTc3d/fg7CGj8EvFM7Q53HxioVrSGBl7UFfuT7Ju5FgnbdBlx1v6w5VtP
         oyNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697981363; x=1698586163;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=I2BL2d+U2ZtLnOjvXfvxtgsXEd1HiRldfSrnOLLHYMM=;
        b=uGApbZknzu+V792sGjzaYqTbiWMSOMWzdv6QlMr35ueaQOmiH/Vgt49zDZrIXRypSe
         yjpZPAnlbG24UUp1/eyhhjvxdEAIqcTMGjaYtdA7pe2ZIdOkRuCEBfe6e02sKqL6tgHF
         B+xqFnoUKYN/4dvyS7ey0bG20DqXJjPLVebkwFfpU3K7nFKjyPrBT53yKfJ8ksuQpnKm
         zhXhJVQKDTjCHwLFpVXyd/7sQ2kJknl7u4cetyRhbp2FQA/IjpN6n/LpDC7093AVjtpR
         8bWON/K67XYzEBLiI9wTdRTdt8cLlozkYPO96yyXPOtoNfSUM2SnPbjBkQMeUCX3oPSF
         vzuA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyCGC3N6ig6Cskxd5GIfquIpU7EF0uTbg1gXDNgSXPf7I0bya/q
	J1sl0TqxUgwDtL8VUntr+zk=
X-Google-Smtp-Source: AGHT+IFm6n8e0ZroJnv5sANaJdWvek85NL3C5M7RQsffW89qyALEipCVfz2hHO018vNX/hTNypDXww==
X-Received: by 2002:a05:6870:1004:b0:1e9:cd2c:ffd7 with SMTP id 4-20020a056870100400b001e9cd2cffd7mr6965378oai.19.1697981363227;
        Sun, 22 Oct 2023 06:29:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:971f:b0:1d0:e2e8:7edf with SMTP id
 n31-20020a056870971f00b001d0e2e87edfls4074095oaq.1.-pod-prod-05-us; Sun, 22
 Oct 2023 06:29:22 -0700 (PDT)
X-Received: by 2002:a05:6870:1b05:b0:1e9:ee04:d20 with SMTP id hl5-20020a0568701b0500b001e9ee040d20mr9197775oab.54.1697981362688;
        Sun, 22 Oct 2023 06:29:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697981362; cv=none;
        d=google.com; s=arc-20160816;
        b=BjhpTw5TQdU7/R5WgqRgk7Vn8PRh3LXuMHXbFWluXNtwIqH98Lbcncxyg+F4HR4Qcj
         RZ1R8dae3ZiBGO3DVZJQ+2wJUHnyVUsuRFWO3ibcXzt+9E+R6mqBD7LcaIBSgISmjVX2
         Eog7Olp9sTYS8q4sjIjOKxiQSZQcHKFOQyRTbmdLTBXmPttuBt1ioh+Xr97wqI74B7M6
         KxpmUNqAhsxR7F6Uyojnye/dRXHj/MELfKm2EY5FdXSbb2ZfGZfginkhMqet0N9Fhjx4
         P7DzJTVgIGzYndZtZuAz9zhjecQJFrjQBCNdZffhb5lfrRXVSkXkh80PMiyXIPAxMZec
         A+4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=Gp5l4yp9FOOBYboUb+SUVjpMMxBhnda5914Vuj7KMas=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=Z9HOQJlHaTCPVUjpEzpUtlhof2g+DuHWosUzsQ2OgxUUs+HwH4IxaegXhZpdtMyMLm
         Feaa5N2O9RHtII1uRIOdrcEzJF+9KkL5x6orqVHnRUT2XYPckUftSr0ghwX4vxTlSiOC
         e79fzKMGMKAskuayMivvXEUvrU13b7+w0u4UzzP6ubmiM0TJiKnhjoVBmW4Tdij4NtTw
         wEHboF3Ss0PF/b5a9A8dhbJxAqQhhF5wM/8kQ5AM6rh/wflvcnyzCLGhzUizCV2Nk3xV
         Cfo3sLPSJcGWOhShxxruxb8hRHB8kJjI0IsdjK241UNgIDtbeqC997CUbOArewHu/PHO
         rc7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MGvwNt6N;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id qa9-20020a17090b4fc900b0025c1096a7a4si562096pjb.2.2023.10.22.06.29.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 22 Oct 2023 06:29:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 03BED6148F
	for <kasan-dev@googlegroups.com>; Sun, 22 Oct 2023 13:29:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id A4D38C433C7
	for <kasan-dev@googlegroups.com>; Sun, 22 Oct 2023 13:29:21 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 8E939C53BD0; Sun, 22 Oct 2023 13:29:21 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203505] KASAN (tags): guaranteed detection of linear buffer
 overflow
Date: Sun, 22 Oct 2023 13:29:21 +0000
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
Message-ID: <bug-203505-199747-xJHDW0IJWB@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203505-199747@https.bugzilla.kernel.org/>
References: <bug-203505-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=MGvwNt6N;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=203505

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
For reference, this is how SCUDO does this:

https://github.com/llvm/llvm-project/commit/b83417aa7e26ca76c433ec5befdecd5c571408a6

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203505-199747-xJHDW0IJWB%40https.bugzilla.kernel.org/.
