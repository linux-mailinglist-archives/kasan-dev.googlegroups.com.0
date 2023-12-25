Return-Path: <kasan-dev+bncBAABBHOQU2WAMGQELRCXSHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4251381E17F
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 17:04:47 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2ca0fb01500sf23245751fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 08:04:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703520286; cv=pass;
        d=google.com; s=arc-20160816;
        b=q4GKVxw4TCg3/U6ND/1zHcplzPZB0WQyO/5ahKOH1RlP2FCon7lhnpn966HQG9Aln0
         n2kWCEQiG8TsFjhMqRvwMR9rhrpOJ83jTWD8heeMd46KYvf+k9Cwr1W5S6sPDB2m68H0
         7D0tG/cWOqqziYLslmc50EUxsSW8wG36Z4XVv6lE4pnS2jG8M85rv6h55zlspUp/or2r
         Un0jrLc/SBYrBk+OBI6A1M0eds84oUvKisS1nB6v+rcqsakStr2VTIL/48vvnEbgYc6s
         KcSvaK/fSeC6qj8Dtt6kGzYpJMPl6IEtyiB7AspXB1Jhl+t5yYyvOK+JC5l5FVDegBzW
         GmnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=o2fPWRpK63sVrsseqxqpi7q0qK8ip55Uq0iJrcNZtVo=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=prCdIarbZE0tyGLYUDGSkLOk1GDIRekpXYvsmS49au8KNy6PRxWUTEeH0sC4Rt2L/J
         ca5GGTq6vQ2lHUdwE8746JxhxpgG/yFHJ80+SAL4wl95aC6BFIh/QZ6sMOgm1kb8qyfQ
         L0hr/popikqVZTOOHxuImSoPDUKY/nu1HnbQoz7PVo4bKnAaR01+qCcewi2tZUGcEtiF
         uJvht6u7XVYGfiPfOYZxo8fP61FC2LLqJG71ZTT4JRzvkUBt1qjcFv2qTb2YWVK17POB
         6xBXILOOLeVYBnciRz8DcRD05lJUOF4PwX508rdgTD7Vh+6a4KYemqQOcKLBe29Ltmpq
         WsQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=EETPx8FY;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703520286; x=1704125086; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=o2fPWRpK63sVrsseqxqpi7q0qK8ip55Uq0iJrcNZtVo=;
        b=qeRJFwL41JwLescHPlNpleikwmOVypxbV6ZCZUYe2V2Sp1lJ9HLLuAqSDMBbTAZaiq
         aQ/CNRsq0y8lQx1p8PPe9l5MnvfYpFq2wvMRAvQmcvN91PVs6SzmX3hJDnJngmTE4cn7
         5gnlTZ2HXkyBF3Ew8WeIsEIEOqxIyqg+ej/X0a2W5e2eg9nHT4K/QxA7ra20Dv3DxIRu
         qzSaTBQaKX+rxiydqaZ1u+K4RZ5zLwN7jhfuYja4IXL7MnvMWD4cR5bVJVcL+jheQkCk
         cE2M3fWVZUgOnhLlvaGvd2ftiMpUFwdPob7AYLtACyLVIeK14XMLgFo/F+tdzkjNYijK
         xv4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703520286; x=1704125086;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=o2fPWRpK63sVrsseqxqpi7q0qK8ip55Uq0iJrcNZtVo=;
        b=pEQAdlLFF/rdicftifQrTOeJ10gioAXaVVJFbEMXn/PnkqKKUVE118aLovkOgDh3J1
         8CTWl7KTaI/B23VQ6ycEhxcOBLHMTwDVDteEbEeGl26A6SaOq4IsTitu9Nr6DaM5aH/S
         Ayx/XvUH+A1nQ/32cccdaIdKYzVd7oplec+OmNvJjRD29z83z0MCtXq3eUVb2/4NeW3x
         WN2XTHD8SBovA+1SMkIbg9hXqpOyiyrquIio8qG2WxwGSyUZKWhoH2ec+S7Z3qbCJKBq
         LgRJGVHMpoGXTBY1uaz1rgfIgmS+7bHXjP+o/dRynq+1Syi9bNVaJBRcsRXjGaDmh5FO
         dJrg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyUB+0J+wgp1eHNZs6iut1DSVe7MnkGH12CcYwCWDmgyY0u+IiH
	7VY6/kqB0N7NXWQzqHWuXNc=
X-Google-Smtp-Source: AGHT+IGWPQD0yBJpBFGAylSDixaRpovhIRo4c1UI22cztbgXs1pKHBgkJhh5bUgVSB5Bh8zx+vhT5A==
X-Received: by 2002:a2e:7e05:0:b0:2cc:7ff2:b320 with SMTP id z5-20020a2e7e05000000b002cc7ff2b320mr1441663ljc.104.1703520285504;
        Mon, 25 Dec 2023 08:04:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:97c4:0:b0:2cc:b572:d22a with SMTP id m4-20020a2e97c4000000b002ccb572d22als506265ljj.2.-pod-prod-02-eu;
 Mon, 25 Dec 2023 08:04:44 -0800 (PST)
X-Received: by 2002:a2e:9c0c:0:b0:2cc:7df9:28cd with SMTP id s12-20020a2e9c0c000000b002cc7df928cdmr1240366lji.101.1703520283707;
        Mon, 25 Dec 2023 08:04:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703520283; cv=none;
        d=google.com; s=arc-20160816;
        b=KaEiTiWQF9mJ9h/mshgIA25phu8OpNJw6lW+6ATRKKIV58HJGmURqJMHdtijGjabMg
         mKYo8SOyXrqThNL933vIVNN/qGNAiHqwFHGsZRNAD6jFk7KtteHpYG9DZ1eu1nlmIzvb
         fIZIo57B9uj8wMZ6vupi428XUhtKgxb9gWFGyLHEHdYSjlCmpy2CWQGojXj47P+kRUwP
         Ty+zZXc77OiSOrvPbINKs4y09H+JYcxZOVbInYF4XniDTNjBMuDAHz0Bpo1Kb1qHVi5T
         AE79P6l2deP0IKFDKJ75JbJQCytjLQZ2qOunPRHJv7dBPzICs5+w2/7jsHl2yh+qSldw
         EU4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=4nPKphnuDSD++k2JLhxVmDZQLVJIH934eWUrFAskqCs=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=KZ1wEekLnr8nYWPIv3wGIAru38zjx7s33qQs94a6jU0NHUYIngWogSedcqnycXw7Db
         hIdA1O13gVK4MRHGwg+nOa8BNN1RJqa1AHQoCEMCyHEgJDl0eIwlahalYom9alOX+jwD
         VaSx2zyoasO9Cyb6rEXFk51K1iX318E+TnJj+NZX1p4L1j8/2IqzdYtJw8RC7SVNEZ1F
         97F32YDd0pBSTzhtFtrJqBErNNQLQF2YMKvz8CUThShW0oNE9nZqClMvLpHxYQQXlFOS
         gaLXoSLsDYVACQsuJc0rfCWUdDIaHKQtcC9vp2worPzuHEmjzU2URi8IupzT+saMvDq9
         N4MA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=EETPx8FY;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id i2-20020a2e8642000000b002ccbedb7af2si115398ljj.8.2023.12.25.08.04.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Dec 2023 08:04:43 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id 1E264B80B32
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 16:04:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id D4430C433C9
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 16:04:41 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id C6A9BC53BCD; Mon, 25 Dec 2023 16:04:41 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218312] stackdepot, KASAN (tags): use percpu-rwsem instead of
 rwlock
Date: Mon, 25 Dec 2023 16:04:41 +0000
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
X-Bugzilla-Changed-Fields: short_desc
Message-ID: <bug-218312-199747-QPIerFoC1J@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218312-199747@https.bugzilla.kernel.org/>
References: <bug-218312-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=EETPx8FY;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=218312

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
            Summary|stackdepot, KASAN: use      |stackdepot, KASAN (tags):
                   |percpu-rwsem instead of     |use percpu-rwsem instead of
                   |rwlock                      |rwlock

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218312-199747-QPIerFoC1J%40https.bugzilla.kernel.org/.
