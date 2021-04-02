Return-Path: <kasan-dev+bncBC24VNFHTMIBBIG7TSBQMGQEAEQ6HUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id AD0E6352B9B
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Apr 2021 16:52:17 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id b21sf5436161pfo.0
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Apr 2021 07:52:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617375136; cv=pass;
        d=google.com; s=arc-20160816;
        b=y2DIvLj19F/Xt76+YzmlNswzxecuuMixOmaniPUnZ22DwDYTdzzhht+THT3DImSQUV
         E2PQNggyyUKlZrk1YK9FZ1VGssaiKZgs5ROd3VAYhzQpCOWWb4LjjetIr01/GThtIbh+
         andhoOAi7MgdYEFUaz3qvlMXR691Tpg0yyQDjt8kzmCPw2jU6eKnDxJgQ/PzNc6J0cTN
         8VA2UtjcOqyO+mH+b/iE8aJm5vyCmAyIDvTYhZmCW1s6rDQyuS1V/R4idchnayEPO0Ee
         174XcwwsY5yMXZ9k0ZvL/iVAhr2foacdvkAEFuJTTriVwRTrXtZzjDmiRqS+Y6QEGMUJ
         dYbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=5SK6GbhG8O55v/PAF+J6dihU/KKbF/K9PG/4tccbysk=;
        b=L5dsg71+l23MlNGauHg9BGLeg6IKVbzlovGDwXPYuOwxqqjaIaZ3b1pXv62FTWCQeU
         akAxtOX0sfhMm5/QDz8QnGSMSeyESPzul54kWlgf+3NN2gBONxvCwuOXignvuqpevAVs
         fbIPqWCZFqx6G+9YLDylQCz+7PFVlPi6B0SKH8M+wwZgo4NUdeO6kSDyzniYNyv+w/B4
         Dw1rcWcigcNP88s3H1YTTDbNB+YFVBpauBkm1rsHDuyW9MknhpL2boANMSu8fh3AkhQo
         eW1I4bPGLriJeJnMF2S4e9SumDW63d6KyCo+akGiRYpzMZ0XuV5FKJLEEQER1d3ci/Lk
         upXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cErWDZIZ;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5SK6GbhG8O55v/PAF+J6dihU/KKbF/K9PG/4tccbysk=;
        b=Ea1OwdEuOUdOxMImWCdixWdewvj0CQa6LmOGpNMPGcS1xk2i8jeO8yxQIU+mbpQQ58
         TLM2/I9Zcox75dIvBLmymfvcGYO5czlDs/qt6lwR2zqUxn3zne23si1rBoGisZgw4I+z
         FOC0BSZTrdGDHf6JWB86Q7SlP5uauz8gvpIqQ9tOugbOknxhvZLmqUR3mlScSxlGFcIR
         pzzz9XL1s346s5eqMlqZEYsZsRad9TN2Y0X5gIHUweaQIHnnyrJ2hVS4JpXW+7tL0L0e
         7P/l6m2ME6VQCa2IUM2kAQdBDfT6pVdYaWFjemIHZImT82GaWVpWxHadMmGlRmTAS/52
         SQDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5SK6GbhG8O55v/PAF+J6dihU/KKbF/K9PG/4tccbysk=;
        b=DLa8w0vwzCl1j31Hc0od+xb3urGMCJGieWUjcGyUmf95Je2ROdnaiDuT2EEX8/UCiZ
         wONyMk3Zahq7WQOqfuNQSbGIkG+supxB/Uxj052cUpFAIK9fJYwQoxaqPR4ZU6al7pOE
         lrKhFZmJpZtvZ0RIgwgaI9J11nCqCRxegMgPtbVzEhVR+LlTm3O9nuazlm47yTH6Gm6g
         CvrPxfNnOoBnBVZIFW2hGcyFDKtK2m3SiPi8cvM4a7DmjjtxW19Ye2c4XaterUyqwDQi
         CM2IfiAQ+bLli17NFIH3r7NzZhcWhubN8eXfceuhT0UpNbEBsy5UApjsxXHGcht0Zkt+
         ec7g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5336wgwqRZWZQZ7L1XDPTn3PKOcz3v7OqCphSE8OE5waG10BARHz
	9wkSw9te/inycqjoPaq6jLM=
X-Google-Smtp-Source: ABdhPJyuBVUOSY61ZFH+x7oAVAwYfyYIxuCUvV2UoTKGRqLrL7ugGcoCoeVQT/E2WuxvmsIo8PW14g==
X-Received: by 2002:a05:6a00:a86:b029:203:6bc9:3f14 with SMTP id b6-20020a056a000a86b02902036bc93f14mr12657448pfl.22.1617375136449;
        Fri, 02 Apr 2021 07:52:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:31cc:: with SMTP id v12ls4538104ple.9.gmail; Fri, 02
 Apr 2021 07:52:15 -0700 (PDT)
X-Received: by 2002:a17:90b:3551:: with SMTP id lt17mr14205856pjb.1.1617375135842;
        Fri, 02 Apr 2021 07:52:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617375135; cv=none;
        d=google.com; s=arc-20160816;
        b=N6o10160r0x6rUnxL4DS19DA8UkTMaX4IZMD8SKxL2p3skFr/d31VHB5V0mIuYGyff
         FZ6dzi9O8dvtym6X+XaHbWQtcYJ80IEDeXOw3Vw4BB6YnhnPB8YQ7rgUP9Gn+i27Mjg1
         Oi+AdL36iemsLigZqoNmtpMqWhwMRGoITbj5X03ZeMMC26B1jY2eiDvj0JqqCrdZmSQ1
         sSiGikacZuHkfkpQxvlG5cvNiVa3WSEtpAwcQUIkQXDqkX9L/6bsnd7FVVCWk7CWMeN+
         ZamN4M/V22DWXVgi8rp9KKD+O1cWIotQMcHllnKUQ/bSapdWsoHUslMFjyy4XlrSsdGg
         zg7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=Yu16xwAMSW4zL1mtKNUrZcwMug0k4eGiyv9rtzGhRhw=;
        b=jCYAebhpPUbj92dttaKt6ex2SKdaQXkoOIuzQdr4TpxRmqwFDpAAYTL5uh5gC/a/S6
         zy9tkoiL/sB78JGV0F7SvOz2CVHpNTvHBpVzQWfaa/Fu7CtEESjVIbUrhHGOop2aaxk7
         SYLGOrdKvN3Zwy85POwSiwJ/dEUDQwkAW+F4u04j5NraKj6O8rer8qpND5EXemdc6tVF
         2lcIHPFiUVeoihcmcStnv1Jwmtpb7E4f49nRlfZ+fR/s6LQv8rumvTIUoHpbajTlC7bi
         VpfPT0AEsVsGBS7mwhWyeJ0VdBkySvuPn+YYtLbL8Ljq7MJxMzmFQPrewOrcjqCEHaTm
         PfeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cErWDZIZ;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m9si713766pgr.3.2021.04.02.07.52.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 02 Apr 2021 07:52:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 7F71861106
	for <kasan-dev@googlegroups.com>; Fri,  2 Apr 2021 14:52:15 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 7598761055; Fri,  2 Apr 2021 14:52:15 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212513] KASAN (hw-tags): annotate no_sanitize_address functions
Date: Fri, 02 Apr 2021 14:52:15 +0000
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
Message-ID: <bug-212513-199747-iBGtHRaMe2@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212513-199747@https.bugzilla.kernel.org/>
References: <bug-212513-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=cErWDZIZ;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=212513

--- Comment #3 from Andrey Konovalov (andreyknvl@gmail.com) ---
This sounds like an idea worth considering. This way we don't need to add more
annotations. But we would need to bump the compiler version requirement.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212513-199747-iBGtHRaMe2%40https.bugzilla.kernel.org/.
