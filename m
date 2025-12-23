Return-Path: <kasan-dev+bncBAABB4GKU7FAMGQEXYLN4JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13b.google.com (mail-yx1-xb13b.google.com [IPv6:2607:f8b0:4864:20::b13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3FE56CD78D2
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Dec 2025 01:42:26 +0100 (CET)
Received: by mail-yx1-xb13b.google.com with SMTP id 956f58d0204a3-64559951784sf6460201d50.2
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Dec 2025 16:42:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766450545; cv=pass;
        d=google.com; s=arc-20240605;
        b=ClSOx62VAF/luGM1sXDHoCZ6T3lqcsbomKSaScekY+V5o7JrSqeRUmYowU01TYMSMl
         JfEN43wyMcXj39IcpsJlSqTDRezH/IKM18r+TI/k+Z7BmiPuR99CRAb942lZ8QAp6/OZ
         448z7aPWtihgFuDB3nziJ5HC3gtuRDkfqYjw3tGChIs0grYIbmXEfr5XvW9OLrnOy6W+
         I3wArsiAPz2lqdXxfhzmTSskiVItm10iOLZBVKfC5bQ02rQQ0V4nv00XkT19vWWCWqN/
         bpnG4OkRYyfCEczlAWSovfUjwthT+hYCwG4PUcTT2FymYx5GzG8y92kBhvF39setd0kd
         edmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=u0bW3+GZT6h2dQ9cNxQAlDzOKTx3TfElxbS54UayPEw=;
        fh=Nf+FeiqTNUCaqWZxb89C+s4HD9uVK7T/UBng8oteyxc=;
        b=By+qUYrcAtt1bQNHSSWkQdnDz3uP85YaVIJ/qf/+V+dNcivB+mUxQLs8gKFjEHuOxd
         oQlK2c7AL1UUcR3JfyaoxzUm0fRQXpuh03xb5N1V//KIeRnLdeW7HNjjuyPz250XKxP/
         ODTHVwEgeOCN1iw5prc4M+J9MVY2eB3LDSYrfoSZPIQdRAr6G4cWUveq+vm2K6pQahOM
         0zwyTkzftvY9D98gtovTscGA+FNSIAiHJ1wIlX1ScLuWCEhhSAct0KwNcmDK0KAwLi9a
         Fmi4NQPtA8W4BHow6BvlwoXEa4vtTQBbvfeo7REJEtjJeacS99VMT/7GP9912SReNQSJ
         9z7g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tRArVkAn;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766450545; x=1767055345; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=u0bW3+GZT6h2dQ9cNxQAlDzOKTx3TfElxbS54UayPEw=;
        b=BrGwrFvWxyDziUaXxgq6Q388tnlB3Lupt/poX7tf5Jkxv32Jc/yTCPCQFbbg69zbtJ
         qKcMYEAAI5jExV3IKjWokTpqXJyBZbnhxuLAJOtBE2SZEOJXbwIjQ7DTurvAOaGPKEv2
         ymGK3timLuLVoz2mBda01m6ya+KdWqw3ApxO1VjwcdNyVk8H/yOSF6+g8HB5t6QzhsnR
         VCSsQbBjJ1JoM8SUdzhjxocPpRqvQsKRo0qrzUXZ3uJUEhbWbe4TyiQRrF0u+ftZ9m32
         gAM2VstQzIQQcZdFJ1KG1ZwjyWfJnjvgLbmDg+qZUZogXtAl3Ny8dvYVyzDNLprpwVka
         MVYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766450545; x=1767055345;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=u0bW3+GZT6h2dQ9cNxQAlDzOKTx3TfElxbS54UayPEw=;
        b=Ie+0EewSqXrUXAmBgKVaPd2yL1to7cwR4xOxAXfHfAwvz9m0DT1g6fSbyX21yRTgtX
         6JLJsCQWzAUD+HvIfK6dSAQlPIkQW4bb9BzU/hSnMiqzlF/JDclkr6fHUYuHBt+mAld6
         8lrELwV6d+7wJkVkd5r8ng89doGQ8ZZJIsWyPxh1g9xCsQTDEaQKenlaq2HMMbHc0pwD
         aRGWOflD2JVH4vs2oocXNU9Dw63eX95JWbkJOuqELLBp7VRvkJQb0yBP9/QbggqS73mf
         bG6aMP+mPPyObsK2iZtQ4uC1d8nDK8GLlSbRA0BKrxSKY1++N1fDjvhaHtqJ3S+LhTnJ
         QLaA==
X-Forwarded-Encrypted: i=2; AJvYcCVyaZnSmPzonJgR1uSCw7YfrwsLtFPGSnra7k2fG3zsnaJiDv4nns5IRG+uWXoVwNvcX+kVLQ==@lfdr.de
X-Gm-Message-State: AOJu0YxqsowH22AHvpq9DnTp6AbJFLbqdnaxh1ZrsBK5xkTJvcoCfh4A
	yh3qmzWPfeANdv9OXXF5GBLdAJHFfDNPceKfX+wC9v5gElGp50M5+kh7
X-Google-Smtp-Source: AGHT+IG5PvWDCgzb17dA+/L0OH5UEULHoTRnGYdFxYJrzd/eebPi7tMjyE/LYtxuRj5vhBkuE+Lakg==
X-Received: by 2002:a05:690e:2581:b0:63f:b605:b7eb with SMTP id 956f58d0204a3-6466a8ba610mr7018980d50.67.1766450544880;
        Mon, 22 Dec 2025 16:42:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYHD2k/7t644lcLQkid/nbjEmkGN2FDT4UeudIjPXpcKw=="
Received: by 2002:a05:690e:24d3:b0:63e:1daa:fd16 with SMTP id
 956f58d0204a3-64554b4469els6246934d50.2.-pod-prod-03-us; Mon, 22 Dec 2025
 16:42:24 -0800 (PST)
X-Received: by 2002:a05:690e:128f:b0:644:60d9:7527 with SMTP id 956f58d0204a3-6466a8de0c5mr10709174d50.89.1766450544142;
        Mon, 22 Dec 2025 16:42:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766450544; cv=none;
        d=google.com; s=arc-20240605;
        b=bnwhvZ3VZyjhbBe9abkLHNtgPvyHXiXsu9M8wRYEy1Dn2tUp5zW2enEk/vc2z86Rvn
         ef0ciSfI7zvQBQ5Mv9slynffwz2MtDj0TetLi6lmv/v8jpDTCMeXYHcYZYYwrtsdiL9+
         oMJReCKC1sVWxHdlszGQve+f6YT0G7wiJ7pr0IvqbyXhgOcl/GqVrxnaQdjHpY+8e13S
         wbe5B7P1AsPd9tAIbXYEwZuFi22QMAdr2gwyRvwQx9C3vy0OqwDvq5u0rftIugHRnS4Z
         afdP5KZXapHXlpV7wcHqLhS/8VILknbmcd9zw1TS0Z+PaP85SCEUz2bNdc97GLVquPIe
         682w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=OaVDiOvn2DUmCv5HoDX/gGChfERCeQFCz3Tj0trVcIc=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=hMbDYQvOHhcO9CcM2mB0s+hU0VxhDKFxEXcSbE9N/N312AfhDWi/FH5nWV6RJK9O3N
         n01GOa3JD086i4BotP39V+5vbS35+HhBSL+T2bHE6M6S+zZev1cV5rjdejgc4MGOH/Rn
         lhbBhTku6o/lFFvChEpOjr6+aZd9zMW0AsKDQb3Ct8E6Gy0gJZ4wqTdCCiGDg+n7pXdC
         kA/qABHYpB1QHRfXLNBacCLXZ2Pj/2Qf+TalxoMl3eLZ2bqrQow1ktP3oxw/iUcahpT7
         klI8ZpAu6l0Iw8LcKyWbSpBAtlEzbwS0qHFCLPmWpjzc1KN7I/0W137WzROu2PjxgDSi
         1I/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tRArVkAn;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-6466a8f08dasi388383d50.1.2025.12.22.16.42.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Dec 2025 16:42:24 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 4B57A43C90
	for <kasan-dev@googlegroups.com>; Tue, 23 Dec 2025 00:42:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 28EF1C16AAE
	for <kasan-dev@googlegroups.com>; Tue, 23 Dec 2025 00:42:23 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 1ABAAC53BC5; Tue, 23 Dec 2025 00:42:23 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 220889] KASAN: invalid-access in
 bpf_patch_insn_data+0x22c/0x2f0
Date: Tue, 23 Dec 2025 00:42:22 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: joonki.min@samsung.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-220889-199747-JPrbmTMVsC@https.bugzilla.kernel.org/>
In-Reply-To: <bug-220889-199747@https.bugzilla.kernel.org/>
References: <bug-220889-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=tRArVkAn;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=220889

--- Comment #3 from joonki.min@samsung.com ---
(In reply to Andrey Konovalov from comment #2)
> These patches likely fix the issue:
> 
> https://lore.kernel.org/linux-mm/cover.1765978969.git.m.wieczorretman@pm.me/

Thanks.

I'll check them.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-220889-199747-JPrbmTMVsC%40https.bugzilla.kernel.org/.
