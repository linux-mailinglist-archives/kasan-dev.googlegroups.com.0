Return-Path: <kasan-dev+bncBAABBN45QWIAMGQEG5OTRDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DB0D4AC67D
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 17:54:16 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id f6-20020a0564021e8600b0040f662b99ffsf2222115edf.7
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 08:54:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644252856; cv=pass;
        d=google.com; s=arc-20160816;
        b=c8BlXlyu4wWD0DgRqILztalUGs62bGd5UF+dv1FiTxnJDXcR002sWPD3UEqgrCHd44
         YkHTZf9hD4RVvHsakR8dwRVBeo8ZXaUSZe4//HA0+Fs6AAEKQ6Q40nnC4q7gok37PGu5
         MafyOK4x7bKJMXr0UC3ivGYXwEJ+H51Ra2fVPqkDJAxW+ClSTw3GCwdO148A1gX9wUv7
         eOVB52hzC0u86TeVWarStq0CJ3DuG8wvvfcI1tLMu3CTO/coO+nZc+ZNtVKniGD4YhZx
         AryJE1dM7EDdfPgCrNZMEF2QO3bb8e+EqCiSxpfJST0g3I/mKFNnh/dePcar5Dc3W5pk
         wGvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=5GQjqcAqDjnUEins7jv9LSCT6e/oUlHcXoec0JxtP6E=;
        b=m5Z3RbA5SnnRPMu8Dzq7kQkBDuPpLHspTt3fWlgMBe6xoubbTgzJbW0gvGwL+sC6eR
         c7BIKhVw9wzjXb4ZQVVcp3B2hcmuUlUWESqJ1ACTTzQk3nDPVNRfd+KZKjaSaG/8Uzze
         tAVCeyMoVKa1knz/FH4el1lzogEYmG11A5ZDwUHsiQKnhTFjfVGTA/WeKQ6fy5EMxyP7
         A8n3WrpjoAOnpqvFdDop4CCo2w+b6tPavjdBMPtvozfahJAv8xvbfSAY08E/hCpiNM7D
         TW532poiI8w2C+hJUDiozoDsnel4wPiD+BSrF8GV54jBkfjp5s4WSb4OUTixjXhzzRvi
         sx7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bYpbvfZW;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5GQjqcAqDjnUEins7jv9LSCT6e/oUlHcXoec0JxtP6E=;
        b=O3qnAeZTYqPGYKZCkNqWb/epT6Fqi1e2I4Rs3M7eSGQsxzWMjSK/ajULOIvq6bcYWj
         hSJCy2QcFuZSemmrroeWe1tk1yb7kgeJnm37NboP+nVMK+ONGydVyBNiXtncCqx7ovO4
         Svr+SpfhS6jE2v3UDVMMAZeXSskJQcPqK3J+dXBEf99pYayvpVtqnfIJdUQyCuhR2/O1
         H9w/Iqit8h4YduXHsBLOL4qbdw+XjfQk47VUem+TktH65PQmUfA2ZUeRcEnZ+G/c/ecx
         OYmBQLJSE8hshbFXLWbUwIGCH4uiwMhrIvBtbOS6gX35qEdEYCDA32yUWr9Y11F8pevx
         bM8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5GQjqcAqDjnUEins7jv9LSCT6e/oUlHcXoec0JxtP6E=;
        b=yfeYVAyXsSnK3jsmaR1VhQgjUPDsd0cK6KMV9devb49ytfxRnRFmjTSRP2jiBFX5Eo
         6xaYlGZ4Wn/eu8smAl7MqQy2s4DUxEVDiycXYR2IYia6e/KYi8sAPLUSxWe8zCDHBaVJ
         Prtbvjto0Irz/49tZKaZr01Ac64k6BqSugoqT9VJyMk5n76eMFZwWFkdQ55Qe5OiBFYg
         HD+JvzCZ60Ba3RVobc6ElOeHH/lLWVa78151L5eNYkRxZO/4am/sbfDcOkWW1QEcJnuX
         cIvVBcx7pfN4nHZFoprjd8yoii6+Fr4rmVC57UIBpOg9yDu4N+51/5n2odYc4hjUS1mM
         NaIA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530jtnEPk1FT3Wy34CILm5a4iTApdItsUgI7O0JT8OAXwJzOhoAt
	Qz4weVDpzHAaBB6K3re1aRc=
X-Google-Smtp-Source: ABdhPJwY53aVyL4k783zITFTVOGeVcieu21nh5CGBcw8K9NJrMtSqYrhCYK8zR2klh90AgSTepTXgQ==
X-Received: by 2002:a05:6402:5179:: with SMTP id d25mr403027ede.194.1644252855850;
        Mon, 07 Feb 2022 08:54:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:5246:: with SMTP id t6ls2109562edd.3.gmail; Mon, 07
 Feb 2022 08:54:15 -0800 (PST)
X-Received: by 2002:a50:d55d:: with SMTP id f29mr374795edj.45.1644252855130;
        Mon, 07 Feb 2022 08:54:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644252855; cv=none;
        d=google.com; s=arc-20160816;
        b=X6QFOdYP37rhwopWp8MX49+wv4ClxQ6UWNFOLQwGPI82dNxs9JJ2fCMDBVqQ09Ccxa
         BR+CxD8RSXCWmiOJAIIAuvgarzji/7dM65ZcoR8SPFPIbmra1ZHGch55BvHcgyg3SSeo
         OAKDtYxAipfxMFAnyTXbBs5c+5BRbdaDjgTBP9kSi8N9qf0VYGQjMStxPJ9EiWw1Jfpm
         qoRzVoKWGW8wsAvAH1dySQdDMN2xvkvM3ym1MR25F19kFObA27KhowY6ml0t/aIS3rm2
         IfUI8oZQF9h1nzeJa9ApZgOhygZZolUOD+ACa5IKck2HmLSp2pkIxQ0lI9IVkVX30sku
         vBOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=UZHX4gHz3jB3eTZUZsMNI0vevB2SU3J8lzT6c7DaBfU=;
        b=f7gHZf/B2jhAOI3madLvrjFRk0Qo7DslpJBjXXo2N87qLphr4M2qjkmcKtx4FUqX1a
         1qt1R724Yoa107kj+Ctcdp694SkefRLZbMG1gnXK65+b0KhrjVc8lTXaLeDkRNu66Rb2
         Mh4+41O+G5HiPdUma+lIk23OPLd1VTA2SL1gGzbqEMbYilRB0du3xIWrB5o0zoU6osok
         q3UZ/YxdXNbOQTHJBE3OASsiop9+WXvcHvDpiIq/O+u2UVepjjjOgFQTLkAJ27kHZiS2
         opcspVtoYwYMiiIitE8hc1ZdT1ZQPoZ+k8wQOu1zI+dqwyV77Yic86ejurCPOcK6xvh4
         +jEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bYpbvfZW;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id kj3si425238ejc.0.2022.02.07.08.54.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Feb 2022 08:54:15 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id D153AB80EBD
	for <kasan-dev@googlegroups.com>; Mon,  7 Feb 2022 16:54:14 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 89EF4C340F1
	for <kasan-dev@googlegroups.com>; Mon,  7 Feb 2022 16:54:13 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 6F998CAC6E2; Mon,  7 Feb 2022 16:54:13 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 214861] UBSAN_OBJECT_SIZE=y results in a non-booting kernel (32
 bit, i686)
Date: Mon, 07 Feb 2022 16:54:13 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: erhard_f@mailbox.org
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-214861-199747-bBDTBjryH5@https.bugzilla.kernel.org/>
In-Reply-To: <bug-214861-199747@https.bugzilla.kernel.org/>
References: <bug-214861-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=bYpbvfZW;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=214861

Erhard F. (erhard_f@mailbox.org) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #7 from Erhard F. (erhard_f@mailbox.org) ---
Just revisited the issue on v5.17-rc3. Seems your patch was accepted as
UBSAN_OBJECT_SIZE is no longer available when building a x86_32 kernel with
clang.

Closing as fixed. Thanks!

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-214861-199747-bBDTBjryH5%40https.bugzilla.kernel.org/.
