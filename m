Return-Path: <kasan-dev+bncBC24VNFHTMIBBSMW7L6QKGQEB7IIJWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 43DAA2C45E1
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Nov 2020 17:50:19 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id i67sf2122957pgc.3
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Nov 2020 08:50:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606323018; cv=pass;
        d=google.com; s=arc-20160816;
        b=WfXbqh2m9zEs5vSoy2Xeb+YP/vEaMLmOX5QOWVb4GMiXUxl8FcuxnSQR4wPyxjLQEH
         9GTU6D/KklykVolcAQpWQQMJjjWZndRBaFhjYS4dE5CVvbt4w1tAWGqa+oBoggT+IXJh
         mxEL4EjWdUwV38/EA49cBBxaiVAxDZ7MVP8MsZBZxvIqY/S7rSkNbj3GVx+DcNALmBB9
         3t3mY/zdFsIhYvsbWP6ABP3/l4YNd0G7CFnM18i9c+qs7Yz1GDqLQduj4VTnlsZzDYr5
         aK9LOVyr8ox+IcFxK5pyoyIxZCo0u/8CCnK8XsAaUg6YGc4IVy9OnjdpQFWRhX/mkSlK
         Rydg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=RPYzw2mSQlfy9t0u0W+uSU2q4G4iXU3Uge0jQwqwhjU=;
        b=yvwSO9pBbUAnZBqNb8KaNuTZT/N46JDE52PPHTzVXQdmPR9Soz3ghMuj2viDf/m595
         IFEJtD2dGat9A/Q/SOCM2b051Bo9x3Z2B951VLz/bz2zaBhAFYLLEN3mv5URSEQqXVlv
         Jeg0F0YETlgqsiJC0hiVyea05SKorz1+rmoiyPD09xrzosG0JJNUob0wBBkz5HktJsJR
         trJi+BAiBvlU3okiQEMsFypPSo1v3Q/baS6bSSsMiPzRwzXRqeoPqB5ACsQzb2t/XyFh
         Qnr9yDcHbCHBneOe4KAgurYxGzrM4x/EhUd3RWLFDDOt+Dx34+ZtnVIdMyMkBuZe089G
         K2kA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RPYzw2mSQlfy9t0u0W+uSU2q4G4iXU3Uge0jQwqwhjU=;
        b=Xadl8jM/2fOZS9PwSeju8hFek6hqFQJKsn4jMH0wjiU1l33EIJCNv4weoEzQK3iq2M
         zHQ1lKjTmRAvWALiO7glpy9N08qZ++eQq84yI1sdyN6UCIcnHMjhOLavoh2hV6vKpLGL
         Irvfnqm4mRMVbjQYs1jU4IJUpYhPiDrtVAivcBUr2oQOc0UTowI8hWHHRcAANL9m2Rfi
         PQE+7zqHuAakln62oO8lMIsq1vIdq0GE7PoIj5SVFj0KLU7L8rqpCYCENqMZ6IANByKP
         dhhNNeiJ/m9DG83zhP/RhAp3Mw2E6hVXm5mHHs0dPw2zXzZC9BgHYbWJQ6aSEEF4UvLW
         eDpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=RPYzw2mSQlfy9t0u0W+uSU2q4G4iXU3Uge0jQwqwhjU=;
        b=feq1Z3duf2FUdLPupkWw3Yx44Lw1CkSemERlgCo1OQn0czTWGqXlS5MZBJR+1nBf/m
         7e1vlSgDqHu2hCMb7m63vTeOUn3+qBiUkpKGAOHnrGp4jQXkCHfCafuG9spFTgQAIZYA
         M7CSs8Kajc7rl8pHLOLwvQLcJ2zrNUQ+Dd3P3Ly+6vhMAac1lywP+orYWhYLlM9p6fu/
         CpLX7yZq1bQE30Xbfa4XtEtUl0Fi8BrYSN9adi39v9+NUut8rCiyupTLkGyalBEoRaGC
         IOmpZIXMPlUM8dYykJaDA5TyDRAz5iHU2V362dxCPWvyOf/H7UMw/IeVyI4hJgVsKjDX
         qJug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532HeGz/RXRUo1a/ffYPoUWmDUSchSPeyRUImWabuV8joLBTPOud
	71xyoE3Bhotw9R7owGMCIf0=
X-Google-Smtp-Source: ABdhPJzZ0VJuqWopvwP1TGf2cjEyAtg+YjamiHgNO5MIHQSixi1PvJPYgUZZMtBoC05V4UgLbU4ltw==
X-Received: by 2002:a63:f24:: with SMTP id e36mr3817233pgl.57.1606323018029;
        Wed, 25 Nov 2020 08:50:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:881:: with SMTP id q1ls1140566pfj.4.gmail; Wed, 25
 Nov 2020 08:50:17 -0800 (PST)
X-Received: by 2002:aa7:8494:0:b029:198:aa:bd6d with SMTP id u20-20020aa784940000b029019800aabd6dmr3857998pfn.13.1606323017490;
        Wed, 25 Nov 2020 08:50:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606323017; cv=none;
        d=google.com; s=arc-20160816;
        b=dmh056Zh/g9rZD5boyt0pK4VinHqyxZ8M/WZ/S2WVaaNekNaNLecfN9nlCGVPN8dk8
         /5M27kjoMqgU2710q/9tjTR6r9uulocPLusaS00A6gf0kCrptvGl00PVKMCAvn7QYZ8V
         ryxBNiZf+K2qXHSzREPI7wNS9Pm/XMCcTDjcwlk2Z70LeQQuVeJ8Bt2Twvvmd3BLD3rV
         uvo0Z+0+lL+ByS3MDNWDxncEHHdoionuDR1Lnp7vsgc6rkDb41N8lNfy3o7YPuNi/N/X
         fyYLX+KvcU/I/j5jXNoDOa7+7Du0UF37sRl00HiyXEoIAX9Dh7PK2Sc6oZ6evzTct/jW
         ykzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=S6ft1PiJcN1+4CdUE7m0wx9tUV3uS8ZeRoahWijv4GI=;
        b=DJCyS3zuiIYm5O3W2hpJI+K7hgysN6Ws0nnOAsxKQOLB+ux1SfquCRvtIVFOqIELDN
         WEbF8fP82E9oR/b4jHnYJ6jWE9EXCGFaTswIJ7hAZTnjqilVz5BujouV5F08yCQ6obVH
         j43vP1oVwWeBxU3vl3rlgRjj9HyijZgXjz0im7Y+kQ9ViQTtQjFJx/91KnONLVxy+mvU
         /P0Lj3rR8tzhR+YoBMEO3ak6r7oiYiANuhq9RPzWB0iTgk1+A6Ew6ROFK97qaYbMkwg+
         7PcHl+56QfGRz8k8QDVqaUWyI406DFNeoeYE+SXzRhllvhOj8pg0HcjMZF8ITqzkZsXp
         zjmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l192si170742pfd.6.2020.11.25.08.50.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Nov 2020 08:50:17 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210293] potential kernel memory leaks
Date: Wed, 25 Nov 2020 16:50:16 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Slab Allocator
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: vtolkm@googlemail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: drivers_network@kernel-bugs.osdl.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-210293-199747-MLUg6zLNWk@https.bugzilla.kernel.org/>
In-Reply-To: <bug-210293-199747@https.bugzilla.kernel.org/>
References: <bug-210293-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=210293

--- Comment #12 from vtolkm@googlemail.com ---
Good, one less potential cause.

Any advise of how to get to bottom of it then, because it seems somewhat
unhealthy?

Each leak report shows:

ret_fast_syscall+0x0/0x58

but that is probably not the cause?

How can the dumps be deciphered? Or extended/augmented with additional
data/info?

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210293-199747-MLUg6zLNWk%40https.bugzilla.kernel.org/.
