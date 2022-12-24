Return-Path: <kasan-dev+bncBAABBCFSTGOQMGQEIXAKNBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id D771E6557D9
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Dec 2022 02:42:32 +0100 (CET)
Received: by mail-ej1-x637.google.com with SMTP id ne1-20020a1709077b8100b007c198bb8c0esf4244126ejc.8
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Dec 2022 17:42:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671846152; cv=pass;
        d=google.com; s=arc-20160816;
        b=T85g/kjB5AiwRQ4va6lqo7T7LUdD6oY/Ee82IMW9wz7sIVLLTupNpXfbRq2a81x13f
         Yb8TWrtMEIn99JkESUhjxYXVy5weWMdZsHfRk/iuY0YavOqx6kLyMOjIaEVW1YXqy5KG
         0vgGBJiFaole+50lpaXxHNzps4DBHp0KEdC5NTW8O5chbCzomaLlQiRkaWKZTmRkIy9O
         t5/68TSN6Cwy9M0LeDT6F7uGCPM8vi57xZc7efqhez/OFdsB/8y48VL19Q/ZBaREZ13p
         FgBRQgvufR4zQ6DEu/IBa6TtBDcW68PJO1MnJwLIvT59tHAFHttQFQXJgglJAFJgq/7G
         d3/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=HoBuD+9XHRr3k8lyU1rsXlCXyS8xVCBjaCRm2UYr5bI=;
        b=PyRWh5OYF2GAmMN4A2tYz/G/rT4Yq2b4z6p0MZYfOYXRSfc8EVJjAdm2/y6lYJ+u2v
         G8YLLL71KGb8/Cw2CPoR6L2WEbCAv65LXYrRgtRIetojsKGDx/04FJ0CauF75e6j4xJ9
         W6Ta97g/1WS65mTiHl4ptgIPHj92UZtiWzOGR1NX6llKAcaIFq5zKHj2Nx1sFcbkj6wp
         LStJGDD8ovnZBcAtAnGG6X6qgvLtrSmU117xI8fzyU+IjZ5x5Lt32O13n9S1bQCwIFgI
         Q8Gtz8IdIVZhZKDeGvxuSFoUDyFDjkphh+aS+XFtozsMJ4b2ufsMplycLRzVnX4Hpk9d
         EoOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jTkFjtni;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HoBuD+9XHRr3k8lyU1rsXlCXyS8xVCBjaCRm2UYr5bI=;
        b=A4jsvyKQFekSuKmSB9Evq/I+dnCIJBk6XSV5cJ8cAxitHqLt4BGHNcd0B8Zil5UODd
         YJsQBS+VJQ6Cy6kZLPF5ps3ezJUZidXQ6b7WtNzArjVGfdIGOvx+t2s7Wo1zT44Tm5q9
         9H9So71hDa0uTZTD43MUocNZaCCDWI05yp+vbLjLJG4wr5AI0WCVWqFxuAIDmassUn2K
         BzyBSu104wrUkb8L3RFQq7jgRPGZG1mXkMbncTJTCbR573wM896LKW3SHrLaxuomuV8d
         ho9l4yeMqOi3C0+3/iQ+UOYOpZcIFcgj5V8UVgXDQndAKIEWNRjKvPKBZAK65JfA0FDt
         +IAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HoBuD+9XHRr3k8lyU1rsXlCXyS8xVCBjaCRm2UYr5bI=;
        b=Qa8TKSpJvzcpkD7kDo73XObVeFTa79hkUR6W1u2ct/F2q79fN2zyUAHzZFGyIU3f32
         dYIuJJrplvA4wF9+u15yL6ge17B/Hwrmxk7oMF1wz3otnIaCBjOyQbki2g+X9LBHxQRL
         /CSrUq1AaJShfWYEXZiYyDDCHr82llDEoPvQwJbkrdEei0GzGuffvY/NI+3HZjcEPyCa
         N6P87T3mT+bgugUGZ5wu5Ysz9Fch1xeDbHAO6OXAMkwAjYLLqovs7pdCU4ILCMHdkNdR
         s9cw6zr1uku6tHvyoHQq8Ri0PGOE91S7M7eptq8xJ29T3g8op6E1ZZBxfwUPd1VcHkdX
         iLwA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koJsrwWeVyDaCASRXF4gD7kqcK2GrZzdE6wkDrh1MCVcu2sl95u
	eeZBWeeUTsYC3mLN0rYbRhw=
X-Google-Smtp-Source: AMrXdXttcjvpzjkRaF941sJukIMNH55G5oYLOVumWiazP7pB0lOU1ZnU3AvQkVsL3nMfb5FbeaiOAg==
X-Received: by 2002:a05:6402:604:b0:46b:e7c0:9313 with SMTP id n4-20020a056402060400b0046be7c09313mr1434666edv.412.1671846152424;
        Fri, 23 Dec 2022 17:42:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4413:b0:43d:b3c4:cd21 with SMTP id
 y19-20020a056402441300b0043db3c4cd21ls1121016eda.2.-pod-prod-gmail; Fri, 23
 Dec 2022 17:42:31 -0800 (PST)
X-Received: by 2002:a05:6402:360f:b0:474:47ce:ee8e with SMTP id el15-20020a056402360f00b0047447ceee8emr10305785edb.30.1671846151691;
        Fri, 23 Dec 2022 17:42:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671846151; cv=none;
        d=google.com; s=arc-20160816;
        b=MwEXbqZiWqHqqgNrjn8M4EVC8mNHhBLibF/ef1M7224avQt6Nie97mlvz+6JvJgot5
         1t3KeB/T2MxGYN9GxLJ2TwbmKX/FjuG5x2RQvDYWrUOnxXrunAv9wETHnruN6NGISpqt
         KAgrGjMadquftGJBD7fGO2TjJrYImE/+lxHR8a+tN1FO+HeMLTzf15lGfrE3PoSU+Lws
         Tlu9QPMYqe7iqX6P0EQNqyWjDqrg9/t034NsTpV/ZyAJ1Im+zYTZRxnTSqCPZ/AF/kpz
         IeQTBPCMk4pzhHd69Ky5Um1NdykY6PiSEBCrvV/V1bRrRB+AxDNnW98Rwst+SpXjBYGi
         /sKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=zt1g5ce25ry98xyizGb+8nEdvwINrmdBu37Jutqnf08=;
        b=N3rSwhkA8p49N++E9Rb2bY1c6UztjkjKHVDICG+SA2NsODeNK8UuynnFkw8oRNO3e4
         qG7pouaMLBO0rto5m/94jGu0BlD/XoCDHAk9TZx1e0obqunD22W1/YcW1t9Dz5dcTUQB
         3no/PeOrphUbGCZ7rO/w+HwGJd7q1nM371A2xJwgCQjxddT0E/mAQdw7/JqhH7cXerTK
         1GxPv+eorpR8P3Io9KjALGxaJxBq1LwUGujtl/KHEITU6HFTvjOAUo/1O90B18deXXVR
         bgDWnvaqebzWyvfKK3f8huLsQQL5eM7Zhk8GDYbnWqbEaagElZRIBbDLhwBALb99yFLJ
         LBMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jTkFjtni;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id o13-20020aa7d3cd000000b004704dd69bc2si204982edr.5.2022.12.23.17.42.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 23 Dec 2022 17:42:31 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 6337DB820E5
	for <kasan-dev@googlegroups.com>; Sat, 24 Dec 2022 01:42:31 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 231E7C433D2
	for <kasan-dev@googlegroups.com>; Sat, 24 Dec 2022 01:42:30 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 0F7A8C43143; Sat, 24 Dec 2022 01:42:30 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212205] KASAN: port all tests to KUnit
Date: Sat, 24 Dec 2022 01:42:29 +0000
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
Message-ID: <bug-212205-199747-EODHERcnxu@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212205-199747@https.bugzilla.kernel.org/>
References: <bug-212205-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jTkFjtni;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212205

--- Comment #4 from Andrey Konovalov (andreyknvl@gmail.com) ---
Non-copy_to/from_user tests have been ported to KUnit in [1] and [2].

For copy_to/from_user tests, we could keep them in a module, but nevertheless
integrate with KUnit. This won't allow easily running them during boot, but
other approaches seem overly complicated to implement.

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b2c5bd4c69ce28500ed2176d11002a4e9b30da36
[2]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8516e837cab0b2c740b90603b66039aa7dcecda4

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212205-199747-EODHERcnxu%40https.bugzilla.kernel.org/.
