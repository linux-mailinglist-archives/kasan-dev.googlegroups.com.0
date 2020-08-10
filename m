Return-Path: <kasan-dev+bncBC24VNFHTMIBBXNSYX4QKGQE6PT3V4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D54C240794
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 16:27:42 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id 195sf7148431qke.14
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 07:27:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597069661; cv=pass;
        d=google.com; s=arc-20160816;
        b=jGpf7ii1J+A+Sh7QRHFQtkh9FoJwpmom1FQKOKHd1J59U7x7tgpAjPUubo3yUmaTx/
         16QOypNd/0FaROnROhA2vLk0iZvTquzc0usdnZTanYXidL4477fNPsn7NSFt7wQe/MHM
         d6nXq9ADbHVukAspNeWjzLyF9OIpWcmwGUoy/8x8bs53RbVhZO4F19jxjk7XcTKBviwd
         CrcZ7rBqmjNj4siu8G0bIjKvNjXFH7GvXaWU+xQHd+QeI1dsbUpHRNoAz85w2SzNnI8a
         vILn1nJNZRIt9xHz+9tdnAz0nBTukWcoglp1WSoKCcbjMintRbyIC5A6sY0kuchycBv9
         WX7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=eSHxHXGCpibhfOxTv/FtNc/sD0M8zB4DQwtt/qnBLxU=;
        b=rbWjzdbFwnQJUhxk8GbbxyXdIw4rmb9fO1Gonv9Lm7VQR1slpsDZsfDevLeQb5sL6Y
         TSSaWp+PoWGn5h3SVixd9K4dfPZkyKFhx7irmZV6vi+rgDmrdFn8vmZBd2DYlyNQScv8
         +v0ZsP+AvErsKubzR3sQNUE4xKfXdGIglLEpd+/Nkqk2PVvNeQCeSGWiOG4dvonCP2Mh
         UB81ZYGFBgsFEPCV2ATLUUMJNmOPtCFJlYJZXAPzp3RD/u1e9TMLWFnNyOtrLZuG0WmN
         3xc/XX+4zKSY4+GXWyqwGxAYO1BaAo3R2WCfsk19LRzfkbJyp9hTSdjUfhfG4j1Qwj1P
         kVdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=lle8=bu=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=lLe8=BU=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eSHxHXGCpibhfOxTv/FtNc/sD0M8zB4DQwtt/qnBLxU=;
        b=B+1KlX9jx9/o1BJLjRaJlwxw5C8waZ2znT5ixpjirORzHPSny6/Sy2H3hWhesZLqg2
         n2f0UdXu66RKs8Kax3Fjyr9Gp8Kx3HbvXXuuzA5lJ4uk/0NTlzV9bYzuGQFArXPmaNzQ
         cs51BbGV5rsHDHNk0TglybgoD/aEbEwyyQe+9E+LwNkLDTbJoXC59G2P75mSlh9Ko0oB
         Sm02YjwtB8t7Lyq4BPlMn/n2met7FNz8Fm5lmy56y1ADQQGgAKZfxWp6Q5/spc3REaFc
         FGSEZJavAC7xYgSJFCW6ftHFhE9WjETJsmal6hmZ/OnthFTlIt3HYDfd20TE4MdwIC4I
         So9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=eSHxHXGCpibhfOxTv/FtNc/sD0M8zB4DQwtt/qnBLxU=;
        b=A2oVjPS+4HCiQFdy11aGbewcpaw4zelhAFAJPexXgxBZ0wgai0rolHZ1ku/2BkxksQ
         CmbzHMQaPUZop3s2H/s9HJ/IKJc6Q3I1VjqQcd/YBmqOzygzxsxsoc1ScNCfm85VdvTq
         Cp+h6f718U8gZ3H+IDTN68dFUofb31rZbe7fkE+5NesXcM1ZruCbVQg6+VcNCppiCk88
         S9Toe3Ni99uSS3/xPwrdsY+egnU744JYP1C1RPFL1DrqunJNTscyQYH/iki9swR3ikvE
         pHRNuO8gucKemcN/+irLrZOr7yEEX+Ov6zwHPkIwk3dq2MfsdGBR42vulbhwS//TS8NN
         fgew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531+rK6AMxWrd1RBUBiMg7MdnxF6OjJNeHwcoCCqZdXBg1Bsxcqq
	Fsk9z4wZoMXj4Xl+k1vUgr4=
X-Google-Smtp-Source: ABdhPJx7CmFgR2IYIM8W/EVJpn+/5hte4sNWNFRZInNUQE9U80Bgx9bSGq0k/R1+XupyS38YeU6Axw==
X-Received: by 2002:a0c:aa5e:: with SMTP id e30mr28289216qvb.212.1597069661627;
        Mon, 10 Aug 2020 07:27:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4986:: with SMTP id f6ls6917846qtq.11.gmail; Mon, 10 Aug
 2020 07:27:41 -0700 (PDT)
X-Received: by 2002:aed:2091:: with SMTP id 17mr27199628qtb.322.1597069660640;
        Mon, 10 Aug 2020 07:27:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597069660; cv=none;
        d=google.com; s=arc-20160816;
        b=Xsih9qwGUrVEtXrPJh0XPED0h+jqlVl1GhkKHH8qIjT2g5jhmcTtYIHFb2q+m3ZOTF
         3CZjWYxD9OFRRs3eGTYq2JXIAff/xF6XRzUB0MOe9bREPcGUmsl4h3+HleJ7WdCXUZYH
         yGl7bXUrCa7ynOiXIxQkVCjdMUNHjAJpPy3SXtyviNiKj+c9NE23WRzyMQQVxSSR+rp3
         DHahw0znanD09cHFOq1C2GUyXxTAEOFwZuFvZlu/UnsCDLuIhqDO/N+LRB5R3Bhs/8Wp
         CWerykkxnGbqROXjJOp3MQd+gIsXRjgl+5q4pTU/NE1MbR0qTwfVzmskeYTYAUmilair
         LdCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=BsktJrHFBFdl4RtsyBc9mEBS4wVOUeC5uzAFBfML61A=;
        b=ytB0ENdQyrYrc8D0rAKaQcingPnVLWS06FLmjbDq343seXNs65UqkEw6Ir6LeTounP
         hK8JLlWXrCFds10VAI3fP4kIWXgYszA/oHwvrBBRSX2Bv25/gQOhbh2BDF32sicXCXB8
         pVWWG9Y5Kg2asuoQ7jGD/esWsA5+ez3JgvxPrs86vnKMiiFZS8kSwl8T1DYgmASjQNTc
         juxWiTOFK82muYh2sg9PTMF7n0VG0nYD7ypU7gRKQu6k/FFaW1OlBik4GzMCKHja5bes
         UgSHpF2b2i5+CEzAD7/9narel6y8eH1Lw0bIg/7PA9Wxu8vaSKmcLZDI8rrx3ikOFNgH
         maRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=lle8=bu=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=lLe8=BU=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n26si1102065qkg.5.2020.08.10.07.27.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 10 Aug 2020 07:27:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=lle8=bu=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] KASAN (sw-tags): support stack instrumentation
Date: Mon, 10 Aug 2020 14:27:39 +0000
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
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-203497-199747-7EcDUHNN00@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203497-199747@https.bugzilla.kernel.org/>
References: <bug-203497-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=lle8=bu=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=lLe8=BU=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=203497

--- Comment #25 from Andrey Konovalov (andreyknvl@gmail.com) ---
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8dcc1d34661d58a7889fb06517c8738d1412d1bc
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=2c547f9da0539ad1f7ef7f08c8c82036d61b011a
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f9409d58e972cada2c524b7f1e54631bb8fa176f
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=cae9dc35ed9ff82a99754e51d57ff6c332e1f7e4
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=51dcc81c282dc401dfd8460a7e59546bc1b30e32

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747-7EcDUHNN00%40https.bugzilla.kernel.org/.
