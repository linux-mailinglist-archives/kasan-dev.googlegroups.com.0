Return-Path: <kasan-dev+bncBAABBGVKR6LQMGQEUKV5ZMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EC77585023
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jul 2022 14:39:55 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id u7-20020a2e2e07000000b0025e08e5df3csf973102lju.10
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Jul 2022 05:39:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659098395; cv=pass;
        d=google.com; s=arc-20160816;
        b=Er4bLZaA+48CsvKftKoXs3EUlWxg9oyVU/mM5PUXnflLHIVJJoY1WvPaChZHQ864RN
         zcINm6Gj3b6kcSV/MKHRJTrVR8E6p0NBZKYFsdCXhZdXQ3iGMnIHOpA4i+IHDlD8TcDc
         iHTNc17+k4Kc3b/VQ7HhE5QfaZlP/z9n3lGEtDvoeq5xA5f30KkenxM9v2mJ29UCXbki
         P+R8tckG3o+TCiJwwBwX9ZiwwRoCIpIqExNcxZ04jQcvoBQuOCssWYY3Bc0Qtu+UlFH+
         J7IfA12u4WedZ3FCO7dE+fmluVx7w43ZZFZprDGgnTMwCXcxKAV8GEMvhNVH08IaOomc
         oJkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=jFKdSB0t/Fc/25EYFu9AfuHw9wdWC2n4Ctl1HvXOpoY=;
        b=ZU1QW9d62QLem6wZ0HLlrTC5Ip37wndRowT7VvfCASSNc1+AFOJ2UCAJg73AaiyBY7
         uvEvT4guQJfFpPZFEe/K8H1y0uCy+f4o2CWjM1oCF7MGhyEI7GLp+ZKfFkpUb2R1y7nr
         yrZKDCkjSeHcYuFQKESlcnZ/1mhDvYqddiHV5iscqzmQbvtp5GovFNFZnKCfvySsAWqE
         FxCvfj+8wNLhy2mlbDMe5aLjOSpEIbk4Ohf1qfzGRtWfQEDEy3GRZ8M0bTjYSCTBsS8R
         iWsKh3RL4ChGU0N6xLkH1zlUahE1TZoQUfVCOkvgDne/t64BbqyqW50gBPPcf8sffQsH
         zarQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FtjvjKr5;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jFKdSB0t/Fc/25EYFu9AfuHw9wdWC2n4Ctl1HvXOpoY=;
        b=TxDI9oJrZBJVaE5gTyA9YAlBtBd3lJlTomMk7cJQiLhFFKUTLgI4Pz/yn8k2/COfyJ
         CXEhtHcVfTG96cBm8xvWA63mBkRIGr7hncbjLOyIsbRJuvn7R43LFjfONvDB1rOE9X5a
         VxyxviTQvVm7j36t4JhHbyyjjvJHAL1aSN6xC1XxGv5w6Z4j00M75nBJwA4vy3o2O11M
         MOdDSAgwOUohTeqBPrx7fvkDzaqHweiVk5hEXT2VY2RnDpWEb2NYifaq/651A6l6ISY7
         kvzqRBxKusFOgceJGSQRldP+HC4Hqqui1W0mLiw+NVcYedw5xyiHHYpf9A0rzvlmd9Gj
         Yh9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jFKdSB0t/Fc/25EYFu9AfuHw9wdWC2n4Ctl1HvXOpoY=;
        b=dIU6sd9VXw4sEZTmURk0paLAeC758kX1tCYjV2vAcUwpuXhViJXsnnCcgcY20p1yG7
         oG4Yu2Lo+EA+4w0EQh5LMWS2MM6cU3ytWhw5m9BO5rMlPbu6koxYrXocB7Nj5qliC4QL
         ObGT3ZGwE+D7odKLsPvzaOpaGlIerOBH2ztDrvMAM5jTaYBk2UPKIwN7m5gmrL00VJxv
         fuwCPRwyzCjHMTyrd1MrVguyouz7dGyNUd9XE9lHU3S559EFruheuudFobkmJMC9TbxD
         IJSj1mXnixtooZVghcnP/XQPO2+EmM27jFpDCVMuS3DSzwSJgSJRnl71hteClWeVVv9x
         kGyw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8vAAn0PfxxI4p+AMdy8WVCEJ5WPei16yYmM7goR9K9Xo7J/gl8
	Cy8sGAI9wumrOEdxA9gai1k=
X-Google-Smtp-Source: AGRyM1t8BzyfdtPcs1Uc+0AAKEp6JzSNNqu/nYoYC5nnYQYMKq8BCMJXk2uhrxxTWdrXpdrP9vVSVw==
X-Received: by 2002:a05:6512:3f6:b0:48a:916b:a6ad with SMTP id n22-20020a05651203f600b0048a916ba6admr1103736lfq.345.1659098394806;
        Fri, 29 Jul 2022 05:39:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3445:b0:48a:9720:5d28 with SMTP id
 j5-20020a056512344500b0048a97205d28ls400942lfr.1.-pod-prod-gmail; Fri, 29 Jul
 2022 05:39:52 -0700 (PDT)
X-Received: by 2002:a05:6512:2243:b0:48a:b093:233a with SMTP id i3-20020a056512224300b0048ab093233amr1251389lfu.70.1659098392434;
        Fri, 29 Jul 2022 05:39:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659098392; cv=none;
        d=google.com; s=arc-20160816;
        b=B2TB4dvmwQkEB0S2uGjsoHiJ9tRJby6gAbmr6Lzf6yn1N+Oks2l6No7rBVLNURHlc5
         Z/AFfyFbzR4AVEcLv4KlsIA+nE3FlTWxwcE7EtoTpJdrwIxERwPqKp58fWO9rJ3umN4c
         JJqgbr7VZB7/t4iempabsxQGBsNXP5lfYmmtzRZsK55t/thBYCpMaR3qRND1w5HA/C0h
         +PXzk4Q92NISF6qhyoAwdPK7NUShuAPgSX8nU8y+lqMy8hX/bW3/OeB9Fe+1vHfRKS+0
         zg7oPTWQMhhDlHtwUDFttZAyr2HPCdX+f+y/UhSWG+wfrXHsZJ/uphBv59hwdwM1zDE9
         xIDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=hxTy9YkvWIaxRn5J7U1WoGv8sxYX6feH972JJoxzZ9s=;
        b=m2Un+UYIeTfiHhuFZdM+wycUKOPyxVjrLqSp+R2WwFobKZUAB3M5TMg5SFfGgbCU3L
         WKFj1htohmIzRCwe/IfmtIwzWpoXw5WLNScPnRbZY00HObRr1PHSL/6MEqEWFdAwwM8b
         Qjl3PkWbwUS3jEmtxQnnOfCppJxgr/rJHCJujnAYBLOPtg7ehQvoG987tPCuWxOjlY25
         L7gk4jvu8Zn2FWGXvlJGVD1kCcuo89EUeEWIuGAFGlECAwSLIhnKJu9QyQxUaAvLtgX6
         HHv7Ol1V/lpmbwBNHkXQL34UX0A0MmAw0N9SdqNd87vvvbVNsZkWQHrL3hoCgV1ICUY6
         lqkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FtjvjKr5;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id u9-20020a05651220c900b0048a9b517b75si131756lfr.1.2022.07.29.05.39.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 29 Jul 2022 05:39:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 7B5C5B826FA
	for <kasan-dev@googlegroups.com>; Fri, 29 Jul 2022 12:39:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 2E66FC433C1
	for <kasan-dev@googlegroups.com>; Fri, 29 Jul 2022 12:39:50 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 12DA8C433E4; Fri, 29 Jul 2022 12:39:50 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216306] KASAN: print alloc stacks in kmem_cache_destroy() for
 leaked objects
Date: Fri, 29 Jul 2022 12:39:49 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-216306-199747-apm9u99QYu@https.bugzilla.kernel.org/>
In-Reply-To: <bug-216306-199747@https.bugzilla.kernel.org/>
References: <bug-216306-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=FtjvjKr5;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=216306

--- Comment #1 from Dmitry Vyukov (dvyukov@google.com) ---
Allocation stacks may always be the same for custom caches, but they may also
be different. E.g. in this case the allocation happens in a common
p9_client_prepare_req() function that it called in multiple places.
But KASAN can also provide "aux" stacks that may also give some glues.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216306-199747-apm9u99QYu%40https.bugzilla.kernel.org/.
