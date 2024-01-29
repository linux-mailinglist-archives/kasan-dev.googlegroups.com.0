Return-Path: <kasan-dev+bncBAABBX4V32WQMGQE4O6YK7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C43C8403BC
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 12:24:17 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-42a9d8bf961sf354781cf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 03:24:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706527456; cv=pass;
        d=google.com; s=arc-20160816;
        b=Nn28Ag+iKkIzBLvNSEb7cxymopcPP7Q5cupym4DkzcGdT7pvfGPIngLX1M/Z1IfjDg
         ffy8fl/jc7Yqi8s85OrWV8hrNkNrpDiEmxry3dpLD2jRusUvDO7qOWtybx6mKsdM4Brx
         NkKcCdKKnyMeLunLfoHVspgIq4tjRProLx5JektLCXJSZ5wQYEVjsOHLRipLKQuJv2Le
         XcO1FMP7z41pYxBsl54D/tHNOItnpQuDu+kTs6rmSH5t/XVCGXHZ/53wwwEDemaHUlrU
         eC7ekd6w+qa5m1eNeUPGIhLLKPqTbDNXUFWHNJF730JtB4YxMWmsxSCPR4NcqGm2iSAO
         R9aQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :content-transfer-encoding:references:in-reply-to:message-id:date
         :subject:to:from:sender:dkim-signature;
        bh=MeinnvpJOS67tGL5+11o8OUQ9fLbea+RyTGF5XTVV5Q=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=uLm+Xeps4oCCRxIL+Rp8jUk829AAAznDssPZ4Udpx5Mib9QCXkM7ACMzIi0A2pv0pN
         492Y+TAqYJZ3uNRRawhA000rBsu/oZ53y6eifD7inQg0FshnlsId1An7MwxLV1Z+Fre+
         H3chBHSLCYZGjKcVjdDywI/jpWIi1ni/wJykUPqhvUPysovpMqJGoA2ty4C5buRQ9h2C
         nQIy9DjUJ32IENmpBhmAnPcwNRldV1uhfnp+cODkaZqTmLK2QdXZ43zLypOwQTOPsD+U
         Fkc7/tkKW6Jfvnp2o5UiqNbBOHKiDaT+ynU1wnkCsVH7LA3uo/Nmkptoakd4Z49QlQ5x
         aEvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AO84hzCw;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706527456; x=1707132256; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted
         :content-transfer-encoding:references:in-reply-to:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MeinnvpJOS67tGL5+11o8OUQ9fLbea+RyTGF5XTVV5Q=;
        b=BJUmzYAbl1+IeL9xF1BJ53onJ1C1h99XTFlFJ1uXerHQk0GgEslV86yuWUGlw3sZvg
         fdpLo+qwtrIbsZovYedyISxl/QlN3oyirjWM6P0SSQxaQa7kOG4GMOLN8MuRgaPmYnr3
         cBeZUmqST8Ima2O8gmAqQAPgcVAJ9/FX3Yf20HYJUQ2tMo9gbz4wdH4HWrkJMb7ntJUN
         bXPv5B0oERq2eRZHDacIqFM1aK4SJM6LRNCo4CNx7uELKsEUTRPIYmnp3DtwYkU9ie5o
         zCs6pgwOvkwqSaFZRdabXMlLGjfPq2LscdUmlO6iH4tliZoqJHrsHDHTiTMahOgbQXLL
         E8aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706527456; x=1707132256;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MeinnvpJOS67tGL5+11o8OUQ9fLbea+RyTGF5XTVV5Q=;
        b=aobo0/vjlZYQ04uI+Pxairdr1l/dla62Scc9ZHe4LKGFFEBK1VmmEhleLak4rCXBey
         2cpJ9RjdNvluYGVcipQSI+mN1M0jDDQyIt7ETZDxAJhWGOFCr/XlhMuG0fi+5YKQTN3N
         6p0c4utk9/WNfKOhv5F61X0RzXEAAeVaNX4JFMLeQ5tTK5EEynBlznxW6cdi/+UNFpj6
         UH64szCoNqoxuVXj7OaZDMw/vhD5EpkDCpdWSCmb5kT5PDoAb1KRaorsz+cNNg2sJ2rk
         jz9SG4hgoyYuID/+0MZcnw7MjLwHN+cDMNaeDR5svknbbx+IndKSx71HnvFi8PsvzLPV
         WYaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yzaw1UW0tRHvp/h8S2x4RcPtoMxhY7V+pfHu99m8V8cGsgI93hU
	onLWVZSSmMsmxVpdv858Wpz/UG2tjK+4VhaqjZZTnMfv1AJAhLmF
X-Google-Smtp-Source: AGHT+IECRPL5bF92TATj3FDvKgzlYf+oofr1KO9xYzH9HAXV8TbYlaxvlWx9hiRQHh5zBAZYW/JeLw==
X-Received: by 2002:ac8:7d8f:0:b0:42a:7e50:74bb with SMTP id c15-20020ac87d8f000000b0042a7e5074bbmr590369qtd.25.1706527455720;
        Mon, 29 Jan 2024 03:24:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2503:b0:68c:45f7:b8a9 with SMTP id
 gf3-20020a056214250300b0068c45f7b8a9ls956393qvb.2.-pod-prod-04-us; Mon, 29
 Jan 2024 03:24:15 -0800 (PST)
X-Received: by 2002:a05:6214:29eb:b0:68c:537f:4b32 with SMTP id jv11-20020a05621429eb00b0068c537f4b32mr727008qvb.107.1706527455115;
        Mon, 29 Jan 2024 03:24:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706527455; cv=none;
        d=google.com; s=arc-20160816;
        b=n67ttRQHy9yKAEMVP6EBvF3yeyBvxSMXtZOa1jDMquPx/z6p+F8ES+L0tYI57SJmql
         34PkJfk/i96VSkXK8BqRwTdU5br1IKIqtZpgtvz3KDyQWA3MqFHlUgsusYQ79euw64J9
         9qI+NdadscQx81MzP/xonmH5gAybTb2XM837Q19Gw1WWa0wX/AO+y7tk5d5mkzJ8KIXh
         2lRiEgmTjfNyh9FTfhraEuS8+dVegebAbk+1PUL1/WMeBgkHI0a7SAXrx0vg//W7f9Pt
         LyIpegjTwZTwHlKk7GJIcmiApb3KVh1Kz6KJxnw94FNQv4wOnjl94ve4B3NWYD3sSq5j
         umjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=CKR/KZEuXoyzy7IdZUOIxl+DY0PKF5RRWdq3Bf+0LEQ=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=Zvha3NVDl8D9rEb0auwBTjwk+g9xmCxbeFXktvuMe6bYMC3XDGlez2aeotlzMBe+Wn
         +Mzt8gvVefe5kuPO/tOLXI0i19Ex9r/MEosliPl+wk/++ZrVo4JvgVXbDVQraeQjN9lN
         hquB2bwDIA8AR2Cuk0yJ3eI1I6+QRAfO2B84zcDDmTMTRhB9Sfh5Ekc6tIRpMbHhlzSB
         /3vn1fFthnEkXXAevM+huT+LoK3jDeFcDZPWXY2/eU8sN2G/WLrstadMFl5iQrcWk6Ct
         Dq/tix5I1K9Rzb/uSaalI/nG4cmL5+y78iCbbtH3BucEci5L0O6WpqUGFk62cC8/aMJT
         DwEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AO84hzCw;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id x16-20020a0cfe10000000b0068c422d109esi301491qvr.5.2024.01.29.03.24.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Jan 2024 03:24:15 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 8B4836209E
	for <kasan-dev@googlegroups.com>; Mon, 29 Jan 2024 11:24:14 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 39083C433C7
	for <kasan-dev@googlegroups.com>; Mon, 29 Jan 2024 11:24:14 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 22050C53BD1; Mon, 29 Jan 2024 11:24:14 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 214055] KASAN: add atomic tests
Date: Mon, 29 Jan 2024 11:24:13 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: paul.heidekrueger@tum.de
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: attachments.created
Message-ID: <bug-214055-199747-07BmMaQK2z@https.bugzilla.kernel.org/>
In-Reply-To: <bug-214055-199747@https.bugzilla.kernel.org/>
References: <bug-214055-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=AO84hzCw;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=3D214055

--- Comment #2 from Paul Heidekr=C3=BCger (paul.heidekrueger@tum.de) ---
Created attachment 305788
  --> https://bugzilla.kernel.org/attachment.cgi?id=3D305788&action=3Dedit
[PATCH RFC] kasan: add atomic tests

Here's a first draft for implementing kasan tests. Is this along the lines =
of
what you had in mind?

I am unsure as to how extensive the tests should be. For instance, do I nee=
d to
differentiate between the different KASan modes here?

What do you think?

Many thanks,
Paul

--=20
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/bug-214055-199747-07BmMaQK2z%40https.bugzilla.kernel.org/.
