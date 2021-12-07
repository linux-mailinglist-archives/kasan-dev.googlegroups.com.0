Return-Path: <kasan-dev+bncBC24VNFHTMIBBDUCX2GQMGQELYAJHBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id C01E946BFAE
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Dec 2021 16:43:11 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id u197-20020acaabce000000b002a820308b14sf10736984oie.12
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Dec 2021 07:43:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638891790; cv=pass;
        d=google.com; s=arc-20160816;
        b=pFSiMS0Z54tWBYQqSGhCR23cxOWAIAunMNh+1pePHV+iPYFL4yihlTSvq0ty4AbabG
         blXU5pp/yvxkAuDLSxL02NpOgvUTil5D4WWsK+Mr1+DMpSj+RvxaXqwiaAp5f1nL5enJ
         bF4TNioJJEGqOQKBGwk/kUA2tp0j7y8+9hZonOghme5GGJPMVb8/xIKbEsgHnL0oIMmE
         saHMT2FbKv4OvNfrFMjCAv1EqoOizkmCqLIU4QrwSVGC9KBONb6sdxC29bh5e707SDqe
         gkcWFb1dzsuwHAejpfj4RZeAZPuwhdm1sT/oNXz3Pz+IkEPhFljyZjOzU698s4jpAwMt
         EZNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=lOgzt7WwpOOydNzivhAvXWmVPXE/eqfBYAZdNZLL35E=;
        b=wtcs5loTSDA+BhIvgg1pPcwb1aUI7ppXQ7JdpR9hHUVAhTwiBMUgq2ThTtRT+cm+nM
         W1tGzMDNLOVDWt6vGJI0YeCgk9UqjAULmwBfuUiCw8+MiK+7n4MEZ7skcaWKI7W89ffe
         Ybw5yUYLpnPCRmBkjq/l2T0dHZsJ5h7M5tiTohmNFt6nMbc7gUv6Qf9mDImplVs3c65B
         ij1QmpbDXxkEDvso/qW9fzgPeDbn2bSV+N8l5ji96WLgEhfXbGltNr1IMnldICoueasI
         yD4i+JZ40p5sLuq/+TbCtX9ZxeDtxV35xiNPQKdbjlyDkAZos2wLNXGA1xfPIh+MKuTT
         jLDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nK2A7lYx;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lOgzt7WwpOOydNzivhAvXWmVPXE/eqfBYAZdNZLL35E=;
        b=kMZYxOQqxzLviOg9nMvZxEiixXgETUIYSaK3MCrJeKdYDYg5gBd7PlsDDlO5gFlMLt
         /WqBkWXvjNAiJBb2uiyFXZeiFlCoC6XDltWlQ/Mx2gky/Pfal3tYt8Iv3Bc9A4evIFPs
         CkkWfHWV714XqAvFb6jnktoEZNTMitA65DxpA32S/NKIUNb7bzlSDoSgrdc8H95s/xS4
         LQvcWG/7yosAyhl8jJEyZPK3RqHwuf/4gizt1d0hRLWZ8ZlqQSfyt9yBBDo+hKoenhul
         gFuGazkxyfNPF84peDea5gFE0Rf++oNDJiD+jX3SwWLt21Zn4rnYXY4H8WL5bQkj7OZA
         yZbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lOgzt7WwpOOydNzivhAvXWmVPXE/eqfBYAZdNZLL35E=;
        b=qlxYS74I9CTC4+Hglq1/SQTIFJcYpRn/Tp5J53T0bw3Vbo0sZ50X7XKVDeIypwO511
         ECtDSvFrUvA1rqulnw4rY1kdmg4AV0xNhXHKd4akeqRdqw/Lb5wAOJdb2Fkvt5Aa/W0m
         Z7y2D/dyrB4L1LZF1utLwMMMTfB7yfCV5Ln02SKz7U7gu0eSNiiVmpAV2eIC5hQmVvLv
         gevf0OK+vRO1cvMcRC9xISZ0wZeXyf3gkk8P5lwN3ao4bIkzrqLOZoZhVq8cSrCPP6YJ
         sSc37HoTevJlEcmvviyo0kmaZSAyI8S3LjS1UAWDHC9sEa+9c7n2PfPcXVzf+FdpT2mv
         IFKA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5335R+OHx2YyBBewx34j43vyVOYA3E0xpim3hCXniz1csP9ogMtd
	5RQSBU7tUjy/BNIpLxIoe/I=
X-Google-Smtp-Source: ABdhPJyqVgoLBS0BHaT2hLM0soMyVgEvVqdCh53ewutr+0zDLUET0GiL5XS7BegH//nsxzNp8omaXQ==
X-Received: by 2002:a9d:12f2:: with SMTP id g105mr36283491otg.301.1638891790294;
        Tue, 07 Dec 2021 07:43:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:ac94:: with SMTP id v142ls7728124oie.4.gmail; Tue, 07
 Dec 2021 07:43:09 -0800 (PST)
X-Received: by 2002:a05:6808:1a90:: with SMTP id bm16mr5983207oib.133.1638891789926;
        Tue, 07 Dec 2021 07:43:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638891789; cv=none;
        d=google.com; s=arc-20160816;
        b=uUfkF13kI9I3LNUDx5BwjLp25WbfEGw5D4DF5sBaw3NnzpSF4DnYMg1pHXAdJajVjf
         Ro8Tz2X7+6wC3cGvUY/iFhPtQ/c0IVUPiidMmndWivVIEO+14RIy9fuppqkdyAqmMoOM
         uuSmDV+P9t36hJSr1UKt5hE5IHyItqnEpNta9fkcUGPCPJRavAhR61LTZp37rZvM2qa+
         KN4ZyCWGiiCyAk5/mKwiXEEt0bn6cvHunuehFMzKs3GS7AcjkmtVIlrsIxnVThq/ilXd
         xTc22c1NgKm/xiudul9R8rn/rI86qXp9CFnfJH/dxLboj1f/yWaG+uS+pkt8ITevArh9
         ZaGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=zZgzIhM0RSPWTeWxT999UVbclylEaVLU64/4lHR2cmw=;
        b=hXld9SzX8TpEE+fJGMAR3R4BahyzNBBUdaywbmDq3H/w3BNMebPyOrTviLok2mGN0M
         7DKSa+rzGU/jCU8qLhxe8tiLoaIdm9B2nufXxhMzGkoQmYNHCJgwS08tCzq3BDUl4cfR
         mmdtPcyx/nPIffZXx5sSn4XtkW2VIBpS9jI8dhffirVOHB4hUlz4FJ4VuL/IBVcsjhrN
         TFX9qu8MQKVUwkd6CtuTCvreHXZBGy4B+Z5WRtamP4HjlOowWvAmw9so6MszZz+QYrRR
         3tA3JlUZngjWGyuMItvPI3scPttTYksDkNulSG1fQLczfSjtnoqxe8G8SNTEYdZbDgZR
         dYlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nK2A7lYx;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id s16si3247oiw.4.2021.12.07.07.43.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 07 Dec 2021 07:43:09 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id 64B5BCE1A22
	for <kasan-dev@googlegroups.com>; Tue,  7 Dec 2021 15:43:07 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 941B2C341C1
	for <kasan-dev@googlegroups.com>; Tue,  7 Dec 2021 15:43:05 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 7030360F14; Tue,  7 Dec 2021 15:43:05 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210503] KASAN: add redzones for page allocations
Date: Tue, 07 Dec 2021 15:43:05 +0000
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
X-Bugzilla-Changed-Fields: short_desc
Message-ID: <bug-210503-199747-hliYFrFq9L@https.bugzilla.kernel.org/>
In-Reply-To: <bug-210503-199747@https.bugzilla.kernel.org/>
References: <bug-210503-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=nK2A7lYx;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=210503

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
            Summary|KASAN: no redzones for page |KASAN: add redzones for
                   |allocations                 |page allocations

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210503-199747-hliYFrFq9L%40https.bugzilla.kernel.org/.
