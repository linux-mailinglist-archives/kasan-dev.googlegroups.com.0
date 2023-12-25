Return-Path: <kasan-dev+bncBAABBWOJU2WAMGQEEM3IC3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 244D181E173
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 16:50:51 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-33697cbd035sf1745639f8f.2
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 07:50:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703519450; cv=pass;
        d=google.com; s=arc-20160816;
        b=i3I1GRaP/Nw+IWvk4ub4Nr05UoHjOZgYErMaOGEO/XhIG4qZAH+Wt20oQDblN2u4of
         DR5TxvfHkqSLnYZ5nNclTs1PpekhkSm6USRZbHQFNJT5ewlJ6pu3TqXbGHTk8DstKYaL
         8eaYrDP2NIzZSP2QlslMFAc1DBHaIFYcGr6fy9wBE/PnldpHitVLUtOy3lmFq0QMqYL2
         6lFZcI33m1sJQoNehSGnmo0vWI6Wps9kVwEfagB3SsZJ2ZKx8w13nR2zu9d/wFS33KqD
         lJ5fNQWjgvAx2r0k4QhOFSbBnwgpC39uyAjywkUNkL11McyV4HSnu6oJsldK1fMMKAFI
         vnfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=44uBuCapihDHgA96+QFoPS6SBzsXi7Y4xVPMwI2guws=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=kfZcA+45AujCS3szllTOds8Zs68RpBFQgq6j+wwQzojXdfuBV4rWgGyqxHNTxG0Txo
         dhqEu0kjwnKGmGmliumNZI86hnO4rq6VpXXEtKPm7odq6YejxsX6J0U4Lg7CRzy6NIq9
         giaK3D1Of+IOdOMcb3Hvq+s5Vu6EQhCFlnwlOy2X+2flVuaCwezUo/C/SaU6BXvqBWcY
         QoogqId8cnm21k/aWWbpmh+POMym3Om7xvznvyqPa7AG8NR4/4HLuzOcBt3ASUVB+Jyr
         e8x86AWRBJG92sbjq6mI5US/puXSUPy+E+rKPouQFZvVxOfJV6XGYBnwWTSIADpn1wcN
         mgvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HN78bwxa;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703519450; x=1704124250; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=44uBuCapihDHgA96+QFoPS6SBzsXi7Y4xVPMwI2guws=;
        b=lJENLfkVnS33Jj9ysdChlsjU0s4ghazQbJZi85KKQPrnDIJqMjIhZJ0s6t2RtJ6OLO
         KkcwY123nTCRGdCbyb+aaTatG5b2/A1v4JgNREWOmnr0ReTLi9xAPMLBrQgLBfehXYme
         zBRJ6/QimdNha6f78uSPr0LnOamcxgELgM7/bI0XVwFRz7P9x6+PVStMVGGc96zuj/RO
         Q990urS/bKtQlml9lq+U5+BGB2mg4PoAR1I+oL+rXYLgTWLu66FOoIv9R5VahoZlNJg7
         cIftLVod/4gMCvotjh6RioD1p3DIiJ6Kw4hgTwEZSyZy6f3mNxOOe80lKXW6ToHBkd6n
         CGLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703519450; x=1704124250;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=44uBuCapihDHgA96+QFoPS6SBzsXi7Y4xVPMwI2guws=;
        b=nXKfEjSmJHpYax32hHjtEVKcit4EWFuMDoPP0odMO73gJ7xTv3AsHweMyCaGXP6QEW
         uuk+9cJvDk+FDEoVX9gXMYYIg5poy53bvJRPkCJm6+edQ2NzYJRw7TmW/XkOGoy/1fES
         BryRDO2M3TSXjFkTVwSF44bbYxWIJLJNEIZ/msKBtxDfAl+7POr6TtjVjUY6siMVjDnH
         7Sh5/OF+bCnEdlalAEA9/46Gh8Bzv9i73uqVXuJCqmzpqzq5wJ0BDZINv6GGu1BfIGTc
         V5lmlsHjLm9kO/e3tL35nFHr4e493KOzCsnw4LgJ2tJubPKUrdEcheImYe5RAMDnexHX
         aS2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzYyt+ja6s/WCcvC9/pHTvRmI85LvUtwtKPN53KWY6zJ/Fup+IH
	C4fRRAh4+vU3oWbP1Eczq0c=
X-Google-Smtp-Source: AGHT+IFLlP4hyl8Ftfg8bMGBlykUtVWCvoipC0MbP2Y6gQ1LEsR0YY/JPNOoFEQlz2X9PVWf5/svrA==
X-Received: by 2002:a05:600c:1897:b0:40c:61e9:be9f with SMTP id x23-20020a05600c189700b0040c61e9be9fmr1910855wmp.120.1703519449602;
        Mon, 25 Dec 2023 07:50:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:588c:0:b0:336:a62d:efdd with SMTP id n12-20020a5d588c000000b00336a62defddls854915wrf.2.-pod-prod-08-eu;
 Mon, 25 Dec 2023 07:50:48 -0800 (PST)
X-Received: by 2002:a05:600c:190c:b0:40b:5e59:f73d with SMTP id j12-20020a05600c190c00b0040b5e59f73dmr1692325wmq.175.1703519447939;
        Mon, 25 Dec 2023 07:50:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703519447; cv=none;
        d=google.com; s=arc-20160816;
        b=IZn1xtFvPh26rqBr9AWRbRVajDSIRf0NfsyINYAbNi5Oe5isxYktrqYVpOm+nHNkn6
         gz68pcMTAVQ2cactyXvUE/+rRyZ04/krvFdOzE439kgtCYYH2lgedFEcT5Q19VOpiM0Y
         lGEV47IohIvP2mgYxZx1shyCDMtW1ek+BesGOkzCTu/Je4EWVYb5Muxgt0R9bkqa2Swq
         MD1mIRSaR0YEUYk4FaemhSdNnWc/xKHD/bB2Kbctg4BfjkxbJbBVg3pN8abkIl2vM1KL
         54Er7y4pgB6QLWgk9TQOFIp3Dexstv2w6Z+CByjh2VFJN7xjxU2inRmR+CS4ykx2orbA
         nMTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=tbYfAudApPBET/MSwlK7nHLiOZT3XhAI64xGUEJzCQ0=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=b5QZ0oN91+D5o69rJwSc4InimmdiHkeruL9TvhJp+y8lNpwxCEREGv9+IHC/bmnboz
         TIM3gANBzP1ambckrsFTcdjBN9GobHs3CKk2T6X2F4qEpQXN62JI6INzlQHIihxHjo5A
         27zPQlRi1NmqCp5C2xm9nWvmyJWbcsaP9sLUPN6Nlt86RlI6h21tNXPuvxBUaVTkyauv
         LHurXA4WSmP0wlNBI3M5M+xmC9gz32fCyS9Ddop4vP4UZBZW1MnUZbnJwNeAbrUWgNGP
         F5rM6qyKlnwRn6FrrKdNs0C4ZL7U5BsAAQuzEWLuBsfo/otcTzw54mYXBDpvigAktZMD
         asPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HN78bwxa;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id z8-20020a195e48000000b0050e76749bbbsi204009lfi.7.2023.12.25.07.50.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Dec 2023 07:50:47 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id 48435B80B32
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 15:50:47 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id A0D7AC433C7
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 15:50:46 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 8EAA8C53BCD; Mon, 25 Dec 2023 15:50:46 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218312] stackdepot, KASAN: use percpu-rwsem instead of rwlock
Date: Mon, 25 Dec 2023 15:50:46 +0000
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
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-218312-199747-ILiIT5hfsM@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218312-199747@https.bugzilla.kernel.org/>
References: <bug-218312-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=HN78bwxa;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=218312

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
(Note that the stack depot only starts using the rwlock with the "stackdepot:
allow evicting stack traces" series, which will likely be merged into 6.8.)

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218312-199747-ILiIT5hfsM%40https.bugzilla.kernel.org/.
