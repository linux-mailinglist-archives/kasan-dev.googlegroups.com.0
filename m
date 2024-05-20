Return-Path: <kasan-dev+bncBAABBGH4V2ZAMGQEKDXYNCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id CFB0E8CA3C2
	for <lists+kasan-dev@lfdr.de>; Mon, 20 May 2024 23:18:17 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-6a8bf642dc1sf27100506d6.2
        for <lists+kasan-dev@lfdr.de>; Mon, 20 May 2024 14:18:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716239896; cv=pass;
        d=google.com; s=arc-20160816;
        b=IAVEkJuILaJ7vaF11jlZrtKZ9J2GNUzQLpJPrm5CXwvr5JxTQvufKnCgPZzVQn9JiA
         oIJgnQcrU9/FyYB9dEdt9yhvJcbM5mh2H0g1Cw0cJyJb1czjpvk9CFI21mCo3FGzO4Zr
         7AvK/nbIndkW2aArcF8h1iXsN70sNC2UjoUjzBQKT5mLTchmcc7yzzz0j2aCAqx0MZhs
         2byM1M4n90Duvmce8dQEbQ24C91dMQqcqBQcG0Iw2lkz4H1oBMgffXoyKEIy2kdp0969
         BwbX0rxOc2qs1Vjt1SkjVTBpu9Min9dmx2hIcPoTVKB94m1m9eDcC5XqVnQxMWBnv2Gg
         iTQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=LY3L+WbTncDxboHU0Lj6ufcT/8XMdZavp9I3aTxAvdE=;
        fh=SteymhOw+mHKnI8UoAAkK+a8//MgmffPsS09EtucruY=;
        b=xSBhRaMwFeLO9KTotRajj1Ia7NJCCtZgrDSsfeOZIICuJ3Ozem0rOcpJrmlRtgexXW
         xXvsw2hhGW6FqitY5UuF33FTPDGzgfPBMgHpy04QlBfPZDrS0FPxUqTpAYEzSgXWcRN7
         txGLqZVaiK2mht3DEeDl2fRPZS7whcnbL5E25j3AUgZXyC+CZ1Q1uFnDK2LQocX0fGee
         KHAdtr6BBppUMFMrAZ2rnmHATdUnFESyw2vf7qF9unCpPQ/wZUn+FbzIT29RaV7/Fqsf
         F+M9KimCTFE/vkMgfxfWCupJFGX1ummT+0tgBdIuUcW9MV0O37lHsKM+00qkhGT5XtuQ
         Q6eA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cofj6nuC;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716239896; x=1716844696; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LY3L+WbTncDxboHU0Lj6ufcT/8XMdZavp9I3aTxAvdE=;
        b=WHikw+ADbzGRAXsd8md/ojOEmwV51yVbn9uclW0QJhLlezt4YKMLrfKD32HgBcGq2Y
         mV0ihbY3I/rVWKCDywhUWH1n5KM3h012UGoXFTHoHc3LvxvrPvSJ2F0UtaqLH6ex2brD
         3n/+ckMDve2O8WdP9JnHSe82NORAgIwZoSKDcaJ3+dIjmlqTRkHkoD7kKWnD44QAcE1c
         WzSg5xIPJVbQoFjDttIPn8R907YdRRLgWSw2XBhkJkB28viGm5ruPewPjZsdrGk7dFVn
         YtcTWuypv5KdgIZwfvWeJU09OmEoa7JC/IpWT5/FGWkiAl6tYQAYr57R4GjjNsNezgnL
         8j9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716239896; x=1716844696;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LY3L+WbTncDxboHU0Lj6ufcT/8XMdZavp9I3aTxAvdE=;
        b=C+Y5aHdSCOnfAF0LKhbh2IdWs9GRl0X3eLeDlv/CaVg635z23ZyviciT/OX/fket7y
         e9pGQPSlpZb6qS4uEBiE6yKunAmZitCSfjomERRPhuNwr355LgtcDmPFEFL2j0aDlSpJ
         jwMfc/Sy00GPSLO/7wYyLPfJm7JTQ1do33AU/eoG4hSTWQvQC4Zzek/+5voTQO0qmuRm
         3jwf8Y4KEUctGG+F6bbiGvop81Ua/r6lmoEcPB6gkksZ5xmUtUmkMP7BrWrbE1NllrZA
         /MSw/XxDTaxgfYL1fCiR8OAFJuuh5py3e2XdiYzmiqfFJRmQ75olT/gJOjl1O6LgbE2A
         vqzQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXIA9LLcKSRIcl8OHM2IPCkw73M0GfBLgAmm61WvTCTc4ceXnpTUGMi5Rufh2+rgCpG0vmuoY/WGoekJSdA+gBiuN0CjWvmoA==
X-Gm-Message-State: AOJu0YysxueboqQZLjXdPLWUa8B92iW3P1ptLSfwvrjTbUTE2Cnm9U2D
	J7tKgwN6gI6FFDgC2u4B+g58yWSg45MjHp2eila0hAu1L4K1fCis
X-Google-Smtp-Source: AGHT+IEXJd1PHx89aursFi2N3Sof95qphy7TN+RAV56nkGiqm0iPIGIvxj6wwKGDkRUdnoYRwneG7g==
X-Received: by 2002:a05:6214:5707:b0:6a0:c903:7226 with SMTP id 6a1803df08f44-6a1682411c4mr427445046d6.34.1716239896332;
        Mon, 20 May 2024 14:18:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f64b:0:b0:6aa:dfec:b873 with SMTP id 6a1803df08f44-6aadfecba16ls14976176d6.2.-pod-prod-04-us;
 Mon, 20 May 2024 14:18:15 -0700 (PDT)
X-Received: by 2002:a05:6214:54ca:b0:6a0:9e07:cb5a with SMTP id 6a1803df08f44-6a168240a39mr337491066d6.35.1716239895841;
        Mon, 20 May 2024 14:18:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716239895; cv=none;
        d=google.com; s=arc-20160816;
        b=WWzK2bYXV1K3pVRJdLbbbT/Unvy0LEhkmcGHRgiUOoaYOJx6CjSkCn8BnJnwQmAAD4
         s0gdUk74rwabmst+Kvr7x8MIff36FKoR4aL7lnGmh8pE3gp7De7/gR52aEBArWJ8rHBI
         JgH76KWEOA6+BZ7l9WZC1OnfjxWngqPvV1V+rohp4C9fzih4Pa/0Cs51rMd7OWU7UFSG
         +AEiYqIL5to1Ok0BylFmg1l1KkEY1RsGYZ79hqwgw7Cr5FHMONm/Vj5EOYnU5Vwldmhu
         QgsA0lQazl8jldA06kMPGjmvkkJFIrP4C15hzJWa/5Fko5wDxyz3dgKj6/4foqLO95Kw
         UZjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=WgPzSjmUc7E1P9L4RP3ikW0ACXUFtD7ys1ehQK9bL7k=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=WRBBmhxXj7qT4UseVx0fAWsPKn/El5qhTVfRGVzMWfMwJ7PaA/f07Y2hVF5b94q5mB
         YVWc4p4g4NMEZQQsIXLzVd0msPLBK7sCMriopovflcejq8rbEEZn8//Uk1xxKYE7Zloc
         VNH4F7MpTKU7lu/LdIe+3+cl6lud0oFNvbetIPeasnxvPjfuZovqaASG1GvCA7qa6fjf
         ASupHvWJinl2sWiYmIkWMtw9+YI4VDuvHAeJ6XAxj1rQUwbbvluS2c1c/dxB7HcIITqt
         INLFt+LoaBtzFwfReRPoOPjmku1rgtS+3guVq5A9M3mk7pOcZyj24J1QAWHeWEhTrsda
         VCxg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cofj6nuC;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6a15f315ac7si16512646d6.3.2024.05.20.14.18.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 May 2024 14:18:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 4A151CE0C51
	for <kasan-dev@googlegroups.com>; Mon, 20 May 2024 21:18:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 8568AC4AF07
	for <kasan-dev@googlegroups.com>; Mon, 20 May 2024 21:18:12 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 7BEE9C53BB8; Mon, 20 May 2024 21:18:12 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210337] KCOV: allow nested remote coverage sections in task
 context
Date: Mon, 20 May 2024 21:18:12 +0000
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
Message-ID: <bug-210337-199747-E2sbcRJQ69@https.bugzilla.kernel.org/>
In-Reply-To: <bug-210337-199747@https.bugzilla.kernel.org/>
References: <bug-210337-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=cofj6nuC;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=210337

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
We also need to support nested remote coverage collection sections in the
softirq context: while the BH workqueue handles a softirq, another softirq
might arrive; see [1] for details.

[1]
https://lore.kernel.org/linux-usb/20240520205856.162910-1-andrey.konovalov@linux.dev/T/#u

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210337-199747-E2sbcRJQ69%40https.bugzilla.kernel.org/.
