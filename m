Return-Path: <kasan-dev+bncBAABBKVI7CSAMGQEBUCIUMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E690743123
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Jun 2023 01:30:51 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-635a3b9d24esf10849486d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jun 2023 16:30:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688081450; cv=pass;
        d=google.com; s=arc-20160816;
        b=jF4+geU1nbOiVICw1Q7cL+EVnLAyKUgwX/GNy2q5K2grd36NKIV+hf+iXc0VCVq18Z
         t1RsK7/qHhGxKFeRDdfOir9d/uF9/70UySdp14FlNqrrXguHwmlriF+ASi1cssAKtfs6
         sEmi+iWqe10QJaM97HWz8G1dB5zM7l+etZJfmNby2SGYtKRhgV0bb/Ue3U2T1HwvoeVA
         T2GhriDfFRNb3ouSdtknPmBo2BVMt+qG3Ys2Ee3pdzLiPm/bYHJjIrhKuissp1vLxGI1
         bxFvCiJ1lxtYfGKyxeE018uK9TriLupwj2YsqnaD+XDLG6htxB7SJusCNoVFVJJX8hLL
         fePQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=Wxghviboys3exSZrWF3/k3UKOcIeTppgWd324mS8vws=;
        fh=DKBepnc4MQU5iECICp0yzPMRbEkFfxKQwwgklF3yzXQ=;
        b=UX5rDsajimkM8gT33/2gSTO6kwv4BMWj11xphsdIKXWIdidelDEKEDcYnxDMiZt1uv
         g+n/UBLqxBwtL78kPZQe3GlB8ImXK2ms/yPfscucPFMuW/IWqYwN/d7ga6nWvdNzBryP
         FJBHuIGe5mv0RXdIczX/S7wBIsYcWH+mVx9cyjy5I6ufGyVe+kAeEOaN0hwBgqlkVYtk
         QoxmHf7mqlXPWRPe9tB5o9v2JXWo6QSv4ViLJtKMZE5tuncDb+zV27oBdWMhI1cRU349
         hw3/AuPqOR2rRG1RBPuviQ3bVK0lJva5R6Ir/+GkmkBNASpOAVMB7f4KJ6KI1tM24Nw8
         mIBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rd8jiTYv;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688081450; x=1690673450;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Wxghviboys3exSZrWF3/k3UKOcIeTppgWd324mS8vws=;
        b=deKgAyBGEwApqqDwdmFOK/vMCIVMRfWTb7SVytXXqm41kinVgDGRIjY0eTfx7gCnmd
         sDmpkwTcY+6CTrbdS6OYOJHdpo17T+8d1Wsow8Dk9jS59n3jxC6F1TZlpSDO6wDJP1n7
         ZOwmWCGmlwVp6FInydHSjVN0z5rc0xSrFMZIy+sSi2QNJ2KIv2FQkwW8cYW307+aGM5/
         Iorzv/3gR18sS3eR1rPlzZASYVUDmYlmeiSeDml3nPOzWO39kI0wKomkBV7yGyWnQ30T
         pqCLjWmRg1o01vZY3wPRA8fdhczTP/T29+pmeNoI7YG4S4mH2UZnvt1e8vH8kS0lk4vI
         vPOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688081450; x=1690673450;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Wxghviboys3exSZrWF3/k3UKOcIeTppgWd324mS8vws=;
        b=gGNswggdOr09pKqR9gAkGoXt3uksa5EO5lQXm4RbJ7FG/VtbxpwqD8oFJjyQ1oynhb
         Vfy+PXUcMod3XlNECXJirA9RZX4yzrLogrc5gMarBo+mDychzKBxH8xaX7DI1gwO/0pW
         K63QdZOvtcHoXBPSnyb4vI+z0j/5HHm7ATirAIaG1oMmNj2W86zgxdvo+XJ2eOC84IEK
         InPYIsFhXJNKo43pyzmK1HLTGDUNBeKvijsUmJQEpTSdwxYQK1xpND1Pa12h2QyiVH/2
         VYaNiTTuuev4d/AcwbHLNMeynCmv65qo5VoAPJLGRZFbFjfCeLm+FOUxjzSRfw0HLoR/
         1XLw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLYoVOgDuhoVKQM5Gffaum6wsPEzbzaay8piVFPMpDh0XhJzW2ZJ
	q/vqZaaPLnw/YlCEE1CfPIQ=
X-Google-Smtp-Source: APBJJlEWodO8R9oORQmJSxcUzkG3UNxCE0+89F7rWuxdtjHdRoAbmstJNAFeuGlvkLMl+7OWUA3tyw==
X-Received: by 2002:ad4:5be3:0:b0:626:3375:6fea with SMTP id k3-20020ad45be3000000b0062633756feamr1290560qvc.22.1688081450451;
        Thu, 29 Jun 2023 16:30:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4442:0:b0:635:e560:ecc9 with SMTP id l2-20020ad44442000000b00635e560ecc9ls1307759qvt.2.-pod-prod-08-us;
 Thu, 29 Jun 2023 16:30:49 -0700 (PDT)
X-Received: by 2002:a1f:3f49:0:b0:471:79e5:1d82 with SMTP id m70-20020a1f3f49000000b0047179e51d82mr686429vka.16.1688081449669;
        Thu, 29 Jun 2023 16:30:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688081449; cv=none;
        d=google.com; s=arc-20160816;
        b=fMao7QahYvkVY1YKXmjV63zP8wKZ6kohe6LSPj5xLlfLSPQRweokZoo1ddCEAOANyN
         D5ppAzQ9GfKXFHTKOhmMatmK++54wYoPplQJvCKeYRC7wbMp4BsRHbrGQ4UyJb2kK+Pp
         uAhf+LWW6dpz5Nu9W9ExXkLINE1pIDaUKNzkZ+vYT3FZgvxFKLf2apeMx5ciCGlFwpcW
         GZlO0PF8BIlrApy9DF24ID9C5wtcoopJgskX4pS06D1XzNntIkujAqevIR5xlTX1TA0m
         kn1Ae00DYuFK22OSLL/PawCcGlbQ+cEgumq7EBWCECC2tIZqXu9kXPuunsbldz2dErhq
         me1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=JFqH8+nFRzWsG30g22G0Y66i4Pif2Amq3Ab3MWrPzWs=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=pPrVScGkV0h9UnHcboW8v+ON3B8S+D6ImAY0i7+tMzEcyzd5RiQDbaeYXCVayXYKmo
         FKgpfgqh8nf4Jh7d+v0zZ7M7K2z/VPAR4OJQ73I8F0a1wLVyqfIfUBOf43ykue+VKmX1
         BnUmtZmuYlPZ8XcGyk+v4qmzCYlqak9ca3Yp2f3XRuABQP4C9IBBpTQDihuiAxpL+CtM
         J+yMv/MNE12E0kWqlVqQJcY/8YygshCNM5E/eTNVx4B6MsaxXylH5mkNZFzfLzkxmS44
         7mW8IE+xVNu8aCbWKVTVAM76J1b6UweHkKZ31cC/c/iEVjAp3uFs5k8Nt2iF+nF+W3ET
         sM+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rd8jiTYv;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id q140-20020a1fa792000000b0046557175e54si1511563vke.1.2023.06.29.16.30.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 29 Jun 2023 16:30:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 16EDA61645
	for <kasan-dev@googlegroups.com>; Thu, 29 Jun 2023 23:30:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 7DD0EC433C8
	for <kasan-dev@googlegroups.com>; Thu, 29 Jun 2023 23:30:48 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 6995BC53BC6; Thu, 29 Jun 2023 23:30:48 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 217612] KASAN: consider checking container_of
Date: Thu, 29 Jun 2023 23:30:48 +0000
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
Message-ID: <bug-217612-199747-VpxgoTnjMB@https.bugzilla.kernel.org/>
In-Reply-To: <bug-217612-199747@https.bugzilla.kernel.org/>
References: <bug-217612-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=rd8jiTYv;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=217612

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
For reference, a comment from one of the paper's authors wrt the idea [1]:

> The simple case (checking if the first and last byte are NOT redzones)
> probably provides a good tradeoff between adaptability and accuracy.

> Ofc doing it 'proper' will be much more complicated with incomplete redzones
> ('complex allocs, arrays, etc).

[1] https://twitter.com/JakobKoschel/status/1674548273338515456

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-217612-199747-VpxgoTnjMB%40https.bugzilla.kernel.org/.
