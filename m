Return-Path: <kasan-dev+bncBAABBM5JWOVAMGQESSWHPQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9645E7E6ACB
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Nov 2023 13:46:45 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2c73f8300c9sf8089931fa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Nov 2023 04:46:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699534005; cv=pass;
        d=google.com; s=arc-20160816;
        b=KVENi7kZGNppoOpcQ6UmoR/q+p3QOFfXayV8BTGvrt34EYCyJVysUU4qhLcy4lXjKr
         FGOD+KS+jl3ESUwFRUUn3/oXqW2jOxNo2R5nLnXhTdFUXTfQuZxe4gK2F34A7HHLFqPb
         Zuw0BNcuMjTgFbIAHg2+Ps/+YjadNASXawxYzCv0jlMAmZ3C0ktEK7P1bE3LTI8dt0J0
         2wTPvnjwSAu9xjQqC1pLktDDMkbthAtrQSdsj+0Rqkax2ePghvAMom60uYBaHK9BucPQ
         5OZGkC6AC6RHBmyQ2lYTLGqOaqzDdnEBGEhk4D/mMnxDuSe6CsW7yvWnii6Gg+Hs0axq
         zs9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :content-transfer-encoding:references:in-reply-to:message-id:date
         :subject:to:from:sender:dkim-signature;
        bh=EMwtlrWq6ihAKUeb7HEMf9eV+DWtAYcY/M4lzSMTIS4=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=dzfUrHbQ6nsYKfW8YWWL4cAW/7gNf3McmfeK/ChDmVgs78x3Vefenw+P5uaLQHyvTQ
         1jAK5PsuJa94nZD6qR8il9oHx1ERcwTPQuw3Cjq/AGpi958jW1jAchUm9SJZ+xp0xohM
         plKesr5lGAIzaoy3anmmjC1sEZJ0HBKy0j/Ewp9wrWXTQK0CwJY5WNFcXHT1FKXOtO26
         yyzGpm3/LU4zLK0vVyX2YibR1w7HCEAeDHuM6wZNKps10JTpq/Yg3x8JtJKUbaKFKRY+
         nVwa1xsFGopwa7ijOk3jguaQ9tAuB6Is8CkvOLEzAaU/PHFI2EDivttYiKGUW/Q1brXr
         liiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YKjGoi83;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699534005; x=1700138805; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted
         :content-transfer-encoding:references:in-reply-to:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=EMwtlrWq6ihAKUeb7HEMf9eV+DWtAYcY/M4lzSMTIS4=;
        b=DsHiI+95W0Z6RHyXuvWi0sma2AuxM4wzg92zKUgIz2Vikim/UHUY4yKLjRdy79wsk7
         2zyMNztiKe8IEdv/bJEyAb8AaCKhq809NcJRxDZ8+jtVP35QgcAPgV9CFKKe0q95hc9L
         29v4jRc9xJQbYA1lke7906odSLkSZeyDzRVVyVgChXuC2fJYioYRRLwHubNNqrTvBgYY
         ZKxGtuSp06rMCemiJE4qLbD+X9miMy6ch24c2CGQ7zCwCxAk0X1M60wnwT5ibAAVAEtY
         /XXE959v2tyYIc3efPJ1rNUhPEW8v6C7Pr6gF3KVcOrmmthQQOqqrKevYxskv5ujoFS9
         Yk9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699534005; x=1700138805;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=EMwtlrWq6ihAKUeb7HEMf9eV+DWtAYcY/M4lzSMTIS4=;
        b=WIH7vqCc1wzLu8E3G0R8HGmNNmc3G0AazZB1mUIiFJN8lbVHdNHyOPCwRIVYuJ532W
         H2Jc7NdMWxN38N3vm7dZy/2FmVDrxphTTh/gGq/f9wTeeYMIBF6RijepJ4Or35OjNbwu
         TwXuHfWA5ENkWqvrqE2UncjoTIXQ+0olkhJToBYbgzzwK9J58zH6yFsJ0rSQzh63wnhw
         dVkhl1vRrU9FOzcgEcpGSUEyYKVecEZ4C0LXDQO9Cvl1HZ3IhX61uqAvicBDXDwvEj16
         mERTEzsehrbwl9rwg7ugF9fc2uwTddGD1Xyg2U8NGdLPAZQUhSikusRKCGm+ZIwTMb8B
         g1BQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YybN1X//yNNfsQ9r/hr5rGpk/jXIUJSEyHExVRpuQ/LJGe44pcu
	40Kj/YlS2bLo2jjf8CoDEJU=
X-Google-Smtp-Source: AGHT+IGoa/ozOQqziUdnoFcuLxK5p8fcmtZZkV8oPhDBDQsemehgNpkwtY+g/ab1dMiTYoak4qVNAw==
X-Received: by 2002:a19:7107:0:b0:507:9787:6776 with SMTP id m7-20020a197107000000b0050797876776mr1348371lfc.5.1699534003557;
        Thu, 09 Nov 2023 04:46:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2384:b0:500:9b76:ced2 with SMTP id
 c4-20020a056512238400b005009b76ced2ls557590lfv.2.-pod-prod-03-eu; Thu, 09 Nov
 2023 04:46:42 -0800 (PST)
X-Received: by 2002:a05:6512:2529:b0:509:7301:5738 with SMTP id be41-20020a056512252900b0050973015738mr1803986lfb.62.1699534001851;
        Thu, 09 Nov 2023 04:46:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699534001; cv=none;
        d=google.com; s=arc-20160816;
        b=Gy4F61gz16TFPYdBwnZPATop7PK0UcUR6VYJb47VgQjFR3w/UszSY5UCJ33f5KkFF2
         IiU6Bi0hGHB4vBGvtWyIC+l0N9E82tgv77/IWzBoHq/5LTY+KeI9Cqx1R1eCF1bHVSZy
         Q6uSkKprMOC0LHrPSDc2NedkzQGHaOVbgaLfj1Sou0yLEEbpr1GkrAgWiJLkDI0iv3HY
         VnLIuurMEV0XKpyhdrtaKG6fTnwJeB3451q/fKlejIOO0/muUqZCDrOUlaENj7CbNQjj
         /p5y0jnswpH0WYlb8jznfpeWLx0NDypcP3+ZL6uKm6BTAg84WWuzeIt+ov6zunsdYbIh
         umCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=lmwiwuKjY6tTZfdGKzN8eAeimhDb3VxCj36J7vkPdFI=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=m7arLuES//1+nk+SHAIaTmUYdFXonfEttN6fzstyRcnDQ1E+RzYHq2QmoYQL12ZJQ2
         /LUcbp8VprBXarL4gJVof/8vvGvNPquMQlMwdUdVk+QHNBmZLmAjqf1jETUY0LEYQA6I
         wnQgCdySODoLi7yVm7iIAoyqLy11ujZ/J/nBe7/oNN3ldOrlMJ2BfRl5S0utJ6qO9k1m
         7lVy91y66ZGxSjoMJLcyi4Ak+bwLqXGJjJW2LYxhrPoC9hF474Ts3e96m6pqjPDVd7yC
         CgR1MSjvMDHCYYgdAkTgdudjvHechYEtM+2TjeN1JeoN0S/2/DeX4d/p4nx1ui/KYn+W
         EHoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YKjGoi83;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id d17-20020a05651233d100b004fbcd4b8b84si989198lfg.0.2023.11.09.04.46.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Nov 2023 04:46:41 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id 32BCAB8203A
	for <kasan-dev@googlegroups.com>; Thu,  9 Nov 2023 12:46:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 8CD6BC433C8
	for <kasan-dev@googlegroups.com>; Thu,  9 Nov 2023 12:46:40 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 78431C53BC6; Thu,  9 Nov 2023 12:46:40 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203495] KASAN: make inline instrumentation the default mode
Date: Thu, 09 Nov 2023 12:46:40 +0000
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
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-203495-199747-3zEOT3IN6x@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203495-199747@https.bugzilla.kernel.org/>
References: <bug-203495-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=YKjGoi83;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=3D203495

Paul Heidekr=C3=BCger (paul.heidekrueger@tum.de) changed:

           What    |Removed                     |Added
---------------------------------------------------------------------------=
-
                 CC|                            |paul.heidekrueger@tum.de

--- Comment #1 from Paul Heidekr=C3=BCger (paul.heidekrueger@tum.de) ---
AFAICT, the versions of GCC and clang which are supported by the kernel all
support inline instrumentation by now. So, there would be no need to make a
distinction. Or am I missing something?

Would you still welcome a patch making inline instrumentation the default?

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
kasan-dev/bug-203495-199747-3zEOT3IN6x%40https.bugzilla.kernel.org/.
