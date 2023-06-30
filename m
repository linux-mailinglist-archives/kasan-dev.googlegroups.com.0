Return-Path: <kasan-dev+bncBAABBEFD7GSAMGQEC6YZEUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 00A66743354
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Jun 2023 05:52:49 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-400fea3d458sf16449881cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jun 2023 20:52:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688097169; cv=pass;
        d=google.com; s=arc-20160816;
        b=aUp36VySdEJMjD3qRci3dME4SwcpuLZv5hvzmVx383POcp5L44pVvxmez4feDtLLRq
         JNa9SokBDaNOklhmQ8O4ZoewWvviOwbmIbSn/MZOVJOkKRht3TKB/mU4bwTipu2x+F1F
         p0+siHxDQQ3c7wJcy9S7XLU1DHIQq79aJRi6G7XE1QlRtdtzirMksNMLncMXVn7M8oKM
         /9ZahDIjxSfnyhf6bg7kYN0ou0vn8DIWBhY6SJb8uO7OdF2aC2O7QsszMpv6RC6poNi9
         8/BuEJLFSMxYVTs3Yeya4AbXTYuoV8QJrWyjAafLRFpgHgw3L1kKfTKW1cLMbhSaSQ5Q
         7rAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=Ohvl5a4IwGkNnxmFG4jXfSIgY1zJLWVhqfExOQxD+PY=;
        fh=DKBepnc4MQU5iECICp0yzPMRbEkFfxKQwwgklF3yzXQ=;
        b=MMTgORD7WrRL4/YN91p/UQAdxq/2DrRJcBU/fxY/8Y646u6U0CTFgk4wvZa2x8+6XM
         aXT4VCNP16VHRfmlTx0vbNCYKpBv0V0mx5gakyK2dfwzBsoJeAxRxj1nwD6AEDmSC27r
         7xRpabR6oztgK9tFAacKpbcnGVxGdQMzftsl5KYD1hsGe2msl9L+upIS0NyV3gf2vfMN
         27MSNJ8MStHybZYAQBZZFJDqrcEawEy/J7IyiCGdkdcBbtMGiQGhW7lDMeE/2AYMN+ev
         j0kgXmhWnCK7Mk38BX2xUW1ARZguQbIcSg2QIHCjBkqtd2emlzZ7hDo1zWdsXzENDQMi
         lwpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GIzowkZQ;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688097169; x=1690689169;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ohvl5a4IwGkNnxmFG4jXfSIgY1zJLWVhqfExOQxD+PY=;
        b=KLNLH/Emh7iQkEdoyuE0QYuLFz0tUtG44BLbe3bOYCuqYmicmkAUjd9vMkU57VyGMH
         CbpZvzwHbkf7/bfOJrn7AWMOkmgfjNmS6hIXcqEhBvoOKxXmkpYOoshFVcgwhj37Esht
         f+533VVfkdayGcUzw+4JM9CpWWrRyHVJ08je1LxpjE72OXpEDbl4c76OcCc4AwfXZQww
         aL9kahoyqDhuRs+daz+P1+UJeDPIxCEQXlPR5K7Se/i8YGHHUIHEiqggz+KRPyNU3R9g
         X4dtm9oWVmXlfBlNU1oxt6vOWJ6RLZLpFvkvu0BjtLPvK9ame9wLAgTo8QQmIED19Y1t
         hdLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688097169; x=1690689169;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ohvl5a4IwGkNnxmFG4jXfSIgY1zJLWVhqfExOQxD+PY=;
        b=LawPzj36vV5E6kLGWUofqOuwB2u80lvApyUNUVer+6Uv2JPOWIJs/ddnhCp1gRe71r
         +bemDmhKFg7VUWbPWx0nflImaE7+knFKUve/CZLfglt/S86u4H37C+LnhyuF4/r0gD+e
         saeo8TRcHhHcQoMAMFJYwu3U2GWZ+6E3ZhBg0LlmegEnsNtFVaiPm3apfH2Gd5DYW3lr
         hAGZ2nOLkwtX6oatRQ9M9UEt2YEV2eGv7ZpPiJ0hd5cMMXlCi29kAjAwN2kzamoMar0r
         onJG9a3P/u7b9yr3u8yU4mf/B3KgR4S4KRIBhj935jfWuc2Hm1+NMfgreBXHleZUPIdk
         HdVg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzYj2Cb/qFSeh8fD6mEWOeFPbCXUaI40yvK/JRo12db9ETRw0Yd
	4Z44GnZBYLGDKEAO9SXtJwo=
X-Google-Smtp-Source: ACHHUZ4tL3z5Xp5q92aMDq0XYuf6MBGmTWCFIO3hJq73FlZRfNwCzPjNokIrzOniXtKeKfu4DMTh0w==
X-Received: by 2002:a05:622a:2cd:b0:3ff:28d9:ccdd with SMTP id a13-20020a05622a02cd00b003ff28d9ccddmr1850882qtx.11.1688097168749;
        Thu, 29 Jun 2023 20:52:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:70cb:0:b0:3ff:42d6:62ba with SMTP id g11-20020ac870cb000000b003ff42d662bals1709451qtp.1.-pod-prod-07-us;
 Thu, 29 Jun 2023 20:52:48 -0700 (PDT)
X-Received: by 2002:ac8:5bd1:0:b0:403:399b:c7e6 with SMTP id b17-20020ac85bd1000000b00403399bc7e6mr1663528qtb.23.1688097168132;
        Thu, 29 Jun 2023 20:52:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688097168; cv=none;
        d=google.com; s=arc-20160816;
        b=i/7s+x62q2lxKytR4UEYt6w04Us0cbrqY1Gr/w5u/hSZbz7CQzcvD2AuG6NYKnTiyk
         VRoK3fPqf98FXCTD2JxhfX7XY8z7XGBTqBHntg8Am5mB/e0Ev2wa+IbSJN8TM1raJh5I
         pG1FRtfRpEbcLe6dsFaj1Bc+X8ksw/AU4Kt/Qwls9thfSBU9ay9bBfkGayOANI4Sxkzf
         ctK+pOkLW+B8YniaX8E7SXVKEENa7v7r4n4J5ESij3Sm9POvomzGkFnsMe9HMJdtgIIS
         slF9dXmn5Yhg1vKkyORkSwTKGV+13Ea6niIDsoCoaaFGgqSZDOrQokQGkG3I4UQWpjVA
         l7ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=hH1dtbh08GHoRYUZlBgrf3UWQ8EvizRtJeIsv0PLjA0=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=bpZvBjXQ8MRRP2DUtwMkD+HUdlENGeIce5tvonMnZ3IbhWtq6CfbkhkXa2X4PBYWjp
         a7e2fQOsHfp297ZWgUy92TgPNfECpICUyYfOp1/bun8hTYce8uDOeifvSKR6v3YlkbR8
         00eTjXfq8+8lyn0NOLymM0Lw05oi6z5GSBFElqZZqFmY+RuKXo6na8p26HFzd0d54+jE
         cVaS6Y3BGhC/ocknh+Qt34LZuqZOeZnpieURALOr6Nc8dIFq0AY2ewp5buiELqtkp0xd
         zRSOVnp1yrLD8qZNXuKY+v0dYo2tiobQZGzzoLxlo0K+VicsFBdvVHGuo5gQkBrdu/mM
         KZfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GIzowkZQ;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id bq6-20020a05622a1c0600b0040323b30fd5si305286qtb.4.2023.06.29.20.52.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 29 Jun 2023 20:52:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id A0C9E60FA6
	for <kasan-dev@googlegroups.com>; Fri, 30 Jun 2023 03:52:47 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id F03B5C433C8
	for <kasan-dev@googlegroups.com>; Fri, 30 Jun 2023 03:52:46 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id DC894C53BD0; Fri, 30 Jun 2023 03:52:46 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 217612] KASAN: consider checking container_of
Date: Fri, 30 Jun 2023 03:52:46 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-217612-199747-RGrt3l0F1s@https.bugzilla.kernel.org/>
In-Reply-To: <bug-217612-199747@https.bugzilla.kernel.org/>
References: <bug-217612-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GIzowkZQ;       spf=pass
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

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |dvyukov@google.com

--- Comment #2 from Dmitry Vyukov (dvyukov@google.com) ---
Another potential idea: if we introduce NEW(foo) macro instead of (struct
foo*)kmalloc(sizeof(foo)) (or perhaps make compiler automatically detect such
patterns), then we can have full object type info at runtime and check not just
sizes during casts, but also types.
void* is frequently downcasted to struct pointers, that could be checked as
well.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-217612-199747-RGrt3l0F1s%40https.bugzilla.kernel.org/.
