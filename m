Return-Path: <kasan-dev+bncBAABB5UM42KQMGQEDSX72JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B55355B922
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Jun 2022 12:29:12 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-10851e269eesf5275658fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Jun 2022 03:29:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656325750; cv=pass;
        d=google.com; s=arc-20160816;
        b=qoBpmBhGVL+aIilFNl8lJQTkB6xJZX+I+yZQtx1elRcW94kqBO6JK4ppX6D7L757OK
         pRIIq+05ApH6PQrdofp2V14YfpWPyCBkVvqXzZQm2vi+i+McMmS3JXUbQf0/TSQNoGqF
         xRNho2AQrCX0+0tS1TqbBXaJ5LLVWEPq6WoutJWQZFmQW1cGDfLgiUPl+tHoCpfhLaqX
         BrPVlgjmV4BQmHFJRP454862aHNoHpATqJh4R6GFDXAAtvr2Z4RM3Ki+5xWNpLLUEFQl
         o9pgSUvJwiRipQyG3WlScjqiMEGcaIyns2f31aLLIt6KqLwjGwNuxElfWdPilreRT/xv
         kL9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=ykBlj052/FNW+pZ14S1ZQYd7gYGmyP7tNAcoQ0/1AcE=;
        b=C8kOL7y5yekwiHdR5EqkDx2cQyI6OPuxUSqEP7B1DhSphK2pHGRwju7lfxHqT34L/1
         x2ObV8o7Kpj2402Batp9yw03Ne+4u3CnDnTOC2Pl/IZDH99fgbWgxEcuM8jDYNpWL/BE
         vY5QxJQhl/Y+GRQ+5QnXTmnKGJNSqWrvYNtU13mviNO0xTsgCKpjtgYjh8s1lNXTnHme
         lxjRhgd0eJgmbY1CmUsdxpvq88Pl31pdCWgueNGkxf+t443j/kQ6bQtV0kPa7+ca5YhI
         tJ+a4MmeQ5ANE0zljAEpi8Cn/5eJuXirWwvMbU956/GkRL91oinIr39zKIw+5uCpuEMO
         V4/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WUEdufTg;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ykBlj052/FNW+pZ14S1ZQYd7gYGmyP7tNAcoQ0/1AcE=;
        b=AF4fjx5nTaqC3SsPdA5MhPeThksdCeGwSOtADvrRwJXadsz0FU+T/eTlRm3agWPbKq
         mXa7jU1Cor0psGsdi4xasFeX6b+t3fZx34I5XdJQu5qVzQhtJMnx/wSfraK/VhNJsv/V
         eIc8hk26RMF7eYDtYp9WJseQEdd0uhPXu0jGfNKi6+8QUhaX76TfRss5McnGQ7k3MnVs
         vW1lFf6BvDW30mEn/ImtxArW0sd0L4IZCZ8SLb+wRVlXkRs0GWJHsAn02MK/ElmFsTqA
         miE59XyZs61nwW1j1kbtlLGnUj3m5EyLn2tp1hXF5BQnkg5/hsygN9eLipSnReqxwjMs
         y82g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ykBlj052/FNW+pZ14S1ZQYd7gYGmyP7tNAcoQ0/1AcE=;
        b=ypVuJMn5qNwJibMU7py9wObBqW7pza4BxlHmJTgwida0Ab3js8PQWu3rGX45SYU8vV
         qW7c97p2VJzZbZ6ctJXFh/8cSlJBG3Uo373qhRseSNpOs5UesBD7pBVdbvaU53mUowCW
         ku6tLjO82PlN6JYtBs6L+QFSvN7YpoWHo7dUdih6AztGSgRhti7s+T00nvkO+kkVF6sp
         2nIcdAQB2tYT6BkxwtaolD5YcYWhI8ipN07H7TNsxY5w72f54UHDcej2b1B/vHBBZM26
         mN9QXRmAdbAgksydC7VZ1y5W93lmhgaYprG9kQfJdIixwS4XwcgCjLaz7wiydKNhSVxG
         xPLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9TE28fahf6rMfF1wREqh4k4DR2UOa7347KE52FIQlCPa87IYEH
	lUTG86zpVNVED2aCMHHtaDA=
X-Google-Smtp-Source: AGRyM1tOZL46/p2VMDvs/JR7QzhxpHbKgt6Ei+UJecQ1YMmfjI+w6O1HCztlxb/5YcChI4F1b4jteQ==
X-Received: by 2002:a9d:156:0:b0:616:a1a3:f36c with SMTP id 80-20020a9d0156000000b00616a1a3f36cmr5532408otu.197.1656325750505;
        Mon, 27 Jun 2022 03:29:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:2125:b0:335:3490:6333 with SMTP id
 r37-20020a056808212500b0033534906333ls3584540oiw.1.gmail; Mon, 27 Jun 2022
 03:29:10 -0700 (PDT)
X-Received: by 2002:a05:6808:1588:b0:32f:eb4:aaad with SMTP id t8-20020a056808158800b0032f0eb4aaadmr9975887oiw.41.1656325750179;
        Mon, 27 Jun 2022 03:29:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656325750; cv=none;
        d=google.com; s=arc-20160816;
        b=yN9Tg8qn+fbdhtNrfSTo5fKipvFBcYofeFTS70udkk/3Qr3h7khts5pIjsfkIF5Q3H
         KOAFPYSVNJI88Di8DMOuqSO5ULwe0SsxMwtRX6oIatm3zkwSzQzirSn1d8uoYpi9/dxM
         N4WHUiPuspPCW15JmWH0UKzw9/8RwqnnT9TV7NhR+f2l3Yg0PRRnZOsfRXBJlgsq62Lm
         wqu1KCuisZUWDj4yGVavQ1ozG2Ttd1WZtPRr2ehdgOUSMI+6ic+zYf5o8Od6ovIjmCHZ
         cg6dPsdkawiov+gYcn4H+i35NRU7Fl0Gs5w1VELSfNtaSZPHI/yRFIXBLnkldLdN3oI4
         ZEdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=qHu9CqkB7iaBIb66ogvfdbWKhUJxiavXctRVm8+tj28=;
        b=NytwnVXNFOAhYM8SGr3wX4W7csRnsQ0txQ7/+rZGXDNz059tfQo6eKhMS8V0LxFlF/
         uLdOxrawy2QgptW5n+K+mqIzvv7hLb1UoDZyqCr3mJJMGbRmHhgQRqAYk/oRibiwoYmn
         QI6KVHnjrMwivu0yCKZ6EdXXPACrIHk8okeTSRjGptYQ4T34e9FKAz19sAiPpEQgm8G9
         AEYowygjyu0vvrCbe4O+4wzO+8Cui+hhyMjLEfRo3nsBESgHXag9A4xLVymeyKr/chKK
         T1r1PeUQk2e7Lho5w7+b4g1Igm7Czqs8Gyil/Vj9iyL1PxtZSc699WfapPzHgvJrrVAz
         PbJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WUEdufTg;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id g5-20020a056870c14500b00101c9597c72si1389776oad.1.2022.06.27.03.29.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Jun 2022 03:29:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 025EC612FD
	for <kasan-dev@googlegroups.com>; Mon, 27 Jun 2022 10:29:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 68DE2C385A2
	for <kasan-dev@googlegroups.com>; Mon, 27 Jun 2022 10:29:09 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 53B95CC13B3; Mon, 27 Jun 2022 10:29:09 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216180] KASAN: some memset's are not intercepted
Date: Mon, 27 Jun 2022 10:29:09 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: INVALID
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-216180-199747-20Q3G0vCbR@https.bugzilla.kernel.org/>
In-Reply-To: <bug-216180-199747@https.bugzilla.kernel.org/>
References: <bug-216180-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=WUEdufTg;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=216180

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |INVALID

--- Comment #4 from Dmitry Vyukov (dvyukov@google.com) ---
It indeed tail-calls. I guess this can be closed then. Sorry for the noise.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216180-199747-20Q3G0vCbR%40https.bugzilla.kernel.org/.
