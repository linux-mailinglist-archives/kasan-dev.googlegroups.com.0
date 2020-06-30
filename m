Return-Path: <kasan-dev+bncBC24VNFHTMIBBRXB5T3QKGQECODTHDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CC3120F4A9
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jun 2020 14:32:07 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id x19sf1160470ooq.16
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jun 2020 05:32:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593520326; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q+17cCHzifGD2SGIVU4E5BDpZueYXQq8+KOXisLkqPXQi5KWZ2C5fbP0h1PRtPEDxr
         daZZTFUTDiIgHpNTVVOudpVoc5MGaYZ+Yh4BfzjUXhpkYmR5imN2BYGsDEA3Z++sgo+0
         1k1UKa5jH/PS7Lr+AKts27Zo5EJkMcfxDz+vzvAB+gwlrLqOVWFc3RG2NBM4g90VkTue
         I5sRqF51dGW4AYDVp1IotwxgSQcrgJltv5c5nkzdNtR6mu67+NhD/NK7rZ3GrIBvsKnZ
         c9FXMqPCz6ATYERBu8yRuHHd+6cu/B4vrkmPdTpuR69tuUu/PRtmDIgOoNZQKJ6TVZ+3
         OgIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=4tLQ2l0rT8g/9x1xW+lrIdiqqu+dbm9vOAiDZRMotZ8=;
        b=h3Xq41WFeQuFTaufO60S2WB8/J+x5NibvlzbRg4xU2SO7jv4hMz6C40XNQ1RhPhJEM
         8lY5Cnm89kigu5vCjIlqjXYZ10rgngnPpKULqKeyldr6UWrZEpoMhUUXCyrS2j5BMp1n
         8MDJY5fXlcFeLBuF+3QTD3fFsB8RHiKYSr6ZqyOBDTSHWoCOfm+X+gdimTy/CIPp2AMz
         Go2tBsOSX1rp43A6fY5fkplYhHwqxRjtqXs3jzvgt+ZrExpcFoQBjkusty5PWNGHLPWR
         /7gsTnLpkiwe1TJ5k2BvAxshgVGl2qdqkPcYvECgTTT2t8GJEQ8VQCkw1ih5WGrMHu5B
         /lWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=npi4=al=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NpI4=AL=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4tLQ2l0rT8g/9x1xW+lrIdiqqu+dbm9vOAiDZRMotZ8=;
        b=a6tk+VSp1tw/j6z8JVErfg/mdiOU9I5Nbjd3p7gDy55dmvMF3nEPSxXsHVWrzwngox
         fGxBMjdvEi9zhwgB8Vm0XDNOQ4+tZZIVDubh9e630IeQGCcd+mAp4VzoKluPcCj9ctmZ
         T42JNyIxJ7XBraGGm7C6Srpa45VhTyH7rlFmGoJQGH+c4oRfhusJgrSTGwyBNcaucr/v
         iQLd2PrDasnPTdd5iK/Z2eWnUHXhJIhgeotldUZgfg22kCUKEe+WRBtq/NF3iIprYhRC
         trILFMxpU/y5pSEry4VTcDXxqTfCtrKWjKdTYFHUkRtUhcioCW+eY8Shte3o5O3rN7ct
         K8og==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4tLQ2l0rT8g/9x1xW+lrIdiqqu+dbm9vOAiDZRMotZ8=;
        b=RUiooZHBAAyu3EXi0dM7dMojkxmqHzysjNcdlgr32GlVrznMmOJbufEo7mdeZS/qZh
         830skxB03jBWWieE38aOobOl5FIFUrdR62/0hNi4AZwPgRWSeC/N41DQeQFj/lFEiyvJ
         oFWafc661i/E3apurTAUP3LdZAipASoAgEskSfKhUGc54W29xmYzSmbc2iR2OxYPkZNa
         lndboI6Bdu1d3Je7A2ZsKfv9Dm/JKrMIegHhNb5cnZIYys7hiQsHIPrpt2tC8C9rSUoN
         Qbj49r1bmekg6ueotTh/hgZ5uPdj0x5QtOTdrqOdGSv+Z5jn8MXsHgZIVHcopBzGb3WT
         r5NQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531KQkkXmUeObz8NzfhKFo2zxIIlko0QQFc8l96RUcr5TLrUROH+
	Owbr34vCh+V910SwAlZSUzY=
X-Google-Smtp-Source: ABdhPJxDB3TE/xWZ9D/clWBp67qOolYNO7WZHbcESHTS1pzRxApNy4XD3nzdJ3P5FNeHiSmky/9s6Q==
X-Received: by 2002:a9d:68d7:: with SMTP id i23mr10552571oto.309.1593520326192;
        Tue, 30 Jun 2020 05:32:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1e4d:: with SMTP id e13ls951759otj.5.gmail; Tue, 30
 Jun 2020 05:32:05 -0700 (PDT)
X-Received: by 2002:a9d:1b0d:: with SMTP id l13mr5616374otl.261.1593520325829;
        Tue, 30 Jun 2020 05:32:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593520325; cv=none;
        d=google.com; s=arc-20160816;
        b=jesELr1z54+M7JOaHq/T+EKZT7bcWnasLz20gy0XygOS/WCcSHRL1LNWKnTTQo6rFn
         5QihSFhIywy0yCPf82DyGlAlpOR/zi8pRfnbTq8huDt6RwLe3jFMlejkzcilWtSI72Xp
         0Abbv6I8vkOhkVSDEKBtIXo+pIhEod6UhTYMaB1bVmCtF4t4F0rN87cpDBtaqZqWWFvE
         Gsz5Lxc7t3fCgYAlA9sDyz1ChfA1pb0pwUt1RByOirV1MbSbBCC5T7pgUKsMK7eX+kmW
         krRPhH5PfG4Gv90J76ff8QQdK7sRiNout/6zdIcfK/7kP7FFUGds8OUNjM4sKdtHx/yL
         8onw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=UIKLGzPDLBI1nxM797Ib3fRj7AmbDgy1jRrhV1OcpcM=;
        b=NsnKCkG0pl3i0PqsFwODEVTCP/c7ALLDA0+A6Gy+jYhjRyj3i6UiuOrNLreAYzunZJ
         7PcGRbPpdXFYWQGISz3b2A/QZKsF8JWEI0vRU6lZMEPy+tga1hNFx+VIfCoGupVhy9+Q
         YAZDVYpI7T2NZ8hRPth6DqtPcXHu3PziHqdl2CYfiqsRRiCZAsiU7Uhx0pklQGEqZ5Ws
         IfIeflUhnOE40upDM3eSaUTO3/e1x5TP1nYBWQx7G0ALD4Atp+aVTZB8PTsvXqS23tMH
         +LLm7JWGTgefcHKpp6z4lkVYO9lAtzfUqt2PEb+eB5krCrfPIwCz+31d942ZkFqKaKXB
         GYsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=npi4=al=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NpI4=AL=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g38si82300otg.2.2020.06.30.05.32.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Jun 2020 05:32:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=npi4=al=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] KASAN (tags): support stack instrumentation
Date: Tue, 30 Jun 2020 12:32:04 +0000
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
Message-ID: <bug-203497-199747-l1b6pc9msl@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203497-199747@https.bugzilla.kernel.org/>
References: <bug-203497-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=npi4=al=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NpI4=AL=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

--- Comment #19 from Andrey Konovalov (andreyknvl@gmail.com) ---
Hi Walter,

Thanks for narrowing down the issue.

I'll be likely busy this week with other stuff, but I'll take a look on the
next one.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747-l1b6pc9msl%40https.bugzilla.kernel.org/.
