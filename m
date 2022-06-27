Return-Path: <kasan-dev+bncBAABBGOZ4WKQMGQESX24PCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E01955B8A9
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Jun 2022 10:38:50 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id g5-20020adff3c5000000b0021bc44c0f7asf379095wrp.22
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Jun 2022 01:38:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656319130; cv=pass;
        d=google.com; s=arc-20160816;
        b=N/+ZN9ZrBH8c0nntd8HvwqQzKMpYU4Q6H8p1Tj10EHRSqTmnyWUCG9DQt7jxkLj9lz
         Oj/wV/Yv0rBvH5mCtcQDB4YiW2+e3HkSLZcz72AXVBPe2JdXQ7gvbnwh1kP9ZEJLs7os
         Lr7VIC69HuLXVKAJYNNczqCTMYvfOj9tsBIrczxYNk+YmGoejPtYWh7yJ2pbfJ4bY6Cj
         gm0YcIG2tlkfBlburX5jtqciipLlMoL5wBjjh+PSQDULitpDvuw/VR2oFyQTZz90lAqn
         7aYmhqFjRCYnnqNLJum4SPwPmNa3Uiyq7sbmv54QdJMTdqtKmYPNg9Zm7ASz8MdakRhx
         IlEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=PYN0CWg5AuYZuR1zsMMalG3lvIJd0V/losw/Gy/a7us=;
        b=od8gEzTEY9fjQ99B08gi5J7rmM2rQ+k/GIGEc+LC1j/zPi+b/eaqBLbsMESGbHMb+p
         hSRfC+2e4XASphLrdqmwO6aSQ9CIOELCveBQf9qZZORW9Sp5uEB0YNl7ZdQqwbovGWmW
         qd2CedldNJocQTcnWcZtBcZRRkvfVYnVpTuJVNFikcIo6NOs7IOANHPXiCuUUimmO6pD
         J/CGepQQiIoGGEIBYwbd/dccbjOQWT4H3+zZHIABYmfMqRru/OyQX8IiUo4CZ8OCDhzr
         hgTJyWKf26/q3CYvN7liBbbq9JJgyNYa2YUh2hlmUVSbTnn3ZHVZOYt6nn806V7JkzmE
         x4qQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bUMcmUtp;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PYN0CWg5AuYZuR1zsMMalG3lvIJd0V/losw/Gy/a7us=;
        b=c1JzFRURNT+xVkY2H7kWWn94ct+FqL/e7nzCiHcPPH+snoh1eGzQf9OF/+rjMz04Hq
         2wqrM97F23FptmotESb6eLDhxCLjf88Y0FOh8fUNTH64m6cvNKtMMvDUbJAKmO5jH//+
         uQoovJTfm9ieb9EN30dvMwhTG4tPX4c1cfX/Lsnoo8a6ZhwFcN4QNgAcccF0w1GMi4ej
         z9tVF4n3o2XB6+j0fIGjoTwI7HM8h4dUf5VNa/LEA+F12vXRjdzFj9p//mvktzmYwuaq
         3mbNwNj7PXTbQYwMRpGsglTDs/8vxeve3j5pubtlAReBR+OfnZFfGd+3b4v/bbmxckYE
         ngDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=PYN0CWg5AuYZuR1zsMMalG3lvIJd0V/losw/Gy/a7us=;
        b=Td+QvcN2zip/t/KWwwi7tAiBA08gNnG+vaLVCY0UnosMlr4Qz1tAV7D28ByyL+RgJU
         tqy33EXanv0RBxGvT4IE6IUKBRD7h0EFGOlyZ7w0Ll3okoIQZ70a5FykmSeqBT/0tD7Z
         1p1YRIS6eIvlEhHzBAxTphO6qnuYdnVQEte5tzEdyDDZatrUTUqJeznJ6wBM3L0Y80ef
         dHN/B/0X6CSjQXLGFowD+iawDdEmZ9G50cCda0RBvLwCnjsDd+eymx/APPftGFupETdr
         vkQRI60wEPttR5rhgPW8gNUFXYrZrk8RdiRCHi+PMEJzglS1KnC/AFzxH0I6GJFz9HT7
         OFlw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora89vo8dF6P72fESqn5KjLf9agSD1j5a11V4GdwW5vkzuOEIL+Wl
	VizvBbwzu4ISFgUW6lwrvck=
X-Google-Smtp-Source: AGRyM1tETOUg/HSxYZfsMGGwHp+owD0y1DeeE5/WlbujEfMuNe72EqeML6xuDf/HC4a5Sm3alPUhmg==
X-Received: by 2002:a05:600c:3caa:b0:3a0:18e4:781b with SMTP id bg42-20020a05600c3caa00b003a018e4781bmr14059504wmb.199.1656319130158;
        Mon, 27 Jun 2022 01:38:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:350f:b0:397:475d:b954 with SMTP id
 h15-20020a05600c350f00b00397475db954ls2812874wmq.0.canary-gmail; Mon, 27 Jun
 2022 01:38:49 -0700 (PDT)
X-Received: by 2002:a1c:4b05:0:b0:3a0:32df:533 with SMTP id y5-20020a1c4b05000000b003a032df0533mr18781380wma.155.1656319129471;
        Mon, 27 Jun 2022 01:38:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656319129; cv=none;
        d=google.com; s=arc-20160816;
        b=ZBvIqIDvYYm454KQ58drBvWtWFXZZ8JTGe4vWHajgh72DZXx9nrtFen5WK4ct9Ve60
         tbW0X7V6YafGL91isgIYWoY+T4Zs4r8fFkILRsSt96/MlNYbgCoh2gSPTSTGhXrZDJ3d
         8IUd1k5zseVy2a1HQp38mrr/WhacuEevJCDdBYCFWz/kGNhO9bTnj+zpDYdnsR9wyU/G
         3FSoyzY7Y3rCRh2yerNKaXzzpV7yuf+ZPNaG461cTDGsOHIdcUBFUF6JOZzNhIkibtk/
         C62wcwSMWUymEMn3lO6xk1B+YdaMdGglvBOefPFqtfwCAW872s6nguOoryRU6KA0uuOu
         ApiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=tomPML9D3k8Ybqy773IvhXXvS02MzY6VBFbKZCwLuP0=;
        b=jsVtwqoOiPMakShdd6AiIu1Ux+mLI0XgqTpti1kZPihqCPuSzAvFw6Yj0k0VjMOVa8
         8u7u51Jpb2mmE/MLCxUbaUddfXW6Kmw7dv5G+pFaMoQ0qhGMTCH4VeSVd3PvrJiDOLJ3
         9D/bXz3prS46jAaEZo1KULC3oh62woao4QntPe6da/OFyZPyf7iZBMllA7c3GzZByDb/
         QSvSrxNOaJ977xntWRrMZkGAGPJUVWu6eBPCkx01p2gLQOm5FB8Xc7+fb9XXNM8mBvcL
         GHE7Ci7zTQYfjqLcU2rrVUlfhETg8jDSuJ7nx4qBr9o9FrBujkdYCgbFpxuKu/fKykuS
         m+yQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bUMcmUtp;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id c2-20020a05600c0a4200b0039c6559434bsi471861wmq.1.2022.06.27.01.38.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Jun 2022 01:38:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 329BAB8103F
	for <kasan-dev@googlegroups.com>; Mon, 27 Jun 2022 08:38:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id E7715C385A2
	for <kasan-dev@googlegroups.com>; Mon, 27 Jun 2022 08:38:47 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id D0E48CC13B3; Mon, 27 Jun 2022 08:38:47 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216180] KASAN: some memset's are not intercepted
Date: Mon, 27 Jun 2022 08:38:47 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: glider@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-216180-199747-H9RNPRvSuv@https.bugzilla.kernel.org/>
In-Reply-To: <bug-216180-199747@https.bugzilla.kernel.org/>
References: <bug-216180-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=bUMcmUtp;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=216180

--- Comment #1 from Alexander Potapenko (glider@google.com) ---
When I build the kernel with this config, I can see a call to memset() in
almost the same place in truncate_inode_partial_folio(), and that memset() is
actually the one in mm/kasan/shadow.c

Could it be that KASAN addressability check
(https://elixir.bootlin.com/linux/latest/source/mm/kasan/generic.c#L162)
returned true for the non-existing page?

For posterity, here are the registers from the report:

================================================
RIP: 0010:memset_erms+0x9/0x10 arch/x86/lib/memset_64.S:64
Code: c1 e9 03 40 0f b6 f6 48 b8 01 01 01 01 01 01 01 01 48 0f af c6 f3 48 ab
89 d1 f3 aa 4c 89 c8 c3 90 49 89 f9 40 88 f0 48 89 d1 <f3> aa 4c 89 c8 c3 90 49
89 fa 40 0f b6 ce 48 b8 01 01 01 01 01 01
RSP: 0018:ffffc9000547fa90 EFLAGS: 00010202
RAX: 0000000000000000 RBX: 0000000000001000 RCX: 0000000000000ffb
RDX: 0000000000000ffb RSI: 0000000000000000 RDI: ffff8880789a6005
RBP: ffffea0001e26980 R08: 0000000000000001 R09: ffff8880789a6005
R10: ffffed100f134dff R11: 0000000000000000 R12: 0000000000000005
R13: 0000000000000000 R14: 0000000000001000 R15: 0000000000000ffb
FS:  00007fd5095b3700(0000) GS:ffff8880b9b00000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: ffff8880789a6005 CR3: 000000005a582000 CR4: 00000000003506e0
DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
Call Trace:
================================================

, so it was a call to memset(0xffff8880789a6005, 0x0, 4091)

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216180-199747-H9RNPRvSuv%40https.bugzilla.kernel.org/.
