Return-Path: <kasan-dev+bncBC24VNFHTMIBBENEZ33QKGQESPAOO4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 11765207A9C
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jun 2020 19:49:07 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id a9sf2018718plp.5
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jun 2020 10:49:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593020945; cv=pass;
        d=google.com; s=arc-20160816;
        b=V18bCc+JUPvVQSI3XgtRR9sIpL3xLsUcWVcxXoivSLJDAWwFd3TFVjUmtmUV9LEL/l
         /8jtxo0KjZEjAdaCncG3hf4zFCqE6MCptqQ1dN9sNVyu8svUHmps/pGmSbUfEVVvbnnU
         8cYhzCIVmMRolKOeSjtFDEFEnE4C0H0elozYYsJO66ZTyfYK7pXqvDqO/7chgGxdtUaF
         6iQ7rR5K9VPfty52hYqZ0rxwjxlgPo7vBuS5XcP8PwY9ESCSO6hNaZJs9qcXn+mX1MNK
         c9ZZzhs62zl0wrAbIIMwmZrBJT8h+RDSRm5p5TJDyVYVy/F3Hu4qKViNxNLHYadZFzlr
         nDsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=BL5CMx33byDdLmtnQA2z5R/3ImplbbNnAdEWNB9ct30=;
        b=QIlJ2wadZScuAMw71OE8fk/E3O8xxaR0C5YN5fUkoxN3JepgaGe0dAI2puAC3ZbBf6
         IemRvLWL8hUZisOJ0PEQV8fTMKqvaWgMTY5V4ruC9ighekgP1wU/n65GR5NJSct5by+4
         22m1yrEn4EKJVCZJ6Sin33I2fAlNLjLcFFETWeogfLbOHntedkYZGxt/5KD0b9bULcmy
         wRr0Nw6gQTlhDXHlN+pbXwZZgSzf1RjWcN/qU7pyeehELFQoAHUrBxM6Lsep4Du4n0hQ
         2S/GAtPpZ8ZkW1Pw90odQmvrgagn1gKcb8Z2ppLpTrJtCZBY83ksN96Q02BJTtNTbilx
         vXzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=7ptk=af=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=7pTk=AF=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BL5CMx33byDdLmtnQA2z5R/3ImplbbNnAdEWNB9ct30=;
        b=UbSzSybm/rExLo4UxRy/XDJO2chyv0OmKyVwowb907EvfStQY1fqIUJst5bJDDYh48
         GXNbALWGgf6SlkiggzWDQG+0eXA0s/gG43NbKcLDlfcfvK1flKZPvJ/pqyd/LagvJ3pM
         fOO9Ng8p0wVNafbbqtVmRhjf/FmJqP/dJdItnjHmAq6cHwPJL7Rpg7fCmOsU7Q/97g2B
         o83RRMZdPzY8gBjOJt42v7UGAOwvWvFsmYXxGry7MhfDxN1HSsstIaoiZEj+XsOKLqdo
         ac7A5WaVoKq5c7tWeQ6jjYf7l4mie2OPDJ6yuENtKS9qNKEJE93mFZtzPUisBnLBfFrT
         klKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BL5CMx33byDdLmtnQA2z5R/3ImplbbNnAdEWNB9ct30=;
        b=T/hwelCjsnQqvNGdrqET0Qh8gU5yTl4dV7f8gtroB7fGhdcl96zNipTVDTIhG4RjRM
         7I6tNO1nSLGSDY5I7j+7psjMcgZv46iD+5fuD6LsOVXIzfANjiE4rO5nNDllr1KwzSkt
         zPofC6Wz6DJMTdAwj7folAifuigykStNhdTcG72nrIvnoUWjYPR4kTuXHVXDrcVd8Gvm
         j62RAqFRFEw/dPD1fb7Dt811WDwGvF611tKXHt29jPINXb6SYnKN4+0FEM258d4ZfuYR
         3DmsMIjV/1OaF4zQ8B8nd63VMN6tP/3towioi5xjbujMFeIqYq0VjC6MoXUbqWBQqmRz
         3kRA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5318CynBIn6OP7SGxp7Q+RrmKsOWy3YfFQNRxjMwzKF2KGF0lq9C
	hHgxu3oJAZHUJUbVvxThjHA=
X-Google-Smtp-Source: ABdhPJwYc6VMHPYDDvgN4e00QsqICUEXWYxdmAg2P3/3ErHZ3QfFWlIhnohZbYBPNOVzag0rpx+8vA==
X-Received: by 2002:a17:90b:238d:: with SMTP id mr13mr30536273pjb.19.1593020945615;
        Wed, 24 Jun 2020 10:49:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b10a:: with SMTP id q10ls1214454plr.0.gmail; Wed, 24
 Jun 2020 10:49:05 -0700 (PDT)
X-Received: by 2002:a17:902:728c:: with SMTP id d12mr8232199pll.155.1593020945201;
        Wed, 24 Jun 2020 10:49:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593020945; cv=none;
        d=google.com; s=arc-20160816;
        b=T2XZ24iz5lL9fFCmekgFYFBficem864YtwPQgt0aytfxLvsPuu+ektCmofNQYP5GnR
         k9Mqi1fPQfP5bMFPkCeFzd4Q6VQv+xb91Wj6OiH1vqbf+0o2URZH17L6ZYn/XCvYtgJK
         N7sco/JWL3ag33Jyy62aDGodrFt0stSg53xpmMgsiBQ8WI8+0UUl2FZ9m+2epN/gQ9To
         5ethBhtFhSW21f5W8bH3uc43Cx0ZfOV9DbbicpLaDewgYisRtHz1Us3bEQ5fBoqyceyt
         3ROqRUxgPd0LEinK6XBMNFFJ1wuJR2HHuRzNcF4BtPT/DQ2YkgxMnnaoUvkL/DbYqr0I
         GeTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=JUerhuh4yC1iJKnJNdXsNHPRJSKnUNvB629xSaKe3uU=;
        b=GGYkfjaat0luMgml0FtPQ6R5xTEuKjRlmKMe2zXMfzX8D1odYVwvfwGWBlsfdn4E0J
         D0wea8wANiLYXfsS1V72cq5hJlvUURMQtJMurCm4/kZ4gErqcGWXqNSlup70qvSStHBu
         r+QY0mzB5hj328NRPSL9iRTIOT4bwoU8XSZak2NIkIjohf00hOOWTeVYBJhJmtq+EGeA
         DwMVpC37NGgXmntN7Y3s1pMrTga8U+m6MhZ7moTUOaXEiZoiTbPNVcywfOxTTzw7NJn1
         +SqEmPyFrfUWxLwLqAs6gzEPu2BnthFW50wdNz6xLWNEm/Ly7UtB5ikNn478OlZdRuix
         KR0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=7ptk=af=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=7pTk=AF=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d16si1017078pgk.2.2020.06.24.10.49.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Jun 2020 10:49:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=7ptk=af=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] KASAN (tags): support stack instrumentation
Date: Wed, 24 Jun 2020 17:49:04 +0000
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
Message-ID: <bug-203497-199747-HWSCuHjn3W@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203497-199747@https.bugzilla.kernel.org/>
References: <bug-203497-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=7ptk=af=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=7pTk=AF=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

--- Comment #12 from Andrey Konovalov (andreyknvl@gmail.com) ---
Maybe we can only disable stack instrumentation for tag-based mode for those
files via something like KASAN_SANITIZE_STACK_init.o := n.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747-HWSCuHjn3W%40https.bugzilla.kernel.org/.
