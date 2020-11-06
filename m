Return-Path: <kasan-dev+bncBC7OBJGL2MHBBROTST6QKGQELJJ4BJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id C13DA2A94A3
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Nov 2020 11:47:34 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id r16sf571810pls.19
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Nov 2020 02:47:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604659653; cv=pass;
        d=google.com; s=arc-20160816;
        b=g/5uiNco2jNyFtGm9JZpCVdLBKjqr0zsq7Os1ao4ek/Ld2chmSchoUt+G1/5lwIelH
         9sP7wZ3uZW8VBaeF8bMqfCHr7dqINdhkz6f0oWui1lXHqa+NsMcMtjY2drXU6kZAzC91
         5ROV/v/Xk9vI9GogVZGe8rWGQYHlmoY7RwkJ8I9phajtHM87XxzuZ6Gqj6sCnvU9P0lv
         1/FeJ5SfjzkHrmeQ02oJjnGgCxcJFxkP+8dKdRqCFNTsuhCrX/hCJeu6Cw5X2OxKGADH
         NN7T7/NROO0tJyzXwpZ9QsqdvuECuGoDBO1jskRfIHsPpx+obvl0hRYsBrPiXCuOFaNu
         yyxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=RIRhs/ggSQxqSvB/25Q7xAGbd6RbkAxkQe6ICrQAlPI=;
        b=Tg7JWS9ZYPSP3yh0gFmJqQVNTBNSrg+xHtYGDZmEzznRzsttvsRlaf1s4E3Dwz9bK2
         GuG5ntpX7wGYll+DitQMSlk/rK3OIU+yD2RPIXcBBNmbei6QrsvigzxTkhGsbxFf7NrZ
         Cz0HuWIbxhuDloFuC8loMs5NKJKEo5Hw8KSQvi+fuBEF3EGCMigdiz9UAEGX1McU10Cy
         SBCuNJrZRHUng20RNfEjBEUt8qA4D0ZC/0VMFH4DfrD9lpd4gg/zUUabyxQgSRGVOC5j
         PtyPJEBkAYQFq3z8jAOHGYqZFmIoNoI1bt3Ocq4eIPJesykFk1wM9LfjPTviKFYBJuIL
         IV0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=REm1ewpp;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RIRhs/ggSQxqSvB/25Q7xAGbd6RbkAxkQe6ICrQAlPI=;
        b=LEtHZAr6q3YMdLLJqtveDZhk0uK7eSotHveNAUP+hFRY3aRPEkIKdyvKmP1Ao3gsE1
         8+6wFY85QSAwP+brZEdM03FrPyZav5x4V9CF4xIMbJdXQMja6TroNH2TEIpQoYNjRMXV
         kHp99yDsFvLWub8ePuwDUEaIbSre1YuZcAwgOIrHQ1RNKzmVB2F1tGl8F+maxltsktzd
         POd7SiJBt6ZpJBsHY6+e0IPpWVwS0dHlHhcq3FBjQsrdKgWDP3gTds3+y6XyUQTb4gwt
         6HVnr+WivhMXhaYUFla49qOXJqUqYgLQZVvrorKA3zny9PxVQar6ccq/UId2jIMzOs81
         e+Fg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RIRhs/ggSQxqSvB/25Q7xAGbd6RbkAxkQe6ICrQAlPI=;
        b=uEmjM6JW74MLUt+cnhRMbgI72BLp9qrD5fJdyhV/PtmyHzlbCee+9QvhFEAbGc7Qhg
         i1NtZmU/wF8QJtsq7H7N/KcTgTTSJs6spQ4B+cM6qpF4zw4d68D/w7p6odkQzrE18MRh
         O8TCdYQLk2puKFULOj5nk5Ru4D9wqlLAf31tSphs942qPJrjg5x1xDHz4TDnq7HglU8Y
         ICCbaiPBTxIRItShPNdCQ4x+DbZWVwinDV/k1n894bphS6QAbgfCjpo0oPzly6vA9yib
         shKACWepA+MJFRWr5IOosTcv3l3sqSBOt/H6NqzSJX0v0Y77VfnQQpcXFU9Ng8aGY4KF
         mhvw==
X-Gm-Message-State: AOAM530M87DOVgwLN7buz5cEdDnGah54XpvfaTzp//HGg2qty9kHldel
	qD5pxnBLAerrviUHFCKJKDw=
X-Google-Smtp-Source: ABdhPJzRD2RhBllDMifS0fd05HBin58UYzaonV6f6JDdfxnOU9aEMIe7G8IMmkTK24YOUiZvUPXUUQ==
X-Received: by 2002:a17:902:c253:b029:d6:a357:3a60 with SMTP id 19-20020a170902c253b02900d6a3573a60mr1269399plg.26.1604659653257;
        Fri, 06 Nov 2020 02:47:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:8cc4:: with SMTP id m187ls445991pfd.4.gmail; Fri, 06 Nov
 2020 02:47:32 -0800 (PST)
X-Received: by 2002:a63:1e5a:: with SMTP id p26mr1246533pgm.85.1604659652726;
        Fri, 06 Nov 2020 02:47:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604659652; cv=none;
        d=google.com; s=arc-20160816;
        b=ADRJr5qKSsijzWM22H2hr26qe9VktfjElD4tXPsm6ujVRpPgxkj13fcl83ANggJyjb
         UcLXhX/F1J0hmQJZNhuuWv2d+qOUahSJrVwc2rQXFHHWZNdZPw1aB8D+9ReQo/xrX6wP
         IvoOkdLnS5TTCxCR5KG+zjXVJF3XAh6gONyBFv4/VodVadqTatx5CFBN0xJrE01QktCu
         PzG1A5iKQDomS+ETSS7OH+9pQ5uFXpFw5r0qwei06YtdTsOV3py87I4tWK9ebd6cZLyF
         nQ2/8aeo5NAocjNGqqj2aNRiDxhJMV16AWQOQJv0MVhCh7hr0HDgbvjJkEF6ukfHDfj+
         LuMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XieLODQoDUtSJdxggAHOW0kb6kiCXrUMxQ1jrfa6znc=;
        b=uThGNKruUPwjWEvR3vJH9Er+WNob7J/n2JpdzncQPiMHFdmj1wMZ9jotGnTr4IKLGd
         YAtC4TMR6YpNeJTegsrXNOchp8GRmoCTZRRpCCC+EcQD9jzjwffogWh24nxhTWHJl0RN
         73Vloy9zOA6xi/slLDDVlEgD1z7DDELZPTUE724xXm6DklEGNZTqMm5C1/I915LuQfOm
         0vEFQD7HdvTIesBngR7+9dOXIiemPO8gUm7hGCk/v1Ul6va02u0QtgZdxA8QB5QCV3vj
         wCAWS+KIFUCNy08CU5imOIm2e0zdUlLrjr4oAFaRtOjcG+FTw4SbI4iueCrXp7OfSGTD
         IOqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=REm1ewpp;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32d.google.com (mail-ot1-x32d.google.com. [2607:f8b0:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id g4si69714pju.0.2020.11.06.02.47.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Nov 2020 02:47:32 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) client-ip=2607:f8b0:4864:20::32d;
Received: by mail-ot1-x32d.google.com with SMTP id l36so852947ota.4
        for <kasan-dev@googlegroups.com>; Fri, 06 Nov 2020 02:47:32 -0800 (PST)
X-Received: by 2002:a9d:f44:: with SMTP id 62mr755169ott.17.1604659651887;
 Fri, 06 Nov 2020 02:47:31 -0800 (PST)
MIME-Version: 1.0
References: <20201105220302.GA15733@paulmck-ThinkPad-P72> <20201105220324.15808-3-paulmck@kernel.org>
 <20201106012335.GA3025@boqun-archlinux> <CANpmjNNj1cc2LUrLdbYy1QkVv80HUPztPXmLfscYB=pU_nffaA@mail.gmail.com>
 <20201106101856.GC3025@boqun-archlinux>
In-Reply-To: <20201106101856.GC3025@boqun-archlinux>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 6 Nov 2020 11:47:20 +0100
Message-ID: <CANpmjNN8J=bQiEzW5Ohrf2z3eec9oZk9YYRR0Zsv0-WDioPuPg@mail.gmail.com>
Subject: Re: [PATCH kcsan 3/3] kcsan: Fix encoding masks and regain address bit
To: Boqun Feng <boqun.feng@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, kernel-team@fb.com, 
	Ingo Molnar <mingo@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=REm1ewpp;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, 6 Nov 2020 at 11:19, Boqun Feng <boqun.feng@gmail.com> wrote:

> > send a v2 for this one.
>
> Let me add an ack for that one, thanks!

Thank you!

-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN8J%3DbQiEzW5Ohrf2z3eec9oZk9YYRR0Zsv0-WDioPuPg%40mail.gmail.com.
