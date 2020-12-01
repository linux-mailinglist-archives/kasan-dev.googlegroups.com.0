Return-Path: <kasan-dev+bncBCMIZB7QWENRBDHQS77AKGQEMZ77IRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 4372B2C98BE
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 09:00:13 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id 4sf475038ooc.21
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 00:00:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606809612; cv=pass;
        d=google.com; s=arc-20160816;
        b=lAPLpAeuP7iAm4LZJwX74/Mz0R9NBQWtZlN2N1eYDj/kHU5M1Zi2g6xY66X2C/YVLq
         CAzBdFBRHl6j4aPJUKEEDPhGgnlcUSj6WJT8Rd1gJwTZts5H+NhpXgWnrZtMieZtwKDi
         pYTIGHLhrnURHhmMZoJiGqTCsZctZNUNQfNQslGapmnj39EAmxKQs8XZa/9f2NMxlIKZ
         u8O7pN2dckCtinDTO0xfojNqxZ3isFJbHaeeYLxDhHJze/3kJi38sQsFe0pM21hC22sl
         GobITelvVJReGB9bxqN7Tuw8ntowUfQHj6cUXVRJ8g0B6WxD1relGT31c8KyeGLTLoZ+
         HdVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tc9E9Mnq60d8+bxoFP2jY7IIDAnDY3xpsvwwWtVjbMA=;
        b=PyKnXUOr1Jgc3cLnhdSdwNXWvm5t5tmDc/fM51vsj305FjFILp1KDZikrJTwlz0v4r
         L6tlo6YyuL72UWCRilTawxqnTLFNN2JCQb7G1knLQrSBVKfn4iJEF2xiJJnJireHGJOt
         n0ptFDb2VQnVLStFQix5ySLIo1UUREtKGsdlBiHrWawMW78Q6nd/gyNhy2BLxqTq2UUt
         Z3ZILpG1hexOfE8vh14M1554Ki3rkm18a1JeGeK5oQeMjcpKJDuNC90qmcUh5VHNaY49
         a+WTNYSSqz5f5au9HFwwMx269seXGZa0jJUSxkJb5mmOzrePS3WRh7eEWPylRiAx4fl7
         Sbkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wJyxFNus;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tc9E9Mnq60d8+bxoFP2jY7IIDAnDY3xpsvwwWtVjbMA=;
        b=QgyZuxwKYoCh8ASY2xgf4yx56U8nErr8KNewJ1Zk4m/0g+TM0EOTgVPpMfYxpRYmWm
         960N0HJ8uERbQEseZi7dj3JkXx6XGDyB2y6uzhzDnA4msLHU54sjjo1cWpxl2hXaACMB
         zvkQB56wDIspdwZfYlr6NkcfvCGLw4MwSC+UYCJLdF4NFtJaajLLgDWGQOl94JNTcALD
         EHaSmPrZYjHh7gfbYWRuhv8aMiVVOXKMcefNWTqxF68uS6fhaaSki76QEKdAZZXBTMiS
         +3cCbD2E1XmcD3+VUGRKJAdJoFev32TH+Qfp2P9yD/nYqnpnH73SbTtoqySjrKibfyx0
         qPsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tc9E9Mnq60d8+bxoFP2jY7IIDAnDY3xpsvwwWtVjbMA=;
        b=nrmXjME+qINzQRUR/WztyIsRHgzCJTKfAzuHbQOO4AjS7WAe/Oov4w49qCHp3WpoJE
         gbzC8W6ovUjJlZi5T/1+OPEB7SfOslooc8P8OU0GxQEuw+56Uo+SkCwUpOJA1PoBBqXu
         pdPm9nQfKc8UGKKzqZVWAv0EzSmxhh+IEhy8CKVHvsRihaUltirKrbxLvJURPqULA23b
         JjTCeKqXAX9isuzszNBjvjxgrl8MGZL2JJOQsoXv7P8V8lQR5y2GDkGBivpzOCGWZwga
         6xtCJwqwGDGC3VM+wZIW1umzJRWNkrQZCdJbyMsXszlwFZGzWTapE5HCG6ZjAqHVjVGK
         wocA==
X-Gm-Message-State: AOAM530UBTShUCKXk2PnGS52MoP5vUowUV/05zw/stMpmBczHWlLy61/
	fiSz8bxXlGzyPOwVPviL3hA=
X-Google-Smtp-Source: ABdhPJyVCUfWjLcEJiaxQGvwkECuqZqgOV+cz7Ii8F1EbXjMqJziHnHRqThUol6riu6UH81ssHObBw==
X-Received: by 2002:a9d:19cf:: with SMTP id k73mr1039204otk.360.1606809612200;
        Tue, 01 Dec 2020 00:00:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1118:: with SMTP id 24ls205475oir.10.gmail; Tue, 01 Dec
 2020 00:00:11 -0800 (PST)
X-Received: by 2002:aca:5413:: with SMTP id i19mr1037527oib.87.1606809611877;
        Tue, 01 Dec 2020 00:00:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606809611; cv=none;
        d=google.com; s=arc-20160816;
        b=ovWmG1aBgYcygPJO2lfnTXv9qQbtBm65tHXhir8HAkv778iJydiGEAtbvUrYEbLHWM
         22piyT+m2kRpjFe/0p4ZzVG29OTJElEObwuFNd1+Y7gDYPnn5TbXBduX/pvxQcTS/d5q
         thWse/mZNcehiYJzvbHeqdbLQegduVtsH8APupNohnN1ZWLjq0D+eiTW/AnWDno3GGyW
         Xz897vTBFKrVAPlEZcPq01jekuKOgEFIFGQ6YvqaEK7hBs6+Tc9hACp4X/dmU+RQ6hKT
         ciR/tGtQfS5qvBcJTKUqTnpKvMkpRyfOCHIjU/BTONQhkF7e4vXhxcE0jqufmb3h1a7J
         WXVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wB450hvW9e7AfsLXXAZocstx55cLQvcfr6fR43xbcBE=;
        b=be5MHhXUL68F5ZhsPPLHIi8u+BwqVrEdOKSzrpJIWnuDkOELbMsmvhHNTZenI4mLCr
         wcpiZ9lDpq3Zlb1/alTFLHvPnagUCYCA+CJAsGaSHt4VtX6iSLG/lLa1tDWvi8j3LWnY
         henXBDw0V9z0RhFskAJG1gH+F/rsjl13FFBARLU62xGKrP3CJSlSNxBXZeUvCIOFxW+l
         quYDGTPl8r0VyZk1ahTG7ZdxwhyXBBrQfWRucnseLmk1DeUlrIgbHnzVj+x1fGybZlHc
         kJrtIsyFzzNCNu0rFk8gnvMEd0+uc69VOfFabBsXdPccQohPxsR5T8BhQ7GdHa9J1cxz
         ackQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wJyxFNus;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id e1si95271oti.2.2020.12.01.00.00.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Dec 2020 00:00:11 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id v143so526034qkb.2
        for <kasan-dev@googlegroups.com>; Tue, 01 Dec 2020 00:00:11 -0800 (PST)
X-Received: by 2002:a37:7b44:: with SMTP id w65mr1641518qkc.350.1606809611184;
 Tue, 01 Dec 2020 00:00:11 -0800 (PST)
MIME-Version: 1.0
References: <20200924040152.30851-1-walter-zh.wu@mediatek.com> <87h7rfi8pn.fsf@nanos.tec.linutronix.de>
In-Reply-To: <87h7rfi8pn.fsf@nanos.tec.linutronix.de>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 1 Dec 2020 08:59:59 +0100
Message-ID: <CACT4Y+a=GmYVZwwjyXwO=_AeGy4QB9X=5x7cL76erwjPvRW6Zw@mail.gmail.com>
Subject: Re: [PATCH v4 0/6] kasan: add workqueue and timer stack for generic KASAN
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Walter Wu <walter-zh.wu@mediatek.com>, Andrew Morton <akpm@linux-foundation.org>, 
	John Stultz <john.stultz@linaro.org>, Stephen Boyd <sboyd@kernel.org>, Tejun Heo <tj@kernel.org>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, Marco Elver <elver@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=wJyxFNus;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, Sep 30, 2020 at 5:29 PM Thomas Gleixner <tglx@linutronix.de> wrote:
>
> On Thu, Sep 24 2020 at 12:01, Walter Wu wrote:
> > Syzbot reports many UAF issues for workqueue or timer, see [1] and [2].
> > In some of these access/allocation happened in process_one_work(),
> > we see the free stack is useless in KASAN report, it doesn't help
> > programmers to solve UAF on workqueue. The same may stand for times.
> >
> > This patchset improves KASAN reports by making them to have workqueue
> > queueing stack and timer stack information. It is useful for programmers
> > to solve use-after-free or double-free memory issue.
> >
> > Generic KASAN also records the last two workqueue and timer stacks and
> > prints them in KASAN report. It is only suitable for generic KASAN.

Walter, did you mail v5?
Checking statuses of KASAN issues and this seems to be not in linux-next.

> > [1]https://groups.google.com/g/syzkaller-bugs/search?q=%22use-after-free%22+process_one_work
> > [2]https://groups.google.com/g/syzkaller-bugs/search?q=%22use-after-free%22%20expire_timers
>
> How are these links useful for people who do not have a gurgle account?

This is a public mailing list archive, so effectively the same way as
lore links ;)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba%3DGmYVZwwjyXwO%3D_AeGy4QB9X%3D5x7cL76erwjPvRW6Zw%40mail.gmail.com.
