Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYXCROAAMGQEEXJMGDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 73A4A2F8D81
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Jan 2021 15:00:08 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id b11sf10249564qtj.11
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Jan 2021 06:00:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610805602; cv=pass;
        d=google.com; s=arc-20160816;
        b=B4OZ0eHLic5j1ADV79mfK5v/MsocBOXLyv7c7eo477XDdv6FYM4fy9XhAXcajK9t3A
         lCaiCfR6DpzNakmhtU3w/pBPOfofvA6g3LOQipS3QFCHdn5RtQqETCAEG/Y0VoWADxsJ
         DOFVnJ6dhhLuTpxVwfhOq9V9uzhMHht8Zu26S3Ja5Sukx+XDpcGWubgCwn2vAPwob+IQ
         2nVGEPfeLGj+/0XUaHHuOCzWsUnwBkdbSYB/EyPGCxtRLMsGgIr/yx2Xlcs8GPQUjnpz
         zPSEJ2BVk68DvHL0cVweOYVJOX0SA9uua9EuNZdAZ4Yh69uZ2h19cgKMIUXPr0lXSpMq
         oNiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=n5Xfotgcnkoh7FCkGF9SQx/rrOFGtYEFcNhAhVIySPk=;
        b=UrO0p/xMY1vLnhqn6TJeA8ibdEZZTYRIaz9/P82TTsELi3hBpUsnAA1U77iXlhC4Q4
         WA7j3HJoZeqhmlLk5byiv7TXnN6KU559HyG0qU9ajv59iGXKcf1xJ9OkpWZl81tn6DXi
         wud/L7hxprN7lTEvDlC2p+IPrF8yuFQZh65w+N+Cg2ihsZ9pXBh740eKymuJU3vOGJ1D
         W2wyzQgbHhoA4e5C4cLxGEe1e8etPngR6PY9dAWUfq+5ipCH4hMnB6sCe8OuKvuABK9a
         HfmNnOuvPvmcbNRXA/hWUl2W4wc45mlYRTCbkOKNAE4I5DTAl/CfLEuCPdftGrfK1S5f
         PFwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZE2gHlbT;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n5Xfotgcnkoh7FCkGF9SQx/rrOFGtYEFcNhAhVIySPk=;
        b=XFKNpHjZe0XOYdgxmm/bbNmpuvUwnT5Nq60ygUccehTI1b3I7gtLwlwzbxaXseH4pf
         9gSnj8R1r0d53diH4pab6BT7jSdmS5V4QSvFo7fOd9SvegGUCFaPx3XUt4s+bDwhJ+3g
         BTg3+Z/ED6usvYOMI3FAJyAglRGypMsEKQmG/mswTuFWM6RDzEzUdySowhD6xjSeP421
         BrTq9uEwW8s4lMZeqyY30e1+GNOKYOUhn+1eSG3tl1SY10dnpOoacnggmqVf83Cd4CdM
         UAfpSQ8nT4xRzkedH3ZZKL+BPit/DjGGWtderuj+JqnpF9IVNVywZ/x4stf5a7es/tWN
         Qw7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n5Xfotgcnkoh7FCkGF9SQx/rrOFGtYEFcNhAhVIySPk=;
        b=ea8Y7luwSQWeUs76Q7JNpDjAUOg6eq5O47UwJEbe+rW6v5cADnBOyLKH5C68fG6Rux
         UMrNxnjqtX8fby19iN3Kn8Pw3W41L58ga0DtoaQ1KQac3BSppzwQg8MemtcGpnwtvAE9
         1a2vitFGmCljQ7nWziR9ZTbsT43B8pknr9eiF2ja9zn1g610wN1Vx5YhUFDAxH09kvrO
         q9AeKAK0p3W3EE+CKg81F/lZCmgh47S4UlNWjiJ9wYFI69UZbT+AeBkrMezOp6brBabf
         OJHBVx91qiUkj4b5qRQBIDU2Gd773vcppKGwerkSSQWO2nOyJgCK0PxS3ALKpjWf7WhQ
         esTg==
X-Gm-Message-State: AOAM530h+tUYnjv8iT2iniR9oupE8dKeEsCl4XazGZ6rytwemDJ1ckMc
	RiaU99gIrrTbFClI+1mL0is=
X-Google-Smtp-Source: ABdhPJzKmv+ItoAMuspywwC6oN1TvpqLvQm5iDlgeA8GE6Ru9fb7YaOAgkiL6C0kkdUldAtrwHkTcA==
X-Received: by 2002:a05:620a:645:: with SMTP id a5mr17041299qka.335.1610805602301;
        Sat, 16 Jan 2021 06:00:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:ea19:: with SMTP id f25ls6222622qkg.7.gmail; Sat, 16 Jan
 2021 06:00:01 -0800 (PST)
X-Received: by 2002:a37:bc07:: with SMTP id m7mr17048181qkf.438.1610805601830;
        Sat, 16 Jan 2021 06:00:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610805601; cv=none;
        d=google.com; s=arc-20160816;
        b=Wxj0MP29E5fA6r/RMcYtvI45UAVf2Rb5meH0VYxlGbkwNvv1/g/M4fWpJ2HsGIVZr/
         fcvmvTUjE9o3DV5iUU/WJ5zJcGfa1zjeN1L+tLYCZgX+KcIn8mTcGIvtnGHnx/+1LN9+
         DCmElLzVRJxhNXN7/cCZ+t1AM1JGsyIU8UfDHqwrYc2vhu4f5fE15iaykBif9B1RyP22
         m4olZEZzGC6hR/VfgDnWsfE9dqlLbu5MblXsfGmK00B5d82E0d4kpqa7ZeZoZn3qpvxW
         Vx0eKQIHx2GDaIAaqODXR8Sa8kbzA5L7puIXZY1leQfVZCDOLzyskt3Pe2L0yC5pmi6C
         dQTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5CFvZTpCZJzYQ5mYlVxp5BmoY9i8eIizwAZi0uxfmFQ=;
        b=mPhr3/zgUosJFbH07t7DJfe4NMFm+XALpm1x2EYkjcgWcMxokCnhCNM6gLKI7M77/S
         COIAuQfXu6jsaaobE5SdmnHwgdiEqqKFFsV18DZvykxorXjFqcSXUaxVliwCD96ZSAXv
         QuSmQUkHXd96Xu1ZQMjcSW4YL9qV6HETsbL6TEAibZifjxM6/hpCrbu/CbtcKHyhpr0i
         lDCNJGoxTwJbqJTMaxRDyGf1AtynIB/bgOT8iua6UEInQJBEULUqIdA2rY4iCKKMcCmr
         EKEC0atT/9AyJLGL6bqGoyM8Efa+Z9dEoXOZ6FeC1aKiZcY45dGDGyrSqPlsmNbWx8+T
         GIpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZE2gHlbT;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id p55si1309350qtc.2.2021.01.16.06.00.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 16 Jan 2021 06:00:01 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id my11so6699200pjb.1
        for <kasan-dev@googlegroups.com>; Sat, 16 Jan 2021 06:00:01 -0800 (PST)
X-Received: by 2002:a17:90b:1087:: with SMTP id gj7mr15763146pjb.41.1610805600760;
 Sat, 16 Jan 2021 06:00:00 -0800 (PST)
MIME-Version: 1.0
References: <20210115120043.50023-1-vincenzo.frascino@arm.com>
 <20210115120043.50023-2-vincenzo.frascino@arm.com> <CAAeHK+xt4MWuxAxx_5nJNvC5_d7tvZDqPaA19bV0GNXsAzYfOA@mail.gmail.com>
 <4335128b-60bf-a5c4-ddb5-154500cc4a22@arm.com>
In-Reply-To: <4335128b-60bf-a5c4-ddb5-154500cc4a22@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 16 Jan 2021 14:59:49 +0100
Message-ID: <CAAeHK+zsY7zdkj90K2zgXOScOj1WbackfBPv6gjJ77SfdzDi4w@mail.gmail.com>
Subject: Re: [PATCH v3 1/4] kasan, arm64: Add KASAN light mode
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ZE2gHlbT;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1030
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Sat, Jan 16, 2021 at 2:37 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> > [1] https://lkml.org/lkml/2021/1/15/1242
> >
>
> Thanks for this. I will have a look into it today. In the meantime, could you
> please elaborate a bit more on kasan.trap?

That's what I call the boot parameter that allows switching between
sync and async. We'll need one as we're dropping
kasan.mode=off/prod/light/full.

Feel free to name it differently. Perhaps, as kasan.mode is now
unused, we can use that for sync/async.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzsY7zdkj90K2zgXOScOj1WbackfBPv6gjJ77SfdzDi4w%40mail.gmail.com.
