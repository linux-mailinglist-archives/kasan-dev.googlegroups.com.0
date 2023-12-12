Return-Path: <kasan-dev+bncBCT4XGV33UIBBO4S4OVQMGQE5BPD6QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id A696C80F8BD
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 21:57:33 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-1d0c7387757sf220915ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 12:57:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702414652; cv=pass;
        d=google.com; s=arc-20160816;
        b=piv828+iGTl5Xciq/5b0sVm3IK5ufDJK5bTNW5Im6/SWIlVvguU5tCzW9ILN7Gjb6r
         bnVTbB74If2D+P4LKRPqgyOQX6BTcmCydB22WwUrislhNAZ78yugIN+6crgEzVG3NCNC
         wIfn0vOhGLazeubxyKWmYXOcgQtJBSOFWF3Lg2TQQY9l7/7HfYnIwU/SmmRry8HdnAl/
         5BZUXZYhKm/8HcAudMqx1fyLUUHSMF5NRIYEGdDW3vBDUZ7riuyGSRZCQpZvG0i5lPtm
         8OlkIV9U6ieBvtV6p0AaHo+JaOC7Mu7ztmtaIHdyFz0yODm7HG3JIZGNeT8IqsLIKsPI
         pzqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=ueNDnQ/lPLWWfBuUGAAnUU+wq6W14Taiyf0RAjvf3HE=;
        fh=j+yJCijhZvypIl3NyKfHIn3cObmCdYCuiEiUtWohkkU=;
        b=UPpWr0lymlECPrVxp2B8Zalfi7rldL8jbpPj4NuzEKpYrV2svU2qlgc7jF6sEiDRIs
         u9GmwChfzViLojDKHZKNLJ5OETCzh6B0/BtL46NHoVmbf7kyyWac89H3ZuzwKJIF5ecr
         AxO+zbOzmZ29HrrtrzBjNBdsE9yCnMKDMtl63A9Po0PGz1LH414T7ajLwSE8SLmw1BaA
         Hkm06v303WSFFZp3BDSB5jiqs1zlufpG0uLWnIKa6BjyE2XizizTySN5js15+BXaE14u
         gA4H60zgyWJ9gQWgsWBix7IB5Q/6b8Ccxc+p89gz8NQyieTYK06l10SDluCqhvr4PeIG
         1XlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=e7knbxJn;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702414652; x=1703019452; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ueNDnQ/lPLWWfBuUGAAnUU+wq6W14Taiyf0RAjvf3HE=;
        b=xWTTqSBqoowIlqeMLy5vBvqMW+FTEuaI9zbxdLPvDCxbTqA4ZS2LhFSUhOLEOu0i3c
         H7N9GbUskx2Ub7b358y0SMJDm2F+kJMVs0trgOso+Db/KcPAw5mvKktrs+jpnWwl3GiM
         2nIVuZewK10qUGt06GQ6jnZgEOwurgf29o239+dPmIwEQ8yDiUBpIKYr6/drnyow37Q3
         VbWN1tfj/QKH0j2l/4XCBiWmuulygdgKIKymg8qmBOSz/3yB73vUGM3shLpszPBBtwS2
         scJeBa5exK442f6upAjvVYEI/8uBS6besStSj8/OZxUCBYvJMHj5t2ldxz0fbn/z1IYg
         8QGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702414652; x=1703019452;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ueNDnQ/lPLWWfBuUGAAnUU+wq6W14Taiyf0RAjvf3HE=;
        b=CTN7LKP39Ci0KDDQgKQZiUu0vKNYzAYPN8AAMqNDij9DtBQxsdZw/sBX9m/pfR/Ma3
         ownK6bGbh4karibWiqSRyCz84li2kbse3DeuWo75SKBJLn+WLJfbjWC4sQPR6djC6rR6
         I6/vfvWIJHgoFe9cw1vRS8ifw0xIKpRzUhxMQkfGlCogUQ3ReQcndizww5CUET4A3TXI
         QEN0CWzfyHnsVO+EvOR3jrDpnKMHCMzv8w+vzGFCrfPNbwaxPSDfaQkPOiZ2ywOkTT6Z
         u6xvkJOGjJhC1JcQo0Mbe0XE5Ff3YazsB8o/NDpAnPLi4Zrtk/l+C31fY0miJEsRFN0o
         SENw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yzxb1W2pjrk/kJgAqOmes1JlTHORdvcr3iEIg/dDB/j8Fgo0PsY
	Om3+QFgdCxnO7T501yJhIXg=
X-Google-Smtp-Source: AGHT+IFscCiRxhIH5sFXVSO85Sq/OPJkHRwZKf6ROnMd9jg9PoW5uQmsRdQAg+J9kZ88AqeF+A0vzQ==
X-Received: by 2002:a17:903:22cf:b0:1d0:d15c:8ba3 with SMTP id y15-20020a17090322cf00b001d0d15c8ba3mr930388plg.3.1702414652031;
        Tue, 12 Dec 2023 12:57:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:6646:b0:28a:b719:72c7 with SMTP id
 f6-20020a17090a664600b0028ab71972c7ls1212963pjm.0.-pod-prod-03-us; Tue, 12
 Dec 2023 12:57:31 -0800 (PST)
X-Received: by 2002:a17:90a:3c86:b0:28a:cb0a:f73b with SMTP id g6-20020a17090a3c8600b0028acb0af73bmr1026282pjc.34.1702414650869;
        Tue, 12 Dec 2023 12:57:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702414650; cv=none;
        d=google.com; s=arc-20160816;
        b=qMm1Io40sBD5EfVGwNvlOQbKWuYQGg/5oP3inPRGKJ5f75zr6Zau6Q8VaSiKHRmWkX
         qfMWpYYqzpDTHWhbGxDs4Yacd/xHhADTDv+eg1PLI28qTXMI7I3OzuDNBF7aNZw+c9FA
         eNkt5ySqRRvo1TBYOt91kBJeXu92zPA3IxCRpAQdTjiSpQb8v1PlYito3+OM+siSaPBF
         EdAJmCwg00h+KgMp35aaqoUq8iclfORtHGNkzQS1xGnS4eJFeW4CueDWQZigk6AtwO+b
         13EJr5hGghqIK3LPiOGCkUgwV1srT7GeLuPpuaQB6SBPE/WndoJIYjFl3/ClnXpjV+MT
         y0iA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=dZJyZJLfQ6WgMHyGRVy4d5YLSkHOLPELn3w4IYaCN+Q=;
        fh=j+yJCijhZvypIl3NyKfHIn3cObmCdYCuiEiUtWohkkU=;
        b=Lx2CFEJUv6KinzwH5Q1hA0iIfQKaZMgv2raEO4lvvnknh3ik6yUU1JRz1v7zLR3bVY
         8jr2E0mapEYrBMOkcQyHh2xwp5uI23Y9pOKdMiPWChEBA0QukWypMCalWZ+mXqrKmKOX
         uLFTsPWjMOLKVj9Ass79vNSAJ6e3pwFVteNazX9QZ8xuwRF82t6Bz/eAAlxkYhPWfZEi
         oKSs/eoZgzhll9HhOFmJXywzV5Ku4kw900MvfE7oI+pb7H9A+iw6X9aWdh7Iv0P5wdCH
         9Yt0zXMUz7IrWuSpEg6Iwbb/n+J/GEcdpgrnzTcrk5qDkpueiapz478RNq+4Fmdae8Jm
         lOTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=e7knbxJn;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id i22-20020a17090ad35600b0028ab0a6ab92si317019pjx.2.2023.12.12.12.57.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Dec 2023 12:57:30 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 33297619BF;
	Tue, 12 Dec 2023 20:57:30 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 98A61C433D9;
	Tue, 12 Dec 2023 20:57:29 +0000 (UTC)
Date: Tue, 12 Dec 2023 12:57:28 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Andrey Konovalov <andreyknvl@gmail.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>,
 kasan-dev@googlegroups.com, Evgenii Stepanov <eugenis@google.com>, Tetsuo
 Handa <penguin-kernel@i-love.sakura.ne.jp>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH mm 1/4] lib/stackdepot: add printk_deferred_enter/exit
 guards
Message-Id: <20231212125728.1a275e704db4a5f5ca30e15c@linux-foundation.org>
In-Reply-To: <CANpmjNNXiRxwTk4wGHL3pXmXo5YUY=VNLCf+g+kB6inXJnC2YA@mail.gmail.com>
References: <cover.1702339432.git.andreyknvl@google.com>
	<6c38c31e304a55449f76f60b6f72e35f992cad99.1702339432.git.andreyknvl@google.com>
	<CANpmjNNXiRxwTk4wGHL3pXmXo5YUY=VNLCf+g+kB6inXJnC2YA@mail.gmail.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=e7knbxJn;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 12 Dec 2023 19:59:29 +0100 Marco Elver <elver@google.com> wrote:

> On Tue, 12 Dec 2023 at 01:14, <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Stack depot functions can be called from various contexts that do
> > allocations, including with console locks taken. At the same time, stack
> > depot functions might print WARNING's or refcount-related failures.
> >
> > This can cause a deadlock on console locks.
> >
> > Add printk_deferred_enter/exit guards to stack depot to avoid this.
> >
> > Reported-by: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
> > Closes: https://lore.kernel.org/all/000000000000f56750060b9ad216@google.com/
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> 
> Reviewed-by: Marco Elver <elver@google.com>
> 
> Doesn't need Fixes, because the series is not yet in mainline, right?

I've moved the series "stackdepot: allow evicting stack traces, v4"
(please, not "the stack depot eviction series") into mm-nonmm-stable. 
Which is allegedly non-rebasing.

So yes please, provide Fixes: on each patch.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231212125728.1a275e704db4a5f5ca30e15c%40linux-foundation.org.
