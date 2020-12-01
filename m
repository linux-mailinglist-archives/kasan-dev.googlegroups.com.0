Return-Path: <kasan-dev+bncBCMIZB7QWENRB35QTH7AKGQEZ2GIHRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id EDCF82CA638
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 15:51:28 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id j145sf1124880pfd.8
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 06:51:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606834287; cv=pass;
        d=google.com; s=arc-20160816;
        b=MdagQ0EdjPbAnLn7WxDk8d3N2dItJ+9MG6dQl7/R4/2AOCgJHB4S4cuUVV/gVB1JL7
         9GpupTt30mGKQrHyKFndThQjb9TKF4FOMq1iuBVWVdNNq0MFBwa8YJRIIOG1w0UfVGBU
         v3ZwVOCE4M34/7BZXBKWz3QqU/n9FjHEjAfCqf9vdEqw7yGqPVD233g8UGzn3rQ2L7WL
         8+EG/SgkTuNU5DMGNyAykfEvX3n+RM42i0ME4/QXT1nxGBxBo6p0VUiJR/mJemSyGp9z
         +2x2RrTdhU5X6QPUdBdkI+1HSkrtcsH2fiu/KaZZeB1aCYb1NMA5AeTdKELhg5LEG3Os
         1nyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PHyf0IUxlMMT/4XzIrmdvUn4k5GdX6TkcLzmxrYQWiI=;
        b=riM31XTPoXt3y5UWRWv5BCQDQEpWHSw0SFZXxlEBCccE0+LxVfDF/LsogUNAqiloXO
         K35as0btWj2aB/aLVNGkDj54q6+rYzmGpJGzQ+PFb5aN+mH1IYv/D6cc9Tb/avmQVYol
         CNyoPeSxDeZI/eSJVrwER3ipg4IFs4mJhXLocWz4zV/PymfwVBevYFsvYSBtZADJxAba
         ssqd+ioeJ9ZCANzD/ZgvKPHcxTBcX0zazgcYJNpBFs5dWz6L22dJ2WWYDYXq9iGRkHje
         u4nNzLDz4B/2+KSHd2Y5QtHbo27Dd7pV7VFkKRcHZgM2zUIdRmOEC1lYFx5V+gqCrE9t
         yUfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Od7Oq8i5;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PHyf0IUxlMMT/4XzIrmdvUn4k5GdX6TkcLzmxrYQWiI=;
        b=WkfCA0hIYr0chMiYL4t5YhqFCEejNKoaJrWsN6LyqR+ouiL63pv9ySCqi1M1jlv37Y
         ASjiWUpzWO1nJSOtMiktSBJor5kfbn4ENbn4cfNFJWJC0htk3wm1c0sxMToFGrfHTafb
         tvcAEu9ke1/9v+CBMCaBwCaAcgYK1gM26IXGenS1U0kguT+DmMeIz9xBofWbNECIQamX
         xUK2tg69f8V6ToB3lu+0BVuuY1um/b4fsZywsG4MPuFQIRWdSogIoZaFl7u8WzkGG82k
         mGFSnzA13YSXttks37Kh33Hwc552loLtR1RNDWUFkclO3q2LTiiBXbapR8V7DYLe8Jnl
         q2eQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PHyf0IUxlMMT/4XzIrmdvUn4k5GdX6TkcLzmxrYQWiI=;
        b=mqy+r/Rs3wax2HYllULHNO5VPt+8rFAB1U4kKAnuRllqgMg5p+T6vkQW3pawXzcpV0
         qwAOGylXfw39W3Mx+5Eaq4RdQdxqFYHgNn0lFJVrgUswbeElcfmBpXX+ePWxQbo9ssFb
         ZUi5nx5LCLZFdU4FaajqPJNL2u8QrTWr7gIvNVJLVz7F96lAwlEgBaXIOA6QfeXHis/l
         YUyslQGXP0PRjkrcqVhpT4cTJcJIuJjW1R/saSopdGdVGD1kGdBQBZytd7PsVFs+VORB
         H/cj24nYFxvTRVsgONacnZhot9eOXcCkbivvXOaz94CN88mU5rfqSNLd27LxzIJ9x3ji
         xz+A==
X-Gm-Message-State: AOAM5309mu7jgvvB6YzKcwR+mJitz3V2Ycq2PN7/lXoJC/tZGY0Y8gzR
	mReMKrs0tBkf5uIsK4wMNA8=
X-Google-Smtp-Source: ABdhPJwdEda+3egx+kBuA4u0vz+SiD1EUgCHEsTO+4VQfk16rcv/T4pBxPi3My1PQbi38DDsxH8uOQ==
X-Received: by 2002:a17:902:468:b029:d5:ad3c:cf52 with SMTP id 95-20020a1709020468b02900d5ad3ccf52mr3129657ple.7.1606834287676;
        Tue, 01 Dec 2020 06:51:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7556:: with SMTP id q83ls1049428pfc.3.gmail; Tue, 01 Dec
 2020 06:51:27 -0800 (PST)
X-Received: by 2002:aa7:9f8b:0:b029:18b:9c0e:a617 with SMTP id z11-20020aa79f8b0000b029018b9c0ea617mr2828371pfr.16.1606834287077;
        Tue, 01 Dec 2020 06:51:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606834287; cv=none;
        d=google.com; s=arc-20160816;
        b=pYqr9YMADCRBdGu1WUljgm6kq3qVlRLmQMb1Yl4JRg0kJexXv5NTPfxzcZ91V2+FLn
         jfkUMmoJ/WVhl63hGepCU6Op174LRZ0a4dU1F01Yu6Ph7F+/Nl24A6EFG3DqpckqWczK
         +SoYF6m3bwGWs7V+eXDRzXZorpJHWfLfFrf+l57OIhiDhr5kvRf1RJggggsmSKf7XPXB
         6Iav4TuFIT/Vfmgq3AN+mLh+9sldbiOtTSTUpnRAQaSHH5x7LGcvncE82zqxhkVjPLX5
         EQgi5ty0zJnUtESLmX4v7dK2ZFqDbpMAxhNkVicfon/5hHVcshZygYwR69oT9szq8XfK
         d7nA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=55sCzQdwTnWWY4frFoH/T/BSKgGKnPew/6aq6eljiTo=;
        b=l8b5vi/ND6EU6Oarhu0DOAkWzqVqHd+liZeh4TVliCtbfCbqRrHuL9T4dDaznd+9t6
         8KoaiG7LfEVVgoozq33E2pR0GZA5lSCpDiVU+517eN0QtJOfrVrGvleMqwrt/DdtXXsP
         F/8qzLM6Lv0uOAqYQdwhsYE+tmqj9T8Ae9GiYQcl04JUZyXNcRccW4Gk9gWuDqexiRQp
         fQC8mqd5N3rjhEdh3KxZ22MQAlRFj+KMc23zMlLCK5+peeZ3VJsFSCVnK5sze8wkg6WH
         0YzO5es7ZIS8Dyu/evgI0drr1lp3ndAgDSRUmcNWMQ/RJ9LvIcPr6C/0mDxwnCb1hLy1
         KsrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Od7Oq8i5;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id f14si91060pfe.3.2020.12.01.06.51.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Dec 2020 06:51:27 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id y18so1436432qki.11
        for <kasan-dev@googlegroups.com>; Tue, 01 Dec 2020 06:51:27 -0800 (PST)
X-Received: by 2002:a37:7b44:: with SMTP id w65mr3270634qkc.350.1606834285972;
 Tue, 01 Dec 2020 06:51:25 -0800 (PST)
MIME-Version: 1.0
References: <20200924040152.30851-1-walter-zh.wu@mediatek.com>
 <87h7rfi8pn.fsf@nanos.tec.linutronix.de> <CACT4Y+a=GmYVZwwjyXwO=_AeGy4QB9X=5x7cL76erwjPvRW6Zw@mail.gmail.com>
 <871rg9hawf.fsf@nanos.tec.linutronix.de>
In-Reply-To: <871rg9hawf.fsf@nanos.tec.linutronix.de>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 1 Dec 2020 15:51:14 +0100
Message-ID: <CACT4Y+bWm_bPdbes60u=3d_u34yxBBC7rGQz1yAt1FQXXqP4-A@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=Od7Oq8i5;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
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

On Tue, Dec 1, 2020 at 3:13 PM Thomas Gleixner <tglx@linutronix.de> wrote:
> >> > Syzbot reports many UAF issues for workqueue or timer, see [1] and [2].
> >> > In some of these access/allocation happened in process_one_work(),
> >> > we see the free stack is useless in KASAN report, it doesn't help
> >> > programmers to solve UAF on workqueue. The same may stand for times.
> >> >
> >> > This patchset improves KASAN reports by making them to have workqueue
> >> > queueing stack and timer stack information. It is useful for programmers
> >> > to solve use-after-free or double-free memory issue.
> >> >
> >> > Generic KASAN also records the last two workqueue and timer stacks and
> >> > prints them in KASAN report. It is only suitable for generic KASAN.
> >
> > Walter, did you mail v5?
> > Checking statuses of KASAN issues and this seems to be not in linux-next.
> >
> >> > [1]https://groups.google.com/g/syzkaller-bugs/search?q=%22use-after-free%22+process_one_work
> >> > [2]https://groups.google.com/g/syzkaller-bugs/search?q=%22use-after-free%22%20expire_timers
> >>
> >> How are these links useful for people who do not have a gurgle account?
> >
> > This is a public mailing list archive, so effectively the same way as
> > lore links ;)
>
> Just that it asked me to log in last time. That's why I wrote the
> above. Today it does not, odd.

Some random permissions settings changes were observed before, so I
can believe that.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbWm_bPdbes60u%3D3d_u34yxBBC7rGQz1yAt1FQXXqP4-A%40mail.gmail.com.
