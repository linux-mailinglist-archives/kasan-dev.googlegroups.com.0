Return-Path: <kasan-dev+bncBDX4HWEMTEBRB5VLTH5AKGQEDFKD6IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 04F62252EB0
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Aug 2020 14:30:48 +0200 (CEST)
Received: by mail-vk1-xa3e.google.com with SMTP id r8sf709175vkd.14
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Aug 2020 05:30:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598445047; cv=pass;
        d=google.com; s=arc-20160816;
        b=vWNU1Y4cb5/F2zFyoDQxdkmNh+S6dS5IuRDXI7+YpomYT192zB9uB5w/CaU3BT73EX
         Ds9bjP6kcmA15tzXadeTnV4xxcWt+LXdIsBIDwl39+dPFeOMq5enzxMg3dqrE28GP7z1
         ui/SHXqWbRfRXppJLEpgmjEW8v43v/ih7oJPosDozGtbKcdPKjb8wM93yNwl6JNz3AoA
         dwASIaBAUq+XNP93e8Uyw6emrWNB1xUczrATc9IyjGd8xFHrHbTjEQJ076EEspd5nXeX
         Mj5tq7kwSsUgBB5QykweHtZfHx3qAnHnJz6kVlotwcxRZcIxSx/JdsfaH9w+9qT+ogjJ
         4zfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Z0vzl/GTrDy5CWFyc2rMChP14f9kcrcIVfDXHAtGLc8=;
        b=u58t6HPNDC07f8mfPeuE71BMJYGzeQB57H9E3glcEAwAONaXNuxr4icOAaKWaM7kkc
         pHDjofma4t2XhJGP++nMdemE48Jc44V88fWCY/9KKQfqi2V26El+cvlARzB20njIG4zL
         FH1giVDUa8UkeyeT4Zw+YhGQJJC0vc6DDrvPkqofUwL9TfQNWcEuWs1/pl9B8vNgg6Me
         UYOKb4VsflSmjDGie2tcgurn8bvgkm0lbgSnycfeeH9liXTKKw45d6Asah0BwXkk0Cy1
         SNO8rgo0hx7r7f/g0+aYLbxlmI7wSbk2wpQMkgERGwMLpM0JXZyClg4dJd1DXBrX7oOT
         LGAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QakGTVbn;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z0vzl/GTrDy5CWFyc2rMChP14f9kcrcIVfDXHAtGLc8=;
        b=pDC1YWkwwrIF1dC/73cbBFl0mhdvPnYM8rMtfMqcX4IZaBAqDm8Zgfp6rd5lYswbcu
         qRy0SpCkaQ7O4NVdUpNJdfEmHI7gnStO9Z8X8DuR6wAlQyO7kQ8qs/Xdl8L3y5D0sKnE
         46YVtxtSDZU65kkrZybaHhRZvAiBhGWnMLLRs9/XCTTahzWRIq6wvNXTjq4V4FYSSGPF
         2YkQSxjU9coplkFnxsYcgJNmIFq3mewqP31n8mhwYv3pUUoMKJ3z5qNw8OC71N0nDjOb
         Jmdtld8ABMoXzCoGqs+F4NjEmDgKm9Ow1zo+en0M7fStOzRim1iBMG/w7u05//9gT+6/
         Jd1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z0vzl/GTrDy5CWFyc2rMChP14f9kcrcIVfDXHAtGLc8=;
        b=YlfiJIYHc8610a5r3CO+lkqD/aNuDQ3/lzIAZarltibrG7ILdAk+D3z9A2bcCzjPUb
         rwjyQyEBaJXIQQF2vUcRucrUlWpGhqAtTwaUvdEvwPO8ZnluRLqM1QU8i4dhNtduGO+Y
         fhMqPYJcQj1eheqmHbwHfOAe/XbdY8rKz+PDynZct9fvGDrzM4dgQxzfB9jMKgq/Gnx2
         k91e9nKKWr0ueI3VqV/8y74ezRU6gf947+FyxISjAKENh15txtcA6cZrLKO8qcR+Ikk5
         z1D/fOFSjgrIsfYpvsdGVirDjAjXHK5sp0KSkW60VRm/LqTtrXMBa6ki18Yj2+BO2SWO
         nQjA==
X-Gm-Message-State: AOAM530C8Q46eh26a0nOhuKvd5xBcieV7tiNqByj7mRpMakS73PUk0S7
	JFCopsjWowlVrVqvgTWpG/I=
X-Google-Smtp-Source: ABdhPJwDZkKMKi9sIOKMfI79P+aK+Z9FhnwxF5zN+VKloEmLNRvimidb8hnY+btSEhd0e/DK/noH5A==
X-Received: by 2002:a67:e2ca:: with SMTP id i10mr2504541vsm.156.1598445046945;
        Wed, 26 Aug 2020 05:30:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c416:: with SMTP id c22ls232796vsk.4.gmail; Wed, 26 Aug
 2020 05:30:46 -0700 (PDT)
X-Received: by 2002:a05:6102:300c:: with SMTP id s12mr8430585vsa.199.1598445046480;
        Wed, 26 Aug 2020 05:30:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598445046; cv=none;
        d=google.com; s=arc-20160816;
        b=UhPXqxixZ+jK3gzbSXrnYui1hZzDyxqphmfobX7fdCDvi/sVMKB3UaZxAF9efGzUKr
         NZGRkxgahA6h3WVcD2v4N75FD9I/Y7hAJTrLTfUF0QbxUqNupMfXMnSrnfkmH16sChai
         E+XMAKBeDn8GbCqJ1d/vzJdqyLYPQ049HOzUibQLIOqVt7MDBSFHq37W4uAr9QElAriu
         ANyYUEJnLTedLUtcVv8bE2BgN41kNZiSsqK7zyBOXic2mC0h+k1XIh5wC267Rv7KXB/6
         +hKF9gomouAAZWfQvgUnvO4mchiu9fFwJrDWQ5dOicBRBLwQcZNpFrQigFPBFuC133RL
         e+mg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lKGfppbU0E9vUo/Yy4y4n653KjJPK3r8SJn5wAvVr+w=;
        b=uZtXMf18huwyF12kZO8H4Hx1qTB5OUY60EGLKkT19qxFp4EDBIAxlaMKHOKVeTekoo
         XHVDQNyHloetCNZ+ACP7s1e0gW3vumm2PtCOsPERqNBO81ZoewZDD8PfK8zWGcGSKLDM
         d3BPPBIa4VWqCg37ylohBmuGME9edd4ec9+KwPY/fv62CrXYrH/J2zVFbeisCKh3REnC
         rQEXfcYCmkRDBcvo5/sur0borOxBB7IGbW4IoitTzLeGsdVbs7CGUI6b08NzBVFzD1me
         y2H9BjulL/QRygUIK0H9+fmQv3nbTTVX9dUljCgnF/itsVVHhUL7Ex3JISqjl41B9806
         KQzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QakGTVbn;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id f20si112917vkp.1.2020.08.26.05.30.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Aug 2020 05:30:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id bh1so818793plb.12
        for <kasan-dev@googlegroups.com>; Wed, 26 Aug 2020 05:30:46 -0700 (PDT)
X-Received: by 2002:a17:90a:2d82:: with SMTP id p2mr5048424pjd.166.1598445045375;
 Wed, 26 Aug 2020 05:30:45 -0700 (PDT)
MIME-Version: 1.0
References: <20200825015654.27781-1-walter-zh.wu@mediatek.com> <CANpmjNOvj+=v7VDVDXpsUNZ9o0+KoJVJs0MjLhwr0XpYcYQZ5g@mail.gmail.com>
In-Reply-To: <CANpmjNOvj+=v7VDVDXpsUNZ9o0+KoJVJs0MjLhwr0XpYcYQZ5g@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 26 Aug 2020 14:30:34 +0200
Message-ID: <CAAeHK+yVShDPCxVKDsO_5SwoM2ZG7x7byUJ74PtB7ekY61L2YQ@mail.gmail.com>
Subject: Re: [PATCH v3 0/6] kasan: add workqueue and timer stack for generic KASAN
To: Marco Elver <elver@google.com>
Cc: Walter Wu <walter-zh.wu@mediatek.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, John Stultz <john.stultz@linaro.org>, 
	Stephen Boyd <sboyd@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, Tejun Heo <tj@kernel.org>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QakGTVbn;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642
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

On Tue, Aug 25, 2020 at 10:26 AM 'Marco Elver' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Tue, 25 Aug 2020 at 03:57, Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
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
> >
> > [1]https://groups.google.com/g/syzkaller-bugs/search?q=%22use-after-free%22+process_one_work
> > [2]https://groups.google.com/g/syzkaller-bugs/search?q=%22use-after-free%22%20expire_timers
> > [3]https://bugzilla.kernel.org/show_bug.cgi?id=198437
> >
> > Walter Wu (6):
> > timer: kasan: record timer stack
> > workqueue: kasan: record workqueue stack
> > kasan: print timer and workqueue stack
> > lib/test_kasan.c: add timer test case
> > lib/test_kasan.c: add workqueue test case
> > kasan: update documentation for generic kasan
>
> Acked-by: Marco Elver <elver@google.com>

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

>
>
>
> > ---
> >
> > Changes since v2:
> > - modify kasan document to be more readable.
> >   Thanks for Marco suggestion.
> >
> > Changes since v1:
> > - Thanks for Marco and Thomas suggestion.
> > - Remove unnecessary code and fix commit log
> > - reuse kasan_record_aux_stack() and aux_stack
> >   to record timer and workqueue stack.
> > - change the aux stack title for common name.
> >
> > ---
> >
> > Documentation/dev-tools/kasan.rst |  4 ++--
> > kernel/time/timer.c               |  3 +++
> > kernel/workqueue.c                |  3 +++
> > lib/test_kasan.c                  | 54 ++++++++++++++++++++++++++++++++++++++++++++++++++++++
> > mm/kasan/report.c                 |  4 ++--
> > 5 files changed, 64 insertions(+), 4 deletions(-)
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200825015654.27781-1-walter-zh.wu%40mediatek.com.
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOvj%2B%3Dv7VDVDXpsUNZ9o0%2BKoJVJs0MjLhwr0XpYcYQZ5g%40mail.gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByVShDPCxVKDsO_5SwoM2ZG7x7byUJ74PtB7ekY61L2YQ%40mail.gmail.com.
