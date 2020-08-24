Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7GSR35AKGQEXOONI6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id E6E8A24FCF4
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 13:50:21 +0200 (CEST)
Received: by mail-oi1-x23f.google.com with SMTP id v188sf511919oie.6
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 04:50:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598269820; cv=pass;
        d=google.com; s=arc-20160816;
        b=BDSPMaaA3SeYwO7rXVku1f5BCmqv+t7aianhxR/vu4I0iQMz42Dw15For5Jt4lTp52
         uuapf6xizbA/4qzNfGKrJ/KE/d1XbKnchRSpe1QV2Xbs6mzfaHZgwD56aLH2oPSt2UbN
         wik1L2wDtz3BraLxW3gBYGWdRL8mLHk524lb1LpBQelXn4BjAvSI2FqUd14r3MpU7bXy
         Ol4M4XhXkGeKIENQMsE2GwXVRaDIS/GtddAWw4IQG72gZxOMochWvhtQibXHdqRAYFI/
         fpd7z9SM6ENskTzZwq62VKl6b5po36eVNetEM4pc65nOX+8yS7LmFfWe5ufIiuCnQeHS
         Liqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VK1GYRJbHHNOV9d/uFS4z0nJL2hxT8ujWbns4TCQGO4=;
        b=MNfnPU30ceiLCVgdIFrlc2+Ua4AWhGLq07ivKgiHaSEKq3mGlZXCB9h40Ft+pt6icW
         iQwvHRcuOmz3zes5SW7ZTVKIKW6GNPf084bqTtWXh/1USE0FVuv3u5VS8dX/OzJkfETc
         iOMppz0EVH/NhgaokqInj+Mfb5HD/xBmxU/OTi4w4j3oPhhjjNA00OuWm1n4b90uJNzf
         d2uXtwHaob6o93JHUgi4nNvICsH4C+4EiBGZaw1XaaTOgskhq9tXZ3eBseDeeJEYB1Y6
         u9q/n0zTYluunGZhiWf9rtmsLOjmU4KcM7oTfODn3Ss21OH3kUgIxkg91U3BvowxMbO3
         wW7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oLyJ6GRK;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VK1GYRJbHHNOV9d/uFS4z0nJL2hxT8ujWbns4TCQGO4=;
        b=aDqvqhMyBex7txC5Jvee4nmt/NWfTwWJYDzn5Rp6ldTp+fu7DXop31NAnydbfDMmrQ
         MjcGnfkYlJdtZkqtSfRE6pelhdTD6CdRS3fBrcNcqNUl1/ey2EknWtWrjjtPuu/132n/
         MOVEvjj8NvRc/jrJh1m9dD0IakNnhaOyJssZk3VRyHr7coRhmPj+FzSgyOXzyV6oP7NN
         IeUcDqXUFulRsybM5+YairwUVncgHgj1aBYvLcmwFfNqce8AJSkkZ7Dco++m6HHAuYFK
         qhjg5H5ES9biwi8forf8mQbdrJOvRopukTf/jz1mYwJHSfNlYzhPwl6qVJA7uLSdlQ2K
         v3Fg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VK1GYRJbHHNOV9d/uFS4z0nJL2hxT8ujWbns4TCQGO4=;
        b=VpAw6W6sJXZvb5QQdz5QHZfioRAmtAxTU1K/08KdjTbIv4bk44yu2OyU7JK6akGXKz
         AuaTH/4wN3ycbAl6awVLr4mEhINSLbOobzCI807lkVtZFrulITm2d9qT8PvQAS8vyC1R
         bAk52gkuNynTm0PE7isZZTF7PIBhQGNQ96glfN6jo8qkf00v5m1zy+LRdTKW6f+TvV1R
         jcHFgoWXbhmhACwf7N4dhzwJmYqMfWmAVLDxLxOScc7Tz7xLf4/OjtqjamH4ezEINBJv
         oZ/mkmiUR9yFoIHHc8Op1mdpss4TlzQh+F5xb+u1fUYwW6n9SmuksLNW26joaoYxXgE9
         eWrQ==
X-Gm-Message-State: AOAM53160tE6v1MdHiRBxLaUW5yE6G9b3pOtbyPWXkL0t+GKlHvronjU
	gwzHphOLcBatQ6femMV5/bw=
X-Google-Smtp-Source: ABdhPJxQavxJUR3KuhEcz5HtoPbGbkzTpYS78FFTN9wc5QQ136RTFw1C0SyCrXgkH7W8bIb2RDy54Q==
X-Received: by 2002:a05:6830:78f:: with SMTP id w15mr1493166ots.208.1598269820665;
        Mon, 24 Aug 2020 04:50:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6a13:: with SMTP id g19ls2017252otn.6.gmail; Mon, 24 Aug
 2020 04:50:20 -0700 (PDT)
X-Received: by 2002:a9d:4b82:: with SMTP id k2mr3370717otf.18.1598269820331;
        Mon, 24 Aug 2020 04:50:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598269820; cv=none;
        d=google.com; s=arc-20160816;
        b=vhKKDY1G88kGRq2W4hrAtWeSFAjmX7M51oeaUcEqogqviK7UxgJlcoBnFReB1NtEt/
         kPWwJwUTEA/fkoMdrqENW3NyibzudJFy/ACbFRe5P1KbXhTQoXSnpkaKuSerfrQ6N7NK
         Mw+lbH/TDJR4hhgZW7o8kKXDitQF9p1swxiz9QQrUZGtWiCNUMkhD2zqAwo45EGFCufn
         E5so0r5RG5U0hAJ5N4F+e1fMreCGHXgXn2FKuF7gT/xhyYT90oqU+lTGrEX4160WlZ7u
         80cjWMKXUi89loV9Wt5C1d64lRaov/1fKB3w41rqzVI6Ckg2Ldxcm3HYq51G5viAD4gv
         umlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yJXg3YmJV9VmBBuMxTtghIxF3sII7GvdsrK6BwX4Nus=;
        b=mmaOPoD9oegW311RciAi5WEbdWQDNCB9C8ikNcUztBYymjdFsG+E18eTv97cr91rSz
         nsTz22Gjo1NqC6y5FThysUp9msE9Z5/59m0jz1ltQckPTviLX3Q7FCWcQfV/tl4l50rU
         KVnLBXbi4gRd5BPjiaXDddl/M15ABXKHklEZjmqL0tCS0Yo1o022PPQSXfHtP6cGd/jc
         SYsCxLoGUdUy0BNX3G1hhX4PwuEP7YOAgIVw0506Dd0elg8LXdh3HWA19lmtJyQI6pGO
         3nlK37fkPlslJC8IGpcc7GDE4MAlpgiJErgyXEPB7eABXs93TmFs5DtB0g1fbrHnEeT1
         mPIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oLyJ6GRK;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id r64si477451oor.2.2020.08.24.04.50.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Aug 2020 04:50:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id t7so7034396otp.0
        for <kasan-dev@googlegroups.com>; Mon, 24 Aug 2020 04:50:20 -0700 (PDT)
X-Received: by 2002:a9d:739a:: with SMTP id j26mr3480830otk.17.1598269819856;
 Mon, 24 Aug 2020 04:50:19 -0700 (PDT)
MIME-Version: 1.0
References: <20200824080706.24704-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200824080706.24704-1-walter-zh.wu@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 24 Aug 2020 13:50:08 +0200
Message-ID: <CANpmjNNYhYwyzT3pBzJdb=XCGyLj7X+Fhqui-6JAZJWGys25Rg@mail.gmail.com>
Subject: Re: [PATCH v2 0/6] kasan: add workqueue and timer stack for generic KASAN
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	John Stultz <john.stultz@linaro.org>, Stephen Boyd <sboyd@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Tejun Heo <tj@kernel.org>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=oLyJ6GRK;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Mon, 24 Aug 2020 at 10:07, Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> Syzbot reports many UAF issues for workqueue or timer, see [1] and [2].
> In some of these access/allocation happened in process_one_work(),
> we see the free stack is useless in KASAN report, it doesn't help
> programmers to solve UAF on workqueue. The same may stand for times.
>
> This patchset improves KASAN reports by making them to have workqueue
> queueing stack and timer queueing stack information. It is useful for
> programmers to solve use-after-free or double-free memory issue.
>
> Generic KASAN will record the last two workqueue and timer stacks,
> print them in KASAN report. It is only suitable for generic KASAN.
>
> [1]https://groups.google.com/g/syzkaller-bugs/search?q=%22use-after-free%22+process_one_work
> [2]https://groups.google.com/g/syzkaller-bugs/search?q=%22use-after-free%22%20expire_timers
> [3]https://bugzilla.kernel.org/show_bug.cgi?id=198437
>
> Walter Wu (6):
> timer: kasan: record timer stack
> workqueue: kasan: record workqueue stack
> kasan: print timer and workqueue stack
> lib/test_kasan.c: add timer test case
> lib/test_kasan.c: add workqueue test case
> kasan: update documentation for generic kasan
>
> ---
>
> Changes since v1:
> - Thanks for Marco and Thomas suggestion.
> - Remove unnecessary code and fix commit log
> - reuse kasan_record_aux_stack() and aux_stack
>   to record timer and workqueue stack.
> - change the aux stack title for common name.

Much cleaner.

In general,

Acked-by: Marco Elver <elver@google.com>

but I left some more comments. I'm a bit worried about the tests,
because of KASAN-test KUnit rework, but probably not much we can do
until these are added to -mm tree.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNYhYwyzT3pBzJdb%3DXCGyLj7X%2BFhqui-6JAZJWGys25Rg%40mail.gmail.com.
