Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPFHXKHQMGQENFVK6UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A7ED497E57
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 12:55:41 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id iw14-20020a0562140f2e00b004204be8b6basf13825113qvb.3
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 03:55:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643025340; cv=pass;
        d=google.com; s=arc-20160816;
        b=oWIMuKDhnneuo72YI/tl7MXBQ8JIjeB6YaRB4jImYQPKpPpe5gLOQgacwnDrJF8a6H
         AE+z8C1SvasiHR1Tbg2E93UyQzfwiFL5UBA0dOj4OC27KF91XXTq2CU2Mz15JkqeEGuC
         tOhgSr930/MsNvUYXhlY/Ql1bsL/BwCWro5645BRjYiWgDDMSpX0BIuXc+t1Mf0NMq0R
         l35J3GtaRFTGV20TiIxQuCB6NCX7cQLX1VHQpPS8yzJM69CDiciXlRXIaTGnh9gXxVt5
         VwzS84IufYx2DXfBOXyrXGija3LT7FzBslPkP116bNI5WNgAZIyz3tMDDHJYBn+JbIsR
         a+fA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=uXl12Qha+xqYMbHOBj8jK2I7SWDnqM2HVg7yMxXkJBE=;
        b=RW9ITsnkVZ3Rd4rDFqfbQJDHxNyZzOfOtHXobeHZIOZa/bNWDthY410c0xMs67XApB
         gxRFVI/SjyeiVkVvtaYr/bzSdR57jEc0LQrtavHX1+X2RgTdhAFQG8QPJ02tGo2QaNA3
         J07kGevFlIRan0dCC9hT3amtJQeCiCyt7rsGMCSJUq5TquA5F1JLup2j9Y7pRticr+yG
         s++AxM8c2uNQ5vwEk/ROoOAe/QzD33kavjTzuo8az5NDHWOFEMHOa8Wdg51tF/ZcJKSu
         r/SS5Io+gLnvifV1xGvIxXTuHZ0imTvxvI/CnZNA2QFjzG59E473wKpl8NemjE/sDPyC
         +TDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HNu+maSS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c33 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uXl12Qha+xqYMbHOBj8jK2I7SWDnqM2HVg7yMxXkJBE=;
        b=gjZAK9JJsGhH9hh+CJnlPZayBUPn5JyYZs7wyKUuPQYAAO7vIe+m8OVtTCT/+upWPk
         ynqAnYN1lWVj8I7pDLHW1XUgPseixzmPoXvGKwV5hW/Ig5mux7EnKi8BKS3vD+Pxtv5B
         gka74oBT+CQFtjH1Z5/drVRotMYc5PojT15qCog2iOrK6WK4yv6I4aQ3b8Zqi1Hnv8aj
         IEW33FpbbCFfy4OQSVipDxjd6jEcxVDfwPcYt7QU2wPExQVxkwsWHgGbtqx6iN+IbQgJ
         bt1ZmyACh2LxW66h3V+Nmkn5oAG9oLJ9EgDTIH20+/L8gyzH0YBut/zNBuKU+kq+7bzd
         Es3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uXl12Qha+xqYMbHOBj8jK2I7SWDnqM2HVg7yMxXkJBE=;
        b=0JYLVT+tC2pj1TA+PAR4HiNrg5nPPBGC7a1z2IhPaU0vDTC0ctkYehyPW/865My29p
         uS8fcJrY3f+eAaZYk+MOF/wedDKEVkBiC9vXBhBAjxaxWDOGWcaWAptzMXjJVfU9bs1U
         yaDPgSVcByQx0RjrnmpP1NR7pxuGwSqStAAhhYGSxLJSzE/OQpRz20OC2VW0saSGZKaR
         k13T87DN7qnXvsTV8Z3og+OzSgNUNG0etzOB86ZSoHaH1E9I68sKM8oQ8pQoYm+vU76R
         JyksFCvaEV/9vV6YDIM5/ncfR2fnOhCp7slNmuXgpbzJYZH9BgUCCyXiPwtaQBk2axkw
         LXXw==
X-Gm-Message-State: AOAM533v/+zCNEy6mh/NysXuDdCxNaoqgQPbr5DW14AxBNsNk3YdPHgn
	DQOp6qH83vCGlA17/SoI6ks=
X-Google-Smtp-Source: ABdhPJzECLjxbH/OQ/1G9fP+NMVKqryPzaVoQvfrqSi3FWyFwoIoUkDk4iR/1IqQ3a+RIIrs7wII+g==
X-Received: by 2002:a05:620a:2982:: with SMTP id r2mr10745833qkp.92.1643025340575;
        Mon, 24 Jan 2022 03:55:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:b207:: with SMTP id x7ls7519540qvd.5.gmail; Mon, 24 Jan
 2022 03:55:40 -0800 (PST)
X-Received: by 2002:a05:6214:509e:: with SMTP id kk30mr2873211qvb.10.1643025340160;
        Mon, 24 Jan 2022 03:55:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643025340; cv=none;
        d=google.com; s=arc-20160816;
        b=O8IBAKWsUZDpg+SajSC8OnjvVXd8bCuoschAIfWzowpd89fdyNy1Jnh+dumksh9G7w
         BXuFlkXRUjEluyTmYN2lYlt16Q/COmiZkchecPgH/oyY6xQhzoB/oud0QfLZhZ2utSjh
         ec/X1Knn9ZwswPmPUFw982uTBszz5LOyYDPYA3WdeQk9TH9YeeDzVA5MK4K0NZkrC/tO
         O/WYfXME/8ZwlIORPS7pK+zlCCCgj2mUQgUoOKlGyWgOw5V+3lAElwxvGAL0aAkrP5f6
         CnU2rwIumokWMLd4G36grBKODwNRk0ahua4iFOid4ZHkjCXSaTeicPMhXCAHy8G47GuY
         FGAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=McNieCwRwqdn4mXgmAvirHEqDHVQd8Qo6rMG0vyrR7Q=;
        b=bSgxemBEgO7MaKjLSwQaqC7xReoo7X5NZmEoQXPbFgTHhmpmIuD/BF3oF6UdomtFEx
         QS+RBd/mlDi6iOPWpCQ4+wzp5F0SZhX7moSx01iOyASvh0iNzoyk6/3LAc713bK9K74q
         qle04l4U+E92S7MmUQoORUhQlY/FhVMa0BuzfsO2D+HtGB1l1sJbnn0W3ikLxs3WA19u
         Fficb7oJtcRJkFIOEVh9U8YGws82voR3rluBBjg0lDRa1dc/VlzYkvU51Kt8Fqq9xiDF
         lF5IbeuqURUmGgnlIxQPwJU5avxN3RLLKdDJvdxZyAp7kDYdeH88GKmRVVPUaP5sPVdM
         ZaZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HNu+maSS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c33 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc33.google.com (mail-oo1-xc33.google.com. [2607:f8b0:4864:20::c33])
        by gmr-mx.google.com with ESMTPS id m1si1773019qkp.4.2022.01.24.03.55.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Jan 2022 03:55:40 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c33 as permitted sender) client-ip=2607:f8b0:4864:20::c33;
Received: by mail-oo1-xc33.google.com with SMTP id v10-20020a4a860a000000b002ddc59f8900so5718427ooh.7
        for <kasan-dev@googlegroups.com>; Mon, 24 Jan 2022 03:55:40 -0800 (PST)
X-Received: by 2002:a4a:bd84:: with SMTP id k4mr2249718oop.45.1643025339517;
 Mon, 24 Jan 2022 03:55:39 -0800 (PST)
MIME-Version: 1.0
References: <20220124025205.329752-1-liupeng256@huawei.com>
 <20220124025205.329752-2-liupeng256@huawei.com> <Ye5hKItk3j7arjaI@elver.google.com>
 <6eb16a68-9a56-7aea-3dd6-bd719a9ce700@huawei.com> <CANpmjNM_bp03RvWYr+PaOxx0DS3LryChweG90QXci3iBgzW4wQ@mail.gmail.com>
In-Reply-To: <CANpmjNM_bp03RvWYr+PaOxx0DS3LryChweG90QXci3iBgzW4wQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 24 Jan 2022 12:55:28 +0100
Message-ID: <CANpmjNO8g_MB-5T9YxLKHOe=Mo8AWTmSFGh5jmr479s=j-v0Pg@mail.gmail.com>
Subject: Re: [PATCH RFC 1/3] kfence: Add a module parameter to adjust kfence objects
To: "liupeng (DM)" <liupeng256@huawei.com>
Cc: glider@google.com, dvyukov@google.com, corbet@lwn.net, 
	sumit.semwal@linaro.org, christian.koenig@amd.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linaro-mm-sig@lists.linaro.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=HNu+maSS;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c33 as
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

On Mon, 24 Jan 2022 at 12:45, Marco Elver <elver@google.com> wrote:
>
> [ FYI, your reply was not plain text, so LKML may have rejected it. I
> advise that you switch your email client for LKML emails to plain
> text. ]
>
> On Mon, 24 Jan 2022 at 12:24, liupeng (DM) <liupeng256@huawei.com> wrote:
> [...]
> > > I think the only reasonable way forward is if you add immediate patching
> > > support to the kernel as the "Note" suggests.
> >
> > May you give us more details about "immediate patching"?
> [...]
> > Thank you for your patient suggestions, it's actually helpful and inspired.
> > We have integrated your latest work "skipping already covered allocations",
> > and will do more experiments about KFENCE. Finally, we really hope you can
> > give us more introductions about "immediate patching".
>
> "Immediate patching" would, similar to "static branches" or
> "alternatives" be based on code hot patching.
>
> https://www.kernel.org/doc/html/latest/staging/static-keys.html
>
> "Patching immediates" would essentially patch the immediate operands
> of certain (limited) instructions. I think designing this properly to
> work across various architectures (like static_keys/jump_label) is
> very complex. So it may not be a viable near-term option.
>
> What Dmitry suggests using a constant virtual address carveout is more
> realistic. But this means having to discuss with arch maintainers
> which virtual address ranges can be reserved. The nice thing about
> just relying on memblock and nothing else is that it is very portable
> and simple. You can have a look at how KASAN deals with organizing its
> shadow memory if you are interested.

Hmm, there may be more issues lurking here:

https://lore.kernel.org/all/20200929140226.GB53442@C02TD0UTHF1T.local/
https://lore.kernel.org/all/20200929142411.GC53442@C02TD0UTHF1T.local/

... and I'm guessing if we assign a fixed virtual address range it'll
live outside the linear mapping, which is likely to break certain
requirements of kmalloc()'d allocations in certain situations (a
problem we had with v1 of KFENCE on arm64).

So I don't even know if that's feasible. :-/

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO8g_MB-5T9YxLKHOe%3DMo8AWTmSFGh5jmr479s%3Dj-v0Pg%40mail.gmail.com.
