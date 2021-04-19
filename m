Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5NB6WBQMGQEOS7HNNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 5579D363F0D
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Apr 2021 11:44:22 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id k25-20020a9d4b990000b029029b46dd5af9sf1297129otf.18
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Apr 2021 02:44:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618825461; cv=pass;
        d=google.com; s=arc-20160816;
        b=0PBIB+xP0UaBI1uHcuJRYz+E1XrqqlhIwpxHH3yJ9Tm31BERp2fqR9s4kNmlYBXIgn
         jCSu0gKQpcuzVaduxbtKfdYwKwbjqqdDv7p8B40MOrn138uq15hy6lPvQvbEoBD8s+Rt
         r5JdQwSFHR4t/BMzcLauVisZ1Dz7xMhd7jerIa2c3sxd9Al4bRRuCw3ixxp6jEp2LFxl
         aI1TokSvRJsYLQlYF+vOHXUj4mB8e1vjtQshLfBjJgO88vebZ6UEua2c5iVqdEJrjYJ3
         LI9LTlGGbISNLGkVu+G9/ZN4lCN0FAs82LQBsLME1wTkfB37p6rmNOh7+8PKqXhJcoaQ
         tpGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+CERUy5UsShU9mPNbtiDolFQGV2cP54/8kKvu0ryddI=;
        b=XFxtQ3m/7BKxYy4aY0SU9Skj9jiKA0Z9Be8GRWuaNd33Vwt3vK7kScAXNvBonGP5G2
         15bgzhduVCSTuSz833aboK6FM641DjNBGqLStgPtPgx/MEzvO6D6zQcr8wMkvhfziKlH
         mWzh6UHy+g/55zS6N0XPzsyefEDW8eFGBsVuQkscS13ICKNwIfhM98g4S9g/i7PanaaX
         0gGsk1GcYhBOx4G3xrHCrJC7HsY1mRQV0ymLBpaef1atb9fbfaqYV0CctnvAoKWy9bVI
         BhB9g0qsI1BwTjIlMRKeUNH5vAmuRnOJpyqXsP/tgj9dTJFr+fnQzPluW1rz3S2HMC5D
         1Yfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Fnpl5H0e;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c35 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+CERUy5UsShU9mPNbtiDolFQGV2cP54/8kKvu0ryddI=;
        b=eWqbYenqhsydcSaBjvvSwW26F3WqZwiaLRRhy+3X47eXETsE/GGILl/e45VIjaoEk8
         DxOPs8cDnalm4qubKYP8NB2X7rzPKCs6S1u6gVAqZMM35aJjNQopYBlUeqcD4CaOPTUK
         llcpEVbb3Vo5z9dHoVa6jCMIQiPqyPURC133BduOEm6cvBP5SBByrgkw1CZl0dBp0AXy
         QDhfCNyxhJOBNHOZGJUdV/a/OaK0lSQlbhV4+ZoQyw3y3mNbZf00Tr0mPsyet71X1f0w
         VYEBDX0Lcm9E+T9JZBrNeT86fner44mqAUVlx0N016QAG8h0wgIl5eQLn5E+rtScM+oR
         9tjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+CERUy5UsShU9mPNbtiDolFQGV2cP54/8kKvu0ryddI=;
        b=tKR3x9MLitcnbUd8noa3vbHlMsM4YuYd8lwRIpkx5Wrj7k5wTECZA8DQ/F9Z1PinXy
         8IW+7bDXLVMKEKO3uU46RXQQOFfp997laSzX7MkYC9PNL3hNgDV26vMCctIoQ7xlPFfn
         cL+nbkyoKGph6VIOuWWgNxSCJx6yhUagZDlVnL856SObBSo0xbYJKRqxnM5W1QKzYlpF
         vP8fMOLnXD+Oaew42TdGZwKh04JiTTb1PTjOQlcLz9jZRWqGhjfCOGHiZQAlF6rvsnlz
         XoQXSTW7Wvr9ha/90+JH9AUY+SwJMfsM/kdqKUFQF6t+wFlSyhxmqjxKa3V7Vb8TUPm6
         UN8A==
X-Gm-Message-State: AOAM533gBL5P7bYrOIfI29tT0mfbzpyu+0sYqNhieRlKDI69E/uzH1bb
	YjIIGPTvkjlsP+bh0biVVMI=
X-Google-Smtp-Source: ABdhPJw1gXTiqbOY50eOydQ2slIkcfgsgF4SztNQy/x96ywC2bjk2mqi6kseI1Cp8q8w2bqHwWQNzg==
X-Received: by 2002:a9d:4713:: with SMTP id a19mr13649736otf.71.1618825461353;
        Mon, 19 Apr 2021 02:44:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:724f:: with SMTP id a15ls1425279otk.4.gmail; Mon, 19 Apr
 2021 02:44:21 -0700 (PDT)
X-Received: by 2002:a9d:7848:: with SMTP id c8mr13636210otm.117.1618825460980;
        Mon, 19 Apr 2021 02:44:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618825460; cv=none;
        d=google.com; s=arc-20160816;
        b=QDuD7LTp9303fTAczWCh1oMIj66ybodzvGLVcNZmPVFX3HRskpFPuWt4aViTbz9qTI
         P8tn/j0OhfE9DtvIg8fjIXMhSv6WuYjonbx8IvL1L3RqvEkjfjDL3V5+tNu5DD96+gxY
         3B5CndzTyNUjuLebNTbruf1XR6OuUxuRNEy8NCjutiJ5vqtLLtazEwDrTSJ11C6AD/Hm
         DhDxQxAHS2hWT1OTW5QsWDF+M3qS9DVuiqp3outkUZh7Wp5o3RioZVqcAA5WfSvILji7
         2nKZcYljF5J2q395J2k7uOgG1SuJMjhxxspX8YiOrUNOt8zIktGPX1mepsuK3C0OiNIq
         itHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=C4SsjBBBWAk9PglcpWZrcZB88JEvecexvFUi0GD5O9o=;
        b=WJvMmqPOe/5nzboW/QrWtNgtk0Rha7l2iSPK0Ea+ppFSMYOXMu8dwL9jNTK0rowcIB
         u1zt6CrevYIqYFQzP3VjXndZ9xy8FfMWXJl7Dx5zv7ljo3P/d70XsEnPOzbETUL/5Qpb
         Tdc05Sd8A7p3k+irxbxNb81f7uBWfqgul2iQHqo2f8GAHHilgPHw9PEvH4/gBQUpCKDi
         DA167xbtJ+qNuYcuqJ0ZL0CZjq9cqWoZ3YgIy9zHkEfH7cMa+aT0rPxyzWOQBCwILeK0
         aENu13d3ksyYeWE7QU9orukSQQlLOm7aqkA24ZdHy4VG24b9Qg3rLes5tjKoxRtLYmnZ
         iPfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Fnpl5H0e;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c35 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc35.google.com (mail-oo1-xc35.google.com. [2607:f8b0:4864:20::c35])
        by gmr-mx.google.com with ESMTPS id t25si1196393otc.4.2021.04.19.02.44.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Apr 2021 02:44:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c35 as permitted sender) client-ip=2607:f8b0:4864:20::c35;
Received: by mail-oo1-xc35.google.com with SMTP id i9-20020a4ad0890000b02901efee2118aaso48609oor.7
        for <kasan-dev@googlegroups.com>; Mon, 19 Apr 2021 02:44:20 -0700 (PDT)
X-Received: by 2002:a4a:d29c:: with SMTP id h28mr12940962oos.14.1618825460590;
 Mon, 19 Apr 2021 02:44:20 -0700 (PDT)
MIME-Version: 1.0
References: <20210419085027.761150-1-elver@google.com> <20210419085027.761150-2-elver@google.com>
 <20210419094044.311-1-hdanton@sina.com>
In-Reply-To: <20210419094044.311-1-hdanton@sina.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 19 Apr 2021 11:44:09 +0200
Message-ID: <CANpmjNMR-DPj=0mQMevyEQ7k3RJh0eq_nkt9M6kLvwC-abr_SQ@mail.gmail.com>
Subject: Re: [PATCH 1/3] kfence: await for allocation using wait_event
To: Hillf Danton <hdanton@sina.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Fnpl5H0e;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c35 as
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

On Mon, 19 Apr 2021 at 11:41, Hillf Danton <hdanton@sina.com> wrote:
>
> On Mon, 19 Apr 2021 10:50:25 Marco Elver wrote:
> > +
> > +     WRITE_ONCE(kfence_timer_waiting, true);
> > +     smp_mb(); /* See comment in __kfence_alloc(). */
>
> This is not needed given task state change in wait_event().

Yes it is. We want to avoid the unconditional irq_work in
__kfence_alloc(). When the system is under load doing frequent
allocations, at least in my tests this avoids the irq_work almost
always. Without the irq_work you'd be correct of course.

> > +     wait_event_timeout(allocation_wait, atomic_read(&kfence_allocation_gate), HZ);
> > +     smp_store_release(&kfence_timer_waiting, false); /* Order after wait_event(). */
> > +

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMR-DPj%3D0mQMevyEQ7k3RJh0eq_nkt9M6kLvwC-abr_SQ%40mail.gmail.com.
