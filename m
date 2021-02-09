Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZX7ROAQMGQEQM6L2XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id 842883158AD
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Feb 2021 22:34:31 +0100 (CET)
Received: by mail-ua1-x93e.google.com with SMTP id 65sf2870286uan.19
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 13:34:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612906470; cv=pass;
        d=google.com; s=arc-20160816;
        b=qqQOuQgjt2BOLk3zv26eOWtCikoXdrvxZp1rpVEtxIFvenKmLwBQH9ADVrhwhzBKSM
         whkxHSiZM+Yb1RiUeCFjZs9CyTBPmFEBjmT6XUjqOiYz4SgPUS3tOE9gj19Za+2Qp/9T
         Gc2XrdUNzqHrJu80ptNv6ZEmfOF6DVa/d4tnqy1FmQSfigs85GVJSkPFz70/04ostzVa
         Ti6bf84G6p8Qva6QT60zUkzcS9FKLJqg/DoSBqNgMqVffPzkq5mvX3YipacHXtEJ6r4k
         edKSDUdiHV2a9UVT6xkE8qFEGSrYdx1Awgn/8FU/vdkyEbUeatM4CGxLeV0UAuaSZ88n
         X+vQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hljV0G9Mq0kOyh3efis5/zadUmTFTF1FDHXlXt63BOA=;
        b=TJbLFt8TUYMibPJKwzPscg/59kAQg6pzCTLrflrHoPnnHPl3q6PUbYfFnn6vU3Qp6X
         5zEeGQOuBLNGUXHjhZMA4YiJM3atP0UZb/8K3Y3mUY93UtBFNwPU0odJaH9MjyN/BjyI
         vgIKWCNgUG2xjdUdh+5Z79+RT+HPpYekGDemSCKN1xlDVRRraN1MiHpjCpxZFwZ7ApV9
         DM+nSuKTEBcYTWYQHsfP0Mmc/OhhMaH4HGSdKfNWPp/mcIh6UyuWhFw1HMhRM/gvPHj5
         kE/CxeFKPtfjibp5HlwPMyrsGIHKa63iAJ2HHNkQC5g6muY6x4Ouv5YRpMF7p7a1wyI9
         XTsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uMWC68Ks;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hljV0G9Mq0kOyh3efis5/zadUmTFTF1FDHXlXt63BOA=;
        b=GW7f+EcLQ4Dqklf5EuzJp5dmvSj6tLBvNXwWuqHxJ1UT70+tEYju4lJ4Z1H4IxCEpa
         5I/X7huh5tDShh5Mv8w6H2bZMAapKcR1SD5mCqmdJc8xYG+LqC+JZgtNb2pUKmxLsrEH
         s7xVBoLaXjvbU4XzHMiq5ovcybAaNjDeX/oWYfTL6rTVbgDEFTaOUz6f2cawiuadeiNG
         INqZVkQJ6AJzd9t3AxUYr8do+csmR7nSMv8ZCJGrV6965hthOfLJHRQEcWTT7jYdbiG4
         yr25XtfgA37aKn65RVJC6bSjkwuOwcz0KnCBw/17oA3BPL1c9kH+O4JxBRgXQorkgDs3
         nKsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hljV0G9Mq0kOyh3efis5/zadUmTFTF1FDHXlXt63BOA=;
        b=icR4azYq/u3uAWDJPbGzG4+UeCpUo3pt97fmGdnOZiSngXMVxvzq3RoOio7RXqGIpU
         Np24vEoH+onzdSFrkSbupw+3I/Nwtli7YDQ53i0Y8sgYZP9O8TitXV06Q+1JeWofcndN
         VutXXZMVsQKtnZhg/18TZedxVwsw3Xx0VvLkt/tyw1OuaGDskFg0hIKTICvBULEksjvG
         ojnLC3I1lYKyiO1YyqHPRUhWUI+1stSPB44D1uNl9tplBSHIRfyUMRDD5+lFkBQqEUd1
         glbmTAq3fYuEzP1Ir5s8Fb76I52B/dW+7ke/rgYqTyFGSljx5nFwlu8YhbO5XUrzay0i
         RCWw==
X-Gm-Message-State: AOAM533epLwOejmpphF+lea527IrKti2WxP5CqZ61bf9VURbFJ3RSlHB
	/ei7rjezY3NFEY5+uChR5iM=
X-Google-Smtp-Source: ABdhPJzq5ZZvy6VeLZMZYvuXpQVTk0rgXAOJIg5Zb05Bii3amYPi5tlX7Z11WNY8XXv+6bhputYa/g==
X-Received: by 2002:a67:eb98:: with SMTP id e24mr7844555vso.13.1612906470421;
        Tue, 09 Feb 2021 13:34:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2f92:: with SMTP id v140ls1461756vsv.9.gmail; Tue, 09
 Feb 2021 13:34:29 -0800 (PST)
X-Received: by 2002:a67:8945:: with SMTP id l66mr15649479vsd.48.1612906469897;
        Tue, 09 Feb 2021 13:34:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612906469; cv=none;
        d=google.com; s=arc-20160816;
        b=0fKjqM4ZDTndk7AtkxafQEb4MRbG97ZAuyODSLaVt4TMkiIFHOZLm7v0F3nWZUws69
         6nXo/eh4/zd8kV+en3peJK7iYIL+miFfPXxiLPLlxN4TvR4FSAwwoN5PZEwb+atlHxS/
         /xbWsR0T5XK68hWylm3h4RChjmfFkpO6jPJ8eO8cn4QK3T8pxGb4i6AQ4UeyRtW8Pvtf
         2ipLFZG4rrG8CvTNQ7frpNksGdAmRDEXXkiqKNWK8Qey21tvodnnKi+ggglFW6P9KYXz
         mVwJAcLKzbejxWyKxdD1F8bVZGHtesKN3EYJ+B9CxFqd0czVd4DQaz+bHhDeojvbLxmT
         UK+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mYfAaU+gBcca7IuAhhFeMVoOKmdaZyZ+mleDrl99M6o=;
        b=0Iuo/4luTJbgxFl0NG0tlefoqNZb0nCzj0xaKsMlm8WV5yAW0rbQkvNuwfqYc1broV
         GUrNk0bpmwGM9WYafHpF0kUSKiuy/XF2BmgWYUG8th+hZwnivcv+qtHSlOVU9IfnEneu
         sIofEo/wbfBYGEl1d8JulAq1QzCXefQGhsrg2vtSlA89D9Y+3MiTn7Pn3U8dyLs0ptYj
         BMIK9N1B7dZPIBLpOMywqxKzFf/PjELEOyL20KRW0yKOVF/EqP83siJFfHONoc9sht8E
         SiDCsgcWSBTJqyQhBkBxXCU/+GCqnCYHmNPM7bzDXNH9aNq8v1uG1xeHKfFnS2CvDYii
         3sCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uMWC68Ks;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32a.google.com (mail-ot1-x32a.google.com. [2607:f8b0:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id j25si4418vsq.2.2021.02.09.13.34.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Feb 2021 13:34:29 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) client-ip=2607:f8b0:4864:20::32a;
Received: by mail-ot1-x32a.google.com with SMTP id r21so10385669otk.13
        for <kasan-dev@googlegroups.com>; Tue, 09 Feb 2021 13:34:29 -0800 (PST)
X-Received: by 2002:a9d:7a54:: with SMTP id z20mr11279517otm.233.1612906469227;
 Tue, 09 Feb 2021 13:34:29 -0800 (PST)
MIME-Version: 1.0
References: <20210209151329.3459690-1-elver@google.com> <4f39ad95-a773-acc6-dd9e-cb04f897ca16@suse.cz>
In-Reply-To: <4f39ad95-a773-acc6-dd9e-cb04f897ca16@suse.cz>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 9 Feb 2021 22:34:17 +0100
Message-ID: <CANpmjNOXjwiZpfzhi0Zu-gdQmwiK4dMiAE0ZhRcOnZaw00DaVA@mail.gmail.com>
Subject: Re: [PATCH mm] kfence: make reporting sensitive information configurable
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>, Jann Horn <jannh@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Timur Tabi <timur@kernel.org>, Petr Mladek <pmladek@suse.cz>, Kees Cook <keescook@chromium.org>, 
	Steven Rostedt <rostedt@goodmis.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uMWC68Ks;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as
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

On Tue, 9 Feb 2021 at 19:06, Vlastimil Babka <vbabka@suse.cz> wrote:
> On 2/9/21 4:13 PM, Marco Elver wrote:
> > We cannot rely on CONFIG_DEBUG_KERNEL to decide if we're running a
> > "debug kernel" where we can safely show potentially sensitive
> > information in the kernel log.
> >
> > Therefore, add the option CONFIG_KFENCE_REPORT_SENSITIVE to decide if we
> > should add potentially sensitive information to KFENCE reports. The
> > default behaviour remains unchanged.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
>
> Hi,
>
> could we drop this kconfig approach in favour of the boot option proposed here?
> [1] Just do the prints with %p unconditionally and the boot option takes care of
> it? Also Linus mentioned dislike of controlling potential memory leak to be a
> config option [2]
>
> Thanks,
> Vlastimil
>
> [1] https://lore.kernel.org/linux-mm/20210202213633.755469-1-timur@kernel.org/
> [2]
> https://lore.kernel.org/linux-mm/CAHk-=wgaK4cz=K-JB4p-KPXBV73m9bja2w1W1Lr3iu8+NEPk7A@mail.gmail.com/

Is the patch at [1] already in -next? If not I'll wait until it is,
because otherwise KFENCE reports will be pretty useless.

I think it is reasonable to switch to '%p' once we have the boot
option, but doing so while we do not yet have the option doesn't work
for us. We can potentially drop this patch if the boot option patch
will make it into mainline soon. Otherwise my preference would be to
take this patch and revert it with the switch to '%p' when the boot
option has landed.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOXjwiZpfzhi0Zu-gdQmwiK4dMiAE0ZhRcOnZaw00DaVA%40mail.gmail.com.
