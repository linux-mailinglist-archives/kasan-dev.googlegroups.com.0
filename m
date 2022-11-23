Return-Path: <kasan-dev+bncBDH7RNXZVMORBU7P6WNQMGQEI2OG2DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id BBF74634CF1
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Nov 2022 02:31:00 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id q6-20020a056e020c2600b00302664fc72csf11942121ilg.14
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Nov 2022 17:31:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669167059; cv=pass;
        d=google.com; s=arc-20160816;
        b=KyfasFVLoOD8mRnvIDrfJ7sp/1WfN7NxKWUewxwSvJ6Zfw9a9rpcJNukh7zEAGzkby
         srMeT6pr2nO4y1KZy3m6I+R/CFxcdMrO2VDREiWzqkHnHXVprbgqeed34y3fQq4xyakn
         fm5IJfHdKnNhbIkrtyx6hPJr7h82pU+BSQoQs/MbqprljinX8qN33y6PXJcglIGtL9Nt
         IAk4pQ9PbdlwK5IiCwTEonmxd1kj5c7E3CA5xGAdmp23/PEL7YieCuLi5fntLpDxQRg/
         FPm1clh7444cBe3QGeS9WPSX34T28tgBFpmKLHKoKFGI6vbUlsdbummjNatFucW7xOix
         NCSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :message-id:in-reply-to:subject:cc:to:from:date:dkim-signature;
        bh=Y7yRb3huVpQGZs74hVB08nKMpci98pQGXBwaYp8D1gA=;
        b=nYGh0Bj9oHWSmWAz8piF41ORE0YJioXDixK9twFkvYSsod0cIeKBdEPLm9X5cbtEA3
         31FB7+B2eepyrGiA5V02dkaej2hBq8a7Ikmqcd6icpAavJkhzD3JqLF+mGulqAC07vP5
         +ImPvIU2QOXHBwmiXHOdU13GDgK3quQ7murLAIlWYLAz8zZNYBqiybjvHte3TjmrTM9O
         26aYF4wh9Rx39nK8Y7Qz8W8Gs0Oo20aAHrPVBTlrffXvBKLXypAJY+U1TBcuPu/Vzy+m
         UKvh3DqcIHekj2akE6F8hikA3GYLmq0u+bu/dlNBV9c9W2MTRfio5UctqNjZFKreGLKU
         fBpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NXD0++W1;
       spf=pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=rientjes@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Y7yRb3huVpQGZs74hVB08nKMpci98pQGXBwaYp8D1gA=;
        b=NpPYPhrRUs+OwNCHDou2LkjygemwgqXV0jQWYN9aABjvDFedIMpc0ERorQ8I5uSbTH
         SueBn5S5WtzkVsM8mXEl7jCma9bH2KW5wT5mDUccvPDu52+FVhnwso6plXWE88rAxk7f
         8VVYz7iEw2dcM9cFUhZVy9A5AaPD6IZVaxtRLA2BRLS7gWYFIr+CG3lu0xDyHBydE576
         Q/lj4lyO/ee73lN7DC2mvEjVBZogi0Tgn2ynPwWVM6D6xmJ1n4AQLS8cCI72qtFo1FhS
         LidwVJGKwfXEoAaDzoDcYMkMNsGSNT1gvIUOd6mDz6kB2l7x6adPhsQRnchwXNa/Fyqv
         snRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Y7yRb3huVpQGZs74hVB08nKMpci98pQGXBwaYp8D1gA=;
        b=09HMZOzuvit8p8MhIXfgJPWi+z9L5O6oaOZvLbSTqkEUH/AayuvLnhkxexuQJLQNnk
         nGVJtk0st4LCEsCOaioLCwslODsVPhN+9NdmUE3L5o0FgG2xHlmvrbo68YJlA/ysSXXR
         XK6VJM7cBVMULdXtVdAS+eSqJXEoi8clDzVQKcfvZLE4ZURAmwBFN4oMeUg7klyefvX7
         I4BWt8WZj9WcUenuKsEcBH19mhgbclA7jdqwztUx0xev83i6SAjz77fzDOuHNKwa2DmX
         oZJ7h5ONTa3PBWfcakMjaz8crRkkZBdBnQCP9eM9Dln5hQc0qOD9SN+iy/Cn7BIe55Q8
         A+ow==
X-Gm-Message-State: ANoB5pm1LiAqJhBBueHSuhQLIlyid5+lYa7XL/uGE40F7gBNI3Tapk/z
	BkDdZnU81f4qe/pWAZABu5w=
X-Google-Smtp-Source: AA0mqf7zswY1fohf7yQVrY1r8K6E5jJxU/kQ9oi5lK6zrJkHThwwp0eEO3Vq8c8ysEFKlEISqF8nLg==
X-Received: by 2002:a05:6e02:10d0:b0:302:bb08:3c22 with SMTP id s16-20020a056e0210d000b00302bb083c22mr7102767ilj.147.1669167059264;
        Tue, 22 Nov 2022 17:30:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:418a:b0:6dd:cccc:38f9 with SMTP id
 bx10-20020a056602418a00b006ddcccc38f9ls1832569iob.3.-pod-prod-gmail; Tue, 22
 Nov 2022 17:30:58 -0800 (PST)
X-Received: by 2002:a05:6602:736:b0:6bc:b2ee:a61e with SMTP id g22-20020a056602073600b006bcb2eea61emr3115464iox.195.1669167058769;
        Tue, 22 Nov 2022 17:30:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669167058; cv=none;
        d=google.com; s=arc-20160816;
        b=yqzDI2BK1k6U73FgqPHLFYrt1w6FVg8oLiOvBKJDSOW/kjFhDdTphW7lZwXC27bnI7
         6RZJgTRRELh55fYFyH6sHU8jD2WUM5sLPKYetCob8YXfvLcnN8fVWszmL6FyAUOeSwAJ
         s2iQ1jSjWcYPBGCmYReBXJwqMkoEeQbOff/0vByggPp51dQY7hpF7EvzG6kH7N3N2D5D
         jluA1Lq302p6bDNnDSVnCxXbEMpTFie2zFJRF6zcI+uHz96059Go78LmZ39FEIeSAXga
         T/mUP6Xep1PFF8fkJybK3NmrvJktGntI7wLshnQSpxiqC62bEVKRJsYtupK5atmHwfJV
         6aFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:message-id:in-reply-to:subject:cc:to:from
         :date:dkim-signature;
        bh=DKO5lR4cLz6p7NWkfnd0y6rPCWBH2+knxhaYnv/yN7g=;
        b=tBd1vGWwvO9WkLbUqQsnddSPx4BpkzKU5/2nR0fU8OdOY27fr684ixK7GIn/3MsPHM
         bvfVInsgOr3qn65jQRqorE8z9v4BeIo28ihmQm6i3lNnf3zIKwzn8uFA/8HlmlZglWqB
         VBNZ9kcyMD9Z7jKQGJKPk2CuJSDyBjt2DjtPIa0pGC/rn31jvcr4Ynh1Lr2pj4eM0INJ
         i/j9H9/cXe8Bc9remk5UDAWB3fIBuJc5RdRbFUC9HN/GvRsiivpX4Hf2HFzsKoT5mKt9
         aeCx/6dzgRiyTZxS9BEPw+Ia62HR+V3L5A5e8h4Utn80s9RLiUZ5+7JTKS6d1ua8slda
         hKxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NXD0++W1;
       spf=pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=rientjes@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x531.google.com (mail-pg1-x531.google.com. [2607:f8b0:4864:20::531])
        by gmr-mx.google.com with ESMTPS id z18-20020a02ceb2000000b0037556a5e914si936306jaq.4.2022.11.22.17.30.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Nov 2022 17:30:58 -0800 (PST)
Received-SPF: pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::531 as permitted sender) client-ip=2607:f8b0:4864:20::531;
Received: by mail-pg1-x531.google.com with SMTP id f3so15547924pgc.2
        for <kasan-dev@googlegroups.com>; Tue, 22 Nov 2022 17:30:58 -0800 (PST)
X-Received: by 2002:a05:6a00:1a14:b0:572:5be2:505b with SMTP id g20-20020a056a001a1400b005725be2505bmr6959442pfv.52.1669167058288;
        Tue, 22 Nov 2022 17:30:58 -0800 (PST)
Received: from [2620:15c:29:203:2520:fc16:115d:2f43] ([2620:15c:29:203:2520:fc16:115d:2f43])
        by smtp.gmail.com with ESMTPSA id r8-20020a170902be0800b00176e6f553efsm12647970pls.84.2022.11.22.17.30.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 22 Nov 2022 17:30:57 -0800 (PST)
Date: Tue, 22 Nov 2022 17:30:57 -0800 (PST)
From: "'David Rientjes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <keescook@chromium.org>
cc: Andrey Konovalov <andreyknvl@gmail.com>, Christoph Lameter <cl@linux.com>, 
    Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
    Andrew Morton <akpm@linux-foundation.org>, 
    Roman Gushchin <roman.gushchin@linux.dev>, 
    Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
    Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
    Alexander Potapenko <glider@google.com>, 
    Dmitry Vyukov <dvyukov@google.com>, 
    Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-mm@kvack.org, 
    kasan-dev@googlegroups.com, Vlastimil Babka <vbabka@suse.cz>, 
    linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH v2] mm: Make ksize() a reporting-only function
In-Reply-To: <20221118035656.gonna.698-kees@kernel.org>
Message-ID: <d49df494-7c42-1d2a-97c8-62972c0d6c03@google.com>
References: <20221118035656.gonna.698-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rientjes@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=NXD0++W1;       spf=pass
 (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::531
 as permitted sender) smtp.mailfrom=rientjes@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Rientjes <rientjes@google.com>
Reply-To: David Rientjes <rientjes@google.com>
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

On Thu, 17 Nov 2022, Kees Cook wrote:

> With all "silently resizing" callers of ksize() refactored, remove the
> logic in ksize() that would allow it to be used to effectively change
> the size of an allocation (bypassing __alloc_size hints, etc). Users
> wanting this feature need to either use kmalloc_size_roundup() before an
> allocation, or use krealloc() directly.
> 
> For kfree_sensitive(), move the unpoisoning logic inline. Replace the
> some of the partially open-coded ksize() in __do_krealloc with ksize()
> now that it doesn't perform unpoisoning.
> 
> Adjust the KUnit tests to match the new ksize() behavior.
> 
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Christoph Lameter <cl@linux.com>
> Cc: Pekka Enberg <penberg@kernel.org>
> Cc: David Rientjes <rientjes@google.com>
> Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Roman Gushchin <roman.gushchin@linux.dev>
> Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Cc: linux-mm@kvack.org
> Cc: kasan-dev@googlegroups.com
> Acked-by: Vlastimil Babka <vbabka@suse.cz>
> Signed-off-by: Kees Cook <keescook@chromium.org>

Acked-by: David Rientjes <rientjes@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d49df494-7c42-1d2a-97c8-62972c0d6c03%40google.com.
