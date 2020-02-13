Return-Path: <kasan-dev+bncBCMIZB7QWENRBM6CSPZAKGQEO6SOBMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6CF0B15B91E
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2020 06:40:04 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id v15sf3490969iol.10
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 21:40:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581572403; cv=pass;
        d=google.com; s=arc-20160816;
        b=MnB3mV7vXlTufioVARF2Nvp/4JTT6BIuEu0iV7jRVTXk+dYcpiq+MHKbL32usWoJPl
         Wif/y/iHscBkZXjmYFgI7AMI83aCBNwJItUPpXe+XF9y4+yakBaH65wCaiOq7KA4xO3C
         q52V+5GXIvJ219tNJ2dcFFe/R9Qf/gnYaw+NH3Dq86XHwLW9975RrSfIvihf+zGL76GV
         SJU0kCve8y4LsbasfL7P/yk3Y1cXvzU9o2YEUpPXXUDoe57FaBJW/XyBdQCPOdm4ERZY
         LE42fG2fStxQ3/78VMAu9uBtpXXhQXhy+hMIem6kMYhmfbI3j/Psr/c0iZLX/8WOqUPy
         ssLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Uz3l5G+Cqu69iF5EhFyRRNAO8Q8n2/MvQMjMxAz4PXw=;
        b=EXxgOoWKNhZWIuTrpLgJ2fhlkBKVO4MtKsDqmBIWjB62lfHWHYDxlvsOg+8CSW0erL
         6T07YXy0rzn2lmKPJBcZZo5MAE9JR/iRQzujs4JxB8t/+OBHK82lPSCUx3ghMF96MAAa
         P7Vy4erBFcVrTKUnxQyxhYRtaGV46GjgSkN+irZLbDn2M6lw7fZushJwDca/IkhHXSl0
         vZQbvKRBd1/6VpmKpEI4MF1WXIJzqvcHR63Rz3oD46pCu8Xb41FkYY2Pr5xx8Jdc7tft
         My3WqBPszbIYTd/KwLenQE1QVi/7pqgV9keJ/ZIgUErkAQEseLcNDQnGx0t5JaMLOLuT
         WC9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vtBoid64;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Uz3l5G+Cqu69iF5EhFyRRNAO8Q8n2/MvQMjMxAz4PXw=;
        b=fmcyliucartMUgToEMZWvrhqwd0vWiITo3Pwzzz00SiSs98T5oCoetkl9RBe7CNDYG
         Sj3HjKlz6Bmb8LiX3N3hqVJfQb9cD3Ngj3sAnfddgaKdlf83xQPgdgUDT1uAsZR+PX6e
         +AAUZiUZH5nuIgnkK1VQqYH+mCimkAqYrSSi6m6Qk2R/oUaJzv+ZLEYfvJSBF614y7Ce
         SBEINOOfXCxILiwEplEOxuPxfjkwExmfY2s03O2/T6DK8ZYQY4C+vhGlKhprwTPcMcIh
         AJN71dRj83wLxJ4EcTtWfHNhGFIhqrwNYJDS00E0VQAH69X5X5M7gAR70Os0WvtEFH+d
         wNlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Uz3l5G+Cqu69iF5EhFyRRNAO8Q8n2/MvQMjMxAz4PXw=;
        b=m86bV7UUhHSPtrlJB99dbaQwRS2PRg83OzmT+wFZjx/HDQKyqqzdsK79861CSCWyE0
         cBU6nKECHdXa0ZXmWHLM579h43SETvX65kkxPSkDkd8/VqXXRfzGbZg3XgjZTIKRhH/5
         wwQkRbOWMGWfMKVIzppM0fVZwHPfK7p10RBmXMiV9GkkAWhaoUXtuBKbxz+zSAeD9xSl
         LFGGTItqzKuJcdE1Le+v/JgVWdZ2jD8Sgcr6zZH2hca54XHNdI9p24a31YIF3nvAxjZ7
         iW/JLAoRz/chqIYLZtJqdBqb0YZXeWzcphhj5pxlt6rI3Jkj1Bgw7naGnk8IEvzCbJzk
         FkGQ==
X-Gm-Message-State: APjAAAVzY62V5ljYIoSttZsHzxHL9xcakaENNj3oj6gfxhmt45vtDfZs
	xBMhgb0YjWr7WzZuXxdSlFM=
X-Google-Smtp-Source: APXvYqywG+FzxTXOvo/L1kl6lwRs8C2EemVPlP9VFNUt1ri6xroUPLUuyLuY7mIQ2GEkTQPuapzPJA==
X-Received: by 2002:a6b:f913:: with SMTP id j19mr19337548iog.124.1581572403404;
        Wed, 12 Feb 2020 21:40:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:cb49:: with SMTP id f9ls4358260ilq.7.gmail; Wed, 12 Feb
 2020 21:40:03 -0800 (PST)
X-Received: by 2002:a92:9603:: with SMTP id g3mr14901322ilh.231.1581572403040;
        Wed, 12 Feb 2020 21:40:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581572403; cv=none;
        d=google.com; s=arc-20160816;
        b=XLw7Yn1HmsWmc14rTfqxHTK1eNhbhczbs7KP4WJjh81LC2UaZjHHh/HLE54hMswNcI
         SCVpJEM+Bm/x1feeCYeo9oPRvSNZqBRddUt3soVWd8eV9gHHtVicl/u6z4VpvofDI3qA
         UuTYe7ixlElAIV0oWBPFz9Jbyf5qeZdMcA2eHIzOGqbmasxWEoddDlAKWZ2C71zp4cJY
         77VszRosPV6X5Cre6oEoKrY14du+l0KlUseOdZxa0Rdi8J+wa48ZVSjqw9LO6roVQFl7
         0rduJ8ncsrHlqoIO2tSp9LVhMWBpsCdy1+D+ZThNMFG4BRmUqnhNvid94xXavJZAPvkz
         Jx6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tFvB3dUHqlfWY0xdzQLpqooj9O1A8mgi9rJRJWCXmFQ=;
        b=VQL2RLUeqTuerbKNhhfbnbVCAbxe+oXl4Zvj4dlyiNi6znV0Db4XhtmrsiolnOXBMw
         YTvow1q7X/EI8vjmRXxsXyOBRFVJS4EghF6lIRjSbQ1p7m+YlqQyO6w92bufuCfhTqr+
         NNMlHWFrvowmZUDUmh8Sns2RaHtF9zVPmpg9afcL28fuU7oulzvhzoTz0dc8YZ0bVLAc
         UGhYwGSUeqiQMnRSMkuR4ciFxxdewjuZaFyObNnpUyXePjKgvbA5Vzhiz5vD79h4vccT
         xgv4gYjoCUoLJeVpqalwJHZNZ2MppHsJQvgdY8i3ZU1TvNJcdPr9dwI5kwjQTP6qb7oo
         7siA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vtBoid64;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id g12si75246iok.4.2020.02.12.21.40.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2020 21:40:03 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id v2so4600718qkj.2
        for <kasan-dev@googlegroups.com>; Wed, 12 Feb 2020 21:40:03 -0800 (PST)
X-Received: by 2002:a37:4755:: with SMTP id u82mr13737500qka.43.1581572402214;
 Wed, 12 Feb 2020 21:40:02 -0800 (PST)
MIME-Version: 1.0
References: <20200115182816.33892-1-trishalfonso@google.com>
 <CACT4Y+b4+5PQvUeeHi=3g0my0WbaRaNEWY3P-MOVJXYSO7U5aA@mail.gmail.com>
 <CAKFsvU+zaY6B_+g=UTpOddKXXgVaKWxH3c8nw6GSLceb1Mg2qA@mail.gmail.com>
 <CACT4Y+aHRiR_7hiRE0DmaCQV2NzaqL0-kbMoVPJU=5-pcOBxJA@mail.gmail.com> <CAKFsvUJ2w=re_-q5PTV8c30aVwot8zMOipRvhD9cCx-9cc-Ksw@mail.gmail.com>
In-Reply-To: <CAKFsvUJ2w=re_-q5PTV8c30aVwot8zMOipRvhD9cCx-9cc-Ksw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 13 Feb 2020 06:39:50 +0100
Message-ID: <CACT4Y+ZJeABriqRZkThVa-MNDBwe7cH=Hmq1vonNmyCTMZOu6w@mail.gmail.com>
Subject: Re: [RFC PATCH] UML: add support for KASAN under x86_64
To: Patricia Alfonso <trishalfonso@google.com>
Cc: Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, David Gow <davidgow@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, linux-um@lists.infradead.org, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vtBoid64;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
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

On Wed, Feb 12, 2020 at 11:25 PM Patricia Alfonso
<trishalfonso@google.com> wrote:
> > On Wed, Feb 12, 2020 at 1:19 AM Patricia Alfonso
> > <trishalfonso@google.com> wrote:
> > >
> > > On Thu, Jan 16, 2020 at 12:53 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > >
> > > > > +void kasan_init(void)
> > > > > +{
> > > > > +       kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
> > > > > +
> > > > > +       // unpoison the kernel text which is form uml_physmem -> uml_reserved
> > > > > +       kasan_unpoison_shadow((void *)uml_physmem, physmem_size);
> > > > > +
> > > > > +       // unpoison the vmalloc region, which is start_vm -> end_vm
> > > > > +       kasan_unpoison_shadow((void *)start_vm, (end_vm - start_vm + 1));
> > > > > +
> > > > > +       init_task.kasan_depth = 0;
> > > > > +       pr_info("KernelAddressSanitizer initialized\n");
> > > > > +}
> > > >
> > > > Was this tested with stack instrumentation? Stack instrumentation
> > > > changes what shadow is being read/written and when. We don't need to
> > > > get it working right now, but if it does not work it would be nice to
> > > > restrict the setting and leave some comment traces for future
> > > > generations.
> > > If you are referring to KASAN_STACK_ENABLE, I just tested it and it
> > > seems to work fine.
> >
> >
> > I mean stack instrumentation which is enabled with CONFIG_KASAN_STACK.
>
> I believe I was testing with CONFIG_KASAN_STACK set to 1 since that is
> the default value when compiling with GCC.The syscall_stub_data error
> disappears when the value of CONFIG_KASAN_STACK is 0, though.


Then I would either disable it for now for UML, or try to unpoision
stack or ignore accesses.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZJeABriqRZkThVa-MNDBwe7cH%3DHmq1vonNmyCTMZOu6w%40mail.gmail.com.
