Return-Path: <kasan-dev+bncBDK3TPOVRULBBHEJRXZAKGQE57AFRWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 706DE159DE1
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 01:19:40 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id y8sf244271edv.4
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 16:19:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581466780; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z9n5aI3mM1FCWyv6gfIdGar30CMB6irmL8+6MOYOE2X5JT23d1SkytZGpg6z0g+0q1
         R5otsZj2Hs1rCoOgab4ldp/bPsDtJPhtqbzryhX92MJwsnvX04PcK/tkGoSuuScAWQa8
         u0Ef+qTyfiP6phhh+g61brTUBth2oZE/cMUVvPX844lZEDiMqGVlhY8AKwMOAAvd23Oi
         +JaqKuYzPMaoUHh2dMTi7jTmLzL+PWPTuJ+0fLfstmSdHOb5mNEKz42S/0jfW9LdFeEx
         pNS6GhHL+gyYTL9W9aeCK7ikFPcx1smSAuTqdDjrdDnLxyMLPZ5dL0ssBw0SbVEWFEKu
         53rA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=MmqsUK4TWL+2H03Mc0fPFw5GeMsfD+oADEbPhpnUoMw=;
        b=mA7z8x+LQVUDD8kcRAgV7WYGRIGcn1G9nOce1XU/fCaEH9op0klmfiwcEXSuy/HQhN
         ogqq46EUMRCrCGI+0KGyrysCn8SNX1ASREWzekJsLjLFb0g03nsMwMaxGLLlPo+q8pN4
         JBHcptaPCIuj6jnSjMUYJeqtwj6rnK5x3oBaUu/0bK1dslJvxxeufL/KFliAtAypp3Ke
         19Xm1u/2USGYgZ6oEaiHCqYwJqb9MKJq9f+zW4c5fLoflkfkxl0PP415BMUSsseglg3/
         K/Pl5eyj1s8tuXRCkEwLIN+1M2LRaO59ternp31+srEf2IHjuzGGwjL1FFMOO+GE292V
         uG9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GJMJjn1w;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MmqsUK4TWL+2H03Mc0fPFw5GeMsfD+oADEbPhpnUoMw=;
        b=bTig/HAX2elWoIQjJsPLG7q1kiLvXEsemd64Ogiv+I8YK3v0l4bDLNrKW7XmGPM5jw
         lRP1lb+FiNlhvETJ5rPWvX5q11SfMD+VsD5JWNKc+cJOatb1ISzovrsVlRSj72DC8MKn
         86+5CLYJvLGZduNpXlHbdONGsb/s+Nj5IOT65oiSXqP0Llmu2eIp4aKqw4ddbjWycH4h
         qkfowCOGzpG9bT+Xz4vaatu17t+G6Fd0Jh1/uiYct7ndTdrn6axmI+60NplNaLQOFLgv
         oI0JUgmSpcRPFFbys2R9hqjtOJx86fGy/4UvUYyH7yWDq/Yg1yHtDl3C6ymk7Hq58b+c
         S0GQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MmqsUK4TWL+2H03Mc0fPFw5GeMsfD+oADEbPhpnUoMw=;
        b=lDc7DBV9dJ7DCo9pNjNlBpjrHwiHWXwSIscoIXGqxBsEISbPAw7uRXaCu0KyYr8aGJ
         YHQVheUnQlehfwT/a1yw/BcACIlFpSwl6jLZANWnDVjkjD2FmidKFpKrSw+vEmivc3eD
         0iKempWelL4IFFuk9lMcpo/Gzg9Gt66Iz/WsovaBcqQtlaFg5pRSkfYPwIeN/jXcTwAz
         IFnkABgqCddk8TK0biA7SqnwK0zgjJuuezlAYYPwppPWjzZHabTK1pKNMvYk0jCLfhKY
         1Bz5ujHkLYy9DBkqHZLsFVMedGFZD0AgY+bdsdHAz9lOOKGPGYl7qOk6KsV+i/YVfEDK
         Mwxw==
X-Gm-Message-State: APjAAAXcX8vy8V3NDuZYoCPXFPFzf4/+W4qX2rNQHzy/JTFcJkQtIlCz
	bzSTxJPnPz2FYgb5hNmMazQ=
X-Google-Smtp-Source: APXvYqzg62mC+DlbMU+OWlMxFZyyNtTViJeUwygagciqEi62TCI5PuOsGbVAnW/WgXJamsnIC9QPCA==
X-Received: by 2002:a17:906:f194:: with SMTP id gs20mr8340470ejb.89.1581466780161;
        Tue, 11 Feb 2020 16:19:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:385:: with SMTP id ss5ls7863734ejb.7.gmail; Tue, 11
 Feb 2020 16:19:39 -0800 (PST)
X-Received: by 2002:a17:907:10d7:: with SMTP id rv23mr8524105ejb.38.1581466779634;
        Tue, 11 Feb 2020 16:19:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581466779; cv=none;
        d=google.com; s=arc-20160816;
        b=By1Y3jN5juombgHplaacbf+VtXRECqSjNYI6ArEbz9XZeK8m+9ILgGH5g6YBWLQbuT
         H3P8AeQ3kBOvcD482iMHeV20d63NN3Kc2b1unTjRIP+gIdQaQixq/V65mp/mSwD3LlSK
         0PmNg4/G48QacUymeFoxF0iDSzQXnthXDPWsbusrMQpTNyaspgFiEtoPE/FZu4vASWcR
         ha8DW+U60r2gLJ5vsYiGFaEj1Meo9gYoQrTtegrV/R3bC1l33tKx0zo8KJja8kdyklFg
         qybZBm8v/rgKn9c+PbfgLD36zNjCeiS6unX8LFQvKYG+NTq3X0od3cmvVmwpXy3c9KR1
         eKRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kG/6VjOjLVBRMvHNzqFl1V+mWBZNEq0jfxDNEBO+YCw=;
        b=jWmb7OtNlTsP2eQapgGwJC0wuYkyxJX9pDLKqGk2A3A/hW3ue60FycBjhK5LLxz6+p
         AJdI7vGMer+AQsS8lxESVHJPudLSnPu5eonXab1VcxDELAbFZ4sxfSNEx5RFhkZJLtgU
         f49tkkrkfUmNOe6KuipN1Ou69QZBs81kjcv4oiu/82oOfTyymTBB/JuBIuNgD2F3I8v4
         lrafKBcDgbw3+sP5doyLodQmjHZytSxoFssVrv3a4NmPKMfEk/9AszaNEOiy+Ct+LaNx
         6tP6TCuJ/1uNpP/pSEYV7kmgBM0gH6gbqgDOZ3DzFJjg2YtWl0JOR1z8wzdqP99Q23uP
         kcWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GJMJjn1w;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id df10si304341edb.1.2020.02.11.16.19.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Feb 2020 16:19:39 -0800 (PST)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id g3so14099wrs.12
        for <kasan-dev@googlegroups.com>; Tue, 11 Feb 2020 16:19:39 -0800 (PST)
X-Received: by 2002:adf:81e3:: with SMTP id 90mr10885572wra.23.1581466779084;
 Tue, 11 Feb 2020 16:19:39 -0800 (PST)
MIME-Version: 1.0
References: <20200115182816.33892-1-trishalfonso@google.com> <CACT4Y+b4+5PQvUeeHi=3g0my0WbaRaNEWY3P-MOVJXYSO7U5aA@mail.gmail.com>
In-Reply-To: <CACT4Y+b4+5PQvUeeHi=3g0my0WbaRaNEWY3P-MOVJXYSO7U5aA@mail.gmail.com>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Feb 2020 16:19:27 -0800
Message-ID: <CAKFsvU+zaY6B_+g=UTpOddKXXgVaKWxH3c8nw6GSLceb1Mg2qA@mail.gmail.com>
Subject: Re: [RFC PATCH] UML: add support for KASAN under x86_64
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, David Gow <davidgow@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, linux-um@lists.infradead.org, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GJMJjn1w;       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::444
 as permitted sender) smtp.mailfrom=trishalfonso@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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

On Thu, Jan 16, 2020 at 12:53 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> > +void kasan_init(void)
> > +{
> > +       kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
> > +
> > +       // unpoison the kernel text which is form uml_physmem -> uml_reserved
> > +       kasan_unpoison_shadow((void *)uml_physmem, physmem_size);
> > +
> > +       // unpoison the vmalloc region, which is start_vm -> end_vm
> > +       kasan_unpoison_shadow((void *)start_vm, (end_vm - start_vm + 1));
> > +
> > +       init_task.kasan_depth = 0;
> > +       pr_info("KernelAddressSanitizer initialized\n");
> > +}
>
> Was this tested with stack instrumentation? Stack instrumentation
> changes what shadow is being read/written and when. We don't need to
> get it working right now, but if it does not work it would be nice to
> restrict the setting and leave some comment traces for future
> generations.
If you are referring to KASAN_STACK_ENABLE, I just tested it and it
seems to work fine.

-- 
Patricia Alfonso

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvU%2BzaY6B_%2Bg%3DUTpOddKXXgVaKWxH3c8nw6GSLceb1Mg2qA%40mail.gmail.com.
