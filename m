Return-Path: <kasan-dev+bncBDK3TPOVRULBB3XWSHZAKGQEZ47VM6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 16B5215B3A0
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 23:25:51 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id a11sf520314lff.12
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 14:25:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581546350; cv=pass;
        d=google.com; s=arc-20160816;
        b=vlEEYwblaw6oN6f65wCpVvr2D1nuM3USfxh+Q4LDFQqay/UvlBwvjZHY4ouCKpPEcX
         OPXS/Ijts+WXYwy+hoGBqJPYy+5yGNENleyCeG9C4pp5Bqy3hClvTWjy2bnMosbDCz7g
         N8cGDnr1m8jSUH4XyiyZp7WZJnyTrd1tt49GENsNfxOf/8ZwYvbWxfBTZJKynDkt3xVl
         1wMMBg+/8Tssax7U2ypPwlvlIf7IXNKFR25SFZqyoW+JPA4VbY0ye+b+jsdhOGA856bm
         7ODpsbWEglB64UFqETIUs89zlx1bpIAd9SSG/uCtDL/gdBvEU8u9TpG1Jbiw7BkOg/Iz
         hZ9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Yoc35syzHGQ0ONaUafLtkphFQVXhQHHWetPMEKtyK0A=;
        b=PScU43pTLOYw5t4YWvO+htRa26XzSYJ/XVesbsjetVJWrIMR5xSJxTIiUNGjhP2iT+
         ZHhYDNbPv9C8WTb55BklIjuVIJNmWhkOhAX3lXCNtPO0AVNpwsKNXrma+23XhYYlkbWd
         7dSPcbpy3VAsW/kqhIt7rKdmnRqkiTh536BgwqoMRkG6X+s5Y8KwH1YRuRYqB+T1p83x
         H0pO6jry5MiI8V57cVczrINV+AKPNr9LkGZbvmuuhHP1h+23ncEQVZ0nD/shU2Esktwu
         5biq0lvNw7e8namLUPoNPZK6pdqKo4ViaNMtXj10fcuowy/1mkidmVIOd3JVODczvieS
         mkuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=U76D1PMA;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Yoc35syzHGQ0ONaUafLtkphFQVXhQHHWetPMEKtyK0A=;
        b=TxgClJmKzyD17GG7sjVDTn7xoc++PtUaSUKq28XKONUU/5q8c4It5t9iXvC4nwzgfG
         nEAOj6xa6ENYvY7pkOGOIFt4FJK5yhRfZp6P5CCYeci7pIwgFsYKDvN/oN3wQLsNE7hP
         8CXVDGRTQfhVvDM997EkYsCax0MqR2t5SDtim37UGOQanA2D2yRl0jmn5z0DNkMSEnd+
         7Seujq9eOMMk8B7LTI+z1b8JG6t7st+JQd8jfS3m8mCXD1Q0oUgLAdHaUxF6jdxMdA/O
         i+IHM4b1ybv+BD6MmQQIISD34Y1w8zqIz+JWUCpsZtF3PdRFnZOzlQuqab1nOrYyWboE
         zC7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Yoc35syzHGQ0ONaUafLtkphFQVXhQHHWetPMEKtyK0A=;
        b=Ae4JYgYDQMyWKnfvvCB/vLPnoEZafgQ5XrbaYlWPyxGEdTlonOHsa5lBffte3sUqax
         uYsHdSgfODmRlHHTvV9FDcQeynivedtGYFR6F/RTd8YdwtQ8NOnlNwmOnXQLibo7bruO
         q3VDXaRPskNg59+qHlX2vCoQ4gSiTpg56nkalWQITerEuVFRbHyS/gaEbzumWojRr7jU
         ECwaBv9eGeXVuhWP83WGFyRvPCoUKcrUCzA03uJynd1bjaHmxXinso0Y1RXaEjV4PNLG
         cSTv5xE67vI50ZGbSVQYhIL3N/sFkOq9LsHurNF99K7RTXNAr7ows65OKQKX99OsEbMc
         f8Rw==
X-Gm-Message-State: APjAAAVx2a1pkkCzCc2hNhZB4oOEyWwtEI2jn/CXLDw9FJQhgHTiAucI
	hvd1UlbLUUkgLzFHfYb2wAk=
X-Google-Smtp-Source: APXvYqzJcki2E0sDEunyHQXDHDl+r55sfI9KIBt4KCXqlwIpwI7VEfXOz85wQAfFxg5/I+XAwH71Cg==
X-Received: by 2002:a2e:b536:: with SMTP id z22mr8822631ljm.259.1581546350456;
        Wed, 12 Feb 2020 14:25:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7309:: with SMTP id o9ls3713349ljc.11.gmail; Wed, 12 Feb
 2020 14:25:49 -0800 (PST)
X-Received: by 2002:a2e:884d:: with SMTP id z13mr9152284ljj.116.1581546349906;
        Wed, 12 Feb 2020 14:25:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581546349; cv=none;
        d=google.com; s=arc-20160816;
        b=Tb+b0bFkdn8ZGO8aiI3120OSZnWYj9TnGjox6AEZpRQUfRfsAxtSGwCDjnu8YiK9qD
         DOmOzHNLnkP+rOU30w0Tl8qnwKtdz91wqBHzLdFwn1MUGk8QPKp5iCNYucH6z+3brZ5F
         qMp2w04a2NNULSZ4wze9iOKYeR3IBw/mVoTGiTUyvKukxZMpQt/KTL4yOFfIK1y+JJ4K
         2iUVv/RIGeNvIXOWGuqvCPC9UeSyZ6xbzPE1rJguGHjPM1Yxv33HyoaGyVGKsQTNP41V
         u3+LUSDzGgfnBWRJmf776zledB9z5jMFxZiSQrmVNWaVO+NtnS/PjwucaWSxYqGZPM2U
         AZwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kqLUL5r8C+tgnaPYz9HWPNgipcce1YW5/q3ifbXu5oA=;
        b=J3RwwZqvImdCuH8nkNyAUu/Ecp/enhltutb88bSOAArjR16I+DsKefM1JZnuJzjRa8
         zJmPF8fiYck3hh41drJ59lhhZyFhXykn6xopGlTQC0x7wAf2Vh7z7tv960+7nBkIx86M
         4Ah6aeTsgwuRX+PNah0gQ4rkwf8q7hAIxbMt7XIcuC30nyhq/MNo6h+judbf+o8H8MM3
         7ogXNQl9Bf6IjUILprdP0rMFntbE+/DarVgSbf/wdSpeV7zChuCITAjJ1Uam64Yah1Du
         uAWpkGqES0WZG+j8Sj0kEYIX0J5wa9bzL42mYD82HP87s58Pcrq8cX9wQqbe0bJ+C1GJ
         CbBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=U76D1PMA;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id p12si19199lji.1.2020.02.12.14.25.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2020 14:25:49 -0800 (PST)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id w12so4329728wrt.2
        for <kasan-dev@googlegroups.com>; Wed, 12 Feb 2020 14:25:49 -0800 (PST)
X-Received: by 2002:adf:81e3:: with SMTP id 90mr16580061wra.23.1581546349050;
 Wed, 12 Feb 2020 14:25:49 -0800 (PST)
MIME-Version: 1.0
References: <20200115182816.33892-1-trishalfonso@google.com>
 <CACT4Y+b4+5PQvUeeHi=3g0my0WbaRaNEWY3P-MOVJXYSO7U5aA@mail.gmail.com>
 <CAKFsvU+zaY6B_+g=UTpOddKXXgVaKWxH3c8nw6GSLceb1Mg2qA@mail.gmail.com> <CACT4Y+aHRiR_7hiRE0DmaCQV2NzaqL0-kbMoVPJU=5-pcOBxJA@mail.gmail.com>
In-Reply-To: <CACT4Y+aHRiR_7hiRE0DmaCQV2NzaqL0-kbMoVPJU=5-pcOBxJA@mail.gmail.com>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 12 Feb 2020 14:25:37 -0800
Message-ID: <CAKFsvUJ2w=re_-q5PTV8c30aVwot8zMOipRvhD9cCx-9cc-Ksw@mail.gmail.com>
Subject: Re: [RFC PATCH] UML: add support for KASAN under x86_64
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, David Gow <davidgow@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, linux-um@lists.infradead.org, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=U76D1PMA;       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::441
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

On Tue, Feb 11, 2020 at 10:24 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Wed, Feb 12, 2020 at 1:19 AM Patricia Alfonso
> <trishalfonso@google.com> wrote:
> >
> > On Thu, Jan 16, 2020 at 12:53 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> > >
> > > > +void kasan_init(void)
> > > > +{
> > > > +       kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
> > > > +
> > > > +       // unpoison the kernel text which is form uml_physmem -> uml_reserved
> > > > +       kasan_unpoison_shadow((void *)uml_physmem, physmem_size);
> > > > +
> > > > +       // unpoison the vmalloc region, which is start_vm -> end_vm
> > > > +       kasan_unpoison_shadow((void *)start_vm, (end_vm - start_vm + 1));
> > > > +
> > > > +       init_task.kasan_depth = 0;
> > > > +       pr_info("KernelAddressSanitizer initialized\n");
> > > > +}
> > >
> > > Was this tested with stack instrumentation? Stack instrumentation
> > > changes what shadow is being read/written and when. We don't need to
> > > get it working right now, but if it does not work it would be nice to
> > > restrict the setting and leave some comment traces for future
> > > generations.
> > If you are referring to KASAN_STACK_ENABLE, I just tested it and it
> > seems to work fine.
>
>
> I mean stack instrumentation which is enabled with CONFIG_KASAN_STACK.

I believe I was testing with CONFIG_KASAN_STACK set to 1 since that is
the default value when compiling with GCC.The syscall_stub_data error
disappears when the value of CONFIG_KASAN_STACK is 0, though.


-- 
Patricia Alfonso

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvUJ2w%3Dre_-q5PTV8c30aVwot8zMOipRvhD9cCx-9cc-Ksw%40mail.gmail.com.
