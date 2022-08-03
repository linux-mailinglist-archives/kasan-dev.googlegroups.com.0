Return-Path: <kasan-dev+bncBCCMH5WKTMGRBY44VGLQMGQEG2KP7NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 667B1588A8C
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Aug 2022 12:31:01 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id c14-20020a056e020bce00b002dd1cb7ce4dsf10323453ilu.22
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Aug 2022 03:31:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659522659; cv=pass;
        d=google.com; s=arc-20160816;
        b=we2x76jHF+PMR7JEkfXFRRKDjBDTDps+EAXaW1ii+EseIo5HA5+v1joCzqZ7PG2oRr
         ADbvMz2QgUS2jVbFtYL/s7EC6Yh/Sa0T6URw8IwpQTzgd73AsyuuGHdukC6uOzbQCYt6
         Gd1nB9oFW3eZNmPiuiDRsO/flkE3HaRkqWKeIVTjv+VgtwMTz4MvGSOGx4HGXO5BRx74
         pA/8tRBknR00wm6XYlK9A6TRY0zO1F/P513Keu4ewB7EotesgoH8t6AFUwMSOk9HXB1G
         ebftPq4OB0XCSFZT4eJI9FG/Ustp6i0vfOHrcTNBXDjU7JokMkYz88XHSEz8vgbm0rzd
         MZ2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=p6jRRe/eQ1nLQu75ZzvVAVfWjOU1jzMk2eHQ2D9U7fM=;
        b=fafPdO0ZVr60qp3h7nUgzyQ6YZ8KI98r7Dt70iFperqEzk4Onrp1DFS2wKTDDuRTVe
         Mpt2+9k1YzhxPfLTQ21JLqxZSEnJPavjpGtsY7ZY01lLoLTi5A6U8W3Gu71X1FqQHmhQ
         We/m5Kqc4PUrtR3ZMfenLabuOihGzkYDX1za78OG1Rly2uzBuVatTL6GQAlJRJzLORNC
         5I9VBh9iyxjDeLJeakz3PivQC0BgepC9i5PpWnOCdeIeIIGQL2IBfV6Dg8SZ0u4AQj+X
         h2wWet4hKnmw59/n+K4yYy/KKgTVEGHd7MhXh8qtsNYkr+qpTDSEhIwB14HSdzBmDzoh
         1bRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bTMMrVHL;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=p6jRRe/eQ1nLQu75ZzvVAVfWjOU1jzMk2eHQ2D9U7fM=;
        b=OjbRAgir8RSxNxAMmORNl2/N8eAcue+GFmmpS2ECljMiSlGr1daBcSUx9BNY+FjEmu
         KwZIR5vPY7Odp1+GVk53cffseEsPFkWC7jrlMrpJC6X0OIvV5nCX2iVsdOhSuIh+KWZp
         F1rYtFsu6HxHDlB5V+2ZxCnax1nnpvQBSxyliBYv+DF5r/EVVQZR6PUOLpNrw+0K3sx7
         G+gGmTSF56AVBCxIjqIy1BLyf4+98M21/ZHAjvsBG3E23cSQPxo7O2+b4lxL25z0RvuZ
         we0uCWzVgCI2IrAWuMCwEJKTaescfm3CVjfFFjuhAd84CjN56JmvwFF5e6Z8ukZazgQv
         rlOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=p6jRRe/eQ1nLQu75ZzvVAVfWjOU1jzMk2eHQ2D9U7fM=;
        b=TwDVCu11UkIhJFZWUjZxLgyVZAV5fUgx2PS+EnijtAO2X81QaXdWSKQ1eyuVBhdl1T
         mjcLax8nASj/9YqsIqlHxBRh6jgdRZ/pnUL2jBJ/c8haOrGszfBhGLP0SusOwhhtKkIS
         KsjEopI3LdPbGZPsyE9+By9d4exZazwydNYIfBd2eWKExBPFaGK8t5GJNtLzAYmMfNEw
         hPwIgIaonbys+6F/xluZZuufx3hlGTNX+n98GwSn2RmeHd/rlUrVXUT1d8GCSwlwmvzh
         lKaS2WD9d9uQYTdhYkW7FvCSa0mnWqtUzfV+kPpSZ18p/wD1VufLWkd9EcDyIhtGp+lh
         JQWA==
X-Gm-Message-State: AJIora8u4ht32JY+aTlY4zNEn5Ht2kAzcvfRf4wlMF2f2AGGdpbCSq81
	njtBulVHgYXXDI0zk65kDCs=
X-Google-Smtp-Source: AGRyM1uAn7T/fPVDIPNBVIDULOYQTLMQK5t04+yacqe6fi2numWFheWFmiwu5DGBA23xVsMnOUd6pQ==
X-Received: by 2002:a05:6638:38a4:b0:33f:74b8:ede4 with SMTP id b36-20020a05663838a400b0033f74b8ede4mr10107894jav.276.1659522659703;
        Wed, 03 Aug 2022 03:30:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:c30f:0:b0:678:7dec:344c with SMTP id a15-20020a5ec30f000000b006787dec344cls1645074iok.3.-pod-prod-gmail;
 Wed, 03 Aug 2022 03:30:58 -0700 (PDT)
X-Received: by 2002:a5e:da03:0:b0:67f:ba0a:e5d2 with SMTP id x3-20020a5eda03000000b0067fba0ae5d2mr2029692ioj.88.1659522658740;
        Wed, 03 Aug 2022 03:30:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659522658; cv=none;
        d=google.com; s=arc-20160816;
        b=FM2eKswM+dYaI4NS/FCLYSWmrywrGpY90HdEqSZRkGqDK7AevdOJBCUmqzPtps3Omg
         wmG/q4QlxUiXyqLQPkUAlTCUKjGbz/A7gSPXNYSB2/SryE5OE7AjLI6TUPr5Y9wsaJ4p
         uRCOYs3nNT5++59Zk6cDpRSpg4Qzl2frhwBIDTzn70PAZe38T3yomRdBEj16PttPwUvu
         6pRm73yDhz7+jiVx+OtRPoYZGQWyb8XytYuLMvYNUERqwH66O8PPZWVCkKWqZ+MLGLym
         TkW95y+uuc9ScR3xkqd7snAphh6aslnT+971ljYULK/Y+xq1uS+9ijnkA/TRu+AnxWj+
         AkpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=BnCISkt/rTW8As5S0Z1/CmUKmWtp6KufxVc54xAHFLs=;
        b=n2J8Ez2CrMoZyuZ8hWFqN4VhEFuQdk9vsKwqzY9DsSrAtu8awKTKGqszHvNi31a4EY
         tzLf+TEpkeV7+CtUFyfAc0anDZF3vdUYIYip74fb3kZmUIIqKxdNPkaMgjTnbFvasEXX
         LvLe+HI/7mSUsQ6bF+ACneWjSzPUwLgFAqpTZZ/6QSH8aJp4bFST58BUr6RjFmzAirtc
         5H8ryNwxv5Tn4y1qFPgJEi70BUZIioM0E8oWWKBG3cEB7L53nJkrIn4QYTCtHpbZDZ6o
         P04QE/qx3G1aXJIEJct1YIL3/3Sixh8uqX1KZ8lr0KWQzf37Pg6KgpdVmxDbG+sD5qSw
         6i8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bTMMrVHL;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb33.google.com (mail-yb1-xb33.google.com. [2607:f8b0:4864:20::b33])
        by gmr-mx.google.com with ESMTPS id k13-20020a02cccd000000b00331ed76f344si700515jaq.4.2022.08.03.03.30.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Aug 2022 03:30:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) client-ip=2607:f8b0:4864:20::b33;
Received: by mail-yb1-xb33.google.com with SMTP id r3so27692228ybr.6
        for <kasan-dev@googlegroups.com>; Wed, 03 Aug 2022 03:30:58 -0700 (PDT)
X-Received: by 2002:a05:6902:1348:b0:671:78a4:471f with SMTP id
 g8-20020a056902134800b0067178a4471fmr19280596ybu.242.1659522658125; Wed, 03
 Aug 2022 03:30:58 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-15-glider@google.com>
 <CANpmjNP8kmZYRsdpHCni33W-Yjgy-ajCAuTE94zwUniyYt7WQw@mail.gmail.com>
In-Reply-To: <CANpmjNP8kmZYRsdpHCni33W-Yjgy-ajCAuTE94zwUniyYt7WQw@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Aug 2022 12:30:21 +0200
Message-ID: <CAG_fn=X8zV2j9aPviz23UH8tsbRTqefGoZOCRgJeVtcivdhKVA@mail.gmail.com>
Subject: Re: [PATCH v4 14/45] mm: kmsan: maintain KMSAN metadata for page operations
To: Marco Elver <elver@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=bTMMrVHL;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b33 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Jul 12, 2022 at 2:21 PM Marco Elver <elver@google.com> wrote:
>
> On Fri, 1 Jul 2022 at 16:23, Alexander Potapenko <glider@google.com> wrot=
e:
> >
> > Insert KMSAN hooks that make the necessary bookkeeping changes:
> >  - poison page shadow and origins in alloc_pages()/free_page();
> >  - clear page shadow and origins in clear_page(), copy_user_highpage();
> >  - copy page metadata in copy_highpage(), wp_page_copy();
> >  - handle vmap()/vunmap()/iounmap();
> >
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> > ---
> > v2:
> >  -- move page metadata hooks implementation here
> >  -- remove call to kmsan_memblock_free_pages()
> >
> > v3:
> >  -- use PAGE_SHIFT in kmsan_ioremap_page_range()
> >
> > v4:
> >  -- change sizeof(type) to sizeof(*ptr)
> >  -- replace occurrences of |var| with @var
> >  -- swap mm: and kmsan: in the subject
> >  -- drop __no_sanitize_memory from clear_page()
> >
> > Link: https://linux-review.googlesource.com/id/I6d4f53a0e7eab46fa29f034=
8f3095d9f2e326850
> > ---
> >  arch/x86/include/asm/page_64.h |  12 ++++
> >  arch/x86/mm/ioremap.c          |   3 +
> >  include/linux/highmem.h        |   3 +
> >  include/linux/kmsan.h          | 123 +++++++++++++++++++++++++++++++++
> >  mm/internal.h                  |   6 ++
> >  mm/kmsan/hooks.c               |  87 +++++++++++++++++++++++
> >  mm/kmsan/shadow.c              | 114 ++++++++++++++++++++++++++++++
> >  mm/memory.c                    |   2 +
> >  mm/page_alloc.c                |  11 +++
> >  mm/vmalloc.c                   |  20 +++++-
> >  10 files changed, 379 insertions(+), 2 deletions(-)
> >
> > diff --git a/arch/x86/include/asm/page_64.h b/arch/x86/include/asm/page=
_64.h
> > index baa70451b8df5..227dd33eb4efb 100644
> > --- a/arch/x86/include/asm/page_64.h
> > +++ b/arch/x86/include/asm/page_64.h
> > @@ -45,14 +45,26 @@ void clear_page_orig(void *page);
> >  void clear_page_rep(void *page);
> >  void clear_page_erms(void *page);
> >
> > +/* This is an assembly header, avoid including too much of kmsan.h */
>
> All of this code is under an "#ifndef __ASSEMBLY__" guard, does it matter=
?
Actually, the comment is a bit outdated. kmsan-checks.h doesn't
introduce any unnecessary declarations and can be used here.

> > +#ifdef CONFIG_KMSAN
> > +void kmsan_unpoison_memory(const void *addr, size_t size);
> > +#endif
> >  static inline void clear_page(void *page)
> >  {
> > +#ifdef CONFIG_KMSAN
> > +       /* alternative_call_2() changes @page. */
> > +       void *page_copy =3D page;
> > +#endif
> >         alternative_call_2(clear_page_orig,
> >                            clear_page_rep, X86_FEATURE_REP_GOOD,
> >                            clear_page_erms, X86_FEATURE_ERMS,
> >                            "=3DD" (page),
> >                            "0" (page)
> >                            : "cc", "memory", "rax", "rcx");
> > +#ifdef CONFIG_KMSAN
> > +       /* Clear KMSAN shadow for the pages that have it. */
> > +       kmsan_unpoison_memory(page_copy, PAGE_SIZE);
>
> What happens if this is called before the alternative-call? Could this
> (in the interest of simplicity) be moved above it? And if you used the
> kmsan-checks.h header, it also doesn't need any "ifdef CONFIG_KMSAN"
> anymore.

Good idea, that'll work.

> > +#endif
> >  }



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DX8zV2j9aPviz23UH8tsbRTqefGoZOCRgJeVtcivdhKVA%40mail.gmai=
l.com.
