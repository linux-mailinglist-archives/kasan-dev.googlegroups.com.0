Return-Path: <kasan-dev+bncBCMIZB7QWENRBV4U7PUQKGQERSY6KNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 794B478999
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2019 12:28:40 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id d9sf51387547qko.8
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2019 03:28:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564396119; cv=pass;
        d=google.com; s=arc-20160816;
        b=VvPf661lqrBflKN4igHxGa3ZCEsAUG6txRJdIB648nHvJB1by5CJiUohB4KFcy46cY
         QJrDGo6SYFR7IQI3Q9nV8YN8Mmdu1FVtijGU0p2SACXPSQIjqPHPmgP4b/Pz8tgWC4Xk
         RgywBhlvbSqPx+ZWWvUmnaESEPwX9alopl+Xs7i6/uiFxw9jgh2A6tuBwFcpU9iVD7h1
         ddRfxolv3gMV/XyqAPp3/DqEBFSooa1glCcLp+xHv7rRSTHuPgmpV6EaNNQ+rzTHVNEz
         +p8jmp0n6kPMnE7PQx4IrSVXyQZ/gVBYm49rHrIJk8ExG39nIYDrOlEHFJbwqEDZtk3U
         A92A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0YlH3jlGZihLyDyBmToUDL3XrHZztqoMW5noDXMmTD4=;
        b=ntBuxC7eR24TuWSfI0drOLleaeEwFYNjI2DjUYETmaqNkqNUsmZvw2XZkttYfTn75H
         RMr9x2zbxS0azsCPk+W3x3s3MtSxTte7E0Ow4EtZjJXK1TfI4jbxzsHjWACYKhAVocJs
         TpLk8OOj3Tck89j81mAlgIR07XRqcEvDTNh6OqaqPuonAxiA0klwiBRpOavgHNGr3neL
         IjeJpsxLDOI1is8IpieqGW7jtQ/+jdisr96+iF0uVFki5zTHyD9LCCGEuPFf1pp3A7mq
         9bhRLLlu3hsU//nmjGqBugiwGRy4dhZSyc7RYdMJZI2LjWO9pgsk2fD14pSzfBWn+AWS
         FBeQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Im51TH56;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0YlH3jlGZihLyDyBmToUDL3XrHZztqoMW5noDXMmTD4=;
        b=s3X+R3lWJd7ONM5JN0AHTGLlKzxq41VIJqYDuTDLju4wcY6cQlrIh/oe8u7iXM/xP4
         YsHHe/aw67noBhLPDUp+TsIW6G9cX3cvSuRKOqSxJItOfgxQ9cAaiZ+7k5oJTaNli22H
         2FUFVObadrpGOtSwynIebcq46Q3ZIcQR73t1fRrBcXpBNAI1UJ+LxlmZdU8rKm25z3Dm
         yEqLOw98p1n5Je+BOOs5/xel8/6aQ8PHP8iIUNosTsaSyM54tKGFB+zFZ/nuOKb0j64N
         eHuFXacIAHWNXs11xRmHmU00k7fH2Nqfdgeajez6LGXz03MwEgtqG32LMZD/xAx+T6X3
         BJgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0YlH3jlGZihLyDyBmToUDL3XrHZztqoMW5noDXMmTD4=;
        b=o4eQZlmJxDVlQ9dUHIjwEMjpauuf3CFDU6sRZFM+437YRGXmksYI/KnudsLyUt+sV6
         Cmezy+tXP8/av7UNfUV7ckHrdwdLe/WZqWZzJAtfKJ9qIpkm5Lh8B2QMZ4aboCo4dvdW
         JrbnT44JYPiLzIt6rf9Kj2/FStXzG0WsWQfHrvgCUn9NYv50vLzcInQ/nb3y0LYzVkSR
         r1mEfpqmVcfaJ/z2tTmkprEAUzLurnJBMl5FUb+GkC+SEy4PC71ORia14KRLjHgpw0bM
         n+V510GzGTdbTDGyfnQ5Nx+jHrRDobBW1iMWQ8YDPX5o4KNlqFYK/Ob4kRAdECo0rIOQ
         mrmQ==
X-Gm-Message-State: APjAAAWBRxoKW8BVE/nTMg185iMeofoHjB2NtJBDtnuQRSUKmHsdU0d6
	2c4qDph5gM6l4GCcm9APDxM=
X-Google-Smtp-Source: APXvYqzSebslAAXWhW5ttNbuMCk4WMIzrU1yx1wl3CiyZ3bVZ0yXK8My4WPgh4gP5Y9NHO9q/xH7Sw==
X-Received: by 2002:ad4:4466:: with SMTP id s6mr79094490qvt.237.1564396119218;
        Mon, 29 Jul 2019 03:28:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:10b:: with SMTP id e11ls3022286qtg.2.gmail; Mon, 29 Jul
 2019 03:28:38 -0700 (PDT)
X-Received: by 2002:ac8:7104:: with SMTP id z4mr76567178qto.52.1564396118916;
        Mon, 29 Jul 2019 03:28:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564396118; cv=none;
        d=google.com; s=arc-20160816;
        b=o6zSAJvCjzfsaVrNENmTXIXvCLE+hFCXVvrNJXJP0A8A2zWASfQcWkstky1k00u9N+
         YW2aX7QUxMMs7V7hW/frOLVncF/E0PE+YEeaoeQbG0VxMMqwDfdYsj8oOuAafPkrsOX5
         k/3X16kkfp4u6G/mZH3iqetyaKtFGFTlINJJO8qUaphzDocbYkI0TkI02zl+aLlNpGla
         ddml8Ll5XrNibarV9Q+UbZPpUhNyBGXUkiQxB3Bc286FY5UUutWNZyN+rTKMmrKw/eaK
         y9DQH4Ak4h84SQH5amtDoj5soQ+/r1MR2sz+AyytQtKAyumVkVA6XF5lUr3QgHsMvBwY
         uzgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3itDB/HMkkFV+oaY7RHK7Sdf6jogzMFoz/vY9dJmj0k=;
        b=wdrtdvitPJhFsyuWNxcZ5YuGpWNwVuCMlbAiJzsUsxh1io7YpT8lF8+vOydkX0wQ3I
         DQQPAheyUXpeEHS0Z3VkJ1+DaVLwyrNSTrmrfLY+ItcrI2tBZu3ULrjRp7KTYnuWRY/B
         N5D1DKaj5BfvRIVqGRdlfwrP5Wmmw1ozAapIA7CrpCH8oI0flWdHkPuVT0Iub0FAoK56
         +GToOXLEjp/ms8QesZOP+iJw91wux2KH081gbAbcoQ3ZntSoxNiJk0tVVIoKxy2xFpxn
         cwBKCFhp0a5HLPpGmNj0L6zx2Rm7WVt8BQySJV4Xn4uVePeTbiICGrs2ZNHty0MCkEgE
         Mi5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Im51TH56;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd42.google.com (mail-io1-xd42.google.com. [2607:f8b0:4864:20::d42])
        by gmr-mx.google.com with ESMTPS id w82si2514181qka.7.2019.07.29.03.28.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Jul 2019 03:28:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d42 as permitted sender) client-ip=2607:f8b0:4864:20::d42;
Received: by mail-io1-xd42.google.com with SMTP id m24so118809442ioo.2
        for <kasan-dev@googlegroups.com>; Mon, 29 Jul 2019 03:28:38 -0700 (PDT)
X-Received: by 2002:a6b:4101:: with SMTP id n1mr74832605ioa.138.1564396117841;
 Mon, 29 Jul 2019 03:28:37 -0700 (PDT)
MIME-Version: 1.0
References: <20190725055503.19507-1-dja@axtens.net> <20190725055503.19507-2-dja@axtens.net>
 <CACT4Y+Yw74otyk9gASfUyAW_bbOr8H5Cjk__F7iptrxRWmS9=A@mail.gmail.com> <87blxdgn9k.fsf@dja-thinkpad.axtens.net>
In-Reply-To: <87blxdgn9k.fsf@dja-thinkpad.axtens.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 29 Jul 2019 12:28:26 +0200
Message-ID: <CACT4Y+YSNdQdUbQS4K8NxuQf7AmbK1SXx0ZdLtM3cfcY6Dpv2A@mail.gmail.com>
Subject: Re: [PATCH 1/3] kasan: support backing vmalloc space with real shadow memory
To: Daniel Axtens <dja@axtens.net>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Andy Lutomirski <luto@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Im51TH56;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d42
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

On Mon, Jul 29, 2019 at 12:15 PM Daniel Axtens <dja@axtens.net> wrote:
>
> Hi Dmitry,
>
> Thanks for the feedback!
>
> >> +       addr = shadow_alloc_start;
> >> +       do {
> >> +               pgdp = pgd_offset_k(addr);
> >> +               p4dp = p4d_alloc(&init_mm, pgdp, addr);
> >
> > Page table allocations will be protected by mm->page_table_lock, right?
>
> Yes, each of those alloc functions take the lock if they end up in the
> slow-path that does the actual allocation (e.g. __p4d_alloc()).
>
> >> +               pudp = pud_alloc(&init_mm, p4dp, addr);
> >> +               pmdp = pmd_alloc(&init_mm, pudp, addr);
> >> +               ptep = pte_alloc_kernel(pmdp, addr);
> >> +
> >> +               /*
> >> +                * we can validly get here if pte is not none: it means we
> >> +                * allocated this page earlier to use part of it for another
> >> +                * allocation
> >> +                */
> >> +               if (pte_none(*ptep)) {
> >> +                       backing = __get_free_page(GFP_KERNEL);
> >> +                       backing_pte = pfn_pte(PFN_DOWN(__pa(backing)),
> >> +                                             PAGE_KERNEL);
> >> +                       set_pte_at(&init_mm, addr, ptep, backing_pte);
> >> +               }
> >> +       } while (addr += PAGE_SIZE, addr != shadow_alloc_end);
> >> +
> >> +       requested_size = round_up(requested_size, KASAN_SHADOW_SCALE_SIZE);
> >> +       kasan_unpoison_shadow(area->addr, requested_size);
> >> +       kasan_poison_shadow(area->addr + requested_size,
> >> +                           area->size - requested_size,
> >> +                           KASAN_VMALLOC_INVALID);
> >
> >
> > Do I read this correctly that if kernel code does vmalloc(64), they
> > will have exactly 64 bytes available rather than full page? To make
> > sure: vmalloc does not guarantee that the available size is rounded up
> > to page size? I suspect we will see a throw out of new bugs related to
> > OOBs on vmalloc memory. So I want to make sure that these will be
> > indeed bugs that we agree need to be fixed.
> > I am sure there will be bugs where the size is controlled by
> > user-space, so these are bad bugs under any circumstances. But there
> > will also probably be OOBs, where people will try to "prove" that
> > that's fine and will work (just based on our previous experiences :)).
>
> So the implementation of vmalloc will always round it up. The
> description of the function reads, in part:
>
>  * Allocate enough pages to cover @size from the page level
>  * allocator and map them into contiguous kernel virtual space.
>
> So in short it's not quite clear - you could argue that you have a
> guarantee that you get full pages, but you could also argue that you've
> specifically asked for @size bytes and @size bytes only.
>
> So far it seems that users are well behaved in terms of using the amount
> of memory they ask for, but you'll get a better idea than me very
> quickly as I only tested with trinity. :)

Ack.
Let's try and see then. There is always an easy fix -- round up size
explicitly before vmalloc, which will make the code more explicit and
clear. I can hardly see any potential downsides for rounding up the
size explicitly.

> I also handle vmap - for vmap there's no way to specify sub-page
> allocations so you get as many pages as you ask for.
>
> > On impl side: kasan_unpoison_shadow seems to be capable of handling
> > non-KASAN_SHADOW_SCALE_SIZE-aligned sizes exactly in the way we want.
> > So I think it's better to do:
> >
> >        kasan_unpoison_shadow(area->addr, requested_size);
> >        requested_size = round_up(requested_size, KASAN_SHADOW_SCALE_SIZE);
> >        kasan_poison_shadow(area->addr + requested_size,
> >                            area->size - requested_size,
> >                            KASAN_VMALLOC_INVALID);
>
> Will do for v2.
>
> Regards,
> Daniel
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87blxdgn9k.fsf%40dja-thinkpad.axtens.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYSNdQdUbQS4K8NxuQf7AmbK1SXx0ZdLtM3cfcY6Dpv2A%40mail.gmail.com.
