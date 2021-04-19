Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHFE6WBQMGQE2GEZ26I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id A1D6A363F27
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Apr 2021 11:49:17 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id n15-20020ac8674f0000b02901b3da8d8dccsf8489228qtp.21
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Apr 2021 02:49:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618825756; cv=pass;
        d=google.com; s=arc-20160816;
        b=GdEJxccHKvl7mfrEOot9Kng0EyfnGnx/UbUlln3kPQsrOC7Vt/8H80YL9ZhawXkq2s
         HFe/ZAVVlwWiUjYeqEYssmJkE0dUZWGO7OKF4pgR/HT3SCVKwx9kPi2uluR2CIwEJQo4
         G9ncbPYo3Y+IWTySVubygN/hex7dcokqjOlMw3cwIKlqtT5rF7W4rczhphFScVMHqx2g
         nCyW0CIMZS/uX/He52KnFYqkzpMn8h0w2+OLCC+28Ve2PxcQBJCXU+gaMyie/PgBxyBa
         W4+cPmc0YBM/X05vgF3CrDnm3uHztGERWNgPRC/OvExalZk0Y5GOlMGnrnpJ7oALOvQt
         zbOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=csdyBp4QwkWYazOzOvN8petNBrdhq+yO7/ilHOxXPVA=;
        b=iVOavldNASODg5ulHvpOzB1eWTm4v/yiMLQjckswS1muLugOCjGolt03ZXK+bFFc4w
         DgseOo3Eadsp7HOgcfv7H60t6m1FqNousQNmnG2+GmJVFS4g0Ow9aBPGeALXAUl1/IN+
         3xrAvHIhx2cxQAUVSYWereskczVIoJ3Lqa/TqgiQP7gqZRTbs/0c8H1lhTzgdGkhhNeC
         BAvrvN8Zolu20Di2eUtfMoI5wU0GaokA7pN97jmqgivtjjsGmtaOCX8wiO4kJgSpIXR4
         XJ8V50rdVdmDnYF054Hk6US/y/H2ZerONrHfPJNM+c4IQXr7eeHfPfu04gegwsXYzWVa
         AsyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SnrQH8zn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=csdyBp4QwkWYazOzOvN8petNBrdhq+yO7/ilHOxXPVA=;
        b=guucqsVvnjzdXGxmmT5cxmI81FIe0LUjdJ085jKlqm/7HZn+uFSp/rqPW2nKrHsKS2
         I2idJG7gWw2cmuJ0ZduN0jjgUEUVJfx0ydXTCuQUYXzJvdiUjwGpL7mPOX79sYXs9oyr
         lwyeMGjEROa2xzaEuw2UsvjWzHR5FIP7Ol6232DXQzwHTeOeXo7CNvp7xTfcCqEfmlGv
         Ly0YJPDdbLFGSHp+tLypc2EqyVzW2AroupzFfNb4EvylXKcS7L9UABZEBIbgb0qDv+FF
         1yR2lkBM8JHlBMntiMKD/+UMv67veZfRzAbmoZcpp+P+Nfl6zDR3U9pW1fdS2OBFZFav
         ST0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=csdyBp4QwkWYazOzOvN8petNBrdhq+yO7/ilHOxXPVA=;
        b=Yz+nixRpaaJbDfWwXwFm7srjytrrZFj9sAKsPB3gFNa1Oj4qkiw3AjDqLvyLPoHnzR
         iRnxOslH9GugiLXLt7fhHS6xC1WOT42bFKWQ39IBwH3rdtt1Q3kt3UF/TEdCxTbPuA0k
         qHf/b6WMK6HJ4kGArcLGLO13Gl2aeSc5NlhKNsvGXFcCD9sSIZhBhqRaLxtI/DIgXJmC
         mlBe+AgMKDEP4FUH5e2M1kZ+pegq32SvlEbMKnlPVlt1/t/nYXbJCt81ZgLKhLgstaOC
         9sEKVzBuPJJl0lLVyEvtv16wSSXkZVy3NiMWrffE7KnMVbWJaQUXUyflGNaTaKISn9cr
         Wfow==
X-Gm-Message-State: AOAM530wkllXVkNvXoIWyQkPBZQodGw/aNNyjNIn8/QJyq64S6RHcSer
	p4omIcrUkbXdebcOv0Lbae4=
X-Google-Smtp-Source: ABdhPJzbEoHNHxxqOlAeXhEkm9ekfRUK0li4eq4lJCEQ5XN6+cK/r9QalhOORFn2kam440vZ824PMA==
X-Received: by 2002:a0c:9bda:: with SMTP id g26mr20408767qvf.44.1618825756712;
        Mon, 19 Apr 2021 02:49:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:202:: with SMTP id k2ls4395412qtg.5.gmail; Mon, 19 Apr
 2021 02:49:16 -0700 (PDT)
X-Received: by 2002:ac8:7dc5:: with SMTP id c5mr11005830qte.270.1618825756304;
        Mon, 19 Apr 2021 02:49:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618825756; cv=none;
        d=google.com; s=arc-20160816;
        b=1ETYmrJzQf5sQoy9jTmQ7gJHbB0aeyp4Pnj3Dd1HZk47zaQd4QLd2ainnIq8RePJ/U
         RkUqq0oHHp5dqw3+lSxD5aOJGMqviyTxv6Tp32WO1OaCx3GljLfv3gAjdllUBTwv8XKn
         20UaEexH7p+fi7C/w7u+2aEFhXIAWjfIQr+XpRiqZGhA7xYZspDiwM/xc/3pcPANHZXv
         YPPRDJRfqIdoBdDiLDVYACD5/486YU2e/CAa049BtVL5sUvUEHILOb/iw9BtRqM1BV+d
         M2R1cDUd1KOiJiKl29Qh3fThpC1yIOD1J3oWC/KbD7KVKXoeEJu7F1RYwQLxnjKL2DPQ
         xoSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nitggrP0xRKevJNitjMdZZF9gGxfx3q/C1mur/zTDM4=;
        b=GcnMtHe21NVfQiv4QNN8kyGkWYgT/3IMG0eO1LX8cEZJV5svQeteC7fWrLnQV6StGI
         KiQgohuukbj5TheFBw1dIHnVNi8R4PrB+IXXvaJiXZq7N3krcLb2w44GcgWXAcRnR1Nl
         6Zse9NmxY9Z5Sx3CwGTqBG4aSwutXlAB/JjwYDSN6SlgLX6Gv+NLwtg87swzt7IhQvM4
         5NZpLLnAnbECsH9EF6aPNZMp0A9vDJVc/pVvSJ46qczXog2Uow3rIQGzAcTJL5b2OsQE
         XaEg+J2VX8/TskbzOiNMDlVpTR3A42HHDsH8j71PnKtX3eWURVv5Cymb0IO4xfJCrOq7
         ZzkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SnrQH8zn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2c.google.com (mail-oo1-xc2c.google.com. [2607:f8b0:4864:20::c2c])
        by gmr-mx.google.com with ESMTPS id k1si1712009qtg.2.2021.04.19.02.49.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Apr 2021 02:49:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2c as permitted sender) client-ip=2607:f8b0:4864:20::c2c;
Received: by mail-oo1-xc2c.google.com with SMTP id e12-20020a056820060cb02901e94efc049dso2684364oow.9
        for <kasan-dev@googlegroups.com>; Mon, 19 Apr 2021 02:49:16 -0700 (PDT)
X-Received: by 2002:a4a:eb02:: with SMTP id f2mr12729819ooj.36.1618825755725;
 Mon, 19 Apr 2021 02:49:15 -0700 (PDT)
MIME-Version: 1.0
References: <20210419085027.761150-1-elver@google.com> <20210419085027.761150-2-elver@google.com>
 <20210419094044.311-1-hdanton@sina.com> <CANpmjNMR-DPj=0mQMevyEQ7k3RJh0eq_nkt9M6kLvwC-abr_SQ@mail.gmail.com>
In-Reply-To: <CANpmjNMR-DPj=0mQMevyEQ7k3RJh0eq_nkt9M6kLvwC-abr_SQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 19 Apr 2021 11:49:04 +0200
Message-ID: <CANpmjNNO3AgK3Fr07KXQhGpqt6-z7xNJFP=UoODg-Ft=u9cGfA@mail.gmail.com>
Subject: Re: [PATCH 1/3] kfence: await for allocation using wait_event
To: Hillf Danton <hdanton@sina.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SnrQH8zn;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2c as
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

On Mon, 19 Apr 2021 at 11:44, Marco Elver <elver@google.com> wrote:
>
> On Mon, 19 Apr 2021 at 11:41, Hillf Danton <hdanton@sina.com> wrote:
> >
> > On Mon, 19 Apr 2021 10:50:25 Marco Elver wrote:
> > > +
> > > +     WRITE_ONCE(kfence_timer_waiting, true);
> > > +     smp_mb(); /* See comment in __kfence_alloc(). */
> >
> > This is not needed given task state change in wait_event().
>
> Yes it is. We want to avoid the unconditional irq_work in
> __kfence_alloc(). When the system is under load doing frequent
> allocations, at least in my tests this avoids the irq_work almost
> always. Without the irq_work you'd be correct of course.

And in case this is about the smp_mb() here, yes it definitely is
required. We *must* order the write of kfence_timer_waiting *before*
the check of kfence_allocation_gate, which wait_event() does before
anything else (including changing the state). Otherwise the write may
be reordered after the read, and we could potentially never wake up
because __kfence_alloc() not waking us.

This is documented in __kfence_alloc().

> > > +     wait_event_timeout(allocation_wait, atomic_read(&kfence_allocation_gate), HZ);
> > > +     smp_store_release(&kfence_timer_waiting, false); /* Order after wait_event(). */
> > > +

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNO3AgK3Fr07KXQhGpqt6-z7xNJFP%3DUoODg-Ft%3Du9cGfA%40mail.gmail.com.
