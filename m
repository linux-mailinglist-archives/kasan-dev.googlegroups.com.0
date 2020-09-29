Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4HWZT5QKGQEJTTSR6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DC0927CFCF
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 15:49:38 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id d10sf3207661otf.17
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 06:49:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601387376; cv=pass;
        d=google.com; s=arc-20160816;
        b=poUrHHqXabox29gJPcMgpvKv4NwLddf/wYq6fnD8ruuPmmWHpCqZpjPqdDgEu1aS9O
         Wncs4BldhpJ29233q+l7tg+47y2j6gNpRX3X5nLArgwExYIso1fVsNxY5poZyY+gZSrF
         CtCQCugKGB58Ip09RWw5TdPAV9YZTpGKgR1Hwe2ktn5Oqax4tQnC/k1FAzV837IkzR8L
         iRJ6q5l4vWDFao92kcLogINPAMGy8E/deAj5vJ0goxShFoT5S6nddLrFmQE74uOW4ciW
         nSpXf9RBCiFdz0JvF5oshdooYTz+f8GpZ5tztx/DjQcSqKtOTX7fVKi5sqydLlscuX+h
         Nnwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6fcMIAyNM/upqmVMaybfxkngaCYjZ1RImL8XbF8eLqk=;
        b=NoSthkTen3byU49lPaQaecU0dCSiA7GLS8V/0CHtn65lb4riz2Pr5mg3YdFe7xBuPU
         JY61yrZsIG/Pt/PVUGLx8E+ZaiAwU+6aUr4ZHGYyYM6AhFhOKSGyml4lS8N1blhnPEKO
         spYpeh0LZSDrWfKKwiBzOacdh+0k1Nuxhx8wPAJ7s299HUtrzr+oU5dB0MszLJ34Y3Mf
         XPxNAlrqN+WkAdkY+LpqK+V3CO7VV2bKPNbCMuj6zE8If99PNcHY4v7yaiSN6ckH9QmG
         WRB4110KDge/GKyulP2crbgRdNUypMvjCjhLXH0oV8oHsAcTx2yq3IZdxzsVYPX6LCQG
         36zQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YWvZewRv;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6fcMIAyNM/upqmVMaybfxkngaCYjZ1RImL8XbF8eLqk=;
        b=Hv/J1rkHHBMq6WKlak5bRPeBap6lq8smj4K+Lk+rMN3iloeLXbr73dy+PgWLmLSSL6
         vIOX48aepNvmemlqaJvzVAc+yq51Y23E5ObmSUs+LozWIgsycCayAkcf31BuNpR9y2ha
         TxOO1NYeDCXvM0yfpbPPe4MfhNE+pyPDELNbA4VIDi1XVdARkiS5/5geZKyJTCJcDe3I
         Led3bHhVyvjuizUJTBv4+2IdrlpTxVssZae8dX4CDQ++pUeSgEH2sZWUnFGQra8uVFxX
         E5vmYxa1KzndAMWHseZ7FSInqA34P5CNsCnG0IJtFMbF1YLMVueelsEOlqQsOFUOCx8q
         IgHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6fcMIAyNM/upqmVMaybfxkngaCYjZ1RImL8XbF8eLqk=;
        b=DbS7jmJVx+OVq6e8Xex7TeAPz8hJBNnD5+eis8NfQExz33SXQnHV0abbXBAcbGe5gn
         jDVVHaRkck2Q4da1IAFY/6c7Z70dWrCQ2XGgjsHbACCqX0TX+BjpmpmJ8RJIY8M3i/Mn
         ocDPLYvlhvE8TjM+gMhmm2QEpUAPTedp00COaAtscJtzKbPoniHOUCP8J+KtAfcgdLOR
         OSaOxYGinaLhFECOKKCKJ9N/Y+LkW5BTMxf7UHFa/5gDTq24o/kNK6/k/jVv5QX7IMYj
         SlUGz03vOSbE2/09Ta4GJCl6V5Bz5L35Evv88KJfaxoLcwshnFpS8OnzQXy3twvJ3b15
         LIvg==
X-Gm-Message-State: AOAM531DDCFMvi7C1FV/M9JztGZ1izk0ORTw/vu8Sq8Uwcn3JE7GYWH9
	cV1BwslLFg4kD/2b3ykFU4U=
X-Google-Smtp-Source: ABdhPJxKD3Ga5IAPldBtmJyYRHwCigSRXHcFmCcd19gYn4ySNVj3L+GRczmQI8EXkZZL7doqQSM1/Q==
X-Received: by 2002:a05:6830:22cb:: with SMTP id q11mr2935021otc.232.1601387376786;
        Tue, 29 Sep 2020 06:49:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:3e85:: with SMTP id b5ls1119520otc.1.gmail; Tue, 29 Sep
 2020 06:49:36 -0700 (PDT)
X-Received: by 2002:a9d:ae8:: with SMTP id 95mr2968158otq.260.1601387376425;
        Tue, 29 Sep 2020 06:49:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601387376; cv=none;
        d=google.com; s=arc-20160816;
        b=avwQK8g5XsZFsMyWUK5CjNgCJShK5bMzU6cTxooWeItzGB9WmhBqHgYr5ArRdCCoKt
         CPQT09RoDFRJGEtla8wrfEl848zKzCIEVRI+uZsiv9huQBftoVZyVdTtPCX7k/bbhelb
         Ncry5A413DNPqro8zbqUD4caIoULl+Ypb5qjWdm7k7SO6Vh89H31cJzg53RXKCIGlumj
         U7uN5suur97+svCZFzld/9ZcPoP9UOBZjo/vYA1YKwgYf30ZmkD5aXlWjkwlkOLGOwye
         NkJIulsjiMboyljITFK1M6L9zgmheMWqDFDJRouRPsfXhCnbk0dsZ35crtytYLOOWU6X
         tb9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uf55h5Im87Thv0CvH7P0y872ufq4n52JjgwdZSbMlsE=;
        b=Cv4V+u3/0VdxDajksXWuxdv/GcpvgArg239WTZ/LPN2tDrrsgTmgH36P7SqiWY+Yol
         N3/0mhlQQZQ4Ulu/PyVS6hBv807Bi8QiruHEPe+QTygcqutiFZps/xUqm/hqFcBBHpG7
         8GYKgc4y3o0taLTtMjZe7d/jNnFYfBJr1CAFR8JAPJU+5/JVmCscwg6GLB3FWU3yDK2f
         E2FSguGd2HGYNCR6y54qU3ylfb+cMd9p4WmOkDEr+yxf6bPgRmBR1R3SA/PPs+xhLfyd
         BUZwA9ZB6rVmyDuIP9COAwRnqRQok9nLx+9X97LMS1ukpjN3FWNtYfkQ/oN2Z/kiGUPJ
         zPxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YWvZewRv;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id q10si736715oov.2.2020.09.29.06.49.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 06:49:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id i17so5475665oig.10
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 06:49:36 -0700 (PDT)
X-Received: by 2002:aca:5158:: with SMTP id f85mr2718140oib.121.1601387375957;
 Tue, 29 Sep 2020 06:49:35 -0700 (PDT)
MIME-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com> <20200921132611.1700350-2-elver@google.com>
 <CAAeHK+zYP6xhAEcv75zdSt03V2wAOTed6vNBYReV_U7EsRmUBw@mail.gmail.com>
 <20200929131135.GA2822082@elver.google.com> <CAAeHK+y0aPAZ8zheD5vWFDR-9YCTR251i0F1pZ9QfXuiaW0r8w@mail.gmail.com>
In-Reply-To: <CAAeHK+y0aPAZ8zheD5vWFDR-9YCTR251i0F1pZ9QfXuiaW0r8w@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Sep 2020 15:49:24 +0200
Message-ID: <CANpmjNOFpFkrSMFezcBFJODwBK5vRi8sSEzS3AvyFu3Y0ZqgVA@mail.gmail.com>
Subject: Re: [PATCH v3 01/10] mm: add Kernel Electric-Fence infrastructure
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Andy Lutomirski <luto@kernel.org>, 
	Borislav Petkov <bp@alien8.de>, Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>, 
	Jonathan Cameron <Jonathan.Cameron@huawei.com>, Jonathan Corbet <corbet@lwn.net>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, SeongJae Park <sjpark@amazon.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YWvZewRv;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
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

On Tue, 29 Sep 2020 at 15:48, Andrey Konovalov <andreyknvl@google.com> wrote:
> On Tue, Sep 29, 2020 at 3:11 PM Marco Elver <elver@google.com> wrote:
> >
> > On Tue, Sep 29, 2020 at 02:42PM +0200, Andrey Konovalov wrote:
> > [...]
> > > > +        */
> > > > +       index = (addr - (unsigned long)__kfence_pool) / (PAGE_SIZE * 2) - 1;
> > >
> > > Why do we subtract 1 here? We do have the metadata entry reserved for something?
> >
> > Above the declaration of __kfence_pool it says:
> >
> >         * We allocate an even number of pages, as it simplifies calculations to map
> >         * address to metadata indices; effectively, the very first page serves as an
> >         * extended guard page, but otherwise has no special purpose.
> >
> > Hopefully that clarifies the `- 1` here.
>
> So there are two guard pages at the beginning and only then a page
> that holds an object?

Yes, correct.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOFpFkrSMFezcBFJODwBK5vRi8sSEzS3AvyFu3Y0ZqgVA%40mail.gmail.com.
