Return-Path: <kasan-dev+bncBCMIZB7QWENRBSNVRKLAMGQE4BSCADA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 8ECE7564EF2
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 09:46:18 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id e9-20020a2e9849000000b0025d1c0800b5sf1203839ljj.21
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 00:46:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656920778; cv=pass;
        d=google.com; s=arc-20160816;
        b=Uy9JT9QxuxzB6UtUJvAy66Gr0ei2fkOLpQnNB/1mHnhQp9ikgbJbgZcIfs9is4Y5lS
         +aJ41YJGVVEnIm4ksD6FgUksYBk4dVMZ85hOHUyp1wx7HOnA/80uCSC46fwNigmAI9je
         9sCzHY1RQhbj82oXBk3Z1Fmw+/OXiEAlwn1/yxsCLfEJ8lio9Fd22iKRKJ9lRs4N+eMq
         fPL50qUerHm+pRzgH/v1nFtbE+yh/hqNSbM081GwkyL/+mGrcdCb26ECWdJDJ5IZUTTu
         SKMiOynNA08S04/pBxXwRX53lXA8qUkgRBWhRYnsgdjUGnHsweDM1/Tf6eNRlDhZNLoO
         l3nQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xVHI+lz4rf5of2aK6wMAH8Voc9/7kPeWVOzaEBmzGcE=;
        b=VEeeyFYxOJyDkbGGjHmQU5U92uaEqg6GGsTcDvcNytsu4kFeEP+BJbInKgR6rHIFV7
         ZslbM2xrUBxKf8CXmS0s9grBjEX0Epqq2EIjXF+dBYjL/E3zPuHBs/VJ/u2nmP3bPsEm
         Z6NJYYDF0qrdRvvn8SBfwFJ8rRGGPNVl+DYwggiDKH7kUt11dtu6CEiOE3pwJDPWhgH+
         yQNstSuYOr3Mv8CKjEOWuvJP58KWchfofkytUbRVSn7BVlBRO2pf1gbEbe6hIvwLp45l
         lnaSW7lRz493XD3ztI2BthYpa661gWvPxGGWZ3VyJEwM8wk+t7moQI9YrmAZXxbZuuKl
         vowQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=c9TZYYVa;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xVHI+lz4rf5of2aK6wMAH8Voc9/7kPeWVOzaEBmzGcE=;
        b=YTAHdm5l8BzXjBHjEGKr3/WMMI/OmL5Ix2s27ikGbEtBkZZ/Zql7dXBHZzTpAu6Qu3
         qd5geKjGrrBsSckxQw9zHlpRnBoBEIMYeI3NPJp8B64jwNUlnJ/5ko55EevUCPfx2XED
         TrQzCGMA/Erw75k8nnulsgOm90YXMa+otkm0gaxnMWuRHoL0amg6l88gKRBMOwi7IReL
         a55QoUU7uh3MdNS1J00wDq5m5jJj1o/EUNTI+gmCQbJNtfwcfZXRiVpkIsdvqjxgEM1z
         jsU8tsE+uW5xaHr9HegoZ20D3xU6mom/u60mnX23qnSaK1YzSPvNhpDnf1naemduEawD
         R6Gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xVHI+lz4rf5of2aK6wMAH8Voc9/7kPeWVOzaEBmzGcE=;
        b=qzHo28rmTS5I8h1BGARHXeMCFKpZwMkIWHqmFD3LPONk766TFUi5/VQZymQIC74B5Y
         4xoA4wWbCWMfyRtNoDgupFjqRf+iXjZDj35BhExx0eAkmvjffbq7SrmEeaeNVXl73KVX
         PaT9t6UXntf04o2KF9ktGqKBuZXs93l1oNLLeguX6RxfX0hG1OjF/fS/hhyWYYFvp5lm
         Bt2dxQXDzoiWM/JGvh/yrWLFePQ/egRfudvO7v7Jrm3dA1Eap9bQtjJZ/TYQ1wzfDtKp
         vIhcYwqXH8EuBRriK5XPXoU/yaXNdAtbUprffl9dfZMJ9f3UdEWi6a1ILDtVdwMnzNWd
         l7FA==
X-Gm-Message-State: AJIora+Ul/H6DaF6maEvFHRBsjOBcA7uDbIbT96YgWjRqRH+wgtwoSSC
	8s/rWIjP7X3P+hZUF6eqOJM=
X-Google-Smtp-Source: AGRyM1tZIjjYKFbfHyWHiWCFoSLLax0hgaMFTNmvivU0jGHM7MobaoyRwRMzuFiglsOF4Qtj4JoY/g==
X-Received: by 2002:a05:6512:3d08:b0:47f:79a9:66f0 with SMTP id d8-20020a0565123d0800b0047f79a966f0mr18021815lfv.576.1656920777739;
        Mon, 04 Jul 2022 00:46:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5a41:0:b0:481:3963:1222 with SMTP id r1-20020ac25a41000000b0048139631222ls133657lfn.2.gmail;
 Mon, 04 Jul 2022 00:46:16 -0700 (PDT)
X-Received: by 2002:a05:6512:2213:b0:481:7d:5aab with SMTP id h19-20020a056512221300b00481007d5aabmr18325753lfu.320.1656920776500;
        Mon, 04 Jul 2022 00:46:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656920776; cv=none;
        d=google.com; s=arc-20160816;
        b=jSgy5VQeMVYJ5BnLIHfHUExRLT+/AD139UbgasVboNCZFVyh0COu9VCJk4mcU0G4PZ
         fXWW+T77eV3ryN4waCl/bATf+wXiL/0o+5+/7HOUSrxvOIv0cUWTMlKrkfgUSgAlYwjV
         FJ/61rXn5TC9EGXtQDn2S8GbpXnYLyCn5u6JZlfAmQ6a9GSdkgCe5Pq+kSYi8J70RnRc
         /u8N6QgvVeAZI3x5jnc5Q+p0BoREe7pF7QVgLztTucoPTmNWQlI7jr29nsGbB+lsBoA6
         Uf+QYK5fjA3kNwrtgM6iZSpb7eDFgAC+QYLUAxe6g4qlyhIlxaVN0ZE4ZLeJVnvvvJ/d
         u2YA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EpLsmKlpKCiUIDe9SFr1Z71rXe3WR1MDQEjPMDRMDOU=;
        b=o9bPNoZtnbPMHKdUsxrbOzLzuIPMRVWLSruyeBFRypMRvyXlSNX4N7K14lBi015O0X
         JCfVRIbtcjZOlGXrio/xClMrPQuBDq1e3KRZm3LmzfnCL84sAL2pON0oV01x1+6dBwLl
         eKyHlFx3Ct3ABt7VjUFQaR5xF6D/zkwij44O/sbYLLY1tNN1CVbHtEh8+ctq/6FMvRwk
         qhC9l3c40vu2C09hsCp7kb5so4PlG//xPDZzGL34LmmE9EQk+XMY5nrhHtb4hoe3LSfV
         uPh9/Wi0yx9fzFXPfQttVF5zutE5xuyyHx0ybeR6n//CB7dJJhcxg4aXZjEkeIpWIeSU
         nTnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=c9TZYYVa;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12e.google.com (mail-lf1-x12e.google.com. [2a00:1450:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id m7-20020a2e9107000000b0025594e68748si1262964ljg.4.2022.07.04.00.46.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 00:46:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e as permitted sender) client-ip=2a00:1450:4864:20::12e;
Received: by mail-lf1-x12e.google.com with SMTP id y16so14317200lfb.9
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 00:46:16 -0700 (PDT)
X-Received: by 2002:a19:f006:0:b0:47f:ae73:abe5 with SMTP id
 p6-20020a19f006000000b0047fae73abe5mr17682143lfc.206.1656920775975; Mon, 04
 Jul 2022 00:46:15 -0700 (PDT)
MIME-Version: 1.0
References: <20220615062219.22618-1-Kuan-Ying.Lee@mediatek.com> <20220703161552.6a3304c8d316e4fdcce42caa@linux-foundation.org>
In-Reply-To: <20220703161552.6a3304c8d316e4fdcce42caa@linux-foundation.org>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 4 Jul 2022 09:46:04 +0200
Message-ID: <CACT4Y+Y3we9jdc1gJ_rhJZg7YWXm7F6F245ZQQFMknrxXRuo7Q@mail.gmail.com>
Subject: Re: [PATCH] kasan: separate double free case from invalid free
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	chinwen.chang@mediatek.com, yee.lee@mediatek.com, casper.li@mediatek.com, 
	andrew.yang@mediatek.com, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=c9TZYYVa;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e
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

On Mon, 4 Jul 2022 at 01:15, Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Wed, 15 Jun 2022 14:22:18 +0800 Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com> wrote:
>
> > Currently, KASAN describes all invalid-free/double-free bugs as
> > "double-free or invalid-free". This is ambiguous.
> >
> > KASAN should report "double-free" when a double-free is a more
> > likely cause (the address points to the start of an object) and
> > report "invalid-free" otherwise [1].
> >
> > [1] https://bugzilla.kernel.org/show_bug.cgi?id=212193
> >
> > ...
>
> Could we please have some review of this?


Looks reasonable to me.
Looking through git log it seems the only reason to combine them was
laziness/didn't seem important enough.

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

I will update syzkaller parsing of bug messages to not produce
duplicates for existing double-frees.
Not sure if anything needs to be done for other kernel testing systems.


> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index c40c0e7b3b5f..707c3a527fcb 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -343,7 +343,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
> >
> >       if (unlikely(nearest_obj(cache, virt_to_slab(object), object) !=
> >           object)) {
> > -             kasan_report_invalid_free(tagged_object, ip);
> > +             kasan_report_invalid_free(tagged_object, ip, KASAN_REPORT_INVALID_FREE);
> >               return true;
> >       }
> >
> > @@ -352,7 +352,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
> >               return false;
> >
> >       if (!kasan_byte_accessible(tagged_object)) {
> > -             kasan_report_invalid_free(tagged_object, ip);
> > +             kasan_report_invalid_free(tagged_object, ip, KASAN_REPORT_DOUBLE_FREE);
> >               return true;
> >       }
> >
> > @@ -377,12 +377,12 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object,
> >  static inline bool ____kasan_kfree_large(void *ptr, unsigned long ip)
> >  {
> >       if (ptr != page_address(virt_to_head_page(ptr))) {
> > -             kasan_report_invalid_free(ptr, ip);
> > +             kasan_report_invalid_free(ptr, ip, KASAN_REPORT_INVALID_FREE);
> >               return true;
> >       }
> >
> >       if (!kasan_byte_accessible(ptr)) {
> > -             kasan_report_invalid_free(ptr, ip);
> > +             kasan_report_invalid_free(ptr, ip, KASAN_REPORT_DOUBLE_FREE);
> >               return true;
> >       }
> >
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index 610d60d6e5b8..01c03e45acd4 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -125,6 +125,7 @@ static inline bool kasan_sync_fault_possible(void)
> >  enum kasan_report_type {
> >       KASAN_REPORT_ACCESS,
> >       KASAN_REPORT_INVALID_FREE,
> > +     KASAN_REPORT_DOUBLE_FREE,
> >  };
> >
> >  struct kasan_report_info {
> > @@ -277,7 +278,7 @@ static inline void kasan_print_address_stack_frame(const void *addr) { }
> >
> >  bool kasan_report(unsigned long addr, size_t size,
> >               bool is_write, unsigned long ip);
> > -void kasan_report_invalid_free(void *object, unsigned long ip);
> > +void kasan_report_invalid_free(void *object, unsigned long ip, enum kasan_report_type type);
> >
> >  struct page *kasan_addr_to_page(const void *addr);
> >  struct slab *kasan_addr_to_slab(const void *addr);
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index b341a191651d..fe3f606b3a98 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -176,8 +176,12 @@ static void end_report(unsigned long *flags, void *addr)
> >  static void print_error_description(struct kasan_report_info *info)
> >  {
> >       if (info->type == KASAN_REPORT_INVALID_FREE) {
> > -             pr_err("BUG: KASAN: double-free or invalid-free in %pS\n",
> > -                    (void *)info->ip);
> > +             pr_err("BUG: KASAN: invalid-free in %pS\n", (void *)info->ip);
> > +             return;
> > +     }
> > +
> > +     if (info->type == KASAN_REPORT_DOUBLE_FREE) {
> > +             pr_err("BUG: KASAN: double-free in %pS\n", (void *)info->ip);
> >               return;
> >       }
> >
> > @@ -433,7 +437,7 @@ static void print_report(struct kasan_report_info *info)
> >       }
> >  }
> >
> > -void kasan_report_invalid_free(void *ptr, unsigned long ip)
> > +void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_type type)
> >  {
> >       unsigned long flags;
> >       struct kasan_report_info info;
> > @@ -448,7 +452,7 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip)
> >
> >       start_report(&flags, true);
> >
> > -     info.type = KASAN_REPORT_INVALID_FREE;
> > +     info.type = type;
> >       info.access_addr = ptr;
> >       info.first_bad_addr = kasan_reset_tag(ptr);
> >       info.access_size = 0;
> > --
> > 2.18.0
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BY3we9jdc1gJ_rhJZg7YWXm7F6F245ZQQFMknrxXRuo7Q%40mail.gmail.com.
