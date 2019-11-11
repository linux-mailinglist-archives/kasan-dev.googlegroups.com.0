Return-Path: <kasan-dev+bncBCMIZB7QWENRB7FIUTXAKGQEEA2BNVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 2452AF6F47
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Nov 2019 08:57:50 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id q82sf10927169oih.14
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Nov 2019 23:57:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573459069; cv=pass;
        d=google.com; s=arc-20160816;
        b=TNNQkMYEurtPdsSqZ9GcovDR6Ptz4VqPSHqnGJO/8SL1A6KwlH+G4jMbdw+MyRkxb6
         mLeEarBJ6vnHFB7TYm8pcuEfZ3qQTnYHzGPzFZlOPOJ+uhhyy/CCwseZApCzGQa2B1L1
         +nQbiClZX+D3Ti1s7MXukGuTz4DzsErlRi1CVWYW1k2rQq9kuxwNT70bzBbHnWQnJBSx
         oZtdiVWZtO31yC55uZ/yf1I+lmk4KY7KuyCYPjwyp+U7T6nYJ8q7ktd2atuWIyJZ27BU
         dwiVCkMauR1KYjH1O3KH3HQK5Jw2PQSbIyZIHE6WcbDzcAXCWJxmeJyQJPnnDibcLbUq
         fq0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HKkZhoNzRklbbnc435Ett5gExA4DndigLt0oI1rHWmk=;
        b=VducR51M0e2yaoydSARl++HZInvYR6Ut/f+Ty8nskyWvoD+xq8i0bZA3fFDZzLlQuw
         igsti5SlbckTbXzyv+zWk1QpWDc0ljySVrfeFv3Fysmwy0F6271vw+36h09wOK+r7IyV
         ATcw3wyE6OtKpfJm5FZMhh5RGFhfpg17EIFYqsUohAhRbPdFol+lxeiZUCk2XHdoBm/E
         Gnhwo+5wzqRF3fnLWKoCVU61syOt8QNP3MZWRFbzSqv4rYIX1FNT+4Q/1ivXcV8HhXMm
         +slDyaik/crg3TtMTOg3LUsDoUfrEtwxKsoqxItAcqxuXoU3ilpR+k8U6kHy8kFHdMsQ
         OQxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g63j6COv;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HKkZhoNzRklbbnc435Ett5gExA4DndigLt0oI1rHWmk=;
        b=Hpw5u9IzYuASOy5jBPl5yY28jh2u29X7GnGHWlA6ljOzvgxzMwffO5hKEpfM1iyio2
         sjMF2uZnlsGIagtBocS/UUzFof0TA7vBF4li+OVLjMvieca0LlkqCuwD/12DZGnkLdVV
         upXTEQd/DigggmZNB1W6sX3dqRzl9HX6l1IEufBSpKg9EjBUjmYs8K3RG6cnH9G2ApET
         BlO1lhMhbWy44HMBaB3+hA4yvOaLTx2E9a8SxPa1bAWupJhleyOL9xlUL5AdAIOnDzz/
         ch9QKWNRyoLi79JmZjmncVIByz7b5dr/l+r04dyXXHxnuy6/nnJhhsuTQN4nHy7Qj546
         gDqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HKkZhoNzRklbbnc435Ett5gExA4DndigLt0oI1rHWmk=;
        b=J/UTVbieR9rrGCsBtfJKBat0zRuHmsqWTRRZUV+gejBp57a0tQkmi+dNq/zBaYbmHw
         /L9/0X6/hV3MMZHB9C77kaUmoRknTchsp8IrTXLoTCjKGkqiznWK5u7sKh7YUHZHauq2
         k34g9UoH70idlAbBMRZT45onzoZR35oASN9sxSV2OXaCrmklzy8W5q+oVrPi3xmf5QMF
         qygXi0zm6dy4T63e9nYiBVMxFhD+Mp/0pxpl5hGoQ4NKVJJcoBRjziA/vSDF+GVJviSq
         mIR1fnsLiWld4jdv+Q9sqoar5SfjtPYfFtNe0wTg5GkkSkSvpCXTG7MjCekJyWyfFPjr
         XcWw==
X-Gm-Message-State: APjAAAWL1Be4sR5jvL7FRgpaiwN61LxKhZGssFXRyVc2krjDcjeHG/Jo
	8KyxyF5bofo6QGLAmFZOfZo=
X-Google-Smtp-Source: APXvYqx9+lk9mXdWML3ENREMJmFrWbqvubmRT3NaFQt4FIQdnJW7Gj/5ILLaP/cveT7BOahrBT0ArQ==
X-Received: by 2002:aca:55d3:: with SMTP id j202mr23107201oib.152.1573459068621;
        Sun, 10 Nov 2019 23:57:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5886:: with SMTP id m128ls1721305oib.14.gmail; Sun, 10
 Nov 2019 23:57:48 -0800 (PST)
X-Received: by 2002:aca:5686:: with SMTP id k128mr23518946oib.34.1573459068266;
        Sun, 10 Nov 2019 23:57:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573459068; cv=none;
        d=google.com; s=arc-20160816;
        b=n0B6wuQAwYv/b0q1AFYCLUIPTKxj/nwliouxKpqciamZktYGjodGau9PPV3wg9y2iZ
         /WGMRSDKY17+YbLj4WEIBdRXENNY//LuOClmpccCxwQA0BQZnxQmAMVgLY9x4uLBqk78
         oB6floOGd7g4Bj5xb//DvnD+k7xYje2RI4NLc1FvP8+f0gDPi06xZZ9W57WgSMSsoMSi
         C4e+tXjSxTdiRJ+T9QhWLE8Trt/jCxlhYxK9MTtJD69R6WRxQ1a5NuKp8GErrU6dpRDH
         qomNRX/LJ+XiHizmQtYhfSfMrOFb15b72Ns93hYep08ycYcI1220Tc5whnf1oRpzRo4I
         vN0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=H7y4zy6OrzaKCbmt5VnQkSfOPrSCD4IzJM4CsQhV4vc=;
        b=GZgxmHrSEpEIH72P8n6IEMDex7FwAhmEw6A4CPVrev/FxVfKXuuhbT8al532h0WnxT
         m8nZMQ9xz7so06oxO6LiZOQ3hGH3dBlQeOTS9W24bPjjy0cHvsgnaQDGn2vLZi9dU0NU
         Ki64g5TWBwykwpwe1pSLaEhMrPJIh0mekW9Zkd0MS/2Lo3RELB//QRarNGvB3WEmetnU
         GBeMrTUUYb+RvLcuf+ga+lIgjVW9s/1Z/2jxqbA7stKeuv+mRhqHNIBcerUPmj16N8zK
         IWwTP3WgIvMvrB0rt/9iBm4W1Bc/kl6qAHzyYEzVNscZQIjbvYsCfD4sNbTMp8IEWIPh
         rRYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g63j6COv;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf44.google.com (mail-qv1-xf44.google.com. [2607:f8b0:4864:20::f44])
        by gmr-mx.google.com with ESMTPS id m7si10809oim.3.2019.11.10.23.57.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 10 Nov 2019 23:57:48 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) client-ip=2607:f8b0:4864:20::f44;
Received: by mail-qv1-xf44.google.com with SMTP id q19so4512129qvs.5
        for <kasan-dev@googlegroups.com>; Sun, 10 Nov 2019 23:57:48 -0800 (PST)
X-Received: by 2002:a05:6214:8ee:: with SMTP id dr14mr22829788qvb.122.1573459067244;
 Sun, 10 Nov 2019 23:57:47 -0800 (PST)
MIME-Version: 1.0
References: <20191104020519.27988-1-walter-zh.wu@mediatek.com> <34bf9c08-d2f2-a6c6-1dbe-29b1456d8284@virtuozzo.com>
In-Reply-To: <34bf9c08-d2f2-a6c6-1dbe-29b1456d8284@virtuozzo.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Nov 2019 08:57:35 +0100
Message-ID: <CACT4Y+bfGrJemwyMVqd2Kt19mF2i=3GwXRKHP0qGJaT_5OhSCA@mail.gmail.com>
Subject: Re: [PATCH v3 1/2] kasan: detect negative size in memory operation function
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Walter Wu <walter-zh.wu@mediatek.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=g63j6COv;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44
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

On Fri, Nov 8, 2019 at 11:32 PM Andrey Ryabinin <aryabinin@virtuozzo.com> wrote:
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 6814d6d6a023..4ff67e2fd2db 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -99,10 +99,14 @@ bool __kasan_check_write(const volatile void *p, unsigned int size)
> >  }
> >  EXPORT_SYMBOL(__kasan_check_write);
> >
> > +extern bool report_enabled(void);
> > +
> >  #undef memset
> >  void *memset(void *addr, int c, size_t len)
> >  {
> > -     check_memory_region((unsigned long)addr, len, true, _RET_IP_);
> > +     if (report_enabled() &&
> > +         !check_memory_region((unsigned long)addr, len, true, _RET_IP_))
> > +             return NULL;
> >
> >       return __memset(addr, c, len);
> >  }
> > @@ -110,8 +114,10 @@ void *memset(void *addr, int c, size_t len)
> >  #undef memmove
> >  void *memmove(void *dest, const void *src, size_t len)
> >  {
> > -     check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > -     check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> > +     if (report_enabled() &&
> > +        (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> > +         !check_memory_region((unsigned long)dest, len, true, _RET_IP_)))
> > +             return NULL;
> >
> >       return __memmove(dest, src, len);
> >  }
> > @@ -119,8 +125,10 @@ void *memmove(void *dest, const void *src, size_t len)
> >  #undef memcpy
> >  void *memcpy(void *dest, const void *src, size_t len)
> >  {
> > -     check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > -     check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> > +     if (report_enabled() &&
>
>             report_enabled() checks seems to be useless.
>
> > +        (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> > +         !check_memory_region((unsigned long)dest, len, true, _RET_IP_)))
> > +             return NULL;
> >
> >       return __memcpy(dest, src, len);
> >  }
> > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > index 616f9dd82d12..02148a317d27 100644
> > --- a/mm/kasan/generic.c
> > +++ b/mm/kasan/generic.c
> > @@ -173,6 +173,11 @@ static __always_inline bool check_memory_region_inline(unsigned long addr,
> >       if (unlikely(size == 0))
> >               return true;
> >
> > +     if (unlikely((long)size < 0)) {
>
>         if (unlikely(addr + size < addr)) {
>
> > +             kasan_report(addr, size, write, ret_ip);
> > +             return false;
> > +     }
> > +
> >       if (unlikely((void *)addr <
> >               kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
> >               kasan_report(addr, size, write, ret_ip);
> > diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
> > index 36c645939bc9..52a92c7db697 100644
> > --- a/mm/kasan/generic_report.c
> > +++ b/mm/kasan/generic_report.c
> > @@ -107,6 +107,24 @@ static const char *get_wild_bug_type(struct kasan_access_info *info)
> >
> >  const char *get_bug_type(struct kasan_access_info *info)
> >  {
> > +     /*
> > +      * If access_size is negative numbers, then it has three reasons
> > +      * to be defined as heap-out-of-bounds bug type.
> > +      * 1) Casting negative numbers to size_t would indeed turn up as
> > +      *    a large size_t and its value will be larger than ULONG_MAX/2,
> > +      *    so that this can qualify as out-of-bounds.
> > +      * 2) If KASAN has new bug type and user-space passes negative size,
> > +      *    then there are duplicate reports. So don't produce new bug type
> > +      *    in order to prevent duplicate reports by some systems
> > +      *    (e.g. syzbot) to report the same bug twice.
> > +      * 3) When size is negative numbers, it may be passed from user-space.
> > +      *    So we always print heap-out-of-bounds in order to prevent that
> > +      *    kernel-space and user-space have the same bug but have duplicate
> > +      *    reports.
> > +      */
>
> Completely fail to understand 2) and 3). 2) talks something about *NOT* producing new bug
> type, but at the same time you code actually does that.
> 3) says something about user-space which have nothing to do with kasan.

The idea was to use one of the existing bug titles so that syzbot does
not produce 2 versions for OOBs where size is user-controlled. We
don't know if it's overflow from heap, global or stack, but heap is
the most common bug, so saying heap overflow will reduce chances of
producing duplicates the most.
But for all of this to work we do need to use one of the existing bug titles.

> > +     if ((long)info->access_size < 0)
>
>         if (info->access_addr + info->access_size < info->access_addr)
>
> > +             return "heap-out-of-bounds";
> > +
> >       if (addr_has_shadow(info->access_addr))
> >               return get_shadow_bug_type(info);
> >       return get_wild_bug_type(info);
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 621782100eaa..c79e28814e8f 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -446,7 +446,7 @@ static void print_shadow_for_address(const void *addr)
> >       }
> >  }
> >
> > -static bool report_enabled(void)
> > +bool report_enabled(void)
> >  {
> >       if (current->kasan_depth)
> >               return false;
> > diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> > index 0e987c9ca052..b829535a3ad7 100644
> > --- a/mm/kasan/tags.c
> > +++ b/mm/kasan/tags.c
> > @@ -86,6 +86,11 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
> >       if (unlikely(size == 0))
> >               return true;
> >
> > +     if (unlikely((long)size < 0)) {
>
>         if (unlikely(addr + size < addr)) {
>
> > +             kasan_report(addr, size, write, ret_ip);
> > +             return false;
> > +     }
> > +
> >       tag = get_tag((const void *)addr);
> >
> >       /*
> > diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
> > index 969ae08f59d7..f7ae474aef3a 100644
> > --- a/mm/kasan/tags_report.c
> > +++ b/mm/kasan/tags_report.c
> > @@ -36,6 +36,24 @@
> >
> >  const char *get_bug_type(struct kasan_access_info *info)
> >  {
> > +     /*
> > +      * If access_size is negative numbers, then it has three reasons
> > +      * to be defined as heap-out-of-bounds bug type.
> > +      * 1) Casting negative numbers to size_t would indeed turn up as
> > +      *    a large size_t and its value will be larger than ULONG_MAX/2,
> > +      *    so that this can qualify as out-of-bounds.
> > +      * 2) If KASAN has new bug type and user-space passes negative size,
> > +      *    then there are duplicate reports. So don't produce new bug type
> > +      *    in order to prevent duplicate reports by some systems
> > +      *    (e.g. syzbot) to report the same bug twice.
> > +      * 3) When size is negative numbers, it may be passed from user-space.
> > +      *    So we always print heap-out-of-bounds in order to prevent that
> > +      *    kernel-space and user-space have the same bug but have duplicate
> > +      *    reports.
> > +      */
> > +     if ((long)info->access_size < 0)
>
>         if (info->access_addr + info->access_size < info->access_addr)
>
> > +             return "heap-out-of-bounds";
> > +
> >  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> >       struct kasan_alloc_meta *alloc_meta;
> >       struct kmem_cache *cache;
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbfGrJemwyMVqd2Kt19mF2i%3D3GwXRKHP0qGJaT_5OhSCA%40mail.gmail.com.
