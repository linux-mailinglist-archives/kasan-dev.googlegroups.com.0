Return-Path: <kasan-dev+bncBAABBWXPUTXAKGQEGGGHPIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id 590FFF71E6
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Nov 2019 11:28:43 +0100 (CET)
Received: by mail-ua1-x93b.google.com with SMTP id b19sf4967874uak.5
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Nov 2019 02:28:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573468122; cv=pass;
        d=google.com; s=arc-20160816;
        b=SaE1VV6MJE81q7xcM34Gik+T+nUomtmBt1Qv4d8rwXnqI3R6P4a5Y4ZDbeGgkxq8DK
         n+lMk0BLd6rKag7PixXSPjW7WEQj0grP63g7pA/KtTwpVAdgqrORom7jSs2fU+jxR4h8
         7wxQs8CLUlNbddmC3zZxpJK9XeGLhenrAFq4bo+D0u5YOOfXTi+B0bFm06BZLMyCMfZe
         Nu6GbGRlkqALub4eu6jSuOdRl1ZubD5YZNxvkalN5Du9XOqvMJbNxJsKSepguGRJs7IA
         hNKYcOphDS6bwypS1+hfKCpMecZ0c/K9zyyNqEL03GbSEVVv91Cj+ov5CJMxIDTkYHFV
         wZKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=XZMCqL0p4Y9dFNnyvJGvlDwAE4jc7n5uuPG09S1aLFY=;
        b=z3yUEcHbIonpW6RHoT+Ry1iiDWByCNlFvNGyklXgUcPnQaR2eO25w3M5H74nJko0v1
         egF2WVvoGLdQOeqry/P+LAWyKMfXmG/tCGf2OKMykOIAPYLNke3t4IPHTwNs+v2fqwkR
         l7sCf61TfJLsE3EViRKkcyUcxk9ImFhQPKvrOV7Qbiov9rnnG2LG7BnqtHx8pIXMWKs+
         8BPO8JyvrDKDG0RiGaoQb6hwCGLnxIULFoTceqpzjZ6vilk40lgDefCUEx7+fTjipc+h
         YxGRlZL4al2YDIgZavsqMU/To3AnJ/AmdpOozLxGGhsI+UzIe3Pfu0TvTFNtNgyC7XRV
         wBZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=X3BPNePR;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XZMCqL0p4Y9dFNnyvJGvlDwAE4jc7n5uuPG09S1aLFY=;
        b=JUwf+9usivawTcrKbLAGqpnFA6TUtHfT//XLjtWwk++qfjYXUEaHC8BGHPfVIdTefN
         MlfAHKY+5jxTDXqlcV5/kolBcca9ZMazTQ8n6b0tLrUQ7XNALFnN9WuCskiyDJme91zH
         U7eUl04/uOC2DrIF2sVfi5O1EdvDYmWvIki0i9nsKc7gts6AKtDK2tPrfYYfwUGFdp+i
         rqxbBgXeygyyUObyXmMpsiS7p/k1xwb0g+KKlf1TBrxkAG5pOPuWUXG62s05hhIWsgxw
         vQhoH352vRaUDiRgRDF0lHYpXj/xw0/ZamuD+layAblBdrI+VQjqpX7ekwJyqdSZV/Rb
         Gjtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XZMCqL0p4Y9dFNnyvJGvlDwAE4jc7n5uuPG09S1aLFY=;
        b=kbFpwbPxK+alzqDo+eOmPxewH0OxD4NDa1s7x5wWG4T02H9fZf+ppD0z3RcmFbGSih
         Oi5OZaVkGP73O3uIVByib1NlemNDKRveMaaLyR3aER15ZIIZIJRE65nPgeBB3xDsilUa
         gaZ/AHhr0oolN4adad1nJhQc+muOx8VWN6rkhMRf46X7PiJ993VGTG/q+XCOHEok8YBH
         YOJ1/7MUTeVMBZDOvZ5jFNKnAc29ANm4AtM1AQh/nyKZtEJTDfpbjr3+pTFoo6Km3gD3
         9R31XkI67KKN941tglvdCkrHPIvN6TYjoAmuMNzmMBwSJBNvTd06AxjOZ42D1MzXhkk4
         M47w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUmnW/q/5abiUT6G4uorHKEYw3HFnq0SHZmY6XsqjsqNUt5k2lm
	II2TMG9geiUgBRXtQZxiB/E=
X-Google-Smtp-Source: APXvYqwQLR19N8ZMD3dTQxPpPTYYssojEC/U+BvnVDe5iUftVY/wGTmPnPFye2UeQ7Wh4u0p+f66HQ==
X-Received: by 2002:a05:6102:3115:: with SMTP id e21mr15517827vsh.8.1573468122247;
        Mon, 11 Nov 2019 02:28:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:5004:: with SMTP id e4ls587339vkb.6.gmail; Mon, 11 Nov
 2019 02:28:41 -0800 (PST)
X-Received: by 2002:ac5:c196:: with SMTP id z22mr17327077vkb.93.1573468121872;
        Mon, 11 Nov 2019 02:28:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573468121; cv=none;
        d=google.com; s=arc-20160816;
        b=EW6j4hSkTOOuu1/4FFzf6btJYVXoOtEkJT47ZlB6F3xqel5D3hjV3PQzbtk6xNMgfU
         y7s1oFKfKYO4Wl1GrjWEoRQQRD+oD3EnCU0r10otGmKeDOUxPxXUuOGjDLuTV5OucT65
         d9kAcMeN3p9Nk74BVoxXqiQNYDlwQb1b2E8pGdnRYMAzyZsUMEimQF07ktDynZjBcKKr
         dje7NiFLqBTKJVor0ZnJkBGdc5QafmKXpOJ3WbzWVV67Yvdh4onWxNUgqlM0HIQrJHd/
         2N69DJ9hLNzferqSyWXLl/iT5vksJD3yJVPk11W7SbWsJMwtLwUmN2nT97eoRLnJEKZI
         1xCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=Uo09G+Mt+uFPoRjbYnLMUPPU/rQnCSKkFsV6CT6/YM4=;
        b=b5wBBo1NxgQ1bx/KVV75roZwpbjLrPQMJy1kPz1HJfDzPK4BG6PhigTNImL/6qDrsN
         W6Il//f3AlnTKGq9HntDepB4aNgjPSsRiJqe/Ull/SuQqE1uLoIY4qr9+o19v869nPYw
         jG862j93lN2BPyq1sKV+3WqBzuRocOUgBHiM7czyEflJB9bhjMcbGVMWIaOYC/ZcixIh
         tkMfgIF0MDHlzNMuUcPWfvEckZRN+/9vph7RmqDxtR7cYha9Ym00ujAKCHLwFmP4yvp1
         zr7QpcxArdwuD0WEJEzOrctNk1tcU8F6856daa3n5VFsAVxDUmWMhSyk0a6/s8AUWAAw
         27Mw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=X3BPNePR;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id f22si814106uan.1.2019.11.11.02.28.40
        for <kasan-dev@googlegroups.com>;
        Mon, 11 Nov 2019 02:28:40 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 5a058e0fb6104c5ca2f49ce08d323b88-20191111
X-UUID: 5a058e0fb6104c5ca2f49ce08d323b88-20191111
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 905569529; Mon, 11 Nov 2019 18:28:34 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Mon, 11 Nov 2019 18:28:31 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Mon, 11 Nov 2019 18:28:30 +0800
Message-ID: <1573468113.20611.61.camel@mtksdccf07>
Subject: Re: [PATCH v3 1/2] kasan: detect negative size in memory operation
 function
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, kasan-dev
	<kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, LKML
	<linux-kernel@vger.kernel.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>
Date: Mon, 11 Nov 2019 18:28:33 +0800
In-Reply-To: <CACT4Y+bxWCF0WCkVxi+Qq3pztAXf2g-eBG5oexmQsQ65xrmiRw@mail.gmail.com>
References: <20191104020519.27988-1-walter-zh.wu@mediatek.com>
	 <34bf9c08-d2f2-a6c6-1dbe-29b1456d8284@virtuozzo.com>
	 <1573456464.20611.45.camel@mtksdccf07>
	 <757f0296-7fa0-0e5e-8490-3eca52da41ad@virtuozzo.com>
	 <1573467150.20611.57.camel@mtksdccf07>
	 <CACT4Y+bxWCF0WCkVxi+Qq3pztAXf2g-eBG5oexmQsQ65xrmiRw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=X3BPNePR;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Mon, 2019-11-11 at 11:17 +0100, Dmitry Vyukov wrote:
> On Mon, Nov 11, 2019 at 11:12 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > On 11/11/19 10:14 AM, Walter Wu wrote:
> > > > On Sat, 2019-11-09 at 01:31 +0300, Andrey Ryabinin wrote:
> > > >>
> > > >> On 11/4/19 5:05 AM, Walter Wu wrote:
> > > >>
> > > >>>
> > > >>> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > > >>> index 6814d6d6a023..4ff67e2fd2db 100644
> > > >>> --- a/mm/kasan/common.c
> > > >>> +++ b/mm/kasan/common.c
> > > >>> @@ -99,10 +99,14 @@ bool __kasan_check_write(const volatile void *p, unsigned int size)
> > > >>>  }
> > > >>>  EXPORT_SYMBOL(__kasan_check_write);
> > > >>>
> > > >>> +extern bool report_enabled(void);
> > > >>> +
> > > >>>  #undef memset
> > > >>>  void *memset(void *addr, int c, size_t len)
> > > >>>  {
> > > >>> - check_memory_region((unsigned long)addr, len, true, _RET_IP_);
> > > >>> + if (report_enabled() &&
> > > >>> +     !check_memory_region((unsigned long)addr, len, true, _RET_IP_))
> > > >>> +         return NULL;
> > > >>>
> > > >>>   return __memset(addr, c, len);
> > > >>>  }
> > > >>> @@ -110,8 +114,10 @@ void *memset(void *addr, int c, size_t len)
> > > >>>  #undef memmove
> > > >>>  void *memmove(void *dest, const void *src, size_t len)
> > > >>>  {
> > > >>> - check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > > >>> - check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> > > >>> + if (report_enabled() &&
> > > >>> +    (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> > > >>> +     !check_memory_region((unsigned long)dest, len, true, _RET_IP_)))
> > > >>> +         return NULL;
> > > >>>
> > > >>>   return __memmove(dest, src, len);
> > > >>>  }
> > > >>> @@ -119,8 +125,10 @@ void *memmove(void *dest, const void *src, size_t len)
> > > >>>  #undef memcpy
> > > >>>  void *memcpy(void *dest, const void *src, size_t len)
> > > >>>  {
> > > >>> - check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > > >>> - check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> > > >>> + if (report_enabled() &&
> > > >>
> > > >>             report_enabled() checks seems to be useless.
> > > >>
> > > >
> > > > Hi Andrey,
> > > >
> > > > If it doesn't have report_enable(), then it will have below the error.
> > > > We think it should be x86 shadow memory is invalid value before KASAN
> > > > initialized, it will have some misjudgments to do directly return when
> > > > it detects invalid shadow value in memset()/memcpy()/memmove(). So we
> > > > add report_enable() to avoid this happening. but we should only use the
> > > > condition "current->kasan_depth == 0" to determine if KASAN is
> > > > initialized. And we try it is pass at x86.
> > > >
> > >
> > > Ok, I see. It just means that check_memory_region() return incorrect result in early stages of boot.
> > > So, the right way to deal with this would be making kasan_report() to return bool ("false" if no report and "true" if reported)
> > > and propagate this return value up to check_memory_region().
> > >
> > This changes in v4.
> >
> > >
> > > >>> diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
> > > >>> index 36c645939bc9..52a92c7db697 100644
> > > >>> --- a/mm/kasan/generic_report.c
> > > >>> +++ b/mm/kasan/generic_report.c
> > > >>> @@ -107,6 +107,24 @@ static const char *get_wild_bug_type(struct kasan_access_info *info)
> > > >>>
> > > >>>  const char *get_bug_type(struct kasan_access_info *info)
> > > >>>  {
> > > >>> + /*
> > > >>> +  * If access_size is negative numbers, then it has three reasons
> > > >>> +  * to be defined as heap-out-of-bounds bug type.
> > > >>> +  * 1) Casting negative numbers to size_t would indeed turn up as
> > > >>> +  *    a large size_t and its value will be larger than ULONG_MAX/2,
> > > >>> +  *    so that this can qualify as out-of-bounds.
> > > >>> +  * 2) If KASAN has new bug type and user-space passes negative size,
> > > >>> +  *    then there are duplicate reports. So don't produce new bug type
> > > >>> +  *    in order to prevent duplicate reports by some systems
> > > >>> +  *    (e.g. syzbot) to report the same bug twice.
> > > >>> +  * 3) When size is negative numbers, it may be passed from user-space.
> > > >>> +  *    So we always print heap-out-of-bounds in order to prevent that
> > > >>> +  *    kernel-space and user-space have the same bug but have duplicate
> > > >>> +  *    reports.
> > > >>> +  */
> > > >>
> > > >> Completely fail to understand 2) and 3). 2) talks something about *NOT* producing new bug
> > > >> type, but at the same time you code actually does that.
> > > >> 3) says something about user-space which have nothing to do with kasan.
> > > >>
> > > > about 2)
> > > > We originally think the heap-out-of-bounds is similar to
> > > > heap-buffer-overflow, maybe we should change the bug type to
> > > > heap-buffer-overflow.
> > >
> > > There is no "heap-buffer-overflow".
> > >
> > If I remember correctly, "heap-buffer-overflow" is one of existing bug
> > type in user-space? Or you want to expect to see an existing bug type in
> > kernel space?
> 
> Existing bug in KASAN.
> KASAN and ASAN bugs will never match regardless of what we do. They
> are simply in completely different code. So aligning titles between
> kernel and userspace will not lead to any better deduplication.

Ok, it seems like to print "out-of-bounds". Simple and easy to know it.
Thanks Dmitry.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1573468113.20611.61.camel%40mtksdccf07.
