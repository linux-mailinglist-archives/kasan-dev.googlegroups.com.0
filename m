Return-Path: <kasan-dev+bncBCMIZB7QWENRB2GY3PXAKGQEYWCJJBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id E5685105AB0
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 20:58:33 +0100 (CET)
Received: by mail-ua1-x93a.google.com with SMTP id o5sf1139395uai.13
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 11:58:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574366313; cv=pass;
        d=google.com; s=arc-20160816;
        b=q+XkFIzm1BpkPNBWlQPDtXn5EVUr6NRVKKyJ1SbySqCuS1V/w5LMJmWqLlZSGjqccg
         rehhi5l9ZK0MCVqOJ7/4/Z/rBCX05GzrDg8oDmdzSkSqWpZDMrtYbCqhHHAxcgBa4Fgs
         EMI4MxXTSERykbD+nuZfVheLhp35UcM40hp4Mm99D5+U11oj+C0d724i+Cpab9pAM0ly
         CCd9sN6KEMKNLfKMPBMHqYBDdUMmnJ7PIwb/yf2BkTVTD8llITqGUNHnS5g7za3kP9BN
         hmO2VDwc5X10kEyVOxdmnprzenQB5O480bMmBXPzlyw2h8l+gygMYBe2B0TYEVGOlhvs
         IWpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=y2Vu1l2Wl2Fr2DP1lZz3IOPbXFFofasblXpMBpYMkoA=;
        b=Mm6+aVxxW+HuCjh5T8BKA1DegqkTdXcNH6CLRH1qrOA7iOyIzjkHKMJrV3b+6ZRSnJ
         KTDz17tl9YpG3AZP31y0K4VbWIXz0sAS41JoUS8cNjSA35AYmiY4D1h+9t+GXUINJxEn
         nVyseIkm4WDIRfBp4CGkpT8rxpya8vE8yb579zwKd4SP4rUsytWpJFfWz2yJXfQ/x6iU
         ftCgzSUkCIrArvhFKjY/QoxmBDUxX2RB7IM03GysoM/4zG+hskPx/ACuPT5tm41i0HBf
         l77g7lfQiTXtze6+PM9YK4Z/xrIzKtOk28sOHt6xUtZdvaX8XyxzExF79o9wTOW8hIvr
         +6Hw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Kd3uHXA1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y2Vu1l2Wl2Fr2DP1lZz3IOPbXFFofasblXpMBpYMkoA=;
        b=VPDz0u6xum5Nx1hpbHRfxHgvCjGDyqRnMBbvZGxIHT7RYax+jqeEjfKA3GHc6SmmGk
         FD+3+UIPFMhh1P5u8ZlxjUr/f/WAvz87e99xem+mq9Pxpq7peikbPJZ00JNr+bm/orUM
         pgpKyRKS7WBqspWzMj7atSX72bOvktONXtRRKC56zMVts8MPx4sEYHYTjGF4BQzTkOdw
         96+JYIpkge7p28taDMesOAsn5rsKNjuqAID9DiY1OzQpShl8aNLA+xGmN6F0ax9ARv5q
         EnoPJrMtgFxBNGWdOLSHtbWxsfqC72Zb66+ZCQQQW+AGDdSBegY9Wr/pSPUIPk7Q8Yh7
         fvAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y2Vu1l2Wl2Fr2DP1lZz3IOPbXFFofasblXpMBpYMkoA=;
        b=ecq3Wm1SoigwslubPTMFOKrcqFQ/N77YrNzWKt1HywCVQbjCWlhMK6G70PegO629KB
         wdsuunUQicp7UMHxd3zapgr+hobsnt6Ok2TqDH8Sosd4XMXHWELEZ8dl4vHuv4xRrWZS
         5hg9/NHNuZ1tGEcWjUZ5y2vKYbbf3oM15TvMXYNQtuYEPputneDZjovdFhYRmTIzv0X0
         e+KkrQDugHRwoo0gkHmAiFRe6kAzQpHf0WmwgcRdAQWD/tanAnVzLJjt5fGNu7MKXNcb
         xe+3b8yKGOPuC+ynC1SflJ4ZIaqR8wlyZY9h8LP257axSkrY2vgjjz48dX8gtVBSZ2sp
         S0sQ==
X-Gm-Message-State: APjAAAVkPvJL3Hsnzqq86GlOA3Ex7nBepc9evYUyfjUE5V/GVueT1kCd
	RhTLXQh2QyxrAGg9JrnqT1w=
X-Google-Smtp-Source: APXvYqwGwatY+Z7dS2UjzZK/eN5BIdbPrF1OnQhduxT7RCETqrckhD0vCSPJ+/r1/HQnPAHQOyesWQ==
X-Received: by 2002:a1f:e9c1:: with SMTP id g184mr7025506vkh.4.1574366312897;
        Thu, 21 Nov 2019 11:58:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c116:: with SMTP id d22ls902166vsj.14.gmail; Thu, 21 Nov
 2019 11:58:32 -0800 (PST)
X-Received: by 2002:a67:bd05:: with SMTP id y5mr7381315vsq.180.1574366312530;
        Thu, 21 Nov 2019 11:58:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574366312; cv=none;
        d=google.com; s=arc-20160816;
        b=PA5uC34V8cOzY7cszdPTzne7f9Ox145RZgPxgTii+Vww9gzF3DSAiQeKDL9ChYx2iO
         hIJtlMIQo3aSp2z90mOezZX9L2BVW6PxPMb3trb52rWGkLyZPvVdOHEYa2hOSsYi1lVZ
         SRDX+wVRM6rCqcxPjnvs3Loq0fwhBi18SfrYBut9L3hloWt9F/3dKQ5+dZ6o4c3sA5mz
         +V8QZvOX+WlBQjbIDDWV66UF9h6WcNgSC+OdU6xnG9YUGP3lO74CyUfbmwadyYUzjNKt
         JJIjZgcyGdN9DP/SY/I6POqIf6Pr9vMLPOlq82Dj+KjMgehAB+2tW9/DtxCo7yQqHTLv
         GFCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NrzxHrY8HSPigVP1ddvjUfQFh9GexeJHE6yrEfyJGn8=;
        b=IXAFQnZoZ+XGTvtZJRRSaty0lNsrd0H1tqVbZZGX2rquRCevGdAHLeiWHHptI0vo1F
         WKbsNVWJOBmREWJotwKh0IOR1q+oYfoev5FRQ46Qc9VQQeWLzhOmdkHkv/7Dz71kce9I
         jwgr5WHqr9UeP5bvUHKO3f3ptltq7dIxsoBtdHDzOLPtlv3ARaOKI/RcG8GR6/CRhex5
         HbzLxxKtrOJigKfLn6Vxsj1Qbi6Iaol2pHhcxb1gYZKWL7V0P8qOTC2cQt6jBgWAbRtS
         Bann+O0bvnmQIMMVPHvSP6ikpRF7g7qklPB1sLiAOwSlJtlnO7KIN+jDhYrnhMZx/uro
         pE8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Kd3uHXA1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id o206si218205vka.4.2019.11.21.11.58.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Nov 2019 11:58:32 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id q8so2425652qtr.10
        for <kasan-dev@googlegroups.com>; Thu, 21 Nov 2019 11:58:32 -0800 (PST)
X-Received: by 2002:aed:24af:: with SMTP id t44mr10377791qtc.57.1574366311591;
 Thu, 21 Nov 2019 11:58:31 -0800 (PST)
MIME-Version: 1.0
References: <20191112065302.7015-1-walter-zh.wu@mediatek.com> <040479c3-6f96-91c6-1b1a-9f3e947dac06@virtuozzo.com>
In-Reply-To: <040479c3-6f96-91c6-1b1a-9f3e947dac06@virtuozzo.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Nov 2019 20:58:19 +0100
Message-ID: <CACT4Y+botuVF6KanfRrudDguw7HGkJ1mrwvxYZQQF0eWoo-Lxw@mail.gmail.com>
Subject: Re: [PATCH v4 1/2] kasan: detect negative size in memory operation function
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Walter Wu <walter-zh.wu@mediatek.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Kd3uHXA1;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841
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

On Thu, Nov 21, 2019 at 1:27 PM Andrey Ryabinin <aryabinin@virtuozzo.com> wrote:
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 6814d6d6a023..4bfce0af881f 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -102,7 +102,8 @@ EXPORT_SYMBOL(__kasan_check_write);
> >  #undef memset
> >  void *memset(void *addr, int c, size_t len)
> >  {
> > -     check_memory_region((unsigned long)addr, len, true, _RET_IP_);
> > +     if (!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
> > +             return NULL;
> >
> >       return __memset(addr, c, len);
> >  }
> > @@ -110,8 +111,9 @@ void *memset(void *addr, int c, size_t len)
> >  #undef memmove
> >  void *memmove(void *dest, const void *src, size_t len)
> >  {
> > -     check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > -     check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> > +     if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> > +         !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> > +             return NULL;
> >
> >       return __memmove(dest, src, len);
> >  }
> > @@ -119,8 +121,9 @@ void *memmove(void *dest, const void *src, size_t len)
> >  #undef memcpy
> >  void *memcpy(void *dest, const void *src, size_t len)
> >  {
> > -     check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > -     check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> > +     if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> > +         !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> > +             return NULL;
> >
>
> I realized that we are going a wrong direction here. Entirely skipping mem*() operation on any
> poisoned shadow value might only make things worse. Some bugs just don't have any serious consequences,
> but skipping the mem*() ops entirely might introduce such consequences, which wouldn't happen otherwise.
>
> So let's keep this code as this, no need to check the result of check_memory_region().

I suggested it.

For our production runs it won't matter, we always panic on first report.
If one does not panic, there is no right answer. You say: _some_ bugs
don't have any serious consequences, but skipping the mem*() ops
entirely might introduce such consequences. The opposite is true as
well, right? :) And it's not hard to come up with a scenario where
overwriting memory after free or out of bounds badly corrupts memory.
I don't think we can somehow magically avoid bad consequences in all
cases.

What I was thinking about is tests. We need tests for this. And we
tried to construct tests specifically so that they don't badly corrupt
memory (e.g. OOB/UAF reads, or writes to unused redzones, etc), so
that it's possible to run all of them to completion reliably. Skipping
the actual memory options allows to write such tests for all possible
scenarios. That's was my motivation.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbotuVF6KanfRrudDguw7HGkJ1mrwvxYZQQF0eWoo-Lxw%40mail.gmail.com.
