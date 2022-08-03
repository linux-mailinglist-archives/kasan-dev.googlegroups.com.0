Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJ5VVOLQMGQETL2LOYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 85EC3589336
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Aug 2022 22:29:28 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id e17-20020a656491000000b0041b51b1c9edsf7249018pgv.12
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Aug 2022 13:29:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659558567; cv=pass;
        d=google.com; s=arc-20160816;
        b=Flm+nLOx2HJXViS9CY7UgVRewc/tpzmSxKHMfgIjtGeNLZhtbSmqvp31vnsIfa2/HH
         Bgs9yu8BItvLDZ7fnoWTAiFE2uQzJfHOfqnzA0fVK3bSWkcbTHrgwp3MBEkh6SQK6oYP
         Eim/+tCVQw+NUN+PTCuq+lga37+FCbEQMsTkgLSiOOpxVU2uijV8l++qRmSOvboPuQ0j
         DzquqrOHbufRh64WxlANRLPz8oBRsEsyWxCTyl9ToA6PUrHaVtmcgYK1pJ6hCMiaejX3
         KF9a3V5M2Ks8HpkyobL5rhQJngoW8bvfz7L/3jeiWTbvm7oz0cuaG7GRU4JbJZdcGb0B
         Dm3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+ZrotBoRFS6x80YlqFydtU3S7wcj7VJe2tSRd3ihJMo=;
        b=d9hjlczzGfBrHHaIFOe89c2s8RmmSHCKowoII5lRCZ6+qBgpi0fFZA+Y00GUci2Eu9
         wTa/pM2mCwfUQORX/b+gqhgjOhF0fO8k2xXznFTOjzDOsXhin8n7Ex4gsm5ZiRmTjIhm
         TWOgGQdHWKOJKlICUJEvI0H5xRqgTF23EWuRSk9Xr9ZFCaGFGIg61b0xN0eSz15hw+p/
         L9XGPgK1tKSwdCSsCdhucnhxxJ8dedtqUXbhekKfzwwm+dBxzfUajTWeKFbWUbMfPQ+V
         4aJj8GcgBL524b0g7TfvAsijzJQvIR4sh1A4TLrGGxyd3HZ2BwG7vIGYF2GhRLGCDaiR
         GJ3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dtquUVtE;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+ZrotBoRFS6x80YlqFydtU3S7wcj7VJe2tSRd3ihJMo=;
        b=L52pJMQ75aeGJ6g+D49Y+gCZ8KwIFIDgNij3K0md8Kz1k8Vqro8Lm1vyN5MZKB69Kv
         Rwm285W1x6V6etEgsnW75FNLY0vdY+6NYZLnB1AYrHF5whK8kYhy1rc5uA+yvsRlKNoj
         p+/nWSN9HJTnM7Bnj5PfJAGF9evLNM1qyAnn61f8YsTM42OyslTGE1czIY53KnQgtnK7
         PhxROAJ9UCJe6wgiSLojOCcT2a04lmUl2H7nQFETSOP+6gzh3ZR1LP4W1GUlZ6++D4aC
         gCrcYha7ZR1GNHrlk1SJUjzFinEr+LiMjYt2/jPtGdZnJ1ALBLLrO5Q+0mt7KmtSx1kt
         +GQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+ZrotBoRFS6x80YlqFydtU3S7wcj7VJe2tSRd3ihJMo=;
        b=KH7DcECpPlWveEXphaAcsMEMhY/9Z90W0GDJc3/siSWF4VRmgoKr21I91VP5p3VnP7
         lko8yRV2j6FOYy/k0w9bKYknz6ZmDW8fQ4YTqnqxy6nmvAHOHhRI1MNichKdwGBrdnLy
         NQKhGqp8R5WYzcMNdm7UykZT1pD6q+/QTNCTfFWtA/kbi0MTGpJCi0ds5UkR1z9BBzAi
         21uEim/fZSSlBbXJ0G4yWNjj8PzTNI984bz0P/jE5kUeWc+nXCGUl+0hCzWmMfxVwS46
         E6tys5D3dZJQLn+yLrlY64hhHTFduB9YwXM8OkqNnBFIdD3FsV8e6fbdHUa4jwpy9SEy
         I5JQ==
X-Gm-Message-State: ACgBeo3NAtxD+Ascjvplx/FNn8N8bM/6rC8U2BQ/2PCJSk3lcww2TcXw
	7SXEt83v4lVhEYpH65+QhRA=
X-Google-Smtp-Source: AA6agR460iwUWuQaUIIaMM4zTnPki7D4RJLiPrOTdaf0xxmebq87Kdei0+iM5yMnPn046z31bl6cjg==
X-Received: by 2002:a17:90b:3a88:b0:1f5:59e0:437 with SMTP id om8-20020a17090b3a8800b001f559e00437mr1720052pjb.199.1659558567165;
        Wed, 03 Aug 2022 13:29:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f593:b0:1f4:eef0:ca1d with SMTP id
 ct19-20020a17090af59300b001f4eef0ca1dls1411379pjb.1.-pod-preprod-gmail; Wed,
 03 Aug 2022 13:29:26 -0700 (PDT)
X-Received: by 2002:a17:902:6bcb:b0:16c:e9b7:347 with SMTP id m11-20020a1709026bcb00b0016ce9b70347mr27748154plt.150.1659558566308;
        Wed, 03 Aug 2022 13:29:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659558566; cv=none;
        d=google.com; s=arc-20160816;
        b=ilp1NwQSF4u4tTsOhLbbpVHNEo/grjpws95YwDsx4xvRUpZYVk1o9sShwMxPj3lF2X
         uAckU0JOM6aGOyULDFF2XZnegvugwacDm3EdZCysHmohzvpPlUXDJsmKgD9d7T6JatRQ
         Gjio29d37HUYklCOB8aq7A4gu4WrqjE4mK0Hw7clXK45ZSNnVtILxa/msO7SRDOTHt9V
         EvI7ThDuqXn278wYmOQNTGGqrAf3EbQ1j93I6lpUH4+z9pmpLMzkE31kogmJ7mQPO6Mz
         /6tgZoPxCmuvLlJHzqRjvOSLsPExGpu9yM/p6ocPsEtRUUwBJqND/MEB5+AnEsxwHLUy
         x3RA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=C8saFETww7GFwNaVKj2+9mgk73FWbmx4D6GhCwjyv5M=;
        b=U+qR4YyMaDi/diQZXZUGxmhQbyvzrduvs5a1Tw+gD+5smGiJHfZ83NI+nbnMWQTSvC
         Tjp19TxouwMQvpCjaLvFPg2GxcNB5/V+KwZ77mTMPbHUs4Mhlo/8JbUNoCICpbc2tPGP
         IqRg+Zcoxo+HfuhxBU/wf1yiLt5eEvSdG87vyQIUhkQqqtsREKI6xKGGEjqPW3k9VPmn
         95tSSA67omKDamLudxdcMDR9qOHIo2bQnsD2AbXRmKhXUtlGtyrzho9JswpgJpMRHuXs
         N98HTThM8S0cnVqaP8zArrYjf2Qgo+ReX7DOZWiF2xxXcWSuijWCEy4OHSU7LZYwqWHy
         hMpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dtquUVtE;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb29.google.com (mail-yb1-xb29.google.com. [2607:f8b0:4864:20::b29])
        by gmr-mx.google.com with ESMTPS id a14-20020a170902ecce00b0016d5881a19dsi154982plh.2.2022.08.03.13.29.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Aug 2022 13:29:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) client-ip=2607:f8b0:4864:20::b29;
Received: by mail-yb1-xb29.google.com with SMTP id 21so7437867ybf.4
        for <kasan-dev@googlegroups.com>; Wed, 03 Aug 2022 13:29:26 -0700 (PDT)
X-Received: by 2002:a25:2454:0:b0:67a:7426:25d9 with SMTP id
 k81-20020a252454000000b0067a742625d9mr3223631ybk.93.1659558565851; Wed, 03
 Aug 2022 13:29:25 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1658189199.git.andreyknvl@google.com> <0e910197bfbcf505122f6dae2ee9b90ff8ee31f7.1658189199.git.andreyknvl@google.com>
 <CANpmjNMrwXxU0YCwvHo59RFDkoxA-MtdrRCSPoRW+KYG2ez-NQ@mail.gmail.com>
 <CA+fCnZcT2iXww90CfiByAvr58XHXShiER0x0J2v14hRzNNFe9w@mail.gmail.com> <CA+fCnZfU5AwAbei9NqtN+FstGLJYkRe7cZrYZN1wtcGbPkqVZQ@mail.gmail.com>
In-Reply-To: <CA+fCnZfU5AwAbei9NqtN+FstGLJYkRe7cZrYZN1wtcGbPkqVZQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Aug 2022 22:28:49 +0200
Message-ID: <CANpmjNPk13ib57zFzL1rmWiuhZVvS4bmD-yfoMJOYVWT1FdynQ@mail.gmail.com>
Subject: Re: [PATCH mm v2 30/33] kasan: implement stack ring for tag-based modes
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=dtquUVtE;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as
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

On Tue, 2 Aug 2022 at 22:45, Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Thu, Jul 21, 2022 at 10:41 PM Andrey Konovalov <andreyknvl@gmail.com> wrote:
> >
> > On Tue, Jul 19, 2022 at 1:41 PM Marco Elver <elver@google.com> wrote:
> > >
> > > > +       for (u64 i = pos - 1; i != pos - 1 - KASAN_STACK_RING_SIZE; i--) {
> > > > +               if (alloc_found && free_found)
> > > > +                       break;
> > > > +
> > > > +               entry = &stack_ring.entries[i % KASAN_STACK_RING_SIZE];
> > > > +
> > > > +               /* Paired with smp_store_release() in save_stack_info(). */
> > > > +               ptr = (void *)smp_load_acquire(&entry->ptr);
> > > > +
> > > > +               if (kasan_reset_tag(ptr) != info->object ||
> > > > +                   get_tag(ptr) != get_tag(info->access_addr))
> > > > +                       continue;
> > > > +
> > > > +               pid = READ_ONCE(entry->pid);
> > > > +               stack = READ_ONCE(entry->stack);
> > > > +               is_free = READ_ONCE(entry->is_free);
> > > > +
> > > > +               /* Try detecting if the entry was changed while being read. */
> > > > +               smp_mb();
> > > > +               if (ptr != (void *)READ_ONCE(entry->ptr))
> > > > +                       continue;
> > >
> > > I thought the re-validation is no longer needed because of the rwlock
> > > protection?
> >
> > Oh, yes, forgot to remove this. Will either do in v3 if there are more
> > things to fix, or will just send a small fix-up patch if the rest of
> > the series looks good.
> >
> > > The rest looks fine now.
> >
> > Thank you, Marco!
>
> Hi Marco,
>
> I'm thinking of sending a v3.
>
> Does your "The rest looks fine now" comment refer only to this patch
> or to the whole series? If it's the former, could you PTAL at the
> other patches?

I just looked again. Apart from the comments I just sent, overall it
looks fine (whole series).

Does test_kasan exercise the ring wrapping around? One thing that
might be worth doing is adding a multi-threaded stress test, where you
have 2+ threads doing lots of allocations, frees, and generating
reports.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPk13ib57zFzL1rmWiuhZVvS4bmD-yfoMJOYVWT1FdynQ%40mail.gmail.com.
