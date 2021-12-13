Return-Path: <kasan-dev+bncBDW2JDUY5AORBWED36GQMGQEC25C3HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FFBD47371C
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:57:45 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id a26-20020ac8001a000000b002b6596897dcsf24673320qtg.19
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:57:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432664; cv=pass;
        d=google.com; s=arc-20160816;
        b=hzmSIrr10VhIkiLKUuMFTL0RRsYSofJYQ1Eyho/eJ5B/9rFtT9q0yVwLOhV6L8Dzeu
         TBH0UixmXLxpLhYhlc+Un42X2gBlWGu4fiY9CSDhC287AqAn9CmhSgG6JQTR90Hhaplf
         O2v5ztOjuOgsksOC8z4yXh6hhchIHa8thm4AK2wlPMIxgo5/0SzWFWB4jvExLRO45PSe
         MpTzwi5ueOAAWtkZ3iITqwZSIFdLNWXucwR978FekaVK2g3s3XsJGfzwXogMYNEiFZok
         t4+CTjfbgnan6PnBxvbMr3jKhQuEl67oVqhEjnyRHF7SlYosDYREzaw74EaifdvwQ6kf
         tmWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=z4itQX8Vm8g0olgkqs1IfvTkr92SnobjwNW44fJXLKU=;
        b=Ze2bp62tKeNmrLdm54L0npP7LFzzLruA17V6DxBS8R0QZt72LnJPRaNKXbFz/idWbL
         2WLY/IDRrghOocfJfUkvi7OQHNpgSAv8vIEA1jAbQT/r3zCl1v8z00K3STdJNDUzZLj4
         oEDw5O7wSUTZSQqImhWs2r8wTn+eQBcrnwISEKhI8xcb5U0U9vdh0ywdk3Ql7Di2dI4O
         nha6+h3/TNTCpZgysFiEfBjHBqtxtaiLzx1U8PtTx/tbsoFIOqDiTyp/OFRQiNcj3VcA
         7d75hPg4YL49KbsCiVd9WXIZiP2r53ZQZT1m7gYEz9EwggkVGdK1co4/khi7qJ8UkHaf
         1cRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=AF0AV2AR;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=z4itQX8Vm8g0olgkqs1IfvTkr92SnobjwNW44fJXLKU=;
        b=FBWqz35IgK3QrVV1OuZhJWXem7xJ9tYLbjONnpb2bg/pkihhJLfYRr8E6RGLgkpDlB
         USzfprG9ZLapCNpPwPDKXuwwZ7JHIS+Icb+0ILxTtCb5P+B0cyogh+ZQRC/HLi0PYmJJ
         ro4PUd3njsvzpS+BhyDPJnwiNlRREovkHRnCodWH17hfGBVQDV0AMQKWkmq5nrMzdmO7
         jKN9sBoQaWPG145uNECCln1bDW37VfE1trJrcx3z6OkTWLKGPTcvGNOs2cKJqUNRoA3x
         fpdzcXxPDiJfYBq6nu7AVvrpwKdX/SyRLEPOn/g15t2bjOI0z9H8Y2rMJst++GN/Uwhv
         5Z+w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=z4itQX8Vm8g0olgkqs1IfvTkr92SnobjwNW44fJXLKU=;
        b=FMVJT1SXfCeFvsD37w8DbZ3vbUhLz/G/CmpwcUdyf0EpiGZTTzhCr2tEQMkwHxfpBg
         21WnUCxROwRDzYEGomrcCzj7yB+fe2kiFnGE0YDbNhtibNGr3WC6IF/4qqBCXllAn90v
         DHQN15/ziC755u+lwMsm94+q+xb2UZ2Q4VVJjQ7gt1b0PwqRRE+U/G0SYwn7jlGnYvF5
         Sh1Yv7Wq1MEpLx3IhuhD9LASeUOx85weyDmrItYkchhviyX9Af7lKeDsIAz9KfIjmsxn
         1wHuAgd6kyaN80/WH1lutk0JMPsdPoZz0raeRk42ITZi3xGh0XSGD6zvf/n6p4m8/Cxi
         3qog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=z4itQX8Vm8g0olgkqs1IfvTkr92SnobjwNW44fJXLKU=;
        b=0Yuyv7IEYgCh4+qEaE8Q+r/E9UJG7P8INC7WMDHJTL1yB8N8G/unuGt7qpV4v73M0C
         gQPTLCKRUR+4a+FXcZby/74NFK2gsqw3GnM/2b8rBQe/fns1x4lF67ppCYYki6X4hIyO
         XlzmsWZlhyCbOc/mtKZ0si6YKe5mYBJPjyxC3x/JRx/TxjLiwMdMmbQiDugRXbQVOC37
         HriuwEwSWof1ruOQueZHxJaPlfDZ/JzmY1X2EfN9pszz9sDU824UFIJRFQ5XsNT/KI98
         MfOQKu7uRgINBQb9zyfrYdtdPHWo4OaBqfrrj6KfQwCxaHdwem/7v1xK0DvVQqcF5I2p
         bqmA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ZwHp04+4Mokcie70/cpwJ0QLbYRQWqlSoeo0cRMhY2htl1Lkz
	H3PI8VdTxiIcoh8SUmJUJmY=
X-Google-Smtp-Source: ABdhPJxUbjDzPQMZBNbLDE8waCvpWCu6kLtM+PAz25CBoD+LCvUlPDUArT8j3bUieQ/xen+wBE4FBw==
X-Received: by 2002:ac8:7dc9:: with SMTP id c9mr1263306qte.541.1639432664482;
        Mon, 13 Dec 2021 13:57:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7f83:: with SMTP id z3ls13641884qtj.1.gmail; Mon, 13 Dec
 2021 13:57:44 -0800 (PST)
X-Received: by 2002:a05:622a:350:: with SMTP id r16mr1277460qtw.389.1639432664090;
        Mon, 13 Dec 2021 13:57:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432664; cv=none;
        d=google.com; s=arc-20160816;
        b=o/GSwYBzc7eZNPnCTFmrffC6VCgkjAbMBozmK+8jCeMAkZTviLZC3HmITTF6HsLKX2
         /3qKefA7K+th+b394uJruUtwn3bzOKLDxlM5vEFGcOkMhNGe99DFDT/kf74pI77w8VJ7
         iPFWp6C1Z9coAuQyREDJHzTZyg7RAiV9dTkLJUKv67r1bWgndhaxfWFs0nixnaDBp38I
         a6izGbA0tRbW/DTuVMcaJZhtWbJ9bqpzUMyRdimW66XaLDgROy9K73GxMZxyKJFPf8Lb
         JrnIh9bTSOJeRUrsViReMA/6YbfFzfKgwI1O68MXJcfNsDv6C7x2YVnI1F+CRDP10hJ2
         E+Aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Izx2PBJI6AWPZSxP/szrg017GVN03v7urPWV5485xFY=;
        b=fiLWo7ZJUkArUEoIpBs7i5r4YRPF+pvzzgOMrLy+vzRAf8VKzdNJlxbO2FLYwhwMiE
         BBLcrBijVIknYhvAGD1R5OHLn0yskc/lh/wGUS5ZS7v0p3HaoQGpREyLh0eVzqHtPnbV
         D7j7kl/DPVYCrZ2NylvJ3vUbfwnHIRNGt8IrFgDNy2rX9V3fGbyrUGDiPyXYvZG1bswh
         UcD4XazriiR8C/vuiNCIq7RAk0V0DdwLyFRITMKpnw4psf2snwbuwHSLNcm1nM4pRf+m
         jIDTCc5aoemeYczoY8ulZAzHp5zUBFj70VuQv15W+cKzdxP2voKSXuwevzb7s6hgfzWB
         xkvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=AF0AV2AR;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2e.google.com (mail-io1-xd2e.google.com. [2607:f8b0:4864:20::d2e])
        by gmr-mx.google.com with ESMTPS id v12si435828qtc.2.2021.12.13.13.57.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Dec 2021 13:57:44 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2e as permitted sender) client-ip=2607:f8b0:4864:20::d2e;
Received: by mail-io1-xd2e.google.com with SMTP id p23so20632910iod.7
        for <kasan-dev@googlegroups.com>; Mon, 13 Dec 2021 13:57:44 -0800 (PST)
X-Received: by 2002:a05:6602:2d04:: with SMTP id c4mr1017624iow.56.1639432663912;
 Mon, 13 Dec 2021 13:57:43 -0800 (PST)
MIME-Version: 1.0
References: <cover.1638825394.git.andreyknvl@google.com> <72a8a7aa09eb279d7eabf7ea1101556d13360950.1638825394.git.andreyknvl@google.com>
 <b777d2d2-421c-8854-e895-988ddc4ff9a6@arm.com>
In-Reply-To: <b777d2d2-421c-8854-e895-988ddc4ff9a6@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 13 Dec 2021 22:57:33 +0100
Message-ID: <CA+fCnZcSAzQ8Lk8ZqH0bv0K=Ern8aZr+=cTSzFJeE0uYMVTxmw@mail.gmail.com>
Subject: Re: [PATCH v2 28/34] kasan, vmalloc: add vmalloc support to HW_TAGS
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=AF0AV2AR;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Dec 13, 2021 at 4:34 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> Hi Andrey,
>
> On 12/6/21 9:44 PM, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > This patch adds vmalloc tagging support to HW_TAGS KASAN.
> >
>
> Can we reorganize the patch description in line with what I commented on patch 24?

Hi Vincenzo,

Done in v3.

> >  void * __must_check __kasan_unpoison_vmalloc(const void *start,
> > -                                          unsigned long size);
> > +                                          unsigned long size,
> > +                                          bool vm_alloc, bool init);
> >  static __always_inline void * __must_check kasan_unpoison_vmalloc(
> > -                                     const void *start, unsigned long size)
> > +                                     const void *start, unsigned long size,
> > +                                     bool vm_alloc, bool init)
>
> Can we replace booleans with enumerations? It should make the code clearer on
> the calling site.

I think we can add a single argument for named flags to improve
readability. Done in v3.

> With these changes:
>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcSAzQ8Lk8ZqH0bv0K%3DErn8aZr%2B%3DcTSzFJeE0uYMVTxmw%40mail.gmail.com.
