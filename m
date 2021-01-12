Return-Path: <kasan-dev+bncBDX4HWEMTEBRB3EC7D7QKGQE466UXUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E39D2F3B5F
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 21:07:09 +0100 (CET)
Received: by mail-vk1-xa3f.google.com with SMTP id k187sf1442629vka.7
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 12:07:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610482028; cv=pass;
        d=google.com; s=arc-20160816;
        b=NNEQaCCMtmBdUGDzlff97jYl67guzoE41ALFtyBh3Mf4W7wgZtge5dOWDzReN93j7P
         1YoqYsOmZjWeCaTwOZUYCXkOjY44qFgxtIzCq1MtqQQEJhYbXZBiV0Ye8WeeuyjmKCPL
         a1wrjhuaBlIH5YPZpkmthVoOmUCfSXCSr0fQiGZMCKbUbkAE+7yLLt9DqX7WkMzhSGkJ
         Eh+cBxvek9CYsMCQQwrzq3O4Q2sFvqp1vubQjdtt8TLxrjfcPouOdclweHlSBJbdNL11
         wnsa4iiubLnUnYXjeAiziLQxecZXjlVfaHHNnM5ubg0nbp/BiyF3Nw4PLPVj5WUq8O7u
         3gqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=svnOzlqqChSNESwE6VyPbA0Gs7Sp7p4GyM1th4JaUyI=;
        b=SWnR54UQKferi7Ywq2KcoFKn725mOvg71J1x9PhH7q5buBE8T7BjYcRM/HL5UA84Ua
         u6WoUhhVicnkBE5bp6Vq8S2CXT5chUdISK3gVaPIB0fIPlrSm1H3jisYgACWeCGuVcVH
         gYSQb60QTW3Fw/UWOxShnEGKFZeqA5BKupReWVmkdxTeybaIzG8c5mnhmz/d4i29srV9
         0IzUJAYoEsR6oetyisxuANRYCI53pYED84aSepFV9YUXi+3R4Jdws3Eb9mTb9PnRuUpd
         tFXKujoJGc/8K3dZJPZcJ5NJjeSVgru4Ud4Z1uiGamarHdUAUgpHYFr04wwldPv/oJ+j
         ku7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hp5afakN;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=svnOzlqqChSNESwE6VyPbA0Gs7Sp7p4GyM1th4JaUyI=;
        b=p+MJsTNpNqn75g6lktcp04e99GWgbNk+2B/Jh6Z/t/OlJ5ldqRscj3Ji12Pqqn7FPb
         M2M0e9sx8FLV+oEAS1hwJVceftpFyaTBqzF1zawzxlxTsV6P5ghvfq6gVxSUIjP4urWb
         lY0ZYBmfId+PnXU3OTnQ4c642vfC9VP6wNSWO+arwSsZ3y2JscoTZk4FaPfhRh4DdIDQ
         eqQibNw9Rfn6EQAgdscFMc3gb89U669Bj8CQZ6fKmracrLPMWC5qSX7pX+z4zUbWXaMd
         K5lSDCmzHUWhnEmXBZF1s7J7Ma+g0zg+UWVxsyAjXd3wzGJuJXeki15ZbbHXfuESvgiy
         2CHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=svnOzlqqChSNESwE6VyPbA0Gs7Sp7p4GyM1th4JaUyI=;
        b=sOqJ9eDlGHG7nZmhvyrH7eb9F9PLJMmEGTghMtr/ghrqEwzfjlRd+slMebgwgHn6H7
         mYl/JotaYxLgsInm3JSg7cPuLWNWmhD+9i8hPSTKwkOo9B6Ma9kZF3Henh8CxC04VKOt
         4xASmp101RVbsaqs8SuAnpwuKv5EUXz9708rLA0EH5QXyUcURLCvO9Yw4fyNlMJVOKJ9
         C261XUCG42mswW6s94opGo+TrmCby1Kt8BPL4iVvLOot41xznnmrQ39+t4LV5Jx9AIMc
         aG2RzhyMRghP14THQhkGJpgCrtTolYtBcNf4VHgHUZb79hURCfM+snGlTafQEfARnpUi
         O9aQ==
X-Gm-Message-State: AOAM530uCOevQqGVOrVneU+WUqaSDemJAjgEkEEsAC55HANg08LVU/Zr
	5NPvWYYsrHkbpisdPuXMGTQ=
X-Google-Smtp-Source: ABdhPJzjkygpUN4Xl1X1YEzPcylrrSAikuZaBsJnlSisnKqxjzqyg2UZkJvP7+WqvujhCET41Vue+Q==
X-Received: by 2002:ab0:6ecf:: with SMTP id c15mr1154799uav.52.1610482028300;
        Tue, 12 Jan 2021 12:07:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:8f89:: with SMTP id r131ls246569vkd.8.gmail; Tue, 12 Jan
 2021 12:07:07 -0800 (PST)
X-Received: by 2002:a1f:5cc2:: with SMTP id q185mr1122941vkb.23.1610482027800;
        Tue, 12 Jan 2021 12:07:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610482027; cv=none;
        d=google.com; s=arc-20160816;
        b=jyOuS4uV15c33CxRqH3lh3V9AR/JYmYHLKeCgfOrp1kmIdDjRvnsv+llsKt5rGtKtH
         zTD1wvOkeH++tnZ0AUrz6x1cOVAKYtHhU6lRw8ZgoCFYS6ALKS37U/NZQBJQgxwz8jj2
         Or3Y83Nc34NNtYgCTbW8PiG/9Kdn5EvqextS2Rmz9Y0G4OggaEqf6qEQ4aRCTrzlHdpv
         /wvTEctFfSC1N+z8aUzbWZxDI4B00GF5XvADaijPIkx4qhM1RACIfqdIUaEIgvDaID9L
         2VbR0amMyYdEzznzkUfMxHmleO50V6QRt9rTFEu/zFYPzzFU5ytxtDo2yFJlVL7XhDmW
         4gjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pMt208i988Aj1RV+YWcUlsqzon7o0ifo6LZ2mK0qEq0=;
        b=QYwFgpF54pE3jXGiSIKzsryx8lTzVPq8VyyKkou7NrahDzIZ+grMMn1Ztp992XdOQh
         heX/pjtKJEHv3/xEb08MskGZKYoNaLs0cLDlFt4UNOUF9cA8JfxSvCP971YuQoCd87m+
         StesyT+eWs35sl6Q9bMVxMltgDutv6QfIQv5882lHqqpnspN+LDzXIQzL7Ui8s4/r6jc
         Xu6SunJr5+aHm7dYJVZyLGB9hIqt1lrxUx1mB40af4WHpF/VMx+KGW8+rAv1CUfL8frU
         fSSx4Ve+4GF1gvxvfbcDTW+CrB2seuf0eSEcqj/9TvoDBatSTlKmLATlOo+TdsfZU8ml
         w6mg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hp5afakN;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id e11si306553vkp.4.2021.01.12.12.07.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 12:07:07 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id be12so2014471plb.4
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 12:07:07 -0800 (PST)
X-Received: by 2002:a17:90b:350b:: with SMTP id ls11mr844230pjb.166.1610482027266;
 Tue, 12 Jan 2021 12:07:07 -0800 (PST)
MIME-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com> <0c51a7266ea851797dc9816405fc40d860a48db1.1609871239.git.andreyknvl@google.com>
 <CAG_fn=VXe2AZZ3q6+HoV+zB=9GLP+kgyW_r9hfqvX-NJHurTRg@mail.gmail.com>
In-Reply-To: <CAG_fn=VXe2AZZ3q6+HoV+zB=9GLP+kgyW_r9hfqvX-NJHurTRg@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jan 2021 21:06:56 +0100
Message-ID: <CAAeHK+xbYpuipd3+Jew7=fL8Mn2J1ZzOVyzK+X6bvtLCeiGFuw@mail.gmail.com>
Subject: Re: [PATCH 09/11] kasan: fix memory corruption in kasan_bitops_tags test
To: Alexander Potapenko <glider@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=hp5afakN;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::634
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Jan 12, 2021 at 9:30 AM Alexander Potapenko <glider@google.com> wrote:
>
> On Tue, Jan 5, 2021 at 7:28 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > Since the hardware tag-based KASAN mode might not have a redzone that
> > comes after an allocated object (when kasan.mode=prod is enabled), the
> > kasan_bitops_tags() test ends up corrupting the next object in memory.
> >
> > Change the test so it always accesses the redzone that lies within the
> > allocated object's boundaries.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Link: https://linux-review.googlesource.com/id/I67f51d1ee48f0a8d0fe2658c2a39e4879fe0832a
> > ---
> >  lib/test_kasan.c | 12 ++++++------
> >  1 file changed, 6 insertions(+), 6 deletions(-)
> >
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index b67da7f6e17f..3ea52da52714 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -771,17 +771,17 @@ static void kasan_bitops_tags(struct kunit *test)
> >
> >         /* This test is specifically crafted for the tag-based mode. */
> >         if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> > -               kunit_info(test, "skipping, CONFIG_KASAN_SW_TAGS required");
> > +               kunit_info(test, "skipping, CONFIG_KASAN_SW/HW_TAGS required");
> >                 return;
> >         }
> >
> > -       /* Allocation size will be rounded to up granule size, which is 16. */
> > -       bits = kzalloc(sizeof(*bits), GFP_KERNEL);
> > +       /* kmalloc-64 cache will be used and the last 16 bytes will be the redzone. */
> > +       bits = kzalloc(48, GFP_KERNEL);
>
> I think it might make sense to call ksize() here to ensure we have
> these spare bytes.

Calling ksize() will unpoison the whole object.

I think it's OK to make assumptions about KASAN internals in tests. I
would actually say that we need more tests that check such internal
properties.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxbYpuipd3%2BJew7%3DfL8Mn2J1ZzOVyzK%2BX6bvtLCeiGFuw%40mail.gmail.com.
