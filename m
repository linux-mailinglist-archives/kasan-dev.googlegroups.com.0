Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYHDWD6QKGQEOSYZIOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 096442AF87D
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 19:48:02 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id m11sf1797934pgq.7
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 10:48:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605120480; cv=pass;
        d=google.com; s=arc-20160816;
        b=rrNIyJMUQ+y+NVLrGyXf3lPelZ8ufxPVj8XL+UCOwEWWugh//13lRw424FEdzLK2D5
         80cqw2M93u+naByvr38I2ozgDL/aAx+ov4RVOQBMxhq37pKDo8Ujb+8bkSDKtuzdMlN0
         nW+pSEBC4iY/WPteDHr03w2gxIy/1+jTp9MkRvh8nEKDpquMx2cS7xb/xHqLsbPN6tvH
         IZEycxSEOcoUdrn3jVcfuY0QVIlSxRIfUqvSC+/fEOweK4VHoWYH+MvbZQmFHqsNLX6z
         NjiSKIY82Z/DVb0hJPSbpkE/SZSxEiVuv+ZLW3Bzs41jpNV63BqpVZiG0erPX19s63I6
         XHaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1iWFxdYR1gZofeeaK1C4cFJBjSKiDnV665lLB40vGec=;
        b=Q1E33vYSRf8/jhnO2j2Yh9AFtb/mg3krY2L7UokkBOt2Ub+ajJ4fHSoaGs8pEJeR4z
         NxY2CP4ixiKWsn+BLJpr+qtJP/x+jv5CmX2e8RurdBQ2W7eQNwo+O06PbX8mirvAljLM
         op39//5+jh9qsr/KK7brC0mZfqEPYVsA8ceHByt+wF7l+aWqJAsQmNL3UDEAfIrXs2uz
         ve8D2BG0508TrQq6vrIaMljlTW5+YGBBJ5uuq6/FwU2re0Rle7TLIe5C28YIKtoPgXQp
         58djRi2TPXOK0o2CfnOz3Niuyp6xRApQTFwKHddEzkXQWODaSNmKv82omgXylOmoQN8m
         1GQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=F4hURf+R;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1iWFxdYR1gZofeeaK1C4cFJBjSKiDnV665lLB40vGec=;
        b=hkA9ZySWEIyPwYXvpeB6rn6NVXyLnGLkc94RRMAvIi4mfylLQ/GfAmyTVyMuOrUsMT
         L2PbUVxD//smVzFlr9oDCjBtpvti1ReHmS4gx8GB84Ct4NriGaJtq47wSKFBL6grf34L
         DE6FE1bCAQ98/GCD0SkWtZfPWcaUnaONbiDEzqdsoPt6dqm5/mi2wGxNnyLv8pip2H4z
         lHHWLUIXsF9KiStwj9510ghyM7O+OckkQfwchW+xcoYcywi8foa81jpK6yVNjA/5Syj5
         pKd3/2vnNeSIspCU4CyXwSlLN1463b8CbPywprxQQFyC4mkfrfc3lqKVF5JFPNUr9RqP
         6Vnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1iWFxdYR1gZofeeaK1C4cFJBjSKiDnV665lLB40vGec=;
        b=iIlO0VC38Tc11fSi2jLK4AYyrQsrSJ2gRL3PtgAxpdaR+uPOWOwOwM0Te0zjoYZYm1
         N2dWTRrphPRCHkhYxJGGqpIWJZ4eXVzJf1xDzv6Y+fF1+67mcQa6WpG6qExQxcKoICor
         K789168fc+Rs0tzRdevtSU5piZvmc9dAgP/MmHo3BG06Rrqz3jethkC5yu6O452DawIc
         WgOSQBGGhZvgrcXsSx+q8V6Ib0DPlisKU8rYym4iNthvZE7Peq1P7Ku0mId5BYBMhCbm
         a7Nb7UgvE9a+XTKArLZF/7ELgbqsCwXT2YxxgQHj8e1kIoVIUM/QYWdqRUu4jJM4q7+l
         Suag==
X-Gm-Message-State: AOAM533tkOewPI/RAljwZQnVlnlNoSd0huayqEwiMUG/5ZrhEBJxXKmT
	CvzaoJ7yxvkE+8JAqhXqZSs=
X-Google-Smtp-Source: ABdhPJxSY6NNSQnFPhfx/Q6WJgXkR8/oChiPo1WaLqxTT5DXzz/WlBY6pJQaYc1hq+Ec0vgLQxt7Jw==
X-Received: by 2002:a17:902:24b:b029:d6:cd52:61e3 with SMTP id 69-20020a170902024bb02900d6cd5261e3mr22712946plc.2.1605120480715;
        Wed, 11 Nov 2020 10:48:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7745:: with SMTP id s66ls122189pfc.0.gmail; Wed, 11 Nov
 2020 10:48:00 -0800 (PST)
X-Received: by 2002:a62:8608:0:b029:18b:a8e:ee9 with SMTP id x8-20020a6286080000b029018b0a8e0ee9mr24438816pfd.65.1605120480147;
        Wed, 11 Nov 2020 10:48:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605120480; cv=none;
        d=google.com; s=arc-20160816;
        b=IWiweftJmUcf8JXAJ83OxzQ3ef2Z1MYNJL9j+xGU/xgJmD4P2EhA7YPsgbfqEIyYrk
         76uTeNxkBNxpQLHj4rOjgY1f43RrPzGdZwTEiPk/lNXNiXXkdxN2w6ynlSyRVPkmopvr
         cHj2qviEJIt/kejVGIt2wldjuw2m4MzyEcE0cQTz8AoG6M8OcqCHAUZfrfzfULvoIDwn
         APlyxPctHXM1wyOMGqABf0G0hOeZjrAh6QH3xXEk+xXIwnn6cBX2doL+Ei1VjwrJqcfj
         sx6Pn4ui93OyzjAHiqFqNxXHTjuOpRZLnpw0eHing1tI4z5aWTD/fBuxD88S0vkuxrpS
         +0fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Y30nQOc9Erw1djQyyLfK/qeAvjp84VdQVely6oznPn8=;
        b=luTfZSozbL83bDGs2QSXmeLdNjCxEQFN8Hn4KaMGQ25PcbAelzroEwhFWv3RR0TbHv
         KZW9seq8DXvbbBaGI2mSnSNl5vwwySLAfuSfUEeC3r8BdzEcWX4P8eNbY142QTTvrSl+
         ePamhvaees/rVDk9VCKrsaq1vcNPpSA6K01mGaUjLuwCSLSLFd7L5P1+gvAmMnR5AwtL
         U5SSF1syqFaOmNq59Ta0bVLvuQ5fxLgffhD2Pxzto3L4rA58ETLEeAXc5D/qVNdjHae4
         ZRBWVin902PlxMVh3t6Y6W22srYXjYtTdVyRt+/KFln7Jlf7a9SoXB/mVKtPkEz7pBlZ
         sqaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=F4hURf+R;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1043.google.com (mail-pj1-x1043.google.com. [2607:f8b0:4864:20::1043])
        by gmr-mx.google.com with ESMTPS id 80si209997pga.5.2020.11.11.10.48.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 10:48:00 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043 as permitted sender) client-ip=2607:f8b0:4864:20::1043;
Received: by mail-pj1-x1043.google.com with SMTP id r9so1144468pjl.5
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 10:48:00 -0800 (PST)
X-Received: by 2002:a17:90b:3111:: with SMTP id gc17mr5116219pjb.41.1605120479739;
 Wed, 11 Nov 2020 10:47:59 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <85aba371903b749412fac34e44e54c89e5ddae30.1605046192.git.andreyknvl@google.com>
 <CAG_fn=VuM=4axS6ex7_MgCeZ47o+Scon1WuFGStF78T36sHayw@mail.gmail.com>
In-Reply-To: <CAG_fn=VuM=4axS6ex7_MgCeZ47o+Scon1WuFGStF78T36sHayw@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 19:47:48 +0100
Message-ID: <CAAeHK+xq2tuVYGOPx=_uj08Xwa_1o9Wv-ODrgN3yWXxAgEGV3w@mail.gmail.com>
Subject: Re: [PATCH v9 10/44] kasan: define KASAN_GRANULE_PAGE
To: Alexander Potapenko <glider@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=F4hURf+R;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043
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

On Wed, Nov 11, 2020 at 3:13 PM Alexander Potapenko <glider@google.com> wrote:
>
> On Tue, Nov 10, 2020 at 11:11 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > Define KASAN_GRANULE_PAGE as (KASAN_GRANULE_SIZE << PAGE_SHIFT), which is
> > the same as (KASAN_GRANULE_SIZE * PAGE_SIZE), and use it across KASAN code
> > to simplify it.
>
> What's the physical sense behind KASAN_GRANULE_PAGE? Is it something
> more than just a product of two constants?

No, just a product.

> The name suggests it might be something page-sized, but in reality it is not.

What name would you prefer?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bxq2tuVYGOPx%3D_uj08Xwa_1o9Wv-ODrgN3yWXxAgEGV3w%40mail.gmail.com.
