Return-Path: <kasan-dev+bncBDX4HWEMTEBRB3MMQKAAMGQEN3EMSFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id B54F22F687C
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 18:59:10 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id m203sf2625177ybf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 09:59:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610647149; cv=pass;
        d=google.com; s=arc-20160816;
        b=X82hdBnYBjLde2D6Bd6teXeXcDkA0RX1UrZLyctSb2XyyrYCLmiB9tiaB/7Dg99H60
         ix/SKPTBKBu5+bhMJ5hCprlX4TOiWODd38qgcT/J2qhyeS6QnMw2IGfITJj30SBbTg4j
         N3OE9PHGVkQH9yP1kHY63FiHWjJUAYJweTUeXe9phXwPpWc/v5xmdgFCuKuVShvCszFo
         V3TbxTxbuRPudq3tZWQ4XVOib+Ox34Phz1nbis+ZI7uYzZ4HD6BswUi3FP7s8k+/NTin
         I/kAPsb+A2Wu9id+LVedSUtXUUvN05JxNzuKGiJYkWCoQVemysv9OzUxL5DQk2syETZ1
         RG4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6IGfKl8SSCctDqQienuvmKDL1uSpfKn+QOqL8hEkh4c=;
        b=ttFrNL/Zyk0IYVEZ0YXDQAgDhBo1XTISJl+IkKbTfzGt0NIFg6AeGBW7MdxNmhkuMu
         4SV0Xj2ZCdIWSEIZ27YV1LExu4Y5GWd5aiHBjZYEyonPofcUj93PxHQu/8hpTPGIEf95
         iuovhwtV5jQKYCPjUtnR97nBW6pvSOGfkp+kjawqnjAFEtpzC9rFTH3m/Bw+RtlnXui/
         3M6vNJO5dcVMvW3lHQy+r/IXgQNF2Xaj+KJi3t2NNokgsJI/O2bjvbR9VcXjPXDd4E/j
         zjfv/H8kveJ4FQM+QF61Ata7MopgUxOkZpVkOQBZc4UQR+hHbWEgxdxeQSno/e6ulZF7
         lPZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PiWe9Ubm;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6IGfKl8SSCctDqQienuvmKDL1uSpfKn+QOqL8hEkh4c=;
        b=TdQgn5hi5TZbtLwZgTmykKnXHFREHShxpfZoDoCU+kmhG8BdRfzha7380N/GBvKLMY
         mMnUAUsui9KgXeGx4DV28Bt/2giVmrumLF3sMm4LV4ndm/lMrMoDzA2DO2rv0aUFU+fH
         INalP8FEG0fTi34fi4KXI64YZWCsV+3Q5wBl+isLkBZo2KA+7S7/eNCLLWL/oE7EpA/b
         Q5qYoJ84ChQt5FgVT1z1WjjB2ixgaiZ8xw80vs0VA7MkffTu6MXKeetmzqofFAjXkxd4
         7gt5sHppQOBgjJ44fu5eyOXevQsoB89EIOcBURM8PIDhztC9B4cHnlwFkl5NoAyuO9gh
         kX9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6IGfKl8SSCctDqQienuvmKDL1uSpfKn+QOqL8hEkh4c=;
        b=adO/cATpzZEcdDDvGnXAgn+GB1sJuxkU5sC75/ZtScblcEU+BO/Dy+k9yimE0HHmHJ
         OBgAb40Vn2rTt9aQKQbzF4OlPgBScPq3rsB99PNF1KnGDorfVoHhRkowsNuc+qQBPi5a
         z77/1rldz0ep98NpAjNjhP6SnEm3FqFtA9JMRTPgh0e6wFHIn3UOS9DxnPwFP/b2ktvk
         xG5ROmwSseZC0eKBhQIaFS3tkBGTTwm3/wvBJq6IFpgeXsC5fYBGN7nq5NsMBZs8fBim
         pOOtGvpli2NTDv6ErS7z25qh0k1fHhw6kiEI6T4R9BRbo7kYQdnmck7OWWDP7GEYd9Kf
         k/PQ==
X-Gm-Message-State: AOAM530ToZy9ktPaZrkV9m4DDFhFVSg2jZckEj750AaC6FtUhtbdwMx4
	btd0TCd2BbCM6eM3X/iLKWs=
X-Google-Smtp-Source: ABdhPJwFRBlGKVHWlG3wxtqPbnRqfJ3PlbOm2NQ5hblfIaO+YJ7pmjAzrUmWaeNWz5flzLvdLwJ0pg==
X-Received: by 2002:a25:ce87:: with SMTP id x129mr12388575ybe.218.1610647149640;
        Thu, 14 Jan 2021 09:59:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:8b88:: with SMTP id j8ls456785ybl.3.gmail; Thu, 14 Jan
 2021 09:59:09 -0800 (PST)
X-Received: by 2002:a05:6902:20a:: with SMTP id j10mr12762444ybs.293.1610647149250;
        Thu, 14 Jan 2021 09:59:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610647149; cv=none;
        d=google.com; s=arc-20160816;
        b=qTfUCsqSb5B5S3zoiS2wydnznbE+w8NV5+KFetV/7EApwYkn3vK+om97F9uYV5AMrz
         w2QKRkeJN2fWu0SleSApQsxqJXqf9YyhIaqzExnjgVsDo6QHsJ2OVN4qxN0VzSMW8jWC
         Pz7C3c19jm05ziBaSLm/BGHrHG+0Y5QEElcJwDbC6KEPfaZQd/Svj5HI9R+Pd8aY4oar
         4t8craOt81MBTj0KkaCFsUDBuHT0vyDZY54IpG4DiVUpLYflyn6DOE4i7hR+ldxpkXaP
         FQuC6AIcy9tPGdeE70cQEdd+LggE/fOSyNtRiv+LouPCtfAI3brJegdIbtskJZzPlio/
         hdeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2auPNUUUKSqA2spBBB38ITsZONoHBGZrmNd5ga3XBtk=;
        b=B6AMRZk2NSfgn61q6xpum2xpIvI8Dpbfwy2TY6C+Js5FAgKPOawp5qp/OHiy/aZ5rt
         WNrynbjPccApXt7E5NBRqwU17wuDxMoCLR4JrR33wTf4qvjVD3wMHU5grEXJUjBY9qSa
         Qth62ma7AtYqjLiaQzAmYc+y/rZOCoFXRPPvDxb12BmSlZ8XieguRn5CW76Ya160zdtA
         pwCUpBESx4uZeyTio9ZCdYjPEFr5CULl+FVsstLtHkbvhKb4pA4wz9zI8DKLfCncTS8k
         Go13XM5snMvR9Skdy9NGoK63HI1GbQNPlqf0uXA4JqKsGZ17+5BlWMrQHKIc0ygFamcM
         SizA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PiWe9Ubm;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x52a.google.com (mail-pg1-x52a.google.com. [2607:f8b0:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id i70si430566ybg.1.2021.01.14.09.59.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jan 2021 09:59:09 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52a as permitted sender) client-ip=2607:f8b0:4864:20::52a;
Received: by mail-pg1-x52a.google.com with SMTP id i7so4283213pgc.8
        for <kasan-dev@googlegroups.com>; Thu, 14 Jan 2021 09:59:09 -0800 (PST)
X-Received: by 2002:a62:e309:0:b029:1ae:5b4a:3199 with SMTP id
 g9-20020a62e3090000b02901ae5b4a3199mr8242200pfh.24.1610647148349; Thu, 14 Jan
 2021 09:59:08 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com> <77015767eb7cfe1cc112a564d31e749d68615a0f.1610554432.git.andreyknvl@google.com>
 <CANpmjNPX9yn5izxtYMq14Aas2y4NA1ijkcS9KN4QQ-7Hv8qZEQ@mail.gmail.com>
In-Reply-To: <CANpmjNPX9yn5izxtYMq14Aas2y4NA1ijkcS9KN4QQ-7Hv8qZEQ@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 Jan 2021 18:58:57 +0100
Message-ID: <CAAeHK+xberuUH0cn8U1N8X0n56Fy=uLCxZ=P3q+E2PPRsfuKNQ@mail.gmail.com>
Subject: Re: [PATCH v2 11/14] kasan: fix bug detection via ksize for HW_TAGS mode
To: Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PiWe9Ubm;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52a
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

On Wed, Jan 13, 2021 at 5:54 PM Marco Elver <elver@google.com> wrote:
>
> > +bool __kasan_check_byte(const void *addr, unsigned long ip);
> > +static __always_inline bool kasan_check_byte(const void *addr, unsigned long ip)
> > +{
> > +       if (kasan_enabled())
> > +               return __kasan_check_byte(addr, ip);
> > +       return true;
> > +}
>
> Why was this not added to kasan-checks.h? I'd assume including all of
> kasan.h is also undesirable for tag-based modes if we just want to do
> a kasan_check_byte().
>
> Was requiring 'ip' intentional? Unlike the other
> kasan_check-functions, this takes an explicit 'ip'. In the case of
> ksize() usage, this is an advantage, so I'd probably keep it, but the
> rationale to introducing 'ip' vs. before wasn't mentioned.

Yes, to avoid having a ksize() frame in the report. However, I'll move
_RET_IP_ inside of kasan_check_byte() as it's inline.

> > +bool __kasan_check_byte(const void *address, unsigned long ip)
> > +{
> > +       if (!kasan_byte_accessible(address)) {
> > +               kasan_report((unsigned long)address, 1, false, ip);
> > +               return false;
> > +       }
> > +       return true;
> > +}
>
> Like the other __kasan_check*, should this have been EXPORT_SYMBOL()?
> Or was it intentional to not export as it's currently only used by
> non-modules?

We can add EXPORT_SYMBOL as soon as there's a need for it.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxberuUH0cn8U1N8X0n56Fy%3DuLCxZ%3DP3q%2BE2PPRsfuKNQ%40mail.gmail.com.
