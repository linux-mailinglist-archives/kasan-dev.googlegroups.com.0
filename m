Return-Path: <kasan-dev+bncBDX4HWEMTEBRBGMVSP5QKGQE6AGZ4DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 28791270047
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 16:56:27 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id d21sf4679645iow.23
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 07:56:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600440985; cv=pass;
        d=google.com; s=arc-20160816;
        b=LoRW9PW7GyJgF5VfbVvB7Z/quAyCF5dDs2dIr93Jd5RJwKvJQyDgZS2pB50+F0vijt
         drlo2B5jDdwoKrP6ntG+5ueOYA2/gZ4KJUQZHzo0VQ3WkqQLbicPBZTvCZcWgwDnG9q1
         yWIWw4qCin6mzRb55HMVO8C4wlrv7gIGRMHf42Mqu9cH0Z/BOTfqrcz17Ij2taCO9Al2
         a5FtxHpu1spTddu8hTiDdDHELA91e4XXYAYJVIyCpzu12eo9KE1Be+/5IdM5iUZ5knCa
         Biy7ehr3Ubloa3yFvgVUwoWkQTc81lug4msrz2Aad3fjnb3JjE7BHTptsd2jRsA5un89
         F00Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=L6thzVNyk9PMhC3O3ldto90iTyVnBsy/pFngcwH/mUE=;
        b=Rq7nHCyOqBJNMTxlYCck4ec8tJBDSsVz9xYcMb/pfNjalRElocNkzI/iBC+m+RUL9Y
         3B5qBo5XC+lnxy+vyXWEfpNPvwAwaZrZct97bnRPIszzOtRai3UFiGvB+gNh6eTexF/v
         wxlWRMPOLpg7MTlO5EFB2eqHBtritChW5KSHxlA+bpZqhfmPy7pAzT5idNQheyNUxbIh
         j1q56M5CcNiti4RCvwF4kVfL2roFjGxBmN52qySxGQ5JTwD+mdguMXtbGTra2IpXxlx2
         N0AbBW3O4GFaY00V7QOceiI2+eGzGCpG9tfYWn3iMMD7tq7DTywcCG7CIq/cKxpPtOtF
         2uvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UpKAXNLb;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L6thzVNyk9PMhC3O3ldto90iTyVnBsy/pFngcwH/mUE=;
        b=hxQ9D4E6PjzmmCHjR7JVruDw4IEKe+e8EEDUXieG48Xso7q62wZ5Qg4WXqxWKsgOZq
         +fGA7E9zktv4hmG/UGx6aTr4ShPwkep30DzfleVI+aB7BWNGpGEviY3YQPhzyx0i3hMT
         3Ka1lqp2tGqwWnQwzWmsDofE0TkjGVUO2NUs39tlxgqAm0K9XY4AJL4aBq3HN1lYZ+bb
         GDGRBceRjTirNTCRl17zzoV1A2ppItcvoL2CNdYJX6qooVfxEbwzNKLenUGy7Fwf2YS6
         ky/2MgyEFPkYtOekNzv39xgHZ2UAERQGXJK1trJErFesCdf6mLcV6V77nPrK7On2rk7i
         m55g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L6thzVNyk9PMhC3O3ldto90iTyVnBsy/pFngcwH/mUE=;
        b=RT3Gf0AO4biULtXSbDA0E/KvVbQlZJbLbSyH/gWEOa48wmp0zCNbfyvey6T0Kwd8tn
         8O9/ueMsB9TXTw6IM5uQj7UWJ67jklyHZIIzJmafWUhkvjyDUay0jjVK9h3bYiAnVdfp
         wvi7HD6w8Hf5bJIFuTF3nWWM9koGEIJmv6dVcammyp8oQWzJH5PZXgb7D6mYA2M6sGGO
         I4aHF2v/FfavMp7CaWDBZVkhXa2HkRoqt0dU+qfolZwbTbCt8bcv9mSkI3HT28WFAuzm
         PPu2FtMx3Emw2cSMX1fgXlivhg4W3DS7HI1hq1SLmtgVzGBj1eZFVnVjtejcomJk3Hpb
         yySA==
X-Gm-Message-State: AOAM533O4l2lpifoRAapzgA+7XOl5JpiQ8oWH/cWmUU+/uMSIQpwPvUc
	CapEAD56Vbze2GFp7z7j++k=
X-Google-Smtp-Source: ABdhPJyUgu5O+/ZrhC2LyngtnrSMAYRRHYstPGN8Wjcpt4btcmvkdx0ntSi5TVbaKT8Q1isHrc8zng==
X-Received: by 2002:a05:6638:250d:: with SMTP id v13mr26034008jat.50.1600440985740;
        Fri, 18 Sep 2020 07:56:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:7312:: with SMTP id o18ls1642496ilc.2.gmail; Fri, 18 Sep
 2020 07:56:25 -0700 (PDT)
X-Received: by 2002:a92:dac5:: with SMTP id o5mr20714384ilq.26.1600440985383;
        Fri, 18 Sep 2020 07:56:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600440985; cv=none;
        d=google.com; s=arc-20160816;
        b=Sx4aENJJY4nSKd8hF94mu9ZKHSAsCAchpk8EVN2Zgmh7Nq55E3jiwAk/42eaOwEUaH
         Aa9PstxpLir24N0FVWKIb3UDjubsy0kp9RM+3veYEKymLDl2vlbcDucAe60Jdm5WL0X1
         NgP/J/ddm5//2FD8sjYW4GNA6qjF5C3EgqlJV/ndD1f2kf30B04PpccsXQ+kqaTAigH+
         QbwLAGBO8TfYug5pqqEP1N59eyZXBGMUXHsgip95y+n12mfADWTlfkI3sIeH6mGnAJ9J
         g8MTPp40Cr6G1wmZJ/7/qm3WDwlGmG7wMfyAvh9oinxHo4V3wEcXiWcCwwOOS89YgTfo
         j3Ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nPppQo1Knuq6bNt9Dk0KPBwC7NFNhQQ/T4+rrskH/0M=;
        b=nBvvwuJVqvDvYAV1KfiFkoERtL+wQSgFKWf3FoCvhWX6/1YchLCDUY42+tkqOBm8Dq
         dEooWT4qQH3f18IKVxB+cw71MawEn6JF0vFWOnBAaJNn2K3pAedZuMTqgkVBRlaTTT/x
         kDrkxmg147oc5hAZTzrzzg3GuhcG3//Ovv3kmHM87dydSeEa/u6NudsApOR/6NrLso2f
         ax1W+/66cbYLkShH9y4dyH8lep06gfmChJ6PC1MdxuuA87J08IMYHPrDjSVbLlHDZbzZ
         Mb1n/Ezq2AooyfArpwgCJgzlLbPGcxYIM8v8LVsI9HbFPRu4r8Q3GgZxbxM61zIzau33
         Y/eA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UpKAXNLb;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id f80si237507ilf.3.2020.09.18.07.56.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 07:56:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id u9so3119015plk.4
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 07:56:25 -0700 (PDT)
X-Received: by 2002:a17:902:b117:b029:d1:e5e7:bdf5 with SMTP id
 q23-20020a170902b117b02900d1e5e7bdf5mr15057635plr.85.1600440984513; Fri, 18
 Sep 2020 07:56:24 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com> <b52bdc9fc7fd11bf3e0003c96855bb4c191cc4fa.1600204505.git.andreyknvl@google.com>
 <20200918130037.GE2384246@elver.google.com>
In-Reply-To: <20200918130037.GE2384246@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Sep 2020 16:56:13 +0200
Message-ID: <CAAeHK+yk6i0QUPZCw-582iX-HeifwNyMiVYsj5HLySuHvv5GVA@mail.gmail.com>
Subject: Re: [PATCH v2 23/37] arm64: kasan: Add arch layer for memory tagging helpers
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UpKAXNLb;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642
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

On Fri, Sep 18, 2020 at 3:00 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Sep 15, 2020 at 11:16PM +0200, 'Andrey Konovalov' via kasan-dev wrote:
> > This patch add a set of arch_*() memory tagging helpers currently only
> > defined for arm64 when hardware tag-based KASAN is enabled. These helpers
> > will be used by KASAN runtime to implement the hardware tag-based mode.
> >
> > The arch-level indirection level is introduced to simplify adding hardware
> > tag-based KASAN support for other architectures in the future by defining
> > the appropriate arch_*() macros.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > ---
> > Change-Id: I42b0795a28067872f8308e00c6f0195bca435c2a
> > ---
> >  arch/arm64/include/asm/memory.h |  8 ++++++++
> >  mm/kasan/kasan.h                | 19 +++++++++++++++++++
> >  2 files changed, 27 insertions(+)
> >
> > diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
> > index e424fc3a68cb..268a3b6cebd2 100644
> > --- a/arch/arm64/include/asm/memory.h
> > +++ b/arch/arm64/include/asm/memory.h
> > @@ -231,6 +231,14 @@ static inline const void *__tag_set(const void *addr, u8 tag)
> >       return (const void *)(__addr | __tag_shifted(tag));
> >  }
> >
> > +#ifdef CONFIG_KASAN_HW_TAGS
> > +#define arch_init_tags(max_tag)                      mte_init_tags(max_tag)
> > +#define arch_get_random_tag()                        mte_get_random_tag()
> > +#define arch_get_mem_tag(addr)                       mte_get_mem_tag(addr)
> > +#define arch_set_mem_tag_range(addr, size, tag)      \
> > +                     mte_set_mem_tag_range((addr), (size), (tag))
>
> Suggested edit below, assuming you're fine with checkpatch.pl's new
> 100col limit:
>
> -#define set_mem_tag_range(addr, size, tag)     \
> -                               arch_set_mem_tag_range((addr), (size), (tag))
> +#define set_mem_tag_range(addr, size, tag)     arch_set_mem_tag_range((addr), (size), (tag))

Will do in v3, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Byk6i0QUPZCw-582iX-HeifwNyMiVYsj5HLySuHvv5GVA%40mail.gmail.com.
