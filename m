Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPHWVWBAMGQEYMZAZ6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id E4F6333900F
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 15:31:25 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id 42sf13436860plb.10
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 06:31:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615559484; cv=pass;
        d=google.com; s=arc-20160816;
        b=Be6vqgrNRdmTq/AxlvJjhmbCWSGtBsafTWlCpS8NNsk4O0CKT0OU1FLKcvFHDd7S4G
         k9P92tLhh09QkZsV/ymWfh7xwheoCR2bul7k/Wcd1Fwd3T2W1XzyiWGvEp2TwXKzKyUE
         5z+4wt3i/wvLyX89HqaqIRIVcHbZlrlFXD33lgVQNMbD3LR27Y2y8F7716SVBLQSMdNC
         QlvT4n1Bsj9ZYpVgy1inKU6MUzRde0EVVUL7SeM+6K3SCvu7tGnuB9tqbXN23g894d0c
         Sj5zUtm32Kz48dkum5OSfUHWK8q0uFXGL8qjYnc/lskVR9rofKPchTSjOIrOicy+aU+i
         8Xbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fcNClmmef4Zq/Tus9OlDzJfiBDp9rL9n1CuzzEEK42k=;
        b=BjjsdIUHGBkectvDF034/s2tFvSLVO4+tATgsUNOIjeNFcAiydDnHxrybTxOfBKTW6
         SdCV2Ynfu8575JQiGcRoLlPaYiwNDvHZOnmdYHMevcxSr52uCs6vsMHcqgzOEp9qcIFK
         I5EkWJROB1KveonT4Yh/bu4Djlo23ObIL77xG21rehV5t30hzUl38+BBXfKNUl8yvFAr
         4mecjzqL2a8EjSPIUuJsHpPWUV2WqTap3qs4G5X0OwMB5Gh0djV2EYC+O9i58EPzHbZR
         pSZfogOqI/JIm0NzT8UjTH+tar/yqGhOjYeg7SHgPWEU8WdGiq55NFxXvzKrkbU+2er3
         LXPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vbw+LKbb;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fcNClmmef4Zq/Tus9OlDzJfiBDp9rL9n1CuzzEEK42k=;
        b=I/2iaO6DZc8GaUMMat0jOe5AO8s8QGFK8KhtpCBkaTUo1BSgcOFQPbTcmwWAur7hYs
         MI5riBljS+Orh+Sy7MEdZbbIvXzMjEoiNy2zm6xi8Q+LFUTYDd1zI0HOiowRbndyCm89
         YU6GDFTymgC5iWFJ1rqsXQGJUeABglMP9F0E3qvhY0n8p6ndeK8isvK6LSXXxGffxszk
         IZu3/zOqDgiVRjUXqFNj9DBTLsFbDItWIODvLKtEBjoUXm5AM5exUqejlEEQ9e6XrLLv
         t0X8/jWLR13t7uc3MPJ9dj7KFD7h1X7/8Z5LmfJrq+WqfYVG0m/yq4M7dgRCNaksS51m
         EndA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fcNClmmef4Zq/Tus9OlDzJfiBDp9rL9n1CuzzEEK42k=;
        b=ge6KHw9xDvhocDS4e7YbgWGKBffqLod9D707KMQBe4DZip9fLxZbUOitFlnvTWydJ3
         o+nfRpVt7vyIuKrYSy+k9OgsP8HkSbhRa9wzJ6lv6Mh5gIh9lgm71QGDshpuJFAQXprd
         5ziRtGOS01BqLVeLa1qUpxBL6LqoJdS2EnTBA6gCaYEeSV50Pz8WjF9SlkRRGAd7BfVE
         vDDMUcEKtDeIRFiD61jAPKwH2xasvsniqnJbIaUwfGLMkZsewl13X3+U+IEL15RiNEtK
         dnP58Yy0KT1d01l3uZfpppknBKQT6iN5MXteAubkOtLfJ5cnlKwjruy1BIoRGJSZqP4v
         aJwg==
X-Gm-Message-State: AOAM533ycmC8zBrJw5cRuwFU1ZhBkWdcNGi2Q4U5cK4O7S8+8u7vhNia
	zP2Y69HHn64FkvYDO7lz84c=
X-Google-Smtp-Source: ABdhPJwpzoi0OVAuKpMuCYwzoXH1AXyzVxN242coH/ZstlmSu9/Wotk+/4B5YVqzl5sRa+sC6v9ysg==
X-Received: by 2002:a17:90a:5413:: with SMTP id z19mr14126515pjh.137.1615559484663;
        Fri, 12 Mar 2021 06:31:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a507:: with SMTP id s7ls5070911plq.3.gmail; Fri, 12
 Mar 2021 06:31:24 -0800 (PST)
X-Received: by 2002:a17:90b:514:: with SMTP id r20mr14585474pjz.145.1615559484070;
        Fri, 12 Mar 2021 06:31:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615559484; cv=none;
        d=google.com; s=arc-20160816;
        b=NRe3clPM4mbMVvUX/A3A0ohoICC/PgIcPV6jN83uoWma3p3I5F5BHZnIdGaCnQWcD2
         CWNiyhy+XaA6EGYyL6KU1wXUOuhHvHgYsz7nxiUFZ7u5qJz3ZnsG8dd9SXteJ3XOoEJy
         tTPlJgE5HXf1LNZi3OSgEcaul37B96R3pjaIg72HlxkighND+2VMwKX8vjnWl4BFdlR4
         t1rR6d0ITNgMZYIHuy9QiSfhTIOp20VXF/MotOFoXK3uCTqwPjaVhLYTsqMocaV/40gs
         U6JJPpOBgV81nSUdskIGrebyzLIH7kLMyb36Ae+YH9S+6hsjAjx3BEGM9JOgWlYR/IBm
         RYgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=87q9jccx8BT/1UJYduCnIq9RvFzXmVQYDuCBWc/EFfo=;
        b=qO2h8YTRQoNuZp8I5yENw51oMGawhRlThU/ysjpS98OiW/mI2cRT/VpgF4sezjx7GZ
         b2q4e8e5gZ65W8cI9ddXJCnQCJF8kGi0hqcAVK0DU3z4X8TWfP95DHFXJNnRauEDiJ3L
         8jXSQlWAxqBf77Dwcg0dMBMnMqX8nydpyDngKyYbmRr2CwZ6CmHufuzMhYBzs1Hq7+Ww
         PTD3tqMn5B77gS8g13HO8UMD12J8eoIcE6MOJwqy+z5eaSG0qzMqVtLwmb49bOtktN6z
         6pv5NUTbtsIu+P2U6ibNww7jGhXy1AnvsS2uGrLTlfeHVKaxGef/wgf7BH3kb61xsxEf
         l3Yg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vbw+LKbb;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x533.google.com (mail-pg1-x533.google.com. [2607:f8b0:4864:20::533])
        by gmr-mx.google.com with ESMTPS id r23si296305pfr.6.2021.03.12.06.31.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 06:31:24 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::533 as permitted sender) client-ip=2607:f8b0:4864:20::533;
Received: by mail-pg1-x533.google.com with SMTP id n10so15981427pgl.10
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 06:31:24 -0800 (PST)
X-Received: by 2002:aa7:91d1:0:b029:1fe:2a02:73b9 with SMTP id
 z17-20020aa791d10000b02901fe2a0273b9mr10366246pfa.2.1615559483690; Fri, 12
 Mar 2021 06:31:23 -0800 (PST)
MIME-Version: 1.0
References: <20210226012531.29231-1-walter-zh.wu@mediatek.com>
 <1614772099.26785.3.camel@mtksdccf07> <1615426365.20483.4.camel@mtksdccf07> <20210310214552.6dcbcb224c0ba34f8e0a0a54@linux-foundation.org>
In-Reply-To: <20210310214552.6dcbcb224c0ba34f8e0a0a54@linux-foundation.org>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Mar 2021 15:31:12 +0100
Message-ID: <CAAeHK+xBcFgft9yqNMEKs42tEWEDt4Za9n1_t95PAEiS7Cqibw@mail.gmail.com>
Subject: Re: [PATCH v4] kasan: remove redundant config option
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Walter Wu <walter-zh.wu@mediatek.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Nathan Chancellor <natechancellor@gmail.com>, 
	Arnd Bergmann <arnd@arndb.de>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, 
	"moderated list:ARM/Mediatek SoC..." <linux-mediatek@lists.infradead.org>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vbw+LKbb;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::533
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

On Thu, Mar 11, 2021 at 6:45 AM Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Thu, 11 Mar 2021 09:32:45 +0800 Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> >
> > Hi Andrew,
> >
> > I see my v4 patch is different in the next tree now. please see below
> > information.
> > https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=ebced5fb0ef969620ecdc4011f600f9e7c229a3c
> > The different is in lib/Kconfig.kasan.
> > https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/diff/lib/Kconfig.kasan?id=ebced5fb0ef969620ecdc4011f600f9e7c229a3c
> >
>
> They look the same to me.  I did have `int' for KASAN_STACK due to a
> merging mess, but I changed that to bool quite quickly.

There's still something wrong with this patch in the mm tree. The
KASAN_STACK option is duplicated in lib/Kconfig.kasan. Badly resolved
conflict with "kasan: fix KASAN_STACK dependency for HW_TAGS"?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxBcFgft9yqNMEKs42tEWEDt4Za9n1_t95PAEiS7Cqibw%40mail.gmail.com.
