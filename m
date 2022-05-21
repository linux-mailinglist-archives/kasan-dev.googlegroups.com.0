Return-Path: <kasan-dev+bncBDW2JDUY5AORBNWLUWKAMGQEUBE3VOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 386EC52FFC5
	for <lists+kasan-dev@lfdr.de>; Sun, 22 May 2022 00:20:39 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id k2-20020a0566022d8200b0065ad142f8c1sf6230802iow.12
        for <lists+kasan-dev@lfdr.de>; Sat, 21 May 2022 15:20:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653171638; cv=pass;
        d=google.com; s=arc-20160816;
        b=M3/8eCTQSbUhZMTMotI7jm2480mvl/4MVXV3nr8pLmvVZE39mRH7JhyXj0a7IOE/66
         1lWvjLaGsUaqJ8nJAmVy0Xv44amKJbUZA+M7PVvR4CV46dYYA4SM/ClIsLfZBioll+k2
         euSYAoP7yxvXc8vzQej/Ql4ECcRMRrMo0w/Cl1IqlFdlK8ryeI2ZkLO3EJvkkpX+AuP4
         cICG/bSUGjhkDQoElJpBoDKKwCpQtVqWAU/faHVIiNDulf6EdDsgB2Jmj1sU7psTHH/3
         uO2Y7kpQmokskoJ5fQ8GBix0pC0Gyc+h23Z4WLpXQ6AqxMi9e7K3OFQmVYESpk6K/VPA
         tHlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=f1vwEYGJ5h7L6lqwwqrYqym5a/UNCyoLVt1ELYbQ4JU=;
        b=FvdASzXhou4jluZcv5fclodI+Kf58HYHBK//hPa2FpRUQ+qBwFyXIbHAj9gnxZ31Je
         xxbTLyg0kl7JgEbWrZgNSv9Z5f9MfRg0c0hCoW0pi9DRimKnXavBoZLEEnvtqKl4XH9V
         44FJ66t0+wmIdMz+pKsnWkf68EZb4dPGjPUQQqz5B3TMw3+g8WmoxRE4wX9NkA5ppaWn
         0egp2AmlV5bqrpmyCwxuGGRSFM+sIL/MUVaySQrMPJxFDQL7ap5gLmHHGGB3YOnvEPrE
         nX+FUbKz/THhC2G5GrVhY5XWEA0r1zL5NbJ/2pTZnFH38EW4cW3Q2Kz2ZunY37i7DCaM
         l9xw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=RW8wHPY9;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f1vwEYGJ5h7L6lqwwqrYqym5a/UNCyoLVt1ELYbQ4JU=;
        b=hQHiEoQt7As1FV6LaYyzd7Kx/dSIvVXKJbzQKKDMD3Pmce51DheWYeg6fBBraBkq4b
         i5PjDxHKfLYM0ew8uw5hIZwJzeh4rlMLKvO+BnSsoy1eEMMFp+9M2TXtxeqV4iUZ4cEL
         ztYL6DbU1U1VgkX0CCFEt3sFvRqE28Z4UX+vUO4IN2pbNPCm9sVsaXOpNl0/QQPH917D
         /TVfqQSY2V+KbUIgNEwG/Bq3pgUMGgju2PAOrDycUqUukRTQf/F7HzXBuxw8kTRXAiKU
         U/pU4Fbh4Q1OUouIfB3x2u9+j1GrVkOEZrj96jU3ih8YaPIue9iYv3AYHnA/OdOOWH10
         rdEg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f1vwEYGJ5h7L6lqwwqrYqym5a/UNCyoLVt1ELYbQ4JU=;
        b=RlDqC16wYbx1V9UbIXGmnWkWwuDx2aOGQrbHZjUjEVU7qiAuOj5Q3wuLxBrW5O0vYs
         uKRr+VOZYQVf08K4rkW92qBqeW7LAe0mPZmtcc3Q4m9h4GcjHWctOGBntMuiCzC0bhSL
         utkOFIhIzTB8RCQY3JQwreKoa5LGjLfWcWX4XEnJWWCK3uLMls1MUNkfvWoPxeY3QkDs
         V/mNpWBDH9w199ABJDbu17lpe8RlXg0IHjroZUzqjYeoaN9yaXxSq9lYDoXy53D0GpZW
         prOHGThBvHHAWsMWqswfE5i1H/mQH8gqSFjJXA7A3SiDXG6rf9TArQLQ2n+ghWHBGCE0
         ytJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f1vwEYGJ5h7L6lqwwqrYqym5a/UNCyoLVt1ELYbQ4JU=;
        b=ZWAwgT/4aSbDGLizdVcwfgh5vbJGuWdoFPml3WBWKrJ8NtA+5k6+SQ31eew0Ql6Wct
         G0RHglFRctCDAZ11ebNWGuprhGT6qYs7jIxp10EVPeW0jBpVU42EWOtf0fXrBb8mpv9o
         8Rg6aCVzig7g0WnfxUK6gu4BGAGG83orxbRk28IQnqitjvDrTYbso2oCpYodkpc42f9n
         xhZA6puUEVY4eVwq5nuollNEdJlafqVPuGoVb1x5u6tBBx9tCPoFINshHb0foCcvaUTw
         xwiWa233Gj3Nd2Zy2M8zHK8CjYgjd4kC8yaGf7gb/hrGyLQSY96yyR6xR3E2ICs3m6Zc
         dndw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ocQHlNx0MPJv+zaHK379sbjR+Tc514glDopY3/f2Of1K+1I18
	fKoytOBBdMrc4blr2E0d40k=
X-Google-Smtp-Source: ABdhPJwEyZcX7HqMLqcBxoUcnp2D3sgXyDn6Tco0vvR+5oTzATMrXUwSi7mHz4L6pWKmoMiPhNBGvA==
X-Received: by 2002:a05:6e02:19cc:b0:2d1:2e5c:a1c with SMTP id r12-20020a056e0219cc00b002d12e5c0a1cmr8119937ill.177.1653171638155;
        Sat, 21 May 2022 15:20:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1c84:b0:2cf:2c9a:f951 with SMTP id
 w4-20020a056e021c8400b002cf2c9af951ls1378918ill.1.gmail; Sat, 21 May 2022
 15:20:37 -0700 (PDT)
X-Received: by 2002:a05:6e02:1bce:b0:2d1:3fd2:645d with SMTP id x14-20020a056e021bce00b002d13fd2645dmr7997242ilv.299.1653171637767;
        Sat, 21 May 2022 15:20:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653171637; cv=none;
        d=google.com; s=arc-20160816;
        b=O7qVPPU1hQ/ITlRMk4yK+o/YhRszSJF/tk+2nDNJaQk5WUTKbPbrk6Hpq7jK7pE1bP
         o5G+jZJAPepotyhHSV8fS08oSr2IdLqTxA/FRUWzH1EOCJS6JAe+K1H8rN02s12PUr1B
         eW31vEBlMU1PZDLINptIxESRn1xitnfs0xZ1R5O6O9sv8tWxSCxpywAqljE0hmq1suHT
         erWc29R5REHrd018oLZqQJ0YfHLQ2Z3il5Bl0WFMYfvxB2oeF8IGlv5yB2biCqVGzwJl
         l28vJd8GZP/TE0RkrO0G2Idmh0m1BnqPyfDl0LsAwqN3qL+rc/HwNdn4VW75egcR/NPY
         HEGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zonrSx1V++s83FsuhPd3xXGHEC4UJOauUo03K8g81yk=;
        b=P3B7ZOJwFJiuKsb/8PBhbcVsxn1o2O6XiODYlsOvBEOe0jApC8adp3oZ3qVdt26v8h
         uPxpJeEGt/HgDTQbyX+MnJvUeMDDa+XXaoSA9JM4029bp0zO+Gkn2U9tLPzy4mYqjfGc
         FRE5eXHDMt0wJGhRyWJDMg0xzTddhx/jNleRQhOB2iMZFohubT2NJYkIQmriJ2P/Z7EY
         3HjApPBMTU4dhN6g/AG+pUT+YTRhG0radD5Xb1EQByroFPEeEeqFiP8vlhjkhrVj0rhX
         W/nvC4kmzOmHSBEHTtRLp0gMTMliUnbI5BWynnsSSlTMmLvNzR4wE4nnUJrqC3CXGVpW
         hQ6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=RW8wHPY9;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd35.google.com (mail-io1-xd35.google.com. [2607:f8b0:4864:20::d35])
        by gmr-mx.google.com with ESMTPS id 7-20020a921307000000b002d19fa6b1b2si45885ilt.4.2022.05.21.15.20.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 21 May 2022 15:20:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) client-ip=2607:f8b0:4864:20::d35;
Received: by mail-io1-xd35.google.com with SMTP id y12so11990265ior.7
        for <kasan-dev@googlegroups.com>; Sat, 21 May 2022 15:20:37 -0700 (PDT)
X-Received: by 2002:a05:6638:d13:b0:32b:cf94:275b with SMTP id
 q19-20020a0566380d1300b0032bcf94275bmr8777103jaj.22.1653171637531; Sat, 21
 May 2022 15:20:37 -0700 (PDT)
MIME-Version: 1.0
References: <20220517180945.756303-1-catalin.marinas@arm.com>
 <CA+fCnZf7bYRP7SBvXNvdhtTN8scXJuz9WJRRjB9CyHFqvRBE6Q@mail.gmail.com> <YoeROxju/rzTyyod@arm.com>
In-Reply-To: <YoeROxju/rzTyyod@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 22 May 2022 00:20:26 +0200
Message-ID: <CA+fCnZe0t_P_crBLaNJHMqTM1ip1PeR9CNK40REg7vyOW+ViOA@mail.gmail.com>
Subject: Re: [PATCH 0/3] kasan: Fix ordering between MTE tag colouring and page->flags
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Will Deacon <will@kernel.org>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Peter Collingbourne <pcc@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=RW8wHPY9;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35
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

On Fri, May 20, 2022 at 3:01 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> > So this change, effectively, makes the tag in page->flags for GFP_USER
> > pages to be reset at allocation time. And the current approach of
> > resetting the tag when the kernel is about to access these pages is
> > not good because: 1. it's inconvenient to track all places where this
> > should be done and 2. the tag reset can race with page_to_virt() even
> > with patch #1 applied. Is my understanding correct?
>
> Yes. Regarding (1), it's pretty impractical. There are some clear places
> like copy_user_highpage() where we could untag the page address. In
> others others it may not be as simple. We could try to reset the page
> flags when we do a get_user_pages() to cover another class. But we still
> have swap, page migration that may read a page with a mismatched tag.

I see.

> > This will reset the tags for all kinds of GFP_USER allocations, not
> > only for the ones intended for MAP_ANONYMOUS and RAM-based file
> > mappings, for which userspace can set tags, right? This will thus
> > weaken in-kernel MTE for pages whose tags can't even be set by
> > userspace. Is there a way to deal with this?
>
> That's correct, it will weaken some of the allocations where the user
> doesn't care about MTE.

Well, while this is unfortunate, I don't mind the change.

I've left some comments on the patches.

> > > Since clearing the flags in the arch code doesn't work, try to do this
> > > at page allocation time by a new flag added to GFP_USER.

Does this have to be GFP_USER? Can we add new flags to
GFP_HIGHUSER_MOVABLE instead?

For instance, Peter added __GFP_SKIP_KASAN_POISON to
GFP_HIGHUSER_MOVABLE in c275c5c6d50a0.

> > > Could we
> > > instead add __GFP_SKIP_KASAN_UNPOISON rather than a new flag?

Adding __GFP_SKIP_KASAN_UNPOISON makes sense, but we still need to
reset the tag in page->flags.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZe0t_P_crBLaNJHMqTM1ip1PeR9CNK40REg7vyOW%2BViOA%40mail.gmail.com.
