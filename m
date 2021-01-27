Return-Path: <kasan-dev+bncBDX4HWEMTEBRBVF7Y6AAMGQEIFRLQSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 261A63066AA
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 22:49:09 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id k24sf421260qtc.2
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 13:49:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611784148; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mby6b9TOk4iHtsJmUN95KYeQxmVHh0284XuE4BqMKmvedLbB+xiVdTeyIq6jYAWalb
         MJnmqtbsOIEUJnnQbdxnvPBkkBMKpp2/udhlb22Hhr7Cy31asiYzWp3yN5yocawzGOxi
         6gThWaM/IcREXskomLoHyoMcboJd7yyu7zg06DSY78wPz29AuGqQheDOEqq+N50bYArv
         At0iKCg3tZSJ5U7ElXDHxcSP5386WoTOqs44S/hhXFOzsWuOFpwIIIjzcHXQycsoVkXr
         I+XlLm5cHvImQb+iXx+R1fefDaQl4jw0J+k5ZFuWPPfZJRwafKnKpJvuCApp7FZa+aFH
         K5Rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Mv2F3NTGwUerDRylrLWRH0MRxURyXq3JnpcdSbjBxRA=;
        b=GezKoiopXHT6iK3zTK6SPuc8qiqEtZt2gAhKKn7vBnuLVGhVLrZE/7t90bPi/uort/
         pWlAkm+hoF/LGXW0KYoPmJ5GIz6uISAfY+7LMiahDm6f/bdvYwW8VzXLakZUqAm7+ZPS
         5v6uOpqPE2QqwvC/yETfDMq01YV46n3hkgZm+QTfOMxDhhqgUK8ScCLBih0Bf75TgVhH
         XeKllF5OWtM0Cq2iM3JG5nzmHmUGaLUlIg5syptxAzkF5/KXBoXmrZk2uxo72PYnAsyU
         HpWdvsE9PyaxnmlAJgjr+56QK/0my69qtoNtszllphIR5CMx1mJ3xdkb5+oMrXqq4qTG
         IdNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=V0jvldsg;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Mv2F3NTGwUerDRylrLWRH0MRxURyXq3JnpcdSbjBxRA=;
        b=JTz3nBwyTWDRFsuEZE+Lhfyk77blhNU81/dct9X4jl78uQD7eOHSyEubbTQ1yGl4sF
         L+xjCbelgFRqwPmHhFr4Jc0aCp7yTMPQmpuzvz1DEGeuGRR9XT2pvwD6TJjXbHf1gt17
         rwYbYX8HTqWGp9kLp3Kq1R+znwLMRRjqexRRvDzNy1NVgePNkR/3elIXJOOM/AiFAC90
         i/XEF8JJXk1yqN+LWJYY8LyZBnn5AA2Bboz8MC3/EY6IGbTg6BUOnrSSE8xAJMLfdytU
         CMNJAvWBRnWgj/d8Eq5s65qkEgN7cnJyQmMWIMIXDJ3GslBU5S09ijH0/Vssd6DfMCot
         ef8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Mv2F3NTGwUerDRylrLWRH0MRxURyXq3JnpcdSbjBxRA=;
        b=VFIec4S06KPGhjyHg/e9lSHm9yk8uPMEzr+DiVra2jX5Cqg3CbCWIU+e/9rZ3FdPe8
         +v5qt3yt0eIP6Nwq+KYIaqc6ks7z6y7svaBMxGMtS10T5pG5M/iWKfGuvKPDwpP7fvxk
         4b2BjEdvT3+M6ncSiV+gPFtE2aD09aOCYbvYLR9OFsMLB4dqSb377yqv4moGbUbI41jI
         2uQ68nqHwKrgeA5KNexBs4vGpjI4hjoWx5wjpTH9td23eOxVHbtqBhiY2dKEyPod7plo
         YMdtWh6MPZyc3itKfrwkfqvCLha4nkSzqiSSJtG5l6uQI8mWL1CMLbUOzGfXLWF77zOw
         ThXg==
X-Gm-Message-State: AOAM532oBG9tyBGGv84pBAspPOznkKAQINUVBG0CBQVF1vMLAujDVMb3
	N7bN++XShhLZNcnKn12P/Ps=
X-Google-Smtp-Source: ABdhPJzcPNvt/lmkVqUa64a/ikug3ufayJnoYTrPjHCNj3Yut0dX7XIebOpDoj4s+NZypCVhMbTfkA==
X-Received: by 2002:ac8:36e2:: with SMTP id b31mr11830550qtc.19.1611784148198;
        Wed, 27 Jan 2021 13:49:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5bee:: with SMTP id k14ls910675qvc.10.gmail; Wed, 27 Jan
 2021 13:49:07 -0800 (PST)
X-Received: by 2002:a0c:eda6:: with SMTP id h6mr12265515qvr.19.1611784147857;
        Wed, 27 Jan 2021 13:49:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611784147; cv=none;
        d=google.com; s=arc-20160816;
        b=XpONNgaQc4a4GN1j7Yw3MnXBHIC9dudDH976XhfHX1dJMAkJiuK9fHNEhSUrx1OTLf
         Qs1Vht45t+q39LMO1iCos2OsPj3oEMRTPY1nsUV5SXNnFzadE5jByQ9UA4RjFRVgpysp
         8j2XZEnl69ks4b/4X4uivF42v8yKTDqfhz2sgaQuTl/Ng+JaYMi4ZP3Hx+kSGTHid8DU
         ls+pouAy/QPWzfOzrkTcnXolP/PvsRi/mNQa2x75pmzLY20DyvLy3x3cgGAuehCOryGh
         /nUARjv/2GBNdyOwqWGyNXEfWrD4mloM6fXfk4n5ZXWKT3bTof9PtGXWVDy9WqohF+7W
         N+6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wZd0cLL8ZkUlig0+5sOea8FRbUknLAg/BHGcl5UT8Zo=;
        b=i50Cln/tzVelcMyFdumKL5BGj0mbSXzEGr+Z48Hwig5h0F9OGxAK73N94zUpfNcOsg
         JQJ3OLKuGey7OiwZOCsm1TliOqA7SjQ719u+4fY1jVMEldq0hwAFg1+V7O4oQDaGtUIG
         V98l7ZhkXmSrqYryIiBpOZKUMvKcfJ+8SCVWvWu1QtjlwgrziUP5ho+45EZFfbRP8NEf
         l+o7q3l/dehzp4b58DF/Cl96ayHvzXAcoTy8jKyx+nr684/XE6dlpo8UPLoxm39KsHGY
         79e2YzS/RkurDJpgqcPIde4V4zpLSqECHA8br2C0tg1ZAxtqOEtmuXtFhdPfjYRatkd0
         r4Ag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=V0jvldsg;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id i2si99210qkg.4.2021.01.27.13.49.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Jan 2021 13:49:07 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id s24so2173987pjp.5
        for <kasan-dev@googlegroups.com>; Wed, 27 Jan 2021 13:49:07 -0800 (PST)
X-Received: by 2002:a17:902:ff06:b029:de:362c:bd0b with SMTP id
 f6-20020a170902ff06b02900de362cbd0bmr12924105plj.13.1611784146896; Wed, 27
 Jan 2021 13:49:06 -0800 (PST)
MIME-Version: 1.0
References: <20210125112831.2156212-1-arnd@kernel.org> <CAAeHK+yOTiUWqo1fUNm56ez6dAXfu_rEpxLvB1jDCupZNgYQWw@mail.gmail.com>
In-Reply-To: <CAAeHK+yOTiUWqo1fUNm56ez6dAXfu_rEpxLvB1jDCupZNgYQWw@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 27 Jan 2021 22:48:55 +0100
Message-ID: <CAAeHK+w4vt6ZDH+Nxy0z4-FzgViDDCDY+jhAXXsUgQKh0bPi7w@mail.gmail.com>
Subject: Re: [PATCH] kasan: export kasan_poison
To: Arnd Bergmann <arnd@kernel.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Walter Wu <walter-zh.wu@mediatek.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=V0jvldsg;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1033
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

On Wed, Jan 27, 2021 at 10:25 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> On Mon, Jan 25, 2021 at 12:28 PM Arnd Bergmann <arnd@kernel.org> wrote:
> >
> > From: Arnd Bergmann <arnd@arndb.de>
> >
> > The unit test module fails to build after adding a reference
> > to kasan_poison:
> >
> > ERROR: modpost: "kasan_poison" [lib/test_kasan.ko] undefined!
> >
> > Export this symbol to make it available to loadable modules.
>
> Could you share the config you used to trigger this?

Never mind, I realized I've been using a branch that already contains
your fix :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bw4vt6ZDH%2BNxy0z4-FzgViDDCDY%2BjhAXXsUgQKh0bPi7w%40mail.gmail.com.
