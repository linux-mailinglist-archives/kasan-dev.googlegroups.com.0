Return-Path: <kasan-dev+bncBCCMH5WKTMGRB5OBQ2AAMGQENBMQ7RA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 51CB42F7D98
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 15:04:38 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id l5sf4860354ooj.2
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 06:04:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610719477; cv=pass;
        d=google.com; s=arc-20160816;
        b=zhNyoqNWscvmXh8HB7/50U55B3eOtVDwLC97YUfSYocedOT5Ck0ta+irIaWXFIvteo
         qJaSlZFMsU9qxkpKFmClWDPKiArEBRYS9wNvBCY7HjgHrPvwT1Ovhp1qfa3CA/odo4f0
         2x8r7wN3ujDZcBL8PLQiEHQIiAomwuaTOm3IdtkLpz4FJnDTkXmFTBfxBJLLo0DlhbRb
         ST/FxZFZgwTCDwg3RXpNuwVLbgs4mwM2KO6EI6B/7WGy3cNE/Iuh3EJbeYI+zkLIjdf1
         oOe85aYr5fF5s5PCsYLnBmgmCWV+swdzUOlnFNOZvste3kmzd/4Wv4q2cFbqL84SjfYe
         lxpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kQ/hVfxeyPGkZd86JuSUXtrnAVDUPsr2diIccAwvNxc=;
        b=Juy8a2n7uPLLg6i5G0UOSah9S5ZakDyqUWvJ9tdil4DaF/oqFBMkwM75B6eY5+D8VD
         3AJFr7nL+XlVr2JgAcTvVqboMo3Rejnst4A1MI3G/qg7o7wWzKCgYauxuiMDTu4ewDFL
         90zV1GcqRi/196OKk+y3gPnzQB36c9qQNAGTMOiV8YdCVwTYYVKjPt3D7Ep+c8CuN1k/
         hkxTsSAM6heQYHm9oqeiv31IRXSgxkMAjXYnC3/EB6k1521FiBgYH82JGHpoFHugSgE2
         M8229wo6hrNKPh9u5N4LWQviJjUmJNhjZI636L3PQBLRHFqCBwS6PIass1s7HTbrhFQf
         XChw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iNs2rix5;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::732 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kQ/hVfxeyPGkZd86JuSUXtrnAVDUPsr2diIccAwvNxc=;
        b=S0NLziM1MlQliEiZM3ToqNCUMeapbTCwA1BpckchtsAcY18IDEtEAQ0QQQnCXs6F4o
         6VMDs9oai185dfVjX/jtvTrZDaBXmcuQewsUDnhoPUZk853FOsFykrOdwWmBwzGAdu8A
         PN9SG+1YumnrNdA6BnSi/O5AmEyCUwxEBCMckw9AklJnHCbla6E6RcFvTbdKlIhO4BVl
         Gs/Rd7lltxJjS5dfhDioIF0IL/Dya+fVvtS5GD44v1zK3q75nOIeyIDcWljOR4I4+gY/
         tf35BTJFf4drZ1tExfCdNGGBSRdii4m2JW2N5Tsfj2lnkeWbsUrIdBb8FgMf+agmwUq+
         BbMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kQ/hVfxeyPGkZd86JuSUXtrnAVDUPsr2diIccAwvNxc=;
        b=MzdFALl+04sRxavt/dVp4Oxgsu4rt84UxZnHg/RmvFiVNMQ+Lka1BSQl1ABxyawwPb
         NB3DB6B6lU7lAJEX2OIxl9wYYJDKQeUoesiQXv+kBJ8pyS4RtJ4DwmCKDZykCPxvZJLh
         UE4CAYK2lnw6Td1YJ0E3XgCbYCLJjy7qGpJPUnXzttTUXNwGUcM8RjFotZ7qG9TU3kEd
         x7dLpD6aO8mDgdwhW7UKqu/2MLQ/b/Y5Jjdt6UePeyhScpcQQ7dyN5eWIn8r9sV/J0jZ
         zGfDqXECm1INcln/0oYoYcNpzfHtFc8GgqeE8EufKx6Gj6H5beWeO0cja5oYXu8vEcbb
         co8w==
X-Gm-Message-State: AOAM530uNJyJU58KW4t4YBEhVPpT8QtKkYwCig5fvSu/Kl9v6sQVzhaS
	cUjxCb5IMjQoWmZHtefUztw=
X-Google-Smtp-Source: ABdhPJxiFHFV3Ch1m1MYdjeKDh7E83ylK5127j4TgXWifeuk6AFmfvv8VPtleFcUvcyhYzgZV7xX0Q==
X-Received: by 2002:aca:75d3:: with SMTP id q202mr5630944oic.36.1610719477311;
        Fri, 15 Jan 2021 06:04:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7c95:: with SMTP id q21ls550371otn.7.gmail; Fri, 15 Jan
 2021 06:04:36 -0800 (PST)
X-Received: by 2002:a9d:6015:: with SMTP id h21mr2234278otj.365.1610719476855;
        Fri, 15 Jan 2021 06:04:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610719476; cv=none;
        d=google.com; s=arc-20160816;
        b=jc0KC7/6jt96TX8jvu8oG8ZyLDiWbTgXjggotvgbo07fsinfI6uxQUtPsVNJuik4as
         0dzM1Z/GfgLx/wXWsK2ZJysKlLFmwAiYFKddXrRf+6G3/ZLi5vL7mS46b4WY5ryCWGEc
         yOzrgIHnifgIoMqIeU8SfkdLYnZolr0af403LG2I4ZyQTUfe09yDaDDWQOy09h4w0f8p
         KTHqsGUW5DY9gy4sj/lB2437Q+otSk6cVus7bBkxYk9Du4j9EJIJp7uifAjEZ4Cllduw
         EUTRg8gbOhbnl1BWLpojK8Da6xaeJ/admT50bl8/pEM/mkTNj6D1o7QWzFFk5D9wO3Hx
         kmxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BvQ70dhce4kxItaPjGS90KL/Tl/xCqV5rnfXoeOdY6Q=;
        b=KiqVwCXii8TqciTQmz0uca3LX0uYmDmYiTwh1DX9X7UPTInAeqkmZ/NtfvgCHRHZf/
         D4B1HlwQBc0XhQDjf+51lzVm8iExTK9EwgH0JQywXoWnXZiHnYh6ibx8FTR+lReZaCfy
         q5CbWt1htD+hPBVulkfdvO3QmWJBSEYmObxypwKmw7VWzLxe9TrTQFArYdn5QyYFQ6nr
         378K6VfuIwPL+5v4Y/EjLpAXTodcLiSY5FYZN/HplBgIj73NEY6w50H7Q91QXci/KXEk
         IrrJtwySuvg2oVgHe+cT/dX6OZzeqy0KGlnGOl5PSXHBNB4ZHW1khuaZo6E+3i4I1+Gy
         yOMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iNs2rix5;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::732 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x732.google.com (mail-qk1-x732.google.com. [2607:f8b0:4864:20::732])
        by gmr-mx.google.com with ESMTPS id u2si776405otg.1.2021.01.15.06.04.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 06:04:36 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::732 as permitted sender) client-ip=2607:f8b0:4864:20::732;
Received: by mail-qk1-x732.google.com with SMTP id d14so11651787qkc.13
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 06:04:36 -0800 (PST)
X-Received: by 2002:a37:70d:: with SMTP id 13mr12162251qkh.326.1610719476289;
 Fri, 15 Jan 2021 06:04:36 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610652890.git.andreyknvl@google.com> <bb93ea5b526a57ca328c69173433309837d05b25.1610652890.git.andreyknvl@google.com>
 <YAGWA4EWQQd+7e+v@elver.google.com>
In-Reply-To: <YAGWA4EWQQd+7e+v@elver.google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Jan 2021 15:04:24 +0100
Message-ID: <CAG_fn=UqURzPmvP14ULhecDtpgHNOzgcdmm8O8w4iEOWJHu1LQ@mail.gmail.com>
Subject: Re: [PATCH v3 12/15] kasan: fix bug detection via ksize for HW_TAGS mode
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iNs2rix5;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::732 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Fri, Jan 15, 2021 at 2:18 PM Marco Elver <elver@google.com> wrote:
>
> On Thu, Jan 14, 2021 at 08:36PM +0100, Andrey Konovalov wrote:
> > The currently existing kasan_check_read/write() annotations are intended
> > to be used for kernel modules that have KASAN compiler instrumentation
> > disabled. Thus, they are only relevant for the software KASAN modes that
> > rely on compiler instrumentation.
> >
> > However there's another use case for these annotations: ksize() checks
> > that the object passed to it is indeed accessible before unpoisoning the
> > whole object. This is currently done via __kasan_check_read(), which is
> > compiled away for the hardware tag-based mode that doesn't rely on
> > compiler instrumentation. This leads to KASAN missing detecting some
> > memory corruptions.
> >
> > Provide another annotation called kasan_check_byte() that is available
> > for all KASAN modes. As the implementation rename and reuse
> > kasan_check_invalid_free(). Use this new annotation in ksize().
> > To avoid having ksize() as the top frame in the reported stack trace
> > pass _RET_IP_ to __kasan_check_byte().
> >
> > Also add a new ksize_uaf() test that checks that a use-after-free is
> > detected via ksize() itself, and via plain accesses that happen later.
> >
> > Link: https://linux-review.googlesource.com/id/Iaabf771881d0f9ce1b969f2a62938e99d3308ec5
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUqURzPmvP14ULhecDtpgHNOzgcdmm8O8w4iEOWJHu1LQ%40mail.gmail.com.
