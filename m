Return-Path: <kasan-dev+bncBDX4HWEMTEBRBEEOQKAAMGQE3I624ZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id BF2CF2F68AB
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 19:01:53 +0100 (CET)
Received: by mail-qk1-x738.google.com with SMTP id g5sf5405623qke.22
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 10:01:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610647313; cv=pass;
        d=google.com; s=arc-20160816;
        b=Sb4aNtkuMYAjYKQQlP9+cnilafO+cDgtdUIilux9YHvNzpawJdvcoHHvKM35ZyNsH5
         RAxDkDOnZRwTVffjmwf6TasFd+IOoFHSDEICGY1Ma68NOgUfPeVdZ/qUlDr60EB709uG
         TF/YtAlGxbiIL/7eReV0yUJVCDMJqhgbv5Lk9l4gT1GYh2Zj/MCCrgvaYJjXlWxck9LV
         N9NXBVxfmfsn8b5Scn2dTm9EKOA/3gTfc7q76Cm61WTqap095c5xrIA2J0QWfpTk/bdl
         NvXdONvJTPap8w1OU2oXlPTapiBQwknCe/7XiNRwcJqDEVjqpRglzOnUN5zK2lOMm8cX
         S7Hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dGZRWmbLgizQBWXW5ObCblHassmKX9Ui2EdailkeZf0=;
        b=mWdcSPRenD8xRuAJHzgdfNyIhqLscPhzjqTnd1XR+6CzSsbHqotUPtrqquzcdcJO69
         7ZRXuDrMtul1NDHxjGEjtJrjr/Psi+GSNXwW1tJcXiLwx+OGr8BwXVKSDeuVdCjYi6iD
         XwJtsLwUBVNDG/MpZ/iyijmSa4zH5uzs6ZlwOY5tSmqhyb5czyhAReBTCL3OUKsEzA+z
         931Y5t/E9gWDBjJVl81P6v023nrBXsoSzV5IK/1U0170LpC3je1AC242Y0FL7IvwJUjx
         Gltn5xoC8xhH4hqLJxSrfruR/9wVacMzjZ0eNCccX6JSJbsJCBCUcjfiDmCelLhElspe
         YW3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Rm6m7vXo;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dGZRWmbLgizQBWXW5ObCblHassmKX9Ui2EdailkeZf0=;
        b=TRolMXzEbwcOcEJCTAFvAsg6xKkXQzxUw7UA5Vzym/JYOAspihBfzeAziT4hfQkErh
         KUz4kR5KVOByASEg8/VrZwvEqvX0iDLiyWSM+js0EPsFE3qM5fWnMT/3AMewadnGoRZv
         cO/oIggJUbOV1juemjnHQK95OMB17Td+hqRLnmnaOSTe9Ssfg66rnr69rkkO/tB5I51p
         Kzqdt6hCtC9HT4W3T1LE4OJBebmp9ByBvNI1W0YlXdAgYDL48cyUBcrdyQ2z9bf6ES7+
         wRQ9LV6IFh8gIPZdqjqnBw8FhaIunNQ//wXo8HVWC4GuzFZpyYzxahdhGMdhuQtBUklu
         pfGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dGZRWmbLgizQBWXW5ObCblHassmKX9Ui2EdailkeZf0=;
        b=ecFwonFaeorvnU3TAc3mzJCPJrDXKh2inwaAFxGgujQkTK1CJOoHkGcumwcAymV2Jr
         qjaV+yPHQLWKPhSjRAzndYbP6GmGbYsiOW2ONQbyc/Bw0B3RQ+bDTj8/WufqBAF9ojIi
         G44RRVkhh4TGaOOvHsrxY82eJIJCEmqIryocmFlnJPLGE9sV5xuzGjVH8hStPr7blSBz
         0sjcYwt57crMOiJU0s234swjeaOiYAQ3p9oR8A21SKXmdxlhDYxhMRCMJwTQweCaG0E8
         g54mcGsWjgh1XlXnNtET7YYWm3H0pWKgEAyZmt3K/Tx2mz//sRAdds+UZM73xyPlpawh
         QgPA==
X-Gm-Message-State: AOAM533hG62OqVyD3vqlqXGvezn71/Xev3o/qPQs04yQiCREg5mQ+JkD
	GK85T/h91ESI/7KHvXnn8SQ=
X-Google-Smtp-Source: ABdhPJz4bUg4bd8NTTyIMaaYAGVwaRf4HG6LKzJFxqWM/OOwNDdh0E1r+uhInHqtR/QwujrZmyz6Kw==
X-Received: by 2002:a37:9c07:: with SMTP id f7mr8142515qke.234.1610647312896;
        Thu, 14 Jan 2021 10:01:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:2350:: with SMTP id i16ls2878001qtc.10.gmail; Thu, 14
 Jan 2021 10:01:52 -0800 (PST)
X-Received: by 2002:ac8:6f69:: with SMTP id u9mr7994370qtv.16.1610647312485;
        Thu, 14 Jan 2021 10:01:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610647312; cv=none;
        d=google.com; s=arc-20160816;
        b=O0NYNArHeOIXRed75B1nRtZCk+V0oudfPl6ar+N3jNuIzBpMb0+6c+mj3nRBKSym2H
         QzucKIJIX8dkzSgGqEbtmHep5V4rznq/Kazj3R16Fq1BwRAEOK+gORFKVT/x/6ASCdrX
         UIg+IWyod610VtUVd9qi/DZCB5I8DvZPjAc70+Nc2VF1X8P604jG0kgfQ9PA9nigGI4v
         XTa1fEsPO2m+5eMtg5p8CjgmTeWrLk4COXOW15PFtxrBJhhslhgwP7HzQRbDqGNBpR7N
         QoX8RtfBlyltDPlZhYM8zcTxxDs1fTanPERPFwZuRYlMAXex8wh+T5wHFnaVHr8Azdye
         u7ZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JZv4YjfcgChZSuWtgMAj6ahr1eW9ywFtx/Fxp020AaY=;
        b=RbvWRCQswrQvmmlFC4OZkMgHNJQ8k7ueGRdlKmUxyQZWkxOktSEJKzsyPDNomVLdMj
         X1DHs+g4RhNrRFOC5m4tj85hoH4lhHi1vbUv5tqqLQGy/S6DsTDBFxShvj+LeW1/6Qo9
         oypSS6Ags0iE078xX4MsKCY/rhDKQs7vj8MMlKKPyb/FOKS4kb0WV1dcwkKFTKRFUvJr
         XYv2u3ezqaE6Hj+9wWS06qoYvdVo3Bp2fLb6kRTb17MIBTdCChtKwYCtUQErU/hyrhnx
         8ed/AMjPGtri6hGj49ou+Q3Lwj3Q+uTNbEmLlVMLWw0ykV9hywBpB8MgxNrUd/tzwRNF
         caVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Rm6m7vXo;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id c198si316280qkg.2.2021.01.14.10.01.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jan 2021 10:01:52 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id t6so3315571plq.1
        for <kasan-dev@googlegroups.com>; Thu, 14 Jan 2021 10:01:52 -0800 (PST)
X-Received: by 2002:a17:902:9009:b029:dc:52a6:575 with SMTP id
 a9-20020a1709029009b02900dc52a60575mr8283559plp.57.1610647311542; Thu, 14 Jan
 2021 10:01:51 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com> <77015767eb7cfe1cc112a564d31e749d68615a0f.1610554432.git.andreyknvl@google.com>
 <CANpmjNPX9yn5izxtYMq14Aas2y4NA1ijkcS9KN4QQ-7Hv8qZEQ@mail.gmail.com>
In-Reply-To: <CANpmjNPX9yn5izxtYMq14Aas2y4NA1ijkcS9KN4QQ-7Hv8qZEQ@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 Jan 2021 19:01:40 +0100
Message-ID: <CAAeHK+zD17_esgDvsUd3Yku4cCKDdADo82_u3c47tMWtHL63oQ@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=Rm6m7vXo;       spf=pass
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

On Wed, Jan 13, 2021 at 5:54 PM Marco Elver <elver@google.com> wrote:
>
> > +/*
> > + * Unlike kasan_check_read/write(), kasan_check_byte() is performed even for
> > + * the hardware tag-based mode that doesn't rely on compiler instrumentation.
> > + */
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

It requires kasan_enabled() definition. I can move both to
kasan-checks.h if you prefer. However, the only place where
kasan_check_byte() is currently used includes kasan.h anyway.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzD17_esgDvsUd3Yku4cCKDdADo82_u3c47tMWtHL63oQ%40mail.gmail.com.
