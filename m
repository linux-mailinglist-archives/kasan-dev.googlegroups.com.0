Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSWC5T6AKGQEUO5FJKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 47B0A29F5E1
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 21:08:43 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id e19sf2578446qtq.17
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 13:08:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604002122; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jj4JnwRrd0pm87HF+6dAnfmNQA8gK/6hk1ktL/i9JUn17ce7+xLwUV8hR8JUH5RzjX
         6bv68Mv8tPdfwVOgIy0gwA9s7Bfa+6E866zxKGlWR5AcjxY6rlBJUMvCF3Ns5e/Yn46l
         imjjzgSFWAhOsdL1OWUH94NpQP9hePc3vTptB7ArxrOYhi1AOvI3yE4mj+WmDJMIhebI
         5jAutegPeTanTgLKYHkU84VHtx0cqJIFLHnpMj6VfCbiCcfQeG7vNeETBRSg+jcAZ1T/
         l0eWnuxINsJKWo70cPP9El9RaQETepZghaDmIrjNtnSNbK5T+hUT6qXhzaW1U+godSQ7
         Cnew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=BlhlIbRsySHa4ln8dnujw8yemVZFFsmQpnQwgVjmRKw=;
        b=RDHbfCrDzgJ4uY1LrTa6+UZC+lmgmAnqZchuXIXfZIcy5TVXq0CheMs2x1XNGuw79I
         bXwfPmrHFvM379Kg9fpS3vDXz2t0/U0VgmD1/llyPyXef6b/85VkInrh1DOSwN+8pJsb
         FfBgF/KkE0v+vAfG5j7tX+TLljVSEL5Bta7n1kSlNZ9j/m4KrojCpn12GiP9YL8GJV4v
         QvcQ+T10l0s2L7EkuPfo/QZ+eTszRshqRcr8RCzOJUr2gawCy2iCWxQwtNlQbQk2azaC
         jMhah54PG6jSLkfaFSgVEb9eX1RivIeE9/SECmBKz/K6b6/Pa4aXSHebZjsY8QTlENbu
         14xg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XOFsBugQ;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BlhlIbRsySHa4ln8dnujw8yemVZFFsmQpnQwgVjmRKw=;
        b=gsvdAznWWMRg/n/z/Xj8X2Zh45+DcHm8wde7fhDi/dez00IUtWFLhJPMedp2pFhQiz
         o+MezfcnIF2WFrXYGAAR+ujLHEB+pqet4fjcXKl9v/JQsTlTaH+EdmMpdzNEdNyxItKh
         q179Las8slL76XlfqXuWwGROGqW3iiJJyqpWbvgZf8E7h0Xqi68e2UYuJxv+hJ6xA4I9
         mtcOKUkyCsCUgzungHBotZdFYf+HmIi/T6p3ddcf2eF74bydIUpMEx4HFj3zHTEYijT5
         1kYei03++BFXCUWynb2AUUaNGWDBCfOpp8PXRQT6O48vrW3+dXAv52+AhCL/M1QvOM6v
         UrpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BlhlIbRsySHa4ln8dnujw8yemVZFFsmQpnQwgVjmRKw=;
        b=j4BcX3sDLSc1exw0xx5QThh140IQRXBwU21Gtlx9IXlAshgePDN/jf+OWPEMeDOWwB
         fk7SI2LlMpsFkHuGkkItrpl2JiB3J6djpBgiQgLz6h9kolEKYAmEGs2x7zGVqYpnbUvs
         y52Ya9DFMDFYv/SD5nogq1D/rsz86+mY6pytEVHsMN8pGbRX0T+vuSV7i/AatuTFYKk0
         jmsMO+z5dpR+7W/ITDG8Z7oECoHPuJwEEOqPc52YxXlb0rQEVfT5+qaJWXcKxbHcTgAM
         vP5VlGxiWMjizJVv+n22VJjYKIYUExwemRmxmBs4LnR9KJKP7LKYagcrqljCIZVg07Pi
         5NRw==
X-Gm-Message-State: AOAM530J9j4pGujK3x4QW9jh31lgTVNsYKajsTLq530Irrk+BOfzaltX
	Lauka4afGK14t/AyJXPWmmE=
X-Google-Smtp-Source: ABdhPJyOQpLJ1bz8ZcLfXVH9QYeDlL6p50PSA62Bwgjyhq36qwXXutL3qPN687Ykenp9Fb5UA5aqew==
X-Received: by 2002:ae9:c211:: with SMTP id j17mr5582293qkg.458.1604002122379;
        Thu, 29 Oct 2020 13:08:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:1352:: with SMTP id c18ls1961658qkl.5.gmail; Thu,
 29 Oct 2020 13:08:41 -0700 (PDT)
X-Received: by 2002:ae9:c211:: with SMTP id j17mr5582254qkg.458.1604002121878;
        Thu, 29 Oct 2020 13:08:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604002121; cv=none;
        d=google.com; s=arc-20160816;
        b=nWV1/sORPRxNo5D/LEop7MW1oBWQPqySfeCVXvLkbwc41GKeESz/Qd66KQLIlsNmgX
         TJShKi0FZJDUqQqSs2HCnE7V/szH+JpjnTfOOIs/qRn7SzQoKzpdRdv8LcNR7HoWsAHZ
         yaKcqiPehU1EfQ1yea/Mb1PDiu91KhaYtQf8lUizr/yXRTf5aNMBR5v2AlaCE5esA76j
         StV4qYlEU/9fpuuunRCoz+yTUOMQgx+Dm4AV8fThpsuszLJ53woJ7GxGGrdh8IkPhIDY
         QpIOJrCydW55gaTIPZuRbGHGxj01VOCgJ+YbBCtRoG+waBvmu+GAQOk1ldq4Pq2yIQq0
         S+JA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dwhYoZVEeWiw6d4kbJoanMt/eIpVSVu/ys3QblYHUt8=;
        b=i3ObNsOBkc6TdGt8f+gNVoytbWxaryj2Q1JvFVNoJqsRP1j5zYdEccu4BhB0dNzKWe
         218ZU7CTYA3ORz/njP4ilmCUGTa+91GoTvnbT4ZFE9wP/vf6c40nCZAX3CqIb5ZhGUKf
         A4JtZMZeWF81X3A1vPXSM5KEUSR7dyPw/vSxKB3ETOf5s2oTsmDU+UBFzo/MYB/C3xOj
         jPJe6tm4cGwtlCfxjo3HbeZJwRYlocf0eJOh6txEjiC50+2dq5ZZbtJ2pqD8IcpGLDlX
         zPACCzg67k3ZLxjjIZsptsFxP7qsfKHF05kvj7FposYNvXyXf6D463dOkQpsMzsoi6Fd
         goxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XOFsBugQ;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id o11si282761qtq.5.2020.10.29.13.08.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 13:08:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id x23so1833844plr.6
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 13:08:41 -0700 (PDT)
X-Received: by 2002:a17:902:e993:b029:d6:41d8:9ca3 with SMTP id
 f19-20020a170902e993b02900d641d89ca3mr5974561plb.57.1604002120836; Thu, 29
 Oct 2020 13:08:40 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <155123c77b1a068089421022c4c5b1ccb75defd8.1603372719.git.andreyknvl@google.com>
 <CACT4Y+Z9iE2u1g9Yg=y2TPuRaYVq3TQoJ-81cYzODso_3aJcGg@mail.gmail.com>
In-Reply-To: <CACT4Y+Z9iE2u1g9Yg=y2TPuRaYVq3TQoJ-81cYzODso_3aJcGg@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 29 Oct 2020 21:08:30 +0100
Message-ID: <CAAeHK+x2URu8hGNyut_TnG-b_N5rt26CwAPHmyTc6OczAnFs4Q@mail.gmail.com>
Subject: Re: [PATCH RFC v2 06/21] kasan: mark kasan_init_tags as __init
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XOFsBugQ;       spf=pass
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

On Wed, Oct 28, 2020 at 11:08 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Oct 22, 2020 at 3:19 PM 'Andrey Konovalov' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > Similarly to kasan_init() mark kasan_init_tags() as __init.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Link: https://linux-review.googlesource.com/id/I8792e22f1ca5a703c5e979969147968a99312558
>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
>
> init_tags itself is not __init, but that's added in a different patch.
> I've commented on that patch.

Will add that change to this patch, thanks! If we combine the two
patch series, we can move this into the other one later. Thanks!

>
> > ---
> >  include/linux/kasan.h | 2 +-
> >  mm/kasan/hw_tags.c    | 2 +-
> >  mm/kasan/sw_tags.c    | 2 +-
> >  3 files changed, 3 insertions(+), 3 deletions(-)
> >
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index 7be9fb9146ac..93d9834b7122 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -185,7 +185,7 @@ static inline void kasan_record_aux_stack(void *ptr) {}
> >
> >  #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> >
> > -void kasan_init_tags(void);
> > +void __init kasan_init_tags(void);
> >
> >  void *kasan_reset_tag(const void *addr);
> >
> > diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> > index 2a38885014e3..0128062320d5 100644
> > --- a/mm/kasan/hw_tags.c
> > +++ b/mm/kasan/hw_tags.c
> > @@ -15,7 +15,7 @@
> >
> >  #include "kasan.h"
> >
> > -void kasan_init_tags(void)
> > +void __init kasan_init_tags(void)
> >  {
> >         init_tags(KASAN_TAG_MAX);
> >  }
> > diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> > index c10863a45775..bf1422282bb5 100644
> > --- a/mm/kasan/sw_tags.c
> > +++ b/mm/kasan/sw_tags.c
> > @@ -35,7 +35,7 @@
> >
> >  static DEFINE_PER_CPU(u32, prng_state);
> >
> > -void kasan_init_tags(void)
> > +void __init kasan_init_tags(void)
> >  {
> >         int cpu;
> >
> > --
> > 2.29.0.rc1.297.gfa9743e501-goog
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/155123c77b1a068089421022c4c5b1ccb75defd8.1603372719.git.andreyknvl%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bx2URu8hGNyut_TnG-b_N5rt26CwAPHmyTc6OczAnFs4Q%40mail.gmail.com.
