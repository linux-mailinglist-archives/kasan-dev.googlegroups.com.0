Return-Path: <kasan-dev+bncBDGPTM5BQUDRBCWN7P2AKGQEIU6L6TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id EA26C1B25F0
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Apr 2020 14:26:51 +0200 (CEST)
Received: by mail-ua1-x93e.google.com with SMTP id g14sf6304601uaq.5
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Apr 2020 05:26:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587472011; cv=pass;
        d=google.com; s=arc-20160816;
        b=VgnUo46IHIdZHnBAmcVeQDYUxFU5sVffLA1fRTGHls7ALn3KvPEjWq5rgnAF1Vm2Z5
         ZtfpSNZLT29jKlXm9itpz0eqq1WorQyaHNOrxqZrl3phKEyvA4ESXk1WWMn7fXDOqt+F
         56kKAw4MDifsLsHrUUSCh/3ooMhllkgXmNq+AqbuICyaKIVG0EkPpkaAsJ8XtJtBWrql
         txPwKfE8sL/dC7TLFIzakw9R9FeVPNti4BesUhZfakjPqE2nSL7hR0CULDf1Hkbh59xF
         vhegwDvs3ZyNxyC8JA1ShWYg3vGEgIeOsgvq4ePY/f0yNIVlGcc1sjEoH+f2glB32PfG
         6A5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=28DQkXwHktXigeW5v1ayZSY9Iurnn8VjkoDjFdCy988=;
        b=HeaRxO3fQiYBPbHERG73CHF1xjn9lOsT71pA4HVBxoO6oqPAxXopxlsa+uNYs6c0F3
         ZQuxMpXjuAKp6S1fcNKG4OShA27SH//cHcWvIXTzUkIejytmNBorJ9Pb+E5vQ7/IpELa
         xxOfSPVMkmsWFKuRRo+e7JcPLLpQt/t81ikciyjEFgZn3Yk5Dx3llpLliHkatEWlCyEE
         Lh6yIvLtIu03jlWqrtRZZhWV0c3WqUSaO6IiHcZ7pptQ4VrU4O1kxyuRb+PRNB5agQHN
         m4rZfcUlhVbIRJKPljmZEpdk2IWe0EOMNgeUPwNJctSIk0KV5xfmxD8t9cfO2XZPclVs
         korw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=ZpZ8SUhs;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=28DQkXwHktXigeW5v1ayZSY9Iurnn8VjkoDjFdCy988=;
        b=Wr83B8EXuBUzC/LekwUrv0mLQcDGSEz2oNnf5Xr7KNV5Z0MnFY7wNw2hZ0TEmQAP7Y
         qLpN7cYSOj75PL+YwnAKeVH3VfCtOaECVgtOP1zTLW6Evqs2p0AptAkNMDI//lNdkEx3
         0FeX5MCYS+eHU5wA7XzweT4q6s50wvmUCYJh03gxmf3xrsfuCSuAZA9WTHSMsaAlnip0
         SXUQM8mTOvVCbEAVV/LCswdMpmW/gZH8DrDdhNvgcrHwRI7lQP8gvWh4MXHANtrn4DrQ
         BQ8zW046eGRIxcn3kpGEVAoWIt2QOIkRBpuLLEj307xAZ1cYgrJnthPG/YHjg7f/Uj8j
         79vQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=28DQkXwHktXigeW5v1ayZSY9Iurnn8VjkoDjFdCy988=;
        b=lXSa4CL69RVscV/7Zm8WkihciAmAPJ5aF3KNADRKsm8wGUpDLfgo6ubKfFwBDbMNvv
         QCLvXLn9YRQFh6KaDgi7ryj0Dd055fX+FwJUPPXPx4vtV6cGPsUeDUcBTtqUZBz4HaSO
         0wbLt0auD63Vuxd1C84RiHZU7aJrz/qQdIJwwV7lhqpglXqN56GvZJZkXAS+pVWIsOi4
         d3u4zVv9DiBb0iU9jdcBifXMmTBhAe9HI/DtKbPDjuHCAPLxPmmp66DCWokbJuuFk2cq
         gp43EdlaxbCUkE7EfcTAWJJsPnE+LRHG5NA3o6zS6Sh0q418uldTVILlRt4tvByP7QUL
         UnXg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0Pubi9QwpMrCVC4yb2Ky/ZrceuvND3u/ML6db5qPPD2buOy3XavXz
	rIGLqdr3QcqosxFdKQqdMVM=
X-Google-Smtp-Source: APiQypIGdbc5MbMTlvSctqe3x6jPcBLbRANve36xDYRkpEoxsKz0YClwh395OduEIOKmIod7b1nYyw==
X-Received: by 2002:a1f:944d:: with SMTP id w74mr15004283vkd.23.1587472010789;
        Tue, 21 Apr 2020 05:26:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:2d99:: with SMTP id v25ls1123336uaj.10.gmail; Tue, 21
 Apr 2020 05:26:50 -0700 (PDT)
X-Received: by 2002:ab0:254:: with SMTP id 78mr11518463uas.77.1587472010332;
        Tue, 21 Apr 2020 05:26:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587472010; cv=none;
        d=google.com; s=arc-20160816;
        b=yxudx4jc0eTmtkmrckYSQjPTepPD4vZcySxQCfb8M7GFj6nqPG8f2V9E79ovV4YRcK
         pZJpObfIb5irbYOC+hhAbfEPz+KxCfXPExIJaJagHIWQ+FWvWwIYqdfJf3VpTuVTmhh4
         iT2YhonE+9l2JSpy1l9UfAOVrDsY7iaf1wl4ooVmfM3idKt9x3O2WEw1BB8f2TY+7iHS
         GN2kGXpUybdTTbiaqtg2pOrzQkksFMWZRv0SQUGvL/hDM7WlTb6geKWFIfvjkTGkTxVV
         ftkel2TpvUOGJ0tuJleH3kQVRBwSlmny4RUl1D6Kwb+NvKL5Su/Byto8BD0cWXBljdq6
         vsUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=1drU5b9UZyhoKKcmaKClDLCSPZ1nRiiu5qjvWITjXi0=;
        b=uqyS7TQKrvnv68mjFxnTuYkHDgT957x8grzh4lt2vcDLMNswF57TzBFiaof6TG+3w/
         fTxILPpzi5lfbmDQjmOX56zpVKh1YYnvDo2Qn6eMcOA9wk6jdJ3pDwK+vK3R/xDy63EF
         55Db+aakiO7qt021aC2zwNkfviMaZoI9g+DVd8qNjGcCk4TH7PEucTwXWB1G6/DL9a7V
         jI1CGMBT/19mWWVAKXQADd9ZlAsR6J/wMic03QyKIq3/3ZqjfL/DzgjXUwkp1fuKH6do
         f0shSkTrs9AYAlzBwQnKpgH6GbMjm5dxGx16/RAwm14JdV8hyJpHVct282pNuXqh9/nN
         tOXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=ZpZ8SUhs;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id f17si153587vka.5.2020.04.21.05.26.49
        for <kasan-dev@googlegroups.com>;
        Tue, 21 Apr 2020 05:26:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: f2df5e8bcb1642a8b8be13b48baa09d9-20200421
X-UUID: f2df5e8bcb1642a8b8be13b48baa09d9-20200421
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 419430501; Tue, 21 Apr 2020 20:26:46 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs06n1.mediatek.inc (172.21.101.129) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 21 Apr 2020 20:26:42 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 21 Apr 2020 20:26:42 +0800
Message-ID: <1587472005.5870.7.camel@mtksdccf07>
Subject: Re: [PATCH] kasan: fix KASAN unit tests for tag-based KASAN
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: David Gow <davidgow@google.com>, Brendan Higgins
	<brendanhiggins@google.com>, Patricia Alfonso <trishalfonso@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, "Andrey
 Konovalov" <andreyknvl@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, Linux-MM
	<linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, "Linux ARM"
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>
Date: Tue, 21 Apr 2020 20:26:45 +0800
In-Reply-To: <CACT4Y+af5fegnN9XOUSkf_B62J5sf2ZZbUwYk=GxtSmAhF3ryQ@mail.gmail.com>
References: <20200421014007.6012-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+af5fegnN9XOUSkf_B62J5sf2ZZbUwYk=GxtSmAhF3ryQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=ZpZ8SUhs;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

Hi Dmitry,

On Tue, 2020-04-21 at 13:56 +0200, Dmitry Vyukov wrote:
> On Tue, Apr 21, 2020 at 3:40 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > When we use tag-based KASAN, then KASAN unit tests don't detect
> > out-of-bounds memory access. Because with tag-based KASAN the state
> > of each 16 aligned bytes of memory is encoded in one shadow byte
> > and the shadow value is tag of pointer, so we need to read next
> > shadow byte, the shadow value is not equal to tag of pointer,
> > then tag-based KASAN will detect out-of-bounds memory access.
> >
> > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Matthias Brugger <matthias.bgg@gmail.com>
> > Cc: Andrey Konovalov <andreyknvl@google.com>
> > Cc: Andrew Morton <akpm@linux-foundation.org>
> > ---
> >  lib/test_kasan.c | 62 ++++++++++++++++++++++++++++++++++++++++++------
> >  1 file changed, 55 insertions(+), 7 deletions(-)
> >
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index e3087d90e00d..a164f6b47fe5 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -40,7 +40,12 @@ static noinline void __init kmalloc_oob_right(void)
> >                 return;
> >         }
> 
> Hi Walter,
> 
> This would be great to have!
> But I am concerned about these series that port KASAN tests to KUNIT:
> https://lkml.org/lkml/2020/4/17/1144
> I suspect it will be one large merge conflict. Not sure what is the
> proper way to resovle this. I've added authors to CC.
> 
Yes, it should have conflicts. Thanks for your reminder.
> 
> > +#ifdef CONFIG_KASAN_GENERIC
> >         ptr[size] = 'x';
> > +#else
> > +       ptr[size + 5] = 'x';
> > +#endif
> > +
> 
> For this particular snippet I think we can reduce amount of idef'ery
> and amount of non-compiled code in each configuration with something
> like:
> 
>   ptr[size + 5] = 'x';
>   if (ENABLED(CONFIG_KASAN_GENERIC))
>       ptr[size] = 'x';
> 
> One check runs always (it should pass in both configs, right?). The

There is a problem, With generic KASAN it may trigger two KASAN reports.
if we change it like:
 
if (ENABLED(CONFIG_KASAN_GENERIC))
    ptr[size] = 'x';
else
    ptr[size + 5] = 'x';

> only only in GENERIC, but it's C-level if rather than preprocessor.
> KUNIT should make 2 bugs per test easily expressable (and testable).
> 

> 
> 
> 
> >         kfree(ptr);
> >  }
> >
> > @@ -92,7 +97,12 @@ static noinline void __init kmalloc_pagealloc_oob_right(void)
> >                 return;
> >         }
> >
> > +#ifdef CONFIG_KASAN_GENERIC
> >         ptr[size] = 0;
> > +#else
> > +       ptr[size + 6] = 0;
> > +#endif
> > +
> >         kfree(ptr);
> >  }
> >
> > @@ -162,7 +172,11 @@ static noinline void __init kmalloc_oob_krealloc_more(void)
> >                 return;
> >         }
> >
> > +#ifdef CONFIG_KASAN_GENERIC
> >         ptr2[size2] = 'x';
> > +#else
> > +       ptr2[size2 + 13] = 'x';
> > +#endif
> >         kfree(ptr2);
> >  }
> >
> > @@ -180,7 +194,12 @@ static noinline void __init kmalloc_oob_krealloc_less(void)
> >                 kfree(ptr1);
> >                 return;
> >         }
> > +
> > +#ifdef CONFIG_KASAN_GENERIC
> >         ptr2[size2] = 'x';
> > +#else
> > +       ptr2[size2 + 2] = 'x';
> > +#endif
> >         kfree(ptr2);
> >  }
> >
> > @@ -216,7 +235,11 @@ static noinline void __init kmalloc_oob_memset_2(void)
> >                 return;
> >         }
> >
> > +#ifdef CONFIG_KASAN_GENERIC
> >         memset(ptr+7, 0, 2);
> > +#else
> > +       memset(ptr+15, 0, 2);
> > +#endif
> >         kfree(ptr);
> >  }
> >
> > @@ -232,7 +255,11 @@ static noinline void __init kmalloc_oob_memset_4(void)
> >                 return;
> >         }
> >
> > +#ifdef CONFIG_KASAN_GENERIC
> >         memset(ptr+5, 0, 4);
> > +#else
> > +       memset(ptr+15, 0, 4);
> > +#endif
> >         kfree(ptr);
> >  }
> >
> > @@ -249,7 +276,11 @@ static noinline void __init kmalloc_oob_memset_8(void)
> >                 return;
> >         }
> >
> > +#ifdef CONFIG_KASAN_GENERIC
> >         memset(ptr+1, 0, 8);
> > +#else
> > +       memset(ptr+15, 0, 8);
> > +#endif
> >         kfree(ptr);
> >  }
> >
> > @@ -265,7 +296,11 @@ static noinline void __init kmalloc_oob_memset_16(void)
> >                 return;
> >         }
> >
> > +#ifdef CONFIG_KASAN_GENERIC
> >         memset(ptr+1, 0, 16);
> > +#else
> > +       memset(ptr+15, 0, 16);
> > +#endif
> >         kfree(ptr);
> >  }
> >
> > @@ -281,7 +316,11 @@ static noinline void __init kmalloc_oob_in_memset(void)
> >                 return;
> >         }
> >
> > +#ifdef CONFIG_KASAN_GENERIC
> >         memset(ptr, 0, size+5);
> > +#else
> > +       memset(ptr, 0, size+7);
> > +#endif
> >         kfree(ptr);
> >  }
> >
> > @@ -415,7 +454,11 @@ static noinline void __init kmem_cache_oob(void)
> >                 return;
> >         }
> >
> > +#ifdef CONFIG_KASAN_GENERIC
> >         *p = p[size];
> > +#else
> > +       *p = p[size + 8];
> > +#endif
> >         kmem_cache_free(cache, p);
> >         kmem_cache_destroy(cache);
> >  }
> > @@ -497,6 +540,11 @@ static noinline void __init copy_user_test(void)
> >         char __user *usermem;
> >         size_t size = 10;
> >         int unused;
> > +#ifdef CONFIG_KASAN_GENERIC
> > +       size_t oob_size = 1;
> > +#else
> > +       size_t oob_size = 7;
> > +#endif
> >
> >         kmem = kmalloc(size, GFP_KERNEL);
> >         if (!kmem)
> > @@ -512,25 +560,25 @@ static noinline void __init copy_user_test(void)
> >         }
> >
> >         pr_info("out-of-bounds in copy_from_user()\n");
> > -       unused = copy_from_user(kmem, usermem, size + 1);
> > +       unused = copy_from_user(kmem, usermem, size + oob_size);
> >
> >         pr_info("out-of-bounds in copy_to_user()\n");
> > -       unused = copy_to_user(usermem, kmem, size + 1);
> > +       unused = copy_to_user(usermem, kmem, size + oob_size);
> >
> >         pr_info("out-of-bounds in __copy_from_user()\n");
> > -       unused = __copy_from_user(kmem, usermem, size + 1);
> > +       unused = __copy_from_user(kmem, usermem, size + oob_size);
> >
> >         pr_info("out-of-bounds in __copy_to_user()\n");
> > -       unused = __copy_to_user(usermem, kmem, size + 1);
> > +       unused = __copy_to_user(usermem, kmem, size + oob_size);
> >
> >         pr_info("out-of-bounds in __copy_from_user_inatomic()\n");
> > -       unused = __copy_from_user_inatomic(kmem, usermem, size + 1);
> > +       unused = __copy_from_user_inatomic(kmem, usermem, size + oob_size);
> >
> >         pr_info("out-of-bounds in __copy_to_user_inatomic()\n");
> > -       unused = __copy_to_user_inatomic(usermem, kmem, size + 1);
> > +       unused = __copy_to_user_inatomic(usermem, kmem, size + oob_size);
> >
> >         pr_info("out-of-bounds in strncpy_from_user()\n");
> > -       unused = strncpy_from_user(kmem, usermem, size + 1);
> > +       unused = strncpy_from_user(kmem, usermem, size + oob_size);
> >
> >         vm_munmap((unsigned long)usermem, PAGE_SIZE);
> >         kfree(kmem);
> > --
> > 2.18.0
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200421014007.6012-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1587472005.5870.7.camel%40mtksdccf07.
