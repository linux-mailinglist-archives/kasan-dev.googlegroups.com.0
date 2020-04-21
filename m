Return-Path: <kasan-dev+bncBDGPTM5BQUDRBNXO7P2AKGQECDY6ZGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2879A1B2823
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Apr 2020 15:38:00 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id o9sf16150930ila.10
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Apr 2020 06:38:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587476279; cv=pass;
        d=google.com; s=arc-20160816;
        b=xMNh/hNpJi4PiQWCem5ppzArkWqr2coSQANtq+CiKF8xTFot6l5EgQBZnwSl3/TA0+
         QWuwhZtY8n+i2uNbOznO4eLITlCOyG8G1ii8vDelJNlBmOQkP46+HvdWErixoNsJSuu+
         QrQErM9MvGzX2xXSjA/YAkNnjRbOVS8BJNQJkp8wky9uQBqIiU4w6yEeEwgJAYrOacH4
         oTH7yE3nF6iPd8T87zNWuL7KPjDAFIv2vqRjOU+Af3gJM0HdVasbZjTNf+y4MuPn1lR4
         USZeR/uPjlh4P8h21cIZJaNAcsUQA2vbSl0SfQhTEwaK/ZInGyGbRSdMx3E5oKshy1bk
         Vlrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=96CGxPQjFlDLFXzx+GZJy4SoDChHG3f0VMBeHVVJlqs=;
        b=cd224v5YzmxL5PGCsZ/xYkXaY4vIXh7r4FLJQJaLJU2apIC0S4681aRyTvosMyDk+w
         EGhi4hwL+mFwi7ZBD9njWC49Uaeq3Rx+1UbuqJbiLBXF+iir8elE+TsMBjPiSh5MpOOj
         cm3RD/Tm89fdZzKrEf9hQrK8zoMlaAQSDB6WG145w2Rtc2t0qdZjhl6/GRML4kp5BCPT
         qfV7ZkP671yYo6dAA//koIuO61IsOu87ISf0XUj0jXf+eTa1mwo3Peo2mDk39TPrE1t8
         HdWwGhkmq4MdrvMtcEIZbAgtD/8rDS0B6O94cQNnEUVk2eCDHj7fIEP4p4R2vQg+mMWU
         yv7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=khjr1WSm;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=96CGxPQjFlDLFXzx+GZJy4SoDChHG3f0VMBeHVVJlqs=;
        b=Ua6Tb9WxVOzEeffWtb3A2f9XBQON40rb3En6yBzUbL/aFzwIF2a2Cps/oXKKsKbLGi
         plrcFg7rzJAWfLJVozMFNVMQpEBbw70kyovYWnl+u+DnX7nWaFPb6/5eudrs1iyXxOm9
         dJxO/vchtkLn1m+E7JjsSAy5AAVjZQj3uecTaMR0koh4xZOb8DTIYpNHquRyROOkzwi5
         1I5svf6fbbuVqSu2d0V+wonjhg8Oa4g/G1S+QP8LZf1eJFvuqGtOMCi2a8K/xnlrr2xx
         73X86ZrauQMVD+pkRUniPWrT7+0wSBe8lHBtTVYXx8OTg4DwgiyNQMpRFFcuxrTGEFWY
         sEvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=96CGxPQjFlDLFXzx+GZJy4SoDChHG3f0VMBeHVVJlqs=;
        b=li3p40HQo+E961EBPm25zFqsUNSbdygwpmJcqrBsZnZSYXzNvXCjaCcm0z8wfB8Ve4
         P3BpUYHO/04O87bHitpMh5BZNAp44PfVUpF9SOp17mCrekg83ItnibOlsYVZX/lYRtba
         JVSqasM/ojdc0cSjDUz8k75Wyjel2apLdb1VhqakI9rpPT0fdOHfpvGKHFkJlM9QsLhE
         bbV5zLSp6ixRbm7kGFmBmVE/vV4u/d+K8NWD8kIIZzID/re7kbzM0DIHjrTJG55jSxjs
         dzXhxmC6EixiYokKA36ux/h0KLp1s1icvr4oXGxyJdXMeaK5pOmV7gbOsvFzaeWaoxtK
         3u2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZRqyaMbNedjbYTxBJRt9/MKYna0fsCSxaUjxMAFdmphEPU+SgH
	9cXwA6yrajzsljUmFilgMzM=
X-Google-Smtp-Source: APiQypJFynWCJGD1BkYyZwulk3eDhuV1sAx/bjSapjh3V4Vl11bLHbOQE8FPVB45laVCKZCXf31VWw==
X-Received: by 2002:a05:6638:31b:: with SMTP id w27mr2577470jap.94.1587476279015;
        Tue, 21 Apr 2020 06:37:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:3d10:: with SMTP id k16ls6553058ila.7.gmail; Tue, 21 Apr
 2020 06:37:58 -0700 (PDT)
X-Received: by 2002:a92:8f49:: with SMTP id j70mr20262507ild.117.1587476278706;
        Tue, 21 Apr 2020 06:37:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587476278; cv=none;
        d=google.com; s=arc-20160816;
        b=cceT8RkSQ5xheBSPuqkW70Fu12uyGsEkw28KZtN7iiElTlPTJ4wnohR1O+g94druTl
         bdIhEp+aROOr7Z4o22pUV2rAU+bciGeYXr2vhM0/ojJ8aJiyuo1sBp8lQhyH8NTz7LKy
         OdOq+uV+kPzLamfW2byl4IF9uEzK7ozvAeVcgyJvmR9pIkTNyS53XzrepGAb9qa0tdd6
         qXnAZFlAPDbhyufAGo2Eo6olJ5So7CzWAa7vBgl2HoP+s13e1pQhCvu+VF+8sWgqL6im
         nLRyz3G4HQbu19598K4iYUg8qvcOOvAnTX5Mf7nJh0CIHLgSYeZ3VLyDSrRk1uj/75iA
         9M/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=JX00X8S2zWSDA5/Zsgs0O/ncM6aJvIG88Eh4mjiOiX4=;
        b=tuWAh1KASu1NEz+dyRJEDUIoMA/DwuFBYwalrS8wXybqVGoxl8F3POuUyePORcZD92
         4AkKwMxbOo3FZMGFDJrEZYLvyMahF/fxfQBuR65IxEyXQ1Wpr+otvVKN2jYW//rnjqS3
         EWHhcLhIpnz1lYBV9lx6fDXFvHbYcG6b02a6CeafGAg/5DQiYSePuHYDrRAlPf4glWxe
         jTEpupqowzIESnZElZzUl1ncb+t5wdGnvZdvMzu4T0mgqw2qP7LyJP6Ylly5gWjTkZ9P
         cNUb5kG2ebYxFkubvov5VNudjNRhEUfXzXrnZyFnyIQX5I+kzou/QLJjn6OOjuMCWMIJ
         VEhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=khjr1WSm;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id o6si216194ilo.4.2020.04.21.06.37.57
        for <kasan-dev@googlegroups.com>;
        Tue, 21 Apr 2020 06:37:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 9b83d4e172dc4a88966709162332ba76-20200421
X-UUID: 9b83d4e172dc4a88966709162332ba76-20200421
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 2022916195; Tue, 21 Apr 2020 21:37:54 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs06n2.mediatek.inc (172.21.101.130) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 21 Apr 2020 21:37:52 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 21 Apr 2020 21:37:48 +0800
Message-ID: <1587476272.5870.15.camel@mtksdccf07>
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
Date: Tue, 21 Apr 2020 21:37:52 +0800
In-Reply-To: <CACT4Y+avYV1xoqB6V5XrQSs-p2s3mKKu+LZQc4EzPaW-jV+KaA@mail.gmail.com>
References: <20200421014007.6012-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+af5fegnN9XOUSkf_B62J5sf2ZZbUwYk=GxtSmAhF3ryQ@mail.gmail.com>
	 <1587472005.5870.7.camel@mtksdccf07>
	 <CACT4Y+avYV1xoqB6V5XrQSs-p2s3mKKu+LZQc4EzPaW-jV+KaA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: BC3A44A52E9D8AE093BF388FD62DAE971AB1F492889557179C30B461B1F267482000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=khjr1WSm;       spf=pass
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

On Tue, 2020-04-21 at 15:01 +0200, 'Dmitry Vyukov' via kasan-dev wrote:
> On Tue, Apr 21, 2020 at 2:26 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > Hi Dmitry,
> >
> > On Tue, 2020-04-21 at 13:56 +0200, Dmitry Vyukov wrote:
> > > On Tue, Apr 21, 2020 at 3:40 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > >
> > > > When we use tag-based KASAN, then KASAN unit tests don't detect
> > > > out-of-bounds memory access. Because with tag-based KASAN the state
> > > > of each 16 aligned bytes of memory is encoded in one shadow byte
> > > > and the shadow value is tag of pointer, so we need to read next
> > > > shadow byte, the shadow value is not equal to tag of pointer,
> > > > then tag-based KASAN will detect out-of-bounds memory access.
> > > >
> > > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > > > Cc: Dmitry Vyukov <dvyukov@google.com>
> > > > Cc: Alexander Potapenko <glider@google.com>
> > > > Cc: Matthias Brugger <matthias.bgg@gmail.com>
> > > > Cc: Andrey Konovalov <andreyknvl@google.com>
> > > > Cc: Andrew Morton <akpm@linux-foundation.org>
> > > > ---
> > > >  lib/test_kasan.c | 62 ++++++++++++++++++++++++++++++++++++++++++------
> > > >  1 file changed, 55 insertions(+), 7 deletions(-)
> > > >
> > > > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > > > index e3087d90e00d..a164f6b47fe5 100644
> > > > --- a/lib/test_kasan.c
> > > > +++ b/lib/test_kasan.c
> > > > @@ -40,7 +40,12 @@ static noinline void __init kmalloc_oob_right(void)
> > > >                 return;
> > > >         }
> > >
> > > Hi Walter,
> > >
> > > This would be great to have!
> > > But I am concerned about these series that port KASAN tests to KUNIT:
> > > https://lkml.org/lkml/2020/4/17/1144
> > > I suspect it will be one large merge conflict. Not sure what is the
> > > proper way to resovle this. I've added authors to CC.
> > >
> > Yes, it should have conflicts. Thanks for your reminder.
> > >
> > > > +#ifdef CONFIG_KASAN_GENERIC
> > > >         ptr[size] = 'x';
> > > > +#else
> > > > +       ptr[size + 5] = 'x';
> > > > +#endif
> > > > +
> > >
> > > For this particular snippet I think we can reduce amount of idef'ery
> > > and amount of non-compiled code in each configuration with something
> > > like:
> > >
> > >   ptr[size + 5] = 'x';
> > >   if (ENABLED(CONFIG_KASAN_GENERIC))
> > >       ptr[size] = 'x';
> > >
> > > One check runs always (it should pass in both configs, right?). The
> >
> > There is a problem, With generic KASAN it may trigger two KASAN reports.
> 
> Why is this a problem? If there are 2, fine. KUNIT can check that if
> we expect 2, there are indeed 2.
> 
Sorry, I originally assume my patch doesn't include in KUNIT. so I think
there is a problem. but I know your meaning. Can my patch upstream
first?

> > if we change it like:
> >
> > if (ENABLED(CONFIG_KASAN_GENERIC))
> >     ptr[size] = 'x';
> > else
> >     ptr[size + 5] = 'x';
> >
> > > only only in GENERIC, but it's C-level if rather than preprocessor.
> > > KUNIT should make 2 bugs per test easily expressable (and testable).
> > >
> >
> > >
> > >
> > >
> > > >         kfree(ptr);
> > > >  }
> > > >
> > > > @@ -92,7 +97,12 @@ static noinline void __init kmalloc_pagealloc_oob_right(void)
> > > >                 return;
> > > >         }
> > > >
> > > > +#ifdef CONFIG_KASAN_GENERIC
> > > >         ptr[size] = 0;
> > > > +#else
> > > > +       ptr[size + 6] = 0;
> > > > +#endif
> > > > +
> > > >         kfree(ptr);
> > > >  }
> > > >
> > > > @@ -162,7 +172,11 @@ static noinline void __init kmalloc_oob_krealloc_more(void)
> > > >                 return;
> > > >         }
> > > >
> > > > +#ifdef CONFIG_KASAN_GENERIC
> > > >         ptr2[size2] = 'x';
> > > > +#else
> > > > +       ptr2[size2 + 13] = 'x';
> > > > +#endif
> > > >         kfree(ptr2);
> > > >  }
> > > >
> > > > @@ -180,7 +194,12 @@ static noinline void __init kmalloc_oob_krealloc_less(void)
> > > >                 kfree(ptr1);
> > > >                 return;
> > > >         }
> > > > +
> > > > +#ifdef CONFIG_KASAN_GENERIC
> > > >         ptr2[size2] = 'x';
> > > > +#else
> > > > +       ptr2[size2 + 2] = 'x';
> > > > +#endif
> > > >         kfree(ptr2);
> > > >  }
> > > >
> > > > @@ -216,7 +235,11 @@ static noinline void __init kmalloc_oob_memset_2(void)
> > > >                 return;
> > > >         }
> > > >
> > > > +#ifdef CONFIG_KASAN_GENERIC
> > > >         memset(ptr+7, 0, 2);
> > > > +#else
> > > > +       memset(ptr+15, 0, 2);
> > > > +#endif
> > > >         kfree(ptr);
> > > >  }
> > > >
> > > > @@ -232,7 +255,11 @@ static noinline void __init kmalloc_oob_memset_4(void)
> > > >                 return;
> > > >         }
> > > >
> > > > +#ifdef CONFIG_KASAN_GENERIC
> > > >         memset(ptr+5, 0, 4);
> > > > +#else
> > > > +       memset(ptr+15, 0, 4);
> > > > +#endif
> > > >         kfree(ptr);
> > > >  }
> > > >
> > > > @@ -249,7 +276,11 @@ static noinline void __init kmalloc_oob_memset_8(void)
> > > >                 return;
> > > >         }
> > > >
> > > > +#ifdef CONFIG_KASAN_GENERIC
> > > >         memset(ptr+1, 0, 8);
> > > > +#else
> > > > +       memset(ptr+15, 0, 8);
> > > > +#endif
> > > >         kfree(ptr);
> > > >  }
> > > >
> > > > @@ -265,7 +296,11 @@ static noinline void __init kmalloc_oob_memset_16(void)
> > > >                 return;
> > > >         }
> > > >
> > > > +#ifdef CONFIG_KASAN_GENERIC
> > > >         memset(ptr+1, 0, 16);
> > > > +#else
> > > > +       memset(ptr+15, 0, 16);
> > > > +#endif
> > > >         kfree(ptr);
> > > >  }
> > > >
> > > > @@ -281,7 +316,11 @@ static noinline void __init kmalloc_oob_in_memset(void)
> > > >                 return;
> > > >         }
> > > >
> > > > +#ifdef CONFIG_KASAN_GENERIC
> > > >         memset(ptr, 0, size+5);
> > > > +#else
> > > > +       memset(ptr, 0, size+7);
> > > > +#endif
> > > >         kfree(ptr);
> > > >  }
> > > >
> > > > @@ -415,7 +454,11 @@ static noinline void __init kmem_cache_oob(void)
> > > >                 return;
> > > >         }
> > > >
> > > > +#ifdef CONFIG_KASAN_GENERIC
> > > >         *p = p[size];
> > > > +#else
> > > > +       *p = p[size + 8];
> > > > +#endif
> > > >         kmem_cache_free(cache, p);
> > > >         kmem_cache_destroy(cache);
> > > >  }
> > > > @@ -497,6 +540,11 @@ static noinline void __init copy_user_test(void)
> > > >         char __user *usermem;
> > > >         size_t size = 10;
> > > >         int unused;
> > > > +#ifdef CONFIG_KASAN_GENERIC
> > > > +       size_t oob_size = 1;
> > > > +#else
> > > > +       size_t oob_size = 7;
> > > > +#endif
> > > >
> > > >         kmem = kmalloc(size, GFP_KERNEL);
> > > >         if (!kmem)
> > > > @@ -512,25 +560,25 @@ static noinline void __init copy_user_test(void)
> > > >         }
> > > >
> > > >         pr_info("out-of-bounds in copy_from_user()\n");
> > > > -       unused = copy_from_user(kmem, usermem, size + 1);
> > > > +       unused = copy_from_user(kmem, usermem, size + oob_size);
> > > >
> > > >         pr_info("out-of-bounds in copy_to_user()\n");
> > > > -       unused = copy_to_user(usermem, kmem, size + 1);
> > > > +       unused = copy_to_user(usermem, kmem, size + oob_size);
> > > >
> > > >         pr_info("out-of-bounds in __copy_from_user()\n");
> > > > -       unused = __copy_from_user(kmem, usermem, size + 1);
> > > > +       unused = __copy_from_user(kmem, usermem, size + oob_size);
> > > >
> > > >         pr_info("out-of-bounds in __copy_to_user()\n");
> > > > -       unused = __copy_to_user(usermem, kmem, size + 1);
> > > > +       unused = __copy_to_user(usermem, kmem, size + oob_size);
> > > >
> > > >         pr_info("out-of-bounds in __copy_from_user_inatomic()\n");
> > > > -       unused = __copy_from_user_inatomic(kmem, usermem, size + 1);
> > > > +       unused = __copy_from_user_inatomic(kmem, usermem, size + oob_size);
> > > >
> > > >         pr_info("out-of-bounds in __copy_to_user_inatomic()\n");
> > > > -       unused = __copy_to_user_inatomic(usermem, kmem, size + 1);
> > > > +       unused = __copy_to_user_inatomic(usermem, kmem, size + oob_size);
> > > >
> > > >         pr_info("out-of-bounds in strncpy_from_user()\n");
> > > > -       unused = strncpy_from_user(kmem, usermem, size + 1);
> > > > +       unused = strncpy_from_user(kmem, usermem, size + oob_size);
> > > >
> > > >         vm_munmap((unsigned long)usermem, PAGE_SIZE);
> > > >         kfree(kmem);
> > > > --
> > > > 2.18.0
> > > >
> > > > --
> > > > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > > > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > > > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200421014007.6012-1-walter-zh.wu%40mediatek.com.
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1587472005.5870.7.camel%40mtksdccf07.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1587476272.5870.15.camel%40mtksdccf07.
