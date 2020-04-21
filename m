Return-Path: <kasan-dev+bncBCMIZB7QWENRBOW57P2AKGQEVRWYCTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C6DA1B26FC
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Apr 2020 15:01:48 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id q142sf12970115pfc.21
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Apr 2020 06:01:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587474107; cv=pass;
        d=google.com; s=arc-20160816;
        b=DxIv4qHIOxmr8s8kPbjiFvmABql8HN4T2N4DHhQ0tJoFCPiQatgHwj1XFGzbPBrHxi
         mIMwIb7LAoWJDuPyp/b77/E1Z7nFuaGVvQxHhgAJfoWbuYl5KbmystWfV5L1n5kA+h4I
         6h7bvhHzCEOFcYopVLfvfFs58oFFhp+g+Y8AcwiNkmOFOSyVeFm8KwxIltwk9wpevbIe
         GTPiueiVoXryxtFdNyhro7MqE1vM7XaBC7L1HLKph9Gy1XbY8tHesl5L3NOcpLAYKC7b
         YtH7a7GLw52/UxQ//synHYMZndtSWbt1d1rdIWBTd3uP3odArbnvLNvR1zPC4o3c2dR7
         X1Ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=QrxsCb+SXx/ZpqLjvcw/l4EvKaUPt5fcjttzvXielf8=;
        b=cZ2Zk0xN7VY4c6vQc1uoFvQMhMftmOtDIlXSQwlOM0HZ2Ps23N92XWZByuiFMhEh0a
         s2tiMG8KYloXL8dR5qaV97wBoC5PAPVNE/fHl8E7avaxNgx0Z6xLeZIiATcUbJIMpLD0
         vWMpvePLwwVq8BaGFZnw1EMjadtYjLfaMTBiUtbttAElZ77x6i51mfpWtXskXG7pNan9
         hppXmP9l32fIwrmhEMBSL7LhQHvmfrfptq//F4Hd+HiEtlD4Hvyklf42MrHZVqR5uXEI
         iehQzBC6aCc2oDxAeGEVnRiHp0yhbREihcFqvoNU/zAptjsmhFzedsSTcS+Mz0Oxu8Mr
         SZiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Y1fbcTDd;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QrxsCb+SXx/ZpqLjvcw/l4EvKaUPt5fcjttzvXielf8=;
        b=aq3rWJfW+S+BHfP947yNRT9zClqq2aqIR4PEf1BEOzBoyfGnl/5o86y0oSDdgWpR+s
         0DrTEiDuzCSSfkXi73EohIs2vC24pK4y8uJJ+C//rrbPGAqqu9JBUXizL7aaso5Gsfkm
         ZXRoQfSrb+4SROblktAdq91DUHCanMYF+XagCOFcPWPbujmwf+M8aW8viQFFmVzjB0Ds
         B/zxN8W3ahsNRjqmdgArhl1FzgIyJ3FI5OhCcvJR/qa+si+RfiJD0NyI1hbQRE3dHBom
         JgRg0TUKQsaEsixwMbgVCq3Xee2wtZ3pQfOVvOJwsYPbTUG2Kxyc4t1rewqCWxgdSfE9
         7K8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QrxsCb+SXx/ZpqLjvcw/l4EvKaUPt5fcjttzvXielf8=;
        b=qXTjNyfDirc2nCpBzVrRw/L79p8ol61cwvBkDGpJlUZm2v6A8+mCPc1eigsDKjIb1G
         kPooAEhjDzFMk9JlegsmueuD8sYE74LLa6WyhGvqzbkVPML20I9qzPgxLK06X2vUt0/d
         Fe1o37gUSi14S3kY8J3ag4MSzI3v6NPs8XCn8OQIt7xbLEW9OzOLpf+YdX2mdDyAExuW
         +6CYLJWOoCrPnmA4W49+veUA8JFvIFmrJ9/Brm7p1Qp9Rxjb4aa5uxyXFpPsjUAGcaXS
         2RcnJvUTlwBdNkO0XzY1fYwcooXJ90RFYQxAhhbGnfRpFNY5vgSkMPVI8xr+Kn6Halbf
         DPJQ==
X-Gm-Message-State: AGi0Pub3k+zvOL6c945/djwITeBGxESjN4TyswGZ6xfeZK90ng1jyiID
	vOHLvodWZt3yoPBq/Lev6sk=
X-Google-Smtp-Source: APiQypK8ZfSigq0Y2YuWwTtHqD6j0S5IJsPfIegCpTUcdtC3YzUyH8uUAbFQBB7WwS7JLRTDnfqeTQ==
X-Received: by 2002:a17:902:aa48:: with SMTP id c8mr20874996plr.95.1587474106126;
        Tue, 21 Apr 2020 06:01:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:ea0e:: with SMTP id t14ls3610459pfh.3.gmail; Tue, 21 Apr
 2020 06:01:45 -0700 (PDT)
X-Received: by 2002:a63:514a:: with SMTP id r10mr19491956pgl.246.1587474105465;
        Tue, 21 Apr 2020 06:01:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587474105; cv=none;
        d=google.com; s=arc-20160816;
        b=L7ZrCSShCht0UJMi4BqHO3LJB6HREjXuNXq91dAjFyRFf5Pg1SqyBkYoU16GOlY4/k
         1iEe864N7Xw4AzbbDpUG9jmsVpEhG4O1A8k2SX7k2axcQtltHs36TjK7N08OHgXdpsCI
         B/QeHaEvVlvLP1zUqgsOv+tvm3y/ulVhTk+HZTeW9v3uzevvka/bBldnpoEpW2XwimL1
         2NARWbdAKYBStFjoygyrpw0CShKB86eH8wR1Vmh3ZZKcqUkg6j3ZY/kjgWLcyLoiVyc3
         kYnbHinLUPGUqMI600yQzFCMgUu/Ps8PGF0wJre5xy9/zXd6Sg0sDHh7ZXG0+zrPvMCc
         Q2fQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6bxpXR7bk9lriyagOO2UqkV9Fm2IwK+BGPfkmvwlllg=;
        b=0rE7ctDYwYQ8bv0RCLYFPfqInon90r9+mrvWDXMqqXRLhSGnnhITKIrUqlLWGCR7hj
         pQOS5UW+7THuU2TQIF1JvmUzSUTxh3pMCPmlXtHyqaS5s9QXIg6mJClYIKbctyVHgCes
         gsHx/hRM53fIolaIfET+Vym+Yq0SSFWmxvOlyEqHgMMTbu0r3JkHoMFnYWVM4GRiJOsd
         TA5SyIeQFopQsPT7si7Tlk2ysnmLhhDWWndtaKPQX+Y9eoy81ycDLiEws/sJEV+bR+SF
         WePY4Y1EFuFJMAAMfe5VoeUTQ1mgAC/2GFD7437gSc8jxgiaT0xcCqYPZBjhmGIIrOM+
         5DIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Y1fbcTDd;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf41.google.com (mail-qv1-xf41.google.com. [2607:f8b0:4864:20::f41])
        by gmr-mx.google.com with ESMTPS id g20si97781pfb.2.2020.04.21.06.01.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Apr 2020 06:01:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) client-ip=2607:f8b0:4864:20::f41;
Received: by mail-qv1-xf41.google.com with SMTP id fb4so6431350qvb.7
        for <kasan-dev@googlegroups.com>; Tue, 21 Apr 2020 06:01:45 -0700 (PDT)
X-Received: by 2002:a0c:b2d2:: with SMTP id d18mr2496270qvf.80.1587474103980;
 Tue, 21 Apr 2020 06:01:43 -0700 (PDT)
MIME-Version: 1.0
References: <20200421014007.6012-1-walter-zh.wu@mediatek.com>
 <CACT4Y+af5fegnN9XOUSkf_B62J5sf2ZZbUwYk=GxtSmAhF3ryQ@mail.gmail.com> <1587472005.5870.7.camel@mtksdccf07>
In-Reply-To: <1587472005.5870.7.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Apr 2020 15:01:31 +0200
Message-ID: <CACT4Y+avYV1xoqB6V5XrQSs-p2s3mKKu+LZQc4EzPaW-jV+KaA@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix KASAN unit tests for tag-based KASAN
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: David Gow <davidgow@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Patricia Alfonso <trishalfonso@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Y1fbcTDd;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, Apr 21, 2020 at 2:26 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> Hi Dmitry,
>
> On Tue, 2020-04-21 at 13:56 +0200, Dmitry Vyukov wrote:
> > On Tue, Apr 21, 2020 at 3:40 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > >
> > > When we use tag-based KASAN, then KASAN unit tests don't detect
> > > out-of-bounds memory access. Because with tag-based KASAN the state
> > > of each 16 aligned bytes of memory is encoded in one shadow byte
> > > and the shadow value is tag of pointer, so we need to read next
> > > shadow byte, the shadow value is not equal to tag of pointer,
> > > then tag-based KASAN will detect out-of-bounds memory access.
> > >
> > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > > Cc: Dmitry Vyukov <dvyukov@google.com>
> > > Cc: Alexander Potapenko <glider@google.com>
> > > Cc: Matthias Brugger <matthias.bgg@gmail.com>
> > > Cc: Andrey Konovalov <andreyknvl@google.com>
> > > Cc: Andrew Morton <akpm@linux-foundation.org>
> > > ---
> > >  lib/test_kasan.c | 62 ++++++++++++++++++++++++++++++++++++++++++------
> > >  1 file changed, 55 insertions(+), 7 deletions(-)
> > >
> > > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > > index e3087d90e00d..a164f6b47fe5 100644
> > > --- a/lib/test_kasan.c
> > > +++ b/lib/test_kasan.c
> > > @@ -40,7 +40,12 @@ static noinline void __init kmalloc_oob_right(void)
> > >                 return;
> > >         }
> >
> > Hi Walter,
> >
> > This would be great to have!
> > But I am concerned about these series that port KASAN tests to KUNIT:
> > https://lkml.org/lkml/2020/4/17/1144
> > I suspect it will be one large merge conflict. Not sure what is the
> > proper way to resovle this. I've added authors to CC.
> >
> Yes, it should have conflicts. Thanks for your reminder.
> >
> > > +#ifdef CONFIG_KASAN_GENERIC
> > >         ptr[size] = 'x';
> > > +#else
> > > +       ptr[size + 5] = 'x';
> > > +#endif
> > > +
> >
> > For this particular snippet I think we can reduce amount of idef'ery
> > and amount of non-compiled code in each configuration with something
> > like:
> >
> >   ptr[size + 5] = 'x';
> >   if (ENABLED(CONFIG_KASAN_GENERIC))
> >       ptr[size] = 'x';
> >
> > One check runs always (it should pass in both configs, right?). The
>
> There is a problem, With generic KASAN it may trigger two KASAN reports.

Why is this a problem? If there are 2, fine. KUNIT can check that if
we expect 2, there are indeed 2.

> if we change it like:
>
> if (ENABLED(CONFIG_KASAN_GENERIC))
>     ptr[size] = 'x';
> else
>     ptr[size + 5] = 'x';
>
> > only only in GENERIC, but it's C-level if rather than preprocessor.
> > KUNIT should make 2 bugs per test easily expressable (and testable).
> >
>
> >
> >
> >
> > >         kfree(ptr);
> > >  }
> > >
> > > @@ -92,7 +97,12 @@ static noinline void __init kmalloc_pagealloc_oob_right(void)
> > >                 return;
> > >         }
> > >
> > > +#ifdef CONFIG_KASAN_GENERIC
> > >         ptr[size] = 0;
> > > +#else
> > > +       ptr[size + 6] = 0;
> > > +#endif
> > > +
> > >         kfree(ptr);
> > >  }
> > >
> > > @@ -162,7 +172,11 @@ static noinline void __init kmalloc_oob_krealloc_more(void)
> > >                 return;
> > >         }
> > >
> > > +#ifdef CONFIG_KASAN_GENERIC
> > >         ptr2[size2] = 'x';
> > > +#else
> > > +       ptr2[size2 + 13] = 'x';
> > > +#endif
> > >         kfree(ptr2);
> > >  }
> > >
> > > @@ -180,7 +194,12 @@ static noinline void __init kmalloc_oob_krealloc_less(void)
> > >                 kfree(ptr1);
> > >                 return;
> > >         }
> > > +
> > > +#ifdef CONFIG_KASAN_GENERIC
> > >         ptr2[size2] = 'x';
> > > +#else
> > > +       ptr2[size2 + 2] = 'x';
> > > +#endif
> > >         kfree(ptr2);
> > >  }
> > >
> > > @@ -216,7 +235,11 @@ static noinline void __init kmalloc_oob_memset_2(void)
> > >                 return;
> > >         }
> > >
> > > +#ifdef CONFIG_KASAN_GENERIC
> > >         memset(ptr+7, 0, 2);
> > > +#else
> > > +       memset(ptr+15, 0, 2);
> > > +#endif
> > >         kfree(ptr);
> > >  }
> > >
> > > @@ -232,7 +255,11 @@ static noinline void __init kmalloc_oob_memset_4(void)
> > >                 return;
> > >         }
> > >
> > > +#ifdef CONFIG_KASAN_GENERIC
> > >         memset(ptr+5, 0, 4);
> > > +#else
> > > +       memset(ptr+15, 0, 4);
> > > +#endif
> > >         kfree(ptr);
> > >  }
> > >
> > > @@ -249,7 +276,11 @@ static noinline void __init kmalloc_oob_memset_8(void)
> > >                 return;
> > >         }
> > >
> > > +#ifdef CONFIG_KASAN_GENERIC
> > >         memset(ptr+1, 0, 8);
> > > +#else
> > > +       memset(ptr+15, 0, 8);
> > > +#endif
> > >         kfree(ptr);
> > >  }
> > >
> > > @@ -265,7 +296,11 @@ static noinline void __init kmalloc_oob_memset_16(void)
> > >                 return;
> > >         }
> > >
> > > +#ifdef CONFIG_KASAN_GENERIC
> > >         memset(ptr+1, 0, 16);
> > > +#else
> > > +       memset(ptr+15, 0, 16);
> > > +#endif
> > >         kfree(ptr);
> > >  }
> > >
> > > @@ -281,7 +316,11 @@ static noinline void __init kmalloc_oob_in_memset(void)
> > >                 return;
> > >         }
> > >
> > > +#ifdef CONFIG_KASAN_GENERIC
> > >         memset(ptr, 0, size+5);
> > > +#else
> > > +       memset(ptr, 0, size+7);
> > > +#endif
> > >         kfree(ptr);
> > >  }
> > >
> > > @@ -415,7 +454,11 @@ static noinline void __init kmem_cache_oob(void)
> > >                 return;
> > >         }
> > >
> > > +#ifdef CONFIG_KASAN_GENERIC
> > >         *p = p[size];
> > > +#else
> > > +       *p = p[size + 8];
> > > +#endif
> > >         kmem_cache_free(cache, p);
> > >         kmem_cache_destroy(cache);
> > >  }
> > > @@ -497,6 +540,11 @@ static noinline void __init copy_user_test(void)
> > >         char __user *usermem;
> > >         size_t size = 10;
> > >         int unused;
> > > +#ifdef CONFIG_KASAN_GENERIC
> > > +       size_t oob_size = 1;
> > > +#else
> > > +       size_t oob_size = 7;
> > > +#endif
> > >
> > >         kmem = kmalloc(size, GFP_KERNEL);
> > >         if (!kmem)
> > > @@ -512,25 +560,25 @@ static noinline void __init copy_user_test(void)
> > >         }
> > >
> > >         pr_info("out-of-bounds in copy_from_user()\n");
> > > -       unused = copy_from_user(kmem, usermem, size + 1);
> > > +       unused = copy_from_user(kmem, usermem, size + oob_size);
> > >
> > >         pr_info("out-of-bounds in copy_to_user()\n");
> > > -       unused = copy_to_user(usermem, kmem, size + 1);
> > > +       unused = copy_to_user(usermem, kmem, size + oob_size);
> > >
> > >         pr_info("out-of-bounds in __copy_from_user()\n");
> > > -       unused = __copy_from_user(kmem, usermem, size + 1);
> > > +       unused = __copy_from_user(kmem, usermem, size + oob_size);
> > >
> > >         pr_info("out-of-bounds in __copy_to_user()\n");
> > > -       unused = __copy_to_user(usermem, kmem, size + 1);
> > > +       unused = __copy_to_user(usermem, kmem, size + oob_size);
> > >
> > >         pr_info("out-of-bounds in __copy_from_user_inatomic()\n");
> > > -       unused = __copy_from_user_inatomic(kmem, usermem, size + 1);
> > > +       unused = __copy_from_user_inatomic(kmem, usermem, size + oob_size);
> > >
> > >         pr_info("out-of-bounds in __copy_to_user_inatomic()\n");
> > > -       unused = __copy_to_user_inatomic(usermem, kmem, size + 1);
> > > +       unused = __copy_to_user_inatomic(usermem, kmem, size + oob_size);
> > >
> > >         pr_info("out-of-bounds in strncpy_from_user()\n");
> > > -       unused = strncpy_from_user(kmem, usermem, size + 1);
> > > +       unused = strncpy_from_user(kmem, usermem, size + oob_size);
> > >
> > >         vm_munmap((unsigned long)usermem, PAGE_SIZE);
> > >         kfree(kmem);
> > > --
> > > 2.18.0
> > >
> > > --
> > > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200421014007.6012-1-walter-zh.wu%40mediatek.com.
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1587472005.5870.7.camel%40mtksdccf07.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BavYV1xoqB6V5XrQSs-p2s3mKKu%2BLZQc4EzPaW-jV%2BKaA%40mail.gmail.com.
