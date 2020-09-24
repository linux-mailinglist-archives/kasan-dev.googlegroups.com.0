Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHMSWL5QKGQEXO3ZSFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 18787277056
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 13:55:11 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id r128sf1751508qkc.9
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 04:55:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600948510; cv=pass;
        d=google.com; s=arc-20160816;
        b=VuFdLmUpi8GO7Lnbef6L/4Avs8EXVb+G5tW+4uJCYzY8iMB6BAEOuc63G6+A4I2BGA
         IEu7spNYkCdbkOKjgT7abZvs1ASHHlSkKGaas5PLfiLmUTjX8WPp9ls4lx6pgA+y27Qt
         MtJ3F7KCNP7mXGV++//3+shy+1PXmVoA1PrFE2d6fVh/cQj5ECCJJHU9NnZRPqEloFk4
         xq3FvAZFhKH6GWvI8BZkOQFXQm/SMezxVW1ZduXfs4pFZxBOPvJZ5XLnPHZq1a2mXxYi
         LKveS4UNyZf8LIbYkgLSX/MJHwIYc/gzJda1RmuKV0e0L46xjshr1Giaq0WXR+Cx8IXX
         GYJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=QvqTYWlrmmefV4I1wElytK5DBZD99xaMgyNljB65q6Q=;
        b=hX9A8sz3avjq77caQOVBXAzT8EL+cxbU4KXjgSHbzdhDHUKji3/ejfhVF50NvfWDaq
         sSEFvnL6PbJAPWHOs7a9PWRZCjTCAmbykzrC2Cl7qGAW2yPGNumvBqI8Ta2wEbSsOHvQ
         ePnzhBOZQLtfhuMsvP4YZWnl45KnIIXCl16jYJY9oRIKQBznOTumn6ZbtAJzkDAHlgu0
         z6W41qKa+ip+jZH4UTpG2ZttgnLWogGIuVYmZenv2mo7Uvagg87AN6eQbAUlrqoY2iFh
         sKkOhZ7/jSiSESTsD6qP+gJHFa32du7ELOK8LBiYAoHBzot07Ru8tOSSubEsGlottYow
         z2ww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KC3r+Mpt;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QvqTYWlrmmefV4I1wElytK5DBZD99xaMgyNljB65q6Q=;
        b=iVxzHxHlqN2dtRPD8GY8u/YSmbYDkdD5oapzbQ6vFWsTfFnLDWzDFjNzal+7F/VxyS
         zrOjeJBAXay7lycfCY70vIsCH/OpN13qd7wxUYw+Aj4YUffZ0o4J25pSH0rnSFIQ2LZw
         0kJsAO/A73l2GGBjTPfpMA045OJ5MDQ30s+Z7ou6G3WQ9dAi8ye2+drxFWtjP/6zA7Ex
         j5Q6kA05lsNezGMtEx9rblL+dLEcjanh1DzUlZYO475lDWAGReHdGFQ00AZCObT/65VS
         zFrsdLgknsxMb7Z42Piyzx8nu+lm3ToomT8fscydcO/2OwecReKLn49OfN8NjRqBjCv1
         y8JQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QvqTYWlrmmefV4I1wElytK5DBZD99xaMgyNljB65q6Q=;
        b=cy5k34bmaMrY4emp4s39MAor0NmicjUXiTmnQpebKs/RxjyvdF+7eS3xCOEdcGNJBR
         e2r3PcaiEmK1j1IXjJR4zpWUAENL1wvy/zjp89BIyQ+RPGkNXEqBkAE+94/RpfFUKRkk
         LVr4fT30NgvyC3jRtTUBE41i3K1egBi+HJ6EVH6BgaBVmmcmvHTbS9l9sky1SpdqjO6C
         GGaCb8ppBsuQbPhC7/iqCcWOE4Jnm2V6KM+IUjQM+MSjK2C1oUiri3GUjbe9E5LOC9kL
         vjFeaayVNs3XKaaD2AExmx/Lvyg2Zh/eVJ8Sx9h+5fU3C50FbCMNszU2QgtWNwNGfrZS
         kSbg==
X-Gm-Message-State: AOAM533BCvOF7M3OLdamZ6wLMfVCzyYw4rfDGPqlkGWQffL43yLChbgQ
	qq7WPpwsuwfMstwBHUl7rkc=
X-Google-Smtp-Source: ABdhPJzQWoVoDLua7An1N1lvJZYmsx0KEatvbUzLqnZTiESX3dY54hJlfsz5kpq5PTouN1l+2fdU5w==
X-Received: by 2002:a05:620a:12f4:: with SMTP id f20mr4314661qkl.312.1600948510099;
        Thu, 24 Sep 2020 04:55:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:4d4:: with SMTP id ck20ls749183qvb.7.gmail; Thu, 24
 Sep 2020 04:55:09 -0700 (PDT)
X-Received: by 2002:a0c:a601:: with SMTP id s1mr4759900qva.57.1600948509563;
        Thu, 24 Sep 2020 04:55:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600948509; cv=none;
        d=google.com; s=arc-20160816;
        b=FYxMG3ceg62kgjzwc+kUvPF8TB3et/oUUAPCGg8+0fFoy/XB91gm6O3PA99UCK3GVN
         1NQWrRnQduT3hYKjYdjJ1nGnYMDk2U429HBR7h4uebzMK0oPUwZSVIe/OXQk+nUPd6cX
         VIIF/+RE3eLmo5m2oduvffhZAnACoE7n/XJIgZLIVP4Tb4RR/0NunS6O7kyDJ8/szBfp
         Nwyy3rd5ErLYzsecU/KPz+x+31toxMkdirTHjOoJBSF8svFHNMq0Zg+SO8dT0bPaS7OR
         /jn1fwco0rVxY4fHLFnbiXbHkzS0nM6q4KIZpmAcKv2UF1nEN995GvNwI6lBU+pEogbT
         tC2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ztRBPPvDaKOY/eanG9V3sp2lDW4LO5Tox/N9KiU+s4o=;
        b=EfarclBvy8vCVZJsFoIOTSS08c5dLUKT3yi3R8QjZmba+4TVL1+yIw9poxPdNsPYOj
         +j/ItMzPIev/P7NsZo+xckELD7qyz9z19mG1q6kpHZqGbJMmvlgpwJveSCS8ugt1AXo3
         7+NmkWg/y1ltrgu5yT1+gwnwIh/8Z/UpXThVg44qcjqGaOe/8BZEzi/3ofXXcgi6AfCt
         RPnuL7W1XD2d4nl6Jm2gcVagR7iueb/vC5hovTqtB/18+899Q9iaEMgU16E+K226H56I
         gvXgIx+3+4dbxxl1c5S/LSU3YqkQ0lk9DppA0md4jD5TcL/W4D6gnTUpKmeR3qmbuwVb
         uUQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KC3r+Mpt;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id l38si155664qta.5.2020.09.24.04.55.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 04:55:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id s66so2891212otb.2
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 04:55:09 -0700 (PDT)
X-Received: by 2002:a9d:758b:: with SMTP id s11mr2619746otk.251.1600948508986;
 Thu, 24 Sep 2020 04:55:08 -0700 (PDT)
MIME-Version: 1.0
References: <20200924040513.31051-1-walter-zh.wu@mediatek.com> <CAG_fn=W2dcGKFKHpDXzNvbPUp3USYyWi2DEpEewboqYBodnSsQ@mail.gmail.com>
In-Reply-To: <CAG_fn=W2dcGKFKHpDXzNvbPUp3USYyWi2DEpEewboqYBodnSsQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 24 Sep 2020 13:54:57 +0200
Message-ID: <CANpmjNNmeqfMLZ0aFC49fHTYS5k7BqTZHP4FmDc=sfZe+j6bOg@mail.gmail.com>
Subject: Re: [PATCH v4 3/6] kasan: print timer and workqueue stack
To: Alexander Potapenko <glider@google.com>
Cc: Walter Wu <walter-zh.wu@mediatek.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=KC3r+Mpt;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 24 Sep 2020 at 13:47, Alexander Potapenko <glider@google.com> wrote:
>
> On Thu, Sep 24, 2020 at 6:05 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > The aux_stack[2] is reused to record the call_rcu() call stack,
> > timer init call stack, and enqueuing work call stacks. So that
> > we need to change the auxiliary stack title for common title,
> > print them in KASAN report.
> >
> > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > Suggested-by: Marco Elver <elver@google.com>
> > Acked-by: Marco Elver <elver@google.com>
> > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
> > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > ---
> >
> > v2:
> > - Thanks for Marco suggestion.
> > - We modify aux stack title name in KASAN report
> >   in order to print call_rcu()/timer/workqueue stack.
> >
> > ---
> >  mm/kasan/report.c | 4 ++--
> >  1 file changed, 2 insertions(+), 2 deletions(-)
> >
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 4f49fa6cd1aa..886809d0a8dd 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -183,12 +183,12 @@ static void describe_object(struct kmem_cache *cache, void *object,
> >
> >  #ifdef CONFIG_KASAN_GENERIC
> >                 if (alloc_info->aux_stack[0]) {
> > -                       pr_err("Last call_rcu():\n");
> > +                       pr_err("Last potentially related work creation:\n");
>
> This doesn't have to be a work creation (expect more callers of
> kasan_record_aux_stack() in the future), so maybe change the wording
> here to "Last potentially related auxiliary stack"?

I suggested "work creation" as it's the most precise for what it is
used for now.

What other users do you have in mind in future that are not work creation?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNmeqfMLZ0aFC49fHTYS5k7BqTZHP4FmDc%3DsfZe%2Bj6bOg%40mail.gmail.com.
