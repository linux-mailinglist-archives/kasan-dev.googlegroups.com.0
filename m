Return-Path: <kasan-dev+bncBDKPDS4R5ECRBSFUQ6JAMGQEPGE55KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id 235A64E9BB3
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Mar 2022 17:54:50 +0200 (CEST)
Received: by mail-ua1-x938.google.com with SMTP id d11-20020ab0724b000000b003513507a46bsf4969812uap.16
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Mar 2022 08:54:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648482889; cv=pass;
        d=google.com; s=arc-20160816;
        b=W7ee4ihWUCT+msk083JGirUvhkbbOQ8J3cU3JW6zmAq7rarIUDyo+FP8nh+8VF6K6Q
         cOQMuewxrEDyLtia9px/lnChb+8dmaquEXLz+8a0ZKNGUkKLfxYP0aaFmkNSjEvI1+nH
         wYOZXGAaMh2m+cPTMiXfKLUkz+odxKIFuDH8NbNdN4QCkfW8NE6folHgxCj6kZIuuC0N
         nIfMveoJZb+XdqQ9qcKMrkDHTq1M5psJP3I4Sl5sBQJq+eIrac1eYgtjV+foLVzKiUc2
         G7BsqK+KoGEbHYXQ2l7OxxnQUnUiu7V5dkyiw6ZWbEIIVFKYCYZkGeN/vaXSUjLqnRFU
         wxEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=JyaJjeJNTuN8XiABHZcYSfDBbQyjqJE8hMJqqFhg9Ws=;
        b=pOYcBkYfRkRHwaaHWkOc1vACLSWCIaKnWXP2eSsBoAVYMJ6DUznc01LS4UK1fJt2k9
         NiYwwgR1Ot1dApRTSD9NXj4xNHAb0V5jYIitbYerLfvXGsclkJF7KkWF/OK7auWarpvZ
         qGsiJNvAWgRH6a535tpK5rSEFFnivIpyOvERggbXyS3LXdwvgiJ8JRsnBHkCCzN48UI5
         pE1FB2jxvME/UvwFDw+Cp7KfON/vr+fE7xII36XIce94NbuGY6QJ58BcKiLOhuxD2Wk0
         qn6t6JeFZemR6kYkn1QiyXm3+dmyOe7l0meEPGapdTMTQo5j6KNMw+3eBlvHholAFeVA
         KLoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=S98nLmUU;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JyaJjeJNTuN8XiABHZcYSfDBbQyjqJE8hMJqqFhg9Ws=;
        b=WjbqOJZisnqWZK5vVtrBo2URbII6G3fxc0y3/ZxeYhZhQmu6HSj4IqHFlUO3R2F8g0
         Kzm/NAi6qNrSZ2rZYZr9Cmkk2OhzhbqjDqcqH/kzPMudvC7Y+9gEiwHeIqSG+92OOeuL
         Icjv2sWnlrYYhxCoxy0lsrfQe9vEaUfML3oY3dJPP8W54fzCLvSUUtLqY+yU2+2WtHWQ
         Vb4hdCr5PM96gcVOwwv67A+lwZVs5PxR2xXPRtVNgJqUPpB6XG38VT2fDcDnBTAOMYZZ
         ohtI2hbZO9DMFhheyJ65LYA3XIWemlAoVTdFC7C8Sez/y5+BBY0VAa+26093YyBPOLp3
         pIgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JyaJjeJNTuN8XiABHZcYSfDBbQyjqJE8hMJqqFhg9Ws=;
        b=ziAbEcs3sX39ZzLvRSwp0+1tCNmhUsjcu5lnMT6wkGFh+2dwKPN5IO+ZLJ52p0p3cK
         fX5nq9cxHq2VZ1pu0PjOuuBvvOSsmPLE7Low9jwSR0tz3hZsYgVlVXWXgafRxRephjf3
         r2Awj8VZSWCg89dF/sxh0NYz7+wSz4rkQjRPQyicHyd/E3kXOpG72aZWWwxC3WnYa1In
         QPLn5Duc9n6IK6sw2cFGp5/lGLRlRQzdx1HlIPhOmVFgbM69b7RbmNPtVwXw+GmRR1mR
         Eu1lnsSVe8VkmlaOaQp6v5u6h90WlAXmudXBJb9s4LO0i0DW+Y/pJ9zlbNaFS4Bo/zQb
         zgxQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530WiyUVgZAJv+0yPiV+4QovG6j77h/C/OJRUu6rgvxcHdT9lm53
	i7Flpg9WkR4xKjvefUpYn3U=
X-Google-Smtp-Source: ABdhPJy12yG+u8V8y0BB1BJoNK2j7LaiPVXX6mihguic5xwgMp+mI+mDH/sEnJFML3i4+hZXh1WAbw==
X-Received: by 2002:a05:6102:3591:b0:325:7323:68b3 with SMTP id h17-20020a056102359100b00325732368b3mr7050312vsu.75.1648482889136;
        Mon, 28 Mar 2022 08:54:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:3343:0:b0:324:e09c:b888 with SMTP id z64-20020a673343000000b00324e09cb888ls2837972vsz.6.gmail;
 Mon, 28 Mar 2022 08:54:48 -0700 (PDT)
X-Received: by 2002:a67:db82:0:b0:320:7056:8b34 with SMTP id f2-20020a67db82000000b0032070568b34mr11002343vsk.25.1648482888553;
        Mon, 28 Mar 2022 08:54:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648482888; cv=none;
        d=google.com; s=arc-20160816;
        b=fpIPg6Tu4VrAVo0mOziHsMPSvWu2Rma515JfLU1HU4IThgeVfEWDavYXn2ofP3grPr
         jjQIOJWAtkd6WOEW7A/5zau7qpXC7dE4u0Ov0c5MT9cxpRG6iLpm0QETXTWd5qqKuDIh
         cGKczAIPc7LNcAlMYyg0yVsruhuo7eA7McyUGwNmfmDENajA4DYZj5629sNQOy4XdIZy
         3EJV7aflzko9Nhn3NGBrDU2bf/rielaY1V9YbO8Btc6oR7oIsNdFtJtbsOSAe5aCqdKU
         aDn7RrDsvCKc9NhfJxnrzo+tStqVYPlB8I9hoq0wMGtAx4+nGkcpuxH0m6udN3B70JYC
         Eq7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=31O2LB6AcOml2RvdEO4cG6BOTLKDOLVfeCmGtEajMX8=;
        b=tFrsAjz/DOckVQeGaXbk+oL57QgSzNJpuinYlJEycIpGxl4zcUtnSA8p9MZxt9cvsA
         LwHtl7MEdpk6+MhNyQfypqaHOnE27DUveLXFRWEJppj1dtCVSA/dj6yAPLwtRT3s/Ogw
         G/2Cn0QjdiGEmv3npr55qsPuIl/iT06MqwGYau8zC0EZx96nO8Kgd2mTh0Np29iAop4k
         naXwIPjWHo+kFo5yyH0pj/9SzPws93A0U7xp0VEPfde0zhCtTp5WPIRMoz/IhKN9TRy0
         ZaX2jy0giB0Xq/4JQLixDHQ52jbDWhAxQm3Au5G8eKlxZIshOo2dqACLXkMj0c6NR6Cv
         YLpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=S98nLmUU;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
Received: from mail-yb1-xb36.google.com (mail-yb1-xb36.google.com. [2607:f8b0:4864:20::b36])
        by gmr-mx.google.com with ESMTPS id h129-20020a1f2187000000b0033fb725e3e3si858865vkh.2.2022.03.28.08.54.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Mar 2022 08:54:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::b36 as permitted sender) client-ip=2607:f8b0:4864:20::b36;
Received: by mail-yb1-xb36.google.com with SMTP id g9so24352403ybf.1
        for <kasan-dev@googlegroups.com>; Mon, 28 Mar 2022 08:54:48 -0700 (PDT)
X-Received: by 2002:a05:6902:70c:b0:634:73ef:e663 with SMTP id
 k12-20020a056902070c00b0063473efe663mr24680640ybt.246.1648482888370; Mon, 28
 Mar 2022 08:54:48 -0700 (PDT)
MIME-Version: 1.0
References: <20220328132843.16624-1-songmuchun@bytedance.com>
 <CANpmjNO=vMYhL_Uf3ewXvfWoan3q+cYjWV0jEze7toKSh2HRjg@mail.gmail.com> <CAMZfGtWfudKnm71uNQtS-=+3_m25nsfPDo8-vZYzrktQbxHUMA@mail.gmail.com>
In-Reply-To: <CAMZfGtWfudKnm71uNQtS-=+3_m25nsfPDo8-vZYzrktQbxHUMA@mail.gmail.com>
From: Muchun Song <songmuchun@bytedance.com>
Date: Mon, 28 Mar 2022 23:54:12 +0800
Message-ID: <CAMZfGtVkp+xCM3kgLHRNRFUs_fus0f3Ry_jFv8QaSWLfnkXREg@mail.gmail.com>
Subject: Re: [PATCH v2] mm: kfence: fix objcgs vector allocation
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Xiongchun duan <duanxiongchun@bytedance.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: songmuchun@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112
 header.b=S98nLmUU;       spf=pass (google.com: domain of songmuchun@bytedance.com
 designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
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

On Mon, Mar 28, 2022 at 11:51 PM Muchun Song <songmuchun@bytedance.com> wrote:
>
> On Mon, Mar 28, 2022 at 11:43 PM Marco Elver <elver@google.com> wrote:
> >
> > On Mon, 28 Mar 2022 at 15:28, Muchun Song <songmuchun@bytedance.com> wrote:
> > >
> > > If the kfence object is allocated to be used for objects vector, then
> > > this slot of the pool eventually being occupied permanently since
> > > the vector is never freed.  The solutions could be 1) freeing vector
> > > when the kfence object is freed or 2) allocating all vectors statically.
> > > Since the memory consumption of object vectors is low, it is better to
> > > chose 2) to fix the issue and it is also can reduce overhead of vectors
> > > allocating in the future.
> > >
> > > Fixes: d3fb45f370d9 ("mm, kfence: insert KFENCE hooks for SLAB")
> > > Signed-off-by: Muchun Song <songmuchun@bytedance.com>
> >
> > Reviewed-by: Marco Elver <elver@google.com>
>
> Thanks.
>
> >
> > Btw, how did you test this?
> >

I have tested it with syzkaller with the following configs.
And I didn't find any issues.

CONFIG_KFENCE=y
CONFIG_KFENCE_SAMPLE_INTERVAL=10
CONFIG_KFENCE_NUM_OBJECTS=2550
CONFIG_KFENCE_DEFERRABLE=n
CONFIG_KFENCE_STATIC_KEYS=y
CONFIG_KFENCE_STRESS_TEST_FAULTS=0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMZfGtVkp%2BxCM3kgLHRNRFUs_fus0f3Ry_jFv8QaSWLfnkXREg%40mail.gmail.com.
