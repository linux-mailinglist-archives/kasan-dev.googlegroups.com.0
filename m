Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBTHDWKTQMGQEWHKXP7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id EF84178B354
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Aug 2023 16:40:13 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-52a1ccf5cf1sf94363a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Aug 2023 07:40:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693233613; cv=pass;
        d=google.com; s=arc-20160816;
        b=yKYtA1EhNt1fV8MdVYrKLRmk+rYEeR5gQG5Xwq/8wZ5285r/p9YpX3GzbCMVFfJCPz
         aTw/v5cBIApg7FW1buVm86x2zwZHOsUfe0LWcGv79erFOH1aiT9tX6RGE1P6SvILNia5
         rLtY9S47AoQqYNwvsO+UUk5E/kOTU6RAEQ5Nr/QKJ89PucCHU34CBmvZEQcyWbb6x0G7
         0Cw7focgBPj3+p4K2L0+GVrP0eP4yxJgMGVYMlOAvubLB8/gjQrY7aK4AxxW2+CptdBx
         XndhhlB9kKrwcGNlCkVUWtlGApeb/fXa1G2subw7XVCJQWxheEKDXqg85zk2iNSbnGtl
         6u/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Va8RK/hpdyPPkeSZFS3Wqdtlg1hvb9SDwwD2pRHqGzo=;
        fh=wMD2Bzzeyk5nubqV0v/7sJHadKGZYYX1QgCGDIygZwQ=;
        b=oDMU4iS9ai80I76BuTyQqzm6CVyZq6ATT5JUbl5rVJx1OlBO6QPas1A27UAoUPfVDd
         9RDjaxiknBOuqU7NFeYVAo/0KEC18um1AGrFGhZYr8wELNu7F/A7+xuWBFJOQM0LRgu2
         /me0/IA1eIPsf2RZ+7WEqmZ/m05av5kzKPsBHl2KRbV6CzWbaaE7cvnA8CMHOkfQkSpI
         qBPPXMpk6+OEdjW8mQO7wc4m2BBaeMDhVu6JoIpC7AQjV+3AYsrcpSNmo4aR7Jjvr+9w
         7Ra7Cbj8AtslqABb+EZM9LFXnUm2Tx+QQK02rs+ksOb42vNRfQpMPdTvAlF9VHoNu9kS
         oscA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=ls7cp4zk;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1693233613; x=1693838413; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Va8RK/hpdyPPkeSZFS3Wqdtlg1hvb9SDwwD2pRHqGzo=;
        b=Nb3IwHf6hLCQ33LlRQxu9z8g+3//Ene6UUW6gfY8zSyU14TwXJZsXMO5iCJkrkx1zd
         69MCuD6d7ajA6IZNmCc+mWN22RGiTLorR/d5B/FYkArSrpq8URrvu9IPyYz7bC1FAAVy
         y4nktCC9HV80p2Jmq6MQ+JcTymPA66KdmBqEdbyR9t6hWlu4JSEa+ClFCGvCauBn4kTY
         ZSGJn2W0P78NGfpfnsJAf4BD9RkvRxHUGryR2b/csuC7sNfaeRNnNGcIm5acyPS6tpbm
         Iqo+KggnfMOqP+u87gkOKZg2PSgCvoj+Aug6mzLmhY/nmfrqrxt1Io6KCcvYkgo0NUaV
         BV6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693233613; x=1693838413;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Va8RK/hpdyPPkeSZFS3Wqdtlg1hvb9SDwwD2pRHqGzo=;
        b=FXwsTi3FzTQ9dgjviooEe4ryz9Hedjg6UhCqW9Lsx8umwuieawiSUqW8L5gsPB+JRk
         2imTyfdtRLByO5hgQWqSGccZvqEjd5Mv5fnEdE5yKy3xdesAmitdBbm+krscqwCPS+ub
         4aGqyiFudjn5/DnTxvLQj5ejE2q5fxp8UC4gjY25o3Hn+uHF2oZTs5GeVQ32iHVk9PdL
         m4jAl5DfwitorDRXzKIbnUK18UVgYZBatpYF/FyM806aWo5c3G7rzFjWBlVUSnAxnFlc
         TdDuevtdWHEBJyb0xN6DNJ7/ZwxQG/FQUidwoHc5RuEWhiEkuGvVV6Ge0phkqHA5fcB8
         OfjQ==
X-Gm-Message-State: AOJu0YyI2mtyxXQHXWBoCjfWYqlHdfjjN54zOh4xEoDjBaBGiIQEP1MY
	LBeMJ/wntEtmgHynjBHAtvo=
X-Google-Smtp-Source: AGHT+IH/KqG9TIvgq6IoRTsg2dnjxF+rSxTBuQAve7RnVX6gw68PpXDZPmLLmJVNJCGaqAZkgfOeUQ==
X-Received: by 2002:a50:c341:0:b0:51a:1ffd:10e with SMTP id q1-20020a50c341000000b0051a1ffd010emr261053edb.3.1693233612746;
        Mon, 28 Aug 2023 07:40:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4e44:b0:3fe:1d45:c713 with SMTP id
 e4-20020a05600c4e4400b003fe1d45c713ls1159947wmq.2.-pod-prod-01-eu; Mon, 28
 Aug 2023 07:40:11 -0700 (PDT)
X-Received: by 2002:a1c:7508:0:b0:3fe:21b9:806 with SMTP id o8-20020a1c7508000000b003fe21b90806mr19877046wmc.0.1693233610914;
        Mon, 28 Aug 2023 07:40:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693233610; cv=none;
        d=google.com; s=arc-20160816;
        b=UPHjeWWqMQsskYw6OdKS9f+vmW48mFeDTSPbPDi55FXF0FgmzBQ8VFbSCb0YNa6pTJ
         OC04d1wb9h7xD0JzfT15+erCdy7iLHwSxfNBUCpH6n1hN6n83QL1xcYuY93MZbpi7afN
         E1t2qbDBkrk+bco23F0VkuGzQbEGBI/q5QXPD9tlZQQeFpyKZK9zs5lndpVJeE6Kz9Iw
         cHyIsJLyrt/UYgCUgD44dxc42o7iZov6v6X8PMaROllV9sBY59+nYxW7feAtbYQmmiJO
         yLm7Qfh/NUotCfajWns0jayueeWGpdDH4RL11mu6pqyme0KOzRSfU4d3niFBaqCoEvdO
         4t+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=j2UbLxhYqoo5RujlArsNRFXdGVrlcSizT9E5D+JEpAc=;
        fh=wMD2Bzzeyk5nubqV0v/7sJHadKGZYYX1QgCGDIygZwQ=;
        b=fHIlfyui3OBdD2nQHHzR2gHhIsg2xnQRbIWLEWnh19T4QeAGC1Zwog3WJ4l8IzbXvl
         UnUIQKNDLksSlo4VmN0cQ/svOKgGp21FCjV9UWjEo9PmEx40t/4oloRGJz+K/yG4Czn+
         hvWx3eYrP1GDhekL7/RedJrRcjK2RTBUQKx1etD2fIQ2YAs+zHl7X8r/fTVqsWmHxngB
         lBi/maBODxZMn4N/li3DH0yynFFkyMLlgvCMKX5w5q17jSyLqGZ8vwPA6YSF6MaY5Uab
         cLQs88kbXvlRwIfJkbAbnAPjye0VO+c3EpUuN+om7et1nENFk3TzAP9oW0VsQCvpUGIR
         ODvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=ls7cp4zk;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id bd16-20020a05600c1f1000b003fc39e1582fsi718765wmb.1.2023.08.28.07.40.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Aug 2023 07:40:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id 5b1f17b1804b1-4009fdc224dso107205e9.1
        for <kasan-dev@googlegroups.com>; Mon, 28 Aug 2023 07:40:10 -0700 (PDT)
X-Received: by 2002:a05:600c:1da6:b0:400:c6de:6a20 with SMTP id
 p38-20020a05600c1da600b00400c6de6a20mr306793wms.3.1693233610358; Mon, 28 Aug
 2023 07:40:10 -0700 (PDT)
MIME-Version: 1.0
References: <20230825211426.3798691-1-jannh@google.com> <CACT4Y+YT6A_ZgkWTF+rxKO_mvZ3AEt+BJtcVR1sKL6LKWDC+0Q@mail.gmail.com>
In-Reply-To: <CACT4Y+YT6A_ZgkWTF+rxKO_mvZ3AEt+BJtcVR1sKL6LKWDC+0Q@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 28 Aug 2023 16:39:33 +0200
Message-ID: <CAG48ez34DN_xsj7hio8epvoE8hM3F_xFoqwWYM-_LVZb39_e9A@mail.gmail.com>
Subject: Re: [PATCH] slub: Introduce CONFIG_SLUB_RCU_DEBUG
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-hardening@vger.kernel.org, kernel-hardening@lists.openwall.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=ls7cp4zk;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::331 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Sat, Aug 26, 2023 at 5:32=E2=80=AFAM Dmitry Vyukov <dvyukov@google.com> =
wrote:
> On Fri, 25 Aug 2023 at 23:15, Jann Horn <jannh@google.com> wrote:
> > Currently, KASAN is unable to catch use-after-free in SLAB_TYPESAFE_BY_=
RCU
> > slabs because use-after-free is allowed within the RCU grace period by
> > design.
> >
> > Add a SLUB debugging feature which RCU-delays every individual
> > kmem_cache_free() before either actually freeing the object or handing =
it
> > off to KASAN, and change KASAN to poison freed objects as normal when t=
his
> > option is enabled.
> >
> > Note that this creates a 16-byte unpoisoned area in the middle of the
> > slab metadata area, which kinda sucks but seems to be necessary in orde=
r
> > to be able to store an rcu_head in there without triggering an ASAN
> > splat during RCU callback processing.
>
> Nice!
>
> Can't we unpoision this rcu_head right before call_rcu() and repoison
> after receiving the callback?

Yeah, I think that should work. It looks like currently
kasan_unpoison() is exposed in include/linux/kasan.h but
kasan_poison() is not, and its inline definition probably means I
can't just move it out of mm/kasan/kasan.h into include/linux/kasan.h;
do you have a preference for how I should handle this? Hmm, and it
also looks like code outside of mm/kasan/ anyway wouldn't know what
are valid values for the "value" argument to kasan_poison().
I also have another feature idea that would also benefit from having
something like kasan_poison() available in include/linux/kasan.h, so I
would prefer that over adding another special-case function inside
KASAN for poisoning this piece of slab metadata...

I guess I could define a wrapper around kasan_poison() in
mm/kasan/generic.c that uses a new poison value for "some other part
of the kernel told us to poison this area", and then expose that
wrapper with a declaration in include/mm/kasan.h? Something like:

void kasan_poison_outline(const void *addr, size_t size, bool init)
{
  kasan_poison(addr, size, KASAN_CUSTOM, init);
}

> What happens on cache destruction?
> Currently we purge quarantine on cache destruction to be able to
> safely destroy the cache. I suspect we may need to somehow purge rcu
> callbacks as well, or do something else.

Ooh, good point, I hadn't thought about that... currently
shutdown_cache() assumes that all the objects have already been freed,
then puts the kmem_cache on a list for
slab_caches_to_rcu_destroy_workfn(), which then waits with an
rcu_barrier() until the slab's pages are all gone.

Luckily kmem_cache_destroy() is already a sleepable operation, so
maybe I should just slap another rcu_barrier() in there for builds
with this config option enabled... I think that should be fine for an
option mostly intended for debugging.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez34DN_xsj7hio8epvoE8hM3F_xFoqwWYM-_LVZb39_e9A%40mail.gmail.=
com.
