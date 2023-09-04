Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEOS3CTQMGQEF2PXMDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 746E5791D73
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Sep 2023 20:59:30 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-401ea9bf934sf10491695e9.2
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Sep 2023 11:59:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693853970; cv=pass;
        d=google.com; s=arc-20160816;
        b=qit7/2K0Jw7cF3MD1y3CgzRgf5ZKmj4toABLZoLegDbH67fz+weBYA4ukLjN+9ltv2
         EHvRbWYNGl0iealI6RosWvHqp4BqBEbFf3CwueWg9yc3JOJe9vMIL8T07c3YKt09qU+H
         yZ8aWSMhDYWVmVr11uoHWlIzJJouVV4HIK9i1ZvH2v4xxawqWxVeWFbOs4WvlLPK03jn
         9Gr+nJ7LwxXF79Cdvttnk0di7461sxkKmlu2pN01H+KbJvp3R0w2pTdPkLnlLm7Vj9tH
         JcM5AHtCTw8MGOHPy0YTVz90Ypy9auyCzQPT9drZle/tREKc2Ows4oKZ/fXIyn/ru2tZ
         2/cQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4mtw457nzDD/S6xXM+d2Ap+EaXZxhJeEYBMAHE+caTE=;
        fh=naLu8b6QNpG3IRa1Sc3pZqeweD+Iq6yOG07UuX+EVok=;
        b=DANQUjq1AZCpMBB7xGyqQw08bQx9aTdwJu4YNTdhXBdlIWTFrDYqxOlM8pjvARFk4j
         NDagxemBXsDnTeBDbqoq5iqvhFI/x0c+gaf7wjBIPalvcS8QhXlIVIZdMLE568SANz1B
         x4fm3Gbmh2dLrbjqip7uZ5dTcaP/LpdQi9yqBRq1nIhup9vqXiBajvU+NoJ9+ZILkh9m
         XfnubpZyu7i+kDP3YmZV2U/ZkhfgKinynYrJRes/3b/R7G7fvsev6QaXQ1kVtG1SE1+5
         T0vaUGlpCsW2D75kW1SLHMP6HQRpiyJU/+eCm9sgDEmvPd0Ge4ADA9dvZnKHMjo9Xzf9
         GtyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=wYYYJ6ed;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693853970; x=1694458770; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4mtw457nzDD/S6xXM+d2Ap+EaXZxhJeEYBMAHE+caTE=;
        b=MwEy1b7eW7gdugefc2rVFHiIgQLnRWpt9gvGCM9inXB9lBX8PINlM3tVzQhWNdxyp/
         /cO4YqwYcMLG1GRNfdcxYi/4huj5bMut/xNwncs/yj5oYFD1mIcA6jc81MJZg75JAvEU
         EP/9rT6eyNZzIUxQaq4YENxQakpxYtswcjqjKuV2mq1xqKcXNPDRHW7NvfcQ1XygxPZJ
         HFDLWisnKkMy8DOxt1UHl/rWyN7cQ019TSy8zh7OfSxDIMzm/ZWr9ehh2DlApOZksYtw
         1RCBF6i66YpYsZo6elqXCjFSPq/0QGt2vE4q0qhn0h5uK4RiZeleleGbteVyw+BofOMx
         3Gcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693853970; x=1694458770;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=4mtw457nzDD/S6xXM+d2Ap+EaXZxhJeEYBMAHE+caTE=;
        b=f/IDvraGXsIMV6WEbwsb0H41Wx0V7gST/rvrCWYJa+YjHwXZKrZFh/QZbKd/XLvhC3
         /cmjwKBBRUZYsrmpw+6DttRTB1wiK0MQ7cnRYCN6j9FaClCMDUeuC/xtNpLGoNDsDsFN
         D7uCvUlykPkOUn38YXMVY4JkTqaNPB/uhHkPUByzXfNz8WHw1kbIJxrVtDIzrwSbmrOg
         xYVRwH85Xsh0VR+6e0AXlykevNDpFHnTBoA3JwHqnZv9goh00Bg3UJkdSzUEcu0tul4+
         ZfQ3/vxfMyD9kGAMYWy54ALc71vWkfDvs/LZUK3EEG7HBAXCS2CWoYwbz8PvrhzjdnmE
         2y8A==
X-Gm-Message-State: AOJu0YwpyyXzYURBTz2NM46glxP/3aMudKdzq42/NmCmwUZLH5DvKaud
	sWJFOTfQ/5vPbULRl1MrHkU=
X-Google-Smtp-Source: AGHT+IH85mtNTAVUyNkJGfwsQurXWdNK6Km5dlGGtP7lvP0wB+5VHI7uID4l5UW4AWdYs464ytow6g==
X-Received: by 2002:a05:600c:ac1:b0:3fe:22a9:900 with SMTP id c1-20020a05600c0ac100b003fe22a90900mr8152001wmr.3.1693853969299;
        Mon, 04 Sep 2023 11:59:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e6c9:0:b0:313:f4ee:a4ba with SMTP id y9-20020adfe6c9000000b00313f4eea4bals1066538wrm.1.-pod-prod-09-eu;
 Mon, 04 Sep 2023 11:59:27 -0700 (PDT)
X-Received: by 2002:a05:6000:14d:b0:314:1416:3be3 with SMTP id r13-20020a056000014d00b0031414163be3mr7306363wrx.70.1693853967454;
        Mon, 04 Sep 2023 11:59:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693853967; cv=none;
        d=google.com; s=arc-20160816;
        b=DzftBRE6NSNe7byD7l59/cHwo0Pkfpqvuy4JRVJANCV+M6i6TmSb2sWW6m/0xxL4Da
         apUtFH/XyhoHcHPtmZYH4hWU6OkYbfazNHBEcHtXSh2sRRn7NEA4hkFej+Nzd+U4aenZ
         5euDhNys1rWc709NI5cxW8fgDLyfaWSDO+tQuJZ8iYwL8awoUsunnAKe9SU1V/vixFxk
         MYU+bQvV2h0BKm6NUkq4lQpAZnIfO9R1ZBELwbv2rM9etrC0wVvMjLylAIVAPLpQE6nX
         4YRCZi4GUWbl2uS5wMiKP+emBjOSu8uM7XpRaPrebNNULivGdocB4SsRcQOwYAW5JV+h
         Xpgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=GDbiLlEqmBfltBmTsCoRx2b9yjBtdlH6iWz3M1Lt5wc=;
        fh=naLu8b6QNpG3IRa1Sc3pZqeweD+Iq6yOG07UuX+EVok=;
        b=DDk6jF2+nps7yMoF95yuRiqwx+2IEgPUkfATTxIZ9fQoziuL+bRp3mMchvzWCZVAx2
         L2pyO48CpErKg8zY5o+x38hqJraqH957P113x8kwES++ndg0cOz1+f1YqzaBXGcwAypT
         aZoIgex5Rs9g9zHqPEQX5kfRd0+/1KEWJAbXufEGgqn8ZKRcuE+PcJTj7ZdzpPO4vwKA
         uB9htUo10smMnf4JU+9grqm+mdJZdts3DzmRUXdawriTfoIFgJzMk5sy9UJcwLPPnKWh
         bBxHOE0h3He2wJ/aOp/o62WzZ7YrkXkXf1MEzqF2LtsF1nCPP1feh8Po4DRTrmZG5XWm
         1NtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=wYYYJ6ed;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id h15-20020a05600004cf00b0031de9b2a3b2si775290wri.6.2023.09.04.11.59.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Sep 2023 11:59:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id 5b1f17b1804b1-401b3ea0656so16846805e9.0
        for <kasan-dev@googlegroups.com>; Mon, 04 Sep 2023 11:59:27 -0700 (PDT)
X-Received: by 2002:a7b:ce18:0:b0:3fb:f0ef:4669 with SMTP id
 m24-20020a7bce18000000b003fbf0ef4669mr8247988wmc.17.1693853966862; Mon, 04
 Sep 2023 11:59:26 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1693328501.git.andreyknvl@google.com> <f7ab7ad4013669f25808bb0e39b3613b98189063.1693328501.git.andreyknvl@google.com>
 <ZO8OACjoGtRuy1Rm@elver.google.com> <CA+fCnZcAuipLKDiNY6LJAs6ODaOG9i6goVLQSdbALrzUDsnv5w@mail.gmail.com>
In-Reply-To: <CA+fCnZcAuipLKDiNY6LJAs6ODaOG9i6goVLQSdbALrzUDsnv5w@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 4 Sep 2023 20:58:50 +0200
Message-ID: <CANpmjNPVu10Y+gO=r3eaU9GP8VL_dqmch3QQXYX8g9D-+HjVPg@mail.gmail.com>
Subject: Re: [PATCH 15/15] kasan: use stack_depot_evict for tag-based modes
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=wYYYJ6ed;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as
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

On Mon, 4 Sept 2023 at 20:48, Andrey Konovalov <andreyknvl@gmail.com> wrote=
:
>
> On Wed, Aug 30, 2023 at 11:38=E2=80=AFAM Marco Elver <elver@google.com> w=
rote:
> >
> > > --- a/mm/kasan/tags.c
> > > +++ b/mm/kasan/tags.c
> > > @@ -96,7 +96,7 @@ static void save_stack_info(struct kmem_cache *cach=
e, void *object,
> > >                       gfp_t gfp_flags, bool is_free)
> > >  {
> > >       unsigned long flags;
> > > -     depot_stack_handle_t stack;
> > > +     depot_stack_handle_t stack, old_stack;
> > >       u64 pos;
> > >       struct kasan_stack_ring_entry *entry;
> > >       void *old_ptr;
> > > @@ -120,6 +120,8 @@ static void save_stack_info(struct kmem_cache *ca=
che, void *object,
> > >       if (!try_cmpxchg(&entry->ptr, &old_ptr, STACK_RING_BUSY_PTR))
> > >               goto next; /* Busy slot. */
> > >
> > > +     old_stack =3D READ_ONCE(entry->stack);
> >
> > Why READ_ONCE? Is it possible that there is a concurrent writer once th=
e
> > slot has been "locked" with STACK_RING_BUSY_PTR?
> >
> > If there is no concurrency, it would be clearer to leave it unmarked an=
d
> > add a comment to that effect. (I also think a comment would be good to
> > say what the WRITE_ONCE below pair with, because at this point I've
> > forgotten.)
>
> Hm, I actually suspect we don't need these READ/WRITE_ONCE to entry
> fields at all. This seems to be a leftover from the initial series
> when I didn't yet have the rwlock. The rwlock prevents the entries
> from being read (in kasan_complete_mode_report_info) while being
> written and the try_cmpxchg prevents the same entry from being
> rewritten (in the unlikely case of wrapping during writing).
>
> Marco, do you think we can drop these READ/WRITE_ONCE?

Yes, I think they can be dropped.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNPVu10Y%2BgO%3Dr3eaU9GP8VL_dqmch3QQXYX8g9D-%2BHjVPg%40mail.=
gmail.com.
