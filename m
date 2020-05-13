Return-Path: <kasan-dev+bncBDGPTM5BQUDRB27Q532QKGQEIWV2TZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 89D5D1D0B77
	for <lists+kasan-dev@lfdr.de>; Wed, 13 May 2020 11:05:49 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id q142sf14340528pfc.21
        for <lists+kasan-dev@lfdr.de>; Wed, 13 May 2020 02:05:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589360748; cv=pass;
        d=google.com; s=arc-20160816;
        b=OsQ2GM2riqIe2N7RDdLVOAF4IrwRxe7w9w4PkOQTW4W+O/5/2HssQZ2uQzzmA2hU7K
         Q7XeyYQgJZxZmOj7JwQOibMpvlmUsxxfwRkRZqrzOhfkLIhHzDY/q7cHCkYsO4IJxAyq
         gSZgW95ewi/lJL9dsKO49BnbJ7Iu0EvFNklkSKF88VhrRBLCAkk7jAvybFhPQ0Mfe9lK
         ydOOufpEABSTUjjNL60Fresbn/PXwZk1PnmzFyL2ImNMTc0hs8ruUaWSM/DoHiHOcgce
         ML2g4AwN0ST+aEwnsEsbssaY5V09dCQhmcAPUFnW72Nvu7jvThHeSbfFy3Wcklc1gMyc
         06Aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=Hsbku9TkN3C7aywtWf+bgdxp5EwGbwxetCow0u5IM9Q=;
        b=T6ktJru+MQt7gqky5syTSkNc+oCs3DZ1DsXBdcnwfZYstKl81XRGUK4qDytvbixieu
         aTnPYJ2fITteJrVy0g+1+V0BQZKDnTQqZ4EnlUAxQTV3cdx33moIVvN5NHJaw7AY+xcr
         8feNF7ySVEghGaCMGJRp20sY/AmeBbVduYzFISQu4y3+gMunIKrXrlOqWI9TdN48/r7P
         r8eOrj9UR5jmJokN1hdjt+w1EJOmvwGz0Yg8+dwqrVjiorZEHiUhbSOMpl2+Ktfyv5PR
         Zv74MmUVCOCww1IuJtjEzKZXmJBkRpqSwYLJlquCCqDoRGkypMcOo7vqIm+GBCwchgX4
         770A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=EujlaFy5;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Hsbku9TkN3C7aywtWf+bgdxp5EwGbwxetCow0u5IM9Q=;
        b=tRrNxZUJ17WJnsI3C9NTxxSSRVjqBA74G5Ziwhq5D8l9Yo9ihtDsgzaiIcK55EL0kW
         9YQfMQp4FYE+riwbXM7h2cY7lQlqbTzv6HvbYjsnmn/K4/zgPIT2iGz8zwdgQVZDm3eo
         j9PqAx7C9a+MDRiHJdcn6g5TtgeNxoCFNIdxJvyJtDaiEAWf+wXQdsjmuq0yoKQQwTQM
         Ym4kVSBvqDJvJ45HXiFpIQ1gG55EyNGydFSaJxA50gEw8ROl0jzgIhbQYZcCc0XDSCT1
         QqvS6b7RXBMmyHb8LrJNu59z+8vHEStIyFONJZWNPjQ6cqOnclNrd2b4lCbmLd+VctaT
         AyRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Hsbku9TkN3C7aywtWf+bgdxp5EwGbwxetCow0u5IM9Q=;
        b=tJ3qZ7p3VB6F1v7ILDsbzLBOEw9lXuX5a5Wxiq/W1iPo38dVD/SNOgaeNXmDTwWRRg
         4s+ff3htCokclWkHZyCy9LhvP+UJZpGsam/kwPwAeqNtLt1obLnO/FNlRID3+n8R0oDb
         s+/eI9VEhpEljdiUGrWadl5XJVHDRnxsxebeyiDFbgOPy4ayiSkzsUc7a7Nk99oKN3cs
         yo75g92hm2nt9IaHkLXTjIQfyt/Mwgi3JIXRsfDYoyH5lLR2vsez9kTOKi8FFdBrAxJM
         Q6lMOkDLcwp8GO6vVJk5UEBdEfKwgIbcJCkDc3syJQ8VlLGZtp0KUdWncGBiUKVTG/0y
         u5Xg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYgd+EfI8jjm02rbgiRGlCimpgeGBEDdnKqMhMr9Qsy9xclyJQr
	/O8xa1UN1zl9SMP/QGiYx7E=
X-Google-Smtp-Source: APiQypJrjZ4YSdGuWpv1QATL63Bl1/LITmDKqidPZTnUcVvieu0FMm2XtzFV64qbm49UFUKo+xMOdw==
X-Received: by 2002:aa7:9709:: with SMTP id a9mr26428228pfg.166.1589360747952;
        Wed, 13 May 2020 02:05:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7c87:: with SMTP id y7ls619365pll.0.gmail; Wed, 13
 May 2020 02:05:47 -0700 (PDT)
X-Received: by 2002:a17:90a:9e9:: with SMTP id 96mr32627230pjo.41.1589360747552;
        Wed, 13 May 2020 02:05:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589360747; cv=none;
        d=google.com; s=arc-20160816;
        b=1JsXYvRHhcsuQlODE+v1NEU5Cnrl8hbjClekEL/S5FMPWCfwjBbMD9N86bXB6OYvyl
         4G35zNcdOXrtdphHC04cHGAJWKq8KutzMjdykmJGquxLFbDfdD+f2OoXYUQZvArRVpfQ
         BQOUg+s3nAaLElclOmWDpDsqMTyJuP1E5Te3SrCjHvVpv6bhCMXiqHQlKYhfGVXHBhna
         /ogl6BKn4+aiYzDF8QLjYkngqfXRVa+XZuCkRbEAbPhWGylanSWIM9y4d1nadjVsWjTb
         COewn6i5l6ucU5LSQBw6rd7booEBOsnOxRIWxsiVxrzEAEpP26paebk6Cu1QCTtbYJPD
         j+Uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=5D8WCKWhqtUmM0QZKWnoCy74fM9ScjwQw/X1UTYKKjQ=;
        b=SK4eLaSvcFKY2o5JnBgLkcbNsql394XnfOWv2wfs2JnkO9VovNyfy573n3FtWD14hG
         XPDVrMpCLqp0GY4FDxI/B/K5v8RknRZl3xhEqASvkxL414YvXfmjbLmw3GR1W9aFZajK
         vt25VLtB99mPBnB93G4qNW+X70iLcgZwkKLf6Az0qI4+NMYL70CsyHcFGY6btI1GRzqx
         UFATM7gOYQJPmfnVH8LXznHjjGYthBWoAuXT4Grj3FAbqaKQYcsqnC5j8w7q/TENcv2I
         Rj7/5mXtJO8Rc2fA4d1jYq9wDFCJwDtpd22SDaj7LARGAW+gozWNvzxxpLYArCHyZ7oy
         Besg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=EujlaFy5;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id c14si78637pfr.6.2020.05.13.02.05.47
        for <kasan-dev@googlegroups.com>;
        Wed, 13 May 2020 02:05:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 1c94421455df4e59b215e8ab80cba6f8-20200513
X-UUID: 1c94421455df4e59b215e8ab80cba6f8-20200513
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1888924811; Wed, 13 May 2020 17:05:45 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 13 May 2020 17:05:42 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 13 May 2020 17:05:41 +0800
Message-ID: <1589360744.14554.10.camel@mtksdccf07>
Subject: Re: [PATCH v2 1/3] rcu/kasan: record and print call_rcu() call stack
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, "Paul E .
 McKenney" <paulmck@kernel.org>, Josh Triplett <josh@joshtriplett.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan
	<jiangshanlai@gmail.com>, Joel Fernandes <joel@joelfernandes.org>, "Andrew
 Morton" <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>,
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, "Linux
 ARM" <linux-arm-kernel@lists.infradead.org>
Date: Wed, 13 May 2020 17:05:44 +0800
In-Reply-To: <CACT4Y+Zv3rCZs8z56NHM0hHWMwQr_2AT8nx0vUigzMG2v3Rt8Q@mail.gmail.com>
References: <20200511023111.15310-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+YWNwTSoheJhc3nMdQi9m719F3PzpGo3TfRY3zAg9EwuQ@mail.gmail.com>
	 <CACT4Y+bO1Zg_jgFHbOWgp7fLAADOQ_-AZmjEHz0WG7=oyOt4Gg@mail.gmail.com>
	 <1589203771.21284.22.camel@mtksdccf07>
	 <CACT4Y+aOkuH6Dn+L+wv1qVOLgXyCY_Ck4hecAMw3DgyBgC9qHw@mail.gmail.com>
	 <1589254720.19238.36.camel@mtksdccf07>
	 <CACT4Y+aibZEBR-3bos3ox5Tuu48TnHC20mDDN0AkWeRUKrT0aw@mail.gmail.com>
	 <1589334472.19238.44.camel@mtksdccf07>
	 <CACT4Y+Zv3rCZs8z56NHM0hHWMwQr_2AT8nx0vUigzMG2v3Rt8Q@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=EujlaFy5;       spf=pass
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

On Wed, 2020-05-13 at 08:51 +0200, 'Dmitry Vyukov' via kasan-dev wrote:
> On Wed, May 13, 2020 at 3:48 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > > > Are you sure it will increase object size?
> > > > > I think we overlap kasan_free_meta with the object as well. The only
> > > > > case we don't overlap kasan_free_meta with the object are
> > > > > SLAB_TYPESAFE_BY_RCU || cache->ctor. But these are rare and it should
> > > > > only affect small objects with small redzones.
> > > > > And I think now we simply have a bug for these objects, we check
> > > > > KASAN_KMALLOC_FREE and then assume object contains free stack, but for
> > > > > objects with ctor, they still contain live object data, we don't store
> > > > > free stack in them.
> > > > > Such objects can be both free and still contain user data.
> > > > >
> > > >
> > > > Overlay kasan_free_meta. I see. but overlay it only when the object was
> > > > freed. kasan_free_meta will be used until free object.
> > > > 1). When put object into quarantine, it need kasan_free_meta.
> > > > 2). When the object exit from quarantine, it need kasan_free_meta
> > > >
> > > > If we choose to overlay kasan_free_meta, then the free stack will be
> > > > stored very late. It may has no free stack in report.
> > >
> > > Sorry, I don't understand what you mean.
> > >
> > > Why will it be stored too late?
> > > In __kasan_slab_free() putting into quarantine and recording free
> > > stack are literally adjacent lines of code:
> > >
> > > static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
> > >       unsigned long ip, bool quarantine)
> > > {
> > >     ...
> > >     kasan_set_free_info(cache, object, tag);
> > >     quarantine_put(get_free_info(cache, object), cache);
> > >
> > >
> > > Just to make sure, what I meant is that we add free_track to kasan_free_meta:
> > >
> > > struct kasan_free_meta {
> > >     struct qlist_node quarantine_link;
> > > +  struct kasan_track free_track;
> > > };
> > >
> >
> > When I see above struct kasan_free_meta, I know why you don't understand
> > my meaning, because I thought you were going to overlay the
> > quarantine_link by free_track, but it seems like to add free_track to
> > kasan_free_meta. Does it enlarge meta-data size?
> 
> I would assume it should not increase meta-data size. In both cases we
> store exactly the same information inside of the object: quarantine
> link and free track.
> I see it more as a question of code organization. We already have a
> concept of "this data is placed inside of the freed object", we
> already have a name for it (kasan_free_meta), we already have code to
> choose where to place it, we already have helper functions to access
> it. And your change effectively duplicates all of this to place the
> free track.
> 

I want to make a summary. Which of the following is the approach we
want? or if I have some misunderstandings, please help me to correct.
Thanks.

1) For different object, then it will has two ways.
1.a) When object are LAB_TYPESAFE_BY_RCU || cache->ctor, then store free
stack into free track of struct kasan_free_meta.
2.b) Except 1.a), store free stack into freed object.

or

2) We always store free stack into free track of struct kasan_free_meta


> > > And I think its life-time and everything should be exactly what we need.
> > >
> > > Also it should help to fix the problem with ctors: kasan_free_meta is
> > > already allocated on the side for such objects, and that's exactly
> > > what we need for objects with ctor's.
> >
> > I see.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1589360744.14554.10.camel%40mtksdccf07.
