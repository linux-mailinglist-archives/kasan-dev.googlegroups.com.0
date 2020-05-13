Return-Path: <kasan-dev+bncBDGPTM5BQUDRB4XY532QKGQEITKSB4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id 04BB61D0BEC
	for <lists+kasan-dev@lfdr.de>; Wed, 13 May 2020 11:22:59 +0200 (CEST)
Received: by mail-ua1-x93f.google.com with SMTP id u10sf7083103uad.8
        for <lists+kasan-dev@lfdr.de>; Wed, 13 May 2020 02:22:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589361778; cv=pass;
        d=google.com; s=arc-20160816;
        b=ldn9MA76SGY5YEtMjmr6Vu/K5TFSAJhpjlZRcGy4CSD3a6MFqoYWIztdRoZDVk6T1b
         tekemRMKWcN3ElKHJMaVPXEeljJADPfI/mOoO3KVsJk8xbJkuXD2ZUpHX5fT15+ipGdR
         ZjnU6pcWQfRSO68u7fooESn4DiFHe+01XRp65L2kc4XRVYBK3alxO1qCm/97N4dUY8+a
         jBLtx8wxGj++FnvgtV31W6k1JJy7JLfiMm5uyePsACrEh7QofRRifLW+k6p156gtcK2z
         DcBqkDsudKFToWS3lizwYD7Dvd66yxyVVStOcni4X+/8VktCYwbaBQ6cfDFL7kC9+Z3w
         MQew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=OdkKOIjpkh0FlQC1VxgI7GaaMHKrmrUOaIzmQrQ3fn4=;
        b=kdjZBwCPXpOMZMbl4hO0LOPsV8evW1PhYxuCo2kliFCiKn+3NMgpHpzXrP6zYf9XfP
         O8LbyUtXQ60vcpIf/5rIS9zIT4otls7HdIx/nuAmVcalpglixeSeG4LZ3i2Rgv/2rmN9
         PrRV+e6oTwZMUVt/c7uLYoehsqjv/wGrzQ8pgcpufObWwf9weI4nllmLQwwIXe1frryw
         DyVmMSfMjedCQrMOmaKHMn2pvucDj5mbnYbYK70kANk72V4kLNQAexrRaX9XOwbSJXMi
         rsKuE2zQbq3wWU1Cx8ym82+gMrnIhGJ/JRYawZZw1IM4f/SAI23g96AxIhfCVLMBZwTS
         V1fw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=IZpjxncN;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OdkKOIjpkh0FlQC1VxgI7GaaMHKrmrUOaIzmQrQ3fn4=;
        b=sQpOvCnB/gW990uKai0cpSoBKyuksTd+DvAMxqazkedfqifl1+U46PJy88HC3aVbBt
         6OFyPH6QPcMRibGm6yMW8AzFnO8PWMsnQAxlvxAb8yg61kcoeXHmExHf6GBKhTjVjwH3
         PM/RhntSrAJk5IAhudwaiP+N5hE48pibfN/3yfDPWm620Va4Klmm0j8dQFm4Qy5rcsmM
         Tn0+gztNY3M5x52b6Rj8yjiODiKYkd3diApZj9+NnHFU1AxcOMq7N+iZEJdgZUhQpXge
         KkbrfOkmUCGqbxaYOKaUJw5YcrFAz++4TLlIrcEVOizFYrs5G9zhK0QT5OI6eg2QLN2R
         aqvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OdkKOIjpkh0FlQC1VxgI7GaaMHKrmrUOaIzmQrQ3fn4=;
        b=YTjqU1xDSByLRbFIs74oOTzbDdzRWbUWPD+2CQ2YviX11O5GKh7zyW9nOqHfNy/Wlc
         l+FqR8+WklCQ7ooTwvOa2EHg7pWD41R/eZIATdsov+9ID1VQsohNucV+SajcjexLjNjY
         av6tP9ss+LCR8eamSqAf53GhkbCFLjtpK/NGQGZJcc/uhYTN+uRb9r6YoxFVpZ0Q3aAO
         Es9jm7Y3lu08qns2dhPN/2LvKZdBguB1Y7M9LBTXU8Kw+Tk4QNOMIwz8ue0Nw6xYaipR
         DqlpXQCi08aZvEumideocRMNfwjke7ciM2/ugwnJ7N/m0mG0yHflZEm1XBvawmjMhRMq
         tDNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530e5suD6S0Dr/3sBEsy44sM99pPs2+2oYyvc3wtPa2A48PwkIRK
	XFDGkYbo40cSVoK3NVsaglo=
X-Google-Smtp-Source: ABdhPJwNCH/sUQYQnI/wYkKU+ojgmZCovHUq1Ll3VhW8IvoncIYPf6yL/tAOL/EJZy29AzYtjUgjXQ==
X-Received: by 2002:ac5:c848:: with SMTP id g8mr12660548vkm.61.1589361778066;
        Wed, 13 May 2020 02:22:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f605:: with SMTP id k5ls144945vso.2.gmail; Wed, 13 May
 2020 02:22:57 -0700 (PDT)
X-Received: by 2002:a67:e1c8:: with SMTP id p8mr19262454vsl.127.1589361777704;
        Wed, 13 May 2020 02:22:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589361777; cv=none;
        d=google.com; s=arc-20160816;
        b=1KX05VAjNHVp2FZKXRMNGPIAKqENigp2ClebGTt2DB3ZX4WStpQZrsma7WwGDlubLm
         vNCrzcWUbxa9wpTWJuv6m+i0E9kyOyUl3VID+bVz8G8hhimPhZwNfXNKkoZDEsrtif/9
         HG1ZSJjyfpZu4yLzLJYRldG2oUbIpu2jlPzUuZNjSyiGfyDjHm7uSQdxMzprY1HcuiBB
         ML9DlgbBxKJ6fU9o5yACFG/bp87sJALQAKdwGhajpXGDaYQ/eXBotUXZKh/lu53iMY8f
         s6aPuxYrcjxb90UEqqzG1QJnTZzaTq92doP3KaWG0uYDVP8UTNi9e6dpzYaOmlGwEX3c
         Ax3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=22zgrRi/oC9kwqIZbeIKNy00cAVePxq0U9heHWhbe+s=;
        b=K+XyGjTJAYxIwxAsbfhZmS/JoHpywoHCskxAH9ggecd+16SYAcBzPa/9Rfh4mPc0TH
         Iw3pVRk7C7FJmd8g7CmccJ+8xgZIYQ52Flw+t+mwhnKyRocZocumP+yB99BQqpDJdD30
         9SBg2SxBWzaCjJDcthnxHB5gLDivgAwKApl5ZSwKg4SXqG79gJXu3p6AA7bAIxgK33vh
         +l39bAXoGXzWctZwUqtkCbOZLHCD/TyZNPeDkoC5GgpgPqSTuNDUUg8vydnwY0olR5AF
         wMcnzSrAdza1Knfg71rP/J1r8NMgzCXLAlSJRAunVKbnAPIJ4b77C0QTC2kLkU3jZwUC
         i1Ag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=IZpjxncN;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id d24si110938vsk.2.2020.05.13.02.22.56
        for <kasan-dev@googlegroups.com>;
        Wed, 13 May 2020 02:22:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: fa62bc129b964dadb0262935d116b170-20200513
X-UUID: fa62bc129b964dadb0262935d116b170-20200513
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1650932209; Wed, 13 May 2020 17:22:52 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs06n1.mediatek.inc (172.21.101.129) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 13 May 2020 17:22:51 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 13 May 2020 17:22:48 +0800
Message-ID: <1589361771.15912.3.camel@mtksdccf07>
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
Date: Wed, 13 May 2020 17:22:51 +0800
In-Reply-To: <CACT4Y+ZycfHeP5xqqkihRHx-aOoBhN9XdhUmzCdTfaYPXTCzAA@mail.gmail.com>
References: <20200511023111.15310-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+YWNwTSoheJhc3nMdQi9m719F3PzpGo3TfRY3zAg9EwuQ@mail.gmail.com>
	 <CACT4Y+bO1Zg_jgFHbOWgp7fLAADOQ_-AZmjEHz0WG7=oyOt4Gg@mail.gmail.com>
	 <1589203771.21284.22.camel@mtksdccf07>
	 <CACT4Y+aOkuH6Dn+L+wv1qVOLgXyCY_Ck4hecAMw3DgyBgC9qHw@mail.gmail.com>
	 <1589254720.19238.36.camel@mtksdccf07>
	 <CACT4Y+aibZEBR-3bos3ox5Tuu48TnHC20mDDN0AkWeRUKrT0aw@mail.gmail.com>
	 <1589334472.19238.44.camel@mtksdccf07>
	 <CACT4Y+Zv3rCZs8z56NHM0hHWMwQr_2AT8nx0vUigzMG2v3Rt8Q@mail.gmail.com>
	 <1589360744.14554.10.camel@mtksdccf07>
	 <CACT4Y+ZycfHeP5xqqkihRHx-aOoBhN9XdhUmzCdTfaYPXTCzAA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=IZpjxncN;       spf=pass
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

On Wed, 2020-05-13 at 11:16 +0200, Dmitry Vyukov wrote:
> On Wed, May 13, 2020 at 11:05 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > On Wed, 2020-05-13 at 08:51 +0200, 'Dmitry Vyukov' via kasan-dev wrote:
> > > On Wed, May 13, 2020 at 3:48 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > > > > > Are you sure it will increase object size?
> > > > > > > I think we overlap kasan_free_meta with the object as well. The only
> > > > > > > case we don't overlap kasan_free_meta with the object are
> > > > > > > SLAB_TYPESAFE_BY_RCU || cache->ctor. But these are rare and it should
> > > > > > > only affect small objects with small redzones.
> > > > > > > And I think now we simply have a bug for these objects, we check
> > > > > > > KASAN_KMALLOC_FREE and then assume object contains free stack, but for
> > > > > > > objects with ctor, they still contain live object data, we don't store
> > > > > > > free stack in them.
> > > > > > > Such objects can be both free and still contain user data.
> > > > > > >
> > > > > >
> > > > > > Overlay kasan_free_meta. I see. but overlay it only when the object was
> > > > > > freed. kasan_free_meta will be used until free object.
> > > > > > 1). When put object into quarantine, it need kasan_free_meta.
> > > > > > 2). When the object exit from quarantine, it need kasan_free_meta
> > > > > >
> > > > > > If we choose to overlay kasan_free_meta, then the free stack will be
> > > > > > stored very late. It may has no free stack in report.
> > > > >
> > > > > Sorry, I don't understand what you mean.
> > > > >
> > > > > Why will it be stored too late?
> > > > > In __kasan_slab_free() putting into quarantine and recording free
> > > > > stack are literally adjacent lines of code:
> > > > >
> > > > > static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
> > > > >       unsigned long ip, bool quarantine)
> > > > > {
> > > > >     ...
> > > > >     kasan_set_free_info(cache, object, tag);
> > > > >     quarantine_put(get_free_info(cache, object), cache);
> > > > >
> > > > >
> > > > > Just to make sure, what I meant is that we add free_track to kasan_free_meta:
> > > > >
> > > > > struct kasan_free_meta {
> > > > >     struct qlist_node quarantine_link;
> > > > > +  struct kasan_track free_track;
> > > > > };
> > > > >
> > > >
> > > > When I see above struct kasan_free_meta, I know why you don't understand
> > > > my meaning, because I thought you were going to overlay the
> > > > quarantine_link by free_track, but it seems like to add free_track to
> > > > kasan_free_meta. Does it enlarge meta-data size?
> > >
> > > I would assume it should not increase meta-data size. In both cases we
> > > store exactly the same information inside of the object: quarantine
> > > link and free track.
> > > I see it more as a question of code organization. We already have a
> > > concept of "this data is placed inside of the freed object", we
> > > already have a name for it (kasan_free_meta), we already have code to
> > > choose where to place it, we already have helper functions to access
> > > it. And your change effectively duplicates all of this to place the
> > > free track.
> > >
> >
> > I want to make a summary. Which of the following is the approach we
> > want? or if I have some misunderstandings, please help me to correct.
> > Thanks.
> >
> > 1) For different object, then it will has two ways.
> > 1.a) When object are LAB_TYPESAFE_BY_RCU || cache->ctor, then store free
> > stack into free track of struct kasan_free_meta.
> > 2.b) Except 1.a), store free stack into freed object.
> >
> > or
> >
> > 2) We always store free stack into free track of struct kasan_free_meta
> 
> I meant 2): We always store free stack into free track of struct
> kasan_free_meta.
> I think it will do the same as other options but just with less code
> (and simpler code).
> 
> Maybe I am missing something here?
> 

You are right, I only make a final confirmation with you. Now there
should be no problems, I will try to implement it.

Thank you for your good suggestion.

> 
> 
> 
> > > > > And I think its life-time and everything should be exactly what we need.
> > > > >
> > > > > Also it should help to fix the problem with ctors: kasan_free_meta is
> > > > > already allocated on the side for such objects, and that's exactly
> > > > > what we need for objects with ctor's.
> > > >
> > > > I see.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1589361771.15912.3.camel%40mtksdccf07.
