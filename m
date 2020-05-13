Return-Path: <kasan-dev+bncBCMIZB7QWENRBXXV532QKGQEVS4YYMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E0C31D0BB6
	for <lists+kasan-dev@lfdr.de>; Wed, 13 May 2020 11:16:15 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id v18sf17198627qtq.22
        for <lists+kasan-dev@lfdr.de>; Wed, 13 May 2020 02:16:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589361374; cv=pass;
        d=google.com; s=arc-20160816;
        b=NOg4ECgHgI/cR/bUo844RI+w+GUJuw8YuQRhCVwkgbdXDyF3AwGoDpBRW1wi+vsies
         3TRMiz/cikKb/GXMLKmw/nh7DHTxsBKEZEIqV7BXqptiAOMu5i7dteMYfFEa2lkLiZQg
         dYl7fo98se9GRhRuwgMpvVc1mzCfLRVj3SY4t53oALr/0x7LvyQcWAwvxj+4lorkC/C6
         NZQPSp2YqNMBGD40OxF115F7jHUizQQ94ped0YmxNigeIOqUuvgGCO7taOv+ubYy2BmI
         WkKKoVzckK3kP2Z8few+j49G+2bmlnaN2Lnohcf8rDzhPk5Hypr4Vm9guD/Cm49+Ugqq
         aRrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=muaxGuVJAS8vB0ANjk6TU2DOZIV2Lxcl86EMdMVARiA=;
        b=NZWMIqIsxgCsNmF+0eE0lp6yfo4ui+vmE6YxEpGyxCDy3wk8ozvzwQ56DY9ZpktdU+
         Nxr/8w/BuuNtj6pXk4c5nn/79oCtAqQPRzApm5uJ1uIOs1R2F0oEim12COwqLZFi8LIg
         A5n2ZdDDeMsbwlBt+kbpy2oht3nHzjQPrLqOWCSGshBjJtM04Fxmv+bFYJCuShhrQ+2l
         u+Xnob7PrZvTWv31dP2jw6nduy2I04gPVHtjoXA0QRTULMjYgU2AQuukH7eOp/Dprzog
         OmL8RSCOPacr1f2J/p8taoTfOSGEblgPXny5TYmlKknJh9gnBiYU0qizqvtSB+i6z5Fv
         +QSg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A5K6VoJj;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=muaxGuVJAS8vB0ANjk6TU2DOZIV2Lxcl86EMdMVARiA=;
        b=m0mkUhPTWJr8ZrnJx0T7dhRiWkZx8Js070bisSh9+t+UpOhVQil9LkQjdS8NgpjAHG
         VnKCVyU257mf/JiYpOz+YB/LNMSDuo7MRC36IlT8K4RjzgsN6fuaNFhhC+oBvoZwUUoY
         wiN7FXboWe2ahC3UJYriqNV01rMTIce2QYWEfjJ+ujGnhi1omogKtsrAH5mIZZugv0c8
         qCvY48AlEQ7QS5NSl9ZqZzmcOBxmPq6dMplp5+qSkuuggu76OxjU7sPac5VMeBE3YgBe
         1wDiRwhRpYE4U7N5MzcTvk3tA4bW09DC42M+eGRl9Nw2qRw4CUwl8HOfB0BRMNh80V60
         M2fA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=muaxGuVJAS8vB0ANjk6TU2DOZIV2Lxcl86EMdMVARiA=;
        b=mNfXmaSQ+4ercumdZpejw/ndfpIE8kP/2L7ZZHgxfiV5rMC3DeKim3ld4KxIUSd2sb
         jul99JQUcEg4GHgKMtmPUgh593XEzGktWVPJWE0L+C4I44N34aOAuoMvYpEZRoVVENvm
         3wSboND5QhRNFtedNoBoE5s5W2abuLc+ki6XhO7ddJ5S8BBw9zhCzTC4gqjmxUrI6T5/
         RY2EP5V5cz2ImVSUBbPqBVW+e+ktrtjm/iytpjMIqc4wlQy//jZqaJMyXfk/HBuH4VJZ
         G6I20Yc7S7cdejERsuZQpdE/ALJT2RGDx4BC3rtGDrSHJsVweOGvLtpCBD4b7nuCX7dH
         oFCQ==
X-Gm-Message-State: AOAM533xu2LVaMUXyGQHe2+dm+gKyuMJHAP4+OtFojurEVnL94ilOLUP
	zYp+NSLoTLRuXxWEEGVvVAM=
X-Google-Smtp-Source: ABdhPJwbi7e3Iikelt5avhgb5q1y0wxk5bvbmf9qcABltcXwvAmH1DGg/X5p4V4BwLV55MXK/VwXIw==
X-Received: by 2002:aed:3b56:: with SMTP id q22mr6039574qte.128.1589361374551;
        Wed, 13 May 2020 02:16:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:8ef:: with SMTP id dr15ls321487qvb.11.gmail; Wed,
 13 May 2020 02:16:14 -0700 (PDT)
X-Received: by 2002:a05:6214:146b:: with SMTP id c11mr24185318qvy.191.1589361374126;
        Wed, 13 May 2020 02:16:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589361374; cv=none;
        d=google.com; s=arc-20160816;
        b=WzWZZmJLrYpNRUSLDhBcnlGz9RJjwQX5jqIeU5C6oH3QCSPiu4V/etg0E756rSbGTi
         W5xhMC7MkpkdKqFtH+KvEy9gSE5XKcgHBMY7VjU4u0VybXCRLTdZtYJaqWjnRJfbQFjW
         0ApNyhezrPu069BIwNiq5VJPA6HoQVjTFvQmqFD9JRPMo4A+7uLHJSVIZ8wpLyI7H601
         cnlUKYFdiiCmCT2YVwHeShrT9MOwIpg0fDlSyogWtmV9Y2mU1BWwwp0H+gmBRmqzZb9A
         q3wJXX6gW4J5Vgnb4F92dbqz2+YMm7SBz5PE4VZOEDrMScdWaUc+5v0g6qCChucr38LI
         JgMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=itos8LHRnARIlzXTWR1kJY/omxPbBoUWPcSfUqjsoA4=;
        b=XmDsXzsLmlU2mwWfVlga4AYeopMwUI3/woPBEKfQLr2C8AOCQsMM1MixwvyE7QamUj
         MsBhx2Chim4miHAUKK9kFnHxKhHDVRGR4AfpvcWbmVSwmwhXVWT2S3nHSyy7puS0XtUl
         zdiSJIJoHhYXJYOcfAiGL7ZC9OUudQFk3+6mvOrNebOj+BQKT7jahCKdfUP1MCMNmJpW
         GR5N075fLpP3qrB2HC/gtZhjRenyyh7Mtbu215OHXsfGykku9cMIzdnMG6BBrfUiQItU
         bL3m/ZAmTQ1u5Oj5VC1NRg2VOH+zubt+96q05XlisyrgCeinnzx7ChVlWRQbzH/jXPZd
         kktw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A5K6VoJj;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id z18si661852qtz.0.2020.05.13.02.16.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 May 2020 02:16:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id f83so16563159qke.13
        for <kasan-dev@googlegroups.com>; Wed, 13 May 2020 02:16:14 -0700 (PDT)
X-Received: by 2002:a37:9d55:: with SMTP id g82mr21819383qke.407.1589361373420;
 Wed, 13 May 2020 02:16:13 -0700 (PDT)
MIME-Version: 1.0
References: <20200511023111.15310-1-walter-zh.wu@mediatek.com>
 <CACT4Y+YWNwTSoheJhc3nMdQi9m719F3PzpGo3TfRY3zAg9EwuQ@mail.gmail.com>
 <CACT4Y+bO1Zg_jgFHbOWgp7fLAADOQ_-AZmjEHz0WG7=oyOt4Gg@mail.gmail.com>
 <1589203771.21284.22.camel@mtksdccf07> <CACT4Y+aOkuH6Dn+L+wv1qVOLgXyCY_Ck4hecAMw3DgyBgC9qHw@mail.gmail.com>
 <1589254720.19238.36.camel@mtksdccf07> <CACT4Y+aibZEBR-3bos3ox5Tuu48TnHC20mDDN0AkWeRUKrT0aw@mail.gmail.com>
 <1589334472.19238.44.camel@mtksdccf07> <CACT4Y+Zv3rCZs8z56NHM0hHWMwQr_2AT8nx0vUigzMG2v3Rt8Q@mail.gmail.com>
 <1589360744.14554.10.camel@mtksdccf07>
In-Reply-To: <1589360744.14554.10.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 May 2020 11:16:01 +0200
Message-ID: <CACT4Y+ZycfHeP5xqqkihRHx-aOoBhN9XdhUmzCdTfaYPXTCzAA@mail.gmail.com>
Subject: Re: [PATCH v2 1/3] rcu/kasan: record and print call_rcu() call stack
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Josh Triplett <josh@joshtriplett.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=A5K6VoJj;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
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

On Wed, May 13, 2020 at 11:05 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> On Wed, 2020-05-13 at 08:51 +0200, 'Dmitry Vyukov' via kasan-dev wrote:
> > On Wed, May 13, 2020 at 3:48 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > > > > Are you sure it will increase object size?
> > > > > > I think we overlap kasan_free_meta with the object as well. The only
> > > > > > case we don't overlap kasan_free_meta with the object are
> > > > > > SLAB_TYPESAFE_BY_RCU || cache->ctor. But these are rare and it should
> > > > > > only affect small objects with small redzones.
> > > > > > And I think now we simply have a bug for these objects, we check
> > > > > > KASAN_KMALLOC_FREE and then assume object contains free stack, but for
> > > > > > objects with ctor, they still contain live object data, we don't store
> > > > > > free stack in them.
> > > > > > Such objects can be both free and still contain user data.
> > > > > >
> > > > >
> > > > > Overlay kasan_free_meta. I see. but overlay it only when the object was
> > > > > freed. kasan_free_meta will be used until free object.
> > > > > 1). When put object into quarantine, it need kasan_free_meta.
> > > > > 2). When the object exit from quarantine, it need kasan_free_meta
> > > > >
> > > > > If we choose to overlay kasan_free_meta, then the free stack will be
> > > > > stored very late. It may has no free stack in report.
> > > >
> > > > Sorry, I don't understand what you mean.
> > > >
> > > > Why will it be stored too late?
> > > > In __kasan_slab_free() putting into quarantine and recording free
> > > > stack are literally adjacent lines of code:
> > > >
> > > > static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
> > > >       unsigned long ip, bool quarantine)
> > > > {
> > > >     ...
> > > >     kasan_set_free_info(cache, object, tag);
> > > >     quarantine_put(get_free_info(cache, object), cache);
> > > >
> > > >
> > > > Just to make sure, what I meant is that we add free_track to kasan_free_meta:
> > > >
> > > > struct kasan_free_meta {
> > > >     struct qlist_node quarantine_link;
> > > > +  struct kasan_track free_track;
> > > > };
> > > >
> > >
> > > When I see above struct kasan_free_meta, I know why you don't understand
> > > my meaning, because I thought you were going to overlay the
> > > quarantine_link by free_track, but it seems like to add free_track to
> > > kasan_free_meta. Does it enlarge meta-data size?
> >
> > I would assume it should not increase meta-data size. In both cases we
> > store exactly the same information inside of the object: quarantine
> > link and free track.
> > I see it more as a question of code organization. We already have a
> > concept of "this data is placed inside of the freed object", we
> > already have a name for it (kasan_free_meta), we already have code to
> > choose where to place it, we already have helper functions to access
> > it. And your change effectively duplicates all of this to place the
> > free track.
> >
>
> I want to make a summary. Which of the following is the approach we
> want? or if I have some misunderstandings, please help me to correct.
> Thanks.
>
> 1) For different object, then it will has two ways.
> 1.a) When object are LAB_TYPESAFE_BY_RCU || cache->ctor, then store free
> stack into free track of struct kasan_free_meta.
> 2.b) Except 1.a), store free stack into freed object.
>
> or
>
> 2) We always store free stack into free track of struct kasan_free_meta

I meant 2): We always store free stack into free track of struct
kasan_free_meta.
I think it will do the same as other options but just with less code
(and simpler code).

Maybe I am missing something here?




> > > > And I think its life-time and everything should be exactly what we need.
> > > >
> > > > Also it should help to fix the problem with ctors: kasan_free_meta is
> > > > already allocated on the side for such objects, and that's exactly
> > > > what we need for objects with ctor's.
> > >
> > > I see.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZycfHeP5xqqkihRHx-aOoBhN9XdhUmzCdTfaYPXTCzAA%40mail.gmail.com.
