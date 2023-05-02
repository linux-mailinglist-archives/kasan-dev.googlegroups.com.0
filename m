Return-Path: <kasan-dev+bncBCLL3W4IUEDRBGXBYWRAMGQEXXBI44Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EDCE6F4B3E
	for <lists+kasan-dev@lfdr.de>; Tue,  2 May 2023 22:20:43 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-3f080f53c49sf24906685e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 May 2023 13:20:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683058843; cv=pass;
        d=google.com; s=arc-20160816;
        b=fyufr5i2KwO8S4myljng8zdbfqukH4uYMdhQaXo5txBi8s5++qx2nnHqhPWnfiO/DO
         WV83u6mvcSbt7eoMQjjQk6wzZWlvNPh5gKL4EZWTnLh3H2rvkgBkVRLCPRZJTnFKRnVQ
         Qtk5pvuJXLDy4aQtzQTpo2bTh1vqaXMxLp9aQDrHaY+whUHdnPhNpqxzCyyea4MZcmJ8
         Bd1ADSVB1YYo93qvbU0VdIfghEgDVXKlJBcr268Nf9XkEesMkiAztQhxgSyCXxX5hCoG
         +hBYaF/85Av0Db0U2nfInmvrns8jCt2JctVfGanS9kDPCj1z3Y0AobWz8nN7NdVJLcoo
         mLOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=75bfBgoCSisbijBZ/E7NJYbcFyoue+mDAYirEAMGCB0=;
        b=dlVLcOe5aGWDfuAHo2h38suB8cIcq3ESP1oby70dWVkZmKp90OJ1El/ZK3Jzr5k6gk
         XguxsZxkJOxnR8rGCTRkE27Q41ovMJllSUIKbzMq9iPc67oTGqa2O+EZwYJArH+VWXhD
         TUl0ZWUErDIviGAVcS0iAyLF/lrlgghnTQco8aM3M2ErOfnEX0sjK/kPIeQIE0LTHNUI
         2viArP+dqN1t1fUxaP1/cdFOaQsEGC/2iVZ9DJfxAd1YJpOJhq7q80QGpq8IHI1icHkU
         80xIQIo+RUjt+bfhliwewkQIMfv3spLDvncD8cjmEU/TRUjzDu62HDRD0UypSv0992rN
         1c/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=nPG1qjOr;
       spf=pass (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683058843; x=1685650843;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=75bfBgoCSisbijBZ/E7NJYbcFyoue+mDAYirEAMGCB0=;
        b=eZaiK0u9eECcEOSglh4euXvAaQgwdeSkkS9ZjynWXcaFkD1PcKN4nMNAeyg7iDZ4G3
         3eBjQPfVfjQMA20pb6zGuafzNtThOmPwAPp43MhV7Q6ovfZWIYIb8i9hJxixIn5ZCLmq
         khe0YU9lCOERTz2CLSTSL+V4pTGtmccu0P8CMZ78Aee+1Cc9OPGBqfV5S/38kftS415K
         EMkvLuEgPsicIbF86njSRoGcf1ZWl0SEimSfnQ9Sw94v6S3mOXMN0x2BKdKbohpZxzzU
         ISu5fbbwhYIIATmWB3ngxuCiR7bqXFAVjs8p2Nh1MuWYetql6qi24ByTJ7Xw0X6m/20h
         9iYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683058843; x=1685650843;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=75bfBgoCSisbijBZ/E7NJYbcFyoue+mDAYirEAMGCB0=;
        b=g3mSSF7McxWP7ZlqlOKGV3NNs7k+t9aZW2UVbmwjD3meF1S7kLNsmLda0KNt/1xAjL
         TmhPkwROTc4bFNe8KLguj+eo6Y/0NQaiWWltgiecUvoG0wc0tgmPrjipBOzMA1310TpW
         opS3wFTt/IMPOu0XC0aqKFS0bLmSf/VZ6MW1zrQkz1Y1y9+ilgEblLarOMCdQQIOjhlS
         4yknGy3+cgDb5rDEUAcZmzQ3Rk0+wikOL/IYb6MPiOn/K03a614COW1O+kQ3/uDQwUJg
         Ra2fLsrb1S4BqCaC7MwvDephxDaxg5RVkbcJpurWJ0UluCjKmwwKTYBvoiTMO1cJzMcO
         sBjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyP0xIkjtlVPtoDQCdaJ/8dtRm8Er6g+Onzz0nk9Rvw/PGohi+t
	VCmCb++zgKv5SvG8QwlI2BE=
X-Google-Smtp-Source: ACHHUZ4GOnxVcUz3owbSspKFDMqilEeOwEgVI1QXPnn6vnaYOkPHxUcjvFXz9xpVqyIBTubH31mBDQ==
X-Received: by 2002:a1c:6a02:0:b0:3f2:5004:be67 with SMTP id f2-20020a1c6a02000000b003f25004be67mr3304643wmc.4.1683058842817;
        Tue, 02 May 2023 13:20:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:46c7:b0:3f0:9158:ad14 with SMTP id
 q7-20020a05600c46c700b003f09158ad14ls474059wmo.0.-pod-preprod-gmail; Tue, 02
 May 2023 13:20:41 -0700 (PDT)
X-Received: by 2002:a1c:f706:0:b0:3f1:923e:e6bc with SMTP id v6-20020a1cf706000000b003f1923ee6bcmr12624766wmh.0.1683058841524;
        Tue, 02 May 2023 13:20:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683058841; cv=none;
        d=google.com; s=arc-20160816;
        b=t1MYwszZaXSIGyycagfRwgDKN4lj7cFdkEkts7DOZIX88HwAbK0v4iR3eFT6Pgv35i
         dId2gyBTszg1lHMajgHHcEbs33WDth/75sZAlIwylDHESvvYCvlkxSpTul6vaYlKBGRj
         d2l1Fj39sYiPQ7SqESvUwRxQTUGNq1nYiJiXtnvjZ1jJsgNRQHaAgWL4Cv9lFAwdTQM8
         i5TP6bZG12/CENIpIt2mMluajEU2Mevz63xIUIrMSjtjexCJGPRYOGf/0v1mncVQQmlB
         QODBa1qL5m5jphuB6TTy+ZMguampJOm8MsAjeJc/bZIiP+rmJo4IQpVHUfkk1D4ZdJI1
         HHUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=NjplYaLubWQQ5jZtL2++PWvD8pdyHWDOHPxaofdWA4k=;
        b=BZ579/rtRM06iCVpWWOCDMA2+ncdk11Umgh5qnRBZlmsv3TtZA9HQhXd5uRgGlEzx2
         vu9+Kf+07mlpbntlUmWTfSGThVWdGz6SOppavEa/0wtMRTQOqrbW0TnUc9RtClvm7liv
         YKkc9zL9G9D9wRI6DLUld1gbeoME/jjMDtt7zLzGhGe7K3SeqYcGLUmWGtUHeo38t9IW
         figUqktEClAiqGS29M6HxhcSVvd2TNnk2N1dW6dtIVfrnRXRwTwIXLNkxenCsbBrmG4J
         OvqCyEu9pxAnQ6L8P5kk3l5ey+ZP7febA38MIAhM2OC1+Ns97RmuoSDwagBVNyGXCKzy
         JY2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=nPG1qjOr;
       spf=pass (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
Received: from bee.tesarici.cz (bee.tesarici.cz. [77.93.223.253])
        by gmr-mx.google.com with ESMTPS id d13-20020a05600c34cd00b003f173302d8bsi1708005wmq.1.2023.05.02.13.20.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 May 2023 13:20:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted sender) client-ip=77.93.223.253;
Received: from meshulam.tesarici.cz (nat-97.starnet.cz [178.255.168.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by bee.tesarici.cz (Postfix) with ESMTPSA id 6FA1714DA42;
	Tue,  2 May 2023 22:20:39 +0200 (CEST)
Date: Tue, 2 May 2023 22:20:38 +0200
From: Petr =?UTF-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
 mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net,
 void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
 ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org,
 arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
 yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
 ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com,
 ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
 rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
 vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org, Alexander Viro <viro@zeniv.linux.org.uk>
Subject: Re: [PATCH 03/40] fs: Convert alloc_inode_sb() to a macro
Message-ID: <20230502222038.57a47a85@meshulam.tesarici.cz>
In-Reply-To: <ZFFrP8WKRFgZRzoB@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
	<20230501165450.15352-4-surenb@google.com>
	<20230502143530.1586e287@meshulam.tesarici.cz>
	<ZFFrP8WKRFgZRzoB@moria.home.lan>
X-Mailer: Claws Mail 4.1.1 (GTK 3.24.37; x86_64-suse-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: petr@tesarici.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tesarici.cz header.s=mail header.b=nPG1qjOr;       spf=pass
 (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted
 sender) smtp.mailfrom=petr@tesarici.cz;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=tesarici.cz
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

On Tue, 2 May 2023 15:57:51 -0400
Kent Overstreet <kent.overstreet@linux.dev> wrote:

> On Tue, May 02, 2023 at 02:35:30PM +0200, Petr Tesa=C5=99=C3=ADk wrote:
> > On Mon,  1 May 2023 09:54:13 -0700
> > Suren Baghdasaryan <surenb@google.com> wrote:
> >  =20
> > > From: Kent Overstreet <kent.overstreet@linux.dev>
> > >=20
> > > We're introducing alloc tagging, which tracks memory allocations by
> > > callsite. Converting alloc_inode_sb() to a macro means allocations wi=
ll
> > > be tracked by its caller, which is a bit more useful.
> > >=20
> > > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > > Cc: Alexander Viro <viro@zeniv.linux.org.uk>
> > > ---
> > >  include/linux/fs.h | 6 +-----
> > >  1 file changed, 1 insertion(+), 5 deletions(-)
> > >=20
> > > diff --git a/include/linux/fs.h b/include/linux/fs.h
> > > index 21a981680856..4905ce14db0b 100644
> > > --- a/include/linux/fs.h
> > > +++ b/include/linux/fs.h
> > > @@ -2699,11 +2699,7 @@ int setattr_should_drop_sgid(struct mnt_idmap =
*idmap,
> > >   * This must be used for allocating filesystems specific inodes to s=
et
> > >   * up the inode reclaim context correctly.
> > >   */
> > > -static inline void *
> > > -alloc_inode_sb(struct super_block *sb, struct kmem_cache *cache, gfp=
_t gfp)
> > > -{
> > > -	return kmem_cache_alloc_lru(cache, &sb->s_inode_lru, gfp);
> > > -}
> > > +#define alloc_inode_sb(_sb, _cache, _gfp) kmem_cache_alloc_lru(_cach=
e, &_sb->s_inode_lru, _gfp) =20
> >=20
> > Honestly, I don't like this change. In general, pre-processor macros
> > are ugly and error-prone. =20
>=20
> It's a one line macro, it's fine.

It's not the same. A macro effectively adds a keyword, because it gets
expanded regardless of context; for example, you can't declare a local
variable called alloc_inode_sb, and the compiler errors may be quite
confusing at first. See also the discussion about patch 19/40 in this
series.

> > Besides, it works for you only because __kmem_cache_alloc_lru() is
> > declared __always_inline (unless CONFIG_SLUB_TINY is defined, but then
> > you probably don't want the tracking either). In any case, it's going
> > to be difficult for people to understand why and how this works. =20
>=20
> I think you must be confused. kmem_cache_alloc_lru() is a macro, and we
> need that macro to be expanded at the alloc_inode_sb() callsite. It's
> got nothing to do with whether or not __kmem_cache_alloc_lru() is inline
> or not.

Oh no, I am not confused. Look at the definition of
kmem_cache_alloc_lru():

void *kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
			   gfp_t gfpflags)
{
	return __kmem_cache_alloc_lru(s, lru, gfpflags);
}

See? No _RET_IP_ here. That's because it's here:

static __fastpath_inline
void *__kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
			     gfp_t gfpflags)
{
	void *ret =3D slab_alloc(s, lru, gfpflags, _RET_IP_, s->object_size);

	trace_kmem_cache_alloc(_RET_IP_, ret, s, gfpflags, NUMA_NO_NODE);

	return ret;
}

Now, if __kmem_cache_alloc_lru() is not inlined, then this _RET_IP_
will be somewhere inside kmem_cache_alloc_lru(), which is not very
useful.

But what is __fastpath_inline? Well, it depends:

#ifndef CONFIG_SLUB_TINY
#define __fastpath_inline __always_inline
#else
#define __fastpath_inline
#endif

In short, if CONFIG_SLUB_TINY is defined, it's up to the C compiler
whether __kmem_cache_alloc_lru() is inlined or not.

> > If the actual caller of alloc_inode_sb() is needed, I'd rather add it
> > as a parameter and pass down _RET_IP_ explicitly here. =20
>=20
> That approach was considered, but adding an ip parameter to every memory
> allocation function would've been far more churn.

See my reply to patch 19/40. Rename the original function, but add an
__always_inline function with the original signature, and let it take
care of _RET_IP_.

Petr T

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230502222038.57a47a85%40meshulam.tesarici.cz.
