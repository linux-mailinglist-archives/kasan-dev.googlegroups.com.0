Return-Path: <kasan-dev+bncBCS2NBWRUIFBBT6WYWRAMGQENNIPGKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B3B26F4AAB
	for <lists+kasan-dev@lfdr.de>; Tue,  2 May 2023 21:58:08 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2a8be1c1844sf21077861fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 02 May 2023 12:58:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683057487; cv=pass;
        d=google.com; s=arc-20160816;
        b=lpsGWIDPmnn8LDFmLb0AZDWlw/yCRiO/ecOrgkSe344yusHZMwa3PRakGS8m/FVNqx
         dg3/BrZQZFHvwHzpTUj0X9eVZtl6qdPkmxrq0Kuf+POwwlzZGlu0kwT4ZWbUaClpqzYT
         x7a0jTouVSBIjuVlcbbZI8aANqKquLGITw57lT1ivcOnZ9gdcQvwpyHectc3AyHnMHhv
         Y2NvlQAfM6tasKWSZKjh4iHJeEhNHhbozUq15unUoXRsgevyzJVe2xN0ANeF8WHDwBst
         HW6LZNIesI1UyRy2+Z250vFWL0Tp0qWv6XS+ygbnTD3VVA7rc/bBmGYByAcucGaoQffe
         fzXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=3dyWjh4LmqLvZuOc6utbpQUaIWf6omVcikcYQrdLHM4=;
        b=y025hVwX2y+sHOzrTEelC/S646Z4QR01NSIQAXGOz9tFLBqoNsy1c6NhfrZylwdoLr
         /jaQM2Md+qE3IcHSt18nCJ1UBOrWnKf/l9FesUUraX9wbPqiL7TNchp7HTYpTPZXXDSj
         7CaaIBX3J7eFY1PYnaMjKRmgFa8ADJTtqXCTW/XDOQM5E3pW5kyRqh7B2zKrGOP4ApBZ
         Hlg92cWmWouT2V4qWCoPtAe71KKZniZt3B0L3qObbHuRqSFPLmX77Ext13qcRZ650NZP
         wa2NN+54saYIVAJgwrrVW8B9I566CYGwTr6iL4ir7BwqxcnKdN0gLOSXyCNOG6PZBfH5
         0JoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=TPEXvTAZ;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.42 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683057487; x=1685649487;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3dyWjh4LmqLvZuOc6utbpQUaIWf6omVcikcYQrdLHM4=;
        b=A+vMZunY28VVJkKwQWv0Vj5KJiQginwkuv5iyFUA10ZIwF0R7Xhrpklg+odaghTet1
         99DxG/5RA5fwZU//O/eaNbGq00bcyNEb1C1vh8Bc1xEzwslfTTDopjDd/zxTTZIspDaR
         pygAfXfViouHVHkAIG296ARiFt5KZpM5eLFY2CGCo/imggyuZvWKxLBwveJS432oHWjZ
         vonAuwodohef0V6uXIYzgGDfDNnAyr19VOjiPdnTZfV9pSS94ZMu73veVWF8o0vk58J1
         N+Re6SDvV7iaGo3P75s4hxv9mkSXGy5RxMa7lOrAp76FxzV4QL9XkEvAO1d2vxM+mpvn
         rP/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683057487; x=1685649487;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3dyWjh4LmqLvZuOc6utbpQUaIWf6omVcikcYQrdLHM4=;
        b=iatmH//i1H6q1C5hNxsl52ZjNkIRawsMGYvzzYg5p+15+jLL71aJFdJ6IhxCXZ8lOw
         Ji/Jhh1o6aPHhoGIFuRw29+swRx+/c4PFUvsVSROeOBa47/RyyEHUAfwpw8TRMDUQE/n
         tXBYCIArgVZaBPq8blA+hPVH7GsMtgztn1I5hlHAeNQJMnsLYRb/3dvMhJGVkfynrsHI
         N1R2JAoEMHQ6ENGG38LhlRitmJfQAvDNgqYzQsZI+mM9cQEhsdtpBfF+SOAUzI+aONdb
         ibLwb/wuPc109QHMbGnnlRXD1/C2liISgUwqkmhiKTxe3WyQFM7QdDjDlEH/sN8daNS0
         dnWg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxMZmMeeMJmUUZ43IRC/04Uto8W9hEkC71Me1jNCtUtQS26Rt4I
	S2d2Gt+oXY4y6CakVYzKRRs=
X-Google-Smtp-Source: ACHHUZ5NyR9mCgOM4/mfsaVNQACdWXhxk91XqT7/2PjYkS2EpigpU7NIdlTAaEbAFBVlG3h6kaNcZQ==
X-Received: by 2002:a2e:6a0d:0:b0:2a7:6bb4:a701 with SMTP id f13-20020a2e6a0d000000b002a76bb4a701mr4216217ljc.5.1683057487275;
        Tue, 02 May 2023 12:58:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:39c2:b0:4ed:c108:7214 with SMTP id
 k2-20020a05651239c200b004edc1087214ls1396472lfu.3.-pod-prod-gmail; Tue, 02
 May 2023 12:58:05 -0700 (PDT)
X-Received: by 2002:a19:f605:0:b0:4f0:ff66:b4f1 with SMTP id x5-20020a19f605000000b004f0ff66b4f1mr279440lfe.22.1683057485862;
        Tue, 02 May 2023 12:58:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683057485; cv=none;
        d=google.com; s=arc-20160816;
        b=i3PkfcHn0h/ExkANiV7B/r4mG3I7IEr2ZjCrFzLemGt1MWaSNKuZ5Ftg0CoaKsM4C7
         v7V4DoMEYB6X1e4eyo8Yq8gDFj1mt7dsBDXX9arLM2LzLbYdxxIIM4/9X1zq206cS/a+
         FscX8npf28kmmAfy4dsndRmNVK1FnKdyX21ADSx/yWK7RpOG9qUtMugoGW+YHbKd2sRO
         BzcnEm5ciO7SXlAe2KXyIcyTJR8APtthgIQ6a4bwSebYvrrGfVUCZcbBqzDZ42E8wHSv
         gnDnTwfZ5rpAaBRtp+J1vkDPZe6mnVt7DUF/W8077UVPcOqgRqbvhSI4nRmqkoZ3NAli
         hCtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=bbTqJ6Cy48RWo6Tz/tI7JJZLpQOgd1GnXsK6J+pb2Po=;
        b=Tto1qDa7ijAMrtNta6uPzGLdLrbaxM3DcBFfBnJhuNcciTkRHC0HKGIyVQ6RxhZkiA
         sb5jrQK5qMwA7vt8s5m84cHJ9yLhg/Y1J9nX5bVDizE98+Nd+r29mUAbispsdb4SY3ol
         oPWnUcKAG3yezHAd+IBTi2d727A+SPTNfyL58iDHd3i7aB0DJQ9S3xUIEt7NPJGydHOU
         yyfRUSN5Tt75MHmCnAgpHXz+esGQad8OuvaZywn//myJdjhDWXa8uf3DrfXCOfdggjrM
         8q4bGRLoaLJkjPwk9Cf7NtgucwcNZSUWk5tyBESklkIf6jPg9qCnmLMuTD7CnD0y09qQ
         qzGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=TPEXvTAZ;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.42 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-42.mta1.migadu.com (out-42.mta1.migadu.com. [95.215.58.42])
        by gmr-mx.google.com with ESMTPS id g33-20020a0565123ba100b004efe97e3546si1716177lfv.10.2023.05.02.12.58.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 May 2023 12:58:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.42 as permitted sender) client-ip=95.215.58.42;
Date: Tue, 2 May 2023 15:57:51 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Petr =?utf-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net,
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
	ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
	paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
	ndesaulniers@google.com, gregkh@linuxfoundation.org,
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-mm@kvack.org, linux-modules@vger.kernel.org,
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org,
	Alexander Viro <viro@zeniv.linux.org.uk>
Subject: Re: [PATCH 03/40] fs: Convert alloc_inode_sb() to a macro
Message-ID: <ZFFrP8WKRFgZRzoB@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <20230501165450.15352-4-surenb@google.com>
 <20230502143530.1586e287@meshulam.tesarici.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20230502143530.1586e287@meshulam.tesarici.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=TPEXvTAZ;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.42 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Tue, May 02, 2023 at 02:35:30PM +0200, Petr Tesa=C5=99=C3=ADk wrote:
> On Mon,  1 May 2023 09:54:13 -0700
> Suren Baghdasaryan <surenb@google.com> wrote:
>=20
> > From: Kent Overstreet <kent.overstreet@linux.dev>
> >=20
> > We're introducing alloc tagging, which tracks memory allocations by
> > callsite. Converting alloc_inode_sb() to a macro means allocations will
> > be tracked by its caller, which is a bit more useful.
> >=20
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > Cc: Alexander Viro <viro@zeniv.linux.org.uk>
> > ---
> >  include/linux/fs.h | 6 +-----
> >  1 file changed, 1 insertion(+), 5 deletions(-)
> >=20
> > diff --git a/include/linux/fs.h b/include/linux/fs.h
> > index 21a981680856..4905ce14db0b 100644
> > --- a/include/linux/fs.h
> > +++ b/include/linux/fs.h
> > @@ -2699,11 +2699,7 @@ int setattr_should_drop_sgid(struct mnt_idmap *i=
dmap,
> >   * This must be used for allocating filesystems specific inodes to set
> >   * up the inode reclaim context correctly.
> >   */
> > -static inline void *
> > -alloc_inode_sb(struct super_block *sb, struct kmem_cache *cache, gfp_t=
 gfp)
> > -{
> > -	return kmem_cache_alloc_lru(cache, &sb->s_inode_lru, gfp);
> > -}
> > +#define alloc_inode_sb(_sb, _cache, _gfp) kmem_cache_alloc_lru(_cache,=
 &_sb->s_inode_lru, _gfp)
>=20
> Honestly, I don't like this change. In general, pre-processor macros
> are ugly and error-prone.

It's a one line macro, it's fine.

> Besides, it works for you only because __kmem_cache_alloc_lru() is
> declared __always_inline (unless CONFIG_SLUB_TINY is defined, but then
> you probably don't want the tracking either). In any case, it's going
> to be difficult for people to understand why and how this works.

I think you must be confused. kmem_cache_alloc_lru() is a macro, and we
need that macro to be expanded at the alloc_inode_sb() callsite. It's
got nothing to do with whether or not __kmem_cache_alloc_lru() is inline
or not.

> If the actual caller of alloc_inode_sb() is needed, I'd rather add it
> as a parameter and pass down _RET_IP_ explicitly here.

That approach was considered, but adding an ip parameter to every memory
allocation function would've been far more churn.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZFFrP8WKRFgZRzoB%40moria.home.lan.
