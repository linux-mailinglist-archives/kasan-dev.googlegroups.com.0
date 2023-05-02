Return-Path: <kasan-dev+bncBC7OD3FKWUERB55OYWRAMGQEAUC62FI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 033FA6F49B7
	for <lists+kasan-dev@lfdr.de>; Tue,  2 May 2023 20:33:29 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-32948b8cb25sf65224325ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 May 2023 11:33:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683052407; cv=pass;
        d=google.com; s=arc-20160816;
        b=HgqXSVyym0YlS8p0uGCJn+n1VaSsquBxIER78TBhfIcscrl47hOR1sywx+oFU2r3kU
         n0kJqvxathJ+34SyIy2BdQlGGeAgIo03kxiPIc6OoeiZ7vvn5CpHLlsfjOjrHTRTK/Qd
         WlfIienglLUYBA2kDbIdtKj2dHgNHGjH4yvJ0thrZpetOjxVgIrLOcKZjG9/xPlR+Pdl
         GXtBw3WP8wvzswY3ngC0CY7k/lSq8gDDJ0+gtISRa9kccDj7JHHZw7VKrucWj9qjqtGB
         3w0Z1UA5NPfXfa2EcSSKkwzVzCLxi6QeapJXjXqwWanx6mUNXCTe9e71Pkzt1Ux6kRf5
         LLdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=myJY4aW1HSGx3afBP0i6dM9Wshn0dL4UGQnBd7jY+N8=;
        b=PPxHKta7WPGdoH6Aic1fg/6el5EqYd7qbhDqFtD7J+P6kaseOt7YfwzG6P9et2S94f
         fZHE8hMxoo5TYOZX5pMldYwBfe4BL1FBv00QjJj2beYCe+UiJ/AAOlUctsMU1FwKkkEm
         SL/9dl9PvyDKocEjoLY7X04Cs58t62zr32/0LVuRi493AAYlqPrd9mrf7gP/noKftRkj
         7lamsFilFfrltRnH1zzmnGfTquMKMCNvDBiTJBjkAc8yZVXMzxPKSuz37Crs3Rha61Uk
         WyBy6SafANAu7IU//m2SvLVWsSStRv0Ggzz0/3AbHp25sp6p59cdHMgQcMZQYsy1mSva
         20pw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=1qOKHMcI;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683052407; x=1685644407;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=myJY4aW1HSGx3afBP0i6dM9Wshn0dL4UGQnBd7jY+N8=;
        b=aklSRJkkUlxuIwpihfDtFr+190uDsWoRBN9iv8DVuDn5VSIXrnIWxMsg66gi1kyQPx
         WFOrNg7KUUmyjjtuQoKdNHT2H5HOAgJZFJBNS4NK7eU4SbiNeinpRjAKIuvbDmFJWwEY
         p69BwqmX7ZMg4PRQPVWxgRoSPaZcgcK6r4TKLfjff0/Pa60CXCx4TITNnw5gu8unspnO
         i5FNs5w64I89EDXrQfk9biiTq5lFjdK2Fps5DHCewqGuHy8gooGlKsBibFrjqL0pWXep
         LPmtSzpwB4d/Vn/iBror+w2iSe6Q3+KAlQCB9CHk9QdtaL3N9+Dv2sxWUjcYUl2bYDlO
         kCAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683052407; x=1685644407;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=myJY4aW1HSGx3afBP0i6dM9Wshn0dL4UGQnBd7jY+N8=;
        b=UsoClW2n/Hsm6ZheJssTA1CctFb7k7/qpT51v177ufB9ANUwVRlnVQ+DAsHsIG4Xbf
         PmJMYgbcjIDYWo3/lDH8+vJh6+Aid0Bgn5R6zvJm4u8W9lUs5IRERkgeUxjVvXttoj2g
         vKIlK+9q59Fj0LVg/F5jyFDm8iosVdz071I4wRCGx28s1Iq9AH/jTjnZHIDKytIaasOz
         qUxDmwh51nhqLVISCcnANJMZYgyyvdq9Wth/f9Fz+gALb7Tb3nliYRe+37/LtbkEn1R6
         00SzWysovmQQRo8zrRbLWGZbbBIOwKjEu9CYRpVe1e1+0S9uAyV53EL+hOIJBiEmRh0p
         TWQg==
X-Gm-Message-State: AC+VfDyuxZx5HNCdYRUnY09tgRnfCglHnOYgZ19AIfB/YENzFrE17SNZ
	pmB5YC20QgwmZk4iuVjO3ws=
X-Google-Smtp-Source: ACHHUZ5a2P48OHz17VCisR3vtGSAqQjooIUqPcXOJs4fJx0fczPJ8uEtIORx4KT17lRjrBE9qjce5w==
X-Received: by 2002:a92:4b04:0:b0:331:cfa:1b5c with SMTP id m4-20020a924b04000000b003310cfa1b5cmr2847317ilg.6.1683052407603;
        Tue, 02 May 2023 11:33:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:cdac:0:b0:32c:c37c:51ab with SMTP id g12-20020a92cdac000000b0032cc37c51abls4376913ild.8.-pod-prod-gmail;
 Tue, 02 May 2023 11:33:27 -0700 (PDT)
X-Received: by 2002:a92:cac8:0:b0:32b:190f:5dc3 with SMTP id m8-20020a92cac8000000b0032b190f5dc3mr12291938ilq.4.1683052407055;
        Tue, 02 May 2023 11:33:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683052407; cv=none;
        d=google.com; s=arc-20160816;
        b=ap14YS6Lqjy86YGZB4Ay+ByN1wYYFzsMLo15CACURlIvfhaBh8ycYiurxBmnXIZEAD
         fbNpbPpIn4jy8FiTV+Oc11bxBuKaKVijYzgwmjc0mMH+xEFxFq8gkdQly8asxVfo+4Jt
         we1xvNMp+a7av1LjKQ15gASLfEzspKlIosQN4YebS50YZeYE6B9KJnXtvN8mW4kqvY4K
         9UbxtSG/g1VnWHmHVyNRxVHk2rXZmkWzbZVOLgtCrzJHvlBBW4En8tlMkqMKo3A9/C7N
         Q6vo5bWhsOacws2LuuP+vSXCIXGr3gQLKy6sdka782+KBtQjdno9Z4EQWtS2Z/JVL1ql
         xYKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1HVL3xDTGrQVKytv3307oE4wI2qXt6O5pXdSbfIsmfw=;
        b=ttfbMqMT11JmouH7b0iA2d2zzrBYvCYsCTWgMZ9feRm7Jd7BKy428Jht+kBvOqSgCZ
         +tukJLbXR+RL7C0CsFR0xAg9rLK6CkPowEKZBGwXTq8uTmHolC3WN5m35d4m0pWMox/U
         Hg/sJO5VV/Hh5JvV0w4+efBXuoUicm//lE2SSkm5j0hZxP48ONnAiAjEv3TfMc/oSPsX
         qg/GMW47H4iosNi4YRdDiVzSw9Tjj4GVUyfjYY78YolSyCcudL1R10iQvBQSR1T+PEa+
         2HJ5O8sXlxDiTEZXgk0PTe3G5bjblmkYqiInRnK9X6/WgvRNfJG65kTedDOegIw4cTsY
         15bQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=1qOKHMcI;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2d.google.com (mail-yb1-xb2d.google.com. [2607:f8b0:4864:20::b2d])
        by gmr-mx.google.com with ESMTPS id d11-20020a056e021c4b00b00330a4a4c129si698506ilg.4.2023.05.02.11.33.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 May 2023 11:33:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) client-ip=2607:f8b0:4864:20::b2d;
Received: by mail-yb1-xb2d.google.com with SMTP id 3f1490d57ef6-b9dea9d0360so4042156276.1
        for <kasan-dev@googlegroups.com>; Tue, 02 May 2023 11:33:27 -0700 (PDT)
X-Received: by 2002:a25:4115:0:b0:b9e:9159:6a0c with SMTP id
 o21-20020a254115000000b00b9e91596a0cmr1235704yba.6.1683052406321; Tue, 02 May
 2023 11:33:26 -0700 (PDT)
MIME-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com> <20230501165450.15352-10-surenb@google.com>
 <20230502145014.24b28e64@meshulam.tesarici.cz>
In-Reply-To: <20230502145014.24b28e64@meshulam.tesarici.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 May 2023 11:33:15 -0700
Message-ID: <CAJuCfpGA9SMwyQ44XHRHHVf32MPu4o6wy1Q6H=AfJy61Ez-06Q@mail.gmail.com>
Subject: Re: [PATCH 09/40] mm: introduce __GFP_NO_OBJ_EXT flag to selectively
 prevent slabobj_ext creation
To: =?UTF-8?B?UGV0ciBUZXNhxZnDrWs=?= <petr@tesarici.cz>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=1qOKHMcI;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2d as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Tue, May 2, 2023 at 5:50=E2=80=AFAM Petr Tesa=C5=99=C3=ADk <petr@tesaric=
i.cz> wrote:
>
> On Mon,  1 May 2023 09:54:19 -0700
> Suren Baghdasaryan <surenb@google.com> wrote:
>
> > Introduce __GFP_NO_OBJ_EXT flag in order to prevent recursive allocatio=
ns
> > when allocating slabobj_ext on a slab.
> >
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > ---
> >  include/linux/gfp_types.h | 12 ++++++++++--
> >  1 file changed, 10 insertions(+), 2 deletions(-)
> >
> > diff --git a/include/linux/gfp_types.h b/include/linux/gfp_types.h
> > index 6583a58670c5..aab1959130f9 100644
> > --- a/include/linux/gfp_types.h
> > +++ b/include/linux/gfp_types.h
> > @@ -53,8 +53,13 @@ typedef unsigned int __bitwise gfp_t;
> >  #define ___GFP_SKIP_ZERO     0
> >  #define ___GFP_SKIP_KASAN    0
> >  #endif
> > +#ifdef CONFIG_SLAB_OBJ_EXT
> > +#define ___GFP_NO_OBJ_EXT       0x4000000u
> > +#else
> > +#define ___GFP_NO_OBJ_EXT       0
> > +#endif
> >  #ifdef CONFIG_LOCKDEP
> > -#define ___GFP_NOLOCKDEP     0x4000000u
> > +#define ___GFP_NOLOCKDEP     0x8000000u
>
> So now we have two flags that depend on config options, but the first
> one is always allocated in fact. I wonder if you could use an enum to
> let the compiler allocate bits. Something similar to what Muchun Song
> did with section flags.
>
> See commit ed7802dd48f7a507213cbb95bb4c6f1fe134eb5d for reference.

Thanks for the reference. I'll take a closer look and will try to clean it =
up.

>
> >  #else
> >  #define ___GFP_NOLOCKDEP     0
> >  #endif
> > @@ -99,12 +104,15 @@ typedef unsigned int __bitwise gfp_t;
> >   * node with no fallbacks or placement policy enforcements.
> >   *
> >   * %__GFP_ACCOUNT causes the allocation to be accounted to kmemcg.
> > + *
> > + * %__GFP_NO_OBJ_EXT causes slab allocation to have no object
> > extension. */
> >  #define __GFP_RECLAIMABLE ((__force gfp_t)___GFP_RECLAIMABLE)
> >  #define __GFP_WRITE  ((__force gfp_t)___GFP_WRITE)
> >  #define __GFP_HARDWALL   ((__force gfp_t)___GFP_HARDWALL)
> >  #define __GFP_THISNODE       ((__force gfp_t)___GFP_THISNODE)
> >  #define __GFP_ACCOUNT        ((__force gfp_t)___GFP_ACCOUNT)
> > +#define __GFP_NO_OBJ_EXT   ((__force gfp_t)___GFP_NO_OBJ_EXT)
> >
> >  /**
> >   * DOC: Watermark modifiers
> > @@ -249,7 +257,7 @@ typedef unsigned int __bitwise gfp_t;
> >  #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
> >
> >  /* Room for N __GFP_FOO bits */
> > -#define __GFP_BITS_SHIFT (26 + IS_ENABLED(CONFIG_LOCKDEP))
> > +#define __GFP_BITS_SHIFT (27 + IS_ENABLED(CONFIG_LOCKDEP))
>
> If the above suggestion is implemented, this could be changed to
> something like __GFP_LAST_BIT (the enum's last identifier).

Ack.

Thanks for reviewing!
Suren.

>
> Petr T

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpGA9SMwyQ44XHRHHVf32MPu4o6wy1Q6H%3DAfJy61Ez-06Q%40mail.gmai=
l.com.
