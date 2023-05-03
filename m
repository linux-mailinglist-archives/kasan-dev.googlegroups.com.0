Return-Path: <kasan-dev+bncBC7OD3FKWUERBXPWZGRAMGQEANM4RWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F30B6F5AC5
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 17:18:54 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-331632be774sf22086565ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 08:18:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683127133; cv=pass;
        d=google.com; s=arc-20160816;
        b=uIxTc7G+eSDrOO6f4qlwn+Ck2VqJErJTQThg2KA2bSmMtCcQgX9Va4n9fQyMFg4mAD
         +B+WhW1KZyKUMvc5I41KXgKamc7s8xI7+QIZjg846LYskmQbymudS9lj1vbl0tb1qjEc
         sH3iAx2MwRoOykhG1S9135RyWc1r1aoTFzgN3Zi2RZlMrbuMDP1KA6kvvSSzDIJbN4U7
         1FpNEzzNGcC0rVGppb5y+dZLH10yCEwYjgUO8vEGqe910QtXPOwheGbfFrN3Fw3uwjds
         mgVNRl2IXOcnb5XlllAbEUQgBquW7Y3YAt18q+pOnZLrJBOtn5uXTYuY0PpAAbBf3pHD
         cy8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4V0BBr1ndZ0R4wk4+Izg5KuxZv+ZTJ3ggUwLmpQz3Z0=;
        b=oz6OrEQmZPQshGVFs4y9UgpBSZS7Gd+o2oCSrK5Al9r7ITAW/6ulpGRBnpveEQolWM
         EofPWTtIyqzUlyHSOalUxXJm8XXDVOq67pS+raBLYyfNohj/6BQDAsEWeRTEp/f5xdHY
         TlsSWlu64hx4q/dtniU7sY633n0aKoQgskTM98zJJA8RttU1AmjZk/sFOo5mDVoaduS4
         1zlx1n8XfRfZ3K7UMmCxUP5cYxrFrGug5BETrEgwW+sPyMavh6g/PhvgK6VYcVN+I+X0
         BskTDF7ZHy7DAgOsboRhgTMNsstH6shaWyNmOM6jF34+elG6d6VkfB9byYn/6KhDFAB1
         FDRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=uY9LZ4++;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683127133; x=1685719133;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4V0BBr1ndZ0R4wk4+Izg5KuxZv+ZTJ3ggUwLmpQz3Z0=;
        b=esRWVTXUYuyjcaBiaP35gKP141mXKvuuxCfvi/tfQs5WV5hKAG3Hi1CoiZ2muB1r8o
         /iOFDbkF9aniA4Fa5yGDU3bjNKnmWvd4QvLJGUJAJm/44QaMt6WN0sNWNKqgxN9fQtH7
         w0Y3Zq0qWHxqO2Xufe7BQuUP3HPxVjhVKtGIw2chdWi3lVmq65GSe6gXEd4rXfEbW8Ih
         441hyBYKHNxIwd3avhmx2K+fQ8zor6GJE+gA4Xrg63Uo/D8gHRtY+wMhbV5LB6PhcX31
         IilN1uR8nQLRzLVJES86Pa8lDgiuDOp8X1RewWYL0LQIDJTa/moSzMmAQnhezjB3/jQS
         +WUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683127133; x=1685719133;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=4V0BBr1ndZ0R4wk4+Izg5KuxZv+ZTJ3ggUwLmpQz3Z0=;
        b=D71oWMjIPczMFlXAO5PwACtU3feAx/pdnLbIBQCvPDNcK7Q6j0qozi1MCuxy91unoe
         iHnmIWRx8SWSgv4IYF/d4bwtKq0awqT8e3vI8NRzgAUGWkSV2IR8rGu/bc6tl8DbXUhF
         LvMHjCegmf1qHu3FrW0JqothliKJ7Ok5JQQ1h3hi/5Pv60Ei/fHFzabs+fNa4oBkNlIm
         ezF118k4HPaaqm4eiFL0dHMU1x7VBcJpRwkRW8sbblQ8cnc8f8gFT1OlXQ0vuxQNtmeA
         fggP4SFuSEZDjZJrp2+tF7eO2nC2JehB4HnQmCufzSCqONhLBHQ6+xujoS/TUVHmXDdt
         hrpg==
X-Gm-Message-State: AC+VfDz/lxDC7oH99WaJmoONaKdjlR1OaFDYYNdIJd/L7rPd91KHCIEQ
	zC4WLm2gLIZmcTM3/jiE9h0=
X-Google-Smtp-Source: ACHHUZ5rWp+ZchIgHOO4CBVi0c76G7/H2k3/odcVz4Knw6+ywz7CKXMyvAG5MR8UY8DwHP+LZWuEJQ==
X-Received: by 2002:a02:7169:0:b0:40f:9f56:2bfc with SMTP id n41-20020a027169000000b0040f9f562bfcmr1821364jaf.3.1683127133339;
        Wed, 03 May 2023 08:18:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:caf:b0:325:cefc:db5b with SMTP id
 15-20020a056e020caf00b00325cefcdb5bls5086723ilg.7.-pod-prod-gmail; Wed, 03
 May 2023 08:18:52 -0700 (PDT)
X-Received: by 2002:a92:c003:0:b0:32b:75bc:cda2 with SMTP id q3-20020a92c003000000b0032b75bccda2mr14163842ild.22.1683127132711;
        Wed, 03 May 2023 08:18:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683127132; cv=none;
        d=google.com; s=arc-20160816;
        b=wu8W9IoRX2kHP79BoM2kCJycUsXgevpy8zHVVXUXNBhQK8EJnVS8gl0U2QPwUFHVbZ
         omV58RRV2VlF/WHyVQd/dvmVfQ0EG6X+ag8QKBLoOxQGusWzWpaJkbzkKZ9vLoGSPNS5
         MCKcKM9kC3eI+UHbapdzy/er5MESo9HtodnuQS2IqIRpJHhke1WOCjEA30TxYO8ozYIK
         UBYmmnh4hzo0JY3VisSOoZRxebOCVYznRnj4mHSaU0d/UF3WeYlLyhbrW3fu0SRr7pjF
         UVeSIxDXNRUw4gDnEu+5JiHnOUn7yYEFFmIXtO/tCRBwynYSye35/F1OezB0omqnaO12
         IPCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=i4wxKwRBUKexs/Rpj6bBCWyCDPYyPPHlLlNupBtzYaw=;
        b=xWCRGitHYT2Zw4dKAsXtiJMVM/xS5b4pMg2O4/H1MuIFO2Qrv5O90AXeQGetAwGkjb
         05klV7xZnLZiRkloj1okhtnT8aSzjRCmIu9jj2z8D9Q+krwBoE3lz9FMu7Rv1AYwBuZG
         sW0NXjt0ldFuXYv0+w78zKKSMGF8krQ10VwelF7RnN2ogAnklYIJ0+Jle7et7CgQywJM
         prGOXwh6D3iJAVc6QKPV0clT+rRCeyidcMjTu1oygtzh10/g+TG0mLZ0zGkh8UuGte/k
         iwsSOnhvZ7KAPImDZHmzHaUYQMCefnP5i6gS8jUWhAoleN9vlpsLHjgqwNGitgn1Ap5h
         X3Xw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=uY9LZ4++;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb29.google.com (mail-yb1-xb29.google.com. [2607:f8b0:4864:20::b29])
        by gmr-mx.google.com with ESMTPS id t21-20020a056602141500b00763b993e80esi1638288iov.4.2023.05.03.08.18.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 08:18:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) client-ip=2607:f8b0:4864:20::b29;
Received: by mail-yb1-xb29.google.com with SMTP id 3f1490d57ef6-b9e2b26b132so2988858276.1
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 08:18:52 -0700 (PDT)
X-Received: by 2002:a25:6844:0:b0:b9d:90d1:6301 with SMTP id
 d65-20020a256844000000b00b9d90d16301mr17445969ybc.47.1683127131990; Wed, 03
 May 2023 08:18:51 -0700 (PDT)
MIME-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com> <20230501165450.15352-35-surenb@google.com>
 <ZFIO3tXCbmTn53uv@dhcp22.suse.cz>
In-Reply-To: <ZFIO3tXCbmTn53uv@dhcp22.suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 May 2023 08:18:39 -0700
Message-ID: <CAJuCfpHrZ4kWYFPvA3W9J+CmNMuOtGa_ZMXE9fOmKsPQeNt2tg@mail.gmail.com>
Subject: Re: [PATCH 34/40] lib: code tagging context capture support
To: Michal Hocko <mhocko@suse.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
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
 header.i=@google.com header.s=20221208 header.b=uY9LZ4++;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as
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

On Wed, May 3, 2023 at 12:36=E2=80=AFAM Michal Hocko <mhocko@suse.com> wrot=
e:
>
> On Mon 01-05-23 09:54:44, Suren Baghdasaryan wrote:
> [...]
> > +static inline void add_ctx(struct codetag_ctx *ctx,
> > +                        struct codetag_with_ctx *ctc)
> > +{
> > +     kref_init(&ctx->refcount);
> > +     spin_lock(&ctc->ctx_lock);
> > +     ctx->flags =3D CTC_FLAG_CTX_PTR;
> > +     ctx->ctc =3D ctc;
> > +     list_add_tail(&ctx->node, &ctc->ctx_head);
> > +     spin_unlock(&ctc->ctx_lock);
>
> AFAIU every single tracked allocation will get its own codetag_ctx.
> There is no aggregation per allocation site or anything else. This looks
> like a scalability and a memory overhead red flag to me.

True. The allocations here would not be limited. We could introduce a
global limit to the amount of memory that we can use to store contexts
and maybe reuse the oldest entry (in LRU fashion) when we hit that
limit?

>
> > +}
> > +
> > +static inline void rem_ctx(struct codetag_ctx *ctx,
> > +                        void (*free_ctx)(struct kref *refcount))
> > +{
> > +     struct codetag_with_ctx *ctc =3D ctx->ctc;
> > +
> > +     spin_lock(&ctc->ctx_lock);
>
> This could deadlock when allocator is called from the IRQ context.

I see. spin_lock_irqsave() then?

Thanks for the feedback!
Suren.

>
> > +     /* ctx might have been removed while we were using it */
> > +     if (!list_empty(&ctx->node))
> > +             list_del_init(&ctx->node);
> > +     spin_unlock(&ctc->ctx_lock);
> > +     kref_put(&ctx->refcount, free_ctx);
> --
> Michal Hocko
> SUSE Labs

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpHrZ4kWYFPvA3W9J%2BCmNMuOtGa_ZMXE9fOmKsPQeNt2tg%40mail.gmai=
l.com.
