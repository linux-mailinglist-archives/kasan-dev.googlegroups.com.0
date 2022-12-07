Return-Path: <kasan-dev+bncBDN3ZEGJT4NBBZOWYGOAMGQEYXLXRGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 896606457DE
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Dec 2022 11:31:04 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id s14-20020a05622a1a8e00b00397eacd9c1asf39042863qtc.21
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Dec 2022 02:31:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670409063; cv=pass;
        d=google.com; s=arc-20160816;
        b=XuSFVx/aiE9p94SSBbh9cJRlvDYM2E41wRGLFuRmtc6oK0vXBP+xxbXnqjONY4Vz+T
         fr5dzF8xv24SXg1FTC25Bi/MtPfHcbGITH9XbSKKvfzKdXIbEUFL1NraJuN5LVikbZq3
         isffFNztfYAvWbLfveHSb1Gon0yBpSE/+mnXmZ1NqLDz2L0BFlJL5CwC8k4NA9r7jzQl
         lsjWLxiOgtHx4KXHtFKpLzf7yjsyWe2eUy9mZbcVFpUaVqlf2JhzqQZpM7IxOaCqjsEE
         Nphk0lKuyAPSM88nzHt4PoQfBtukpdsYs6gyy/SYAvsGdSEe5sTraJgVh63LWYjrFU44
         AGjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GE3OCP5B/iMdPnOUN1xvcNvlWcgFFcceZFJIC7eTNro=;
        b=IKyyHTpIr9HMnRIn0olCzhB1QWxkaCmAJZdE9Ghgq+XVZAq5deKfQOs+HyYJ+lE9PD
         SkQ2IjlI4ef8EHAliK+HmYw21DXWX2qZjp1wC634LnGXbByjYsjpmTR4rXkbtSuVy3VQ
         Hv/fAPfKarVKIZjbPujSFD/ExFxwXn81SDS9Vwrg3S12kvECiHf2UgPu2Vzc+PW9HOey
         /c6AxKLaKZP3RX6nD1N8rT3A97eEi85Oq97hdoRCD81hjnbaicrb44GBPGmSeeIGrfdN
         6ORsN+qMp03bAmvr25JAC3ufdwdvSWXH5MJyjovrunDCpcVUb0PqH6+20b1AHoKDGQII
         k/1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eBPc6LCd;
       spf=pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=edumazet@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GE3OCP5B/iMdPnOUN1xvcNvlWcgFFcceZFJIC7eTNro=;
        b=K9g6YBYQbYzrUdoVxKdWKVvQPF1Z9AUW81NfPdYmb2KCuqD0O3oXozOo7bwfYMja49
         Qk7+i7A/tG0jzKJ9h3fuwTMz8zxCdWpOkUEqOf7yjOLtqlyAE0TdeuednfxSzOuhBpZI
         zA8UbWui94RvuS02Qs9rytPKULeQGDYtI6AxJM/7PhQeP8Oef7WQ/u9sRe+FE+Lnnn/a
         y1ffwIsyLvBrThvZLQCVPxikAn1yCsk5l2PJg5dOofXQCFFqM3oQ1V3jxi08R2ZuDI8U
         Ao2JIln3VaB0qwnEYIEGa+aP+0/G/bBwNvEs4zpSvBGplEFUS22k1rRcPK9/iUcf5HGG
         sEUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=GE3OCP5B/iMdPnOUN1xvcNvlWcgFFcceZFJIC7eTNro=;
        b=xWG8yoCTZIHJPHYghSqxSb/pAS1m2p6VCYy2nuo0Yug1QTIha9MQXV+cmSlgTZwYg9
         Qb5HR/gYvw6mKirmhMnGy/LJyZ84OvF2MyL8mE5zzfJQe4w3MC8egA6jST+TSVnjtACq
         EDSjxc4OC7yr4j3AR3qE7mgzkgs8UlSVABg05rhhFMXmf7O7j2FKFtAdCN5V2z+Rb7ax
         81yFhn71BUdM4moZZSNzMeD4JkIHTFIYs1RBuC02YypXy3QKPqbzD2uB8oYXqSjQUIkC
         56Ze33McDMHFdJ5+jPHhCN1yCuCHwFTmMOOZD+pqHvWn/c8pfxYCdyepk2zf/6FzftTf
         cKnw==
X-Gm-Message-State: ANoB5pk50uTEDQ9yojDAWjrdl9SO1XYhSovfWlUt8JlRYfET7uuycip9
	OAEqFypPw35DCDQb520awxM=
X-Google-Smtp-Source: AA0mqf5mNAlYddZAwQV9OBblJb6saxXXbwB1nJ3u8t+woVPzGvhmLS1j1vDLt3XQpXTF0BCF3DnC7w==
X-Received: by 2002:a05:620a:2728:b0:6fa:1d3b:fa74 with SMTP id b40-20020a05620a272800b006fa1d3bfa74mr79424880qkp.123.1670409063217;
        Wed, 07 Dec 2022 02:31:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:c543:0:b0:4c6:ff53:22 with SMTP id y3-20020a0cc543000000b004c6ff530022ls888423qvi.6.-pod-prod-gmail;
 Wed, 07 Dec 2022 02:31:01 -0800 (PST)
X-Received: by 2002:a05:6214:4281:b0:4c6:8e11:b1ea with SMTP id og1-20020a056214428100b004c68e11b1eamr64777274qvb.18.1670409061281;
        Wed, 07 Dec 2022 02:31:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670409061; cv=none;
        d=google.com; s=arc-20160816;
        b=Q+rSuiES4SBBp/WwaQpkQDNM/sTqVzWO4iuUzjJF8TB6hgFw8EFh3JRuor/9EdPxye
         EJQZF/3GqSGytZZkU18A4EOFHOawzpWx7PCcB66l1F8odqzMa0X65fl7iNDnKnSfMfNW
         WJ73XLF7UWWEcLFosQp3ZWTUL5gyLDOuQh6i1qyYATLdBMiWsgVoDARClzJQNh1GIu7H
         P2nIYQBH2IEDjHtf695a5xBY0Si1iROfwGxH+xjQD5w519Kmd2U+jRKjmiHXVWTOoW4H
         bWXkCZ8qczmWP5hqObglBTYxH0kc62dTFSbPvECNOmzS00gdlKwwV4m3fLc8tPhKqOZ0
         YRkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Te+qRfL0gSPa2I5bK5OY5bAXbxohK6qh4ntuX06onLw=;
        b=cnrtpOO1T0kZ2Y8YVZ9Xq/bUO8/A+vh/rMGGyEzONHA0BhEhv1JZF8Mq0YBCfa56pE
         Ay+jCQK2L5f3+oEj0NVPhGHydj1/eWxn55aPj4/y11NqPOykU2Tek6TPno80PQ3iRSRn
         CnDrjeYYbLS9X4xDdoi6iN35T5YTnh2LKESyTeIFgy6meHS41kOWxwh4IrJHZP9q+OLI
         SRzsZaNaTq7DoTDHpfOxV7ctPOJETgntfKgnjIn0N0d8jNWATafpW2RnjvaFQsN7P+3+
         4iAlif/0oP/auHxOPA4fAbLySDryrKPPNtePfhRRkF82G1NOWVNw/X7U2adJj3vLLGWE
         DU3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eBPc6LCd;
       spf=pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=edumazet@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb29.google.com (mail-yb1-xb29.google.com. [2607:f8b0:4864:20::b29])
        by gmr-mx.google.com with ESMTPS id x28-20020a05620a099c00b006fedd2a6d5csi176883qkx.0.2022.12.07.02.31.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Dec 2022 02:31:01 -0800 (PST)
Received-SPF: pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) client-ip=2607:f8b0:4864:20::b29;
Received: by mail-yb1-xb29.google.com with SMTP id i186so9953055ybc.9
        for <kasan-dev@googlegroups.com>; Wed, 07 Dec 2022 02:31:01 -0800 (PST)
X-Received: by 2002:a05:6902:1004:b0:6fe:d784:282a with SMTP id
 w4-20020a056902100400b006fed784282amr17363367ybt.598.1670409060680; Wed, 07
 Dec 2022 02:31:00 -0800 (PST)
MIME-Version: 1.0
References: <20221206231659.never.929-kees@kernel.org> <20221206175557.1cbd3baa@kernel.org>
In-Reply-To: <20221206175557.1cbd3baa@kernel.org>
From: "'Eric Dumazet' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 7 Dec 2022 11:30:36 +0100
Message-ID: <CANn89i+A49o1zXLJHTjQPrGrdATv7Mkis06FahZ0Yy2gLB1BXQ@mail.gmail.com>
Subject: Re: [PATCH] skbuff: Reallocate to ksize() in __build_skb_around()
To: Jakub Kicinski <kuba@kernel.org>
Cc: Kees Cook <keescook@chromium.org>, "David S. Miller" <davem@davemloft.net>, 
	syzbot+fda18eaa8c12534ccb3b@syzkaller.appspotmail.com, 
	Paolo Abeni <pabeni@redhat.com>, Pavel Begunkov <asml.silence@gmail.com>, 
	pepsipu <soopthegoop@gmail.com>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrii Nakryiko <andrii@kernel.org>, ast@kernel.org, 
	bpf <bpf@vger.kernel.org>, Daniel Borkmann <daniel@iogearbox.net>, Hao Luo <haoluo@google.com>, 
	Jesper Dangaard Brouer <hawk@kernel.org>, John Fastabend <john.fastabend@gmail.com>, jolsa@kernel.org, 
	KP Singh <kpsingh@kernel.org>, martin.lau@linux.dev, 
	Stanislav Fomichev <sdf@google.com>, song@kernel.org, Yonghong Song <yhs@fb.com>, netdev@vger.kernel.org, 
	LKML <linux-kernel@vger.kernel.org>, Menglong Dong <imagedong@tencent.com>, 
	David Ahern <dsahern@kernel.org>, Martin KaFai Lau <kafai@fb.com>, 
	Luiz Augusto von Dentz <luiz.von.dentz@intel.com>, Richard Gobert <richardbgobert@gmail.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, David Rientjes <rientjes@google.com>, 
	linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: edumazet@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=eBPc6LCd;       spf=pass
 (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::b29
 as permitted sender) smtp.mailfrom=edumazet@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Eric Dumazet <edumazet@google.com>
Reply-To: Eric Dumazet <edumazet@google.com>
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

On Wed, Dec 7, 2022 at 2:56 AM Jakub Kicinski <kuba@kernel.org> wrote:
>
> On Tue,  6 Dec 2022 15:17:14 -0800 Kees Cook wrote:
> > -     unsigned int size = frag_size ? : ksize(data);
> > +     unsigned int size = frag_size;
> > +
> > +     /* When frag_size == 0, the buffer came from kmalloc, so we
> > +      * must find its true allocation size (and grow it to match).
> > +      */
> > +     if (unlikely(size == 0)) {
> > +             void *resized;
> > +
> > +             size = ksize(data);
> > +             /* krealloc() will immediate return "data" when
> > +              * "ksize(data)" is requested: it is the existing upper
> > +              * bounds. As a result, GFP_ATOMIC will be ignored.
> > +              */
> > +             resized = krealloc(data, size, GFP_ATOMIC);
> > +             if (WARN_ON(resized != data))
> > +                     data = resized;
> > +     }
> >
>
> Aammgh. build_skb(0) is plain silly, AFAIK. The performance hit of
> using kmalloc()'ed heads is large because GRO can't free the metadata.
> So we end up carrying per-MTU skbs across to the application and then
> freeing them one by one. With pages we just aggregate up to 64k of data
> in a single skb.
>
> I can only grep out 3 cases of build_skb(.. 0), could we instead
> convert them into a new build_skb_slab(), and handle all the silliness
> in such a new helper? That'd be a win both for the memory safety and one
> fewer branch for the fast path.
>
> I think it's worth doing, so LMK if you're okay to do this extra work,
> otherwise I can help (unless e.g. Eric tells me I'm wrong..).

I totally agree, I would indeed remove ksize() use completely,
let callers give us the size, and the head_frag boolean,
instead of inferring from size==0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANn89i%2BA49o1zXLJHTjQPrGrdATv7Mkis06FahZ0Yy2gLB1BXQ%40mail.gmail.com.
