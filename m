Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEPX4CAAMGQEKLPQEFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 02DD430ADF3
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Feb 2021 18:34:11 +0100 (CET)
Received: by mail-vk1-xa3b.google.com with SMTP id d68sf1349910vkg.10
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Feb 2021 09:34:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612200850; cv=pass;
        d=google.com; s=arc-20160816;
        b=wfMxearp6hdB8nTOqz6H19nW3qKecDCCCrPDVuDRpInUTHDayU7Sxs1c9qHFSCYHWm
         thkfHsXT2N1I4eht44zMH4H9+2Shbf1LB4MXKkRupV7iSqkp+AGn8B9I+0a0lA3llOEA
         /Vgl09YvvcE6TkbP2MdCSgoQoQh9eQzalOiE/XAXpZ1s8dw1/7zIGcOwZr8f7JGNC2hv
         f2n2cijzNHP4dy57Bzks+anuUGttLMUGFeZP+C1kdgCsqgpc1Isnsf8kG8dMOjuPC3v8
         nF4wHz8gCtCLZKZi7OeqKvp1crsDpPle48Fy14fTMt/UeKA3vFy6g7BsxshRZaBilGAS
         QWrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ogRchZPltzoHUCfYmZgrJ8HhKOA0zoKfw98L2W5r828=;
        b=x76nnacu0P/9QuPlgXMQsCRPdylX0FlOt88NPdb2RV7mhZYJfzLPATF7dlFajpl1k8
         F8nSt365nxV6QCuq5s2LeJQN2D27y6wPDjcMihvKH14F29MUNMI0kwFW2pXMPq6l/VEb
         Vb9YsGSy5tmlOmBiAwhN7b8z8avCURscbKe46Wb2F+dCztQEgF7F7rqwpK4omCaj9PF7
         g2OV/gTYAhDUlQPqbA3gZMmbTBgvLFHpOU+QtrHC/WxQFwp0MXquzDFYZeLv1kRcJ3Td
         CRpABHsTxXODIxGG7afr3oqAPT47MaUlVoN2E1TUj1qqsepaGhLqtDbGheGj5UZzoTHT
         izKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PTLhm003;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ogRchZPltzoHUCfYmZgrJ8HhKOA0zoKfw98L2W5r828=;
        b=drqa1UQaAmRUbc1KaGAAlDx3usLs4RugitVZvKhczj4/uv/Pb2KQkuuQpKy4FMGR/Y
         7HUYH7gtOxiAbhNNDdO08ocNqfc8sRX92oI/i53dKtzYTHv0tsBRHvrgcbmRQGB8rqyA
         gWr3UJn99glmCzdBFKlEIMyHbD8/51c5WNQassPjf2AhzzswXFgkghlQaqBA42qM1JPy
         LwjrgoselGzu84N+QUt2RYWGckBwx8TNxCbl9shKwhcui5W1GEf0fi9SbfBTQ26EQYVW
         StWChnuGdAShPS8t4RKYTxWD4ElWha14pfCSOJ0NZoIATWdDBXHLJOE5FId2TaP8IQtc
         VTdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ogRchZPltzoHUCfYmZgrJ8HhKOA0zoKfw98L2W5r828=;
        b=tdmktYaf6QzvdjUOYzTdmw6X0fNdaqAPYK37T4Dnkm0/QvGvo9Knxzcj8b9foIn4G2
         KmJRb9sH26Lh9wwq/flobAK2rb7jrw1G3KrY4gUCGfQcB8BY0GhNltL9Ihzlw2w5LL/J
         +2F829DTv8sMm/pGQyRHqwCiUik4jLB8DRpV19HcXRQagR+Km1Lz+Gi7drxMtIEfRd+2
         hVU/zqIAzHYzCp9jPeq3qCSty/bE74pMZqKpdaP5cdTd1JLMlReSqRNVHmk4wmd8Dn3u
         JcfYpoaLJCXHMEZBozgouSfOekYoqRRl31ukOqC9VQCHkA6kXUIoVnkfu7rbgIMEgsqz
         /OWQ==
X-Gm-Message-State: AOAM533XjAInSvzPqlXa4bM0ZGa7D18BvkD/rFn0NBLo1uap/5QpZeus
	RVADpNSc5WSjwRmkNjuPUhc=
X-Google-Smtp-Source: ABdhPJyJRhOqjnUiHtO5DTOe7sJDpgdcyA3ecMgGY/eQgyrqwLWGnzQ4pysODXr64ZeNXG37ZHnLeQ==
X-Received: by 2002:ab0:6dc7:: with SMTP id r7mr10151093uaf.115.1612200849862;
        Mon, 01 Feb 2021 09:34:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:3d86:: with SMTP id k128ls876458vka.0.gmail; Mon, 01 Feb
 2021 09:34:09 -0800 (PST)
X-Received: by 2002:a1f:1d4a:: with SMTP id d71mr10098189vkd.12.1612200849355;
        Mon, 01 Feb 2021 09:34:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612200849; cv=none;
        d=google.com; s=arc-20160816;
        b=OSX1ZZHniJ6WJPw1knQnQJgE/lUunZxYmjs9ZcEt9488HUYpGQh7I4kTpOYDja7P1S
         c685zXARwkXdnRPfXgFt7bnkCGSLgQ6Ro4YC0PI4Ti6FdWWl3Ci0+3+8RC1W7mnIq65x
         ImpIFsl/0OOaWc41SP1FIERyRjXpO8z26OwNkd5lSvLNdxEFeZ2MeyEICjDFNsFjVGrN
         8G8SZuN4IDFcK4fVeMLBlqQu0HhhhHZbswddyWrqEMhdtdqRnf3UAgwQjB8gL+eDAZ6d
         3BqoWuZKImj0xLlmGWhbQt3S7fTdO6/sux7woz79Euo5mCLKDJiv+keNA+ddCtvA6bsi
         NAeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=oe4wUnUrEXeJigbdmJ1Zo8HkG5rVFt/oiu13Xp4cGG0=;
        b=RYBK2mrbYmn5bjT7AqBgMGESRPY08mgjCG+yFnmrgTjSeDON/wojHtT/n1duDCalTK
         JR9/hKGXlkInraRozYN9EiWC80SoDFonKRtCT/1N/nJxm+H+99NJ9/ffgONWetYGr4AZ
         ErzvCr2bYLgL0kwLjSMx0uzI1HAP5knPJoeygvyLEeGl/G4ZJz3PCTOVVwzNcDTDQRBv
         mGkNE+M+psissleT7eN0F0fZTGjqiynD/tnjhSlrr5vzj9LkngDUOJ7ohmnZdsqZvajC
         MQQ/1/LJIWeXr70nzAv9CEX21YO+HoRRUwzdh568z13Np6UbIKdCkfCoy7YaooHR+XSe
         rEGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PTLhm003;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x331.google.com (mail-ot1-x331.google.com. [2607:f8b0:4864:20::331])
        by gmr-mx.google.com with ESMTPS id c4si1121509vkh.1.2021.02.01.09.34.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Feb 2021 09:34:09 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) client-ip=2607:f8b0:4864:20::331;
Received: by mail-ot1-x331.google.com with SMTP id e70so17063219ote.11
        for <kasan-dev@googlegroups.com>; Mon, 01 Feb 2021 09:34:09 -0800 (PST)
X-Received: by 2002:a9d:3bb7:: with SMTP id k52mr13016105otc.251.1612200848825;
 Mon, 01 Feb 2021 09:34:08 -0800 (PST)
MIME-Version: 1.0
References: <20210201160420.2826895-1-elver@google.com> <CALMXkpYaEEv6u1oY3cFSznWsGCeiFRxRJRDS0j+gZxAc8VESZg@mail.gmail.com>
In-Reply-To: <CALMXkpYaEEv6u1oY3cFSznWsGCeiFRxRJRDS0j+gZxAc8VESZg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 1 Feb 2021 18:33:56 +0100
Message-ID: <CANpmjNNbK=99yjoWFOmPGHM8BH7U44v9qAyo6ZbC+Vap58iPPQ@mail.gmail.com>
Subject: Re: [PATCH net-next] net: fix up truesize of cloned skb in skb_prepare_for_shift()
To: Christoph Paasch <christoph.paasch@gmail.com>
Cc: LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	David Miller <davem@davemloft.net>, Jakub Kicinski <kuba@kernel.org>, 
	Jonathan Lemon <jonathan.lemon@gmail.com>, Willem de Bruijn <willemb@google.com>, linmiaohe@huawei.com, 
	gnault@redhat.com, dseok.yi@samsung.com, kyk.segfault@gmail.com, 
	Al Viro <viro@zeniv.linux.org.uk>, netdev <netdev@vger.kernel.org>, 
	Alexander Potapenko <glider@google.com>, 
	syzbot <syzbot+7b99aafdcc2eedea6178@syzkaller.appspotmail.com>, 
	Eric Dumazet <edumazet@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PTLhm003;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as
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

On Mon, 1 Feb 2021 at 17:50, Christoph Paasch
<christoph.paasch@gmail.com> wrote:
> On Mon, Feb 1, 2021 at 8:09 AM Marco Elver <elver@google.com> wrote:
> >
> > Avoid the assumption that ksize(kmalloc(S)) == ksize(kmalloc(S)): when
> > cloning an skb, save and restore truesize after pskb_expand_head(). This
> > can occur if the allocator decides to service an allocation of the same
> > size differently (e.g. use a different size class, or pass the
> > allocation on to KFENCE).
> >
> > Because truesize is used for bookkeeping (such as sk_wmem_queued), a
> > modified truesize of a cloned skb may result in corrupt bookkeeping and
> > relevant warnings (such as in sk_stream_kill_queues()).
> >
> > Link: https://lkml.kernel.org/r/X9JR/J6dMMOy1obu@elver.google.com
> > Reported-by: syzbot+7b99aafdcc2eedea6178@syzkaller.appspotmail.com
> > Suggested-by: Eric Dumazet <edumazet@google.com>
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  net/core/skbuff.c | 14 +++++++++++++-
> >  1 file changed, 13 insertions(+), 1 deletion(-)
> >
> > diff --git a/net/core/skbuff.c b/net/core/skbuff.c
> > index 2af12f7e170c..3787093239f5 100644
> > --- a/net/core/skbuff.c
> > +++ b/net/core/skbuff.c
> > @@ -3289,7 +3289,19 @@ EXPORT_SYMBOL(skb_split);
> >   */
> >  static int skb_prepare_for_shift(struct sk_buff *skb)
> >  {
> > -       return skb_cloned(skb) && pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
> > +       int ret = 0;
> > +
> > +       if (skb_cloned(skb)) {
> > +               /* Save and restore truesize: pskb_expand_head() may reallocate
> > +                * memory where ksize(kmalloc(S)) != ksize(kmalloc(S)), but we
> > +                * cannot change truesize at this point.
> > +                */
> > +               unsigned int save_truesize = skb->truesize;
> > +
> > +               ret = pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
> > +               skb->truesize = save_truesize;
> > +       }
> > +       return ret;
>
> just a few days ago we found out that this also fixes a syzkaller
> issue on MPTCP (https://github.com/multipath-tcp/mptcp_net-next/issues/136).
> I confirmed that this patch fixes the issue for us as well:
>
> Tested-by: Christoph Paasch <christoph.paasch@gmail.com>

That's interesting, because according to your config you did not have
KFENCE enabled. Although it's hard to say what exactly caused the
truesize mismatch in your case, because it clearly can't be KFENCE
that caused ksize(kmalloc(S))!=ksize(kmalloc(S)) for you.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNbK%3D99yjoWFOmPGHM8BH7U44v9qAyo6ZbC%2BVap58iPPQ%40mail.gmail.com.
