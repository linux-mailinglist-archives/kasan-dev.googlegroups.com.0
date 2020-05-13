Return-Path: <kasan-dev+bncBDGPTM5BQUDRBTND5X2QKGQEQAYBW3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 693951D0482
	for <lists+kasan-dev@lfdr.de>; Wed, 13 May 2020 03:47:59 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id 18sf11628149pll.3
        for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 18:47:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589334478; cv=pass;
        d=google.com; s=arc-20160816;
        b=iqsGWYSl6vsSMpuzxdx/V05/z8OlsKj1rwGfNjUK1TAHeoZR35I/5FJcEsGJ2EETRS
         cnNUyAm1k3oiOl425zN4R8VrXlDievePQYrJ0eGGdKsSNo3/PL+Y3wC3nKT8SxAgBKW0
         gDk+rJFaK+tWo1n072832b44kWd6dBSeq1jXnO66DZybnx9YUNEwHSwl0fwPYm0DBcHB
         AmgaF2foNehAqgMbAaEw2ivE1VJ9Ttuz4W0wxAqXju65ZvShUGvp+xIUjfEcu2iUVpoD
         HzKa88fm3By/o4f6MofFJtJQdHjjqmcpkyCflx5JnUxoU442Q1Xn4qrdpqULsHj8V2H5
         lFWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=i4yFThqBm70VphgC/9CIT9+jG0mcuo8QN+54C3aa+tw=;
        b=odJwy+bR3cTn1LFOapA/WaRdL7jxTKKnvnYMTjOE4mjmlThEfF5ytpxuKEvSQL6Vda
         QFGqdDtaAAB5RBVN5mDgqzFCcMvakiAMFuzHPIqXfGCY1xHIDcKDU+xm/b+g2wthEHjR
         wz4bNCzeE/+19TPqcbGhCEa436PpwBap3xh0LmQfMA8yEuOv8ukyP1iXFfuvG35l83fA
         iwg740pLlooLR0pqGGXEB2DbSfL/SDbjvB3jRdcy8YWGJL6CWApWQ5n4jCZbcMxz10zR
         mn/oXD8IxbbHd4EDO3uFLlPdBhD/M74D27v3Q5WVIZMQwwTFS+V6AtxxgjDHvZeGvgeA
         H65Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=DU2MZ9ww;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i4yFThqBm70VphgC/9CIT9+jG0mcuo8QN+54C3aa+tw=;
        b=sjZm/toZ7DH5z8dOAUsya6Yl5FXLeQai4eXTEe1WNNyxd3NCkOWmKCWSq8p3b7p43s
         c8z1009TNlQzigNvk9GC7+L5umFqJTI2TT4N6JRrVqmWV/0+Pfrw6khcJopmTRxYHerQ
         O1Fubswtl5ur5FeD0WLRl4xZW2FtYBWEYcOEWZjg5+Hbl8+J95S7um0aNLrL20FZHOUi
         ebNmtWSKm0JbDHma3q6cbG8w7zKohJt6Ufn/PWeRFYd89ltdxF1olbjp1LIeTYxvxOpQ
         gpZPz5s6Y2U+Kq6NeO23X/jinhqjCj4tHlzdHseCsZjfOktVYKWT2WHRByJWOtKx/L9L
         htXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i4yFThqBm70VphgC/9CIT9+jG0mcuo8QN+54C3aa+tw=;
        b=ipoF+mvqqPLsCy1e/q5ZMI+YDLndyVBF5siH/sdyfhfcFtx6Jj7U2hF+wir9d1tK9N
         5QEQlewfoBi3j9fMulQBznmDp3DzYGmiwUyC5w8iqytw22fPOetVeMNBI9Jwn//5IMkj
         dXuUPieYXHrmHHNrHUQRcqV4Hug+GP0tE7I1oEp+lsicu5u9F5GTmRf43HKoTJ77iMPK
         OEzTlrYgC6DZuNcd9v58Qax9Qnw4bbrm1a+6ddNNIhr3kGvVUGcKWxrFqnmEh3Nbpwwl
         /fTum4HBP/4LmUONwupYxFpXQL/QOuvdg6zhx3eyBmIMdn0KcRspm1b7uQnawcfDM6Cx
         JfhQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuY9TMgnvNbbon5soTIhwLBsytN8BU+JY1vmD8Mu/TFNGP6q8V/9
	DDNf3BcachIi5CRqN2HgQr8=
X-Google-Smtp-Source: APiQypL9YeCcTpvbXxjwqcj8AqJ3C9Wg7WZfrsTCsd3/+03OasaOL3UGszzWsAicNZMNyxGLxkZ+5Q==
X-Received: by 2002:a17:902:9049:: with SMTP id w9mr22911354plz.27.1589334478006;
        Tue, 12 May 2020 18:47:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e283:: with SMTP id d3ls188960pjz.2.gmail; Tue, 12
 May 2020 18:47:57 -0700 (PDT)
X-Received: by 2002:a17:90a:bc90:: with SMTP id x16mr7044635pjr.78.1589334477594;
        Tue, 12 May 2020 18:47:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589334477; cv=none;
        d=google.com; s=arc-20160816;
        b=RURVLHdkf2aXiIyWaXymfz7i8Z9jHXQJcaeAeO5Fgjmwn7BpcMwTGGXHfWj8JPOPWm
         cCIVwB0mOX4s3I+Qw6bh007KR7G+QwmU9/7+UmSRIsnKmtTuTWQKzUa9tjKnAPb8rgVg
         3x2/KZQBpVvX7jFfGWu4u347jOECALKJO2Q5emK3XiRTtIyUndw3TetEYQrUr7VCFzja
         xelFQ9xK42Gwn2CZ1xcjjZTKIuVNN5YBmcCNBA9TWNUSNcgGUQoS5oyJqkHGApiA96Ik
         kcAVVP+oHVvP4roZUwoyUBGZAjG0DltjBD5W81PKuLW2cg6UQd9WU5kSieG/ho72r0wG
         K/Bw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=o7JP9AdWJu6YlfE0C1p8Mhx9/TUpPDMGmCuMKKblwlg=;
        b=HQEfYq9UMS9W56cODuBBFFjZyXwkOyieubJBBoKbpogkb21SJ5mzG/LEBBNrGF5V9U
         665n8QkXdng7FvNtOYJUnE1z312Fj4Z4zBtUM5slytT+m1xXEaqLKuxmu0A+GPRGkL8Q
         Uvw1qgFMgEbS7sWLzFgm+0E+i8oR7Xyf3jn+YIyC+L4nQjiXVaP6wq5ld/Y5ld1Msd7h
         AJEmeoM7eL0+D48Mt8sCc7Asoan4hHKjYKuFNXI9HjX2yXU6lZLqBz5sdLYzWqYG/bYZ
         T7Xh6i1y4ffvB45wdK4/lmX01soz50FxVZ5Yl+/RKVr0LO4d8xWccvsZ4bsu2iNuMqTA
         FwmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=DU2MZ9ww;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id e6si305626pgr.1.2020.05.12.18.47.57
        for <kasan-dev@googlegroups.com>;
        Tue, 12 May 2020 18:47:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: d39001488b2a45ac8a5bd4504e47d692-20200513
X-UUID: d39001488b2a45ac8a5bd4504e47d692-20200513
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 2033237458; Wed, 13 May 2020 09:47:53 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 13 May 2020 09:47:52 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 13 May 2020 09:47:52 +0800
Message-ID: <1589334472.19238.44.camel@mtksdccf07>
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
Date: Wed, 13 May 2020 09:47:52 +0800
In-Reply-To: <CACT4Y+aibZEBR-3bos3ox5Tuu48TnHC20mDDN0AkWeRUKrT0aw@mail.gmail.com>
References: <20200511023111.15310-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+YWNwTSoheJhc3nMdQi9m719F3PzpGo3TfRY3zAg9EwuQ@mail.gmail.com>
	 <CACT4Y+bO1Zg_jgFHbOWgp7fLAADOQ_-AZmjEHz0WG7=oyOt4Gg@mail.gmail.com>
	 <1589203771.21284.22.camel@mtksdccf07>
	 <CACT4Y+aOkuH6Dn+L+wv1qVOLgXyCY_Ck4hecAMw3DgyBgC9qHw@mail.gmail.com>
	 <1589254720.19238.36.camel@mtksdccf07>
	 <CACT4Y+aibZEBR-3bos3ox5Tuu48TnHC20mDDN0AkWeRUKrT0aw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=DU2MZ9ww;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
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

On Tue, 2020-05-12 at 16:03 +0200, Dmitry Vyukov wrote:
> On Tue, May 12, 2020 at 5:38 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > Are you sure it will increase object size?
> > > I think we overlap kasan_free_meta with the object as well. The only
> > > case we don't overlap kasan_free_meta with the object are
> > > SLAB_TYPESAFE_BY_RCU || cache->ctor. But these are rare and it should
> > > only affect small objects with small redzones.
> > > And I think now we simply have a bug for these objects, we check
> > > KASAN_KMALLOC_FREE and then assume object contains free stack, but for
> > > objects with ctor, they still contain live object data, we don't store
> > > free stack in them.
> > > Such objects can be both free and still contain user data.
> > >
> >
> > Overlay kasan_free_meta. I see. but overlay it only when the object was
> > freed. kasan_free_meta will be used until free object.
> > 1). When put object into quarantine, it need kasan_free_meta.
> > 2). When the object exit from quarantine, it need kasan_free_meta
> >
> > If we choose to overlay kasan_free_meta, then the free stack will be
> > stored very late. It may has no free stack in report.
> 
> Sorry, I don't understand what you mean.
> 
> Why will it be stored too late?
> In __kasan_slab_free() putting into quarantine and recording free
> stack are literally adjacent lines of code:
> 
> static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>       unsigned long ip, bool quarantine)
> {
>     ...
>     kasan_set_free_info(cache, object, tag);
>     quarantine_put(get_free_info(cache, object), cache);
> 
> 
> Just to make sure, what I meant is that we add free_track to kasan_free_meta:
> 
> struct kasan_free_meta {
>     struct qlist_node quarantine_link;
> +  struct kasan_track free_track;
> };
> 

When I see above struct kasan_free_meta, I know why you don't understand
my meaning, because I thought you were going to overlay the
quarantine_link by free_track, but it seems like to add free_track to
kasan_free_meta. Does it enlarge meta-data size?

> And I think its life-time and everything should be exactly what we need.
> 
> Also it should help to fix the problem with ctors: kasan_free_meta is
> already allocated on the side for such objects, and that's exactly
> what we need for objects with ctor's.

I see.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1589334472.19238.44.camel%40mtksdccf07.
