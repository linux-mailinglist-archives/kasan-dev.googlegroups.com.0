Return-Path: <kasan-dev+bncBDW2JDUY5AORB2FT46FAMGQE5TVU42A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id B9A694202AA
	for <lists+kasan-dev@lfdr.de>; Sun,  3 Oct 2021 18:27:22 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id o4-20020a17090a5b0400b0019f76ac2577sf4027330pji.9
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Oct 2021 09:27:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633278441; cv=pass;
        d=google.com; s=arc-20160816;
        b=DHP+RFRaYHs0W1dLdqO+1crgw5j5y0IlRl79o0OShULJCGxYZ/Sy1dSdewXSJt4gkI
         bd51uelgBAOwRUf0Ik87bAwxQ8z/kkYz0fGmM39hI2Puoa1zmsj0xgk91Gi1qWiiVRoi
         R14jcFI/RtEXEVq5+I117OPlVo+J4GJ/loxxjkn6vBMn5FkcwUu6uu7JLB258RjqjdbA
         /SYcX+1/Q5aGlO0QL+5ZMGjETmrcKnLIf8F641eMWjYaKumLBOd3MQiTbFYYpV7sXsWe
         e463IQfSt/GqrtxXWrz5vKrHlBqEMEsa7kWYXM98+i8ZVe7w7ACUZ/30YguazIsBX61j
         c8RA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=l+XC5g7f7sus1gOCo+qcfo/ST6S1vKBJYlY4y/Hlv14=;
        b=f7wJyrQsKZt5kodIc4l/Ql6DtGRXceBGDuRfuGy31ym1gAz7uG4AJodJua+hbeZNl4
         tovwA+S3fK6zNLe94hKafuiTXBhqjrsHMohPuYkpmR1VA0Np2ZTH3Z/kqHsPNfqTeEXZ
         Rgxoz7f4X53Ki1zQrkvg46DxnKl+28fKrSdQ616dpE+OMDHOLa0im9aby+CLMejquRH+
         lnNXoQb/11U6x/6bRvf1XJaYnS50/V0VopB6iOupA0FcgLVL2ExXux4otei5XfWNp+v8
         4b1OYwux8vN206TfjxJ85lF3pf8vY5hEkxmspWaTwwmASOqdOMyhAGGJotPJb25qMc7/
         8C2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=WV0sN6Ck;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l+XC5g7f7sus1gOCo+qcfo/ST6S1vKBJYlY4y/Hlv14=;
        b=ly8IKEQILCCDpxjkAYY89I2BHkpjXYGwogVwL0o0g8/OumCtNicsH5ib6slNcFeGkq
         sSfmyQH8OnX+B8BSVjAjXjncrAk/Tw3ubIRRBOYvvG0yatzXTXJd46pam3v78HZuX1zV
         EsU+7JwrLGpe7ZIw4Eg9D99t+l/rqPzs3HtBkdfeqPoTgiDw8koxCEozOvZId47w4ZDh
         nr0uLDC+574fhXkATJDtm1n/ND2OjWYzDhjxwPiyMr4ciy4ml1GZL3kdLFXMVzysAtu5
         HeNa/wAtNxoyXpucHlGF8VNZXgMQOr6phihIe9RVq/PDYN8BMf4trAhC9rGWzcsHziBD
         bgog==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l+XC5g7f7sus1gOCo+qcfo/ST6S1vKBJYlY4y/Hlv14=;
        b=KlN2lPLDgjDvCJr4okXZnNJWPvsw63JEF7M62GEocjBNJlHqxiYao81E8WegNPtMzD
         ps0gW5zpXFAz2Kr0IhWBZkk9Wn1zaZQc5tJ2S2i+c8kVyKKJIc2Z6e3UeBG3WyyySrzz
         Sf5HrB9J4ythErNNcgprKlPDAw+bX6P24pUsnoCLddX+VFMceV63mLqrpEuOLbWJ2bvK
         7D0JlCRr+KVjriamtegk/4Fvn3QTNbrJfhxM+Z4KjrHDXAJB1w+QLcFGK/0sRbn1o+hf
         Z1jeAyXric9UmpO2+OZCSSiA8nrBoe83F7VrNZrJnjC0YtTPUyIxefaUwr09HVt5op3A
         QPLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l+XC5g7f7sus1gOCo+qcfo/ST6S1vKBJYlY4y/Hlv14=;
        b=MIjVpTdJcTxeHBqP9HciKfyNh+g7/BM9f2D3yuwZseOgsj1cbR61sBTiBHJ88bVuXe
         RP4P/D7uORryTyIBKNp29d5dXw//ry3+gatoq00FGOTxVnYo1k6d7WtP5qmAkt20QYhU
         Cl5rSjukuY/hdVXwKqu+syXq1sgoYfU+tQ5riS2gvLo1QEyN4FTrhj6s59CrAe3hVut/
         LarwGcW8ThxIvVvD23AFPPGj5qYKtK5tqcOeW21RtoSB0ZK8hCqAwWgJ8CSLogPbhCJF
         ncfcBEdw/tLQGfUEpahoMz+jx11lIMvdbgA4rruVYy+N2RPJfwEX5FQ4CJ8MHR5mWDGG
         sDgA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532wMJctnk9ootmL5vW9LewNGltpOEtyP9TsO4X0+FiwPsHa2Enf
	w+sjdestyhMjYbaafjq5ai4=
X-Google-Smtp-Source: ABdhPJydTlvGO697gK/oeWc/1w53DFdL/7p5GJyE6p8Y0WKgfMil07aLWlUi89siZ7f2zd53DE2WdA==
X-Received: by 2002:a17:90b:248d:: with SMTP id nt13mr15453422pjb.239.1633278440983;
        Sun, 03 Oct 2021 09:27:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e398:: with SMTP id b24ls4572118pjz.2.gmail; Sun, 03
 Oct 2021 09:27:20 -0700 (PDT)
X-Received: by 2002:a17:902:7e4b:b0:13d:b90d:cdc1 with SMTP id a11-20020a1709027e4b00b0013db90dcdc1mr19633130pln.72.1633278440457;
        Sun, 03 Oct 2021 09:27:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633278440; cv=none;
        d=google.com; s=arc-20160816;
        b=K+zexqF5A9vwpNBFHBaJZA/U9/LjD12D4k3RHYoqlYSKLPjgwPmFDhzrh7WBsd+DX2
         tvRPvTFXaR/AzTklnT7hUrLe9pRgom+KVRnX85cWnUbzFXrUd6Q28lK8RCkzVqQ0MBsD
         M9ehAULpCcaq1ZzHomZQnVoI2aXTPII55B4tMlKclumjptUDkxol2YUcwpd1i6pANF88
         ulGDvWWzsmGCDPluM98AW4rE//5yaY3SbqHZC5P/uPSl+4qiSeA+2znW7dVrvcEYJtUw
         QmhvhBxeV42xczHsG6VR2/vj6Blni4tpaivCDryD1tPKp3FXAOuKVmSxqsausU7RsKDf
         E4HA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gGz/7798TEe0PuD2hstTWSueeSofOrfEOZMUAoLV9NI=;
        b=HVPZGT5oZlorpIyO0WMgVp2e0HhqCqFC50OIBnqIrAtfbUX44asOVOFGnUp0OZv4gs
         dwhQnUBGxzq7dBeUDt8LXjuJ8hBVmwLXKLL+wzz2iHZxKFFs4KPRUwp+lddO/dbRLJRH
         TzFdY5O220xCTACZao70k1xyGKoWRg9A+d4nIzATns+5SP07REVmJZxr8D/irF7uUPMF
         Kfvhnq5y6q6v00JB1Loziqjy8PgxapeHCGsBGvYJ6Rr5czeu0HYrra+GKwnM+AR+Qsdd
         sjjBKkobD8bb3Zb2wuBcJ7EjITAX0rtqMGjvmM0lj4l5k57reOhdi+TekGh6sbCaHtk2
         BYkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=WV0sN6Ck;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2d.google.com (mail-io1-xd2d.google.com. [2607:f8b0:4864:20::d2d])
        by gmr-mx.google.com with ESMTPS id r7si666555pjp.0.2021.10.03.09.27.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 03 Oct 2021 09:27:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) client-ip=2607:f8b0:4864:20::d2d;
Received: by mail-io1-xd2d.google.com with SMTP id q205so17527369iod.8
        for <kasan-dev@googlegroups.com>; Sun, 03 Oct 2021 09:27:20 -0700 (PDT)
X-Received: by 2002:a02:7b01:: with SMTP id q1mr7320811jac.121.1633278439943;
 Sun, 03 Oct 2021 09:27:19 -0700 (PDT)
MIME-Version: 1.0
References: <20211001024105.3217339-1-willy@infradead.org> <CA+fCnZfSUxToYKUfHwQT0r3bC9NYZNc2iC3PXv+GciuW0Fm79A@mail.gmail.com>
 <YVcVtNLnyJModOhn@casper.infradead.org>
In-Reply-To: <YVcVtNLnyJModOhn@casper.infradead.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 3 Oct 2021 18:27:09 +0200
Message-ID: <CA+fCnZd7dGOz2T3eVwbJzAEmXMB7YezB5FoZt5a0D92mPPv74g@mail.gmail.com>
Subject: Re: [PATCH] kasan: Fix tag for large allocations when using CONFIG_SLAB
To: Matthew Wilcox <willy@infradead.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=WV0sN6Ck;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Oct 1, 2021 at 4:06 PM Matthew Wilcox <willy@infradead.org> wrote:
>
> On Fri, Oct 01, 2021 at 03:29:29PM +0200, Andrey Konovalov wrote:
> > On Fri, Oct 1, 2021 at 4:42 AM Matthew Wilcox (Oracle)
> > <willy@infradead.org> wrote:
> > >
> > > If an object is allocated on a tail page of a multi-page slab, kasan
> > > will get the wrong tagbecause page->s_mem is NULL for tail pages.
> >
> > Interesting. Is this a known property of tail pages? Why does this
> > happen? I failed to find this exception in the code.
>
> Yes, it's a known property of tail pages.  kmem_getpages() calls
> __alloc_pages_node() which returns a pointer to the head page.
> All the tail pages are initialised to point to the head page.
> Then in alloc_slabmgmt(), we set ->s_mem of the head page, but
> we never set ->s_mem of the tail pages.  Instead, we rely on
> people always passing in the head page.  I have a patch in the works
> to change the type from struct page to struct slab so you can't
> make this mistake.  That was how I noticed this problem.

Ah, so it's not "the tail page", it's "a tail page". Meaning any page
but the head page. Got it.

> > The tag value won't really be "wrong", just unexpected. But if s_mem
> > is indeed NULL for tail pages, your fix makes sense.
> >
> > > I'm not quite sure what the user-visible effect of this might be.
> >
> > Everything should work, as long as tag values are assigned
> > consistently based on the object address.
>
> OK, maybe this doesn't need to be backported then?  Actually, why
> subtract s_mem in the first place?  Can we just avoid that for all
> tag calculations?

We could avoid it. To me, it seems cleaner to assign tags based on the
object index rather than on the absolute address. But either way
should work.

There's no security nor stability impact from this issue, so probably
not so much incentive to backport. But the patch makes sense.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZd7dGOz2T3eVwbJzAEmXMB7YezB5FoZt5a0D92mPPv74g%40mail.gmail.com.
