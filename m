Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBE4522GQMGQECTTKW6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id C9CD64718D2
	for <lists+kasan-dev@lfdr.de>; Sun, 12 Dec 2021 06:54:29 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id q82-20020a627555000000b004a4f8cadb6fsf8506960pfc.20
        for <lists+kasan-dev@lfdr.de>; Sat, 11 Dec 2021 21:54:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639288468; cv=pass;
        d=google.com; s=arc-20160816;
        b=j9u1sYmMXRX8yOQHrz99DjPF4QnGxo+CVSjJ1atI0cW3zOnD/2T6kM5s5t1klMo/0G
         ekr+u80T35iBBQpbWofgHHCMGEbAbADBb2NAN/iaPX6fW59sGFLG7iu1KWC473lWt0ro
         mrXsdAc8dbS/YiayJQ2zQQltLEgFvNSUimJVF7wLsUHMc+xzlJK5npRUI0n8gqmvBcA1
         gbJVMwS9EvEuawDqRdtWwZV2GfiekYNvVjloen5XQPcDKt7IZOGy/q8cbJs+WcjiBBX8
         lvyoV2uA0CMGtEXSUt/T/hvf7R79Bhzot4nNEd82q+nTZxkTtRlBpCy3WzzZLAMvWONS
         PPQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=qaq55FoyETSTAusI0RaY3MV0HafyfWEqPJ8pRXoAghU=;
        b=L2xBDz1xdsb3FrNNYXQZXBx4Qe6CCYSoD2Ydn+Ql6g+uaxy6xbOa23ZphrkhmrdQLa
         YtgQjHVi1sfEsLN8P7aFrlBWeCbCyqfI3D20IlLbxUnXmq8bti0qpL/sypgTQujFVtcX
         FnbEiR3yiIiX8cA7aRkHkKELV5sqOoaHKAbnVCL21BD1cmuxYefuHl8fvrutQTgiPhn6
         bAEC9dBjiAeTDcF7Rt8uqNtSmm9mpKhn6cYGaz6EZWbraFIwKArc6imGsSNX5q5l2f1G
         RCjI9ZBTK539LpTKCWzEjWGunB8bQUjrFwyA8oeD428LQjJMEZRxZl4KPus5c+dVA//F
         2AMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=o37rdZ0G;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qaq55FoyETSTAusI0RaY3MV0HafyfWEqPJ8pRXoAghU=;
        b=QkLpgYcLc2hA04TKHH1mpSgBz3dr6s5ueceYp1TzNq9Rhap2CBgmabaNJUxoyK7SgB
         aV3qs8NgzAv4JwTSxUPNQTo1XFjXUBL3KJ97hrykVN2D6hFaax1Wvk4j/T8Ts9OYxPNZ
         z1gpganjrUw8q7LIdfACfsne1tfoOPh9OyvfRSXs6KF57K+DUYZR/Apf0Ve3dTeMGwYC
         s9cp7MN7yZ14WEaxZhsFlg1vD0ndNA4IOZkZa2c8LrghUkGb3CqmbrTygkIMi74DniCu
         bCMgIm6EAEzP5tfMjmv97eLzRpjBvS60Mc2sj4tXZmvu3BO6sZDOlGrcetPGhAK630f6
         G5zQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qaq55FoyETSTAusI0RaY3MV0HafyfWEqPJ8pRXoAghU=;
        b=kkbVinFzfFvq91wWTg9Yr+qdoglgZ9UxkRjCXn2o4ZIX/aCeaWDeFmZGH4lTwHHR68
         xs/lv5anaTqosuLVMG86VGfI2VCD4w5mnevTBespg5l6HXiS4msw5ALS6m+IFYq3ieua
         iTU/8+2U7CdtzpLobm7LPXOeQlnJc1GNpgwjPva5PdDJjxFKU0EdI/L8ubu5kc/S6wli
         LFfqoc4lJe/0Q7/Og26JtGIcGNQRiDjQWwkEQDFm+h3We4RXAkHzLHNmYppx7cMBPdz2
         qtQLwPoW/AuHMUx4xWvN5F+/7w+ylx2k4rygZ0IBPuYU4f/MeFHCoBGd7GZ2k5qV/K29
         yihg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qaq55FoyETSTAusI0RaY3MV0HafyfWEqPJ8pRXoAghU=;
        b=EmT1c4HKXvDo2xb/oK8D+vsWeeSZtY4kQr8LWofxdWH5jC/Hm20vTnU6Amp1wy7SMu
         Q+y75lPHzcaDblvCJXMPCP93b3Y9tDUuKwrY3eyflsykdiiWiPvP5RApS7J7sqiHAp5Q
         7qLIUnkApzZqv/E5hc77aQRhfzmN9MgfbA5aIZzIq8O0+OJkrF4tbN211f+2PClnc+pu
         urM0FlnzTZrYuWRfEqeU2J/QQxp4d1Q4Aa+1DEe+tTbE0KCbB7wlebG7rRCHMqphbpmn
         SjV7MloPmgH17NaCo6VfVfh8SkqKV8zPk5UHK8MZl4/WDoP4udhXVP0jbzla8c0YVhTP
         YVAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530dMLkokLcvDuR2mWFqtTNMbDFN7tJ8+svoPHvkN5EtHCoi8tIh
	qYB5m6/RlzNPkbiYX2+MCZs=
X-Google-Smtp-Source: ABdhPJwJyHjCQSGy3XS5vCT13eTPRAQ8+1SA2evDjNCX0H09JCfj9X3nuzagOLlW5aGDqsQbogXGig==
X-Received: by 2002:a17:903:110c:b0:143:9edf:4985 with SMTP id n12-20020a170903110c00b001439edf4985mr83705789plh.15.1639288467850;
        Sat, 11 Dec 2021 21:54:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:491a:: with SMTP id w26ls3703672pga.10.gmail; Sat, 11
 Dec 2021 21:54:27 -0800 (PST)
X-Received: by 2002:a05:6a00:a14:b0:4a0:945:16fa with SMTP id p20-20020a056a000a1400b004a0094516famr26480129pfh.9.1639288467148;
        Sat, 11 Dec 2021 21:54:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639288467; cv=none;
        d=google.com; s=arc-20160816;
        b=Wct2xQWwlgeOobab4JLpCffxjW9GIku9oIrgKZXaSEsoza+AATFVrg4wdVJSgNdIsS
         v1uax4BXAFgJQm7VXaj86fUJSYX/yScmgLvLB9SEs0cY6Y4w9LwFNLAiEWOeJQF2qDHi
         Nlmitko8U9CHt9YPx0TTd/Z4hJlb3Q6H7+IOBuD1hDS5tqwUjtRM1K+hXOCUMccg4OIe
         fe8Ws8hZ17wJeQ35U6qqZ7bDw6BTMf21LEGEJUBLFHyR/eVUy71cTOma5wDHE1hIL4rS
         c3w2zbRPvKN6LuuGtSGPbmnOJz7WbY4Q5ITGTO76ZOxXU1xtnfh62F8qUAEp9Ftl49Rl
         93ZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ENK+0yKya7IQicbCDEeQU/Qo9FMF4UqG6i5xVlrxVaY=;
        b=0WU/Wy/uHgXCHMKMSNHzeA0+srLb5KduV0fvb+4l9Zz4qazjSwVeAdFQFAMcx5lDcg
         J3/UQHMuOnQ2uxYUdw1XmYcFq7tLj9yhTBSD2GrRivnPrmW2EAj8ywxKsRMkjY2dI157
         cJvJSV2Pa744vatDtx1j4o9pn6uPRKSPYgIl8WUL90AiLvNobjrl733cbWx0GCGhraXS
         S6SU0/e/hJlDjdSp0RYPJkaBWaZT3xht96FZ3WkMM73vMlEqTOGXPZx5Lr+PhUd1GS5M
         agkxo35J28lo1hzM+mI0wmCAb8lmWGBci+PPcnfL8YPp2MzysH3Zcm+Le4qNsngp0+DX
         bC2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=o37rdZ0G;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102c.google.com (mail-pj1-x102c.google.com. [2607:f8b0:4864:20::102c])
        by gmr-mx.google.com with ESMTPS id p17si375766plo.5.2021.12.11.21.54.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 11 Dec 2021 21:54:27 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::102c as permitted sender) client-ip=2607:f8b0:4864:20::102c;
Received: by mail-pj1-x102c.google.com with SMTP id j6-20020a17090a588600b001a78a5ce46aso12387364pji.0
        for <kasan-dev@googlegroups.com>; Sat, 11 Dec 2021 21:54:27 -0800 (PST)
X-Received: by 2002:a17:90b:4b4c:: with SMTP id mi12mr35546234pjb.66.1639288466879;
        Sat, 11 Dec 2021 21:54:26 -0800 (PST)
Received: from odroid ([114.29.23.242])
        by smtp.gmail.com with ESMTPSA id x37sm8530902pfh.116.2021.12.11.21.54.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 11 Dec 2021 21:54:26 -0800 (PST)
Date: Sun, 12 Dec 2021 05:54:20 +0000
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Matthew Wilcox <willy@infradead.org>
Cc: Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>, linux-mm@kvack.org,
	Andrew Morton <akpm@linux-foundation.org>, patches@lists.linux.dev,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 31/33] mm/sl*b: Differentiate struct slab fields by
 sl*b implementations
Message-ID: <20211212055420.GA882557@odroid>
References: <20211201181510.18784-1-vbabka@suse.cz>
 <20211201181510.18784-32-vbabka@suse.cz>
 <20211210163757.GA717823@odroid>
 <f3f02e1e-88b2-a188-1679-9c6256d19c7a@suse.cz>
 <20211211115527.GA822127@odroid>
 <YbTXXwVy/a+/9PCn@casper.infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YbTXXwVy/a+/9PCn@casper.infradead.org>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=o37rdZ0G;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::102c
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
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

On Sat, Dec 11, 2021 at 04:52:47PM +0000, Matthew Wilcox wrote:
> On Sat, Dec 11, 2021 at 11:55:27AM +0000, Hyeonggon Yoo wrote:
> > On Fri, Dec 10, 2021 at 07:26:11PM +0100, Vlastimil Babka wrote:
> > > On 12/10/21 17:37, Hyeonggon Yoo wrote:
> > > > On Wed, Dec 01, 2021 at 07:15:08PM +0100, Vlastimil Babka wrote:
> > > >> With a struct slab definition separate from struct page, we can go further and
> > > >> define only fields that the chosen sl*b implementation uses. This means
> > > >> everything between __page_flags and __page_refcount placeholders now depends on
> > > >> the chosen CONFIG_SL*B.
> > > > 
> > > > When I read this patch series first, I thought struct slab is allocated
> > > > separately from struct page.
> > > > 
> > > > But after reading it again, It uses same allocated space of struct page.
> > > 
> > > Yes. Allocating it elsewhere is something that can be discussed later. It's
> > > not a simple clear win - more memory used, more overhead, complicated code...
> > >
> > 
> > Right. That is a something that can be discussed,
> > But I don't think there will be much win.
> 
> Oh no, there's a substantial win.  If we can reduce struct page to a
> single pointer, that shrinks it from 64 bytes/4k to 8 bytes/4k.  Set
> against that, you have to allocate the struct folio / struct slab / ...
> but then it's one _per allocation_ rather than one per page.  So for
> an order-2 allocation, it takes 32 bytes + 64 bytes (= 96 bytes)
> rather than 4*64 = 256 bytes.  It's an even bigger win for larger
> allocations, and it lets us grow the memory descriptors independently
> of each other.

Oh I thought there won't be much win because I thought it was
just allocating additional memory for struct slab and still allocating
memory for struct page as we do now.

It will be more efficient if we can allocate descriptor of slab/page/...etc
per *allocation*, which may have order > 1. And currently we're
duplicating memory descriptor (struct page) even on high order
allocation.

Even if we do not allocate high order page at all, it's
still efficient if we can reduce struct page into double word.
And we can allocate something like struct slab only when we need it. 

One challenge here is that we should allocate the descriptors
dynamically... I'm going to read the link you sent.

> Everything currently using struct page needs to
> be converted to use another type, and that's just the pre-requisite
> step.
> 

Oh, you're planning to separate *everything* from
struct page, not only struct slab!

So your intention of this patch series is preparing for
physical separation. It's fascinating...

> But it's also a substantial amount of work, so don't expect us to get
> there any time soon.

Yeah, that will require much work. But I'll wait for your good work.
It's so interesting.

> Some more thoughts on this here:
> https://lore.kernel.org/linux-mm/YXcLqcFhDq3uUwIj@casper.infradead.org/
> 

Thank you for the link.

> > > Yeah. Also whatever aliases with compound_head must not have bit zero set as
> > > that means a tail page.
> > > 
> > 
> > Oh I was missing that. Thank you.
> > 
> > Hmm then in struct slab, page->compound_head and slab->list_head (or
> > slab->rcu_head) has same offset. And list_head / rcu_head both store pointers.
> > 
> > then it has a alignment requirement. (address saved in list_head/rcu_head
> > should be multiple of 2)
> > 
> > Anyway, it was required long time before this patch,
> > so it is not a problem for this patch.
> 
> Yes, that's why there's an assert that the list_heads all line up.  This
> requirement will go away if we do get separately allocated memory
> descriptors (because that bottom bit is no longer PageTail).

Yeah, we don't need to care that if we separately allocate memory for
struct slab.

Thanks,
Hyeonggon.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211212055420.GA882557%40odroid.
