Return-Path: <kasan-dev+bncBAABB4MKR6UAMGQETAXSM5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id D614C7A13EE
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Sep 2023 04:46:10 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id 3f1490d57ef6-d817775453dsf1876210276.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Sep 2023 19:46:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694745969; cv=pass;
        d=google.com; s=arc-20160816;
        b=DvAXSkZ1apW8oiTGRr7PJfpZU9aPs3edAEzItR9eQoGQw+px1oNtM9viGVVYzjxJa3
         cqzrSWsEnMfFciQ3Hj1NlXbGkNuTT8jRY+KpNRLMypiSIJ3hqHq6QCy076B4ip5hfowm
         0q7YmbdgdesGuFGTgjRrBWpcmnHqZUzNNBEGAtEnelnCbOrZ0sfDA+27VE6m/rxGdSf1
         A+P8F/HO2sv+Zl09P/sw4rldNUDw87j1TQnvyYMxNrCeTCM6KpHr+K3ZwvEbsVXyj4uv
         wMPu9UfIx74mHd/JF8gLlqSFD2x8sygJvMoxNaUC/gRBvONTfA8GYQwxho4/hcU0TLeo
         jNlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:dkim-signature;
        bh=2R2mfutmaepcNz4ycLCVmSxH2VWV/bOzX1tVkuLdQqo=;
        fh=xnjHze2hhizWMWL+c23S4hdacx+DEnw7TyPmO82Bvos=;
        b=MV/E9ZWvKauC9n6mGXk9OKGRBkP2q2ORrRAIOiJtTKTRpCyJQ2F0urlp+uq1FrMA8/
         qUArRnlv8H38FV7KfRjYCGdLXbOQmHMUxpInS6K+TEyUCBoT2Kdh/8QDzH2VqQjLSrqc
         8FNfq9wxxwyARzzII2JvLiqTb6WuBXuEr8fqc0QwU+3YYA1p1cZjEuwX+5xu5sePwF8N
         kTL3XodaWo81af7iQWpRzeoIYfCYJ+FBPfmz9XCn1vUhEZHZUnFAR3pkx5YDAjxUDcQ1
         kEA2zim+ayjwZefTyQq7jswwDm0lpp4LCHrWa8wF1mfajgVssesLcJyEwztdroKZk7cE
         eiQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=LGetPjaM;
       spf=pass (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=haibo.li@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694745969; x=1695350769; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2R2mfutmaepcNz4ycLCVmSxH2VWV/bOzX1tVkuLdQqo=;
        b=XFq6oX1aEKZc+EcvXEqW8j2sRJyMm4zlI0dfQXQKa82cheMxkO/rDZyf7n/Lp2xyue
         1F/cQ12O/9VZQuh02JPNu9ATl3w+BbYt29vPdnk8uqs3CZ/Wt61dz8GQNp5C/yTYqrFP
         f290kr47Smj6L7vnaTliAyF7NCuUPLfA1ZAe/7Pd6my6zKYV2stBLxLaWLmfdEx+kY5d
         dteIjDew8hx/0KJiFkjq/A6HSYrsPk6uvKYNu+rJes1qZGKoZTph7bWFnh2KmCIpzlP3
         79bK8iOuob1gXdSlxRUYAyMjo4GuKXO85rMuwPYi7Zx+A+IPCTa5wDUP5xM8XVklBxHA
         9EFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694745969; x=1695350769;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2R2mfutmaepcNz4ycLCVmSxH2VWV/bOzX1tVkuLdQqo=;
        b=uGJa/AiG83YjSYU5r6bRl5DtPLCsY8cjgFjZ9EwdQ+KIskkMUYsECm9JL2BWDCUhJd
         QA8mDeo/MoXIVPI9+RXE9E4DG5C3Y+yKXA9eTQHoEF0rnPPRXubxWH/8wbfWZj3mZ7eq
         9uPD+8qnuUh8RM2sRKXu+9GyLnpu0+yVJjnZmbOz945UnnYatM2VlfER7TmiAS62AFQl
         pFdBGVhb/PyaRGY4TYHYvR7paO8Bbu+Jfq1exHvwGhi7LxzJWbzEPSan/v/a5hfvSh/k
         bDAVft9GFQRerkPbIhOoKE1UJ7WxoxRZuq65Sv2Va1sJqJlgsh7wfgkK7+CBDIhuTcCp
         QUMQ==
X-Gm-Message-State: AOJu0YwCMuo2h4KKN1TLLfBY2p90EUnsl8VYs6/8lVptycTRXIxigfgn
	zsCeyfG3GIDAk8jFoW9YpBQ=
X-Google-Smtp-Source: AGHT+IHw/5arc6L1ZIg2tGK6MRK7uXB7vva5NOtJk97DQi6lWXnDpBkOWlLKt6qxGwTnJtM5ZGMF9A==
X-Received: by 2002:a25:db05:0:b0:d81:58d3:cc72 with SMTP id g5-20020a25db05000000b00d8158d3cc72mr316216ybf.36.1694745969451;
        Thu, 14 Sep 2023 19:46:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1542:b0:d7a:e0a5:9256 with SMTP id
 r2-20020a056902154200b00d7ae0a59256ls1342139ybu.2.-pod-prod-03-us; Thu, 14
 Sep 2023 19:46:08 -0700 (PDT)
X-Received: by 2002:a25:6941:0:b0:d47:47c0:d7db with SMTP id e62-20020a256941000000b00d4747c0d7dbmr293282ybc.21.1694745968542;
        Thu, 14 Sep 2023 19:46:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694745968; cv=none;
        d=google.com; s=arc-20160816;
        b=bCnBIFFapYNZcr5CHVxtW8fhhZkFyjo8DKRFq2GZixSUH2s0s6HMtwfZflx+1nikwW
         GPTl25i3PvH1OJh9VDUO7KERC1X2kG7khatRK1u8FRbUoJyyRa87bev5ybW7BOtd6nKr
         6HgyDEnJzi6f2gIepApgx4MzI+zZ3Zjs0tDpTf+aBwnK6VJTNxLc969PnJvZWiUCrXaU
         edOCqqCcR/dOqp2DEgl67hRfSHejksLs+zVAUc8ajWtg6uj8Z8wValJ0G8O2VNi2ki5a
         72+9OwiHOo6taO/c2L6J3nS/EZNeKvjx5fzlJOmDF6oio6hMA7ThZ6ZWJEAlwga2oOVB
         O2nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=RK7ek7Jr01ODZjowTcUOfcKbHQxnH1wn+srDfh3q4PM=;
        fh=xnjHze2hhizWMWL+c23S4hdacx+DEnw7TyPmO82Bvos=;
        b=EGzhb/3PRN8WhaN0tyqAEv1mhO39b17t3rikJTuAtBvcdTW2gyk/CfwKQAlmday4Ja
         cr67yYFxGYN1olhFnPtcyiPxvH936z4cynPO1uG6yFeRbKgfJ8vG+5ZMOEEO3E+qNtxC
         yLYUixtA0YzE4+2ykvPWWU8mHppqJh+Hla5i3nSgYAkKUw6n+2lPUHi4m6OHUulkZT1D
         ODmArWQOXuUsOJ5EfsLzddPiITRKseqZulXejw9lq9aX1O8pr0+k1jQshKbsH5ZaVAbr
         e/sli3F28umSh9NPXnpu/hDAHN86LNZlqH8thugFLZ49ExNKbymlVcHE8iciY7pwYM0A
         TOAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=LGetPjaM;
       spf=pass (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=haibo.li@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id 85-20020a250458000000b00d7e3a95143csi356989ybe.0.2023.09.14.19.46.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Sep 2023 19:46:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 0208f7ac537211eea33bb35ae8d461a2-20230915
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.31,REQID:273d4d59-8a9f-4528-ac37-dc0b424d25af,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTION:
	release,TS:0
X-CID-META: VersionHash:0ad78a4,CLOUDID:954db8ef-9a6e-4c39-b73e-f2bc08ca3dc5,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:817|102,TC:nil,Content:0|-5,EDM:-3,I
	P:nil,URL:0,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0,AV:0,LES:1,
	SPR:NO,DKR:0,DKP:0,BRR:0,BRE:0
X-CID-BVR: 1,FCT|NGT
X-CID-BAS: 1,FCT|NGT,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR
X-UUID: 0208f7ac537211eea33bb35ae8d461a2-20230915
Received: from mtkmbs10n1.mediatek.inc [(172.21.101.34)] by mailgw01.mediatek.com
	(envelope-from <haibo.li@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1408545457; Fri, 15 Sep 2023 10:46:02 +0800
Received: from mtkmbs13n2.mediatek.inc (172.21.101.194) by
 MTKMBS14N1.mediatek.inc (172.21.101.75) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1118.26; Fri, 15 Sep 2023 10:46:00 +0800
Received: from mszsdtlt101.gcn.mediatek.inc (10.16.4.141) by
 mtkmbs13n2.mediatek.inc (172.21.101.73) with Microsoft SMTP Server id
 15.2.1118.26 via Frontend Transport; Fri, 15 Sep 2023 10:46:00 +0800
From: "'Haibo Li' via kasan-dev" <kasan-dev@googlegroups.com>
To: <andreyknvl@gmail.com>
CC: <akpm@linux-foundation.org>, <angelogioacchino.delregno@collabora.com>,
	<dvyukov@google.com>, <glider@google.com>, <haibo.li@mediatek.com>,
	<jannh@google.com>, <kasan-dev@googlegroups.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-mediatek@lists.infradead.org>, <linux-mm@kvack.org>,
	<mark.rutland@arm.com>, <matthias.bgg@gmail.com>, <ryabinin.a.a@gmail.com>,
	<vincenzo.frascino@arm.com>, <xiaoming.yu@mediatek.com>
Subject: Re: [PATCH] kasan:fix access invalid shadow address when input is illegal
Date: Fri, 15 Sep 2023 10:45:59 +0800
Message-ID: <20230915024559.32806-1-haibo.li@mediatek.com>
X-Mailer: git-send-email 2.34.3
In-Reply-To: <CA+fCnZePgv=V65t4FtJvcyKvhM6yA3amTbPnwc5Ft5YdzpeeRg@mail.gmail.com>
References: <CA+fCnZePgv=V65t4FtJvcyKvhM6yA3amTbPnwc5Ft5YdzpeeRg@mail.gmail.com>
MIME-Version: 1.0
Content-Transfer-Encoding: quoted-printable
Content-Type: text/plain; charset="UTF-8"
X-TM-AS-Product-Ver: SMEX-14.0.0.3152-9.1.1006-23728.005
X-TM-AS-Result: No-10--26.184700-8.000000
X-TMASE-MatchedRID: +f/wAVSGjug4HKI/yaqRmya1MaKuob8PfjJOgArMOCaCsBeCv8CM/aaZ
	f1+j//eOkOti/7QqGXUh5AyXWmAqpmu2g5s6p8lPW7gz/Gbgpl6hi9MC6OBOwruqk4cq52pzvb4
	+3z1qe65wj5BBW++UfCbtuknoGANVmGpYaWdk09LhqJ6oLOc8QW3eqxoVjgMEzsQ8iRVyD44DsB
	KNVu8yHSHQK8Uc9fmXaqMgKdVUqQ9sGQsY/Fc7u6XD9CBSVyH8WPJn4UmMuVLJYIv7y0tu9u69j
	M3AtKAfmapKR6Enamd1VhrfJVJ6xDfVJKfK+bRO2x93SnoxhVeeimGtNywjtslk/SMg0CpQo8WM
	kQWv6iVkvICuNJteaI2j49Ftap9EkGUtrowrXLg=
X-TM-AS-User-Approved-Sender: No
X-TM-AS-User-Blocked-Sender: No
X-TMASE-Result: 10--26.184700-8.000000
X-TMASE-Version: SMEX-14.0.0.3152-9.1.1006-23728.005
X-TM-SNTS-SMTP: 31D8B882395646096EE4B3E748433B78DBB106D4F0ADFA8A05354A6A0A2C39E52000:8
X-MTK: N
X-Original-Sender: haibo.li@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=LGetPjaM;       spf=pass
 (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as
 permitted sender) smtp.mailfrom=haibo.li@mediatek.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: Haibo Li <haibo.li@mediatek.com>
Reply-To: Haibo Li <haibo.li@mediatek.com>
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

> On Thu, Sep 14, 2023 at 10:41=E2=80=AFPM Jann Horn <jannh@google.com> wro=
te:

> >

> > > Accessing unmapped memory with KASAN always led to a crash when

> > > checking shadow memory. This was reported/discussed before. To improv=
e

> > > crash reporting for this case, Jann added kasan_non_canonical_hook an=
d

> > > Mark integrated it into arm64. But AFAIU, for some reason, it stopped

> > > working.

> > >

> > > Instead of this patch, we need to figure out why

> > > kasan_non_canonical_hook stopped working and fix it.

> > >

> > > This approach taken by this patch won't work for shadow checks added

> > > by compiler instrumentation. It only covers explicitly checked

> > > accesses, such as via memcpy, etc.

> >

> > FWIW, AFAICS kasan_non_canonical_hook() currently only does anything

> > under CONFIG_KASAN_INLINE;

>=20

> Ah, right. I was thinking about the inline mode, but the patch refers

> to the issue with the outline mode.

>=20

> However, I just checked kasan_non_canonical_hook for SW_TAGS with the

> inline mode: it does not work when accessing 0x42ffffb80aaaaaaa, the

> addr < KASAN_SHADOW_OFFSET check fails. It appears there's something

> unusual about how instrumentation calculates the shadow address. I

> didn't investigate further yet.

>=20

> > I think the idea when I added that was that

> > it assumes that when KASAN checks an access in out-of-line

> > instrumentation or a slowpath, it will do the required checks to avoid

> > this kind of fault?

>=20

> Ah, no, KASAN doesn't do it.

>=20

> However, I suppose we could add what the original patch proposes for

> the outline mode. For the inline mode, it seems to be pointless, as

> most access checks happen though the compiler inserted code anyway.

>=20

> I also wonder how much slowdown this patch will introduce.

>=20

> Haibo, could you check how much slower the kernel becomes with your

> patch? If possible, with all GENERIC/SW_TAGS and INLINE/OUTLINE

> combinations.

>=20

> If the slowdown is large, we can just make kasan_non_canonical_hook

> work for both modes (and fix it for SW_TAGS).



Thanks.

The patch checks each shadow address,so it introduces extra overhead.

Now kasan_non_canonical_hook only works for CONFIG_KASAN_INLINE.

And CONFIG_KASAN_OUTLINE is set in my case.

Is it possible to make kasan_non_canonical_hook works for both=20

INLINE and OUTLINE by simply remove the "#ifdef CONFIG_KASAN_INLINE"?

Since kasan_non_canonical_hook is only used after kernel fault,it=20

is better if there is no limit.



--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230915024559.32806-1-haibo.li%40mediatek.com.
