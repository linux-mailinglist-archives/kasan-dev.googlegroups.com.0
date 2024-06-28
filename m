Return-Path: <kasan-dev+bncBC27HSOJ44LBBEE47OZQMGQEZ5QC3IY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EB2D91C1AC
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 16:52:01 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-4229a964745sf5783715e9.2
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 07:52:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719586321; cv=pass;
        d=google.com; s=arc-20160816;
        b=J2FP5tZdRpImeEYPvbScj2R+YgzIRgfqUfjSZaJSm3fCy6wr6yOZT0j82IpxHI1+UA
         dl+14F3+epJm72jJm0fEJA4XAv/g4L66sQR9Wm3WrSluT8jKfYYHUyVqsi9iD87V6XOD
         2IlruSMOfsjpFB35y7vh0sax4/xNn9TkrCCb4LrU8RFGxiOJbszcDX+E3aHOX944KNNf
         EX4+OndXr7tIH+TUDhsJ0NpsmG6cCTSDPy9IQeUyib1NzRSULzLY+KtFqonTFjal1frt
         OEkP3nLLByti4pnfSczF78SYz1uQIIMP91EEHFnzUrevGPYxbmobr0rEvzmL2H3YE3FF
         z56w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=lbKziFgKK4ga24jYruFmENc1ytsYVBUzs8Ws2XzSljQ=;
        fh=SLGxURtP/9VPLhsKkQLMbxwGSnryVD38EOw1Tk7QFw0=;
        b=Z4ucJms9vk7XCgnx0SZRVJxvqI/XpUNyfQrmYHr5WHe9HhH+6gAnA/terw4LqVB7eZ
         +OST3rGa4j5Sm1tM3kEjwg69U0NcBZla3WjSj1clxPycXimGokDUQMlIUxN7yKI2ax+o
         xHVhbg++eFE/lA4fXp/G0CEQ5ks4LJl/DiEDj7RLRvZVVb7dmVXao297tEsSKPvg+wyg
         pehapwivJ0/aqybgh/gy2lqBZ7CVNKt62yBRihU2b4zL7kvNqdSrt+bEV4u02NclhQjF
         PSN2OMSxjg7h4V/03Om2LQonYoraZ7UliAT6XWf9oCrHu6NBSUbORFJjeY3mLAdBdlLy
         RUpg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719586321; x=1720191121; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:mime-version:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lbKziFgKK4ga24jYruFmENc1ytsYVBUzs8Ws2XzSljQ=;
        b=ODgW34u+gUzkJXzpxR0fK8gLaoMVNH/gK2MS9MU+XeNih8cD5/C2HDgsJKA5BDsGvW
         XFpLEf9XMguUW7++p7mUtLW6OpL1m2w2OnK6bXH2Q72heh80pFZdEOYqUUNW/LjDaB3q
         MFuh7tZoXAp6NPjTgYYpUFn3Mgg0qo4aF9OFHQsG9KKxKzKZcsnAV0EracAouNvJxM5m
         +kujIgd0RkhlWQoToC2yuucvtL7wVbNGp91WiAglA2fEUiwcdvTuTXiy30mBzpKP1iyF
         IcyxwJ5MiMHAT6qUwwcnacQLBIGSX2K3GH6BR0PW6rs1ZWwvuGwMqw2knfzYcqsEnizW
         QCbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719586321; x=1720191121;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:mime-version:accept-language:in-reply-to
         :references:message-id:date:thread-index:thread-topic:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lbKziFgKK4ga24jYruFmENc1ytsYVBUzs8Ws2XzSljQ=;
        b=LtqBF7sodwqgaX/uUpn9M3BNwdmyVkHS8UuY6j1FqQqegX+vYPfZ/hd6q+Vkg2YkeF
         uvBQUTT7mcg5QvTBxRwWZ/LJZvFZbXNsYL306Nvo9KqojmnEQo3i9RgQub283tku7r0O
         C1+NCc9RxIQ9rr7auOkwIa7Ih46tr3hEXLlJpVWjRQr+CmB2vSIlJG6tPlEV71vFIW+6
         mnhY8C9l8Alenwj0KSQ6clJ1CxmHR6tbnuKMW/JRBQHX+SHvr82sv3+QPBIbFZlYMu0c
         sz4shgRmkO0IEPUOMtH3XOqIbG+OLwMtWzm9gyVkapCi+z4sliUnEmGxyLka6XgFg5YW
         2ebQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWlP3D6nPlFIz3jJ+vqwGEusFpyeGCw9AN8yuo8IbDaQUdonlBzXQuje2gECL767EGfqi+Wt1h7GeW82OxmtQ5lBec4HnsUYA==
X-Gm-Message-State: AOJu0Yyzh/ckrbliZDctdlmCAcY+vYmcUQKNF4DhS98GZPhnZIgBpzkF
	mGXdOM611+kmle3poHgKCZkzb7ZZ03gGCW8mAL2RqfqDLRebPq/h
X-Google-Smtp-Source: AGHT+IF5QZcPCcbYyrKey2fYkOAXrRHfrTfEN6ApGOvnvAXgenBj3GbclKuCjsthTHGQS+//CMBegg==
X-Received: by 2002:a05:600c:4311:b0:425:6bc4:c006 with SMTP id 5b1f17b1804b1-4256bc4c2d2mr18629775e9.16.1719586320436;
        Fri, 28 Jun 2024 07:52:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b19:b0:425:68a1:9da9 with SMTP id
 5b1f17b1804b1-4256c7e9523ls3784455e9.2.-pod-prod-09-eu; Fri, 28 Jun 2024
 07:51:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU+VxVlrhjr4Q7SvIMoGs2PTxMaWdXfTpVSnKGoyzyloQTlrd+NqtHpqqHiCqaHXLWi7piINx9GHlwwfrIIy9x80wkn+rFiQK3GHQ==
X-Received: by 2002:a05:600c:511b:b0:425:6510:d8ec with SMTP id 5b1f17b1804b1-4256510de8fmr35600405e9.23.1719586318058;
        Fri, 28 Jun 2024 07:51:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719586318; cv=none;
        d=google.com; s=arc-20160816;
        b=a5MMM4yDMdTm1cewd2thLvZdxqp5HCdl1u+q/tsqwgv5xsVHuV84nhg/y8EZJl72Lj
         OVbrlmi7kUM5QC4I2reWAl7cAGvCNCIbMeNCmFqu2EREyHy079lQfniLR2BF1x/g3T7H
         1kiiz08cduKb9r6OdwyUGNs5BY1lRRitY/ffD3frX3EAkPUBdXdNVHE34EE9x/he95Hi
         xcHrZV4TBEzsM6p3LiKMeZiV/LuVrza7fE6lzaykrcTckC82LFNLvTEYP1xs9Ndvii41
         ON6kmX5h2FFuTMw1l2pIU6TAXbsAKm+Z035qHDr8dBSEjTt610dY2bwMCBppIrE3/vx3
         COQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=aluzX6XcpilgB3wDHaOqW0ZRnk7WB4V+K/VgLgLVeaQ=;
        fh=Bh+r1ylNfYUlUntlishPFiNpsqyfH4mRNOXtX17RbKE=;
        b=bJXlIeeJN954tv73BYw1sKYXIXjaIY8LP7Fvl89YKFEwX/GRamDxkyxrI8oRLXMYWJ
         AOgyXpukmA2+XGjHEVeQGcYsUI6QA2cRpTTFdH4LRXgMYXpQqBDzRTTSaJKxcha1GqDt
         195ZJejOiaExwSMLR0mNPi6lc1SFgzAtbr6ONu7qKCre0/iSbHdw2fRvrFYOSUjnca5B
         JkSIaGaxSLMDzDXZfAxzFC3/rK0ekIR2mnaDJchfQb0kvhWGqPtVGnyopBDdnQ5reIZk
         KAx59ez7tqrlhCJyNXmppZvzOfARecycNanHz9K18LilIStXo4f/PDb8sbPylIA/O+/l
         rXfA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
Received: from eu-smtp-delivery-151.mimecast.com (eu-smtp-delivery-151.mimecast.com. [185.58.85.151])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-424a2ae3de9si5907205e9.1.2024.06.28.07.51.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 07:51:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as permitted sender) client-ip=185.58.85.151;
Received: from AcuMS.aculab.com (156.67.243.121 [156.67.243.121]) by
 relay.mimecast.com with ESMTP with both STARTTLS and AUTH (version=TLSv1.2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 uk-mta-104-l7HmKX8rN7mrGQuUZu-NOg-1; Fri, 28 Jun 2024 15:51:55 +0100
X-MC-Unique: l7HmKX8rN7mrGQuUZu-NOg-1
Received: from AcuMS.Aculab.com (10.202.163.6) by AcuMS.aculab.com
 (10.202.163.6) with Microsoft SMTP Server (TLS) id 15.0.1497.48; Fri, 28 Jun
 2024 15:51:19 +0100
Received: from AcuMS.Aculab.com ([::1]) by AcuMS.aculab.com ([::1]) with mapi
 id 15.00.1497.048; Fri, 28 Jun 2024 15:51:19 +0100
From: David Laight <David.Laight@ACULAB.COM>
To: 'Marco Elver' <elver@google.com>, Thorsten Blum <thorsten.blum@toblux.com>
CC: "dvyukov@google.com" <dvyukov@google.com>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>
Subject: RE: [PATCH] kcsan: Use min() to fix Coccinelle warning
Thread-Topic: [PATCH] kcsan: Use min() to fix Coccinelle warning
Thread-Index: AQHaxgSOjZ6+csUQK0qGWpfhAg1cdrHdSOuA
Date: Fri, 28 Jun 2024 14:51:19 +0000
Message-ID: <1bebf2e8a8a64b4aa4097fd045993106@AcuMS.aculab.com>
References: <20240623220606.134718-2-thorsten.blum@toblux.com>
 <CANpmjNMHPt7UvcZBDf-rbxP=Jm4+Ews+oYeT4b2D_nxWoN9a+g@mail.gmail.com>
In-Reply-To: <CANpmjNMHPt7UvcZBDf-rbxP=Jm4+Ews+oYeT4b2D_nxWoN9a+g@mail.gmail.com>
Accept-Language: en-GB, en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-exchange-transport-fromentityheader: Hosted
x-originating-ip: [10.202.205.107]
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: aculab.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: david.laight@aculab.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as
 permitted sender) smtp.mailfrom=david.laight@aculab.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=aculab.com
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

From: Marco Elver
> Sent: 24 June 2024 08:03
> >
> > Fixes the following Coccinelle/coccicheck warning reported by
> > minmax.cocci:
> >
> >         WARNING opportunity for min()
> >
> > Use size_t instead of int for the result of min().
> >
> > Signed-off-by: Thorsten Blum <thorsten.blum@toblux.com>
> 
> Reviewed-by: Marco Elver <elver@google.com>
> 
> Thanks for polishing (but see below). Please compile-test with
> CONFIG_KCSAN=y if you haven't.
> 
> > ---
> >  kernel/kcsan/debugfs.c | 2 +-
> >  1 file changed, 1 insertion(+), 1 deletion(-)
> >
> > diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
> > index 1d1d1b0e4248..11b891fe6f7a 100644
> > --- a/kernel/kcsan/debugfs.c
> > +++ b/kernel/kcsan/debugfs.c
> > @@ -225,7 +225,7 @@ debugfs_write(struct file *file, const char __user *buf, size_t count, loff_t *o
> >  {
> >         char kbuf[KSYM_NAME_LEN];
> >         char *arg;
> > -       int read_len = count < (sizeof(kbuf) - 1) ? count : (sizeof(kbuf) - 1);
> > +       size_t read_len = min(count, (sizeof(kbuf) - 1));
> 
> While we're here polishing things this could be:
> 
> const size_t read_len = min(count, sizeof(kbuf) - 1);
> 
> ( +const, remove redundant () )

Pretty much no one makes variables 'const', it mostly just makes the code harder to read.

	David

-
Registered Address Lakeside, Bramley Road, Mount Farm, Milton Keynes, MK1 1PT, UK
Registration No: 1397386 (Wales)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1bebf2e8a8a64b4aa4097fd045993106%40AcuMS.aculab.com.
