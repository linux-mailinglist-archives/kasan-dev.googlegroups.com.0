Return-Path: <kasan-dev+bncBC27HSOJ44LBB3GIZCTAMGQEO2QQ2TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id BF9E67739E5
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Aug 2023 13:18:05 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-3fe216798e9sf34296155e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Aug 2023 04:18:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691493485; cv=pass;
        d=google.com; s=arc-20160816;
        b=dklJuP5sxR8U+/VK5azUCyEBztwgF79aSSTlkzFy3BZJPZzbN4Fprk3NczKYsgX1iQ
         K+5UDhXXIPs+MJl7XQ6wymI7FcuH3OKKl8phtMnd9+0vr3PKGjgdpsBswvu3EHe5QJ1a
         auNJVi1SvDFVBsKicfsXwfA10pqWrJ4t4e0nUGP00m9zo2YDYXYQUf2Cp8aadsv9nlJq
         4bduVy8P+CXV+C8eoafvTc+yzFGLlSzrKs9IN9xQbnASYFcvaWev3/kxqjhGo8u2q6wx
         T/a8ajjXaKhLHus8EZZgaCr21iqjDy9y7ynYIAklj3M9qz9BGY0VFdt+owbdwPBqz3dI
         miNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=2z0ShjjVIXYCGNTHgnHMQQ/YLshfu66XNfddNJiSjxc=;
        fh=fjZOuepxBGDgclKn18K9Q2ou4LceB34JPiulF9FvcYw=;
        b=Q49WkQovYZjvdXxpKf1RaOpkK0tbxlQTh4pwGl/AQnjvEbK6F5UOJTDyPAT7aheZTY
         8ceTwgZUtC0ADsFqlfDZFkCeeze1kx60z1lflvre8iw6uvIAN1t3bLS4h6qRbH3Sj48+
         DhzIDXr7wGvzTKguNU2S9VPhBIJHqgdBfNiaRNXRtyQoVLbODXMb889URDWkiOuhzHn3
         i6aJ+JRd17snRyZhsFSVuLKFZzUkyljSJbJsqqoY9WOOdBNJRiGOke7EC8kaSCpdPJ24
         w7aNf7x3xCB5wnPDrF5Q54VOErjyFj7FBUbw3Ag2rNbjzIkx1V0YR+wbDbIYERTyRKj5
         NeEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691493485; x=1692098285;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:mime-version:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2z0ShjjVIXYCGNTHgnHMQQ/YLshfu66XNfddNJiSjxc=;
        b=FJvowuId16wcVYV1h0U8ISBMx9m96onyAl+3Auh6KCESfmLZnTu4045+B5lMB9BjZz
         0jfxITKp9y8AKQnJmtMCcULySOiWr84Hg/gcVUjGz+xEEOOU4bHHRGDC4oVOvdkdt3er
         WwojNQkqs6U5q8/1Y3E27sPrLKTS1gQeN5mWG3gaSnSb/YD3JijHMYzcyzf5ebSdXMq/
         fqdW7ox2s6blwqjh0UaRUs7rGyuHFzpypGVrneGobgp4ODjGMr24mdO3xIPaA4CWcfIX
         dOZPGm1brmEXP8ldJwkuDOUhg8UKMRLifW+TBEwgN8Zzh9kuPgZjRhi/viTxdsHwZXlD
         Oi5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691493485; x=1692098285;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:mime-version:accept-language:in-reply-to
         :references:message-id:date:thread-index:thread-topic:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2z0ShjjVIXYCGNTHgnHMQQ/YLshfu66XNfddNJiSjxc=;
        b=Ic0mjUUaifM3DQ1Fg/RgM7ixq6SSC8w2GghGK/MabZ5knMFUw8DVurSFJWSU7EhP3L
         rZrCGRFAmoKlD+nMwOEOIt0Exg57xi+9WGwEd+w5DYzKUmvQ246rBXKby/YVMt9/vi+g
         K6ZYT1K8Bf15vj2Kwy/cfxWkiQNTdwBuyCCNIzGf1x467N98MQsltOB2jw5xl+A6AMCx
         nOwWj33625SVucuddybgSnTNaH5hP94PCfOgwzgOhlBM1Pf6MYSOVLmgc4qjFFEHcNte
         WLFva1E9/mX4U/33Ulo/t2zewHulMKgDCHUXWfvQXA/2m6/3cFBr+49b8HkMVYB72i7d
         rCug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxwQC8PlFXlbfkk4gd0gbvXZJN54krG02mBp5VS5yPjz2xYJnWk
	YsIw9xnhNDvih9+WZsHzNfa71Q==
X-Google-Smtp-Source: AGHT+IHGw/RKXuQB9M0UgNJo1Na3uLXeiO+Mt0lj9mQjYgFIVEUN79GVrlQBb+B4/iqIom/o3RV7XQ==
X-Received: by 2002:a7b:c4c8:0:b0:3fe:2e0d:b715 with SMTP id g8-20020a7bc4c8000000b003fe2e0db715mr9467158wmk.18.1691493484388;
        Tue, 08 Aug 2023 04:18:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d83:b0:3fb:422d:4ff8 with SMTP id
 p3-20020a05600c1d8300b003fb422d4ff8ls1728398wms.1.-pod-prod-02-eu; Tue, 08
 Aug 2023 04:18:03 -0700 (PDT)
X-Received: by 2002:a05:600c:ad8:b0:3fb:a0fc:1ba1 with SMTP id c24-20020a05600c0ad800b003fba0fc1ba1mr8811715wmr.35.1691493482902;
        Tue, 08 Aug 2023 04:18:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691493482; cv=none;
        d=google.com; s=arc-20160816;
        b=lNlIrr0wwuMZk5q2OgzVf1SNnixbHWNKuhm06txZb5YoE9lpwcjuCnVRq4urc5JDGY
         ra5LjM0aAMG5R8A87fjxtvAqOE9DncywSFAff12VIRVVNbLVC8cNH3OdEiStldqyaQcM
         /ECGtLb/r0jsxX5n5QtjIOUEK15uLwFf4jn9yNgM2OVtDmthmsCEuDjNyQBRrBnJ+61+
         XL09Pftu1T986xZq0vZ+CXiWRwvhWL1YGDtkJxUpZqwT/m97y3Wg/n4B0k9niDw+tjCL
         e6LuKFpKKykwtmTQ2JHfNxbQvL74Z9w0gAGnzPHjayOkriPQRw/S5gGJfEXar+4Fh6Vu
         lf4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=OShto67rIPnUgjQx9BPl7gCVmVOVOe6WNo/5cebtndk=;
        fh=fjZOuepxBGDgclKn18K9Q2ou4LceB34JPiulF9FvcYw=;
        b=vrIZZ+fKHS/8bzzrIp00eokfVfNsheVlVFzO13HoGpPxWJM9XmuX+n5S31T0MBt8OI
         ofaO1wKJwomAb5AJosSfYvW7o/MJt2nhCsNwTNVnzgKActRAb3wUPhsTNxVyumbhNdFa
         zvrQfSEttqJGGihNy5RKtPnuj4LBGhAAXExz5Uwbco1gxrVYNjYTY+ZO0R0+/wIJ1EMQ
         e27+3ShP4KhrM8s+TCCIeS16pblLaNpMB1n3fl15TA2AzRD3gYwgBgLmRAEOC9xj2W1S
         U+6rSeeZFrnoyH1UNn1gwRdwJOx7l+MlFe9Du5p05nsgJ7k8uvfOe21vN3XjvkOn296m
         Do1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
Received: from eu-smtp-delivery-151.mimecast.com (eu-smtp-delivery-151.mimecast.com. [185.58.85.151])
        by gmr-mx.google.com with ESMTPS id p23-20020a05600c1d9700b003fe241a5aabsi1135170wms.2.2023.08.08.04.18.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Aug 2023 04:18:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as permitted sender) client-ip=185.58.85.151;
Received: from AcuMS.aculab.com (156.67.243.121 [156.67.243.121]) by
 relay.mimecast.com with ESMTP with both STARTTLS and AUTH (version=TLSv1.2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 uk-mta-188-r8ab3m5YOcmwDLBl3hsptA-1; Tue, 08 Aug 2023 12:17:52 +0100
X-MC-Unique: r8ab3m5YOcmwDLBl3hsptA-1
Received: from AcuMS.Aculab.com (10.202.163.6) by AcuMS.aculab.com
 (10.202.163.6) with Microsoft SMTP Server (TLS) id 15.0.1497.48; Tue, 8 Aug
 2023 12:17:49 +0100
Received: from AcuMS.Aculab.com ([::1]) by AcuMS.aculab.com ([::1]) with mapi
 id 15.00.1497.048; Tue, 8 Aug 2023 12:17:49 +0100
From: David Laight <David.Laight@ACULAB.COM>
To: 'Rasmus Villemoes' <linux@rasmusvillemoes.dk>, Petr Mladek
	<pmladek@suse.com>, Andy Shevchenko <andriy.shevchenko@linux.intel.com>
CC: Marco Elver <elver@google.com>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	Steven Rostedt <rostedt@goodmis.org>, Sergey Senozhatsky
	<senozhatsky@chromium.org>, Alexander Potapenko <glider@google.com>, "Dmitry
 Vyukov" <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>
Subject: RE: [PATCH v2 2/3] lib/vsprintf: Split out sprintf() and friends
Thread-Topic: [PATCH v2 2/3] lib/vsprintf: Split out sprintf() and friends
Thread-Index: AQHZyWXSqz0YrpkIvk2kVFpZOdRD+K/gPfNw
Date: Tue, 8 Aug 2023 11:17:49 +0000
Message-ID: <96476d194c324092807a1c49f42d44bb@AcuMS.aculab.com>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-3-andriy.shevchenko@linux.intel.com>
 <ZNEHt564a8RCLWon@alley>
 <fdd7eb5d-2b76-d326-f059-5cdf652b5848@rasmusvillemoes.dk>
In-Reply-To: <fdd7eb5d-2b76-d326-f059-5cdf652b5848@rasmusvillemoes.dk>
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

From: Rasmus Villemoes
> Sent: 07 August 2023 20:32
...
> No, please. Let's have a separate header for the functions defined in
> vsprintf.c. We really need to trim our headers down to something more
> manageable, and stop including everything from everywhere just because
> $this little macro needs $that little inline function.

The problem I see isn't things like kernel.h defining a few 'library'
functions, but deep nested includes that means that pretty much all
of the headers get pulled into all the compiles.

Some nested includes sequences can go through an "asm" header
that you might expect to be architecture specific stuff and then
include something like ioctl.h.

Add something like #define IO_WR @@@ to the top a C file
and then see where the compiler finds the duplicate definition.

	David

-
Registered Address Lakeside, Bramley Road, Mount Farm, Milton Keynes, MK1 1PT, UK
Registration No: 1397386 (Wales)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/96476d194c324092807a1c49f42d44bb%40AcuMS.aculab.com.
