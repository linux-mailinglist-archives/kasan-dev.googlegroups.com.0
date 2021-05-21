Return-Path: <kasan-dev+bncBC27HSOJ44LBBOP7TWCQMGQEKDQQJSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2299038C367
	for <lists+kasan-dev@lfdr.de>; Fri, 21 May 2021 11:39:06 +0200 (CEST)
Received: by mail-ej1-x63f.google.com with SMTP id 16-20020a1709063010b029037417ca2d43sf5976612ejz.5
        for <lists+kasan-dev@lfdr.de>; Fri, 21 May 2021 02:39:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621589945; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZryiVvMKPBuK/uUQyFtvUNG/X+X7CpRPocgAhyA92LAm8nrjpi6jG4dozhx70gHDPn
         WcCD3fPTwQW4HXgyu0CQbTFF9VTb+LgZHWcNt/UhZBX2I6agmWcF0CAb6fQ2OCKBS1rs
         jKVcaUKxYcteXp9qIS1g4rJDXQufh9Xjzqy/3HXQKeybb8r8V0i69gdfYZlJZb+UUZHb
         1KUspJDUxzJ03u4FexOLBdpBB9zS55tH0Fk0Xzj+TUJkD825L8bLt0TitJjupdePTZWx
         FGifd/y6N8GMMKm5ntR/pIxa/J7cDIwt7FMiqjfDreLxSJti885qUf4JecEbpiA7NEt/
         Vm5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=SnQVTbZC8ZoAlK6R4uREuqyvTTjh3vOIG1U90ALzij8=;
        b=XyibRc8GVkC1bmyP5YGNl3R5SP3Ngf1ZpweKTXPKQJ6slKSg1jKQW2uRvnvtr9cCiO
         Cb/Y/2uqqZ3X21ay6K5mKuemW1PDjvJBxo/NlqjiTu9q1NVTdDkFTAHU8EWwS1QPI1f1
         LxbF2kzeAVium9trrVfaJea3Wi/BNjGpSl3fPe546gGrnKLPLtlw/pPtTJWte8AP/InP
         +Nt2YosRHC5fm8AmLh9XhGzRdoAldQ1I0c30Im5R1CRMiff4RqdD9Vrxeret0RpSkaiL
         IOzwx6NLsqNF0ThwQw91gVzZs7RsAKn2P5utkrcBcZK3/3ERcYH3Am5ecjymErExbWKK
         asMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:mime-version
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SnQVTbZC8ZoAlK6R4uREuqyvTTjh3vOIG1U90ALzij8=;
        b=B4104buN3/akXtwYRsv6EzZqERSUj55gus2htZa6vUCszRQzysEhM2/6orh64iYuG2
         OhcqhFqt+miJAjINXvxffuhcpHks/tLu1YbqCViVKE9/LM8Giqv3PRa5AXPeX3JssgdQ
         uMlYxx71dgCz8Y47ZUIdRk9FmmvU4taP0LmmgOmp/KNZfr5l4JvjMRNGYSB+YYGEj3iV
         GTwAp+rYmBorRd0GhZZxY+tRMWBN7vY83uuGIjKnrngXlAVMNmtItnVI2aeJGJDMF8tG
         BLwhMW3ihocicMI27btErznicStFdkf+zU0KXGFgEJq05WPILupFv/GC+nPXf+397SGd
         ORCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :mime-version:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SnQVTbZC8ZoAlK6R4uREuqyvTTjh3vOIG1U90ALzij8=;
        b=jqFwf4Oqb1XyA+akb2QC9DGhuMfeXBbDRUtofXRGQDkirSUtZgVhUBpLZ9oJd/EqYH
         GOwoIKobrhY3hBvzEi1bU+F0tExaQDX9VlMnRWeeHbZU1QkJ31rGJlD17pct4heOS9Dw
         zmI9TFcettiiMADByl2LBOQbDzbPC50+4gOqu3ukzZZhoLo+iZFlE2kKlUfoGbb0gjhT
         PcTAjYSXNe/tSk8sR0q70RuIjnUzPvGvjKAWIz5G2GvgjPi76dmNGVFpXTtK2zN9RKjZ
         rkJopliAiQJwG1tFuInYOdq0VxgdYeF2IpbuidiDxTN1m7dO1mWbXHKJWi0BJhJzKKTy
         ti8Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533lphMTKehg+VeKYJghh7J1In/L7JGwTERibYuPBny0qm5LzlO0
	IIFH4JaECgi+e3FnHRgpKow=
X-Google-Smtp-Source: ABdhPJw5RoLRICikd69lMNze+aIITRTMG0OmGPy0m0pJyC2xpQZmCT+H6HKwa0Rw5Ih3XjCRFj1AWw==
X-Received: by 2002:a17:906:4a19:: with SMTP id w25mr9247265eju.500.1621589945879;
        Fri, 21 May 2021 02:39:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:94d4:: with SMTP id dn20ls2739298ejc.6.gmail; Fri,
 21 May 2021 02:39:05 -0700 (PDT)
X-Received: by 2002:a17:907:961e:: with SMTP id gb30mr9785279ejc.58.1621589945032;
        Fri, 21 May 2021 02:39:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621589945; cv=none;
        d=google.com; s=arc-20160816;
        b=sGpv0sjZxXYuaTQ+Z/5iPEdGlb0QJe+zcS4fenJ7ukaJCpoh0bBuePxLgsoJ0UtdQP
         /GAAwm27S2ehhgT8INS+mPkdMGYMYWe0Zjd5ibNDCGezYBZa3BWGAE26cBw+8/fBFgFk
         E6yQDDZlTKyuAkjbUyWPFC5pvA0HQaAZWn7r1PwmfRdB5w4YC6CZ/h2eqN+2/hH4hke1
         wqqInNQOi3QE9V3BT5ofiFcHaUD++Qj5V/ltLpDgSeig4R+Z90L1MGlKwFQ9NHMWmUDO
         QFTNzm2/jZU8zBlJlYJkxK2eFBNzeF/1ihcd+Tt8vI1UOB9WlvvEi1Bj/eGocXR5jGzE
         O6dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=XEW/+Rrx5eHCAl70a09zm7F81wlMboO9Fq/P6uzK3x8=;
        b=DR07M4MyI/CNaDNrqh+DPEpe6K1koEHZDL7vjqHqzFAHn+5cTN631u9oKzRwkDHuL2
         RiKFFR9WZ1ioN1mqRdDBgd6bkW/goUxC88D7PmDlXRObm2pGVsl24FuAYvGcGdA011Ok
         HfhDMBhMMZ4ilz3/kAJz+rVugH4Y/tTIsFHcfAnuPul3IElW4opU9P9d/KN8yWxalIkp
         bhk7k7Moe0jhz5bCNFf37ZFgMtQFoCibhcoAdyfliemyPH0NQ/gf5oBn7V2jYUViIBfv
         BHlMATYntrLQ0nqOgtz12oKb9Sa0WB7A4POibU9wX8nOEz7hI4d9eIhR/o5P9xyTdiro
         W7bg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
Received: from eu-smtp-delivery-151.mimecast.com (eu-smtp-delivery-151.mimecast.com. [185.58.85.151])
        by gmr-mx.google.com with ESMTPS id r21si415783ejo.0.2021.05.21.02.39.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 May 2021 02:39:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as permitted sender) client-ip=185.58.85.151;
Received: from AcuMS.aculab.com (156.67.243.121 [156.67.243.121]) (Using
 TLS) by relay.mimecast.com with ESMTP id
 uk-mta-48-ACZyF3WhMFusJGlOpJA7Qw-1; Fri, 21 May 2021 10:39:03 +0100
X-MC-Unique: ACZyF3WhMFusJGlOpJA7Qw-1
Received: from AcuMS.Aculab.com (fd9f:af1c:a25b:0:994c:f5c2:35d6:9b65) by
 AcuMS.aculab.com (fd9f:af1c:a25b:0:994c:f5c2:35d6:9b65) with Microsoft SMTP
 Server (TLS) id 15.0.1497.2; Fri, 21 May 2021 10:39:01 +0100
Received: from AcuMS.Aculab.com ([fe80::994c:f5c2:35d6:9b65]) by
 AcuMS.aculab.com ([fe80::994c:f5c2:35d6:9b65%12]) with mapi id
 15.00.1497.015; Fri, 21 May 2021 10:39:01 +0100
From: David Laight <David.Laight@ACULAB.COM>
To: 'Marco Elver' <elver@google.com>, "akpm@linux-foundation.org"
	<akpm@linux-foundation.org>
CC: "glider@google.com" <glider@google.com>, "dvyukov@google.com"
	<dvyukov@google.com>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, Mel Gorman
	<mgorman@suse.de>, "stable@vger.kernel.org" <stable@vger.kernel.org>
Subject: RE: [PATCH] kfence: use TASK_IDLE when awaiting allocation
Thread-Topic: [PATCH] kfence: use TASK_IDLE when awaiting allocation
Thread-Index: AQHXThvT1D7AluRty02nSL8F2LU+eKrtrQGA
Date: Fri, 21 May 2021 09:39:01 +0000
Message-ID: <bc14f4f1a3874e55bef033246768a775@AcuMS.aculab.com>
References: <20210521083209.3740269-1-elver@google.com>
In-Reply-To: <20210521083209.3740269-1-elver@google.com>
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
> Sent: 21 May 2021 09:32
> 
> Since wait_event() uses TASK_UNINTERRUPTIBLE by default, waiting for an
> allocation counts towards load. However, for KFENCE, this does not make
> any sense, since there is no busy work we're awaiting.
> 
> Instead, use TASK_IDLE via wait_event_idle() to not count towards load.

Doesn't that let the process be interruptible by a signal.
Which is probably not desirable.

There really ought to be a way of sleeping with TASK_UNINTERRUPTIBLE
without changing the load-average.

IIRC the load-average is really intended to include processes
that are waiting for disk - especially for swap.

	David

-
Registered Address Lakeside, Bramley Road, Mount Farm, Milton Keynes, MK1 1PT, UK
Registration No: 1397386 (Wales)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bc14f4f1a3874e55bef033246768a775%40AcuMS.aculab.com.
