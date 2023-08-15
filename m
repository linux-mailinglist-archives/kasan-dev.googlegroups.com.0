Return-Path: <kasan-dev+bncBC27HSOJ44LBBZEY5WTAMGQEXHQIKBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id DB78A77CADF
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Aug 2023 11:59:01 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2b04d5ed394sf9060781fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Aug 2023 02:59:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1692093541; cv=pass;
        d=google.com; s=arc-20160816;
        b=rbBG6cLvAX2z7/RAo/PtC4Rk7w5+QgSspXgsRWcSahGyV4oEiuFZIL94nMSuzKJRXJ
         NqD1uP+cPFIJ76170eN3jFAwHTcKrWnifXLB6WDFlkLp40Sf1fT7lOZ4QPZWaJy9KFT9
         R9+ZI0KVcjTyUYaLjWE9o04orfEjrOVfG0THERptA2XyMY3wM8K8sp5WDqiWqpLKaCR4
         jinIXHuqfSzhBUF873bjN5IL7QkPDRER23JZrNqnKT9brnKk8csgzgHoSS8bb/rSbQPy
         6bioBhoqbteJhyHlWcZBE9k+MWrSDtpFpTjZBjOrbZTNs/5+xT230B9SbNy8PqQp5SMo
         4X8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=bZQPmk/NvmsWC63V6dphNEhy7CbGF3b6Zvr14vRF2x8=;
        fh=fjZOuepxBGDgclKn18K9Q2ou4LceB34JPiulF9FvcYw=;
        b=HBOoNUKg04rUAt7BJ8zVSSQSsEJSZ7G6Wlnxl+19jU3ZFlRSpqTXJWyAwQXGSQtixT
         6IyeXG0J3+dYC7n1E/7sHaWRpgs8XJyQ38AwcoIe5rDhxgRZBZndQ8ec5MoKNR0XsU4X
         urVKMKuRZ5Kg8EYUCoVnT7xjL8sEyRU3nD0kAHjefv+zD3+sWUwRKHGJz2IgM11ATB6r
         y2uLS+AoO66Bf7+0UhqIj0euHepshYqazMqAUFIXta8zSW5lgP7fJ1Ze3yszsVY//mF0
         rnQTQb6c0dMahDcFdenXa6B1Pc+QX9JMBIIlDxBOTSEZtdQFO3rr5H4O0R88njcf6ApC
         vs7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1692093541; x=1692698341;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:mime-version:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bZQPmk/NvmsWC63V6dphNEhy7CbGF3b6Zvr14vRF2x8=;
        b=PbZgY03sCWq7SG2KgX3KmjZNfBqYSNvRwBHkkW37zxsH30hq7aWVOQkRooxgPQciUI
         54YTeHngwN4lQco2oHyQwL1CWbIeYfBFKs5PHOPaZCDUWazuPQ9kJK6yFV+ybyScf3z7
         Qr0t2tfTKOrH7zEg1/nTKgWdkFuP90husmVi0CjZnac9pJyhSAVPuoeEKe5x3/D6EjtO
         yOZw5luG0rS+Im7WAp7KYFL86gjLMrxXaNV+ruvN67fqUhuN7QNQPCUINJGB7cBo18YO
         PrxUJ9XAHpznpen6KujqVdkIW9rMZa3XIFZLl0rf7mZ7MStSMu60ZeLsU7aJQ4uaCJ+i
         yYbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1692093541; x=1692698341;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:mime-version:accept-language:in-reply-to
         :references:message-id:date:thread-index:thread-topic:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bZQPmk/NvmsWC63V6dphNEhy7CbGF3b6Zvr14vRF2x8=;
        b=iZTz2tYyxN1KZ2hi71vc6VT+trr5PWsMJXtl/h5KVu8b00Gdqi/DR7SDpJUU1cg++4
         Ly5VURPVZeAQ06s7ZrkRLmf83Zw9Ci3ibl0uxLezfvk6XRmwVFwI7ODe/UMBRF0fuZGF
         vSRBGjQ59mKsmRm3zCEzYV8nEXSo+HP/1dGvzUgnNqpI+2TlFVaMgugUGUDr82R+7C4R
         7ikeUsW3vTkGqB7N+jieRjKV0JuLoVw5MqB4jwBvVl8PJvq3v72PcCevHaDYNd5mFlNE
         tSlgXj8yw01uroJT0fEOWZYEzgfJNKgUjbwcUE9k5Mor/821HLBso6yapZ5bjHsnIf6+
         KqEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwrF5Ek3SovtaCKFlQ+v/zjOFXcpvnry1KDTAbnIBNciEOp+gcK
	OWrOHd2A3rVBo6X9tiqwPCw=
X-Google-Smtp-Source: AGHT+IHYAynxeuZE4+MqlcWhe66ctod0fHGDVVdmoqbm2pUjYZNCBpr8jaWIDTIqxTZjjfEKGUyULQ==
X-Received: by 2002:a2e:2a84:0:b0:2bb:9229:30ac with SMTP id q126-20020a2e2a84000000b002bb922930acmr388569ljq.2.1692093540755;
        Tue, 15 Aug 2023 02:59:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a7c6:0:b0:2b9:6182:b0a4 with SMTP id x6-20020a2ea7c6000000b002b96182b0a4ls830169ljp.2.-pod-prod-05-eu;
 Tue, 15 Aug 2023 02:58:59 -0700 (PDT)
X-Received: by 2002:a05:6512:3dab:b0:4fe:193a:e15c with SMTP id k43-20020a0565123dab00b004fe193ae15cmr11509885lfv.40.1692093538919;
        Tue, 15 Aug 2023 02:58:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1692093538; cv=none;
        d=google.com; s=arc-20160816;
        b=FBRu+TI9SXGFXHpUW+woGMGsDir1R91T4pWCU3QN6D60CoHR/MMgSWPRUWq0v1il8E
         uOBYc4I5YQFhXdlGIaxJCLnHGlc2ObhoaSD8UCuuplySbXiw3JYcS8VJSekzKZzRxPiz
         WBShsDRu6xfjWa1+XzEWm/+vytpCkVZs+NTqdkzUVbwOKQGuby11C3g+aAwjU06eF2et
         Nucc7X5YlssDVd0CNzDbHXtl8B2eyUAx8YeSoNy9ehGxKOy0jFFaqgl0MH3qiQFoHYdp
         5CeGOFStm7AAtZ58DBh9y3WbwIsRY8gfVOwMp1xoIlUuWXpjBv5rUtPldP6AOEisrllM
         rk3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=YZr/DTEV1J9GIH+v38AZCpmaGqum6vGLcMIqt+o9q9M=;
        fh=fjZOuepxBGDgclKn18K9Q2ou4LceB34JPiulF9FvcYw=;
        b=Y5XqSkd2PjjVcIiJqI8HsyDVwrII8moBHA69b7oCGhHq8HsOe/CRai8rSae4GW7DNB
         pQIIcugJS24rtgeQaNNA+os/fpjuvWl7D9PlXEYGjQ4owL69MSHQVq8e6MGX84xF4kyI
         US2JC/SZFdGai+UfUsSkoKoOPfcSp+6wOeBenANZ2a8vyDYWytDX9t3WEy7l9HiJbfkE
         fWP0lqtAW7o2R5jO7zAiWfkIgj1oKOsz0w9VUgEs3DApgztKdUQZkEGFNDe1FOeuOcFl
         ooeISJFsnV43suhm4+dko0f+45y6l/lZNS5whS7MmFFB9xfB9RECCKonzseFmnmcuvzg
         lCsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
Received: from eu-smtp-delivery-151.mimecast.com (eu-smtp-delivery-151.mimecast.com. [185.58.86.151])
        by gmr-mx.google.com with ESMTPS id s7-20020a056512214700b004fe157ebc07si882086lfr.1.2023.08.15.02.58.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Aug 2023 02:58:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as permitted sender) client-ip=185.58.86.151;
Received: from AcuMS.aculab.com (156.67.243.121 [156.67.243.121]) by
 relay.mimecast.com with ESMTP with both STARTTLS and AUTH (version=TLSv1.2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 uk-mta-227-vdxOefj1NCKEtYViSq1POw-1; Tue, 15 Aug 2023 10:58:57 +0100
X-MC-Unique: vdxOefj1NCKEtYViSq1POw-1
Received: from AcuMS.Aculab.com (10.202.163.4) by AcuMS.aculab.com
 (10.202.163.4) with Microsoft SMTP Server (TLS) id 15.0.1497.48; Tue, 15 Aug
 2023 10:58:54 +0100
Received: from AcuMS.Aculab.com ([::1]) by AcuMS.aculab.com ([::1]) with mapi
 id 15.00.1497.048; Tue, 15 Aug 2023 10:58:54 +0100
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
Thread-Index: AQHZy2pYqz0YrpkIvk2kVFpZOdRD+K/rJqDQ
Date: Tue, 15 Aug 2023 09:58:54 +0000
Message-ID: <83824aca89a148bd861e8eccef54bf44@AcuMS.aculab.com>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-3-andriy.shevchenko@linux.intel.com>
 <ZNEHt564a8RCLWon@alley> <ZNEJQkDV81KHsJq/@smile.fi.intel.com>
 <ZNEJm3Mv0QqIv43y@smile.fi.intel.com> <ZNEKNWJGnksCNJnZ@smile.fi.intel.com>
 <ZNHjrW8y_FXfA7N_@alley> <ZNI5f+5Akd0nwssv@smile.fi.intel.com>
 <ZNScla_5FXc28k32@alley>
 <67ddbcec-b96f-582c-a38c-259234c3f301@rasmusvillemoes.dk>
In-Reply-To: <67ddbcec-b96f-582c-a38c-259234c3f301@rasmusvillemoes.dk>
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
 (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as
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
> Sent: 10 August 2023 10:09
...
> We really have to stop pretending it's ok to rely on header a.h
> automatically pulling in b.h, if a .c file actually uses something
> declared in b.h. [Of course, the reality is more complicated; e.g. we
> have many cases where one must include linux/foo.h, not asm/foo.h, but
> the actual declarations are in the appropriate arch-specific file.
> However, we should not rely on linux/bar.h pulling in linux/foo.h.]

IMHO (for what it matters) it would be better to focus on why
#include <cdev.h> pulls in around 350 other headers (look at
a .d file) that worry about moving a few files into a new
'leaf' header from somewhere that pretty much everything has
to include anyway.

	David

-
Registered Address Lakeside, Bramley Road, Mount Farm, Milton Keynes, MK1 1PT, UK
Registration No: 1397386 (Wales)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/83824aca89a148bd861e8eccef54bf44%40AcuMS.aculab.com.
