Return-Path: <kasan-dev+bncBDW2JDUY5AORBR7DT23AMGQETU72IJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 78CA495C06A
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Aug 2024 23:46:49 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-3718eb22836sf703530f8f.3
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Aug 2024 14:46:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724363209; cv=pass;
        d=google.com; s=arc-20240605;
        b=I0PIf2AbzQKRUbOJEDmS449FiKmEuxXT+z2iJhIEgR9LJAkb2QN+yfYANqLpUtXfMN
         BFKVDODKjmxjUlm0yQ0WzaW+ONbnWQY8J6T6vW9XcMrNaBIcKnyn7GQfqY80jrKybPM0
         B6z6R6LSJAS5/e6Ik4bS8ciTkktLuUuApQJ2RbQM3JG4ItCpIRkzF2VIRq7PehZKcclQ
         MURSkkI+QYr3U/FNBDWM5ibTDHFsFKfuT9XOMGCGXbeeL9sHawzrNWCy1mfAFIqtou90
         VFKI0DJY5Gb8BxH0M9/Gd1YWfVYBAiQuwcCj+c7Fk9r8pmoz8xUa67L34CBdXwgbOg/l
         Tkpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=TXhftUHs4dQTh93j2E80UuNaYPuTTnxycy04m/tToGc=;
        fh=wfRTPB86wAERoYH8YGpuW2VuAVtXtDUGVLngZjbh2sk=;
        b=TFzrDY/dIVQWHDKXhLagXWCh9PWGlKA1fZhAbcv+najno5QeLWB7BmEQxpv0PHRTHc
         aymhzjr0BAuP75CN+4zOrv+2uFy0hSR7EmlQu5t1uN1Edix5C0clhvs9CeNXYiJdfuZu
         qYehs6GsRtLxNOn2/PCIeQSCYI1zo6mGfPY+HIftUXYLnk7JbkofdImdNKQTN1MkMlmc
         G92vJsdUUhj32YDKKYw90G50ARijMzlbv6O7N5+DUN7SxVTFLiQwHl4y5Brju0TQIIgF
         zvM70vnaIy5kXX990SgWiVcOCVhuuphE1RCf2JXpYe2ZEcEWFlr2JP+HD8KR1lFhnw/p
         unww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=H15A1Pso;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724363209; x=1724968009; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=TXhftUHs4dQTh93j2E80UuNaYPuTTnxycy04m/tToGc=;
        b=BtgvCJ3LsiS6xMBeAYzGEN+zQvmWPggsTHBykFFIod7OHIY3jvrwOQOxfMzeFDQeeb
         6HziMv4jQ/xC3xmQN4uSEbtZ+PcsCotanlrnIHKaw4u4sjsWnlEVzxjWD86WUbbafAIp
         1RJtOnd6Fwckz6lLKCsKcvchvPVwH10nvAwWX7rOtSUha4TBNNJl7Br2e36xl9F0QChp
         23HYertE38l/h+XLv3SdoWFYQVHZUINWKC6ZLBl4ysO2vod2EOtxwCulxwiW1VVPs9Wh
         x4lZn3y8AfYzLEgwUJi8S+5iCetPCrl7GCq7vb2eVgq8P4VaYSkOnXSmy91bqZQeUZUx
         golA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1724363209; x=1724968009; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TXhftUHs4dQTh93j2E80UuNaYPuTTnxycy04m/tToGc=;
        b=i4Gh63d6p6sz0KcX1JUKUQWssXitLDAC2nEZY2vaFUz/v8fsM1r6ht7zDwYMCudxNn
         xuvO7mPMf2SwLuZZcxlAs56TRaasVHwGZP/tjUS74dIyyy1rLp2iqgA4MJqwkfMYBy4/
         1qv+AZ7Hw/EvpRdM917KPRK1j8IM35e3XvGlgJr6ZGSvMj9kn36q834yVqxENJm3XdKj
         yLqQv5Yas0NVZbtsBhCHWNfO4YheOIUpEtAmheyy1b5fQN1d2SfjVQkMYcqcUIxJjd6X
         AjHEyDXEB7E8p7mJ0y3Skd31/CVirgElQ2HbJhoMwclUN+4yjsWDqyGqNDF3uRsthbkp
         YgeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724363209; x=1724968009;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=TXhftUHs4dQTh93j2E80UuNaYPuTTnxycy04m/tToGc=;
        b=jUfon4nZ5rhg8zy3J8UwcysWv3M0Q5gBSboIVxPZhfoIjGHb7nWHuRMR9kIIOesuF2
         TdRW9Px+XbQwgjOCuD8Og5bteU+TWBcUtjNeZjS6hO73tQnRfZU3jtPBdtTzKozNUNcP
         CNDBaHkkz4QhlbW/sxl4cJUBmwTcbDRlO8Tup5gaVlykZoN2A/1BKJgYE0EnJmFIlr7H
         SZr66Kd4cBH65JBI6D5VB6qTh+WHyMfa05LgrEGjjVTcl8ox0fiXqS+mdWFpQiW8kPaI
         7t60R7+u4/J6ICtc6mJ35YgrP6F1LLZLTB3CAgLAv9ywzrfoa8Z43bupnaZSGkmXkPAl
         OkjQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUGVxDNqpt4tQ8Nbc7fw9zr7x2fcEmIKZsCAb5mKfEXMRwSteGtaR0VzbdKBMz8hjT4UHZ3sg==@lfdr.de
X-Gm-Message-State: AOJu0YzhJS4aO3ed7Rfpz09v+vf0uL+t8prfCN5TmZycZ273lODsWPpZ
	WNYF+y8qAUH5MyfJe6xmy1yHj9Sq0BBL3rJ2u1VZETsJeiV3acZU
X-Google-Smtp-Source: AGHT+IHkpkQ1kuZ/2Iyc3SzbfkpwTXam2IKdXFa49GylcNIqf0vbNfmhWQVjQd9WEAupjo1tuILKcw==
X-Received: by 2002:a5d:4a08:0:b0:371:8bc4:4f with SMTP id ffacd0b85a97d-373118e2fc6mr68855f8f.51.1724363208081;
        Thu, 22 Aug 2024 14:46:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c85:b0:426:6eba:e1f4 with SMTP id
 5b1f17b1804b1-42ac3c0c1edls6990805e9.0.-pod-prod-02-eu; Thu, 22 Aug 2024
 14:46:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXvFow/QVoHX+vONHkD22SMBfRptCG7YTHmZehMID62Yyh/XbnETkXmt7mQzehXMVEnnwslxRKovWw=@googlegroups.com
X-Received: by 2002:adf:e8c1:0:b0:371:844f:e0c with SMTP id ffacd0b85a97d-37311840fefmr75134f8f.10.1724363206082;
        Thu, 22 Aug 2024 14:46:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724363206; cv=none;
        d=google.com; s=arc-20160816;
        b=g2m/XEvm+M9K2KlqE/qmeyKjCczxLYeEgJkb6XlJHnTTHAHUECrUmmsDAHOE3zXBhz
         XvYC4DkIfkBRByxS8vlyagEGPOx3aBpnceJgfD0a9ivKQgdbv0jvb6yU9Dx6RWHWaquG
         GI06+0iKCmauj8R4FLjt4Yt9oR4Pq4uezkDUUdWglsnzYKEKHbvUMWZOEBsKYYewbNIf
         X8F3zq1ssK2QFD2MLTV/a5xhGO7G5cM6llnxbczkRkiJSDTJb18dJV/CbOfTM/JRN6oQ
         3TbwaH90FvZqfCH3z0uHitMOcfCx1+Y7xcfOtLY9IQe5POXr+dnpBMxfMG3c/qWBn1zM
         B9RA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=2ObMnDIQZlaNLUtvENvNnRW6RrF/I2xgEC9S7H+saKg=;
        fh=7/wSf+PgeX36rQlTmfKk+r8e4Cn5b9rVo7bR6Rt6f8g=;
        b=oPPYdxJrkGw78Qv02qUaonzhvYLoE9S5sXsY+dUZgQQSL2cZ6HheVPqkESwr9y+g81
         K4c2Zg7nEKF+DGJzF/62R4Lo29Fi1gnkiKaxl/9XcnZSNXIoZh40Vv2SGwQgY1zmYdgy
         LpDCnH1ZoBSvbCFq/J62ljfClQyrdfzlDUPdfTNS2bFa324/RzVWGj7i/UaWBuoYz8IM
         Rt+jslbmfiJzCUj5kJ8bPUpt60mS8neeUyvXpJFTVvdKruFNcN8gGMg1lVAgh3mvRwgC
         LzDvGC4A7S+fxZXEPGi+wAIPbWWleUMsfzqBM2zsbzea+jtT5VZhpWuaB4B1RL62i3qS
         tOxw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=H15A1Pso;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3730827d2d3si51281f8f.4.2024.08.22.14.46.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Aug 2024 14:46:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id 5b1f17b1804b1-42ab97465c8so9334155e9.1
        for <kasan-dev@googlegroups.com>; Thu, 22 Aug 2024 14:46:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUYes5Cvt3n+o2eLswadRRW4vUf5+eIIXvOOcWBUGuQgW+390sVBKxaQ71vEWkpR+ma7thCBnuLo38=@googlegroups.com
X-Received: by 2002:a5d:63cc:0:b0:371:7c71:9ab2 with SMTP id
 ffacd0b85a97d-373118e2f0fmr82331f8f.52.1724363205185; Thu, 22 Aug 2024
 14:46:45 -0700 (PDT)
MIME-Version: 1.0
References: <20240814161052.10374-1-andrey.konovalov@linux.dev> <CANpmjNM7p8-U1eh7m4vCh5M7pKODHExzw0EVtOXQRu-udb7qaA@mail.gmail.com>
In-Reply-To: <CANpmjNM7p8-U1eh7m4vCh5M7pKODHExzw0EVtOXQRu-udb7qaA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 22 Aug 2024 23:46:34 +0200
Message-ID: <CA+fCnZegmsUGgnwqtvJKyz9QxHHquGEwGbUKwQDo63srsJao5A@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: simplify and clarify Makefile
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Matthew Maurer <mmaurer@google.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=H15A1Pso;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Thu, Aug 22, 2024 at 3:49=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> On Wed, 14 Aug 2024 at 18:11, <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@gmail.com>
> >
> > When KASAN support was being added to the Linux kernel, GCC did not yet
> > support all of the KASAN-related compiler options. Thus, the KASAN
> > Makefile had to probe the compiler for supported options.
> >
> > Nowadays, the Linux kernel GCC version requirement is 5.1+, and thus we
> > don't need the probing of the -fasan-shadow-offset parameter: it exists=
 in
> > all 5.1+ GCCs.
> >
> > Simplify the KASAN Makefile to drop CFLAGS_KASAN_MINIMAL.
> >
> > Also add a few more comments and unify the indentation.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
>
> Acked-by: Marco Elver <elver@google.com>
>
> Just in case, did you test SW and HW tags modes as well?

HW_TAGS doesn't rely on Makefile.kasan, and for SW_TAGS, this change
is a no-op. But I did just test them just in case - everything works.
Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZegmsUGgnwqtvJKyz9QxHHquGEwGbUKwQDo63srsJao5A%40mail.gmai=
l.com.
