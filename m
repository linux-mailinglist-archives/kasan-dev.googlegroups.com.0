Return-Path: <kasan-dev+bncBDW2JDUY5AORBK6M3CTQMGQEGC66FHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id E0BDA791D60
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Sep 2023 20:47:08 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-34bbda33121sf9700255ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Sep 2023 11:47:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693853227; cv=pass;
        d=google.com; s=arc-20160816;
        b=kmOzzuK/AQseRFsZ7vWOWt4a9SouXXKcG3JctsBXDiRBZ+3hEu3sz0o0VEVyNnFHAX
         UM4jkbgCU9Jinqa5Pjlzc26S/xZGfWEelmjP5yQqGJA2tMXyjPLWJ/W8gT21USk4Qcpr
         I+KvWLOUFqB7srJhxBnj4IqHPmpB7Da7lI2nNdz93spG52lfwsJ8rU5HisL+oPxNfphw
         9z2Mr1lw14LqKhFH8vyTcBul3RS01An6o+03N1zqn9smJF6TDRUMnTR0zAydt1yth2zG
         EjRcePX1jAaZgyiUOm59avVVlknVJLuxvisKXnSEpDs/1UGjPB1lELDeQH64bM9H9hcp
         hTVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=+0sBlGMyTSciaXE5ey+eo+W/mxVHXBhQWhYftcVSB+0=;
        fh=EkQQo0mnqQaYvPndBUmDdLhkxIkyTtDAkl55p7TcvuQ=;
        b=gIirViQapEA80nEqNOk8SJikh2ZZ6zwc8QKKrhGjUoUTN1xWJkgH0+MzPqtqjobVUw
         bt4fcJMq+TSgOdajEZ8Gb2M8eLDvcd+pQtxdVHo7ToO2mcMsB1zT9zmwHn4pX/ugxOur
         yiUfO++BQo0oG+8eZvhdHdNFqAIkerYi38PxlowiUcmc7GWBgvExKIs6XL6oOXTg2Vde
         oiBXPdKfkN4shV4bYmOhlI7PPDXvu+hMpvfd4ThMrEZl1oIIQGtlecIfK7uRTO+aDVJ1
         v9D8I+sUuuYYpQzcIoSBhwYjtTjFgbziX3Xtplr8M563pSM5X/gOlIQrOYuvuq9z1hq0
         RVDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=sD2KY+Ap;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::233 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693853227; x=1694458027; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+0sBlGMyTSciaXE5ey+eo+W/mxVHXBhQWhYftcVSB+0=;
        b=pE9nRbMRaDcM6/96Iyq1vvZP3eryN0Q2OhiHsw+bn2pnf2+vHkdy4JSt1RbYgUKwil
         +d7uzWptRZQSAZAtvwc+uq9FuQ3hLIrv0LT2C7+4bwpQLbZ7p5e92kAvCr2noru5e64k
         ZCg8NUrgoROxCXQ4NecA7ik2clstiw8352Y0x4VtqZKyHxOffyZjo2cV7jvfRmfk1lAD
         XwM7v5TmEFwHKfU0/Oo/OipDrtUBhfKIzscK9wqQUY5x23+Z8aJRwufXFa+uhI0o0+E0
         BNqX3pVSyyEX+3k86hE8tD5lKpIn5JFbrnv+s9IYCuetRV2AI5X5mISrESKFIN5b/CjI
         X2Sw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1693853227; x=1694458027; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+0sBlGMyTSciaXE5ey+eo+W/mxVHXBhQWhYftcVSB+0=;
        b=pomIy9kmi8BUQJCYEp3/izLIGSbFCKF8dYvGxCp42/NE1ym3/ZR9ksDmUFzxo0d1bx
         Y1HhWV4M22KGIIZ778JPuke8PFNXbaq0SV9bxrN9+KVRqZS0+ZUweLgzhmr+GkrusIAk
         GgsgupcEbpNpMcFjXWWU/5YQODXwkN85M+z+mm4Jj2ipMJDIK1wlKXIGXncKHuFwDr3i
         1KraGicFW6MmtIpYFZWL6YaMYJDb0zRxZxqeVUpvRDGds91Qox3NIsiE+KayJ4MQscfx
         ujYE6Q2PfC0MOqS03s10UWAZ+25vEn3uyLASlyjsftHFO2zdD4hixcIap1yhDVQIXYiT
         1Mkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693853227; x=1694458027;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+0sBlGMyTSciaXE5ey+eo+W/mxVHXBhQWhYftcVSB+0=;
        b=hDGmXZyFjd5YbXiQn8szsw73WUkSg3f1lvdNW7u2muk5dhyGtJ5plvMVKV2Er4b2Or
         dPq1Pq+hjc0efcuzIyIPJq0QJ7LKaZIb+eJLwOW2fx6iXH/f1o/O6ccV2mXHP88W5QL/
         dJW6WbcJlclAEOpsDP8xnrMQ/+5WylUv3GXmb05R4FUJKwxaxkUEfZ+1T8khntO6dc6c
         /dsZQSq0aoYuKS/G8E4ab83kFDFKw7qvJ/uqahAGxI/6VvXEVi+qFq2MyAalN1O6lUim
         Il510bFrsTYKCxQJwJl+h55LW3b1X8Weq+cded8XquB2MukX2ZhaxfRLENuYryk2XWmh
         KABw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxhT27+r0QmUMAUnqB/Q9kenlcix8TraSrsiZOu5THV5WSxVq15
	Y7pBouFw0PSAsP5lISGNTK0=
X-Google-Smtp-Source: AGHT+IHbFkcri8hnmT26kJCFcI8d22bAJtz6gN9mE0rjaRyljZ9Q9xbz5rrYu9tOPtpG9l7uVJwZmw==
X-Received: by 2002:a92:c5ab:0:b0:34b:abfe:25c7 with SMTP id r11-20020a92c5ab000000b0034babfe25c7mr11541056ilt.22.1693853227461;
        Mon, 04 Sep 2023 11:47:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:b312:0:b0:349:b8b:c2c5 with SMTP id p18-20020a92b312000000b003490b8bc2c5ls2003367ilh.2.-pod-prod-05-us;
 Mon, 04 Sep 2023 11:47:06 -0700 (PDT)
X-Received: by 2002:a92:c94d:0:b0:349:8bd3:b5c4 with SMTP id i13-20020a92c94d000000b003498bd3b5c4mr11900911ilq.5.1693853226813;
        Mon, 04 Sep 2023 11:47:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693853226; cv=none;
        d=google.com; s=arc-20160816;
        b=NlweL6gbqd7MFiCTBWb935isP9y/oacsQ1C1oXQTAKZaq90Zm9Ax7gbjXz+F5fs8dv
         lISRyINbSyMz94WB6NIGHlvbtLhgPB2WCH20zaOenUh8UqDXLq89jbg759hb4YUSdR1H
         q2qzkEGJsnYfSEEMiWqROABG/jX/m95MN4V6liAQbGQ1XbCtK2WkYfjOnXuOYxbGzq6t
         IXXOJbEU8hwYc3gli2ZZKQql1C9avellTCSHmJI8E7UmlDQlYDM5OC4nyrdwrY9PwjSE
         uXRg1IDFpJAaRERDNLQjmkeBF/1d0kl/ts+YilCqpnygLn/39Hx44Uu+e51FOKUxCpL+
         BLGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=oaTRr5UMKxcVsZRJAV9XvJRS8SqRW/bF8mzq2cA6680=;
        fh=EkQQo0mnqQaYvPndBUmDdLhkxIkyTtDAkl55p7TcvuQ=;
        b=OgmVS+NCa/OOsXZz7J4GhqT2ny6vl37YJm/AhctFq5UPKCQ8cRWNuotykdQS2Ygh9g
         FdcKKqGUz7NbbD7Qfg7AJjbaaAuFadI6WxVD3Ism2f1DSGl9yjq97Da42CY+m/B1VyjI
         me3ASPAv2p/AZZU7xWcBXqKJlEc91yOA32VbnFxqnbZ2HoP0Eupy14T7+XiNqXno4yCT
         8y5WAKTkDGb6jmHYEKL7ErpmsapS4BZjOB3WWIk34ntNd3eaHaHy+ksAd9R/cIyJbYK5
         MqipkIRG7Pz2okTVD2LANCsHCB7Y2cjWhRG9tRYZM0UfQfmLL8uQwqKQknQf1+zaKqGn
         LJ3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=sD2KY+Ap;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::233 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oi1-x233.google.com (mail-oi1-x233.google.com. [2607:f8b0:4864:20::233])
        by gmr-mx.google.com with ESMTPS id h5-20020a92c265000000b00349a5e508b7si972044ild.0.2023.09.04.11.47.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Sep 2023 11:47:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::233 as permitted sender) client-ip=2607:f8b0:4864:20::233;
Received: by mail-oi1-x233.google.com with SMTP id 5614622812f47-3a76d882080so1397194b6e.2
        for <kasan-dev@googlegroups.com>; Mon, 04 Sep 2023 11:47:06 -0700 (PDT)
X-Received: by 2002:a05:6808:14c7:b0:3a9:c2d6:41ef with SMTP id
 f7-20020a05680814c700b003a9c2d641efmr14490048oiw.43.1693853226412; Mon, 04
 Sep 2023 11:47:06 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1693328501.git.andreyknvl@google.com> <306aeddcd3c01f432d308043c382669e5f63b395.1693328501.git.andreyknvl@google.com>
 <bb2f8a4f90432452822326b927e8cab58665cd09.camel@mediatek.com>
In-Reply-To: <bb2f8a4f90432452822326b927e8cab58665cd09.camel@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 4 Sep 2023 20:46:55 +0200
Message-ID: <CA+fCnZc-3_bDaSaa0u-EYfkvP=580bYMiHRtm99=XRypRCVXDA@mail.gmail.com>
Subject: Re: [PATCH 12/15] stackdepot: add refcount for records
To: =?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?= <Kuan-Ying.Lee@mediatek.com>
Cc: "glider@google.com" <glider@google.com>, "elver@google.com" <elver@google.com>, 
	"andrey.konovalov@linux.dev" <andrey.konovalov@linux.dev>, 
	"andreyknvl@google.com" <andreyknvl@google.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>, 
	"vbabka@suse.cz" <vbabka@suse.cz>, "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	"dvyukov@google.com" <dvyukov@google.com>, 
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>, "eugenis@google.com" <eugenis@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=sD2KY+Ap;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::233
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

On Fri, Sep 1, 2023 at 3:06=E2=80=AFPM 'Kuan-Ying Lee (=E6=9D=8E=E5=86=A0=
=E7=A9=8E)' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> > @@ -452,6 +455,7 @@ depot_stack_handle_t __stack_depot_save(unsigned
> > long *entries,
> >       /* Fast path: look the stack trace up without full locking. */
> >       found =3D find_stack(*bucket, entries, nr_entries, hash);
> >       if (found) {
> > +             refcount_inc(&found->count);
> >               read_unlock_irqrestore(&pool_rwlock, flags);
> >               goto exit;
> >       }
>
> Hi Andrey,
>
> There are two find_stack() function calls in __stack_depot_save().
>
> Maybe we need to add refcount_inc() for both two find_stack()?

Indeed, good catch! Will fix in v2.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZc-3_bDaSaa0u-EYfkvP%3D580bYMiHRtm99%3DXRypRCVXDA%40mail.=
gmail.com.
