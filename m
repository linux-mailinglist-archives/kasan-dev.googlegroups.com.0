Return-Path: <kasan-dev+bncBCCMH5WKTMGRB25FYWZQMGQETF6SSKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 02C6A90C54B
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 11:27:10 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-2c2d89be34csf5780900a91.2
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 02:27:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718702828; cv=pass;
        d=google.com; s=arc-20160816;
        b=GUA3sez/VIFm46VP7lZk53X8ftEh1CncOyW8AWyQ20P3Yv3DAr5OQCwaWsNExScM76
         ZFwbl7n0/r9+fkAMgoE+f1g1CAS6rcY6Mzyyie39RpdhSM4Vwx/QETI4NoUr9uIE2Qtb
         FG2L8pZZiYByGk4QP/PuIUuD2/lS5IerjS5dAG6VtAYeNobFPoepqhJLJQnxX7RVwgFD
         wH9+p3ykUx9d5JtODSODx9RtmuoWSmyZ6hbZdgi3jtYFrnOQ+h4FWeJEJ+QJYJzBarwj
         jFD9+ndF/gpvruBZooPhTeZtWDOUBasKA4QkzAlhtA+lqoRO4U9X3IhakDKDroXBZ+wO
         GotA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bd7DhQ7gPbpykT3M0W+xSGLPO+kBkSU7B3yyb0oJx4o=;
        fh=8g29+nXyAQo8340rdIshmRRetgT8itLqKlu1BXE9NpY=;
        b=jLebQete/W2pfnLpCPtUNgF8sYTEicRzW1HhYf8Mba9Udgq+QiZ6hMKJwrJb94GVgP
         OGM6IMez/8NEBU30h/JKXnVOHQhnYFZPWWZyXI09f7mc19CWxyAI1pcWTCUeVjmUYGzV
         MK9UQBFTeMIDmqXw30gez3ZawE9G2IEzDAFCwm6CdITzAkZw+eh0Jvtn7FbrUYd1Kxy/
         QDVd/5zRKa39+AUgAlu8XAI1/6WG6b+NdlCz07xnyT69toofMqKIrdRvxcWa0GC1q28P
         4nF3a99nhRIJE59hKx8zHwLnyu/7PBtVunXlH+nt2vrqr7s/XK26dySSm4c7afi7MgCh
         80yA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nBPSPo3r;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718702828; x=1719307628; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bd7DhQ7gPbpykT3M0W+xSGLPO+kBkSU7B3yyb0oJx4o=;
        b=BPzi9y9o2PXoWbF3jEMQvy4ZgXlShs8npv1A4qEz68xFhaKyAzYx/uD8lf+IXdMrYU
         CfXSAFqHM2lPxrBuVtjITefYIKaK+T2lv5ACAvUUruNzIH2w/gkQ/Hztu6Bw37Bufqua
         QdHGxAYmciqoSwVqatKyWZoookHwd1QpuYRhh8aPcFnGrx0XW870cnGAXMLy1tFNS9e7
         eb307l+W2VadetYGGynVFF5h7VRfozrJQWbOzkXSRsFn/wxqZeU8/4QuAZ3GktyZAZmI
         jdhBHPGhJ3jfFhCHP9Ca1HiJBKUGtzdnOIM8+GBLwBEEo3iAZuPoP3/wzmGfjrvnnCwe
         7ZDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718702828; x=1719307628;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=bd7DhQ7gPbpykT3M0W+xSGLPO+kBkSU7B3yyb0oJx4o=;
        b=Dxft6moKs2Ak640LSXM/O1YCep/4TPDpGWR9qHw5Qd9cVQWdxSMkw2N7E6IhedmD4E
         QVrn/nlfQSuhq8Oa3SsaYjMoltxMQW7sOF3YCnzfkNA/jyey6XjHIwnjK5AT/OrWjDYP
         5Wtk4qLoPEQzSPJo28cfgoDjD/aKbwxN/J1RYFXpwy90TExkW946vEQUuhOGEijK5fDT
         W7Ey1WdHQO2MFH14Yc6YKuVc1PUW/xHI7M7cInXtKYhy7MUhrBShBX3XNotpXnoVlq8X
         74X7/6L4nasSOVElmQvJ/ZTZc9K8vLZ8luiFva3Hp+qMZcVXrEYgN1tDku/bgXg1lkzA
         xTgw==
X-Forwarded-Encrypted: i=2; AJvYcCXsJ9C0AdrKUOT9/2rUWB9G7BQzxzIiDZleyeWRYihpnZCWyHDsjKPVyjuNTPpLj/djczOYY7U226SUA7Z1ZLUm2rMBwMZaMQ==
X-Gm-Message-State: AOJu0YxC0ZEfjFom8/CQ/bmAmoNze9whzneu+LUE3DFeMOpSoI6Q5aIe
	8Ijnz7wovd3OTnRi6qYmGeQ83DJzxbrvOTMJUcTRWj4vfGD3xEYI
X-Google-Smtp-Source: AGHT+IHIupTTRGhtcN2D8Wt5JiV9m4Z2iVpAXnxPh+HUYLHSMVhNr5Be3v4+fimt/m9dw9qQYDelNQ==
X-Received: by 2002:a17:90a:bb82:b0:2c7:7e23:63d8 with SMTP id 98e67ed59e1d1-2c77e236567mr451816a91.44.1718702827875;
        Tue, 18 Jun 2024 02:27:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3508:b0:2c5:128e:23d with SMTP id
 98e67ed59e1d1-2c5128e043els1506054a91.2.-pod-prod-08-us; Tue, 18 Jun 2024
 02:27:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWQNAfmiV/2bG5zgm1GAu/wEkH9ly0J1hbqx39/gMiJfJ3CtTIeqpBXVK2mIrEuURCrNJu2tNqEK4hXFDLYC+VWy5RkZYnCistSow==
X-Received: by 2002:a17:90a:8c94:b0:2c2:f07d:8bae with SMTP id 98e67ed59e1d1-2c4dbd44f9dmr12068571a91.45.1718702826748;
        Tue, 18 Jun 2024 02:27:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718702826; cv=none;
        d=google.com; s=arc-20160816;
        b=rQwZXI7D7J7EwJ2Wph69CLrsuNivjKqz3MGNrh+kMyzkBPW1wC0/9SGmb4ZBKkEZbV
         YvLEgwBAD14D/xCuTjA0cHr2lhpeKyM8MKm/aX6TAuloOfKSfQhKvAAbt+GP6M44qLf/
         A598ZQARKaSSNr5PPOz3PZ0j3Ru649axGNhMB86YSfLDTBt6ZfweSr48P0Rev6DUrjYR
         na2fxqyw9s6E9jG9aiVmn60SFU21SUljBM7TuO5YMFg4j88m75dlUaN/Fb8DMUHwWB1R
         IXWGW/I8yWI99lzhdkkxMAy/NpY148t46lXh7Y9AdJ7caqzBAEUlHggZA5CqG2siZ4yZ
         QOww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=HgjCqFVtKavNFxLDu8aE6OS/1nGbyLOwVqAAdquKtbU=;
        fh=XZMrGRXL6wcfqHeA34xIs1lI+2PqFZBTWx28wDoaEN0=;
        b=x45HKbC8ax24PaJxV0QvQfxafGqh4cAdzVWT01Zd9NUtq2MJBtbBiGgm6yMQ12Te/J
         yF+eDC0o3MpI+ETfWl/M+QmA5tJ0v2tCPhUu0s59wUBsfNPvC/Mm0SC+ZywRD1GFjpiL
         pYJbD8XEYYMtOZC3ifFaNParj79QHHHoGt6J4ekKbvzYawsoKfRKjawXeTlOTqiB0u7R
         ScMbpIIOyqWsHzD2UnaRQ7+kFxRYJ9qNIwt424YyTKtHpJRKfhDC2kybDOuyyuUyeYeb
         dfwO1VPSrm8v/Sfe/MWh1OLGVGW4Z+tZAkKM49aLEehpTxyDHdVnl21IP/V6TWixcGhF
         NErQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nBPSPo3r;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf31.google.com (mail-qv1-xf31.google.com. [2607:f8b0:4864:20::f31])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c738b2270fsi83300a91.1.2024.06.18.02.27.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Jun 2024 02:27:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) client-ip=2607:f8b0:4864:20::f31;
Received: by mail-qv1-xf31.google.com with SMTP id 6a1803df08f44-6adc63c2ee0so20143356d6.3
        for <kasan-dev@googlegroups.com>; Tue, 18 Jun 2024 02:27:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVT0ECCElewVUFzhIt6qyIPdp5u11czXDisN5WC3k2LQ6ksxQ/UcSbNfsee0tQvPRPj0PzBT6KIiMjYTkCq2fRdJzu6R6mdZ0ddeQ==
X-Received: by 2002:a05:6214:1249:b0:6b2:cf8b:21db with SMTP id
 6a1803df08f44-6b2cf8b2252mr79472176d6.53.1718702825469; Tue, 18 Jun 2024
 02:27:05 -0700 (PDT)
MIME-Version: 1.0
References: <20240613153924.961511-1-iii@linux.ibm.com> <20240613153924.961511-27-iii@linux.ibm.com>
In-Reply-To: <20240613153924.961511-27-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 Jun 2024 11:26:29 +0200
Message-ID: <CAG_fn=VVGwxBUH=3HrVHhNs6AQFMqFgw7JDLqUFBTv13FOd5cQ@mail.gmail.com>
Subject: Re: [PATCH v4 26/35] s390/diag: Unpoison diag224() output buffer
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=nBPSPo3r;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Jun 13, 2024 at 5:40=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> Diagnose 224 stores 4k bytes, which currently cannot be deduced from
> the inline assembly constraints. This leads to KMSAN false positives.
>
> Fix the constraints by using a 4k-sized struct instead of a raw
> pointer. While at it, prettify them too.
>
> Suggested-by: Heiko Carstens <hca@linux.ibm.com>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVVGwxBUH%3D3HrVHhNs6AQFMqFgw7JDLqUFBTv13FOd5cQ%40mail.gm=
ail.com.
