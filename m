Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7H3XS2QMGQEZAF7DKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id A4E32946D6D
	for <lists+kasan-dev@lfdr.de>; Sun,  4 Aug 2024 10:38:22 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-25e950d4899sf13474595fac.1
        for <lists+kasan-dev@lfdr.de>; Sun, 04 Aug 2024 01:38:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722760701; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qnk8T8UGOdsWT0KG4G6XyYL9O57NY7p83qbp0c4EW8B/VeGHFxUJza8B3kCBAVEo5N
         JI5bcKXcMd55YAGQ/swsS8XB7c2k2hQjxPfxEgNBCa5L+MUIeRFOrVh0gmrf3fEQgD/j
         mTymMU6+CLtYJJxtHOaltxlHgu2ASIw4WkhKt/bLzeZrJ3b5kG2hCi2vGvO3HRrf3Jn2
         J3R9b8jusHfp13zK1F49RVhKtV8thFzoPjVs1N+HSpFXjnkRTp5rpUTWGGWIdsEZXXPW
         3AgZ15UfxjqZ+IOY7ErFZKw0zGKFSe0XVtK0TC0S8JjA6m9/I4gmRu6vyWkm1KpoEhYb
         lJcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2kuVfnDGWMIEGmgxtqfPQIlJx7CD0/6cRuuSGZnsOZE=;
        fh=CaP5ul2spMx4SNjryQwnmlG5ZAIGp8yS9p1Oiph5j70=;
        b=w/oXV6IknQOgtTcF/N3Gvq5J5AGaLagElRPNAzu0cQH5pKDfoWBEtzmKDXyT/1oraW
         uTPzduW2i2nuPeyP+/wWw6vPp46s5fzf8EBt6wTL/96AxOOLo2o97uIPFJKMHiu00hzf
         0q8cr1KDzXMYgb2wtrTRhdJvFd0YXemvyRuosm6/H1xdALMvHjKMelI4dyzTPZ82+/ux
         /m+Qe0Uch6PrXBehOxbK6m+R+HZ2Xr5am77YyIpovT+ygSxyMRbhkr3HvLY9VUTKOCLp
         /WNQJTD6lvaOxMzDjMjO7QV/SVSOoyd8zuipPzaaQpM4fCyrnZDdtr610krdn8u38z12
         ogaQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=n4n7Q6PP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722760701; x=1723365501; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2kuVfnDGWMIEGmgxtqfPQIlJx7CD0/6cRuuSGZnsOZE=;
        b=kx7MPs9LtznnwTj4vj7ZgrU1qJw66zT/RjYm7ZIYnQef+A+pj5v4726YCNAJQxsLQS
         u2UO9SGV1+dbFqW96I4JSC+tSO6lK/3xEMEMKLGj4/rvoREAlY+K0slfBMOdSJqwhnrv
         ljXDcJLqwoizQqi3y/mS3++gMRgGoZTgAULImHMxadCRpHfQNwS+6nwA6WtkVHMM5sCG
         C/f619q7yfH86XR0Sij86mDHq/oxMNtGKviCsULho2dtf0aGpSZNAlhHLt6iB9NH6FH5
         Usnxa8n3MM7hjkjeojGF/h0Ex1RRZGgbixIlJj2csGbwXTCSh4DuOlUW/OOvg3gWCOXu
         dAdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722760701; x=1723365501;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2kuVfnDGWMIEGmgxtqfPQIlJx7CD0/6cRuuSGZnsOZE=;
        b=TFU82A3jjOQtBhQGGtfknE8EE/rCZxB/WXkJc4OqatxGjWh31UIJZGTAZWyPmwC76A
         mkJvrZnbi0rER1AOZh65ubF31pWp0dGpWlblC+SR+zE5PEZCqrDTjQ3khY7P9tyU6yIh
         YdCn6ayWzhvHavMNRyMliz+mrBv1oxwiFLDCPK/eeLSN17yk2x1tZW99+thl+kUu7OrW
         GDV1qU2BV7pyQyUC33o27FqTTFEDLe4AEEy8xUouCfARidTw5iXKPW1fxaAAGkmhQj7Q
         goZI1HRv4l3HfU7pd4XQG/K5dG7xW8adnWBqDxpwHi4gAz4pdIkBHYz3ezuZYN4oQS4W
         +I7w==
X-Forwarded-Encrypted: i=2; AJvYcCVfpD2Nt1MSZkeCTjDia4j/80U7E9TueqQM1QdyosOCYOc6NPxsHjb6oOmoU1QaselyIzXgnRZgdd+OGre2aJcxB+qV1U6u5g==
X-Gm-Message-State: AOJu0YxsMUHW9eQ9x9TQmRZ8sSSH9rOq3TcUUiZYeiURymhw05yJPfBd
	wPelS6l6a31M6W1BvUeEkpLA4CnlnC0eqcSbOIyBiX2HxOZWf/Xt
X-Google-Smtp-Source: AGHT+IH5zLMZEUWHq/U64n7ethLBC2EjregRvfBI5SvWhQ7pZtX64+J/cljLVQT3YnNQnaOC67XDlw==
X-Received: by 2002:a05:6871:7988:b0:260:f058:48eb with SMTP id 586e51a60fabf-26891b29e73mr10017612fac.20.1722760700933;
        Sun, 04 Aug 2024 01:38:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:e88:b0:260:e534:4f13 with SMTP id
 586e51a60fabf-268ae007d8els1947848fac.1.-pod-prod-01-us; Sun, 04 Aug 2024
 01:38:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVSKEniFiYZe/q/KedKONe0urTT/VXN1VrUEgsahd4DcdPddtiplN90pYncKh47Oe2KQhQ3X3ynCwk8hrCcePL/VmFT6I7H75iOig==
X-Received: by 2002:a05:6870:a552:b0:25e:fb:af8c with SMTP id 586e51a60fabf-26891b0e0c4mr11410225fac.18.1722760700163;
        Sun, 04 Aug 2024 01:38:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722760700; cv=none;
        d=google.com; s=arc-20160816;
        b=rV9f0Gk4qnF/rWw7q4U4sTGFW9lLNps7+hUENFxILTGu5Td8NhaCSf3YS6QKIRbzYt
         cMG7tW9gpnHlWv2rCtGzl5uUhUHYlg0PKmC4640uSB+jvGWs6WB649+XnNuuQe+VB1SS
         AgUZqn4HLoVosyINEnK4nwpg9/xRA/N6ghWq/AEEz9+4RoSZwR5b4gQsNulFk9XlwKu8
         TK6tfKUEL1irJUyRpFuyI9XsmQW3i0cXQYE8OKX9jSD4ceam5f9crFr2RTvx+kogGkjL
         +EPwkRTTC7+0ZubfKOZHgSkXdN+94HgTMdtc4RewlhSUl4AaCBuNV8F9w8xCqfER4TSY
         FBuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/Y1DLbxzKJLluxdE6YPNo/iiR8s6T9dilcizg++ekz4=;
        fh=RIDR33+9GZQowEe8zPBgXLJAXPZU1+ii8aHMLUmJOnI=;
        b=ihH1EWeKVfJh8f+V4nWrYUnHSStayRfkSJhnra/hnXkTtj54FPuFc7AFHQeejBPqIi
         GSqvEIZfNiRgeEocSAXT9d1lqDIOGlb+gwEOq8YXKVqD/JP2EgUdGc4w92BGMT3HPrJS
         937/JUWusFJiijhzFutF/OhvoOLQ+cnzFuQ56WG7e21Nxs0Cz96clGRfu2xUBInyLjAF
         CXxs5M3sDX/SXEsVBQKsT68wvvTw2Hd40dCXZZdLkD68cRYHM4eo2/FV3AQ/he1Rh9nJ
         Y6/68nMScz2CxDxKnuVuyIU2tUNmvd3Bt8AnoKtO1cOHlhPvI0Q1+GmwFIKXmx7Ol/kD
         o4bg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=n4n7Q6PP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-vs1-xe2d.google.com (mail-vs1-xe2d.google.com. [2607:f8b0:4864:20::e2d])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2689a6326c7si236859fac.3.2024.08.04.01.38.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 04 Aug 2024 01:38:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2d as permitted sender) client-ip=2607:f8b0:4864:20::e2d;
Received: by mail-vs1-xe2d.google.com with SMTP id ada2fe7eead31-492959b906eso2555858137.0
        for <kasan-dev@googlegroups.com>; Sun, 04 Aug 2024 01:38:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWXayPmb+MY/LwNYjD+2mk4ENM8jRXHm5eUJLSKZIuIjjUk5kGyygygv7KiawWsqhVvESQjuCCdWuXucI6y/GyPuv29tJe1/qdw0A==
X-Received: by 2002:a05:6102:50aa:b0:493:b2b4:3708 with SMTP id
 ada2fe7eead31-4945bf02c0dmr10323828137.27.1722760699323; Sun, 04 Aug 2024
 01:38:19 -0700 (PDT)
MIME-Version: 1.0
References: <20240803133608.2124-1-chenqiwu@xiaomi.com> <CANpmjNNf8n=x+TnsSQ=kDMpDmmFevYdLrB2R0WMtZiirAUX=JA@mail.gmail.com>
 <20240804034607.GA11291@rlk>
In-Reply-To: <20240804034607.GA11291@rlk>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sun, 4 Aug 2024 10:37:43 +0200
Message-ID: <CANpmjNPN7yeD-x_m+nt_bsL0Cczg4RnoRWGxPKqg-N5GdmBjZA@mail.gmail.com>
Subject: Re: [PATCH] mm: kfence: print the age time for alloacted objectes to
 trace memleak
To: chenqiwu <qiwuchen55@gmail.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=n4n7Q6PP;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Sun, 4 Aug 2024 at 05:46, chenqiwu <qiwuchen55@gmail.com> wrote:
[...]
> > I've found myself trying to figure out the elapsed time since the
> > allocation or free, based on the current timestamp.
> >
> > So something that would be more helpful is if you just change the
> > printed line for all alloc and free stack infos to say something like:
> >
> >     seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus (%lu.%06lus ago):\n",
> >
> > So rather than saying this info is the "age", we just say the elapsed
> > time. That generalizes this bit of info, and it'll be available for
> > both alloc and free stacks.
> >
> > Does that work for you?
> >
> It does not work for me actually, since it's unintuitive to figure out memory leaks

The number printed is the same. It's just the change of "age" to "ago".

> by the elapsed time of allocated stacks when inspect /sys/kernel/debug/kfence/objects.
> It's unnecessary to print the elapsed time of allocated stacks for the objects in KFENCE_OBJECT_FREED
> state. For the elapsed time of free stacks, it seems no available scenarion currently.
> BTW, The change from "age" to "ago" is okay to me!

Well, what I'm saying, having this info also for FREED objects on the
free stack can be useful in some debugging scenarios when you get a
use-after-free, and you want to know the elapsed time since the free
happened. I have done this calculation manually before, which is why I
suggested it. Maybe it's not useful for you for finding leaks, but
that's just one usecase.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPN7yeD-x_m%2Bnt_bsL0Cczg4RnoRWGxPKqg-N5GdmBjZA%40mail.gmail.com.
