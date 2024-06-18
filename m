Return-Path: <kasan-dev+bncBCCMH5WKTMGRBDVYY2ZQMGQELI2PEGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3218F90D57E
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 16:39:12 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-2c7a6c639bfsf389018a91.3
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 07:39:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718721551; cv=pass;
        d=google.com; s=arc-20160816;
        b=Uoi69yN9lKtbRi/y/7I7jFIzIbuEByDBT4vm72xgiEQvjqJnGsSdyzrtFhZxdvCHj/
         x7Q6Z8MoFG4J4qI0Q6akxMXVcqadGyMee8e6Xpmb2tWKB/BtscUrc2I46Jr42JCHivGN
         Zt/XxfUMJnrzrOZ0Ch9BtsqZJm4mTouWT0rwhuiA5BeTB9vJfdcbWi06G5OqWUctuApa
         MpKPnTMDu4ydG6mcob5N+mGW/qYIqhzemfWGeSW6Av+JjV4TyEWPza5MupGMDMztdufI
         D6Faou4cxrbL72gXcsKf9bd6zuuKJrGMx6JwaJCx7NXIt1BWeEmXvSMUd87QrklLVbDJ
         UJug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sSSSp+l0SaHehya7Y7V8Azq1Qt0TRDymYY8tG0w1Y7g=;
        fh=9CJX4nX7J/AHhsjVHuYoYPdJfU3Lc7Oc9/bQ8pJ6Ihs=;
        b=dF+RB7VGuZ1AsIIImgz62H/qClyCchlTLsRoLzCXO4A1g33PtFfvFQWDwHQ/+6dBjZ
         osRPv5eIWRMSVUnXqBucfI3p3oJwoJ5nyAWzW2xYrgRo1E45G3i7wI0t2PcpwSQHSjcj
         YZCBdGbTu34yujxeHDWZYFHXK0Y7bTCAFb8g2OPlYv78wdZstSK60CVGkyfiGb9kiEPl
         442ejiHRqTocdNGluZkaLTuvAw6c6xKEJXYlRYZP7duYMUTsILB/Z0ccDj0vxnOUb4g6
         JRUOeMmSQrNcIfBpNtEx9v8f94Up7FBtFLfybEEqbR+3awdImeCPiFGzY9c8vzcDPpmU
         HNNA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Oz+UvyhU;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::332 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718721551; x=1719326351; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sSSSp+l0SaHehya7Y7V8Azq1Qt0TRDymYY8tG0w1Y7g=;
        b=qDhUCX5+IJ0JFTf0hpxkB/HYXEZZCXTAvRE/UqrKDiNFf2P+hVJ3WRNryBhbBE1MsL
         eUk0rMPpjmQ+vzTHnHwFdQk1S3PgKV8iaQY+cXAsGXWcBs6dbrk+SqbyqAaBi3IlcKwj
         TrXG/gh4kdUdFSgfAiyha5/5lPEb6tjRS0qrC0rTDUDzJRclbuoMoB4w7WvlQV2qe7zY
         QdeWR2yOlkVIkd98mPzuQ6N+Ka3qogTqTF3yVWZVI3b1D0Zz14i/OnAwGRIuNw9WXte1
         DE5fLPSirqw4KS9c0127P0/tGHIL52EmGegFGuha3kxMI+73N3d45d0/fxXJlN1dOYNw
         fYIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718721551; x=1719326351;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=sSSSp+l0SaHehya7Y7V8Azq1Qt0TRDymYY8tG0w1Y7g=;
        b=IzrwJ/8BhsWMOcwYrwXAch8wPrFDUWELgQD41WOh7xxfm598zeSzxdPtONT6qxZ3j4
         +a2g3EvjmNxG48ptwI9YOqIBf08k2G1nx2Z05U1khaaWxyY1M3cfBaEkWY76VRCkCoDd
         VQSRIqTqp4RcSehMStEEvJz6DdbEMWpFt3Dl2XQ9QB9+BdxvzkQWAqtQo8l6+B3QGli9
         HUszq5xKRtKQ1OQs6UcxctKLh4EvR0YN3lUK5MaqS1uQ1/T+Zj6JDNqUElJl+zI49geL
         q72WtLSM1pZ1MBijqg8RptC1uvpkDHWUeX8Kt7WFh5cBsdeR1uZvFWkgHIUNiavDRFMp
         xmvw==
X-Forwarded-Encrypted: i=2; AJvYcCUXXHNFL/trvM7TwlHOKuMgvYmXYP41iI1WDYQGha6mQ3yrg5zQcr5Hf8/5nCZDMSX9/gPD0sliHXfLnShGDvfkp/bz7PH/+A==
X-Gm-Message-State: AOJu0YyRKAhKBeBMXo24fpVONrS5CtHD92KVETvCUZ4vLzXJARioxsp/
	Dg6LHCrrgUbMadCr6RPQJR5UEpvHEl5jquvq5lB7L/aL85B10JFE
X-Google-Smtp-Source: AGHT+IFpSumhpwd0S6o5GfvtwbZCrUKOrZ3jLb8NoSiuDIvTlLnhQG0LF5qXADAXcCfPGYbqk0MC0A==
X-Received: by 2002:a17:90a:148:b0:2c7:7718:a9e3 with SMTP id 98e67ed59e1d1-2c77718aa70mr1203327a91.3.1718721550579;
        Tue, 18 Jun 2024 07:39:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d34c:b0:2c2:e876:1da6 with SMTP id
 98e67ed59e1d1-2c4bdbc0a78ls3335318a91.0.-pod-prod-03-us; Tue, 18 Jun 2024
 07:39:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX+PEGA7Ne/P2cAevjEFYEgT2m9PjweHCaeeU//sf17bO0Lyk185NzNAiX1qwJTWETd6iktza64Ypr7vh3XFxcm3jaUcgRYOZ6AjA==
X-Received: by 2002:a17:90a:7e82:b0:2c2:dee9:d922 with SMTP id 98e67ed59e1d1-2c4dbd37f96mr12947140a91.42.1718721549342;
        Tue, 18 Jun 2024 07:39:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718721549; cv=none;
        d=google.com; s=arc-20160816;
        b=t5UOfHal67dvaFtF4eu6WEsdA2N7UckDSREc3+8p85wg/+i3QYwGiTDczj2zBRauqk
         13wM+feFJatIfAdG/X/5oLqr3I1ajd3cUVWI07Qre7orwwU6DPTAv+a3GI6SHE8PQALB
         IPbwY2pbKK6NmjE5mkeNGBU1sP004GLQDWp2wrnNQJaXf0gcgrgVfbZ6xa3q0I+RSf5y
         tatnOLr2wQT5S3/5Yk3sehHWg/vS5rO9P+diE182xd9lhN4JQDTtBaQyf87lZbbepU28
         AMlP6MxyNuzIiST+EhtBoPQ9LrwXGiDE7iycd9UYd4f1630fRG1A68zeIbp2SqxtcvbY
         zn7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dBK+Ndw0Vot1wf/eS0eqhW75oHUr4im8qRpkAfEJRNo=;
        fh=U2amOziIozeHP04QksSbDSYPKrdKIejQZvOfffjPy+o=;
        b=U9lkWqV5tkpsMxLlDjTxke12MNszzgz4Vvc+gqnxWh9/H0Gq0PUI594BTuKAYUs5xY
         7TrAl6SL3rqQAFq3G5YNN9tFlm2Xz1QtGW2S2xFnTw0UQjmy9+rQ9zTpvQ3Yx4qxkUB1
         IqWTUxhLV8dPXVWIc5PrVOGkjrv3+Zidi8MA7tgZilqd9HppexQqOCv0t5CUPebEjRss
         9ceRLKNizz0mOgxuhxe9zxGJH+dDkwqlq9PkLRQ7GG1nFhDABJgB68SViCbQ2Stop/15
         O6DNFQWTCniFs0irMYCAGpk6EnhcVizlhtj2DUmeox2Q+6XswxozWFO6W8QP54x4dGhU
         kiDw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Oz+UvyhU;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::332 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x332.google.com (mail-ot1-x332.google.com. [2607:f8b0:4864:20::332])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c4c44fd729si553256a91.0.2024.06.18.07.39.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Jun 2024 07:39:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::332 as permitted sender) client-ip=2607:f8b0:4864:20::332;
Received: by mail-ot1-x332.google.com with SMTP id 46e09a7af769-6f9b4d69f53so2952300a34.0
        for <kasan-dev@googlegroups.com>; Tue, 18 Jun 2024 07:39:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXq0zAy3PQueMKEG4ffhz8z0A5Pd1zTShRFjLbwO78y8DxnHyJ3QgpUOlrb3TTedgD1+oXusPC4gZl4nyW2XD/dfEi0UbxdegryaQ==
X-Received: by 2002:a05:6830:1d8f:b0:6f9:6e0d:dfaf with SMTP id
 46e09a7af769-6fb93b08befmr13854300a34.26.1718721548293; Tue, 18 Jun 2024
 07:39:08 -0700 (PDT)
MIME-Version: 1.0
References: <20240613153924.961511-1-iii@linux.ibm.com> <20240613153924.961511-17-iii@linux.ibm.com>
In-Reply-To: <20240613153924.961511-17-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 Jun 2024 16:38:31 +0200
Message-ID: <CAG_fn=Uyx7ijj-igC2hgSpdzmChM0FVy46HTRXyKzNAA0OFK7A@mail.gmail.com>
Subject: Re: [PATCH v4 16/35] mm: slub: Unpoison the memchr_inv() return value
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
 header.i=@google.com header.s=20230601 header.b=Oz+UvyhU;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::332 as
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

On Thu, Jun 13, 2024 at 5:39=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> Even though the KMSAN warnings generated by memchr_inv() are suppressed
> by metadata_access_enable(), its return value may still be poisoned.
>
> The reason is that the last iteration of memchr_inv() returns
> `*start !=3D value ? start : NULL`, where *start is poisoned. Because of
> this, somewhat counterintuitively, the shadow value computed by
> visitSelectInst() is equal to `(uintptr_t)start`.
>
> The intention behind guarding memchr_inv() behind
> metadata_access_enable() is to touch poisoned metadata without
> triggering KMSAN, so unpoison its return value.

What do you think about applying __no_kmsan_checks to these functions inste=
ad?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUyx7ijj-igC2hgSpdzmChM0FVy46HTRXyKzNAA0OFK7A%40mail.gmai=
l.com.
