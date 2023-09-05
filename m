Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHVK3WTQMGQEHBNQYAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id C512F792563
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Sep 2023 18:19:44 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-52a0f5f74d7sf1959075a12.3
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Sep 2023 09:19:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693930784; cv=pass;
        d=google.com; s=arc-20160816;
        b=MvfcVP67rE6+HxwYm8aEexR0DLpduR7G3hZwFKfiX9cn7xpBZYyDEUSphKF5EtlEsV
         tsNl04Gut8sSia7RT+OW5yIuNLroXErvwkBS92d1Z06nVBiFLULatrxoCEsuiDwyKf6D
         VPT14iu3v36n53vvJQLrpickzl9maDMWd6yqnQAfjzJnqkL8VO07IDhiYXOZS1kiHPaB
         1g7kG+kLD2xuAOg2TU2Rlj7/9GYQl3JNG9ECigvOxlG0fsB6s2mX3snPMbR1rJ35klWe
         7nrKhPbPN6A9uxYD3nr2aUopHxQVcs69VNqNZIbHvAFs4sR3CES7FRJIhxrP85/hDzUb
         x8Hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NGTUOA0Ix1+JGPE0fG60EUJTIJnfVQO0Zt0DooCcyYQ=;
        fh=naLu8b6QNpG3IRa1Sc3pZqeweD+Iq6yOG07UuX+EVok=;
        b=wSlyZXeYMBUX/6va2a5Cve9M4RoUS8mTly+qdRasjBaQpHlEVLVnS/e+zMybmT6RZ0
         StpYr8NbVQCEikQZpBFX8H2Vx0/kCw3FBoxrLpYVxb0RmUnE/iz0ifN5n+VMZyL5cSBy
         VEzPeuAYT1BEcYCDOS9Z+2AVLsLqphSgLGbgbT5MNDVpp9siLjfznbAXtp5HhB5diUXW
         yn8mxw2JyXvkybNZ6kgp5RAfNMkT6U5uFRtcT6UD4WfV4LRQpq+fZKw7geR3OyHLycLv
         hbCLC7xdtDMZkP+ejwd6ZrlP1Zd8diaI2VzxekRY8c0IkB2ZbtYA58RBuuaynjHOCJfk
         hl1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=pYzZyI53;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693930784; x=1694535584; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NGTUOA0Ix1+JGPE0fG60EUJTIJnfVQO0Zt0DooCcyYQ=;
        b=gqPbKBzTo1Hmih7onFFDTGiMRdFYCbGgm0wKsVLfyyY8QMXoDfwfqb1xtHicMzkTHL
         oLbin5qXcMJjhPFmPD+/tvEPkoNJDlFwGQ8BQUpPkIQQuMd9rkpq6rKR/brGJyI9aXP9
         C+WfFj62vLL8xEqJkxWb3sDsOtfLfUqA6cetFEHDcZcJnQWzw/WdKi8B9HWLR2YXRjj/
         4W9SWaaiqkNjEqxWbLEf2Mq9cZWn08QYE6IdRKkJ1Gf3vjLlCLyVpnBtqHiCRu+OGuWH
         ZZV0/6GqBI8Efa2S2AxnCMO4KQvh27YLSR+AnPp/lRDqloOietM/Z8YYJmPQ32TufL5Y
         h25g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693930784; x=1694535584;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NGTUOA0Ix1+JGPE0fG60EUJTIJnfVQO0Zt0DooCcyYQ=;
        b=C7w0z79feOa3izQIugar7dkW9ZvuKr7sSWmqRMFEeM7yL+WTEziclYb90rT1AdQ9lY
         5ETTRcOAb9rcRHNKD8cjXOOSZQKfQyyDGU3gKcyDG/9w5hjrJSvWWSe6BwBQju1C1t06
         +UuEyqHrBDAzapTURhpiIxumeQDmVwXI8WGTojGgtw1WHIziuUvtjEL6HWflXAsj1sgg
         5LjGW4fiIszMGV7lh4UKwh2m260SGUH1qy12fu63kdzfUejIKxHSDcgzCuoNuhLRWfbb
         o+PVr6kx9NKq8LhooVPDJh96lq6XM06SZ+1KRDvERewzqSJnTdJXr2xOiGszxRk/g5J0
         QBLQ==
X-Gm-Message-State: AOJu0YzQFBQ4fl4s31SeK7BC/mQw4CEvBYplQk5pYRbG0/2eQr7y4ZpJ
	tWlUEOJWNRumcmpJ0ri5sJE=
X-Google-Smtp-Source: AGHT+IEHoEdmPEjYz087VhZmqun6zzUnkYp48YWnXXegx7yChgIyYI1ffaKnvE0w1AxLdqkUgCVM+w==
X-Received: by 2002:a05:6402:12d7:b0:522:1d1d:1de8 with SMTP id k23-20020a05640212d700b005221d1d1de8mr251736edx.2.1693930783004;
        Tue, 05 Sep 2023 09:19:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:f02:b0:52e:21c2:719 with SMTP id
 i2-20020a0564020f0200b0052e21c20719ls1294797eda.0.-pod-prod-04-eu; Tue, 05
 Sep 2023 09:19:41 -0700 (PDT)
X-Received: by 2002:aa7:d1cb:0:b0:52b:d169:b377 with SMTP id g11-20020aa7d1cb000000b0052bd169b377mr229613edp.6.1693930781143;
        Tue, 05 Sep 2023 09:19:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693930781; cv=none;
        d=google.com; s=arc-20160816;
        b=xQ8Uk4B+Ig2Vukcnw2eaiiEs/+UJFvJC6Hn9wlfTECXjmMgpkxbAVj5VrKIHdgDoK1
         7nIdvE6ZkKZ6X6poIgdfymOjjU5Y9VbhXZAVrsdpFllKYxV7UT6mhGzFm26oC3TJ5+gS
         UYTrabk6XA7CVf8t0w7RaVYewEw70d0mHNY6H9iAvchUdkU7xekSCvlyNaMD9g0l397j
         xl1EnRQ6uMkWxYQ70pfeecIErLiQRehdYEjThFER8zo+hmYI1uiSwc1Zswdb+arciYjL
         HB2mIJTW1wRnIZNDz4Lb4KuRJNnZrBPOUb3G4veCRK2cbxdH5tYcCq+yF5OMBorfCn0p
         VEQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=p6oY7/OBmfJxk+eRddlxtREgaCt+NRSSuVpUhmBP/Wg=;
        fh=naLu8b6QNpG3IRa1Sc3pZqeweD+Iq6yOG07UuX+EVok=;
        b=GPKtWg7jS2Ds9TNCKlWhYo6pVDYCBuoeN/Wo2n4gf0N+DPrQbAJiPqEaZCRijEdijn
         H+UFMzH00n0PcWabXc3WeLQ+vfHk3jucKBQ3QQ0OrFk+1JgvB3RzK2o2iZzJllm5cDnv
         LaE/I6l44tJxy8Doa5ag68VehbqOOQFngvR0RZTVJ4upfmVrrYIGxhKhnNcJhGoTSzXt
         3SVIvxu+Q+2RgE0k6P1UIFdJHnE61RsqkCNORVSy7eQCFf844c149EPi/TFp1cLHjL5O
         rxY/w5EnWmu9fiqpNGPOwNlm3tn5g/955v5Ai97ZJiSXG6OGXVzAMTEFR6/RXD7omqaa
         EG7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=pYzZyI53;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id dm16-20020a05640222d000b0052c584e82aasi774014edb.1.2023.09.05.09.19.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Sep 2023 09:19:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id 5b1f17b1804b1-402cc6b8bedso23506395e9.1
        for <kasan-dev@googlegroups.com>; Tue, 05 Sep 2023 09:19:41 -0700 (PDT)
X-Received: by 2002:a05:600c:128f:b0:3fe:4cbc:c345 with SMTP id
 t15-20020a05600c128f00b003fe4cbcc345mr162850wmd.41.1693930780661; Tue, 05 Sep
 2023 09:19:40 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1693328501.git.andreyknvl@google.com> <6db160185d3bd9b3312da4ccc073adcdac58709e.1693328501.git.andreyknvl@google.com>
 <ZO8IMysDIT7XnN9Z@elver.google.com> <CA+fCnZdLi3g999PeBWf36Z3RB1ObHyZDR_xS0kwJWm6fNUqSrA@mail.gmail.com>
In-Reply-To: <CA+fCnZdLi3g999PeBWf36Z3RB1ObHyZDR_xS0kwJWm6fNUqSrA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 Sep 2023 18:19:04 +0200
Message-ID: <CANpmjNNtT1WUpJu_n5x_tA2sL4+utP0a6oGUzqrU5JuEu3mowg@mail.gmail.com>
Subject: Re: [PATCH 11/15] stackdepot: use read/write lock
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=pYzZyI53;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Mon, 4 Sept 2023 at 20:46, Andrey Konovalov <andreyknvl@gmail.com> wrote=
:
>
> On Wed, Aug 30, 2023 at 11:13=E2=80=AFAM Marco Elver <elver@google.com> w=
rote:
> >
> > > -static int new_pool_required =3D 1;
> > > +static bool new_pool_required =3D true;
> > > +/* Lock that protects the variables above. */
> > > +static DEFINE_RWLOCK(pool_rwlock);
> >
> > Despite this being a rwlock, it'll introduce tons of (cache) contention
> > for the common case (stack depot entry exists).
> >
> > If creating new stack depot entries is only common during "warm-up" and
> > then becomes exceedingly rare, I think a percpu-rwsem (read-lock is a
> > CPU-local access, but write-locking is expensive) may be preferable.
>
> Good suggestion. I propose that we keep the rwlock for now, and I'll
> check whether the performance is better with percpu-rwsem once I get
> to implementing and testing the performance changes. I'll also check
> whether percpu-rwsem makes sense for stack ring in tag-based KASAN
> modes.

I think it's quite obvious that the percpu-rwsem is better. A simple
experiment is to measure the ratio of stackdepot hits vs misses. If
the ratio is obviously skewed towards hits, then I'd just go with the
percpu-rwsem.

The performance benefit may not be measurable if you use a small system.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNNtT1WUpJu_n5x_tA2sL4%2ButP0a6oGUzqrU5JuEu3mowg%40mail.gmai=
l.com.
