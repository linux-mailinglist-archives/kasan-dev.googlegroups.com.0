Return-Path: <kasan-dev+bncBCSL7B6LWYHBB3OOQSYQMGQEU3Q6KTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id A061F8A9C00
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Apr 2024 16:00:15 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2dbef696ebesf3831081fa.2
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Apr 2024 07:00:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713448815; cv=pass;
        d=google.com; s=arc-20160816;
        b=YslVomKOHiykIMmGYJSUglN15z0QBSqXxKW8QIqoQDahFfxRWybK2J75qGwgl8TlWD
         FCZDkOKVtnR+CgEVZZMniZnDaP6prR6G2/VqdtKXD75qksEKT65Kap8wmtLEBFFSSA5z
         9LysfC+kyoNffHuAM9dOc2fACMpxBm2xPcNgr9KU3Q3xUU72xJcZRVChly1/aG87cjAP
         t6B7vPbbTrf4fsGS1hcH/rjszNIAHxL8mTh27NHeDRGsJOKdvOgbq0pehcLMzNS3ndFd
         ua2zVsaAIgrozg8dwgZo6lBe7rOGmuGcOqbz99y2hPQ59CYQPNQkXe/noitrSy9iee5f
         F89Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=y1b0RRYTbvUJKz3QtvY07OIzw5Q7Rx6Wn5tNB8w4HXY=;
        fh=xs24zdqahVp3pnxqqGULbHp2qLpFp1OBbZgl6f2tjBQ=;
        b=wJ4zJOUv8G4KLP4wBGJ2ljcajquoalQ94oetIvPLq81qKxejzpk9SmgrH+Nm0+qElf
         qpGFHhFSJTqLK7X5BSxHcwaNEuFfi5b4ir68p3zWjJ2DiMRHDIKPq++o02U9AYIcJkvy
         kjhVL5FfCAJ2feh1UzVvfsE1fACa/POTEsm2LGH2pzti8CIloug+Saa7xH7n9jNjMa+E
         YjIHWJb5j/bgbgnD8GafM0NY/wuFJ1iSn6qUnIq/7UTiIWf0uMi8MZ9I8KvEuX8dBNDg
         LUp0LV9L967pMdh3VDIPH2M4E8l+YBEXw/Ovy3tpLopp8/vnuaYWu+N7ZIxToX/W258K
         sMZw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GAcaBzpr;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713448815; x=1714053615; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=y1b0RRYTbvUJKz3QtvY07OIzw5Q7Rx6Wn5tNB8w4HXY=;
        b=nrPJcCywjaVi/2vsCpuf6PVuqB0EIGpcajbDvpwlQ+6VBvVsc5JXRnECp7tOdOJ2H8
         ehZMESx+XZ70P4kX9MAZvA5jTZD39DWiqUvzOZKqzUxiePzDdXYsKHHUxzJZLG9/gOmk
         bFJPntOjHFvWppeFXmId9N6NCS6uREM6IVpC/ngQsQWwRb3Yn0ZX+mbFkywxCZsHgjAv
         9G+TVsgFvtad4ELpFb0mW/o0FW9GqQY6Uccbt5YwQmRoimzxv6RqtcgrW+SvzqVpLa6g
         2ql7XJP0yfreLNFcAa+BrjwyK7mFlA+5zTKZBuMM1KBdY9MbYnbF2P7+kmZ/gv1Pjr5B
         0ncA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1713448815; x=1714053615; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=y1b0RRYTbvUJKz3QtvY07OIzw5Q7Rx6Wn5tNB8w4HXY=;
        b=UGeZWcWWCjY/mKq6/ccK3xpaX/cS5mWkMdOPLDRUyhf0O7rxT6BulOIzAN9LiNSEV5
         oCoz0gkKFBns5L2KJGtK2FYBzS9SLeVyjr8Ke+KRet1FWCw57JHnSk+stzgbW87rSTPC
         nVFl+Gst5xeyXDIuEpfVgKf+rqoZBaJgA1lxWlGTmADnM+KGlbL3PIp2o0XoGBBN0yH6
         AYQWjn6EaH0p+bqE3qRvQSbJ7zqLhOwsgQ/3SR/CwaLbNEmeRorqvhSt7Um5n3+tVYQg
         WAc0kuSZ7Y6eqpv8IKG2mDiWFqMZ7VSQQBW9qL1Seot8X5iWj4QtPfCAY+p7C1WScZ8l
         AHLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713448815; x=1714053615;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=y1b0RRYTbvUJKz3QtvY07OIzw5Q7Rx6Wn5tNB8w4HXY=;
        b=sFB3MBa6vp+ONqJHnOOgj7cJcs/p9GopXOiEXUFLygNpOYnZ2mGkKSwFV2PEFMWYHy
         XpY8psh31mm+nKKtJKOOq2bUqF+g4B/C1+tic4S2goVnrwYiFlFXlY/MMYTCLF6dTCeK
         oRLa6Z5gvDRb6G0YDN9TJeAYQeWKrK5GqOWDyrsZy84ertVJiuL9f72q3W6qetuqmfkx
         GeMhMkdkPMeWKQXzgXrZTWO/q0DdKlwRYg1SJdOv7hg5l4NqK7GQcfvqSf3iLSbJS+8E
         2qLdDEWKKadZcye2hVWmNLU9mHQQsRj4N8QMkgm0eRCv50VvkyeM8gVIXS/YUH0YdaoY
         neyQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXbzb4VhfomMDOj7BoX74/9eGWYjxxL/c98doZDa/CyxuICxg8d2WXBWYW0V9KxWrFZbW45mYsuv6qw8AsDDT0caE7GJIiDWg==
X-Gm-Message-State: AOJu0YwootyohJE/Bw/UzzTQKDb8Mid4n6dBBuawFyfCMKnI2esDQKjv
	o3qD2ecLFpvZpj1wgjLJ/As44M0xZUHzEzAmK3zoKSRveR9SWfwX
X-Google-Smtp-Source: AGHT+IE5DlOPbf5fbpZv7i5sZVxl/2xC2qw0pqs3aVWxeYO9tRUD6ZqkyWm4xCg9iPQMZsF4D2USXg==
X-Received: by 2002:a2e:9346:0:b0:2d8:8368:e22d with SMTP id m6-20020a2e9346000000b002d88368e22dmr1492318ljh.42.1713448814122;
        Thu, 18 Apr 2024 07:00:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8919:0:b0:2dc:5d7:9d23 with SMTP id d25-20020a2e8919000000b002dc05d79d23ls78631lji.2.-pod-prod-06-eu;
 Thu, 18 Apr 2024 07:00:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUU50W+gI3qbGWSE9MRz7hAbowOh1QiOURovgOkd/wBciTG0GXR6+JtOaJ5Q1ZpKqCM4SfK0chKvjd11DTQ3B+aIgCfICbA+ATmoA==
X-Received: by 2002:a2e:910b:0:b0:2da:6f19:d359 with SMTP id m11-20020a2e910b000000b002da6f19d359mr1826028ljg.2.1713448811719;
        Thu, 18 Apr 2024 07:00:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713448811; cv=none;
        d=google.com; s=arc-20160816;
        b=SYPNjstT2fHVyLLr0wALe0cWtFwQ3XDVy6TM1C9rSy0EiyiMqx8hmIsiaA/sbyseUc
         9a76VsRUVVQFv+BS69omulmJ3w4Z6Um6oRZwPkSLBFgNI0ZasnMDv9d92K9DWyIYr8ur
         waU9OalyDq7edWN13VJ/yvFTzI1wmxP1hIuFDbsVFH3OyWtqtVDQYhYfanlQFqjpexI/
         X8iUwd95umhNZGhUzyPTXD6y+IdVlBhRlgBOz2NjgMslHoQEGXZ8Em/X6eM6jM21LcdF
         zqkef0qtlNq99cvZ2chvW/GwAT7dS0Z5c35DtaAxjPOPJ9n/WLevjExzLEf+4FNB/UzF
         9AMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=RrJobdf05VR55MPzvvqAhAZGqW+VKfpfsZCu1Cykk0o=;
        fh=V+yX8Mnw0DYvL93uMz0CAQ2eulIs2E8YpniWusavkoo=;
        b=J1Z2s13koKSRJTP6iCwl0QngozVdnDC1BMpoMUM8Ra8bBF0mfCDBR9/ZVC2/qXKEAN
         oBLqkfsdOTDP3luRNwfx9/yRROD6dXTtY9WOiBQkebzzfh39Qj8t70S9pa6MFtu9sty3
         VSOGCbb/6nIjj4HI/Q86F1b5v8yvKpOXTaT2iE8R2OkDHw7DLoP9/xHwT/kJ9Cz/ZwO3
         Ag9MFsXtW9UTtKg4urP7I59NVsEpLbMetiTFDwqLdfZ+HnftOmSyAf+kahZIhhAOrOKD
         zJSFq49HXqme/5h8YciNI51Pgb85cUdJqMFaqfQDJkJXiWQlEi/MmvjC/v883ImBZkci
         NkmQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GAcaBzpr;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x429.google.com (mail-wr1-x429.google.com. [2a00:1450:4864:20::429])
        by gmr-mx.google.com with ESMTPS id c19-20020a50d653000000b00571ba238acdsi73819edj.0.2024.04.18.07.00.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Apr 2024 07:00:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) client-ip=2a00:1450:4864:20::429;
Received: by mail-wr1-x429.google.com with SMTP id ffacd0b85a97d-346406a5fb9so686018f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 18 Apr 2024 07:00:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUl/Hw6xwhFp8Vnc0mHcxKpb4IM+LcrzEqb3j7FWqzXVl3QP79izPyeL7w3AkBxgBwXbQBuzIWTLFIy+1Xlutkuial+JC2/DTdsrA==
X-Received: by 2002:adf:e481:0:b0:349:cafd:a779 with SMTP id
 i1-20020adfe481000000b00349cafda779mr1555514wrm.68.1713448811029; Thu, 18 Apr
 2024 07:00:11 -0700 (PDT)
MIME-Version: 1.0
References: <ZiCp2ArgSzjGQZql@dread.disaster.area> <ZiDECInm854YiSPo@infradead.org>
In-Reply-To: <ZiDECInm854YiSPo@infradead.org>
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Date: Thu, 18 Apr 2024 15:58:52 +0200
Message-ID: <CAPAsAGxPEZYBCb30=an8yyku9zNZT74g3n4W_XFCRwLgg=9Xyw@mail.gmail.com>
Subject: Re: xfs : WARNING: possible circular locking dependency detected
To: Christoph Hellwig <hch@infradead.org>
Cc: Dave Chinner <david@fromorbit.com>, Xiubo Li <xiubli@redhat.com>, linux-xfs@vger.kernel.org, 
	chandan.babu@oracle.com, djwong@kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=GAcaBzpr;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::429
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
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

On Thu, Apr 18, 2024 at 8:56=E2=80=AFAM Christoph Hellwig <hch@infradead.or=
g> wrote:
>
> Adding the KASAN maintainer so that we actuall have a chane of
> fixing this instead of a rant that just gets lost on the xfs list..
>

Thanks.

> On Thu, Apr 18, 2024 at 03:04:24PM +1000, Dave Chinner wrote:
> > The only krealloc() in this path is:
> >
> >       new =3D krealloc(ifp->if_data, new_size,
> >                         GFP_KERNEL | __GFP_NOLOCKDEP | __GFP_NOFAIL);
> >
> > And it explicitly uses __GFP_NOLOCKDEP to tell lockdep not to warn
> > about this allocation because of this false positive situation.
> >
> > Oh. I've seen this before. This is a KASAN bug, and I'm pretty sure
> > I've posted a patch to fix it a fair while back that nobody seemed
> > to care about enough to review or merge it.
> >

Sorry, must have been my bad. I didn't find the actual patch though,
only proposed way to fix this bug:
https://lkml.kernel.org/r/%3C20230119045253.GI360264@dread.disaster.area%3E
So I'll cook patch and will send it shortly.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAPAsAGxPEZYBCb30%3Dan8yyku9zNZT74g3n4W_XFCRwLgg%3D9Xyw%40mail.gm=
ail.com.
