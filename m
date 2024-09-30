Return-Path: <kasan-dev+bncBCAJFDXE4QGBBO7I5G3QMGQEF4WABIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 431D4989EB3
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2024 11:49:49 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-37cd23c9226sf1594236f8f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2024 02:49:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727689789; cv=pass;
        d=google.com; s=arc-20240605;
        b=XR+K8Ij19YoLONNZzXcAoF7I9PmDrN/O7ZwUisanSemI6y3FkcUa5g6JcyUbmVySMi
         IeTmCC5lCXD45Y7P6tcfZwCVfWC1u152ftlXx1n1zWmd10lLbNDUfDPxZse3lOSjGAZR
         Ra8AW7ZHhCDzs+1O0xioNuE8VPtmBoOqa4eLLuoi5Abtt6xn/+S7QRP9Y2Nd5O285s6/
         UXyQNMUw2hhPobRI1lN7TTppYoWWNI/dea+H8Io/koM8JqqUVXPR43OT0mgTjy/OIkmL
         WSPEWk0D73t6NhwQcM/W49nsksSC4iwZva6jMStCdmm7JlPqmbLhEujxIoZX7zFkBw4V
         azww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=jlhTfmeZK7eksmW7jsup2fCuSSfOK7Bphpgd7xDmKA0=;
        fh=6ws/YuWRHR1TCBx4lGDpDVwHzQm+Dli+yAvaTlsb6bA=;
        b=Ocq0YTPBCUKEDZyrHdgj6pJxT/xhJSD2mgHL7MonsKiOyqehpZEGLZmXNXTVq01pqF
         LcjqPmUXJrgTzjimUGBDLe10R4oVSWtWwdfrfh64ivecC/rF3bsguvaJY/oPkm6PZNd4
         BWWZz8tDZX+v5hMe5pzgrM/kX/dp66GqNfn17OsKy62r81SBgq3QwSofpS/rjjPucX8D
         iAv2QqdJY3yI5cgnS/ioJqWa0BWrIS6rA4Epb8TenGRaXlIWXLRRdsTHcluTXeujdBz2
         HW99h67YGVqGMsO7ISW3/BKQ2TBp7xKADIIxyhfXsOacTwkW5uIrxKOwWnFypgJdOb7z
         Xsjg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Ck2nOBCN;
       spf=pass (google.com: domain of adrianhuang0701@gmail.com designates 2a00:1450:4864:20::635 as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727689789; x=1728294589; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=jlhTfmeZK7eksmW7jsup2fCuSSfOK7Bphpgd7xDmKA0=;
        b=oE4FauPpOAMB/b2BRCEWO/yn+yG97YbpElkY4LAY8XIC/a1SNTbJtB0uQiuD0tOG3e
         b8ym75jpwyJ1V6FCdStMhntPx4IRl5tCaLea2j60XIWI8pey8ZwYykHfeBo/XU00mfr0
         7EIfDd4LBJmLe9qkt83nfFZS7YyhOwjAJafAL9NBRpLqtjeIm121yUakOizSKFStms2W
         XAiIAj5Ew5732t6LNPZdoPxgTcwHr42GRjTf+Jiy1ICEWM5GnU/k/lua5syNxxZdv5/o
         Y+p8Onlnf6LUDXdhAG3ws8Wsp8QnbmqNJ28el2u8yJLRfjUdkXxKHX8N/UrtYKkN9iap
         Osjg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1727689789; x=1728294589; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jlhTfmeZK7eksmW7jsup2fCuSSfOK7Bphpgd7xDmKA0=;
        b=PFgkemZnLDb1qDbtZHN6vq7RqPr1mQ5kcxppAsu6oXJN9qaH/myV8xCRxPKytw5hG1
         g7hMpbp24zWZayyJvC65J9VBPc21cl9ixsEPpSe3aHaLKm1IjDSvsMaI46/i4FwSvxpv
         5ReFiNMq5PnCo8h3RR23Eh7nDHVow4f7fMS8Fp/yl3J5kXOHnreVU5EcedVEGITOzrL0
         F5/8cnlJfVxrFEU1kF3KGdTFbeTUbU47gl2idQVx6r3oNy1yW09md1TAhIk4r86ujexC
         fVJUV7pY9Sp49R7JInytru0ulGb2Z28RqCqkmzgI+W1NLm3RVVP4qLfPMGP5J1KjFD0U
         aVbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727689789; x=1728294589;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=jlhTfmeZK7eksmW7jsup2fCuSSfOK7Bphpgd7xDmKA0=;
        b=v9WEVRkjVDpUGDXSqC+OLcGVgx+MNNgQpdavH61OD7eneSEbFb1sG9LMXAyN803vvt
         +nl/AJnWtb1QJenVtpaWA14sBN2PGEIBFN+H2Ek1Y+R2WDQR5qKn3hYT/FTCpPYrj51M
         9fpRP8UM8N/4VED4SpKiWyDTPwK/psCjj90EJTPDfn0KmbYY2Nvxvu92A5/ZNLj3qpuR
         n+l65+cYKxZqYzfkmv+PqtUTmtgaLgYLqIUOzaNtiOHTv9tOYNpfzlU4kv6OLrGW0ZTS
         pHC3Z06jWBeCQKqrTAUQ6WwXiinsokt9/Y1p8loHFf1XjCGf/o2/46QzHF3HiAwhAFn2
         vHUA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU22T98V6VcCrntZbH5YBrzcvKw2myCQtHpCeyQn5PwtpmGo9o9+NNkzN4GJ/aaOmpFLnKtdg==@lfdr.de
X-Gm-Message-State: AOJu0YwYTN0xbzVn7v1hFc7g6CIdslSsPSmXbyuIR90SfO66I7nn3BIt
	+b4S6PgpClNGuNrtWqP9EnCS7axM16qdysL4XhVyg+9sn7b87bJW
X-Google-Smtp-Source: AGHT+IFlBdepR4xrGG9AQeTKbtufcANCfR6lAv+MVuv3mzTuLsHyD4DbvwwsM/jcQfqq+zSJRc1QiQ==
X-Received: by 2002:adf:e94c:0:b0:374:badf:3017 with SMTP id ffacd0b85a97d-37cd56fb8ecmr5597367f8f.33.1727689787908;
        Mon, 30 Sep 2024 02:49:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1090:b0:374:c124:db78 with SMTP id
 ffacd0b85a97d-37ccdb80ecbls263045f8f.1.-pod-prod-00-eu; Mon, 30 Sep 2024
 02:49:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWax73uOBlBBMJz69sSFASy6yFqty42WZaw3teXzeRg/yYm08WzegDddirVPzDYbBiq+Pu9BBoVgh0=@googlegroups.com
X-Received: by 2002:adf:fec1:0:b0:374:c692:42e2 with SMTP id ffacd0b85a97d-37ccdb126c6mr9352347f8f.9.1727689786198;
        Mon, 30 Sep 2024 02:49:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727689786; cv=none;
        d=google.com; s=arc-20240605;
        b=aEWEZYgzI31GwU2Jhk/9z/GHRzNx2xpm2ykHiXFywMjIOl9EXVIlFGrVNaz53rjOWK
         z6zJm2q/zHT1cG2kWiKyyDvl78l30qg5t4vBvHt3jlaNK51WEv6y18uDL8eTAi8Qhz0H
         4fG09wT9m2Gx9GUpTqLYwZ/y4BTYbrZUuuOUNfNSg7HZIMUieiV0XqkCk33rwM3PaZNw
         NoTFgXfBywgmqMEeBoB267dT9eDbHoIXCbNT766V+3h2FCeAHXzX/eS9BwxovzVRfUny
         fHWGyouhj2GDxYva/78sdpZv0jikblpaEF8Z5Sr8tAsxGw1Qd8YafABdsCn84sgOT0Zi
         7/3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=4Y8xzZhNdiTm4MfGV2ugvdzV/xOWaN3/MM1HAjacBWE=;
        fh=qG7+tWmLllME55In21eAaWr5nVvFc2KyFwgp3MD/Ymw=;
        b=Uso1ZQl5jKZ/mhSp0+DBn5tbdnVh8mYVGIcJNrwYFoVR1H90GY0sdqkHlVJqGdD8oE
         ssMuTRVp9YjAHmpMa5StOYTFnhzkgWHdkm4rMWkdGyHD9mIf9noKUw0fSWHYHQmJ54N4
         9ewvKkoqAlw1dEHW7O5cuWRSiYpj3/E9NmfU4cIraECbzF5CSS8LtuqQ62C46Cpq/8fa
         jMMikKXwFG3jSenzJ/lW6tiXEQynHJA9QAKi024i2duoUIw+aNtBjpTcXg+te0dVKObP
         0mO2/sMsE7X2909qpDXX77y26/ZP8NpUy9JXf4CXel1PitKduPODfmp7CAz9wWqq8Usg
         dJ5g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Ck2nOBCN;
       spf=pass (google.com: domain of adrianhuang0701@gmail.com designates 2a00:1450:4864:20::635 as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x635.google.com (mail-ej1-x635.google.com. [2a00:1450:4864:20::635])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42e9025c28dsi6285545e9.0.2024.09.30.02.49.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 30 Sep 2024 02:49:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of adrianhuang0701@gmail.com designates 2a00:1450:4864:20::635 as permitted sender) client-ip=2a00:1450:4864:20::635;
Received: by mail-ej1-x635.google.com with SMTP id a640c23a62f3a-a8a789c4fc5so890520366b.0
        for <kasan-dev@googlegroups.com>; Mon, 30 Sep 2024 02:49:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWQ5KOGacKMxCKRVyUhbEcBfd0pWhfPSI2ZIKk5a5A3oEhlri7N6P0FuBDA/lEgGoLhTrSh5u54GvM=@googlegroups.com
X-Received: by 2002:a17:907:6d25:b0:a91:1699:f8eb with SMTP id
 a640c23a62f3a-a93c320e687mr1288321266b.28.1727689785361; Mon, 30 Sep 2024
 02:49:45 -0700 (PDT)
MIME-Version: 1.0
References: <20240925134732.24431-1-ahuang12@lenovo.com> <20240925134706.2a0c2717a41a338d938581ff@linux-foundation.org>
 <CAHKZfL0D6UXvhuiq_GQgCwdKZAQ7CEkajJPpZJ40_e+ZfvHvcw@mail.gmail.com> <ZvWI9bnTgxrxw0Dk@pc636>
In-Reply-To: <ZvWI9bnTgxrxw0Dk@pc636>
From: Huang Adrian <adrianhuang0701@gmail.com>
Date: Mon, 30 Sep 2024 17:49:33 +0800
Message-ID: <CAHKZfL1jUs1Nh=aqnUrLLMiwb-F15kPc-fqC6i0hRaw0HbtMLw@mail.gmail.com>
Subject: Re: [PATCH 1/1] kasan, vmalloc: avoid lock contention when
 depopulating vmalloc
To: Uladzislau Rezki <urezki@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Adrian Huang <ahuang12@lenovo.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: AdrianHuang0701@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Ck2nOBCN;       spf=pass
 (google.com: domain of adrianhuang0701@gmail.com designates
 2a00:1450:4864:20::635 as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

Hello Uladzislau,

On Fri, Sep 27, 2024 at 12:16=E2=80=AFAM Uladzislau Rezki <urezki@gmail.com=
> wrote:
>
> Hello, Adrian!
>
> > > >
> > > > From: Adrian Huang <ahuang12@lenovo.com>
> > > > After re-visiting code path about setting the kasan ptep (pte point=
er),
> > > > it's unlikely that a kasan ptep is set and cleared simultaneously b=
y
> > > > different CPUs. So, use ptep_get_and_clear() to get rid of the spin=
lock
> > > > operation.
> > >
> > > "unlikely" isn't particularly comforting.  We'd prefer to never corru=
pt
> > > pte's!
> > >
> > > I'm suspecting we need a more thorough solution here.
> > >
> > > btw, for a lame fix, did you try moving the spin_lock() into
> > > kasan_release_vmalloc(), around the apply_to_existing_page_range()
> > > call?  That would at least reduce locking frequency a lot.  Some
> > > mitigation might be needed to avoid excessive hold times.
> >
> > I did try it before. That didn't help. In this case, each iteration in
> > kasan_release_vmalloc_node() only needs to clear one pte. However,
> > vn->purge_list is the long list under the heavy load: 128 cores (128
> > vmap_nodes) execute kasan_release_vmalloc_node() to clear the correspon=
ding
> > pte(s) while other cores allocate vmalloc space (populate the page tabl=
e
> > of the vmalloc address) and populate vmalloc shadow page table. Lots of
> > cores contend init_mm.page_table_lock.
> >
> > For a lame fix, adding cond_resched() in the loop of
> > kasan_release_vmalloc_node() is an option.
> >
> > Any suggestions and comments about this issue?
> >
> One question. Do you think that running a KASAN kernel and stressing
> the vmalloc allocator is an issue here? It is a debug kernel, which
> implies it is slow. Also, please note, the synthetic stress test is
> not a real workload, it is tighten in a hard loop to stress it as much
> as we can.

Totally agree.

> Can you trigger such splat using a real workload. For example running
> stress-ng --fork XXX or any different workload?

No, the issue could not be reproduced with stress-ng (over-weekend stress).

So, please ignore it. Sorry for the noise.

-- Adrian

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAHKZfL1jUs1Nh%3DaqnUrLLMiwb-F15kPc-fqC6i0hRaw0HbtMLw%40mail.gmai=
l.com.
