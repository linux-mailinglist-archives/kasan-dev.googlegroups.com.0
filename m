Return-Path: <kasan-dev+bncBCCMH5WKTMGRBYFU2W2AMGQE67RCCTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 837CC93191E
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jul 2024 19:20:34 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-70af58f79d1sf3435387b3a.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jul 2024 10:20:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721064033; cv=pass;
        d=google.com; s=arc-20160816;
        b=C79QKFuHflersinQPAw1KXskx/M91QeB7zUbEi8Mdy81YDEMVLZlCu+OmRMK+YasMf
         1qqxzlED+92ioaEVhyDi2/t+MfW0+FAYnnGIyLD2c/+9I7+mG4Pl1Yu75o4SOFB0diuU
         U8aunwNSiVpFojmw0u5JZUk9QUrsm7ns0sw7ulj3prFingSmgQdidk9UZtCzmSQgHmCO
         0MPyVc/2iYFgVtuBHMHsdEYcop9npjmFxEluKSBmRnL7TG4k8JMulY0KKRyZVaYHMlNk
         Kx5hz+2FgmKYEZqiW0IccmyfPNCngD4ygJgmEes7vCjPaE9L2y6IVrARUhnyRr7zOLDT
         viCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ns2eGHGA2nO2KIFZB9YZ/3c8xDKjy2rvGCxW4m1pqNM=;
        fh=EHVoBMinThvigT1y1CSQBxjW+eVutZHYe5I6bTdnz6U=;
        b=NrrogFFi3+WqnGigdGfEs58MdkCDoH6gxNrRhIPfdnd1Zwyi0NCINVCQZUCGuHh9WJ
         RUkKOwE3RsXWR13+rkyt/46+9J9BJNtWzfHx/U9KFcXrIKToLHxgFI1CcuyLlOM1xgfc
         jVjLDqUiEnvqgbhD/5zLNuthN6ZUDVq9P/82pMpjv9Bg7JSCOdZ3L9iCoarzhKg5FboW
         XgxmAzq9vgMt0ngA/FOceQsIbVC7Q7kxp8qX4ZS5bkame5jwaKd3USce+B0u2F5XHwZQ
         9Z8GhJJT8bTQxTb27R9ch+jA6qmiATc/m6cvlxGiruiu+rhYVedONs6zJrt15Az11Md8
         cg0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RYKwsT9+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721064033; x=1721668833; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ns2eGHGA2nO2KIFZB9YZ/3c8xDKjy2rvGCxW4m1pqNM=;
        b=qg19tyjsc8KuFstVOOqm1ZJTdst//3YB/v8D4lFfJleSDp76STOGPaINChW922mOgI
         ase+olu4NUpwDhs14eQviJwt6T08DoUaRO9eJKOY7zSWHNrQaqTwffRwSeOLtL3pUe1/
         q3KzmwuUS9dvNdSxawag3nGHICpoNa/nyV4BI84CeCpYywh3NSjWCHYXm1/6CBI4lj0g
         bbJtaglzCD9bYN87Ldcc0VbUg2kA83tZZontf6sUewqqtgKvoENojjr6Jh0FykHe5MY5
         CPX5az1oQRs2ysUCHFWKK/ZLQQKrT/BJeeRPxyiIAuEC145deVVQ97yPHI32ifyKMg+e
         RVpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721064033; x=1721668833;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Ns2eGHGA2nO2KIFZB9YZ/3c8xDKjy2rvGCxW4m1pqNM=;
        b=IOJIUL4+2oojvOM5T3NC/Lvgx3aLaKczNVJDXktu8nZy3dWrtUKNAkFyqZv6r3uFe6
         E2kJNywhU60dGIMfsb+yZWUVsXo0jwb6T71rPl13vHBug3chEGyHkIrVj+TGa4SdC04+
         EuIs1lg8fTxCGzUaVefdfW2Ng5Jq2gtMdQW46qmu8tHTIw4XWAu+vJiHUBTJGOxRaCRY
         4NsGNItJ3dWjNcnIFKhpagfEwTPp9ZvoOEy3Co7tH1ydF/U4NDXV4ZqiiFuXwU1Tiial
         UVdUMDVjLj6rwSHRZPLmJY2Cv1YXpnvIqH+FgEjlrjiAA4SP8+Ph58Y/5OugAVlv4B93
         /4zA==
X-Forwarded-Encrypted: i=2; AJvYcCUX6Jvbz/ampQZEhAxgo02BfUXaSgY7q5Vi6o4xq5mqKE11lqKe54idPDkfdJKfXZN9WHxRvQCrq6eVb4Y6HFRelM9sXFvVOQ==
X-Gm-Message-State: AOJu0YxndM1lpW1xm7lt8rS1XT8pAeWFbWappGEZ75PUP3RASD9KWXRr
	pfDkdEgJoLFDnO5uPAzbtwY6Dt5vAfBvfp8Uxjv6NvFkUZvfFFWE
X-Google-Smtp-Source: AGHT+IGZ7lZrz7rhTV18yc9Iidl8fBjf9Jn8aBfhb/+rZkB2P2EsgymHJSs9SmFOUByKanRjTa8fkw==
X-Received: by 2002:a05:6a21:3995:b0:1c3:b0b5:cbd1 with SMTP id adf61e73a8af0-1c3ee657806mr591008637.38.1721064032617;
        Mon, 15 Jul 2024 10:20:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:87:b0:2c9:69cd:716f with SMTP id 98e67ed59e1d1-2ca9ff558c1ls1928759a91.1.-pod-prod-09-us;
 Mon, 15 Jul 2024 10:20:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXZDjlByeOoukiQDsPkYOmzjDUDLeT4a/2EALw7KmAEisICXeqBdGrJKZ04i/jPjb7hYs9/e5htvfle57Itjh+ujTXjoIVmhLXTsw==
X-Received: by 2002:a17:902:da86:b0:1fb:e95:2993 with SMTP id d9443c01a7336-1fbb6ede194mr155456515ad.62.1721064031418;
        Mon, 15 Jul 2024 10:20:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721064031; cv=none;
        d=google.com; s=arc-20160816;
        b=dwVqIW9hGvJIZ295dGcsDMREBWfigV21ZVn+nfBJe7PgNolhG/XypotEh+hyVPVZJI
         8BHb7J25lWpclAkMjo0ViHEYxvt67cACkrWZo2Vd8IYNlLKRfL9J8kMXAu8O473Z3q6W
         mnR0wXwJl7C+wl2X7caPmfHhf+WdM/6e57FCqfW6JjD6pwgLmCnlT/Ppeg7MNKPb70at
         u+iCTZQXNiiuWhNTTZ5+GOZlQ1El9TKGcGsPk3SLr2F2G2h9Fg60OVt2tFAJ9EtLW7aQ
         5dcq2F6a70QPpY25EB1VACrDHus/DV8n2CQmrV+4VGNVB/PnDYhQOtF+LOkbu1H84AMH
         d7YQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=VqLbFBSLY2VQJjycHe2xsMNFC1xNLCGi7MCyaLlxLMo=;
        fh=3N4Ino7e+B4Ykq604c1RVrBArN1n0bcc7IS6oSNkCfk=;
        b=Rzfs7wdGZGwaFYHzerbAO316m01PFO+azQouZO+18b3e8QdZ8A67s/YZ4/oxvoRUle
         gXDGIhqZH/xYY2ncw0ex8tAwM7108scI8d6/NhcUD00/bwPSTn1TQOX/SPNupSNhFceY
         l5T1qaxdhLvTOnChSA371gK8/ugD49UU6fbtGZ89YXX9sMdhpr8/22xM3t7dU6JQrFQF
         loyGE8EAnS6ovth6KIxxkWGRLEhvXvIJHcevpN05bUOsq7DZTUKjXHIiVN0IUWHhvWYt
         kn0Ipffim2/wjG4QqMGNy3OtT7nMOR6GHC3PWUCRubVHxWEwzBYTFCdNu5N3gZRprSqi
         lIRQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RYKwsT9+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf31.google.com (mail-qv1-xf31.google.com. [2607:f8b0:4864:20::f31])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1fc0bc262c2si1917465ad.7.2024.07.15.10.20.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Jul 2024 10:20:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) client-ip=2607:f8b0:4864:20::f31;
Received: by mail-qv1-xf31.google.com with SMTP id 6a1803df08f44-6b5e6eded83so28415246d6.0
        for <kasan-dev@googlegroups.com>; Mon, 15 Jul 2024 10:20:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV5k3S3n1vQwa2rKF/tVqYa9H99QZwS9i6fF3V0mbtH97DFuNfY3yjFG+ruM+3L0TvTwk0+uhLx4iZ5h6Fh5oOjt0VwReyjsDMoLw==
X-Received: by 2002:ad4:5aaa:0:b0:6b0:77a8:f416 with SMTP id
 6a1803df08f44-6b77df284b1mr3820816d6.47.1721064030333; Mon, 15 Jul 2024
 10:20:30 -0700 (PDT)
MIME-Version: 1.0
References: <20240618064022.1990814-1-mawupeng1@huawei.com> <e66bb4c1-f1bc-4aeb-a413-fcdbb327e73f@huawei.com>
In-Reply-To: <e66bb4c1-f1bc-4aeb-a413-fcdbb327e73f@huawei.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 15 Jul 2024 19:19:49 +0200
Message-ID: <CAG_fn=VTKFDAx2JQAEur5cxkSwNze-SOqQRbqBGwDx96Xq-6nQ@mail.gmail.com>
Subject: Re: [Question] race during kasan_populate_vmalloc_pte
To: mawupeng <mawupeng1@huawei.com>
Cc: akpm@linux-foundation.org, ryabinin.a.a@gmail.com, andreyknvl@gmail.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=RYKwsT9+;       spf=pass
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

On Fri, Jul 12, 2024 at 4:08=E2=80=AFAM mawupeng <mawupeng1@huawei.com> wro=
te:
>
> Hi maintainers,
>
> kingly ping.
>
> On 2024/6/18 14:40, Wupeng Ma wrote:
> > Hi maintainers,
> >
> > During our testing, we discovered that kasan vmalloc may trigger a fals=
e
> > vmalloc-out-of-bounds warning due to a race between kasan_populate_vmal=
loc_pte
> > and kasan_depopulate_vmalloc_pte.
> >
> > cpu0                          cpu1                            cpu2
> >   kasan_populate_vmalloc_pte  kasan_populate_vmalloc_pte      kasan_dep=
opulate_vmalloc_pte
> >                                                               spin_unlo=
ck(&init_mm.page_table_lock);
> >   pte_none(ptep_get(ptep))
> >   // pte is valid here, return here
> >                                                               pte_clear=
(&init_mm, addr, ptep);
> >                               pte_none(ptep_get(ptep))
> >                               // pte is none here try alloc new pages
> >                                                               spin_lock=
(&init_mm.page_table_lock);
> > kasan_poison
> > // memset kasan shadow region to 0
> >                               page =3D __get_free_page(GFP_KERNEL);
> >                               __memset((void *)page, KASAN_VMALLOC_INVA=
LID, PAGE_SIZE);
> >                               pte =3D pfn_pte(PFN_DOWN(__pa(page)), PAG=
E_KERNEL);
> >                               spin_lock(&init_mm.page_table_lock);
> >                               set_pte_at(&init_mm, addr, ptep, pte);
> >                               spin_unlock(&init_mm.page_table_lock);
> >
> >
> > Since kasan shadow memory in cpu0 is set to 0xf0 which means it is not
> > initialized after the race in cpu1. Consequently, a false vmalloc-out-o=
f-bounds
> > warning is triggered when a user attempts to access this memory region.
> >
> > The root cause of this problem is the pte valid check at the start of
> > kasan_populate_vmalloc_pte should be removed since it is not protected =
by
> > page_table_lock. However, this may result in severe performance degrada=
tion
> > since pages will be frequently allocated and freed.
> >
> > Is there have any thoughts on how to solve this issue?
> >
> > Thank you.

I am going to take a closer look at this issue. Any chance you have a
reproducer for it?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVTKFDAx2JQAEur5cxkSwNze-SOqQRbqBGwDx96Xq-6nQ%40mail.gmai=
l.com.
