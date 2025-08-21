Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBPEIT3CQMGQEXPE46MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id D8097B305FC
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:40:30 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-32505dbe23fsf537474a91.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:40:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755808829; cv=pass;
        d=google.com; s=arc-20240605;
        b=RLeM78z9oimtD0Hdz6jeDFZanwjt+WIyEkNW+aYToVKrVvwtOrdUMX2nSqjwhfD1Ij
         p7qGnc+64b8DMh4q+/wrIXA4ZVox8xqoq4XsJ6d3QORxlJBwtNgwztssUKFZPfByWkaZ
         4AgJC+zD6c8X/uGAUIZPX1YdFqewxQ7f4Vm/VBKuQwyM2PZ1vXF4Q8KppO/ZdR0aW/7L
         HocSoDQD5bbwmEf3XPNTbsflUCNyb5kjjfQHZGLdGfvxaBpRXrYA2V5au3lhoZx1G0DR
         ZBgnYczJuW9hWDCEufQzmW//RHAIVyQ9n2MVIfJVPl9IOU8YNRQSPfagi2H4aUMhX9s4
         OJbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=dNnMK9YP5c1s2PI1JtXiO6rMv5zpfre1KIjxRvokvrg=;
        fh=T7evRhMxZknVE5Ty/X8FkGaZf2yfB36RWAq/Z35X2aU=;
        b=QgEkuDp9yRWvtUYx5FbkcOY29tUFUkWaC7UQM2yf6BZ14aogJORYNd8os9dauL113+
         jDpAh20KdNt9deX8QLn5NCCzc0n7lcYAZj/r7CuRsjzb0mBDHTA+jMFLeGMSk+jZQ5lJ
         6kYtLIynLOsiKJGBTUCSAbf6b+Q1Eya8yTxyFaw0Rqy0EpjVypvpk+QfXAHR1+Iws1+L
         TaXwcdS/awIIm5Go4MXhNbunEFbHG7m/ati42gpjhB2jqNbJiTqdiaDkdn2alScSdHjn
         gUVTNTu47VdXqcRtViUCxdCh7bP9EUvaXPaXA1Z1GQ6gF4VkkTwHSCI8KyRY3oZTZvOH
         2v5Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=h8GyEnDu;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755808829; x=1756413629; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=dNnMK9YP5c1s2PI1JtXiO6rMv5zpfre1KIjxRvokvrg=;
        b=n5DOza3Hf50GASBwiPAZP1iEUer3BnoYIdUH96Pi3Np4vuQ4JwBk9JtKXKhV65VQcd
         R3idPnddQkwyE2LqHeWIb23pf5l/nSpTulEEzemVHCgcTBpAe2a/+DMoe02DlRIRHuo8
         kHdVUeEsbkGVODdl35wIsVPQIbgiPJIkHr0Oxl4H7z8/kRByB1lvsPWSgOYbR/Ksu9j8
         BA1UnH/IXqqopxnDu8naHAguHf6Vvgipp2LaLyQ+NnFh4NM9nKmHK2QayYggYjKf69jB
         QXG70SwN1Iq5T+1RplOsW3CoU0eGZDvFQRGPPOEcNdNi0Eobl0900KIq/ikf1SqM1pL9
         HDew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755808829; x=1756413629;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dNnMK9YP5c1s2PI1JtXiO6rMv5zpfre1KIjxRvokvrg=;
        b=B3nDOA17sPWpUKPTMI7X3gMV8WFGV36sMcuS5m5oIeTSXddjod/WDiHNHq37NQRI1d
         Hg5fkZgb82s4vmyzCeeB+E8xxCzxt0O/+ql4/e3ACA3qbCAUEpNFS0fFfEMgi4r6nHwv
         YBZmS4hV/8LYvTA5DhUfLNuB7Ows2ey7U1xz9bqmrp6pcXfn3ItTHXIyS9U3et15KHhh
         Z56OMnWp/EGruBmfnCq+zokaSEVjd0yGj4PZafwzZgWlryNqbetFA6c8IfNBFcuqUEux
         uPFYJ+hccqY2M4Nu6dX+t2XQLwsGjv2XVD/KrgUJ8NIKeTFzvOgkQVsK87X7eyJ9LhE9
         ylvQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUE7j1S+lvkR2zxUSXL7b9b7k4/Tgqs48fWMk2T1SARh4HyARDRwozF9695bkqMet9IGz9zkg==@lfdr.de
X-Gm-Message-State: AOJu0YzmOmjiyYHE9ROSfClz8U65QJzlRHwmDqzQkV7uiOLqjp679N9S
	5uhwC4RN7wtsO5iGgGtI3Z9/e+bhwEG4C81HALJ45y/MApkai6Jc2tW6
X-Google-Smtp-Source: AGHT+IEu4fO/rhj3Kg3mrU6c7OlxT0/LsAkVnlH8OXh3v4LzgKOgh/59N8/riy5vIOJokQiNj/JJ4g==
X-Received: by 2002:a17:90b:554f:b0:321:27d5:623e with SMTP id 98e67ed59e1d1-3251744bd6fmr1049957a91.23.1755808829239;
        Thu, 21 Aug 2025 13:40:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdA7KVQ1QrWaZ6JC1nTfL7Zvauy8SJpG1wfoks9xvvvtA==
Received: by 2002:a17:90a:fc46:b0:31e:f3b4:707e with SMTP id
 98e67ed59e1d1-324eb6ed4cfls1319895a91.0.-pod-prod-02-us; Thu, 21 Aug 2025
 13:40:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWkRV0HyFUolLq7WqfQz56M8hHJGXmwwgDH8+/3sI8E8mzX19gTJQfK2eB4vCSQzYnET8Fmsv/Q5K8=@googlegroups.com
X-Received: by 2002:a17:902:f543:b0:240:3584:6174 with SMTP id d9443c01a7336-2462ee4a523mr9650895ad.21.1755808827408;
        Thu, 21 Aug 2025 13:40:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755808827; cv=none;
        d=google.com; s=arc-20240605;
        b=X8T3v4LBsm3stAGe8aTDIXjSrBBErvkd+B5eMeN3crAVoeBhOTrg/S28OVWC4oT2GA
         dVCoRfi5Y3z/GQX73ThB3ZY1FbcIENXayUop5ZMoU7Ib5GoI+2qgWnPbab6sgRuViLaL
         ZvDOz52HUEH6D6YkzhHMrgE9amaeVcxIm6utQnQEvM9RnQ3xgDDibAYnkpdWds9fR7XC
         9HIiU+ChX/NAnKlbXpZQ+ecBByTUvijwoJDniJ2mEtxNc44fy/sRn/0fUN94kJroMlCQ
         hvOpg53rKditBB+kHA7lMhs7AUNevB8wphiUCyQqd87uVxRBgrSD0dG5pcZHc0F2fX3N
         dm8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=lHa4LrampbSXQx1Wyi9Bh9OjrywcR0PvG9lus2xsnNw=;
        fh=QkhS5EwCkhmqqHFawZeVgbsF6OUwGoaGwMcbVxqguHU=;
        b=OVoT5ySecz2YeIcC/lowRhY7t6IGGP+Lz7IWxxM5NnxYg/+CJNT1XOtcojmiWi8ww5
         sy+3mvmAdp3e1vSeEu7P+K2G6O+Xu2/A2BX6QhnrnFgdY+biUMWIsXEkO8dM51jYD7Hb
         AtwSuysfSJ9u2355+jMWMVeO5td2LVD8H2sOu+NQT49MT4sjBB0A4fZhrslld5H7EPUQ
         z8Ot97WrQJ14xZAoo6WtjQQwAD1PDCEtLS0rdZ25c22R33DEkN01GH5LLMYuG1xwyg+H
         I7MXKhAnmqA7QjWDnQG3Y7wNjnRb+8AjD2LE2FqE281g1oz9VYnXAqZOKxfRcdfILsGF
         ITqw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=h8GyEnDu;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-yb1-xb35.google.com (mail-yb1-xb35.google.com. [2607:f8b0:4864:20::b35])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-245ed4261besi2848135ad.7.2025.08.21.13.40.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:40:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2607:f8b0:4864:20::b35 as permitted sender) client-ip=2607:f8b0:4864:20::b35;
Received: by mail-yb1-xb35.google.com with SMTP id 3f1490d57ef6-e94d678e116so1459989276.2
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:40:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCURxhOTvlqkrr1nTWUlMFbM9vKCl1++a4k6EjNi+lPq4D56edrIrsfGvvgORVMXmYQG0l99Gu0hPcI=@googlegroups.com
X-Gm-Gg: ASbGncvgWegBpnicuqit6XihLd4Al1YWeGhv1jnL4BAAGSi26Pg0vf7gBj4bhXxmF8f
	yL3iOnSWs4ec/zfuXpMm4KnRwt+8eNePfUG70nbuUCsCh3eU6FfF25uYODla2JbgQ2dmEUqxh27
	HzOKAvJxM8huuvIESECnJbZKY5S4QOyHxEDA0GjrsO7fy9o19UOcc6F30Q17GJ4Qidu0OxZqDeB
	6yDtFzSHfsF9u3o
X-Received: by 2002:a05:6902:c12:b0:e93:457a:37b0 with SMTP id
 3f1490d57ef6-e951c33ee1bmr998901276.20.1755808826442; Thu, 21 Aug 2025
 13:40:26 -0700 (PDT)
MIME-Version: 1.0
References: <20250821200701.1329277-1-david@redhat.com> <20250821200701.1329277-32-david@redhat.com>
 <CAHk-=wjGzyGPgqKDNXM6_2Puf7OJ+DQAXMg5NgtSASN8De1roQ@mail.gmail.com> <2926d7d9-b44e-40c0-b05d-8c42e99c511d@redhat.com>
In-Reply-To: <2926d7d9-b44e-40c0-b05d-8c42e99c511d@redhat.com>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Thu, 21 Aug 2025 16:40:13 -0400
X-Gm-Features: Ac12FXw_AatpwCNNPCEiMwiwdQxQbayKDzVf5K7yc3iQ5tLY7APrv3zl2U8Z_SA
Message-ID: <CAADWXX_5AJxTsk5m_RvP58d=quRMqT4-XbnQQx=obBTKjHr1Og@mail.gmail.com>
Subject: Re: [PATCH RFC 31/35] crypto: remove nth_page() usage within SG entry
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Herbert Xu <herbert@gondor.apana.org.au>, 
	"David S. Miller" <davem@davemloft.net>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Brendan Jackman <jackmanb@google.com>, 
	Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org, 
	iommu@lists.linux.dev, io-uring@vger.kernel.org, 
	Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>, 
	John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com, kvm@vger.kernel.org, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, linux-arm-kernel@axis.com, 
	linux-arm-kernel@lists.infradead.org, linux-crypto@vger.kernel.org, 
	linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org, 
	linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org, 
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org, 
	linux-scsi@vger.kernel.org, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, 
	Marco Elver <elver@google.com>, Marek Szyprowski <m.szyprowski@samsung.com>, 
	Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>, Muchun Song <muchun.song@linux.dev>, 
	netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>, 
	Robin Murphy <robin.murphy@arm.com>, Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>, 
	virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, 
	x86@kernel.org, Zi Yan <ziy@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=h8GyEnDu;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
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

On Thu, Aug 21, 2025 at 4:29=E2=80=AFPM David Hildenbrand <david@redhat.com=
> wrote:
> > Because doing a 64-bit shift on x86-32 is like three cycles. Doing a
> > 64-bit signed division by a simple constant is something like ten
> > strange instructions even if the end result is only 32-bit.
>
> I would have thought that the compiler is smart enough to optimize that?
> PAGE_SIZE is a constant.

Oh, the compiler optimizes things. But dividing a 64-bit signed value
with a constant is still quite complicated.

It doesn't generate a 'div' instruction, but it generates something like th=
is:

    movl %ebx, %edx
    sarl $31, %edx
    movl %edx, %eax
    xorl %edx, %edx
    andl $4095, %eax
    addl %ecx, %eax
    adcl %ebx, %edx

and that's certainly a lot faster than an actual 64-bit divide would be.

An unsigned divide - or a shift - results in just

    shrdl $12, %ecx, %eax

which is still not the fastest instruction (I think shrld gets split
into two uops), but it's certainly simpler and easier to read.

           Linus

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AADWXX_5AJxTsk5m_RvP58d%3DquRMqT4-XbnQQx%3DobBTKjHr1Og%40mail.gmail.com.
