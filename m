Return-Path: <kasan-dev+bncBD4YBRE7WQBBBRENYDCQMGQE4F4JYUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id A4E2AB39549
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 09:35:33 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-45b71eef08esf3267565e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:35:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756366533; cv=pass;
        d=google.com; s=arc-20240605;
        b=PWKTI4HG6KRp9HKe/1VT34iTZ/fc+CnN8sLMzBzn3yJUR9W1HFcAfr6Vcg99beuETx
         yW6hdhT1SMPKunQd13qXZKX6qENRbNAA5jKPzJN8ujpxbS+ZJGB+cbMMVI5fW2mOg7+P
         l4kdRBwmm9vm7K2VrmDoVnHGjYIijj/I7qTiXJ4LKkGKEpNkWdU1BgUwhg6Id0JNISCW
         JQeTvKa6A1bHyglOT6NbnggU1Lo1jbwgxVNEeOncjLgsF+afqt3nXaZep5nD29KWGasd
         PDhuhCs+zmmyBQh2wi25JDybWC8UBDeEpDh76o32cEGFw77mdOcnR2BjyD8uDGmlV8oD
         /9JQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature:dkim-signature;
        bh=ObkddpxyMSOyWs1bV7cU/4oiJEbnyilByrtO03/ZVFk=;
        fh=f3FqV0z7qX+crfUiel9bz1ngNJfqgZ+uSkaNMzz9P0c=;
        b=An0n4zlYNjoY1SQ9VojNWZKJcOM9nmcFHryUaAAGk09XdDuiDwQDql3yje0xT4TIWn
         +iDHDA4FUYx3tzP/QoMRoeyYj3mExiDghCfT39bVViDob/o6o+ZVs5Ly0OKTde4USgQP
         DCtSCAD/uyHev2p8heecdHpyJQWYkx8N0bWt/VeASE6YN6ivGa/C9Qx/a64u6x+YTACp
         k4MBUMuo23TcrNIg7pDoe9q+Y+8gvbFAoR+v1vvtTEnNhwH07JZQ6I/KnGMHnMEF+yRh
         qcsaRZyzKTcHIdv6zF4c8XN72nrAK7ahODn0Ydy96Wu8Y2aSQ50k76AUwMieAoqPjSt+
         OTSg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VsxVP+Xy;
       spf=pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756366533; x=1756971333; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ObkddpxyMSOyWs1bV7cU/4oiJEbnyilByrtO03/ZVFk=;
        b=s5y2lTGO4BbAPI6p4gd/MPAM3rNnhHUMA29OA4yDPRiVF1goJmDA7hlyt3WxKlbZBZ
         mPtGnaNwX1Cqc3GlkmQJwcLOWZOQwIjfzH3lEGCaT2OAEYyAvzuYPSdjIajXAi9IRm5O
         UBO4S9UqF20iyfnzCXkCqmfvV+tR3uy1bjgDOrXCY2ydBbRMNDWK43XXtqCKXqWXuRY4
         18odpt89Ejzt+XaA54fDu+JB1sJ/v6CgijogxLsCVbyP5THDHelGqCInnZFGRgiqnqko
         DaaxHnuvxC26CV89uRb9ViTx8fKWp4pX+dPWGtD4qJ1617FGHi3evW+q7CVepVt6M3PH
         qyng==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756366533; x=1756971333; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ObkddpxyMSOyWs1bV7cU/4oiJEbnyilByrtO03/ZVFk=;
        b=ky52lpR8p52HhXKFpyWr40Sr5EXNvUNz+IbPowPVaRTtldUA8uo0f8hzUzwBNeaQgW
         SBHQi9gGM7sWB0PsH9XixMZOp6UiEvtB85ovOWyJuJgcdaAyBORaiq/KOymDYxQIMzAE
         hDFqbI5+aN5QjZdnHBFD0wbro4mpWUV5ZJ43Zl449zxcgFH7Xh+RTpSB8tW1rrUfcmdC
         FqcENMMJ3nUrskajQ6zk9cFXzBj/GkBc5rdAgCXdiCcFushk/SvJ7TMIeE6vZRlBag5r
         WjN/CTZW9/dQBqrANzIu/jXOuZQIFP7bFuxcFg+XPnOj05FtoGfuQZyRll5sNl9BS21D
         E2PQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756366533; x=1756971333;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ObkddpxyMSOyWs1bV7cU/4oiJEbnyilByrtO03/ZVFk=;
        b=DFTOw0NldmiGznVrzo6uew/IzFjbZPyOHVpyuxxoCNe1IF/kfHe9r/SNbwF6754DUl
         g+HUlcuL01cvONXnOYFTGGcqyljRIRv7xAtXZ4E6ieRjz8hXp5zqqThYkAZg/a6soKMa
         hXaflIYc4wc1VBO3Z/SnYBO63lkXv75b3WS+OshFbhbQK1vjaN4XJCUbQsE+hvwvd7Vm
         ca6l0NuIvgoHRYmWBY7uG+P+zcvO3g9GnLmUpTTgkZYjtUW3VZD2JlkN+hGC5lpBTKx2
         4Btp8mD+2hrASGGhKVAe/oxIh2514PZ1HGhHKPUyMlvDqmVkjo1RFBH/TiBXrvFBU7tp
         rhaQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXYRSL9XGPuEIzhN2xpL04bjYAsoyFDhVeoqklieJDEidkiSVBRWZVQYgMVXzB4absIDT300Q==@lfdr.de
X-Gm-Message-State: AOJu0YxbpQ7JuyhcFWrH3u60psjFF3NjLjKk/K4EIsXJ90vYajUx5k4Q
	LHHv8N9OT5jzWcjkhaj6WJm0ewNFWWH1PiIlJdRR0rFtqsr4/8CbxjSn
X-Google-Smtp-Source: AGHT+IFCaxcBqOTlHvTiaVrMW8PtEukpHaaE/eNyZ0ZKFR2MfLB+BD+5b37e+9A46wBWix2PPi0UPQ==
X-Received: by 2002:a05:600c:6209:b0:456:161c:3d77 with SMTP id 5b1f17b1804b1-45b56e7b0abmr238856045e9.16.1756366532846;
        Thu, 28 Aug 2025 00:35:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfJtmMZPHKA7dypq0K0UKyfrbAGrG5q11r7eqUT4DT96Q==
Received: by 2002:a05:600c:1993:b0:456:241d:50c3 with SMTP id
 5b1f17b1804b1-45b78cabfbals2687185e9.1.-pod-prod-08-eu; Thu, 28 Aug 2025
 00:35:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUWcTOwlNdSAjhDDuM2nvwFylPd1gatqQAbErp8GAToi7a9oy3Cyt7EwAE0lY5yPeswVAZEIT2mTKg=@googlegroups.com
X-Received: by 2002:a05:6000:288e:b0:3b7:895c:1562 with SMTP id ffacd0b85a97d-3c5da83c60dmr18290618f8f.11.1756366529871;
        Thu, 28 Aug 2025 00:35:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756366529; cv=none;
        d=google.com; s=arc-20240605;
        b=XKK+GfzaTHZ64mYnnAU4gZxLOfMNkol7bM0+6D3+LFRXJtnXv3T9p9QpEgaUbDNjE4
         6xC9VjyIN/f4z1zO5WjBIydrjGdu4W5XEUXtPAAOKm3jxcNuTjUq4k/fe+ej2ebhOTfR
         szaavfoYeU609MUN11N1RmRC/TWQ2E8qY6MUei/OkjFqI19y/cCzXMd1pp60TABq9nEz
         Fr28LVyD0LYVsLx51P3ZGhuokL+crnxQNNTritKyQviSgYpkPuLrSnPj3VMCKwzGn9FZ
         c4hJH9N4gNmDByAahC0BaARg7CX6GvUajA3hpiuDeo/oW7+Y/V+ZNGmMlGrT3dxew9DV
         d/Sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=7wdLKdu3gRydbgkaOExgCyxr/LuNr8ANanTK9VurXYA=;
        fh=f1FsZFQ2dXXupqKxUGCDIg1HhQwKVtllE+mMw3nm+L0=;
        b=gINe11KhUw8Br4TznHWfZzZjuo/iTb5SQFJdZ4VSkf0enl6EJwob6SNDWJVGixW6Ku
         sF7pLGb/vnzAsfuePNRdaqAXPQ/P5GFZwIAtsZ8bSwzV4sGGZXr4qOyIbSBlesL5lHis
         w33MfzfICpHKwDt1LopPgEDaaA8+Rw/TwL4ulxLoPe1vl3O9r5NbhwUwj/Z81v6xxxH5
         cDslMrB9PBbwsmwZGiwTLymDrnaPKyHX3C6trVcNmeDvUIFuEtt0cUWWursFuFYeGuUT
         YWFwlKcBWIJrpm9igs31WmJUo+Wy2yLDCkKnpe8n3pUUhvzNePTA+221rIEcnYYHDUJ3
         cG/g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VsxVP+Xy;
       spf=pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x529.google.com (mail-ed1-x529.google.com. [2a00:1450:4864:20::529])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3cd034dfae0si66448f8f.5.2025.08.28.00.35.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Aug 2025 00:35:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::529 as permitted sender) client-ip=2a00:1450:4864:20::529;
Received: by mail-ed1-x529.google.com with SMTP id 4fb4d7f45d1cf-6188b793d21so746985a12.3
        for <kasan-dev@googlegroups.com>; Thu, 28 Aug 2025 00:35:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXSnNwj0iXvlR0gYHaSiMxkNUAoNYIpxs2xRxOJRwha7B6wfftO+Jys+KhlRAnSGjONBPPZfi22TPU=@googlegroups.com
X-Gm-Gg: ASbGncswyMO3L9R/549UOLJG2xMFcEdDaLjurtnpJX9X0nveFQz9HRHm05jAC2Zl6IP
	AAb6mO9c+ddtjUPRVg+Bb70oEDkwrHjdk5DXO1252WEM3msoCVECqDlUiJ/Pwtlb5/ukpUap5wS
	p5gC5Mzj/ALYS1Q/vDMtXJtNLTwScipjwxK8+jQpVIPD7YLcFtTXPqec6AMRx/p0oCvHPAZWcd3
	Epn20yeuT9KQkDxrDIJzYWcmRXzJPO9jdwYvPgCj6xemPGLC+W/SgWOiltt8evueqqDszNkqwYH
	jlLW1ArVApPinhYphaSXg0nSDtqxuR9AK35ZqRJH6TaQYcR1koHTMC5dmpG73CBQXKigrj+6/OG
	tk9QvrtO7xxkyFgUVPRNyZxnY5w==
X-Received: by 2002:a17:907:3f0a:b0:afe:d590:b6af with SMTP id a640c23a62f3a-afed590c109mr310258266b.20.1756366529084;
        Thu, 28 Aug 2025 00:35:29 -0700 (PDT)
Received: from localhost ([185.92.221.13])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-afe77c2b758sm886311466b.84.2025.08.28.00.35.27
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 28 Aug 2025 00:35:28 -0700 (PDT)
Date: Thu, 28 Aug 2025 07:35:27 +0000
From: Wei Yang <richard.weiyang@gmail.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org,
	"Mike Rapoport (Microsoft)" <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Brendan Jackman <jackmanb@google.com>,
	Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev,
	io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>,
	Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>,
	John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
	kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org,
	linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org,
	linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org,
	linux-mmc@vger.kernel.org, linux-mm@kvack.org,
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
	linux-scsi@vger.kernel.org,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Marco Elver <elver@google.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Michal Hocko <mhocko@suse.com>, Muchun Song <muchun.song@linux.dev>,
	netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
	Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH v1 09/36] mm/mm_init: make memmap_init_compound() look
 more like prep_compound_page()
Message-ID: <20250828073527.u4k47fohaquzf3pg@master>
Reply-To: Wei Yang <richard.weiyang@gmail.com>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-10-david@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-10-david@redhat.com>
User-Agent: NeoMutt/20170113 (1.7.2)
X-Original-Sender: richard.weiyang@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=VsxVP+Xy;       spf=pass
 (google.com: domain of richard.weiyang@gmail.com designates
 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
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

On Thu, Aug 28, 2025 at 12:01:13AM +0200, David Hildenbrand wrote:
>Grepping for "prep_compound_page" leaves on clueless how devdax gets its
>compound pages initialized.
>
>Let's add a comment that might help finding this open-coded
>prep_compound_page() initialization more easily.
>
>Further, let's be less smart about the ordering of initialization and just
>perform the prep_compound_head() call after all tail pages were
>initialized: just like prep_compound_page() does.
>
>No need for a comment to describe the initialization order: again,
>just like prep_compound_page().
>
>Reviewed-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
>Signed-off-by: David Hildenbrand <david@redhat.com>

Reviewed-by: Wei Yang <richard.weiyang@gmail.com>

-- 
Wei Yang
Help you, Help me

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250828073527.u4k47fohaquzf3pg%40master.
