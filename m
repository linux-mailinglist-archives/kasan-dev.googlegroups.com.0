Return-Path: <kasan-dev+bncBCT4XGV33UIBBUWGUKZQMGQEYG636GA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 573D0904459
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 21:19:48 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-5b976c32d9dsf5862028eaf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 12:19:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718133587; cv=pass;
        d=google.com; s=arc-20160816;
        b=SPa7fBn/rYzv5ZrjwcOMCjKHOIx3oNhl3HhWIQFhXFCqcZK/FPmVoFi/bU7UW0Ac+d
         30oYvRZxtzF5XRBZh1bKZaIszg+4Us/HlTPMVyx0BLq5me/EaF0Uguy2mc7QFYrE230f
         7CzLs69JS1Xl+VnwQk8yvud2iyW6IUpJpRsV8pYg6XbrCZz02ycRbYRTjo5GmFjezgqO
         lKZmk7mJt0sjEoArZEe95/xbLvRRYxCxXW9/CjFR9jGHHk9NSyxZ2JR8a5Rqkd/wlAbd
         XIcs51B1J+nuhQAPTE0p6cjwftWHEqYfxze+UvvYnGNk9Fgcwdr/0O2UQGa9jU3jCFiI
         1moQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=DmwquaaEtzqwl4LcE1hm8xRdeJvmH20JePng7gc2t4U=;
        fh=BTzDgq/EAkJl4oNS2PVbbnfj9CVFcLFsgp0Ih8Q8zlc=;
        b=LfUzoekFPEpJ3NnFg4eJHrqN9kY6c0mI3hzgl8OgMv86YOVmZUXYKtBGWjGLfoD+eF
         m3AZoS/ehaHUKCLs46v+MyU4N9DViVkRcv+w7+raHdBD7eAwGk5MJ3xk/t7IkvTuuf88
         RP1o+S2N2vLv3rqBaApIuNOmPVYPclgP8edmfpr/YWZgLW7nokzmX88Xh6wzuGIp0k86
         bWMNUDR1iPPmuvcYOV4St0UsRCyKo1YEiMB2+FCSZsdqXe3qWaiDO3GB+btdYHa5C0Gq
         mv8pD93p5lMIJmAkJEhYulcSoVLtdMkk8OfmFmKjh/Eg5X1oT8Simz/DyrU+KxLkYbSC
         3Ecw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=eEh1Bqsw;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718133587; x=1718738387; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DmwquaaEtzqwl4LcE1hm8xRdeJvmH20JePng7gc2t4U=;
        b=BWW09vSFCGduFBtAheQAfJSGVW4hm8ZXzjBuMoa9YdHJ67TX7ybbeV/osDv9P+LgNK
         eywWaoHZMBnpdb8S+Tmzp/IZN6/2NM6pN0b1hNqgBoT7Lj4Nk/x/pSrVSXb/yTsBgkgR
         O/o7vwy2Z2/VX25MlwaDJKoosIEiqwFz2nxT+BQ2gAAHeSW7+g6yu55VdkOYS8BNal/S
         vRfWwEZLan3w0mG8CvyO/uJxtUi1UVOnFt38zLuXqWgwFI2XmJSMiDtFHSj6Aj/bg+i4
         5v9T/H5sETc0PF2Zj1vPWValMlmc9PzIYg6UdKJYhFu4TQ1ivEm05uonAT2beXDXANNu
         qPhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718133587; x=1718738387;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DmwquaaEtzqwl4LcE1hm8xRdeJvmH20JePng7gc2t4U=;
        b=ds9wj4RZb7mpXcmIZDuOSOBwHlbcyEyNFXJ89bDmsmcqATdFcBMmz703CQCrd1xAW4
         UcLMv+LigU5wTXNdgh1V4kCwkxQiiB12XdOIBl1DYYnwgOF5PEn5xs1/r4MXV21o29to
         Nk6upD4K8+mbMA+lmnaitDRiSc4nVVkO4hpDnB3KVbeGOhgDZhBnNXL3rmBgH2haZEKp
         Ulgyk3MYJsLkHNM/LpqasvjTdGkxHNmb1EJ77NiEW2loLEBz69LZ9/XrP9X0ouNaLSrl
         08GaHlnC5ZkBwoEthkonaX2D0/5k/COlZwNP7+Trs3QlujGekb0VFyaBUpedqfD6mWyQ
         DERQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVEirIbLTr7Nqfd3oIFNWMEIMXqqkliSqoYc5pzn+gU3wGRo0XhKk0xnvijeITIhWg3T2KN2CV5hhn/K2AQujBV8PmlQhPmHw==
X-Gm-Message-State: AOJu0YzJ3FQGnVSxz4ld5pgs1P9ckrKzvbgS+9mlxWuUG6tBr3fiByUP
	kOAVZkEJK6nwEt7F0t5GW2UcUf2zWL6cKB6l7binDmKHDE4VM6tB
X-Google-Smtp-Source: AGHT+IGxp9c7mHmRgnb+1QBXVBqmHjegqvJLBB9mHYsFbEQE0Esu7FcqoDY5PxZxcRm3ShSsBHJlmQ==
X-Received: by 2002:a05:6820:555:b0:5bb:1bed:31a7 with SMTP id 006d021491bc7-5bb1bed5d74mr4965051eaf.6.1718133586633;
        Tue, 11 Jun 2024 12:19:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:ab87:0:b0:5bb:1b55:bbc0 with SMTP id 006d021491bc7-5bb1b55bc75ls1352129eaf.1.-pod-prod-01-us;
 Tue, 11 Jun 2024 12:19:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWKrog3XoCmWX9n5dsY8qsr8G3xAcgW03cPntTq5Db9cawqNNKRHoDSlLVe0TFVZ8HsD0FLLuPZkl/4nTBxQxJkM1Ismxil99ZmxA==
X-Received: by 2002:a05:6808:23c7:b0:3d2:2768:c8e2 with SMTP id 5614622812f47-3d22768c970mr8616583b6e.30.1718133585782;
        Tue, 11 Jun 2024 12:19:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718133585; cv=none;
        d=google.com; s=arc-20160816;
        b=ZMqREejcE9YMm1ekgT+8vjyl+9yr6u+VZV7h4ZmnJvhzDma5Q+w5kjeg0J0FS2RM5Z
         Q4emQEhzurGF85uBatsQpgszIXJjAGh8IzGRPRqLdPthWPPD3LjGlL3eBRo2Pu+7GMPc
         wsQutKJkoCE+UnH9PyD/TjgFVY6S1DD5usrkAflopsRsD9/gz7QzmuxH3WS0+pgCW3i5
         WpdgHFWLMAyoO5UwQaihhpTSFgFXtVHTWJtqaIHQ6LxSFkii7C8BCRYndD2+LM1tri9z
         Y0DN1F/NSvtW9xFETmtiuA7cQLBERkoaakcc1BlAN/17RdORLm42DJlptXm8YsppmkIb
         0jyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=jEeggShN2PxC9Vfcn6tZkQMtIb+6pr/j0fV0AJbG7qQ=;
        fh=H6CH34hcYenSB7FXrgY3SiQWBl/4Errpy/cWaxiK6f8=;
        b=vHAjYDFj9wBl6V+7QpCRj7wgUBMvdFdyncK5sBp6yPm5fPYzyaKuSV44IP+9YoEBOp
         7QcHWCN7RFKszDl9BobTTwREhCHiXkNZ+kH45KHOBuOcGZrVtUrxxfMH9Vwv/p8eh10y
         DL7C6FngzRB45aw+m5rr9v2F+Dz/1pKO4EuXTJaoxa8UYcVLvXPZTrXLiV06XarYsf+x
         BVXMjSLjVy3Zy/I6BeFIkm8yg3Qrx43SPJvEpP12AB8NtpC1Xw/T0Y6k+qCE7S4UN3yN
         iZfvoU6+YAn/yFcRKs47kjmAsnGvA+dzRNzsH0xU8m0B52pSk8W1/qRvrXdkaj0qe5PF
         aPFg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=eEh1Bqsw;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d21e8ca39fsi377971b6e.4.2024.06.11.12.19.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Jun 2024 12:19:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 7BE7E6115A;
	Tue, 11 Jun 2024 19:19:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7CA6EC2BD10;
	Tue, 11 Jun 2024 19:19:43 +0000 (UTC)
Date: Tue, 11 Jun 2024 12:19:42 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-hyperv@vger.kernel.org, virtualization@lists.linux.dev,
 xen-devel@lists.xenproject.org, kasan-dev@googlegroups.com, Mike Rapoport
 <rppt@kernel.org>, Oscar Salvador <osalvador@suse.de>, "K. Y. Srinivasan"
 <kys@microsoft.com>, Haiyang Zhang <haiyangz@microsoft.com>, Wei Liu
 <wei.liu@kernel.org>, Dexuan Cui <decui@microsoft.com>,
 "Michael S. Tsirkin" <mst@redhat.com>, Jason Wang <jasowang@redhat.com>,
 Xuan Zhuo <xuanzhuo@linux.alibaba.com>, Eugenio =?ISO-8859-1?Q?P=E9rez?=
 <eperezma@redhat.com>, Juergen Gross <jgross@suse.com>, Stefano Stabellini
 <sstabellini@kernel.org>, Oleksandr Tyshchenko
 <oleksandr_tyshchenko@epam.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v1 1/3] mm: pass meminit_context to __free_pages_core()
Message-Id: <20240611121942.050a2215143af0ecb576122f@linux-foundation.org>
In-Reply-To: <2ed64218-7f3b-4302-a5dc-27f060654fe2@redhat.com>
References: <20240607090939.89524-1-david@redhat.com>
	<20240607090939.89524-2-david@redhat.com>
	<2ed64218-7f3b-4302-a5dc-27f060654fe2@redhat.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=eEh1Bqsw;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 11 Jun 2024 12:06:56 +0200 David Hildenbrand <david@redhat.com> wrote:

> On 07.06.24 11:09, David Hildenbrand wrote:
> > In preparation for further changes, let's teach __free_pages_core()
> > about the differences of memory hotplug handling.
> > 
> > Move the memory hotplug specific handling from generic_online_page() to
> > __free_pages_core(), use adjust_managed_page_count() on the memory
> > hotplug path, and spell out why memory freed via memblock
> > cannot currently use adjust_managed_page_count().
> > 
> > Signed-off-by: David Hildenbrand <david@redhat.com>
> > ---
> 
> @Andrew, can you squash the following?

Sure.

I queued it against "mm: pass meminit_context to __free_pages_core()",
not against

> Subject: [PATCH] fixup: mm/highmem: make nr_free_highpages() return "unsigned
>   long"

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240611121942.050a2215143af0ecb576122f%40linux-foundation.org.
