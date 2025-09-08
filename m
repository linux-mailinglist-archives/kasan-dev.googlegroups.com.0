Return-Path: <kasan-dev+bncBDQ2L75W5QGBBKPM7PCQMGQETCJTQFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id A813DB49342
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 17:28:43 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-400bb989b1asf69196595ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 08:28:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757345322; cv=pass;
        d=google.com; s=arc-20240605;
        b=lcfenLHlmWHsE9o/8T0ibo3Te86pkZ7ZUnV1zQXGoXnH7A2V5cpapPu9+HXCdvCoi5
         Nje5ychkiaR3WXKwt/j0xCHvWYfgalDdU8Sk57CQQILdIVEPn66hs+2Rw3z09Evlo7u8
         14re5Xvum59QKqjoLbDmkS43WrCgKhUfD3ir2tWLLiLNSCW64mGCJ+BUMyIdw89crbLM
         2zhBIjGmiMTrpH31S2CTcvINZjlPjcymoJBQ7F3HM7xheS4EvBWScRyLZjxZH3gT+LnP
         82Tgk6kfiY+BU0yuNZSMIYSTJvCXwLg10Avb9SSmZx7GvSS9YUoBpq3m4yYGzujlk9QB
         pY0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ww5SzLXYOT1PPUXzpegF9JLPW37LRdMY0shGuGXLiFE=;
        fh=kFhwaLawXkVO1Z1Vkk13AcmJK5SRebIDxcwtILCm0+8=;
        b=TjjiQ3k12I9aJSod0+rShXkglOnep7SNIZ9AgaXxOtBrWAfGLrG6D4NnwJ957LVffj
         Lpsl+m0WzpLa5RxA2S+fqvwFJk2R8BmlPd5NzUZZhqw6k+L3MwFxKnFi85djVFI0CLTu
         72au803HTqMWFL0rdcvJX2xmLGQyCX48LhltQvp7x+/ZhTW0ytIZ/XkQbV/eRYWQKiMw
         NuJq1JYovlGAEjQql9U1I2uTf1oY7vAd+OBrT2lTB699orNA6jRgQs0GmlthDD9TjXgm
         WeNiQ6FqzAlHxUy/PyNxrihUfkVEOaPUJPAtBsR0O3f3p961nxgxNAq9trlbmeyBCeKQ
         nRXg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PsNHM3XM;
       spf=pass (google.com: domain of broonie@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=broonie@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757345322; x=1757950122; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ww5SzLXYOT1PPUXzpegF9JLPW37LRdMY0shGuGXLiFE=;
        b=oODOZ0Ue3DPLAoWTwxKXASQi5QrJk0tCNHo+d3GvVuun18XDP+asCEUNRhwW3MD/jL
         AwlbIn2ZRq20U3g1f+Vc1zf+o4gC6FGn8e2VNp/RJrDUMGW/qEpl54VR8kXzSKrBC/uL
         yPAqnFfpyJtazb4uvnwbBBtHuJBEH8YOxqfAKfEm2973PN+bWVz+7KJ2JbRKqkKk345T
         DWy2V1FtoWLVmZYZMjfJ5QT22rAl9J/lAPlBeWrTnOQ1DKfpw6TT0bl2KLA2tEizRTz1
         ksX34QsYpkrTPTQbbLJwytzm/2F2oBzefEEY3y8T7yggCkTjPMcafqBg/ozTNWid3I97
         kN2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757345322; x=1757950122;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ww5SzLXYOT1PPUXzpegF9JLPW37LRdMY0shGuGXLiFE=;
        b=GKFjYwnyx05QqC+P/y7ltQ16tBs9GmYPQBZoPyZ3474qtJa8VA/AXSmA6g2zmO0efo
         OG94fyI3/rPT0OSQgaA4CEQ8e10WHyaeiika8MnZXINPVBvK6Gl2UPfGnyGjMGp/UliR
         XkXVIkOv2vf3wylyGPoHmULwdMs3z1/8UgBI1C93U3vo3PPfusD4edYe/3XCJAe6zn2c
         nIOtafhwCOLfZANvakJ+u0oHAHSJcCQE1DdCRw4ovfJU+UYN8i7WIFUW5wh35AVxnj6Y
         uH0I3s//LsM59fyIdIYyUpIxagnXpwa0Uu/aFbdVCoGTGF1UNRtUGY7ptoIMrnfwJa8C
         5EHQ==
X-Forwarded-Encrypted: i=2; AJvYcCUl2ZBkHPJHjeBtJMQWusuWg6pZKc04anrzGKZvtn9KqrN/JKvWq+2BOBdGTG+Cyqgk+l1szg==@lfdr.de
X-Gm-Message-State: AOJu0Yx2czVbnNwI5Eh3yd7+TCeqxQ/sByyZqy/WR+WpqH6RsYYTBLuj
	rfgmdzLJ22ft9hsuya10D0DmVLTidRonkCmVXdLki0SdH9zx/oGHds5x
X-Google-Smtp-Source: AGHT+IHtaxgPcZ8WnwIctxs8BiMT+fBW+I8wDriBk2N5IsfPi3gQlvljZV4yHu2C7Ej6810C67G1Ag==
X-Received: by 2002:a92:cd83:0:b0:3f6:5c52:5c75 with SMTP id e9e14a558f8ab-3fd7e252fbbmr107906195ab.5.1757345322171;
        Mon, 08 Sep 2025 08:28:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfHPJTHbPcXe69Z20Jg65tTzqPg30YGbnvNhdtbyeyENA==
Received: by 2002:a92:c263:0:b0:3f3:14e2:8797 with SMTP id e9e14a558f8ab-406cef103d4ls11847785ab.0.-pod-prod-02-us;
 Mon, 08 Sep 2025 08:28:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWy1IYwFsBYf22cCwM4pnAiDMHHp0qTyTtVuxH/MZ47ayDmplM+dV/PM3MUC5RPZ7Usq6aRPI+2+UI=@googlegroups.com
X-Received: by 2002:a05:6602:150a:b0:887:69b9:bafa with SMTP id ca18e2360f4ac-88777693bbbmr1209772239f.10.1757345321022;
        Mon, 08 Sep 2025 08:28:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757345321; cv=none;
        d=google.com; s=arc-20240605;
        b=dTWuJ73TU0odvf0c8AXk7daLPDII78sTSXmbAVALVDfQgEbVaew27UtOWuX0XN9Bqr
         Ji81YR5uTkXfAXb8jhz2f0v9nq2UOULJHp8E/MCZAJEsYhExIfxJGEVVwJx63nR0343S
         1WODiRb0sNlIU/IAI1qDPnVak+V7firCEVH9Xld+SOx86w94gPwSPF9FspApEbGZqAmg
         34OrE/zOHajzl3iWaXs6jmGNlA65O+m7jT89Ji9vxcu2QoeWWT8YCs/78HkFu/vyRimx
         Xy1YvjMkMpjpbE1Idyxc0jDRgZQV2bAPmWOfH0jlmaTh4bK4hXjXoa6QvobiypTK8DC/
         kldA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=KPIEyPKg6yE9CiWVc3UyQrHWiGAGsO4BawT7nG0zg1U=;
        fh=vX6gO3pliJpm/AGrWIy9cYz9F3J0yH3JYHwS9n457z8=;
        b=fBpRy7PW3RGoR31B+755eMACdZiqQIoTfxi7b6SSEDKam7klpY/Oot97eWba/V3qAe
         JnYdsV6kZ9TIZz9HA5BTNi3rj97yEGQ5VGBkGY37I0eJ2bEKyGZzqRwqFOlJp+tN7K0S
         lVASgc4ou3OAjBH1K+JsuAUZMTxVidRYpyhycKnAE8UqsSzrEP7G/3HyhJwBZsFFXtQ4
         kU+Kw/YrUiUKjzcwG0pizpRqAMA/4otFAJgvX5Xm1D/IjkbcwQAIr0teMIrXkei7b+0M
         iwIcaamN1z+tudk9ZOke6sCnrcUWnuChS0hL8+cGBZEJaFs5ttsurfFsB6u+XezUr8dT
         gzZA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PsNHM3XM;
       spf=pass (google.com: domain of broonie@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=broonie@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50d8f054ff5si1172057173.1.2025.09.08.08.28.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 08:28:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of broonie@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 3E59360054;
	Mon,  8 Sep 2025 15:28:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A1A6FC4CEF1;
	Mon,  8 Sep 2025 15:28:31 +0000 (UTC)
Date: Mon, 8 Sep 2025 16:28:28 +0100
From: "'Mark Brown' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>,
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
	Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
	Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
	Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH v2 19/37] mm/gup: remove record_subpages()
Message-ID: <e8428944-e2ef-4785-b0c2-d4896b291cb1@sirena.org.uk>
References: <20250901150359.867252-1-david@redhat.com>
 <20250901150359.867252-20-david@redhat.com>
 <f5032553-9ec0-494c-8689-0e3a6a73853c@sirena.org.uk>
 <83d3ef61-abc7-458d-b6ea-20094eeff6cd@redhat.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="DHpSdvAG938A2yDi"
Content-Disposition: inline
In-Reply-To: <83d3ef61-abc7-458d-b6ea-20094eeff6cd@redhat.com>
X-Cookie: Air is water with holes in it.
X-Original-Sender: broonie@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=PsNHM3XM;       spf=pass
 (google.com: domain of broonie@kernel.org designates 172.105.4.254 as
 permitted sender) smtp.mailfrom=broonie@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Mark Brown <broonie@kernel.org>
Reply-To: Mark Brown <broonie@kernel.org>
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


--DHpSdvAG938A2yDi
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Mon, Sep 08, 2025 at 05:22:24PM +0200, David Hildenbrand wrote:
> On 08.09.25 17:16, Mark Brown wrote:

> > I'm seeing failures in kselftest-mm in -next on at least Raspberry Pi 4
> > and Orion O6 which bisect to this patch.  I'm seeing a NULL pointer

> On which -next label are you on? next-20250908 should no longer have that
> commit.

Ah, sorry - it was Friday's -next but I only saw the report this
morning.  Sorry for the noise.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e8428944-e2ef-4785-b0c2-d4896b291cb1%40sirena.org.uk.

--DHpSdvAG938A2yDi
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQEzBAABCgAdFiEEreZoqmdXGLWf4p/qJNaLcl1Uh9AFAmi+9hwACgkQJNaLcl1U
h9Dbtgf+Lll52kCjsemPK6UaH7DQkWfZmHDqtHqLwe5SzgAfSeqnhQgasjG5jMSv
Nx5981jPRrpwjz/cI58x/+7VGV4mHF331CfuGkvW9jVYKznATgc/3x877cxjQPYg
I0fxXcE59j2a4VQrjcWqpuF0unCRYckVgvCsxK0iBkltPEMKR6iqf1xBECY8ofae
HYKT9ows31m6zoR1t0ed+9WHQqIH9nlo9gPcNJm6Vw2vMSwDBa5BuQv3MIIyOFq3
9MutZOCRam8c+vwt91HNCNUP85vbnHqG+eZCecu4Y2rVwHaENgW7ayTBrmb1OQ4G
cd9uBVEvCzE0tE1Rm7r+1srw8xc6vg==
=z4uX
-----END PGP SIGNATURE-----

--DHpSdvAG938A2yDi--
