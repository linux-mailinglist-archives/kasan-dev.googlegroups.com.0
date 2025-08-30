Return-Path: <kasan-dev+bncBDTY5EWUQMEBB7XWZLCQMGQE224VH3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 534B5B3C967
	for <lists+kasan-dev@lfdr.de>; Sat, 30 Aug 2025 10:51:12 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id 41be03b00d2f7-b4f045e54b5sf3309a12.1
        for <lists+kasan-dev@lfdr.de>; Sat, 30 Aug 2025 01:51:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756543870; cv=pass;
        d=google.com; s=arc-20240605;
        b=gkapHOjZ2i7Za1ytS8yKXids9oUTBwMouzI3rfYnrqfdDbR0vQ15aiK86ZoWCZQHKH
         MpsP/ahS9v5U2x8QKNHlz7QOEP3w3wFDVbbPAtkBl6Iu/7wDOXIs8TxX1vqkATtZLXoj
         laD16V7jkB5gDejJK2cjtDqQl0aITzoVW0AZraJjApzsRSClhXV66BSIhPDI9iQhs/5z
         PSKmgMN+mytvewOlYTnr1ZgntOIMFjrg9Ev4l6cpJhhAW4r8WqQ5yVsAE0gbHwrGSHl0
         Sip7qn/PuKmVoULqk71g8T7xf2HGXikq1ijaJWojfTZp/O0gVXqoFhkQateLUwJPC+cC
         ZBtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Hs3fCfWTyuNC/qjjqo2NA2ed0a/XnOyJ1Bfpy4WSva8=;
        fh=FfKhIy3b2yeVX5KmvEBYPXRXFxVEl9RV2p4QHrL18eU=;
        b=K8Ep9qVbgwoyDkiba0Imr8dIcqVh9C6RLxsGAF/MjbLDd/+uBVVNlwEviQR7gRDXYt
         dQwpAVgxnR80u1ToAOGkf0SqP3ZdQnOHbEZ4g8os2SVqNLJlvzQQC20WNhHg5rizVeJ3
         7Rd3ajBIh7n1XEWEqoYJTdtFOV6ne465S1ANH8xQnqDJ4ZUMGgOLAz580BhR2OnGZZJN
         emXk49xZ7FHaCn2bmDX54av5R5e0rJnHAggF6KQL3f23X1DEv4GEIWcisTjn6YgiDeeE
         c9lwdQ31s3q0ahGbnYBNgQlxW58fynh/1k3ipPcm50ynpu/n89CxMTPMWe1IX6DJAd2J
         mUVw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@hmeau.com header.s=formenos header.b=GuMcrSCS;
       spf=pass (google.com: domain of herbert@gondor.apana.org.au designates 180.181.231.80 as permitted sender) smtp.mailfrom=herbert@gondor.apana.org.au;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=apana.org.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756543870; x=1757148670; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Hs3fCfWTyuNC/qjjqo2NA2ed0a/XnOyJ1Bfpy4WSva8=;
        b=YtW0As6t1skhsNZx9FduRs1HGMp9l6DVf5zTV8IMYNigGHwKxHLh8oIwNGUueZg/2g
         182SNR1TlRAvdx888CSHj3zxC/w5cRjrXKL3Cl7wGGZWufl7PCfwdHUh9bxq99/GCQOc
         yhVaqAsk8rdWlPgpl9iv3krMMu/D0dJB4nHQ2JY1NCQ6tbi69NQ5inWJM4wnlYlXQVZ1
         HN72FJx69WLmgQoJMdTQtrcQWm68aJbkatpGhBlyVK0IIfcLVlGUS6aTgEzRMMp4mnZr
         K/9l0scVER0hk+z3hqSc7uu1ejFlu+xMVPsBMZ10Ph2uNA7pgdnGwCvNDr1szjB3w0Tm
         8nVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756543870; x=1757148670;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Hs3fCfWTyuNC/qjjqo2NA2ed0a/XnOyJ1Bfpy4WSva8=;
        b=BRx06QJGaUqYcvNPyhJFeCb4ENDFLAkfTQ15L3lHnMm464r3r+7Xq30dPOXH3Um7XO
         Sbe7ogV3YMo2SZp4lNG+C5CJloBejNzX4NmwUpme3/tS4iPQdI6HsHIcD5nhHX632n/U
         RtukWwsYIPlqAvdvvgUbGZnNM9Yic3CMFVKlmffGtXOCNnneoNJh5/rT/78di/MV2YxG
         INLqLNbtW4nCrnH6pbjOaerMaE8cvVSexNZi7VN+3xmCgvNw+YyIwNDd0KcrLw+WwU6h
         zJVywcWTzRZPN7+tBLoOdVn3M7AI9Ami9FnFTW8GvfBoF0oMjw4NKZzrA12O0+bHJ9UF
         hPqQ==
X-Forwarded-Encrypted: i=2; AJvYcCUOISF2I3WUm7Uk8NdxNg0oIyIHmaZdcxJ1uP/ptAaRZ/sqI2kxQz4jENUJtPIWJYWsW+ZZGA==@lfdr.de
X-Gm-Message-State: AOJu0YxLYdHVbeJ4wsFeTa/3mjW0Dt88F3Lc7bkCMRVUyOoymK1LOAtp
	Os1hkmJdH44XjVY3TG3SQk85w+GsGu3Z0id97Fku1ooTksElIp53v6fs
X-Google-Smtp-Source: AGHT+IGyTbNS/f2oZr5r0C6iTWHbau8ULEwGcD1OeirZHPRA3EMLsFRePWmAt9HsLnlyFHL2UzMjEA==
X-Received: by 2002:a05:6a20:3948:b0:243:a251:cf65 with SMTP id adf61e73a8af0-243d6f52621mr1799287637.49.1756543870348;
        Sat, 30 Aug 2025 01:51:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcxHsC9xh1UkzethtC7TBtCtPVsBTJNu6Z/6AdswW4Gnw==
Received: by 2002:a05:6a00:f8a:b0:730:940f:4fa5 with SMTP id
 d2e1a72fcca58-772181dbd7cls2874449b3a.1.-pod-prod-04-us; Sat, 30 Aug 2025
 01:51:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUNEQfa/i8zVuE+JWbqn44C0xxBCVGpt5hfbyCq7LJbh1yhj+A7ScTtzxspH8SbS27K2YxmQvbCBz4=@googlegroups.com
X-Received: by 2002:a05:6a20:5493:b0:243:a3ba:601f with SMTP id adf61e73a8af0-243d6dc80a6mr1853865637.9.1756543868816;
        Sat, 30 Aug 2025 01:51:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756543868; cv=none;
        d=google.com; s=arc-20240605;
        b=S1HTDOxqBAaj2VUygOJBLGfmZO5W1iQq4JGd4p7WGvuVEdv/T78Fgxxpkh69an916W
         Oig75BoDQfTxlm/p7TVLsJYDfhL2BAfrYSo+bFu3YgVgo7jGqGYGb3eDwqOiHkrqQwT+
         9QYZxeej6s/pLc5n1B0Nn2e5gWlCJDEurDS9uI54+P3HnHA78svJeYCrQiWJ/QoFN+BY
         nXNOTi05H1j43VXAVDiC/toYsrk1bRngt4NPWrh3Wi3iB7mpKgWyqKGHd2hsB1c2qvYS
         vLUjaDBt+l/YQUhJSIXtowHsPc8s0axBvCUoHk6tz4z8exJ/b8e9PdP4bCF+S/DRpas3
         C98w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=XvJAs0oWctTv+IZjXYqOb/DT/digU3gWo9ZFZvSPVF4=;
        fh=qATwZx/l/RieOLvb1uSuoQNcMHqfMMcujWLE8khEIiY=;
        b=dGVIGhW/iDizFtBupr4RRtrYZB/MaAelMOnBeLgkdrJAjv3uPri9w7mvKHp6mBwXkI
         +SxelpLgGsWjioLNR7gV4Q7t1x3Nm4iSjWckcBtB1lB2IL4mY+MuA4xuozW+9DHhmVuu
         wMPu5dukRTGgVE7uSgaGRny/3e/NB+KO3p9bDEd+TREEzZ27jtoua8QIOrO7HVHe4+k1
         uJiPQq4rZDbTe4U0/rVPD09LwGdY+aiAP7l0eKBeUmlaptGFH1vAAjXfmwgCELhZ1XCB
         W8Zl95T+d9UnZxPR3iOkiJe4xLRBsnuoRiCPJzkubdhUH//3KNm+fcpyvYVewl19uXgy
         qgBg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@hmeau.com header.s=formenos header.b=GuMcrSCS;
       spf=pass (google.com: domain of herbert@gondor.apana.org.au designates 180.181.231.80 as permitted sender) smtp.mailfrom=herbert@gondor.apana.org.au;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=apana.org.au
Received: from abb.hmeau.com (abb.hmeau.com. [180.181.231.80])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b4e61004f72si48945a12.5.2025.08.30.01.51.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 30 Aug 2025 01:51:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of herbert@gondor.apana.org.au designates 180.181.231.80 as permitted sender) client-ip=180.181.231.80;
Received: from loth.rohan.me.apana.org.au ([192.168.167.2])
	by formenos.hmeau.com with smtp (Exim 4.96 #2 (Debian))
	id 1usH32-0017AV-0k;
	Sat, 30 Aug 2025 16:50:53 +0800
Received: by loth.rohan.me.apana.org.au (sSMTP sendmail emulation); Sat, 30 Aug 2025 16:50:52 +0800
Date: Sat, 30 Aug 2025 16:50:52 +0800
From: "'Herbert Xu' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, "David S. Miller" <davem@davemloft.net>,
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
	Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
	Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
	Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH v1 32/36] crypto: remove nth_page() usage within SG entry
Message-ID: <aLK7bP285OO83efR@gondor.apana.org.au>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-33-david@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-33-david@redhat.com>
X-Original-Sender: herbert@gondor.apana.org.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@hmeau.com header.s=formenos header.b=GuMcrSCS;       spf=pass
 (google.com: domain of herbert@gondor.apana.org.au designates 180.181.231.80
 as permitted sender) smtp.mailfrom=herbert@gondor.apana.org.au;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=apana.org.au
X-Original-From: Herbert Xu <herbert@gondor.apana.org.au>
Reply-To: Herbert Xu <herbert@gondor.apana.org.au>
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

On Thu, Aug 28, 2025 at 12:01:36AM +0200, David Hildenbrand wrote:
> It's no longer required to use nth_page() when iterating pages within a
> single SG entry, so let's drop the nth_page() usage.
> 
> Cc: Herbert Xu <herbert@gondor.apana.org.au>
> Cc: "David S. Miller" <davem@davemloft.net>
> Signed-off-by: David Hildenbrand <david@redhat.com>
> ---
>  crypto/ahash.c               | 4 ++--
>  crypto/scompress.c           | 8 ++++----
>  include/crypto/scatterwalk.h | 4 ++--
>  3 files changed, 8 insertions(+), 8 deletions(-)

Acked-by: Herbert Xu <herbert@gondor.apana.org.au>

Thanks,
-- 
Email: Herbert Xu <herbert@gondor.apana.org.au>
Home Page: http://gondor.apana.org.au/~herbert/
PGP Key: http://gondor.apana.org.au/~herbert/pubkey.txt

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aLK7bP285OO83efR%40gondor.apana.org.au.
