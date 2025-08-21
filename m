Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBHEET3CQMGQENFI3Q7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id BEB2BB30581
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:31:26 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-32515a033a6sf247185a91.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:31:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755808285; cv=pass;
        d=google.com; s=arc-20240605;
        b=dpQKwB2d1i+hS3/QkKz7OBGLdret5yfl+xDNqL+YsGupPkK3ju4ktz7GrXNZo2mxyX
         GqfTD1KYcYX9ytVnCTTiTeeCeZIPIA+9183eFZIN6BNH21x5w8U+6LzjYMiO9R7lYMfm
         +4sIE/kWBDMAISTyt3hOEpES4LehAX4JDZ2YI4zQxpDkZHIGQp71OzrEtEAQJjQrl0Bi
         G/zltm3dNAnRpav2nmex90JaLhVgNakooxL7WL1SKimj7giehxDyxMSw+D6kGzw/0Sr7
         rQUlhlAXJGrJ1jOVCg5cC+oK+xVgwa317w0wzYiIFz8T/P3Y6pBs+OBecXXWTsafwdNN
         YmcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=x1OizSSfv5SwDf+7P5sxGWisX8JbFvqW+US2FSHAKGE=;
        fh=mXqcMnEzMbvgBgSjrEtCyqbSC6s8IdlzuUFYpDqFnOw=;
        b=G/TUt0vOWxU9gMvwhTmbATnaDf0QSgaXFPZ3/rjlUsqPDjplOc0o2V1ULCeEI+aSfA
         J/p4GqpcN5u7z/34/lN48pjpwzBLNOpx/IQ5M7sTpBzQ9NJAFiJcagH63N7OdZZAI3nj
         nLZ222Ml1012R9NpLs2LpsMvJSJZ/bO2lmpS714op34n19AAnPgzd+qM+9LmghqCS5rj
         QOke4aJILUEVLFoOvWohsWLFaLJ0UzFBqGQB1iY41A0cyAOf2kk6hJcUTK3aULYDLzDc
         LTD9vuQVZIppD/XNpmWfhRI1X67aS1pQ9agL+jIK1/UZTDKAygDixd4g4PS2dx3Frr7s
         2Htw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=EFA06Jbs;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755808285; x=1756413085; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=x1OizSSfv5SwDf+7P5sxGWisX8JbFvqW+US2FSHAKGE=;
        b=OIT67DW1gxRHEOt4xB7D2filtPNz05P7RAEIz5QPUz/xi3hLLbMUVuHmxU36tjpTl9
         XVe7KYo4HMMYO1b48Pe6bUXz+H8Z62C4G5rk+IxvectyrGJbGq7WGs4Pjx6s+hB7o1IF
         L62YYMTe/XlFPVpo0kgzxu9EEzF7ugrRCars16pG20g3wog5LlkGlnAbv2pRPx/8P7KI
         TR4IlP/71ctfi9mpsJAYmAQXwrCAnvqmOzVHIMEWEB0VvBxMhG4E1A3NODUjguSZSCfj
         CFYvEENf105WmJYKTqYJkQ7Fftsdj6+65PWPZMJgy7YkXfRm+ZW+Lg+3589uwDRYlpH6
         M0sg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755808285; x=1756413085;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=x1OizSSfv5SwDf+7P5sxGWisX8JbFvqW+US2FSHAKGE=;
        b=VmuxMognLy1gM/ME4g79Vf1vzWV/aZTAtEmNrY/T1mu7olS8/RaRPd+buXBvSenFrR
         LKrqo+Ayvza4dsy/18DrPmTVtIJu0VXFrnELw8D2SKuF4xD4/Oixv3BGXa9rjMP6mRe3
         0D1lxeQoCV1qZJUNKHpxByLKJ+faL7FUR2nJ1hKFfEFZryrt0Rp0AlgRZ2dHH0FGnCFQ
         +kwMjYkFdopKTa45ldG6xxWKDe/HgId/gkD+ZoML6i452G+Xpe6tB4rK0s8gpxTLKGRt
         SI2RQbXskUQ70ebzsktyueSjF26TDRwvm0022R/UHtLAO//w0j0lW8O5EXIwcxWv++vp
         wrsw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX7bQqoKG2Hyk/7IpQIJ2mxhYz8WT+aswnM0+tYtf8wQttRdX+HEc8wSN71fKDozpIR7KzwBA==@lfdr.de
X-Gm-Message-State: AOJu0Yyzkp1Th3lsFaLdtcKRMoiIQKqH6jEpj0BwHFkStgCNq66pbhmk
	d6yZlgOo/1IQI/K6iVcJh93aC6fSkMC61mahtu/AFbKdgFUDHaugFFyC
X-Google-Smtp-Source: AGHT+IEVq8C8PYZWBs6cpZNI9tWctvraBiILWS9JMUr0dR07jRWwXJFQgNz9xX6wHfPNZU7uLv9EVw==
X-Received: by 2002:a17:90b:530c:b0:311:9c9a:58d7 with SMTP id 98e67ed59e1d1-32515eaede0mr1205439a91.19.1755808285233;
        Thu, 21 Aug 2025 13:31:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcWEEomJKR8bk2Q0qghJek/LcbStnuLJHE8ZZLM65wEfw==
Received: by 2002:a17:90a:d2c3:b0:322:129c:381d with SMTP id
 98e67ed59e1d1-324eb6b9697ls909644a91.0.-pod-prod-05-us; Thu, 21 Aug 2025
 13:31:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU7YrsYTzWPuUpMqELfCJobzSQP1TAwfBVYo+iIb1O+kI/Gc33RW3zifehZolkhC/8iHB3nbXmqETA=@googlegroups.com
X-Received: by 2002:a05:6a20:3d1a:b0:23f:fec8:9ace with SMTP id adf61e73a8af0-24340bd0efcmr542524637.11.1755808283537;
        Thu, 21 Aug 2025 13:31:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755808283; cv=none;
        d=google.com; s=arc-20240605;
        b=MxJY503xKo/0y0sWr3KFg4pIHnr92frFYwVTy+oE9RezlmO7m8q2mD6QyhjVPvGuAd
         MN1xjegMIXAjyql0qK/AdhMIUsu9zDIqEpzaJMESIN/XwoDWomRiFJIfe9QKV8jxiebo
         uHboVvOZn5fmBSNr1cx9dgF2n5iK+EBUX133biACJh5HGWIcGZJrKrY4PZ/rDv/q3hU4
         54taO0l+fnnGJFcnmu0adNLpjAdcDUhnwLkAwmadt5JsJ9q73D1GxllfwynYvVjrEoNq
         1RBQssN5dvppJib737VNQb+J7SNMH/3s7oJQjp6076KUDTP9V0xUMigRw3nsvdTEzyle
         IUyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6aeG3+zXNcZH2d1Z1/su6zkQOg7Uc4j3Xw+oqie+iPw=;
        fh=9Ey92zymby7gNBid2oTiik0/4o99dU3oAkyCxrh+15g=;
        b=KdLi8EVov42wowAqr/EqwDp3WfgmJlvoTffEa5snVHuY/bJ2aDLJreQjCyoodbYaqU
         mYMjGu70SFiV4Av9xLHtDeiB2MVud7D+ZlHQTox8YZvs9X2x76hRSOGlS8wUeCNIHqZD
         sKhCtlApYp9vyGUTgvb/0M0XQyCQIZ3jZqeT1E6rw6a35RH5/0zB9BUgftrvDUmlkUay
         LkIQuvxKIdwtJiNuSGOEmH36xNAfv2uPeW7f/tB3VAfXlz7hrQ/RId2eHo4QI8T+VYkC
         oJ4VOSZV6vsPbFjR7xlBovIuBRt0XWCsjNSHWfcrCru1UagM0z6lBw+Ir8TwtY7RbOL7
         6r0g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=EFA06Jbs;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x736.google.com (mail-qk1-x736.google.com. [2607:f8b0:4864:20::736])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-76e7d0f6783si406541b3a.2.2025.08.21.13.31.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:31:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2607:f8b0:4864:20::736 as permitted sender) client-ip=2607:f8b0:4864:20::736;
Received: by mail-qk1-x736.google.com with SMTP id af79cd13be357-7e8706a6863so172289685a.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:31:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWs+1cSJa6CcJEscC+fWvsTn0wgUgIX9J8MIeemLA7JFe3rLa1R1bIBPadFKpxGVs5LXjqbBzDQNK0=@googlegroups.com
X-Gm-Gg: ASbGncv0NX6fxV3kfLyYXMPVNV1HkdtOwIpFQqy8sHDNVjR60uki80fxqiZpHJUt42e
	IuSj6bIeFofBxuxDecUADCX4RKXcoAg7ZiH7B8aPRng7rUgnfnjupr0p4dNkmzN9dutXuLXSeWC
	OXWPH0UJ0vIMgBL7UbP4r5gul5JIX8oy5fLMCnA7o1/bO877qfdIf3iYaU4B3nW26pwWTwUVwPg
	oo1oUcYFa16ZYSyVdVfn+yaso4kPPo7GdoxKh52pBynCMLb67thl4sgwwC3F+bX0lM7cKDSHf6h
	16TJqQcXXp1zdaaGYMdfPuq42E/6J18OS22rrJaete4W3PTleVS28tY4Tj2n/V5Mw8t7WpsEijg
	LLEz4y1NEvbz1M5e1ZXyZZpCnXqmGdbn9+hQMxhWlIXJ68vsBIWD3bD1YlLdG/sXitGa2QMKgpd
	KR
X-Received: by 2002:a05:620a:c44:b0:7e8:3f25:d8e2 with SMTP id af79cd13be357-7ea11045e0amr70705785a.62.1755808282232;
        Thu, 21 Aug 2025 13:31:22 -0700 (PDT)
Received: from mail-qt1-f180.google.com (mail-qt1-f180.google.com. [209.85.160.180])
        by smtp.gmail.com with ESMTPSA id d75a77b69052e-4b11ddd693asm106278681cf.37.2025.08.21.13.31.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:31:21 -0700 (PDT)
Received: by mail-qt1-f180.google.com with SMTP id d75a77b69052e-4b109919a09so17882791cf.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:31:21 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXHjxE50q3GKAh/j1HCK6Okc//kGim4LEdSCQvdcsdNFdBy8mNuCfryS+dwQ3tg0WYWMGZ4kobRjeY=@googlegroups.com
X-Received: by 2002:a05:6122:1ad2:b0:53c:896e:2870 with SMTP id
 71dfb90a1353d-53c8a40b923mr212315e0c.12.1755807884664; Thu, 21 Aug 2025
 13:24:44 -0700 (PDT)
MIME-Version: 1.0
References: <20250821200701.1329277-1-david@redhat.com> <20250821200701.1329277-32-david@redhat.com>
In-Reply-To: <20250821200701.1329277-32-david@redhat.com>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Thu, 21 Aug 2025 16:24:23 -0400
X-Gmail-Original-Message-ID: <CAHk-=wjGzyGPgqKDNXM6_2Puf7OJ+DQAXMg5NgtSASN8De1roQ@mail.gmail.com>
X-Gm-Features: Ac12FXxaZhwn04a0gbwY6rjh9UGLxnRlGOG0Jy0WjRbVAG0UxLDqNy0Wydj0GQk
Message-ID: <CAHk-=wjGzyGPgqKDNXM6_2Puf7OJ+DQAXMg5NgtSASN8De1roQ@mail.gmail.com>
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
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=EFA06Jbs;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
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

On Thu, 21 Aug 2025 at 16:08, David Hildenbrand <david@redhat.com> wrote:
>
> -       page = nth_page(page, offset >> PAGE_SHIFT);
> +       page += offset / PAGE_SIZE;

Please keep the " >> PAGE_SHIFT" form.

Is "offset" unsigned? Yes it is, But I had to look at the source code
to make sure, because it wasn't locally obvious from the patch. And
I'd rather we keep a pattern that is "safe", in that it doesn't
generate strange code if the value might be a 's64' (eg loff_t) on
32-bit architectures.

Because doing a 64-bit shift on x86-32 is like three cycles. Doing a
64-bit signed division by a simple constant is something like ten
strange instructions even if the end result is only 32-bit.

And again - not the case *here*, but just a general "let's keep to one
pattern", and the shift pattern is simply the better choice.

             Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwjGzyGPgqKDNXM6_2Puf7OJ%2BDQAXMg5NgtSASN8De1roQ%40mail.gmail.com.
