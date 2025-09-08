Return-Path: <kasan-dev+bncBCLI747UVAFRBRMIRLDAMGQEUAUBZ5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 291F1B52B45
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 10:11:51 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-72e83eb8cafsf7914026d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 01:11:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757578310; cv=pass;
        d=google.com; s=arc-20240605;
        b=WpcKYLwKFnrgejDHrk86pHhnbw67L5RkkK3V3b/DFHhzKrsNqPI6GlKuNHLfUB0oWe
         sDduqCcL7Nx86Dm9+8JxgrJPLwXxsqry315z1otDccIXdu3saicAomXcoQkp3mIzOpmY
         MERhe05YqjHlNg8dVm4u/1wHfMAZ5CjzvFlBTTzXo1NOnaBz1nO9OMsnH6fH9okxFjhp
         8BFzLRh+ELothtg3frihETLfSOms1X0DmlKElmiB9Rx9b5pRS70FaczvHOXdqnm1hiY7
         L5BSQesp9PihuRLNmbhME45LRJQPuoY8w16z+MIZlYK8lC5SjkDkHTUExJwv8e2SbwGd
         PMXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4svnEzBTI8cTNMFbSuoEboupw4ySZ5escoLCk5vqb/k=;
        fh=Z3opW5QkMLF+zhFqghT9MeGe0A8RvsZBY75msiBVJss=;
        b=kE3OFH1IOamlUz3YmTHofqTbRpcoIHente3WYnsRACaXxY8UJ1GEMVU+BNHgtthKu1
         QO5//8SGOwCMI3qcudjiYRWTk15AaJ/Y8bZQS8/+FFKExnHjQvhioSw48MKjR07qVY/e
         VBM2s+HRlcXA3JyZdFrbRlW+iaKXM33sikLsScNsmv7tqwPZFfagarraCrz2gbn/IDxf
         sHCNVOQu3zulnRqvQDhd6Jiq48qoaV4df4p6tQjEsO29xxY7RXwfFwBhPHRZR0kcUiPW
         H73ZNwJ6QVgZrvMbtEiqYP2iW4sm7iswMgc8ChvBfHBXy59mcoA/b4FeGn3oMQxay/To
         2u1g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=Xljewnqu;
       spf=pass (google.com: domain of srs0=isgx=3t=zx2c4.com=jason@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom="SRS0=isGX=3T=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757578310; x=1758183110; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4svnEzBTI8cTNMFbSuoEboupw4ySZ5escoLCk5vqb/k=;
        b=FpCcKSqCgzCTJr3nuemI3KWdi2XSX+ZI5Kc6E8Tvtp09sF45jo82f2x0e1fhCbnpF6
         TSG9mxsN8H4oN57tEpDUskkMesIjxZtaWNn7FJDwsZkf2F7zvTSF5Y9ReuQ87rLT9u4G
         36hYjceIOE8fOTRaT384PJmZr9WL+xbMOctJHB0OGPpFLz22/o19SAQ5/VxFtmzDbTS+
         51KlvXKw71dL6czk3xfuHozAB9oVsU0kWeR0y/405vbklZ5BL7hHrJMp3aLzH0/NWHfo
         DzXy0Ddxhl6CZjntldVhEOvfCWZnXefnjpTVPJef5zvGHaeaAmcn6bzBnjhUuv9Yif5a
         WYOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757578310; x=1758183110;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4svnEzBTI8cTNMFbSuoEboupw4ySZ5escoLCk5vqb/k=;
        b=HVvHaYoxGdS+sOS+cBFVaRj0htAoyJWx4+Tl9N3TBeurXoVDn7aEWQc+X2yvb8XyiI
         gIgzcHLltb/szJ55sXzPlzjhrd/i1m6THrawtgWBlasIopMJOihOoPaJ28/+VwBOcgED
         +ZD+KWa4n++L1P99hg5PImPUKF1C8cMp/l9ox7PZtDXBQFe1fh9ktbLmh8x2/kDXMa0y
         +xBmKthBn+zfptItK6yzAyXFfVPqIvPIzG+kc3Mu9j6Uug+t3F87pgB+VoCWeJUWmfmi
         lwEk5kupo94kkk0XdAigKZFdcJgTi7CtcTJbL+4+JupFhDkVLTnjSOZFwO2J9xcY/k7D
         ycUA==
X-Forwarded-Encrypted: i=2; AJvYcCUzO9kmjJBYdQ9PRr6NzY8sr18F5eFm5oj1H+SroplEVk5Fr4ELPL/U2SreGQrUgA209Z+WxA==@lfdr.de
X-Gm-Message-State: AOJu0YwFDgCbVe2wMTbujXfPlJkHeYWiB9DbF+rzpCvrzj638MDqt36n
	wNRbh3ZFysQLCap1uAHBJG7aBNM8YDgIA2P3o5zjfIafeuBFS46U9iGs
X-Google-Smtp-Source: AGHT+IGFv1yU5hCCnRXXG+69sC+zUZU3cihkHDQ4PqZ6xLyBeR/tyyG5ttLU9dcGV0J+qSJnruLn0A==
X-Received: by 2002:a05:6214:488d:b0:742:90e:d8f6 with SMTP id 6a1803df08f44-742090edebbmr206771366d6.28.1757578309706;
        Thu, 11 Sep 2025 01:11:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4isIJTe925wa5QYiKhxxVIp1iTpd/2UqAgppuUAyVQLg==
Received: by 2002:a05:6214:f6a:b0:70d:9340:2d97 with SMTP id
 6a1803df08f44-762e4c92309ls7795756d6.1.-pod-prod-03-us; Thu, 11 Sep 2025
 01:11:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXaOgvgB5nVJfu1Ov32HUTjmzQZAjlV9dzjwwq/PrZ/Ylz5L0mXnXA/t45aCtJ1ey1gyOPe7Br2nYo=@googlegroups.com
X-Received: by 2002:a05:620a:470d:b0:81f:eef3:b0b7 with SMTP id af79cd13be357-81feef3b0c9mr344945485a.10.1757578309207;
        Thu, 11 Sep 2025 01:11:49 -0700 (PDT)
Received: by 2002:a05:6808:2221:b0:3f9:f009:458e with SMTP id 5614622812f47-439b14f5491msb6e;
        Mon, 8 Sep 2025 09:47:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWJ7OlmLdjIXeCBghSMsg8UV33+NG2qAvSYFDOJhY/0Q8cG2+uUUKNNNvNw0S4EFniL/G7jSb4l2rw=@googlegroups.com
X-Received: by 2002:a05:6602:728f:b0:887:516e:bb97 with SMTP id ca18e2360f4ac-887776d8c03mr1382852539f.9.1757350049249;
        Mon, 08 Sep 2025 09:47:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757350049; cv=none;
        d=google.com; s=arc-20240605;
        b=EckhZ57Wq5fi1Eb7MzgpeBZbEnP3jt/RHGZ/4kCZvEZc9MaCLcnOhVSKIyQAcsD1ky
         EAwiZyssMgpAddynz2agzevgOvBKwjHxdZTR3NbpKraEPcVUHOyPoh++qDT9Qpp5WyxF
         edyrv2Eb2LWF+A+9nEjU/MMVD2caJEi2t8jDjdriPOKQxsFmfkvAsLpimumhUeYD2vS7
         N6x8ufjOEJfReDh7UajyzDbgMltmEwE3Dmvq9SfVd0T7+njPQeg4ChyphN64Hb0UoWmc
         KIEIJilejfutoWWUgoqFFMpOfnQsmwNQXd8rRe4xXtKG24DiwT5sK/wSOhcA/nDB+6za
         PccQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lHuXjtnGIwA8Zzr3bT7RPQh03xIe4TvMRJ0gk9Qtcas=;
        fh=pWLdePR2nngtu/MT4KVSyMrvf4VDAt/k/HPNkusrOnI=;
        b=JVgNjC4cjPMUlBaLWgPpTGtVraEgHZztSnJdMASF/PeU6EUD+5rGk9JDAD+wmljOXk
         QmjgaJDHl6rQflOI1AHwIksMXSJUvKbXO/EFzZJfthj9Hbt6ADhVJmq+kHSyl0FpI9nn
         MX3Os962fJMXo5yb7wkxRVQCwDWQm7qIgKt2924GNlV9GX62v3c+M1gPD2P7e0cujmJI
         QPCZrROS0XHCBWrs5zDtjs5n8KRuHCoW5BGzVgp9W1pOTwpzvht+UGjeiZ2DFb659Xpd
         SGofVEZHEzKa/Bt+AXUcfWzU5X/NANojXMFXPKVoPgMuiYMFQVQLZxAERTAmT4zmn+Jk
         i+RA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=Xljewnqu;
       spf=pass (google.com: domain of srs0=isgx=3t=zx2c4.com=jason@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom="SRS0=isGX=3T=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-8871e3d377fsi85118739f.2.2025.09.08.09.47.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 09:47:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=isgx=3t=zx2c4.com=jason@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 64B33601FD
	for <kasan-dev@googlegroups.com>; Mon,  8 Sep 2025 16:47:28 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D15B0C4CEF5
	for <kasan-dev@googlegroups.com>; Mon,  8 Sep 2025 16:47:27 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id c4a054d8 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO)
	for <kasan-dev@googlegroups.com>;
	Mon, 8 Sep 2025 16:47:22 +0000 (UTC)
Received: by mail-oo1-f54.google.com with SMTP id 006d021491bc7-6218ef6bbd7so331195eaf.3
        for <kasan-dev@googlegroups.com>; Mon, 08 Sep 2025 09:47:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXAczd6FrhiQwrzDN4Vm1NySgIDxoavBDSCujitVT3dDnQrwLsd8WzZINglAADf6bzAlN6eXc5Wjt8=@googlegroups.com
X-Received: by 2002:a05:6808:2e4b:b0:438:37eb:62b2 with SMTP id
 5614622812f47-43b29b952ffmr4287499b6e.44.1757350039548; Mon, 08 Sep 2025
 09:47:19 -0700 (PDT)
MIME-Version: 1.0
References: <20250821200701.1329277-1-david@redhat.com> <20250821200701.1329277-6-david@redhat.com>
In-Reply-To: <20250821200701.1329277-6-david@redhat.com>
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 8 Sep 2025 18:47:08 +0200
X-Gmail-Original-Message-ID: <CAHmME9pO-g4qUUsbF+XZqcPcwfP3-N7AxR+MX6G73adc2-NAkA@mail.gmail.com>
X-Gm-Features: AS18NWDayNVnEOpkO7Cmy5o2hUWkz6cio8gfE7ZsOxyaASSZD8l09i-KslFVPvE
Message-ID: <CAHmME9pO-g4qUUsbF+XZqcPcwfP3-N7AxR+MX6G73adc2-NAkA@mail.gmail.com>
Subject: Re: [PATCH RFC 05/35] wireguard: selftests: remove
 CONFIG_SPARSEMEM_VMEMMAP=y from qemu kernel config
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Shuah Khan <shuah@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org, 
	intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev, 
	io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>, 
	Johannes Weiner <hannes@cmpxchg.org>, John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com, 
	kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>, linux-arm-kernel@axis.com, 
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
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=Xljewnqu;       spf=pass
 (google.com: domain of srs0=isgx=3t=zx2c4.com=jason@kernel.org designates
 172.105.4.254 as permitted sender) smtp.mailfrom="SRS0=isGX=3T=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Applied, thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAHmME9pO-g4qUUsbF%2BXZqcPcwfP3-N7AxR%2BMX6G73adc2-NAkA%40mail.gmail.com.
