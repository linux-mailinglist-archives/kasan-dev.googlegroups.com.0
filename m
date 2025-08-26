Return-Path: <kasan-dev+bncBDAKBT4T3QFBBNVOW3CQMGQEPMGPJ6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E9EBB35AE4
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 13:15:04 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4b10990a1f0sf156922381cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 04:15:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756206903; cv=pass;
        d=google.com; s=arc-20240605;
        b=IKVV5ik3XFJkWY2krhDkPOr+5oYcFe52hfaFNO2bvJkOVX368exaKgMQV3rnDT5Xr9
         jNzLk+sIln8swnGf4M5kgBUshUSMF1ZRv80gAXt/LH9GZ8gM3efzL7cZnIahDV+p4/19
         5BnGcdcRI3XjjGRBdXkRocMm37tFGuUDwDocVyhx3xqkg+0CK/LnwUqL0mO6k+1Eb6Oa
         NRnlHSi6XoXJdHVf90mHEPvVHSDFJ+PpHoBHqXwsJGcne6NF39+RqPDPlFJStgrVayci
         peXIqfqbYug6gmB+MrL2uEQu219IEaMuWaysdWDWUeLHhoA/Bd4jarv6/r6ZnX6AKxDV
         2bMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=526iM4MJsKMDINwnRNaKoXcmMQGQknKFiTH994y+4IU=;
        fh=BxkUTUUlcpgA7rbX1GuuKn6xDu2JE7jkmD5P9efttww=;
        b=eSsXvqBu/IphxgW62kfVBRnwF5KMG1svHjs4u2upwTbJswvQlJN13BR3E5LFIUV7um
         JQwSSHKQJ+zFY0/T3rY1nx+WsnXO8edftlT8YhtkhkMOAkBLgJXZAzuvHluXLUoPai/T
         QZ0Z61/1UEiMpr9i2MzTElJCVjGI75fx4gB0HLPkWqYSQjpksGbMz9VlA8FbW4E2n4LC
         oRsD8tlSecmBxAwWUWtaMs5MXEg2PCTNS0Ty/WJMbM+5YrxpmOYTFqTl73HIM9AiUw6h
         evAD6VeuOhOZ/TrXgtgkNJm3nK032fBN6mK4FxCT10kolJrITRUyWLCF3fJIMvnDH5Wr
         vp2g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=bkKDgAuF;
       spf=pass (google.com: domain of matteorizzo@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=matteorizzo@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756206903; x=1756811703; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=526iM4MJsKMDINwnRNaKoXcmMQGQknKFiTH994y+4IU=;
        b=mFaPKePSIH6L8KqU1m8XZNYAMDmzoEFexhhUo9d442pJccw2aCCSnqfev+/eOQ6i0i
         YQdE14RNAG063a0t2NrsZOZPkedRlGZnYPNzmwpTJ85kvbZQfee7LWSGkQkM32qr5PJH
         EVbnlsyp/wFghrCFMXFiHeBjcc404HELwNDmGrCtLoegyEEc6eWIA2B3Su/ZIsR58Hc3
         97mCZh6Ak/+YBK1NO7PmL2/ySi8rDPRH1Sc3O30umPHKyL9jYbVCeEFjD1ZuZqbA1pPy
         VQPclyKkTV1daTU1yS5Z0teHmVeyw50eesNuJlDsIAZZwBfw+KzbR6zxPVmp6oqnqdKh
         3RYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756206903; x=1756811703;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=526iM4MJsKMDINwnRNaKoXcmMQGQknKFiTH994y+4IU=;
        b=krn0sRUXiPTdlU26Fo0cAg21BIynbuvzi/Vp/i2w1E5zjqRNBoHoPTHkhiBDXcymcL
         xGBBqrDu2LzpNAKjKbQuB9UdDxduNM84vZ7MqLO9sXk5AAjN7BrLZe4WjZcXndwmflVu
         pp407CKsTgNGDmwd5ZCIAfnn0sK5tlql83rNhwt0NIt5oZSmkHn53m9GNKYs6qvhaQQU
         xTRn9tAQjcpvJae/cGva700Ayz/Tr24ARRcKhdIG0qZdugxncYN+mUcYTnVfIHJ3ZkHA
         NYxvav8Dwy6OzOLTebf+I3HoAuxP1w1D676K/tUnysiGBXMesHkOnGCAQUj5SNzZkUOq
         yPng==
X-Forwarded-Encrypted: i=2; AJvYcCWHukse3MS8fPF9i3ltjuc5TWvCIbX+bZyJLcoziAol2YNxDsItzB/kt9coPiHRwmId+/uxAg==@lfdr.de
X-Gm-Message-State: AOJu0YylsjdWb6wzArHKs4fF50IR8b1m0+qITRm7PJ/uLioj+Ic3lPv3
	1oZfVBrRhEx642y12K3BeduJQY0FWuBsZiPA8TaS0ToW7lkLxr7F2kKq
X-Google-Smtp-Source: AGHT+IHf0ThWGeqm1B//zbQwoDXFEkRSwcqB5Zhi2EBkUDtys7I8/sOhrrs6FMAV4krL0t2qDuhXPg==
X-Received: by 2002:a05:6214:4b07:b0:70d:a31f:8dd0 with SMTP id 6a1803df08f44-70da31f8e55mr132998666d6.31.1756206902733;
        Tue, 26 Aug 2025 04:15:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcpF/rQH55OHyiBIp2av7lLKO7Mzs5R73naeu4wS8sJ+Q==
Received: by 2002:a05:6214:1d22:b0:707:6c93:e847 with SMTP id
 6a1803df08f44-70db0ed9338ls47892706d6.2.-pod-prod-07-us; Tue, 26 Aug 2025
 04:15:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXe+KiVy3Hy8cF8rfBxTX3wWRAiUXDiQ6pqJvbQ7YsEeuilTXCWUwshJIEIySbnTGOMBdVoZaNh6IY=@googlegroups.com
X-Received: by 2002:a05:620a:280b:b0:7eb:ccb9:5280 with SMTP id af79cd13be357-7ebccb9531amr1241157985a.19.1756206901087;
        Tue, 26 Aug 2025 04:15:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756206901; cv=none;
        d=google.com; s=arc-20240605;
        b=f43ON2h8MZ7DCxxnxi606JzCZ8mh3KhIAqU9jP8khuimd0o3jnry0C4xQgoUtbgXmp
         DQQJ3v/hOPj30dVn4PwjS3jwd+UjDdsimw9krK0+TSKNZ7eX8nY+l/CvEDM8b/+d9wcr
         ej/5rm6/ntBix6ZZRxafFAepHyhJtTqOOp0uOJjuH14IpzU31qr8KS/xFy3PJK4731As
         CEuW0yEmb3jBuDkWd1/grlI9D4OfNOnXSH05IEauKqD6z3IOp5LdgHEmwUqgMnqA3/FV
         sH5bWEPH4AqQEzBd/wGaIaTKXwNpHnc4jg+HDl6ydN1uk2Yds+VQkJu3O9QMojImr4bv
         BQWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yNKW1svPWQYfwzN+Mwhz8LUQicThZsVtWpSBP88B/Xg=;
        fh=cITESEgAvA4S3bSncVE4dhlV2DieoJ5dESc1giXA2KY=;
        b=C1oWNZyzvVoa7KbEp5MlhvBeRY7DRxQf7QpeEVcmYaJfq3etv4NhpNgo2fHiL2hOs3
         5kgZ7dwE5WK3mB0E0n3MlcQhHmrvVE2bFH1oBsYmi6CNfmYxTmPKtrjGRofU3mu5paaO
         w5luW3+cee0ckkEp5InFDzNBaz5OCB84zSL5lOUre2eqnMraa/C1eVhxVRh9DKoZkQrv
         CUKJKbCTH2xSfaRq8+gLoVMgj/SUyz+egAzmLkMM/IpDLAjijh6KeP/SCc9YDMs1Vr7P
         bE8S5AbU9BjU4o/P8ak/03fMvUOoLzIr10NL2cR7ADvQ4lquwgvjrw2jyba2G+x5nl+b
         wfOA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=bkKDgAuF;
       spf=pass (google.com: domain of matteorizzo@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=matteorizzo@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf35.google.com (mail-qv1-xf35.google.com. [2607:f8b0:4864:20::f35])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7ebf03c4a9csi41533085a.4.2025.08.26.04.15.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Aug 2025 04:15:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of matteorizzo@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) client-ip=2607:f8b0:4864:20::f35;
Received: by mail-qv1-xf35.google.com with SMTP id 6a1803df08f44-70ddab8117cso311006d6.0
        for <kasan-dev@googlegroups.com>; Tue, 26 Aug 2025 04:15:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWZI6yy7u8/6sRUAH6wz4YbjkQM8ne6Ij6PXvq1tMbsx0IfgpdN4lxOIxtEA5rvTxiadO3R0o/cYvQ=@googlegroups.com
X-Gm-Gg: ASbGnctuhFce/wnitdEJsaBAgmWQqtLsMfHHLAykKgEy3XnZ4yFCr/8/4CPNvGuoWcl
	pNp+5HwbnUntGrVxrgp+6ip+HFkT0DIpsjteuAiAOiGESddxUm3GEo/BQxirSc47E71lrBCBcHe
	9mIiqvw0JqCLgTRih4mo0RhHMu5JEyWTGA8Vf4UEARhxoRfm3gyXtMBAb/MhbwjSzTE1YcCuezk
	mL9KS6nvvd26yfE/Svn6DN9V8/NUxk/snaawDwhxABN6N0bu4E1CPQ=
X-Received: by 2002:a05:6214:20e6:b0:70d:8665:3c5b with SMTP id
 6a1803df08f44-70d970b2b0dmr209892786d6.12.1756206899995; Tue, 26 Aug 2025
 04:14:59 -0700 (PDT)
MIME-Version: 1.0
References: <20250825154505.1558444-1-elver@google.com> <aKyT2UKmlznvN2jv@hyeyoo>
In-Reply-To: <aKyT2UKmlznvN2jv@hyeyoo>
From: "'Matteo Rizzo' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 26 Aug 2025 13:14:48 +0200
X-Gm-Features: Ac12FXyU3fT-SuKRuDR_nD8uSQNd7DGjj8J1BVXdXRtps1xhjblio7NMt2GtdbY
Message-ID: <CAHKB1wKZmp2Rpw0zry70i16-c3FVkwtb3-XpLs5P1s4eABDD=A@mail.gmail.com>
Subject: Re: [PATCH RFC] slab: support for compiler-assisted type-based slab
 cache partitioning
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, "Gustavo A. R. Silva" <gustavoars@kernel.org>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	David Hildenbrand <david@redhat.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Florent Revest <revest@google.com>, 
	GONG Ruiqi <gongruiqi@huaweicloud.com>, Jann Horn <jannh@google.com>, 
	Kees Cook <kees@kernel.org>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, 
	Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Suren Baghdasaryan <surenb@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, linux-hardening@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: matteorizzo@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=bkKDgAuF;       spf=pass
 (google.com: domain of matteorizzo@google.com designates 2607:f8b0:4864:20::f35
 as permitted sender) smtp.mailfrom=matteorizzo@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Matteo Rizzo <matteorizzo@google.com>
Reply-To: Matteo Rizzo <matteorizzo@google.com>
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

On Mon, 25 Aug 2025 at 18:49, Harry Yoo <harry.yoo@oracle.com> wrote:
>
> Not relevant to this patch, but just wondering if there are
> any plans for SLAB_VIRTUAL?

I'm still working on it, I hope to submit a new version upstream soon.
There are a few issues with the current version (mainly virtual memory
exhaustion) that I would like to solve first.

Matteo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAHKB1wKZmp2Rpw0zry70i16-c3FVkwtb3-XpLs5P1s4eABDD%3DA%40mail.gmail.com.
