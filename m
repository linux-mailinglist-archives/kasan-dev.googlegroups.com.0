Return-Path: <kasan-dev+bncBD4YBRE7WQBBBXUNYDCQMGQEE5H234Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id DB359B3954D
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 09:35:59 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-3c79f0a5bd5sf584452f8f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:35:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756366559; cv=pass;
        d=google.com; s=arc-20240605;
        b=fLKC9llExOL/f4rMMk3xgHXbYyg9Mo89BOXdgWcsuqJNK3doBGNQ1UNdBQB0cACQ4t
         ckIy+YIQMl720wmfqe4XmNKyUq7FxpskrB67KugOTJLnuYuZb67Iew/LSHjOoCVc8z/V
         GPzEANp0srpESMw0a+0gAgN+9pTysEL58t6wwxsOFofKue7Lv/AOGalnMlFmrrkPnaGK
         At2b0IMwMj6qpWxLDAtoiW1/7ptgIdfmfIWBgWS2DbAVH46NJA96S2z//HR0lTxe6rzj
         l9mWsrY9MyQo2dMkRDSj8T3RrtmKUKIdBiTMTZTJs7rbzA2PHtMbjdu5X8HR3mNJ9cvB
         qkEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature:dkim-signature;
        bh=EJRR8250Ya/8jj6rTH6irLtHLHS74a1oG9CnuG92g2I=;
        fh=n7dIGQxeo9eZ4LhbM6dqP3PDg8slPW7Lgu8FjzqbkpI=;
        b=BG2RO/isSiP+EMHg1Ucqqv44jhWVr0TKoTIjcV9FhLAxt17mkqF+GCzusOxVM6OKJH
         pooP+/H42Hlj1qScDRkuCh0QfoGYcpEYwJM3zEH0vARhFrqmXhP7oDy6iW2v/T2P+F1q
         0bN6jM3/eXZPxkesgQziwIlkqcK2v8F9LzhLMe2/r3lE3XtT77qVurTAMUAotZzqzy+n
         /KYVBEgUHy26gE69caM25KuMIcxDltBzwYaudZTMMLUwcNULUE21sOyK6L0NnCdet94m
         7RbH88PS7yDpU++/2yHv9qJH8zodVqWBO/t/1S1u15gr36U8ZH3LcGN62ZoNZpfOWlRX
         55pQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HkDWQqJ8;
       spf=pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756366559; x=1756971359; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=EJRR8250Ya/8jj6rTH6irLtHLHS74a1oG9CnuG92g2I=;
        b=HvnoOBtHPK/jtJWHHecS6dk914mhJjG3Mwoj2y13i39dSTLl3jcbKapeYRXKZh7gpX
         WGEMYbu30XPfNXYWYNSB+3vxuWads7nWmIWCab/Bj8/zjbM4j+GbIespwlQxSB9ljrPO
         g2Px0rtXjJoC/byfu4z+T5vmLtuPZjCAc9C7eFbxV1ssS6uNLHQXLMeqvLtPQCeCqzoX
         XuT91H4ZQhfLYPuG+kuZirFAO1r+v1RqKrjXffwd6FE8xJgqJiIG73iv0/2GBcCntcFe
         O+VaVBwbyMX6QUKwpeNre3v6YfoxD9v65Vgz6tcIZUsHFpmjx9q6DvmEtEsD3WeinEi/
         EPsw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756366559; x=1756971359; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :from:to:cc:subject:date:message-id:reply-to;
        bh=EJRR8250Ya/8jj6rTH6irLtHLHS74a1oG9CnuG92g2I=;
        b=GS9ROxiV2J+SJbRVzgqAy5QPrt298KzpD8PGNTNRiaqk6dI4YNbcQ8OPuAQ68HU4As
         h1uEgNhreJoX4L3VRh881ewcL7fxP2E8m94nvMxwWs41V55uuaFw4KJtmn6M1c0YbKwV
         JYI8c9iEwlZN8ZUa6PhyNjE8oOY2070/V1yliEQWmzveX7rm03fUuIwUXW5J96Cz/PAJ
         TSrLOxGurSCHz+vs7HbAKCesBfPEc5gX45UWFaUGwUKm2GAnmWGjKKlMKFBMCR4elJGm
         hQxUaJiGw6pcCFnZZ4aMu0m/Ad4Er/JQ+nQNtTxfCVCD9j80LBrHXqQN5SNSF1h4uRY0
         5h6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756366559; x=1756971359;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=EJRR8250Ya/8jj6rTH6irLtHLHS74a1oG9CnuG92g2I=;
        b=A/UEj2X/po6YeF2LyDKK10OwMn4NXFsegREA2Fv+RT/yVSs5DCMOK2ylOhrkW9rW1B
         qEP0zFJ5Vbcbm757nvl8MIMcZLpAeWrbWugDmtABS96BqOfbSWc2gPqiQUcHNeYu8Izo
         aF4JQY6xzP4gXKYF75CG9odC5VD50PAw20aMmTVcCmJ2aXB+JdCR9UMfq0XHNKyE1ykC
         SZ/J0ru0pY0QiSAeOaxwIv/ZbsN3hvy4wp+g6mw6P090FttBoeIB6MeHXSfAoxvjPjov
         sKTyp8NTS4/DuMxQBh457y23ozxL2xjqWNr6iZt1NJwmQQIr1vC3YNdSvZf9GU9UXiJ0
         OHSg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWSwGca5QRdYFcN6xSKJtjEbZAPfPesko/pgYJCUV3Dx8gj0V/O9a/hm4c5/Aj+Y/tnsv4r8w==@lfdr.de
X-Gm-Message-State: AOJu0YzMsazSGaq7/7hwwePaDVshjXuwguJ6L0uFU0H89Qkli5DTOUc4
	NKzU0rpc/xdmyB7ZVJ3uMlkVdK4VvwI2IuO+aiyEDRlXnAlOdmAShgqn
X-Google-Smtp-Source: AGHT+IHTQJqbzaUojGqaExd8h2u2+NGmvlUsa83d29+wXRs/ZngV1XxYEg5dCJXZpVZZyAluZ0f0Bg==
X-Received: by 2002:a05:600c:3149:b0:45b:47e1:ef73 with SMTP id 5b1f17b1804b1-45b517df336mr168958585e9.34.1756366558862;
        Thu, 28 Aug 2025 00:35:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfMjtLpqHWeAG3iaBhZ3KsgUrMGkiCwkHnt1P1rRmnlUw==
Received: by 2002:a05:600c:1993:b0:459:d42f:7dd5 with SMTP id
 5b1f17b1804b1-45b78796496ls2258535e9.0.-pod-prod-09-eu; Thu, 28 Aug 2025
 00:35:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVScgDuwqcyqvDfAmGaTQglkRCnsDXlkE+OHVZMa520a/3tg1UGqPr8T5P1fMWiNdkgN8DCe53FlvU=@googlegroups.com
X-Received: by 2002:a05:600c:b8a:b0:45b:72a9:28ba with SMTP id 5b1f17b1804b1-45b72a92c50mr38558545e9.28.1756366556054;
        Thu, 28 Aug 2025 00:35:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756366556; cv=none;
        d=google.com; s=arc-20240605;
        b=jxlUWcFFzmhuWWxx2bjjQ0Pp1vKfXx7cXaKLinJBOtSeIJ3ITt8/lPxuChSZsKd+qx
         7ojP7mR+dI39Ldcym3JRBRYahAVtWmz7LONnZA6Qn9Khiu1RIXHs85CAKi+yMyl8rmOQ
         UlliLFbbAPElkc7pv7VSxXK8bs/NYFF7WBIpNL1GX26MEQnvWIK5NQn5Ad3wyDqO4mq+
         rQbGrcx2kXdMraQVwcjgDA/4U2V29mKQNJXBs653lDwu44gRYe/sHrImyill2jV2tDyP
         TFAf4Rzj6YsqmMlJgGNadM0GpyiNgFj5Yhzdpqp9QafohqT9LKS7U5/NJ3nQaiOTKcf0
         0c7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=Q0BfjvXaX7EhpBrJcO9diF40ujDlSeO28TY40tQufFs=;
        fh=nD0FTH5uz8wHqWvliKgqgrxoNGopfKn8irSa00IrAF0=;
        b=jRY2mnHOc9jY89IXqV6H4uRyLI/EzbBX5VP1VEdSX3nFI2gSXwRg7C+VUm7NUxnF7n
         1A8axWZNk5LOlb7EI0m85YyPnt+EzmTcoO3ofs4e8MfTpEeqFkFm3SIPeWelJSP8QXbn
         RglJRBunZNUbZHFBzPmuTKgELa6dlDInz72zN5ZC7zB0UuwBT7tRd1rBGWtL0/AV+C3c
         tDBsavenA+hyFuuMI7zaMDc2NCc1k5jkmvMzM1XJaOiWkgLYDUJY1U43DzhwiESW0+Uo
         6N48bsw5zBCcX7isBBfz3VvfOu1UvnSguo7JHYq5BHKM31kH+n3C1MxOB+CjEpd3OPgi
         fyEw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HkDWQqJ8;
       spf=pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x62d.google.com (mail-ej1-x62d.google.com. [2a00:1450:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45b7322df19si572315e9.1.2025.08.28.00.35.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Aug 2025 00:35:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::62d as permitted sender) client-ip=2a00:1450:4864:20::62d;
Received: by mail-ej1-x62d.google.com with SMTP id a640c23a62f3a-afeee20b7c0so26089466b.3
        for <kasan-dev@googlegroups.com>; Thu, 28 Aug 2025 00:35:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWP1erBsyAHREP5fnvLS4OBc6HuP5FrSZRfBXwmh5/tP7gNyMZ+Bgn4nssfgsN4iM0q28pDsC4wMTM=@googlegroups.com
X-Gm-Gg: ASbGncswtARYbVN2XKCTCwXg56xICWHa0JRRk3iZTu4o5W3HpKwbmfNq91sj/SWf2bY
	1Nd65KCXOgzvqsvRHfkBPV9UxV+WCBHBqzTKfXus6clX6jvNllCzyEGIYbNiViDA/WgG5r07OQ2
	0V0vmWNuJDFzh/5yuXkkiHliuvaEKn80kUmvh1f4yhOuhrpNYEwgfUa+lq9IArninZE1a95mKpC
	Tr1BepbEdLMQO1T24VzcpFkjQF/EcN0j5vwEPu362Kn1AP4Bi+BPx+CgQf110dJ5TvbXfyQp8fg
	xrNzfeFH5SjRG8HqYzWPDMrORd4c92g/6j3MJXHkKtDbfHeVy1LWv1CyltDsXBD4Q/H1YeukFWM
	Zs10SdGobKJWcsLtRjkwii+0+kA==
X-Received: by 2002:a17:907:fdc1:b0:afc:aa44:bda1 with SMTP id a640c23a62f3a-afe296bcae4mr2097332866b.54.1756366555363;
        Thu, 28 Aug 2025 00:35:55 -0700 (PDT)
Received: from localhost ([185.92.221.13])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-afe68891cefsm988052566b.66.2025.08.28.00.35.54
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 28 Aug 2025 00:35:54 -0700 (PDT)
Date: Thu, 28 Aug 2025 07:35:54 +0000
From: Wei Yang <richard.weiyang@gmail.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Zi Yan <ziy@nvidia.com>,
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
	wireguard@lists.zx2c4.com, x86@kernel.org
Subject: Re: [PATCH v1 10/36] mm: sanity-check maximum folio size in
 folio_set_order()
Message-ID: <20250828073554.evipmbkxrint3tbs@master>
Reply-To: Wei Yang <richard.weiyang@gmail.com>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-11-david@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-11-david@redhat.com>
User-Agent: NeoMutt/20170113 (1.7.2)
X-Original-Sender: richard.weiyang@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=HkDWQqJ8;       spf=pass
 (google.com: domain of richard.weiyang@gmail.com designates
 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
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

On Thu, Aug 28, 2025 at 12:01:14AM +0200, David Hildenbrand wrote:
>Let's sanity-check in folio_set_order() whether we would be trying to
>create a folio with an order that would make it exceed MAX_FOLIO_ORDER.
>
>This will enable the check whenever a folio/compound page is initialized
>through prepare_compound_head() / prepare_compound_page().
>
>Reviewed-by: Zi Yan <ziy@nvidia.com>
>Signed-off-by: David Hildenbrand <david@redhat.com>

Reviewed-by: Wei Yang <richard.weiyang@gmail.com>

-- 
Wei Yang
Help you, Help me

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250828073554.evipmbkxrint3tbs%40master.
