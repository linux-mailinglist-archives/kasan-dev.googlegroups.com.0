Return-Path: <kasan-dev+bncBCS5D2F7IUILRVWAYQDBUBGD45MFE@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 19CCFB19A85
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Aug 2025 05:38:34 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-459d5f50a07sf3054655e9.3
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Aug 2025 20:38:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754278713; cv=pass;
        d=google.com; s=arc-20240605;
        b=PNRiw5jFeU14Vs1PWHxjyN/9NWzc5ocZCC1FOfHHNyTPyh9JnKLYSsFl5rzhAnFktM
         +qqfpHVKQ8N/WFS2XLvqHKa07wUuFc2BYfvRzVYXn+GXe00hRzcZaEM4tfoL9n6X9eoM
         16+15fk7u39WJLEaDat9U1IzcT6CtE59p+Ga1POcvsbSjzkX4/TR0bv6gNJ9QIw3NJHl
         VaHygze9jgQa6DBxKlQx7zAmDHnDZ2mYBrfueNCxQs0kHh5AHNddve9s6OPNRhLBFD/9
         ZG2pw1uxB4UP4pLRjkhWhkB4DCJwMX4SyhkFzfS86lWOeLETS8Z7p57MQ2cWhkhXheP2
         CrXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=UELzc94GE7CUGyLDY3SmMGWNVQPIFRcE9odKrkgUpDM=;
        fh=xg+54AfJluuR4TBTfC3CcXn37iyqV9Uo3PUmVpyf4lc=;
        b=j3LSG+dRuJYGtEzaZ5dUiyfnvJwgZwweTJc+BSAk88ZXFQHV73R77MN8VSgv3JI398
         Uf9WIK8mgNP6IjOH8Gp+YUkl8lCxJNenIsZ/dteaApPusYbwz1SyKlJNup9kcwDoUNmf
         Y76yCg6RZ9ARQoYNsJJuWk2yA3x6aU0g22+npw127Kqnb48FVX+OkgUgh/q9y8BgMTah
         GU7UTVT2F3lw7Mi4yaEcHnUD1vgY6nj+adYwtTWGmGk2yvQTlxl9eGdNIkL+zZMs7e7Y
         SP5na0bgDcOKZY2n1CiPWzkmFlgXpnUk+b+jyqwUSK7AvnNGx7uIKGykDn5N9zrrUPMU
         3v+A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=vIsLKdYF;
       spf=none (google.com: willy@infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754278713; x=1754883513; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UELzc94GE7CUGyLDY3SmMGWNVQPIFRcE9odKrkgUpDM=;
        b=lPrnVi48SqckG38PuS852XVtvYEsdFVPjJd5vDiTj4PGkBsgGxBx2Ms5kZLKqbAvRc
         NphEuVykyd4l5lW5ZWyRHjhsUpjatrz7mEumRMgmkRF8p2lrJ7YIhKbjnntG6lRzIUZU
         2DVVA5RTTC4LC60ZaGLxmgdCDtccMzR+odgYKAfkvdispDH+5uSeo6D23I+cOCFxke1o
         EM7xQ74rv9mbJEi5TLkOB0h0cWrXIl8u5Q1xGEkQKCiZZ9wEniSTmVsnoQT5+2H9jFns
         tcbBKfX/LwRZ4ZJNuyUKnlj0WxjBprTj2uwAb0P1J/T0bOrabtTAONr3Ek8h9F+ublYd
         7s6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754278713; x=1754883513;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UELzc94GE7CUGyLDY3SmMGWNVQPIFRcE9odKrkgUpDM=;
        b=qjl5mZY/nUHl46fzThSF/kbuINIerluS5UKdUsj74HCE2IbrSnhji1YyxDIAR+ylHe
         Kw1Dp94dGE+hFztZom0y8gGZhI9bHTpjoZTdZOc9EvpbBTSO1mBN64627tJ+hUXXM8FB
         RzN0hoJSiFKzm/PvxKJf6AlG1dECpr303ssAx3A8m1+9uhgPGP2KmQ2FMsrzTabt+Ddq
         Ktlju2C5kuV1YQA0coqSHiTtDd20ftE/wBGrKRIp8KhDBpIHMfYbTwLBjgAOAtcvimRB
         UlT3CbeRnFAA0YUpuo19hNshHImxLX4ukSS7033XLRmFR0JSP94THY6tZ+R1noY9o9Ho
         Q83A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXCi8OTbDJQW8GzrBvph0Ra+pNyBd9kbC6S6IE8moA4dCDICz5b3OsTdaBmaHcEMa3wp1BzWA==@lfdr.de
X-Gm-Message-State: AOJu0YzVJD7xlXpxAt+ljgHYOEbnU3bJvza1K9DqM9soHyRrcISF9Ksg
	tXBMQVN6t0R8YXS/UBA2sfKeq2NZ+Ny11BxntWBh6VmJweLdZ0KfrJcU
X-Google-Smtp-Source: AGHT+IGfHolbTW/FG0TFXu3fbp5tnHcimyWf8LwAmB+PcOfvPK94QWAPh2hrMQ15/6UDI+nmQHFcDQ==
X-Received: by 2002:a05:6000:381:b0:3b7:8fcc:a1e3 with SMTP id ffacd0b85a97d-3b8d94d1a44mr5268116f8f.48.1754278713097;
        Sun, 03 Aug 2025 20:38:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfPULbPhYmJ4wZSRv4VkwmKE3xX2qUyjgxmfd2r0ghshw==
Received: by 2002:a05:600c:4748:b0:459:ddca:202d with SMTP id
 5b1f17b1804b1-459ddca250als505995e9.1.-pod-prod-01-eu; Sun, 03 Aug 2025
 20:38:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXshE76SZjfW18J0BxG2Kur9eOM6bRJ/w//c1idua61wUbhstURhclfQ8qB5A7g84bvdtF6yH2Na2E=@googlegroups.com
X-Received: by 2002:a05:600c:1c28:b0:458:f70d:ebd7 with SMTP id 5b1f17b1804b1-458f70dedeamr28893775e9.20.1754278709811;
        Sun, 03 Aug 2025 20:38:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754278709; cv=none;
        d=google.com; s=arc-20240605;
        b=ARl64Oz3EKqlF0s+MzOsK/3/HQaewT/TOMHH2XMDG4NEnVABd5GBwbUW1mvZ0DuJMX
         9tt+X6qK6lLKg7ONXSlAxdHx8wpKxKtmcEMG4N8PHDBJL9tp0rNqleVYu28zXx5PmRbr
         x26tpqNXK5ZjdylJEyFxigQZZuFekOnMakdEhVFTT8jAgyClvMqqv8MS4ZTgqUkqvb6r
         rlAs/bB7zp6QKBchl20lMt4ySUFhVrBTNRYIY+kkgZFLv6Q53nEZIOl94QgmhlWk3jl5
         LFOyD190iaIH14HI0rj81bkz6UzUh7p2iq2DHp1hBLEHpd/j52zsrSZpDhemWSHFK1pO
         YijA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=SmxoINSQKVJVK+Bn4i2QXaigutnESsGDJWcnHJouMq8=;
        fh=q8Ni9SWeqr4efSq6IVHYIp9A4Dgc0LGTtqtr2iCPkDE=;
        b=Fly9O7pke3FDXalEBLsjVuLGTHhudVJZAhT7GiapoiVuS5+h7s9bIoqUPBavkP/e/B
         hbN9Vp3+znZiGLsu6agnjWB6EuUskuNg3WgxphH0BVP6VdKhi05hgMb4GI6bG6+1cfdU
         AhyaLp612W5Fq4ZvRkCxTa3/e9J6joOoTVAfJf4ZsTxzZJSKwGscyEFvF+20YfA3Qtx+
         PreoPgr53pnDkur8GxjJQiVI1mp+BvbW7mN0bTzWCaoTEYrbE8AoxC1rtsta4wLliWwB
         AqXxdeL6TUnREPe8fp4vv3V4PG7bYXHVDiEapgKL03Laxj2s+X2N47ajti6K03q8Z6tO
         f+CQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=vIsLKdYF;
       spf=none (google.com: willy@infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-458b75c5450si1147205e9.0.2025.08.03.20.38.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 03 Aug 2025 20:38:29 -0700 (PDT)
Received-SPF: none (google.com: willy@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.98.2 #2 (Red Hat Linux))
	id 1uim1N-000000099Z0-0JOE;
	Mon, 04 Aug 2025 03:37:57 +0000
Date: Mon, 4 Aug 2025 04:37:56 +0100
From: Matthew Wilcox <willy@infradead.org>
To: Jason Gunthorpe <jgg@ziepe.ca>
Cc: Robin Murphy <robin.murphy@arm.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Christoph Hellwig <hch@lst.de>, Leon Romanovsky <leon@kernel.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Joerg Roedel <joro@8bytes.org>, Will Deacon <will@kernel.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	Eugenio =?iso-8859-1?Q?P=E9rez?= <eperezma@redhat.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	=?iso-8859-1?B?Suly9G1l?= Glisse <jglisse@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, iommu@lists.linux.dev,
	virtualization@lists.linux.dev, kasan-dev@googlegroups.com,
	linux-trace-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [PATCH 0/8] dma-mapping: migrate to physical address-based API
Message-ID: <aJArFNkuP8DJIdMY@casper.infradead.org>
References: <CGME20250625131920eucas1p271b196cde042bd39ac08fb12beff5baf@eucas1p2.samsung.com>
 <cover.1750854543.git.leon@kernel.org>
 <35df6f2a-0010-41fe-b490-f52693fe4778@samsung.com>
 <20250627170213.GL17401@unreal>
 <20250630133839.GA26981@lst.de>
 <69b177dc-c149-40d3-bbde-3f6bad0efd0e@samsung.com>
 <f912c446-1ae9-4390-9c11-00dce7bf0fd3@arm.com>
 <aIupx_8vOg8wQh6w@casper.infradead.org>
 <20250803155906.GM26511@ziepe.ca>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250803155906.GM26511@ziepe.ca>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=vIsLKdYF;
       spf=none (google.com: willy@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=willy@infradead.org
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

On Sun, Aug 03, 2025 at 12:59:06PM -0300, Jason Gunthorpe wrote:
> Matthew, do you think it makes sense to introduce types to make this
> clearer? We have two kinds of values that a phys_addr_t can store -
> something compatible with kmap_XX_phys(), and something that isn't.

I was with you up until this point.  And then you said "What if we have
a raccoon that isn't a raccoon" and my brain derailed.

> This was recently a long discussion in ARM KVM as well which had a
> similar confusion that a phys_addr_t was actually two very different
> things inside its logic.

No.  A phys_addr_t is a phys_addr_t.  If something's abusing a
phys_addr_t to store something entirely different then THAT is what
should be using a different type.  We've defined what a phys_addr_t
is.  That was in Documentation/core-api/bus-virt-phys-mapping.rst
before Arnd removed it; to excerpt the relevant bit:

---

- CPU untranslated.  This is the "physical" address.  Physical address
  0 is what the CPU sees when it drives zeroes on the memory bus.

[...]
So why do we care about the physical address at all? We do need the physical
address in some cases, it's just not very often in normal code.  The physical
address is needed if you use memory mappings, for example, because the
"remap_pfn_range()" mm function wants the physical address of the memory to
be remapped as measured in units of pages, a.k.a. the pfn.

---

So if somebody is stuffing something else into phys_addr_t, *THAT* is
what needs to be fixed, not adding a new sub-type of phys_addr_t for
things which are actually phys_addr_t.

> We clearly have these two different ideas floating around in code,
> page tables, etc.

No.  No, we don't.  I've never heard of this asininity before.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJArFNkuP8DJIdMY%40casper.infradead.org.
