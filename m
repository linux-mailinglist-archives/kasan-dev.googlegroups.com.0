Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBO4OSPCQMGQEQXVE2SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 47BEAB2CC60
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 20:49:33 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id af79cd13be357-7e8704e0264sf1577127685a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 11:49:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755629372; cv=pass;
        d=google.com; s=arc-20240605;
        b=YI7Wi1jRk7iE7gaPpMFVcLI0TYYTcCNtPKVHYwgIQh5jHX9d3cm4yrapDQ9452X5bK
         Qj/B+W3w9EieyAaLyJprdGCke+ox40Fr+co9kwMZCQC25OMxT4gobaw8tnKEwJKYgVlf
         txUmhdWoy000cRyyYMv6Xe4RgDRg0I0ehuMU0s1UVvn1z0ExkFumDLTfZqY0xg+cGv2E
         8REWJjrTi2fE33wtsyDSG3Jlp+ibDo8mpPf3BgcmN+7GqnJDJjusmM3YW3DGKwuPCfn4
         B77KcsfwtKsVJSfk/YXsjhS6tpzwSXrfLuQCK9gxNhBQo2wfxivFnZdwnz4s0w7tadOt
         Uyyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:subject:references
         :in-reply-to:message-id:cc:to:from:date:mime-version:feedback-id
         :dkim-signature;
        bh=b4pMJqSHIqmKmjdBrMdkT24UvkRNvRSd/o6iHWKm4U8=;
        fh=AMXJlLz12v++rRGWVR8bGZdRK75qOZIWFLUF+rbFny0=;
        b=Zrs8NHvPY1QhQl2FvXyo5MhqgiXF1581GzQoByUhKg5M0o/9HL+zKRFyAJYu0d/bjV
         FzB1ZMbwOwi1UH1dGbFI9/SDNHTxjylxRq7tzYdVE/OE0pe3kkvIrooaE5EQloQ/2Dw5
         POgqukzaXxvXz6nakRlHOOsTCuVNNeJiIaixNh9PLwotkx7VK5KSvhvbndCTI7njnl3T
         lguu4f6W5lg64nPKG7vEKZx21/Qc7biPpnkxWTkxd+X3ab/gzzRiH3Ub+7S8e5sCw/Pw
         gPrxkYq9MM53dhO9v0MBbdyMPW8yKiKevL9Wa9FL7eGI4zCUEJOW20JCqBBOgv1WGwdM
         dRMQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Xmpr6nUl;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755629372; x=1756234172; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:subject
         :references:in-reply-to:message-id:cc:to:from:date:mime-version
         :feedback-id:from:to:cc:subject:date:message-id:reply-to;
        bh=b4pMJqSHIqmKmjdBrMdkT24UvkRNvRSd/o6iHWKm4U8=;
        b=uVIcYjvE+UDEmDz0vBFRD1ZI4i7qesGVIykpEDdKJM6J2syQOhvm5j1B7v9xE+a/84
         VKjGMIZJ7EJGF6r1MFF9a0W0xDgF8u6wBiO+JB5ajQcSJELpk5cbPQDNLSm+4C38ecOp
         GY3hMe3M/Rmu1QS5gx7Kh8mH3vOnEiiCymsDy5tcM7HD3bfSXzWjdeBjqiE6YK32oEzb
         nvRSMlM40WWDe5BbruwSkCjcDYFrmVdcAhwySI7ILpZ92VaRnDtBZ/ZUO79qZcLmbBbf
         H+V/gKLgsgzm9QK2AF+AZLsohyqLSaU7u0FFnVSVmaknk+rKv1rKqA09f787Hz+XMXzj
         P5jA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755629372; x=1756234172;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:subject
         :references:in-reply-to:message-id:cc:to:from:date:mime-version
         :feedback-id:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=b4pMJqSHIqmKmjdBrMdkT24UvkRNvRSd/o6iHWKm4U8=;
        b=BdtpcP1+fAMMQZHpEmfTBEmPGN+xXAFc6aPA5Lkn1HaDxXkerQMJO08cV3MFDlzqYQ
         qg6jw/pPNL1MbGJ0080OHzz2ApOnKt5ZKxZwFtdezMsm9X2H06DOuxydxAfsVuqvLPwe
         wb+vo8fSpV/n6iRWW59vHKDBeQgLfYWMP4xNHHdYxvie/PfDeiNx0QjPlhO3e7JHFKgi
         93M5FaZsP6xwdZ80QQIVCQvYPKwqbZ4hj1vyAOEf1I1nFhp521pHju5EnQ3st8PKskGP
         Q2bmOqQAw8BxWVbzeAGD7ggPbTvvuhrPX6f9lVKyZwti+pXBFAKudQ6Xd0xTj07eeRod
         o4bw==
X-Forwarded-Encrypted: i=2; AJvYcCXo+aKtRwqbWMrrXgVu/DHI4/Nl5G7Z2Oqp12NfKaBBF6p5IKJDjcytXan+Gy6OIhTTDhbWGg==@lfdr.de
X-Gm-Message-State: AOJu0YwgeWbiQb85tczCOEgXri9CxpFG72JMdAus/K0x0dyAiK5ir285
	Ih7eE1kdj2mwEbewj0S8PAAiYcRlxoTXitUFNKfRw4dYzjLK/dA2PPrT
X-Google-Smtp-Source: AGHT+IHHGgTy4qh7+Geqb8P9rjvUAyYrNJ38Cu1/YPBtdYs8IVQNBk3Cg5s7GwaNOYzaMOVbN/kk0w==
X-Received: by 2002:a05:620a:bc7:b0:7e8:6ee1:5028 with SMTP id af79cd13be357-7e9fcac6b56mr45529285a.33.1755629371908;
        Tue, 19 Aug 2025 11:49:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZelMjQXRlZiPHifP+EmvSa2b2r8GtDmSFjT2FBjBP1ulA==
Received: by 2002:ac8:7f87:0:b0:4b0:9935:4645 with SMTP id d75a77b69052e-4b109adf384ls88388561cf.0.-pod-prod-05-us;
 Tue, 19 Aug 2025 11:49:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUvLPef9kEBDdNBn4kOE2R1F/qh2PBCMKH+WaH7jdblrfzdOholn6aeuoVPGDec+09BleHn4pJ2Tdo=@googlegroups.com
X-Received: by 2002:a05:620a:2903:b0:7e8:5143:d58e with SMTP id af79cd13be357-7e9fcb783dfmr34371885a.49.1755629370038;
        Tue, 19 Aug 2025 11:49:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755629370; cv=none;
        d=google.com; s=arc-20240605;
        b=PykMAOnyYPrDC+GliRXq3x7KG3bcQm+9Gm3Hd80mGz/a+9uV/ZwnbBhwZ8NbtXu4+F
         aB6GYSRJx8vUmGcOFSAzLVegsgnfMAIA3lUyhtjmuChAhgTX/8sCpeyaBu08+l/ZEpkk
         n0dooKFy4QoWWZ2RY8eTlK5K3psluP65Mr7yZaUvDL2RcjN/duxKBt2y+3sSZmeaHqPl
         kivsDfdQ4tKiiGVKsFFeKGQxT+tI6Krl2zbsdV2qzPBf/S8G49XFjqYYd+X8lWfB0mLD
         x3qJzsdS1vwMuQujvHCHFWCwNKGw9/N6ygDsRZvEs4neUNjINGcCtFGN47krqAZ66+5G
         D+yQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:subject:references:in-reply-to:message-id
         :cc:to:from:date:mime-version:feedback-id:dkim-signature;
        bh=V0a8rCSgjkAz7gnhnXOKuD7c9T1R+bK+iGUt9hpQUxA=;
        fh=vUub716dNyyCM7QU9ZLKLzVlbzga0UNabQSvlQY7OFs=;
        b=fHvUq6Xd3mjDJJ1mx5H6TSKDAXE1f4i4kngZR8lKy2gt5IA3l6JbMMbkTFSA0I3Pf0
         Joto3buMJ21KJnbT11hzXyu7U5bAsP6Qwf8PCE/NhvovWETGRiNrZU6SS3udeaIIy6/F
         tjOCUzYK/Us+S2NrpVCB7zKdOD3+dUxNDPMPtmL0GqdbESzwdIQRcPz7qyOj+YQigaRI
         tNyL+llSUMyio4kWAlABDfjWcz2l5x5O6SYNIFQxM7OLb7Bzyfx+7jkxwRs3SXT1tY9p
         wpLoOL4FxiJhTVIXkPXJA7+/IursNimQtSdk3Jd04o6JzH6pqs3tjKZ25B84XzvdvM9T
         NfoQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Xmpr6nUl;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e87e1ba202si44659585a.3.2025.08.19.11.49.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 11:49:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 8FB685C659B;
	Tue, 19 Aug 2025 18:49:29 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3F0B9C4CEF4;
	Tue, 19 Aug 2025 18:49:28 +0000 (UTC)
Received: from phl-compute-12.internal (phl-compute-12.internal [10.202.2.52])
	by mailfauth.phl.internal (Postfix) with ESMTP id 31D3DF40066;
	Tue, 19 Aug 2025 14:49:27 -0400 (EDT)
Received: from phl-imap-08 ([10.202.2.84])
  by phl-compute-12.internal (MEProxy); Tue, 19 Aug 2025 14:49:27 -0400
X-ME-Sender: <xms:NsekaGLkpYYn_tL5rT3yO_BkXqxiddfgdxidgKxcHaH-MXl652p3cQ>
    <xme:NsekaOJlIC7TCSjCwYmRCpvzsFljgqYaxuYOZolEbVOqnFcN0Yb2GZzTgHG2uybzM
    aWMSS4nJkDgbbBx7tg>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeeffedrtdefgdduheeivdehucetufdoteggodetrf
    dotffvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfurfetoffkrfgpnffqhgenuceu
    rghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmnecujf
    gurhepofggfffhvfevkfgjfhfutgfgsehtjeertdertddtnecuhfhrohhmpedfnfgvohhn
    ucftohhmrghnohhvshhkhidfuceolhgvohhnsehkvghrnhgvlhdrohhrgheqnecuggftrf
    grthhtvghrnhepjeevffelgfelvdfgvedvteelhefhvdffheegffekveelieevfeejteei
    leeuuedvnecuvehluhhsthgvrhfuihiivgeptdenucfrrghrrghmpehmrghilhhfrhhomh
    eplhgvohhnodhmvghsmhhtphgruhhthhhpvghrshhonhgrlhhithihqdduvdeftdehfeel
    keegqddvjeejleejjedvkedqlhgvohhnpeepkhgvrhhnvghlrdhorhhgsehlvghonhdrnh
    hupdhnsggprhgtphhtthhopeefjedpmhhouggvpehsmhhtphhouhhtpdhrtghpthhtohep
    jhhorhhoseeksgihthgvshdrohhrghdprhgtphhtthhopehrohgsihhnrdhmuhhrphhhhi
    esrghrmhdrtghomhdprhgtphhtthhopehmphgvsegvlhhlvghrmhgrnhdrihgurdgruhdp
    rhgtphhtthhopegrsgguihgvlhdrjhgrnhhulhhguhgvsehgmhgrihhlrdgtohhmpdhrtg
    hpthhtoheprghlvgigrdhgrgihnhhorhesghhmrghilhdrtghomhdprhgtphhtthhopehr
    ohhsthgvughtsehgohhoughmihhsrdhorhhgpdhrtghpthhtohepghhlihguvghrsehgoh
    hoghhlvgdrtghomhdprhgtphhtthhopehkrghsrghnqdguvghvsehgohhoghhlvghgrhho
    uhhpshdrtghomhdprhgtphhtthhopehsrghgihesghhrihhmsggvrhhgrdhmvg
X-ME-Proxy: <xmx:N8ekaMdwa-bjfjKiy_bnjKe5pj-w5KnECjXqAsQ2QeQdV4SQA7pQwg>
    <xmx:N8ekaPdCW9gH5-vPa6JOMA4aaqp_1mwWnXjSovauczKDDBtpYQ57dA>
    <xmx:N8ekaKnKy6VKuw8SWj7LEaUJFkqm2rbcIMv54YWlw8KOdD3OfERqqw>
    <xmx:N8ekaE8iyeSnMuDLLObkGrzOSgmAQEbj_4QdVJQzRyQ8881Jp0dwDQ>
    <xmx:N8ekaGEni2UyRaNp_TjZoxjj4fIEinDxeQ57M5QUT8SDp3Eg6UepfRUM>
Feedback-ID: i927946fb:Fastmail
Received: by mailuser.phl.internal (Postfix, from userid 501)
	id E45512CE0071; Tue, 19 Aug 2025 14:49:26 -0400 (EDT)
X-Mailer: MessagingEngine.com Webmail Interface
MIME-Version: 1.0
X-ThreadId: A0xmfm2pPGfg
Date: Tue, 19 Aug 2025 20:49:08 +0200
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Keith Busch" <kbusch@kernel.org>
Cc: "Marek Szyprowski" <m.szyprowski@samsung.com>,
 "Leon Romanovsky" <leonro@nvidia.com>,
 "Jason Gunthorpe" <jgg@nvidia.com>,
 "Abdiel Janulgue" <abdiel.janulgue@gmail.com>,
 "Alexander Potapenko" <glider@google.com>,
 "Alex Gaynor" <alex.gaynor@gmail.com>,
 "Andrew Morton" <akpm@linux-foundation.org>,
 "Christoph Hellwig" <hch@lst.de>, "Danilo Krummrich" <dakr@kernel.org>,
 iommu@lists.linux.dev, "Jason Wang" <jasowang@redhat.com>,
 "Jens Axboe" <axboe@kernel.dk>, "Joerg Roedel" <joro@8bytes.org>,
 "Jonathan Corbet" <corbet@lwn.net>, "Juergen Gross" <jgross@suse.com>,
 kasan-dev@googlegroups.com, linux-block@vger.kernel.org,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linux-nvme@lists.infradead.org,
 linuxppc-dev@lists.ozlabs.org, linux-trace-kernel@vger.kernel.org,
 "Madhavan Srinivasan" <maddy@linux.ibm.com>,
 "Masami Hiramatsu" <mhiramat@kernel.org>,
 "Michael Ellerman" <mpe@ellerman.id.au>,
 "Michael S. Tsirkin" <mst@redhat.com>, "Miguel Ojeda" <ojeda@kernel.org>,
 "Robin Murphy" <robin.murphy@arm.com>, rust-for-linux@vger.kernel.org,
 "Sagi Grimberg" <sagi@grimberg.me>,
 "Stefano Stabellini" <sstabellini@kernel.org>,
 "Steven Rostedt" <rostedt@goodmis.org>, virtualization@lists.linux.dev,
 "Will Deacon" <will@kernel.org>, xen-devel@lists.xenproject.org
Message-Id: <82f3cf3c-960b-41bc-82a8-ce84353706ed@app.fastmail.com>
In-Reply-To: <aKTAVOBp0u6ZSC4w@kbusch-mbp>
References: <cover.1755624249.git.leon@kernel.org>
 <22b824931bc8ba090979ab902e4c1c2ec8327b65.1755624249.git.leon@kernel.org>
 <aKTAVOBp0u6ZSC4w@kbusch-mbp>
Subject: Re: [PATCH v4 14/16] block-dma: migrate to dma_map_phys instead of map_page
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Xmpr6nUl;       spf=pass
 (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "Leon Romanovsky" <leon@kernel.org>
Reply-To: "Leon Romanovsky" <leon@kernel.org>
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



On Tue, Aug 19, 2025, at 20:20, Keith Busch wrote:
> On Tue, Aug 19, 2025 at 08:36:58PM +0300, Leon Romanovsky wrote:
>>  static bool blk_dma_map_direct(struct request *req, struct device *dma_dev,
>>  		struct blk_dma_iter *iter, struct phys_vec *vec)
>>  {
>> -	iter->addr = dma_map_page(dma_dev, phys_to_page(vec->paddr),
>> -			offset_in_page(vec->paddr), vec->len, rq_dma_dir(req));
>> +	iter->addr = dma_map_phys(dma_dev, vec->paddr, vec->len,
>> +			rq_dma_dir(req), 0);
>
> Looks good.
>
> Reviewed-by: Keith Busch <kbusch@kernel.org>
>
> Just a random thought when I had to double back to check what the "0"
> means: many dma_ api's have a default macro without an "attrs" argument,
> then an _attrs() version for when you need it. Not sure if you want to
> strictly follow that pattern, but merely a suggestion.

At some point,  I had both functions with and without attrs, but Christoph said that it is an artefact and I should introduce one function which accepts attrs but without _attrs in the name.

Thanks 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/82f3cf3c-960b-41bc-82a8-ce84353706ed%40app.fastmail.com.
