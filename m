Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB24C7PCAMGQENLDALYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 35763B27816
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 07:11:17 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-76e2eac5c63sf1407498b3a.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 22:11:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755234667; cv=pass;
        d=google.com; s=arc-20240605;
        b=SB1eO4lyQ9JEDguDMRdMpThU75Af+87sDDnRMKOgt6Pbd697T6WxcMPP9LaJvFUFGn
         VwOLl9dbDWGOxUL5jNfCDlhnjWVBRUFNcS0tiUqCVOvOqCeJNc3Ek/58nfDp27VSVjZn
         CL08aJaPxTkxAe+YX9MWLHvTPOxN6pn2NyqBk+qBamKzh+vcii8r/jvuB8LOv+4j54IP
         aVfDqSg0vWHdVjCLaXOTAf/ZtOIontr90f2V5eZ2YK4CfKFpw9XoA3YecuNSOpjf0Z6t
         As3oeYbMBEDwWWBZOuX94Irsw37P0Xt6iyhsBWhl7tA+C8K6s+273F6IS1IPdMaUE1d7
         njeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :subject:references:in-reply-to:message-id:cc:to:from:date
         :mime-version:feedback-id:dkim-signature;
        bh=v+uX0oidL+oOFkKp8UJifLxGas3Ii/8y32joXeloSkg=;
        fh=g1cb6Jnz7eLkNv0Y9mm0wLp2/WbjZvZz7a0tebd0YgE=;
        b=lgq3vcfb819OrbN+CxvRkUcWP4WSHMWfs3y3iE+jAG6n6pRpBVmcQrpNkmFZUcZlLz
         q9AOcVRYURXXb40hU+S++Y/jLiMwg5wgO81rT78kKP5sQU4P96hVjQtygksVKNUXgY7f
         6uaCJx3yvafczXYabtLZQGDrfmzvipteontH+FgBONiAjoC+C4FM27Q0W0ENJFoTaADu
         JJWku5eyGPdl4boTDlLDqVfKkHRv1aDoAF8iCO4ImW+KNmFygjBf0S2OaHgRFS2q30aI
         PJKDMsU8FKmsnSg1NkDh++z2t8IsDLgmqVJRgJ4FXnBBbgVzDQdvvxipbBN//dg9O7Gr
         +aqA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="qaZHeg2/";
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755234667; x=1755839467; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:subject:references:in-reply-to:message-id
         :cc:to:from:date:mime-version:feedback-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=v+uX0oidL+oOFkKp8UJifLxGas3Ii/8y32joXeloSkg=;
        b=LQ6S83fuvAoCzbQqxHcscvlueLj/NMbKtZkK8lZ1CTNtC4VXV5clCWrk86Ib7coVQb
         w1hiwpKe9zm79GZJuJH3piVGoreNEY4ymiw+s7iqHHDQDiBrF5qQ7d8OjTegH2WvMBGn
         h2E2GQG556R3V4K2wnag6q3LJTsGIcSiigThXw4AWM4HX/woWKTR4qWBM8PbH/Afruig
         ICRU8GbAtK62bpHAQ7C/txC1wqgu/ZTmFISYX934nMTMYMOxy+f3N4OwFS13Fhl5qgWh
         2xNfxI1ndSFkUZQ4nTSMTKV7UZJ57lyUmsTj5i6H5BKYXZdU43o37olYpvG80R1kloYF
         7gIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755234667; x=1755839467;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:subject:references:in-reply-to:message-id
         :cc:to:from:date:mime-version:feedback-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=v+uX0oidL+oOFkKp8UJifLxGas3Ii/8y32joXeloSkg=;
        b=Htx9137pmFFt03Vdzsc48yCgrH2t7fIaGbfjw08q5j0uDCs1gVi+uHTEpCLm4tWWqc
         4lqfrkZUMg4dUYLJ0n31rJHs4H0C0INblA5XZJS6n382nJCk1QGkhxmnUDKfKRjlNl1l
         YPYI/0z3OqKF9OztKn5QCTBAjJtnmaKubKkNVd/CjOnGx6njEF3L0UPmQG+id8jC91xN
         stBaH3id/FmH2/z6L+F/x3bjnxSaqb9DuHnwo2kzk407UERTv/x3+aMwYZCBWHW21lNG
         Pzw3WWPBoQ6SDZeR6gEbzRQYQqM2GsgaesxRrxDtaPiuyyMrDB7N7nBq434eQ0sfG/mQ
         BoxA==
X-Forwarded-Encrypted: i=2; AJvYcCWQYk3kPMTMbLYSq0yKUEa6q8wD8wAtTwT/SvO9uU9066gXfWLXzdkm8kGRGSRiIxMyTPeuiw==@lfdr.de
X-Gm-Message-State: AOJu0Yz0GZLd+iD6kVBbC2ii4JYmyuDElyLYWYNgVTM0oVXEdo8qY4rC
	ngRfwe7LG5ChZcGRjT2gu9X0ddk6399opFbws90I1qsNWtvGYWevx4RB
X-Google-Smtp-Source: AGHT+IGDGEOPa7KJGkM32QB54Y5rRkUCbm2/09Gh2P8hGqk+woa1jgDy1T7lH7Y7NNa4OJDSHVhgBw==
X-Received: by 2002:a05:6a00:2183:b0:76b:cadf:5dbe with SMTP id d2e1a72fcca58-76e4455a32cmr1024497b3a.0.1755234667441;
        Thu, 14 Aug 2025 22:11:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe34y7t+bpKoVJ4rhfsx82aSpUCxRMV9jnERkVexOgBNQ==
Received: by 2002:a05:6a00:4d16:b0:728:e1d1:39dd with SMTP id
 d2e1a72fcca58-76e2e5592c1ls1081991b3a.1.-pod-prod-05-us; Thu, 14 Aug 2025
 22:11:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWv212c+kVYQLPLee66RYZ2K7Sdbl4p1iCw+4YnDzeMSeK8I452SGHcnHKzutjpRCg1u+vlqqBuguA=@googlegroups.com
X-Received: by 2002:a05:6a00:928c:b0:730:9946:5973 with SMTP id d2e1a72fcca58-76e446aa90dmr990698b3a.5.1755234665971;
        Thu, 14 Aug 2025 22:11:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755234665; cv=none;
        d=google.com; s=arc-20240605;
        b=Yx6ET+6I4VH3YCR1wXH7UMhPj/dSRU1mS1k2gLeuUR5M4jXzYlyM4i0rUjOAmedJ4V
         Oyp5wiWyykXztWOfsSSisPQe0T0bvyO/vnm26A+kqJi4Jg4Uy/ZMQmlhlF7nGp3+8lg8
         Al2R28WaHvVX+QEeHhVX6bBj65sBfslu4sRhB72xJdheM1CEKFM24fTz76iR3KMU516/
         97VET10e4B846bXYGk4DxCJY/KluGBBNQC5VkIJF0KIbdZBqQuGueDkMPsJg5wFiJsHU
         PSxP99uYXFK89rJan6g0oGOwrZp/oeKHBlfytYXKstSiGSsatTLUFafgTSwCYBAgwinw
         RZ5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:subject:references:in-reply-to:message-id
         :cc:to:from:date:mime-version:feedback-id:dkim-signature;
        bh=XUOWdZP1cezLj5JR2qWET0ULt+yC1LXg9Jc7bXW5jXo=;
        fh=02IbWeXGdA2Xs+Y7GudDY5bwewtk803djPqhYGx4qlo=;
        b=YjbH/o/OdAAPQBnCtovim/8RHaiqCyD4KanjFb8cZJRoV2fmJKeBJLE+LqoRs0YqiO
         1tKjmv5T623ARa6lRxxg7A/C6nARN4+wdXsklzkkJfTQjIWuE2NgDUzhttJHvb6h6XF8
         LNL7MBRDgbCyXwBZV5bWb2j6inX+Oomg0cmMgkdAZYrIrFykyTOScw2z19kitIz4eGM/
         GuiFcp62oTLwPaAt3zt1mOw21q//TzHvoV2UepOkWMx4KIAhUm8dPHOkQzpOxdAhAbTz
         vilhSgnPDRLB0w1nPOzGT1+1UDXON0Djvb1qWQQZkq2qCvTsxfYojd3+k071ulyaCjyX
         DsyQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="qaZHeg2/";
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-76e4506715bsi19887b3a.0.2025.08.14.22.11.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 22:11:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 4BD8E5C5B0E;
	Fri, 15 Aug 2025 05:11:05 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id EFEBCC4AF09;
	Fri, 15 Aug 2025 05:11:03 +0000 (UTC)
Received: from phl-compute-12.internal (phl-compute-12.internal [10.202.2.52])
	by mailfauth.phl.internal (Postfix) with ESMTP id CD58BF40066;
	Fri, 15 Aug 2025 01:11:02 -0400 (EDT)
Received: from phl-imap-08 ([10.202.2.84])
  by phl-compute-12.internal (MEProxy); Fri, 15 Aug 2025 01:11:02 -0400
X-ME-Sender: <xms:ZsGeaEjCAtEWX1UaHLA2gfColtQZO7w89chtZ2uFaG4vMYHweTmDIQ>
    <xme:ZsGeaNCED0uQ78E9d2j9GAg3NYkGAhxwrM8S6giPlAbcy5DsDkd_hrjkIGTNdnggG
    4eL_xWyjdx6jEOR_bI>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeeffedrtdefgddugeeftdekucetufdoteggodetrf
    dotffvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfurfetoffkrfgpnffqhgenuceu
    rghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmnecujf
    gurhepofggfffhvfevkfgjfhfutgfgsehtqhertdertdejnecuhfhrohhmpedfnfgvohhn
    ucftohhmrghnohhvshhkhidfuceolhgvohhnsehkvghrnhgvlhdrohhrgheqnecuggftrf
    grthhtvghrnhepffegjefgueegffffjeevheektdekgeevheelvdekieehvdejvdejjefh
    hfelhfefnecuffhomhgrihhnpehkvghrnhgvlhdrohhrghenucevlhhushhtvghrufhiii
    gvpedtnecurfgrrhgrmhepmhgrihhlfhhrohhmpehlvghonhdomhgvshhmthhprghuthhh
    phgvrhhsohhnrghlihhthidquddvfedtheefleekgedqvdejjeeljeejvdekqdhlvghonh
    eppehkvghrnhgvlhdrohhrgheslhgvohhnrdhnuhdpnhgspghrtghpthhtohepfeejpdhm
    ohguvgepshhmthhpohhuthdprhgtphhtthhopehjohhroheskegshihtvghsrdhorhhgpd
    hrtghpthhtoheprhhosghinhdrmhhurhhphhihsegrrhhmrdgtohhmpdhrtghpthhtohep
    tghhrhhishhtohhphhgvrdhlvghrohihsegtshhgrhhouhhprdgvuhdprhgtphhtthhope
    hmphgvsegvlhhlvghrmhgrnhdrihgurdgruhdprhgtphhtthhopegrsgguihgvlhdrjhgr
    nhhulhhguhgvsehgmhgrihhlrdgtohhmpdhrtghpthhtoheprghlvgigrdhgrgihnhhorh
    esghhmrghilhdrtghomhdprhgtphhtthhopehrohhsthgvughtsehgohhoughmihhsrdho
    rhhgpdhrtghpthhtohepghhlihguvghrsehgohhoghhlvgdrtghomhdprhgtphhtthhope
    hkrghsrghnqdguvghvsehgohhoghhlvghgrhhouhhpshdrtghomh
X-ME-Proxy: <xmx:ZsGeaPWPNXdI6VvYib3k9QdMC2XlJbr86LA_KN5YspkDL_EEK6BRlA>
    <xmx:ZsGeaI3d1bh3fFRFl4aiXZUts9ejR-WHFcon7KnhJbC_6nOGWjjn2Q>
    <xmx:ZsGeaIdgKvfZyaCQpAF_MAary9Xg8Dva0Q5zSBAie2gJ8xC3nka9fw>
    <xmx:ZsGeaNVlXDFhOQ5jT6MnFggS_FVesjsSUNJLf3EVumbGV5Io7NaXkQ>
    <xmx:ZsGeaG9LccLFJ2EboOYrfkTWU2yRr6gsoUbWRyvB7Ij-X0QWOgy49Rp5>
Feedback-ID: i927946fb:Fastmail
Received: by mailuser.phl.internal (Postfix, from userid 501)
	id 8094E2CE0071; Fri, 15 Aug 2025 01:11:02 -0400 (EDT)
X-Mailer: MessagingEngine.com Webmail Interface
MIME-Version: 1.0
X-ThreadId: AWyaQ402xWe7
Date: Fri, 15 Aug 2025 08:10:43 +0300
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Christophe Leroy" <christophe.leroy@csgroup.eu>,
 "Marek Szyprowski" <m.szyprowski@samsung.com>
Cc: "Jason Gunthorpe" <jgg@nvidia.com>,
 "Abdiel Janulgue" <abdiel.janulgue@gmail.com>,
 "Alexander Potapenko" <glider@google.com>,
 "Alex Gaynor" <alex.gaynor@gmail.com>,
 "Andrew Morton" <akpm@linux-foundation.org>,
 "Christoph Hellwig" <hch@lst.de>, "Danilo Krummrich" <dakr@kernel.org>,
 iommu@lists.linux.dev, "Jason Wang" <jasowang@redhat.com>,
 "Jens Axboe" <axboe@kernel.dk>, "Joerg Roedel" <joro@8bytes.org>,
 "Jonathan Corbet" <corbet@lwn.net>, "Juergen Gross" <jgross@suse.com>,
 kasan-dev@googlegroups.com, "Keith Busch" <kbusch@kernel.org>,
 linux-block@vger.kernel.org, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-nvme@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
 linux-trace-kernel@vger.kernel.org,
 "Madhavan Srinivasan" <maddy@linux.ibm.com>,
 "Masami Hiramatsu" <mhiramat@kernel.org>,
 "Michael Ellerman" <mpe@ellerman.id.au>,
 "Michael S. Tsirkin" <mst@redhat.com>, "Miguel Ojeda" <ojeda@kernel.org>,
 "Robin Murphy" <robin.murphy@arm.com>, rust-for-linux@vger.kernel.org,
 "Sagi Grimberg" <sagi@grimberg.me>,
 "Stefano Stabellini" <sstabellini@kernel.org>,
 "Steven Rostedt" <rostedt@goodmis.org>, virtualization@lists.linux.dev,
 "Will Deacon" <will@kernel.org>, xen-devel@lists.xenproject.org
Message-Id: <45552b38-5717-4b0c-b0eb-8c463d8cf816@app.fastmail.com>
In-Reply-To: <ccc8eeba-757a-440d-80d3-9158e80c19fe@csgroup.eu>
References: <cover.1755193625.git.leon@kernel.org>
 <ccc8eeba-757a-440d-80d3-9158e80c19fe@csgroup.eu>
Subject: Re: [PATCH v3 00/16] dma-mapping: migrate to physical address-based API
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="qaZHeg2/";       spf=pass
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



On Thu, Aug 14, 2025, at 22:05, Christophe Leroy wrote:
> Le 14/08/2025 =C3=A0 19:53, Leon Romanovsky a =C3=A9crit=C2=A0:
>> Changelog:
>> v3:
>>   * Fixed typo in "cacheable" word
>>   * Simplified kmsan patch a lot to be simple argument refactoring
>
> v2 sent today at 12:13, v3 sent today at 19:53 .... for only that ?
>
> Have you read=20
> https://docs.kernel.org//process/submitting-patches.html#don-t-get-discou=
raged-or-impatient=20
> ?

Yes, I'm aware of that section. It is not even remotely close to the realit=
y in different subsystems.

There are some places in the kernel where you never get any responses.

Thanks

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4=
5552b38-5717-4b0c-b0eb-8c463d8cf816%40app.fastmail.com.
