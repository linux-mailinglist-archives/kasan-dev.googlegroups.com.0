Return-Path: <kasan-dev+bncBAABBNNO43CAMGQEYIWN3XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id BA410B1FFEF
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 09:09:42 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-7073cd24febsf40286866d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 00:09:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754896181; cv=pass;
        d=google.com; s=arc-20240605;
        b=FcOWNrXE8JJzhL/EsxU/uAy8RWqLsLjFcZZIc7LiJnaYb7cOxOwz9wTSLFZOGDuOpA
         f46asbKhy+wS0mEcCZpfhnUyG/mt9k6apkgkqwfz9Rod5D+6muxNPg6tDqY6ivqWxosO
         ZUhgdffnDBjmvnTJAV5d6XTiaNZqc44egTtyOnsKjO6knlTSp2p8C/XBsfI/exUda02w
         HJjZ8+tioD9uBeiFzJuXCkANuIsIazf9DkW1gFKtmBc/QsmZogVAKxJmFB0GmOKsGkUi
         f1GsXivjEuF74OFfjI8HlE4mMc/NKULJ7bH99gy+rghhp5eDfBPlKxGNBt3FSNHfKHsO
         tN5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:dkim-signature;
        bh=AuZDJLci/0IxUZjoNIz3NgivJdurR84QbjCE1xPwM0w=;
        fh=aLMeoqWw4FBPKpzFdzrswZaaZ0umpJps2pksuhMoUSs=;
        b=FkhXO2UZWBQ+SnCZ0iB/rY/gL8mRdxxNVA4K5SJ0yxVoxQ6MVgkDPLy2oGi4CVND9w
         CSuarSWnLyB5ofhiJcipXmfG3C0T3saURXOfXbfjHbL3j6O9gl0awzjNjY6J3oUnxD2Q
         YN6mL7pOBVqHqLj0OgWQQWP7W7x6zA2nfOZmWPXmmJAqztgOWldjNe+chr+ipuSIOQIq
         NP2P40un4hWhQBTVqwv6XkAmGeu3bolqd51RkWh5ZSBTGLM8ys0QPM4USwTWIcFnEQPS
         5J0luDWwhlUN1MlEZ0KkPZBYtBLk53A72HAKqsbAE6JKHXySdkDSovCjTHcj/1jMeaax
         nU7g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jSgMoSnb;
       spf=pass (google.com: domain of kas@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kas@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754896181; x=1755500981; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AuZDJLci/0IxUZjoNIz3NgivJdurR84QbjCE1xPwM0w=;
        b=SsTBIjsp7T7uTzA3TLwuPt3++7ui1uKHna+MbJ4urpn35GplPi3wPEzQWKtRC4P+4W
         lu3HwqFk71reBAt1cNRaKGSXNskgIZvZ8VZFCArcxL0ymqwONOKNYlHnTYNB9OGWf4/M
         gPTf0R+h0cwYW4baqKmkmnWY75jrRR5Sea+CMG1yAX+q3N1vOWIxzJUW+Yua0sjJEH+p
         OiuiqvCzRufwaUx482W4FBbiu+I17q8s26Z+cr+OdAcaKXSZHs5viBz3A3uofvtgRygn
         hXwHwp1qdBs7AIZqn5knnUdfAatFB/o1LTNRoeuIsr/+eFt3IJ5F3oKuHWe4j+I9KVmW
         5CRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754896181; x=1755500981;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AuZDJLci/0IxUZjoNIz3NgivJdurR84QbjCE1xPwM0w=;
        b=J8X0SBPvY6UYWN6RpNVZiXhPz/oU9ltprNF9pviQlCUE3nsQnP5AwNSGloRzKkYLy8
         UViELD+q/ASU27PsLboZ69ngOqIm/bwONcv5jaZ/cORz284E2P6/qwrQoZzNPHNOl3DP
         a3J9KV9aZggDl3f4MaKEZWuQYcR8HCa4nleAA9D4M9Eq84pEwE2ZXNpJ/fMD8mmBvTR5
         7Q9VPX7jzqwpU9fd+l9v2MATjvFFJRZxZ0+FwVaYncXE6kLC4895VGlvDfDAoIfkeK0R
         BYrERDESHRaXowlTUuqGyBu1dkw4jY6wJOAR6I2NwuUN4mlFwXuob61c4urpca5U5KAI
         ZCGw==
X-Forwarded-Encrypted: i=2; AJvYcCX9irURda5eatWfxZjKG4t9OHhFLlqTxY2528vNpaIjhzOBTdMUCKy+jsTm22TlNdBNq5f21g==@lfdr.de
X-Gm-Message-State: AOJu0YxkgmIqA6K2loEiY4YcQY966d7lBS90iC6orXtsVNi84vkxKE8C
	hAi3hyJfKhFPVd65Q/CgLnJK341PGo7PLhddwkJ7T2Y+EjFOeO8/dk8l
X-Google-Smtp-Source: AGHT+IFm9byMyq8/H4SUefCgYzypbRn0cAxT7YARjF+2D8kUREDd6Cs0txML8sYi5548fY8DNIeIqw==
X-Received: by 2002:a05:6214:21ec:b0:707:33f8:6edd with SMTP id 6a1803df08f44-7099a3dc71fmr198910316d6.23.1754896181209;
        Mon, 11 Aug 2025 00:09:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcKaB4ZEzpEh+mDkmoblLq8kurPH5b1GDj93Gb0R/9tOw==
Received: by 2002:a05:6214:410f:b0:707:71f2:6be6 with SMTP id
 6a1803df08f44-7098809e3aels57384716d6.0.-pod-prod-08-us; Mon, 11 Aug 2025
 00:09:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWWqN3hNsLztcPkiWEKt5PHARmUa/yJbOW2o8a5JrWCkxW9KeuHZp2JgktGGc0h3Ekre99yKxrYv/g=@googlegroups.com
X-Received: by 2002:a05:620a:454d:b0:7e6:9900:6e06 with SMTP id af79cd13be357-7e82c75088emr1646390285a.42.1754896180352;
        Mon, 11 Aug 2025 00:09:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754896180; cv=none;
        d=google.com; s=arc-20240605;
        b=TTD1lwcJBaDYFHF3NhNYsufGlqMyr95nhC5CLO0u7v8l7Mpv6LOD8OiluPBWLbyWOX
         rhrAxKgU330vAA9kexxGJ3oLV5lMnFsnbZc7JVWRr1VNhIXKkdnrQLzmB6f06Cr2DHjv
         q/Fbnla5x/uSyQ7h2lJ9ZSoXaB9uc83ZT8xMw4VlNb3fnkNWPLZwt9kHIj3LYtvm443v
         1rpIg+P0qqvMb3NAfAUMyRfA9ZyqDPRa2ICiJh0ZPLbgIQSuvmwz/MHzxjCKEKPNxPqo
         S4bd9ACeMaf60JgtnYHkHPFWnq4agqj4HSmUNxihM/q4pMD9kgOAeZrN+MmBmRij/nCQ
         z+tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:feedback-id:dkim-signature;
        bh=nYGW20HOdxmPiEoqhRtBhvf9IFz/tFlA/9VUt4ajYtM=;
        fh=xqnr+c2OfP8BBanISRvGihlTGiZ5LqQqNibAq9ZSAUM=;
        b=eudFXFTUqm9zeT2VlzXjXZ/SMToWvZ6fFzWfsv7aES5OEDhJR5SGVgn8Z1EbZm1UMW
         hSV5UsYEr68qIGjHOH4w4D80pAahKuu9jzTHZ+iXI/GylWz+n5jTV7Rq0gVE/ilPJ+bo
         YwbtArC6vwunyyfVpB+3R/9LwWDC3sG/cuH/5m9WOGHW43T3ufYKp6m2+9VlJ4+U3JZv
         BwQa6JNVZ7+nbmetVwHJ6tebqyC8UEFWoUE2rT1pzKD8aBfYIwBOYf2pFackwgpJEBqF
         JKYEBZFXqlw4pNL9skEkWGVE85PPPRp9NyU4PWycotwAS79am2j6+C1YrSv3Yg8CrZ5n
         4vYg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jSgMoSnb;
       spf=pass (google.com: domain of kas@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kas@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e840daf309si10115385a.3.2025.08.11.00.09.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Aug 2025 00:09:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of kas@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 5942A45D44;
	Mon, 11 Aug 2025 07:09:39 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1ED5EC4CEF6;
	Mon, 11 Aug 2025 07:09:38 +0000 (UTC)
Received: from phl-compute-06.internal (phl-compute-06.internal [10.202.2.46])
	by mailfauth.phl.internal (Postfix) with ESMTP id 61606F40068;
	Mon, 11 Aug 2025 03:09:37 -0400 (EDT)
Received: from phl-mailfrontend-02 ([10.202.2.163])
  by phl-compute-06.internal (MEProxy); Mon, 11 Aug 2025 03:09:37 -0400
X-ME-Sender: <xms:MZeZaAKhv47jBdQVbZBUzCxovzHYH_0rrP55uhLzR3Dqu-Hy8rtmog>
    <xme:MZeZaDm4-FA4AmkgD2YQQA1xH-F3sHPexYTS35ALEVFWRqWFjvQXtfar8y28gGpiS
    cXt0_A1OFnzm3zDBmM>
X-ME-Received: <xmr:MZeZaM-CyM-RA_V15WzO_HJwVVjXwS5bJQX1q813TA-nJyYUmhcLGBheIsW3>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeeffedrtdefgddufedukeduucetufdoteggodetrf
    dotffvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfurfetoffkrfgpnffqhgenuceu
    rghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmnecujf
    gurhepfffhvfevuffkfhggtggujgesthdtsfdttddtvdenucfhrhhomhepmfhirhihlhcu
    ufhhuhhtshgvmhgruhcuoehkrghssehkvghrnhgvlhdrohhrgheqnecuggftrfgrthhtvg
    hrnhepheeikeeuveduheevtddvffekhfeufefhvedtudehheektdfhtdehjeevleeuffeg
    necuvehluhhsthgvrhfuihiivgeptdenucfrrghrrghmpehmrghilhhfrhhomhepkhhirh
    hilhhlodhmvghsmhhtphgruhhthhhpvghrshhonhgrlhhithihqdduieduudeivdeiheeh
    qddvkeeggeegjedvkedqkhgrsheppehkvghrnhgvlhdrohhrghesshhhuhhtvghmohhvrd
    hnrghmvgdpnhgspghrtghpthhtohepkedtpdhmohguvgepshhmthhpohhuthdprhgtphht
    thhopehhrghrrhihrdihohhosehorhgrtghlvgdrtghomhdprhgtphhtthhopeguvghnnh
    hisheskhgvrhhnvghlrdhorhhgpdhrtghpthhtoheprghkphhmsehlihhnuhigqdhfohhu
    nhgurghtihhonhdrohhrghdprhgtphhtthhopehrhigrsghinhhinhdrrgdrrgesghhmrg
    hilhdrtghomhdprhgtphhtthhopeigkeeisehkvghrnhgvlhdrohhrghdprhgtphhtthho
    pegsphesrghlihgvnhekrdguvgdprhgtphhtthhopehpvghtvghriiesihhnfhhrrgguvg
    grugdrohhrghdprhgtphhtthhopehluhhtoheskhgvrhhnvghlrdhorhhgpdhrtghpthht
    ohepthhglhigsehlihhnuhhtrhhonhhigidruggv
X-ME-Proxy: <xmx:MZeZaGZbB5w_M42lUmZvSVfIC5VjvScMKskxvkLxG0mVV0m3V7kKAw>
    <xmx:MZeZaBc00jAWL5dtGe5myKZzMdQ7PLHS6rajsmRqWQuvhtwgycMP1g>
    <xmx:MZeZaGGN3-BRzRyZ3VTcErLpqp_9MdvkA37zFIuvtc29YHSY7cqBRg>
    <xmx:MZeZaEPqxrTYCm-gaYlP41qi_-NhCIWpAR2UzkynZnOmQu5E2MBG4Q>
    <xmx:MZeZaO4ZV2QSxZoQAn7qeAHqpWYLVxkPnxGf8XyRRwOEAG9Iw4NuNkCY>
Feedback-ID: i10464835:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Mon,
 11 Aug 2025 03:09:36 -0400 (EDT)
Date: Mon, 11 Aug 2025 07:46:13 +0100
From: "'Kiryl Shutsemau' via kasan-dev" <kasan-dev@googlegroups.com>
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Dennis Zhou <dennis@kernel.org>,
 	Andrew Morton <akpm@linux-foundation.org>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, x86@kernel.org,
 	Borislav Petkov <bp@alien8.de>, Peter Zijlstra <peterz@infradead.org>,
 	Andy Lutomirski <luto@kernel.org>, Thomas Gleixner <tglx@linutronix.de>,
 	Ingo Molnar <mingo@redhat.com>, Tejun Heo <tj@kernel.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 	Dave Hansen <dave.hansen@linux.intel.com>,
 Christoph Lameter <cl@gentwo.org>, 	David Hildenbrand <david@redhat.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 	Vincenzo Frascino <vincenzo.frascino@arm.com>,
 "H. Peter Anvin" <hpa@zytor.com>, kasan-dev@googlegroups.com,
 	Mike Rapoport <rppt@kernel.org>, Ard Biesheuvel <ardb@kernel.org>,
 linux-kernel@vger.kernel.org, 	Dmitry Vyukov <dvyukov@google.com>,
 Alexander Potapenko <glider@google.com>,
 	Vlastimil Babka <vbabka@suse.cz>,
 Suren Baghdasaryan <surenb@google.com>, 	Thomas Huth <thuth@redhat.com>,
 John Hubbard <jhubbard@nvidia.com>,
 	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Michal Hocko <mhocko@suse.com>,
 	"Liam R. Howlett" <Liam.Howlett@oracle.com>, linux-mm@kvack.org,
 Oscar Salvador <osalvador@suse.de>, 	Jane Chu <jane.chu@oracle.com>,
 Gwan-gyeong Mun <gwan-gyeong.mun@intel.com>,
 	"Aneesh Kumar K . V" <aneesh.kumar@linux.ibm.com>,
 Joerg Roedel <joro@8bytes.org>, 	Alistair Popple <apopple@nvidia.com>,
 Joao Martins <joao.m.martins@oracle.com>, 	linux-arch@vger.kernel.org
Subject: Re: [PATCH V4 mm-hotfixes 0/3] mm, x86: fix crash due to missing
 page table sync and make it harder to miss
Message-ID: <qsprh2qiisldfsielpx6inuiw3rrh5owr3urin7maxvwtlhipz@zbioc6hgqe3r>
References: <20250811053420.10721-1-harry.yoo@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250811053420.10721-1-harry.yoo@oracle.com>
X-Original-Sender: kas@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jSgMoSnb;       spf=pass
 (google.com: domain of kas@kernel.org designates 172.234.252.31 as permitted
 sender) smtp.mailfrom=kas@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kiryl Shutsemau <kas@kernel.org>
Reply-To: Kiryl Shutsemau <kas@kernel.org>
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

On Mon, Aug 11, 2025 at 02:34:17PM +0900, Harry Yoo wrote:
> # The solution: Make page table sync more code robust and harder to miss
> 
> To address this, Dave Hansen suggested [3] [4] introducing
> {pgd,p4d}_populate_kernel() for updating kernel portion
> of the page tables and allow each architecture to explicitly perform
> synchronization when installing top-level entries. With this approach,
> we no longer need to worry about missing the sync step, reducing the risk
> of future regressions.

Looks sane:

Acked-by: Kiryl Shutsemau <kas@kernel.org>

> The new interface reuses existing ARCH_PAGE_TABLE_SYNC_MASK,
> PGTBL_P*D_MODIFIED and arch_sync_kernel_mappings() facility used by
> vmalloc and ioremap to synchronize page tables.
> 
> pgd_populate_kernel() looks like this:
> static inline void pgd_populate_kernel(unsigned long addr, pgd_t *pgd,
>                                        p4d_t *p4d)
> {
>         pgd_populate(&init_mm, pgd, p4d);
>         if (ARCH_PAGE_TABLE_SYNC_MASK & PGTBL_PGD_MODIFIED)
>                 arch_sync_kernel_mappings(addr, addr);
> }
> 
> It is worth noting that vmalloc() and apply_to_range() carefully
> synchronizes page tables by calling p*d_alloc_track() and
> arch_sync_kernel_mappings(), and thus they are not affected by
> this patch series.

Well, except ARCH_PAGE_TABLE_SYNC_MASK is not defined on x86-64 until
now. So I think it is affected.

-- 
Kiryl Shutsemau / Kirill A. Shutemov

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/qsprh2qiisldfsielpx6inuiw3rrh5owr3urin7maxvwtlhipz%40zbioc6hgqe3r.
