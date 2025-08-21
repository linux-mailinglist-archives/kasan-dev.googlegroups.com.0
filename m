Return-Path: <kasan-dev+bncBC32535MUICBB37YTXCQMGQEWBYSRQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 396F7B30359
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:07:14 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-32515e8e4cbsf497828a91.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:07:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806832; cv=pass;
        d=google.com; s=arc-20240605;
        b=Gv2pCdBfnaf8OJ7cJn9+vSkboCtz8CmDPktpEJRe8kem4kq63Y106MacvoHO8+pfkr
         lQsJ7BSbyqm5fTVL9JUGgbVN789oTCLWHLWz8fsvO0ce2hTF1skEIm3Ep9qNoVJonz1a
         +vFNEGJ+/C09XHal1M/Subp6+osLuXikHQ7vNlr285Qjr+jKgYP7FPn7szYcYqRJHqu+
         dIuj5U+oxk2xfOVOoyWkUUuj8tQgnBW4dfqOSw+jLsvY4hSR+4UvFsvLWEzrFR167Byw
         kBty4W2tlc1Kn/g7YMqXqYXPz+SzqwJ7N9EwVeqU8mCd/AFTVNhCPmR3f2lAaGFMmSk3
         C/tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=Ln+PMT+sa+L69NsEemIix/OJGSqbvcmHZ8IhKdt6Xs8=;
        fh=LaUdFA3nOJHRWC+v9NqRkZ8VTp4QqU8oSuc2cyPIqTQ=;
        b=IkHmQPPzt1C3ms+F7R7DwRBAiEi+pZHQCRs8s3j4sJxw1Y6GNrG4UPHo8bfnAZ/Nhm
         Vp/3ojsAVyaWwQhsYIj5LCOrXIgiM98EzVhhsX/Gwtct17TaH8GNVqb0MqiEiyEs9XSX
         iEjIfRvSjYe2FjdS5P+ZciX1g5nxPR0ObqOetba1eMZnjKYU7tVPEyW9ZisdNM4njTKh
         A41gLIiCNnfnI0oMENJdteTJXu/KI7bF8Xcrl/oT8Bab23hk31Sr7+k69ldTttokiRwk
         +Teq6QfKouQHCBEn3O+850i1QzsYcXlRkEu++OEC9D2pR0iPgKIvRZOFa5EdF9h3Zpk7
         xTjw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=bcV9eXYU;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806832; x=1756411632; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ln+PMT+sa+L69NsEemIix/OJGSqbvcmHZ8IhKdt6Xs8=;
        b=kAGsCeOtHAsCednW4vyL4b7K7I8yD336HGygJsN1YRVBCwzduoDaYLtcStXTKL5T40
         DQP0zh8RBliSPMp2inYFJni+5JoFvryWRcuFqJaj3AYKmKhBY/+KkKPRLSzcSeCaSCSQ
         DJens2wZ5JZumyipr0jhNYnNi3Y4jcRFAeQVWN36/4s9OaWjBKsLVics4HN5HJKcv3fC
         HkxZawNHcfVYexaguEhTGttWGhmQHq7m6L6T0vrVPXWzctIJcPu8MCbWDyeeJcGf2oOY
         qTZ1p10dfR2Oau2+Za2RdPiEamfg7VgA9eH0lb/twSePOTSXTUQAr/i8hWC0/3zUn3RM
         snPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806832; x=1756411632;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Ln+PMT+sa+L69NsEemIix/OJGSqbvcmHZ8IhKdt6Xs8=;
        b=lZJKdDr0ZRTOGQYda6g3AUtBVJh3FoaNPzw7Yc5Sy3Rj8K6iPwDc8l3XFu0TH+YN10
         8BjOblGK4BjPo87KiyxRGzAmOH7Tvw9DRaLLFPYJkJxH2lp6iDFY+nlT7F/RUOwnvdHw
         37Te5aktwif4y/6SPhDCCltxci5JZN4pmZOCfhmtDCruWdHC1ISSozKBNSummL9dbop4
         Lu1GAQ7SoDb5DBhbS7M+A5KguBFJp1mGQaW8cVysP3pBPQiSyCK1ubQ41r80XbLfDo+T
         CTwJ5SAWyGUv2XEdeXp03673ZaAUZHOxZi2euEYZxJOvT8RTTqIBdfaKkQNo72K5biwZ
         fbew==
X-Forwarded-Encrypted: i=2; AJvYcCWtmXNAjaKvCjSIPziO17GzdegjWquB4Xgd6W35NK26yb0uDolh8SJl1xUh1x3UWZZsNAD7Pg==@lfdr.de
X-Gm-Message-State: AOJu0YwluuVLzFMQ+Jr51w9VRMPE+E0Ounb8IJ2LsDPuP9V5m7VL5iup
	yE9mQvaVXwMFOtG8LQF7FFB4HcWhoKT2lxCZW5kLh0jGs+OGIZeuMZWq
X-Google-Smtp-Source: AGHT+IH2llOdnGoV3Eu7zwa42m4kUR7WVl9yLNbv1QUT9uh8WkyT/3L/uKh4F9+/FpTVgCGNA9JOSw==
X-Received: by 2002:a17:90b:2ec7:b0:312:51a9:5d44 with SMTP id 98e67ed59e1d1-32515e221b8mr993356a91.5.1755806832319;
        Thu, 21 Aug 2025 13:07:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd8z/sPgjRsxkjUErwnmyPPw1lpq3ORmcFGgfJ7KWuofg==
Received: by 2002:a17:90b:3bc6:b0:324:e4c7:f1ad with SMTP id
 98e67ed59e1d1-324eb7e8cf2ls1664414a91.1.-pod-prod-03-us; Thu, 21 Aug 2025
 13:07:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXnxDsEKcwnmLXPkJ8Z89mNvREzOJlGvAvDFlNcVPlgIN5P8KsOEi7G6BaiFiVGjZvnINk+uOLWX6k=@googlegroups.com
X-Received: by 2002:a05:6a21:7e09:b0:240:328c:1225 with SMTP id adf61e73a8af0-24340ab3199mr521653637.12.1755806830644;
        Thu, 21 Aug 2025 13:07:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806830; cv=none;
        d=google.com; s=arc-20240605;
        b=a8clgwC7Zglh/Tu+EqBKDNqY61XE4LSarPk/PUGmQ2CxyD9ezxwHChRmeA72MCSD/k
         lD0v54S3MDu9ArqrRp3g9yuIITbmxM3trt9Bf/YSEjqTVfCn7EOXoIsT0zG3rtMYezHe
         /+aOgJEEcGp+Si2KGlW2rfa3vx0/dgD/eOqjpTJSqvdbykEmWzyE6Wx1qAWGWxRu/dS8
         fXdET1z2Qld7r3zERZ/04woS8D0HTRLrHQEJ1tSPrbx4y5vWvZjP1TcEQ3H/0a31WaDf
         nlD1CS8d+06m9Rvs8n0LMF/eujbAGAY3/aeRaxv+7kyIxzIgPh++k0hP13e1POlksD6T
         RorA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=LLdMjSHtv+zm1bY5U2c0p8D/d+U3cemLYeHBKaj7voE=;
        fh=flH/IlrUl6IdleVhceU/vMwSHfb1AVPu2gtlYT0uD6U=;
        b=Dv4Rg6qXbpEmD0eRV5Lr8fT+jcIB9vQkn2xJcwN4yua5HvMGM8DOQlvpEncbbWy9az
         hdYABtuY9Kp8ZYSV2PluOCiq4GJ2lF/R53ExGMog/r81VPcwrrrlozfXJRMbiMo18cPB
         MuJsJrqnoBPxasQyC6LamXB9TLGEQhHX4Yh9DNfxCmfhfSOWKRkeIadMsfQxYoLv48zZ
         2jDZ3qqQNfOU7ZBWIAr8biFpctatUlzjUhK5MHci+aBMgf/ssVwLDgUGQx6VBX6jxeQD
         esNY3WtW5zon38gVyDTD3LdAza1bdyi/z+vTt7judJ3ETAJSpPY5ZEvN1E9ccz9crevX
         VfEg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=bcV9eXYU;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b476409d18asi254888a12.3.2025.08.21.13.07.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:07:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com
 [209.85.128.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-497-rO2qhkoSOFqMEuyKsGG3BQ-1; Thu, 21 Aug 2025 16:07:08 -0400
X-MC-Unique: rO2qhkoSOFqMEuyKsGG3BQ-1
X-Mimecast-MFC-AGG-ID: rO2qhkoSOFqMEuyKsGG3BQ_1755806827
Received: by mail-wm1-f69.google.com with SMTP id 5b1f17b1804b1-45a1b0511b3so8300205e9.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:07:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXS0ziU86/HRMGj+8W8liwml1H/I68BTdx9Zlcv7ujrAdA5tQDMXcZYybK7mJsMl/l6wdKO5HvhG2I=@googlegroups.com
X-Gm-Gg: ASbGnctGLQ4u8pmKP35stR/ybTopyw2VrPoNVoANa769tU1dqIUW7uYcCPDS899gK/C
	LvXqs0jAy3w6DTcdT2MIAcB1Z44K4HNc+IqQ8Z2TTXGLwNdYJzsanrB4SFaetC0Qya71J0utSvI
	RGoDfp31FKQsK7wLyJx9TMQJexMUu/JVB14QdJkyZp+TQV1Hcu9NznyPu9zVecq7wpa5FnDPsvu
	Jwc4WM1RDQ1odtQ2LIE7rZO5eWMWwf1oz9XeCjsCOtG7Yfb6QR4AxukKO5zr6yv28JMWNVP96v6
	+Fk+fGHnNg2Z1spBoj6qNs5hw4OE3s3TYSQJ+D3uesL3jWYnSFY460ceKNizywEnkhEEL7YoaqK
	dTLLkLQL31dQxkh6bCVgM5Q==
X-Received: by 2002:a05:600c:4506:b0:456:1bae:5470 with SMTP id 5b1f17b1804b1-45b5179b6camr3190975e9.8.1755806826454;
        Thu, 21 Aug 2025 13:07:06 -0700 (PDT)
X-Received: by 2002:a05:600c:4506:b0:456:1bae:5470 with SMTP id 5b1f17b1804b1-45b5179b6camr3190665e9.8.1755806825859;
        Thu, 21 Aug 2025 13:07:05 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3c077788df7sm12764142f8f.48.2025.08.21.13.07.02
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:07:05 -0700 (PDT)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Jason Gunthorpe <jgg@nvidia.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Mike Rapoport <rppt@kernel.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Jens Axboe <axboe@kernel.dk>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Robin Murphy <robin.murphy@arm.com>,
	John Hubbard <jhubbard@nvidia.com>,
	Peter Xu <peterx@redhat.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Brendan Jackman <jackmanb@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Zi Yan <ziy@nvidia.com>,
	Dennis Zhou <dennis@kernel.org>,
	Tejun Heo <tj@kernel.org>,
	Christoph Lameter <cl@gentwo.org>,
	Muchun Song <muchun.song@linux.dev>,
	Oscar Salvador <osalvador@suse.de>,
	x86@kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-mips@vger.kernel.org,
	linux-s390@vger.kernel.org,
	linux-crypto@vger.kernel.org,
	linux-ide@vger.kernel.org,
	intel-gfx@lists.freedesktop.org,
	dri-devel@lists.freedesktop.org,
	linux-mmc@vger.kernel.org,
	linux-arm-kernel@axis.com,
	linux-scsi@vger.kernel.org,
	kvm@vger.kernel.org,
	virtualization@lists.linux.dev,
	linux-mm@kvack.org,
	io-uring@vger.kernel.org,
	iommu@lists.linux.dev,
	kasan-dev@googlegroups.com,
	wireguard@lists.zx2c4.com,
	netdev@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	linux-riscv@lists.infradead.org,
	Albert Ou <aou@eecs.berkeley.edu>,
	Alexander Gordeev <agordeev@linux.ibm.com>,
	Alexandre Ghiti <alex@ghiti.fr>,
	Alex Dubov <oakad@yahoo.com>,
	Alex Williamson <alex.williamson@redhat.com>,
	Andreas Larsson <andreas@gaisler.com>,
	Borislav Petkov <bp@alien8.de>,
	Brett Creeley <brett.creeley@amd.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christian Borntraeger <borntraeger@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Damien Le Moal <dlemoal@kernel.org>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Airlie <airlied@gmail.com>,
	"David S. Miller" <davem@davemloft.net>,
	Doug Gilbert <dgilbert@interlog.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Huacai Chen <chenhuacai@kernel.org>,
	Ingo Molnar <mingo@redhat.com>,
	"James E.J. Bottomley" <James.Bottomley@HansenPartnership.com>,
	Jani Nikula <jani.nikula@linux.intel.com>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Jason Gunthorpe <jgg@ziepe.ca>,
	Jesper Nilsson <jesper.nilsson@axis.com>,
	Joonas Lahtinen <joonas.lahtinen@linux.intel.com>,
	Kevin Tian <kevin.tian@intel.com>,
	Lars Persson <lars.persson@axis.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	"Martin K. Petersen" <martin.petersen@oracle.com>,
	Maxim Levitsky <maximlevitsky@gmail.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Niklas Cassel <cassel@kernel.org>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Rodrigo Vivi <rodrigo.vivi@intel.com>,
	Shameer Kolothum <shameerali.kolothum.thodi@huawei.com>,
	Shuah Khan <shuah@kernel.org>,
	Simona Vetter <simona@ffwll.ch>,
	Sven Schnelle <svens@linux.ibm.com>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Tvrtko Ursulin <tursulin@ursulin.net>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Vasily Gorbik <gor@linux.ibm.com>,
	WANG Xuerui <kernel@xen0n.name>,
	Will Deacon <will@kernel.org>,
	Yishai Hadas <yishaih@nvidia.com>
Subject: [PATCH RFC 00/35] mm: remove nth_page()
Date: Thu, 21 Aug 2025 22:06:26 +0200
Message-ID: <20250821200701.1329277-1-david@redhat.com>
X-Mailer: git-send-email 2.50.1
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: MhF2Cno8-s79aFSnjqHXBR4lq7LfFeAVvhhqr0QuNKM_1755806827
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=bcV9eXYU;
       spf=pass (google.com: domain of dhildenb@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
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

This is based on mm-unstable and was cross-compiled heavily.

I should probably have already dropped the RFC label but I want to hear
first if I ignored some corner case (SG entries?) and I need to do
at least a bit more testing.

I will only CC non-MM folks on the cover letter and the respective patch
to not flood too many inboxes (the lists receive all patches).

---

As discussed recently with Linus, nth_page() is just nasty and we would
like to remove it.

To recap, the reason we currently need nth_page() within a folio is because
on some kernel configs (SPARSEMEM without SPARSEMEM_VMEMMAP), the
memmap is allocated per memory section.

While buddy allocations cannot cross memory section boundaries, hugetlb
and dax folios can.

So crossing a memory section means that "page++" could do the wrong thing.
Instead, nth_page() on these problematic configs always goes from
page->pfn, to the go from (++pfn)->page, which is rather nasty.

Likely, many people have no idea when nth_page() is required and when
it might be dropped.

We refer to such problematic PFN ranges and "non-contiguous pages".
If we only deal with "contiguous pages", there is not need for nth_page().

Besides that "obvious" folio case, we might end up using nth_page()
within CMA allocations (again, could span memory sections), and in
one corner case (kfence) when processing memblock allocations (again,
could span memory sections).

So let's handle all that, add sanity checks, and remove nth_page().

Patch #1 -> #5   : stop making SPARSEMEM_VMEMMAP user-selectable + cleanups
Patch #6 -> #12  : disallow folios to have non-contiguous pages
Patch #13 -> #20 : remove nth_page() usage within folios
Patch #21        : disallow CMA allocations of non-contiguous pages
Patch #22 -> #31 : sanity+check + remove nth_page() usage within SG entry
Patch #32        : sanity-check + remove nth_page() usage in
                   unpin_user_page_range_dirty_lock()
Patch #33        : remove nth_page() in kfence
Patch #34        : adjust stale comment regarding nth_page
Patch #35        : mm: remove nth_page()

A lot of this is inspired from the discussion at [1] between Linus, Jason
and me, so cudos to them.

[1] https://lore.kernel.org/all/CAHk-=wiCYfNp4AJLBORU-c7ZyRBUp66W2-Et6cdQ4REx-GyQ_A@mail.gmail.com/T/#u

Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Jason Gunthorpe <jgg@nvidia.com>
Cc: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: "Liam R. Howlett" <Liam.Howlett@oracle.com>
Cc: Vlastimil Babka <vbabka@suse.cz>
Cc: Mike Rapoport <rppt@kernel.org>
Cc: Suren Baghdasaryan <surenb@google.com>
Cc: Michal Hocko <mhocko@suse.com>
Cc: Jens Axboe <axboe@kernel.dk>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Robin Murphy <robin.murphy@arm.com>
Cc: John Hubbard <jhubbard@nvidia.com>
Cc: Peter Xu <peterx@redhat.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Brendan Jackman <jackmanb@google.com>
Cc: Johannes Weiner <hannes@cmpxchg.org>
Cc: Zi Yan <ziy@nvidia.com>
Cc: Dennis Zhou <dennis@kernel.org>
Cc: Tejun Heo <tj@kernel.org>
Cc: Christoph Lameter <cl@gentwo.org>
Cc: Muchun Song <muchun.song@linux.dev>
Cc: Oscar Salvador <osalvador@suse.de>
Cc: x86@kernel.org
Cc: linux-arm-kernel@lists.infradead.org
Cc: linux-mips@vger.kernel.org
Cc: linux-s390@vger.kernel.org
Cc: linux-crypto@vger.kernel.org
Cc: linux-ide@vger.kernel.org
Cc: intel-gfx@lists.freedesktop.org
Cc: dri-devel@lists.freedesktop.org
Cc: linux-mmc@vger.kernel.org
Cc: linux-arm-kernel@axis.com
Cc: linux-scsi@vger.kernel.org
Cc: kvm@vger.kernel.org
Cc: virtualization@lists.linux.dev
Cc: linux-mm@kvack.org
Cc: io-uring@vger.kernel.org
Cc: iommu@lists.linux.dev
Cc: kasan-dev@googlegroups.com
Cc: wireguard@lists.zx2c4.com
Cc: netdev@vger.kernel.org
Cc: linux-kselftest@vger.kernel.org
Cc: linux-riscv@lists.infradead.org

David Hildenbrand (35):
  mm: stop making SPARSEMEM_VMEMMAP user-selectable
  arm64: Kconfig: drop superfluous "select SPARSEMEM_VMEMMAP"
  s390/Kconfig: drop superfluous "select SPARSEMEM_VMEMMAP"
  x86/Kconfig: drop superfluous "select SPARSEMEM_VMEMMAP"
  wireguard: selftests: remove CONFIG_SPARSEMEM_VMEMMAP=y from qemu
    kernel config
  mm/page_alloc: reject unreasonable folio/compound page sizes in
    alloc_contig_range_noprof()
  mm/memremap: reject unreasonable folio/compound page sizes in
    memremap_pages()
  mm/hugetlb: check for unreasonable folio sizes when registering hstate
  mm/mm_init: make memmap_init_compound() look more like
    prep_compound_page()
  mm/hugetlb: cleanup hugetlb_folio_init_tail_vmemmap()
  mm: sanity-check maximum folio size in folio_set_order()
  mm: limit folio/compound page sizes in problematic kernel configs
  mm: simplify folio_page() and folio_page_idx()
  mm/mm/percpu-km: drop nth_page() usage within single allocation
  fs: hugetlbfs: remove nth_page() usage within folio in
    adjust_range_hwpoison()
  mm/pagewalk: drop nth_page() usage within folio in folio_walk_start()
  mm/gup: drop nth_page() usage within folio when recording subpages
  io_uring/zcrx: remove "struct io_copy_cache" and one nth_page() usage
  io_uring/zcrx: remove nth_page() usage within folio
  mips: mm: convert __flush_dcache_pages() to
    __flush_dcache_folio_pages()
  mm/cma: refuse handing out non-contiguous page ranges
  dma-remap: drop nth_page() in dma_common_contiguous_remap()
  scatterlist: disallow non-contigous page ranges in a single SG entry
  ata: libata-eh: drop nth_page() usage within SG entry
  drm/i915/gem: drop nth_page() usage within SG entry
  mspro_block: drop nth_page() usage within SG entry
  memstick: drop nth_page() usage within SG entry
  mmc: drop nth_page() usage within SG entry
  scsi: core: drop nth_page() usage within SG entry
  vfio/pci: drop nth_page() usage within SG entry
  crypto: remove nth_page() usage within SG entry
  mm/gup: drop nth_page() usage in unpin_user_page_range_dirty_lock()
  kfence: drop nth_page() usage
  block: update comment of "struct bio_vec" regarding nth_page()
  mm: remove nth_page()

 arch/arm64/Kconfig                            |  1 -
 arch/mips/include/asm/cacheflush.h            | 11 +++--
 arch/mips/mm/cache.c                          |  8 ++--
 arch/s390/Kconfig                             |  1 -
 arch/x86/Kconfig                              |  1 -
 crypto/ahash.c                                |  4 +-
 crypto/scompress.c                            |  8 ++--
 drivers/ata/libata-sff.c                      |  6 +--
 drivers/gpu/drm/i915/gem/i915_gem_pages.c     |  2 +-
 drivers/memstick/core/mspro_block.c           |  3 +-
 drivers/memstick/host/jmb38x_ms.c             |  3 +-
 drivers/memstick/host/tifm_ms.c               |  3 +-
 drivers/mmc/host/tifm_sd.c                    |  4 +-
 drivers/mmc/host/usdhi6rol0.c                 |  4 +-
 drivers/scsi/scsi_lib.c                       |  3 +-
 drivers/scsi/sg.c                             |  3 +-
 drivers/vfio/pci/pds/lm.c                     |  3 +-
 drivers/vfio/pci/virtio/migrate.c             |  3 +-
 fs/hugetlbfs/inode.c                          | 25 ++++------
 include/crypto/scatterwalk.h                  |  4 +-
 include/linux/bvec.h                          |  7 +--
 include/linux/mm.h                            | 48 +++++++++++++++----
 include/linux/page-flags.h                    |  5 +-
 include/linux/scatterlist.h                   |  4 +-
 io_uring/zcrx.c                               | 34 ++++---------
 kernel/dma/remap.c                            |  2 +-
 mm/Kconfig                                    |  3 +-
 mm/cma.c                                      | 36 +++++++++-----
 mm/gup.c                                      | 13 +++--
 mm/hugetlb.c                                  | 23 ++++-----
 mm/internal.h                                 |  1 +
 mm/kfence/core.c                              | 17 ++++---
 mm/memremap.c                                 |  3 ++
 mm/mm_init.c                                  | 13 ++---
 mm/page_alloc.c                               |  5 +-
 mm/pagewalk.c                                 |  2 +-
 mm/percpu-km.c                                |  2 +-
 mm/util.c                                     | 33 +++++++++++++
 tools/testing/scatterlist/linux/mm.h          |  1 -
 .../selftests/wireguard/qemu/kernel.config    |  1 -
 40 files changed, 203 insertions(+), 150 deletions(-)


base-commit: c0e3b3f33ba7b767368de4afabaf7c1ddfdc3872
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-1-david%40redhat.com.
