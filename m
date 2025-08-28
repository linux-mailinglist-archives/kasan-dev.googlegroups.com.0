Return-Path: <kasan-dev+bncBD4YBRE7WQBBBWMOYDCQMGQEY4CWXDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 38EECB3955E
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 09:38:03 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-55f3b663c7asf529309e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:38:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756366682; cv=pass;
        d=google.com; s=arc-20240605;
        b=GVf7/4Ptg78DO3GhMTZQuaBqHq14/SA2IbGJT+BgSc6xWoo3lk2e1kx7oQ290tOGb6
         yDnHYaAZ/T2mzDXLNm7/ilmP0sw7HVHuvJTRO2+c6L4ZEGpzBQNbJZRyxvCIry6c29Be
         9kZ4OEJMFFyN7zL0DRdvcz17sTkHGyWvYAi4IBm0TOuoZZUWhghUkYWmEI9OEfJonz+e
         FZBA8vYD3FX2EyAa40lV+ACSBwrnWkYlygY0yCzZkSyzy7vdwJIJr67NqADJ/kI001py
         McArL/srgo2rTXwSp1wxZBhya0KHiTEu4+uN231cJw2Fe3XS9Mrpp+gnz2RnU907nzI7
         7ySQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature:dkim-signature;
        bh=zWkgUerBvnDQe2QuRgfCuvYccV2en+GrxXqjb+kM3cI=;
        fh=dY4oRjhmuqqbEoRuyOATNeyxgxSgHqpRg7u1yR0HM5E=;
        b=kZC/On4qhY6Sa/r/hQhxu30FIiX4hGdtmczQG8oa4KEr2v25lLesRzPKlHN7W2nJPG
         LbQPLGKEiv2kmEN+ffygl9bdcT8LeHeJjreS32p1y4N7pY96Xx9QwvbQvwbjpFT1oqjU
         /QB+CwBvhkYjVZqlS9JiIHkPOaKC2kaLeua4h95KK6tQMNdmKAft9VAfRXxWrMksAcdn
         2qH/pC9J3lJDHXcrS8JCQc7snPQ7ZFLyQiYJ2ZINgZZCLdDiWGduO07dHYZ1RL6xVBxG
         4bWhn9ZIpIHM0sDgLYC7Fvp22cOiD255olHyhm5XG6wOsrRY3j5igD+mvKC4ukw0mouK
         JKAw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FtwgLLJf;
       spf=pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756366682; x=1756971482; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zWkgUerBvnDQe2QuRgfCuvYccV2en+GrxXqjb+kM3cI=;
        b=LBWuVLNylUtYrwNoS+4RGEbI22Ou0NxxC1DANQJrFybMgpI5tW2oexVKKbfbGKcgYg
         g8tSlwmiGaaPXnnSauq2VzTqNX+8pe/msYINR6m+bFPdJPwO7Mp7j1qQ7IHLwVz6bCnu
         S1k9Y3y9an0dHr9XDsbc5A2l+6Brl8FrZr1SUIU1u3nKiLih/pYvUiyCxFnLAAzjYNjn
         Cu/OmCcoxYrSA1PBBbd30vz3iURyLeyZVQI1dKR/PDb8JZi/oPLRDyKB9Fbqd5t286bG
         lBrvC0N84EvM20PXlapPCrct5douNdopKlFuO44gBJNrT0e2C6gVxJcnmtJvVCFrBNOW
         53HA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756366682; x=1756971482; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :from:to:cc:subject:date:message-id:reply-to;
        bh=zWkgUerBvnDQe2QuRgfCuvYccV2en+GrxXqjb+kM3cI=;
        b=aM3j+JFzygNnYUZyWqZbwQhPfz9bxITshwWSs0D6YvZYDBXuKk5H0/fVlmneu7ym6r
         rYZDQscm0uPstUZvLawDQHhalRHkjqVQJ/npKIVxX5u6VwfmyAtBuMITaROxriqLcWG7
         Vm2p+NsVGYherJ+0QOk2z44GRb9/p0y29hDDyG5SEjNGEQyDY1xNhXOZiPprrDlgsgFI
         bOAiGRhS94cCWiw8NbFNARMnow/sCs56WtpGI3Z1U/dN+Bi3FlRxZW46hvXtrBejdWbr
         2+i6VN3izxr3197lj/xQ5drETN8lYSd1tFZu8tC/FWY/m3uIC31Teg+6tcQ2QwdBT4Lm
         rOLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756366682; x=1756971482;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zWkgUerBvnDQe2QuRgfCuvYccV2en+GrxXqjb+kM3cI=;
        b=QFAjQrHLQXAUGgTFfZ8FZHSFUFlQSE52PYGy95fCzufOvwLzD4KBwLDSESaikGLHPr
         GCkPPEXSYsHcvWCEUqB4602vvZbYfH5yaOO6me4hKM/4DMo6MWHi4ncvVZLRPsW2oaET
         2rLD9bVSW8l8uf3ptp5dwNIJio7x5aJxgMJc/Dr8hHkozcqXAQZMAB1kW+Co0/Dd9To+
         1CFJt5Lwjh5zluiLd3DoXSAbffvj5XYej2/uv+3j/fFT4xeZL6WEqaS7V393JvObIsx5
         gxnIasXEGlk9kFGpOrOalpbazrwcPBBrS0vRX0ftRhE58lm/Qgpoc9BpqgLzVh3CNR7n
         Q8tg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX5JPvz1SkGffCF42B+8lZZUQznPNBcADcWO6C5UG2ioJd+ZTILkOcZn0tmwMhAljk0IbEoFg==@lfdr.de
X-Gm-Message-State: AOJu0Yx+q0a24nAeUGjlV2Q+ouh5ktXI8CYb9TAzZ9HnKHUWYmTdg3pE
	MyX1EA8Atztuc798b5e1qzy8h9sqqpXVOrXPao7pfmUkakAX0hjVNw4t
X-Google-Smtp-Source: AGHT+IG7DB5bsDvLdqzCDrMeVP36930eVesUOCHCMDa49IhznbGkH+A+KowejANP8AAM1NuFi2Lw/w==
X-Received: by 2002:a05:651c:1503:b0:336:955e:9fcf with SMTP id 38308e7fff4ca-336955eaef7mr14486691fa.9.1756366681877;
        Thu, 28 Aug 2025 00:38:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZclrt6kEX14SpBwof8ZB0Qr737u+cUXDUZSDHCj3d6SnQ==
Received: by 2002:a2e:9a11:0:b0:336:ab71:15ca with SMTP id 38308e7fff4ca-336ab7118ecls787151fa.1.-pod-prod-09-eu;
 Thu, 28 Aug 2025 00:37:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUFrV6Fqrk2JxA6p0Qd5Xk6TmKQuAYDD7M2TBFNynlJgdn+Tx5UfSGutfE48jlfdhOJmmKMIP4YLhw=@googlegroups.com
X-Received: by 2002:a05:6512:6282:b0:55f:4953:ae91 with SMTP id 2adb3069b0e04-55f4953b230mr4137295e87.5.1756366677534;
        Thu, 28 Aug 2025 00:37:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756366677; cv=none;
        d=google.com; s=arc-20240605;
        b=iH934vKc092hKBmcMMdDWL1+aOd4J7FtV1JXhx5EULlt1JS73Zqt2NEbMPCQRVlo1p
         TD2XmV1RQHI1Zb4l/xH8Hwc00lDn33Xt3mIg+5id9nmJyuiKMYLxjOL/9V+5t9D1/q6+
         LW10jqpeiCOy04X9DXIXcpozex2KM13QC7ZAWmsW2EiRCqjG33Lg+l+2jjH7E9QkKBKt
         umaeYCDc4xZdfWEnxmCigKxeyYopFRf8LUQlejzxZqg3xRLIOytrMaBQCnynbxRiZz6a
         sOH14TqjnTGV6g0Vomye0rcIfU0uDi+V+aWWCuwHk/qA0/ENqzPlXbAvxbYADIb0rsxy
         32CA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=TVrt2ctwbXgHbo+Hn2TZ0gCxiv/sLljbJFjbqAY/TQU=;
        fh=/rncpyFodJ4kMoOuuRfUb5WPRKcCuKDfCHYM4MAAdIs=;
        b=gZisnCUypWFGivwt5HTuDqIZlE+6Weg0RKizRwXpGS38ZkT/b9ZCBvvTuYa54QDxX/
         +rPWhh4rX9FEZx4x9TcKOu+Cj+lsxbae0waUYLm7p8/I3Fp/FrNYH11lrvCZHKr+mNey
         uZCQzeYantxx0zF0b7LBkf9IacukEL2zMyy2EdkYwOApVKrnArtKCL/9ZvZdCWShW7iF
         rg7iCC/o7zJhbdC8RLe3ePP9KqfQ6zHrTHmLKB8qO2LggXcjWcwe8hS2yE+g01CU+nY7
         L8RzVbcQMG4twXimoJfhTgT+t9k2WrWVO1usoJpJNmTZisy6yHbkRNTj00kx4lH49LRv
         rK0w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FtwgLLJf;
       spf=pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x532.google.com (mail-ed1-x532.google.com. [2a00:1450:4864:20::532])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55f35cba50fsi308398e87.8.2025.08.28.00.37.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Aug 2025 00:37:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) client-ip=2a00:1450:4864:20::532;
Received: by mail-ed1-x532.google.com with SMTP id 4fb4d7f45d1cf-61c26f3cf0dso1069315a12.1
        for <kasan-dev@googlegroups.com>; Thu, 28 Aug 2025 00:37:57 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW+ooSDAOi/4t2Q3Aq49j6I655BXplSgPOR48nDkqgG6EkJVUP+IkwLVR75j09WLxTBPmmdVAG6h/Q=@googlegroups.com
X-Gm-Gg: ASbGnctGkTQO0KGrAkmzywPNY+FnVicMEU2zwF7PKJJBjU/EAiV7UCgj2lDI6zgsCKo
	AZnp1H8ztshmbtYXTPbs1HD5+IF5C2F7SC8FFhOz5mdOvHuAXCL7IlXuK++gLESSw4Ck1DiFi+F
	1wPHftQjyxnQBqQWqvtS0MFwuiav1FtQTwY6d8+WzJB4vzm4LIs6GPfUPXvKKQWX+MsEX7pzIkN
	J2KBDB+Q2RWo8vwqxH7A7KsaaMjUuYF8iOhmMjqQ3eo0pnafdGWiYM/W5kie5w0RFH+41DytyzV
	L1R9OLVanSGozbSnvvB90QoPhM4rJ7h+yVhsNjQt9feYLYohdMMjlexDP5tTigJubcT5nuxSMvR
	n2fuNWia1/k6eLwzwG3SZ69zChPfDlLmvKOd5C+EGPTfrY5A=
X-Received: by 2002:a05:6402:52c4:b0:607:28c9:c3c9 with SMTP id 4fb4d7f45d1cf-61c1b453182mr20154119a12.6.1756366676733;
        Thu, 28 Aug 2025 00:37:56 -0700 (PDT)
Received: from localhost ([185.92.221.13])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-61cdb00baf9sm715248a12.33.2025.08.28.00.37.56
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 28 Aug 2025 00:37:56 -0700 (PDT)
Date: Thu, 28 Aug 2025 07:37:56 +0000
From: Wei Yang <richard.weiyang@gmail.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Zi Yan <ziy@nvidia.com>,
	"Mike Rapoport (Microsoft)" <rppt@kernel.org>,
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
	Michal Hocko <mhocko@suse.com>, Muchun Song <muchun.song@linux.dev>,
	netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
	Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com, x86@kernel.org
Subject: Re: [PATCH v1 11/36] mm: limit folio/compound page sizes in
 problematic kernel configs
Message-ID: <20250828073755.gyq5cyafrxb7lnw2@master>
Reply-To: Wei Yang <richard.weiyang@gmail.com>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-12-david@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-12-david@redhat.com>
User-Agent: NeoMutt/20170113 (1.7.2)
X-Original-Sender: richard.weiyang@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=FtwgLLJf;       spf=pass
 (google.com: domain of richard.weiyang@gmail.com designates
 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
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

On Thu, Aug 28, 2025 at 12:01:15AM +0200, David Hildenbrand wrote:
>Let's limit the maximum folio size in problematic kernel config where
>the memmap is allocated per memory section (SPARSEMEM without
>SPARSEMEM_VMEMMAP) to a single memory section.
>
>Currently, only a single architectures supports ARCH_HAS_GIGANTIC_PAGE
>but not SPARSEMEM_VMEMMAP: sh.
>
>Fortunately, the biggest hugetlb size sh supports is 64 MiB
>(HUGETLB_PAGE_SIZE_64MB) and the section size is at least 64 MiB
>(SECTION_SIZE_BITS == 26), so their use case is not degraded.
>
>As folios and memory sections are naturally aligned to their order-2 size
>in memory, consequently a single folio can no longer span multiple memory
>sections on these problematic kernel configs.
>
>nth_page() is no longer required when operating within a single compound
>page / folio.
>
>Reviewed-by: Zi Yan <ziy@nvidia.com>
>Acked-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
>Signed-off-by: David Hildenbrand <david@redhat.com>

Reviewed-by: Wei Yang <richard.weiyang@gmail.com>

-- 
Wei Yang
Help you, Help me

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250828073755.gyq5cyafrxb7lnw2%40master.
