Return-Path: <kasan-dev+bncBD4YBRE7WQBBBW5BYDCQMGQELVYXZBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 33A66B396A7
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 10:18:37 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-45a1b0cb0aasf4629575e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 01:18:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756369116; cv=pass;
        d=google.com; s=arc-20240605;
        b=GNn5ntrFnvHBY6wwOWOy2SNmOGTXv7+35DunLX/s/YbdGnmsTdloMuj+VLY4Z9/VsE
         nr40fBNSWlh78tWXB/t61r1Tg93IglJYQx3EZuukRsE9Vksr3XuomEpjL0qIe0htuxDG
         ToXRyuC99uRSHhtLb7xdj48j1V95526ktdABzJehKrAZLjDsFmZq0UpSDpEY1HVGDTwg
         xSUTqOqY+2MnijTxiq2G75nAl2n3W21IVaIq2YHYj79d0erVsFGdh55NWglFLmM1lHJk
         f2M9mWpNGCXcKwQH1K/iLak1qE0uCdHIkK/2DYoNqf1vnpvUCEHBr5zP/ld0sL0EQuUr
         /4Sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature:dkim-signature;
        bh=CaO8sDJ37Voa+RQ1yhe9c6bk8iXuvLBoTcT6ifP7yYo=;
        fh=+V1MV4hgyPGDvpsBeh8mJOTjHJPgOhvb0wQmE3Kvw18=;
        b=a1ozl4di1Pz2QEgCyZoY36BR6HIZamBRxpT9jU9nipcb4yodniIlHB/O7ZJvY0KUjo
         nvONL2IpbKUMzxKDVXTXXj+0l6X+v+ST/nFu32CqnuU2e6B4v4qY5VG6mcC8ecpyb5cY
         Dq4H5Pvw9RNszbXoJHeNQowINq/BJ1UF24p3vQ1M/JjH8dbL1vksrKMrU4ufE1KWoSyp
         K6yiai4hLoQ35Ceki3GzMRO8KxvNJiGKrZ4Fu4Wh7qyrRxuFlEeu5FuzAxIjaDIc9K8x
         D7VyZBeztW7EJxvfmk/S3BIuHJYoDgxiIpIJOFGkZe6stwtBvdq30Qwubn0+iZRf2Yyp
         KAow==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bdbWohNq;
       spf=pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::629 as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756369116; x=1756973916; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CaO8sDJ37Voa+RQ1yhe9c6bk8iXuvLBoTcT6ifP7yYo=;
        b=t0xTd6KlAxBq7qm93rPFK+k9Zwe2IbX46fMrmd3u8vPv9CfvkR3GTIOZMuVEPZdt28
         XVYbrlraguIxjU4PNNI0kNVgT1Q6WDQdycK01b5lBTZMEiol3Ni0XN2tWwb8tZRvz5u3
         sh6BD+K0E3eDIJm9Nt3BpMFHGXec/4VIl6lejGthHx4FJvLH/lVn25lS9uH9NM992EEE
         Jxt7m66kF6hcrvmQK8B6+v5a5E3mtmdr8g1KfwOmgBL2EhCnlUrJTq5i8ebymSx0Kk0k
         5ZlB3hcV3DSt+E9WdlEH4IWq5UoMpYzMh6Cqej5aDOUFn/FjUNpGfKGSlBzAM81DJRj5
         PBuA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756369116; x=1756973916; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :from:to:cc:subject:date:message-id:reply-to;
        bh=CaO8sDJ37Voa+RQ1yhe9c6bk8iXuvLBoTcT6ifP7yYo=;
        b=m9qYW8wnkoUj3O+3dG3FXyfv+WOm8FhuOhCfj4BgLBs9RlAVsMI/9BKyryMe5czlF4
         zl6sfM9PIQxQXAmGeZeN+L3vQSWshg+9hZ/TEAAZWLbN4JuRIsKLT/sSfvmcSSr2/3yO
         4GIBSdH4Y87hUn2BPr2usz3vwBWGE72k0i+VY7XYcQMN0UlEADKrd3f4Hm56uZBMEjNC
         2Va5K4R8WXbPEXoBIt7k+fzHRm7OIrwVBLgBvPwaatQCU7RkT3ujz2thwcffNQDBPOjQ
         euywQrIEeE7EsoqmjwD2YWLqTgDzmBvB/1QocRLSjIl6CToD8ghDXxq2TUTAQxH6xHAP
         c57A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756369116; x=1756973916;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CaO8sDJ37Voa+RQ1yhe9c6bk8iXuvLBoTcT6ifP7yYo=;
        b=g9lTIbGxtmNH+fpfOY69GLFjo4SJzP5ySzRewSTYPx3u29lIkUN4Kb6D6vz+RH59GI
         CdiPSLS/XFtCfzUp+wy/gjZA7up9qfjP5uxCjkwDIjKT/BhStY9c1haufLh/VZsGeHwk
         KS/cF2kLUL5dWhTDTSIsWtrrnIfGhlZTHegvfIbx6HWBnI4Wc1qU6WoWCZkV8n+e7Vm8
         XtM2nPcrAZWr5ejNhUb5GrB9baZOLdtjqBVGnrxw8owTnCm3joir1JWNLlXimitlnv+9
         8/nGANcL/N5wwbZUMW6KqIV5hxS88hJLn4907ywbPLMICe4hgMspmJqeLu8pHZhKlsro
         qqvQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVZpCMhXoQbw636A7UdSNbKMf4oIEY84SGIAb7wZoNZDgM3zNl+35kmQbtVvHkiLS7l564Hmw==@lfdr.de
X-Gm-Message-State: AOJu0YyWT9G3oz17hruV35PMyP1wXclsEcRDvkag697ebc5/pJj7116z
	uFWsIVSFWGUSeafGrjzgyuHPWByt0/kzYiGz02AnR2jLZhYl2TO7lXCb
X-Google-Smtp-Source: AGHT+IH80sVObAShkxYi0qbEqk61levixM6vMVHF/5Y+ucBqSPQgMpqsu7aQEuVyNmyBM5hVEb0CbA==
X-Received: by 2002:a05:600c:1e85:b0:456:1006:5418 with SMTP id 5b1f17b1804b1-45b5179f0d8mr197844485e9.13.1756369116506;
        Thu, 28 Aug 2025 01:18:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdEAWY8QxstgcdA27BFDqRqbr2FAIZP1lexsRYdZhyBvg==
Received: by 2002:a05:600c:1993:b0:459:ddca:2012 with SMTP id
 5b1f17b1804b1-45b78cba21els2992665e9.2.-pod-prod-05-eu; Thu, 28 Aug 2025
 01:18:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWO9+ZS5DHLPNlrRRuaj07WbxEzn3ks1j4qpscUpX50+ZMF2kegoME6Uljjmnoo1mXFV9BJJzo95UE=@googlegroups.com
X-Received: by 2002:a05:600c:4d02:b0:45b:7a93:f108 with SMTP id 5b1f17b1804b1-45b7a940181mr6345435e9.3.1756369112740;
        Thu, 28 Aug 2025 01:18:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756369112; cv=none;
        d=google.com; s=arc-20240605;
        b=ZPYS++Toxm1iEyI4bL7Qa2MihldOfIL+i+kZdpQLmyhb71S6cz/hwK20s64AAM89gf
         T1aDHkulnpCs8KP0ocZAVkThyxgt7Cs/xwnuWXRBIiKN05qk/XXza8H7T4ONJ5anSwvf
         G4f6Nf52luY5GrH2Os7KokBfQnQeoiWVXFnR4yCWbC1OIITfeoMiGd0HBBwc/Y/WDUJr
         Ali8bLLIWRT8w4wTWN0oJxBGEpFfrLvi2MitTlY6ko9200rXwsE/7gMhGrr58AhS1kNQ
         0UDG3EVSo6sY+zBjEdNZWeB77ItvDq+7DVSdoobhToKNulfnGPCRDJqr7GaN9rdOn3ep
         I6Hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=CFlTc2o50xP7q9jUUn86Cat3HkUhlqoaXfvof6seHm8=;
        fh=SNCvYVVRiI6bpIOvbUVB/65M3exuGTDQVMByeme3iDU=;
        b=SKO5XHIj8pbcZBkfCliqBNtQsDfXwTxOiP+mgS3Lv3uJt5VZq4NDsjpkIOAslJX1NB
         P6EwE5GNYrLJvJ/23iPX0CxE9vr0LmmiUqe3MlkicqljLxwFWW4OW1vTOvp/sSwr8x/w
         4IJ9rJDOLFe9t86QWqZXUdofkr+DzOmzf75VqYHiCluYXhMTev4ov7nUpCiWnhgn0//R
         MniVznATLxFarCBb0IVl8oLOYgQZV259zfwkfvBkiYik2tjFF+59Zy1OMlZVXhZkJ21Y
         8mMn93GPLH8kvBBNtcLOYLrxhI/8h1+tdNoJl74k7RZFTj+H0XipCr1zp0RzXNsZKz94
         PP5g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bdbWohNq;
       spf=pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::629 as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x629.google.com (mail-ej1-x629.google.com. [2a00:1450:4864:20::629])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45b7554915fsi657855e9.1.2025.08.28.01.18.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Aug 2025 01:18:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::629 as permitted sender) client-ip=2a00:1450:4864:20::629;
Received: by mail-ej1-x629.google.com with SMTP id a640c23a62f3a-afe84202bb6so75676366b.2
        for <kasan-dev@googlegroups.com>; Thu, 28 Aug 2025 01:18:32 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXqr3ZgEGsvda9qi06SWphNr3hlwz1RUVWLBL8uZR+TJFESeym/JNCht895xeDpCC8Whzn/L9vQqD4=@googlegroups.com
X-Gm-Gg: ASbGncsq5yQr6gbuXUjprDNo3+nc0DTmlKXlvu6rDEJIIz/xpTemTXR47oGmd6uhsVe
	rmLMrpbcMWqoH0rOlva9o4JsuEdTIB9TGfM32rafXfwAw2sX0kBY5Auisc7+4FdcuK9qJvFbkme
	JNmZAr5cOqUL1kjhmEal/EIkbg0UJwHG3JChWnwBoiH+18Vr6y0OMyhMh2PefsniiTvEErlVuuN
	NPE2lOP/vRnT/0SskDiKxgCmEdfLKOIckqJQG0681iidKCbkIrmBvLoSuYjWVPRCAvE5luT3Gu2
	i0+OLVbLFpxz7TEMkYq1u1jJu28v4FZ+5GNWJCmc9hA0mOA2wJqCnvtGCMapuvaybAn3WJTwMYZ
	INTbF9hIl3ZWZOgL5ssbk3vw274aBgMYRq25/
X-Received: by 2002:a17:907:1c27:b0:afe:b878:a164 with SMTP id a640c23a62f3a-afeb878abecmr620398166b.50.1756369112172;
        Thu, 28 Aug 2025 01:18:32 -0700 (PDT)
Received: from localhost ([185.92.221.13])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-afe80daceb5sm811531866b.68.2025.08.28.01.18.31
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 28 Aug 2025 01:18:31 -0700 (PDT)
Date: Thu, 28 Aug 2025 08:18:31 +0000
From: Wei Yang <richard.weiyang@gmail.com>
To: David Hildenbrand <david@redhat.com>
Cc: Wei Yang <richard.weiyang@gmail.com>, linux-kernel@vger.kernel.org,
	Zi Yan <ziy@nvidia.com>, Alexander Potapenko <glider@google.com>,
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
Subject: Re: [PATCH v1 12/36] mm: simplify folio_page() and folio_page_idx()
Message-ID: <20250828081831.fv4bs77kihwbffdi@master>
Reply-To: Wei Yang <richard.weiyang@gmail.com>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-13-david@redhat.com>
 <20250828074356.3xiuqugokg36yuxw@master>
 <0e1c0fe1-4dd1-46dc-8ce8-a6bf6e4c3e80@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <0e1c0fe1-4dd1-46dc-8ce8-a6bf6e4c3e80@redhat.com>
User-Agent: NeoMutt/20170113 (1.7.2)
X-Original-Sender: richard.weiyang@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=bdbWohNq;       spf=pass
 (google.com: domain of richard.weiyang@gmail.com designates
 2a00:1450:4864:20::629 as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
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

On Thu, Aug 28, 2025 at 09:46:25AM +0200, David Hildenbrand wrote:
>> 
>> Curious about why it is in page-flags.h. It seems not related to page-flags.
>
>Likely because we have the page_folio() in there as well.
>

Hmm... sorry for this silly question.

>-- 
>Cheers
>
>David / dhildenb

-- 
Wei Yang
Help you, Help me

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250828081831.fv4bs77kihwbffdi%40master.
