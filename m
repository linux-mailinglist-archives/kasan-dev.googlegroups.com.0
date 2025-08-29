Return-Path: <kasan-dev+bncBC32535MUICBBL7WY3CQMGQEP4TRDHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 52794B3BE01
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 16:37:37 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id af79cd13be357-7f7706f53aasf468282585a.2
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 07:37:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756478256; cv=pass;
        d=google.com; s=arc-20240605;
        b=TYTrap2wsy5ChzdnRs/iEMlOL5o7TsfP6gRTsdbU5uYI9UwKZSSVx4i8b//tH9tc8d
         6NgRz+rEVxfEhk1mEjhkddJdsbvVFgqKknPTYqWq5xLcS0iqKAKTgnmovQ2nYge6A+bw
         VnXTiVbNm/5wbef9L+E7YOs1SxAHPAZZCVs/h/QQ1/1Xh1dcF865vTuuo4fgOBRWLUa3
         Z0Q0beydNcADWQEC4OaJp7PckT2AdLgO/63FLO/heTYjPliXT+uTldGU8uotvSeKpREP
         d31JjoTLqGhz5sTVJ7y5PaYCbCmn+wpODyGi8MGFIvqTKPQj/2M09zS6GsAaHFlKLP65
         7XCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=sYXQqyZafUZ6V3lihQb/nUc8QxdjAInp5BzDbKkwBsc=;
        fh=Q8hI6o7A3UqCZ895nXZs+FuYqhaGYBiSrcI2KCdmK2I=;
        b=YXCpRwmcEd7V93/h1WsfXGP28I0oSxquqtfN/XbUYUox9NF4OM42iQcoPvhxqoZqlt
         K/fswhJlJ7vHbiRcoS/tdRe+miEHdizt6q4Fj1h1tOb+MBTA6JGg6xGPd+XIRXc3vt7d
         TZ954HwXE93kskYzL2RKWcMyRroCfpL/wsDbt7J4+fTdLmtlkSbsBfqqHB3A9IwMFtzc
         HCyyvHDArSHoRvI3iYF3+3ZcxTiWmxE/miZho9umrN9xO2/4Z+BiWWFkkehqTaNIsVG/
         hMqWj/v/6XzLBZm1QnzbAG78sxvRC/P2rbnc/fNhFiTQDmxPlRdh1j68rWzQYrwY82CA
         0rDg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Tnbq9Qej;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756478256; x=1757083056; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=sYXQqyZafUZ6V3lihQb/nUc8QxdjAInp5BzDbKkwBsc=;
        b=SV/7EOF8PO/kC/7MGxWY9c62w+u2wKY6M+qH4aCCoVIlZx0kP8wwjOMUJaTAznFwy0
         iXIPZ3aK7d4ZOjnms4ahXLms6KtyhfEfPaIDPyZ/d0dgx/9K1x7N49yt9QpW04RURlO0
         zbLIGud8kVxM8e/eaSjDZQ4Hu6GE91B1KqOv0vNcRQRgoNDqUfIuzrodorCw0qPlKpDJ
         WcCj5+ljbM3djggGzewD+PYYat6WAw7bJI0n3bJ4I+4H8+zIXJkbs9QwDwpDj84+Z5Ke
         E+fQGd71bxI2PeBeAjwQFeghxrXPx7wnn64kJeqzEmmWl6l+GOP96CG7GbKv1zJysTVU
         lJrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756478256; x=1757083056;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=sYXQqyZafUZ6V3lihQb/nUc8QxdjAInp5BzDbKkwBsc=;
        b=oJYTj+MhjFnRIKUeDusdLi0Lma9klE1i9X8wFpLsj+tfk7jcwJN/j1TORYi7omxb9O
         ITXwZiqUV6wQq19SdXzOkWlqUWqvT7A66ABQZGGeMr49yJiJn+E7Uy2A5KwN9JiI7FLA
         WfEkf48otEHeN9fb7TvNSL47KfH2s0fbOpGbDFRk0W7BQfNHqvw6sWivWXy1b8h/xHR0
         MXEXCiK9txNlLwi7yqA2dsi9leaW5GVlFHd0ukrwcdzMIBelNnL1fGjg06OgU+YZvzE2
         vSKOYgBLDd3WfJQC26fLCwgTm6VH16KssxFVCwnU7VGQLe7IqSn7LtK+TwnaVtQS0J0S
         OHKQ==
X-Forwarded-Encrypted: i=2; AJvYcCXBtbCjM65kgjs12MOrTnhZzKQ3XK9xZvsyFVNpQT3K981wzNKnfcIa1SVxijPh+BozkgW8NQ==@lfdr.de
X-Gm-Message-State: AOJu0YyO5C/8+bfo6kmtblHmAEATZnsiIVof6EPT/++704W9iYDd1p0O
	EFac0MDmazBZMC79AEM9hKD6iyvF+427vWDZQAWjnecU1p/05cFJzcoS
X-Google-Smtp-Source: AGHT+IGFJvtvVbllGiqe0ezOYuECYpCeLicGMGaGYDqaGzl8JlO1TAeYVpql4qU0qQ4kh2meF9j8qw==
X-Received: by 2002:a05:620a:7117:b0:7e1:3537:c2cf with SMTP id af79cd13be357-7ea10ffd6a3mr3168405285a.34.1756478255659;
        Fri, 29 Aug 2025 07:37:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcIiGoWpnrtUQZLj2luJZQ3SYHKS+V4bxkRpZomPttk3A==
Received: by 2002:a05:622a:1a20:b0:4b0:907c:917b with SMTP id
 d75a77b69052e-4b2fe630d6cls31177111cf.0.-pod-prod-07-us; Fri, 29 Aug 2025
 07:37:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVwTMfQuo2ockilG8stBbs0nGRl7IAAlPldM1C/lL4XAUlD9fOI8igLp1A0/sGmSSGE6kijFJvfpOU=@googlegroups.com
X-Received: by 2002:a05:622a:2512:b0:4b2:9b6b:3e with SMTP id d75a77b69052e-4b2aaaa4fd4mr326481981cf.36.1756478254239;
        Fri, 29 Aug 2025 07:37:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756478254; cv=none;
        d=google.com; s=arc-20240605;
        b=YMd3OKsGK5bnvHODQitzXg6dc/c8Dt18gJqHV5I5io5/HS7+da7CLddxQoWJg71Eht
         Km5vFXRHimut+5ktYq/BIqquM6Oh2vY2kSfkgh3IaU9bd03Nqjq71oM5uAyc8pV6Ua1I
         nGUP+NLkXrfWZih3BFIylAZODj5G8JJVFSsV7gJNxqVOb3ikUzzt9ewhip8L1Z4J+vGz
         7P0I95McHMkW8P/kZ9ltxe1i8P8Yabe2MovHdrHujfHRSMm+dYrS2FJY+A9RDN6WK8Zt
         evKoJM1l7jHiQLF+LV8PWNsWHJDErzmgEpOymeV89FWfKifUdZZhmMr29AoON+G0Igi3
         Fd3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=FneLljPHDM9XgGJyT12mwKiq6vPBg0z8/AklpfNT7Sc=;
        fh=Qnmk4Zi+WCJ9xyHg440dkwOV3TpksSLjYp0ildQkKzU=;
        b=UJdTGJbO51VPfjn8H50LQAL+qwARoA3ipkE2yfoNLk3i5wVLAu1xJOwRRgmeNhtXBD
         otSoDcwfcC/wXeAmRGM6LSOX4ln+gQBTRvtDKMExkKffIh9Fymyck3//iRTJ6mEI2nfb
         Ouxl6j19OnyaTxvqIoWKslmPOILjkGwmNEODDWIvMJYUp1i5dbdRVYNrnKpkj2kKskyb
         4dqGf5XwswFBuB10w5sJ75sEudxaNq3gzoZlHX1ylwVc+ppLUebzwGRE3HvybjiBCsnH
         D4P386EMXrkccHLuUogaullNjzbekO0ZojymSuJglhxWrZq9/qzEw2ydyuq1hM20Wsp0
         LlzA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Tnbq9Qej;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b30b56950asi613241cf.2.2025.08.29.07.37.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 07:37:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f69.google.com (mail-wr1-f69.google.com
 [209.85.221.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-119-XsqkQMN2NPq5QXdExIapTA-1; Fri, 29 Aug 2025 10:37:32 -0400
X-MC-Unique: XsqkQMN2NPq5QXdExIapTA-1
X-Mimecast-MFC-AGG-ID: XsqkQMN2NPq5QXdExIapTA_1756478252
Received: by mail-wr1-f69.google.com with SMTP id ffacd0b85a97d-3cf48ec9e40so511745f8f.1
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 07:37:32 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVY9CAejpTIFE0/BUj+HP5TlJEvW6W8OcSSjn2XUeu6KDqGKt4g0jn6xU+dbaMxXlReyMlSQtrOJaI=@googlegroups.com
X-Gm-Gg: ASbGncs6mD70X8gjAWQgeJjWNmCi9nycsJjDlUERw9S+BT2ja8QmfF23GnkGmp8jydV
	WH4YFZAAi/LNyLgFCihVsVsFRGTs5D7ilQtx2KPaR8y1Wb9sCIQHNCZB/GSMb8VZe20g3wgJH94
	pDpjcboodDQb9GgnEnd4sfoSw7ALzKdVDUceHT75kmt++Qx8aQts+lcjqqxJnKRUMXcXx8NBchn
	K4FqBfe+K0qv2Jy/lHhdzzbJVkJ8/6NzCgdR3cJFqbOAINLSvEvca+LGLbybbu0pongPgoPEjbt
	BgtvWfPFlMJSMwWFBt8kChjq4vjIoi0+hA/ocVILtK6X46doLLEOWcstlTChF7lhTS7bxv7lXvc
	jXdAEp239b/fbOyflA6ljt86ePOSqKyDCdCUW0oO1agzjHzkWY56i2FTTR13Pf3Gc
X-Received: by 2002:a05:6000:4181:b0:3c6:cb4:e07a with SMTP id ffacd0b85a97d-3c60cb4e5f4mr14776389f8f.30.1756478249731;
        Fri, 29 Aug 2025 07:37:29 -0700 (PDT)
X-Received: by 2002:a05:6000:4181:b0:3c6:cb4:e07a with SMTP id ffacd0b85a97d-3c60cb4e5f4mr14776347f8f.30.1756478249246;
        Fri, 29 Aug 2025 07:37:29 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f1d:100:4f8e:bb13:c3c7:f854? (p200300d82f1d01004f8ebb13c3c7f854.dip0.t-ipconnect.de. [2003:d8:2f1d:100:4f8e:bb13:c3c7:f854])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3cf276cc915sm3557153f8f.21.2025.08.29.07.37.26
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 07:37:28 -0700 (PDT)
Message-ID: <07b11bc1-ea31-4d9d-b0be-0dd94a7b1c9c@redhat.com>
Date: Fri, 29 Aug 2025 16:37:26 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 24/36] ata: libata-eh: drop nth_page() usage within SG
 entry
To: Damien Le Moal <dlemoal@kernel.org>,
 Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: linux-kernel@vger.kernel.org, Niklas Cassel <cassel@kernel.org>,
 Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>,
 Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org,
 Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>,
 Johannes Weiner <hannes@cmpxchg.org>, John Hubbard <jhubbard@nvidia.com>,
 kasan-dev@googlegroups.com, kvm@vger.kernel.org,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, linux-arm-kernel@axis.com,
 linux-arm-kernel@lists.infradead.org, linux-crypto@vger.kernel.org,
 linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-scsi@vger.kernel.org, Marco Elver <elver@google.com>,
 Marek Szyprowski <m.szyprowski@samsung.com>, Michal Hocko <mhocko@suse.com>,
 Mike Rapoport <rppt@kernel.org>, Muchun Song <muchun.song@linux.dev>,
 netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
 Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
 Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
 virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
 wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-25-david@redhat.com>
 <7612fdc2-97ff-4b89-a532-90c5de56acdc@lucifer.local>
 <423566a0-5967-488d-a62a-4f825ae6f227@kernel.org>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <423566a0-5967-488d-a62a-4f825ae6f227@kernel.org>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: CQAKqb-KVZ9zjZ_e_WaYisINFqwWaXOYQKL_fKgq_sM_1756478252
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Tnbq9Qej;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

On 29.08.25 02:22, Damien Le Moal wrote:
> On 8/29/25 2:53 AM, Lorenzo Stoakes wrote:
>> On Thu, Aug 28, 2025 at 12:01:28AM +0200, David Hildenbrand wrote:
>>> It's no longer required to use nth_page() when iterating pages within a
>>> single SG entry, so let's drop the nth_page() usage.
>>>
>>> Cc: Damien Le Moal <dlemoal@kernel.org>
>>> Cc: Niklas Cassel <cassel@kernel.org>
>>> Signed-off-by: David Hildenbrand <david@redhat.com>
>>
>> LGTM, so:
>>
>> Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> 
> Just noticed this:
> 
> s/libata-eh/libata-sff
> 
> in the commit title please.
> 

Sure, I think some quick git-log search mislead me.

Thanks!

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/07b11bc1-ea31-4d9d-b0be-0dd94a7b1c9c%40redhat.com.
