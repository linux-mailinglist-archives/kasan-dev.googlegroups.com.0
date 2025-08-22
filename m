Return-Path: <kasan-dev+bncBC32535MUICBBNHFULCQMGQEDYPZW6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id B07E8B32210
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 20:11:02 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-245fd2b644esf40528705ad.3
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 11:11:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755886260; cv=pass;
        d=google.com; s=arc-20240605;
        b=Jt0F6pNlwKMXIJ7wGSxDvzKY6kQdv41UkqIsGuf30oi+006w1h1Py0b2wZ2JPMgqzn
         GbolrSPa9L8tLVOjZGVHn2FI7QXLlynalbXHLTXNv3jxXhHSOuIbHUhJey7CbkLcJCdM
         8mdusHDsC810X6ceMLMB3wzXztFpgX8+BQnf5vOgi3hjuRFEdS3f+LJpJbjTGrdl7QPG
         6j7KOBaRyA3zjtTqg7XYtYqjJOFKS4GR5XWyoHCZgSjV5l+6T4dKvNP3mJxpv05tp9vA
         SlDmkxysrzsZXKOd+ss3k3TNSfLh0Xr3GdC6eeQg7vHpUfYsXCdMMKjmn/BvI8EQm0Jr
         Bd2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=Pd8jyyoci+mqxFkc+T6zCBQa36mFDaT9unkO1vwsets=;
        fh=uzcvYOu/iWkxioKHcyU3sGY479RH97v6gCRXkWDWC34=;
        b=DPu16FMILsNQX1KeVW9j5ogxg+DK7Ne/s1q5RSwcI9fgT7AxRJw73t2tWtQMoS5Zc6
         526SRF+kcQovCzK2N0AbWos6JMb9XJ1Ovh0eE+xSiHFuvzyiRCgOU1cj+8U08ZKFkNjN
         8GbDWONbmx35c0A7UcxoAo3z3gtpvvtG9HHpMb2R1YW6pTWPTNskWufe/d9N1Sa6XmG/
         USJGufl+6runDHfGKBDF0oHT671OlgMZDGTfkvMovg/nzRHouXrpCsvY1snUxYqcSBN0
         A72ZJnlrxCZvZWy+6s7uN1N343Vf9dl3nne7Zu0EUyyRCPDEYlVLkllx6ZXoYFQOlGV+
         JzLA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=IHlqjETq;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755886260; x=1756491060; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Pd8jyyoci+mqxFkc+T6zCBQa36mFDaT9unkO1vwsets=;
        b=IRwHSS22hn/c64rz+Sk/afLxNM1cionbtdGLecc8lHZT1MxDKiECnrFfe27k7TDOft
         1ZZvvL4OWM36LmKV8deI75vhE9TM1jdXY7cdbXEVfy3LDx4SEXKyQiykG6hSJtoatluM
         Xgjt98Xqxxc2jNhtTxHndUDyudbA3IC2XfCxivNaXcojcDzLnwHmd6l5dfv3PnURS/s3
         wlK6ijmFYQgmNgjaYrHWKG7Q4av/mGvKH/y/W+rx6ueP7nPp0vjKv/O9kf/KXT88kBFC
         FWAlzLIPkOYufDCbOBINg7zGCCQGL9BxSrLYeRIxWYUsdPzF/O+3LJ9kJWftAvhA3Sl6
         uE7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755886260; x=1756491060;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Pd8jyyoci+mqxFkc+T6zCBQa36mFDaT9unkO1vwsets=;
        b=sxfB2BUFdvkBmHhVn1WiLfYNM496/z9KMBVdhLp2l2blH+VHy/vYqVjSI9NxeqORJO
         EUm4S7oDy4s0FKDbt4mJ4WENaHZ1zzaxgxJ1it2h3cLZFWgWmjLJveWWF5t8j5JiIrTz
         tmn6t+Uxnt3rVfoedBVgazMLzWRuS+uvRdb4G8fNXgDoIZsTPL5S3Mn1XK5ANm76y8kk
         thKszKUxrudV1K8ORcTiTRzZE4bGNmUXmOIE/nzcXtSkwZbRka9R7BhGkUFBurBgdSGp
         JZD2zmqs4D6fl/hdpdoI/D5GgaPrj8CG/8S19Ho7EaLcID0cPH4RjZqEgUBVLU7XLG6f
         rlyw==
X-Forwarded-Encrypted: i=2; AJvYcCWkpL/sIcI8jE2g4asOGH2EmuwhwkaAamakw/f44tr1VL+AC4snOlNfpICo5xXGBgFnrK2HLQ==@lfdr.de
X-Gm-Message-State: AOJu0YxUgvKavWZF/pbaLDh+rJgFflO+w7iF3wx7HUVTCyVjvS+jFMBf
	gzdfApKNlo6f4oTZMVkqkAl8vSpG2gFy/ydOvjoA/WiF4MMrhEPBjAOh
X-Google-Smtp-Source: AGHT+IH3dyWi2zQIG4T5ArHFXlTgzbBxfQxEpDKk5uUEYarWgIRViU2aQ9Hb8eZiieVYl2hzBeDj3A==
X-Received: by 2002:a17:903:1a24:b0:246:4d93:78a8 with SMTP id d9443c01a7336-2464d937c89mr35939635ad.6.1755886260551;
        Fri, 22 Aug 2025 11:11:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZectmCN1QEdFPcGi8CRWWPhZDHeSnbwua1PiwULOUOEGg==
Received: by 2002:a17:902:dad2:b0:234:d1d3:ca2 with SMTP id
 d9443c01a7336-245fcbfe918ls32559915ad.1.-pod-prod-03-us; Fri, 22 Aug 2025
 11:10:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUowR29bxnQHLxSNcVh8xkU/FjZxDVRig+DOg80r1yNJ7+diNzyM9f22dnLfGEPYsx0yzN/5B67YrU=@googlegroups.com
X-Received: by 2002:a17:903:238e:b0:240:50ef:2f00 with SMTP id d9443c01a7336-2462eea80fbmr63011885ad.26.1755886258997;
        Fri, 22 Aug 2025 11:10:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755886258; cv=none;
        d=google.com; s=arc-20240605;
        b=Y2/VkSfkDuGT0cfFXPWZlZond8UXPgPBXyD0Lla53jLQ9v8wihuEWiKZvfQxXZsX2o
         V3xgrvoiNza7niJSh5x63dPmNUo/sNlcnYZDhVvDLYrhfMJmF8DVumqqWtLJFwYZBC7N
         e/M7mD4PRgfaZ2nrpa+4S2o9Q0PPjhVjTumEJdNR+tSUPf9R+gJnimDhjT1lNnBxO7ag
         X8JKAvjzc1dXh6XfmqRP4Dth7Av8Fgo0bGz9dKSd214HxDyfF/S/izFoPfdG3UV50sfI
         3PEmcJLuz8IAau29LYoFRlsifjKgq5hGNlm5Kk0VNr8JnKbSsfVZWp3/YGV7DOy4CH32
         /N5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=Cs65i5/BwS5INh2iU3PXL6F11yYfHDlCfNAhWqRXwfw=;
        fh=dr+oxYb0I0YNLQDyl+XitZtzl+a0nY3VZHSxKBReMWQ=;
        b=hEHuI0VNtN61b51oBegvfD2VKcUZ5glQNIucyjo8z4lxWN4uKwrhNv2L0iX+Mk675V
         6Qof0MAuN6W7CUjvsdAt9aS1Rxd8tH+vxVEsKMqD++PMOHahY8rXDUmnM1JwpNcHJZe8
         WIuWV91D69ar8VrxaXSIe8yrUlm3zDKEW6N5WyFK48wE9q3TFrqOJZZdy3RD+T1tOT2+
         mbPIWZEFAKsAahA+ZEU2yoS3vwsGiOjhkxg0ya0uBc1LG8ohaeJ1DQNj0q4vbkXSF3gs
         qk+tTUTddUbkKniM1ZbSjYxZncaG75mYEFlJRYfIvns6zvYZQIpTgal0DX0es8id4ME4
         mpxw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=IHlqjETq;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2466879c3f0si171035ad.1.2025.08.22.11.10.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Aug 2025 11:10:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wr1-f72.google.com (mail-wr1-f72.google.com
 [209.85.221.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-346-GrpSM_JCN6Gw6V1Hym2tzw-1; Fri, 22 Aug 2025 14:10:57 -0400
X-MC-Unique: GrpSM_JCN6Gw6V1Hym2tzw-1
X-Mimecast-MFC-AGG-ID: GrpSM_JCN6Gw6V1Hym2tzw_1755886255
Received: by mail-wr1-f72.google.com with SMTP id ffacd0b85a97d-3b9edf41d07so1140885f8f.3
        for <kasan-dev@googlegroups.com>; Fri, 22 Aug 2025 11:10:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU4RABGWUizQ7dRXWDeYBL+4xxamH6HrRjrGgqCeUlnyuJ01ppvrYfzJT0A646HGAkuVLjM9NUJmj4=@googlegroups.com
X-Gm-Gg: ASbGncubwKoPPUpVtYZPActMHVcMVupP4Y2z0HSfCbQRQV8Yddh++rRW32H8NyNqolq
	l1lr+UGNEpkH/Jw2vKUoSmNM6p5T3VQlcnzFshRp01CHd4QvdFj2vFnTH74m/4+Q1IkN9goRPjP
	PT/TeqCLkcmwTDwNQtB/iwqDhEIYTiPDfeDsi4/XJe8cRV05lyaNOj4S0ZM8H0TP1Udn2+pmucg
	sczi5fMP+59bttufYtmwgWWIzo1gUaq121bqADCth+XZbP0aqiLpgXwWLfNsSlvoh5ytrhvBcwb
	8fKSUPnrBN7cWOnyE2Eq15Ch/wfmIoq5kvQfn7VKhmAUrZOgwDwj3spFws4E72KkprmUoLhi38U
	tsQJFnq5iecVsG43tdBs82rKT0WnksZn21H+1rnxtSfP768T6TtBWD00S5pC7sq/pDoc=
X-Received: by 2002:a05:6000:26ce:b0:3b7:83c0:a9e0 with SMTP id ffacd0b85a97d-3c5daefc76amr3207802f8f.25.1755886254494;
        Fri, 22 Aug 2025 11:10:54 -0700 (PDT)
X-Received: by 2002:a05:6000:26ce:b0:3b7:83c0:a9e0 with SMTP id ffacd0b85a97d-3c5daefc76amr3207779f8f.25.1755886254021;
        Fri, 22 Aug 2025 11:10:54 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f2e:6100:d9da:ae87:764c:a77e? (p200300d82f2e6100d9daae87764ca77e.dip0.t-ipconnect.de. [2003:d8:2f2e:6100:d9da:ae87:764c:a77e])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3c70f238640sm404818f8f.26.2025.08.22.11.10.51
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Aug 2025 11:10:53 -0700 (PDT)
Message-ID: <9a9eb9ca-a5ae-4230-8921-fd0e0a79ccbb@redhat.com>
Date: Fri, 22 Aug 2025 20:10:51 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 29/35] scsi: core: drop nth_page() usage within SG
 entry
To: Bart Van Assche <bvanassche@acm.org>, linux-kernel@vger.kernel.org
Cc: "James E.J. Bottomley" <James.Bottomley@HansenPartnership.com>,
 "Martin K. Petersen" <martin.petersen@oracle.com>,
 Doug Gilbert <dgilbert@interlog.com>, Alexander Potapenko
 <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>,
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
 linux-scsi@vger.kernel.org, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Marco Elver <elver@google.com>, Marek Szyprowski <m.szyprowski@samsung.com>,
 Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
 Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
 Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
 Robin Murphy <robin.murphy@arm.com>, Suren Baghdasaryan <surenb@google.com>,
 Tejun Heo <tj@kernel.org>, virtualization@lists.linux.dev,
 Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org,
 Zi Yan <ziy@nvidia.com>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-30-david@redhat.com>
 <58816f2c-d4a7-4ec0-a48e-66a876ea1168@acm.org>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <58816f2c-d4a7-4ec0-a48e-66a876ea1168@acm.org>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: _18_3w1otChSkjEmqYJibZU0Rk7blmPbnTf9CXq_S9c_1755886255
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=IHlqjETq;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

On 22.08.25 20:01, Bart Van Assche wrote:
> On 8/21/25 1:06 PM, David Hildenbrand wrote:
>> It's no longer required to use nth_page() when iterating pages within a
>> single SG entry, so let's drop the nth_page() usage.
> Usually the SCSI core and the SG I/O driver are updated separately.
> Anyway:

Thanks, I had it separately but decided to merge per broader subsystem 
before sending. I can split it up in the next version.

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9a9eb9ca-a5ae-4230-8921-fd0e0a79ccbb%40redhat.com.
