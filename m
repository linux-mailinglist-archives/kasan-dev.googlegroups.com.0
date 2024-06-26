Return-Path: <kasan-dev+bncBC32535MUICBBJWB52ZQMGQEK6JMOMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 78B079177CF
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2024 07:01:28 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-1fa308c917asf838745ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 22:01:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719378087; cv=pass;
        d=google.com; s=arc-20160816;
        b=N+WEx/iiGkGTnGEY9O1cecrpLv50cVVktEhubn6NG7DcFYPCc51uUjEapMEzNEc6Cu
         ktkxUIBrwxAQpfWrBKwiuv8Ykg3M6Os7WNgFBXYbaL+Rn9Pqsl3l3lO7def+eDQyQdmI
         EN+11EmXAkF1ga7lY+RgaJbNZAka2GPqqXuN/nDaYTIVaS2w8HVdlB5o3RLWDT9u3Z7Y
         9HTkCpvtH3ZJtPv1pUFxzwHed57JforOgtKrKyewurDKAt8VgRymOLDAYk44Xo2c/WCU
         I34IE7jtdbmtG09zeJ6jj0DOTtMsl+ks16KML98IEYhhd7njKwfXQk+KsL9LR9JDHm6C
         elPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=nlNTtsJAB6Yuc1505h0fah4kxw/FrE+5Syu347Tz07Q=;
        fh=/178ypkIu80Pa/DXxo566Qec/oUFo8kv+EdGiTyaH1g=;
        b=vexWSamQBV8K0xhCwPqw85uuoqQ95Hbs4RWukewMdlkFZxv+dHAL2jghnIDdTx2gCM
         VPxClO+qt8PU5NiaVVetBAl7noQ37GI1b8oApwQHxU4eUcf+z79atLoldhdCv6hy1kgz
         j4vFeXCSGfSJiwAqSJ4EbX2wk8mFGS/yHRjLTOMqHm9qO2fSGqmnTRM5TilbaoSDJ/Fl
         mUbqT3hkekTXfMO+XjWwjpO3iiSPDB0VXXd/YToFdOCjPoH5qUdFFyNxKh5sT57wTIyT
         PiMOFZHPIgI97EjE7hsbH27q37IQaT6/UQJB3uKserpoeEiiHCrR8uqNjt1hz7jX0VZW
         dIfQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=f1VKA+X6;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719378087; x=1719982887; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=nlNTtsJAB6Yuc1505h0fah4kxw/FrE+5Syu347Tz07Q=;
        b=hWFr9DtA1+G+mgVxdHRbqlIS7j0vRGs2fzasgTun+PGjOQXyqWKdcbBge+0hhZID09
         Dg/iDQk7P4chTvsABr95jFmOod3uSZMYlUqXsTKiAw/Sf8o1pltBR+MeJ6U3vq8aVTZ+
         EsbSXJB978JTPDi7OivVJEWwKzsjQQeWI9nDHlIb1CmwVCq78XnMuXZyjU30KTOLOeOg
         zkrQTe+rRw5DfGIPPDugw9RU4VMPz5chtnH+u6PsrNGqXci2JrMUNK7CULqyiKzY3uFo
         mRvGRLDba7ql0AB18aA+WdZEiLWCE57mHLt5aZXwk0IEgoNplOkU5FQjmGWGrctEX9Al
         0Bbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719378087; x=1719982887;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nlNTtsJAB6Yuc1505h0fah4kxw/FrE+5Syu347Tz07Q=;
        b=imWJKmwBZzJJRjKbBnyPvoxGD+sfYdb4bTTLuHV5msN0oxsRQYzAtvF8QXvc+chTco
         IbWiRRYbSYbyTZoz6cCQCTeV+MSSOuj80hog3A+KkCScMfVZkFFxN5D3dIOdiEM74zaN
         pAw3VqUB++ppKa47D6tBo/V+i2uhJVQq8AKxPBILX1OWN/ueDd/iJ8vTn8elM3v5TV8/
         w19DhITP/4gue8mx8QKKdii7VQFy5DEfDi8dEUzdXJ8CLhuCU9E+cVzL7F0nBl59fofR
         Ds77HKQ+nNdPBtIXYSbuEpOf1xNXQu6YcEnhWAc+RsElKs+Su9S+ziXRKW+RpAhsQcFu
         QtBQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU1HweKB0MChgLTt7AfE6gO4I29Ui8wbk0D1LlayFEAcz3DqY+M9vNrSCDvtDFWPI3n5EGFHJqRuqz/jKU5XxKAMJsulp5sGQ==
X-Gm-Message-State: AOJu0YxntWmBeHWygCB09lN0BIUD9i37ZvMbWuwqGX2D1+1UAe2loQBh
	DbOTMaeYP7nVZ+ZbcGA9+yOGcDEAZ6tr6/ZE2EiXWCkK2W3tvM+F
X-Google-Smtp-Source: AGHT+IETCcJ0vtGW4k25VLFWufAMOtJaAYZmcH5hV3x0vDy4r6IfdqkL80R2tdrkfpN7Wmbznw5tHQ==
X-Received: by 2002:a17:903:783:b0:1fa:6047:1c48 with SMTP id d9443c01a7336-1fa8d011ac0mr1309565ad.9.1719378086639;
        Tue, 25 Jun 2024 22:01:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:17c1:b0:2c4:bfdb:3038 with SMTP id
 98e67ed59e1d1-2c7dfee1a5als3349103a91.1.-pod-prod-05-us; Tue, 25 Jun 2024
 22:01:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWEPiyo8+g6YimtOl2/Ti6PEyANrPcFYtvnMyDzr21ypE1q5MhNn9T5FGYrh+1JKcl6EOgNxJijdN72ZqQej1RghYOSRv66ujZBhw==
X-Received: by 2002:a17:90b:4c0f:b0:2c6:f21d:8d8d with SMTP id 98e67ed59e1d1-2c861485d08mr7662964a91.41.1719378085309;
        Tue, 25 Jun 2024 22:01:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719378085; cv=none;
        d=google.com; s=arc-20160816;
        b=L8zMzwtrhIBcE/A4MtJxhWuL/IMLiNCSbomNGgVwzsuHsq2zfgwKK6dy33T0WUJit5
         +EKAeK+xVFvkEZCaId/6Eo5/Rmk3j42pmg2ClNnLv6n5uwVwgJf1NQPABBjMBndxX3S2
         2gFPuOIEUeD27fWBWnqsocWo96Dqf4Dk3UHXU7z4mZK3G58hzUItKoJfwrtVZ43vUWOJ
         VlWoEC1l4kWKSIK/smz+Vl77dLBehWPNlHPqt9GBsIfj9vtf6I+PYc57dS1vhhl2wrVJ
         1PLgNtYQqT6p5R1Lxe+3sctE+6HNhE9cMG9urLk+7SAznuiJzhfkiICeif0hfq/I1kCQ
         peWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=HwF4neA1Ypjh3MK2yusEpJBcmzkoo53PN4KI5vuznrw=;
        fh=VLRaPUB9uHSrOxkNLzzZ+4z1xVqMtKOmdA0NWYGgje8=;
        b=eFzHJWOCilygmb04VTCK5v/iQToFaz1HYlL+RGvkD1PKZAtO7HHtou3mlyvVNa4u5r
         bpthDzjMFLnCIDlroDBEDlhWM8V+0tLqklLWtiEYmjyBpj5V9E9MzzRBDZdQXZRRiKeV
         eH/S1fF5Pv7gazAHHiag4BfXWmtSMff/Q0ZKWGFHJL2V3bDta4DQ/NTs0XhHXARBl+RK
         VCLUTTLJD+2yz9bW7UHr+gy/BYQSU2wR9ApyjKFIswuK7zBbnKbC7QJf3txUTadzDV6A
         gnKH0MenzzkobLFaJrI2XAR0xQiVMxLiSydhBQ9RTPpdry8NV/d63TqLPRxS4yzp/yIi
         oSog==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=f1VKA+X6;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c8d7e5808csi38950a91.1.2024.06.25.22.01.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Jun 2024 22:01:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-lf1-f69.google.com (mail-lf1-f69.google.com
 [209.85.167.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-277-DSFQDsDYMZaYKQ4Z_HPiiw-1; Wed, 26 Jun 2024 01:01:20 -0400
X-MC-Unique: DSFQDsDYMZaYKQ4Z_HPiiw-1
Received: by mail-lf1-f69.google.com with SMTP id 2adb3069b0e04-52cdbeaafcdso3196673e87.1
        for <kasan-dev@googlegroups.com>; Tue, 25 Jun 2024 22:01:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW7h4A7krpEAckMrBLxaBADYCo4VQ8GsorjC7pHNfRHAF2r0uMbpw6O9xFHguA2ktSFqofohApvmzpqCjZ7acrdqcFVed7bwe3HPg==
X-Received: by 2002:ac2:47e8:0:b0:52c:86de:cb61 with SMTP id 2adb3069b0e04-52ce1832c4fmr6006878e87.10.1719378078689;
        Tue, 25 Jun 2024 22:01:18 -0700 (PDT)
X-Received: by 2002:ac2:47e8:0:b0:52c:86de:cb61 with SMTP id 2adb3069b0e04-52ce1832c4fmr6006851e87.10.1719378078225;
        Tue, 25 Jun 2024 22:01:18 -0700 (PDT)
Received: from [192.168.1.34] (p548825e3.dip0.t-ipconnect.de. [84.136.37.227])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-366389b8ab0sm14651814f8f.27.2024.06.25.22.01.16
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Jun 2024 22:01:17 -0700 (PDT)
Message-ID: <9174171f-314f-4d8f-8b14-5bb6d34b45a5@redhat.com>
Date: Wed, 26 Jun 2024 07:01:16 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 0/3] mm/memory_hotplug: use PageOffline() instead of
 PageReserved() for !ZONE_DEVICE
To: Andrew Morton <akpm@linux-foundation.org>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-hyperv@vger.kernel.org, virtualization@lists.linux.dev,
 xen-devel@lists.xenproject.org, kasan-dev@googlegroups.com,
 Mike Rapoport <rppt@kernel.org>, Oscar Salvador <osalvador@suse.de>,
 "K. Y. Srinivasan" <kys@microsoft.com>,
 Haiyang Zhang <haiyangz@microsoft.com>, Wei Liu <wei.liu@kernel.org>,
 Dexuan Cui <decui@microsoft.com>, "Michael S. Tsirkin" <mst@redhat.com>,
 Jason Wang <jasowang@redhat.com>, Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
 =?UTF-8?Q?Eugenio_P=C3=A9rez?= <eperezma@redhat.com>,
 Juergen Gross <jgross@suse.com>, Stefano Stabellini
 <sstabellini@kernel.org>,
 Oleksandr Tyshchenko <oleksandr_tyshchenko@epam.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>
References: <20240607090939.89524-1-david@redhat.com>
 <20240625154344.9f3db1ddfe2cb9cdd5583783@linux-foundation.org>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 xsFNBFXLn5EBEAC+zYvAFJxCBY9Tr1xZgcESmxVNI/0ffzE/ZQOiHJl6mGkmA1R7/uUpiCjJ
 dBrn+lhhOYjjNefFQou6478faXE6o2AhmebqT4KiQoUQFV4R7y1KMEKoSyy8hQaK1umALTdL
 QZLQMzNE74ap+GDK0wnacPQFpcG1AE9RMq3aeErY5tujekBS32jfC/7AnH7I0v1v1TbbK3Gp
 XNeiN4QroO+5qaSr0ID2sz5jtBLRb15RMre27E1ImpaIv2Jw8NJgW0k/D1RyKCwaTsgRdwuK
 Kx/Y91XuSBdz0uOyU/S8kM1+ag0wvsGlpBVxRR/xw/E8M7TEwuCZQArqqTCmkG6HGcXFT0V9
 PXFNNgV5jXMQRwU0O/ztJIQqsE5LsUomE//bLwzj9IVsaQpKDqW6TAPjcdBDPLHvriq7kGjt
 WhVhdl0qEYB8lkBEU7V2Yb+SYhmhpDrti9Fq1EsmhiHSkxJcGREoMK/63r9WLZYI3+4W2rAc
 UucZa4OT27U5ZISjNg3Ev0rxU5UH2/pT4wJCfxwocmqaRr6UYmrtZmND89X0KigoFD/XSeVv
 jwBRNjPAubK9/k5NoRrYqztM9W6sJqrH8+UWZ1Idd/DdmogJh0gNC0+N42Za9yBRURfIdKSb
 B3JfpUqcWwE7vUaYrHG1nw54pLUoPG6sAA7Mehl3nd4pZUALHwARAQABzSREYXZpZCBIaWxk
 ZW5icmFuZCA8ZGF2aWRAcmVkaGF0LmNvbT7CwZgEEwEIAEICGwMGCwkIBwMCBhUIAgkKCwQW
 AgMBAh4BAheAAhkBFiEEG9nKrXNcTDpGDfzKTd4Q9wD/g1oFAl8Ox4kFCRKpKXgACgkQTd4Q
 9wD/g1oHcA//a6Tj7SBNjFNM1iNhWUo1lxAja0lpSodSnB2g4FCZ4R61SBR4l/psBL73xktp
 rDHrx4aSpwkRP6Epu6mLvhlfjmkRG4OynJ5HG1gfv7RJJfnUdUM1z5kdS8JBrOhMJS2c/gPf
 wv1TGRq2XdMPnfY2o0CxRqpcLkx4vBODvJGl2mQyJF/gPepdDfcT8/PY9BJ7FL6Hrq1gnAo4
 3Iv9qV0JiT2wmZciNyYQhmA1V6dyTRiQ4YAc31zOo2IM+xisPzeSHgw3ONY/XhYvfZ9r7W1l
 pNQdc2G+o4Di9NPFHQQhDw3YTRR1opJaTlRDzxYxzU6ZnUUBghxt9cwUWTpfCktkMZiPSDGd
 KgQBjnweV2jw9UOTxjb4LXqDjmSNkjDdQUOU69jGMUXgihvo4zhYcMX8F5gWdRtMR7DzW/YE
 BgVcyxNkMIXoY1aYj6npHYiNQesQlqjU6azjbH70/SXKM5tNRplgW8TNprMDuntdvV9wNkFs
 9TyM02V5aWxFfI42+aivc4KEw69SE9KXwC7FSf5wXzuTot97N9Phj/Z3+jx443jo2NR34XgF
 89cct7wJMjOF7bBefo0fPPZQuIma0Zym71cP61OP/i11ahNye6HGKfxGCOcs5wW9kRQEk8P9
 M/k2wt3mt/fCQnuP/mWutNPt95w9wSsUyATLmtNrwccz63XOwU0EVcufkQEQAOfX3n0g0fZz
 Bgm/S2zF/kxQKCEKP8ID+Vz8sy2GpDvveBq4H2Y34XWsT1zLJdvqPI4af4ZSMxuerWjXbVWb
 T6d4odQIG0fKx4F8NccDqbgHeZRNajXeeJ3R7gAzvWvQNLz4piHrO/B4tf8svmRBL0ZB5P5A
 2uhdwLU3NZuK22zpNn4is87BPWF8HhY0L5fafgDMOqnf4guJVJPYNPhUFzXUbPqOKOkL8ojk
 CXxkOFHAbjstSK5Ca3fKquY3rdX3DNo+EL7FvAiw1mUtS+5GeYE+RMnDCsVFm/C7kY8c2d0G
 NWkB9pJM5+mnIoFNxy7YBcldYATVeOHoY4LyaUWNnAvFYWp08dHWfZo9WCiJMuTfgtH9tc75
 7QanMVdPt6fDK8UUXIBLQ2TWr/sQKE9xtFuEmoQGlE1l6bGaDnnMLcYu+Asp3kDT0w4zYGsx
 5r6XQVRH4+5N6eHZiaeYtFOujp5n+pjBaQK7wUUjDilPQ5QMzIuCL4YjVoylWiBNknvQWBXS
 lQCWmavOT9sttGQXdPCC5ynI+1ymZC1ORZKANLnRAb0NH/UCzcsstw2TAkFnMEbo9Zu9w7Kv
 AxBQXWeXhJI9XQssfrf4Gusdqx8nPEpfOqCtbbwJMATbHyqLt7/oz/5deGuwxgb65pWIzufa
 N7eop7uh+6bezi+rugUI+w6DABEBAAHCwXwEGAEIACYCGwwWIQQb2cqtc1xMOkYN/MpN3hD3
 AP+DWgUCXw7HsgUJEqkpoQAKCRBN3hD3AP+DWrrpD/4qS3dyVRxDcDHIlmguXjC1Q5tZTwNB
 boaBTPHSy/Nksu0eY7x6HfQJ3xajVH32Ms6t1trDQmPx2iP5+7iDsb7OKAb5eOS8h+BEBDeq
 3ecsQDv0fFJOA9ag5O3LLNk+3x3q7e0uo06XMaY7UHS341ozXUUI7wC7iKfoUTv03iO9El5f
 XpNMx/YrIMduZ2+nd9Di7o5+KIwlb2mAB9sTNHdMrXesX8eBL6T9b+MZJk+mZuPxKNVfEQMQ
 a5SxUEADIPQTPNvBewdeI80yeOCrN+Zzwy/Mrx9EPeu59Y5vSJOx/z6OUImD/GhX7Xvkt3kq
 Er5KTrJz3++B6SH9pum9PuoE/k+nntJkNMmQpR4MCBaV/J9gIOPGodDKnjdng+mXliF3Ptu6
 3oxc2RCyGzTlxyMwuc2U5Q7KtUNTdDe8T0uE+9b8BLMVQDDfJjqY0VVqSUwImzTDLX9S4g/8
 kC4HRcclk8hpyhY2jKGluZO0awwTIMgVEzmTyBphDg/Gx7dZU1Xf8HFuE+UZ5UDHDTnwgv7E
 th6RC9+WrhDNspZ9fJjKWRbveQgUFCpe1sa77LAw+XFrKmBHXp9ZVIe90RMe2tRL06BGiRZr
 jPrnvUsUUsjRoRNJjKKA/REq+sAnhkNPPZ/NNMjaZ5b8Tovi8C0tmxiCHaQYqj7G2rgnT0kt
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <20240625154344.9f3db1ddfe2cb9cdd5583783@linux-foundation.org>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=f1VKA+X6;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 26.06.24 00:43, Andrew Morton wrote:
> afaict we're in decent state to move this series into mm-stable.  I've
> tagged the following issues:
> 
> https://lkml.kernel.org/r/80532f73e52e2c21fdc9aac7bce24aefb76d11b0.camel@linux.intel.com
> https://lkml.kernel.org/r/30b5d493-b7c2-4e63-86c1-dcc73d21dc15@redhat.com
> 
> Have these been addressed and are we ready to send this series into the world?

Yes, should all be addressed and this should be good to go.

-- 
Cheers,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9174171f-314f-4d8f-8b14-5bb6d34b45a5%40redhat.com.
