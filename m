Return-Path: <kasan-dev+bncBC32535MUICBBR5F7TCQMGQESWQX4KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 46949B496F0
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 19:30:49 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-336a33789d3sf25473041fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 10:30:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757352648; cv=pass;
        d=google.com; s=arc-20240605;
        b=KAmZXgg8tTucCe8YApO31ME+rTLmmPJv+YrQrtu6aWU0/RhRQ8iZGYFR+kZZxhrjC1
         Ou65wtFGOGPiIVdiBN1wLj5qfRS36aTVeyvKF90LtmZP0jzFVgSOV9yOZ1lRvcgApwXT
         3CXCQARTOSNxBn0e+TOC/zVch5y/JDCq0gq3czTX+WKilqtAwm2IL4ZZ5ruIua80Nz+P
         xHY7MOgJygIPkK4rTpyhDuqVSaidm5l5PRAcUzGz/Y4mzScXyWqdG111lp2XCKsiJ2Eq
         EFLiqLQ26ZK5uq7HdDs+qbqbn9SdpkK/S53NauVznzCpgnJyivcQDuudH0oCpYiO23c1
         mCBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=aE2K4xBDucsR7OkSJ+5BvP/c4DNR+lXrKgrRWpBgEtk=;
        fh=gMXyIx+2HjRWPwfHxJcm7b5vQKukdAr35ogRrnqodoQ=;
        b=UtQnj4GOv+TfGYTj4m10pZD99hZkxENOD8AZdwsVog/yW4xkM3J1g+l0GlDdtt5CbF
         DMcBPjKs4eAZ+GXx/0bmv14cPpuBQnq7JixsRVEECT+qeoCAlF23yRRPVUbx1hlVJmPw
         MSRAA1hO1ge/nrZB71Ak/L/xq4WDjEpfbI+RL+ro8PkiHIFU6lFPDwdrWPmBGT5iPOLe
         Lsrq2uq+YqHo0KzRNRnZIS19MILRSim2E8J2tkbP32wJbljdzmxJozLgNCTFSbJmO3/F
         //DEmzrtrbxWbvqtjdczHLsRehLUSbLx37YF1wLlq2EzFdKnCbD7BEoEjn/0U8N6SHWl
         hwzA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QYWRPAmM;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757352648; x=1757957448; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=aE2K4xBDucsR7OkSJ+5BvP/c4DNR+lXrKgrRWpBgEtk=;
        b=IPhZDenBuo5FlBlJNWF/O0FBIKdwhGtEbyD8sSNjXpWSDqyTgTnh9kgj/2/Ouja0dv
         e0ljqoL084PICsyrT6Ebzt220bk9unfDQAdilKk3QWPElXXLqGzR67KS+iMmB5WmSEXM
         0Oq+GFgEjyw2ZDP5vvFB9F74a0Q9zELleL8au9EHFcdpRbPE3+JUVeTbj3d6HcHpdyqu
         nG3CfjDR58JM8rUfCRRTiD4CW+YFPSs+gmA1288eceWaaTkwm5psXMJIIzV+7m7d/+oK
         W0XI9LRs9PtX8z3QtYkgfe0NI5l8RwR65U63STF0miGUUVggTF43oi3oJga5dsm3g0EL
         tfpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757352648; x=1757957448;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=aE2K4xBDucsR7OkSJ+5BvP/c4DNR+lXrKgrRWpBgEtk=;
        b=IaX9cyi7iOLcadJQr7Q1WBR+zc97sG0cF+blnax6ZIAziBJOUOP3MxuaUvaI2zrfpB
         mpYQi5iNRE3MKv6MUqnnD1bAwqRBPGlPiK7Ggza/lru9TQOt43nEPMpicEKsYtoMHnHd
         RdWzLAK9ushTdVHkAqW4XaARKhGTf2+8vstjxvoLXXY9RrhSavd/Vab7HZNhEhqGMk7n
         vkz79oQm27g2TJgUl5uHKnkObyswwt4APZ1AjTBxhYRg10Kr0Obk0n3zKYBkK99WqgsC
         bP0S2GHMVpYszDxK5iLFQ9htmbctWQAflo9FYQqFeRPsXVLPyeMt7COn/B1CpeMXhjn3
         fTIg==
X-Forwarded-Encrypted: i=2; AJvYcCUEEgVwUTvQ3k8d8rH1pQoHhGue3cTKLX8cWfNf6thR1XGfD7Pzb+q/pLUad0wDW3zPZux92A==@lfdr.de
X-Gm-Message-State: AOJu0YynXnVtKqOwaHWshUOsM3NUSjl143t1vge81F9k0XfCjdLt15XW
	4hR7vGv36ovSVX8lok0bTCH5mhM75U3y9WaZfGFXcil7wKY/3W3yQ0Yl
X-Google-Smtp-Source: AGHT+IFHWYINeFXkGtjW4mIW3WHdGZKT14z5jZYudvMcJUIf94bSaE/MUkwL0ENTCa2hTWHAbP9n7w==
X-Received: by 2002:a05:651c:220b:b0:32c:a097:4198 with SMTP id 38308e7fff4ca-33b58fa2f3fmr26544301fa.1.1757352648051;
        Mon, 08 Sep 2025 10:30:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfelQ39Dpiv9x/DvEA+QRCKDsCbLDqugpG5SuOrmr/Qkw==
Received: by 2002:ac2:5e22:0:b0:55f:48d5:149d with SMTP id 2adb3069b0e04-5615baf3214ls787672e87.2.-pod-prod-08-eu;
 Mon, 08 Sep 2025 10:30:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU4VA4/2KJXWjlq4zrZg6V8mM+fnXqBieds7K+fl1TRYrAnnGxg/lX1NA0zVSN1/QdI+YAMe3luNRk=@googlegroups.com
X-Received: by 2002:a05:6512:238d:b0:55f:5704:806d with SMTP id 2adb3069b0e04-5625f53608fmr2287904e87.21.1757352643511;
        Mon, 08 Sep 2025 10:30:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757352643; cv=none;
        d=google.com; s=arc-20240605;
        b=gMMEEGzl2vvHuBPvSA4z7gB098AGnmiBZOkJb8m/KPqVkqfbJ3kki01L5z/SIyC2z9
         cGuH/e1lijE0BGzazF9RdhIXhfSnMU+de9dXBRDReSpReh5fYw/hBLkWFQ0aQFO1RpPZ
         UW77GpxD1Uy4FrfEjndnnYYsSP8fqNgZy3fGov5qhJ4ameGOTk/7H20YAnCrQ3KMDeb9
         wP7CFOez98raf2Y1yTEc2CNInyyKpeYOFwPAFCp3V5pFy42t180UGQ0h9I5tSdza9QQu
         hEKdlO6E8oBaJWxYdig8xlzPFAwQPl651un6EYkg6GtLRn1rku6ezQA9cU2FXCZDsqJD
         TIhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=RAwcm1nPLLX4X92euXLnYeRyvAbGSoqBmBe5SHTlwFM=;
        fh=YC54lrzgXjy3mjtGe+EhKJoMR3XnuZ0YOEc5rfvxtFw=;
        b=i8CqpJ8MTk1QdBVw12BRFjyZHuE+/Yl2W1/JznjM+ujNuhDmVdJdBthEoBgApP0Gm8
         dylO/98/kN5Z44dCTm0+VFvGi2LvJKjGKPhVg1pll4DDUvnIMoFyTUMRx3E+6beRY7Lc
         JWMne6LRDVTl51SolvpdgU+z8lfNYyOVQ6ZB5+h+S2q38d2hRfB4N1pa49+2ZXmwn0uV
         3tcXZrM8wdRH/L8TCwhsEwq1gV8ZRmO2ZfI44Uhc5Cfe24EYN+OcdDR1jDPmPggG1cwG
         4+noY7LEwoJzpH0tXI3okoZEDqBn74cQqLAP7bpaK9jbfozjGPoiX4comQa5qP6JJL3c
         3q0g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QYWRPAmM;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5608acb5e9fsi263309e87.6.2025.09.08.10.30.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 10:30:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wr1-f70.google.com (mail-wr1-f70.google.com
 [209.85.221.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-84-gCJreCtKOEuoyXJrgLBaZQ-1; Mon, 08 Sep 2025 13:30:41 -0400
X-MC-Unique: gCJreCtKOEuoyXJrgLBaZQ-1
X-Mimecast-MFC-AGG-ID: gCJreCtKOEuoyXJrgLBaZQ_1757352640
Received: by mail-wr1-f70.google.com with SMTP id ffacd0b85a97d-3dbf3054ac4so2739075f8f.3
        for <kasan-dev@googlegroups.com>; Mon, 08 Sep 2025 10:30:40 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXEizXTT8R1S74DJFPaVKnaFmy9q2sEehYL8DcNRi/BePzZHQfxp0CRUb9IFrw+Zah/VDCE55c8iBo=@googlegroups.com
X-Gm-Gg: ASbGncuS3FDZv+mlOUr/wfj8C8YXjFuzFxDArmheWgdNQl1J6ogwOvVc/QFvIdYhXHX
	jUcZVPO/Ww93+7m4/zZ2Q5OSvu8+LHZ5I2Nkh3Q7Wuua+kxPQoJWu6/qoIfglQ/HFVvUdkHB5Ut
	C5b9T11y5ouOjdevJWup/O/vmlJ1tNB646L7XPGbqjKy2whI2ov8EKX4s+SxjvKOiybQhMeMSqH
	lb07WmUUwVCA3nEOcd7CZl6YEGSOhfQ3C6yIWLAvSSDv8luZ+eSp8AkJupjeA8bk7RXwjYfAgFp
	TAr35uBV5CRnFo9EpsCkwOcWE1ZHi/vkfa78E/pvW2UtNBI/H6taHpNGkSZ7j6xqXYYIri2c97x
	YXPe6mGBCCHh9V0pxd+010zh73eW0lj1cvoq5gs6+FSGbwOYRf+YBF02fqt4Xog8T
X-Received: by 2002:a5d:5d05:0:b0:3ce:f0a5:d581 with SMTP id ffacd0b85a97d-3e636d8ff6dmr7012173f8f.7.1757352639325;
        Mon, 08 Sep 2025 10:30:39 -0700 (PDT)
X-Received: by 2002:a5d:5d05:0:b0:3ce:f0a5:d581 with SMTP id ffacd0b85a97d-3e636d8ff6dmr7012120f8f.7.1757352638837;
        Mon, 08 Sep 2025 10:30:38 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f25:700:d846:15f3:6ca0:8029? (p200300d82f250700d84615f36ca08029.dip0.t-ipconnect.de. [2003:d8:2f25:700:d846:15f3:6ca0:8029])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45dd296ed51sm197762845e9.3.2025.09.08.10.30.35
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Sep 2025 10:30:38 -0700 (PDT)
Message-ID: <92def589-a76f-4360-8861-6bc9f94c1987@redhat.com>
Date: Mon, 8 Sep 2025 19:30:34 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 03/16] mm: add vma_desc_size(), vma_desc_pages() helpers
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Jason Gunthorpe <jgg@nvidia.com>,
 Andrew Morton <akpm@linux-foundation.org>, Jonathan Corbet <corbet@lwn.net>,
 Matthew Wilcox <willy@infradead.org>, Guo Ren <guoren@kernel.org>,
 Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
 Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>,
 Alexander Gordeev <agordeev@linux.ibm.com>,
 Christian Borntraeger <borntraeger@linux.ibm.com>,
 Sven Schnelle <svens@linux.ibm.com>, "David S . Miller"
 <davem@davemloft.net>, Andreas Larsson <andreas@gaisler.com>,
 Arnd Bergmann <arnd@arndb.de>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Dan Williams <dan.j.williams@intel.com>,
 Vishal Verma <vishal.l.verma@intel.com>, Dave Jiang <dave.jiang@intel.com>,
 Nicolas Pitre <nico@fluxnic.net>, Muchun Song <muchun.song@linux.dev>,
 Oscar Salvador <osalvador@suse.de>,
 Konstantin Komarov <almaz.alexandrovich@paragon-software.com>,
 Baoquan He <bhe@redhat.com>, Vivek Goyal <vgoyal@redhat.com>,
 Dave Young <dyoung@redhat.com>, Tony Luck <tony.luck@intel.com>,
 Reinette Chatre <reinette.chatre@intel.com>,
 Dave Martin <Dave.Martin@arm.com>, James Morse <james.morse@arm.com>,
 Alexander Viro <viro@zeniv.linux.org.uk>,
 Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
 "Liam R . Howlett" <Liam.Howlett@oracle.com>,
 Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
 Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
 Hugh Dickins <hughd@google.com>, Baolin Wang
 <baolin.wang@linux.alibaba.com>, Uladzislau Rezki <urezki@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 Jann Horn <jannh@google.com>, Pedro Falcato <pfalcato@suse.de>,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-csky@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-s390@vger.kernel.org,
 sparclinux@vger.kernel.org, nvdimm@lists.linux.dev,
 linux-cxl@vger.kernel.org, linux-mm@kvack.org, ntfs3@lists.linux.dev,
 kexec@lists.infradead.org, kasan-dev@googlegroups.com
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <d8767cda1afd04133e841a819bcedf1e8dda4436.1757329751.git.lorenzo.stoakes@oracle.com>
 <20250908125101.GX616306@nvidia.com>
 <e71b7763-4a62-4709-9969-8579bdcff595@lucifer.local>
 <20250908133224.GE616306@nvidia.com>
 <090675bd-cb18-4148-967b-52cca452e07b@lucifer.local>
 <20250908142011.GK616306@nvidia.com>
 <764d413a-43a3-4be2-99c4-616cd8cd3998@lucifer.local>
 <af3695c3-836a-4418-b18d-96d8ae122f25@redhat.com>
 <d47b68a2-9376-425c-86ce-0a3746819f38@lucifer.local>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
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
 ZW5icmFuZCA8ZGF2aWRAcmVkaGF0LmNvbT7CwZoEEwEIAEQCGwMCF4ACGQEFCwkIBwICIgIG
 FQoJCAsCBBYCAwECHgcWIQQb2cqtc1xMOkYN/MpN3hD3AP+DWgUCaJzangUJJlgIpAAKCRBN
 3hD3AP+DWhAxD/9wcL0A+2rtaAmutaKTfxhTP0b4AAp1r/eLxjrbfbCCmh4pqzBhmSX/4z11
 opn2KqcOsueRF1t2ENLOWzQu3Roiny2HOU7DajqB4dm1BVMaXQya5ae2ghzlJN9SIoopTWlR
 0Af3hPj5E2PYvQhlcqeoehKlBo9rROJv/rjmr2x0yOM8qeTroH/ZzNlCtJ56AsE6Tvl+r7cW
 3x7/Jq5WvWeudKrhFh7/yQ7eRvHCjd9bBrZTlgAfiHmX9AnCCPRPpNGNedV9Yty2Jnxhfmbv
 Pw37LA/jef8zlCDyUh2KCU1xVEOWqg15o1RtTyGV1nXV2O/mfuQJud5vIgzBvHhypc3p6VZJ
 lEf8YmT+Ol5P7SfCs5/uGdWUYQEMqOlg6w9R4Pe8d+mk8KGvfE9/zTwGg0nRgKqlQXrWRERv
 cuEwQbridlPAoQHrFWtwpgYMXx2TaZ3sihcIPo9uU5eBs0rf4mOERY75SK+Ekayv2ucTfjxr
 Kf014py2aoRJHuvy85ee/zIyLmve5hngZTTe3Wg3TInT9UTFzTPhItam6dZ1xqdTGHZYGU0O
 otRHcwLGt470grdiob6PfVTXoHlBvkWRadMhSuG4RORCDpq89vu5QralFNIf3EysNohoFy2A
 LYg2/D53xbU/aa4DDzBb5b1Rkg/udO1gZocVQWrDh6I2K3+cCs7BTQRVy5+RARAA59fefSDR
 9nMGCb9LbMX+TFAoIQo/wgP5XPyzLYakO+94GrgfZjfhdaxPXMsl2+o8jhp/hlIzG56taNdt
 VZtPp3ih1AgbR8rHgXw1xwOpuAd5lE1qNd54ndHuADO9a9A0vPimIes78Hi1/yy+ZEEvRkHk
 /kDa6F3AtTc1m4rbbOk2fiKzzsE9YXweFjQvl9p+AMw6qd/iC4lUk9g0+FQXNdRs+o4o6Qvy
 iOQJfGQ4UcBuOy1IrkJrd8qq5jet1fcM2j4QvsW8CLDWZS1L7kZ5gT5EycMKxUWb8LuRjxzZ
 3QY1aQH2kkzn6acigU3HLtgFyV1gBNV44ehjgvJpRY2cC8VhanTx0dZ9mj1YKIky5N+C0f21
 zvntBqcxV0+3p8MrxRRcgEtDZNav+xAoT3G0W4SahAaUTWXpsZoOecwtxi74CyneQNPTDjNg
 azHmvpdBVEfj7k3p4dmJp5i0U66Onmf6mMFpArvBRSMOKU9DlAzMi4IvhiNWjKVaIE2Se9BY
 FdKVAJaZq85P2y20ZBd08ILnKcj7XKZkLU5FkoA0udEBvQ0f9QLNyyy3DZMCQWcwRuj1m73D
 sq8DEFBdZ5eEkj1dCyx+t/ga6x2rHyc8Sl86oK1tvAkwBNsfKou3v+jP/l14a7DGBvrmlYjO
 59o3t6inu6H7pt7OL6u6BQj7DoMAEQEAAcLBfAQYAQgAJgIbDBYhBBvZyq1zXEw6Rg38yk3e
 EPcA/4NaBQJonNqrBQkmWAihAAoJEE3eEPcA/4NaKtMQALAJ8PzprBEXbXcEXwDKQu+P/vts
 IfUb1UNMfMV76BicGa5NCZnJNQASDP/+bFg6O3gx5NbhHHPeaWz/VxlOmYHokHodOvtL0WCC
 8A5PEP8tOk6029Z+J+xUcMrJClNVFpzVvOpb1lCbhjwAV465Hy+NUSbbUiRxdzNQtLtgZzOV
 Zw7jxUCs4UUZLQTCuBpFgb15bBxYZ/BL9MbzxPxvfUQIPbnzQMcqtpUs21CMK2PdfCh5c4gS
 sDci6D5/ZIBw94UQWmGpM/O1ilGXde2ZzzGYl64glmccD8e87OnEgKnH3FbnJnT4iJchtSvx
 yJNi1+t0+qDti4m88+/9IuPqCKb6Stl+s2dnLtJNrjXBGJtsQG/sRpqsJz5x1/2nPJSRMsx9
 5YfqbdrJSOFXDzZ8/r82HgQEtUvlSXNaXCa95ez0UkOG7+bDm2b3s0XahBQeLVCH0mw3RAQg
 r7xDAYKIrAwfHHmMTnBQDPJwVqxJjVNr7yBic4yfzVWGCGNE4DnOW0vcIeoyhy9vnIa3w1uZ
 3iyY2Nsd7JxfKu1PRhCGwXzRw5TlfEsoRI7V9A8isUCoqE2Dzh3FvYHVeX4Us+bRL/oqareJ
 CIFqgYMyvHj7Q06kTKmauOe4Nf0l0qEkIuIzfoLJ3qr5UyXc2hLtWyT9Ir+lYlX9efqh7mOY
 qIws/H2t
In-Reply-To: <d47b68a2-9376-425c-86ce-0a3746819f38@lucifer.local>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: aW-_08wNWGHeiRPA40X_4G4zTThOwqz-Ecj3__9SmmA_1757352640
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=QYWRPAmM;
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

On 08.09.25 17:35, Lorenzo Stoakes wrote:
> On Mon, Sep 08, 2025 at 05:07:57PM +0200, David Hildenbrand wrote:
>> On 08.09.25 16:47, Lorenzo Stoakes wrote:
>>> On Mon, Sep 08, 2025 at 11:20:11AM -0300, Jason Gunthorpe wrote:
>>>> On Mon, Sep 08, 2025 at 03:09:43PM +0100, Lorenzo Stoakes wrote:
>>>>>> Perhaps
>>>>>>
>>>>>> !vma_desc_cowable()
>>>>>>
>>>>>> Is what many drivers are really trying to assert.
>>>>>
>>>>> Well no, because:
>>>>>
>>>>> static inline bool is_cow_mapping(vm_flags_t flags)
>>>>> {
>>>>> 	return (flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE;
>>>>> }
>>>>>
>>>>> Read-only means !CoW.
>>>>
>>>> What drivers want when they check SHARED is to prevent COW. It is COW
>>>> that causes problems for whatever the driver is doing, so calling the
>>>> helper cowable and making the test actually right for is a good thing.
>>>>
>>>> COW of this VMA, and no possibilty to remap/mprotect/fork/etc it into
>>>> something that is COW in future.
>>>
>>> But you can't do that if !VM_MAYWRITE.
>>>
>>> I mean probably the driver's just wrong and should use is_cow_mapping() tbh.
>>>
>>>>
>>>> Drivers have commonly various things with VM_SHARED to establish !COW,
>>>> but if that isn't actually right then lets fix it to be clear and
>>>> correct.
>>>
>>> I think we need to be cautious of scope here :) I don't want to accidentally
>>> break things this way.
>>>
>>> OK I think a sensible way forward - How about I add desc_is_cowable() or
>>> vma_desc_cowable() and only set this if I'm confident it's correct?
>>
>> I'll note that the naming is bad.
>>
>> Why?
>>
>> Because the vma_desc is not cowable. The underlying mapping maybe is.
> 
> Right, but the vma_desc desribes a VMA being set up.
> 
> I mean is_cow_mapping(desc->vm_flags) isn't too egregious anyway, so maybe
> just use that for that case?

Yes, I don't think we would need another wrapper.

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/92def589-a76f-4360-8861-6bc9f94c1987%40redhat.com.
