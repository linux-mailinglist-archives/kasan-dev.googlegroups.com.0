Return-Path: <kasan-dev+bncBC32535MUICBB2W67PCQMGQEIOMJM5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id C6C14B49235
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 16:59:56 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-40b48e4a0desf13776615ab.2
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 07:59:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757343595; cv=pass;
        d=google.com; s=arc-20240605;
        b=BnenytIW/71KpCZVk3psnBuwolgVu65jbnOuFPrXIKu+rmExuZFoxyp+16KtrSS6Ux
         u4tP40/gxiv9Z9iqdL3gS1EQ7DAUaNBI8W1CN0M5VmITO0K55fTa8O58GKZyE9wBZkrb
         V/3di5EJlxI69/z987JrCvQjMzDUZsAFe6pkeqquPNkGswMmzvr9CFlUyWiybgNQSqAa
         tK9bPbJu9P9pSaYsaqo0xC9m4nP8F7biyq4XSuRD77TnWe+1PWKgLjlD8jKJW3bYgDI1
         1ATfayioe3wPa9Kv5B1PeZB+M7CkEt8Hl0jSVlJbun6C3UWQyaAYxSsTOcULBG4lvhPI
         IpzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=nT8TdHvx768oySwqBRVtpsO9sEhcFsbc94hxzNBiQI4=;
        fh=DmMzOU+CAGFpLoCvKgpD1MTmI5aV/HvBNVFV29wAzOc=;
        b=j6JrC2Hg+Q7K7Q6YGo0bEhzH0K2szJv0B0HzcZ+GB114X7qjxc0DTENsIWPbcB0kXU
         4CUwM6OOW6BU6O4NJyIS7TE8+6DmPgMuvbZ2QcnqxOorTbSsme5YXi8JGVpTS0m+i4bn
         E4+IDt1DVJjVsuYZhUDt4K2qOopcLvgBM+IiECPD0IYRI6ISblrJdvlAOZGTGWousIeP
         q4EcQuopbKWLv4YTOfEpEZ5KP1/xf8GfD8N6aEWuYr4eKfaL5YqxP1OYeLGKBvhloPZm
         ciW6qyq9QsMtSSXa1IyzNPCsyp6N/wyJF9I7Pb7GdobBydHpffgaBLivCgD6hsbNvLW/
         U4sA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=g0azDLjH;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757343595; x=1757948395; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=nT8TdHvx768oySwqBRVtpsO9sEhcFsbc94hxzNBiQI4=;
        b=Ckx3zBHnT86mWDDzxQpc5CsmAfkETONgqDU9OKHAfgSMpfN/ABKEiMdfVK1U6tGvAw
         NPA160gTQFBCxkfzST46yuzB85VNrLbt7Fa+BnmgavUblZfUx+jaYQtN6LUGDs3iUnjY
         Y3TOf0ENA+Q7S/V3XFCT6OgxivhWkUWm+G7uxVelFAm0Sue0tU4FY8KSgcDKJPIbtF13
         YKoSoZ3ulePKRcbmlnHaHSav7v2NoYJTlSJuZlfCrmMhhABAmBjbql6/S0Qh5ZiRBNVU
         NjoFydyAoG1SdfNXIyLC9+XDTIKIAp5g2p03x4YAAD5J20cPuMu1qgualKJjOngEWLva
         5aiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757343595; x=1757948395;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=nT8TdHvx768oySwqBRVtpsO9sEhcFsbc94hxzNBiQI4=;
        b=kv7ucZjHj2F9Gm/hCNA7xootaCrQYxLgNGm8GOy2oBrMekDTe4Dky2WDDZz/g8h8vG
         JhD8rzdIoQhR41MNEtkaZBOXoLskYdfKdMTW4pAfZegQhvYjKpy5yF6glwDcdG6TP3LR
         YxLKp1ulHqkTPSqz6jbQZvOycP/JtclKU4/r6JeA3r41qEvAkQ2i7Jut0z2YRYSVGXNp
         XbzGaZ6JpTqSw7CdlnLmiztXveKqYCbezrAnw3QPRzJeO1kX2CNxuOqpqcO/qjV1MsIx
         ml7CcvJhvWqcA4lF6T0yWvdWUdlcaAXO0fh/erhIHnRL8WkTRacJCuMRqRiuYwB9AVgk
         QF9Q==
X-Forwarded-Encrypted: i=2; AJvYcCVbvLtU3vp/phMMmW/EIcncC0QpxKvUTM3riVxVfnHVQTYHTGD5lqmqMCufK/OWPz8A9b5HlQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy7gDJpddm7vXAqlDDSGTzHQXcmX5n17row85uVNLwMZWezhWkL
	NhLXe4jUPWIX2YITH94UK6/cMr66uHeNbnvHt/GDBQl/6d7F27vqncXl
X-Google-Smtp-Source: AGHT+IEfw7QtAZFKm0B50RZHWF2FlZ5gfPDaZvDg+GuIPmVT99gPpelFTgIt35IHDNzhNFRBzfrNXg==
X-Received: by 2002:a05:6e02:1a61:b0:3ec:248b:8760 with SMTP id e9e14a558f8ab-3fd94a13fc3mr124347445ab.18.1757343595461;
        Mon, 08 Sep 2025 07:59:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcLMbaJ0ITub0Wopk9K8LOhTj+NPjqyWAo4GK8kDWa62A==
Received: by 2002:a05:6e02:470f:b0:3ed:8be3:e759 with SMTP id
 e9e14a558f8ab-3f8adcb41d7ls33177835ab.1.-pod-prod-08-us; Mon, 08 Sep 2025
 07:59:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX+VEaV/+ZYviixJJxM4XLH9KpR8/l9W/jUs1VLsxZh6F1NK6NVh45pGamcGH4XTwIObCtNaBMjZJw=@googlegroups.com
X-Received: by 2002:a05:6602:140f:b0:88c:30f3:32ea with SMTP id ca18e2360f4ac-88c30f336bamr430897539f.8.1757343594081;
        Mon, 08 Sep 2025 07:59:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757343594; cv=none;
        d=google.com; s=arc-20240605;
        b=hatztd3HRXPWZI3zu7elrYpU5Rkyp2/S7E0JeUMR+JmpluvavE/JjkDNyGtZqNi2b0
         uwXJmyfb2M80GfTRRt34Zitva3TLrSuNIcpn0/H/v8iat0tdjbW22LWBGw5O6745D34O
         062lJIB9TO4v5+ovQAT/dB8wMFQxh/NdLteA7aEXbsUUWAuKLKfs2vbU8CbtZk4jaMFm
         rND10O0UYUINnxgdE8oKTOD7GhKYkQ0r0sJLgKnSFMCMW9Nm0P0gpN7dur/p1FhZMpy0
         ZgR4elvmF1JSGSkKQYiQU3WtAHgzdjCPHLM1AZujJQd5JP4/suyk51wRaWWhFbTkIDey
         CTpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=zj/W2A1w620z3uj4NM/KYzIZPfPCpjNHUO9sqnkbSZI=;
        fh=kKFYQ46fe/OXRzV0OSqTBSEQvIApnkeP1JrADrVVYZo=;
        b=GItwaiTVV3Vpjr5uUIYZYofTXzpXC1RC4H3D6R3BLAsRGbSoqD5kLxqQducWBzgIpU
         Dss5p8OJ4r2ajk1eeN7POx0sTNS56V5I/KtJALIkpEAEEIH0kinGkv5iYlIpt5Fw7XMO
         0M1zyKawmmMegoZH9sY5rLKO8Fh9EICUcrMu3ubLHX/389LlnzihqAAxd90wizET9MVt
         4nyw0aQgB5o8sneqIC5BjNIlt8ZGRhNQz1iTkglQJIIIZ3wfulkIb3GH7BIyONAMXdW2
         Usjr7fd4nuerEaLDC3OOfL6OUDzHi3MG2SYhGSgBmJ7XVZA3Je5LFhWXl1iD6ZiKb503
         MvVQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=g0azDLjH;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-8871e3d377fsi83887839f.2.2025.09.08.07.59.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 07:59:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com
 [209.85.128.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-581-J-qJvZnBPDSbdR2t76o1Qg-1; Mon, 08 Sep 2025 10:59:51 -0400
X-MC-Unique: J-qJvZnBPDSbdR2t76o1Qg-1
X-Mimecast-MFC-AGG-ID: J-qJvZnBPDSbdR2t76o1Qg_1757343591
Received: by mail-wm1-f70.google.com with SMTP id 5b1f17b1804b1-45dd66e1971so30137695e9.2
        for <kasan-dev@googlegroups.com>; Mon, 08 Sep 2025 07:59:51 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXrccM8LFKUK+PGd1JAKw3FWI5CqmH40nJlPvzaSqiqx1h544meldvM7ZzsF2eXhdfANzNL7WyFCGg=@googlegroups.com
X-Gm-Gg: ASbGnctCL4YqYG8gEQ8jPwL4xRaNJMRav8RCmhCXcwtidDf91isieiN5970ois/uv5f
	qg3GXYTFf7xIJFsTuco9MS4ZSntFfue1HfuweADbBMJNcv+RqKzXH3Y/OcDTEJxtm/HkJN71ac2
	d0GNV0xwH6NaBW/RMqt9RngJEztfNe7mjEKW++QmCiIPqCd/k57mXqhxfuZyH+kyz0TjQAVGMvs
	y7YE1pWaZV9snD2mNNxGxESB+v3hFX+5nepFGDmdIlD1FpzIytFyAOlrPFY8DmV2suyT77aIgzn
	4qutm8AX6Rpz4/9snuAJz8FaHsFqvwEbGxme/OP9+anylp3kMJa3GTxmaEDzM5NU52B34d21778
	NojMbcerCd3rUufyhBi3z3D4iJm0H6rf7x0D2pfNC/2/8RvCo7t/9lfL5LF2t7p3q
X-Received: by 2002:a05:6000:18a9:b0:3cb:5e64:ae8 with SMTP id ffacd0b85a97d-3e636d8fceamr8124651f8f.11.1757343590412;
        Mon, 08 Sep 2025 07:59:50 -0700 (PDT)
X-Received: by 2002:a05:6000:18a9:b0:3cb:5e64:ae8 with SMTP id ffacd0b85a97d-3e636d8fceamr8124577f8f.11.1757343589898;
        Mon, 08 Sep 2025 07:59:49 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f25:700:d846:15f3:6ca0:8029? (p200300d82f250700d84615f36ca08029.dip0.t-ipconnect.de. [2003:d8:2f25:700:d846:15f3:6ca0:8029])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3da13041bcasm25975587f8f.35.2025.09.08.07.59.47
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Sep 2025 07:59:49 -0700 (PDT)
Message-ID: <cc59a58c-266c-4424-9df1-d1cec8d740c5@redhat.com>
Date: Mon, 8 Sep 2025 16:59:46 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 01/16] mm/shmem: update shmem to use mmap_prepare
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Andrew Morton <akpm@linux-foundation.org>
Cc: Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>,
 Guo Ren <guoren@kernel.org>, Thomas Bogendoerfer
 <tsbogend@alpha.franken.de>, Heiko Carstens <hca@linux.ibm.com>,
 Vasily Gorbik <gor@linux.ibm.com>, Alexander Gordeev
 <agordeev@linux.ibm.com>, Christian Borntraeger <borntraeger@linux.ibm.com>,
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
 kexec@lists.infradead.org, kasan-dev@googlegroups.com,
 Jason Gunthorpe <jgg@nvidia.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <2f84230f9087db1c62860c1a03a90416b8d7742e.1757329751.git.lorenzo.stoakes@oracle.com>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <2f84230f9087db1c62860c1a03a90416b8d7742e.1757329751.git.lorenzo.stoakes@oracle.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: A9ArQa2QUOl2PRFUqNtbp-Iwk4pcmTP25MZB_TnQ-Qo_1757343591
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=g0azDLjH;
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

On 08.09.25 13:10, Lorenzo Stoakes wrote:
> This simply assigns the vm_ops so is easily updated - do so.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> ---

Reviewed-by: David Hildenbrand <david@redhat.com>

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cc59a58c-266c-4424-9df1-d1cec8d740c5%40redhat.com.
