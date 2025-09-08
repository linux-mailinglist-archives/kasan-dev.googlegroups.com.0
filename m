Return-Path: <kasan-dev+bncBC32535MUICBBSVI7TCQMGQEZ47FF2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 01DB9B4973C
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 19:37:16 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-337ec9ab203sf19243911fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 10:37:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757353035; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ng7oOs1BEryh6OJ0jBRhYvN1GNudf5kQK50/VySQXfvWTnr1jUjq2ZvPavnkY0Bn/M
         JiIPwU6j2uehrmZ8RCZL/XRRD0oqpFLaJ1AZMYzifnNp7rr3UJ8T17LbYXe/oUVw1d47
         3h/64ZscWfRQaeabE7KsheUuWz0Dw516JDT+0l3/47IuIbGjmRwCo7X6VuvB/eeyi6Na
         MAesf+rKtNexuADvryozNduT8xRZQfey25lPIQr6xU0y8MS1orIgvA/izarvvvbz2Pob
         HAckn2KV556Kh56xj5JyXFYod2k6MeFbOQcyuI49keN+kXdvYMPqjgI5xr/T0DN3s/F6
         LN5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=lLjXBZ2Zn9YE+w1hRqOhWrDgX+ym66ZPGUXGnN1uuNs=;
        fh=wW9XrIb/8R8nrFIVJZRz19RoWKXyNPSs9tGhh34HLBQ=;
        b=GWeEo3gx9pI/c/99Bhf/5IYF3haFdjoj/wPnsyx6aqYalUWlh/cI8QCmYZu2MtCGnS
         YYrXtL5u5goeEereS3jq1KMDaRhjryA/V0m0wPmZH7b4M2g+doyPmZZgYoDZNCHY85g6
         L9+m10Lu3YdTEib0qLtg+JGW4NCTZGdHLF8YZEKPK6D3ETpv2sEB5m61HnRyEZInO/YH
         bVQSoYL8WFu8M8X2utHQ8OtOk37iQow0G5JE8+9HsQqmnti+tWZLX88Sg836kh7mpB0+
         Zu6OXFsbhcBqdEbZ6i9yKGEYBbsRsPgTSF4F21LKTU+/KhiS9l4FzdGNj5GAQxj5mKE4
         q52Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Zau4t3QH;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757353035; x=1757957835; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=lLjXBZ2Zn9YE+w1hRqOhWrDgX+ym66ZPGUXGnN1uuNs=;
        b=WL+j1iG8Q5BUJpeL21GIj8b7QVZTAjDlufZ6n75AnYINW7Byaa08DpHGcEVyLA8868
         9HGwq9nYle3xQSf8Je9gaSJHHUT/8igB4bzcfuaBNxwndPtuDFMvK/ztfEJvOM+H+zMz
         xGoFZEFpZcrT5ufB5iFMYPTBPZbiIabhfyv9QgV25BdJ/mpFpHqCZbsug3IyQfUFuRKt
         W/0pG/+NBUpBdRZBqCU515NOQpAH0JIaEGXXt04U/pNhmZ4LblJppzewkWC5aQsNg6fd
         RoPFVYvhfWeC9QZDKeidVRBu0KTgvpT2lt64F1J5FXxV+z+Hj6fZn+8OTjNpury1Atd7
         UYlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757353035; x=1757957835;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=lLjXBZ2Zn9YE+w1hRqOhWrDgX+ym66ZPGUXGnN1uuNs=;
        b=D/dKZ8fMruxXxdLXtIGgXorH0Va/qrgVdsbu0S+QPxZSat26V1VuZESTxOjsS45mHI
         0MMGgVefq/n4tv4k2ZTWwp1DM4xDZ0zyVy7lJ7P8R+ECLJvBnvob15PjFD+UxcypI+Cl
         WnAz0TJPNx1OxS1wGkrsHkeBZs38M+YA7662/KnsqdBE6EuKk+TSgW9LWmzxr8j0Bm9J
         yUnCoAmyVq7mpTo/2mK/7EfG3agMoKesUzElfU+vsR2GBRLJ3KknquTwW/bhyDTld+Se
         lKK9FOc4ahduQXdbakXFp4eKAIa5CpSkoxrI73lyxlrpuDiZ2AR5JXniLjswOP29S7oA
         yMxA==
X-Forwarded-Encrypted: i=2; AJvYcCWNUye199bxvTJx8zdiTy5lObe84AXGGRz7cCZS8K32KOGXFyf0A6EDj7hjV3uqLLnFtARKQA==@lfdr.de
X-Gm-Message-State: AOJu0YyxgmsfIH+eRuZOh0r7bUG08JNiA506hJ5NNn0Cp+dZixOvnCk4
	5zhyIMRYkcN/rI/9Wevo/se1huG3sOI7sLw5LkZx/zAfPG9tUOcJIJSn
X-Google-Smtp-Source: AGHT+IFXvOnzYzHuRDyy0nBxp+K/O1X6/JpKogRY9Zyx7HR0d00eDxsDyN8jovvcUleJb1KOVs8dIQ==
X-Received: by 2002:a05:651c:4117:b0:336:6481:1549 with SMTP id 38308e7fff4ca-33b57f3bfecmr14772431fa.12.1757353034937;
        Mon, 08 Sep 2025 10:37:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc75GMCPtjpql2Iocngper+gSf06/t4xIrhd9Q3gFFX1A==
Received: by 2002:a05:651c:4183:b0:336:cf90:7e7d with SMTP id
 38308e7fff4ca-338d40e39bdls7674071fa.1.-pod-prod-02-eu; Mon, 08 Sep 2025
 10:37:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXEytUdSWEJ253NrOAb+k+x1B399hXkszqpJPvXPffGMUZouKumOZKHJ/rt6CVMSKM9SpkYweHFMO8=@googlegroups.com
X-Received: by 2002:a05:651c:2301:b0:330:d981:1755 with SMTP id 38308e7fff4ca-33b56fb06b2mr15523741fa.6.1757353031745;
        Mon, 08 Sep 2025 10:37:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757353031; cv=none;
        d=google.com; s=arc-20240605;
        b=Zbe6cA3LkItExvp0YHXI72fSvRi+rQwpijwQy+9g7I2A0Xivk361eMq/9QTIBlvPOn
         WtZC9PsAeRKP0nDEl4EhCkvRDXs7Wi+N6uxV0RKfmXgNjrCUjjlbpC41extAIQ7CEFHO
         9j06V8+XsKAZ3szKtXJEHTc5mixfL2t96mrUJvz91MxBG3B4lqVWGOvyvsJ2xWDrwRYO
         4y8KQlnlWwwIrvFz26QecozANLV70gPoug/R1qA6/2iL+aAhh4899dN0s2XC7ViUsFO8
         /a9SYKzMsElLfgmL/NwL+lH2wmuHrzs2YKkTiYL7oK3XeLePRwAXAuq97ey6aBv+Gr+F
         aa9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=ddTrLlBONI++Tc0vmAVCsKGI5mMqVsSsSog7PjuxMWA=;
        fh=8wQ1w3CCcM6bquChf8v/BiQ+m8bN2CKz9JCBTlvJQdY=;
        b=ELQdfiFVnAIht64O6e5QuA70qnv6ZWvClrgQUwoTgxLpM+V5zAmTa4lEfnwVHCXIOJ
         S9eyYW20Elb1XZg8N/KFEVHmqVU1XFk7x4zsRVm4q9JoMhKibe3t5VAAlO0rJW4iCmbV
         cUQ4Ksf5Sg5Bm1o6jtCvc7Q8j7kNEzvRVJFnoYk5W52mskl6pYmP4qcKGcc1V2Fbwjvx
         cXnAOz7NUGy695d18BygWRSNjSonKVpKf8mqDK0ZulwzaMFbDcbr1zsCawLZvE8M7C7x
         uT6P9oVH5DmD/tEnjzJt28ZYyyit/QPFnmHA0yO82HaPEOprm+fhJDlJazW8PFOIzQ8G
         aBxA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Zau4t3QH;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-337f4c2ec8bsi4257651fa.1.2025.09.08.10.37.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 10:37:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com
 [209.85.128.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-582-jyo1eRd-PaGFC3JpnWDVtw-1; Mon, 08 Sep 2025 13:37:06 -0400
X-MC-Unique: jyo1eRd-PaGFC3JpnWDVtw-1
X-Mimecast-MFC-AGG-ID: jyo1eRd-PaGFC3JpnWDVtw_1757353025
Received: by mail-wm1-f70.google.com with SMTP id 5b1f17b1804b1-45dd66e1971so31503535e9.2
        for <kasan-dev@googlegroups.com>; Mon, 08 Sep 2025 10:37:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVJEZwqz9yhzEURSkgpbCklkSaGwJmuaejSQMmFISaahOJYvUYWLBsnGbs9YbEr/FwCCkeiP4YHVWI=@googlegroups.com
X-Gm-Gg: ASbGncvjAppUdT6YZ/FvHmZEzYhG+z3P9dmB+gpowGUQFzXQSSPP/Bcci0gQJZEf/De
	t7P1bMj520i+DeajA2kCkJCr775DRroyZBaFdMBwuIYbHvHsYVHgjvwDjj+MxVKauqbe1MCZIW7
	MNnn39PajIGR2ppwFv+ADfD+xJdEYxMhzuQdGkBfJp4alobfAviEkdib5297/6AFjiHRzRjzAIQ
	bNAdLMuLwMbknx/NunndlNmlX3vbhbVJilLRQvvF2b5GnLGgA1Ys0tPYT7qARJRoM4E0cTUTbKb
	VL5a9VKLxbbbWDhgdN4thqkxI1x2svM3OFbWUkMTtDFEAm32H6oZddjR1H7PX91wlJ+IgSbvZQc
	qkNvrNF7xuDNU+sCHIQul5n0toKTJ+Qs5EYSwfl/Qk5f6/XKcslBhTtmpOPcdUk/w
X-Received: by 2002:a05:600c:4e93:b0:45d:e0d8:a0aa with SMTP id 5b1f17b1804b1-45de0d8a342mr90484855e9.17.1757353024917;
        Mon, 08 Sep 2025 10:37:04 -0700 (PDT)
X-Received: by 2002:a05:600c:4e93:b0:45d:e0d8:a0aa with SMTP id 5b1f17b1804b1-45de0d8a342mr90484185e9.17.1757353024430;
        Mon, 08 Sep 2025 10:37:04 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f25:700:d846:15f3:6ca0:8029? (p200300d82f250700d84615f36ca08029.dip0.t-ipconnect.de. [2003:d8:2f25:700:d846:15f3:6ca0:8029])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45de16b8b58sm99810995e9.4.2025.09.08.10.37.00
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Sep 2025 10:37:03 -0700 (PDT)
Message-ID: <7b0f5b81-e18c-4629-a715-b5fee722b4aa@redhat.com>
Date: Mon, 8 Sep 2025 19:36:59 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 03/16] mm: add vma_desc_size(), vma_desc_pages() helpers
To: Jason Gunthorpe <jgg@nvidia.com>
Cc: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
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
References: <e71b7763-4a62-4709-9969-8579bdcff595@lucifer.local>
 <20250908133224.GE616306@nvidia.com>
 <090675bd-cb18-4148-967b-52cca452e07b@lucifer.local>
 <20250908142011.GK616306@nvidia.com>
 <764d413a-43a3-4be2-99c4-616cd8cd3998@lucifer.local>
 <20250908151637.GM616306@nvidia.com>
 <8edb13fc-e58d-4480-8c94-c321da0f4d8e@redhat.com>
 <20250908153342.GA789684@nvidia.com>
 <365c1ec2-cda6-4d94-895c-b2a795101857@redhat.com>
 <3229ac90-943f-4574-a9b8-bd4f5fa6cf03@redhat.com>
 <20250908155652.GE789684@nvidia.com>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <20250908155652.GE789684@nvidia.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: G25YlI0yHuvxKQvIDftbMti89C9-IOZlwhIntJDPGxQ_1757353025
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Zau4t3QH;
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

On 08.09.25 17:56, Jason Gunthorpe wrote:
> On Mon, Sep 08, 2025 at 05:50:18PM +0200, David Hildenbrand wrote:
> 
>> So in practice there is indeed not a big difference between a private and
>> cow mapping.
> 
> Right and most drivers just check SHARED.
> 
> But if we are being documentative why they check shared is because the
> driver cannot tolerate COW.
> 
> I think if someone is cargo culting a diver and sees
> 'vma_never_cowable' they will have a better understanding of the
> driver side issues.
> 
> Driver's don't actually care about private vs shared, except this
> indirectly implies something about cow.

I recall some corner cases, but yes, most drivers don't clear MAP_MAYWRITE so
is_cow_mapping() would just rule out what they wanted to rule out (no anon
pages / cow semantics).

FWIW, I recalled some VM_MAYWRITE magic in memfd, but it's really just for
!cow mappings, so the following should likely work:

diff --git a/mm/memfd.c b/mm/memfd.c
index 1de610e9f2ea2..2a3aa26444bbb 100644
--- a/mm/memfd.c
+++ b/mm/memfd.c
@@ -346,14 +346,11 @@ static int check_write_seal(vm_flags_t *vm_flags_ptr)
         vm_flags_t vm_flags = *vm_flags_ptr;
         vm_flags_t mask = vm_flags & (VM_SHARED | VM_WRITE);
  
-       /* If a private mapping then writability is irrelevant. */
-       if (!(mask & VM_SHARED))
+       /* If a CoW mapping then writability is irrelevant. */
+       if (is_cow_mapping(vm_flags))
                 return 0;
  
-       /*
-        * New PROT_WRITE and MAP_SHARED mmaps are not allowed when
-        * write seals are active.
-        */
+       /* New PROT_WRITE mappings are not allowed when write-sealed. */
         if (mask & VM_WRITE)
                 return -EPERM;
  


-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7b0f5b81-e18c-4629-a715-b5fee722b4aa%40redhat.com.
