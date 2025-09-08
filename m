Return-Path: <kasan-dev+bncBC32535MUICBB77H7PCQMGQETQ6E6DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id DF607B492E8
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 17:19:30 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-30cce8fa3b1sf1886646fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 08:19:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757344768; cv=pass;
        d=google.com; s=arc-20240605;
        b=UfyUcRqajXSo7sWj202M5GVFv7VXvcd00N8gVWo58g9vRxWYPUeToz2sA4OnR+Xm28
         zB6DN/xoATnaGTV+LHyJmYuqAEayNRyIqruony+h7yd+gpjYN31QDanA79NSYOAAFrMI
         bsB31aymCsIo+iPW6DoTEueEvox3cV3efRR/SQHLuDoeEctZCf12+TIjoFuRBjE0DkFP
         AHzfeohlP2Fg/S1GpcswtKBvrFU9N45kkx6ZXyXxOJWhJKfEFey4j+EtD7Pffq0DalGw
         mox5NllgKVQoMOljb9omGGObwCf6Ft6jsbdvq6Kef1UyXrJ+/kfix7NcnWpy9Elwid/0
         uc1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=BK+vaCDZ9TGlx9lQ7C/5fag/VsPsvs2O7Y8zBd9Yvr0=;
        fh=9GvaJp8XeGB7ahYXKhsleLVQMeL9Vgi0ssFUuYawRyE=;
        b=RdNxfZSeVmJw+Xpv0BkR6sHO/7qNMnkpwTHOcJ7KkrQ2gsvN9LK+OZIiHDKmbRut/G
         v4Xk8c7gghFkbvYzinB9vqqxmQ5Q4kLImPN4pmxwXaBgIHk0KiTMMAQ3T0qJrhzGHZgw
         OvRyzAGZ2tP+aoq7Rf1lHWi91nBIwEoMd8XDQxHnIJ7M2i0H1Rrkr6wPiEeDpeJbEsYw
         FcsgvRXnvkICNsumyiSXfhaCrDKV+6qpeBoHFV93kqI25QwFmDefUORQjpGsNH9x53wW
         sh9j9bdJyG3nb3bI3/XSXBL2jt52zr/5k/R6xvRgj0bgnH/tRK/DPen9u2ef+HKerywv
         36gg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=INUYLamX;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757344768; x=1757949568; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=BK+vaCDZ9TGlx9lQ7C/5fag/VsPsvs2O7Y8zBd9Yvr0=;
        b=RLIl8oA9/I+FR84sk7MV/V6wJP+wazsl448MrIMegK+GB7H+rranYbpiVC9S8li6u4
         tVrSN+WXasHD6ExdcFIWKZqmoAu+YE9vAyJJQ7BLHPBNucSYm3sIhwNpNBDjJ5+ZyZcB
         NNnzZp9TvOkADxokDT8XW0CNtlEiy9qXSx6ZXuO+1WSzFvGs1WCYZbvQR69COuUSjng0
         DIp7YHzVuBmTvtADt1aTcOHlSgWUx28ABQZlmX0/vUYwluuqcLguO36rTdkvQhT2oCOJ
         FzKMjPx798nVSkHK210uDr5c48Pbsleeslg0d0I1DlDEHmLtnPR4IHr04f290+Qp9yN+
         J9ZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757344768; x=1757949568;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=BK+vaCDZ9TGlx9lQ7C/5fag/VsPsvs2O7Y8zBd9Yvr0=;
        b=Jy2q01TIyVM07EnvAa+PwFn9WyIHDNY+fmZizQURVLVhEJ16XoYWkVPRyghpA9g7wm
         pqOteTrpVfD/pVCVkr74O+ztoe47a212dVeb5pEO9c5zrBTTxdprhSBgK1fa+MQHzjbn
         /eHIcaCY+l5YiV/Sx6MLppgJ7WG1sNbnHKU46T9fbimf+ki95EP8nCSVCUi2t+QUu9Lu
         EtUb5V/H8pua/H2ipJM4tutrtUkaWKUYZOuK9aj/FbBKfshOBTsTK9vRRlLHE4aCnENk
         nPQMh/jrPoX0m+f9IT0uB2xuqG58GOksQAqZIR4TuGFxqcZQaDrTxFAlQeS+PMqJzng1
         4i/g==
X-Forwarded-Encrypted: i=2; AJvYcCUhENdVZengtCWrefPrZyOuyNEyzpg8UEeqUfZsjxp0+z1fTHqJsiO3BUIZWajOCxHe2jx94Q==@lfdr.de
X-Gm-Message-State: AOJu0YxYmPFKSLSzqJZz2NTXRtZ7jWMj/OdkRgCnmWxSFk8iYGYd3LOa
	C+Bz0qxkIpE7jvlG3Ole8i51c+j3gtQ0+yX4kGNwAz0S3G9jAyoQjChA
X-Google-Smtp-Source: AGHT+IHORqfAyF+zYBtLQmbMQIW4PasaSCPp1yfV32mn12z1YYjD7JhsIQMr8q0+GRPxDRM9EH9qBA==
X-Received: by 2002:a05:6870:d188:b0:315:c11e:cfb8 with SMTP id 586e51a60fabf-32262d8eea6mr4417427fac.17.1757344768057;
        Mon, 08 Sep 2025 08:19:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6hROqRhZMBkxInrYk8eQHFt4KMbl3A24IOcydLtU6z+g==
Received: by 2002:a05:6871:81d1:10b0:31d:8b8a:ce6e with SMTP id
 586e51a60fabf-32126bc4120ls877618fac.0.-pod-prod-04-us; Mon, 08 Sep 2025
 08:19:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUjh1edWyAyqleTyd47x/Ya2Qb2g1ZgNHh5XI1J5YiWYbyXjU6GxFQd/1v9tL9FNqY6EjX0yb/ggD4=@googlegroups.com
X-Received: by 2002:a05:6870:14ce:b0:315:bbfa:b712 with SMTP id 586e51a60fabf-32264e26e8bmr3591707fac.40.1757344766758;
        Mon, 08 Sep 2025 08:19:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757344766; cv=none;
        d=google.com; s=arc-20240605;
        b=DW+7PIGKb8eGzMqVYnxWh509XJyKgMj8ZoEZs6/YLJ0Xrp8gagdl9LILpopKQc2jl9
         J/pXukoH8hqDOuOfwJW35uXXKqspvHFG0OyzZUovad42f2aTCz0igHsaH2P84xKSYNo/
         /w0ozqppdJJHKR7OwIRUy+mykqgGj44JaX8J/RaUS3NyWuAHMrwX43kLdXI+WsQVYL/O
         QJrHLKBzKfbFdOv6mD5LAu+mz32z6DTUBndFlb45Pc66lQeRZb1Nfi5/wASVGk34ZtOO
         FWYOSkHGzZihHILJF9ypPb6Crl1wvVhF7HyGlL7UB0tHGZFW+awvkgH7TMnYlZhmK28E
         WY5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=qLko7oepEfn3Ol1TqVFkknNfSGDQeUkDVqazWBqSvlc=;
        fh=dDa+z/9Ka5eH96zqNo9IzEx57TqaKh7evDEYO7Hetcs=;
        b=OanT0vlhNvoCf4R1pK13PdK4e5yPMhNCk9je5Leb0px6ol6deS4gafBZFRRvoYrLUJ
         3ph9Yslg8i49Q6e7tjwFk67BfT7u8sMWmLOPZ+L3k0IXI212OCMa8lLKYqZEOBYRCLNv
         zbWw3n/UVSLJ65CYOecAnxoQ3gEr+ajsPorgegXxHgbH2zj5ZK9GrYrVErs+VhvBKyAk
         Pnt8cIpLNHe9rrqlsGo3w524g5LrO4CbM1bANAKdalauzPGZq4otCQti7cfsgTfJg1uk
         kvJXcubdpPivhIDkiCz0aJSj0LBQOUnYlkcWc/+WYKn1X6kD7DlZaUJH+TZtQdejxhPJ
         Iikg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=INUYLamX;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-31a11ead7a2si774273fac.0.2025.09.08.08.19.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 08:19:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-632-0DQltIMhOk-9XXMZOLGusA-1; Mon, 08 Sep 2025 11:19:23 -0400
X-MC-Unique: 0DQltIMhOk-9XXMZOLGusA-1
X-Mimecast-MFC-AGG-ID: 0DQltIMhOk-9XXMZOLGusA_1757344762
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-45b920e0c25so34929745e9.3
        for <kasan-dev@googlegroups.com>; Mon, 08 Sep 2025 08:19:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVzphwvyXUVIlJeIlUdpJ9VPkfj5m+EiVNYBQi3sKhwoM7tFWrykc4c/ajH3oyE9+NQfxwF5+EvmyU=@googlegroups.com
X-Gm-Gg: ASbGncv6sIFMdUnVyf8AKij/mv+Z2+gIYOSN/hvdexLJ8POK2aoIdAy5DvfdSrWOwkp
	a5KezCXAwY3NGVQiH2AGCo8J54tDEA0Ald08FtVC4Jg8YKkdlUnzMnX6ST44u3STjabfGLYSiuL
	k0ga9tat+6Dy4U6Qx+K3i1vY9WSR/CWx961e3uVwUGhVGSurpkR0Y2J3hn7ChluFkHCQ6L15go/
	vNOuJptb4wmlux0p0XDXkXOrRUIzbKhFPRX3MJMksyXFA/BuNjh6jOv13ngAeUvoQkcRF370+8E
	Y7VL8gr7opALm2zwjzKvw7YsG0zfyLi/OfloMN+aFk6d4mh49BGfDCRxCdgb7zbY0TxI/uMTVU4
	jdxWd2aiZmfZBoeOFm2y2eMZ7LaPs9MXIFygkYhTJGRiEDUK2UX2KlgLQSBL+7vOm
X-Received: by 2002:a05:600c:1ca0:b0:45b:8352:4475 with SMTP id 5b1f17b1804b1-45dddf02148mr79226135e9.36.1757344762209;
        Mon, 08 Sep 2025 08:19:22 -0700 (PDT)
X-Received: by 2002:a05:600c:1ca0:b0:45b:8352:4475 with SMTP id 5b1f17b1804b1-45dddf02148mr79225565e9.36.1757344761709;
        Mon, 08 Sep 2025 08:19:21 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f25:700:d846:15f3:6ca0:8029? (p200300d82f250700d84615f36ca08029.dip0.t-ipconnect.de. [2003:d8:2f25:700:d846:15f3:6ca0:8029])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b9a6ecfafsm298385255e9.21.2025.09.08.08.19.18
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Sep 2025 08:19:20 -0700 (PDT)
Message-ID: <07ea2397-bec1-4420-8ee2-b1ca2d7c30e5@redhat.com>
Date: Mon, 8 Sep 2025 17:19:18 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 05/16] mm/vma: rename mmap internal functions to avoid
 confusion
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
 <626763f17440bd69a70391b2676e5719c4c6e35f.1757329751.git.lorenzo.stoakes@oracle.com>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <626763f17440bd69a70391b2676e5719c4c6e35f.1757329751.git.lorenzo.stoakes@oracle.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: zabVIfMjDsj1I3YJNVAx5EZXHHJJF6pDkU-7qcNtVM4_1757344762
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=INUYLamX;
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

On 08.09.25 13:10, Lorenzo Stoakes wrote:
> Now we have the f_op->mmap_prepare() hook, having a static function called
> __mmap_prepare() that has nothing to do with it is confusing, so rename the
> function.
> 
> Additionally rename __mmap_complete() to __mmap_epilogue(), as we intend to
> provide a f_op->mmap_complete() callback.

Isn't prologue the opposite of epilogue? :)

I guess I would just have done a

__mmap_prepare -> __mmap_setup()

and left the __mmap_complete() as is.


-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/07ea2397-bec1-4420-8ee2-b1ca2d7c30e5%40redhat.com.
