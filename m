Return-Path: <kasan-dev+bncBC32535MUICBBC7G7PCQMGQESNDUBNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id D9225B492AE
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 17:15:24 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-726aec6cf9fsf150344876d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 08:15:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757344524; cv=pass;
        d=google.com; s=arc-20240605;
        b=Uoez6FB96srUuu6qTa4yU2DKLADL64Z9uQ/pfvNZdEFGFfIBoJ316oX3F8pqTwqZQe
         GEaXtSr31bquCXS/KEuRFctqThlexUmHxQy0Pz+blm8JDnW4yjWGC+iyotfS6WMZHzbb
         XZFaFTq8kPLiL7CY0md0dxsPs6eJVbRZSMYZw9GpH43PCepnQKhCVNqqAAhK/Kvtt9Be
         mju6W9mDAQd4IUkZWwfSk6Y6YAh/w4leQpRrIQKjfDbI/9JwNGDD6LOfD0xbmlFHdGwz
         r7Kwm05WcRzdm8H1IusNcZBS9rTYAvV2dID4dzSK1Xgkl5LKZ98xv70eYPP4MHM2Nk+D
         iswA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=J7nJqDClLZS8AU0jiQNiuDkN7UxRNYL/qY8/fgbV79Q=;
        fh=TKV5vOuati0yuugWT7iYds9s7WLTwHEnBUyLxSdImu8=;
        b=h0yL1eojnt7iu3vE+Krl9hLUmeb3tYsk+vTffabjMXCjkAf9nv84zsmcylHisD9L2H
         cZ3lyxBJ/+irBRBqJ7vIJ0p47QN7CViBFN0JnFN8anfvEwZ72h+S95v2W1mCPoe/wjOY
         MQDfSGBSaVaa60adtYaJhYKoNJfuZq/JEpKg65yTPKO0xJPVKs3Ai5crxOG099NZ44Ck
         HRPwQk7x2afSXL/AolqhQ7tytf8sifociTSchNroksyhvw+UPACIE/uHx252oLhS9x7U
         3yod4ACQvgz9z6zZHs9wJXVad2VvxYxfw48rQlfW38K5Iq/nnEcvADaB6cFBPktNGANk
         0Bog==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="gq+/EeAT";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757344524; x=1757949324; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=J7nJqDClLZS8AU0jiQNiuDkN7UxRNYL/qY8/fgbV79Q=;
        b=u2QbBsRWZCvTcx3zMglk4PfyQRanUOTJzWIfGb+C20zo2dUIHd7WIUQfW7XnBh4aQf
         wgp6iKJQACKSa/a6ieHmm/AQmONjpcrPRv28usNrcrLDydn2PMaASUBwgNTqnLxywsbk
         7uNd/arkD0I4CDGzOXzRPUpKhDwit5jjNkuyoaW6uwjoAHbRFc6Izw075am7jC08rRK4
         4hHREo/5671QCvXEUIuwVNcAdjvASCfHmgL/CqAVZRW+4wI0Pwbs6MhfZEhKV2Z5Kwr2
         VpEU/2iJyCNxSaIl1HQmpyCs8/3d9BormXqxjTRA9WE2hKtKInUm8vcU4b7X8J3NE25d
         Y0Gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757344524; x=1757949324;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=J7nJqDClLZS8AU0jiQNiuDkN7UxRNYL/qY8/fgbV79Q=;
        b=EXhl5W/6hN+KoEGOq/LpOop0puCD4B+fhEefEcQBHtXGpGZ15mGt8r8S521Rt4f8Y1
         tRC2lPJFN/XQewuGEUoRIev/ZcGj73p5CrC5wgw1I0WwSKb1h0pZWNCf5CiZ5i5OGgFn
         0gBaEPxuIkxDfQPsPj2NiNZvW3R2eEJqcgoQjh3v+L2napEh2CDN5gEi2wDtJZoPx+24
         DlNIdH2aG1fXZ4EUZrd43EkHlILBJVWkQmVT0SziqGeaAqB65bjQipW3ZlslGLfVj7NN
         h2xO5qZUNMo6VeNIijg2V9NqrgUfNXqhUHgLE/vOUKzFDBFeRrKIW13nSVmTZXMMPOAq
         Ap/A==
X-Forwarded-Encrypted: i=2; AJvYcCUP68VNCRe58Xhgi0UTiSe3YA2Q/QQOafdtFDiMPziGv34AmjeT8UFms1OWSirkcvZOkHv6qQ==@lfdr.de
X-Gm-Message-State: AOJu0YzVjvc5q5NOUBFjShypOh4EWz2g/XMXTggTKfXut8E9cnx0Ge3V
	7+gV3x9kFJjuds1QQxJf+qQO+OFEzhcHcfelfNoWHSvTOEHVXVh3pEx+
X-Google-Smtp-Source: AGHT+IEXZplueZEt1MygWJimcsLGEHX/M4aJDn6ozzbJ/ga2tsJ2ZbyZfZXmYsbVluye6XfEhKNuoA==
X-Received: by 2002:a05:622a:1887:b0:4b3:285:91da with SMTP id d75a77b69052e-4b5f847ce45mr85173891cf.68.1757344523438;
        Mon, 08 Sep 2025 08:15:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe6yDjzb/WUCAWVtuzqSn9A8Evuv+M/EKikBrHbps/B0Q==
Received: by 2002:a05:622a:14d:b0:4b3:45a8:eb63 with SMTP id
 d75a77b69052e-4b5eaa08b64ls51598061cf.1.-pod-prod-06-us; Mon, 08 Sep 2025
 08:15:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXO/t7TLUplHD4gq4bHTc7TH1AQkVGvmNDm29Df48nwr/OIy+aihjFVaNnfq5CcEJkEp+dYai3Kt0c=@googlegroups.com
X-Received: by 2002:a05:622a:1819:b0:4b5:f714:da72 with SMTP id d75a77b69052e-4b5f836d56fmr85777481cf.11.1757344521887;
        Mon, 08 Sep 2025 08:15:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757344521; cv=none;
        d=google.com; s=arc-20240605;
        b=ljpLu73+gJ+d29RzbHDqdjrIUzV5ykD/DNyKD/BS+tb/VJvkFUBCZ183YXvSx0PsGV
         rNs6Om1wNLTYM+hNfbNF24Wm+hhZEL7mocMUHZH3UKTjjn1pEYgW5SmUwGC0VwrpUydO
         Z3eoZXnAi9HXQ00U6DlZRPv9NFIL0zlebLyDBkxdpYsjo27Pj7AZpjcfDLfo9MMa23nQ
         PBFtJDEXnfR4GNoS329QYeiGx2yqOYyCpxSJ6XRQRHy9+Kppg/2aFRL8o+cTaP60vw9S
         wRIKux9O5tnaMu/RkvTqguRnSe19ZxKfBEjm1DYfheXjz8lBI8UVKW4whAKqYjFWmXcI
         /ZIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=x/hWHs+Oc+ZmanXHj1zb/uT9WG7h+yFz4TNF11CDu6c=;
        fh=BKdGdcOl2C7w7vJTciURuGSdqmhkPynwkeesxMn6dPs=;
        b=C2r0nXNlco4xVQWFmr0Wo7XU/UW8NywReN20mHlW+n1MM1cVOEKdmtCu/evzTxD4P+
         2aqCC/v1+k5fdJ1pKRKj+OAWuc+8aJcGWcPN3BoQzMt61ydNS3J6hv1umzd7FpBddrjd
         WfkzwpvDjSxvPc7Ets1beo9lOULrU1ggl5WwlservQeeuwK+3ThjUqVcsbD1Fib1y7mC
         j0BcGFoqSTBQ1FOpUBWxLcKDUlXNcyBgK8Q6diPjq3m2/aI6ZHuoGUvCZdppBBGnHZ6t
         dOdYBkKEq/jd9JEbu7mVjeqY9yvd81CMuIMfk2bma4UbHmh6pwD6nlArFA8coUYuQx/f
         t4Ww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="gq+/EeAT";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-80aa0b14b1csi53409985a.0.2025.09.08.08.15.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 08:15:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com
 [209.85.128.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-499-CwmRmnjnPOG3hXfQuAj5Bg-1; Mon, 08 Sep 2025 11:15:18 -0400
X-MC-Unique: CwmRmnjnPOG3hXfQuAj5Bg-1
X-Mimecast-MFC-AGG-ID: CwmRmnjnPOG3hXfQuAj5Bg_1757344517
Received: by mail-wm1-f70.google.com with SMTP id 5b1f17b1804b1-45b920a0c89so18275265e9.2
        for <kasan-dev@googlegroups.com>; Mon, 08 Sep 2025 08:15:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUT/xHJSQukeMtGtXEGrRNKiEwn0HbueDaaRHF+c+kn3odAp+56IyLoRe9Uu6PthpOLOnd+qoesZeE=@googlegroups.com
X-Gm-Gg: ASbGncswlgzRz8yE9OpztyUlEt9GDFqdsom86jWHmhvsuT6swg2zGZByJfcNCWGhLmg
	/Pjsht7aE8/LBuGUuzvNy53qoUnvVePmQYv65OAzkFem5bK0azzjUKdDceTy87zASZdhDTly7zu
	5CcQofof1LjB1k90+SrG+27L1SMTiqH1pvC0PmnruOXr/Id9pn4NLxgWWx/zKkpAuDzSXNx2v6e
	u2KBWVIz/It6LgICdwolmomL7txyiOBjManWuACxFz6zEawZt/AEGsq6kGZThzoeWjb88hbOvNn
	RPmD2IgtHEcbvha116WXJ3rCm68SxnwaX4LW1OdqT3ayTjEXsQvVqTkK0tdord1kEiuhzMTa1KW
	j6oMtXTuWjqKjRcF0KlSQsi1Ns6y5qybfDlDhAT8UawPNzT19HQDcdwVclN+e/a6j
X-Received: by 2002:a05:600c:4692:b0:459:db7b:988e with SMTP id 5b1f17b1804b1-45dddeb907dmr68698545e9.13.1757344516487;
        Mon, 08 Sep 2025 08:15:16 -0700 (PDT)
X-Received: by 2002:a05:600c:4692:b0:459:db7b:988e with SMTP id 5b1f17b1804b1-45dddeb907dmr68697815e9.13.1757344516004;
        Mon, 08 Sep 2025 08:15:16 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f25:700:d846:15f3:6ca0:8029? (p200300d82f250700d84615f36ca08029.dip0.t-ipconnect.de. [2003:d8:2f25:700:d846:15f3:6ca0:8029])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3e23d29bb9esm15808547f8f.4.2025.09.08.08.15.12
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Sep 2025 08:15:15 -0700 (PDT)
Message-ID: <e9b9b4f4-8ed1-40e8-8b49-22a0b10c72e6@redhat.com>
Date: Mon, 8 Sep 2025 17:15:12 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 04/16] relay: update relay to use mmap_prepare
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
 <9cfe531c6d250665dfae940afdb54c9bd2e9ba37.1757329751.git.lorenzo.stoakes@oracle.com>
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
In-Reply-To: <9cfe531c6d250665dfae940afdb54c9bd2e9ba37.1757329751.git.lorenzo.stoakes@oracle.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: ANKZIdl3UXOShrMPRXL8kzs3lOf9VAhpQ78wmxCzIRk_1757344517
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="gq+/EeAT";
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
> It is relatively trivial to update this code to use the f_op->mmap_prepare
> hook in favour of the deprecated f_op->mmap hook, so do so.
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e9b9b4f4-8ed1-40e8-8b49-22a0b10c72e6%40redhat.com.
