Return-Path: <kasan-dev+bncBC32535MUICBBCF6SHDAMGQEOVCDXDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 614F9B555BB
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 19:57:31 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-775f709b3cesf3847962b3a.1
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 10:57:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757699849; cv=pass;
        d=google.com; s=arc-20240605;
        b=cgUOCQmQ5wv9r+QXShMs+hdPddLYOhIkE4JLDYpMnQzhp3S6LbejYTunb77qIOqZ/h
         d/vN9FgN06Zy0N3UJ/lyqr+t0+ls1Dd583/laKZDlL5DcxgBBqirfeyphlfmgtn7PduZ
         Oz7BwHC84jxgbX4APRq/0AahUfDD6CVXA3GpWP6d1P8fP5AQnaVu9iGXkIwWEBEWyhss
         31S39xinEXNL5JAFFt9kCEOmtk/oGLOOdwQ6XTiT9v5fXC5MAlnfebgVAUbEr5klhRRc
         m8olEHHa6SUjovDSJwRr9se5qyZjDI/wmbUbcs9RFP1mMgG5g9kfXRSDeeT0DwCDDAhM
         xHlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=NC233SL8v4rP+2nnKP0Z1tpSAv6xLqrFUw2wbYyC03Y=;
        fh=hFySjrqZCeJ69Do74mHdLEz6icbZ+uNSvBJsLRs/Aig=;
        b=kbNXPRSOrxsZz4uvM1UjR5EJQUrm6/X+Pb3sUv+TYSnxgQjFlFNFalyehN0zUPmrRr
         kXXwfwaRtaHMlOIXgTTMj218WXBGtOrS5TBo2/9eWSkr2JqJF0koMQDn7GqpViajguGt
         5u14Wcv0KUe1Vz0tvbP/byompOgZ7pmBhVC5dGSxTbDBdiCPeke4TT3mNncMQwZ1Lq2G
         gnT12xQc4gyyYzkzPLlaw9opfuPJb32H1aMG0d5iyL856HWZiWBJBBtKbJJVOd5zDxsx
         DYABLuRmUF5rvPzGjCIej3CHT/0ZnbzCkWM65JAjFqzyFgGFwtE3ipmzv+gy0uFk2Pxh
         gMNQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=GSeYHRFo;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757699849; x=1758304649; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=NC233SL8v4rP+2nnKP0Z1tpSAv6xLqrFUw2wbYyC03Y=;
        b=w8KXL5qB95v5wL4b64BRUn/B0CGTZgCCVg7crUhah1tNwtOjIv9L9Yh06WWkfFe4pr
         ZKFefE5zHRyq8BNyuN3VciJoJRTTPY9VWq+yVj+BaGk+5IgEmXVeYo3ILRHZZGsCszhJ
         vFPcOWaDwpsYlr6hFKvItXUgQL5xjfPwTnI7+bVZxGOAO404ymYN22vM6z2bH1vA/+BD
         x8GUXbBruWEREGMCdiju6NUR1g9b6cawUITmQkl2miDheuz5Kh1XhVcYTlLQY/WAiEfo
         NLTtsoylykPY+fXXnXmFMDAM6nw/prLT9aZy0GWguqELhGod1e7lCR0/SgeDL5cZgowU
         OxEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757699849; x=1758304649;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=NC233SL8v4rP+2nnKP0Z1tpSAv6xLqrFUw2wbYyC03Y=;
        b=MhbGCDrGc17+iM8aOJqRwMqnHuE0f4UpwXfVuN9K7E6K0ulATMKLSk6Fw0/qomu79U
         iJHqvp6XODIHtcZbbXfItj5+CcqqNrmMYLE/9FUiRxW7oRwX3h1IHbDCbfyqrRH7/KMv
         5Xgc3DtlNoxNtaKPK05q0bQ1MqhjdnT4n7Jh8prWpfo4YS4VbVdNJU/jLrHtFmRNRh7V
         7cMrRtyMNta8oAAF5judNhs7dfU7SoE6FcKkx6DlWUwiLFgzctGtIvQwNKL7TC+PfsCB
         aBYDIjt3lL6nEQfgLS6CGKo3XLfN+8Jl7g6Vlae6qpQuqwUxUhfnqcGdJirnPss6j3l+
         XJPQ==
X-Forwarded-Encrypted: i=2; AJvYcCVSRlscQJ9+DlWHq8+PddfQx3Lg9/ahE97/lAOizfnwwbHZDRhhHpz5JZkNorqefwNH9ivgpQ==@lfdr.de
X-Gm-Message-State: AOJu0YypP7r9GIVWfWEH/B9q02eRbf+MJKV2Q7zJ+qV6qy6Nv41uurdB
	FZruJBKqGWTJmnjYBboKFUGZ/JcfW6dUx4LY7D/Dntmt4Zf9Ie3igCyf
X-Google-Smtp-Source: AGHT+IFvwDe4o4BDGjQmr2QlFgUY9alPa9JUshxX7a6/0j/21pgpFQ/DnFU3dUv2OGzkwM9AQYU8NQ==
X-Received: by 2002:a05:6a00:2345:b0:776:20c2:d58b with SMTP id d2e1a72fcca58-77620c2d91amr572776b3a.24.1757699849478;
        Fri, 12 Sep 2025 10:57:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe9e/iiJG6AdH6bpiYUyvg/NTY+gSur0BgGH3KFT4z50A==
Received: by 2002:a05:6a00:1d12:b0:770:532e:5fc6 with SMTP id
 d2e1a72fcca58-77604e27621ls2079607b3a.0.-pod-prod-06-us; Fri, 12 Sep 2025
 10:57:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVKLbA7Qd8lBgvrI2Ls+hXNVG6RRJDcvRvdLCkfGradVXyHQB0w07IzVtIkj+pvimTSdUJGH9rGpEc=@googlegroups.com
X-Received: by 2002:a05:6a00:4219:b0:776:14f1:492c with SMTP id d2e1a72fcca58-77614f14a69mr3121335b3a.12.1757699847891;
        Fri, 12 Sep 2025 10:57:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757699847; cv=none;
        d=google.com; s=arc-20240605;
        b=eK1v28JEvTMnC/3s7fEc8xe9bKfVXg514BQJmrBk+cyDRMbHLT7kjIibbH6BZrjTUR
         qC0WiE84bIBsemYZVfxCFGeVAdLOOQcILEtNy2f6MiklI5bveQFKyTXr2AGenUlfQ1NC
         WEMnpVC+hEXNZvrKUgtE2N63zLrgvwHefKQ5ZrkDz3F91t0TXnLDmk6Na8kWSuoecc8C
         iky0Uy1AA1rSiwTPCk7+pavflCCszujIPug79GjuEakN33ril/7ujQ3WJxlI43xcK39G
         TnYZFqboqElRSvD+lCgZY18OM2P4qqMY8AewupNlo+RDrBUKSl7FoO6xl51vPlfsh438
         i5+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=vWibyIDQ5IpFu2wsAavMRvUdSscXCQdcm/6IEQcQG6k=;
        fh=gDnYdPeZw+A/0nyJpnyYKgLsTWOU7/QA5vl3qcoZyy8=;
        b=aOtIvqHejfPsLqENQBUT53A/3q1AYya9FUQhBoXsfA9UIeZDeaMQK266Ti11rpPywh
         mwVc6rhFlv4kAg//WS9JngulbMxhSx2Qy0nH0N58Mbb9bfjWPsJkAIcjXtqwyM014Nzv
         BjHd3sF6MXMcWao2CiWDa2lUPmNJhmz8dSpg7xJ+DTjDG4vAQNqvyC08xVIh/f0Nb2AM
         Fm4nwpmqP72Gpe2l5rK75HvmkAYrTGSLse8TYYqD1ts4ua6a0M6gO6WdWnC4+7JeJhga
         Z2D78iurF9guJixzaVJVuF/eydIshfOo3DRdPgM+62NoOFbPfY5QTU9GXu3D+3YNKd7d
         O1fQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=GSeYHRFo;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-77607b487f2si218718b3a.5.2025.09.12.10.57.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 10:57:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f69.google.com (mail-wr1-f69.google.com
 [209.85.221.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-575-si4HBFL2MEipfz3FTcbMiQ-1; Fri, 12 Sep 2025 13:57:25 -0400
X-MC-Unique: si4HBFL2MEipfz3FTcbMiQ-1
X-Mimecast-MFC-AGG-ID: si4HBFL2MEipfz3FTcbMiQ_1757699844
Received: by mail-wr1-f69.google.com with SMTP id ffacd0b85a97d-3e2055ce94bso1647455f8f.2
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 10:57:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVZuQk/ZBMQXaz5Yty30B+HeZMB1vT2Zx5SJrADBlRWszRlPa7DEB7V/99NPw44lDQwBdkSifvfMtU=@googlegroups.com
X-Gm-Gg: ASbGncv16hbLrALzqR4SksvWJOymOCnh57JNJI2VLzJVW1gGEDqMx2se272k5vB8Pc4
	e/zetZXcvs3g1sYbt5Y2otJkfwufPn/9Bu35u0wiMmgApRS/RzEn3IWPTQVIEUcm8m8/Sj+HtDG
	fX3qUOYccYJG9SgIM4cpROVQMNPTH2865h/Q7+r2UtNk9HL7wrZJdnFAzYIEYyQ+aXUb9WP2+Fo
	Vx/cvJIblSqd1+Ji07E6x1K+G0y23E8pTuQW6KK5+PT33CT4aUhdjmznQuaVrRhlt7JMCH0lhj8
	JEpzz/yT4tMqOG2JIYbcHd5RRUThwcFYt86WKtBFhXHL84AHx2kS+P4hoHRuUanH9OBEyd3S6XO
	UzQLCU6Bjym5L3SZP5pteZWcyvw9E6r1zZaO6TUFAYRFMdcL+1JGK6/i0d9wV8J9wVqQ=
X-Received: by 2002:a05:6000:26c6:b0:3dc:3b91:6231 with SMTP id ffacd0b85a97d-3e7658bcb7cmr3820058f8f.12.1757699844116;
        Fri, 12 Sep 2025 10:57:24 -0700 (PDT)
X-Received: by 2002:a05:6000:26c6:b0:3dc:3b91:6231 with SMTP id ffacd0b85a97d-3e7658bcb7cmr3819999f8f.12.1757699843578;
        Fri, 12 Sep 2025 10:57:23 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f20:da00:b70a:d502:3b51:1f2d? (p200300d82f20da00b70ad5023b511f2d.dip0.t-ipconnect.de. [2003:d8:2f20:da00:b70a:d502:3b51:1f2d])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3e7607d7bb1sm7362076f8f.50.2025.09.12.10.57.20
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 10:57:23 -0700 (PDT)
Message-ID: <97117b3a-1d92-418d-a01e-539c77872ff2@redhat.com>
Date: Fri, 12 Sep 2025 19:57:20 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 05/16] mm/vma: rename __mmap_prepare() function to
 avoid confusion
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
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <9c9f9f9eaa7ae48cc585e4789117747d90f15c74.1757534913.git.lorenzo.stoakes@oracle.com>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <9c9f9f9eaa7ae48cc585e4789117747d90f15c74.1757534913.git.lorenzo.stoakes@oracle.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: lTFl6eJMBg-QJRXdcDWmb5NdPY5054jW-_Suyq4qlI4_1757699844
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=GSeYHRFo;
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

On 10.09.25 22:22, Lorenzo Stoakes wrote:
> Now we have the f_op->mmap_prepare() hook, having a static function called
> __mmap_prepare() that has nothing to do with it is confusing, so rename the
> function to __mmap_setup().
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/97117b3a-1d92-418d-a01e-539c77872ff2%40redhat.com.
