Return-Path: <kasan-dev+bncBC32535MUICBBY7A7PCQMGQEYWSWJ6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id CFA59B4925B
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 17:04:07 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4b5e303fe1csf88196361cf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 08:04:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757343846; cv=pass;
        d=google.com; s=arc-20240605;
        b=YN0xYjPqPFVYO3Bzb2ABE37+8YKhGoJo+EI9d+V+UWDq3y7ZK82Jva9/oU4+SKj5g9
         kQlfcDXd//n9JWM/mbvQC0G1IYKbuVJcL2a1PNlDMm6Q+ctppFTTF6zvR0Il10fB9juj
         pHzzmPqCj04tC8fLVclV+KCL0gSSxB9f8kNVe6p3LSfpFjY+3NZ7LHQoEyXSDocQlOAN
         dk/FmUd7P0GFd5SZ8KG4wDt9SaW1es+RY0k2rFcju1lJkPYKE5eWvVDrU00NgQLpirAk
         sklWmLKeHLmkZL9OAn6xAmntKhwig03iLD8EJm9RYya5bp2/8VWA1cf6wQbTQnTbgs2d
         PXQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=eSA5jssbQRWiOyVXVTzDP6g87mSLxLxIX3eqTTAMvMM=;
        fh=jogqimlUUpk6Aac9TUH2yWwOZglcBvyUkDIgR0B5k20=;
        b=By85WdxX24Z+3QqnAdkRYUHYaGsNYudVNR/iMb5arjegDiCeEKSwT4R5R7xLqQUBkH
         9yDoQHIqh5LhNIi/XAf3AT2V4PpKOocabLAOkNXvmm8aARzy3A6d/J54EgN3Jaq6n4RC
         iJ21RhMG11nY0/rrUvKyDms/Huc2FjYKM1LrHg/J/6AI7KvfnwsjsbSFn5ZczbCeZC2H
         6ZwFETJhSJowzlhN3NuBNt8EGqcWZ0nVggRbB/30itQgVrvGamVS0D/95o5qehW6pEwK
         EP/5dtqLV5/nwOXnrboAi3uQhQt+7vGWJSpC/1N+a1OCWYLzdaaq6CUqmKK47bpo1Wr0
         AcoA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=TT9jDVnx;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757343846; x=1757948646; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=eSA5jssbQRWiOyVXVTzDP6g87mSLxLxIX3eqTTAMvMM=;
        b=lVCBpx4Ctv2NJYh0UihBv8W3Rpk+ohSY5uGn0kGjuRd3cssVPLTMJqRWjwL0xFOtCT
         sXTp3dCkinqQyMW74Mt8i+IaQIKNkNe1R1k/qQgo7f5Yc+kcypjA71EYcmg3Sd/0+h8K
         SPIy7qkDZoEfvwd6EQrKq0rT8HIKo5vIg0C6GZ0tMA6cRIcd2OnR3GQApdJuj4RVbl27
         oSWzw0yN+PqCl9zxCItppzMl2bbju5ujJJcbaGEVWHzRSMYv4YLlkdVTb+Yv5aNrj5fV
         dBWDAFaI5V+Khu3MZVh2LHSh0spzSGYgy+hwXPA73HvYV75oLgVQ8F1YsJb21GFO3P1o
         GRzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757343846; x=1757948646;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=eSA5jssbQRWiOyVXVTzDP6g87mSLxLxIX3eqTTAMvMM=;
        b=egCR0Om5PctaHRHMl0/BBuLxGaW/UXz/BKVn95ir/JTq2fM65mf0M4E0QHCrA6umav
         2ml1yd/XSu8/HeiZYftrIQkxKZKBki7gzuY30W2hhbdns7z+rGDoNYtr+t0DZMhLtz5B
         aVT7J9fEQAuwc/W4dsxWBQqA+G7xeEjwzvHfSUsYvAU2FBftyFGlVeCh2cuU/9Yys4pr
         GegNEFZTBI9sDnGaYSJYN2K6nMQyVBizcH9n2yVHDnK8SvviWARQURz+EIets5C5+QT/
         nmVL/w4MEzx/A+oxbZ9O81tyV+FaHX3Nf0mkEuKGRpid6xs7zfTWj9kiEbeh9HC84gf1
         x0ug==
X-Forwarded-Encrypted: i=2; AJvYcCUlt+WPOMiGEwDf3/dmzyTWQcGwpzwr5AbnSB7zYNzMWBcditAwOtstQEyd67B/v2BLTHL+ww==@lfdr.de
X-Gm-Message-State: AOJu0YxmhL2uvO+gxcbFsHjcqV4eE5oz0nvl08mUC5fDcnCu9t1ijgVw
	T637cgrIFytVJ3Lz8FgAXHWj5M4Aq5caBnsKL6AGB/7owd8C5x1UD75A
X-Google-Smtp-Source: AGHT+IHCjS4JGxhc0Ce5RS7EO8CCTHdic6fTJuwLd0xcBSYn5L5pbFMQh20jyDMRzVaZFPt261kmRg==
X-Received: by 2002:ac8:5850:0:b0:4b3:27e:72d8 with SMTP id d75a77b69052e-4b5f843bc9dmr74615351cf.40.1757343843579;
        Mon, 08 Sep 2025 08:04:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeV+CfAkIbRmJQL+oSfSKCsQH6yffTXPW5Jtk8/7b1mjw==
Received: by 2002:ac8:7f91:0:b0:4b2:deda:ce94 with SMTP id d75a77b69052e-4b5ea98fbfbls62052891cf.2.-pod-prod-02-us;
 Mon, 08 Sep 2025 08:04:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVRpQbV8m1RnOYUPR4fJa2x2ExOfB/4V532z+ZQhYQUc100UbJspeSAhpZXV1wsIoEAGqA2YEv1pig=@googlegroups.com
X-Received: by 2002:a05:622a:4114:b0:4b5:e75a:60e1 with SMTP id d75a77b69052e-4b5f83a8091mr83227891cf.29.1757343841752;
        Mon, 08 Sep 2025 08:04:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757343841; cv=none;
        d=google.com; s=arc-20240605;
        b=CuwZ1bm8o8BC0qjZm3t9ImrNYJX3mXoPPlGE9TrsMKFJkvCsQnbLcteMODANO/oGvi
         sUw6Iy3Zzey8MtSgeEP+Rwh+WavZ/97t8pnRwVOqx9FcUipoec/zE+CAotX6s5eQWdMZ
         qGodswzBNynTZQUN9tCbnt/TuYeZX6JLiBzLfpT7MJIK70wwgXy3S8ku6GVt/zrMpSSE
         Z9dHR053HjGjri2D0i5gCsSebEDDQfbhh5w+c6Lb1intIpN1WRoJY7gXZn30H3STR9JH
         /89hbP5hqq0gss/DAGcXKkFmtNYVDuWRlrz2IXCTIt2Idr5xwpd9HkRWUPgqYNUeREAW
         oUhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=QDJIN7zG3W3mljseXZ/jACk2q/AyQF9T/9Te0n2aogQ=;
        fh=xkQzYumRmPvyEAuRmRY6myZRxnwh0k4anaJ2obtrPDk=;
        b=CddLSdT2piNxjcDYu0LJNdAD1Pm1Fsrx5kOIUNVnxC9ETzmxsGUzLad9xACUknAge8
         qdSvbRNM1Rz1xR76wFCdLqR1goc9cL8DmqfdugTXlSHJ3KPND4sMkFKIhSEMR1jFXr1V
         jmtR7krwoa5PKF6RReiumDA42pPUUUWYBsDkLrkFbkrhEtfextp0UlHw76p+joTOVXiq
         QfWVdiCoebmYrgsi8BdxMuc6vZGwriZKS8lU7nybJMDJs9tC6wfjLcPWnhFoCwvJq7HB
         E9usIVW0EqZP1m8w5AvXHm5tUEiQTE8MpcfrFJZpwH6wzhejRyQF7M/3BhvAll627C5B
         MlkQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=TT9jDVnx;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b5f36f48bcsi348881cf.2.2025.09.08.08.04.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 08:04:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-655-hF8yaV5sOau_0sfcm7PiTw-1; Mon, 08 Sep 2025 11:03:59 -0400
X-MC-Unique: hF8yaV5sOau_0sfcm7PiTw-1
X-Mimecast-MFC-AGG-ID: hF8yaV5sOau_0sfcm7PiTw_1757343838
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-45dde353979so12308595e9.3
        for <kasan-dev@googlegroups.com>; Mon, 08 Sep 2025 08:03:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWHWwVPgdNvhGaz9y1Pp1qEoBa7B/g5chwLqhu8+YoinVXr4tKa7yWul+fS9Yli9p6f70SyaIZObeE=@googlegroups.com
X-Gm-Gg: ASbGncts4yLlY5/TPN+1XIScldJJHoLifRjw9Kp1R8lpc2F1G3T0/vuozh0WUtK/06+
	FqzXRhVFBE6mjqkvUWNmDhB0pPthMmpMDzGUw7blgVGHKl8qXHPEmP9bMrqHNHlVFk30XtYSuGq
	rc0h8w2sRA+9QNM7RSAHeGjYLE73hlA8alRgNH21cR5gaLxdl/o3FQ+tajXlearaeQ6CWbSLkQB
	RsK1c2CyDHhTtmtGHWlgWne1BBPcd3hWbwS7Qo3aqWDrqDfm8UPsRkSKw0aBOgqQ5o1RhAzhENR
	3DbsoDvUQCKGT4ZERppLo1LerxJ11eoMdK/XceqdYvieVto9CrYkJF9OUFyzTeJ3FtcY9tSlfRw
	UpSwQg7cYs7BnlLjgN4BrXctn8fuwqqtTy79rgydzIdwZ1hWFQmuvlcHQTOjgdsF+
X-Received: by 2002:a05:600c:45ca:b0:456:29da:bb25 with SMTP id 5b1f17b1804b1-45dddee902cmr75155805e9.19.1757343837724;
        Mon, 08 Sep 2025 08:03:57 -0700 (PDT)
X-Received: by 2002:a05:600c:45ca:b0:456:29da:bb25 with SMTP id 5b1f17b1804b1-45dddee902cmr75154915e9.19.1757343837183;
        Mon, 08 Sep 2025 08:03:57 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f25:700:d846:15f3:6ca0:8029? (p200300d82f250700d84615f36ca08029.dip0.t-ipconnect.de. [2003:d8:2f25:700:d846:15f3:6ca0:8029])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3e115c4f755sm17147156f8f.39.2025.09.08.08.03.54
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Sep 2025 08:03:56 -0700 (PDT)
Message-ID: <e9f2a694-29b0-4761-ad7a-88c4b24b90b7@redhat.com>
Date: Mon, 8 Sep 2025 17:03:54 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 02/16] device/dax: update devdax to use mmap_prepare
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
 <85681b9c085ee723f6ad228543c300b029d49cbc.1757329751.git.lorenzo.stoakes@oracle.com>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <85681b9c085ee723f6ad228543c300b029d49cbc.1757329751.git.lorenzo.stoakes@oracle.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: Q4MryitRfKfAdeiOTkV9ratzukTC7jdwtx2hXuLIv3k_1757343838
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=TT9jDVnx;
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
> The devdax driver does nothing special in its f_op->mmap hook, so
> straightforwardly update it to use the mmap_prepare hook instead.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> ---
>   drivers/dax/device.c | 32 +++++++++++++++++++++-----------
>   1 file changed, 21 insertions(+), 11 deletions(-)
> 
> diff --git a/drivers/dax/device.c b/drivers/dax/device.c
> index 2bb40a6060af..c2181439f925 100644
> --- a/drivers/dax/device.c
> +++ b/drivers/dax/device.c
> @@ -13,8 +13,9 @@
>   #include "dax-private.h"
>   #include "bus.h"
>   
> -static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
> -		const char *func)
> +static int __check_vma(struct dev_dax *dev_dax, vm_flags_t vm_flags,
> +		       unsigned long start, unsigned long end, struct file *file,
> +		       const char *func)

In general

Acked-by: David Hildenbrand <david@redhat.com>

The only thing that bugs me is __check_vma() that does not check a vma.

Maybe something along the lines of

"check_vma_properties"

Not sure.

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e9f2a694-29b0-4761-ad7a-88c4b24b90b7%40redhat.com.
