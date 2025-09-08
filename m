Return-Path: <kasan-dev+bncBC32535MUICBBRHU7PCQMGQECONMSOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 80BD3B4940C
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 17:46:13 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-45b99c18484sf19452835e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 08:46:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757346373; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ij1FbO4xnNJjxGljqy4qemHNWd+Nj/e2XKoA3aCcKdTVIeZe9ticpeZBKj1/JzokM3
         zNkS4wyVFHDqFdxcvH8OOssEQV16E1b22djlVzlrACD/J+czPfoJJ24bgnH43DMpUaYX
         YG44oamq47KTfjtJGZx9zCGhyBwYIJOqwORU0ZX9O2dHAlMIiovShSCPMh0doFJ4VR/w
         rX5yb1siyplP6ic6AVr7GZqx66Mq6hBIzuvVbpwXmAHVSAeEp4QVnjOVcrw2wLppYOww
         HljZiC7P7gkw7XDNxh96fgGcxtgF3s/QNJp4Mz+vL7ZTnjCRgvyQrmHzDl99q+/Fq2F5
         kNdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=1TDbv1NGRu2OM0xdx9kFvOqeTbGPgRVHZ3qgxNEzE3w=;
        fh=rKzdK4AhsiKSE/WT1UqgPgJVhDRWgnDK/AEyYUUvmbk=;
        b=khWvrpVkl3FKuZVij2lI+otMZ6cDSsZLyOiPyCZYQCYpmbiXS9hLaSQVOlaVlsZsDz
         8yH9HliRJAzN+L+DX8BJ+cHrCtEBBGWtIVyUJ9bxA38XjmEh4mecgJ8ktIrX3ptpBovz
         7Wp70V6r9xp9T6vfhRz0wyKKIgcPYKHHoeJGRDTKYee67kd0J07Vi3h45G4umTPmP7NT
         qmSNxQZrvoFnkAdGj0Yatx0HvRFMYgITL8LDwdqTSMBX7zUly2rEXIDt8Y/m8SxTlxED
         dkyXr92/4RJ8lnvlQD9x4DvRt9BKizAD27EWRqKd4Y/0cO0AeD5NYSEL7mxW/JqmKZRp
         aXXw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ZrDdYZvt;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757346373; x=1757951173; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=1TDbv1NGRu2OM0xdx9kFvOqeTbGPgRVHZ3qgxNEzE3w=;
        b=PZwqT0AUejSkMexS/08pj4vWUQE+f8WnYWuDeUV0tDZD3qcmOqZeUbQhU9RImQVoep
         hGkg4HK9MPczU44yo1FjcRhRnqKnRic3u6//FZWzkFMQipLFSgDrZhg8hMSs8GVyIr3Q
         XxIoEUV7xSAcO1vT04bXPOwdKkvXdvdjPK77Iye/Lct9fez2kTiXNPxHM1NVv99ux5vp
         3RrgZMCLEo21QlzHqU3LHHREOXwkGwYAKExUCMoqGoJlmttyFodAnSrWnDLVF1tzBLNM
         eag9kzIKonHEGGhTan06fF5PLcl7EdWMgSzXssctHsQKoJrF3qmKm0BxcwpifnrLdfyL
         5oHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757346373; x=1757951173;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=1TDbv1NGRu2OM0xdx9kFvOqeTbGPgRVHZ3qgxNEzE3w=;
        b=HVIDaaCuXYV+fzT7qf6O8IeCI3osauY+NiN2ivmvWZBtBTi3V9N0EsARiFj+MCZ9as
         1/UpI3DY/Zzs3EBvTRpWzoET21sd392T5VeKeXBhuT4vH0KqC83UYT3UL0+CusftQD7a
         aCp7LulIsYa21i1bNGUMXQCX/hbNiSuwhqdMB5XwpnBtoEGi0WcIRFJxiMLEoETCYYKD
         p8/ylappMOAVR8qhMTSBbxeq7UfS/k50PlrxDppDMR9Oz3c62aRWbr82yY5Q72ufepr1
         7PWZYRexlrLG4Bs3OJUrBzon023IUH8c6w+w4dcCktTmDzc+0P7MIScT5uqn7AldorVv
         3erw==
X-Forwarded-Encrypted: i=2; AJvYcCU1yCkDEhvN2p5fVAmOJuMa527Wir9xz3ELiAWjPQp0Lj1G3Ink+CMSutm06M0HWjRIsvCVGw==@lfdr.de
X-Gm-Message-State: AOJu0YxvB7hmW5wRFYQZDwJb7gcIzau+kTRSvohn4IRuadkGLYx3hGVH
	91olewXD1OGJM4r0jj6ZRWj/CFFAQj9qPXRENYONyaH5741XUoSCCEhS
X-Google-Smtp-Source: AGHT+IHJnWSxAQuf3yH/KGi6HjxrJrgINGLFhdH6/mCavBzpfF8soKtVGJjPGVKHDe1uIpWc/eIGEg==
X-Received: by 2002:a05:600c:45ca:b0:456:29da:bb25 with SMTP id 5b1f17b1804b1-45dddee902cmr76774565e9.19.1757346372678;
        Mon, 08 Sep 2025 08:46:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe8NVduvsM6z5ndDjvSMgl5F6TfLxEVAJ/zPeveVYGeVA==
Received: by 2002:a05:600c:1d89:b0:45d:d27e:8ca8 with SMTP id
 5b1f17b1804b1-45dd84046b4ls17305015e9.2.-pod-prod-03-eu; Mon, 08 Sep 2025
 08:46:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXVEUaKepyL4m/QAY8G9pVmy9pq15F9rYxYZZIXHAvYC8HRhb98weDLHBjFvG+vt/fkqXRQK8trr3Y=@googlegroups.com
X-Received: by 2002:a05:600c:34cb:b0:45d:e0cf:41c9 with SMTP id 5b1f17b1804b1-45de0cf447fmr66078155e9.22.1757346369844;
        Mon, 08 Sep 2025 08:46:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757346369; cv=none;
        d=google.com; s=arc-20240605;
        b=EYUocAEHNkeUYsmL12YggPad/HN9Iqy44VwPcGiEXv88jli3x8a6PMX6bloo1Rsifa
         A4QrTPjxTgNXUnqlIJzeXqm6CtkVjWsh3PuD8rhV2nePdaRBg1I/Da1N/khEUfqQYRnz
         1ro60NAd6JjaVrs2C2pL3wsN9ONCwHZ//eA3LXNKl/VXk+GkI++ZWDc+FhHm6Sej3wdE
         YtiILwpV0K0Yd29xKBTgK6Bo0glnq8nzWFN21dDDJ4LDJGgL+savPHQLkh5pNRZRbS/Q
         OlcxM9WtBCFTNef+uHdj4+G/ClfQq+iLwdDIWNuzkFF7QXSemHlPJt0ayeZGP6Qg4ZKw
         4h6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=ZriZC5ZCFi8VYhXaUXVlHuq1MXLstgNz6E2jeOUAEIM=;
        fh=lJ3TLegnaZRzIUmZ4b5I54kB+gV62//98Bq+wOB45gc=;
        b=P3JC8gWeewzg7xXK11aiHF1ahK178CeFH0OlDjdUUEyqceCHfkg/l+ZkB9qcmp8U6u
         2xkudkNREbjksenMM/iUd4I+WztP8hsYaVxKcpu9opRNwiMrvNeqi4AIhhqZRtqaqrRb
         aK9+uLzjUGfuDBtPR7EuzO3hazHhd9ZXB1E35zHiw+dYr0QPCJ44uzb04rSvdv+GV0qb
         NGLNaxWNH3ub4IlelHoOuoGkO8yTfimGEM2azR40eIPxjzUEFi2fDr1Z0u6xcRzw3K1/
         ailejkm5HtNvHrq+O4blVfTr0+kBn1IJ0eQpOKoR82Q64FhcOW5FIb+1nobJccoVJ3cZ
         2LwQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ZrDdYZvt;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45dd058fa6csi3489135e9.1.2025.09.08.08.46.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 08:46:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wr1-f71.google.com (mail-wr1-f71.google.com
 [209.85.221.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-322-dlzhXEJwP8CDq1iYNchEBg-1; Mon, 08 Sep 2025 11:46:06 -0400
X-MC-Unique: dlzhXEJwP8CDq1iYNchEBg-1
X-Mimecast-MFC-AGG-ID: dlzhXEJwP8CDq1iYNchEBg_1757346364
Received: by mail-wr1-f71.google.com with SMTP id ffacd0b85a97d-3e1e7752208so2245742f8f.3
        for <kasan-dev@googlegroups.com>; Mon, 08 Sep 2025 08:46:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW3KDlI6vCACbamJF0RbG8VpBmx154GI2wci5eyedZdvS48PTts8mI5QMAib/tLwE5JWEPAOyIhgrA=@googlegroups.com
X-Gm-Gg: ASbGncsZS2hXxgW6q+mic22ssmc42zUrJGEVtNIyROo1dOtIDQB7DisUyX0fibP4nFG
	LKUe4hKt/fOF9tjrtIG3fEkGjvfQRASi6VB5ADDcPjZ/X7Pgs1henkTrfBR2/z/cWTPOr72evIx
	B48hj28VV8twFiInq21v0/s+d4OGvecU2oq4Sqc6StSvOxQa+GvWWsNsdq2+u0X2xo0rbscZlE4
	JMmXJ88wCRLbLlEgx+/SEL5EpPSTwHq8wPVeaYq5LwGpP1zpsVfcoQn+GsAQoCyvsJuGTPWVDiq
	HVLLt57lUSpHDvuBCaCoED7cfF20oHRNhJb7SovHlJaURiHtEcbQL6zByj54plhtMqmMjWBI8Zz
	Qv4f3yVv93seIP2LrpQ8GBlL9J6XOJujBZnYQ0TX5PekYFY+ycF0jYNU/dpwVl0fU
X-Received: by 2002:a05:6000:2601:b0:3e4:64b0:a776 with SMTP id ffacd0b85a97d-3e64c4a5859mr6039923f8f.52.1757346364015;
        Mon, 08 Sep 2025 08:46:04 -0700 (PDT)
X-Received: by 2002:a05:6000:2601:b0:3e4:64b0:a776 with SMTP id ffacd0b85a97d-3e64c4a5859mr6039843f8f.52.1757346363314;
        Mon, 08 Sep 2025 08:46:03 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f25:700:d846:15f3:6ca0:8029? (p200300d82f250700d84615f36ca08029.dip0.t-ipconnect.de. [2003:d8:2f25:700:d846:15f3:6ca0:8029])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3e21e4c0e6fsm15532578f8f.17.2025.09.08.08.46.00
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Sep 2025 08:46:02 -0700 (PDT)
Message-ID: <365c1ec2-cda6-4d94-895c-b2a795101857@redhat.com>
Date: Mon, 8 Sep 2025 17:46:00 +0200
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
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <d8767cda1afd04133e841a819bcedf1e8dda4436.1757329751.git.lorenzo.stoakes@oracle.com>
 <20250908125101.GX616306@nvidia.com>
 <e71b7763-4a62-4709-9969-8579bdcff595@lucifer.local>
 <20250908133224.GE616306@nvidia.com>
 <090675bd-cb18-4148-967b-52cca452e07b@lucifer.local>
 <20250908142011.GK616306@nvidia.com>
 <764d413a-43a3-4be2-99c4-616cd8cd3998@lucifer.local>
 <20250908151637.GM616306@nvidia.com>
 <8edb13fc-e58d-4480-8c94-c321da0f4d8e@redhat.com>
 <20250908153342.GA789684@nvidia.com>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <20250908153342.GA789684@nvidia.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: C_tvO5ZjK8rZH6IXtyghbueepuPq-A1gENdemkzDjvo_1757346364
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=ZrDdYZvt;
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

On 08.09.25 17:33, Jason Gunthorpe wrote:
> On Mon, Sep 08, 2025 at 05:24:23PM +0200, David Hildenbrand wrote:
>>>
>>>> I think we need to be cautious of scope here :) I don't want to
>>>> accidentally break things this way.
>>>
>>> IMHO it is worth doing when you get into more driver places it is far
>>> more obvious why the VM_SHARED is being checked.
>>>
>>>> OK I think a sensible way forward - How about I add desc_is_cowable() or
>>>> vma_desc_cowable() and only set this if I'm confident it's correct?
>>>
>>> I'm thinking to call it vma_desc_never_cowable() as that is much much
>>> clear what the purpose is.
>>
>> Secretmem wants no private mappings. So we should check exactly that, not
>> whether we might have a cow mapping.
> 
> secretmem is checking shared for a different reason than many other places..

I think many cases just don't want any private mappings.

After all, you need a R/O file (VM_MAYWRITE cleared) mapped MAP_PRIVATE 
to make is_cow_mapping() == false.

And at that point, you just mostly have a R/O MAP_SHARED mapping IIRC.

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/365c1ec2-cda6-4d94-895c-b2a795101857%40redhat.com.
