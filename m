Return-Path: <kasan-dev+bncBC32535MUICBBL7K7PCQMGQEX4SDNBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 95DB3B49310
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 17:24:33 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-40e59fba0cfsf5318475ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 08:24:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757345072; cv=pass;
        d=google.com; s=arc-20240605;
        b=MbtznKSTmBufkxWaMvAY1ikkUh1Fyp/Tzpa0DFN9ckDjCRCqMdlL4gSe5l2+5wXdge
         4EHNmE6nq997umC/T94bqVYiZahlV+EIQWstlFA+QjVIumE9cy56ZVJLwmWZO1XpAUq/
         BlnfMjgLP+phnK+fufBnKw09gJNIZKTl5KmVL5TJa6NuSmmKsA1H7suLkVXP+Vg+wxkC
         6opKGO5MPiy1ML2R70OaCkFAOBSB7aiLbtYQ2B3rHhics2eoAlohe4m2V10epEYpT0aX
         pOx6FeQYPDVZuzUERTmNszH9VgTqcY/yqqEjN+VgWgGJ0oJEU8CQUPLd8pU3RLOKUPsq
         wkcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=X6iFXM0aZUlHTnMDIB84aqMemw/AuOArSUG9ViDox38=;
        fh=C+dhaCWDrY3SRR+ZmQ0tjqjIjqNlrup8M3d17Dw4mPI=;
        b=DPq0dPPzQKJh9vF8SIOIs7S6JhSUWGurG9R2yKeeYwwtMxW516v9hqsii1swblYip/
         twzxgmfSArcdo+q4PPQhbK+gIZYuGbCG71dM2um+NwsDQoQdSyfEeEKmYeMB1vN6nMsS
         djHHmaSJGwRg0tFH50haDVDO39O3kAeFEW1WYPiSUsy4rE85/45E88gvSLBbrq95C7Dz
         Zz+aJ/0/cEKHJ/+G7cXqmZoReem82lZ/iM0eqL9Emp55ZsynPrcVKq1/4DRHJD69Dvn+
         4a8zNqkUaj/f0OZ/tP/bei+kl2/w5e81zJMImjrGIjC4Oau7cGIRAsIYFxTTxDRyNXJH
         Nn5Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="htBqgRd/";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757345072; x=1757949872; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=X6iFXM0aZUlHTnMDIB84aqMemw/AuOArSUG9ViDox38=;
        b=bPD3QnAfxyKcoPHU3Q1sclPKEkI/D6fuTmyBpRii8WlejZfc8EJKsawTdBR59doiEm
         tnZLZE5tCBiUamMhZg2Uggi9qyZeP1OFJLnOS2+8sz6HeF9mazb+g3wlVEdX60S7hDvv
         hteNHp/xPsSa/PYePNRLlf15lPPrqc9p+S+2eeUyyjiSglY1sPuLx/hV0HHpvLlECQKj
         EvRZ/ZNa79j1u4oeaFF2QkcqUXNEZExaJjhSP08pWFIY6K1OHIE04tVMBTHGQ/ASsU5H
         Nb9H5Tmn+uUmQm12DyyCD3w9eOrYKdt+sr9MrxyoL66PYma0ozSFxhmn4tuvQbPCAk4H
         oGrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757345072; x=1757949872;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=X6iFXM0aZUlHTnMDIB84aqMemw/AuOArSUG9ViDox38=;
        b=qdBfJHGTD4F3fCgE1yCSYa1vK3reP1LfENQsroTyafZ4FaPCn9tMa3sMgzqL+iYW8i
         OQdTsqWVJDH5PWCw5etyZDnbpzQk9qMJqdUq9/gkCG0lychN6gbnwE2eCoczubGRtFT7
         /xmsdy74U819G/4trksQxN49kUQkAwa+e0g/+7lYimtvi//xWRsZ8+j4+UW133MPqkDA
         qiRp022zucVYYGGF/HlBHRoeEwbrys3IwzhLEVWbEUj+At+mgIPixwmmOvFIx8aqCpZQ
         zvYitPNSSop+jwdk6IAcQOV/tmsNl1H2lXfHUJBidk4S13qU+ApCvErhtMhk3RzrVTfZ
         WKKg==
X-Forwarded-Encrypted: i=2; AJvYcCWfLSVmVl8UzanO1joj89O0CulIH/qmjOvpPZf3iq6kLLqpe3Zo0LrnJZnwgxLEp1CmAWph8w==@lfdr.de
X-Gm-Message-State: AOJu0YwRlbjCsDR8Z672LxTZIWveeChzJMizwG1taFGGMx4ohTYvIZpL
	sNlPtMqk4Q/06/yduMgpfJAD/4KPCSw2ScJk54xDZ8wZbXmWJy5volHm
X-Google-Smtp-Source: AGHT+IH43MzDKV1br79q5/fEvWL/cro2tK05QJ4/QjmmF5IOzbAXmS1zn6X9NHxhwV1mODk9JT8mTA==
X-Received: by 2002:a05:6e02:3810:b0:3e5:4e4f:65df with SMTP id e9e14a558f8ab-3fd82163cbfmr122988925ab.9.1757345072336;
        Mon, 08 Sep 2025 08:24:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfCvr8BjlHIkoH46i3d/F7nPZxFiisVKM3WR9sRvBWM4w==
Received: by 2002:a05:6e02:471c:b0:3e8:f926:ab42 with SMTP id
 e9e14a558f8ab-3f8a1bb4a84ls26275385ab.0.-pod-prod-01-us; Mon, 08 Sep 2025
 08:24:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXp6rCHqeUWarTXDck2Sdlm9giVuVlZTcBjMG3SjDaiLAXSktXlMMrPtFZtoRBBa8/3bsdjDBWVkW4=@googlegroups.com
X-Received: by 2002:a05:6e02:148e:b0:408:3b68:3902 with SMTP id e9e14a558f8ab-4083b683adcmr44250795ab.8.1757345070920;
        Mon, 08 Sep 2025 08:24:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757345070; cv=none;
        d=google.com; s=arc-20240605;
        b=RnTpsakh/rjCupUoyRzl9fVT1RGnTclGVrNkqvDQ4n+dzO2tFkVsYmp4Q4GPPapB+8
         3rW1U/6CsXyEaBSH4Kybl5zxSro/77m9JQEmvtuvMjUgnV+tIgcff/vjI2V+W19kjECX
         4X38zpCvESIec9t+rD9ssflXN14ggVHYJzzCwxpwr5juOIi2xLzFQfCIEEgUuS5HiXo3
         BW0UqXWYDTyXi/vAafqKGQe5ugpZatsdxxBiR7Asz+ueEqpzoeRQ792hgq5c0WRks8iE
         83K7+dsxeJKbnh6Toufj3cdXs+LRx9J5PuVSibeTsYfViQXpRIltRmGb9JB6dvBiCzlh
         NTjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=OFR4fsYCPzy26gT9T9kYZtLy/SzbzsJmYYmla+zsN4U=;
        fh=JzGSXV+bAf2quOllR40RgU+0gvIdIO5EtodbKmVSmWQ=;
        b=lusLKdwkz1K+zljYd0Q8KnognQkIg4dRUWyM3x4HCvgxwFnbY5Y31Nfvakp5R/0r5w
         wG5AHmt22K7X2uEhAry4JU0/sAIncH99rouczH4QIEbM4NVxZt02uPRwNZtBBvlN9JfV
         Ucwz3XxZbJpHzsnyvyILNPsFmfW5Ueck40WhR19if/hjGxB5hyw6ss/qcOkKvhuZBrfz
         2CbFuQOvHecEC2PNaaieN02GdLqRjD8UA/vtmAxQEEUyLK5AALp2FLQm6XzMs+I9mi0r
         EQsCmR6bXXV9rtNxBRpfBaeEDiW1wFjLzMbe+EB9pHIL7lzwGYeX0uESJlE1ifRwYJl/
         0/GQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="htBqgRd/";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50d8ec80f62si777441173.0.2025.09.08.08.24.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 08:24:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wr1-f72.google.com (mail-wr1-f72.google.com
 [209.85.221.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-542-HJ0gGVCDNgefemkzy9-WBw-1; Mon, 08 Sep 2025 11:24:29 -0400
X-MC-Unique: HJ0gGVCDNgefemkzy9-WBw-1
X-Mimecast-MFC-AGG-ID: HJ0gGVCDNgefemkzy9-WBw_1757345068
Received: by mail-wr1-f72.google.com with SMTP id ffacd0b85a97d-3df19a545c2so3477277f8f.3
        for <kasan-dev@googlegroups.com>; Mon, 08 Sep 2025 08:24:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVrJ9/nX1dkuu1RhSZH8Fzh4dvgFcjTMIAG+wJZs7dQIAcwQcm0+N6Ir77k8MmXmoaUJjVgjVHwX3g=@googlegroups.com
X-Gm-Gg: ASbGnctxh+tKbuscSGTBhU7dDStEPEQo0MFtb9Q+LqapSHp/Lqeam8n+I8Up6rBVxvT
	zndNkusoUqqBOueBQ+25RIx+4fzhJvFdJtUUUFH1MyFBuTzwfsWaJkjVkcwd3BhahXhxQcRte90
	n2cHdm1ITyMvfakxMtP2X8YV1xWZJtRCs/ljfgW7doKIfMelnMXlbwJjrsafcaA+u6GakJd+We0
	Qet8ehD38/2vJS6OzxHlmXmguJKry3pfoD7gaWlUUkj3bsV/gpZjXpt6QTWWccSkX8QbHjCkna0
	gbguhcDhQTx11TFS4HKyA5jHwIPP+u0ii9yqCM9kpDHHlz7yjlqrItki6igHBpw8aU/Gs99V+68
	BJQIaqbpRnGiMKuZ+uF54ZxgLYY8xR05rWomZrkW52FlGLK2/f1x4GRtf7U37LxiU
X-Received: by 2002:a05:6000:2087:b0:3de:c5b3:dda3 with SMTP id ffacd0b85a97d-3e645c9d0fbmr7224240f8f.44.1757345067791;
        Mon, 08 Sep 2025 08:24:27 -0700 (PDT)
X-Received: by 2002:a05:6000:2087:b0:3de:c5b3:dda3 with SMTP id ffacd0b85a97d-3e645c9d0fbmr7224167f8f.44.1757345067184;
        Mon, 08 Sep 2025 08:24:27 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f25:700:d846:15f3:6ca0:8029? (p200300d82f250700d84615f36ca08029.dip0.t-ipconnect.de. [2003:d8:2f25:700:d846:15f3:6ca0:8029])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3cf33add504sm41539994f8f.30.2025.09.08.08.24.24
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Sep 2025 08:24:26 -0700 (PDT)
Message-ID: <8edb13fc-e58d-4480-8c94-c321da0f4d8e@redhat.com>
Date: Mon, 8 Sep 2025 17:24:23 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 03/16] mm: add vma_desc_size(), vma_desc_pages() helpers
To: Jason Gunthorpe <jgg@nvidia.com>,
 Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>,
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
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <20250908151637.GM616306@nvidia.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: mOZ7Qydt_mE9M0_-QsiRPGVcnsWlRIFs-WjOAylrH3U_1757345068
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="htBqgRd/";
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

> 
>> I think we need to be cautious of scope here :) I don't want to
>> accidentally break things this way.
> 
> IMHO it is worth doing when you get into more driver places it is far
> more obvious why the VM_SHARED is being checked.
> 
>> OK I think a sensible way forward - How about I add desc_is_cowable() or
>> vma_desc_cowable() and only set this if I'm confident it's correct?
> 
> I'm thinking to call it vma_desc_never_cowable() as that is much much
> clear what the purpose is.

Secretmem wants no private mappings. So we should check exactly that, 
not whether we might have a cow mapping.

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8edb13fc-e58d-4480-8c94-c321da0f4d8e%40redhat.com.
