Return-Path: <kasan-dev+bncBC32535MUICBB4PL7PCQMGQEN7APLBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F868B49335
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 17:27:47 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-720408622e2sf97193146d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 08:27:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757345266; cv=pass;
        d=google.com; s=arc-20240605;
        b=NbcHE74VPSUXHMdthRNLEgUOtqmRqyHo72gd8O45xyFbWTJxDF/OswADnMwoLprDmC
         jziAZlKDl7vNPfBu5KhoHswOa320BXX+dc3lZHSamJetfsr4LzmZIrAh8RpdeandchD5
         xjWsQmAqso2UTUatowZ/6VieQyWUGSi17aw/wA3NBmEfLtrSgvnIBA60AO+i/XblO83L
         sRfksFNW1qz3SuLz2k3ReykmV6C0vFY3hJUTrvd7fzqjOQdFf4m1UZxCGTfCmvSTLTpD
         cdFTTJqjejGCtwzROfsmUdxn7PjF8rUIlDl/h+uIEVjt9VhUOT7YRI1y6fqgiQrJwMEI
         GQtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=CmBhi6vRvSfyT4LErrdUkZjHrRa6Uksd9sMT6+MWxKM=;
        fh=QzDMMqoEe9Zvn2D1Ewd+VkruOviwm5JgzqF8xIzGNxU=;
        b=Me7NTUJimRft8DfWU7Cwks0GVi/ZQ9PE0ASmYpNXFXF2GWedr9yNHyZzwqLy2McYYT
         R+p2kknYtG/88UVPZ4+F7oM6kev9FpmKCcDmcJYoH8kUR0X4B0vMFhHT3PmOZCnsvK2s
         MevN3OfOovYfR5OtcrlunLAPy3vhs7LtctB0mJEUNtEW8PQabjS3dwHQQGJfum0PwYN4
         u8cpstJ1bqCDUpfmo0nH8MawULG8PnleMHtmWSpEfI97N84PsMWLjTnsIY0bIYd3SDnS
         oLHa9xxwB07r5kwmiOkfNdch9X5kVn7F0nyshbsYyf291SpBcPu69D6W14Bj6sK6xyoL
         p+IQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=FZnr2q9D;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757345266; x=1757950066; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=CmBhi6vRvSfyT4LErrdUkZjHrRa6Uksd9sMT6+MWxKM=;
        b=fsXhcLy7UniEJTMLFKcFa+WhVKhTQVbMAFEKsaEM5wlT51XBTh6Daho0FbUUcVl+cM
         ognFXMCyMRtvcsWuOGAXln1UFGq/cG5qagBHrAEZufeVkNZMcI7SbiZLXSc1IDWYDSjV
         1vooU+UJJ2Qbs7bEUJwjqbEAKegWUyadov9n7EI0lnbJdCeCEeBBVz0GbuY6mOdcW+LQ
         jpf8SjnlkQUNA8gej0NRScNiq4I/9UiFz95P73pOBw9E8hczRbCYavV5gSxSFURz//U0
         LWqNOuFpENb56zxRQ9WcMMMOnA7O9eEK4ysLG+ndHDqNLGWEi2XmhoD8GDaO+Ji9wG67
         q/qA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757345266; x=1757950066;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=CmBhi6vRvSfyT4LErrdUkZjHrRa6Uksd9sMT6+MWxKM=;
        b=eOonWZPfGM1G3nEIS79EkGpslXsBJtFrpMaEgEyEV3V1IVzH5VeISg/yHdheaUpMbe
         g05WHkeukvjfVO2KrJNeRAZYhtwSAeZdBZxsfEkMPSXgqw3nzDyO1ltN709AKz8eek//
         GS4NswpBOgjfCo55qSg/kMvpI5K2xrTpIx0ueX1Dkj6FXol93VhBRRWYxWpeDQ5ZB2vl
         So0LINsUNYNIO2L9Y33ITXWaO41xh3+SUT9XNRerByyE0cR3J7hKuF6Aw3Btbyvb8lil
         0bSVcVbgCsacj9f+2HiLhg52egMs6Cj7UreUdbkcm17s78Ax/VGU6aHBqKD5XCSlzfCe
         5lgA==
X-Forwarded-Encrypted: i=2; AJvYcCU50swkVBL8XQFlxLxBsTKNS6RGrzNFLXauxNcRKpUJvVENlZUX/XWKnokrjY//nZX1vrM8Ig==@lfdr.de
X-Gm-Message-State: AOJu0YwJ3eWzSi6fSzoh35o/yqP9C0ebJk2MkPjRxxMf6iOlCfRGXR8f
	fqIyIyA9nV6NbVvMi0OImNu0qUiAIeQN4kQH7oecGHeyKKJmrg13nNw1
X-Google-Smtp-Source: AGHT+IHATPufMiZyAVuSr4/BnOkBpYOBel+TapuGSu4QroUKKUkEGM73UZScPTGgkZ3JzZ6pn4rlGg==
X-Received: by 2002:a05:6214:21a3:b0:72e:fdcd:3ea0 with SMTP id 6a1803df08f44-738fc8db9c9mr80463066d6.0.1757345266039;
        Mon, 08 Sep 2025 08:27:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6qp2zbO2jjUtfNxImaw6z7rCYXSWX/uPcBRJLHONlRQw==
Received: by 2002:a05:6214:dcf:b0:729:c1d:d07d with SMTP id
 6a1803df08f44-72d1a699529ls46477056d6.0.-pod-prod-01-us; Mon, 08 Sep 2025
 08:27:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW25qZYx054aIcCqdtEVaHhKtZP3c7k+m0K637spm7uTg4f+IoOYI6TEP6dtDt8OJmnl6eFtKwE/os=@googlegroups.com
X-Received: by 2002:a05:620a:4113:b0:810:aa1:987e with SMTP id af79cd13be357-813c596fc28mr632948885a.82.1757345264977;
        Mon, 08 Sep 2025 08:27:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757345264; cv=none;
        d=google.com; s=arc-20240605;
        b=JPD/HsqCDc64CBa+DJHFt50CkaFkibH66Qy9zhQAigxePL5Z5baDeBCaJFx4d3w2rS
         OSlmwbTPLkvTeYMmGtCSyubI53i08amsYUbGOEC+xcRce1zjspiKdoNlkkuoRj5lQZ2H
         p5QVCA4Og3eW/vSKlHdPkiGCCTc3g5hCNvNTKy1kz6n1EF6tshfNVPf2NBD+Y9GkFiEj
         8FyPXK519+Ir8NMppRHZULPIIInBI3K5T1uoKMNTmuIu/37JxpLvcYuDCYuw0/8WOba4
         oZF3Rj+toDxnL1aeXnw1TLVls/3V7RF2MgZHcQyNaHGndOWHQq4b1mJUhtu9qgdCzlTB
         IxRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=AcVb4aGGb/PCSNKySt679yYA4SUgcrQuR3+AtlRJhW8=;
        fh=HsMZIatFjlEZatd0YAXZVtgjp46SJyPIAtkT64eLzno=;
        b=RX2Sh6uW5SREOBsCFcqioVzYF+N+QuT24h5rmiWkzj6S8GVo1f6zWQYnwsz70UBXuB
         C/fTUm61qjElEG0RV5FSqPc6Rz/G0VBlyOSCG1lsjucwwVsq1Wx4GCmvTmi4Uzwgt+9U
         tWQGHYIs4LOxU7jTIVcHCmHpADrjiq+U6KTMrRC8UoehFs9zlsfldPy+tSevlqjXF29h
         6pOxq5GFAKMKEieafCqyBQq7V2qQQCevgx7H0uVn9Hlh+LQRYeHSlqDrGF4xl9Ft1PMm
         Cp4OcXStKIyVwu4cSURUd+xtIsdBeLQQbWWJ1GjDFB1AxIurRyKkhGJp6cmq0fvWQqse
         PW5Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=FZnr2q9D;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b48f78b3e5si5601491cf.5.2025.09.08.08.27.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 08:27:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-255-uTrdCG71Pfyzui2r_Bf9HA-1; Mon, 08 Sep 2025 11:27:43 -0400
X-MC-Unique: uTrdCG71Pfyzui2r_Bf9HA-1
X-Mimecast-MFC-AGG-ID: uTrdCG71Pfyzui2r_Bf9HA_1757345262
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-45b467f5173so31872175e9.3
        for <kasan-dev@googlegroups.com>; Mon, 08 Sep 2025 08:27:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWnNQoNtofg3ry4EKev9424WNciEfOnFAc68OtOE7AAnKfSU6EGmiJEGes+dJhtJHV+QiIqVB+5dzo=@googlegroups.com
X-Gm-Gg: ASbGncusE6yb2Kwk3Wto+wXJJow2kIqozYhZgHiJR9nAvmQVrEOQXs8kzwaW53dPajZ
	oNY9lRY+cmgMlYm56unNe6gTBAgrUFstRP0m3ZzaRu6XRA6Kr+ZVHV+PSUPqNndsI3yKMkFecJ+
	/KVJXG+nlM26jSa9W3dOK+AVmynPGaoOz16nOQyQQl9WgurYOdjTmjxT1AQghIlMFtEfqmAaQbM
	YvBq4DV9+76JqVIuDkUzwhdZsr9Pmo9mm44wsU1R5HlbkF7IkLWFdBUEUFcqXntYsUmmU2DUW77
	w6auKTFPbrwY9Gx0F/Cq8j6zyHa7wxd2jLl6u2XgoA7e6Hw1miAPWkXm5+XkOkKzjG830H1ZFsy
	pDDMVpGohMLAszNqfB+dXz4FV3G0vJNgep/4ie1Z0ug1fVtq3ziWrhQ/P6EIwXR95
X-Received: by 2002:a05:600c:1547:b0:459:dde3:1a56 with SMTP id 5b1f17b1804b1-45dddeda169mr71401885e9.28.1757345261607;
        Mon, 08 Sep 2025 08:27:41 -0700 (PDT)
X-Received: by 2002:a05:600c:1547:b0:459:dde3:1a56 with SMTP id 5b1f17b1804b1-45dddeda169mr71401445e9.28.1757345261153;
        Mon, 08 Sep 2025 08:27:41 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f25:700:d846:15f3:6ca0:8029? (p200300d82f250700d84615f36ca08029.dip0.t-ipconnect.de. [2003:d8:2f25:700:d846:15f3:6ca0:8029])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b7e8ab14esm485746255e9.21.2025.09.08.08.27.38
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Sep 2025 08:27:40 -0700 (PDT)
Message-ID: <ad69e837-b5c7-4e2d-a268-c63c9b4095cf@redhat.com>
Date: Mon, 8 Sep 2025 17:27:37 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 06/16] mm: introduce the f_op->mmap_complete, mmap_abort
 hooks
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
 <ea1a5ab9fff7330b69f0b97c123ec95308818c98.1757329751.git.lorenzo.stoakes@oracle.com>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <ea1a5ab9fff7330b69f0b97c123ec95308818c98.1757329751.git.lorenzo.stoakes@oracle.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: HbRBm4tv6ADQexu6nWfz8bhRvPOAVNA1iyhOTW6n7G8_1757345262
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=FZnr2q9D;
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
> We have introduced the f_op->mmap_prepare hook to allow for setting up a
> VMA far earlier in the process of mapping memory, reducing problematic
> error handling paths, but this does not provide what all
> drivers/filesystems need.
> 
> In order to supply this, and to be able to move forward with removing
> f_op->mmap altogether, introduce f_op->mmap_complete.
> 
> This hook is called once the VMA is fully mapped and everything is done,
> however with the mmap write lock and VMA write locks held.
> 
> The hook is then provided with a fully initialised VMA which it can do what
> it needs with, though the mmap and VMA write locks must remain held
> throughout.
> 
> It is not intended that the VMA be modified at this point, attempts to do
> so will end in tears.
> 
> This allows for operations such as pre-population typically via a remap, or
> really anything that requires access to the VMA once initialised.
> 
> In addition, a caller may need to take a lock in mmap_prepare, when it is
> possible to modify the VMA, and release it on mmap_complete. In order to
> handle errors which may arise between the two operations, f_op->mmap_abort
> is provided.
> 
> This hook should be used to drop any lock and clean up anything before the
> VMA mapping operation is aborted. After this point the VMA will not be
> added to any mapping and will not exist.
> 
> We also add a new mmap_context field to the vm_area_desc type which can be
> used to pass information pertinent to any locks which are held or any state
> which is required for mmap_complete, abort to operate correctly.
> 
> We also update the compatibility layer for nested filesystems which
> currently still only specify an f_op->mmap() handler so that it correctly
> invokes f_op->mmap_complete as necessary (note that no error can occur
> between mmap_prepare and mmap_complete so mmap_abort will never be called
> in this case).
> 
> Also update the VMA tests to account for the changes.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> ---
>   include/linux/fs.h               |  4 ++
>   include/linux/mm_types.h         |  5 ++
>   mm/util.c                        | 18 +++++--
>   mm/vma.c                         | 82 ++++++++++++++++++++++++++++++--
>   tools/testing/vma/vma_internal.h | 31 ++++++++++--
>   5 files changed, 129 insertions(+), 11 deletions(-)
> 
> diff --git a/include/linux/fs.h b/include/linux/fs.h
> index 594bd4d0521e..bb432924993a 100644
> --- a/include/linux/fs.h
> +++ b/include/linux/fs.h
> @@ -2195,6 +2195,10 @@ struct file_operations {
>   	int (*uring_cmd_iopoll)(struct io_uring_cmd *, struct io_comp_batch *,
>   				unsigned int poll_flags);
>   	int (*mmap_prepare)(struct vm_area_desc *);
> +	int (*mmap_complete)(struct file *, struct vm_area_struct *,
> +			     const void *context);
> +	void (*mmap_abort)(const struct file *, const void *vm_private_data,
> +			   const void *context);

Do we have a description somewhere what these things do, when they are 
called, and what a driver may be allowed to do with a VMA?

In particular, the mmap_complete() looks like another candidate for 
letting a driver just go crazy on the vma? :)

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ad69e837-b5c7-4e2d-a268-c63c9b4095cf%40redhat.com.
