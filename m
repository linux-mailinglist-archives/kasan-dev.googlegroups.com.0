Return-Path: <kasan-dev+bncBC44327IZILBBDOLYLCQMGQENGCEZ7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E092B3AA58
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 20:53:03 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-772248bb841sf686613b3a.2
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 11:53:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756407182; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ut4EuVN6X7k35UqgaJLRcmAnRyLjnqRPhWLkck438JTtc0lWwmqmFZs2tNJXx+olvf
         e0p5bXnNNWVXLm1LHrcTBo2lWtCx5TJFsgZOpCpwzBICEJ7b8cW3l9LyKujeJGF9ziQ4
         p9PU5XDqzDNTworFV2uWTeXB5f4NF3HpvC90p9dp5nhPIZkvyGgxia+fOoq+NunsSOil
         DErfDaKKwzBToMvWgdo6TF266yB8YCFDvxPxnlN1xzYNlqoifwYTeCjc/Kk8aEvM/09K
         IBM+7ypqXRuAGoqNUdwGBUaYaThj6UhwMCXLiAkH7NgQ8cRPa4h9AftnCXHV4fMkqVKm
         qZ7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:organization
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=n5h/pZ7qDyFYk59Uncz82FadLU85TODAZCDY8aZ3NxI=;
        fh=TxUYiLrwp8drIEy9iciFEAH0zzYxQ9sj3sCY7nPI9V8=;
        b=F51p3DK2vBxCv90h7b3QOff1ND045yJasRgDJOZ4b3eZYbqdoDfnOfPuCRGcglwyaP
         Jy1rpFM0TnSSyxYSh2HCe0k5/th0pSeQ1PEQvlobmJ7dX4IMhcecDZXFAqvInPBTMxsb
         BIpiF2obu45NyLQfZmzZePGkSbQwbG3G+dh4JdA2KA55D/OvyscnIzMuWOv9Yt8Ho+PT
         jNi8vyWgNUkGeO97nBwrd4RQqvy6Q9o4bAqdKElcaeEWRnApy0C+E+Ynuhvb1gPekU2/
         jhyZQg8F3Q3wwOlwVmBPszaURIX4y7KW/Vwrxg7d0Dhb0SQnClzNSx50K7cFGpAlGgOj
         jJ2g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=E5WBwKoG;
       spf=pass (google.com: domain of alex.williamson@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=alex.williamson@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756407182; x=1757011982; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :organization:references:in-reply-to:message-id:subject:cc:to:from
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=n5h/pZ7qDyFYk59Uncz82FadLU85TODAZCDY8aZ3NxI=;
        b=w12rjcgGHKShnBVO0vMYk8VKPpYGWmdyCdQDj92/jlJbN5k7pj3+35RIkRF91uYF9j
         w+vx1edfYSCbGtoQbZeAUXas0VO4ytSQJaeXze4u5YH8EljRiLAGxKLBpqXYymJAlaH3
         h4FPUhtb9u8KpEu1qGV7MW983yrp7ZbMKSg7s3Hz8h/Vz1jRdZTkai1E5gWxZ9rj/qUO
         ORO6uFsdEmD0IDH9Mfg1sGOPn8thzoWeVf3mAeZPruYhIsrkhlJPnCmxVBlDcK4WefxW
         YH6O8HtlE/MNiq+zbLdD8uqdDhsB075RnBj3mFoWIliRJYXRaYwlfa/irsKI4gjAz7M/
         XnQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756407182; x=1757011982;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :organization:references:in-reply-to:message-id:subject:cc:to:from
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=n5h/pZ7qDyFYk59Uncz82FadLU85TODAZCDY8aZ3NxI=;
        b=p50tiTZWJM1Sr50zvEdRRwXOPjT0aWHmfc74dz7GiXXYQOrrz6cst+0tz0NdqS0YuH
         fFgKkn7Eu3fLrhNe7iUQ0bdYnMbHaXPY4P1uX0K3IcSCBN5a+CqO0FSGYYsakUKZR85Q
         jsGFPRVAvzKt8hflsJOxYmrUcj/GlhF05lI6IlTKuMdU+0Gpr8c1WmyoeLLlEsqKhnLP
         /gd9g3dd7Qsfj4VTZ776M8VegitUpnRorN8yvz6h4iAbr5IqI9gaWDdwBJGjl8D7Njh3
         TIT+SJ13LgbZEUPoNWzKLA6Z6etHbzsw4VVR8ROyOSZmknNrbMHp0FX5H97BKfO4qODJ
         GdrA==
X-Forwarded-Encrypted: i=2; AJvYcCXLB1Df8Cg5/QuSxhYwZ3lwlNNxfP5r9yJ8NauAluoG3Y3Ba5WvYZsL2WXudWiUUgU8iYK4eg==@lfdr.de
X-Gm-Message-State: AOJu0YwMfZeptoXP+KHSssdY10d6drWH4iyTdEF9N5zOjOKcR/eptqMs
	yGUhvhYCiZ1de2ugMisB8IW6mcAAFU0yQHN/CANtD4IKbdRRAplrgMdE
X-Google-Smtp-Source: AGHT+IHJCacpMR+5RTM/CjhQ2dCct8lpsYJzfZrbzP9fDXQUr9qIsb1zuel9VbB1BMmp55hArfcu3A==
X-Received: by 2002:a05:6a20:431b:b0:243:78a:82af with SMTP id adf61e73a8af0-24340db3acdmr38720594637.55.1756407181622;
        Thu, 28 Aug 2025 11:53:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcgbwDyHsmFkHrtTn2++WKxt0r+MP/0VS9wLyDRc+YNFg==
Received: by 2002:a05:6a00:1d84:b0:771:f987:3f6b with SMTP id
 d2e1a72fcca58-77217e567a6ls1283801b3a.0.-pod-prod-08-us; Thu, 28 Aug 2025
 11:52:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWFbt8tIx8rH/g1pTj10n86+Vj7i5TG7w/rNwqHffRVsk5/PIiPO+oRcRPwYTE5K4TzsmbzW8cycQk=@googlegroups.com
X-Received: by 2002:a05:6a21:998e:b0:243:7617:7fbb with SMTP id adf61e73a8af0-2437617847bmr23335290637.43.1756407179703;
        Thu, 28 Aug 2025 11:52:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756407179; cv=none;
        d=google.com; s=arc-20240605;
        b=MYWJUbeCfJD/XOxp06HllZeZyjvArCLWwt46ymoMTD+J2XFz/nSSAyNw9zYWjBIUy0
         eXBjnBLYXtaomgFclZ8gUXBQZNS3POJhawRuA56j0Tw/aDm0zJaCyoe1/JLne9yBzWFb
         eiZm9lYaLWuh6EUU1EF6Hbn9nmT2X+YFePvVQ01v8rkCeg5Oq9LrRyfOitJdTTF95xya
         ZWM1M56lbkuzwZj9eAP0MSQDXmlZBYKHyTJ83IK0xxacDsRqbYuWeRUECLsPrw6NyXQA
         iioECShbA8bbecab4/b20XtKu78R53+04G7kPBFVg+hf1QNLK4UemTth1v5eOcfJD0ox
         c23w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:organization:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=Ox+fdqHLvqvHkCQcV7jSITHMPKa6EWT2tpRcTnamaBA=;
        fh=wPnXpJN42j/qcaNonTsVsjRn64qSlmELzbUIoe1VpkQ=;
        b=jQtedoY8zH3fWilOjYJFs72KHOFl38z9gOCe1VCX0Xy5NQNsaXXU2f9pGKhWsWRPP8
         22yPF7J+8hJHqyUDEwwcLRrCm150ckKbraM5oX7B4S4ajlJWMsI43F2cLWmbN9knxoB3
         03/svFLA7CF3kGT+obobiAktVaRtTOq0J5PK5hX467+kxy2+xUZ8oOpY29cz3BuXZxuL
         bpNuNwbHNSOn45D+NMGhrqewHaV0ZsSJmwNcsYpG2A4UDm2/GD6ruIB+MJEvnsNL1TNa
         UyciFrRiKggldY3IylBvbEIZVDdeiKekfKTjNOr7ziHJfQZiGZnGHZkLs7u1msKNrzed
         I6Sw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=E5WBwKoG;
       spf=pass (google.com: domain of alex.williamson@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=alex.williamson@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-327d977ec13si27189a91.2.2025.08.28.11.52.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 11:52:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of alex.williamson@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-il1-f197.google.com (mail-il1-f197.google.com
 [209.85.166.197]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-443-CirQRmN1OqWRPr2F0do4zw-1; Thu, 28 Aug 2025 14:52:57 -0400
X-MC-Unique: CirQRmN1OqWRPr2F0do4zw-1
X-Mimecast-MFC-AGG-ID: CirQRmN1OqWRPr2F0do4zw_1756407176
Received: by mail-il1-f197.google.com with SMTP id e9e14a558f8ab-3e67d83ee31so2007265ab.2
        for <kasan-dev@googlegroups.com>; Thu, 28 Aug 2025 11:52:57 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV3iBW/rzGA4U/XqirZRKD57k35nYXqXsMAA9eYmLguFwBvDqQ+CH95TSF5MsPW35RS3yJEf37r5Bo=@googlegroups.com
X-Gm-Gg: ASbGncu6q4OFvxdppNUNlrQujt+Zemu+DrElx6LekZfhOpjMyIGp1RikeebqjCLLfHS
	gzGJiSlSPLxVLuEbiIbZXEgg2MLBxBm133z/wczUml3QYNC/AnsHBeD7thTEYO2VqC57og5Va0s
	saMOooqiWa6M5iLrfTzVlrEU6TwOj5alumXPDPKNTWu0i0TgRq0IlYhAElpMVOmQ5qpEmzH/wNe
	3cyhhKsJT11cNyoU1cTysXKMe7lIlzRaksTBXxxcojDwKxBvR+888HpFDnef+Oo1oM3nlCuRcPQ
	LxahNdOWct0Ehe5yAdl17j2SEnV8LQewxhWlLH0gl1g=
X-Received: by 2002:a05:6e02:1a86:b0:3ee:cb14:e90f with SMTP id e9e14a558f8ab-3eecb14ea03mr61888725ab.7.1756407176410;
        Thu, 28 Aug 2025 11:52:56 -0700 (PDT)
X-Received: by 2002:a05:6e02:1a86:b0:3ee:cb14:e90f with SMTP id e9e14a558f8ab-3eecb14ea03mr61888495ab.7.1756407175934;
        Thu, 28 Aug 2025 11:52:55 -0700 (PDT)
Received: from redhat.com ([38.15.36.11])
        by smtp.gmail.com with ESMTPSA id 8926c6da1cb9f-50d78c67b4dsm47783173.7.2025.08.28.11.52.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 11:52:54 -0700 (PDT)
Date: Thu, 28 Aug 2025 12:52:51 -0600
From: "'Alex Williamson' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Brett Creeley <brett.creeley@amd.com>,
 Jason Gunthorpe <jgg@ziepe.ca>, Yishai Hadas <yishaih@nvidia.com>, Shameer
 Kolothum <shameerali.kolothum.thodi@huawei.com>, Kevin Tian
 <kevin.tian@intel.com>, Alexander Potapenko <glider@google.com>, Andrew
 Morton <akpm@linux-foundation.org>, Brendan Jackman <jackmanb@google.com>,
 Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>, Dmitry
 Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org,
 intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev,
 io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe
 <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>, John Hubbard
 <jhubbard@nvidia.com>, kasan-dev@googlegroups.com, kvm@vger.kernel.org,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, Linus Torvalds
 <torvalds@linux-foundation.org>, linux-arm-kernel@axis.com,
 linux-arm-kernel@lists.infradead.org, linux-crypto@vger.kernel.org,
 linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-scsi@vger.kernel.org, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Marco Elver <elver@google.com>, Marek Szyprowski
 <m.szyprowski@samsung.com>, Michal Hocko <mhocko@suse.com>, Mike Rapoport
 <rppt@kernel.org>, Muchun Song <muchun.song@linux.dev>,
 netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>, Peter Xu
 <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>, Suren
 Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
 virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
 wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH v1 31/36] vfio/pci: drop nth_page() usage within SG
 entry
Message-ID: <20250828125251.08e4a429.alex.williamson@redhat.com>
In-Reply-To: <20250827220141.262669-32-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
	<20250827220141.262669-32-david@redhat.com>
Organization: Red Hat
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: meCQvqODeGn4UKL0fbcSJ_bNQ4hw9jd-BOlkJh31ndY_1756407176
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: alex.williamson@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=E5WBwKoG;
       spf=pass (google.com: domain of alex.williamson@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=alex.williamson@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Alex Williamson <alex.williamson@redhat.com>
Reply-To: Alex Williamson <alex.williamson@redhat.com>
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

On Thu, 28 Aug 2025 00:01:35 +0200
David Hildenbrand <david@redhat.com> wrote:

> It's no longer required to use nth_page() when iterating pages within a
> single SG entry, so let's drop the nth_page() usage.
> 
> Cc: Brett Creeley <brett.creeley@amd.com>
> Cc: Jason Gunthorpe <jgg@ziepe.ca>
> Cc: Yishai Hadas <yishaih@nvidia.com>
> Cc: Shameer Kolothum <shameerali.kolothum.thodi@huawei.com>
> Cc: Kevin Tian <kevin.tian@intel.com>
> Cc: Alex Williamson <alex.williamson@redhat.com>
> Signed-off-by: David Hildenbrand <david@redhat.com>
> ---
>  drivers/vfio/pci/pds/lm.c         | 3 +--
>  drivers/vfio/pci/virtio/migrate.c | 3 +--
>  2 files changed, 2 insertions(+), 4 deletions(-)
> 
> diff --git a/drivers/vfio/pci/pds/lm.c b/drivers/vfio/pci/pds/lm.c
> index f2673d395236a..4d70c833fa32e 100644
> --- a/drivers/vfio/pci/pds/lm.c
> +++ b/drivers/vfio/pci/pds/lm.c
> @@ -151,8 +151,7 @@ static struct page *pds_vfio_get_file_page(struct pds_vfio_lm_file *lm_file,
>  			lm_file->last_offset_sg = sg;
>  			lm_file->sg_last_entry += i;
>  			lm_file->last_offset = cur_offset;
> -			return nth_page(sg_page(sg),
> -					(offset - cur_offset) / PAGE_SIZE);
> +			return sg_page(sg) + (offset - cur_offset) / PAGE_SIZE;
>  		}
>  		cur_offset += sg->length;
>  	}
> diff --git a/drivers/vfio/pci/virtio/migrate.c b/drivers/vfio/pci/virtio/migrate.c
> index ba92bb4e9af94..7dd0ac866461d 100644
> --- a/drivers/vfio/pci/virtio/migrate.c
> +++ b/drivers/vfio/pci/virtio/migrate.c
> @@ -53,8 +53,7 @@ virtiovf_get_migration_page(struct virtiovf_data_buffer *buf,
>  			buf->last_offset_sg = sg;
>  			buf->sg_last_entry += i;
>  			buf->last_offset = cur_offset;
> -			return nth_page(sg_page(sg),
> -					(offset - cur_offset) / PAGE_SIZE);
> +			return sg_page(sg) + (offset - cur_offset) / PAGE_SIZE;
>  		}
>  		cur_offset += sg->length;
>  	}

Reviewed-by: Alex Williamson <alex.williamson@redhat.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250828125251.08e4a429.alex.williamson%40redhat.com.
