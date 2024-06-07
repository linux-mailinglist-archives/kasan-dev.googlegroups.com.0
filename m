Return-Path: <kasan-dev+bncBC32535MUICBBYU4ROZQMGQE2RUDLOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 4BB958FFEDD
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Jun 2024 11:09:56 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-37588e93375sf29385ab.1
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Jun 2024 02:09:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717751395; cv=pass;
        d=google.com; s=arc-20160816;
        b=P4MrzWcQJfcIfej7CDT3aoA9pxNkSbeBQo7OPsHHG1A5gxKXBH1FN7PNNf0Wzpw/yc
         CBJ23JbQPnB9sVMSCijjM4HWaRypx+TZ69Y6PxwyqNYzoGWdGPNcbOixXJZK7TrDobR9
         ptfK6Ph1u/wwtFZS97QGb1wFMdqjBzv1u1y8gHuhRSr3YJBX1lX9TKayAasEJ8Au/blA
         SCpJb9aZPwhaT6qwU5Pr56mIP4xGUb4RNMFCQJEy8qSYy56BrU9I/+Feb+uIMl+CTsP3
         eTr8bR/Uzt8ui1UAf0svN1ZcrKPHOlmey4wevS31TsKuE8IHRoi4xcnpkCu8WnfEbjKA
         jSUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=hjCP3yKeuGJuTrsbiAx16R6UHuI2YN68rZvCRnltHP0=;
        fh=eQjow8/WzmlM3sQjm2DOl3EO9eutAvy+SKZjitDNkGg=;
        b=fRMnEtDz8DB8nd1tb0KwX0k+FhT0YHx1CFZZn5aJcbDW8aea5qJXb8z1uVqvUYXnBX
         +hhjjbpuwx7N5k8A7wySkT/xCS2oCu9zdOQ6lwQ0RsVd1Y7nPo96veics+rj1/KjSCuW
         QQyjkORTroPxr8zhVK76Vg+5eMSh3tnqyZ9sle88uPHGnkIX8eW+DOEWl6R3qVi/lRhl
         2hFcv0SHnPpRntZYDfBXzjN5N/JqJxXzkgkyWBapvRCiK/r2T/hUpWST3x/J/ta9lKsN
         xNOl4hwoJupDqGSnKv/V5zBAh5W0TsbSkBqJz2Fp1CUnXDdOixlz79Kj+6dRH6TqvK16
         157g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=apjgsSaV;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717751395; x=1718356195; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hjCP3yKeuGJuTrsbiAx16R6UHuI2YN68rZvCRnltHP0=;
        b=f1CwQn/+GF53AnWrLRpvClKb7dirLEiy+Ko6mySmpyvGFo338qs5bNdD/ysYeg/29P
         sJMwQqzazD9+rL4f/yLYeiyNnnf8B2q6Yk/n1AbBixYBBNGPH+Nb+YlrUh3YpBt73+oi
         SMnGxHobFLFqzoKYHBeVjQcDo7mEO4MTmHGR5VlpuXa7MtY7ulQyK5MI+MqX8BVySKgP
         jAO1/xXCLpSqZB9q3syUzcqZqSCRz1rGCARqGK+dPr+h8+EruW1GkELa15kXgS5hmbWe
         Ol4i+MGt7jmTw6/vE2b9qdamhKyiz8bCvXOfiGmkA4cqGCJ4zL0VhTZN4jkTsUCFi1yn
         kmSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717751395; x=1718356195;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=hjCP3yKeuGJuTrsbiAx16R6UHuI2YN68rZvCRnltHP0=;
        b=eADMGFviCPZsbuHK5jSQMnWjQlsTb5K3k4rl/Sek8FTEkebYTgYp0wgqfnkDQREdsY
         HElrkBbNc9TLIiUzPdaXcljqf28AOIXsQ4qq1gaWN7HGxJqcSUZBRpSLydC0scGIcmPa
         WKE8cTHzdlTnIPWghU99cpggl1ESvVkjizkzgLtY9oTQdmfwAA9UGAkUXFXTsWAyp6rL
         7CDlWC52HKRMe0zHFyYIFY+IeOGGeqZumsBOzE1/3NI4AetlkLb6pEfwaTMQHNld0ETh
         6wCJ/XtgFK4rMhDbrv2v8DOaBUb7zgZOYdGYBfcwJKtN7TJWY61r9I22Bz2Vpi8j+1wY
         SDog==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUMBQyOK5YlHUnwDGAsVI3uhSa4g76qUs1uUaEgYHFZUw9gY7cE9Ssu8tplmKIV5Gy6VIEzOpeIGf/MeJU+BXQEd2TPhDpouA==
X-Gm-Message-State: AOJu0YyolB19lgZjIT1OUWDgY7c3/aByLVc00MNx9o2ooEGdCzFdaLRR
	dBiEx0tK5071k5qwEhYZRhbonDIRn9aONXcsCTCRjDmpSXMWbUfu
X-Google-Smtp-Source: AGHT+IECKBC3zhvNUYwUe0uztERNMTy0B9pCmtRHXlK7TCdneX2dpBJgM8Gd/z2gxw0frPKbWRSrzA==
X-Received: by 2002:a05:6e02:221e:b0:374:8a54:7622 with SMTP id e9e14a558f8ab-374bc0837c9mr6688685ab.19.1717751394864;
        Fri, 07 Jun 2024 02:09:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3886:b0:374:a665:e097 with SMTP id
 e9e14a558f8ab-375150f6ecdls7927055ab.0.-pod-prod-01-us; Fri, 07 Jun 2024
 02:09:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWG3+F8UkBnFCdTsUJ/DoNzCPQCnlvPgBCu/kj/POeJ0CjpTP4TvqUdfrkWRA42jERZ4rZgyBjcBYEI0IM0hcK4vrd+A/jnxL+KHA==
X-Received: by 2002:a05:6e02:1a69:b0:374:b1d5:ed67 with SMTP id e9e14a558f8ab-375803ac234mr23457165ab.24.1717751393912;
        Fri, 07 Jun 2024 02:09:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717751393; cv=none;
        d=google.com; s=arc-20160816;
        b=V2M2T4tjgprtkxR9gaRj2qpRjjg5Qk99cMHfPReHzAQ9ZhFcLR6yEeLYjf/oUut4cW
         S+Y8KhDpEoqlpl0OXUvQOK86N7LUuavuZSuzfTUi2vZ9Hj4ID92G+g0EeVtLN22HqIsj
         A+nfrI9+9pgltJ7oAnSo4EZqtF55KW4XjDf1IbaJJllv9cQvKu9yHn0+V4erodw0NdZD
         axsH9WIGESQelzugC2w+DeVbj2GeqmavcGQ9cxSOY5NO1eQD/WoP8uTaasat9kP272MJ
         b6WZUqnMCvI9Jfn+rHRO2AOJdp949t/aKoeo/hNESrHuZArpvWkU+4ZVXGRYHdj6h8un
         VEFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=QzQrIOtS4DHvHPJ4+HHeRZGer7eituw1+x4QYHDabqc=;
        fh=8obm1S+EgOJGM37d32V0lIxEEqS6t/kRT3OFvw5SNhc=;
        b=ZpnA9dW3+m2P1rSVvK5iyI4kEYDU8X3vnrTO8waUbsEdy2CcC217N+w29OWSArbvRp
         7d4Ur/Ll9Q52LLFug9WptJTK2Rsg3mgbCGq1xeNdTLGtpxRC3lQOv8N8WUvaR4K4kvV2
         wv0nQzEfciuceiP72cMRsG6UePUgC4uxIIE4h6O4B9RxWA45Y43Z4Df9ksdK1efMpPKO
         GyvLzqyVs+Kn7AE9tBe1A56B9o1PZ5zpA2/x2RrumPPY4hv3vlrdkSPqX5cjSrgz5QGk
         jT0X1hapYqpdYfrb2+p99yREE4aalUIOJDGFQ/UlQNcItu+jJr838DF9YYBUKxfWF6bF
         Yu3Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=apjgsSaV;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-374bc09ee5fsi1545605ab.0.2024.06.07.02.09.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Jun 2024 02:09:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mimecast-mx02.redhat.com (mimecast-mx02.redhat.com
 [66.187.233.88]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-629-FnEQzJIXPkGraVrUGETiZw-1; Fri, 07 Jun 2024 05:09:47 -0400
X-MC-Unique: FnEQzJIXPkGraVrUGETiZw-1
Received: from smtp.corp.redhat.com (int-mx01.intmail.prod.int.rdu2.redhat.com [10.11.54.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id F2F3680B5C7;
	Fri,  7 Jun 2024 09:09:45 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.39.194.94])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 6D69F37E5;
	Fri,  7 Jun 2024 09:09:40 +0000 (UTC)
From: David Hildenbrand <david@redhat.com>
To: linux-kernel@vger.kernel.org
Cc: linux-mm@kvack.org,
	linux-hyperv@vger.kernel.org,
	virtualization@lists.linux.dev,
	xen-devel@lists.xenproject.org,
	kasan-dev@googlegroups.com,
	David Hildenbrand <david@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Mike Rapoport <rppt@kernel.org>,
	Oscar Salvador <osalvador@suse.de>,
	"K. Y. Srinivasan" <kys@microsoft.com>,
	Haiyang Zhang <haiyangz@microsoft.com>,
	Wei Liu <wei.liu@kernel.org>,
	Dexuan Cui <decui@microsoft.com>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	=?UTF-8?q?Eugenio=20P=C3=A9rez?= <eperezma@redhat.com>,
	Juergen Gross <jgross@suse.com>,
	Stefano Stabellini <sstabellini@kernel.org>,
	Oleksandr Tyshchenko <oleksandr_tyshchenko@epam.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>
Subject: [PATCH v1 0/3] mm/memory_hotplug: use PageOffline() instead of PageReserved() for !ZONE_DEVICE
Date: Fri,  7 Jun 2024 11:09:35 +0200
Message-ID: <20240607090939.89524-1-david@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Scanned-By: MIMEDefang 3.4.1 on 10.11.54.1
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=apjgsSaV;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

This can be a considered a long-overdue follow-up to some parts of [1].
The patches are based on [2], but they are not strictly required -- just
makes it clearer why we can use adjust_managed_page_count() for memory
hotplug without going into details about highmem.

We stop initializing pages with PageReserved() in memory hotplug code --
except when dealing with ZONE_DEVICE for now. Instead, we use
PageOffline(): all pages are initialized to PageOffline() when onlining a
memory section, and only the ones actually getting exposed to the
system/page allocator will get PageOffline cleared.

This way, we enlighten memory hotplug more about PageOffline() pages and
can cleanup some hacks we have in virtio-mem code.

What about ZONE_DEVICE? PageOffline() is wrong, but we might just stop
using PageReserved() for them later by simply checking for
is_zone_device_page() at suitable places. That will be a separate patch
set / proposal.

This primarily affects virtio-mem, HV-balloon and XEN balloon. I only
briefly tested with virtio-mem, which benefits most from these cleanups.

[1] https://lore.kernel.org/all/20191024120938.11237-1-david@redhat.com/
[2] https://lkml.kernel.org/r/20240607083711.62833-1-david@redhat.com

Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Mike Rapoport <rppt@kernel.org>
Cc: Oscar Salvador <osalvador@suse.de>
Cc: "K. Y. Srinivasan" <kys@microsoft.com>
Cc: Haiyang Zhang <haiyangz@microsoft.com>
Cc: Wei Liu <wei.liu@kernel.org>
Cc: Dexuan Cui <decui@microsoft.com>
Cc: "Michael S. Tsirkin" <mst@redhat.com>
Cc: Jason Wang <jasowang@redhat.com>
Cc: Xuan Zhuo <xuanzhuo@linux.alibaba.com>
Cc: "Eugenio P=C3=A9rez" <eperezma@redhat.com>
Cc: Juergen Gross <jgross@suse.com>
Cc: Stefano Stabellini <sstabellini@kernel.org>
Cc: Oleksandr Tyshchenko <oleksandr_tyshchenko@epam.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>

David Hildenbrand (3):
  mm: pass meminit_context to __free_pages_core()
  mm/memory_hotplug: initialize memmap of !ZONE_DEVICE with
    PageOffline() instead of PageReserved()
  mm/memory_hotplug: skip adjust_managed_page_count() for PageOffline()
    pages when offlining

 drivers/hv/hv_balloon.c        |  5 ++--
 drivers/virtio/virtio_mem.c    | 29 +++++++++---------
 drivers/xen/balloon.c          |  9 ++++--
 include/linux/memory_hotplug.h |  4 +--
 include/linux/page-flags.h     | 20 +++++++------
 mm/internal.h                  |  3 +-
 mm/kmsan/init.c                |  2 +-
 mm/memory_hotplug.c            | 31 +++++++++----------
 mm/mm_init.c                   | 14 ++++++---
 mm/page_alloc.c                | 55 +++++++++++++++++++++++++++-------
 10 files changed, 108 insertions(+), 64 deletions(-)


base-commit: 19b8422c5bd56fb5e7085995801c6543a98bda1f
prerequisite-patch-id: ca280eafd2732d7912e0c5249dc0df9ecbef19ca
prerequisite-patch-id: 8f43ebc81fdf7b9b665b57614e9e569535094758
--=20
2.45.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240607090939.89524-1-david%40redhat.com.
