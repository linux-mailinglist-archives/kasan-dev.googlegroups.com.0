Return-Path: <kasan-dev+bncBC32535MUICBB24EX3CQMGQEJ64I35Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 302F3B38CFC
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:10:53 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id 46e09a7af769-74381fe311dsf375386a34.2
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:10:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332651; cv=pass;
        d=google.com; s=arc-20240605;
        b=SfxB/2KJMnI1l4+OlVRmbGOxbZ6qmr6s7WUgdw9H9IaKAfSiCI/UJXtKKZ17cT5Nqk
         oyHtOTEMAfIQFd7vgClZq2+P59rEI0NT8el6Yavxpnw5fYsL/gKr95P4w4ouKTYUwYV9
         2nU/D4eoKXAt7LdkjzPigIbj+YWfR88HnZRdbnqxvmYV6W81DRvPxqqPISEZegH01BXw
         U2jLOtL4U6SiHyuzQhnJVfw3tGx5BGtEkqMf7cbqzrmkvGn4F6FCLlDs5sMOxdvZVh3s
         v79MhfhcSqfy1YW2KC3XCeCS4+/rLAYRl+cYClGcBlCcqXXJbPb6o+zgPVw3rpfVgbv1
         nW9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=GeiJiisHieXxry+tM7Lnv8m8OCcGWbl9W3lH6UK9d1Q=;
        fh=LVfsWs4gUM3F7trNgLGEiWVvXMuWAofj+pvwq26Odvs=;
        b=cVAC3o9LhIwC084YrTaDLCIxl50sM1qKi3H54Y7A9+AEXb7i5QfHFRwHnS7NauC9kl
         8LSVQGjFvp3rK+CGrPb+ngA7wjPJgU5m5FR1RWtMn+iuWbvCBrXvEZN8z/mYnTAkkkzU
         UYNev0wOhmBTzbhZV3o6TQabAK1B5xL7dELTRp/ZDzrIXbaO0xkV8MkNv9AY/NpB3yGo
         qDX6DqS12CQDeKx/o2ATT8SpdS+MvdQTY2MVcHvkhM6ud2WgaRPAEWE5+V/8yaiqEiIn
         Ozmg1QTNFIve0tZ2thH6P0S4DbHhcUR6SAEzkouDY+EkrQhtHUEQ32pgGz+5W2navgWA
         ULSQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=BZANU+85;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332651; x=1756937451; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=GeiJiisHieXxry+tM7Lnv8m8OCcGWbl9W3lH6UK9d1Q=;
        b=fWeXJfSvlaELhD++diVO+qZQu/EisLRlWyYztJs6rTgNGQSVmJBjTzawRdbU5ZJpGZ
         5NjHn+RA6n0NAYdz6IajG8wEOSGXEYcfBw/aa+OduhOW0CMWyoX/bYVni+/d5QJUl1RI
         XJZDzcMHJv3tpT9F638cHibVuxmVhNDgN9KGUWCj/kRESlW6nok1TAu2npQ8mY3IzAPv
         pZKG7a0ikodsHbU7ap3x3be7odZdSq22KFFy8udcBFQFyEfhRRbrUfb5bRkzA7afs7Ah
         +vo7hUNuI3pSgBxVvGVlQ/bKlPydgO0kdVLmHOpgfJIOPcysiD8SmXVpI5oBsrIJ32uV
         eIrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332651; x=1756937451;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GeiJiisHieXxry+tM7Lnv8m8OCcGWbl9W3lH6UK9d1Q=;
        b=M3tjXuj+RDTtwS8JafUZqnGt6H0FFglIN1vur9xeqqYbBqd3KBBcijMYOyLrS01t1I
         xRr4JkSWcBlJilgI1KcyqdlvucASjd7PckDc0oPeC6Pr0Kz6kbrwuGQBph1Uw49nnH1+
         1Uxn3kBR9tZj0LFVlVXPlsLk6vINupYRVuWhfObDISLLKf5Ast4Yw0kd1yGETPfppJPW
         MihaZ9pff+Bxyf5fApD01QcS5QTSuV3LU/B1aX0ctcIkzQD0bzac9umajQEp8my28Xpe
         EN/NzPopuf+n9w9BOWA6R4MktbU5rHxg+srPxQttFccNJv+jX+xPz/knYMptRZseyKNh
         Uvvw==
X-Forwarded-Encrypted: i=2; AJvYcCWgQhl/NZJuskjOQb0m1Qv1xPA2eafhRCo1vS9ZhpTkR3gqtKLUGBM/ciCG+rq4tuITcKV2Jw==@lfdr.de
X-Gm-Message-State: AOJu0Yw8oYftWUwhw2Wx3QQ3dD4dQKCeKbnIwlbVfU/RrmwkxbEqthmu
	gahNDqThpbZRbXGixME5un5jMgjcWls4Or2j62SnEW9SYsoOwWoJoWjb
X-Google-Smtp-Source: AGHT+IEvzsigKQ5yWVB6KbCyOLipieF+hLWwrNGmYPfxb1fuywGQBm5J0H6WjAbFdAOqlKG2+ZPYoA==
X-Received: by 2002:a05:6830:4994:b0:73e:96e6:252a with SMTP id 46e09a7af769-745008fd4ddmr11037068a34.4.1756332651562;
        Wed, 27 Aug 2025 15:10:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc2NpU6UJpC+2FWy27UEx/kZLGBHDpCI0KC49vRgbkdHQ==
Received: by 2002:a05:6820:704e:b0:61d:f8d4:b321 with SMTP id
 006d021491bc7-61e126e9ca1ls34019eaf.1.-pod-prod-01-us; Wed, 27 Aug 2025
 15:10:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXfuYbAZz2+yO16BsvQkv8ueXC++lyAtHCErtmiHBD8J3XkNX16dG3k/0t/hUIpZXqjb13eeU2vnEU=@googlegroups.com
X-Received: by 2002:a05:6820:16aa:b0:61c:130f:7519 with SMTP id 006d021491bc7-61db9b4e637mr9398181eaf.3.1756332649972;
        Wed, 27 Aug 2025 15:10:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332649; cv=none;
        d=google.com; s=arc-20240605;
        b=ST4X+UfSv3fN9rxZjSHRdPEbtUu2pmmLZWVo0DmT5jyn+MXhO9q0bRFtE8cP4N2H9q
         jaHp/1rgC1e9l4Rskg7bUqQwJ/eZhAY6je6q9x2BerCcq5tCjEu9j6Rmf4uzrB8UsoRG
         Vvhl1vV8AdR3HVb011FwJG8C/S33CfapPz1mAy7j2vew6ubSrCL8nqq87Qhpv/qjrpYT
         mObKzAEQuzPY1/zeD6bMGTB9u/ZTxesPh5Nd3yDSGgliegG3+JVsOM2Im8PzFW5DMnij
         kkHGQUUojN2Oad0RwsYfkyAMPBIpghT0+Ef+ot5ht/abjyTHyLofbQ+YbOvyfFZ0GFJ3
         D1Uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=YpVNTL/msyfj4quk+zG5idx/zOSmESitaXX9oJyyDlo=;
        fh=Ul+tUGbD03HNH+vdIPwVgnaB7Q82iuus0RjVVsM5xsQ=;
        b=RwMrsZ3oxoWtTFJ8ayoe2LK611OSNtdhm/BA0dVFSc8DshqU1XEgHiSPS8FzriNwP7
         Ub+T1B/h2xSwcjNl7+lQto5VZ0yLzRqCsf+Ox64mQOA2Vhd6NPoH5pA0D5aNPlEJa88t
         +zFMMvn6BkITfRUF31d4cf450jxRj7vGgvBLX2vBznbgbRY0R4WvpYSilF00+Hfixqq8
         Lr07NfNlHo3LvLE0AxT08HxTOyWpY4Si7NoCHrsNDWhC11U2Y8mIV5jYzS9FahJddhuH
         z/DvPQEWRWnddhQJhgTmAwbZ4PNjtyYd4TLKA+xPsYtIf2FuL72oM52VnPARZHJROVfe
         CSIg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=BZANU+85;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-61dc74760f3si559695eaf.0.2025.08.27.15.10.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:10:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-628-sl5k46szNKGimV3zS5dDew-1; Wed,
 27 Aug 2025 18:10:45 -0400
X-MC-Unique: sl5k46szNKGimV3zS5dDew-1
X-Mimecast-MFC-AGG-ID: sl5k46szNKGimV3zS5dDew_1756332640
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 75B6D180034F;
	Wed, 27 Aug 2025 22:10:40 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id A20E430001A1;
	Wed, 27 Aug 2025 22:10:24 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Bart Van Assche <bvanassche@acm.org>,
	Doug Gilbert <dgilbert@interlog.com>,
	"James E.J. Bottomley" <James.Bottomley@HansenPartnership.com>,
	"Martin K. Petersen" <martin.petersen@oracle.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Brendan Jackman <jackmanb@google.com>,
	Christoph Lameter <cl@gentwo.org>,
	Dennis Zhou <dennis@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org,
	iommu@lists.linux.dev,
	io-uring@vger.kernel.org,
	Jason Gunthorpe <jgg@nvidia.com>,
	Jens Axboe <axboe@kernel.dk>,
	Johannes Weiner <hannes@cmpxchg.org>,
	John Hubbard <jhubbard@nvidia.com>,
	kasan-dev@googlegroups.com,
	kvm@vger.kernel.org,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	linux-arm-kernel@axis.com,
	linux-arm-kernel@lists.infradead.org,
	linux-crypto@vger.kernel.org,
	linux-ide@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	linux-mips@vger.kernel.org,
	linux-mmc@vger.kernel.org,
	linux-mm@kvack.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-scsi@vger.kernel.org,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Marco Elver <elver@google.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Michal Hocko <mhocko@suse.com>,
	Mike Rapoport <rppt@kernel.org>,
	Muchun Song <muchun.song@linux.dev>,
	netdev@vger.kernel.org,
	Oscar Salvador <osalvador@suse.de>,
	Peter Xu <peterx@redhat.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>,
	Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev,
	Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com,
	x86@kernel.org,
	Zi Yan <ziy@nvidia.com>
Subject: [PATCH v1 30/36] scsi: sg: drop nth_page() usage within SG entry
Date: Thu, 28 Aug 2025 00:01:34 +0200
Message-ID: <20250827220141.262669-31-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=BZANU+85;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
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

It's no longer required to use nth_page() when iterating pages within a
single SG entry, so let's drop the nth_page() usage.

Reviewed-by: Bart Van Assche <bvanassche@acm.org>
Cc: Doug Gilbert <dgilbert@interlog.com>
Cc: "James E.J. Bottomley" <James.Bottomley@HansenPartnership.com>
Cc: "Martin K. Petersen" <martin.petersen@oracle.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 drivers/scsi/sg.c | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/drivers/scsi/sg.c b/drivers/scsi/sg.c
index 3c02a5f7b5f39..4c62c597c7be9 100644
--- a/drivers/scsi/sg.c
+++ b/drivers/scsi/sg.c
@@ -1235,8 +1235,7 @@ sg_vma_fault(struct vm_fault *vmf)
 		len = vma->vm_end - sa;
 		len = (len < length) ? len : length;
 		if (offset < len) {
-			struct page *page = nth_page(rsv_schp->pages[k],
-						     offset >> PAGE_SHIFT);
+			struct page *page = rsv_schp->pages[k] + (offset >> PAGE_SHIFT);
 			get_page(page);	/* increment page count */
 			vmf->page = page;
 			return 0; /* success */
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-31-david%40redhat.com.
