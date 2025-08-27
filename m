Return-Path: <kasan-dev+bncBC32535MUICBBYUDX3CQMGQEBZZTREI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DEDDB38CB6
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:08:35 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4b0faa8d615sf37263431cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:08:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332514; cv=pass;
        d=google.com; s=arc-20240605;
        b=Rj/3KpYVZTJo1C2cZA1RJENHFyW0im+ysXifUvpCzXCMjAThgANf29Z1C6SqoI7+hS
         Q+j4vgm/+TGefR2+gcAgPOYRojoVm6C8OFMtNjh60hXGzNj94SqWGRyEl7wND3Hg+SZD
         WxI0WX+zZfDkqWLPZTE3Af4UEb++Gm41u+NtG8p1Et2ge5Kk1CS+6/x3fK1lLu8XX69x
         rxuBfn9Y0mONLVJ40zena3y6Xy+d3zuoq/CvrGMLWNicVvlHfyv35CYEnLDQ+NJcN5Ji
         ODmaohkQgqAxxo73AVkieplVEw0q1GbLAf9mGlzvjBK5gynRboMLSkZbTIsmU2QWdd+5
         rcbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=QK1QM564bCCiDhU7zgbCSP98NPO9Gesvmy9gw8lBmzY=;
        fh=XRGpg5pyM/N/7Pqbf6AhIz01FoNCizbABcfafGBCOzk=;
        b=dkb71xguBkJdiVE8J2IDMSTzdgvNNv7p01rPjfsFykgabd7mFLGN/NzwJaDr411IZc
         hg9FuHy5piRN5w/qbQRnhnLtJYAXGoZYZki47lugIiXEP6p31Zzg3aEjLJOgsRhFUeTu
         sw60oc4URIPUCrqCjLbLg19JLn/8C4kzlPeXu2gk5iW0XkgdjrwaagtV4BNHdecUhqcz
         PZ1s8eyRGBnew2cnzmb0XD6DCI/nin1Zdrh4XVjurq361r4sN4+RVSIF4ZOn7Q+WPOxm
         vmLxzrjziqnJrrS+nYfudxEFDj0p4pO3pyPl5SFvqW83SullkgkY4fl18RntQeedjLOE
         CSqQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Q+WfCGch;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332514; x=1756937314; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=QK1QM564bCCiDhU7zgbCSP98NPO9Gesvmy9gw8lBmzY=;
        b=o8zzDiHtmW9bSjFxbH8BjeaSLAclcXvgmOQwIeAdNKPjiz5yhznbE85/IPKZgZzgVt
         SLFxG4+jksUDn/SiNVeGr3cUYaeEX1oGeUTSUrPN8Fnx+OIhdHTZtN46RigvuIulKw7/
         KkuLsFmB+ZxG8OdR5r4rJKPLYxRZx9hT4l9XD66iCDOnhHo6xvSsDESLfBMMF9OkZy2d
         0/taEZCn3GK9UiTErE98EWQ040QXRDivtsu0WOPP9ih74B5aSQ0G5el2WTGACiCF1Zd/
         /MuwgXJx4wdM15jMDa3lbh5G6XHsx5kWzbjrZv9MowX0iqBkshIdGJ6AtTqvd4AYQKPK
         SP0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332514; x=1756937314;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QK1QM564bCCiDhU7zgbCSP98NPO9Gesvmy9gw8lBmzY=;
        b=o9q9Z/nQFvWCLHTv7L6Kk3erzm0XWLvMCYPPZ4vnTqpdB0VPGbK6jyWjT7XsH5Vxrd
         /DBpvqQ0/B+3p65WD3Cv+YxwNOeC2meZOxI+3NSZwgnACY2NeU/TllyDnZCB2E1+86zE
         7pGf+Ywb+dKs4lkkVvCRNDR58SmkktiAO0h1AwyVRDefsRc7LZTZuy2ORODgZMoYNS9k
         Yns2MU/cmi84ssU8GMWU8QAv9CvUxo/LSW3pittP6BF4TOBUozmXB6oHECHQjyZN2IrY
         c1sy+21PBxGJpy+mbE2MoVbB7GiahEA0pi2J12nblVzafsFflWCR88aH0zDFv4iWcZoG
         DeIw==
X-Forwarded-Encrypted: i=2; AJvYcCUYwLWYq0N4E8236UeY8lh+dpiRlmC4beIJh7lY/8F/diWfLh2L72RTEYbaXffSQFggLOUryQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw7LtUxdP8FG1Ditd9MloEYaBmfDIOd5rcyzx7uxvJZqkY5kD6V
	xWwBdAOBZyWwNBfMVok0PHgGzITNoRIZIyGCoRsF22D+IrBynoYwzMwT
X-Google-Smtp-Source: AGHT+IHxxGs0dWcwI2oDTgHdLFXALwu+7nTY/3anueXlAl6dnKa6rta6rRfqoPCXPoxgqsyhDWP/lg==
X-Received: by 2002:a05:622a:1316:b0:4b2:8ac4:f098 with SMTP id d75a77b69052e-4b2e76f6e7emr106561791cf.34.1756332514221;
        Wed, 27 Aug 2025 15:08:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfu1B85qwertZt5u5SRN7fdYigzxURNkdHbpnxTqWWjDQ==
Received: by 2002:ac8:58cf:0:b0:4b0:7448:c7e8 with SMTP id d75a77b69052e-4b2fe87eabbls1741991cf.2.-pod-prod-00-us;
 Wed, 27 Aug 2025 15:08:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXePFwr1saL08e70lhAlPss2sAmQq/cO+DfyLUlCl5guCmQBTNFbaPNUK88V9EHtHbYmeGsvdBIxfs=@googlegroups.com
X-Received: by 2002:a05:622a:105:b0:4b0:69ef:8209 with SMTP id d75a77b69052e-4b2e76f8326mr82160781cf.26.1756332513448;
        Wed, 27 Aug 2025 15:08:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332513; cv=none;
        d=google.com; s=arc-20240605;
        b=MVMf1GRzvJHoubyV2/qww8X0tknMhpL/Tub2TH8m1s6MVXUblOnCEj09WzJLKmwsRh
         K9XE/BUFHY2+lYT5wDwu7Rilma8oA22CCSPvW64TCwMTx8d8r0qDu4oZ9H+IL8NrYji6
         K+f58CmspF8087IeXAlch04ayFD3qGhTBW7bOmb9KO8tOiYgmQ/HVzlPQSaey18Kf/Xi
         ajI9Dheq2ErqVkFf5Kk7xYh4ycLoMezZLt3LTQDRN6BrF2Kaffon3O5WbS4cBf88tlWs
         /I/rNEAhAutF9yOOshYwFG53Z21LqaNL21201U+YUDk75wBeQ7Ks3vo1OIJEx2EP/jnm
         d+ng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=GyTIiGqaihmq+uYsd9xO3vzeYLCbCBgmjSTF8jMJzDI=;
        fh=rQNjLbwJlcMDGbUf9ZxRoQ4TRN7GFcelVCwTx7WcT9A=;
        b=dfuOQ+m0xw2M3eYO4FoC55L8b6d6H/uMBAxVrpoC2PUd0eqQpLKHyu4OMocFyI5GqZ
         cVYBSrfUpMIspb8ZuceXQXMEHFsGi+PLIo3zfFqL6SOpUt9C8JHXqFXFi5W/i/1evzDb
         jS2lSW7YAdK2HAc6uszkyeTfj/hkFV7i7MTsCBOx2eXCac/8UPNaaewyT9sFHaTB1Wv5
         VhDuCXRaErWSNsCe/3z9P87L7v8Muez/i4sNZU+6vfcOTaClqhTK1sgECttYBZ3CsGYE
         0YhHEQKenU3o7fJVWNkVtUCb4dqY8ovGo36gU0/3CFMfOcDSVD0xKY4WbLA43igLtqeQ
         swlg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Q+WfCGch;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b2b8c4f53dsi488681cf.1.2025.08.27.15.08.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:08:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-624-SKfpSwPANCeD7Iv3DGve7Q-1; Wed,
 27 Aug 2025 18:08:28 -0400
X-MC-Unique: SKfpSwPANCeD7Iv3DGve7Q-1
X-Mimecast-MFC-AGG-ID: SKfpSwPANCeD7Iv3DGve7Q_1756332504
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id A45A7195608F;
	Wed, 27 Aug 2025 22:08:23 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id BE0A330001A1;
	Wed, 27 Aug 2025 22:08:07 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Robin Murphy <robin.murphy@arm.com>,
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
	Michal Hocko <mhocko@suse.com>,
	Mike Rapoport <rppt@kernel.org>,
	Muchun Song <muchun.song@linux.dev>,
	netdev@vger.kernel.org,
	Oscar Salvador <osalvador@suse.de>,
	Peter Xu <peterx@redhat.com>,
	Suren Baghdasaryan <surenb@google.com>,
	Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev,
	Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com,
	x86@kernel.org,
	Zi Yan <ziy@nvidia.com>
Subject: [PATCH v1 22/36] dma-remap: drop nth_page() in dma_common_contiguous_remap()
Date: Thu, 28 Aug 2025 00:01:26 +0200
Message-ID: <20250827220141.262669-23-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Q+WfCGch;
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

dma_common_contiguous_remap() is used to remap an "allocated contiguous
region". Within a single allocation, there is no need to use nth_page()
anymore.

Neither the buddy, nor hugetlb, nor CMA will hand out problematic page
ranges.

Acked-by: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Robin Murphy <robin.murphy@arm.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 kernel/dma/remap.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/dma/remap.c b/kernel/dma/remap.c
index 9e2afad1c6152..b7c1c0c92d0c8 100644
--- a/kernel/dma/remap.c
+++ b/kernel/dma/remap.c
@@ -49,7 +49,7 @@ void *dma_common_contiguous_remap(struct page *page, size_t size,
 	if (!pages)
 		return NULL;
 	for (i = 0; i < count; i++)
-		pages[i] = nth_page(page, i);
+		pages[i] = page++;
 	vaddr = vmap(pages, count, VM_DMA_COHERENT, prot);
 	kvfree(pages);
 
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-23-david%40redhat.com.
