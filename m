Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBCUPS7CAMGQEJFAY6TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 28D6CB12DE8
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Jul 2025 08:30:36 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-70734e02839sf28126846d6.2
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Jul 2025 23:30:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753597835; cv=pass;
        d=google.com; s=arc-20240605;
        b=BSfZIOT2d9mrtaHhW6zS11Fc2FKSuzGYPmZA8ZrGnwQrLvAltDov4KOQr5/4KihfqT
         kmBIvCDJ6mFfJqAoCtl8BhcBOvUVTenm5MoFRwm3LobwkIcEEEftivEembGx8zETbLL6
         jbAV5PslvEbTbP5AsKNG0k5RCp1RS9PZxOMTMFQAxRP1zGLwuDoR5msMY+rfDcnv63zr
         /Dcp9D7h1H4dWR8xJjlwClFm6hYHb6/QGBR0wvL+aVFIYMsc9e1xxvhLEybO9eOncw0F
         HrRDgfvIlRs/3NMypruTAwi6VBUXlv1IOzYYFyqEtlvAK8OGnYKcVaX1ciniLvKEmYbB
         76iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=3L/20W9wQEPmJPG7ZZhtj6Tu8Ss6bLdkeU2KwgdzfL8=;
        fh=GMmsVqEXUUu1eoPUBMYtVIJcrCv7QnTb1+TnHpDIJBg=;
        b=MMrjwUNyoI6yhLt4GAMvzrlr+s3Rd84t8V9KXC5MHiiNAE9EOCHGluQLZAV6NnZlKp
         QNOe3OJ7Y9yksej7rYWSNjec1Amra+EVZmR+YLJDTfMgEsxUnk6SfQx8p9Rwiqne3dxV
         ZkfF+R6VZTgL9FL1t9skb9M/irdxsyvdrslXwXFct4uE4RFiPmOHpePot1ntm6ahq2Gx
         YcpbNleZP5rC+Z5pEbh4sLVGiqp7+zOoyJfq/jALw5St+Gqn3LkuNPQSohSXYif6jlyg
         IzL7zZVuVmtbezAQ1usfwcRbuP9XbMtPxphov5FxJFxOeLreHWkWLPsR1Kiur9/T27TK
         e5nw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=O08zmCcV;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753597835; x=1754202635; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=3L/20W9wQEPmJPG7ZZhtj6Tu8Ss6bLdkeU2KwgdzfL8=;
        b=Y2sRJSTrVoA0DJO1DmRAScdB8sx4VHb+1ZF3pEgkwCK2tKAQJMMdZQm7CpPoOspmbZ
         dNH+MPpBBpZENvM9Ek/6nJN+u05cGEi5GkYrLZufva0aEevISzvEwQ2MRM0bFGVvSJKb
         agM+0yLiSD1F2/Gx8i2b3misek0kjGhyNoFS50CMS9a5LBwgQwN6IwRmi0GCXHFMjXiQ
         CqSMa+PKnLVq6QX8BwnLXDKqsMLZ+8hksxuboBNWysOKfG/OxOfxe9ywNnKA40/Q3Q9M
         S3L5dwQ+x+k3l2ZQDSc+eA1DVFsUCN5XuppHJbuu1yN5kSAETt+z/oLFQYvg/BB5gIip
         lp6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753597835; x=1754202635;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3L/20W9wQEPmJPG7ZZhtj6Tu8Ss6bLdkeU2KwgdzfL8=;
        b=ecySAQieqhf/D+oq48H7XvQdfh7ysbU9Dhxic+avI7W+KW5GdtBFX3O+VWhU6jzjqp
         UgP/tXABQP0030pKQUuW9upzM4JXr2XSAijnWI9HM2cMp2S/vRhrVwkygsphhEqc2VoX
         DZk/exj2QSP8Wk8dLQoKdwfOAjXwgFPMd/8uSiguK5q08S3Shgtx75fjpHrRA3RGTxnd
         dt9JD0zk3pwZykptNFuHfWByiqrjoZeXO0el7+G+55xzplgbjN0YxH8bhM091i94Ha37
         xeSZ+cLcNjE33W2NxAWgx5p1a/GLrV8TcX7sago8KoX2+pGj1Warufdz2i7KTr1JPfZ2
         o70Q==
X-Forwarded-Encrypted: i=2; AJvYcCVq9/aEabPqdOYvb1uKtgYZebAhi58IUJvOQMiYc6+FILaLuiIThtNYe0myE5G0OhaL0EyGPA==@lfdr.de
X-Gm-Message-State: AOJu0YzcHZBqww1l8Y8quFJVSNrjgrfk99ObAl8g5uyqJVvjBmvrZ9YZ
	eud2n+kkW6dBNig2TqjBdgKYQYdLD2SNN2bOcUb3JqD/woClRa+H89Pw
X-Google-Smtp-Source: AGHT+IELu7VqavAEpnjqKugT4fxtZaaGlJsHPNmrOGnjJc1vlJMG3klTuSdDQq3mLdIMbegDylzrUQ==
X-Received: by 2002:a05:6214:29eb:b0:704:8e16:51e9 with SMTP id 6a1803df08f44-707205ef5fbmr111670856d6.45.1753597834659;
        Sat, 26 Jul 2025 23:30:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdS3yzzf4lu4zF7h+4UuUZFvzstozcD23GGD+tThVaEDg==
Received: by 2002:a0c:f096:0:10b0:707:1963:1420 with SMTP id
 6a1803df08f44-707196315cals26413566d6.2.-pod-prod-04-us; Sat, 26 Jul 2025
 23:30:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUug/T30xo/Oir/4agch5fXeF+9IFhkNA5w1l5HE0acuTnRQoHa9N1AM/Ex+mFOfdqVQpn/aPcIHqQ=@googlegroups.com
X-Received: by 2002:ad4:5d62:0:b0:704:8fa0:969e with SMTP id 6a1803df08f44-707205e6db0mr94309236d6.41.1753597833524;
        Sat, 26 Jul 2025 23:30:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753597833; cv=none;
        d=google.com; s=arc-20240605;
        b=cF/2lfZh/9s19cy8Q6XrHWC4/tcy/7I5HkfRoLbBqW9A7xv+3XkoWMUCndqBvxIuO6
         44BxvO7uocSCpCArtbHkABGZOKUZ2ax0ttQ2qU9aP8TInP7CROLBSIckpb2OjvqS0JwK
         zfNnoghbOnLzxSPSvwJLb4TA7Ub4rRAH6HPQyjEbj3Ry+5iZu//xesU9PvwUlWl1f8K/
         IA3EMms3lPZ0D+UG0QOPUY4bCoJivKrNIAou7vgtf8yxQTKaw4683FyYX3o99KniTTXr
         bpw81fhrmPGjms5GZQZyZAeQ+iE4NP7GEaWMoAEvHv5S+hiMbl0V2Zp9zAc4biuc5mQ3
         Pb9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=jjfcCyoAyA6p4trAoq7FoBBrNSgnRiG/tjvLuL/5Dpk=;
        fh=n+xh4rv9CeJzJ2V2/by0A5Mr4fESDR4ol/8zcFfTMu0=;
        b=PgrwaqMDa3xsrGrFcoDmVf+Gt4BEwr+kPd9DUoLt837MWlrZR4QwaD0MmksYh2WYHv
         Fb6bBpd6F3eHhm5+j3gH5SnwSLV0xaF5EhKdSU1FYoEP4AKsYhzx2/spjNcxANn3+56E
         ccYKDYewDLW015nj+jmBsn19HSpzHany7iYBYjspoD8ziyy9IEJ7QGftZoIe4ZGR/Eae
         COHm+gCJ7wDjfNrEXiM32YrA5Xhdx35vijwOpqi6Fblciv8dr+ph6cWPY0SRz/xJgx+x
         3iO1iboNRu0T/IYXUrg7ehV4oAyVBBnouwQZeoFXLxFpc9Mm50aUBkVwJnJRZc8FCKJG
         TF7Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=O08zmCcV;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-707438ffa1csi180246d6.5.2025.07.26.23.30.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 26 Jul 2025 23:30:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id F2F99A53E7D;
	Sun, 27 Jul 2025 06:30:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8D8F2C4CEEB;
	Sun, 27 Jul 2025 06:30:31 +0000 (UTC)
Date: Sun, 27 Jul 2025 09:30:28 +0300
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Robin Murphy <robin.murphy@arm.com>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
	Christoph Hellwig <hch@lst.de>, Jonathan Corbet <corbet@lwn.net>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Joerg Roedel <joro@8bytes.org>, Will Deacon <will@kernel.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	Eugenio =?iso-8859-1?Q?P=E9rez?= <eperezma@redhat.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	=?iso-8859-1?B?Suly9G1l?= Glisse <jglisse@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, iommu@lists.linux.dev,
	virtualization@lists.linux.dev, kasan-dev@googlegroups.com,
	linux-trace-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [PATCH 6/8] dma-mapping: fail early if physical address is
 mapped through platform callback
Message-ID: <20250727063028.GX402218@unreal>
References: <cover.1750854543.git.leon@kernel.org>
 <5fc1f0ca52a85834b3e978c5d6a3171d7dd3c194.1750854543.git.leon@kernel.org>
 <02240cf7-c4d4-4296-9b1e-87b4231874a1@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <02240cf7-c4d4-4296-9b1e-87b4231874a1@arm.com>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=O08zmCcV;       spf=pass
 (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted
 sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Leon Romanovsky <leon@kernel.org>
Reply-To: Leon Romanovsky <leon@kernel.org>
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

On Fri, Jul 25, 2025 at 09:04:50PM +0100, Robin Murphy wrote:
> On 2025-06-25 2:19 pm, Leon Romanovsky wrote:
> > From: Leon Romanovsky <leonro@nvidia.com>
> > 
> > All platforms which implement map_page interface don't support physical
> > addresses without real struct page. Add condition to check it.
> 
> As-is, the condition also needs to cover iommu-dma, because that also still
> doesn't support non-page-backed addresses. You can't just do a simple
> s/page/phys/ rename and hope it's OK because you happen to get away with it
> for coherent, 64-bit, trusted devices.

It needs to be follow up patch. Is this what you envision? 

diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index e1586eb52ab34..31214fde88124 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -167,6 +167,12 @@ dma_addr_t dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
            arch_dma_map_phys_direct(dev, phys + size))
                addr = dma_direct_map_phys(dev, phys, size, dir, attrs);
        else if (use_dma_iommu(dev))
+               if (IS_ENABLED(CONFIG_DMA_API_DEBUG) &&
+                   !(attrs & DMA_ATTR_SKIP_CPU_SYNC))
+                       is_pfn_valid = pfn_valid(PHYS_PFN(phys));
+
+               if (unlikely(!is_pfn_valid))
+                       return DMA_MAPPING_ERROR;
                addr = iommu_dma_map_phys(dev, phys, size, dir, attrs);
        else {
                struct page *page = phys_to_page(phys);
~
~
~

Thanks

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250727063028.GX402218%40unreal.
