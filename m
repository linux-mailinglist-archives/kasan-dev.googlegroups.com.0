Return-Path: <kasan-dev+bncBC32535MUICBBSMEX3CQMGQE42HIX5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id EA77CB38CED
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:10:19 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id 41be03b00d2f7-b4c20148c54sf239312a12.2
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:10:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332618; cv=pass;
        d=google.com; s=arc-20240605;
        b=Me0cKsFV7bzwwO6XQh1My5rR0+82uQLrEsKgA3Z1ZGf2HqybGknNnjsPKv3rjRQQ4Z
         e8JGkJqXe9NVahW0OXkDLeF+jtpteVK2yZJAO3DCm/aD/TANcYQmxO0J2Ez25UYZSCfK
         6U48vlsoK83oE5lcBKunDdp3RlVgw+WQM1gJPgzvwVk6iLayTJgqSqIy8XRZZ9nK0M3S
         kFgCj1y1/YtJ8SdeXWum3hc2bipJ1YDbPHXqoBx3006IeHA/+BYD17RSN0u+eTnu1bG6
         8JJ78y7xslqthetAwHZnEV4MOcF52M4GDERRI0fgNMcW40iBM3NuaF5r7rsTVEBpOpuv
         eL6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=ZNTIBxZhqHB1pB9nAm3oZflblsZ90G3yWVdgaD/qM2A=;
        fh=Sd+2syGHf6pUD9toT6iGWlEMUPFv0FVdKxYIjQafqdk=;
        b=MG9wOAhOdaP+Rf5FBxYLVoBOtKJyqN5bGB/F2TuIdLKPgGg5lfYEQuMw0j1NOFx9Gs
         z+cXbVcZa7WmFsplFqYw8ha6MwuYCaSB84DF81lzhrwli5k+bEVO+MgOzgR2iSgNLWn6
         qSpi6vJgnlij4u7p+18YCJ27ShQWfWNpfogTYU7IImHZ8kxtMAZdvVJeFM9wsf32ZENk
         4WudbF11nPHfbS/C4TT4AiI89qJqDzxuAwlLzZZrX6YgLIq+LfIwj7aNswvn1aeSp7Vh
         Qcc4SCHAOUy9B2WMLs/7TiyMvwq6p96m1yCQJcIqpe3FRo8huDKmAFa9XVrT9dWKBARq
         rslA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=HA+WgFhA;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332618; x=1756937418; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ZNTIBxZhqHB1pB9nAm3oZflblsZ90G3yWVdgaD/qM2A=;
        b=S5FKXP5p4zITXfBW/KzoNJ5inqwsKLFi5kFpQ9LI6c4cI41QIuXG9qthl+fiICAdvx
         zlT0bNwXkt+8YYttAm+T/NLQF4mfLkFjDZn3lmf3AC8RnmuXfzyLr6/99DB32cpDMxVk
         ONLILt52sOaIMNon/hkGtkHW6U5jQPfVVosiSCcOiOYSI5qgGCcT2vOaie2Lm4IFWKlF
         Rz6NZAg2sh93GFVpmXQU5s/2uyYBtfqzU+04UnePBIRec8pu71k0tSjAd4mXsGwOW/hz
         iWJLayBaX7e9+dwjNbqmcF9KNevNUjQJ9o4/2LaOA3MEmjBQP0qnDQYz1q6wqRVz4B6N
         rELg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332618; x=1756937418;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZNTIBxZhqHB1pB9nAm3oZflblsZ90G3yWVdgaD/qM2A=;
        b=Ffg4ILXLve8QPfs8Xum3M3Pqsl1r47tckwUM99DpcGsXDqxC/mSPhKQfAnWVdzcW2t
         HJDEcxanhiu7RjwyE3VIvVCCQdXeMU5T1muw3h8hrroPfL5NIH1sjqREb5aav7KQFtlc
         qHB3ESHohE7QiiusLSsGl/jqZ3XsJ77CdlgPsWR4KUWD78JdUQOnM4HKxTMBQjVnlacN
         /wpzAmE+49NTRm9Iv3CSiM2/yUNxYJfjvcju+jOyN+qcxb7GbxKKGyvQKHeJnGBKE7uZ
         aEsohtYOG544eXgoMdJpkhHL2MVg+LIbFd6lj9z4pO2t3Xxy1OP362e8tRUwYosBZPgI
         cpEg==
X-Forwarded-Encrypted: i=2; AJvYcCWaBw2lDYxnrNwa3rml4TTSc1Vqbq9qKZArCBVUXOu3Zc340ReN6DpxwYmdEGLQZpCI/P85Qw==@lfdr.de
X-Gm-Message-State: AOJu0YwymJQ8sCCo5lp33mTmx+ZPxSKvaSYN1n93S1SZbQb8ou1XdeOt
	Vugg7Wv7HsxTlY0bEHGWyc2BNzchgdZiGabgkkrNH5KL3b22H9hrxdLO
X-Google-Smtp-Source: AGHT+IENyWxf+1ogu40y84Ezu77UQJbujPVlhmqcgSuWEd/McPGuiq7D2GQxOT6HhQgzGEH+/8qrKw==
X-Received: by 2002:a17:90b:2752:b0:325:1548:f0f with SMTP id 98e67ed59e1d1-32515ee0104mr26574927a91.14.1756332618282;
        Wed, 27 Aug 2025 15:10:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd4PyC/Oh89vZf6f+90ey3uxT9SwmE4vfHwjHqDQD7Nzg==
Received: by 2002:a17:90b:5082:b0:325:7c02:d093 with SMTP id
 98e67ed59e1d1-327aac6d100ls143695a91.1.-pod-prod-04-us; Wed, 27 Aug 2025
 15:10:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWksWa1NVZjb3siTn5V+UD6rRiO3DgPwR3jHwEHzqDgSd+8ftXmPnF1BAbo1gpffVoRMoVTaaHH1wU=@googlegroups.com
X-Received: by 2002:a05:6a20:7f8e:b0:243:78a:8291 with SMTP id adf61e73a8af0-24340e2d3c6mr33157990637.56.1756332616835;
        Wed, 27 Aug 2025 15:10:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332616; cv=none;
        d=google.com; s=arc-20240605;
        b=dEhkdzHzoBJbZM4iF8yaDawp+t+lQDWKD2bT0uRbA0aJeZYBXl2UXIdn9G8crAs1pw
         otoaRg9nHoGTbGaYN0QB+V5TBSu2mqrU5CRKhrLfi/32nEyXxG+8xnK178THEIa+IvMJ
         +p6OGI/X5Cjd/AMKH6Bynd+l7ImMFku3U3qEH5KiRzBpd4JL9jjW8TTEbUEPFvDJcj2G
         zHa4hM3Glv9Ac5a/2vY9Ox8M+KBcToTt/2GKbmufWQfZLtzVs1yvM3DQ/NfpKsp5+XB3
         j8xhZf49yHd/pLPAN4vNDf0lOQ91EcIcFtgNlcc5HWXfDHFhN98HbZaNO+wvCYMFtP0d
         Ty+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rAsuOXpZW6+ZRpVYsSsl6meZaoXTi6zM/YFmOyHNi6k=;
        fh=Ir5xvMHiWpq2xZ0MPW4Q/4xzqR/6UMDmVH0ci2kSd1M=;
        b=kHsSAn+DxArLGA4bir7rIhdyXbNMivj54HmNJ0/5Tku46ssG7UHwD20a4OEfkXGRe0
         t9TiWdq6UzfI+fwzsMij75rj/ZiG/SBbS/UJMf82hWRvmKJQrPQWIDPfBml7OgRsZgO5
         B6WojP+2xKnash0LqHBIpJI39YuJAPMDnP11STaGF+myqCFc11F4gVUUav2FcNAI1X6M
         dR5uPhs8HeOO7sTmfB7IQK2uS9dCimNL5/5NfgHK9aHKUm4nmSvn+EQ/sByB51C8pLeX
         mlZEtxZTy1sDK627aPNQheR6sHxW82QMdd/1usOt6MKP8DL2ZcxEpfaIxiga4MFGBr79
         1VxQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=HA+WgFhA;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b4c23c1ef5bsi378228a12.3.2025.08.27.15.10.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:10:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-145-dHJEc5UDOjeaJ0EVKtmuGQ-1; Wed,
 27 Aug 2025 18:10:12 -0400
X-MC-Unique: dHJEc5UDOjeaJ0EVKtmuGQ-1
X-Mimecast-MFC-AGG-ID: dHJEc5UDOjeaJ0EVKtmuGQ_1756332607
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 4A9AE1800352;
	Wed, 27 Aug 2025 22:10:07 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 8ECC630001A1;
	Wed, 27 Aug 2025 22:09:50 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Alex Dubov <oakad@yahoo.com>,
	Jesper Nilsson <jesper.nilsson@axis.com>,
	Lars Persson <lars.persson@axis.com>,
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
Subject: [PATCH v1 28/36] mmc: drop nth_page() usage within SG entry
Date: Thu, 28 Aug 2025 00:01:32 +0200
Message-ID: <20250827220141.262669-29-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=HA+WgFhA;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

Acked-by: Ulf Hansson <ulf.hansson@linaro.org>
Cc: Alex Dubov <oakad@yahoo.com>
Cc: Ulf Hansson <ulf.hansson@linaro.org>
Cc: Jesper Nilsson <jesper.nilsson@axis.com>
Cc: Lars Persson <lars.persson@axis.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 drivers/mmc/host/tifm_sd.c    | 4 ++--
 drivers/mmc/host/usdhi6rol0.c | 4 ++--
 2 files changed, 4 insertions(+), 4 deletions(-)

diff --git a/drivers/mmc/host/tifm_sd.c b/drivers/mmc/host/tifm_sd.c
index ac636efd911d3..2cd69c9e9571b 100644
--- a/drivers/mmc/host/tifm_sd.c
+++ b/drivers/mmc/host/tifm_sd.c
@@ -191,7 +191,7 @@ static void tifm_sd_transfer_data(struct tifm_sd *host)
 		}
 		off = sg[host->sg_pos].offset + host->block_pos;
 
-		pg = nth_page(sg_page(&sg[host->sg_pos]), off >> PAGE_SHIFT);
+		pg = sg_page(&sg[host->sg_pos]) + (off >> PAGE_SHIFT);
 		p_off = offset_in_page(off);
 		p_cnt = PAGE_SIZE - p_off;
 		p_cnt = min(p_cnt, cnt);
@@ -240,7 +240,7 @@ static void tifm_sd_bounce_block(struct tifm_sd *host, struct mmc_data *r_data)
 		}
 		off = sg[host->sg_pos].offset + host->block_pos;
 
-		pg = nth_page(sg_page(&sg[host->sg_pos]), off >> PAGE_SHIFT);
+		pg = sg_page(&sg[host->sg_pos]) + (off >> PAGE_SHIFT);
 		p_off = offset_in_page(off);
 		p_cnt = PAGE_SIZE - p_off;
 		p_cnt = min(p_cnt, cnt);
diff --git a/drivers/mmc/host/usdhi6rol0.c b/drivers/mmc/host/usdhi6rol0.c
index 85b49c07918b3..3bccf800339ba 100644
--- a/drivers/mmc/host/usdhi6rol0.c
+++ b/drivers/mmc/host/usdhi6rol0.c
@@ -323,7 +323,7 @@ static void usdhi6_blk_bounce(struct usdhi6_host *host,
 
 	host->head_pg.page	= host->pg.page;
 	host->head_pg.mapped	= host->pg.mapped;
-	host->pg.page		= nth_page(host->pg.page, 1);
+	host->pg.page		= host->pg.page + 1;
 	host->pg.mapped		= kmap(host->pg.page);
 
 	host->blk_page = host->bounce_buf;
@@ -503,7 +503,7 @@ static void usdhi6_sg_advance(struct usdhi6_host *host)
 	/* We cannot get here after crossing a page border */
 
 	/* Next page in the same SG */
-	host->pg.page = nth_page(sg_page(host->sg), host->page_idx);
+	host->pg.page = sg_page(host->sg) + host->page_idx;
 	host->pg.mapped = kmap(host->pg.page);
 	host->blk_page = host->pg.mapped;
 
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-29-david%40redhat.com.
