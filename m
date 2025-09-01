Return-Path: <kasan-dev+bncBC32535MUICBBTXP23CQMGQE7NUSTEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BC81B3E8E6
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:12:16 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4b31f744865sf7886971cf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:12:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739535; cv=pass;
        d=google.com; s=arc-20240605;
        b=OK0G9F91bF3WbidrtsntnhiUlrk8zvLEfTG9RZyaBhl+WE+SSzdNqgXxnd+QB00Z/j
         AjsMqoyRzF7HPjrZU4GYp2MZqhZhm1/jdBFyimdV4IXgvN3h8cuJ2w5uvGQQJFPLeBWW
         8yaR6QY6H02MZoI2MNEFz7Y2/thQPkGFaS28FTaByv+WpZA7MPm2Qw+4F1RazYxdbDCS
         VR476j6QZottkszK7LDWZnyFq6s0Dl+eGLyufJYYMhrB7l/lKv5ZIivhN1GcTMwPWpXM
         tXKfxHSQn8gx4c3Cv+HK75/nKwY9qvMlH0UCtBEmJ98KUb+JxmIIMpOTyC8OkPu8QI3N
         UPRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Lxn8JT5VQBqq0d4j3E9SxtWdvrRHXvD4AcjiJuBl4Iw=;
        fh=56CdYHCYxB2gdfbGQoJF9kgaGUKcrDxaBTm5IAhlRdo=;
        b=eTyskaAe//dWp+hV/SggPsEZiBKxpooWme32hoi+PSTAnTgPaLfxfFojOnv+pz0Fac
         Bt9L7zILASUKrABWWfKy6suO68ft2eKGKtGs8Il2CUOZUWJplv+lKkxIh2oDG+L28nb4
         Dbgu0I6G30Tx5uxhrIdgs1nQarl65q9eP9+Fbi2B7avkobxPusnNNbUj+710AqyUv/y0
         /XywNfOOQW6/ppp3LJTTNsCuXfuWqFuezP+0/ADDoT/IS/Ie+36Y/Lj2O0GBBAfR6Sih
         76fdObVR91K8/2KIcY5jK4EZpYEaae0BZMfowj8VLjXM4NztapFCoo06uSJTjey3GPN3
         UHKg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=L87N05LH;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739535; x=1757344335; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Lxn8JT5VQBqq0d4j3E9SxtWdvrRHXvD4AcjiJuBl4Iw=;
        b=lczdal75rAsbtp3v7QtFknnoGS6IZaCvGyQmY7tzafN+AWRQF6HBilk/aVKRELtI6n
         SZ9WSB5rvmgMAkjcqGi0cT454t9Eu3WzWAqg61vQcjaWRD4CaNVc9rcxnhe0b8C5N24n
         dNzf2V4SWIONDLfTnmOuQcE7WQFdYWo9yLhbFgSe7c1tJZHwT+/WK8wUyPPC4Y9zB5qO
         I6NqTuhjZqCUY1SVaAGx9Ff4W7IRclGtuOYxryCkPuNxK4qUzc4j5EhDx4Mb/vH+W+by
         ajBvaI+yO8ZEyJUF5F+Rb5VpjZU1N84lPYkbDwYRA0egeTY1OE8BMo52lzFBkZ3ajsHp
         EBig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739535; x=1757344335;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Lxn8JT5VQBqq0d4j3E9SxtWdvrRHXvD4AcjiJuBl4Iw=;
        b=OucTQIHl7//4fTwCAe68JOPW+5yjKSeo1PwYIMIarEnAS/Jqz4GpXbx/GXV8hkn/kJ
         Ewz0FhPflFUR5QWQyQHPEMJ/Kh6jUAttpUzk+MTxefep5sAnZyJ19y4+AS8swg85VBnh
         2ahP37FzZobhIPNqyCoYVPBg/MLzJg4PxPpTimXkdqQOZWdHVcoVgltTU0/QQxU93UsG
         N9/7irzI1VGoIj4YmEA5vRP23YHD1TtncgCoMxFXmouQYHon1JQ7gDRcLOntuvTvEHXq
         hMHUMzoTGP97n6a8MzwC6gvRR1WxhlHOTQl2cqZ7g7p6yvfkmackG+N3VWP3Vmt/2sKx
         4h1w==
X-Forwarded-Encrypted: i=2; AJvYcCWSqP5Kacd5SQq/u26XG34tIOBFUGWqvZMH869KcyFR8+jO+fULc4/pbrKz1USbVXlD+TK/dA==@lfdr.de
X-Gm-Message-State: AOJu0YzrhHyU0vvUrYih1cmCENPhflM3WwQaYEBYTwBeLnh0ps9GaZ13
	xHqEeSW3QLqE+LrVAznWS4H/B2eYzTUYJTodJuif9D8jEyMuJgPfFTEs
X-Google-Smtp-Source: AGHT+IHZV1msTCyZ7XtMZzwH2Ws3HqCX5h+kAIloVklDk4DsqECZKzcOW8LUHHuW7Ss6LtmFlakzwQ==
X-Received: by 2002:ac8:57c5:0:b0:4b2:d4ff:9ef1 with SMTP id d75a77b69052e-4b30e91ece8mr101449891cf.5.1756739535196;
        Mon, 01 Sep 2025 08:12:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfTCsOGP4NQSLdkXCh38RB7jtLNOHugi59KtcBMUy4zsQ==
Received: by 2002:a05:622a:453:b0:4b0:889b:bc70 with SMTP id
 d75a77b69052e-4b2fe8929d9ls90200841cf.2.-pod-prod-04-us; Mon, 01 Sep 2025
 08:12:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCURGf0GKKh/gHwYyQ4Z1qtvH7ee0X+sHEpUB6kb/R3ChhzAUfYnkZrxq4Q35yYMYPzYHldoqR+hdk8=@googlegroups.com
X-Received: by 2002:a05:622a:12:b0:4b2:fc8c:24d2 with SMTP id d75a77b69052e-4b31d89f637mr84347121cf.6.1756739534243;
        Mon, 01 Sep 2025 08:12:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739534; cv=none;
        d=google.com; s=arc-20240605;
        b=Pu9fJ0dJevGB3wM9s6G5gg5Zm01pKnLVw+6tM5AQNUFpYoiANnFKTjwqtSm/CBjCeE
         /nGBGMTZ857w67dkjxSFIvgzzNRtk3NpOA9Z56dcUQu2Io93ILoiE4GyR7cVe0kGY12g
         /Uq5YeBtP0rpfMhJm8Y7h2O5d7vYZLBVRcU0kD4eNiwaWXIecAWwoweKAwqJJPPzn1ZN
         FQYXbkIuIRmFM1HDNFfjWRyaiUo/U4AbvivSngZ3hLYVh3cWV/lU45PobjqBpI8X4OjY
         XEzIsI6DEg0W2QY2SKx302x5Hg+Sfg0vZ0eHDVhWr8HjuS+cCIWd1e1utisVRmHVz9gY
         +33Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=RkXi9jb8SbuESKxwWn0khRdBbK2P/CuDfx1yGIyBM6s=;
        fh=pOloqIvb0cdqBd5zs6nEbdZZpIBrB/lmeSUiPJxNdeo=;
        b=Zc4kgcce62SJ7+3oPxo9IRbK6o6Dpt0NBTIBQMgkUBWgjQfGVWj13XMc4Du1AncAts
         Yg/4EeiCirsG9rRR4n01rD7fB4YZv2FGcGRk2MUmb8erJJzFd9LdFijzOoia6mC89bYq
         yY/yFfhRZR0xZaNb8BvaiMjCN7qlBRBdwYPBzg7nvdox0ZH3JRV9MlkOSqyNV04hd8/M
         Qivdkqshtwl8xqryW7hqnQMZ7CtL7IvTgHFdBrxadZAVbdctSete+O+E9a20QTJUBfBO
         cWJ+rec5cojzubKfT0uCbyQAFzUH3oecNOUO1w35MMxV5LYIDLkirL6T1TmOnRjxmIgt
         y2dA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=L87N05LH;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7fc0ff05a7bsi35897585a.3.2025.09.01.08.12.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:12:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-83-3PVjTBDCNyiukKZGpg4ObQ-1; Mon,
 01 Sep 2025 11:12:10 -0400
X-MC-Unique: 3PVjTBDCNyiukKZGpg4ObQ-1
X-Mimecast-MFC-AGG-ID: 3PVjTBDCNyiukKZGpg4ObQ_1756739525
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id B577E1956089;
	Mon,  1 Sep 2025 15:12:04 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 0AC2B18003FC;
	Mon,  1 Sep 2025 15:11:48 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
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
Subject: [PATCH v2 29/37] mmc: drop nth_page() usage within SG entry
Date: Mon,  1 Sep 2025 17:03:50 +0200
Message-ID: <20250901150359.867252-30-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=L87N05LH;
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
Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Alex Dubov <oakad@yahoo.com>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-30-david%40redhat.com.
