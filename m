Return-Path: <kasan-dev+bncBC32535MUICBBPXZTXCQMGQEDLKRNUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id E1F4AB303B9
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:08:31 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4b0faa8d615sf65092851cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:08:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806911; cv=pass;
        d=google.com; s=arc-20240605;
        b=JzuxIlbzjhaZ4SuqpJRnVJi+1YI+Mzq7mRbbN3AYUcgfSrObv5uJfugld37j2pd+I+
         kSfve45R5/o268/rOeayoXAK4399TJ4aiWix/f1n9399ZpeaG7Q9H24z7WFDRDjQlDsv
         tXX6qBCRaQriUqQvqYHhOo+eGlfg7rXJv4YggLVlTwOwTLZ6V11qGThkDY7zGflyzqFu
         xZ2e6lAoa4QonRY8wEUQA6EALxHDxgP+p0AV8JUHC/nNP1lG1qd+PW4GZScdk2BhTgfC
         NrYVx6VPg9UUuTtT/tJCQ5htxcnkenpURuM5V//jFEZt5MP8FDQx3/YCeX12NBvJENiw
         D3TA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=WdFj9VpLaQCJiREx1aP/8jwv8ts0uYfZVEvOBQC4NJs=;
        fh=/7qO+Y14o/c1qd3WqAAhjmbGffYTS14StRwf1Jwuvz4=;
        b=Ean4WqCts+jHqNLlP1Zujkk53Gdb4v4IjxlBQJCYhMEXMkWBucITyRnNnCoKnqlBvd
         lNRSjGD81wFQ3WnSV5sgYYVThzjYjUZvzvWLIaSGChqsld6RnS+7xJx40xRpDBv8tJ6x
         rZSs7oY2MjtHgFAYJWJ096vcKGVAST+Bt2mWmnlgOPKrqb1PlfpI1/82C1BddlmlXJya
         zhzOxSvMx4J3f2bMOedSqYzrpzj7NrHo73hvJj8r/FvK6T3dP5Q5LWbZJong3X/GYK5a
         Ia9NEEuBKIU30Wj3q3AwtZgiAF760M9N+BqQoUIf4ptariHQ+JgJLjj+fKXHVS+IHVO1
         TDIw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=NWRarvld;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806911; x=1756411711; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=WdFj9VpLaQCJiREx1aP/8jwv8ts0uYfZVEvOBQC4NJs=;
        b=krGXg3COeLV0NBgtWgKt+cPxfiTGAabRUMxkcl2jAfr20sqq8EHJLwHH7CPDVKxQ4n
         T4QhImu797n1h1pRgDFCdtc5vuNHOIR/sNy+3c/mnuLL4fsVQbTRxWlX4GGSzzNJmss+
         o/pTVXEIPzRqkJ1t2ZBXQVVUt4hMqBBgcTBusl5LAu9HnxsxHmjby4kyQ4kJuu+Vbo5f
         cRc3D6lTg+CabA/zcsSDBdBq6cj+5dos5v9tiv85wfCJW8c9UNaaZcLxF9kjHgXsM+v0
         kvoVADhmfjz4RgzUmb016V1Z7qo5XNaneHcR4XMG6sulNzITAdCNrEBNhqMGLEy7ONJ4
         6g/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806911; x=1756411711;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WdFj9VpLaQCJiREx1aP/8jwv8ts0uYfZVEvOBQC4NJs=;
        b=rdOCnU7hRZydl0NJyxuU/dYRZCIBG2sf8Zix61QEmR31v/VsUu7kGPIGVHO3cHwrSY
         tel4L1kCQNjdNtDiQJkiLRB6ycyynglFQfEnBzj4SXcxBEa8lqpXfN9WpTv5PWqM4/Eo
         KUTWpCHGWUZae19eIP/8Ah+AJmqD7bhgJfU0vNozcc8nJTIQPYx1vJtYBwuIfPbNs+Ym
         d37cJiYcgmzJa2FurFhZPWy1bymf0IoCxAHv0iAdkznP/ud6iEzsOhjNhh7sAg2MqbgD
         x2AKF0FtAtgBll+SWDew7episxmH6EArgVd4t8+ZN79+RE03Mu2ymXkp1n/qpPvo1i7S
         3NMA==
X-Forwarded-Encrypted: i=2; AJvYcCVE6TnGn/AG2TJuMjIugXnoJYVqNrSAC/kpdc4bIqBXq3EJHMrb66xBy0VMGV6AmktNYCqSKw==@lfdr.de
X-Gm-Message-State: AOJu0YwzSpdjmlFeNC9FmX7hjEU0NeBmik9ns06dVSvt0uuM8bEl/6mU
	mTYftghJ+TOQxmXEA32wgIuS2FU9DQVbZS7SV55SiKGQKFFDI6r8xmwZ
X-Google-Smtp-Source: AGHT+IHis3HQCxMzR2kRlGtytRtjEX8jX5DneM6VAvyKa4g5ej6B8k3ylYLaia2VkdAwJo76E95mFg==
X-Received: by 2002:ac8:6f14:0:b0:4af:233c:4c07 with SMTP id d75a77b69052e-4b2aae2df46mr5820721cf.5.1755806910703;
        Thu, 21 Aug 2025 13:08:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc2zwYJX+wQw/W+PCoqP7pnv2CeGi4g+2D0+Lm6zSJYPQ==
Received: by 2002:a05:622a:4898:b0:4b0:73b5:1969 with SMTP id
 d75a77b69052e-4b290c225acls18276781cf.0.-pod-prod-00-us-canary; Thu, 21 Aug
 2025 13:08:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV8lsotIjoWWlgYm/LdywfKmwnpGY3s2m/byJTFQLQMobaAYHYr/kQgap9oAjQyF7tRY9xeO6MoY7o=@googlegroups.com
X-Received: by 2002:a05:622a:307:b0:4b2:9883:830d with SMTP id d75a77b69052e-4b29f9b5a0amr41615871cf.0.1755806909803;
        Thu, 21 Aug 2025 13:08:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806909; cv=none;
        d=google.com; s=arc-20240605;
        b=jOAac6+d2XKMmlZipljiFdNepNZttAI1SxA0U47jzHge2mGmW8QYBFDna32rqFcSrZ
         XEn3TjGu4K7Cm+zcT7aVfWdsYl6BX9d8Yhzq5QLlC2DqoCOTLbUZmgS5NK6RJp1U51MX
         ckf2n87Ungq5QCZHMkayPweGKo/MLptQyDjE9fh2k/BSHffj31b1ThxBHcMcKKtQpd52
         WU3/kxBmpCxISGXu+sywVt9RjvAJbPL9fAY6ybZ3S2PQfTWcX6wqWi5RQzpV3nKpPBaj
         h+LOBxLwtaGjBnramgeKj4nstbak9e2Op/izlEkC39Ag1u2bGQVH5obpcKvMMihIXGjG
         gXpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=yKmA6ti8X8/YIeKKq4I8EEiHVsObQn302mzSXytdc/A=;
        fh=ekx5BQvwkA3zVi8gu5QIruBs4DTUx87yzLTWK9tXdQ4=;
        b=fDSyBFjK5/P6zMxE4chwhBV1DrHKOpSuFBmBjTtLDlnPBVjv96ZTksmQQMGz/NPz9B
         s4iZJEoN3xSHs2wcXPmeqGiL0GFSWQddjB3uYFCjvbdi0k4ABNdLOZyb0N/D58mraF+y
         THAJZgE2uyHQxPLvOlmsGlvPJtyg7xUyvdzIOcf1RSh6pHibzWfph5VYQq1u0o7AavO/
         nXslGW80CHgfAEgyV2LYbczE6kBEMXpV7bXSZKhHDKm5g8QOkjXDSZuWEXc5ZkcLDb7R
         G3l1POK3/52AkZ9XvYBsTtkmegKfTj3ZvPFc0fC7jL0qLFnsmzJQxGbnypeT4MHr1ADm
         7gew==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=NWRarvld;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e87e0e54b5si41219685a.2.2025.08.21.13.08.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:08:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wr1-f71.google.com (mail-wr1-f71.google.com
 [209.85.221.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-458-Gnb7_wB5PF-Zg7DIO6sS1Q-1; Thu, 21 Aug 2025 16:08:28 -0400
X-MC-Unique: Gnb7_wB5PF-Zg7DIO6sS1Q-1
X-Mimecast-MFC-AGG-ID: Gnb7_wB5PF-Zg7DIO6sS1Q_1755806907
Received: by mail-wr1-f71.google.com with SMTP id ffacd0b85a97d-3b9d41b88ffso838603f8f.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:08:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUEo8qzHHwtOD73+iUoWFXaLLXGwN6A3tgE3WQhCf0CAPgqYGhYyDTbfhESacg2cWr+0FsIgypIw3M=@googlegroups.com
X-Gm-Gg: ASbGncsadjtvdlamBjO6b3BoPh101/1CuHqLv8d0VMkobEsPyzvwTL+yiWQI3Ewj4xJ
	bleJKKlBrHVG+wefgzwGfoZ/CodUZlMBm6DQS0SUDCAdp+FXtwFg/zeinkoiWyBA5SsccW4V/Gk
	DQ/B2/18vt6U9H0dCUc0SAoV+dGi7Wc5lI7/BlU9hie7jQdjaLykrvOIwKi7SmIFQQd/h86RXNR
	tYvnKx4JDHV5NYIVvqzjx14HJSzUSfYHnIBrKIpfKTu1+6Zheqqq9DCNXLYD0BmHCHPZQp14c2p
	wsKcHj/B4DbymhdPB+5TqnowiEr26QU76qyEkJ0V22in3c5gqhbIPCSEN0emADS/noLvHKTs5aX
	svugx4U0M/vfg1s5me3JXAA==
X-Received: by 2002:a05:6000:288a:b0:3c3:f134:28ba with SMTP id ffacd0b85a97d-3c5db2dcc73mr210120f8f.28.1755806906748;
        Thu, 21 Aug 2025 13:08:26 -0700 (PDT)
X-Received: by 2002:a05:6000:288a:b0:3c3:f134:28ba with SMTP id ffacd0b85a97d-3c5db2dcc73mr210077f8f.28.1755806906301;
        Thu, 21 Aug 2025 13:08:26 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3c077789d12sm12702699f8f.54.2025.08.21.13.08.23
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:08:25 -0700 (PDT)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Alex Dubov <oakad@yahoo.com>,
	Ulf Hansson <ulf.hansson@linaro.org>,
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
Subject: [PATCH RFC 28/35] mmc: drop nth_page() usage within SG entry
Date: Thu, 21 Aug 2025 22:06:54 +0200
Message-ID: <20250821200701.1329277-29-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: WWEIZIkW69muerw5Ji5gUn_jVOMMFc7cPjF-fcSzQRE_1755806907
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=NWRarvld;
       spf=pass (google.com: domain of dhildenb@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
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

It's no longer required to use nth_page() when iterating pages within a
single SG entry, so let's drop the nth_page() usage.

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
index ac636efd911d3..f1ede2b39b505 100644
--- a/drivers/mmc/host/tifm_sd.c
+++ b/drivers/mmc/host/tifm_sd.c
@@ -191,7 +191,7 @@ static void tifm_sd_transfer_data(struct tifm_sd *host)
 		}
 		off = sg[host->sg_pos].offset + host->block_pos;
 
-		pg = nth_page(sg_page(&sg[host->sg_pos]), off >> PAGE_SHIFT);
+		pg = sg_page(&sg[host->sg_pos]) + off / PAGE_SIZE;
 		p_off = offset_in_page(off);
 		p_cnt = PAGE_SIZE - p_off;
 		p_cnt = min(p_cnt, cnt);
@@ -240,7 +240,7 @@ static void tifm_sd_bounce_block(struct tifm_sd *host, struct mmc_data *r_data)
 		}
 		off = sg[host->sg_pos].offset + host->block_pos;
 
-		pg = nth_page(sg_page(&sg[host->sg_pos]), off >> PAGE_SHIFT);
+		pg = sg_page(&sg[host->sg_pos]) + off / PAGE_SIZE;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-29-david%40redhat.com.
