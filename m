Return-Path: <kasan-dev+bncBC32535MUICBBQ7P23CQMGQEODSU5GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id BEDECB3E8E0
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:12:05 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-329d88c126csf61523a91.2
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:12:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739524; cv=pass;
        d=google.com; s=arc-20240605;
        b=Up3EggW/aSVvTboE5g5q2fA7dtOfA+3XJVn1BlhZmml4DNGdPHDlV8yieRuVf4FE+n
         RXMuz/ZBUZVajYfeAi7WCngwEXhu91NkkyiKARzM9fy3NGTNl9LIR6lc5INDeOblWaHk
         UhA2GeU7MSKDo77ZLf8D3vk+BQX7fxwzpBNwv/J9z8k0aalF2+QB3PYPrA3/8jCABt6A
         4RlUlARKgpfZmYKzY3ECgK141vIP+SqPB83d1bdK/d19XGXwhUSWs41H8YT550fVTDqb
         EzDUtHgSVlXST1u5wR/D98WHYiQ0S8R+e5b8e4wq9gj7vQOGgmHvgCLJ7qY2u3ofFzik
         rNOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=18T6ZAVf75G/w8DbIRcM75sV4wOr4xcPmGdBVQ+hZ/Y=;
        fh=SatFl3xKfnxUZ3d/aB3Y1GGQt18THFC36S/Lis4x6H4=;
        b=G3BoRbPBDoLLUByQWZdycafGGQyoX+RBkssGhoDGqNj2suusRre9KWgq1YdHpjY1KI
         4fTUedyfmxMs/eO1or3BkVvBYG1kq+E3ueHRBT9Gn8a2m1n3GKtDfF7/XGimI/RN6QYm
         ABH7qkEV8wj3Opn5fe0VUsIjN2pyPY2XsQQXuSw12wJTjZ/D3FFQALy/H4H5xoCfiDjo
         KuEQ+uJ/AV0CwFtuHPytgKy1PoyusG1j6YKWXqam/4VOvG25Jnj8U7cNKeR0REiBUSl1
         Wsss2LgWIdXCGHtsDAUmkGpxEi5cvjJwr90PuhMDz0y0a+uYEsBbTPnr+9NhAEnLibtK
         elOQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="OeSI7P/z";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739524; x=1757344324; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=18T6ZAVf75G/w8DbIRcM75sV4wOr4xcPmGdBVQ+hZ/Y=;
        b=t3qFJxspTL7f/SSh4oJVJgU0v1KR1FvO3KnYzqv6JE+aLgjmL93RqSo+EBSZjlOcQi
         o2XBrBwIxhAvt9VYtsVS5qgctyOyasQ3jMJMuIhoYNK7668u/BQDatga5I8rnc5a6A54
         RwMNItMjlHFXP3epIYE1w7o0QYJj7FZX/BjGsYH43kyjlFK8e9Tu+eOeuCy5fAIwB/fP
         wXXzpckwl13TH3B1f9cxNd3vKD9Lyd7E2PBqid5Xv2jLcQOQ4oi2r0/uXU5ReZG8RMMv
         UVHXXBlbopTA9NXeBoD+QMg2yqiK31qiyOHjwTYxlbPVKlZfyh54808VzWypJ/PWPKS4
         7wUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739524; x=1757344324;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=18T6ZAVf75G/w8DbIRcM75sV4wOr4xcPmGdBVQ+hZ/Y=;
        b=v3CAfCbezzVfoOj9uMQ2bb0cnFtE3sv5UgNwrlydn01TJC8ALsVig51zNiVEXp71Yl
         lJU46SyAUsTuzoIFgfNu2WXdPXWDTvqJ5c616V72lbDlILp7VGevsX5xCXZmfq0gj3LX
         QPPzKtMnFZ6qPIJiikjjCRSnz/g59IJuq4PtSRKbuHXk3ilJv0KDBziqwEbD3R+a2uB2
         Sxde29EKEmoSIxODF2A1yiTDrMTUgMNRX14pRW/dq7G2Qs+fS8QlCjjG9Xz6zdulTE5P
         zTgIGLGycLjDUtord200ZkIr+W1TLlSGA3IRHaixY4IWDsTwERd+eO2U4MfkHbRHVZht
         7neA==
X-Forwarded-Encrypted: i=2; AJvYcCXp5v/YIo3VFbiRSz8YtnkEnXcU8EJxwtly40Nt1p8FJ+Zi4p5aBJBwd7PWRBXcLKdQAwFakA==@lfdr.de
X-Gm-Message-State: AOJu0Ywv1EZIbj8Gz1KuHhqh7/JHTPr9pbbUN8RpcYP1I2RZuWTf4iZk
	dJhYp6zzYmcmOufeIr3kwCAjXHPwwSK5O8lvpx/agbuGL4fZ0ghnLXVg
X-Google-Smtp-Source: AGHT+IFQGU5vnxic//1Vp5THL9TWDNknmj19zk80mG2lABxxKtT15OUGmtKBs48QSxSDGzwHwzQXTA==
X-Received: by 2002:a17:90b:3f08:b0:327:c417:fec with SMTP id 98e67ed59e1d1-328154515e3mr11846082a91.15.1756739523910;
        Mon, 01 Sep 2025 08:12:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcjAAOHYcY9ebt9KAgA921pvYX6//SGgN157VlxFeQFMA==
Received: by 2002:a17:90b:4c8e:b0:327:d8f0:e20b with SMTP id
 98e67ed59e1d1-327d8f0e3e6ls3822166a91.1.-pod-prod-09-us; Mon, 01 Sep 2025
 08:12:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX4PtZAJY9qm/3ZXEPTYYP7zIGB9Ia07/RIvsddNe/E8pSV6deMMCGSWWYddzFqWyknj/cqceNpeU0=@googlegroups.com
X-Received: by 2002:a17:90b:3ec8:b0:327:9735:542b with SMTP id 98e67ed59e1d1-328156e57b1mr12629747a91.35.1756739520620;
        Mon, 01 Sep 2025 08:12:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739520; cv=none;
        d=google.com; s=arc-20240605;
        b=cMC7gvkwrC1QTD36LthuV6rOvPuxIEz6hh4KVrGbicVtFroI1tmbg2+TJP1G9N6mPe
         rGE0qUKVPDGGhgrcukQuCpNefZQ3Qc9h4Ua3zGAK9ZFEvJAAK5rmubih3tiW945+ZgQv
         wyuelGWbjwepyhAo7HA9MQ+I+F9UvkDLTq5i6h82XzSGDhN+et+2NgUkhwYEPyKa7R4l
         tUXqGTCUcLKTVALD6xVJ1ZkykwprN3sMc0XQc4bmTAOtPDutsC8uRMlwtuwaF0qiBuqX
         o4RDvsw4pDK334ZDanVI+VALq9LTPGc04VSE0at/vkGWvHgmcPtanwotHgdE9x8JE+t5
         VM1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CbPxT+Idhc+6GwH6hstH+a12TgxrLcV9FQ+XUGXVJQE=;
        fh=fvedQo4vQjbZYpEFV+wFhJA/YMCG75fdLIq77JRWiy4=;
        b=Fz0IW3/ACJIUFIwmam1d02ncj8aeJyy+BBoB9ih9uyfGEjmmijP7x+lUBIm3nM/hdW
         5687niFUwV5mvNqDER0gZbJBp1D7WjP1Fewn/PPgoS1epuegGkppVkBK637BB3Ukj0l5
         HFQvjdDqtOG9uLHdb7ZZu3ZmgAcHVrqQ0UUDUTy91XykfozvsJakiCcLxZYagYoKrdfB
         8YGodlSXW/rwtQqQUx6SXmuFdIh0NjnFYSSv1qppOLJSqYyvq+4hi62gB5ud0mSSdUJC
         wN9cBJi+YgLpzgXqtDQsSXJf4G9Sd7RD/6fZ+rveX5hEPPNAWgYedT0Kh4yPZnG1i0ft
         OBNA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="OeSI7P/z";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3296a38df0fsi182670a91.0.2025.09.01.08.12.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:12:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-349-FAlU1mU9OFawvMcvPCgBRw-1; Mon,
 01 Sep 2025 11:11:58 -0400
X-MC-Unique: FAlU1mU9OFawvMcvPCgBRw-1
X-Mimecast-MFC-AGG-ID: FAlU1mU9OFawvMcvPCgBRw_1756739508
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 773F21955F0E;
	Mon,  1 Sep 2025 15:11:48 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 3D0F61800447;
	Mon,  1 Sep 2025 15:11:33 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Maxim Levitsky <maximlevitsky@gmail.com>,
	Alex Dubov <oakad@yahoo.com>,
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
Subject: [PATCH v2 28/37] memstick: drop nth_page() usage within SG entry
Date: Mon,  1 Sep 2025 17:03:49 +0200
Message-ID: <20250901150359.867252-29-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="OeSI7P/z";
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
Cc: Maxim Levitsky <maximlevitsky@gmail.com>
Cc: Alex Dubov <oakad@yahoo.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 drivers/memstick/host/jmb38x_ms.c | 3 +--
 drivers/memstick/host/tifm_ms.c   | 3 +--
 2 files changed, 2 insertions(+), 4 deletions(-)

diff --git a/drivers/memstick/host/jmb38x_ms.c b/drivers/memstick/host/jmb38x_ms.c
index cddddb3a5a27f..79e66e30417c1 100644
--- a/drivers/memstick/host/jmb38x_ms.c
+++ b/drivers/memstick/host/jmb38x_ms.c
@@ -317,8 +317,7 @@ static int jmb38x_ms_transfer_data(struct jmb38x_ms_host *host)
 		unsigned int p_off;
 
 		if (host->req->long_data) {
-			pg = nth_page(sg_page(&host->req->sg),
-				      off >> PAGE_SHIFT);
+			pg = sg_page(&host->req->sg) + (off >> PAGE_SHIFT);
 			p_off = offset_in_page(off);
 			p_cnt = PAGE_SIZE - p_off;
 			p_cnt = min(p_cnt, length);
diff --git a/drivers/memstick/host/tifm_ms.c b/drivers/memstick/host/tifm_ms.c
index db7f3a088fb09..0b6a90661eee5 100644
--- a/drivers/memstick/host/tifm_ms.c
+++ b/drivers/memstick/host/tifm_ms.c
@@ -201,8 +201,7 @@ static unsigned int tifm_ms_transfer_data(struct tifm_ms *host)
 		unsigned int p_off;
 
 		if (host->req->long_data) {
-			pg = nth_page(sg_page(&host->req->sg),
-				      off >> PAGE_SHIFT);
+			pg = sg_page(&host->req->sg) + (off >> PAGE_SHIFT);
 			p_off = offset_in_page(off);
 			p_cnt = PAGE_SIZE - p_off;
 			p_cnt = min(p_cnt, length);
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-29-david%40redhat.com.
