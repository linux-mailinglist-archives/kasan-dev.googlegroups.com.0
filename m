Return-Path: <kasan-dev+bncBC32535MUICBBO7ZTXCQMGQEOFQ7DLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id AC27EB303B7
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:08:28 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id 41be03b00d2f7-b4716fa1e59sf1129608a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:08:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806907; cv=pass;
        d=google.com; s=arc-20240605;
        b=N/9w3C7fLXFtRM9CI+32n2//fDLYmOpkEWMsCrC9zYAJesSWHvy/vvTtedd6KycKL0
         +iQO5VYDqj2j6slbCJ2KvHfeI9kORZaO2GZnb9O3sSAxkZBai1J202goiPCgfOHcCLWt
         KiuA+g6Qtzz8SPusmqX2iWCDrUm5bUb7MijtelgTgyVy7LKipJ3SbhoY3DkG6ffuYjd0
         vfyD8/zwMqR12OXVf4iPAAPLGisOqBdANXJLLu+Rxp072o3indcWkrqSa5vPN10Df6Hd
         QjHKKnFtB5ybLHHeKEsxUa0SK/PFY9EZ0F6pqEeCV7gj5lXq3x5lO+8pBSHp3uo/IE54
         p3Dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=2QpSkrAJepBJ4w0MGbyFf2Y0XtUazX0JhRKnoSjiWr4=;
        fh=WhrDOTT20RgLH5s+/97W8X/JctU4Fw36MAzXDbOkkq8=;
        b=Vi3Ac1Pe/DBUXSoQUuhLfqPYPz3Jcj7LFu2hurqNrt0/+3IMAO58TBhqgDcT0g79xI
         v/+zoMMAqwc9Rnj4/lrJ2kJp7tuWpaivoRAihWUq2eYRwraSA3kRx6vlKE0N4X5Jq2t1
         0jVMbcltwxmlNGYFauIpXoIpSm8d9YfGMXt+Kp1B8sijtOzQr7dA8N1GBful/Vw9oIa5
         qqhniWLs+yYDkYFC7udptbxesFvM/Y6VrMdzB5+K+K7KsUwYhCIDnzFGe7PZFNwl/1ZF
         fpecpFPH++4NNWXwBjOU8AWKMHgAqVtOtvTIVI9/A3de9lWtAwjkw9V+7IjLG4d8bouF
         qiEg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=CJ50KabH;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806907; x=1756411707; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=2QpSkrAJepBJ4w0MGbyFf2Y0XtUazX0JhRKnoSjiWr4=;
        b=X0KmZcE46eWQXfkLObGi8WecZ8xZhA73l3ZdcpHwtYInuKjz8BXJAWexxBiyqhTyBq
         8QWT2iyPhKI7S9pFD0hklJKQUos8BixV46M9fcsIqoCpk/5OEs0NEoIdBSKqqBo0vQN2
         C7HFFciA14Kwy0UrBGSqGuVCJfHXK8BUwVKOf8Puws8kd/L4T7u7aGgvC/bMzQc9+7m5
         sXbAdeJZPda6JzPOWqu7tIKGyDNpFTixqSXcE0cvYLUGqMWLXnZNIbF0Hijzc5V4WTeU
         fCLNMkCsqdyZe7aHSYpmXvFsGB5dy9a31YJ6GOokiJlC7VF5WQ8I1q9sf/Ba4SuYcgMV
         8ZVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806907; x=1756411707;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2QpSkrAJepBJ4w0MGbyFf2Y0XtUazX0JhRKnoSjiWr4=;
        b=NmE4xWoUwfWWW0kAH/thQPnh+C6HB79LixKs/9R9VUkyl0XZG70V3aMbfU7pS1vN6F
         YPtuAcHV0WewsffTgmQjEnnbF95Lx7K90ICQbHuB/KPKfE7vtxH1voJHFg94AKZWjeC8
         VftgRGODphixGpD2kTyK5VtDHoLM+3GaEqmVc/UU9wuzlgcngeqhnelL/fU37/rUdqSi
         DTiILlK3IuuIz99bpGpBAPdS+hrSYXHvou8N+vTFR/l8K1KsUcZJZuPmtHxTKds3pfNU
         UlHEcjxsdptB98xNivBMFUJmOdxAhOhyhINMCZV5m8+sE21WGSvzKr0qyKrAXpb8F7jd
         Y7dw==
X-Forwarded-Encrypted: i=2; AJvYcCWr3SZ/5w3lYj6FdVUD1rxH7Jj3Da9H2FPnXbBddnOuCauuvs1oTe6rrs4xpKMc/y05q+/zVA==@lfdr.de
X-Gm-Message-State: AOJu0YyTqhaJJXSJbA0GyQ5S/n7phX1Nrq/kaVnJ7VBsqV7zUK8Sl29F
	3JvLbhkZJbYEh9b7HWhEARruetcLI+psnKlq3FbVMtgoBw8XO2GTukrx
X-Google-Smtp-Source: AGHT+IEskr2BlTsLuHNVOdIJuurkv7/81XSMic/EPIbenquOQme0UHkXQ9oGn/5/qQk0soYicAQ2oQ==
X-Received: by 2002:a05:6a20:734a:b0:240:50d:4285 with SMTP id adf61e73a8af0-24340db081emr607708637.38.1755806907282;
        Thu, 21 Aug 2025 13:08:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZce2VLxkaMHY//B2qNQXs6iKWHdW1nADMX6zHxLLBGWcA==
Received: by 2002:a05:6a00:3495:b0:76e:25f8:1484 with SMTP id
 d2e1a72fcca58-76ea0147fe5ls1051830b3a.0.-pod-prod-05-us; Thu, 21 Aug 2025
 13:08:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUerWEjNUXejzGuSjAs3Apsf4USZtPOxgPg1Xo9GDYEXh97BpTtme0qu/S2B+fy87a1JNQSxTbKJYE=@googlegroups.com
X-Received: by 2002:a05:6a20:430f:b0:23f:f7ae:6e24 with SMTP id adf61e73a8af0-24340daf82bmr552758637.29.1755806905714;
        Thu, 21 Aug 2025 13:08:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806905; cv=none;
        d=google.com; s=arc-20240605;
        b=UdOIwVdzK5GwFVeBbwf7yFJ9cKINM6WQsD/olJxGAC0mpA+jOdUUVN1Ry6vU9tD/x0
         5z8MzXhMHkPfuoYf0XPZhINjZG7/59TvFbSVjmk8xklPbP8xqB8UO2gO+kB7l72B22xf
         SVn2MVsyGF/8PSAKdBCXXeO2hmiTyxc0YEAs2z11RUe1n/NBgZiFi6TgRgl2HzlGFXoF
         9Va2Umi7GhF8AxpFC6eP5yskyV9tUfYTiKwTcP185wGdwENkWuIaMuIjBaZvBn6qAigD
         KUGF5twTAHg4FL9RrcEHG0xh01dbK+GLxLrjeRvMk8DN2m+GEVGkn87QUf293HhxYuSd
         4Fkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5m4ogAvLOK+AKMqlHwhkjmyVbS/4gGgmBykcdwEFmjg=;
        fh=kM1O+L7RdIHynKIuKFtSeltvd3/lOm44nWD6y1VEenU=;
        b=Anr95M/HjXQAYJ48ikfdT4XUj/PWVpPoJGfRC08qp6drC8iRE3mIW4ucj1tPwBReMA
         yNTAimhBnXLOqXLKfqnOCC2I4LjX87+Tki2EGs6CCfKPm2pt9TVKOvJ7XxFXllgjJQqN
         HRWzWFGtFOBwHaJO753lq8V1VSOljlnrrKbQYyG1/N/rEo2RZ9hbijNuv/2QP+Dk3b/e
         sNGtTGuuks5ymNB9LrCgbh8x0D0yw4gDWXc9e3Uhr62TirdZ+5A7vapufCMfWs6qaC9i
         UvItQyM1F24AZ5qis8NmPz7HQVdKJSfrWNOW2dsb4wfJWu75Q/gkDceNtFbq9c1/dSRg
         5Lrw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=CJ50KabH;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-324f80d9c15si84077a91.1.2025.08.21.13.08.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:08:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com
 [209.85.128.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-668-E30Uwh_yMYS-zloxlaxvtA-1; Thu, 21 Aug 2025 16:08:21 -0400
X-MC-Unique: E30Uwh_yMYS-zloxlaxvtA-1
X-Mimecast-MFC-AGG-ID: E30Uwh_yMYS-zloxlaxvtA_1755806900
Received: by mail-wm1-f70.google.com with SMTP id 5b1f17b1804b1-45a1b05b15eso10523125e9.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:08:21 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWidTo/bHs0+BOP3JepLxFePMLzgpVpP1khuK1mK0aSzLtbcJv/iydyGG+i6cOKEqE3iAG53NyCrIA=@googlegroups.com
X-Gm-Gg: ASbGnctYab4PerlTIA04GWKkKNeh6uxNBohF1yvdFNkrq5y3b7FkGdMR6bwaUzDTVOS
	Z3CYaNV0+w3jny7xAX7y94fWTxYWNr5guLT+GvMlIksyQUWd7m8r8b1pHdIRV+6sen9rGEHdkAC
	IK+gK1A6WTTZ9lHdYfX3PAuq+0d91lcSnXxn5xbKEmvj9vmYMyI9gEX0TRNPBOlzHngH1VBWwlp
	GNTdk1hl653DPE3S+rMRfzzPqUlJaOyGdMEyjrJGdpyLtCRvhbw+B2TX5HVf+r2ELtmLNlXm8Uf
	yzz0eOzqFdu5pN2fxnYlpnECn/kyoN+wWcufB3KuS1rZMp5k/4anplEwqCgiW+0bgcE7FS7M3g/
	1U5tPV54JvxEP/GdkLT6o5w==
X-Received: by 2002:a05:600d:15a:10b0:458:bc3f:6a77 with SMTP id 5b1f17b1804b1-45b51f2fe8dmr510345e9.2.1755806900289;
        Thu, 21 Aug 2025 13:08:20 -0700 (PDT)
X-Received: by 2002:a05:600d:15a:10b0:458:bc3f:6a77 with SMTP id 5b1f17b1804b1-45b51f2fe8dmr509915e9.2.1755806899756;
        Thu, 21 Aug 2025 13:08:19 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3c07487986fsm13999227f8f.1.2025.08.21.13.08.17
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:08:19 -0700 (PDT)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Maxim Levitsky <maximlevitsky@gmail.com>,
	Alex Dubov <oakad@yahoo.com>,
	Ulf Hansson <ulf.hansson@linaro.org>,
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
Subject: [PATCH RFC 26/35] mspro_block: drop nth_page() usage within SG entry
Date: Thu, 21 Aug 2025 22:06:52 +0200
Message-ID: <20250821200701.1329277-27-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: c7r0UsRYwfmVqpvREFoRDeKPxN7xpvLLtLrSj7n6qpQ_1755806900
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=CJ50KabH;
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

Cc: Maxim Levitsky <maximlevitsky@gmail.com>
Cc: Alex Dubov <oakad@yahoo.com>
Cc: Ulf Hansson <ulf.hansson@linaro.org>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 drivers/memstick/core/mspro_block.c | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/drivers/memstick/core/mspro_block.c b/drivers/memstick/core/mspro_block.c
index c9853d887d282..985cfca3f6944 100644
--- a/drivers/memstick/core/mspro_block.c
+++ b/drivers/memstick/core/mspro_block.c
@@ -560,8 +560,7 @@ static int h_mspro_block_transfer_data(struct memstick_dev *card,
 		t_offset += msb->current_page * msb->page_size;
 
 		sg_set_page(&t_sg,
-			    nth_page(sg_page(&(msb->req_sg[msb->current_seg])),
-				     t_offset >> PAGE_SHIFT),
+			    sg_page(&(msb->req_sg[msb->current_seg])) + t_offset / PAGE_SIZE,
 			    msb->page_size, offset_in_page(t_offset));
 
 		memstick_init_req_sg(*mrq, msb->data_dir == READ
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-27-david%40redhat.com.
