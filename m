Return-Path: <kasan-dev+bncBC32535MUICBBO7ZTXCQMGQEOFQ7DLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id A2572B303B6
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:08:28 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-70a9f654571sf32214426d6.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:08:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806907; cv=pass;
        d=google.com; s=arc-20240605;
        b=YzlTlzL30SrIHKwLWcES6xPTVE6kMg8eKm8FaoInwYxuf+eJiJH4hjimaSYykJeo53
         oNXmnfuEHZ4AJ2CnZM6DroeWNoIIw9yE0gQbs2TB+yyKTlCDibo6e3+pneTn4MzNcvWC
         ebXaxD1LKFRCq4sP98z/KNmeMkXv2Tuj2Dq8ZmcAK8sC96zAAUKbKTBth420VQPpw6xs
         zTz35bTKMbdfpKZWg36RffFHTtD9cBLxA1whQMy0RYlltXr4TrwZpAvHT5p/DDH2n9v8
         A5fAyI5n2Hizvzc5v2zDCxY5c0qw9Ca76DmF/EmHUtncXES4S8PltIiDbnDdtEVvWiHt
         PG+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=vZsw9wLkKeXE6RhIgVojyA8sXeSUZu5g8EOBIcHBzfA=;
        fh=G5soAqsqyVvMKDMZFqQ6kZOJXYmiYDsaYHAK73MSIHI=;
        b=PCsSbHe+qDYNRg6hk4FN+jeJxUMva0e1BNcFAtqz4kdH74IpgPEubA8iYGIpfZZwJC
         moFd6M0vigZRh8EYAjxCQihvqgASXD1eGzeMmc4t+FFinwDPhKFBnmaO8AD3bNDgEkEN
         EGyiNprTiqDszzJtBxw54PLg7hXwcbGNWuVuQcoq3+Zzxa1WWp2KxgSy457qxLG6c/na
         LFTulcN0DVW8fk++hRbF0eFnadm5Rko3bi6qtD/nLJ4gr7fAPqNXOGpzxg+t+FR5g5AU
         8Bi87YxnNNtyNdJHpXrF0g/fiG+ymgOkMPF7jrrB5H/hSpyXIV9gHBiYDxkWYiS4BWaV
         zzxg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DpJ2gAzW;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806907; x=1756411707; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=vZsw9wLkKeXE6RhIgVojyA8sXeSUZu5g8EOBIcHBzfA=;
        b=atrCO+vcxM4GmYNkAXo7SZxgsG8IOLq9MGvWtix8WZ8TueiPeekGjdNqWtrBptmgEc
         RDN4tkVUbKaMHLG2KfCySW2XBgfi9BbnrP+//bdHPD0xFp9nM/PVc6jxyIVKl/SQFRcF
         jD+kXbhRQnxQgpj9JBj+VeJcUOz4fJqCKziX3XILoa0OsGacDFo/N2nrR/DA2ofEc/tj
         FVX8nx/CQsHw0+z3lRNvuPpAjHLKp2yUGd5xlpE/GkvD/G5mSgRVkRxVMvltBbquEB+x
         LaEx8Y6wZ0Oj7oa7qRq3h6RTnNLxDQF2xb7rfJ4RPJVkwcywR/yPBUnDR/aEnKbhbEJz
         7i+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806907; x=1756411707;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vZsw9wLkKeXE6RhIgVojyA8sXeSUZu5g8EOBIcHBzfA=;
        b=cIacJEObb+JdJIMVSlzz8KvV4qiJNgelPO9d51a0TxEkKTPLRm3071673WbJSLvZkI
         UvZ7f9P4BGiTmJrkrZYWMVfxROB73L2lo4TmYZMXZ3hIukR/GLNx1TuIof1FeB7kaQE+
         L9N9bzWRTNLWnLhJZLsgaaMhQyw3eun57S1xd8Cj+rOSP3MZ/mZM9fsK5A9reXLmgRwP
         alqgG1L5BsT/ulxXVUma8a+bks8Q2Ju8xQrz9kDPgGoh21ZDm6wG9BK9M+Fk/MNpU0A1
         B4TEetQlfTr430Qd99rcpIakZRntt3UkATOx6GkBZKJd4mjbrm5L3geKatl4Qr395rZZ
         gYog==
X-Forwarded-Encrypted: i=2; AJvYcCWNPY41aMyr8t+WdE+maXTJRV+jZkXmtAkiGhXvmO4qXqCvCjI983/7bmrSUHRpDJz8ZzY1OA==@lfdr.de
X-Gm-Message-State: AOJu0YzZf9mCgIMJLQiiGSYRDgV1jGENX+JqTriZaUvxBtf1lodo42eH
	INwjJhcVn3zLR5z0P87jYkSszp7NUnUih/piNxd6yedU5QEA/87XBJgD
X-Google-Smtp-Source: AGHT+IHk7v8tz0rfqr8489B/b7LHtbbBvMCGaGxj5IXFIz3C8skMAmWQdCvvz9ScNfTJ5kB4jEryEw==
X-Received: by 2002:a05:6214:262c:b0:70d:6df4:1b1b with SMTP id 6a1803df08f44-70d97237f5fmr7917216d6.56.1755806907523;
        Thu, 21 Aug 2025 13:08:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcpez9b10nTfnRa02uWPbgVSTKK9F4yr1t1H03O1lzKXw==
Received: by 2002:a05:6214:d45:b0:707:b7f:69d1 with SMTP id
 6a1803df08f44-70d85cc9d40ls22652356d6.2.-pod-prod-09-us; Thu, 21 Aug 2025
 13:08:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUFLdrfhvj2pZpOa5qnEF+oU57NFol+u4zE+qYXoOXzZwGL66xrVbJyOa9PO5WOQlIJnOfL4jbQiz4=@googlegroups.com
X-Received: by 2002:a05:6214:62d:b0:70d:6df4:1b18 with SMTP id 6a1803df08f44-70d9720e4demr8091106d6.53.1755806906652;
        Thu, 21 Aug 2025 13:08:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806906; cv=none;
        d=google.com; s=arc-20240605;
        b=aROJ37XuODOc2iw0j/S5VhaJ1REiGYi3FLU+bI0/fGYT1rMRbRSz2HL5tPyUUs03nx
         4OAZx7Aal61GG5sU5unYUMH17yIJQg4ZjGoiUxEnPpWo0u/DeOaMTT6fbGnBcF8Lotfi
         w4It+CspRM5P2QAgeFTirBa6Za29WWbCapKuaNxE17w3CtWl2cSx96DWV0TN/rNAZoAf
         H3rUFFOrQGeNTtqm2O6X7y3ibPGcqJGuAXkCvu1azsYvVCnlzjAh0ISHAkIK99K48ERs
         rpYz5BsGbGz3je4CKtGleYWSdq5RI0+A+w8MeEMHcG5CBxTElXO8MSakHu71UyShPPhC
         BbfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=yR/3u5W37RASrGsn/s3pQVQ78UUgH4ByCavV3b4UG3M=;
        fh=1AD0Hwno817yWYwpQR+5997WtAcT2FZ1PNlnQ96nyAc=;
        b=iDxm9cMIQtQq9TeINdeY3oQ15SsWHr3Wqw2vLMRmKHAh/KA+JPC2KMTwWyIO4U5MRs
         NWbaDvnoZ1m/1Z570KozFSD1c/wotIAannuWSyEC2y570rMtj6ykYaZxXr0dXNuh3ewx
         TUzxJWuW4YVMtfytNWxUIgxUhBciXu5Ylnqrxq+bycdWHgb4rNJe+sOLKbmibRRIiFAR
         yzgW09cNxVpf/6Ljp4VHO0eReilwDFf6pKiMgcU3VHqPQF1PFe5b4E24oZ1IYDL2WubK
         ++J6OnbwvjHdK1m2JT+GXT7puokxjMJd821JICeNL1vHTpcZyIVvJ2yrrAR9QjO9+qJY
         TlzA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DpJ2gAzW;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70bcb1c7b8asi3980176d6.6.2025.08.21.13.08.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:08:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wr1-f69.google.com (mail-wr1-f69.google.com
 [209.85.221.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-374-s_zDCEXRNXO6Fq93Vy3I_g-1; Thu, 21 Aug 2025 16:08:25 -0400
X-MC-Unique: s_zDCEXRNXO6Fq93Vy3I_g-1
X-Mimecast-MFC-AGG-ID: s_zDCEXRNXO6Fq93Vy3I_g_1755806904
Received: by mail-wr1-f69.google.com with SMTP id ffacd0b85a97d-3b9bfe2c601so767113f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:08:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWwOxkzJOGWiaaEheqFzm3HUPEq+66ROEIzf48qHzV6WXxOOG/F+YhMKBmCsZx+wHHj6dlsaFg0zhs=@googlegroups.com
X-Gm-Gg: ASbGncuVQwx0oz9kNL1WtWg97o7o+dOpZ5/x+5s2XGQH0pm2TCOAKZ6369U1te88aIk
	3EvvjY2fBEi7EzNXdWoXK7CAGFDpQoQP+zpSSIuog6CQl8yd+AaoCy2kga8/B5M7OGEJkpnvlGV
	Y8Z4aKGQEDgbTG8JZXG09NEeBVIfO/BGWGi6xgHnE/koTXBjeaAyzgrneWDRU5xOSKh0jNBBCnU
	vuZBseFPyGAF34hQvOjgon4dMf47N9OXnEOnfyfL/GrW5w5Ui/PKm5f+rU1cU24wg0OJBc9pbml
	6SR4v+pKe9mNldnWuvakRORoqUMeZolaDbwtGlkvryX2o7X4w8VhEgDZCdBcd5AwZhcejzQaGLR
	PP1xu2j+tTg42fA3y7AdU3w==
X-Received: by 2002:a05:6000:310e:b0:3c3:5406:12b0 with SMTP id ffacd0b85a97d-3c5d53b40abmr247267f8f.30.1755806903616;
        Thu, 21 Aug 2025 13:08:23 -0700 (PDT)
X-Received: by 2002:a05:6000:310e:b0:3c3:5406:12b0 with SMTP id ffacd0b85a97d-3c5d53b40abmr247245f8f.30.1755806903113;
        Thu, 21 Aug 2025 13:08:23 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3c0771c1708sm13032145f8f.38.2025.08.21.13.08.20
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:08:22 -0700 (PDT)
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
Subject: [PATCH RFC 27/35] memstick: drop nth_page() usage within SG entry
Date: Thu, 21 Aug 2025 22:06:53 +0200
Message-ID: <20250821200701.1329277-28-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: Q_zijXFwNcUqfa6C_p59QiaTVGvwZYn2wcN-kGx1ZPg_1755806904
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=DpJ2gAzW;
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
 drivers/memstick/host/jmb38x_ms.c | 3 +--
 drivers/memstick/host/tifm_ms.c   | 3 +--
 2 files changed, 2 insertions(+), 4 deletions(-)

diff --git a/drivers/memstick/host/jmb38x_ms.c b/drivers/memstick/host/jmb38x_ms.c
index cddddb3a5a27f..c5e71d39ffd51 100644
--- a/drivers/memstick/host/jmb38x_ms.c
+++ b/drivers/memstick/host/jmb38x_ms.c
@@ -317,8 +317,7 @@ static int jmb38x_ms_transfer_data(struct jmb38x_ms_host *host)
 		unsigned int p_off;
 
 		if (host->req->long_data) {
-			pg = nth_page(sg_page(&host->req->sg),
-				      off >> PAGE_SHIFT);
+			pg = sg_page(&host->req->sg) + off / PAGE_SIZE;
 			p_off = offset_in_page(off);
 			p_cnt = PAGE_SIZE - p_off;
 			p_cnt = min(p_cnt, length);
diff --git a/drivers/memstick/host/tifm_ms.c b/drivers/memstick/host/tifm_ms.c
index db7f3a088fb09..0d64184ca10a9 100644
--- a/drivers/memstick/host/tifm_ms.c
+++ b/drivers/memstick/host/tifm_ms.c
@@ -201,8 +201,7 @@ static unsigned int tifm_ms_transfer_data(struct tifm_ms *host)
 		unsigned int p_off;
 
 		if (host->req->long_data) {
-			pg = nth_page(sg_page(&host->req->sg),
-				      off >> PAGE_SHIFT);
+			pg = sg_page(&host->req->sg) + off / PAGE_SIZE;
 			p_off = offset_in_page(off);
 			p_cnt = PAGE_SIZE - p_off;
 			p_cnt = min(p_cnt, length);
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-28-david%40redhat.com.
