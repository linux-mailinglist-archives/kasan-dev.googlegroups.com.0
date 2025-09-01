Return-Path: <kasan-dev+bncBC32535MUICBBRHQ23CQMGQEZLNGOUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 086C6B3E91E
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:14:16 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-771e1451631sf8506667b3a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:14:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739654; cv=pass;
        d=google.com; s=arc-20240605;
        b=bnfYdRI4ppxtcOtIstuahQ8XDLeubzEuFjQHEJFg2eO828Is0x6MpBtfLtSJsCflZ1
         k8Vk5aUhjJT95Cf9mrjfsvgUXSZ8mH4brT+r7QNqPRdS3kBVvYSq4GZNkr1UCSisAEpn
         pY3O3bpFZT3ulVz4XbyDU2pz9XF/eC3hZoNMiyzvfsPdRIUEKXtLuZ5/CBPFy9LMnZ7i
         B0xYfCPuHXmO0+w2s70QLPg1/MvBhC+rA9V9u1NyR3pRdL5So/6T4qfCoCLv63M1hsXu
         G4ZiB/A5mUM+2YtTV2nnJYZ80kbApFtiqDwavYGFB2Gr8ygrodXQEuOVpLtwFkyK0lsu
         55ZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Q+16mvC09bhaup4YvPu6nXM116QHEyA1PtzHqK312HI=;
        fh=INAS59HJQmo63QRNQZukO5T5ceMjrayKu1wY4gznMWo=;
        b=eljy05qTUMrCjkaU2Sdm/dUCLVNGzFozpE7f1EQhmCaGCFunRWWDOJc2GrIgXUgG7v
         89eIemHbk3jrySdZe0E1cLNOAYgOh6Rtms1d7UtTsdMWnZIFJBTmKgLmSfzS1yg3mrsU
         RREX1meKGgzWPP18G+rZ0juXb9GVNa5P8dBWHbaiKrzhzqQb4gVJDBNs77PVunns01zW
         yLrhU2HGP/G2cs/mh3MfJglnlrdCRY7wbLTA4+JcifrVrAr3IDewqE+rvVmb3ztvIh93
         V9LPyhBImZvjEpfWLhYMF2V30j/T1bN+qkxMVpGj5/Z/EH9YpvzHXWRFrBoQ1S6ITX+r
         aYWw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=YNb1THl2;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739654; x=1757344454; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Q+16mvC09bhaup4YvPu6nXM116QHEyA1PtzHqK312HI=;
        b=Cm9ovXXv/JTz/WNOEn5s2Ss3guJjaNwFSHcNa/VtSgk5lWfM1OFwCgwE6fU3KgETn1
         KOJHLUY9vzyrpDm+zlv8I/kmDx96twRVUg/0OfM3dsVOgkrGBHLH5oaDpoBr4V2CAE0Q
         N8KGRR6G+04MJ005Ze1DK1amB/hiiZhFnOfxa0/EE/s6VMEdOpgiUMlMIyNTPknfp2rw
         SoiVOu5zddqwdd1/0Ba7yd+3F1sNFMpYYHp51+vK5iycV9MB2dvO+AvcSyJpguR97bIE
         rUymAdBKpfd3e6baSpDKxsJ9lG1OyVO3kM0ot3uXD5QbUgpsAx89nwB3xIrz0p9Qp3FA
         KucA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739654; x=1757344454;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Q+16mvC09bhaup4YvPu6nXM116QHEyA1PtzHqK312HI=;
        b=c5sIzuwJvX5VxSQ4sCbpFwg8s6YCUvK6tSWnD2K4bIRJlqyXNBzI/0C3FqFOGHn3U1
         72050dayjgotJ92PceVE7WWob/wGEdXiHYRv6TtnO0gnNftCSShyb4Ksus4LeSYY0deu
         3LXuckK7vru04NrEvxM6f3XcmMKIvGW9hf2fHEAvwlRr43Cf8OztWvNlWYMd902z0Sat
         1LLchx76YPMH5WhrKwXEPskSuu5sHLTuyfTrcKfc9xyEpUSGvMXGe5lO0ZMWIJPon08z
         xfhX087SLkBsU311ROa1kdoOieBapEW0R9cUR/e//3joJXobn3AijVhCoEMTaHPWDjq3
         HUqQ==
X-Forwarded-Encrypted: i=2; AJvYcCUjGo35Gfb2rVnR89sNRxY7LT9GMrhcyYOdaTvL7jYEunELuanWIft20DLUU72KJGRf6ICHOg==@lfdr.de
X-Gm-Message-State: AOJu0Yy20ofCKNqAzdf52n7hDjw0nwpiFbdhHmMfNjFxj7gM0SH92oy3
	zpxVChWSdep0NPSTv+4ISH27+DdsU9hPPy/oHhM3Qs0Pr8wvzUle+cln
X-Google-Smtp-Source: AGHT+IHTJaennljSYFnYXmWoLFvQZhtS20z0AJUl8sOkvSlJ/AqM/F8pPbxpSW5D2MUX7UwOLYtmHg==
X-Received: by 2002:a05:6a20:938c:b0:243:98f9:a620 with SMTP id adf61e73a8af0-243d6f882aamr11497785637.54.1756739652574;
        Mon, 01 Sep 2025 08:14:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe2UhmTGDS6+y3jAydlsrvVL7mUOb+O3e4RM4/3rLE9eg==
Received: by 2002:a05:6a00:b47:b0:772:51f8:58f4 with SMTP id
 d2e1a72fcca58-77251f86b62ls1317642b3a.1.-pod-prod-03-us; Mon, 01 Sep 2025
 08:14:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWMBpjxewbqJgjeKJi+FW5bTX8ByLCiimg9I1AYbqp16S4m/sfipIQQVHAXVzGwvrEx09yRQ9mA0T4=@googlegroups.com
X-Received: by 2002:aa7:8895:0:b0:772:1fa1:be43 with SMTP id d2e1a72fcca58-7723e407fb4mr7712310b3a.30.1756739650318;
        Mon, 01 Sep 2025 08:14:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739650; cv=none;
        d=google.com; s=arc-20240605;
        b=jvO2kRDQzSmFNwLPdbpiOy16dF4rg26XVzVvI3jRZ2mjReGLw9SyLFstdTgruvd5jy
         ERswyCNI5ZvnpfY+6cnnmy0qVdgXVE4PTjPF2sT+DT+cTH3xYvbRLjccmYXnnw0gv+Ko
         Hc85sDueJrk3WhNgLywf3Vhfep2htPK5gJJz/VIGYUfGoIVgNaAwpUYapbJS7APZxk0q
         hDQPCN/dBPWg0PgW1brEb3AJHJpdzRKHmqhZTN0uqwiM4NcfXlqqOovDtktidfaKo92N
         9MNMbgoiXKsDo53TNqnJMhoTYBvixa60BUmXCc9wdO19i/n/e57xWyf4czhIeHh3K7bo
         fdSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ZB8VenTnhwuJsxCOtg12iGGVlRBSxMcM5zW2W1CE+LA=;
        fh=a+0inipWR+gxi2bF8fgHCUkmRRcEkdXajxBfbsdM2UE=;
        b=RASceU5fHRtmnolwSqQuXelo1d1BwCfMeA5SDMuovDhZV39/Y30Qday746RuZSfI52
         E+iYPMKMAQHJ34qCV2DTND38/Ap1JGlzHNy9gLQHLMG4FIC00/+r0qVYiHXA9kx5G5KC
         twHA2x9kBWIglmaNshiw7SHnpC9e4wSVYcuSPsMMPlit3wUrq0aTLCc/gwX+fwZhnf9j
         Amp6BAdM9kCMbTl5QI4YPlvb3YqXQO9ZxxnaY8neIMQEYd8Eyt4Ke6CK0xCBNRVlR33m
         +voR4Vu8iilSuKgZhoANF8vxMdRfTblVVEWQULh/2TLQQNIOYcwLyA8wc1/t3JuzXhSF
         mC5Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=YNb1THl2;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-772436d7ef8si204058b3a.3.2025.09.01.08.14.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:14:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-160-CInaJEnEOsyAhyUHiabiVw-1; Mon,
 01 Sep 2025 11:14:05 -0400
X-MC-Unique: CInaJEnEOsyAhyUHiabiVw-1
X-Mimecast-MFC-AGG-ID: CInaJEnEOsyAhyUHiabiVw_1756739640
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 6DCC31800342;
	Mon,  1 Sep 2025 15:14:00 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id C0BF81800447;
	Mon,  1 Sep 2025 15:13:45 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
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
Subject: [PATCH v2 36/37] block: update comment of "struct bio_vec" regarding nth_page()
Date: Mon,  1 Sep 2025 17:03:57 +0200
Message-ID: <20250901150359.867252-37-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=YNb1THl2;
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

Ever since commit 858c708d9efb ("block: move the bi_size update out of
__bio_try_merge_page"), page_is_mergeable() no longer exists, and the
logic in bvec_try_merge_page() is now a simple page pointer
comparison.

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 include/linux/bvec.h | 7 ++-----
 1 file changed, 2 insertions(+), 5 deletions(-)

diff --git a/include/linux/bvec.h b/include/linux/bvec.h
index 0a80e1f9aa201..3fc0efa0825b1 100644
--- a/include/linux/bvec.h
+++ b/include/linux/bvec.h
@@ -22,11 +22,8 @@ struct page;
  * @bv_len:    Number of bytes in the address range.
  * @bv_offset: Start of the address range relative to the start of @bv_page.
  *
- * The following holds for a bvec if n * PAGE_SIZE < bv_offset + bv_len:
- *
- *   nth_page(@bv_page, n) == @bv_page + n
- *
- * This holds because page_is_mergeable() checks the above property.
+ * All pages within a bio_vec starting from @bv_page are contiguous and
+ * can simply be iterated (see bvec_advance()).
  */
 struct bio_vec {
 	struct page	*bv_page;
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-37-david%40redhat.com.
