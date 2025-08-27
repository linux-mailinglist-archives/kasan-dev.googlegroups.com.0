Return-Path: <kasan-dev+bncBC32535MUICBB4UCX3CQMGQEDY7ASSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113b.google.com (mail-yw1-x113b.google.com [IPv6:2607:f8b0:4864:20::113b])
	by mail.lfdr.de (Postfix) with ESMTPS id 35E7CB38C79
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:06:44 +0200 (CEST)
Received: by mail-yw1-x113b.google.com with SMTP id 00721157ae682-71e7d652a65sf3492217b3.1
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:06:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332403; cv=pass;
        d=google.com; s=arc-20240605;
        b=JdQWmHV4WEs2ftmqMFide0iYb7s6anF0nzRsjC5XoL7gH+pdshGzXKoNwvlQ7lXCux
         h+8MLMp9zOchCiINDoP8t9wwiC9Bo7QslN9EfC7z33dJE/UJ4B3Cm7fT+oi2qvqQnwKP
         lBwvgTm+cyGpooJ8SqHuaGLvpmUhZt4CGlH1ptD93FH67Simjc638CDvZVT48UbW7T9J
         mhqnoNM9saID2iA1kPXHvLCK2h8dIOx+OYx4joQwFlJVD9UqtDW0WsbLEM1ZhrvdPLo5
         kODwj2epE8LQl2RXRKW8EvpDeug/9WwYBET473GO+uMZh4huMazxMMNgvFQYTgdup6sJ
         swuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=qYUmxHwMbppkHuMxiaDNBv1VBSuTc9Yg3AUedNOYZyU=;
        fh=Oei0MqpNnZlRDbKcUgf3yDI/IUyKzSj4wRUq7ps04Vw=;
        b=dpMSlKrVFDOkjgFO5RffX/S7CmCa3sCoF2/mkHgw5rMnTs/UgOd63leUn3pgjUb4wb
         KbAaOMZYg/H+/brA1JMvAqLVibsKc5hMCCRSZx0Qua298Lan5BaIilTKG7CztV2hfqxF
         +eGxyUXHHlAPzLfdCZcg+HPm6kIhyU5lmCKiq1kLh8Op7mvzj/Cn/gOzbWaXhy2dlQrm
         AZoPvcwnqXs6F841BS454nBGJXQmNKGSHgqBlpQJ9s8g3+GzyHYWCCCdDpauZ3J6RznR
         uhPPKqBEhvFmrOACugzWbgww5s46Nhl5FDtNeQQB+sE8CFwHqGMEg9gyrh5pn+o+ZTfV
         56kw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="EVtd/s+S";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332403; x=1756937203; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=qYUmxHwMbppkHuMxiaDNBv1VBSuTc9Yg3AUedNOYZyU=;
        b=TNN5xVYCX7sphdA/z6zKBGAYYdLg8t9NZWVIosGKGWTjS1ekU5IMZtKIHPFct6dHGT
         ZcnUt7RDGesWfXZgpNSn9aDjJJ8m7fcgP7/UVaFaO9nN4S9N9MY2I3iy1CY3DyqLZCZI
         /WXme8AInEV8dsdv6tB8Eg6VFy9NVX75amW/chK67G2AsKYEL8BWSzmEsrjRMZ6w0nwY
         GklPmXdiOySwoQS11v3KGSy++aMT0Buu9yN6XAgx3FDBS3qmCf49zn2lSrMgzTjSZD0q
         FMFBPRsDe2gxxc8AiIPiIbYKXDcw6G+NdyM84anY18ez0BsrgQtD2EFtTzPSGGbhjxzO
         w78g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332403; x=1756937203;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qYUmxHwMbppkHuMxiaDNBv1VBSuTc9Yg3AUedNOYZyU=;
        b=lFbvVlzLn5N9O5WW8TW/bOX58Z0HAM+TmR/Yh/5ULNMsdKj2+0brTZRHt+sT7faj8V
         zl2oZuWXPDt/49cGUeXcAnY0qdM1laKP5uSjDyh+04R03tixzqOCmNA3sAPO9Wf9omZ/
         NxbjVKsaRytZRCXNN8yP8ueSZWhTqVQZfEIJlVZRAYBvZRJGQsQG8CgmD0IsrwMxkt7f
         Oe3UacMtP4pbr+qQUBqR87aaYUajDllANIRsi6yOK+s0JUhMPkOiyUv49TgBpnHlLG1u
         9TL8WjITFZ1ZdshC+Z104IGiXiA32l8KdxO4+l8cUNNo8P6Cp+/yWP8hirX3UbOvJ600
         cnEg==
X-Forwarded-Encrypted: i=2; AJvYcCW6otdABmEBGAs6Wpi9qwhC/KK6aDc9kUOUf/kxY/vhsoiWvH7rx2P66e8lF4zpKJfoXTPMyg==@lfdr.de
X-Gm-Message-State: AOJu0YweUD24JQFkqSyIlAf1x+vjnAF4pfvivOVY5yJA/TZFEsW/9U9z
	loe+BUFopVu6hGhlpwEcLTnsjT2VBwAg8YIIleVeK5wuNmxsQkXLeHQI
X-Google-Smtp-Source: AGHT+IGC3CfPdpq8KUkdC7zYZg8azv/YodyOi8g+rNLw6xt3Abf8gyuPpXwwhfvIJK2e4YFmKXNdGA==
X-Received: by 2002:a05:6902:140c:b0:e93:3738:e0d4 with SMTP id 3f1490d57ef6-e951c2e64a2mr24536139276.13.1756332402880;
        Wed, 27 Aug 2025 15:06:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfHKtjnQDodgGqt986OkvFFDDM1zY8OVHimN2eHNFAY6A==
Received: by 2002:a05:6902:138c:b0:e96:ed33:558b with SMTP id
 3f1490d57ef6-e9700b1f7acls195864276.0.-pod-prod-01-us; Wed, 27 Aug 2025
 15:06:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXTud56XARCCtna2QqW5t3Bi324Vw4aVr78T6DaG28sjRjC8HQ5/tM5JqrC+G2113JQEt7ZaaJ7Jyk=@googlegroups.com
X-Received: by 2002:a05:690c:f86:b0:720:b0b0:e514 with SMTP id 00721157ae682-720b0b0ebf0mr144532037b3.49.1756332401411;
        Wed, 27 Aug 2025 15:06:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332401; cv=none;
        d=google.com; s=arc-20240605;
        b=g8V0BCbwxsPnryb35fYu19YciQD6gwCYLBOWYS3yjMJLHrBZiVvgX/aLRxgGHzpBve
         yz00nSgGiy+cycZWXzqs4bBNMQroE2jqEphsTgVVNVJnw83ejV7zaWk/6SYEzsf2lsYH
         cjih+wEZMu8u0DgCZzrUTPpp2In3xZrZpkzh9mx9h5UgAxNGTdcy3eApreW42usOjKgF
         xmeZK83COiTV0bH1EPHnvHWjJRMV7t/xjDCVM4pbqzk8T8V4vPyoSFgO5bcfy2P5Uz4Q
         NpOOFmpE96ZHE27zIOc1184IKZ0lrcUMbeudxcbUutUgPLhgrat/UKUykeyV4aEp2j5S
         O+3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rjZeFWjCbDhCMUqSkeYcKpAMeyN7QE5gKijkCrCFfpU=;
        fh=b8pL5mxsrifaEynZEGzAqvQF5L+S8U+H1jEuAVk/IKA=;
        b=ZLgocjvPehgHtDW8n5mvCUZHe5+Hmc9q85sIJ45IPxgNJfkzjh4JBgwpI76aCBRAb7
         zBlTTBjmkdqKXQQA4oqncoNL6epV0/fPfIIRBItKgGq7QpcH8qPQsYNlLJGUmGU5+KZK
         xbP6U8Ve6MsZNEMKTjbGAZllEux3tsiNREd4bzj1Dhw61TIM6AKQ3ELRsmAvVZuJBzyj
         m2uCDNTdxyOsGF6SJoEMECoNmlAg72kkOFLlTumZO3PMpL1ZyvV4hvt6n9D4aseXE40v
         HbmclC96RHLfansGbACtupVTBc9AcD7pRZ7LXrHe22JOeCQk6KKbR8p/OvjzWuruxlqo
         KegA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="EVtd/s+S";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-7212cb27f01si2476487b3.4.2025.08.27.15.06.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:06:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-553-lA8LiC6sONKppwkqSITe_w-1; Wed,
 27 Aug 2025 18:06:37 -0400
X-MC-Unique: lA8LiC6sONKppwkqSITe_w-1
X-Mimecast-MFC-AGG-ID: lA8LiC6sONKppwkqSITe_w_1756332389
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id F080119541A4;
	Wed, 27 Aug 2025 22:06:28 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id AB5F630001A1;
	Wed, 27 Aug 2025 22:06:13 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
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
Subject: [PATCH v1 15/36] fs: hugetlbfs: remove nth_page() usage within folio in adjust_range_hwpoison()
Date: Thu, 28 Aug 2025 00:01:19 +0200
Message-ID: <20250827220141.262669-16-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="EVtd/s+S";
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

The nth_page() is not really required anymore, so let's remove it.
While at it, cleanup and simplify the code a bit.

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 fs/hugetlbfs/inode.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/fs/hugetlbfs/inode.c b/fs/hugetlbfs/inode.c
index 34d496a2b7de6..c5a46d10afaa0 100644
--- a/fs/hugetlbfs/inode.c
+++ b/fs/hugetlbfs/inode.c
@@ -217,7 +217,7 @@ static size_t adjust_range_hwpoison(struct folio *folio, size_t offset,
 			break;
 		offset += n;
 		if (offset == PAGE_SIZE) {
-			page = nth_page(page, 1);
+			page++;
 			offset = 0;
 		}
 	}
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-16-david%40redhat.com.
