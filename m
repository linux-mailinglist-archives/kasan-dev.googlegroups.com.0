Return-Path: <kasan-dev+bncBC32535MUICBBT4BX3CQMGQE2BGLYWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FC5EB38C20
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:04:00 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-e96dc0032e6sf325601276.1
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:04:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332239; cv=pass;
        d=google.com; s=arc-20240605;
        b=GygEL2ZUQEjgZlgsL2wm942UURfKNmHVMVPENsePgixFJSgPyxKBxKcTvnH0/I1Mly
         OTwANKoIKVI1PMMpqjTlayW3XwS0+A5YE80So32ETDwGHtIhhwYAic6Q2Chag1IugXGG
         hCEIb74z6tO8YzzHBlHYCRZ9ohBCrz4I3UxjzEwNf0Wp1/nMb9rU++2h22RqH59yK6fS
         ETkcFaUsifPC13iPDJAoNTCQuWZ9RQhXcecQbPTYdnCUsWWm6s6UscvH6a5v1f2R1jjO
         DwnkGpDo0/9ajWXgpJdFxngW1QFJBcXXcNDkYAJ9xi3ZFjI+nsnfJnldhiX8iWvSrnQp
         HSbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=wOLmCGAdFFceR/ciNXGbSvLISX8CBebH0R0ft8e5LO0=;
        fh=3+Cika8MXc0ycPYQJO5vOzaidROjSdRa29lO2Dlw200=;
        b=gVIWQf8ruZR/qEDxSTBL36LNXHPb3Uk5iHStzs1IW6EL8I3/VgG4SfXNQmyyNO/Dr4
         Ftz3DK3/vOrcW2uZ8c5Ifu3RMYuvBbR3tqMJ3PwAzpnWXr03u8RN8keuxngt0G0ar3Bc
         sRkoN8r0hByBcIfOdnvBeejA791Bro7CzkfQLXqL0LymID5rhINpimON+P9OPAMjgJdX
         0VV8/K48oDQXDAp1Td2HpX3uVeHLlLIG2raohAN4GN20nTWhjLYtDCM7MflREAo85SAR
         QJyK7tjqO3ukwIae5JzPcE9zmrx0UsCZFewTdHkrUSjfHWRBf7uHerkF4kJBsfvmDPc0
         AebQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ZPoKmsdy;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332239; x=1756937039; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=wOLmCGAdFFceR/ciNXGbSvLISX8CBebH0R0ft8e5LO0=;
        b=V/VwnkQGVSKs4zxH2xF0THlyGMXfNVxuk0DCK0iRYWR2z27FlpaPVMTliIJqIAUhCP
         UPRqRz/++F8HYZHmSaxXVEVPPx1oztnCDRTZSRGMxCckIWmPCfHTM6hivDMXpfJLi8vW
         aG2f53cBbLnRgJ9P8Er3vfxxDIpPXtkcxsdEZZaLg3EHh1FnmhjYRRFBZuWJul7eY0Xh
         S2/eNZOb/KFZAIvs4NVaI4TP/3rOdYJx5K2C7m5+1GhZAJfX/grH0ez8QhZh4RSQFCmu
         ePE4C6YLFvxzLsT0if9wHEZGYqYm3i5f71mP7cpx907tobzvskJyXfptPkRzRD9Jl1T2
         j+aA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332239; x=1756937039;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wOLmCGAdFFceR/ciNXGbSvLISX8CBebH0R0ft8e5LO0=;
        b=Bs+ZMkZSkPtIZn20YmbLXilpD24IZwrj73a7rW6E8jhFScU+e2F5t+iZ9F8yeJUhTj
         4vCs6iRxvO/v3QuwdJkkL8VV5n8Zhq9YjXWYOFcnVPU1Z3luE0uGfF0OL8e+yZmvXHD5
         /DOO8haMw/4RwNQEdUXwEAmyadIF8pkBHkY9wkrE5c7YefeaTiEccTPS6TFJEmUHOYnO
         28gf8xG70/zfYt7C93s8qY+oTzKZVjmIRl4aS8j/iRiCSkKOVgvmEy4nEsIj8qbTo63G
         +V6/BoMrwkwcCEo10skrzoOmtst6KzHrhVi5Zaeo/MHUXuF05a2SPiWAQ2onpzbGc0gM
         QVBw==
X-Forwarded-Encrypted: i=2; AJvYcCWSDFO+10UaBBASDn2yFg7eER9zbe1BdGB+ZipDmcESxqaSP616f7P7eGdKE5Xai2lyFaS0sQ==@lfdr.de
X-Gm-Message-State: AOJu0YzNfrbJLgDxEjICAf6fdPJcr86MH61Q4SMNGYHbkCHvekMNDtBI
	GNNxCFZRbrMRORv4/TCNSl3wuR3ynt4jRMHVjmpQbdylqQRwkvK1tRFO
X-Google-Smtp-Source: AGHT+IF1x/hrWaKf2iQhR7PKniiCiN59iEZu8gvIyPW+wjzkoBUUOFoJs534lCxiH5hkwqDveQ9jSg==
X-Received: by 2002:a05:6902:340e:b0:e96:c71a:8a19 with SMTP id 3f1490d57ef6-e96c71a9c85mr12747641276.47.1756332239185;
        Wed, 27 Aug 2025 15:03:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcFc8OD+r4jD3spy13V95no8Z/LGFZ/ejIyVwcpWE+wyQ==
Received: by 2002:a05:6902:138c:b0:e96:ed33:558b with SMTP id
 3f1490d57ef6-e9700b1f7acls193994276.0.-pod-prod-01-us; Wed, 27 Aug 2025
 15:03:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUksEwE34W+ELci4QEPEW0C7yGIHZona//g0WsERCGRPRQLK1R/k13C4y/ttbm5tWw+kyf87Lx8wVE=@googlegroups.com
X-Received: by 2002:a05:6902:721:b0:e96:c483:3118 with SMTP id 3f1490d57ef6-e96c4834043mr14594758276.18.1756332238260;
        Wed, 27 Aug 2025 15:03:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332238; cv=none;
        d=google.com; s=arc-20240605;
        b=KQsP1bw/u43VVhJI2chN2yNe4bw2qcDJDJvMUDt8vp51ipBrClC99fQR5paldGghOb
         NNrD9S+egAlr96i/N3R93tvNG9eYXpHyDV2w3Ys6pnTRn3mRR7EaCrDsaf5mQSreJ9MP
         D2NeZjsMkN+yNuJq6OJxVna/XA4isn4JCyuO3iEDlGYLg+HzZzNmCySM7XpnlAkGJxrD
         HrJRsswGEXgGrr/Vic1DBp3SqlsNZnvfBDvFnXeI3aZEaOtCAyxCVYP4i8gleaODG27H
         dENzb8zIsHNSWH0qWm9Pd+UalR8qZGnhfAJKuK1FSYIX9RP2Z2kYpxAvfMyXKgLR3EKA
         +tqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0slYk4bfz75S649wa7kW6E6tBTFrSx9AC44N5jnD3cE=;
        fh=DsBu3SJmkLKY6VQD2NLA+PK7Pil0SnCiZidX3W9Xkiw=;
        b=QSywBaxzVw4wY/Td2pj54511WQgCltZsykh3kj4xAJEix7p7XzcNwzeo6BHxJDSRQc
         bVq4h11+8d4QdJR+yC1S+obW5g6t8hWjRVPkY34cqVekLBjIpsYPa+kpsGkUueVe2A0Z
         PXlNBN8mRj2Q9wTNZM4ku6NBC6reb1kSgk77qR86QJ2U6byIb+oTDv2E3auD9TmfeCoD
         1sV98KWKrSD45uMCfXGIDIe/CLrnqE0zuu5r6JZBqojzZL9kvDEIH4Vah9PBdesNmSbR
         xO/jOCOlwzhwKr07Fiwht2nDO7ke8NNVqb3Q8gmPLSrwhlCNWuRnARB04P9YDnYnyb6i
         X+oQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ZPoKmsdy;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e96d869d159si276235276.3.2025.08.27.15.03.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:03:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-49-Gig6YInBOwuPYECmvWEljg-1; Wed,
 27 Aug 2025 18:03:53 -0400
X-MC-Unique: Gig6YInBOwuPYECmvWEljg-1
X-Mimecast-MFC-AGG-ID: Gig6YInBOwuPYECmvWEljg_1756332228
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 7A462195608A;
	Wed, 27 Aug 2025 22:03:47 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 47BA430001A1;
	Wed, 27 Aug 2025 22:03:31 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	"Mike Rapoport (Microsoft)" <rppt@kernel.org>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Shuah Khan <shuah@kernel.org>,
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
Subject: [PATCH v1 05/36] wireguard: selftests: remove CONFIG_SPARSEMEM_VMEMMAP=y from qemu kernel config
Date: Thu, 28 Aug 2025 00:01:09 +0200
Message-ID: <20250827220141.262669-6-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=ZPoKmsdy;
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

It's no longer user-selectable (and the default was already "y"), so
let's just drop it.

It was never really relevant to the wireguard selftests either way.

Acked-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: Shuah Khan <shuah@kernel.org>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 tools/testing/selftests/wireguard/qemu/kernel.config | 1 -
 1 file changed, 1 deletion(-)

diff --git a/tools/testing/selftests/wireguard/qemu/kernel.config b/tools/testing/selftests/wireguard/qemu/kernel.config
index 0a5381717e9f4..1149289f4b30f 100644
--- a/tools/testing/selftests/wireguard/qemu/kernel.config
+++ b/tools/testing/selftests/wireguard/qemu/kernel.config
@@ -48,7 +48,6 @@ CONFIG_JUMP_LABEL=y
 CONFIG_FUTEX=y
 CONFIG_SHMEM=y
 CONFIG_SLUB=y
-CONFIG_SPARSEMEM_VMEMMAP=y
 CONFIG_SMP=y
 CONFIG_SCHED_SMT=y
 CONFIG_SCHED_MC=y
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-6-david%40redhat.com.
