Return-Path: <kasan-dev+bncBC32535MUICBBM7M23CQMGQEKLOV3JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 44F4FB3E835
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:05:25 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-30cce50fe7dsf1666689fac.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:05:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739124; cv=pass;
        d=google.com; s=arc-20240605;
        b=gTeiY6kSJ7sVok8Q0+DtFPXP79f4iUFmzdaCXXgMg7coiporkACzwKXLK+3TP9aSqe
         LR+zt109QqvkrS7Ki50bWUzh9TWFA6j68tfHAthF3T7mVKVit6qMgEk1PMKPFlY3ha3C
         WXb/PGBb4nHyilTpJU4ankS8O+ZdxSd2Ha6ydqejL1UsP/3j8TzBnP6vrUz3a3FoVqqG
         CMJLGTYlwp9dtNvxmYa2gNT926j+CuTgBHsjKce9jEJk2mTX+8t0L0uDnh6ndDYgz4Ch
         7jyDFzX5KVoj4NvftpomrF+NF8U2Xg2q6d/ItRvYlu89bEezg4djaTEqQrslGzHphBkK
         Gsdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=rKUExlHagoWOnI5P6KoZ/NuftNFsh46Gqcajl8wjh1I=;
        fh=Z2Od2vIQ0X6MT65czFsTZUvBLauHK19AAYe5fkmqawY=;
        b=N3wrnD+IqdfNDUaY924RKQiR/qMc92yCUatYngjm42uqJu1NBlD+H90/VtNyhiC/v9
         72npe0qBylYGXYBFgzDl6cfZQv+yURSuN02/D3/eslcXD9m6hP9F+xFSsGzT4AJyE801
         wCw3/yPTpj2UMjzkBQxMA0z6ZDmPH5Qd4lmoFvFmart09z+eCO4jmybbWlGY7MpEEPOi
         YHCYgp0vFpSkXIMvinF29+avs3Z3LWh4QT0jNiTN+hfaM0Kpk3hp/NRj7O6FhKxhxHh5
         tQD6Xwc6F2WMtn4OhJUtwmELz9VW9Txq4qMhfs+OSr8DCzJHthdMDPD9J7525RzpgeUZ
         t6rQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=D0uxajqa;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739124; x=1757343924; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=rKUExlHagoWOnI5P6KoZ/NuftNFsh46Gqcajl8wjh1I=;
        b=AWsgDXHSx9F5MIrExgs7ZhrEPIAe8EulxGfrn6IzexKG/4pYDg3M2d5zz0Ltm1GkwS
         CaAX1PAe449F9Lk0OTWywDThNtL4RPGWVQwPNREqiANSN6u/Q2jxTseA9zvV1FwSqgHC
         W3Qoxp+rnF80GpPQhEuKZaTR1SdEaG0A0WA62q1mWK238WnD40IAP8B2xl7Z8hMfNeHK
         BDSnJj3INdxTaQ2NuMJCp+S4D7jk4bLVm32GTBPkrYXCLUWA/QXAW6X8entR9+5MsT8i
         iL6PB+V7VvIQiiE2jt1vdH+VKVXBgOxZhRxBThQSd/pGbodaosNTtHP0V5fcDxugv7Yw
         cABg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739124; x=1757343924;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rKUExlHagoWOnI5P6KoZ/NuftNFsh46Gqcajl8wjh1I=;
        b=sJp3YFPqLfShqn4hnlUKSFYnkOFvboDlxVVh+zoQbIIPhU5pnsa7blbKSmcuxH6I4s
         S0Ux+U2uNFBxeMU5KqFrAUypNIpP+TfbaJhCVAvzgFSJHw+yJvELEJx+M1x+I8V6wTGZ
         NE2DLew4IcFydxzMdKCdBikkPQ5IQDdrh0ikfmnvEqwkl3Jc0cin/+XVme+btTSW/6rq
         Yka5ua1ChMM3TFzepczzZcd36Z9dcmPO/0dEGTQwc5Z+UudBukVzOmPBy+A9WHcOvIei
         F/5X1OJse/kuYor2OkfBsLEgbDcxB2xOnyvAp6yAklTJeoJErnThzDAJIKRmL3Ty36u+
         bvjg==
X-Forwarded-Encrypted: i=2; AJvYcCWZyEHG4N8cEBnXQT/FOSDy6qjnAy4RU44n8ehxvuG9fOw1Lrohsi7fSThH0FzvwK2rJlmbvg==@lfdr.de
X-Gm-Message-State: AOJu0YyfmIVKEJRZ50ISp3BMP2HN1orBBpcG6fVhXhTCdDvL34lHm+1N
	09oOPyDDxm9kdQeiTZEhkfd6hhXMd3s/J0kFyEBPOA9wFbE374zBf39w
X-Google-Smtp-Source: AGHT+IERribK5KegTmHsZimBDC/5GmX+8KNx6WkOIEPfKs2T7f9/Za5RJ3yFGI1Pv1A7jYShupIVZQ==
X-Received: by 2002:a05:6870:5ba6:b0:30b:ae56:578b with SMTP id 586e51a60fabf-319633d8fb2mr4164900fac.39.1756739123532;
        Mon, 01 Sep 2025 08:05:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdNRrOhaeg90mqd2gu7Dru3Z6pktvcZIZ6i83rCaDk6hA==
Received: by 2002:a05:6871:58a9:b0:2ef:17ae:f2b0 with SMTP id
 586e51a60fabf-31595d603ffls1413542fac.0.-pod-prod-06-us; Mon, 01 Sep 2025
 08:05:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUJlzu+DdX/2KbzDXNoRLcEQFnwR7Yko0kOrKjuy2Ngnr9X0aXLOw7rum/HzZfIiwtsdb93BE5v1BY=@googlegroups.com
X-Received: by 2002:a05:6871:7a0:b0:315:b513:a6ef with SMTP id 586e51a60fabf-31963473ee1mr3654740fac.43.1756739122192;
        Mon, 01 Sep 2025 08:05:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739122; cv=none;
        d=google.com; s=arc-20240605;
        b=LOKWSMNyveyEZwUKbEqxi/Sk0CPyCR6lgFqptBIKJNIjMMFgUwsnJyTQBercv/hEDR
         CkoTJKgRFxRRc06fH8tGvfBNjG4PuAumRKqSzKvIWr/YE8RDsnxv3qs9iOnCenHgCAg6
         lhstAmHt1O4ims/5Smj5LeJudQ5hGWRNAv+V/E2x4kGileYhgoS0NncYv58ZQtsZ10im
         DWJqK7ewnRMNw71bnhWigxBuTbZxUxVfvZecbQRzh2Ih3qL5QhR8e1zVge3IhgUKG7V6
         RKSgEVAIma/QHmVatEuwvl9FyzXSMwjy1DYCWg97WhB/8iAYVoACAWAZpLLV5VtwWh6d
         +/+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lga6UMMa0aQahAKpa9DbBvj6lFfUW2++fx2DNoNdxSA=;
        fh=ZoNhNJNUrADBrstWtpSB2JkJ5jgRh/Tc/+EILrC2RVE=;
        b=k28Yfnq+OvdYjyRRdgbAuFY0+VSimFEyyQlaFDkoSHM39YJlw+GLli9OhQ/2UFdTF7
         hFboTZ0XOiDQZNDw5s3oau/6X2Sq39ITNkz5sgeJafKrF7/wrfHjUsXr/WvFrKE6dMIL
         7duclTWiWg3QdgZ61MRAeHFrGoMdbtbPtht7PWD5k6bj4tgI4tkiSVWo0XvjqX/0Bb19
         /ZRf8sB/Z+yvFtcoKtziPdA8cN6WnOt0nxdNOfspJML3IuqZq/cHiPTv9XJKfjCrFPOw
         Vk069L7Es3oDi19NGQQE7vq6DU8sTBMzJtVu86QEqPA0qOjO8fcGK5+iRHGwA7Ifrqa5
         LPxw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=D0uxajqa;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-3196d53ce80si205055fac.5.2025.09.01.08.05.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:05:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-357-kjaS4mfWPCWoOwPIngtDKg-1; Mon,
 01 Sep 2025 11:05:17 -0400
X-MC-Unique: kjaS4mfWPCWoOwPIngtDKg-1
X-Mimecast-MFC-AGG-ID: kjaS4mfWPCWoOwPIngtDKg_1756739112
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 9E3B8180028C;
	Mon,  1 Sep 2025 15:05:11 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 418001800447;
	Mon,  1 Sep 2025 15:04:56 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	"Mike Rapoport (Microsoft)" <rppt@kernel.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Will Deacon <will@kernel.org>,
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
Subject: [PATCH v2 02/37] arm64: Kconfig: drop superfluous "select SPARSEMEM_VMEMMAP"
Date: Mon,  1 Sep 2025 17:03:23 +0200
Message-ID: <20250901150359.867252-3-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=D0uxajqa;
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

Now handled by the core automatically once SPARSEMEM_VMEMMAP_ENABLE
is selected.

Reviewed-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>
Cc: Will Deacon <will@kernel.org>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 arch/arm64/Kconfig | 1 -
 1 file changed, 1 deletion(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index e9bbfacc35a64..b1d1f2ff2493b 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -1570,7 +1570,6 @@ source "kernel/Kconfig.hz"
 config ARCH_SPARSEMEM_ENABLE
 	def_bool y
 	select SPARSEMEM_VMEMMAP_ENABLE
-	select SPARSEMEM_VMEMMAP
 
 config HW_PERF_EVENTS
 	def_bool y
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-3-david%40redhat.com.
