Return-Path: <kasan-dev+bncBC32535MUICBB7HYTXCQMGQEAIPWVZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E5A3B30369
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:07:26 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-3232669f95esf1444615a91.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:07:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806844; cv=pass;
        d=google.com; s=arc-20240605;
        b=aePnrnthmmhw3vrywJIc8K5gCouvZSRK9irQbrGDicbK5vllJYacz6wViInvqvgay+
         6Dv9WMdVBjxl3upO9rPDlO50I18Ak+7PDe+GsZdr743AW2lpUg5f0TnwMOx7VW7VJivN
         HK2xCkSOu52nuP1bBO5VAizFtLut2kl3NvL3TyEj54X8XQ4Z9r0F/B3/EXBNnZfxS5Yf
         yN+mVUwZnwEgIq/IZcqk4Hdkn+Zu25YxFM7SAjXiqtWhOzl3aMfVz1LlgHCLEvdIRuHb
         qGrn0zS3gtMIqxrdcDwgZ0FPa41Sw/RYS4FFmngAHizCfTbNbfazuBhuSKZ+wa9lVmY/
         QvgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=fFL+ztTYtNh15gMl8HFKEifbjQtQCRu25ELfQJRYB0s=;
        fh=3Rc5An+5hvjguFuXmp8MjX1RAugMIB9qykI+xMo7WVs=;
        b=HM3haq5xQXEbLN0NGYyJlKTq2JnSKC0Z2iLOGpy8mX4rvZ0Mo7aAf8VZcu3aUkH+EI
         K73UBOgBDaJ2o/iA1kADvj4MkpFfnox+GdlqC4WZDQZz2qJ0jN4lvCexmEVawoVZA+/A
         jNJK+aSz3VXUfRvzKMdRT2+aykHiHufv1YcW65E9ZOdGSLAe8fYG9U/t4U/kYAIuuBp7
         R5leIcROKVIZ3WpmZGZsz6906TlVGa5Clr+B0fFr0ipIynhaP+MZtGRE+SqWs68nscdC
         lZNwIRYFgG3WR/pEGjvH9RX5uwBJ2pYwUxoj4oAN0unSepT64i0dyRvNWOMK/Gt1v4+J
         yUdg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=V+7hqylo;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806844; x=1756411644; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=fFL+ztTYtNh15gMl8HFKEifbjQtQCRu25ELfQJRYB0s=;
        b=KsYJInNQm/xyXqTQR5/eQGqyOwG9CUi7l+kLL705hO4aYV3t5EjOoTk3dPUIKqAo1A
         CwACLR5dezXWUVNp+E4hHwiwh46os7iNj8QNjcS+v3F0vKtje4/HQQFqeHMcMlpiJAIk
         bR8OCOd9w89Ag44ATbljWQ1LbbEHU04p4ga8Uzd7GLxBbDzrcCocYFPTC7VKFR4G1xjL
         k/AQhfMRmQbO22Ec6yCNSDFeCkMksoA6ZKwGY4SsgPAlQsi14dCv4aAEksVHABqVREUF
         3WQz6RYTGMwyyATXXLF/trv4Af/FzukNTRO667fiOytYWuOsB1VA8cynYEN9oztNkthj
         BfLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806844; x=1756411644;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fFL+ztTYtNh15gMl8HFKEifbjQtQCRu25ELfQJRYB0s=;
        b=Jd/IM7AlvkSkyFOT6rG6eFC5yCmOp7/qjvz+xnpIq8AR6GXp0LArfzuuPh32FLvYYy
         A3bqRgsyg0kYrLn4BbwQfdOna9IXpReSKGIuoxo2XOhyKh0X7e/rfU+vKC3NGJzF7AwD
         lrUjgs6gnAiBvprqwFOiV8pyvl2vNSuO9iC/61cCFpC6dDkqdxX+KXzfxLWSA2L/hA3S
         q6jsszQMtOblSrYJrmU9RABVNB9Q5Ro0SX3FBa8TI9LNhfwSRTng7IyBOZ0xdjcAuzJb
         COHkNKZWeCeMvVGRfWYd4her1aW0GrGH8ZZuXdvIf6ZFzSZnk3aqS95UbU5IEJWwXnKJ
         l+Hw==
X-Forwarded-Encrypted: i=2; AJvYcCVibdDdNWH86E0NBNrZOGkcy6oB09DIhoknmJaKXP2wrQfsE+RM9L2EGzonJDUHK/IYn48eWA==@lfdr.de
X-Gm-Message-State: AOJu0Yz1iENn6AGbpHFO6tMD+3uFjXjjS2BYJRapzaW5D1tDKPxOJq9H
	yhcXfjUIDucI/AsCfhg8GQT+WqA370cK736ce+8ThUJ3AYXMd+cdMb6E
X-Google-Smtp-Source: AGHT+IGhqcwkzHYjNoucsFLEVtKOAghVg985wtIrjCp9SBhnteK2zz38U6MuIcXKMjio0qVLoaI+7w==
X-Received: by 2002:a17:90b:3805:b0:31c:c661:e4e with SMTP id 98e67ed59e1d1-32518997f87mr887576a91.33.1755806844516;
        Thu, 21 Aug 2025 13:07:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcx4EzA1KqxClHoBWIVr1GCP+WjcSc9dnDBkqMR5LIcoQ==
Received: by 2002:a17:90b:10e:b0:325:11f7:5df with SMTP id 98e67ed59e1d1-32511f7062dls264694a91.0.-pod-prod-01-us;
 Thu, 21 Aug 2025 13:07:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVnGNT0k1uVDqNq31aHZKVbcQKnIzhTLMay2TOjvMWzC+Hqp1j8LICl6fiF0xIrPZPx3qVdhaf4L7o=@googlegroups.com
X-Received: by 2002:a05:6a20:729f:b0:233:d85e:a698 with SMTP id adf61e73a8af0-24340d02345mr515141637.32.1755806842530;
        Thu, 21 Aug 2025 13:07:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806842; cv=none;
        d=google.com; s=arc-20240605;
        b=inC9jvgwHeCkDA6lDGzRdXXtlFlRof8VbBhc/j2PDJagTAf1I8h692Uef//6f7BZ4d
         t0SGWoUjUHgPFXceJRTCfXOisNtw1QuGMJpqpOOIi5rzzBZ0K7EurqDxnQe+n004FBrc
         p/1cHK05p7hEJVcWQ5RAf45TgVVXxG2zK4UaYBPluKY7cYgRqzkAQAmf1XUUZ/uuycIm
         06Wy5eYDTxvOqAJ/MHddlRw2qApQPGLvJi4TRb28S6qPY2hZSPKbvw77AcXRwpBtF5+g
         ioHQGeq5vRKtbw36yuraQBtHEXDDAca6RMxR0zOhTzYBfI/Dg3zdRM6N7TRLUcxMlv2n
         A1Gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=iU84NUWejaBSUFBs/T0/O04YrYLlq1RcxZMywEFGjU0=;
        fh=zYse8wi+6mzSiBNgc4gNTp2vt1/8wyNXC/bjlC7n7tw=;
        b=Qw6gBl1djEMkQW/2z6SYFZ61CKBkmKgRdtPnsS4oBHsf7a9j6SN4YaZjU91g9ZyeVU
         7soDzL/bL1+e3cWt8tBzHCTK916b9KKVxv48Y2fPtMNiqO903+KT4jPBbOQniLeBXTkD
         3g9JaTR3qlmXt0SfW88G891cofPPcRJ7BSFVAHIYOJvV0RFzQ4do5BVoKtcsJ7t8tYzH
         DsfeqtoYaXhsXrd6DnSc6ubrluEm6vHe67PMOeSBZIWP9Kfaut3hH0K2Cb46pLN6LR2L
         sF2vcjU0eOVJkUlgPdb63+bpIyxxmZiIlx7kjiHYhq36QzkTUrVPtdcD1P3ci6z/D7Iq
         j5GQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=V+7hqylo;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b476409d18asi254909a12.3.2025.08.21.13.07.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:07:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com
 [209.85.128.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-547-gjV22owwMGqhihoE_Tpjlw-1; Thu, 21 Aug 2025 16:07:20 -0400
X-MC-Unique: gjV22owwMGqhihoE_Tpjlw-1
X-Mimecast-MFC-AGG-ID: gjV22owwMGqhihoE_Tpjlw_1755806839
Received: by mail-wm1-f70.google.com with SMTP id 5b1f17b1804b1-45b4d6f3ab0so8375945e9.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:07:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUFlEo35yytX4rJqHYwNdAYpWAwnERL9sdEkGWE5X/hkaySnAg6gZabMcVCv+wrfRnAUvDV3f3ec30=@googlegroups.com
X-Gm-Gg: ASbGncs8DltpHoYlOoXpXnocFdq63JSLxpYvTGc6u8QHhn8eeB9Q9vpGFCOJZd50E5+
	xqXV7dBtzk1y2Hma5CwVVWjx4JeosH0V6fjb6oK22ymr3xwqaWiQXztKHAq8sJ5gU44rJ8I9ZQD
	6bnnwqIYFi9ZwjbFqLbVTqRti1aEqdlLxX/h41a31jyQjXYlFV+yBADFhXW6C+FpJs+VtYMKjv5
	vA40tKMXHoyiSuoNkl7LA++CEUisbkezzTVk2z9YQVM54tntGNETOhei9LSmgvh3nsEwiWtLsxj
	OGqVbFXFXKrz5kv/YwX1zd3hs2iBtBaSkhsOxiOH88husIka1Oe2No9Hdc4GKOlaqnR2HXyvbmW
	bu/oszWLMi6qT7azS8eRBuA==
X-Received: by 2002:a05:600c:1f95:b0:459:db80:c2ce with SMTP id 5b1f17b1804b1-45b51799428mr2845765e9.7.1755806838978;
        Thu, 21 Aug 2025 13:07:18 -0700 (PDT)
X-Received: by 2002:a05:600c:1f95:b0:459:db80:c2ce with SMTP id 5b1f17b1804b1-45b51799428mr2845125e9.7.1755806838506;
        Thu, 21 Aug 2025 13:07:18 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id 5b1f17b1804b1-45b50dea2b9sm8988005e9.15.2025.08.21.13.07.16
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:07:18 -0700 (PDT)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
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
Subject: [PATCH RFC 04/35] x86/Kconfig: drop superfluous "select SPARSEMEM_VMEMMAP"
Date: Thu, 21 Aug 2025 22:06:30 +0200
Message-ID: <20250821200701.1329277-5-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: JLhhMm5I5pbKcAMcz0iogkCN8p-nEJSd6EM85LRMzMM_1755806839
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=V+7hqylo;
       spf=pass (google.com: domain of dhildenb@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
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

Now handled by the core automatically once SPARSEMEM_VMEMMAP_ENABLE
is selected.

Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: Ingo Molnar <mingo@redhat.com>
Cc: Borislav Petkov <bp@alien8.de>
Cc: Dave Hansen <dave.hansen@linux.intel.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 arch/x86/Kconfig | 1 -
 1 file changed, 1 deletion(-)

diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 58d890fe2100e..e431d1c06fecd 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -1552,7 +1552,6 @@ config ARCH_SPARSEMEM_ENABLE
 	def_bool y
 	select SPARSEMEM_STATIC if X86_32
 	select SPARSEMEM_VMEMMAP_ENABLE if X86_64
-	select SPARSEMEM_VMEMMAP if X86_64
 
 config ARCH_SPARSEMEM_DEFAULT
 	def_bool X86_64 || (NUMA && X86_32)
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-5-david%40redhat.com.
