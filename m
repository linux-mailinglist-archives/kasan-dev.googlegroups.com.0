Return-Path: <kasan-dev+bncBC32535MUICBBVXM23CQMGQE52FPJKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 86260B3E847
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:06:00 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id ca18e2360f4ac-8872f760af6sf235394239f.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:06:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739159; cv=pass;
        d=google.com; s=arc-20240605;
        b=eZS9y6HzQzNDFLvuZv9DvtZmutfOkuSNipPCeg/L/XSJ88SYK/FNRXHOyWOVBc1O8V
         0kidO9Sz6vRhJcvFCrb+BfWro+YV6/0Xv/Qw8K01ni3iQ7enPWryJpKk4c+IJfS9Ew9v
         Aw8RmaNtqp0Z3jB2T/zELjZgUbR8WRp9aHwI3mc/4NNYy9SjAgWHruM6iS8JUojfoPja
         3nkPi3SPbBazb4YrOE7E34c1+0tCTz1+h3IHsq5kTfJI/0BrpTJQOVXTTBZAFqYLgnG+
         oeOtMFnSMq2Nuz7mK3E6rap0SoQTPo83Bn4iNGksDb8N+A58ACwKo6Yh5nJZOo+iFV1k
         A6rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=9Q6tChzIqMk8RRB2gATecPhgPVMU7iS4MsrP6T/KV7w=;
        fh=gCkolSj0UNrNwLGME57NL5EAA8RJCWtygUjiPORqcns=;
        b=S0HPasIMJoE389bTXi6SEwRx2uRqIBF9AJTc6jknoZM4B8J4afSsR+wX+aHuRz+fL7
         pW5aYQ/2GwlR2qPlZR1DwR6tGI/uB8YA3QcvRM7e4tvXzCrYHeOcUkbf1Qkfjw2snnqc
         7/dza8yoaq3AvDCx8MJfc21kvtazNLz5bLWNlBIxUqzSc0KhZqyvKizTQxMnE+ThhLpu
         MTizKLdrSLX6LAPaRLWb99RsrCLrOtfFvH7qdeFxq0w33cpGig+JHPTppyYbeIFXGmgO
         ptXJFWuKbr+ifUZ/3blmNuozgYWICMWYJyNDcoWis2jgdbgMx7HmBXBq2DbBckoAF+L1
         T0dg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=BXWw6yoG;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739159; x=1757343959; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=9Q6tChzIqMk8RRB2gATecPhgPVMU7iS4MsrP6T/KV7w=;
        b=P123IE9M8mDkPmhmrAVAXH/nX8Im4+Xr/XcNHYFoT5QzNIF++919cEMT/nwF9gHuAP
         jHQZlLM1/Bn26dsWb4AqS50JcMjhMVV+TiKyrPxAtInya0QswsGc4CCE7r2T7sk4E6op
         xhlk62ikAmq35d7WWG1Q/g6XitoOBgvAJSOC69uyD1qac8CVBriuBsuTo/hBTYOCfWWD
         JvbGkbituJHvfn3OKmMmp3JqulNspHJm2i/F3QPGIxtwPuzpC/PHN3lHDzTyHVmIFM4f
         TpbGgT3nkPIXZOCno/czNPsS/KoBPFBj2YsLNGsHGyy+RsXOgb1Ni9KoZcFkxAWOCU10
         vz8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739159; x=1757343959;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9Q6tChzIqMk8RRB2gATecPhgPVMU7iS4MsrP6T/KV7w=;
        b=PeANKhtDvcIaLiLgHXj2i1nKomJbksB2PSwutgseH1dN4I60tQWMGgocV8zOJ40I/x
         DklZ1SeD56/3Br27hfz1G0t9LWjmN6I5+mFSWI2KttkavR7aKN8N8OsKJXULIRfMHfQd
         HL+Xa2IcaBxADSs7W55m8eG6BO0JmHxoIGFJl+QCAe4GF9nMRFLMJP3cHNfrP1aLmJz2
         l53prTgyYfV2LlAcgrqMjiFs6LmU38x/mrasuvhQVhuedvVw6tIje1OevtpCmfiojLIw
         NfgtZgn6srqRmjxii0+FhoZvaV9Hcir/BmAVUMiIURYuCy3seo5FMNb2KEsCw6DCdMk+
         CttQ==
X-Forwarded-Encrypted: i=2; AJvYcCXHCPcKNa5tXjipFPVpavnw6/Zrl9L9QbRyRrZA+cDAx9qK+mpGQMavP1FKXXBZekzON68lfQ==@lfdr.de
X-Gm-Message-State: AOJu0YxYpS8+VdzCQE/GbUvQxtGAiC+p3QHDCCAVH/o+JXerht+4UwUO
	8AmyyuEeTu2mIAviMTrfdVJHTyv+I0NwnST4/P6KFiLbgSsaI4kBsVfp
X-Google-Smtp-Source: AGHT+IGyzrYLH7VzMMPE9djel1V2h9269Uc2Lr3ZoW84dhRgBAUKyeH+x4Px9mEt6rNGJfZ7lE2xDA==
X-Received: by 2002:a05:6e02:218c:b0:3f2:99cc:5247 with SMTP id e9e14a558f8ab-3f400479aa4mr172214625ab.14.1756739158770;
        Mon, 01 Sep 2025 08:05:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeBe46JJNOLkQoskEyJb8vluItB5iKb0OAc95oN5/pvRQ==
Received: by 2002:a05:6e02:1546:b0:3e2:b055:6934 with SMTP id
 e9e14a558f8ab-3f13bb1e949ls46451495ab.2.-pod-prod-01-us; Mon, 01 Sep 2025
 08:05:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXmH1aX3XXK/RuIY5N9lWaSj1V1axWq8jGVtsgYjB/HfE4qYx2mMnr9Q5eCE1rjavI3VWeEoV7gchA=@googlegroups.com
X-Received: by 2002:a05:6e02:2194:b0:3ee:a3ff:96c7 with SMTP id e9e14a558f8ab-3f401beb3a4mr156154705ab.17.1756739156592;
        Mon, 01 Sep 2025 08:05:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739156; cv=none;
        d=google.com; s=arc-20240605;
        b=GsFLUKnMYxCF2X+75RdQaoGe/F45Ic9/zqa3JACMi9evUXxn2fkfq24hvOcQkMlPT6
         x/L1h2mC1LEztO+DoYIS5ftky6DQocM5Rgtxbedz0xN63Mgbgwh7HFEvLA2Kz6zi84kN
         RR84vde5PQZmM8JX8yO+59VU1ZZJKhibcMacPuVrZhqGkt94NIc5f6T4A3g4ue00Y9/j
         EUJf1F4CxqCWlpjpNRFAbPSFH05nRBWstYNzdSml15UUqgUSNQ7dMx2/dBwF86RB3baa
         zhp8YqdFDrTYdHEdDU79HU7VuKhTFP8EEa3B8MN2d0Z1xFbJZTuODxOmSmRZvxCQIvpC
         +sKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=u9ikJfv6RMgWpDoO/PrbRDajESXjomPX0LKmeM4ApTo=;
        fh=z9hqPsuKODOw05S4sMALmSmusoJcJVC6TmtUnjEl1y4=;
        b=ELX3V7abqqXOjPbllkgl6lzk3BcqkSuFzxeAoxv3rqE7QJbFXoeSkt06/ycBCFYqfh
         CnUfjy+asMODWRtOkPz9UlNQpEZ7CwNtanhwyVnL+hA5dLw9O11Ya0Kk1O/j24MRSgz7
         GkJb6iz9aycI1Za9fKXsHlBSj8R1ZNMg4JsJxQTCgP3rAwL6IVLhXneW3poNW9fZ7Bec
         gxYjESpGJvdJOUy3DDJxSKctDcYyiZEG1RlUz+KrQ4DHgGYSTPRu4K+9cuRu5awSMW/C
         980S+artqTaIhjULw8d8KwRyDlRcDwOO/Ds7lmSAZ2+W/zvYGaiJiKnYoEITVUj5vOXc
         49vw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=BXWw6yoG;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3f3e0411afbsi3058245ab.5.2025.09.01.08.05.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:05:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-321-BCH8lRQHM2i3AvlSIjWhRg-1; Mon,
 01 Sep 2025 11:05:54 -0400
X-MC-Unique: BCH8lRQHM2i3AvlSIjWhRg-1
X-Mimecast-MFC-AGG-ID: BCH8lRQHM2i3AvlSIjWhRg_1756739146
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 6BF1118003FC;
	Mon,  1 Sep 2025 15:05:45 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 0BD8C1800447;
	Mon,  1 Sep 2025 15:05:28 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	"Mike Rapoport (Microsoft)" <rppt@kernel.org>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
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
Subject: [PATCH v2 04/37] x86/Kconfig: drop superfluous "select SPARSEMEM_VMEMMAP"
Date: Mon,  1 Sep 2025 17:03:25 +0200
Message-ID: <20250901150359.867252-5-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=BXWw6yoG;
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
Acked-by: Dave Hansen <dave.hansen@linux.intel.com>
Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>
Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: Ingo Molnar <mingo@redhat.com>
Cc: Borislav Petkov <bp@alien8.de>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-5-david%40redhat.com.
