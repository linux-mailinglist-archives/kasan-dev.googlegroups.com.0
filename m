Return-Path: <kasan-dev+bncBCMMDDFSWYCBBEUD5XCAMGQE3IPJ2BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C2D2B22869
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:28:51 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-4b08431923dsf134669741cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 06:28:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755005330; cv=pass;
        d=google.com; s=arc-20240605;
        b=c6XEKQGhXtHJYHJaP3/MIyOPRr60WeV2CPgwyw9h2+OZJjnO4+N3Z9llWvmqJKwwak
         /Ol/7AXYMFeyrkbqm3AoF/xMJedJ92R+zuumvXorRko5SWUQdAzlrEEOB+XibF5PpSfe
         84MNa+OpgfvAeKnqDBRIvfjy6CBjLJYGb1zZ3D7MZ3XDRsmYHdEvMetVXlaEktCYeONg
         y1UGNJqZvN0gKhPRlMfhJopnW4S4u9SSR0Np0C9O5KYCCH0CiNCFeksQdl+NIM8SzRnR
         9RqC7bjuBT8OqpNVhmEE5aT59YGJxaYGhO/VJHM8w2IhMp8ghieerXMF0K1zZaCdTk0N
         SVeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=SdfvNDPN7pJAU1pPzLOR+B/xtgAPp0begjU8JXjDw0M=;
        fh=lwKE8k7H5vOlkVrP8yjh6T2lrYILZW7IvrktlUkGE4M=;
        b=ANl7gV7vUw2mzkxyqKWc8PDHpBySJyRJZkqggwqafzyQLI1mV2FGfDevCifX9Iy7JM
         oA5ZlGqA9ZHatyVd85Ix3h2hEZaKRR+jxwPQmai8JEuwK+vtzqekcrBVVJxhGGa8gmCZ
         0l6yAOZVHuA7nMRXPDdJRv7OJoHQBqRzVWtuMxf6dIsBMMujKH37akGcjMckPjUqP9Hx
         9aWxgv/BjpHVnwIqH+ycwAmXoh4VueFQbUJMkpeWRwk/koXdRi9GqzczDuariQsmq4fE
         jYcr6nufstIUdw/ggPK3wg4yguxp2KJOnIaq3aXe+hncqa7J+iT8hpEm3+83JPzDg+LR
         uACw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=dohaW+no;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755005330; x=1755610130; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SdfvNDPN7pJAU1pPzLOR+B/xtgAPp0begjU8JXjDw0M=;
        b=a0TwfTeTqC6qZtOZCZhFOFs2OFQIwssOunOMmN1eWbfrmySMaOgdrX0lB+EG3uRl+6
         UcfC6RfqsY3kzQ2E49wSnLsjJGzXdaul04bEr3QOMyfbwFmQ5vR2dPZcVroC2hzYlkw5
         JcgNPk+xijViybEiHQRERYxFNUuqqTK3rCCqjpk8Iz4f/s6Pu6/F8+BFFSSmZgFs6S5X
         oCRIoVijhC+o0XzlsMfkESJ3OzO2DQJFaJ9+EEt05LBRX63XvVbWhEFa0229cl/4/ct9
         trubN8k9l3fa+0VPmTwhQ22YM1SnqmSvZ/yYCFQhTiLuq8v6xPx8zEXJbfJO5ugADHGw
         BrgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755005330; x=1755610130;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SdfvNDPN7pJAU1pPzLOR+B/xtgAPp0begjU8JXjDw0M=;
        b=nDVQbv1Pl2D4SQcyswlLZbjPx7k+9Vr/hv/MbITA6xAFLb0yjZbREJavXIkKAPlHuQ
         tdVJ6c0orhxkiN4gaV2dG5aMxiIR5C0HHcZE4F8Jb6JWgRzPB3DQ7+6HacuSXUAQ8rZb
         oMglAq7HhUZf+Ovb19vk5wAagoBLqBYSQ1HQjQJhBUYrbkQNM+tDKJkbxiSnww+SD0cj
         wlPBalGIQnJ4vEvwi1k92Bvw9naeHL+oGwz8lldezahu1w4zqWpTX2903f9RX1EElEeg
         mf4o4S8bXAgOPdrzoXGW8N9cUft+6hHZHaU7si6z/pWn0ANNQxNXu7QzuYR+TdnPR6Lm
         mP/g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXBM1Kzp9ur+y0TRT0t7iOnGGlzh6zAECphDbJNrfC1j4Vi090NkSG+H4o0pE/zo8DxxP188A==@lfdr.de
X-Gm-Message-State: AOJu0Yx2FlezmE57H8myvbnjhvz0faeHpXzl1Dxjgy6Q+EzmFZFCubih
	BnWxxKDiS8/Sgma20dSSK33MDOS2IaHcZw6XIDsXvaKa/+Tr6m41F94a
X-Google-Smtp-Source: AGHT+IFgTuSp+qQVmUuVdKmirIRDLVCEaARp1+jdWMIg/jX1ItCEwHPO6Ecir5faaVrXeBSXO14yUg==
X-Received: by 2002:a05:622a:a953:20b0:4b0:7ace:1ca2 with SMTP id d75a77b69052e-4b0ef5a271emr23708181cf.16.1755005330260;
        Tue, 12 Aug 2025 06:28:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcUxbvRaFcn8tGmbPytiT1gJYGlT53TsnbpzY02cS3jRA==
Received: by 2002:ac8:59c8:0:b0:4b0:9c1e:fca1 with SMTP id d75a77b69052e-4b0a045a211ls74261811cf.0.-pod-prod-01-us;
 Tue, 12 Aug 2025 06:28:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW204kNRXC7MRVNUDzqKm8pTK1uGq+MwRcUBn0FONxRFPS0O1K8aU35nJkLx20orq1+6Mmu9VcQ26s=@googlegroups.com
X-Received: by 2002:ac8:7d8c:0:b0:4ae:f8bb:7c6a with SMTP id d75a77b69052e-4b0ecd04e1cmr44224151cf.54.1755005329457;
        Tue, 12 Aug 2025 06:28:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755005329; cv=none;
        d=google.com; s=arc-20240605;
        b=PQwztSG1Nd89V+Tog2RDIjX3NXWLi3AGWCr048P/T1Ka+JnsC6/c5pEOvzHZXWQ176
         Z/9hFN6N4oem1/1OniCkf9NY/prnUN+EWlu6rPFu4ZoYDpQpxS38gowVZoE/iZS639Zp
         TaF8abRCdBhOej/GpTkVeSp9jLSMAa/dyLE32Txcx9htQFF9YNCNA2wfdNb55K2jFJGg
         Gea5neyjImzq/2IFZYuFCAV8fkSojIFFJ8xDJHK7AdkM3jOoXGqLZUCIsj11qx9umJfx
         71iqQxaUI5yaR94s5mGfNw3RIyAKEYG08PwFJWVTjWLQgouM2sxqJsx+TuLqVyDRjKbB
         5z9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=iHJ6iFS8ysRcPJg5oDGHM3GTKm2yblW43OcQ59Osn08=;
        fh=eWu/aO2D40nqoCm67aTC6qXZDH3y79upeaB1pmat6Ew=;
        b=kpnfO8WmNe5abvTYhnS1U/mZPoPM4pfyFcNL+zz9c26fp5ME1Fsew7pAXfYc+4Zbtz
         +Q1n3iyGzYAxd/vxZmV1h299hkxQi9Y/sz9GoO8IN4/Qx/UB4KVKgIBpJy9m9uR24Fyv
         1+ECJ2aMwl1AwfGD4dnPgCLTogvDDI5tuC3fZOgL1XtCnk5DV21RSDyvU2SbzoQwrPLQ
         TJ77MgAKJeb7TxSlEEA4r1xcw7ZCwhrpyHgYAKxYnxo4m2jd1SS6egQnleZkDH6rC4AP
         ZCIysewJHAkS2bWp4VZAOBkeES9O0upWyerbAeuDl1Y6MMaWsptg2cRO5hlCKr8lAGEi
         T6ug==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=dohaW+no;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b096b6d8e0si2180001cf.5.2025.08.12.06.28.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 12 Aug 2025 06:28:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: vh3McnIbSpK0sJo+9fVomg==
X-CSE-MsgGUID: siyumnqKRfqk4oRG9YRtVA==
X-IronPort-AV: E=McAfee;i="6800,10657,11520"; a="60903682"
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="60903682"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:28:49 -0700
X-CSE-ConnectionGUID: 91sElzL6QCmJr0sQT27i3w==
X-CSE-MsgGUID: 58vZSmAIQMuehLmPiYiDkA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="165831526"
Received: from vpanait-mobl.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.54])
  by orviesa009-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:28:25 -0700
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: nathan@kernel.org,
	arnd@arndb.de,
	broonie@kernel.org,
	Liam.Howlett@oracle.com,
	urezki@gmail.com,
	will@kernel.org,
	kaleshsingh@google.com,
	rppt@kernel.org,
	leitao@debian.org,
	coxu@redhat.com,
	surenb@google.com,
	akpm@linux-foundation.org,
	luto@kernel.org,
	jpoimboe@kernel.org,
	changyuanl@google.com,
	hpa@zytor.com,
	dvyukov@google.com,
	kas@kernel.org,
	corbet@lwn.net,
	vincenzo.frascino@arm.com,
	smostafa@google.com,
	nick.desaulniers+lkml@gmail.com,
	morbo@google.com,
	andreyknvl@gmail.com,
	alexander.shishkin@linux.intel.com,
	thiago.bauermann@linaro.org,
	catalin.marinas@arm.com,
	ryabinin.a.a@gmail.com,
	jan.kiszka@siemens.com,
	jbohac@suse.cz,
	dan.j.williams@intel.com,
	joel.granados@kernel.org,
	baohua@kernel.org,
	kevin.brodsky@arm.com,
	nicolas.schier@linux.dev,
	pcc@google.com,
	andriy.shevchenko@linux.intel.com,
	wei.liu@kernel.org,
	bp@alien8.de,
	ada.coupriediaz@arm.com,
	xin@zytor.com,
	pankaj.gupta@amd.com,
	vbabka@suse.cz,
	glider@google.com,
	jgross@suse.com,
	kees@kernel.org,
	jhubbard@nvidia.com,
	joey.gouly@arm.com,
	ardb@kernel.org,
	thuth@redhat.com,
	pasha.tatashin@soleen.com,
	kristina.martsenko@arm.com,
	bigeasy@linutronix.de,
	maciej.wieczor-retman@intel.com,
	lorenzo.stoakes@oracle.com,
	jason.andryuk@amd.com,
	david@redhat.com,
	graf@amazon.com,
	wangkefeng.wang@huawei.com,
	ziy@nvidia.com,
	mark.rutland@arm.com,
	dave.hansen@linux.intel.com,
	samuel.holland@sifive.com,
	kbingham@kernel.org,
	trintaeoitogc@gmail.com,
	scott@os.amperecomputing.com,
	justinstitt@google.com,
	kuan-ying.lee@canonical.com,
	maz@kernel.org,
	tglx@linutronix.de,
	samitolvanen@google.com,
	mhocko@suse.com,
	nunodasneves@linux.microsoft.com,
	brgerst@gmail.com,
	willy@infradead.org,
	ubizjak@gmail.com,
	peterz@infradead.org,
	mingo@redhat.com,
	sohil.mehta@intel.com
Cc: linux-mm@kvack.org,
	linux-kbuild@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	x86@kernel.org,
	llvm@lists.linux.dev,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v4 10/18] x86: LAM compatible non-canonical definition
Date: Tue, 12 Aug 2025 15:23:46 +0200
Message-ID: <5dee53bb1044787199e143f7b5f6ec13204a3029.1755004923.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=dohaW+no;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

For an address to be canonical it has to have its top bits equal to each
other. The number of bits depends on the paging level and whether
they're supposed to be ones or zeroes depends on whether the address
points to kernel or user space.

With Linear Address Masking (LAM) enabled, the definition of linear
address canonicality is modified. Not all of the previously required
bits need to be equal, only the first and last from the previously equal
bitmask. So for example a 5-level paging kernel address needs to have
bits [63] and [56] set.

Add separate __canonical_address() implementation for
CONFIG_KASAN_SW_TAGS since it's the only thing right now that enables
LAM for kernel addresses (LAM_SUP bit in CR4).

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v4:
- Add patch to the series.

 arch/x86/include/asm/page.h | 10 ++++++++++
 1 file changed, 10 insertions(+)

diff --git a/arch/x86/include/asm/page.h b/arch/x86/include/asm/page.h
index 15c95e96fd15..97de2878f0b3 100644
--- a/arch/x86/include/asm/page.h
+++ b/arch/x86/include/asm/page.h
@@ -82,10 +82,20 @@ static __always_inline void *pfn_to_kaddr(unsigned long pfn)
 	return __va(pfn << PAGE_SHIFT);
 }
 
+/*
+ * CONFIG_KASAN_SW_TAGS requires LAM which changes the canonicality checks.
+ */
+#ifdef CONFIG_KASAN_SW_TAGS
+static __always_inline u64 __canonical_address(u64 vaddr, u8 vaddr_bits)
+{
+	return (vaddr | BIT_ULL(63) | BIT_ULL(vaddr_bits - 1));
+}
+#else
 static __always_inline u64 __canonical_address(u64 vaddr, u8 vaddr_bits)
 {
 	return ((s64)vaddr << (64 - vaddr_bits)) >> (64 - vaddr_bits);
 }
+#endif
 
 static __always_inline u64 __is_canonical_address(u64 vaddr, u8 vaddr_bits)
 {
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5dee53bb1044787199e143f7b5f6ec13204a3029.1755004923.git.maciej.wieczor-retman%40intel.com.
