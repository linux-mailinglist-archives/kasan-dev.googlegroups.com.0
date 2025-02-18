Return-Path: <kasan-dev+bncBCMMDDFSWYCBB74E2G6QMGQEZ6N2VGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id A9206A394F5
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 09:19:12 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-6e1b8065ed4sf103967876d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 00:19:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739866751; cv=pass;
        d=google.com; s=arc-20240605;
        b=OBxR2wuZ8KdMGWL5j0pnyPwckutUV+IRPqboodmpS2a8vMlObTdVcHJq6ku7gdCI15
         /NXHEu9XVSq+cfv+0GJ4YApGPQqJV336h36zaZy5Hevj26qvRu4yVthn8lk1NxMkBJYt
         h26rqBVMivlMZCc42lW0cIDF33k7hRPtRT2SuttzBf3l8RgwQ1ft/d2+/bK1QmKkq4jA
         sn6OeSuZm7R/HT3o24p2VKl1f5YW/HK5mAX/IvR8E9crJKoM64AxZ10E0DeOdm/HjbhK
         5skIX/DoLDl9aYYELo5fyXBlrxXcZjjAtst48qycL65JiePDR1TB32lU8+XpgHPnZ6zU
         HZIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=G1ywe5iQsFZTwEk4Iqayfxrnp2B1vpixgI2jswCb86g=;
        fh=AIbzkesF8nJ9X+EAREeUNcFcEa9DOJ9NbwnleoUqt/o=;
        b=BIYJzd6XSfS71W9/aT3ImbNJx20qVOdBH/gL7GnAy+nsue/15LlVEAn3tGgARKrZSY
         ZX46gcnbnrOD+E0lxJzCby+GLVpWJsFElGokaroj7f+xsYI8mEvUJgGbwph5olnNELym
         h6iEKP7Mj22esVO2vDuZFhRYtoPu+3VHsp3vPcXRk9nEEwuivcWNl48tyGyv+QqaHzOG
         QLf/QrTZQBG2Zy3Sw0RhK/rzCJ7Pw05cUDtLQLBON0vY1SNz+ytJ/otx9/hCaL2tU+39
         c5vdj/s8jjpvWyiMavYtKRWIJ17eSmbFNYk58pI7L54kmAh04gEUguOUueHSYGqpYO/D
         bVaw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=bAUkdsNN;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739866751; x=1740471551; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=G1ywe5iQsFZTwEk4Iqayfxrnp2B1vpixgI2jswCb86g=;
        b=YiytJjzilcHBd3ZAkerQZfwTliSypZTMvvaRyxtC+c6gLoXltiYbu9yntBSGAobESw
         9I79RIOe7zSpkGNrpotDvO+oZgm3Hc29AvsQF+4Gpziu10odzz19B+0bb5C12/O6nb5j
         GY5nNnZnA7lBMKdccyIaZe3wvJ9cZAclb47dFNlStE0fvusTcMcvz4lTQNDqb8d/JtZT
         AieIUZ8BMoKUFuJBiHR1a3pvMfX7if6ZFMtDY1hXTX12hM5qZdYkPWidL3Su2Z64gInf
         nfbRvae/gsz0IX6P/k6s3ine0n27087EUXdJTh1L8XHIDwOI+lKza9zzATs9Sbfw3hle
         XwNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739866751; x=1740471551;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=G1ywe5iQsFZTwEk4Iqayfxrnp2B1vpixgI2jswCb86g=;
        b=VNOaSKzpqJhMRYie+sRTx34iGSTnCOjfWG83Q9NFr6ZH2jJEYLKKkmpNOG7lM+RAz4
         Nh8nI5gbgmm5HZ/tKYcmQagqDcK1l0dNYTHMAwwP8aZxy7MWnD+UGfmc3qOYyy/Fy56h
         pHnpFKPuGOAd2B9uIU6n9w3ejEFmYcUVEcPzXxx9ucaRPvhUao8fzaBD4g8QPwKBie7F
         erovLIqK16u2MxP240gioVg3RnVPY2105SxABOtmWaunt47+Sv8XPwtwpmrxXSQQaN/y
         XwibHYNImKXOKHOvynN9tayyjuXo+dgHQMQVsQh9Ajnh5wSlSmgGsRJkNOW7XV8iCHaL
         Y3yA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWfzdPBeKxWz+s3M6hFssid/WRLYmMQOL1l6T6LfrpWaDxqkV2NGclI0StsQT/SPuCGMQc/hA==@lfdr.de
X-Gm-Message-State: AOJu0Yy+N1YWqYC6VYEPuCZCVQ+ZcKsPDUicWJcZa+h+U7xG6dddzW9c
	l0L/5/GlPW5H/mosYAjAgq+6rw4i+9c9wIa44GfTERPiR1+7ny/S
X-Google-Smtp-Source: AGHT+IFonq6MrSI994svWZ8TeUZMU+4jJUxQj0nCd4Q0Ivrni4dKCzDzr4rbMO8BqYVbxHUvsi8HsQ==
X-Received: by 2002:a05:6214:627:b0:6e2:49d0:6897 with SMTP id 6a1803df08f44-6e66ccce2bamr170288416d6.24.1739866751398;
        Tue, 18 Feb 2025 00:19:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVH6ojtCzN6aDu+F0ADmLxzZO4A+RhVBC1SsOmRXeRmxlA==
Received: by 2002:ad4:5894:0:b0:6e4:41b5:919e with SMTP id 6a1803df08f44-6e65c24795dls14033076d6.1.-pod-prod-07-us;
 Tue, 18 Feb 2025 00:19:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVf870OkOywGhzwVian0O4zWkl0nzvqOh7rsgrBwnu/cBVz32gheiY+addCyqql7Xl68YG5hJqscG8=@googlegroups.com
X-Received: by 2002:a05:6102:38d3:b0:4bb:e80b:4731 with SMTP id ada2fe7eead31-4bd3ff3f0b0mr6139031137.16.1739866750215;
        Tue, 18 Feb 2025 00:19:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739866750; cv=none;
        d=google.com; s=arc-20240605;
        b=eEV44uvbujQtVl/NrCXSKdhtdPBjHBt6POFpJlxL/icNu9BZRSv+qkdnuh89E8xics
         votaFfA3m4QbWTfLrrUhLc2+63LLeYjZ4l0ln7CSTCFzQEdcstIbF7i1ex+SQ46k2sff
         EUkNdiRB/RPPSEqycKWjU0gnuFRGdpLrUkte//dgsFHzssSSdnzeOVe0rkESmdslqUfy
         BHPENfTqn8T1fj46vy1ZTOQUNUqcdUpIp8i0SlCmUdAigvD13HoGmrCZ9s6Jdcp9EHds
         WlgrgHkBNogpdodyh5qAamadMnP7qIl4vUPJg3Gcwk/ULjDGbSEPwHbNy9NbE9860Cyy
         V96A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=o0QxH8z6cj5lUaoAwjX8vI7JCJobGz53CoJ6O2LJ4cM=;
        fh=t/SH+Gg/XGt5WVAQfMl2l/LCcdyTZmDfR0ct3DuRE8Y=;
        b=BXFTqBsCfUZgzERgzQ//oSG5iQxMmZpsxnDJIOJT7kK2u8X3BMbirlWc6fg3AMno6b
         41VzG8ro3Jjv10zuebFI38beQTmVXHKDLlSG8sGPY49zEr/ILk8xt9O9KKB3TPP+vrdV
         20naHEOFi7FzFsYiTkwkLuHa4OVH5YxHm8VlQVlzHPlC/F5QljZGSniBYy3R8tViWBdb
         D5EEIXsZIu2joMR74RY9d1RLTxbb/mNfecNUctNVK2FFP8M+lGu2q8by8O7376Rvc+d9
         JWPIkc/jW9t4fq/XsBXnnPq6r05BHdg3rj8A83w/74tEf65MRJ9x7fl8WbeH5ddocbKs
         aQKA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=bAUkdsNN;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.16])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-4be5da4b7a7si214461137.1.2025.02.18.00.19.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 18 Feb 2025 00:19:10 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) client-ip=192.198.163.16;
X-CSE-ConnectionGUID: KMKbI0pHR4GQKZbZvu8JvQ==
X-CSE-MsgGUID: PfrVczTMTP+vECfDJ0tFyQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11348"; a="28150378"
X-IronPort-AV: E=Sophos;i="6.13,295,1732608000"; 
   d="scan'208";a="28150378"
Received: from orviesa003.jf.intel.com ([10.64.159.143])
  by fmvoesa110.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:19:09 -0800
X-CSE-ConnectionGUID: TjE0RLKdQ9KhXqTyx5cbfw==
X-CSE-MsgGUID: sZVzDBj6QnqZ2EAIVQa3TA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.11,199,1725346800"; 
   d="scan'208";a="119247808"
Received: from ijarvine-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.49])
  by ORVIESA003-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:18:48 -0800
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: kees@kernel.org,
	julian.stecklina@cyberus-technology.de,
	kevinloughlin@google.com,
	peterz@infradead.org,
	tglx@linutronix.de,
	justinstitt@google.com,
	catalin.marinas@arm.com,
	wangkefeng.wang@huawei.com,
	bhe@redhat.com,
	ryabinin.a.a@gmail.com,
	kirill.shutemov@linux.intel.com,
	will@kernel.org,
	ardb@kernel.org,
	jason.andryuk@amd.com,
	dave.hansen@linux.intel.com,
	pasha.tatashin@soleen.com,
	ndesaulniers@google.com,
	guoweikang.kernel@gmail.com,
	dwmw@amazon.co.uk,
	mark.rutland@arm.com,
	broonie@kernel.org,
	apopple@nvidia.com,
	bp@alien8.de,
	rppt@kernel.org,
	kaleshsingh@google.com,
	richard.weiyang@gmail.com,
	luto@kernel.org,
	glider@google.com,
	pankaj.gupta@amd.com,
	andreyknvl@gmail.com,
	pawan.kumar.gupta@linux.intel.com,
	kuan-ying.lee@canonical.com,
	tony.luck@intel.com,
	tj@kernel.org,
	jgross@suse.com,
	dvyukov@google.com,
	baohua@kernel.org,
	samuel.holland@sifive.com,
	dennis@kernel.org,
	akpm@linux-foundation.org,
	thomas.weissschuh@linutronix.de,
	surenb@google.com,
	kbingham@kernel.org,
	ankita@nvidia.com,
	nathan@kernel.org,
	maciej.wieczor-retman@intel.com,
	ziy@nvidia.com,
	xin@zytor.com,
	rafael.j.wysocki@intel.com,
	andriy.shevchenko@linux.intel.com,
	cl@linux.com,
	jhubbard@nvidia.com,
	hpa@zytor.com,
	scott@os.amperecomputing.com,
	david@redhat.com,
	jan.kiszka@siemens.com,
	vincenzo.frascino@arm.com,
	corbet@lwn.net,
	maz@kernel.org,
	mingo@redhat.com,
	arnd@arndb.de,
	ytcoode@gmail.com,
	xur@google.com,
	morbo@google.com,
	thiago.bauermann@linaro.org
Cc: linux-doc@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev,
	linux-mm@kvack.org,
	linux-arm-kernel@lists.infradead.org,
	x86@kernel.org
Subject: [PATCH v2 09/14] mm: Pcpu chunk address tag reset
Date: Tue, 18 Feb 2025 09:15:25 +0100
Message-ID: <383482f87ad4f68690021e0cc75df8143b6babe2.1739866028.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=bAUkdsNN;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

The problem presented here is related to NUMA systems and tag-based
KASAN mode. Getting to it can be explained in the following points:

	1. A new chunk is created with pcpu_create_chunk() and
	   vm_structs are allocated. On systems with one NUMA node only
	   one is allocated, but with more NUMA nodes at least a second
	   one will be allocated too.

	2. chunk->base_addr is assigned the modified value of
	   vms[0]->addr and thus inherits the tag of this allocated
	   structure.

	3. In pcpu_alloc() for each possible cpu pcpu_chunk_addr() is
	   executed which calculates per cpu pointers that correspond to
	   the vms structure addresses. The calculations are based on
	   adding an offset from a table to chunk->base_addr.

Here the problem presents itself since for addresses based on vms[1] and
up, the tag will be different than the ones based on vms[0] (base_addr).
The tag mismatch happens and an error is reported.

Reset the base_addr tag, since it will disable tag checks for pointers
derived arithmetically from base_addr that would inherit its tag.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
 mm/percpu-vm.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/percpu-vm.c b/mm/percpu-vm.c
index cd69caf6aa8d..e13750d804f7 100644
--- a/mm/percpu-vm.c
+++ b/mm/percpu-vm.c
@@ -347,7 +347,7 @@ static struct pcpu_chunk *pcpu_create_chunk(gfp_t gfp)
 	}
 
 	chunk->data = vms;
-	chunk->base_addr = vms[0]->addr - pcpu_group_offsets[0];
+	chunk->base_addr = kasan_reset_tag(vms[0]->addr) - pcpu_group_offsets[0];
 
 	pcpu_stats_chunk_alloc();
 	trace_percpu_create_chunk(chunk->base_addr);
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/383482f87ad4f68690021e0cc75df8143b6babe2.1739866028.git.maciej.wieczor-retman%40intel.com.
