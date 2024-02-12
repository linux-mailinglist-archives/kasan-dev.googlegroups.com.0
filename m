Return-Path: <kasan-dev+bncBC7OD3FKWUERBHNAVKXAMGQEJ4MW6DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 22612851FC3
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:39:43 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-680118b101fsf61165626d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:39:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707773982; cv=pass;
        d=google.com; s=arc-20160816;
        b=wTi/yMb6IgIIexnocBVZMppHEByEi+2VDhTQSofgmUZOaeqRBNF9LVSKwiPkEr7I1A
         1Jm5O0pDJ0w1t3nPSBHBbJUJbvpdXTnTV1LnilQeDtTdCJy73OS67TxcqBzWb3OammKE
         7qAZJAyadx+wl9zpliYZj6CID6FVKrMOQmXvIYRU9rQodbBJlCEvhL4/HB5H/jJXHNca
         a+NoH5bsXnPDYxDoqMxbl4cV/9rzlYyTgs7kgI7xtAv6DV/31EjujKQt5xAVTOrI9Zn9
         GbFO7vgXuTO9v9xnAEiA3wooE7Mx83PU8vE9PEmWO1Lr5nMsiQ5WtFXNt146jcaB5Knd
         ky1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Siz+jGwIGxnqSqO+hocGaOkpCfHiHOC/0GCn+x63ypI=;
        fh=lokYJcvskq/pY0Rzc1diT3p34W11foHHnkKOsGdSIaE=;
        b=lWF6QSiI5QRGkr9Oex96Bj0iCEKZrPcqzI/srxtsPpCd31Yn3qyuRrbRBvP9BTIbGO
         Mi5eUv2vC9EwejmlCs0eaEH1hpsMkiq9nggRs7LtLqpQcF1E2sH4hak/2Rx7NIXxwCMW
         j9ZL/8addT+zhMh97q16P4fc5iRYV2XEp5zRqvBVVRLOE064wrJiz0uyZyHxGX0aBcN0
         PDTLnnJCIfPj5FqxzwlBQSvFeOA49d1br7jpXzqSFPnZUTy3W7/a7nBFMbplRLNxN+cA
         ZAzWbFn2dy3hKnGCKfTWDUWB8dN9O0gE4kDhoQ+RDzN9UjtGhZgkJM/5XfYC8GhQ1Voq
         cQFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=H3C7EbNG;
       spf=pass (google.com: domain of 3hjdkzqykczsnpm9i6bjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3HJDKZQYKCZsNPM9I6BJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707773982; x=1708378782; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Siz+jGwIGxnqSqO+hocGaOkpCfHiHOC/0GCn+x63ypI=;
        b=m6ddxGNv69tj0E4qHvy+DIRYjBsY9OrhpMS4M/biZ429Tlokuuzvrc+C2Ay5/ZEg80
         rZW6mIpD910qOhVWAIFaB8KvLn5lMhPrIYCExyWqJ9d3iPq8JT0BoczbrvewoPeM7pm6
         bGt7T+PB0CpxD7HVZeA3erCL5LnUb0A2/wt6cTMRMbV1iossIoedmn9MbxUzEs3zYLWn
         ihpYg7VY2YNTFgdcSyJIXBPybg3slvQnKJiUeT1C5lQyarkVVnbEdgmw1VBJXFXsLcrn
         MfuAebeFe+nJolse++3Rj9kPl5tu3vvXXOW3b/zMbno3LHVIcWnIUnTvkVYM28LY9h8i
         xOLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707773982; x=1708378782;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=Siz+jGwIGxnqSqO+hocGaOkpCfHiHOC/0GCn+x63ypI=;
        b=Tlo9mnty7fK/YTmvefqJJyO5RWbzo29SMuMp+n1K19eDFYNS/dethW5VOzFcDKCim9
         bwy7BJo++H5PAg9BW9//epCNAD+B06NnsfDID+Mxny1Vfw6YkC+ZZ3aI56+HkVYQK/R6
         iFP41okvu2wS7rhZyrhXsvklUkX2renN8Dom9f9k8VEInzMCj01ywEgJLsTkyww/sKQP
         /Hi3ykFHD+tOGblh72LjKb3u0+ZmwYcSuNFVSZq9iYeT+JPghYZis3tn4/XLongcqhky
         ntHanrN/Im6TRzMwHE2atS6TjuLDbGrado+MkmpwaWl5c3QCSbtSV4+rMdim+katAdF+
         6eHg==
X-Gm-Message-State: AOJu0YwlJZYthReFu5rGdKUHKpn/f+WfXmPDadqIlhJ+oRUmaQpusE98
	2tmQlvtpi2WHw6A/gh8HccdoAEKHU11//SBZ1vca2gKvORsOQVmN
X-Google-Smtp-Source: AGHT+IH+OvmYm/yYbRJuIVlBLuZpnnMKPg67qhIdqEFvqoVP17IvNk2SEkh0JXnsJUMQGVWhHjgwWQ==
X-Received: by 2002:ad4:5962:0:b0:68c:a81c:2b77 with SMTP id eq2-20020ad45962000000b0068ca81c2b77mr9355655qvb.27.1707773981989;
        Mon, 12 Feb 2024 13:39:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1c43:b0:68c:be07:46f5 with SMTP id
 if3-20020a0562141c4300b0068cbe0746f5ls2853658qvb.1.-pod-prod-09-us; Mon, 12
 Feb 2024 13:39:41 -0800 (PST)
X-Received: by 2002:a05:6102:30a9:b0:46d:3597:9f9e with SMTP id y9-20020a05610230a900b0046d35979f9emr6604894vsd.31.1707773981321;
        Mon, 12 Feb 2024 13:39:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707773981; cv=none;
        d=google.com; s=arc-20160816;
        b=BTOPDN5si/fx+vpZSwO9qAkNaZL1OmP9c8JVClfjc9dPjZr3v+lFQ3ywB3SM4i0Mhy
         LMlC0u4KS7TP0EdiIJacvYzHAIIf+S4DXYKdlQumUOSgjMLyMWzp5BduwwYLaBAEHnFX
         at52u30K88eHEXrSIUNjrQvsbXqR585SWsn34VDewXlje2MIa+BZo3XYJmHXEl+7fIEe
         KyvZAtEU9dtkqJjITaBpxgsFkRuEkiYNSeDK9RFNQvjLPhufD7PsyNnhp8eAcP0/wJsH
         gwTexUueBJhk0sAf69z8gtJe2aaB/3abiB9c33mwY25tSkovGtFv3nkCVPGNkg6R0BOI
         vYOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:dkim-signature;
        bh=S1akKlUBB/xj+27ZoPrRWZFBMZktx+X63RMMKv/Ae94=;
        fh=lokYJcvskq/pY0Rzc1diT3p34W11foHHnkKOsGdSIaE=;
        b=PubsftosdftEUyYr4ZHR7GMg3D4dF6YmV4rrweSfrSJwTTrRPdUHrFI1WvwtfCfFOo
         BfuhfFdO9HuwF198HICvDxI6XbL5SOl4zK4Rx/YqpvaY1m6L16Nbmol1oNqELoghpmt/
         wU7IzHb7SRfVKkU3QS1bZdAv/ntYzKI29GivzO1+qoDoasxLhS0LJSPl7LsNYtlvKLCL
         9BduMuQVt8fXVESHlGjlGtaBygZl9wx7Fn0My8A7G/Cmz8qLRn+W9adtYMW44lXOliM9
         rtQkKZP26IgoKaweAbMklv43a1l68hcnOTBSmEte7aRuXozz04Np/bnuQ7dAbCW/IvDM
         BX0Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=H3C7EbNG;
       spf=pass (google.com: domain of 3hjdkzqykczsnpm9i6bjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3HJDKZQYKCZsNPM9I6BJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCUi7RZTKjeaWPnfqKwFje1F4P7JtkgIlee/2qg+aMdqW7cqVujggJodHIBuVR2dhcKAR98xASWaQqaBzWWbMhhKGAHdRxsytiF9Fw==
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id g25-20020ab072d9000000b007d68e9b21c1si769960uap.1.2024.02.12.13.39.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:39:41 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hjdkzqykczsnpm9i6bjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-6077ca422d2so6807437b3.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:39:41 -0800 (PST)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a05:690c:a90:b0:5ff:a9fa:2722 with SMTP id
 ci16-20020a05690c0a9000b005ffa9fa2722mr2210184ywb.3.1707773980866; Mon, 12
 Feb 2024 13:39:40 -0800 (PST)
Date: Mon, 12 Feb 2024 13:38:50 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-5-surenb@google.com>
Subject: [PATCH v3 04/35] mm: enumerate all gfp flags
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, surenb@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org, 
	"=?UTF-8?q?Petr=20Tesa=C5=99=C3=ADk?=" <petr@tesarici.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=H3C7EbNG;       spf=pass
 (google.com: domain of 3hjdkzqykczsnpm9i6bjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3HJDKZQYKCZsNPM9I6BJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

Introduce GFP bits enumeration to let compiler track the number of used
bits (which depends on the config options) instead of hardcoding them.
That simplifies __GFP_BITS_SHIFT calculation.

Suggested-by: Petr Tesa=C5=99=C3=ADk <petr@tesarici.cz>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/gfp_types.h | 90 +++++++++++++++++++++++++++------------
 1 file changed, 62 insertions(+), 28 deletions(-)

diff --git a/include/linux/gfp_types.h b/include/linux/gfp_types.h
index 1b6053da8754..868c8fb1bbc1 100644
--- a/include/linux/gfp_types.h
+++ b/include/linux/gfp_types.h
@@ -21,44 +21,78 @@ typedef unsigned int __bitwise gfp_t;
  * include/trace/events/mmflags.h and tools/perf/builtin-kmem.c
  */
=20
+enum {
+	___GFP_DMA_BIT,
+	___GFP_HIGHMEM_BIT,
+	___GFP_DMA32_BIT,
+	___GFP_MOVABLE_BIT,
+	___GFP_RECLAIMABLE_BIT,
+	___GFP_HIGH_BIT,
+	___GFP_IO_BIT,
+	___GFP_FS_BIT,
+	___GFP_ZERO_BIT,
+	___GFP_UNUSED_BIT,	/* 0x200u unused */
+	___GFP_DIRECT_RECLAIM_BIT,
+	___GFP_KSWAPD_RECLAIM_BIT,
+	___GFP_WRITE_BIT,
+	___GFP_NOWARN_BIT,
+	___GFP_RETRY_MAYFAIL_BIT,
+	___GFP_NOFAIL_BIT,
+	___GFP_NORETRY_BIT,
+	___GFP_MEMALLOC_BIT,
+	___GFP_COMP_BIT,
+	___GFP_NOMEMALLOC_BIT,
+	___GFP_HARDWALL_BIT,
+	___GFP_THISNODE_BIT,
+	___GFP_ACCOUNT_BIT,
+	___GFP_ZEROTAGS_BIT,
+#ifdef CONFIG_KASAN_HW_TAGS
+	___GFP_SKIP_ZERO_BIT,
+	___GFP_SKIP_KASAN_BIT,
+#endif
+#ifdef CONFIG_LOCKDEP
+	___GFP_NOLOCKDEP_BIT,
+#endif
+	___GFP_LAST_BIT
+};
+
 /* Plain integer GFP bitmasks. Do not use this directly. */
-#define ___GFP_DMA		0x01u
-#define ___GFP_HIGHMEM		0x02u
-#define ___GFP_DMA32		0x04u
-#define ___GFP_MOVABLE		0x08u
-#define ___GFP_RECLAIMABLE	0x10u
-#define ___GFP_HIGH		0x20u
-#define ___GFP_IO		0x40u
-#define ___GFP_FS		0x80u
-#define ___GFP_ZERO		0x100u
+#define ___GFP_DMA		BIT(___GFP_DMA_BIT)
+#define ___GFP_HIGHMEM		BIT(___GFP_HIGHMEM_BIT)
+#define ___GFP_DMA32		BIT(___GFP_DMA32_BIT)
+#define ___GFP_MOVABLE		BIT(___GFP_MOVABLE_BIT)
+#define ___GFP_RECLAIMABLE	BIT(___GFP_RECLAIMABLE_BIT)
+#define ___GFP_HIGH		BIT(___GFP_HIGH_BIT)
+#define ___GFP_IO		BIT(___GFP_IO_BIT)
+#define ___GFP_FS		BIT(___GFP_FS_BIT)
+#define ___GFP_ZERO		BIT(___GFP_ZERO_BIT)
 /* 0x200u unused */
-#define ___GFP_DIRECT_RECLAIM	0x400u
-#define ___GFP_KSWAPD_RECLAIM	0x800u
-#define ___GFP_WRITE		0x1000u
-#define ___GFP_NOWARN		0x2000u
-#define ___GFP_RETRY_MAYFAIL	0x4000u
-#define ___GFP_NOFAIL		0x8000u
-#define ___GFP_NORETRY		0x10000u
-#define ___GFP_MEMALLOC		0x20000u
-#define ___GFP_COMP		0x40000u
-#define ___GFP_NOMEMALLOC	0x80000u
-#define ___GFP_HARDWALL		0x100000u
-#define ___GFP_THISNODE		0x200000u
-#define ___GFP_ACCOUNT		0x400000u
-#define ___GFP_ZEROTAGS		0x800000u
+#define ___GFP_DIRECT_RECLAIM	BIT(___GFP_DIRECT_RECLAIM_BIT)
+#define ___GFP_KSWAPD_RECLAIM	BIT(___GFP_KSWAPD_RECLAIM_BIT)
+#define ___GFP_WRITE		BIT(___GFP_WRITE_BIT)
+#define ___GFP_NOWARN		BIT(___GFP_NOWARN_BIT)
+#define ___GFP_RETRY_MAYFAIL	BIT(___GFP_RETRY_MAYFAIL_BIT)
+#define ___GFP_NOFAIL		BIT(___GFP_NOFAIL_BIT)
+#define ___GFP_NORETRY		BIT(___GFP_NORETRY_BIT)
+#define ___GFP_MEMALLOC		BIT(___GFP_MEMALLOC_BIT)
+#define ___GFP_COMP		BIT(___GFP_COMP_BIT)
+#define ___GFP_NOMEMALLOC	BIT(___GFP_NOMEMALLOC_BIT)
+#define ___GFP_HARDWALL		BIT(___GFP_HARDWALL_BIT)
+#define ___GFP_THISNODE		BIT(___GFP_THISNODE_BIT)
+#define ___GFP_ACCOUNT		BIT(___GFP_ACCOUNT_BIT)
+#define ___GFP_ZEROTAGS		BIT(___GFP_ZEROTAGS_BIT)
 #ifdef CONFIG_KASAN_HW_TAGS
-#define ___GFP_SKIP_ZERO	0x1000000u
-#define ___GFP_SKIP_KASAN	0x2000000u
+#define ___GFP_SKIP_ZERO	BIT(___GFP_SKIP_ZERO_BIT)
+#define ___GFP_SKIP_KASAN	BIT(___GFP_SKIP_KASAN_BIT)
 #else
 #define ___GFP_SKIP_ZERO	0
 #define ___GFP_SKIP_KASAN	0
 #endif
 #ifdef CONFIG_LOCKDEP
-#define ___GFP_NOLOCKDEP	0x4000000u
+#define ___GFP_NOLOCKDEP	BIT(___GFP_NOLOCKDEP_BIT)
 #else
 #define ___GFP_NOLOCKDEP	0
 #endif
-/* If the above are modified, __GFP_BITS_SHIFT may need updating */
=20
 /*
  * Physical address zone modifiers (see linux/mmzone.h - low four bits)
@@ -249,7 +283,7 @@ typedef unsigned int __bitwise gfp_t;
 #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
=20
 /* Room for N __GFP_FOO bits */
-#define __GFP_BITS_SHIFT (26 + IS_ENABLED(CONFIG_LOCKDEP))
+#define __GFP_BITS_SHIFT ___GFP_LAST_BIT
 #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
=20
 /**
--=20
2.43.0.687.g38aa6559b0-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240212213922.783301-5-surenb%40google.com.
