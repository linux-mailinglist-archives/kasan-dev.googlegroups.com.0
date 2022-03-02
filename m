Return-Path: <kasan-dev+bncBAABBJET72IAMGQEZF2SBUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id C4FC74CA8D9
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 16:13:40 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id f12-20020a7bcd0c000000b00384993440cfsf706150wmj.3
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 07:13:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646234020; cv=pass;
        d=google.com; s=arc-20160816;
        b=xmhp944oTwyzBSNVkH5OwAy2BK8QUfXcwhs7bo8rAUT99tAOGFOIxA0b+p3LwgsdGC
         92QQNwzKxJ/BjO4xrvlMbNLwG4IEoD0kSHNRim/sQtqlfM62besP7Kxp1SXqEStwiToc
         LKnb1IABQ9dsOlLaAXN7W+eegc7Mh/6qspe7un0jrFkRN9tW4QhkHRCppG4Q376FPNQa
         CqLpMSWsMFHLtd5Zxdp0v4MUafFgRrnYzVqm0WdRm8UMazNNCTGdZ29T0eeTfOe+ySJR
         iEh9r9Dzxfshkr3ZmCF6+6sucpNOBir+kOLnBPo8VsI4QpDsDul6jdEqvbmYEoVDAXHA
         mTOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=kVrIRvbZGCAf26KhLlxJ2STvWtu1YGvVamk9mAz3YGo=;
        b=gvN5reEryrpcIVVvNSDV4rJTJv61wqXNMvCiX+5RNTh1IW1xbRwYbWawa1pvsI1Jjp
         4vwSA2ulZAOIhf/7Sj3oMkBXwlMZRrKsIlnleGNnJlCFnWK0B1iDxcECSBTyfGMifbRY
         d8SLv55aHKa+CXRxUMnkMng1d5pBDFZibgTGt6ux5K6KqdgoPUSUzSLM5GoOkVczkQHX
         PsB0MuIbdVVzJuWTxhot8xYNUuYmMKuaJ8c/WfjOjYUpMns5VdhMSADeu6XB1XK2SAVm
         gVn65bZbW2XZMsBf76kEItDWewBN/zXlfQdA7Wu5Wd4NYqWwls6uQV1EQarNXuFOXgrv
         spsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=CSGzfx3o;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kVrIRvbZGCAf26KhLlxJ2STvWtu1YGvVamk9mAz3YGo=;
        b=qU+1jLIjJ2mniCgA1WVWv+0CXRG3xSrxpN/d/9fy9lerZ3R1wOE+lMM2iKXKDTBtpp
         WaW/qWzRs6WGuOD99itap6zUPqe7OS+/Fm3MBVOy/TgfBbcrSCsj6DBbFZLUpBp6UDDv
         C4Qzxd4L8rOfCs65tztrxw/remlVnPGeJqpO5ntU/heuudh7km1FenVeQVp+R3rLQDlZ
         /n3iYyMTXFytr5pACLwlpGfEWr6UujozKGymjzAURf66bpyfx1zyc4Hmp2aimqdoO2vy
         A+hZryOOxWHajbwmdwV/1IU5q7LgtRNIpr0aj2jSrXcl8a3iEUqyhNeAiYgmDz3iIFn7
         DIrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kVrIRvbZGCAf26KhLlxJ2STvWtu1YGvVamk9mAz3YGo=;
        b=TPdNRxi7FGOrpVFzxRkmszBn0WwsM0+v2t8GOR6GtMnJKCqfsJxix5Wh6DfjWkvTVd
         IPPsw31DyMnZNOdk7afUCXhSIbGSrdF+CXXz4SRwzToWAIIJWO7JT3d3kGVzQr58RC4M
         7n3SHpB9vQ9+Ix/9252ndDOrQBuK+px/YK7PesagXxnaioIowvW66fARhZnPhktgkNqB
         Ad8kiBvSUExha+2vLld4G9a3mJrHEPkp60Dtn7qpDwiJyS33aNSmhoEG8qMfFdu2w5Su
         4wI1LdDD+MPla4To9CCyjtixY/iGvRVtPEi8h1DAdsR902CyDFRGCTZxE6r+bC7Ty0NY
         Ml0g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531bJRVuwMV9EQpUvnT5Y+McO+CS2IwxhKp1SY33Dd+V3Ov8pi7e
	gB+YJl8BcEyIi+RrOpC7lEI=
X-Google-Smtp-Source: ABdhPJyTRcheYi2VbmipFp7Gkxx2g0kVPJeG1y7OPNAey18K8Rf9pUUL9X9ehimgVpRXiOiPsY1caQ==
X-Received: by 2002:a1c:a54f:0:b0:380:4f49:624a with SMTP id o76-20020a1ca54f000000b003804f49624amr186907wme.164.1646234020366;
        Wed, 02 Mar 2022 07:13:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2747:0:b0:381:80e8:be59 with SMTP id n68-20020a1c2747000000b0038180e8be59ls2870686wmn.1.gmail;
 Wed, 02 Mar 2022 07:13:39 -0800 (PST)
X-Received: by 2002:a05:600c:478f:b0:381:44df:aeb3 with SMTP id k15-20020a05600c478f00b0038144dfaeb3mr180194wmo.49.1646234019637;
        Wed, 02 Mar 2022 07:13:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646234019; cv=none;
        d=google.com; s=arc-20160816;
        b=hhUr+n+FEVSRA8RBgfaBLLOqVDCfcRKkuhA58f7kdTi1zt+qhefXbGQhCKK/RpyH4G
         6GdUrrmXfWYa8MJBsf4Mk0ME7qMLkzsF6LkQt0jKdDkUY7e4C94ANIsvolegfVZaQzCw
         T4D9mZgbIFHgsRvXDcGEaWPlPX0G4bH+eWELpP1jFd7ShK7WSKkOcaGu3dAXU+30uRo/
         TStvkZN2EhVPNJpESCtTaUS5F86K1NpOhI9X9ghm66aVtf41+IJIyiQpW+o4qQ8SgXL6
         smeUF2JGeIKo++OoW2QTY4soMyPqRQxbYsJj23bvKuR1piRTc50kIgvCJw06l7V2pNp9
         Nhrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=j3qLOT6ZMaAmt2b0mGfPQFqvAJBBG++PkHqA3Cl101c=;
        b=TBFushGJjHEBHplchHTmgQbNiApZ2V5OwyijPeFYUSgMCIAwOHnT4ACmqnnm6COJCB
         1Kqg4Ithv6lK8i3ekk24RzJa9wo4anJmd2AWM/mVgt8WeaRMCaxSknAKJAhkWlXpqObU
         Jc1rdLqmMzr1/+uVQI1B4hKQo4B+oXbfast2+8Hk6vr3IFv76v5/QJ2je1i3kRsVsZWr
         0cIsRXeN4zK0wzgS128zTH4sOHRngKkYww9yjtJLvDp71McoaKzEEiyHc7pbn7otp5wl
         rpXOq8r7fqZjAOA74dNqPB21lGPHGJ6xvSWn93yp6PXNes5XzFOf1HeTxzA5jd4Zw/ln
         92dg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=CSGzfx3o;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id k18-20020a5d5192000000b001ea7db0abddsi844628wrv.6.2022.03.02.07.13.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 02 Mar 2022 07:13:39 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Will Deacon <will@kernel.org>,
	Sami Tolvanen <samitolvanen@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 2/2] kasan, scs: support tagged vmalloc mappings
Date: Wed,  2 Mar 2022 16:13:31 +0100
Message-Id: <2f6605e3a358cf64d73a05710cb3da356886ad29.1646233925.git.andreyknvl@google.com>
In-Reply-To: <9230ca3d3e40ffca041c133a524191fd71969a8d.1646233925.git.andreyknvl@google.com>
References: <9230ca3d3e40ffca041c133a524191fd71969a8d.1646233925.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=CSGzfx3o;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Fix up the custom KASAN instrumentation for Shadow Call Stack to support
vmalloc() mappings and pointers being tagged.

- Use the tagged pointer returned by kasan_unpoison_vmalloc() in
  __scs_alloc() when calling memset() to avoid false-positives.

- Do not return a tagged Shadow Call Stack pointer from __scs_alloc(),
  as this might lead to conflicts with the instrumentation.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Andrew, please put this patch after
"kasan, vmalloc: only tag normal vmalloc allocations".
---
 kernel/scs.c | 11 +++++++----
 1 file changed, 7 insertions(+), 4 deletions(-)

diff --git a/kernel/scs.c b/kernel/scs.c
index 1033a76a3284..b7e1b096d906 100644
--- a/kernel/scs.c
+++ b/kernel/scs.c
@@ -32,16 +32,19 @@ static void *__scs_alloc(int node)
 	for (i = 0; i < NR_CACHED_SCS; i++) {
 		s = this_cpu_xchg(scs_cache[i], NULL);
 		if (s) {
-			kasan_unpoison_vmalloc(s, SCS_SIZE,
-					       KASAN_VMALLOC_PROT_NORMAL);
+			s = kasan_unpoison_vmalloc(s, SCS_SIZE,
+						   KASAN_VMALLOC_PROT_NORMAL);
 			memset(s, 0, SCS_SIZE);
-			return s;
+			goto out;
 		}
 	}
 
-	return __vmalloc_node_range(SCS_SIZE, 1, VMALLOC_START, VMALLOC_END,
+	s = __vmalloc_node_range(SCS_SIZE, 1, VMALLOC_START, VMALLOC_END,
 				    GFP_SCS, PAGE_KERNEL, 0, node,
 				    __builtin_return_address(0));
+
+out:
+	return kasan_reset_tag(s);
 }
 
 void *scs_alloc(int node)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2f6605e3a358cf64d73a05710cb3da356886ad29.1646233925.git.andreyknvl%40google.com.
