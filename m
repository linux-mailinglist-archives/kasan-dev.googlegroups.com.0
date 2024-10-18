Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBTFWZK4AMGQEBJNE7SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 271EA9A44A8
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 19:30:54 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id 3f1490d57ef6-e290947f6f8sf4221151276.2
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 10:30:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729272653; cv=pass;
        d=google.com; s=arc-20240605;
        b=RPUj3FJhiL3WOmR3h4y9QuPqSWb+X59W2dYWBl3s2bmmcpMmg6XOacCkKAnzDvq/HC
         Xf0/qPBBaovSRdThECI8V/MB8UiUGzVhBYwF39TESbHAOsOwT340+QxqhjY3ZtdTpIgt
         TfHwuVbqTC3wkl7ErnMaHautiIo5rpqw0xttkxVcjrUHkAt2yNz06hXjEcH763PRKLvZ
         2cSf+7t7XCk2fDtgDp2P+UQmxal0SlYAGLe02M5u4CQGwSm7G5zJmDefSxrU4dOUwFUf
         GlQ03H6XWpEpvqMrFnitKFfSBgjTg00rAKfud7RLsfW5u9b7obOi2f0SOxqVsDBtC/Jx
         yKxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=S4mqonSYXZ+tJiUgQa9Mla9vDeMaAmfUW/D15KBVCwA=;
        fh=yIBGY6iaeKdm7fS9dyFKu01hbK+ZYOOiZhVSdbWzUpE=;
        b=LNiUz/N2lT5cPQzc1vAXmuC4kvAS+jwsoCVGX/Txq0jMstvtmWLp01pk4rSRsyqDes
         ioZ8wPc3OoAwl5zWuIHA7vUpCcTYhUjjeeOLJDfckUCLtJ61xfz0wVTGUbsf+Jemyr9p
         qe6Y1g4Svez81zXVByTDwu6ZZflOF5S/9eZozOwnvFoZHuYv4F8Fa4j6D/+KauxlBggS
         Cvtdl0ZOpxdJWPQal7Sq0oGUqGILffRdASo5np7kugdjLBkwZIp/4rZy8qYK1l3jYCPU
         deU9v41bpWNYEbhU2dox8y+cec0DaVMr7yBpazSk5kl0YpQ5VG/utb07Ls1Zyk0yq8rC
         wFzw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UFr0Lsxa;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729272653; x=1729877453; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=S4mqonSYXZ+tJiUgQa9Mla9vDeMaAmfUW/D15KBVCwA=;
        b=fJLMKXsBvg1YQAJV4X3pFRFQBgEny0ibGErF3/WWF2bxpcckWCLTzv9bG1q59+MZKB
         94PgZsT+hWLw9YmnkZIN/hCIk9Zw9nGGUetRvGVfIVL1bYdY4kE5Nuw0tYz4jichf4h9
         npod4ySElpt5XtkE//4MuWzAJHnvbvRKoiI0l9+5qf3tfMJYWnCl5M3R7n/c4UM762uV
         7CJNxISUJgBhDmY5YJiGXHr8Be6JfURN1cwhuw6x4vBhNQklQE/4Kv4O64zUdqfTxGnT
         5y4WrHDmDVIeqUedM50UcJ7ROeckKidKZHrmitKIp2jSNpvjYkLtMkBGQ/LT3edDOK0A
         VBvQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729272653; x=1729877453; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=S4mqonSYXZ+tJiUgQa9Mla9vDeMaAmfUW/D15KBVCwA=;
        b=MPvPYgn3zjJQBGuXeND4rEQvikwBDLEnA4+GyTNDAdwg+Hg3sTrh3uh1Zn8Zj7nqs2
         DajTQTZ2qtonN86YAfofIUHBryjdSR+2zVwqtjuKLbStXBmpZ7g4mCq2nRq2Br18JLkm
         5r+QIrXH1D23+cyFzWpE5Yu8Xc4g7wOolNWNq+uPDrptvhPpoFMFTpVbRmtOHbbXhQ3e
         IKkgYqSR9ixoKlDElVlnKkHBuLpatKcovF1+NKOPCCzp4Kld0gXBE244b4rnczvPiXuk
         V3PgAfqZyAwWOyKrO+ZBTuSilWE6lrQu8jDA12jWJoXg8TUsQ+gB3HDAQ3cp8cAvuuqP
         DzLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729272653; x=1729877453;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=S4mqonSYXZ+tJiUgQa9Mla9vDeMaAmfUW/D15KBVCwA=;
        b=ldopVPdu3FzokzEKSrnlNp15+nIyJ8385VxlX7UqAyMaTOzxnY66ylmyafB/418C/p
         F7bhDWmuYdjtC+uxomiMm1oWF0U7Miq0VNp7s0oJmJ4cOFyLwwPYk50lqsdX+BaUEPbB
         6mH6WRHlgJP9xZLXriZja5Byb4HdREFo6p7Swp+AeuKp+vNvWQ2o2gw1gGafUoHpfaVN
         O4ztal91IkS8qoi51w149VLwOn6y50DB/P2Y7nl13LIzKYFbj5bZ3Ee7ozfBP5nn5g24
         OUUNX/+62x/QUM1Ao8B3eVMAZnc6Bz0MeBIA9/QTQcyBEUVlhsbwhoZqPdsd4rRR9M5g
         0fNw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXuUSsP7xo+ikxQ2j69YNFS6/VjxmtpiocZAMVLPZXnKsVoQinWnUaAnxw5abT5DR6QYDsetA==@lfdr.de
X-Gm-Message-State: AOJu0YxER+9TPDIm5YRcXM8vV5rQCnH9laD+rqt4eG4WzBSy1xg7OWCV
	mzCxiZGkELJnyA8rTPOoAqCw2S+N0cey3dBk9sbZRglz8dXf9rZG
X-Google-Smtp-Source: AGHT+IFUYkWGAY7F1oQfgXPmSuelvR1H4aLPp8IZn/7tXRzUmGT3X/nEa9wVjUNb341aiHf3ov0V/w==
X-Received: by 2002:a05:6902:72f:b0:e16:6c22:8112 with SMTP id 3f1490d57ef6-e2bb11bd758mr3117687276.1.1729272653084;
        Fri, 18 Oct 2024 10:30:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:72c:b0:e29:6c21:20b6 with SMTP id
 3f1490d57ef6-e2b9cdf5688ls2753303276.1.-pod-prod-04-us; Fri, 18 Oct 2024
 10:30:52 -0700 (PDT)
X-Received: by 2002:a05:6902:1104:b0:e29:441d:33ee with SMTP id 3f1490d57ef6-e2bb16c38cfmr2884704276.56.1729272652132;
        Fri, 18 Oct 2024 10:30:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729272652; cv=none;
        d=google.com; s=arc-20240605;
        b=VDFyRVAlJ3c7N/7Dxit5neIf3zTIClK2HFWUTBecmHaqGVof0Ww8LR5j153HF9K/uW
         qykYeeAHaz5ClOYtfhkjrLksYw1wr9J3jQze4rvQ71LcgzLZuhUwcf4T8EDSRFeAelee
         S8wkNtUqtlD3kuU4rwyZgN4zHfEcZA5KbJjJZ3jvnfyfTg+VG3DWKAlsrwOHbe8frn4T
         j/WUBwTLlbL3co1aSW2b+tws5MdjIWPqhcWl//seOsmW6eyfIO4QjN+Z9TIKT/CXCmwA
         cwdpW1J50CwzMTEhbj2EROEM3Fq0/NHVcya8ZzI28awC+yJ5iGLRO+d2yGSfwV6Wsnh4
         G9Cw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/yT2xkfY2cuEcnEiccNoddLAZz1lOngFGOhNqKs9rtU=;
        fh=Bj4mozzLk9zJsLtJNyH+nEsVaBAd92VPaXopXx18a2s=;
        b=lyG47wfuK3TxsZ33Ny78aG1iSWdpQoWJdYfCSwLcbWLYnuLPM1Ps8TD4tcZSJ7i8aE
         irlhUskax7JsQXGNm+Z9L0czsypgk5oIaHlKPAHwala0fM+oXklN26bNp0rb3aAqiaZ5
         tLF6roSOvFVR/07bW0VnTT+mCaLREXAhyTQcjxHN/IWRPrJYmxrQt7c4YRpc3Apb1Seh
         0Xs4PD4I0+dppPJsKhFK8Fs0B5MDijyK2LqZM4nZ5zS6UFNBF1KQ3kBn8yBIbrNFkuMs
         OL1sb0R3iWE25O4naBQnT0Vx4DU+nob+JpE6Yp7xlWLD/P8Nw98V+7oj3papIzaKRQR3
         EuNQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UFr0Lsxa;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52e.google.com (mail-pg1-x52e.google.com. [2607:f8b0:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e2bb052b405si101594276.4.2024.10.18.10.30.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Oct 2024 10:30:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) client-ip=2607:f8b0:4864:20::52e;
Received: by mail-pg1-x52e.google.com with SMTP id 41be03b00d2f7-7ea8ecacf16so1734663a12.1
        for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 10:30:52 -0700 (PDT)
X-Received: by 2002:a05:6a21:3a96:b0:1d8:fcf2:9ce2 with SMTP id adf61e73a8af0-1d92c57db72mr3781064637.44.1729272651290;
        Fri, 18 Oct 2024 10:30:51 -0700 (PDT)
Received: from dw-tp.ibmuc.com ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71ea3311f51sm1725242b3a.36.2024.10.18.10.30.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Oct 2024 10:30:50 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Hari Bathini <hbathini@linux.ibm.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
	Donet Tom <donettom@linux.vnet.ibm.com>,
	Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Subject: [PATCH v3 06/12] book3s64/hash: Refactor hash__kernel_map_pages() function
Date: Fri, 18 Oct 2024 22:59:47 +0530
Message-ID: <0cb8ddcccdcf61ea06ab4d92aacd770c16cc0f2c.1729271995.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1729271995.git.ritesh.list@gmail.com>
References: <cover.1729271995.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=UFr0Lsxa;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52e
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

This refactors hash__kernel_map_pages() function to call
hash_debug_pagealloc_map_pages(). This will come useful when we will add
kfence support.

No functionality changes in this patch.

Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/mm/book3s64/hash_utils.c | 9 ++++++++-
 1 file changed, 8 insertions(+), 1 deletion(-)

diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index 0b63acf62d1d..ab50bb33a390 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -349,7 +349,8 @@ static inline void hash_debug_pagealloc_add_slot(phys_addr_t paddr, int slot)
 		linear_map_hash_slots[paddr >> PAGE_SHIFT] = slot | 0x80;
 }
 
-int hash__kernel_map_pages(struct page *page, int numpages, int enable)
+static int hash_debug_pagealloc_map_pages(struct page *page, int numpages,
+					  int enable)
 {
 	unsigned long flags, vaddr, lmi;
 	int i;
@@ -368,6 +369,12 @@ int hash__kernel_map_pages(struct page *page, int numpages, int enable)
 	local_irq_restore(flags);
 	return 0;
 }
+
+int hash__kernel_map_pages(struct page *page, int numpages, int enable)
+{
+	return hash_debug_pagealloc_map_pages(page, numpages, enable);
+}
+
 #else /* CONFIG_DEBUG_PAGEALLOC */
 int hash__kernel_map_pages(struct page *page, int numpages,
 					 int enable)
-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0cb8ddcccdcf61ea06ab4d92aacd770c16cc0f2c.1729271995.git.ritesh.list%40gmail.com.
