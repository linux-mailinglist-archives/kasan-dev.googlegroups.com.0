Return-Path: <kasan-dev+bncBAABBZF33KUQMGQESEK6CQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E8727D3C40
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:23:02 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-5079630993dsf3450439e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:23:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698078181; cv=pass;
        d=google.com; s=arc-20160816;
        b=lznL2Nis2XZ2c4w/zF1EFAfGbAEEWgc4CxskY+PYxbgK6p9p99rlfem7XOlyRsUtDu
         0ApI4R/pcfdb8SURL/285Zo0KFzg3cHaE37J4rLGuwMPznykhHpbjtcO8P0/ivXYAAJ/
         1B+2rIj6Pa6HriGQSiKyf31sUBhKUMJh4j1AtLqvsC4c81HBy4VOA+9x36KTuIPn45Rx
         bGJH+kSdJdrVsrvIIY9GGDAhjLqhSdWzBfyKBDAiXJR7NBUE2HsduG7PotNuP1EftZd9
         VVUbROISXIGIjuM75BMe4cnNfot27RtntC+CKbgLeUU3p6FYoxWtG5cFSYg35expJ/i9
         FmFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=AEpbLz5OjSg/bZqiD8xSBLh9ONO/qfEzkEOKpJNlNus=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=TqHO+rZNRlnIujKbh6FiQfY/2qGAfcpUoulsPh3GRruKG45CWaW7y9VqZtwfZ2tB0T
         geYDKWF+jJVeLTbg6YqLRyYu0Mjp3pZjVDyVnij7OpMsjjb+sMVjkBwf7By7hWnfCHlO
         +E/B+3zRuYKUP0Hxm7fEIA87p+4elO/4F5uruBsGXyLi7ijVRPmYR1yGw8M+gGkNFPyt
         kX5eeg7ScglX3wqG+qwBYnoMGzePUoDwhTpIn4aXxvpfCePgRSbTXEQq3D7zVkft+Gq7
         d9wh7IJDPS5HH4+9b1r1ATiLb0yp+CULwanK8xJjI4y7T1pn3ln3n+WKyLXF/Uumdroc
         YHxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=CkRusZIQ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.202 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698078181; x=1698682981; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AEpbLz5OjSg/bZqiD8xSBLh9ONO/qfEzkEOKpJNlNus=;
        b=HFnXH/HAs0ggnkzLT1mhjdrEBVOD6XQRQ1qjubHggFD2ybqBEO4W/r3jl0kenPVLJg
         ZhfS+oAyT5d9NNrhGHeP/ieyC7BS60dWT4YHCuNldIKK03mS3S3Pwtk7ixzPUeEqknR8
         fyiQ77sJ5fvtJkSdJaJzvcJO946c3/fG3hzyW9ck2s5KecHDbu58WTbdtugeApknjfMW
         nv3PdskixU6Tqkc3wQWAPIhSdJC8PXotxYVTHjTn/X8OrT7Hdt4DhEOixaQmSov524Cx
         y7rpzVuasAD20xRqdygtH4oiNRhvq5l+9r3yA9otOcaWjYuwzCzZAfQ1TEuVZT1Y3fFx
         vVoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698078181; x=1698682981;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AEpbLz5OjSg/bZqiD8xSBLh9ONO/qfEzkEOKpJNlNus=;
        b=VqWvGW8Gr08nY1JFkn0jKPujzSspQwLMRfQ1gvSzKXM4lwgoX9wfZml7LoIt+DwvyH
         qhu63lDN7EOW+xHreJHCfI61rPr97ndRdKER1f5ohc0byRoODLKhmqVmAcmdfnXcdQcl
         D54zP++mGVs4Re9YmChumi5A0wzuQ1fNwWHJPjXuHK6nY8EXeMsx8gIBI6r0AtcnYDc4
         sqvQwYupgTn8+pkBh196NGU7MHMvIt3mgz4LGl+ZFRHHhIwAVQmUCeoM7nSfmhujceO0
         eZMDvWTLRTu00OOhwX4++z3IPVb/EknzcPcWOZYMK9S1hdHDFOgjbrXIDcjFkwiLG8y4
         soeg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzXDKMG7vI/1RRqpskuNZ3bA1EBO2D91DY/ZBi13V4mZYF4F48b
	CGKq6zb/LQ5fQ7FbVb3g8DM=
X-Google-Smtp-Source: AGHT+IGZQdWdU3JmI3n+wDyZt1TEOnW2d2j2S6EmpKkSiSazM4e4MHo7xpr/V5hz0yuW7PJkwi8HeA==
X-Received: by 2002:a05:6512:10c6:b0:4fb:9168:1fce with SMTP id k6-20020a05651210c600b004fb91681fcemr8398405lfg.59.1698078180549;
        Mon, 23 Oct 2023 09:23:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3c8f:b0:507:9d16:db with SMTP id
 h15-20020a0565123c8f00b005079d1600dbls264218lfv.2.-pod-prod-04-eu; Mon, 23
 Oct 2023 09:22:59 -0700 (PDT)
X-Received: by 2002:ac2:42cf:0:b0:507:97ca:ec60 with SMTP id n15-20020ac242cf000000b0050797caec60mr6732684lfl.3.1698078178900;
        Mon, 23 Oct 2023 09:22:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698078178; cv=none;
        d=google.com; s=arc-20160816;
        b=cFNaP39n7Fykmae1CqUa2/zmL1rIuupuVZoFM031Xb72QZhQgE2BtP7VapJQ8VhqK8
         8ZwZ1dtiBsfvZyYi8k7MhJzRM6T/zd5O2L9Mfhlf6jxxm8C/7vNn0BouXFpam9twEZJx
         fSR2X1+IxZZlD62U4rpbwJQDPZK1Sfav2ylvWkBhfQbBNXX9EK2alHzKUwgKFr8wBxMt
         4Pz2SZQ6e1GhfMioKsQQzoluEC17XPAXiXNSO+Aa2dEpva15XgJ8saPBzPioWaQmOVYh
         2S1NmQfysbHJC9xhwhuta0VlwWvvx/YWFg56rkebumBpZyyjJJtEBChRx6s7yJbxa/il
         C8GA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=dA6zDrMISQ9ixV+61d0CbJSFq6N+6qPUyMdB5Zjx2Sw=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=HCY7YTWEQ8RfRDw8aE7DnlSNGUPPgmH6FU4DVSWsQtjA/0k5LD0hDa6yuuMkBreMrj
         IFv9W25b2eXDSYSo1iYVFT5wL/R6n3b0KglM/74XQgXOuOENnbU7FxPDiU4htEQrIGaN
         vdPL1mK4Dk+gygKyLuXmEdNxgADvJxoDKEsHS4/tNgTxXWu/Q+ULAWDqU+wqSA1+Xnsv
         lSZMm9QahAedlI2ZS1EWe1jKVf6Q5x8uY+icwSYJgjY39B/BlPmVTJ7BmeOzmrBIKWus
         lL5mct9XwV8VzkaOzPuB2c0F7iOUV4mOBej3NPfibp1AtSqwW14RHqbEtyF7etLJF33M
         g6ZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=CkRusZIQ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.202 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-202.mta0.migadu.com (out-202.mta0.migadu.com. [91.218.175.202])
        by gmr-mx.google.com with ESMTPS id b19-20020a0565120b9300b005079644d21csi308588lfv.7.2023.10.23.09.22.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Oct 2023 09:22:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.202 as permitted sender) client-ip=91.218.175.202;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v3 01/19] lib/stackdepot: check disabled flag when fetching
Date: Mon, 23 Oct 2023 18:22:32 +0200
Message-Id: <db27742c47b373f3957d2053457454b4b4964b34.1698077459.git.andreyknvl@google.com>
In-Reply-To: <cover.1698077459.git.andreyknvl@google.com>
References: <cover.1698077459.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=CkRusZIQ;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.202
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

Do not try fetching a stack trace from the stack depot if the
stack_depot_disabled flag is enabled.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 2f5aa851834e..3a945c7206f3 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -477,7 +477,7 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 	 */
 	kmsan_unpoison_memory(entries, sizeof(*entries));
 
-	if (!handle)
+	if (!handle || stack_depot_disabled)
 		return 0;
 
 	if (parts.pool_index > pool_index_cached) {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/db27742c47b373f3957d2053457454b4b4964b34.1698077459.git.andreyknvl%40google.com.
