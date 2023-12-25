Return-Path: <kasan-dev+bncBAABBBN3U2WAMGQETZCUFTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 652E181E165
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 16:19:35 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-40d37517936sf38911285e9.2
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 07:19:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703517575; cv=pass;
        d=google.com; s=arc-20160816;
        b=e95OkztiU8o0teZDW46soqlAyjygGtwDU3LiUv8gd+KKDLk8V6WizIOIYcc+8SqUXr
         wDMuFIL2RV/eanPoHAXjFhk9Pz/CAvLLRyqtxyHqWGp8SckeVzTtwpjoFC/SNERdpFc2
         OcBHZU6y2auud7YHASVyzQor5Fo6sTJVZYUuHU8enx0rLTpqFbO9muj6u3Kv85uAN3uP
         gEmNc5ZkzUsdU24Oo4gv+ApjjpzYH8bOlccztshneKeLNJnNLi9owioQwOkxGZLcnqSt
         n3VG2RXfZn0QTt6MtMxqBwZkLh29TI0KdDjdRYiFQSwPAvQ48joYcT3rehK8PVTR0MFT
         6sJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=vUXuDYIKH4SZOnnj0ZLzTG1RbUoZd1b9YoYCQD/Yd10=;
        fh=39a/93hWRhBqbTclet/W9kHjKz2DsjZ5PwpcxR0ys54=;
        b=TQU2nnbYntg7eebTCxdL/tvxj2R8CWo6pldegsmGI5sQCrWSNRhzLbgY2i/qAkOYkJ
         s4VnycZeh2nk7eg12ZL8QDoGeg3r91Qln1jgT5jKM5XIPngILZnYHXenoCdMjBmjATQs
         6+2pQoKkN721t52cxytCF7N5J5wlB3CLdz7E+QXardEXoO4SZnUmreP9S8NFNFig7aw3
         71oZBeu0vDth2oMiwTPGSfFut1aK19R3PJupK5DoO933Tfp4brnpsX5vC0IWk0XeMd4R
         dSrgbzD2kPCyk8/pm50yAZ0P1z3gUOa8D7RSNP92OGyGDkdPHoadier1NLDMXDG+cY5z
         18Ag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=W5ZZFxgU;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.189 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703517575; x=1704122375; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vUXuDYIKH4SZOnnj0ZLzTG1RbUoZd1b9YoYCQD/Yd10=;
        b=mfRBSpPj/y38T9VVhDO4uk3TlS2/k830b/kNs5fPwlapGDgURnauhLyiL4BWGDxT8s
         Q/cza7WDh23JT4H+Ovun0kHHQzguYAGBo0D+veMsuGdiCZW4GiPTa4FC559/6EDFbP2e
         Vb1NyPvPfos4VOYLsI1qleXPfDtauJ/ysvnsJbgT77idTwAknN2PVlUrnjnLalltGLi1
         928FXSIO9x2w+5B5oE7/YQitPIPdcJR77hBov5hKwjKudc+uN03QV/3AHW+dpunFKLr2
         rammFHS9AkEMzy2rZXHKFuiRS2yV1DWIufN4hSR1hZkx1z7em9F+I8LPalc1GPSqRVzy
         EZZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703517575; x=1704122375;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vUXuDYIKH4SZOnnj0ZLzTG1RbUoZd1b9YoYCQD/Yd10=;
        b=u4BQ5Uj+fdL+KXrGXZblJXyqOzkUTpvkaOj8qDJG1RRdVAZEvyWWYCiDAqtX3HN07Q
         V/MuFjnza+wwyVS1vtT672zCHeeVD7ib5y5B6QNBNi0ZQ2k1i7bypqC4aJ0KbTl7FMG5
         mQJ5vbJ/wmyK1RZzO8fKzK8PtOUOkxP7T8UCXi7kvlptvqvaMqrs7Q5i1CTB3v5csJ9C
         aIHPENpEPyCEsu2DuiVDhZ01jf1R/xcL+bxaAKXIHjtVo55B/rCxV0qOtR+do6IsaLiZ
         8dod1EhrGOxxioZeSn/lEIjAbFbMdqCHDYc2FdZ7L2LmeYiaJTgcn53N0+DTGpMylG8t
         akhA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyfVPIwtjAuw8sSyqeDD96JtVEfRKK04Pru/ZjGAk3r3R+8tiqq
	0alNv3p1YqscDGsXz+n5GR0=
X-Google-Smtp-Source: AGHT+IHSf44tZHCiYLNeDy/Xh0odu98zb7wS/WX93oGAHmjYPmTAKc57ZiAVTM/eUlNI/jRPT9YY1Q==
X-Received: by 2002:a05:600c:8518:b0:40d:4878:1abb with SMTP id gw24-20020a05600c851800b0040d48781abbmr2928407wmb.38.1703517573809;
        Mon, 25 Dec 2023 07:19:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b84:b0:40d:3a0c:41d7 with SMTP id
 n4-20020a05600c3b8400b0040d3a0c41d7ls128610wms.2.-pod-prod-04-eu; Mon, 25 Dec
 2023 07:19:32 -0800 (PST)
X-Received: by 2002:a05:600c:4fcb:b0:40d:137b:1cae with SMTP id o11-20020a05600c4fcb00b0040d137b1caemr3064331wmq.65.1703517572188;
        Mon, 25 Dec 2023 07:19:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703517572; cv=none;
        d=google.com; s=arc-20160816;
        b=IJYnFa5+QfwPnoRrA9OPP4dxyawEnHzm0rEXYJ1EzL4yz0JFtOpOIv7fCZ+Sql8mV1
         EO3oCTWcM64i9z+0rAFDR/dgqJ4nEWmrVjTwi5r8d5C3moykEtkfcQTWmCDwN+7GPVnK
         /vClX+TthXmhn1MknSyHh90SpvsC1ZQfp80jUIFWmE/rpGxVy3vSE9gd7A92wjJ1zkW0
         8iosxMgWlEwdyZ4rS1uQJ5fVmgPuFUwyts4RWhYStLLk//vxZdvnCA/6bDVbzohPSbMp
         c6KCORnSRrptHSBeJfycU19Cjcio7Fb7Oka6VUgkBIsMpDRrS8df1wsRVFfaFI8JZQY0
         MC1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=gtILRKJ0trYPt8tyQFLeNeQ04NHz6IkEJP80Wwo1cS0=;
        fh=39a/93hWRhBqbTclet/W9kHjKz2DsjZ5PwpcxR0ys54=;
        b=u10D5pMAB7ob2QYQ0buwmZku2frhhmcC/nq+qYi56MUS2EWCXPAXZ4LZFBOLGG6bfz
         3y1/B67reqrDOx8fzzuPUiZSOiIPqhQJCd/GhWxn2ibaBZrzXoJ0hfMJcTi2riDpm2gh
         byQaVvqf1U00RhfGPrWADj6Gs6/WJHD+2nqY3K/X6mztLuVITjP6qNgHXPbE+HFLAEGP
         B4Y9vBEbtKtmfuav+JLkA2/FVdtRlfTlm0nZlldeBfT0plqFkcd67hBrCEzdchpVVgkV
         /5+/n6BL7JjBurS4wbd3wCiTSmqb14+wahq79oCcYGt6bzmhqNZZnpXsk+n9NXgqyxDH
         dkiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=W5ZZFxgU;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.189 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-189.mta1.migadu.com (out-189.mta1.migadu.com. [95.215.58.189])
        by gmr-mx.google.com with ESMTPS id j34-20020a05600c1c2200b0040c69352d1asi179817wms.0.2023.12.25.07.19.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Dec 2023 07:19:32 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.189 as permitted sender) client-ip=95.215.58.189;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Chris Zankel <chris@zankel.net>,
	Max Filippov <jcmvbkbc@gmail.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>,
	kernel test robot <lkp@intel.com>
Subject: [PATCH mm] xtensa, kasan: define KASAN_SHADOW_END
Date: Mon, 25 Dec 2023 16:19:24 +0100
Message-Id: <20231225151924.5422-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=W5ZZFxgU;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.189 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Common KASAN code might rely on the definitions of the shadow mapping
start, end, and size. Define KASAN_SHADOW_END in addition to
KASAN_SHADOW_START and KASAN_SHADOW_SIZE.

Reported-by: kernel test robot <lkp@intel.com>
Closes: https://lore.kernel.org/oe-kbuild-all/202312240755.MqsWuTno-lkp@intel.com/
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Andrew, please put this patch before
"kasan: improve kasan_non_canonical_hook".
---
 arch/xtensa/include/asm/kasan.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/xtensa/include/asm/kasan.h b/arch/xtensa/include/asm/kasan.h
index 216b6f32c375..8d2b4248466f 100644
--- a/arch/xtensa/include/asm/kasan.h
+++ b/arch/xtensa/include/asm/kasan.h
@@ -18,6 +18,8 @@
 #define KASAN_SHADOW_START (XCHAL_PAGE_TABLE_VADDR + XCHAL_PAGE_TABLE_SIZE)
 /* Size of the shadow map */
 #define KASAN_SHADOW_SIZE (-KASAN_START_VADDR >> KASAN_SHADOW_SCALE_SHIFT)
+/* End of the shadow map */
+#define KASAN_SHADOW_END (KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
 /* Offset for mem to shadow address transformation */
 #define KASAN_SHADOW_OFFSET __XTENSA_UL_CONST(CONFIG_KASAN_SHADOW_OFFSET)
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231225151924.5422-1-andrey.konovalov%40linux.dev.
