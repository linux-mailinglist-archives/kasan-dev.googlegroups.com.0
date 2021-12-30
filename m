Return-Path: <kasan-dev+bncBAABBNEJXCHAMGQEPBEEQWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id CF571481F7E
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:12:52 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id g189-20020a1c20c6000000b00345bf554707sf12968549wmg.4
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:12:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891572; cv=pass;
        d=google.com; s=arc-20160816;
        b=hDTqHM9LbmupLG5zj5itwqSnuyXvXjs10G03lg2DWcMxuv0aeea+bYExdwVp3ZS6jR
         MUFPOYpwgeK/1jyXZbgAh/Pe+oMjmubz5juiGmxTwgPS2vHcVQvz0u20oT8b2V0h0Opr
         81/xKzwO6EibQM24bemle+SsUqTm2T2fBsCdmjdskCkJvz/I60k8aiopfVHhmFkdMkmn
         uh4OgXSFB+138f4uDEpWKEP7J+KPQ1qoC7XJUCKoEoqNY8uNiIyzJL2U/HFnS3GcILtp
         bpz9j+iaHZs0gspofbqnA+pN9v/hl9bMZLe3Dwq9PoQ9U3xkWrjlUpm66uGlHdcSAFh0
         Wvhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=LwykSHxwSEot7aT4emakZG48JYoMVTUFjIk5kAjMgx8=;
        b=T5l8HPcj2KHbMG2OTnibnkeZoXAlGaDh6FxDRPNaTVnzrwy3Vpb99yJFc7ZBh0ZcaM
         A0leWRHkJa36nbAh8A5f9ETvRZT52K6uHRbmC+aW6MuUP4T/6+Y9FOrr0n2DhypnIIGq
         t1c7C5s0aP8FWrwumtXFnoY+l/mf/Rov3Q//K0QS3BdE4GGxcYwqLBhz39hIcVRQ1bN9
         mPmLBGTg3AxximiGyqsuUh44Ot8/h3h594Oon9BynovBgYhvsfOzFV9oDoh5aHsmcLcH
         4fl66caMkaHYuh1JE6NMlPiipSQCkCYn13vI2vHKpPlRKed1RApO1+HEuQDr5HFn2CNg
         uFog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=VjUsadY1;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LwykSHxwSEot7aT4emakZG48JYoMVTUFjIk5kAjMgx8=;
        b=TJYfXuKPDuXd3vhsM5/IGPVN9wzUXP98bsbHkNbiTfZdQT/h5o1sFfgEPaqb/9MPT7
         lAE2xNeLA3kzcMMwoUsloIoaKPWkl5/EoT/hNPX/uZGg/ApfBLV1TxLBBtqLsuKpdt80
         Ye7r/54IpMqbC0bbqSXNA8uK6F10ZZXxZHOdNA5PBa0sopGJ2v/3/opN98Qc7ShI64Up
         nMoFTSnw9ap7rbRq1ZT+4vxvIf9qM+HJwUYVhAMBPKeQpFqRadmveFH7417sbSJkENBt
         hKsNB/YLCB2/m78jg+se8C98qRUqVfRTeFnG5XW6RkTvER2C0THMjFGqHXz4xeu0+WC1
         jgBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LwykSHxwSEot7aT4emakZG48JYoMVTUFjIk5kAjMgx8=;
        b=XTzW6RcsSdtTumESCmSXOByPiNN6Mc7m9WdEKmp7WBdJMX9mQfPfrXjzOPOxzAaerH
         l9raaxEFULVudWtYs+5AJ4ndHFrVEPiMNV91QCyi0daLMZc3Zn4rRqjt1ibq9MVOa37O
         56ea2qKp8j2xLSFKMInt3z9ScXl6bpSNkjSyPJ0f17ii/8JUekKR8OP22WJ02s7yDh22
         hDxT3QIDAnAIKOBClaySPu3nu5QKFO0b47rd6eKecJQP+22DCQYnwH7eu8d/UQrv9zmb
         kQZNY3fUgN7COssQEcMWD3SF+MI9qSWy/usIeLHIUZJQ4O3gbYrYdcF7/UWQJ7ERR3AQ
         BYyQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533U4ZcsRMRCwip0vWVS6QX9fBHwszYuOvFHtyKPN2LB0Xvp+skm
	0JhOX2fQWwUuiY2mUniysXE=
X-Google-Smtp-Source: ABdhPJwmO3b0S6YsRGUtt7GXQOwFykI9v/tWrib5cSz6452M1vBnAWd610DMEQKALmMGh6sHX3CXPg==
X-Received: by 2002:a7b:cb98:: with SMTP id m24mr27711204wmi.188.1640891572627;
        Thu, 30 Dec 2021 11:12:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5111:: with SMTP id o17ls322516wms.1.canary-gmail;
 Thu, 30 Dec 2021 11:12:52 -0800 (PST)
X-Received: by 2002:a7b:c30e:: with SMTP id k14mr27049846wmj.156.1640891571947;
        Thu, 30 Dec 2021 11:12:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891571; cv=none;
        d=google.com; s=arc-20160816;
        b=dSL97H6EgjCKcSYRDL3z13JVrat9w8ZcEX+9Epa80Nog+YzcD8faqOcaLxALBR5Qc7
         EHmV9/GP9hVewDhTkiVbh7e5Jj6GBCkmChQ1AoG7ksaESWA2HpfylXAa0gwBacr6mU2R
         K2nioLfaqsU6ezdkdSQxXg3/KZ+ESrZs8V9WOU3haNPTUms6kgbID27wzBf1dgXaF7mt
         WqcppFqP+Qos0Yq9emzqghfoDVUM3o8afNq+Gsf1bDuf8VYdDqT3lpf0lTbMjZ0BRDvo
         dmLapnoInl1Sp5h1olXyDDXFMJT+xMEJCqJcFFE71Bb8enWW1WH8qC6bjn9nKJxPN8E9
         8icg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=C7bL1Zr1naNl/Uo665wUTq0llGclMt9lfTghUSLQOMw=;
        b=td9Sq8nLJXD7LHk17p32Wy+p5xf8kwe3VEGasBPckdHW5UCL7hdeIMGkTxs7i0pRiN
         ux9KmAm6yLgBE1Hzzl3Vo+Ead50sXQKB9loRKNzoztJQmDZk0tO7cURqlORgvPT4wmgr
         xyzDma1ntTYt5mlUKL9cOma84xgywjnu13Awr4NBcCR6+uPEhffKM0LL1BVQyxIewxoT
         PPYmothMzuWj0sVtUlYb2+SC+A+9c++i8IzgqKk2hNjbV1ByBg4RIK4BfhtrlT38kC+Z
         MWfWxd/sdspgjF5DuR/Ze4OSP4VgfvMPSB7dRg/WduQXhSCjE7mIO37Y2Kq7NCU7GS8g
         j2rA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=VjUsadY1;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id m12si946354wrp.3.2021.12.30.11.12.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:12:51 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
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
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v5 07/39] mm: clarify __GFP_ZEROTAGS comment
Date: Thu, 30 Dec 2021 20:12:09 +0100
Message-Id: <4ef9f470c0d41437d7a2a111e2c739957f49ee39.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=VjUsadY1;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
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

__GFP_ZEROTAGS is intended as an optimization: if memory is zeroed during
allocation, it's possible to set memory tags at the same time with little
performance impact.

Clarify this intention of __GFP_ZEROTAGS in the comment.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v4->v5:
- Mention optimization intention in the comment.
---
 include/linux/gfp.h | 6 ++++--
 1 file changed, 4 insertions(+), 2 deletions(-)

diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index 5f893d994dcd..19e55f3fdd04 100644
--- a/include/linux/gfp.h
+++ b/include/linux/gfp.h
@@ -228,8 +228,10 @@ struct vm_area_struct;
  *
  * %__GFP_ZERO returns a zeroed page on success.
  *
- * %__GFP_ZEROTAGS returns a page with zeroed memory tags on success, if
- * __GFP_ZERO is set.
+ * %__GFP_ZEROTAGS zeroes memory tags at allocation time if the memory itself
+ * is being zeroed (either via __GFP_ZERO or via init_on_alloc). This flag is
+ * intended for optimization: setting memory tags at the same time as zeroing
+ * memory has minimal additional performace impact.
  *
  * %__GFP_SKIP_KASAN_POISON returns a page which does not need to be poisoned
  * on deallocation. Typically used for userspace pages. Currently only has an
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4ef9f470c0d41437d7a2a111e2c739957f49ee39.1640891329.git.andreyknvl%40google.com.
