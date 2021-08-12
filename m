Return-Path: <kasan-dev+bncBAABBAXM2SEAMGQECMKPGYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F5593EA6E1
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 16:53:55 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id x7-20020ac259c70000b02903c7883796e9sf1701123lfn.11
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 07:53:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628780035; cv=pass;
        d=google.com; s=arc-20160816;
        b=LDvqd9OQ3/MoYKz6z3UCJjyl62p+DtM6SWxe4nXBljDkXvwmXrh6L2oSlMNb84oiBR
         HuMUcIvrqHQ/prHsD8Zq4afT6t64Hij3pu2P8VBUX+P+EiA7LLx4z+xL7ENyair3Jvnr
         i0gwM1UhqFJes55gMXHq8yk1syLYmvWzMFOKLKGsrJaBPKPNqULw6hCe7bubPqRDGbHN
         s77CCPoyYNMWFdJUm7VCFJsZiBmL8iu6EyD8Z4vBY4KE+wZKUleU1ZUhmjN7z+TTfYS4
         cY2s/MEwAAsTWmtdCz137Vqpl7Hi8gmO/bvxSGdOnhGPupl53y8dio2GklhI3s4YpESZ
         F98A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=XVLNI4J4znywktcrJb01wHwgqA2zk3G9HRgcS7jFgSE=;
        b=WltGwqsqwkQPanuSgoRejdHCJvlZIWi1q/+DhY4WK1iVnFs9+vgYxo+hj4eb8evEof
         CYaSfswCVIxOpIEG8XxLdxE49G/jgPX6sQYe0P+mfqPU5LLMV87wTUDyJqZzEJOvllIj
         OXnPA1oGlIfu388fN8xeOE7j8diEq8IhlL963BHqHjfd2eMo2b++F1E4u6nCjt2jOTCX
         E4wx/2zmAyyy9TZJ+x2BV1cMUiOA2j9YEk/jW9i+XpXXrlxL72AyKbcymIznHOYyTHKx
         wvNvKRDUYBJ9BvcRnYFwXUaZMlVCy2FIsjr3suwjw7/glgPriM0s2p/CR9XeM5rU1txW
         RcYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pr6XeKYA;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XVLNI4J4znywktcrJb01wHwgqA2zk3G9HRgcS7jFgSE=;
        b=VZ7Sm5DUdHOIgMq0nG4SRNhnbyfrki1SjEKqS3Zhb9HCeQ9PexF0bn3tSBpUutgHwu
         KT+g4+judBQkNTk0t/jwgL44pRdA58V3lZF4xrQSuykumhZFGh8b1pz9iNDwYmOB7Hnd
         cw5kuAkd78x3m+E8vcXk4StpxkGk4DGL86wFDV+Fpfn3WFxum3FiX4RoQ7s6wRF4Xwpo
         HVuhoylf7eweSmRAffPfOpnGHRIqZBrRdyNe4/qUZF+BH9X8gjMyOmMnACAG12GyXohJ
         dPxarSas38Ej/hgcvtunGtwTKW0gKQ/tlhXjP6fp6j1YXQbIZiFVtMEnT8K+eS7BAczm
         Gyew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XVLNI4J4znywktcrJb01wHwgqA2zk3G9HRgcS7jFgSE=;
        b=SvDPxq/VOgTyrbhHWedseiE492EripN7Val5Fy+f5im1Xi51NmRmqqHozhSfSPEHpp
         ZJvt+GDdX07pFRmjX4nuZZhzGFkjb+tRxoo4Hv1cmZ7u+DeC5jUd5wlaURPZ98YE09+l
         Si+r8rSIKZm/gTBaqDWD2PlFILd/+VKkQRGxyrC/lPJu5qqWG8riTzmKcpMepQ0MNqhf
         8KZcO+9A8NQlEiDrHrxjlRLGs/gbBOGcHejEBgPGLmTyudqS+8pTkoLV4kBLUBAGtzV9
         qcSiy3g+ZJ4vQtJggSzfDwmB7bpqId9pq/eQ2g3ASFER9UyMGJ6zScFaYVTRFF/ARebo
         lDfA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533gzBaQIgzH0C2Q5AUyAO+UL6YaUYnX1OCfuRKYEWcLtMVzlB3Z
	QuNlwzsxQgiOP/ckPZdsBuk=
X-Google-Smtp-Source: ABdhPJwl3goUvWB0/CQbpxc1jAioCW04JEh4fjGFtbzb/O2ekTEsSYLufWJ/iSE7LK/VydK1ZIdz1w==
X-Received: by 2002:ac2:4573:: with SMTP id k19mr2783889lfm.459.1628780035015;
        Thu, 12 Aug 2021 07:53:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5395:: with SMTP id g21ls725505lfh.1.gmail; Thu, 12 Aug
 2021 07:53:54 -0700 (PDT)
X-Received: by 2002:a05:6512:1592:: with SMTP id bp18mr2925621lfb.350.1628780034299;
        Thu, 12 Aug 2021 07:53:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628780034; cv=none;
        d=google.com; s=arc-20160816;
        b=yDigGMAsl1dimJ+rBSN/U3v0WD0+w9Wa6dOf8ejusC5wcKI3JjO8rdaSIPpFb7jGEn
         zpNXAmC1rpHbVklto08g/MVMQXlmMHPzsg0jFGkIIoXGSdWB+Hx4DAsLuaY+6tRBSNIl
         ditHo1/Mg4RRCr1AtoPVZ0bVXt0DZ7M1qvmpnBpEanYpTUgjJouLbDgSI9tECmblvPn4
         Tm6jB5TS0SzGyLjdPKLsnTo3hYFOXjQhtmVKWktNNNqTEuIeTa9s6eYcUTFcTY+h7izZ
         wQFjDrDoSHDpdqo8FB5PHB1MD3sR5eACfAJ4IxTI2rToiPyrIGLr6rbn4YMhvK0D+b+W
         8lkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nFE484nExSDg5Ok/GAjUckuGCTsrDMPO22KkRkoS4wU=;
        b=yCOPDORJS2UlE+BWNoDPGB/PMK52BxBoCzI2oy0dwAeSki6NZO++tQiHewN6pACvgB
         ej+lstsaQCIxXEZUzKkhvYfIrO2KtaKL1xGmCBwWDDSONT3+JYgWP9Qisg2z0sLcnUll
         VP3vWVHsVL0ECa2RXnIqDowS1sFunz0rclGIzJ1WWaOifCg1BNZGxO16J5BvEbtyu1ok
         ffccT+lv5YD49x8cfUG+oiovsjPRStzcGqGnmuAOJTAQ5rt5fW+M7g22Hq/Oxuk3+sTN
         RFNcS+iDATp9lxmRiOGx/PKBPOvCelBnsBui568trMlg+g02+ckpONdSRxesifAJu+0H
         9nMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pr6XeKYA;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id k40si140598lfv.0.2021.08.12.07.53.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 12 Aug 2021 07:53:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v2 5/8] kasan: test: only do kmalloc_uaf_memset for generic mode
Date: Thu, 12 Aug 2021 16:53:32 +0200
Message-Id: <2e1c87b607b1292556cde3cab2764f108542b60c.1628779805.git.andreyknvl@gmail.com>
In-Reply-To: <cover.1628779805.git.andreyknvl@gmail.com>
References: <cover.1628779805.git.andreyknvl@gmail.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=pr6XeKYA;       spf=pass
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

From: Andrey Konovalov <andreyknvl@gmail.com>

kmalloc_uaf_memset() writes to freed memory, which is only safe with the
GENERIC mode (as it uses quarantine). For other modes, this test corrupts
kernel memory, which might result in a crash.

Only enable kmalloc_uaf_memset() for the GENERIC mode.

Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 lib/test_kasan.c | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 1f533a7346d9..1dcba6dbfc97 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -534,6 +534,12 @@ static void kmalloc_uaf_memset(struct kunit *test)
 	char *ptr;
 	size_t size = 33;
 
+	/*
+	 * Only generic KASAN uses quarantine, which is required to avoid a
+	 * kernel memory corruption this test causes.
+	 */
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
+
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2e1c87b607b1292556cde3cab2764f108542b60c.1628779805.git.andreyknvl%40gmail.com.
