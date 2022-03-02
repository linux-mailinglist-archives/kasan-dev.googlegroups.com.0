Return-Path: <kasan-dev+bncBAABBIV372IAMGQES65WPKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 7DBE64CAA88
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 17:38:58 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id az11-20020a05600c600b00b00381b45e12b7sf1012409wmb.6
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 08:38:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646239138; cv=pass;
        d=google.com; s=arc-20160816;
        b=jLZi9HxHnKWOx/izn981bmR5wDqN/SggcJizhk5Nt8XjHJ4703FRom/4f9qmHnsNx9
         StFCKmq7ot42oDy2cA8dGoK0LCLfHUgTlrumPq8EhSDFzbA82WVN0pp1JnlnsJKWWI/W
         amQ5PpVssjz2HPqolXjqNpIzU8y8T7nIBqZ8SRx6430Lbq3zUoQzK25VX2Jhl2C4VDa+
         bSt9I8pH/XF3k294jRDCEah9oEBzy902FzFgybCfL78yWahdodlDc5nS7Nw3cdyXbeCW
         kT2VH+xKiPicIOuUO7MzP55B+wkgfxq69QYECQWVflY48h3Vb+hV7ynJKPlVQdyxe7ZQ
         gHgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=mK+QrSnkAgW9oa6wtMiL3DqVwQhhOVrT/J0A2CEgkQ0=;
        b=ddkzZFpsiGYd8gIFeC9dep9TqW/n8YkuU6Jjmvh6Nuk/WiHK9haMbmRoCJH6DPzJ1F
         1pBv/RUdSm9tOZ1SZGRNgOiE9/+XLNNSYlAXUgylx6jMTc0fJEKJH0I6v8lvIJH+Kx9U
         myBrEf7ZKKESJ7sS3KgGUSQiLgLu06phG1Z5DJdqgVnHk7Esjz2SwzQI01dF7Zt0BSrR
         aYXLXYBu3jLKpRYdQunbpfepgVWVmj8fYsjof3jqVzJN/7m4SyZ9MkUP7sQ215MsXKrj
         Gh4bBKFjEIi/8yAeOW1HD59qMEAveUwe1VaHGwZPun6Wh8VcIjUM7AGjkgjLtjJ7olFH
         g9RQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pFiF5ZBB;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mK+QrSnkAgW9oa6wtMiL3DqVwQhhOVrT/J0A2CEgkQ0=;
        b=E9wvXhKwNiZYBVtQRXCfCmEAejj26IGxO2Dm5bmzP+Vwv8GUssB3Sk5DSKVhMBYWvs
         9JUhoHyS5hb4Dwvfl0fALbZTdXg1uBRULq+nS5bsZW1/dSd3iBavNXD2AK9mw4R/EIMJ
         Jer2CtbJqzL+uDb1DtINbjLwdunVi6j5xS7T1hLt9gZEJy9IlBs9/KLJo56XFvTlaYU4
         2ad4JZ6eySdn2cGM36LbSoQofrlwj8/kv4Qn8RL0e3QsNW9kBrXMKb7/SUoveIWJkCkK
         umaq/3LrWlx8Cux4fwhrtcPhgZNrhnaFTEM5facaM8v5qK4GqsiWpPRR3WTZszVwZNr0
         0PqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mK+QrSnkAgW9oa6wtMiL3DqVwQhhOVrT/J0A2CEgkQ0=;
        b=Q8DpIi6HZpuU2Ajj8HMRUbutE/+ecdFzOhUBUbh2i4FabRZA6KlFmFLO2/sfFJjhd3
         e5VORwzS5PAUrv9mKCSjSVFJvKGuM5VTemKuG11l2TDw0FyB0DOb2bKrmFXgiCFdi5H1
         0H/vHXaUMoSD7YR7Ml1J3o6wCfadPFo+MO4ZTBAAXeOLjem2h7CMDrgsatqKx47/LVBk
         hbp2WeesSTisftM+CuvhlDPr6FCu8BRaNUeEf7F2aD6iKWVq51ftSKqrI3y2mLdcgrAk
         R2rXlpq+e6obW0roqoQocTlzoBKmNCoGRovVlfUCT+JjiYllNIh+jXNTbFq9Augh/tzQ
         dteg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532cukesoh2pCnaVGHgH17hvnLPbMuRERbIqLZqrQ08lQcCQHLa/
	SsQycuRDdcKCEW3dG/b1B3g=
X-Google-Smtp-Source: ABdhPJyDpv24K6iNdFreKr2jsixrOrbJuQ275AohnbWsOyb3y9emWEUzb+81/FgM2OKQAFXdVT/7pQ==
X-Received: by 2002:a05:6000:156a:b0:1ed:ab73:e248 with SMTP id 10-20020a056000156a00b001edab73e248mr23913841wrz.292.1646239138254;
        Wed, 02 Mar 2022 08:38:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:47c6:0:b0:1ef:f983:3883 with SMTP id o6-20020a5d47c6000000b001eff9833883ls662897wrc.2.gmail;
 Wed, 02 Mar 2022 08:38:57 -0800 (PST)
X-Received: by 2002:a5d:59a5:0:b0:1f0:bf:64c9 with SMTP id p5-20020a5d59a5000000b001f000bf64c9mr7491278wrr.352.1646239137448;
        Wed, 02 Mar 2022 08:38:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646239137; cv=none;
        d=google.com; s=arc-20160816;
        b=M4gFYCkDbwgeoMI8/7MUHIALwY6nCPIjHofc1fp8ZVQKLr0VCSGTy7gkOFHyKK7p1I
         lR353W95r18fdPPzi+6YEloQFNPJzH39Tngu5/DMlZFU9z8DCW2OHs4Gpk3PPMNT9ZBj
         tpy/Njw0JYvIr1wyxGuIOe3878VcGKO0y8SKo+RSOpgZ8FVxbHImfrcsmXrYEBwFmMqB
         GNGx97/z6WJdzv+gTuWYuoIL++3hIqy+vQoLkdoqgQ9BFwo8ADoLPcfKaQkWyzc4KWEt
         1uNkv7PxdnKlj85+lY80u+q23MKkZ6SHKEOqxQNIynPw7Lr7TJKUnzhA/sTlwNAu59mp
         Kbzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JGZE0bvysohYUpkupChxa3EWr4j93F81DU4moq+5lLk=;
        b=SyhB/UStzWTMEhM0rDGJdq7WAO5dZDMAND6DUBOKPmv7orucm7wk29JK4tRLjObRt7
         eRCeaqucFvCPHM35kRHgM/BQBnjIQf4ARtaAMlJVAxbtHPJkiDRB5VHVVTd4VJa7iC3Q
         KNCLb1qejALQP/LDeiePJPie5vDpr6iKcQIUazLOvxBN1DirN4+5oWT1P+rRKGxFAqMl
         uHE2QDuruxqFgY5FRudTRO/VNMtLbiuZoSibuBV+nvfAYvOD75SqSDmJdTGMoNSswHHn
         vKAsWuC/JsfWVtkD9dbUg9h/SnQGxdwTBGUT9hkTphUwb6vLkznBH71f246Yl43otjyG
         4hfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pFiF5ZBB;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id 185-20020a1c19c2000000b00380d3e513d0si293194wmz.1.2022.03.02.08.38.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 02 Mar 2022 08:38:57 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 12/22] kasan: simplify kasan_find_first_bad_addr call sites
Date: Wed,  2 Mar 2022 17:36:32 +0100
Message-Id: <a49576f7a23283d786ba61579cb0c5057e8f0b9b.1646237226.git.andreyknvl@google.com>
In-Reply-To: <cover.1646237226.git.andreyknvl@google.com>
References: <cover.1646237226.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=pFiF5ZBB;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Move the addr_has_metadata() check into kasan_find_first_bad_addr().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c         | 5 +----
 mm/kasan/report_generic.c | 4 ++++
 mm/kasan/report_hw_tags.c | 1 +
 mm/kasan/report_sw_tags.c | 4 ++++
 4 files changed, 10 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index bb4c29b439b1..a0d4a9d3f933 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -444,10 +444,7 @@ static void __kasan_report(void *addr, size_t size, bool is_write,
 	start_report(&flags, true);
 
 	info.access_addr = addr;
-	if (addr_has_metadata(addr))
-		info.first_bad_addr = kasan_find_first_bad_addr(addr, size);
-	else
-		info.first_bad_addr = addr;
+	info.first_bad_addr = kasan_find_first_bad_addr(addr, size);
 	info.access_size = size;
 	info.is_write = is_write;
 	info.ip = ip;
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index 7e03cca569a7..182239ca184c 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -34,8 +34,12 @@ void *kasan_find_first_bad_addr(void *addr, size_t size)
 {
 	void *p = addr;
 
+	if (!addr_has_metadata(p))
+		return p;
+
 	while (p < addr + size && !(*(u8 *)kasan_mem_to_shadow(p)))
 		p += KASAN_GRANULE_SIZE;
+
 	return p;
 }
 
diff --git a/mm/kasan/report_hw_tags.c b/mm/kasan/report_hw_tags.c
index 5dbbbb930e7a..f3d3be614e4b 100644
--- a/mm/kasan/report_hw_tags.c
+++ b/mm/kasan/report_hw_tags.c
@@ -17,6 +17,7 @@
 
 void *kasan_find_first_bad_addr(void *addr, size_t size)
 {
+	/* Return the same value regardless of whether addr_has_metadata(). */
 	return kasan_reset_tag(addr);
 }
 
diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
index 44577b8d47a7..68724ba3d814 100644
--- a/mm/kasan/report_sw_tags.c
+++ b/mm/kasan/report_sw_tags.c
@@ -35,8 +35,12 @@ void *kasan_find_first_bad_addr(void *addr, size_t size)
 	void *p = kasan_reset_tag(addr);
 	void *end = p + size;
 
+	if (!addr_has_metadata(p))
+		return p;
+
 	while (p < end && tag == *(u8 *)kasan_mem_to_shadow(p))
 		p += KASAN_GRANULE_SIZE;
+
 	return p;
 }
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a49576f7a23283d786ba61579cb0c5057e8f0b9b.1646237226.git.andreyknvl%40google.com.
