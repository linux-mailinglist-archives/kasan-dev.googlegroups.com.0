Return-Path: <kasan-dev+bncBAABBINF2SIAMGQE7XUL4HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 786104BFF15
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Feb 2022 17:43:14 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id p9-20020adf9589000000b001e333885ac1sf9160237wrp.10
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Feb 2022 08:43:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645548194; cv=pass;
        d=google.com; s=arc-20160816;
        b=L8bB2P1CTj7ayF0CtLFaO/L+WqST9M23Lthmdnwr1l8K5M1E1MfUOvJBvYMtITiPKY
         HLuDg//5hCoJDqYwmFo59e1B1YHZ8mS2KDgMbcJt6GQOBsZiZWbsM2hNbEiV1qAi6Ftz
         +/NfmZrO3QF9pcQ4qw+Zvo9CoLSaWlxvDufynkrdA01B7lm5QTpQIRteoOukzUyC9Y5O
         8wjtXMGsEzQQPEZtWxzzKXy4cJdj2SpWzU/y+58v7NICwzUTY9LPrwGVP1HlyKnHDkDG
         L9PYMIwg14eRGBTc0Ei3sioQJBkd+H6Djb2fG9x4eYqM+wiwS+61g462hBJcOgwUyaLr
         Sd4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=yFTIQ1ozLSF4UgT7epFJkLnapAmASIPQkk8ztGJZ7BQ=;
        b=xe8YRHnayIq+Uh0OD57M91QvfO/NKuUGLi+PfMYytLI5Kkd90SJ1PCXvyM//2xuAkl
         n5FIkOUmT1++Swa4B1sM3m9OfK3pUbkuG1xItP/oOwiVkcBTAuJzFZ+x/COKil8G7vOO
         gkfF5o8+v3iTCrMSAF+jQX4RfggSAtj8Y2fDRQXwkD0IfT+06s+xquWCLjwNwRJXLyVs
         i0RTguw1w50PQH7qKiQ63TT6ZM1c10TynZ/QhO4o/lPjYvdii1IsFTuOWps9bJbInYl7
         6bFp4ss6brb+Pa6TV7WdwE6fnKDi82vvPEVT7Vi/Gzj5Khm/iIHDZGSyCymKOOZm5+RA
         hsDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Dmf7G2E3;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yFTIQ1ozLSF4UgT7epFJkLnapAmASIPQkk8ztGJZ7BQ=;
        b=mRDggBv61rbRE00PONzhp86ZbX3MiPabwLnL1iyva+v4PkfR1M6TuWWHlxmKMJ68fs
         GUEUjQozsmXtSeJ6wFkuNSCwvmflygd84uMsSMff86SYZ6rqKDzCpDcI9bQFOK8MilzS
         tdMI6dhbOEDJBT+YK8zehV8rhzamDcVKcNBqYGhvlARty4aLrz0U24CvdTeR5tFfmHBG
         QksmSR2wC71BirCqm9UdMFcI6qcLjCBVY58TEgprGR9DTWX8hgT7sTI9zAENpy1EZJZF
         4s8v2O+x3GEnZXZxaMfUALwWM72wTrMID+nxdqFZphcI3EhKzG24Cezv8guatuqxS5TY
         Jz1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yFTIQ1ozLSF4UgT7epFJkLnapAmASIPQkk8ztGJZ7BQ=;
        b=JF2FcW1rXDQm9rInZFnfuWBWh6tlns3ToCmpSFWfzUQ34ZfsHuKK3Tlq0tGoL3NYra
         RCkWkS52mae8MCjzGj/Ux998koD+SjwGZkkOEQgLqJf+TQrQa7CSEN2rlH9Cm7sWesDo
         sZ+MTC5Q7KeCII1WUlsnoRjeIXochAUgv5Iu9oa1P69ZX4nAgBOU5uHw+y5VNelP2Si3
         plXFEdqBLUzbB2jCAOCXCJDo7um/pR6Nxa0SqEhmti5r9YM7LnPwspO0N8NB9yexuQb7
         CJEJMmfjt8/I2AamT5jSeVLoGehJYgFOHijZQTON0lcyMagINj7mV24s51qqpvQBFSpv
         udFA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531nBWXmk9CC/9jDrI0wKrd4LNhU+uKOaCjtTOEzYkgiOtGzm+0i
	NXDQ4acBOjqckknTa0GJybs=
X-Google-Smtp-Source: ABdhPJyaoEgVtAVLWP7x7g0n8zWY6vxzVwUwT+dIzPG5ziZ3ynwdpEWZVRQgR+xfg1NU8Tzt9F8BvQ==
X-Received: by 2002:a05:600c:511d:b0:380:e340:bfaf with SMTP id o29-20020a05600c511d00b00380e340bfafmr1893924wms.159.1645548194082;
        Tue, 22 Feb 2022 08:43:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4575:0:b0:1ea:7cfe:601b with SMTP id a21-20020a5d4575000000b001ea7cfe601bls180419wrc.1.gmail;
 Tue, 22 Feb 2022 08:43:13 -0800 (PST)
X-Received: by 2002:a5d:5887:0:b0:1d7:36e4:e40f with SMTP id n7-20020a5d5887000000b001d736e4e40fmr20484718wrf.298.1645548193411;
        Tue, 22 Feb 2022 08:43:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645548193; cv=none;
        d=google.com; s=arc-20160816;
        b=TL6sFhMFO4vN+IdyM6S43C1AIYL8C442BUeXlZ2yrnH5BsrDsKv58lTE8yoBCjFvv3
         InOTv2WJ7vRXOnsyf75PU21kuFBMDT4kzOm89rUaW1cUm/0Lnhnb+e9OomL1682UW+Od
         svuWLnCPss7DRyzUfRnaLAMio8phteQiXoD4MCGxRQER+wZFp6zJ3TlLZFv79JmocZmq
         2cc5+FsC8nb3h+mtdZkoL1zSPIWbFDBzNhG+AcXbuX074DKBNc0H05JqNhh2Ufkvr/4U
         5KGJQn0zKCtS2B6LgpeUpE9ZXRvT5P+s20qFOPc8k2wmlXn7E2rCWeMVVlih7zNp/rPG
         xm0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=ZEtbE1Y1jeIgzgzA2TFDElC+yLbMe5ouicxIZ65PMO0=;
        b=nY3vuz8euMicJ0vQSHerLhwlcOhqImvq1+IfD42re1j+XdYT/bkOtwGjlBCOHHO4iH
         zOFrDNCAdH1+APNz+Dm+E69Yc7gP0I+CsGVTma81N/BiiIbOXUkNbALq6EweJzMqh2FH
         4JY7pkt2s45TvspxleGmkgeSQNhfbm4o4IZlRPyiUmOS/Nr29VmP+dyqC93tBYIqpopj
         yszVyvw5vZz7RovEA+mJqEFSpAh8mfYlSMh3WkdhCsBIO0FeRHCtMT5fyTFtw/GQGwpl
         nG9mrqAZ89BO2eGU1GL9OO/NDdIJi+yn+VsGIa7K4k42TxRmIlGCv6g4ga1kVxoR8qPA
         g+iw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Dmf7G2E3;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id bg3-20020a05600c3c8300b0037e391f947bsi160094wmb.4.2022.02.22.08.43.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 22 Feb 2022 08:43:13 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v2] kasan: print virtual mapping info in reports
Date: Tue, 22 Feb 2022 17:43:08 +0100
Message-Id: <6ebb11210ae21253198e264d4bb0752c1fad67d7.1645548178.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Dmf7G2E3;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
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

Print virtual mapping range and its creator in reports affecting virtual
mappings.

Also get physical page pointer for such mappings, so page information
gets printed as well.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Note: no need to merge this patch into any of the KASAN vmalloc patches
that are already in mm, better to keep it separate.

Changes v1->v2:
- Add find_vm_area() return value NULL check as suggested by Mark Rutland.
---
 mm/kasan/report.c | 15 ++++++++++++++-
 1 file changed, 14 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 137c2c0b09db..f64352008bb8 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -260,8 +260,21 @@ static void print_address_description(void *addr, u8 tag)
 		pr_err(" %pS\n", addr);
 	}
 
+	if (is_vmalloc_addr(addr)) {
+		struct vm_struct *va = find_vm_area(addr);
+
+		if (va) {
+			pr_err("The buggy address belongs to the virtual mapping at\n"
+			       " [%px, %px) created by:\n"
+			       " %pS\n",
+			       va->addr, va->addr + va->size, va->caller);
+
+			page = vmalloc_to_page(page);
+		}
+	}
+
 	if (page) {
-		pr_err("The buggy address belongs to the page:\n");
+		pr_err("The buggy address belongs to the physical page:\n");
 		dump_page(page, "kasan: bad access detected");
 	}
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6ebb11210ae21253198e264d4bb0752c1fad67d7.1645548178.git.andreyknvl%40google.com.
