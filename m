Return-Path: <kasan-dev+bncBDX4HWEMTEBRBUO4QD6QKGQEWRM5YMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FA842A2F20
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:05:38 +0100 (CET)
Received: by mail-ej1-x63c.google.com with SMTP id e9sf832488ejb.16
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:05:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333138; cv=pass;
        d=google.com; s=arc-20160816;
        b=G+DtO8yDJguCmMQTAKm9TsAV4IG6TVJwVKE0nYIo3hV+2Gt9JGdtdJIQdgaWJ/Wr/3
         kJ19Dei9vr+TWHEDbzvLHsy+0FA9CcWWj8NrVfbCNR25vNOV4KYvO4ouhSsRfumpvpZ3
         xWkJTbTt+wgb+Xyel029Pp26zf1n/Ziu7pQ4/um6NiroxTTBwuXNDkb8QvssJVurdYR2
         +Az/CfSJ0amF+8ZlzYTcVQLYdD31w7K9+KAoSaBhRNPKnw7tctCHws0KyYGNaBN993x7
         GBPa5XvLMkdQ2W9CzXXcucsRTWbNF9AcUDAlDspZWCHkpq1tWEC220K/+HOY/hq3hts3
         Q7hA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=avJbKGVFXoNyJw6+ify4frzoMKW5EdkgiBjYSwETv4Y=;
        b=PFCL6b2e+VHjTdK0q1M4WpO4siFgesoC/CRHJ8l06MXFCGdrslFhXU4xDs7ZOm7ozD
         zmx8lGcXKnCWi0VEvJlMZmvyyQGoNnNg4FSaNPaUxaJKav5rcuaooj3/VSpBgW0eGaU2
         FdFZm7e7Qf6GoDsZSyH2ZmSRpjX+J/np8deX5kbtuO6S0VtalNT0hC1RUaVfuL6MKRFD
         U5x53+ca0Pkqci4pS2Hy596Tnh9WWeEtsmfttHqqR/Y61jiOppl0KJj8Bx5Q4/oKnOwh
         DaQipRGMvST7D6f5XTdq12PFBBUMFtLgmIW6LrxrJESKnC6UD1PbKhK8TgaI4tV1ZKKp
         vQTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="qerdM/Iz";
       spf=pass (google.com: domain of 3uc6gxwokctenaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3UC6gXwoKCTENaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=avJbKGVFXoNyJw6+ify4frzoMKW5EdkgiBjYSwETv4Y=;
        b=Da94zRGkPD4AeCbiq0DVg+IpLp5xhGENq9bZ9P8x6Py3N4L2PC9MsVyqQ/G8Ql2oUu
         CnTaW/eBoirQOt24dKPTqX1+O9zqnNaho6YGoNDZYWL0buTVaPmeOUlEQvV/1Jjy5XX4
         OlUZCndThpsxlsh+c0eKgKyywHmR2zNOVCqyNh+NrieIcOVuaV4EsvxegEFIs4XISIOf
         NGguotAOSjGYLERdmWdfatciqw+Zc/8bxsIDIUelWXdE40KKRmPQv5UBrWoYgFRfKpto
         IAnfqi4hqdWqBtqti/R1o5/2LavpAoQngD4vT7SXGQiMAJ3saG/bVlNbVlZ2nSEECIC/
         t++g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=avJbKGVFXoNyJw6+ify4frzoMKW5EdkgiBjYSwETv4Y=;
        b=KvUJ7KmF/gVqg15pmsovcHXcIYO0vHKOWO3HSTS/sQuXEM6zXCMQIYoez7talosfaY
         P+Jsi4gkqO1+TaiOBidep6i4+ttWhIiKkY6wAl/IffbSl5tRRLWII8De9h1xCpD43vfj
         vvWrETv/f9IQgsYPC6397w8bNdPyTdFBYC0abhbPSeyBxYwdgSgympmU+8QCnaLWcgSK
         U2KSyXMGw4/ESvRyy8yKOUSVKbiPJTzYP1gt5PH9GLgFBzfaiNiHHeSSDv1eVQ2yHxML
         1Z6hk8WdJUkhgvenvFyJzHwdqCZafsSobYJcHX/365/RFy8m/kND1rNo5BKGviJ/on8T
         hbAA==
X-Gm-Message-State: AOAM533gemMrYq1eKfsj0ukiKRfPJvIXP+6i4uAnmzXznWCEojeNyj+r
	y+SD04Ukc8wCRNS0R/rvWoE=
X-Google-Smtp-Source: ABdhPJz8YUKvKB7/29cCu2zpVUYcvayeZSRfU4W21/G9WGTMRiwPZ7zMVWCfAWasfQIydUokSNqj2Q==
X-Received: by 2002:a17:906:cc8c:: with SMTP id oq12mr15251257ejb.177.1604333138165;
        Mon, 02 Nov 2020 08:05:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:d981:: with SMTP id w1ls7383053edj.2.gmail; Mon, 02 Nov
 2020 08:05:37 -0800 (PST)
X-Received: by 2002:aa7:cb92:: with SMTP id r18mr17915108edt.13.1604333137172;
        Mon, 02 Nov 2020 08:05:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333137; cv=none;
        d=google.com; s=arc-20160816;
        b=kT4cVt768rP0AWacUCyRl9kT9zijy6LUEsgHcmV5j1NRJX19X57jB67HZ/kArZfI0X
         VpZmZBXWq1UbV7paFUIirBRNKpKhAGXNOMJiwOJ4BldpWlJlI/G3Zx9ger515+sNTyyL
         okv6Sc6oBT5NHFaM20M3lsGMlUe6ipRZ5cgmmwGIKozZGsgqpvkHxD1D/1hQdcMvGnIf
         N1Hvtt1uqMzYT9NvIV36dq9wZrgphvRTc1Q3Z/iql1EEbF6Bqbrnrb7Fgp9V/8yFxrp9
         0JDJNgoXHhSgu/LTDDtuedkBvqRz2Q1+Cq0h2fwXEIyc/NGIKu3MD0CAw00/AH8EvJwv
         tJGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=85BahkB/ARH3bXDyEMCLh1SMwp72o82khunrv9SMNJc=;
        b=UExQssYlsd7BjsozKuaAfLKlMZyvgOFuf27OyLWEztu43JH3GITLpNK5rAFJKjVIbg
         wXsNbuVvHBzN5z1ahdZc8vksjCNkw+Qg8sAJzO57np/EKbTSFsP+YbUz3L2gA3IQtBX4
         dVVv042WSEbo2RCEWHMWUwsTOmH0Li9hMKa7lhkgE3AArd9Rlyp/P7mF0NnHSiXu111a
         62gcZuxMjm5tmsOV6jtqoOI6drziuGDkQCCd1u4KWjcimPwzQGwz7PzCaj17EjPqPxQ1
         GihWpZ9F5nxcntrSiSq0Dph9IW7asuO9zx+Vr3MHWi++UAbrz1n2kDcAiITus5v6zuQV
         6PGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="qerdM/Iz";
       spf=pass (google.com: domain of 3uc6gxwokctenaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3UC6gXwoKCTENaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id g4si332768edt.2.2020.11.02.08.05.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:05:37 -0800 (PST)
Received-SPF: pass (google.com: domain of 3uc6gxwokctenaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id s85so2025375wme.3
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:05:37 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c1cc:: with SMTP id
 a12mr48615wmj.0.1604333136445; Mon, 02 Nov 2020 08:05:36 -0800 (PST)
Date: Mon,  2 Nov 2020 17:04:09 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <eed14fbfbee5e19505457ba61448c618dcac2308.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 29/41] kasan: rename SHADOW layout macros to META
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="qerdM/Iz";       spf=pass
 (google.com: domain of 3uc6gxwokctenaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3UC6gXwoKCTENaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

Hardware tag-based KASAN won't be using shadow memory, but will reuse
these macros. Rename "SHADOW" to implementation-neutral "META".

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: Id2d836bf43b401bce1221cc06e745185f17b1cc
---
 mm/kasan/report.c | 30 +++++++++++++++---------------
 1 file changed, 15 insertions(+), 15 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 594bad2a3a5e..8c588588c88f 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -33,11 +33,11 @@
 #include "kasan.h"
 #include "../slab.h"
 
-/* Shadow layout customization. */
-#define SHADOW_BYTES_PER_BLOCK 1
-#define SHADOW_BLOCKS_PER_ROW 16
-#define SHADOW_BYTES_PER_ROW (SHADOW_BLOCKS_PER_ROW * SHADOW_BYTES_PER_BLOCK)
-#define SHADOW_ROWS_AROUND_ADDR 2
+/* Metadata layout customization. */
+#define META_BYTES_PER_BLOCK 1
+#define META_BLOCKS_PER_ROW 16
+#define META_BYTES_PER_ROW (META_BLOCKS_PER_ROW * META_BYTES_PER_BLOCK)
+#define META_ROWS_AROUND_ADDR 2
 
 static unsigned long kasan_flags;
 
@@ -240,7 +240,7 @@ static void print_address_description(void *addr, u8 tag)
 
 static bool row_is_guilty(const void *row, const void *guilty)
 {
-	return (row <= guilty) && (guilty < row + SHADOW_BYTES_PER_ROW);
+	return (row <= guilty) && (guilty < row + META_BYTES_PER_ROW);
 }
 
 static int shadow_pointer_offset(const void *row, const void *shadow)
@@ -249,7 +249,7 @@ static int shadow_pointer_offset(const void *row, const void *shadow)
 	 *    3 + (BITS_PER_LONG/8)*2 chars.
 	 */
 	return 3 + (BITS_PER_LONG/8)*2 + (shadow - row)*2 +
-		(shadow - row) / SHADOW_BYTES_PER_BLOCK + 1;
+		(shadow - row) / META_BYTES_PER_BLOCK + 1;
 }
 
 static void print_memory_metadata(const void *addr)
@@ -259,15 +259,15 @@ static void print_memory_metadata(const void *addr)
 	const void *shadow_row;
 
 	shadow_row = (void *)round_down((unsigned long)shadow,
-					SHADOW_BYTES_PER_ROW)
-		- SHADOW_ROWS_AROUND_ADDR * SHADOW_BYTES_PER_ROW;
+					META_BYTES_PER_ROW)
+		- META_ROWS_AROUND_ADDR * META_BYTES_PER_ROW;
 
 	pr_err("Memory state around the buggy address:\n");
 
-	for (i = -SHADOW_ROWS_AROUND_ADDR; i <= SHADOW_ROWS_AROUND_ADDR; i++) {
+	for (i = -META_ROWS_AROUND_ADDR; i <= META_ROWS_AROUND_ADDR; i++) {
 		const void *kaddr = kasan_shadow_to_mem(shadow_row);
 		char buffer[4 + (BITS_PER_LONG/8)*2];
-		char shadow_buf[SHADOW_BYTES_PER_ROW];
+		char shadow_buf[META_BYTES_PER_ROW];
 
 		snprintf(buffer, sizeof(buffer),
 			(i == 0) ? ">%px: " : " %px: ", kaddr);
@@ -276,17 +276,17 @@ static void print_memory_metadata(const void *addr)
 		 * function, because generic functions may try to
 		 * access kasan mapping for the passed address.
 		 */
-		memcpy(shadow_buf, shadow_row, SHADOW_BYTES_PER_ROW);
+		memcpy(shadow_buf, shadow_row, META_BYTES_PER_ROW);
 		print_hex_dump(KERN_ERR, buffer,
-			DUMP_PREFIX_NONE, SHADOW_BYTES_PER_ROW, 1,
-			shadow_buf, SHADOW_BYTES_PER_ROW, 0);
+			DUMP_PREFIX_NONE, META_BYTES_PER_ROW, 1,
+			shadow_buf, META_BYTES_PER_ROW, 0);
 
 		if (row_is_guilty(shadow_row, shadow))
 			pr_err("%*c\n",
 				shadow_pointer_offset(shadow_row, shadow),
 				'^');
 
-		shadow_row += SHADOW_BYTES_PER_ROW;
+		shadow_row += META_BYTES_PER_ROW;
 	}
 }
 
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/eed14fbfbee5e19505457ba61448c618dcac2308.1604333009.git.andreyknvl%40google.com.
