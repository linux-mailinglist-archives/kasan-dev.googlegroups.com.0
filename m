Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRHCQOBAMGQEZW3GSRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id DCE4732D57B
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 15:40:05 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id g17sf30899533ybh.4
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 06:40:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614868804; cv=pass;
        d=google.com; s=arc-20160816;
        b=l0iQ6mO9/juhULRWhB0+JN0XVMCyXPkoOzXrWqPmuiidlF2BKSB5Oi51ZQxM2ciI9Z
         YyoDQFiyTgJQsy8B+2wDVDc8HClpxgRMOiQRi5Mx5wVWVUwnSYFS/Go9u5LvcvfaD481
         ZbN9LuchbrYwjQ4B7k69U4T35xRE0WL2ju5gO+ytQL9VBxjdw0VR3YpkTFgURohdjCbC
         wqKDAdvKWO2KNfcWGU7Pny72WL3ORauvldLn60s0NBoiw+cgcB8UuyGVtnP9JU7dVMtq
         EtkK92CfpU5V13h34eJRlJmQqDARwe4O7ZNPDtiPqWJiBMy9IriItmpoqqSuEOyWGQq0
         e2zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=JRFHtky5t94hxJc3r0VXT612PcJdfehG39cKoHDOY8M=;
        b=ytqTHdN1H7qQcvw/YBIa5v4BtAO/0malcu13z7JXgIWbkEwGzluXT8MPvrsqiMlhl8
         GQq2xUt8Hwv719wWSjU4q6g3ia8uL8fTcUYZaVVf+mp0QdWkYy35Vpchn0/Q30evcktr
         qqDRn+gfKz6ooCB6f+qURLIgA620XjBMI5VcFULPUJP/HYFr/vFN4/llYuowxrARU9Vo
         Ka1Aj1EsoGl+UuY8VjM8JvbhFRejDNybVYXY4TA7vXBs5xmCcVNUvVuHv/tz281k0UuC
         /yNFFsqvhb8PFLkkWs2KrBTP+mb1/xb6EgFngf+C5At8PWMPMq+xEyNOMsLzawV2dHdi
         y9fg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=D2kCIfqN;
       spf=pass (google.com: domain of 3q_fayaukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Q_FAYAUKCTISZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JRFHtky5t94hxJc3r0VXT612PcJdfehG39cKoHDOY8M=;
        b=N1iPUIUW0vjAfk20yPvnG7f7q052WgmP7kDkP8bUxLqW7gWNk50zECV3Y/Zknxskon
         iuVZMWXqZhpcLnSwTkk2nl7ybZNYtvlYbNRQZe6BMfUXiaD4+jG6fDsQ0GyC8YqEiyp/
         1V53kNZwug68EiLW3CLtnlRgGx6ZkZ/3P+jfkiCIEKkhZ/eoxze9UOHkw60UEgqeiVnf
         Tz7dY9R5go/I3j4SlWUk3gZJeUNo1AWQCCTNhBxe70tdr6skmuQonqFDd75GdqUjzt0R
         ooyDjNXYC2O0VJpFuF/XcoO8rMwJGKpDkayFy/UZ4ONnmZLaJ90+0IIM9J6d1vz21j6k
         3wrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JRFHtky5t94hxJc3r0VXT612PcJdfehG39cKoHDOY8M=;
        b=FHcthXEJpcX8Q/ptXD78vkZzHoVvphgZoHNo5iieSlNUZMEwxYX4oUB4u3Fq79pyIy
         Kc+po2ywKAgus8EiAUJpLlUTjd0uei0OZ00xGUzwoNIW54GxPZOwiQEko/P3y943zG4E
         q//WG8b5jpsF5WPJMXO9/EpcTdMjrS5JBICMT2ICjy2/Sn9yqYAbm76YBCRot09eb4wX
         a1qdrJn6844GqgUoGbz7LqbIUP2Qq0MILC2K4hI/trHsQdtIVi2Y/LdnvwltKf2CLR9/
         4mAghQ+K1hNGgZaRaQ6yWbrwjUSsU+y6AWNwfPzvxatOLhW8kC+nO3a9fAmZ5Gh1LjDO
         wCcQ==
X-Gm-Message-State: AOAM532ek/63X38mRKYn1QB1J9JAAfoTbnyw9xUN33jaH+aIeAIYk6uK
	F5t5Vz3fpBTZXGg1Cwgr6aU=
X-Google-Smtp-Source: ABdhPJxKB7byeLsROf2CAbRIB5QThAIFaPCzc2caqmhn3Leq09IM6ZQ0YH+24kywlL+vDxmGKI/t0Q==
X-Received: by 2002:a25:eb02:: with SMTP id d2mr7115203ybs.250.1614868804716;
        Thu, 04 Mar 2021 06:40:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:77c7:: with SMTP id s190ls2909442ybc.1.gmail; Thu, 04
 Mar 2021 06:40:04 -0800 (PST)
X-Received: by 2002:a25:b91:: with SMTP id 139mr6715346ybl.115.1614868804259;
        Thu, 04 Mar 2021 06:40:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614868804; cv=none;
        d=google.com; s=arc-20160816;
        b=FOVZ8U9d26lnjT/EOrwWRMNotR+GkVTnhr09vGO0XgSTk1z5+paL/RMVN3R/kxh6n9
         Gkpmgw0RT9K89ynz7dP1XyUAyvjsuBya5kNcqN/rU6/hJVzjIvrOxvnrrd3Ux2/r6zhv
         XhG6oC2bQaikVTeryJMQdoxkG/jhPq+PA1DTzMpIdB3ZfV9HevSiRf0ZzLNoX6WCuhii
         AGmUh+36s1vEX61FwtadP/I7/q6U41vcW07+QGNmMIEzkBLp/qzMUg/NJF/U+69xqTrH
         SJQKxaUwOd5wFECauwflXJy1pV3l33aA232R6g6QD8jCUv1TZQqnry9rezM3qYbAjK2g
         IqtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=J0Eb4BeQ/LcK1uQlkM6nbhOgm0bqw0Va6B9G5XeIs/c=;
        b=VF+edk9ynCrm1K/OWpUqgXMKsn9C/aL2D8eFa1Uyiy5h+kBRIEHxXGuwrDGDecArDL
         h1effizvxVtVQ3buOmKuS0U24cW07sPIrJhtCB/aV9+uaBboxXzUr2T5DsdPnwc/bY1P
         FHYMUFDYg38uOt60xPiKO+8Ud+7stoxsgvhMWRCDRORFq+4xgvTamLlgPMIvTqGWbDgK
         hKCBmz78aUuPDJQVv1iRxuG0UITV7qq5/zBfw5kTOHNAsJsFs1qttEb/tNawzIDIZ97k
         rs0ZEJHPJyFBgTF2KMDlhcGyAAjTjLAu9IW1ZOeC3IhapJAdbUJR8R/y2771j+SOgIMR
         bQOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=D2kCIfqN;
       spf=pass (google.com: domain of 3q_fayaukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Q_FAYAUKCTISZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id j205si560632ybg.1.2021.03.04.06.40.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Mar 2021 06:40:04 -0800 (PST)
Received-SPF: pass (google.com: domain of 3q_fayaukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id v196so30782117ybv.3
        for <kasan-dev@googlegroups.com>; Thu, 04 Mar 2021 06:40:04 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e426:34b7:f237:f8d3])
 (user=elver job=sendgmr) by 2002:a25:c586:: with SMTP id v128mr7118421ybe.416.1614868803915;
 Thu, 04 Mar 2021 06:40:03 -0800 (PST)
Date: Thu,  4 Mar 2021 15:40:00 +0100
Message-Id: <20210304144000.1148590-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH mm] kfence: fix reports if constant function prefixes exist
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, andreyknvl@google.com, 
	jannh@google.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, Christophe Leroy <christophe.leroy@csgroup.eu>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=D2kCIfqN;       spf=pass
 (google.com: domain of 3q_fayaukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Q_FAYAUKCTISZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Some architectures prefix all functions with a constant string ('.' on
ppc64). Add ARCH_FUNC_PREFIX, which may optionally be defined in
<asm/kfence.h>, so that get_stack_skipnr() can work properly.

Link: https://lkml.kernel.org/r/f036c53d-7e81-763c-47f4-6024c6c5f058@csgroup.eu
Reported-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Tested-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kfence/report.c | 18 ++++++++++++------
 1 file changed, 12 insertions(+), 6 deletions(-)

diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index 519f037720f5..e3f71451ad9e 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -20,6 +20,11 @@
 
 #include "kfence.h"
 
+/* May be overridden by <asm/kfence.h>. */
+#ifndef ARCH_FUNC_PREFIX
+#define ARCH_FUNC_PREFIX ""
+#endif
+
 extern bool no_hash_pointers;
 
 /* Helper function to either print to a seq_file or to console. */
@@ -67,8 +72,9 @@ static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries
 	for (skipnr = 0; skipnr < num_entries; skipnr++) {
 		int len = scnprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[skipnr]);
 
-		if (str_has_prefix(buf, "kfence_") || str_has_prefix(buf, "__kfence_") ||
-		    !strncmp(buf, "__slab_free", len)) {
+		if (str_has_prefix(buf, ARCH_FUNC_PREFIX "kfence_") ||
+		    str_has_prefix(buf, ARCH_FUNC_PREFIX "__kfence_") ||
+		    !strncmp(buf, ARCH_FUNC_PREFIX "__slab_free", len)) {
 			/*
 			 * In case of tail calls from any of the below
 			 * to any of the above.
@@ -77,10 +83,10 @@ static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries
 		}
 
 		/* Also the *_bulk() variants by only checking prefixes. */
-		if (str_has_prefix(buf, "kfree") ||
-		    str_has_prefix(buf, "kmem_cache_free") ||
-		    str_has_prefix(buf, "__kmalloc") ||
-		    str_has_prefix(buf, "kmem_cache_alloc"))
+		if (str_has_prefix(buf, ARCH_FUNC_PREFIX "kfree") ||
+		    str_has_prefix(buf, ARCH_FUNC_PREFIX "kmem_cache_free") ||
+		    str_has_prefix(buf, ARCH_FUNC_PREFIX "__kmalloc") ||
+		    str_has_prefix(buf, ARCH_FUNC_PREFIX "kmem_cache_alloc"))
 			goto found;
 	}
 	if (fallback < num_entries)
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210304144000.1148590-1-elver%40google.com.
