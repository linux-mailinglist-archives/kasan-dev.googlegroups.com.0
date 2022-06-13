Return-Path: <kasan-dev+bncBAABBYVXT2KQMGQEK6WI3WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id EC38F549EE4
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:19:46 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id c5-20020a056512238500b0047954b68297sf3501125lfv.3
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:19:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151586; cv=pass;
        d=google.com; s=arc-20160816;
        b=KEgC+FfOEsLLssOKdQo876AuttAQZN5VH+ehGQ9OqZTa3jjJblK3+1gva6cWZPwu9A
         e9CK2LNvbS/bjDbjJbIauEz6usemK6e6sHffBwQmvhiGSkeAUfT9+Luo1DR3XP1Rqcy4
         p+xqHlA2dj6sX4UcJv/oaciPkrMNJ37WTAHiIGlRcT+eZcIYqQ/hIuaEBUKznK/AB+IJ
         x4wy+bNwAo0wM8yDubtuzDLCWOIFnXWrwugJTl+ZZfixnT5Qbu05qONm2B1Ran7U0iMF
         peHSwPHR64y/ILOlYDVgp13v9I+aIp6mLHOEgrCrLt9MyvlX9iNnGysnmcGfMgx/Yw8Q
         ffWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=IGqViK4jx8zlhN90ZGZV8nCyJjcuZGSz59JPA0J7VTk=;
        b=dmdq+w5zyb30UfMlYEftM3j16kTgUL/xZ7qnHHJX4WtLWqf1uDqq3JRND3m4iYdQMV
         2iq+SMPPwAKJd6dHCE4sEp6j3zlPS3fsSaOowu+fI68iWtDfvWQZIeJVJva7t0Ky4HQh
         5s/g0S1/W2gpE8YHgIt2S+UrhYcpQC1PxXSl5uOqsxwPi41jrWdvgE4/SaRoI1GvdpD0
         apoqhvNdSHyNoKpRfZwN6YKKQ+uktxGOkHkKoQBazpBT/uzndd3Ah0/RtDVxPJYdLPdR
         WYEib73Gx6Ih2HXRMoud4lPy/4b73yAlq2cfi6kjVbfg0iALUlAubgNGmHFNHHDjr/Ab
         LAsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Tx3ufgGi;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IGqViK4jx8zlhN90ZGZV8nCyJjcuZGSz59JPA0J7VTk=;
        b=mXtA/EvGFvDDQV56+OPt7XTkywdTRP297aKytzhCrZDSJAclmjlSf/LjbWMfxscY3x
         me1rUubtcXHf6cGZiLg7chpk+6T2zOb77yzr0LwndXLBaqSWIrbyqbLclkS32YBMyUlH
         nYAwqEe+K8L/aGfmPEARevpQRj/TWN0VeCb5Et4jtj7p2vrmnyZtF1p9RfJfEQ3FVDbg
         7UvzTiABJWMzVUKrOreQUVuG9toxsGh1H1Mh70aR0OFIPslJDXKdwjoAffLr81KWiqkn
         nooHaZL7t1uTSDYELTDPCQYIIFPU2gC+08/FwEITvxn00pa58MjMvUMaOwzu+8KchnLa
         AF9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IGqViK4jx8zlhN90ZGZV8nCyJjcuZGSz59JPA0J7VTk=;
        b=BJAZ2XOEOeKjIQwiNJBc1kex+F8OCEwZx10B6T++KPZke+dH79MeWLw3ztDYaQcSy2
         JGl4d+RsI/GLgw/zVfpAAn8kQVaTvAN9VkrDiDoBuHHPAKZ06ivMEfSTTu/0Ugx2P5bs
         cuJn0MgUO1oPlvUl3a0if/p+1Fhf6S+Jogg2+hdxQ4fNlCKxvaOgLBFyTorIxLDa/Ws0
         fapRxUgQhtu+sEpkB8tinLUGz8RwJJt3gBKo8M9cE0S+UrMHexEwtkzlkb53Iel7cmFj
         1l8oSkKdA/26Q5w0TDbpk+cXNDooqx0NWElAEHdz8lly4Y2Ruga3JVYnrFznXzQKTdIj
         h2pA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+Y/xnwnc7GSPRqQQfZItwBm3T/igWY6OAmYbihPdDr8Y5QPFVf
	wbsU7OlcTfjz/FHpk7EUj2w=
X-Google-Smtp-Source: AGRyM1vzLqfz1dJE/a/eqD9goz+IJ9BKcNNyE3nXZXfRSOoiSd11yY2gzASWm91Etu6DNQYAHK9K5Q==
X-Received: by 2002:a05:6512:2607:b0:47d:ad86:2761 with SMTP id bt7-20020a056512260700b0047dad862761mr941188lfb.133.1655151586497;
        Mon, 13 Jun 2022 13:19:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b95:b0:479:6748:7081 with SMTP id
 b21-20020a0565120b9500b0047967487081ls188960lfv.3.gmail; Mon, 13 Jun 2022
 13:19:45 -0700 (PDT)
X-Received: by 2002:a05:6512:3045:b0:479:5a22:3231 with SMTP id b5-20020a056512304500b004795a223231mr900023lfb.451.1655151585676;
        Mon, 13 Jun 2022 13:19:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151585; cv=none;
        d=google.com; s=arc-20160816;
        b=aPOcsygrUflde/ddfVQ8hWsikq5BaBmU/oV0/DEaDGSchyaHhDtGFodcDhL9eb+Ij2
         p61n7un+9pChoaQC99gEnh/b9r4Nyff3VzG69Jws/Y/m0pLaiw6BQaPR4cqQWIfyzY9O
         FPEv5wPP2ERga1lAiOwrBSCZ2QHTVqrDYO3uJO/V20hd7rbT2WyoZabW5QS9PCiZBrDo
         YnX2TsXLOsMQan9/8Nnfcwgk81cMwfrCZMZkgzQS56pW+2ZGcQcMkUEl9Gv1IT8WCh+t
         8vG+9j6jFJV9glZeED+ZsnHKblXdkWcGW0RpTwgYGb2u51j2Q6rCsKuuJm81cuA9Rgeo
         JjCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=bgGIoP7jXmxJI/MRAshv+0ZSBU3qLuiELKkrVE3erv8=;
        b=sU+WirKZMlLLR+Prj2kdRvhmR8S2ajQ6AQF/Fi2yq9/QqroQGR0mprcTUyj6Gm3bmH
         oNIJzksb0Icb1zReTijmi/TNWXLSB+15ax0R2nTCVLDJSd40rtAlQLQxyJOm5oht217J
         cEARmKhvPQetjaR1MVp5jwIbIqcZRi4mnq+h3xi14e2PZB+gKY/RXXZm5ImNlrVejgAK
         H4E/uEyxLCc+sLRnA/Sn5O9gD7JLkmG5iE75WcxIvGVEcR6fHGPq64BrNU7tTIG8JTvt
         SeiP8clzaS51X0Y52oeDzXd32mcstyoxmNcesFbmDNw8Y2wokRz7wCAecFPHNg2xpEx4
         YkfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Tx3ufgGi;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id bp22-20020a056512159600b004789faf5d76si301919lfb.12.2022.06.13.13.19.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:19:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 27/32] kasan: introduce complete_report_info
Date: Mon, 13 Jun 2022 22:14:18 +0200
Message-Id: <dcc8dd2856119f660f7402977de9da2b2419b175.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Tx3ufgGi;       spf=pass
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

Introduce a complete_report_info() function that fills in the
first_bad_addr field of kasan_report_info instead of doing it in
kasan_report_*().

This function will be extended in the next patch.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h  |  5 ++++-
 mm/kasan/report.c | 17 +++++++++++++++--
 2 files changed, 19 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index e3f100833154..0261d1530055 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -147,12 +147,15 @@ static inline bool kasan_requires_meta(void)
 #define META_ROWS_AROUND_ADDR 2
 
 struct kasan_report_info {
+	/* Filled in by kasan_report_*(). */
 	void *access_addr;
-	void *first_bad_addr;
 	size_t access_size;
 	bool is_free;
 	bool is_write;
 	unsigned long ip;
+
+	/* Filled in by the common reporting code. */
+	void *first_bad_addr;
 };
 
 /* Do not change the struct layout: compiler ABI. */
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index cc35c8c1a367..214ba7cb654c 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -407,6 +407,17 @@ static void print_report(struct kasan_report_info *info)
 	}
 }
 
+static void complete_report_info(struct kasan_report_info *info)
+{
+	void *addr = kasan_reset_tag(info->access_addr);
+
+	if (info->is_free)
+		info->first_bad_addr = addr;
+	else
+		info->first_bad_addr = kasan_find_first_bad_addr(
+					info->access_addr, info->access_size);
+}
+
 void kasan_report_invalid_free(void *ptr, unsigned long ip)
 {
 	unsigned long flags;
@@ -423,12 +434,13 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip)
 	start_report(&flags, true);
 
 	info.access_addr = ptr;
-	info.first_bad_addr = kasan_reset_tag(ptr);
 	info.access_size = 0;
 	info.is_write = false;
 	info.is_free = true;
 	info.ip = ip;
 
+	complete_report_info(&info);
+
 	print_report(&info);
 
 	end_report(&flags, ptr);
@@ -456,12 +468,13 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 	start_report(&irq_flags, true);
 
 	info.access_addr = ptr;
-	info.first_bad_addr = kasan_find_first_bad_addr(ptr, size);
 	info.access_size = size;
 	info.is_write = is_write;
 	info.is_free = false;
 	info.ip = ip;
 
+	complete_report_info(&info);
+
 	print_report(&info);
 
 	end_report(&irq_flags, ptr);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dcc8dd2856119f660f7402977de9da2b2419b175.1655150842.git.andreyknvl%40google.com.
