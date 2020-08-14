Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJ4T3P4QKGQEIFEJW3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id B8AC8244DCD
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:28:07 +0200 (CEST)
Received: by mail-ej1-x63d.google.com with SMTP id d24sf3590224ejb.3
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:28:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426087; cv=pass;
        d=google.com; s=arc-20160816;
        b=WhET/icXJ1C9GdK9V1Wju2Tv1foFO/+GmcvCIgeXjZ6dIXAVDDf1Vjfp0oki33kBI5
         PGN1ljKhn194x3+nsXNiESTIfq4M51CBKYb/8ok4omAk7G4POTpagysUi6zp+O9a95T+
         er0qD9yumramBaWJIvHrtR3ANG5bEle7Fr1LGXAp/ysm2PG7dNSkk2BZ2zfi7iaoaQkD
         RS98JZqPgVU7WGB8LFwr7iNs2JA+5tCobwbuh0DUNmkOOFScY+kAfmxxpBFz0roE0eaR
         YQHxioJIBF0nWmRNcmBhFyFowmby92Ou5f3qrgLM6PDB0tS+Vmr1albDuB6UzX1HROn/
         MX5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=y/kCp/IeyQHiewsO/DFjuoIWHlG2eekoHlGdn+IOWkc=;
        b=WNOWyfecfjQ1xnYn9vhM9qODOOs27d6y8Ew1GQfPCtLtGX6TjN3bNGh8vhQxVaZSbO
         uNZgrdthHEHMFz9TS3ztcSx0x1B8bgPjPHcWHIi+A8F+/FmkpElPoE53cWZ/2OUgOukl
         WSJNnISXPCfOZlQMQ5sCb2PlbYzQ2Oui40srnvxdb0onVz+VvqWHCddvOsNjwBml5Edc
         +Gi3h6EBhRp4irJChHTMdyfguwCG0SqQEuDzfDoeoY5z1l832AUlA7e/uiwUyB+2ft+j
         Mjy63ULC5CDj6z6O9RR9JfKD5W94AovCbtkIXHl/CCGdkeEhdGKmUKhYh0TSM0v+Jr32
         6hWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YudbnRxx;
       spf=pass (google.com: domain of 3psk2xwokcruv8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3psk2XwoKCRUv8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y/kCp/IeyQHiewsO/DFjuoIWHlG2eekoHlGdn+IOWkc=;
        b=NXiTLF5+aHXbTvFyMxVOYTYUus94YoHh05mF0cDyPNi3rLYI4KyIJb0pzQYGcrv3Ml
         tjh2aeYhIcGYPCOyQlWTL03Hv+gcfPtG2Ar50TMPCNN8KS1H+TNlHLWTyFhEJiMy3JJ9
         w8uvb9D+jkAgDXYxYxnoyuRD2oapMokmlxSlsayI4ow7FEXZWg/RS6Nv2PCoX/yZmp3/
         QP3T5QNcPKpn3pcgGyPqjU5Iz65VqQFNSqW3nCqsn9po2FvbiFZoI1ENHrd6sC8InJk0
         f6bIyEOzSHKQm5Sg0qcevkcDq/EN7HemxfmH76PsMRkitIqjOoFTzo35HQVHlSWsOATV
         zY/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y/kCp/IeyQHiewsO/DFjuoIWHlG2eekoHlGdn+IOWkc=;
        b=NhSSCNvDyV9nySEJaeU8IdKcC/Em2f9pndXHvJow8ofkoyq/h69gi0v4EIQ84R5x9X
         Qk2vMz0xpyWXbkhCYTHT9PJ7x/yqn7rTXReRGhFY8xu+crAOPesBmMVJUKo2UfcyskCu
         A8dO41IWlsdPuIjMPwvjU0YqAIgDFE0c8/+TbhKEusnV5OX1AWw0g49MWgLvoPboU+aF
         8USnXXUxxiffwrArFzO8neSZFlcud7YymDLDubUOdKJv4tV6Dxfhu5zuKJvO7Q8KvQmr
         lR1CkEe/vq75BQL8OwVD1hoUHoCKYu27wsbQF4GybAaITuelZZB9Jn+0MagtDwuwezgI
         CsJQ==
X-Gm-Message-State: AOAM532j1CObV6bXTjQn3elaj4kCjov5RdQAj569ZvNsMvuFPNnlJJV9
	wiOaZaZrHj75NBVfSbCD7Ko=
X-Google-Smtp-Source: ABdhPJzuHyVa+B2GcuQvGZzJdOgyYT7wuu87Kd4sBiGlZOS2Hoaq2RxiY2esqF1fxnVeEiRnmqyPIw==
X-Received: by 2002:a17:906:fa0b:: with SMTP id lo11mr3555503ejb.235.1597426087466;
        Fri, 14 Aug 2020 10:28:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:bc05:: with SMTP id j5ls1078830edh.0.gmail; Fri, 14 Aug
 2020 10:28:07 -0700 (PDT)
X-Received: by 2002:aa7:c45a:: with SMTP id n26mr3314867edr.45.1597426086991;
        Fri, 14 Aug 2020 10:28:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426086; cv=none;
        d=google.com; s=arc-20160816;
        b=zX5RtKKsSzzOGjtgguDGe4RE6MKVEWrSmqh5ExW/73jaC5tIQLxCjWrH8/5anD417T
         8jPTZU44v3dbQJ0cu5N2fVYpY1cV3cn4ENnTcutewEUjKLewDm1MH04rQMfXdSs5wbmz
         Zyylzkr8twHCXQjp2Zp+rJGwFChMmUVYrh+GfTVLBL1X0b5xHTkW81x5zIVcX/R5F8lJ
         rxFS8y1/VCpMwAyxjzRMLRi/ZCDDsNPtV6QvCLZH00WRX8axoMvU5K0XiFEQAdHRWNdz
         BSWAoT7ZoDZid+xC+mNy2QtaWpzzpD/oKlC50vqygtSp9R5TzH+vp8FSWurxVBHuV0jd
         lh0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=d/u4o8cOL5u+yhGc4q9ktVy7qi4vlYcfWqeNAALsvIE=;
        b=drXRYTDbedWV5ctC0UTvvfoSKyc1KGxmjt+fw+iCkle6kc+T/Ax5tWiZtfeH/PM1kW
         lvTOY02NEVvwVOFxv1lK/4ApOzuJ5vPetVjAUjgERv69ba0f+Z/FM/5GmWp0KZhco48Q
         NUJE/wN3KVPylaIa39T4q9dd5xSLjmJ6wtEUrpTKwQL0m7G1kGLWGaAJOyZYcyE7bCTp
         mwkTDo/qt0bNiqBkvMdtYSpNsrSs59202vBRbyrjPBRgvVXq8+47L7R5bgYfqV7fl2hv
         KEclc+ZlBw6y6YtWVvqVB29k41L+htcBFAy4NrfbRvU6fFfxw/WTEUZ8bg6l0n+6/mNU
         c17Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YudbnRxx;
       spf=pass (google.com: domain of 3psk2xwokcruv8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3psk2XwoKCRUv8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id x17si295774edr.0.2020.08.14.10.28.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:28:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3psk2xwokcruv8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id k204so3425842wmb.3
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:28:06 -0700 (PDT)
X-Received: by 2002:a05:600c:c3:: with SMTP id u3mr424029wmm.1.1597426086237;
 Fri, 14 Aug 2020 10:28:06 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:27:00 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <cdcf749c4b78368810885a0ba83b8f3f0328d722.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 18/35] kasan: separate metadata_fetch_row for each mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YudbnRxx;       spf=pass
 (google.com: domain of 3psk2xwokcruv8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3psk2XwoKCRUv8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
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

Rework print_memory_metadata() to make it agnostic with regard to the
way metadata is stored. Allow providing a separate metadata_fetch_row()
implementation for each KASAN mode. Hardware tag-based KASAN will provide
its own implementation that doesn't use shadow memory.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h          |  8 ++++++
 mm/kasan/report.c         | 56 +++++++++++++++++++--------------------
 mm/kasan/report_generic.c |  5 ++++
 mm/kasan/report_tags.c    |  5 ++++
 4 files changed, 45 insertions(+), 29 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 38fa4c202e9a..1d3c7c6ce771 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -56,6 +56,13 @@
 #define KASAN_ABI_VERSION 1
 #endif
 
+/* Metadata layout customization. */
+#define META_BYTES_PER_BLOCK 1
+#define META_BLOCKS_PER_ROW 16
+#define META_BYTES_PER_ROW (META_BLOCKS_PER_ROW * META_BYTES_PER_BLOCK)
+#define META_MEM_BYTES_PER_ROW (META_BYTES_PER_ROW * KASAN_GRANULE_SIZE)
+#define META_ROWS_AROUND_ADDR 2
+
 struct kasan_access_info {
 	const void *access_addr;
 	const void *first_bad_addr;
@@ -167,6 +174,7 @@ bool check_invalid_free(void *addr);
 
 void *find_first_bad_addr(void *addr, size_t size);
 const char *get_bug_type(struct kasan_access_info *info);
+void metadata_fetch_row(char *buffer, void *row);
 
 #ifdef CONFIG_KASAN_STACK_ENABLE
 void print_address_stack_frame(const void *addr);
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 6306673e7062..c904edab33b8 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -36,12 +36,6 @@
 #include "kasan.h"
 #include "../slab.h"
 
-/* Metadata layout customization. */
-#define META_BYTES_PER_BLOCK 1
-#define META_BLOCKS_PER_ROW 16
-#define META_BYTES_PER_ROW (META_BLOCKS_PER_ROW * META_BYTES_PER_BLOCK)
-#define META_ROWS_AROUND_ADDR 2
-
 static unsigned long kasan_flags;
 
 #define KASAN_BIT_REPORTED	0
@@ -241,55 +235,59 @@ static void print_address_description(void *addr, u8 tag)
 	print_address_stack_frame(addr);
 }
 
-static bool row_is_guilty(const void *row, const void *guilty)
+static bool meta_row_is_guilty(const void *row, const void *addr)
 {
-	return (row <= guilty) && (guilty < row + META_BYTES_PER_ROW);
+	return (row <= addr) && (addr < row + META_MEM_BYTES_PER_ROW);
 }
 
-static int shadow_pointer_offset(const void *row, const void *shadow)
+static int meta_pointer_offset(const void *row, const void *addr)
 {
-	/* The length of ">ff00ff00ff00ff00: " is
-	 *    3 + (BITS_PER_LONG/8)*2 chars.
+	/*
+	 * Memory state around the buggy address:
+	 *  ff00ff00ff00ff00: 00 00 00 05 fe fe fe fe fe fe fe fe fe fe fe fe
+	 *  ...
+	 *
+	 * The length of ">ff00ff00ff00ff00: " is
+	 *    3 + (BITS_PER_LONG / 8) * 2 chars.
+	 * The length of each granule metadata is 2 bytes
+	 *    plus 1 byte for space.
 	 */
-	return 3 + (BITS_PER_LONG/8)*2 + (shadow - row)*2 +
-		(shadow - row) / META_BYTES_PER_BLOCK + 1;
+	return 3 + (BITS_PER_LONG / 8) * 2 +
+		(addr - row) / KASAN_GRANULE_SIZE * 3 + 1;
 }
 
 static void print_memory_metadata(const void *addr)
 {
 	int i;
-	const void *shadow = kasan_mem_to_shadow(addr);
-	const void *shadow_row;
+	void *row;
 
-	shadow_row = (void *)round_down((unsigned long)shadow,
-					META_BYTES_PER_ROW)
-		- META_ROWS_AROUND_ADDR * META_BYTES_PER_ROW;
+	row = (void *)round_down((unsigned long)addr, META_MEM_BYTES_PER_ROW)
+			- META_ROWS_AROUND_ADDR * META_MEM_BYTES_PER_ROW;
 
 	pr_err("Memory state around the buggy address:\n");
 
 	for (i = -META_ROWS_AROUND_ADDR; i <= META_ROWS_AROUND_ADDR; i++) {
-		const void *kaddr = kasan_shadow_to_mem(shadow_row);
-		char buffer[4 + (BITS_PER_LONG/8)*2];
-		char shadow_buf[META_BYTES_PER_ROW];
+		char buffer[4 + (BITS_PER_LONG / 8) * 2];
+		char metadata[META_BYTES_PER_ROW];
 
 		snprintf(buffer, sizeof(buffer),
-			(i == 0) ? ">%px: " : " %px: ", kaddr);
+				(i == 0) ? ">%px: " : " %px: ", row);
+
 		/*
 		 * We should not pass a shadow pointer to generic
 		 * function, because generic functions may try to
 		 * access kasan mapping for the passed address.
 		 */
-		memcpy(shadow_buf, shadow_row, META_BYTES_PER_ROW);
+		metadata_fetch_row(&metadata[0], row);
+
 		print_hex_dump(KERN_ERR, buffer,
 			DUMP_PREFIX_NONE, META_BYTES_PER_ROW, 1,
-			shadow_buf, META_BYTES_PER_ROW, 0);
+			metadata, META_BYTES_PER_ROW, 0);
 
-		if (row_is_guilty(shadow_row, shadow))
-			pr_err("%*c\n",
-				shadow_pointer_offset(shadow_row, shadow),
-				'^');
+		if (meta_row_is_guilty(row, addr))
+			pr_err("%*c\n", meta_pointer_offset(row, addr), '^');
 
-		shadow_row += META_BYTES_PER_ROW;
+		row += META_MEM_BYTES_PER_ROW;
 	}
 }
 
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index 29d30fae9421..6524651b5d2e 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -127,6 +127,11 @@ const char *get_bug_type(struct kasan_access_info *info)
 	return get_wild_bug_type(info);
 }
 
+void metadata_fetch_row(char *buffer, void *row)
+{
+	memcpy(buffer, kasan_mem_to_shadow(row), META_BYTES_PER_ROW);
+}
+
 #ifdef CONFIG_KASAN_STACK_ENABLE
 static bool __must_check tokenize_frame_descr(const char **frame_descr,
 					      char *token, size_t max_tok_len,
diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index 6ddb55676a7c..4060d0503462 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -85,6 +85,11 @@ void *find_first_bad_addr(void *addr, size_t size)
 	return p;
 }
 
+void metadata_fetch_row(char *buffer, void *row)
+{
+	memcpy(buffer, kasan_mem_to_shadow(row), META_BYTES_PER_ROW);
+}
+
 void print_tags(u8 addr_tag, const void *addr)
 {
 	u8 *shadow = (u8 *)kasan_mem_to_shadow(addr);
-- 
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cdcf749c4b78368810885a0ba83b8f3f0328d722.1597425745.git.andreyknvl%40google.com.
