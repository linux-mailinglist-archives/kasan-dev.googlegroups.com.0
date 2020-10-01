Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFOE3H5QKGQEPJVFCTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 10D9C280AFF
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:11:18 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id j17sf60830lfm.9
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:11:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593877; cv=pass;
        d=google.com; s=arc-20160816;
        b=ybjDMfLlAUrE1HDD9CRjL6SVSIejGahaCGiVb5F8iSRNayTi7Gxulfv4H8me8YhhNH
         kB/nt5SBBW744n3v3qXdWy9wSR6+VU3a8e27kewQ6fRfTnZGdz0MJsA3G76z5LHxyFTr
         IyF7IsAfl5T21T7I4ucaRxnKqwM9SuWAW75NF8OwvzhZHwvwLhji/5mRAuJxrHG4kFUU
         ujGWGU2pxPZmsW/XVKe5IbrwO/fYE3MNEw51gQouhDG5bypTOzeTEXJXiubJW/4MfAng
         Ri1bsswwsoajhpXcjfUXnpHJZP292cNoCcCOwARdGHxmx8n9NuVKkIYzUyTYFhesgNA6
         /Sjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=GDCJ/gIY5WVzEXA7HlJjLLaD4BqUKy6xLcrgGuV2KRQ=;
        b=zP/U1Vgfmgcs7OLaBOQz2WUHzLBRQaOgUizL3o+FOf+AmwXZfZ5SI/TBk+0tRyhueU
         M/cCT0nlB/UKlCaQV3AOyH6Sz9vtt4KdcsaJ4pNzgKgurUNENBqnszj00I58VPAFJBY8
         xLYJkNnkAE9kdE4VbJfcktgwCG1qsnQuwln1wA6m8MFi8pU5M20tboBCZ7fxPHrvciEp
         Wa2MwxvczXSW17sF2j1dUMqIcIamww1Uei1rbawAPc7U0boi4UR74kFDN8M6aMEO0/rq
         jGO4VFrbtuXjq51OX3Vmt2GVPZUkxGxNF3UoCWQsWBX6TDDqQGcQDEKolo30u8f8/lqn
         8MKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Dsq/YBkg";
       spf=pass (google.com: domain of 3e2j2xwokcbisfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3E2J2XwoKCbISfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GDCJ/gIY5WVzEXA7HlJjLLaD4BqUKy6xLcrgGuV2KRQ=;
        b=Urhudq6BVPRJRX+lcPGWHHY5r7H0alM0Jac0wIU3ehJip83VZa4C+TRN+2HfUpUGRW
         +beiaEXysec7ZQdTnXhVSNrqhj1vEXj8K0yYqmpqyh7oMrNXKo3toADDDW2OmZBgNV5P
         yve+FheSclT8vIifm33+bCr8DVLe775p96Luw4RoSG5pZz+Fmby6LByXE0v7f8TPwWlU
         M6ZCBLR6uhKYcmSM3gNBQfGfMU00oZl1hXxQZx9yffDvTcZMhDaFeQtMBlSAgC8tCy5d
         IHwmnda/vCshS60rXGL7nyXclhN3Dc3/At7LSCVO2cHcJiqJQTPEowlfgTXFDHEZ4gW8
         c2VA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GDCJ/gIY5WVzEXA7HlJjLLaD4BqUKy6xLcrgGuV2KRQ=;
        b=UBaBg+U2dl9FRkxfqVxDuEV+necEgQFdUrKCdr6ZR4XcKjdgDvvafYNlGdz4ntM68V
         lqHx6vhIv7qJMYV//FMA430pWtX925ygx3dn/yt/lz/W/MKDVK9yb0TaCEM8NOvWKPAC
         dJJDfv4J3ABsszNsVGaPuUDZQ/CnLYmfEIEfZdo8hIkX+L+BLZe7tkVolJ3Av8Lt3e8O
         FpbeTIFRDgavNmr+SbJkhgIm/sYfQa+dkDGZ4lF5pmrxtkWO0yj1jSABPrdouBlfVT+Y
         qLexyKhpjHmtku1CxH4eE/5qDdTv2VEjSB/fO1OMXCerHgf5RIfR2x+sEx3/lOCgTQWH
         dSmA==
X-Gm-Message-State: AOAM530ivNH9Mdrz/jGofM4HEPeRLQpeWYodXbkdqBS0bQ0bkvRnRGSs
	116me4+GFRhYpjUVzb/bFG0=
X-Google-Smtp-Source: ABdhPJyo7ireVXrij0/vFiEjAden/DMcaXLkL7s/8m0Ua92VhaR/SHhMGya/inDDEdpM1gfpAumZwg==
X-Received: by 2002:a2e:89d6:: with SMTP id c22mr3297012ljk.242.1601593877556;
        Thu, 01 Oct 2020 16:11:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5c44:: with SMTP id s4ls2138701lfp.3.gmail; Thu, 01 Oct
 2020 16:11:16 -0700 (PDT)
X-Received: by 2002:a19:103:: with SMTP id 3mr3162321lfb.452.1601593876497;
        Thu, 01 Oct 2020 16:11:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593876; cv=none;
        d=google.com; s=arc-20160816;
        b=b2q3jdyuuD2X50dC4jtbcU4TAK5FzknbpdyWFddfwUku1K4W9cxQ8jglMrsRp33WJK
         mrF25hSMCA3x+pxh7TPnCn7Roa7ZO9ZcbwBr018zb0M2Ar2k+QfhfUhZELiEhdxvyrl8
         JiYzuEYfvVxbD2T1j7IZHhQbgdtq6lmpaRnZrxkHIfYwpLl5u8UrrCglvrp0IC3jVvOb
         WCE1+tWHACHqgR4PRVJVdkRA3MY9x/8X4VpO37rOB/1N2IuUjmIyCxMdZVTkfxE9fS+9
         VUV/HfU7TsufZm0mrGeAYkMdCFxM5tZd/9gDCBdhUuyKIZa3vXxKOjp2ZquIhSHTsmKD
         VL8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=cF2oZSzhrvdoeGLQw8li6A/kur1xexwZGy7EDIo3018=;
        b=ZOMxPYRdoQbZi8wVVCrMHagfIo/+rAp8FYm01wJRBBheXbzErapdkYtaw+gS4KG9vC
         ZT8fPzPhTHXRtpGsJYLP9gyThTUTm7RV6ORJUVThme1QRy+Hxx8QyQX5FrYKznMIsroa
         wIiJOdaOKs5TckYe3RvuwPHqOpGHSIebYS+cel8P0V9IbbYKOLhzFclLMYBm3RSFDviJ
         b2FQQlh6DRCy7kvNjwyxm0ixgnU++hUn7zR5xRUEYn17yqo2LNN3xSxMMCDc5IgATYNU
         c5AwPzZNc/8b01d4fAClUMyV0f+qOUYVLh3yRLnc+PF49vZbTK3hpTEgLesrjzsCbRaW
         HVEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Dsq/YBkg";
       spf=pass (google.com: domain of 3e2j2xwokcbisfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3E2J2XwoKCbISfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id x74si177513lff.12.2020.10.01.16.11.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:11:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3e2j2xwokcbisfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id o6so132977wrp.1
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:11:16 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:4b17:: with SMTP id
 y23mr2253346wma.162.1601593875808; Thu, 01 Oct 2020 16:11:15 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:14 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <2047d61bef0ecfc7e75d22f14ee6958ac005eb28.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 13/39] kasan: decode stack frame only with KASAN_STACK_ENABLE
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
 header.i=@google.com header.s=20161025 header.b="Dsq/YBkg";       spf=pass
 (google.com: domain of 3e2j2xwokcbisfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3E2J2XwoKCbISfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
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

Decoding routines aren't needed when CONFIG_KASAN_STACK_ENABLE is not
enabled. Currently only generic KASAN mode implements stack error
reporting.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I084e3214f2b40dc0bef7c5a9fafdc6f5c42b06a2
---
 mm/kasan/kasan.h          |   6 ++
 mm/kasan/report.c         | 162 --------------------------------------
 mm/kasan/report_generic.c | 161 +++++++++++++++++++++++++++++++++++++
 3 files changed, 167 insertions(+), 162 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 3eff57e71ff5..8dfacc0f73ea 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -169,6 +169,12 @@ bool check_invalid_free(void *addr);
 void *find_first_bad_addr(void *addr, size_t size);
 const char *get_bug_type(struct kasan_access_info *info);
 
+#ifdef CONFIG_KASAN_STACK_ENABLE
+void print_address_stack_frame(const void *addr);
+#else
+static inline void print_address_stack_frame(const void *addr) { }
+#endif
+
 bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 void kasan_report_invalid_free(void *object, unsigned long ip);
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 5961dbfba080..f28eec5acdf6 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -209,168 +209,6 @@ static inline bool init_task_stack_addr(const void *addr)
 			sizeof(init_thread_union.stack));
 }
 
-static bool __must_check tokenize_frame_descr(const char **frame_descr,
-					      char *token, size_t max_tok_len,
-					      unsigned long *value)
-{
-	const char *sep = strchr(*frame_descr, ' ');
-
-	if (sep == NULL)
-		sep = *frame_descr + strlen(*frame_descr);
-
-	if (token != NULL) {
-		const size_t tok_len = sep - *frame_descr;
-
-		if (tok_len + 1 > max_tok_len) {
-			pr_err("KASAN internal error: frame description too long: %s\n",
-			       *frame_descr);
-			return false;
-		}
-
-		/* Copy token (+ 1 byte for '\0'). */
-		strlcpy(token, *frame_descr, tok_len + 1);
-	}
-
-	/* Advance frame_descr past separator. */
-	*frame_descr = sep + 1;
-
-	if (value != NULL && kstrtoul(token, 10, value)) {
-		pr_err("KASAN internal error: not a valid number: %s\n", token);
-		return false;
-	}
-
-	return true;
-}
-
-static void print_decoded_frame_descr(const char *frame_descr)
-{
-	/*
-	 * We need to parse the following string:
-	 *    "n alloc_1 alloc_2 ... alloc_n"
-	 * where alloc_i looks like
-	 *    "offset size len name"
-	 * or "offset size len name:line".
-	 */
-
-	char token[64];
-	unsigned long num_objects;
-
-	if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
-				  &num_objects))
-		return;
-
-	pr_err("\n");
-	pr_err("this frame has %lu %s:\n", num_objects,
-	       num_objects == 1 ? "object" : "objects");
-
-	while (num_objects--) {
-		unsigned long offset;
-		unsigned long size;
-
-		/* access offset */
-		if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
-					  &offset))
-			return;
-		/* access size */
-		if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
-					  &size))
-			return;
-		/* name length (unused) */
-		if (!tokenize_frame_descr(&frame_descr, NULL, 0, NULL))
-			return;
-		/* object name */
-		if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
-					  NULL))
-			return;
-
-		/* Strip line number; without filename it's not very helpful. */
-		strreplace(token, ':', '\0');
-
-		/* Finally, print object information. */
-		pr_err(" [%lu, %lu) '%s'", offset, offset + size, token);
-	}
-}
-
-static bool __must_check get_address_stack_frame_info(const void *addr,
-						      unsigned long *offset,
-						      const char **frame_descr,
-						      const void **frame_pc)
-{
-	unsigned long aligned_addr;
-	unsigned long mem_ptr;
-	const u8 *shadow_bottom;
-	const u8 *shadow_ptr;
-	const unsigned long *frame;
-
-	BUILD_BUG_ON(IS_ENABLED(CONFIG_STACK_GROWSUP));
-
-	/*
-	 * NOTE: We currently only support printing frame information for
-	 * accesses to the task's own stack.
-	 */
-	if (!object_is_on_stack(addr))
-		return false;
-
-	aligned_addr = round_down((unsigned long)addr, sizeof(long));
-	mem_ptr = round_down(aligned_addr, KASAN_GRANULE_SIZE);
-	shadow_ptr = kasan_mem_to_shadow((void *)aligned_addr);
-	shadow_bottom = kasan_mem_to_shadow(end_of_stack(current));
-
-	while (shadow_ptr >= shadow_bottom && *shadow_ptr != KASAN_STACK_LEFT) {
-		shadow_ptr--;
-		mem_ptr -= KASAN_GRANULE_SIZE;
-	}
-
-	while (shadow_ptr >= shadow_bottom && *shadow_ptr == KASAN_STACK_LEFT) {
-		shadow_ptr--;
-		mem_ptr -= KASAN_GRANULE_SIZE;
-	}
-
-	if (shadow_ptr < shadow_bottom)
-		return false;
-
-	frame = (const unsigned long *)(mem_ptr + KASAN_GRANULE_SIZE);
-	if (frame[0] != KASAN_CURRENT_STACK_FRAME_MAGIC) {
-		pr_err("KASAN internal error: frame info validation failed; invalid marker: %lu\n",
-		       frame[0]);
-		return false;
-	}
-
-	*offset = (unsigned long)addr - (unsigned long)frame;
-	*frame_descr = (const char *)frame[1];
-	*frame_pc = (void *)frame[2];
-
-	return true;
-}
-
-static void print_address_stack_frame(const void *addr)
-{
-	unsigned long offset;
-	const char *frame_descr;
-	const void *frame_pc;
-
-	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
-		return;
-
-	if (!get_address_stack_frame_info(addr, &offset, &frame_descr,
-					  &frame_pc))
-		return;
-
-	/*
-	 * get_address_stack_frame_info only returns true if the given addr is
-	 * on the current task's stack.
-	 */
-	pr_err("\n");
-	pr_err("addr %px is located in stack of task %s/%d at offset %lu in frame:\n",
-	       addr, current->comm, task_pid_nr(current), offset);
-	pr_err(" %pS\n", frame_pc);
-
-	if (!frame_descr)
-		return;
-
-	print_decoded_frame_descr(frame_descr);
-}
-
 static void print_address_description(void *addr, u8 tag)
 {
 	struct page *page = kasan_addr_to_page(addr);
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index 7d5b9e5c7cfe..42b2b5791733 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -122,6 +122,167 @@ const char *get_bug_type(struct kasan_access_info *info)
 	return get_wild_bug_type(info);
 }
 
+#ifdef CONFIG_KASAN_STACK_ENABLE
+static bool __must_check tokenize_frame_descr(const char **frame_descr,
+					      char *token, size_t max_tok_len,
+					      unsigned long *value)
+{
+	const char *sep = strchr(*frame_descr, ' ');
+
+	if (sep == NULL)
+		sep = *frame_descr + strlen(*frame_descr);
+
+	if (token != NULL) {
+		const size_t tok_len = sep - *frame_descr;
+
+		if (tok_len + 1 > max_tok_len) {
+			pr_err("KASAN internal error: frame description too long: %s\n",
+			       *frame_descr);
+			return false;
+		}
+
+		/* Copy token (+ 1 byte for '\0'). */
+		strlcpy(token, *frame_descr, tok_len + 1);
+	}
+
+	/* Advance frame_descr past separator. */
+	*frame_descr = sep + 1;
+
+	if (value != NULL && kstrtoul(token, 10, value)) {
+		pr_err("KASAN internal error: not a valid number: %s\n", token);
+		return false;
+	}
+
+	return true;
+}
+
+static void print_decoded_frame_descr(const char *frame_descr)
+{
+	/*
+	 * We need to parse the following string:
+	 *    "n alloc_1 alloc_2 ... alloc_n"
+	 * where alloc_i looks like
+	 *    "offset size len name"
+	 * or "offset size len name:line".
+	 */
+
+	char token[64];
+	unsigned long num_objects;
+
+	if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
+				  &num_objects))
+		return;
+
+	pr_err("\n");
+	pr_err("this frame has %lu %s:\n", num_objects,
+	       num_objects == 1 ? "object" : "objects");
+
+	while (num_objects--) {
+		unsigned long offset;
+		unsigned long size;
+
+		/* access offset */
+		if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
+					  &offset))
+			return;
+		/* access size */
+		if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
+					  &size))
+			return;
+		/* name length (unused) */
+		if (!tokenize_frame_descr(&frame_descr, NULL, 0, NULL))
+			return;
+		/* object name */
+		if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
+					  NULL))
+			return;
+
+		/* Strip line number; without filename it's not very helpful. */
+		strreplace(token, ':', '\0');
+
+		/* Finally, print object information. */
+		pr_err(" [%lu, %lu) '%s'", offset, offset + size, token);
+	}
+}
+
+static bool __must_check get_address_stack_frame_info(const void *addr,
+						      unsigned long *offset,
+						      const char **frame_descr,
+						      const void **frame_pc)
+{
+	unsigned long aligned_addr;
+	unsigned long mem_ptr;
+	const u8 *shadow_bottom;
+	const u8 *shadow_ptr;
+	const unsigned long *frame;
+
+	BUILD_BUG_ON(IS_ENABLED(CONFIG_STACK_GROWSUP));
+
+	/*
+	 * NOTE: We currently only support printing frame information for
+	 * accesses to the task's own stack.
+	 */
+	if (!object_is_on_stack(addr))
+		return false;
+
+	aligned_addr = round_down((unsigned long)addr, sizeof(long));
+	mem_ptr = round_down(aligned_addr, KASAN_GRANULE_SIZE);
+	shadow_ptr = kasan_mem_to_shadow((void *)aligned_addr);
+	shadow_bottom = kasan_mem_to_shadow(end_of_stack(current));
+
+	while (shadow_ptr >= shadow_bottom && *shadow_ptr != KASAN_STACK_LEFT) {
+		shadow_ptr--;
+		mem_ptr -= KASAN_GRANULE_SIZE;
+	}
+
+	while (shadow_ptr >= shadow_bottom && *shadow_ptr == KASAN_STACK_LEFT) {
+		shadow_ptr--;
+		mem_ptr -= KASAN_GRANULE_SIZE;
+	}
+
+	if (shadow_ptr < shadow_bottom)
+		return false;
+
+	frame = (const unsigned long *)(mem_ptr + KASAN_GRANULE_SIZE);
+	if (frame[0] != KASAN_CURRENT_STACK_FRAME_MAGIC) {
+		pr_err("KASAN internal error: frame info validation failed; invalid marker: %lu\n",
+		       frame[0]);
+		return false;
+	}
+
+	*offset = (unsigned long)addr - (unsigned long)frame;
+	*frame_descr = (const char *)frame[1];
+	*frame_pc = (void *)frame[2];
+
+	return true;
+}
+
+void print_address_stack_frame(const void *addr)
+{
+	unsigned long offset;
+	const char *frame_descr;
+	const void *frame_pc;
+
+	if (!get_address_stack_frame_info(addr, &offset, &frame_descr,
+					  &frame_pc))
+		return;
+
+	/*
+	 * get_address_stack_frame_info only returns true if the given addr is
+	 * on the current task's stack.
+	 */
+	pr_err("\n");
+	pr_err("addr %px is located in stack of task %s/%d at offset %lu in frame:\n",
+	       addr, current->comm, task_pid_nr(current), offset);
+	pr_err(" %pS\n", frame_pc);
+
+	if (!frame_descr)
+		return;
+
+	print_decoded_frame_descr(frame_descr);
+}
+#endif /* CONFIG_KASAN_STACK_ENABLE */
+
 #define DEFINE_ASAN_REPORT_LOAD(size)                     \
 void __asan_report_load##size##_noabort(unsigned long addr) \
 {                                                         \
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2047d61bef0ecfc7e75d22f14ee6958ac005eb28.1601593784.git.andreyknvl%40google.com.
