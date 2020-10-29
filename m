Return-Path: <kasan-dev+bncBDX4HWEMTEBRBDNP5T6AKGQEUF4ESWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id ED37E29F500
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:27:10 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id t10sf2937289pfh.19
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:27:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999629; cv=pass;
        d=google.com; s=arc-20160816;
        b=q0EFf94FF6QFH02Newjtfw61oq8nDTDLdt+ZnPBs1YSbQYLJmymd+BfevAWemth8Uy
         Et8TQaANxN9/TUFvtj7V2/ezREb+a0lm9kLpTInw/2lioG0oBHLnqJtSYhhIA83Gbauj
         djwpBpZlAHidHU2/P2kAFDh8E1pKIFDQvFTRCLCPwwT4+YWDrimosqeU1eyKbEb5a8Zm
         jL45x/ISHTn/gQnPx92xqj52oohpw7VC5XO/n7UsMjRN8YgdunRTxWzwBhuUGeqVCfqV
         8i3QptAaR0WVbbL9LNDXaeHPPkcD9OIg5f57cf2Fr+QoCsj6kUFTMC/qDI8l8L+pxTgN
         cZNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=8LVtV3AqdituQpr8f83pXweyBKjw8bbH9J/gl+ngIk4=;
        b=xs4wdLjwUMj+MJP40etybaSgidEqXbS2Cv/L4pqql5W7lAt2f/p6okEFeZ31K8g/uu
         yvB6Oczw7HDBp1CVC2d1vhAJLjTkx5sf3+Ni5+3io6wOvj6QR2wsbfy09PL29GyBu1ab
         VwgM1KyurySa/lVuttP5INZfLqCkYzfJGKt9L03XVsEZVQXD8zZpCE4UqToscAnrUnA3
         31NBNu459RwfA3n4GjKx96y4TIBjlurxL7qqSkVo4FEnEonpM+Vhp6+6pfWbQc7xvmwi
         KhJaaKLpkE+IUi/4GSwDt3HnuUhH4oCQT8hMAnV0A/mYe7WCmscsybNpcJ/Me4JkvySp
         wVnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EdQyVtnk;
       spf=pass (google.com: domain of 3jbebxwokcsshukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3jBebXwoKCSsHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8LVtV3AqdituQpr8f83pXweyBKjw8bbH9J/gl+ngIk4=;
        b=tEvBsh+eql/n4lA3SENTc5lgJHsNLq3zmxMA5tAWtHf8zDo+/uW2ZURZXAO/tS9P+9
         mbuPBwfjReSWNgjr2lSJYgq3SmKQvvbe9FZc0jMSrolffyilYUpq0FrU7LUfzqwGG+WG
         IKBYXXqQ3O4EGUc4EhdWj0eOBQayF3YTbkbZRhapDACw+oVJRTLmX8GLoYA1OKjXDcjW
         qzSmiMPz2bHu4NVdyGi8/0XgXty9j04KBYblTUB4bLSIbmG5TKvXzj+F+fVFWrXNzEsf
         jJwX9Ae17hntxMR+lmuP7/pR4486uY82j6xJhwjLA7b7tKiocJqmXEtIzgikbd6MSEFU
         hCaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8LVtV3AqdituQpr8f83pXweyBKjw8bbH9J/gl+ngIk4=;
        b=ii0SbbfnZfArAeeNFS4TV4Ln1ZiooNlwBIsTt3nuQZ0gykunpIF4zgKJnFWUMJGc9P
         P4a1qk5suz8aQo9Iz6kUmLr02sSWe/Pt2a3Q11laMYqkP/1DsqwX/NiSHpoMFeklGDAd
         1zGe4p++XW6xDICW7FTwD6KZYJZkCYvd0CmXQfszASWAW15FDUo2PcDipT++VorX/2Wf
         774tJiqdxt3tCJlmwvBTuZ9ReGZsTU3BbIs7aKoKUdCEgXnY/a68Zhp8LQqCxm0+wbtx
         euQVj2E7g9vpKuNDmxq5tpVwYEV9g1p7GWQdNdVyEnyzQSP0XKrJW8PI5shzQ+hzu/vH
         rnLQ==
X-Gm-Message-State: AOAM531U3Ed3Vgt0up0Yc8kIucZ8zzDVMCEU8XJjw0/sdbtRKrG7gA5t
	HR56DnLe/1CK48O1APejKqM=
X-Google-Smtp-Source: ABdhPJwQjU96BO3We7iSvv3LW0LzotvUarpRjViOVpn1YoRybeNnwY62Aq7CbaSYNFqAG3jtyNjPxQ==
X-Received: by 2002:a62:2a83:0:b029:160:d8f:6598 with SMTP id q125-20020a622a830000b02901600d8f6598mr6156818pfq.30.1603999629723;
        Thu, 29 Oct 2020 12:27:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7d8d:: with SMTP id y135ls1415710pfc.3.gmail; Thu, 29
 Oct 2020 12:27:09 -0700 (PDT)
X-Received: by 2002:a63:8c49:: with SMTP id q9mr5446384pgn.427.1603999629227;
        Thu, 29 Oct 2020 12:27:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999629; cv=none;
        d=google.com; s=arc-20160816;
        b=SBF4QUkSzGANNCZ9O8y4l3qw32zevIi6ehfVgyLMdfq4pyeob7WNiT5xPz0ROHzsrQ
         4f7TG7rCL3WKQRSWifCvSd0hzkoaSqwu1hbeXAmSkvLQECiLBcCyXb9VtBDnKnsJQS+3
         2HfAwkJJeF6EKTeWwd94iAVL9Ob1xuzTwiAMTqLEELobv4BbHMkOs2JGNfb2zpqm7cO4
         xFDrrlc2lvle9wW9idq6tT/ypX8pnhstLFqAolmfQOZMQRUngVt47IRQ7aNZPmriDwAM
         K7TXxtnJIAs844wRSb6j2/EnLcYSC/r8buZv3Kg7Cd6OEswlk3JOqtnog8Hs561EZ66Q
         0vWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=MeYcqtBqx2zX9SLBJun3MMNhtoyJ+Q7swKHdtnpeAZI=;
        b=qF+x+RmM/LrCZ5KXznldyCcI34MoWt7INiT1EKH0SThLdMsvemhLy5L50h1LZdaIsX
         DZ8VpZmVrejVJ8xyIfgyIzubcsEfwYgxkoxAvvYuNh135f4ZQctDG+gQ1jzB7EQ1lFcc
         22buWlg8fn3WF9uqxJDRO5AaGPDvd0UW6qog1l1Ab7Npk+M8hixyzddlyAC0f4Bu/MIn
         +D452jL0d2hwOAaQqZ+AsuCLjIJ/CVrl0hfKDJa2Duxg4LvUVwE0adV58/dnIre42Yd4
         +U+gvtZJOtUfNIixi4Z9G/bDBJx2Ut7Q6mieu3NP9bhEPbIHZyP/rWot1sGnYx91V1zb
         u6Kw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EdQyVtnk;
       spf=pass (google.com: domain of 3jbebxwokcsshukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3jBebXwoKCSsHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id h17si51620pjv.3.2020.10.29.12.27.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:27:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jbebxwokcsshukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id u16so2420838qkm.22
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:27:09 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:ffb2:: with SMTP id
 d18mr5644573qvv.44.1603999628350; Thu, 29 Oct 2020 12:27:08 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:46 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <b40c5b1c9faa43e7647682a3b41107e8d7fb516c.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 25/40] kasan: rename addr_has_shadow to addr_has_metadata
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
 header.i=@google.com header.s=20161025 header.b=EdQyVtnk;       spf=pass
 (google.com: domain of 3jbebxwokcsshukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3jBebXwoKCSsHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
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
this function. Rename "shadow" to implementation-neutral "metadata".

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I03706fe34b38da7860c39aa0968e00001a7d1873
---
 mm/kasan/kasan.h          | 2 +-
 mm/kasan/report.c         | 6 +++---
 mm/kasan/report_generic.c | 2 +-
 3 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 2b8ca8f2aed3..139fc52a62ff 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -146,7 +146,7 @@ static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
 		<< KASAN_SHADOW_SCALE_SHIFT);
 }
 
-static inline bool addr_has_shadow(const void *addr)
+static inline bool addr_has_metadata(const void *addr)
 {
 	return (addr >= kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
 }
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index af9138ea54ad..2990ca34abaf 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -361,7 +361,7 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	untagged_addr = reset_tag(tagged_addr);
 
 	info.access_addr = tagged_addr;
-	if (addr_has_shadow(untagged_addr))
+	if (addr_has_metadata(untagged_addr))
 		info.first_bad_addr = find_first_bad_addr(tagged_addr, size);
 	else
 		info.first_bad_addr = untagged_addr;
@@ -372,11 +372,11 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	start_report(&flags);
 
 	print_error_description(&info);
-	if (addr_has_shadow(untagged_addr))
+	if (addr_has_metadata(untagged_addr))
 		print_tags(get_tag(tagged_addr), info.first_bad_addr);
 	pr_err("\n");
 
-	if (addr_has_shadow(untagged_addr)) {
+	if (addr_has_metadata(untagged_addr)) {
 		print_address_description(untagged_addr, get_tag(tagged_addr));
 		pr_err("\n");
 		print_shadow_for_address(info.first_bad_addr);
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index 589b1875f5e7..363afde3c409 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -117,7 +117,7 @@ const char *get_bug_type(struct kasan_access_info *info)
 	if (info->access_addr + info->access_size < info->access_addr)
 		return "out-of-bounds";
 
-	if (addr_has_shadow(info->access_addr))
+	if (addr_has_metadata(info->access_addr))
 		return get_shadow_bug_type(info);
 	return get_wild_bug_type(info);
 }
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b40c5b1c9faa43e7647682a3b41107e8d7fb516c.1603999489.git.andreyknvl%40google.com.
