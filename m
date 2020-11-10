Return-Path: <kasan-dev+bncBDX4HWEMTEBRBKNAVT6QKGQEFWYFTVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C12C2AE2C5
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:11:53 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 14sf1377466wmg.1
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:11:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046313; cv=pass;
        d=google.com; s=arc-20160816;
        b=j0TpPUN0x2FKvSTwLT+UGAlj/WQexRuUIez/tcOJpkzOxOCEXPqyyG9hVntGPB3n16
         qD/e1ialgHwr1i9FUCJ7+WH8vtuFTUxQ5BdBgirfHZ7mK0LKtfgzlWDcEESroN7LvEqh
         8S9E8bS9JZHZCXHkIfm4gOKdASMemrX3QEHyKz22tQFqbf2TvVXjXcHwWnHps7rceHJl
         p6keYv/MpQV69cIN0dyRv7o/AVD9ZgZsbeXcwz6OCa+mFHmJaEXfk5eGOwAxENOZO7Zs
         Wy6FD8rLAG9ooITXy4ecFnrE2emq45iAT0JQXNpPOMnXe7Z4f2nMcKWgk26dpQ6C605P
         R3uQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=2J8x7NqeedEiRAA4qhr0B7TYkDg5VZ7oYCONkuIqOuw=;
        b=t5xGnoNpC+WiddTIkpo3BxIdrLRNb3tzWCruibu3qqk+ffZHiTIBT42VNgxEFftltH
         8M9zgrq2vTjw9RUlWrBl049hl1HVKFTan+7X9S+E8hX2pBS9W3I1+2889ZUfZJ3+Gzjv
         V2eW1Lk6hBd9yIJsKtzqzMoh86aiilJJ67DpcIdv2kN1pb0fWA1n9KfP8Sw++yTOrsKQ
         jNwN/yVgbm4NxPYyg91Um58yMibIwh/P3rA67IFVtnoN/j5XjM53uu7zKFwHwSDHwoQ8
         QBLEAzaLabf2xsi7px4iTXPKkxdpLzGoBxq9NG5hwTCyl09pzDwJMxYjbmTNAsYD+VKi
         xOpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=X7YjSmgD;
       spf=pass (google.com: domain of 3kbcrxwokcfczmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3KBCrXwoKCfcZmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2J8x7NqeedEiRAA4qhr0B7TYkDg5VZ7oYCONkuIqOuw=;
        b=NAZ1kRmA4nmJlXCsZ+7PGXCMIm91z71xdAf5+aDoe8nMeRlyI8itA3ckNFycNOU6kS
         VZtS0l655AxZXAiCaL59m+pdhD0YGo6C645+D3fEVemwRVqzhja67rIHKpLJIdT/UOz0
         nRYpQ1DK3xOu1fImqFmqyjTp9uW0TZzkTqQmhETTGC70JPxhESIyeXpl9LlJoQDnTOpY
         oJUU5z08c18Q+FVVgb+zQudLP7sLywW0Nh7Gws4sXt6/oBGrzzotSI3SyanKPbDNujkz
         Hlgn7zNnHjvFPblPu1le/VyRcrnZCKHuGNIdEcFJHZVGIXV+Tnv42viOO3rXhmJDCCB9
         kbHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2J8x7NqeedEiRAA4qhr0B7TYkDg5VZ7oYCONkuIqOuw=;
        b=fsPE3gsqa0M9eOB7D4N6n7IpcNOmNBG16riTwzJIUMuyaJJasrUQTroyq6rN6fYxgW
         hhu23rFBbeycU2t+TZT7J8+eXjP6S5xbbo1nGBj0QCxwhelR/fp7c/6VI+G6Tt0n65Au
         ta07eBFSsJxzfJr2Woi+nA9c0cb+O4oEeNtmI5XofAGzHLQzrddxcQ1d+n1v1v4ER/Mx
         xFHejXU7javfcav/A8CbzIgnVjxEDRQ65uYeK1Fek9a5Mcwe7bcewFWcfp9R8vyp++TZ
         0c+32JoXZA2GzvwBcodlP/2jLJ6aVIY9wnNsa0tMoJl4kCknaMeVNn5Cilpb4CSwxvrx
         5pxA==
X-Gm-Message-State: AOAM5333W0B2JsIwqH0NGVCh3PFD+xAVMY62u0gFpC5QkjPT5CTJF7bO
	4owkONhTCeuzCwDmSueW0xs=
X-Google-Smtp-Source: ABdhPJyOew0VzYtj3ebr0xXJnw4w/98Znor6SYGsocACLANrdnW0LHeCa7cCdCXqpz7fs55CoC2/qA==
X-Received: by 2002:a1c:e006:: with SMTP id x6mr238266wmg.107.1605046313255;
        Tue, 10 Nov 2020 14:11:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:5417:: with SMTP id i23ls213035wmb.2.canary-gmail; Tue,
 10 Nov 2020 14:11:52 -0800 (PST)
X-Received: by 2002:a1c:4b18:: with SMTP id y24mr268502wma.154.1605046312495;
        Tue, 10 Nov 2020 14:11:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046312; cv=none;
        d=google.com; s=arc-20160816;
        b=zXUofSpS+ypjq6OVzq9vJbTwIB+SSDa8D6uAzbNqJln6hq2doXBzlM7WKF2nBVL+YE
         ZZ25Cv57lMbMt5aapHS5fzAi6GmhDF4foij9P2wpFPa54pVSgOa0DKxO64mKphoMiVz6
         mvT9joYl+IkfonScJJYkJSftyYsm7djYL1GAAgo/HXprHgBejxUDyLAuf8HNQx/fwbGR
         Yjcul0CSTlvV6Rg4V7q4LG5piRT+jZ+UY2BCMSW4DdqBHOFf8C21GjQftyww1AmvTZou
         TeVhjlV0Pgixd3CiqRSwLk6IIVIeOjh0rUFIlGaTmc1P1z4MuA+/pbbTIgv2CFAaU4DW
         ioJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=f+E/U7KjS3eO8ZHDl6v4LSa9uLmsgT0jRyLIgabh0JI=;
        b=eSH/kQdvGQsL4WtaGOGd7ZimuSBhvNnXKPm4x7hLl19eZj33x5L1fFwnIBr2dSZehf
         Lv8qFfelYw7QIEiALlAzj+7XfRGJBdP0G06R0oW+Wj70YfIdDvszEuBainqVoDH7+NGW
         5QWtSBipb1ysoOwZWWYGoHkr7POMRb5Ytac9F5yrM0QVC6r/g3LyhLyaV4C8SDnJpxNQ
         nQq2uhkMIRguIKwSP9GaophOePWRdvjObIlMmPfZTggxUywoDrTB45Qm383JtPu7+Dhm
         9UMnP+LLE/BTBZrTVuV0JNXlvw2ufuuKU6HFUY73kpFd7K8LvmlPQimY84Hdk5B3sI4B
         pO1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=X7YjSmgD;
       spf=pass (google.com: domain of 3kbcrxwokcfczmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3KBCrXwoKCfcZmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id z83si250811wmc.3.2020.11.10.14.11.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:11:52 -0800 (PST)
Received-SPF: pass (google.com: domain of 3kbcrxwokcfczmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id c8so1160336wrh.16
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:11:52 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:530c:: with SMTP id
 e12mr20014512wrv.355.1605046312145; Tue, 10 Nov 2020 14:11:52 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:16 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <1034f823921727b3c5819f6d2cdfc64251476862.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 19/44] kasan: rename addr_has_shadow to addr_has_metadata
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=X7YjSmgD;       spf=pass
 (google.com: domain of 3kbcrxwokcfczmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3KBCrXwoKCfcZmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
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
index d0cf61d4d70d..f9366dfd94c9 100644
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
index b543a1ed6078..16ed550850e9 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -118,7 +118,7 @@ const char *get_bug_type(struct kasan_access_info *info)
 	if (info->access_addr + info->access_size < info->access_addr)
 		return "out-of-bounds";
 
-	if (addr_has_shadow(info->access_addr))
+	if (addr_has_metadata(info->access_addr))
 		return get_shadow_bug_type(info);
 	return get_wild_bug_type(info);
 }
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1034f823921727b3c5819f6d2cdfc64251476862.1605046192.git.andreyknvl%40google.com.
