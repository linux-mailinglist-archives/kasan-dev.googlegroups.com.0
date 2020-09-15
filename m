Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSW6QT5QKGQEEM7FLUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id CCD9426AF58
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:16:58 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id a81sf724198lfd.1
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:16:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204618; cv=pass;
        d=google.com; s=arc-20160816;
        b=RFl/iffMQ1Vv3/3NkqX1OROCbAvnNgFFZdQxmUac84c3ZFMPc0HRRRcV3nW1jnoiDi
         ARel+mTFYmn0W5VbZ/MJAjdiu9/fd8Kv8M7PY3anGRdbJzOHf9FZ8uFGV1bi5jvb3/uT
         ijsUlCu8GxMY2vcOiNjuaEtpWOw+tGZ5m82wZfWyPVk6TfS5o0VoDkrZ3qSw5E7wFrR3
         dsh2cStUCPXeXwWB/Pq4KY0qWg+UXvgol/zEGjLmdaCm7FyBeL3435GS6QSQQcfHUqOs
         MGKRxSlookrBLQ1r1np1b8iXWMN3M657IUMrsZxFFMU8Kv9gQ/at2Hze7IMdco68um02
         lVnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=6StX2Y+mEW2YVebY3oqF/ovZc4oV4ESyyKDaNiI5psc=;
        b=uLybEybR/s0pxX6mKcMcQX4YGhEBy3bBk++6XioKBme9b2MdIohGoEZn/6Bg4DhFYx
         86LAyBg0iyJYJLz9cLvb4VqxCBSniV2n7IsoCAysuoiWNTCyw3ZhCZfTeSpQ+N0x0DWJ
         N2cVx4yaA9ZdvSDaQ9lfCq995OELOL7pEX+2a6MgTI+0xXizFxY5nwMDBhoxcECeT5fS
         6L4+/BC9ItdFOLvbecXk+mkSthgKB5C/jde2fuvVBR8JAJX7ZK+OmhaG5CebArGLjfOZ
         SWjJ4RSxZbHxo9EI6p+dGrTPQYgwN1SJek08+5rc4KgZtbiRNBz2mdo+lR5dcve3tpfG
         yoRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LidLdQly;
       spf=pass (google.com: domain of 3sc9hxwokcs0jwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3SC9hXwoKCS0JWMaNhTWeUPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6StX2Y+mEW2YVebY3oqF/ovZc4oV4ESyyKDaNiI5psc=;
        b=BGE3wxaG0wNZN1k74AUWaFckop/QsnosqFi+JV/MbfdahQzRVXVomGxDfLnmkYyPTf
         vU/bPVNengMX5w3vBtFXUrn+oM4k6cs2oWoYt5VXuG13LqqfN5FLk1fuFsQkMpzM/34h
         XSxSfgouCNjvB2cH8+BA/ynrh+bOCFZhRPbcc7KfB2BLfCB1NE3wBaiTQpAg74pKh2uj
         FvfrwYA9OOKtqPgeYzzfdSQvPUkolFiz5qu+zxXMJErvgWeTtQVEYidL7zTMyT7EF1eo
         inHnhZMssFsRzSsHzf8IEqvMMtWX1d9ggol1rDg1Sus/oaqRmMGahq83MRzFqVhY5FRn
         OHlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6StX2Y+mEW2YVebY3oqF/ovZc4oV4ESyyKDaNiI5psc=;
        b=YTvK+7OCSNorPPH3LsrnnyAmEcHRzJp72+4YzehbDVPXcHVN/rxaSJqmbPjWNgcXw2
         dDsNbJwjL99lE/8ZJUEA2dLm90uOdSePIJqt6czdXo7TpeMTriWmUw/mVhmO/Bm+hn1F
         4Mvstx2UPyLC5j6u8qpN0/NytDG9axu8+w1UPIqp2lFzBqmXiDAUhNzIpfAUN7DKBXT3
         ELUtTsVMUw8DjSBCn2iIZ9dkKfUkr9qFjcZ0151V9WnOjitpGcfwq5D+OLUae45hEL7k
         2u29z0QRI+40n28RLlORoe9HkrzF0fl6HjTnvLZYLzOMz03yU3mbmKsJAK3XW9/3yoC+
         75KQ==
X-Gm-Message-State: AOAM531taDcaJBG9UrISAiBOUyuUetoqIkH+JozPC89Kcfvqg77lAl0v
	ohdxsqbgSMI9mvtlJAsHsyw=
X-Google-Smtp-Source: ABdhPJwxvWhVaE+quaK0pct45Da66oA6rolkjFhvEmgmSQyiN3BCDwrrQu24OSBXk0KQz995QG8Iqw==
X-Received: by 2002:a19:89d7:: with SMTP id l206mr7683370lfd.110.1600204618401;
        Tue, 15 Sep 2020 14:16:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c7c8:: with SMTP id x191ls16697lff.0.gmail; Tue, 15 Sep
 2020 14:16:57 -0700 (PDT)
X-Received: by 2002:a19:48d5:: with SMTP id v204mr7136775lfa.287.1600204617375;
        Tue, 15 Sep 2020 14:16:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204617; cv=none;
        d=google.com; s=arc-20160816;
        b=vbRujbdiYpBqdecG+vkPz4T7VJ2vMN0A70ei3kKpAqZnozUylbuShxrcVtbs3ayuHi
         kKfU2rcX+fyV3yzLYp6y4ewbrR0RfuQLky7VZx1J0WWgKMD8q6BolLaWfSsi+WOKxmdb
         NkphLZLcqvcCmIPcO7HKiGrU2SBhsX86gUEv1TyAi54dnThm+cQCF6KkRaNSR0ZW41VK
         Tq9fu0IdlC5pxXiTzvn3ouU6dwBspqYdQVUcIX+PlC/wFocgtHqD6dRnOVj98pQFhzS0
         n0tru5M6ss8fwlNAPrxWl68MuF+GGVIQviZBUG0pt7YMHZ9dPw/XgGoiSu8YWsMgN5ju
         vO7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=NFU27GtWbL95WCt8F/LRedzvWo/LtApbnjc66sNmtks=;
        b=Zz5/hdwyjlLWnSr9n+EadqlMmsaOduGywKgq4MezHCtKuf9AQaFNrlmZnl3xeHBkSv
         yooogiEwRlkNqenoHNaKNqpKMkX6O7RtLH4huZeVqQ5KBS2+ACLJREvbD0QakK5IcLn7
         /m5VocY05mUDR5CnbxedQlGFuq7wV+3sGpd3oMy/0UvUpcAIH2XgZ4uBG7Rw0rtKhnLU
         MSQ/zohcLzH/OArKfNlAb6CEbqWoXjXlKJSinNQQRe3ZkL4x6yzAqaugyGtGq71UoCY9
         XLivQnh+tf4dRIEZOpyGGVgi8nHNaHt0vltYJ0LC7c7mmDUj1Sx8N/DmJYRi31HVXKPs
         7EGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LidLdQly;
       spf=pass (google.com: domain of 3sc9hxwokcs0jwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3SC9hXwoKCS0JWMaNhTWeUPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id m11si265868ljp.6.2020.09.15.14.16.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:16:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3sc9hxwokcs0jwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id y18so225157wma.4
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:16:57 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:9c93:: with SMTP id
 d19mr23867458wre.275.1600204616832; Tue, 15 Sep 2020 14:16:56 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:15:56 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <b48d1be05f393b9148874115844625ab4a07ee8f.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 14/37] kasan: rename addr_has_shadow to addr_has_metadata
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
 header.i=@google.com header.s=20161025 header.b=LidLdQly;       spf=pass
 (google.com: domain of 3sc9hxwokcs0jwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3SC9hXwoKCS0JWMaNhTWeUPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--andreyknvl.bounces.google.com;
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
---
Change-Id: I03706fe34b38da7860c39aa0968e00001a7d1873
---
 mm/kasan/kasan.h          | 2 +-
 mm/kasan/report.c         | 6 +++---
 mm/kasan/report_generic.c | 2 +-
 3 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 15cf3e0018ae..38fa4c202e9a 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -145,7 +145,7 @@ static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
 		<< KASAN_SHADOW_SCALE_SHIFT);
 }
 
-static inline bool addr_has_shadow(const void *addr)
+static inline bool addr_has_metadata(const void *addr)
 {
 	return (addr >= kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
 }
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 8463e35b489f..ada3cfb43764 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -334,7 +334,7 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	untagged_addr = reset_tag(tagged_addr);
 
 	info.access_addr = tagged_addr;
-	if (addr_has_shadow(untagged_addr))
+	if (addr_has_metadata(untagged_addr))
 		info.first_bad_addr = find_first_bad_addr(tagged_addr, size);
 	else
 		info.first_bad_addr = untagged_addr;
@@ -345,11 +345,11 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
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
index 427f4ac80cca..29d30fae9421 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -122,7 +122,7 @@ const char *get_bug_type(struct kasan_access_info *info)
 	if (info->access_addr + info->access_size < info->access_addr)
 		return "out-of-bounds";
 
-	if (addr_has_shadow(info->access_addr))
+	if (addr_has_metadata(info->access_addr))
 		return get_shadow_bug_type(info);
 	return get_wild_bug_type(info);
 }
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b48d1be05f393b9148874115844625ab4a07ee8f.1600204505.git.andreyknvl%40google.com.
