Return-Path: <kasan-dev+bncBAABB3H2QOHAMGQEMHUYTZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 12D4547B5A2
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:02:21 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id ay40-20020a05600c1e2800b003458b72e865sf1016499wmb.9
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:02:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037740; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zm3T000ppJtw4BdjSo2ElJWS8XovRH4Diy+DSoYLb+kdKsmYhIK29WO4Ngeb0/rZFE
         kwHe7RqjsOgHQK4JkZMLdmZDn54NC2WeAT2k8iQ0F/dfjfIPXd1R59DjlV+wd1keQQ6+
         Y5w2UU2PC6HlWpDPvPtj3F1QklEngFG5M7p06fOPJx8aXuAAbbeKrelWWc7EWA0SFTvn
         6wqAOc3uD6I3RzCQPpIkRVjzNxYZ/ie/hzhEg4+iS4rfBW9CsYxFiz37M635Cyg/3cqI
         7oMagxekBebm+5NWuPArOIwfEeqCJkB7vu7y9lA0jqsl/MSR8+CXldtO9BrbUSOhvSkY
         01wg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=fokkVAWSnosylUA39AzxcHYC6LTVsQBHsaikxU0pTLQ=;
        b=r5zvIycZ7qgq1vJ/oG1tV9X0RjT3tJHDcDga+Hv4ruaFYkzNW2l0rKzXetc1UZAYUp
         8vgjJ1KrJ8GCsoEMTNJG7dtwQd6rt0a4Rw0UzQME6JdOf5INY+75bbpEbwf7HU/SHS7p
         itBiARxZHkQEZisxUEyavPGQgxqkmsDRLYCFyLqD4EsBJFTMg/ySJo2tlztTG3ueYa6Z
         FqY0OjQF1X1xxrg7Dx0/gElcD/GbGccnC26CZ1hjunPSYsTEPj4zp+figpo8zvktr+rp
         LJtgDDdss3QqLljGu+rVX38D4U1oncC/81NfkFmqzSYMnzDq0eEt7NhHtvF+cv+m8EXv
         CRYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=djH7pQvL;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fokkVAWSnosylUA39AzxcHYC6LTVsQBHsaikxU0pTLQ=;
        b=lOyvamegQFwBeZ1XtpT3+pa2T/NIqzPv5kRzY+mf+RxShEQ5wi64c2mDDW0Tk1bvn2
         9RdfsryFdpSf4/kCP5tsPv6QFPXHB3m/aF+EByh6IuZq6uR4jwCykP7lHJoCkPOHX63F
         4zqbklMxTSXJIgI3unVYC8zEoyD/MHgvSOyU6nuEJOsIXgMq9YO7grExIMPCB7BZWRp6
         FZrctul7jB+Yplb78u7fu1AG0ZGicx5wAkfYIHP2u/TawAB9/P9eL3PEtrsTyVq1vjix
         dE3jaLeDAdtH+FyOHEjt+e9Fv0Nl5vXi+0QLRbS13FAHP9+4FQ0Hf7TDjIlfzgBg91Eg
         uWOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fokkVAWSnosylUA39AzxcHYC6LTVsQBHsaikxU0pTLQ=;
        b=stzLlySAPOcQMKBYlNFBe2dToRflV6udKWxfk/vddG4f/pNHFgxaWNKz3h6ji20rXn
         HijVbkBUNBneBsUTFTsq0spMf51Powrs75xtA5kzLNJR7u8UKYXC0f3ZMi/mTKe6C5ib
         V5e8E1ZFIse2tLFN2t89o/o4/YpBJ0CuZ941RMYJVZgkN0QJIhwdVGwbjKpOhbhKojUp
         lr39KK1wgciHKK2TaxP1tmbEvOFqW/jhLAcp2NXXoAQCqgczgY/NdPbB7vbFzp53mBdi
         39A5kcTzrGkTuXr5hhon3OfXcmZN5BFDpLiGX28YXxz6FNNw8MysVzlY2Kpr/0lZ8oJS
         9brA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533aof00EbN475jpdZTj2gd6IWIguu9h9rwuxPO61i8P1OClYJ4p
	7xTpEJknCq62LcWIuuGVk0c=
X-Google-Smtp-Source: ABdhPJyN6NAaKLPdnwpWIdN6uneOdVxikSM8hMwZ6CHt3xFU95EAerrZ7d+AJcvTsRxEI3g73+mDVA==
X-Received: by 2002:a1c:f005:: with SMTP id a5mr50221wmb.19.1640037740906;
        Mon, 20 Dec 2021 14:02:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d21b:: with SMTP id j27ls6389637wrh.3.gmail; Mon, 20 Dec
 2021 14:02:20 -0800 (PST)
X-Received: by 2002:a5d:5409:: with SMTP id g9mr120044wrv.298.1640037740354;
        Mon, 20 Dec 2021 14:02:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037740; cv=none;
        d=google.com; s=arc-20160816;
        b=Rr4Oh5Qx37sJywCn47Vt6SBzEe6NRePEl2RP13+vEi4krwy+maHomJZQOfbgsqZhID
         +Bv+5OImS1crVF/ExMj+Q3pPb8E80loZHX1l1oiRl4UJhPQrkSLw6qwhkexbJRSvRaM3
         rpbIP3nml7GxdUJYAT0kfz7duj5Oo09KaWLiAtjemFQP8v9RQOle6lC59rzvuJUwxYxN
         1la9NJ/Uqjsze8zdp2SnNgZTunBeznL3gMLRjIo1yflT5k1afTJEJXxBeGM/c0NWvUj9
         bVRY66LZgIcB2aQq3Kjeo3WJV8NxywNUxQzY+ysw6jFYzEngaO2VWaAnge6ftLse2eWC
         6fbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nibMKNPOUfTfl0PGq9c+gFreyTXEodKWyYW93h99/Mc=;
        b=jpRBim0wk+xmlugT5NRUAOGSDiVSK5UcVizwNUdiSGF2QPwDbDa3BvDqHfD3Bax18c
         GoU5NElJaqKnXCUCzPs/eMDAjRuwn1pjOrH12oIWi0ORrsCQZzvYjbkPJjVofYvfJ0fC
         pmf8xBhADo3QV+29E3rlpKOR1xqvQKco0EsivbrwFRaiqZdlPVpRx9K0dgz1V0ZYc5+8
         tqmYDsFXayAqkBnOKvRMgKmiOQue2ZlEIgvsXfrixe7nl71vT8lHNIKyvFHlHHZrzYrD
         RYVZOlODiPsZExuFe5kYT3ueoKkKuHaeAajA4Fpi2jHvFseUqGWKaF6RCos+0HJpD3Yh
         fZeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=djH7pQvL;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id j23si79714wms.4.2021.12.20.14.02.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:02:20 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v4 27/39] kasan, mm: only define ___GFP_SKIP_KASAN_POISON with HW_TAGS
Date: Mon, 20 Dec 2021 23:01:59 +0100
Message-Id: <8e2ce1656dcd9fe47d04779ab359d18642ed7878.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=djH7pQvL;       spf=pass
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

Only define the ___GFP_SKIP_KASAN_POISON flag when CONFIG_KASAN_HW_TAGS
is enabled.

This patch it not useful by itself, but it prepares the code for
additions of new KASAN-specific GFP patches.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v3->v4:
- This is a new patch.
---
 include/linux/gfp.h            |  8 +++++++-
 include/trace/events/mmflags.h | 12 +++++++++---
 2 files changed, 16 insertions(+), 4 deletions(-)

diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index d6a184523ca2..22709fcc4d3a 100644
--- a/include/linux/gfp.h
+++ b/include/linux/gfp.h
@@ -54,7 +54,11 @@ struct vm_area_struct;
 #define ___GFP_THISNODE		0x200000u
 #define ___GFP_ACCOUNT		0x400000u
 #define ___GFP_ZEROTAGS		0x800000u
+#ifdef CONFIG_KASAN_HW_TAGS
 #define ___GFP_SKIP_KASAN_POISON	0x1000000u
+#else
+#define ___GFP_SKIP_KASAN_POISON	0
+#endif
 #ifdef CONFIG_LOCKDEP
 #define ___GFP_NOLOCKDEP	0x2000000u
 #else
@@ -245,7 +249,9 @@ struct vm_area_struct;
 #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
 
 /* Room for N __GFP_FOO bits */
-#define __GFP_BITS_SHIFT (25 + IS_ENABLED(CONFIG_LOCKDEP))
+#define __GFP_BITS_SHIFT (24 +					\
+			  IS_ENABLED(CONFIG_KASAN_HW_TAGS) +	\
+			  IS_ENABLED(CONFIG_LOCKDEP))
 #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
 
 /**
diff --git a/include/trace/events/mmflags.h b/include/trace/events/mmflags.h
index 30f492256b8c..414bf4367283 100644
--- a/include/trace/events/mmflags.h
+++ b/include/trace/events/mmflags.h
@@ -48,12 +48,18 @@
 	{(unsigned long)__GFP_RECLAIM,		"__GFP_RECLAIM"},	\
 	{(unsigned long)__GFP_DIRECT_RECLAIM,	"__GFP_DIRECT_RECLAIM"},\
 	{(unsigned long)__GFP_KSWAPD_RECLAIM,	"__GFP_KSWAPD_RECLAIM"},\
-	{(unsigned long)__GFP_ZEROTAGS,		"__GFP_ZEROTAGS"},	\
-	{(unsigned long)__GFP_SKIP_KASAN_POISON,"__GFP_SKIP_KASAN_POISON"}\
+	{(unsigned long)__GFP_ZEROTAGS,		"__GFP_ZEROTAGS"}	\
+
+#ifdef CONFIG_KASAN_HW_TAGS
+#define __def_gfpflag_names_kasan					      \
+	, {(unsigned long)__GFP_SKIP_KASAN_POISON, "__GFP_SKIP_KASAN_POISON"}
+#else
+#define __def_gfpflag_names_kasan
+#endif
 
 #define show_gfp_flags(flags)						\
 	(flags) ? __print_flags(flags, "|",				\
-	__def_gfpflag_names						\
+	__def_gfpflag_names __def_gfpflag_names_kasan			\
 	) : "none"
 
 #ifdef CONFIG_MMU
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8e2ce1656dcd9fe47d04779ab359d18642ed7878.1640036051.git.andreyknvl%40google.com.
