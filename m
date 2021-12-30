Return-Path: <kasan-dev+bncBAABBYUKXCHAMGQED3CFDHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id DDCD7481FAE
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:15:46 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id g20-20020a2eb5d4000000b0022e0a6d890dsf1574990ljn.15
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:15:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891746; cv=pass;
        d=google.com; s=arc-20160816;
        b=R3grOdKiyZtYxcOs/n742GuWlwKMa9yPSVTlxNyUkjuDPtR9t6XYtxv9ENEOy4ELcI
         B2VZmj3enAwkhteojZkyFCpn2qg/+MkSh+5mCZqI063xsoW9OIWJZg7yNO3xYTH4xKMG
         69SAwfF/xenmlkT8rroNIKHatPc5RRSzx+eMSlg9VS280OYV+KJKr9YLMqrsOd8Ycqtg
         qedpdkN7cnGMnyvneenzqQa5T64VP9JFuWiy24cohYh7DhmvVdednUAfv1tpETjW0/qi
         6PCDhjsf3rY8Dyw6z4cD7SuXAmNld0YvMrQLtrh9DUJNC0O7l/NRrXQJWfQE8MzmfY6v
         ZnIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=oldAK9DYCv0klbxNDuvotHhY7nAfZ5bN98zLY/IUlrg=;
        b=No8Cai4CtW27SEhBMz+rVgiNxvHOYNm13csmqkOEZBJh4hg0uy7m6Vxx+9Q1QJhfv2
         T5kPgB+MSHzM8RIZAuRzv8PFWZGIxZRJBBt8752sd3m5DS6F947pJoDveLfPKqzOLRsw
         CjlKxWqPCJet6Z+Q7gPsKaXBlutjn6YeKvqwnplJGZdtCHnTQf1lKrjpWtNFCSdtpONh
         yJwC13A28ONlYLcfDJ+yMc3iTv8qOJf2+32n24ZO7XgwYqThuwPwbrxfv5ezlBLCu0lU
         9o7JVY9n0aSUMMQhKzyGuiViDLjPkGYIbylDSHl+U08XvbP+LAtoinOl9IkbCP6P6/Fq
         CHiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=KoP5wR6S;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oldAK9DYCv0klbxNDuvotHhY7nAfZ5bN98zLY/IUlrg=;
        b=JK6l/3KUU+53PW/X4CzINyR6WULg/7sBLGSk7FENBIatnnow7hw4VFv8S5H9IoFD1y
         oMUH9gACFosjIRJK9QzM/uqdAzLfuNU7hn2JSrFn90f0RQStPaYkEtz6CU6i3m9BE/jM
         xAbmxmESpbHs0VkLD3HVRc/ZbxKLhcSK0xzYpVXnvsyns6mgMgE3rqcTFUBteBd188NU
         lEZI9ap5xffJ92tvBTc4tYIGhV2T/3X4ieEA5dcI9n9dXkSU0WU4AziMsoIZvAQ7syXJ
         RRGNM9JdgIKTJoqqG6NfLbkz3PIeHra60T5MBKn/eJ/EZn0gFFJBrouNT1we6IcnP0+J
         PH/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oldAK9DYCv0klbxNDuvotHhY7nAfZ5bN98zLY/IUlrg=;
        b=Op2J0Nf+u+rc1V7ay03+M24WtXNNZDgpaCISbMWzWqbLvEJSQ0aKyGWqe92pqyKGc9
         aJuzaWxEolvERlDHiDv0bMpqR8q43qd3If4gsRdhI3r5DhHDgRkzEiCFS9Gj2NXHgW0B
         RMd4U/ipxcdlSFww6dN6CrKMCv6n9S4uQTMCwxhiYe+EgVZb/MDaxb/m80QPzc7pIJEc
         grNBhGI60zvbt5EgQFe0GE8ZODQq/ZwvuitoobaNmnk/r6+SQKBJBSK8ddc2eEXpdWxh
         LtSCMb6kjtmnjwdU1JQRTXtXLRXpZMC+ElceKki4K6hx2WHxMxYg5FmV3utKzUZNk6fp
         6CbA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533xBIgBLLgn5cIAk7unsFByf656Jk0IKsDk64nbVF6RRQeaqnrT
	Yk5PwSawRsTt4fY/vozH2PI=
X-Google-Smtp-Source: ABdhPJy9/mtr1gIUq7BQr4UaDDnesXeDGsdAGHUHQ/4rodAsNS9L5C+V5wAPg2IbIyGLIAK+h1kh4w==
X-Received: by 2002:a05:6512:1599:: with SMTP id bp25mr26889760lfb.689.1640891746475;
        Thu, 30 Dec 2021 11:15:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5304:: with SMTP id c4ls2238629lfh.3.gmail; Thu, 30 Dec
 2021 11:15:45 -0800 (PST)
X-Received: by 2002:a05:6512:2209:: with SMTP id h9mr25865993lfu.79.1640891745808;
        Thu, 30 Dec 2021 11:15:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891745; cv=none;
        d=google.com; s=arc-20160816;
        b=ZhS7SlHPsSBEuJw706N5W4N5LIWQkqPwBHFO1/+OGlLo6yidqsiRXzgQzfrKt3lMzX
         3ZeBLYhIRLILrCEVzLRhcnirqkTsz6b/sgCQJnlxAUnx3u9ibSDcIU4/ZXviV9ejRYlb
         ZEbUv8xxnx9nF0JGCLPaLBg5D48F0DVX44ytB2rmHmwYx0fvmZriAA8hedogGUgVtQbo
         tvP/LZ8hs/Aypz9SI2knH0GhAw7hz6rekBS5JK6TnKrS8cSJ6xJbEaiDYlHO6Hz+NBHG
         HY2iuXHXiITOcqi1Lly5sY61F+Led8dhcwq5NxlRRctPi2Bf9kz2u8PiVWJg1aqIDmPR
         Lx6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ADPuMcEd3Xni1DgUQrhnIN4hiRS8YivzP0ls/GzEPcc=;
        b=P1J9shUU6JSJadIJRN/JoLs55jI84Dd4CyjZiREmz9GMBGXZUxEktBDx/tGH7ad7zK
         G9HXcUrIZX+8EEUh449nJu+UODQDfYqTNZqBNQyDksoJAmtvJwpoDDMG6r+63/c85kgQ
         D44ZisstKHBMwSojYELlqAMBBEz+mucAuHh7YQFHTJCuYQ6ImUqtlC3xKNKKL7IUVxD6
         fmQaorOPZOx1k73b7PTUEa6lrocSP2LBnTHU5zR6PpZEwlf+fqFksXVRR/w3EjVGXiXq
         BlBuU8PuyUah+cIoKP3ljvD67ddBoRONd73GnvXIgt1dt+IIPcj84pfVk0pJU+/hLxam
         I+fQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=KoP5wR6S;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id x32si1186482lfu.8.2021.12.30.11.15.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:15:45 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
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
Subject: [PATCH mm v5 27/39] kasan, mm: only define ___GFP_SKIP_KASAN_POISON with HW_TAGS
Date: Thu, 30 Dec 2021 20:14:52 +0100
Message-Id: <715abda1793c68cc49c833876b6ca993fd2535f9.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=KoP5wR6S;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
index 19e55f3fdd04..9dce456d147a 100644
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
@@ -247,7 +251,9 @@ struct vm_area_struct;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/715abda1793c68cc49c833876b6ca993fd2535f9.1640891329.git.andreyknvl%40google.com.
