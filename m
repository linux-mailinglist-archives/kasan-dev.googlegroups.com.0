Return-Path: <kasan-dev+bncBDCPL7WX3MKBBR7HVG7AMGQEE73N7HQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 20ADFA55F4C
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Mar 2025 05:19:21 +0100 (CET)
Received: by mail-qk1-x73e.google.com with SMTP id af79cd13be357-7c3b53373fasf255304385a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Mar 2025 20:19:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741321160; cv=pass;
        d=google.com; s=arc-20240605;
        b=GzrDpYLXWDjgKPs4WVK+i7khqUYJgGuSHnh4ebdnH7K8LSNkjaJ6kLkMYvVreUcHYz
         utNY1W9Ud3SfsV8ObquCzBO3YEDl9JS3URl2yvd4+aHvxG4mS0MD0s+0eiThUOta6Ylr
         FMCnll3hiZw9w40UbPUvfyZ1VyHuLxNSdX1ntpfSKs4LhqjLD/JrzZF8HYJlEI8nsrfn
         GrPLS7oVwMQ/z2eYssaeHkLflKkdGqaIfWMwfDRU3t58Z+BUQCXXGXsTCENa2nTAjZPr
         ZoGzQg+F03F8wdzp6cN7MCvkPPcQEkK6Ye7tlDQpC16lyfGBZGYsw2FbTKMHcRPoNl9z
         g8AQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=U/IWSsMAhZ6DV4f8YIGK5uxEIMoHjZFX68mzuhoVvNA=;
        fh=ugNd9GMhhv+sWMjwOkqJwJ6U7rmXfucl1W3XUiJbOHk=;
        b=IpkFqs7QHpmKVq5k4SrzVdUKbdRrtqN5QvvEj15qbF8nFtZUHZZIumLbiDJ2mny1UL
         3bETFTotFthjGDHVhNAp9KB+lMGBeXSPhttS31H6S61E0uiulTUqOnFI+t/lACy9pQUY
         d4CNlow16LOP6e0rYkCCovbAYIC/f98P8prS4ead1xkbw22Fq+ABvoCgcI4coHZC2fPn
         +mKVRDSyX9h8BN12LgUSOLCMCogaLXDDYqVzBZtN0TYIN8I86dhAvtOh2fOgHY9pmkgm
         FkNHogrrXgHiypV/r3GedelLWIF6HkihAOymhlnvh/uEE5UoEMJGcDPEl/DGEx6AiEcH
         e6AA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Rz5g9Vap;
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741321160; x=1741925960; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=U/IWSsMAhZ6DV4f8YIGK5uxEIMoHjZFX68mzuhoVvNA=;
        b=f2jdrA3u8wWgOapB9oeL0nPv6fXtytTIJ3X8eTAm91H49NX3ngpH1b8/0pC/YDznPH
         cscrcS8dp1lSYGhQse82LyfbicwlO6GgbYEvaiBKbX6CB7O5VRe0TcVSgUxWqqw6eZyQ
         xdQeqo8X4I46gstnoqp0IxjwAWsYr8GsifXPp85r2lRLOvy+yjlGs1+bkDgQ/djDb3jX
         /XOx7dgNr3QBAPFZo+ts/TU5VdsmQgnCIZRvOHJl3aZvVE1pAXFTDBO9x6Mo+/qEIhBC
         Mpjl2gFDQKqFpVEjxwsAMeiNRgwEutN2IaZitLR0eQd1hWUCzDLEsXkXyeMKs1Z7pMDL
         xvdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741321160; x=1741925960;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=U/IWSsMAhZ6DV4f8YIGK5uxEIMoHjZFX68mzuhoVvNA=;
        b=K9rvuzn7D8cWnsaKWllgsEVQZqk/Q1+TxypSA0EvhICctZhMU01svczlnv7sKptnJ+
         12GLFdayazOI8H6fnpU4CYH3UoXc6GnJtKKen99Ag1qXOQ0XOtbEP2HB7kirlbnt/R3/
         R+C0+Ct6/5j3Md3bpMsdaoROCCxhMU4nmQjU/ycbYhS/5zQ1FdzZmn6+2u3cG2Hjuavw
         9bHC45SVDju9U6Jsmz+//w2zgh4L8zgaeVEYjU89mshHHdKpYgwQmEraY86KQA8swgL1
         q8oOVoFDnZDbFxbwYyFonYPFoWiLeWO8jw2N7KpG8HPf3AOB7rZEIfKLc+oB+Kga3MEX
         IBNw==
X-Forwarded-Encrypted: i=2; AJvYcCWn92QWTJuobNxTN7Z/oyF/9zYwJhYNUOTqXbYTbVYUCl8Vx4oHcq9qyOPGTKe6FuEtlqhnFA==@lfdr.de
X-Gm-Message-State: AOJu0YxcrBE7/Xx+a4PO5cRpLxkUtcS5pX05DGgYwJpgzJkyl3uZi2QY
	c/A5eIYYABpEL6iJcjW3ws2YI85D7WJflRt6Ko4ZL7r9VOnYPmP7
X-Google-Smtp-Source: AGHT+IEWcg/5uk7ukuMRSQe+Kpaomf0yqUBvq4bTG9JuMwAGiun/04GqHsRX0XdeJiEgtsMw9P1WOw==
X-Received: by 2002:a05:620a:6884:b0:7c3:d2f7:ca5e with SMTP id af79cd13be357-7c4e1678c16mr276196385a.12.1741321159913;
        Thu, 06 Mar 2025 20:19:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVETgWrlX86MA0JGABHcnnsESJya3k3Sg3FlZT/2aGvS3g==
Received: by 2002:ad4:59c4:0:b0:6e8:f267:6759 with SMTP id 6a1803df08f44-6e8f4d72397ls26266776d6.0.-pod-prod-02-us;
 Thu, 06 Mar 2025 20:19:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWZHJ5OsJoTvGKdntvkyNBLUjPRMSn9vD59mKqtLi1avBnAI3B0zywg5Wkd3d/h5jV+NGWntYz2UMA=@googlegroups.com
X-Received: by 2002:a05:6214:1d02:b0:6e8:ebc6:fd5f with SMTP id 6a1803df08f44-6e9006326e9mr29584096d6.20.1741321159144;
        Thu, 06 Mar 2025 20:19:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741321159; cv=none;
        d=google.com; s=arc-20240605;
        b=IdwTa56Ex4TkDUjeo3OIWgZfUlcqCF55T7MqW+iDoCSymZdIXzt0Yk718+5ygEIUFm
         z9dXI/aIWKQn403sz1h3LzUoy4qlLjjQleb8H7cbe19gK+gstHBwL6Sj2oz1+dvK3Hdp
         omY5IFuleM0oj4iQDwY+Z6C2/QEBRr5NfDLEpyD72vY42HkU48Xceu3UO9NlxIM0B6VB
         NHkesekHPGU4ROgxmP4hV0QT3kZfxMfii/B2/vPXt+TLqdcH5jxlVlC6mE88yys03DrK
         s/SC4rL1/KFsjus/befxD/G/JChHtspCCHA39Wu+sHfEBpgA539FTALgVrrz2eOvK0pe
         rEpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=p72ZGDokQzigREDZXcLM1VcjYqs/GyzAGmfnWbuJVvI=;
        fh=YlFMr26WTZWVJevYQO6yDjgH92fFU9GmhJxxVKyBhxE=;
        b=krzI5x59DJT0uEhy1rZLx1RpMD1EWoYwSUaHNue3+slTS7cWRV1pK4LkPqYCq6ho3k
         uDzhTq6KvTQ+obJF6XMr6qgHmPdH0c7f8LpuDymgvJWvEeItgZKigSecrJ/YnYQtfaQb
         gjRfKmsottKwAoxinaNM9fcbJq+5IoqLOdPaembY60gg2bDLCtAnBAH6Ku92XsztWmWv
         e//d3pzY9nL8vDoaT1W3/dn3AfiPSBxjDDdbL7s91YOufLM4Lf402E1uLnxKAzT6Bq4I
         hNFUl+YYf0f+/42i7TU1TffJUXwosjfKRZsOlGff76mhOUN0KR84CBQSuuDlD41RVpCa
         6xMQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Rz5g9Vap;
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6e8f7123595si1232146d6.3.2025.03.06.20.19.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Mar 2025 20:19:19 -0800 (PST)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 30F5FA4544A;
	Fri,  7 Mar 2025 04:13:48 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E2590C4AF0C;
	Fri,  7 Mar 2025 04:19:17 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Justin Stitt <justinstitt@google.com>
Cc: Kees Cook <kees@kernel.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas@fjasle.eu>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	linux-kbuild@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	Andrew Morton <akpm@linux-foundation.org>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Hao Luo <haoluo@google.com>,
	Przemek Kitszel <przemyslaw.kitszel@intel.com>,
	Bill Wendling <morbo@google.com>,
	Jakub Kicinski <kuba@kernel.org>,
	Tony Ambardar <tony.ambardar@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Jan Hendrik Farr <kernel@jfarr.cc>,
	Alexander Lobakin <aleksander.lobakin@intel.com>,
	linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH 2/3] ubsan/overflow: Enable pattern exclusions
Date: Thu,  6 Mar 2025 20:19:10 -0800
Message-Id: <20250307041914.937329-2-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250307040948.work.791-kees@kernel.org>
References: <20250307040948.work.791-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2094; i=kees@kernel.org; h=from:subject; bh=swXPVnzWC/FlvTAyt5YU2bLA06oGPklYrKEuppMNs8o=; b=owGbwMvMwCVmps19z/KJym7G02pJDOmnivdFn5JrOxe5UsvST1KT0T7/Z9y/CeZXXiyc2sBj8 qlu7n+tjlIWBjEuBlkxRZYgO/c4F4+37eHucxVh5rAygQxh4OIUgImYiTH899uitEkySfFFhPd5 Twe+z+sZfp7XnD/3eSUL01tGu5u+tgy/mFlqc12+iT/Jfya++uLdam6eJ5l3xSeqvl3FGcJdEHy YFQA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Rz5g9Vap;       spf=pass
 (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

To make integer wrap-around mitigation actually useful, the associated
sanitizers must not instrument cases where the wrap-around is explicitly
defined (e.g. "-2UL"), being tested for (e.g. "if (a + b < a)"), or
where it has no impact on code flow (e.g. "while (var--)"). Enable
pattern exclusions for the integer wrap sanitizers.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Justin Stitt <justinstitt@google.com>
Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Nicolas Schier <nicolas@fjasle.eu>
Cc: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: linux-kbuild@vger.kernel.org
Cc: kasan-dev@googlegroups.com
Cc: linux-hardening@vger.kernel.org
---
 lib/Kconfig.ubsan      | 1 +
 scripts/Makefile.ubsan | 1 +
 2 files changed, 2 insertions(+)

diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index 63e5622010e0..888c2e72c586 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -120,6 +120,7 @@ config UBSAN_INTEGER_WRAP
 	bool "Perform checking for integer arithmetic wrap-around"
 	default UBSAN
 	depends on !COMPILE_TEST
+	depends on $(cc-option,-fsanitize-undefined-ignore-overflow-pattern=all)
 	depends on $(cc-option,-fsanitize=signed-integer-overflow)
 	depends on $(cc-option,-fsanitize=unsigned-integer-overflow)
 	depends on $(cc-option,-fsanitize=implicit-signed-integer-truncation)
diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
index 4fad9afed24c..233379c193a7 100644
--- a/scripts/Makefile.ubsan
+++ b/scripts/Makefile.ubsan
@@ -15,6 +15,7 @@ ubsan-cflags-$(CONFIG_UBSAN_TRAP)		+= $(call cc-option,-fsanitize-trap=undefined
 export CFLAGS_UBSAN := $(ubsan-cflags-y)
 
 ubsan-integer-wrap-cflags-$(CONFIG_UBSAN_INTEGER_WRAP)     +=	\
+	-fsanitize-undefined-ignore-overflow-pattern=all	\
 	-fsanitize=signed-integer-overflow			\
 	-fsanitize=unsigned-integer-overflow			\
 	-fsanitize=implicit-signed-integer-truncation		\
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250307041914.937329-2-kees%40kernel.org.
