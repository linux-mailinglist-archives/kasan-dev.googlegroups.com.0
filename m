Return-Path: <kasan-dev+bncBAABB472QOHAMGQEK67IIPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A1C847B5A9
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:02:28 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id t1-20020a056402524100b003f8500f6e35sf3755060edd.8
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:02:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037747; cv=pass;
        d=google.com; s=arc-20160816;
        b=R9vodXVsBzVXjDZAElVUD+7WQ8t6PLaLbCKfXEq9j5ZareEzL55TMP+TqIKakO9Dxf
         IjxXvnLE/7bWY6Q09cbJcmRfjz1GBE51al+vTjT0hSGDlQ6Lm/gXTjKSf8QqlL3FObUJ
         r184Dds1sAvO7wnDB7t0POTDL9M9+3VVT8VdlDGPk+vhAOUyXp7z4ayGg8sjIp2XkUZN
         Ack5a1lpqK6f26pDBMdW9wYll6ZrDnb49fVpbkFiQ9O+8ElrNC/WIaxPFIOEGFz7DeVd
         f8q/qJAva6YEB/dELZC9A/pWKJ+hKZKst298EXXezABld6GRfx8aIN2S60IM8ItoAWAj
         IGbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=kMFXo3EAjeQrpKoMuM8XvBaVX8WQwZh/Y1q+DpFs6rQ=;
        b=ysAzONRq/3tYXXEfDbtEHbiEi5AAL/zZ6yjCdqdmMZe/S/3+3MLr6cvA62G+bfsh+S
         tRX65GgtkwXz91RN2PtLMCIwge0Vpnqce9VklNp75VODtDnq2S2K9nJ9vDrk0aD/8EiY
         m0lW3wXcOjzr5iME1lURSNfIbvBrmrfAvXeqcGQ3PZew9IQzPXFyNhkYbmxNuEh4VQTu
         YQZjrMGccNz7hYkDKuR4cOwRWoXrJCA6fxLZLEp43RmdMPAVaF12+JSfkSThFMWbjx9a
         lLx79qbpAebfSdHND4dK9qw0Bxn7+zFh2RfR3NU23o1IwejCTqV5Z7xrfh0lxReGB5pe
         MuzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="wCJ/sXMO";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kMFXo3EAjeQrpKoMuM8XvBaVX8WQwZh/Y1q+DpFs6rQ=;
        b=ENO3D4n+jWdj81nP65d9tjlTGaT30rtxsmgSkUhHpB+NB8FggnoPHglH7AsvGrJWF4
         0jkAh7lTT6VhqWd2FNDCc7RUWA/tPYJdUPpEoPBO+NinR50yi88mk3oVFFdjRCpsnqk2
         w5qrSOZQ1xpvXJXSB+8V+tpBmikAJ7/Tj9QSMschJVn1zxPfU/D9gAKrSnobNsxLCtWs
         6zc+aB1j34JcpSrT7T4Jlzr7O/OUvt0hfoBSQvgfib/W/M8cz+XZXEWqkKHqvbFE67JF
         /58yJ1omgb0eEqHs+bQ4yV4JRkEoB5CarqNQ9FAnqrxyigFDTu1S5C4tzgvTTBh3aKOY
         Pw0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kMFXo3EAjeQrpKoMuM8XvBaVX8WQwZh/Y1q+DpFs6rQ=;
        b=JNFfOKE8a2IRSxjE2p596c2Zs4xVApK9QSfJJkzM0RNV2qQ48PTBSkC+p59pUxxGPG
         f79OaOOKUgvfYZcKk47y4ssVQJYWENeNaroxas40i8RJUgGOHFZzCK5/sBM8hCIYVc0v
         TsStg5JWn/naauy37F6rdJIpPVQEAPGonBi3QFkaQiMyOxXOG/XwofRF12NzctymJlu/
         dwOJLm6VnGQ+zUTHIdXrnjggx/8idKbUOZPEtRDye5d3WVhLEN+H+xNscOPHi6uFckKU
         BvELVYxoxBhpeTVW4mUuLd2TW4/LGF+b9WwqzwwYoWlKyaZlBf69uP9v77ZY544pR99Q
         NFKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533P6ek0BqErFaG4Y7xXxwxyKH1utimuxxH0+WyxvDE10iQqHDZZ
	JMfSVyHVQPKvOiwL3GNOW3I=
X-Google-Smtp-Source: ABdhPJw1qcZl3L69b1FsPgNKUCEZZ12zS4JSdHTAML5fJJ9rKDwGAxexBnASgSFAZmFhhALepM5PXg==
X-Received: by 2002:a17:906:aca:: with SMTP id z10mr133620ejf.535.1640037747902;
        Mon, 20 Dec 2021 14:02:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:50d1:: with SMTP id h17ls924723edb.3.gmail; Mon, 20
 Dec 2021 14:02:27 -0800 (PST)
X-Received: by 2002:a05:6402:1e90:: with SMTP id f16mr165314edf.112.1640037747202;
        Mon, 20 Dec 2021 14:02:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037747; cv=none;
        d=google.com; s=arc-20160816;
        b=OV5aJfI/YOKDzJxFzbGdLb+oIs2wvpkiL4y1Z03IOLr1qWQsm59g4lzN0b2KP50hEn
         yEKsZy0AfIVOLu34Sdd9RtVdBHQK5+y0kIkMXPSDAwXoiwC4ijmKXedUzamJuQpJLfvY
         Ke+MnLf6XMXJJn+yponCJCsAfvdi2kbJzxPiN6EyJX6QpV85b9mqTbAL/7xA7XnCbh1a
         ivQ3BJktTbNYWKAw5cOmJ/Fqy271K02WhWhSoqQg4bvgk+D/C4OZdUrOo6wI/LtbYlH7
         81EeDMUMzXs2PffwQY76Q7UXT6a9L4313fWuVSsqMfrbxsF1Y/ZwaOcsuPD9+KVCe9na
         Irdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hR8bpTKg9o/0qS9DZQupKoGy2DR+telbSe2yC2ZqoZM=;
        b=wz8b2GYDC+RZXvFvzSz1ckZiqZWIABrr4IRGfr5lVkBmnfarRs6GUaRJ1cv8MStDCT
         cHxixBMY6cfL9AUF1dMPkXDh5SXIIyLGnaE6PFYHFpYFRxiM9qkSJiEm0Quk0bmQ3T3J
         ZS7rUGTPHuJPTh0P39nW4lJxI2nJ7lhigwqpJoWTlwM0euOfbKznZP7hCGw7NhfxnUxC
         b0fHWX+geDccA7cBNccBIlCyAhlvOPj/xYwiQmLtU/pF8ZPogGOGxwNgZzNl7Btw2e5f
         rbPHkmgDoEsVpvZ2Oo1B6r8jbiNfA9KZ1MqcIi+qILO1nTWL36beLddmzpw4n6k1nZ6q
         m0hA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="wCJ/sXMO";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id bo19si591519edb.2.2021.12.20.14.02.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:02:27 -0800 (PST)
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
Subject: [PATCH mm v4 34/39] kasan: simplify kasan_init_hw_tags
Date: Mon, 20 Dec 2021 23:02:06 +0100
Message-Id: <c155e133946179a5f34380d75f49ec90bcfa08e5.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="wCJ/sXMO";       spf=pass
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

Simplify kasan_init_hw_tags():

- Remove excessive comments in kasan_arg_mode switch.
- Combine DEFAULT and ON cases in kasan_arg_stacktrace switch.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Add this patch.
---
 mm/kasan/hw_tags.c | 12 +++---------
 1 file changed, 3 insertions(+), 9 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 6509809dd5d8..99230e666c1b 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -159,20 +159,15 @@ void __init kasan_init_hw_tags(void)
 
 	switch (kasan_arg_mode) {
 	case KASAN_ARG_MODE_DEFAULT:
-		/*
-		 * Default to sync mode.
-		 */
+		/* Default to sync mode. */
 		fallthrough;
 	case KASAN_ARG_MODE_SYNC:
-		/* Sync mode enabled. */
 		kasan_mode = KASAN_MODE_SYNC;
 		break;
 	case KASAN_ARG_MODE_ASYNC:
-		/* Async mode enabled. */
 		kasan_mode = KASAN_MODE_ASYNC;
 		break;
 	case KASAN_ARG_MODE_ASYMM:
-		/* Asymm mode enabled. */
 		kasan_mode = KASAN_MODE_ASYMM;
 		break;
 	}
@@ -180,14 +175,13 @@ void __init kasan_init_hw_tags(void)
 	switch (kasan_arg_stacktrace) {
 	case KASAN_ARG_STACKTRACE_DEFAULT:
 		/* Default to enabling stack trace collection. */
+		fallthrough;
+	case KASAN_ARG_STACKTRACE_ON:
 		static_branch_enable(&kasan_flag_stacktrace);
 		break;
 	case KASAN_ARG_STACKTRACE_OFF:
 		/* Do nothing, kasan_flag_stacktrace keeps its default value. */
 		break;
-	case KASAN_ARG_STACKTRACE_ON:
-		static_branch_enable(&kasan_flag_stacktrace);
-		break;
 	}
 
 	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, stacktrace=%s)\n",
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c155e133946179a5f34380d75f49ec90bcfa08e5.1640036051.git.andreyknvl%40google.com.
