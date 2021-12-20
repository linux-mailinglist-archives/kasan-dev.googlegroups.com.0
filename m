Return-Path: <kasan-dev+bncBAABB4X2QOHAMGQEARYSCVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id F046347B5A8
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:02:26 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 85-20020a1c0158000000b003459d5d4867sf259766wmb.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:02:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037746; cv=pass;
        d=google.com; s=arc-20160816;
        b=K6bzI9yLbHEdh5/jGcznlTbtzVRVUjsGqxKUF7gRebTAB16DZprlu811l4P41E96Gi
         c67xaOhAJVuXMy1Od0Mme7h4Cv9nLMUEyHj33grZz0UjHPZoeTnBPIZcSqe7GaLfIH5V
         o4KSjzFDnqKnS/fUfqEva/98jBb/xNzt8AafvVYubHGNytX81iIrRw7X/jGWchbbCkGP
         EGmkDSrtiuSp/SVxlvWFEip0qVjOmiIOGGP4IDcCQQR2c46wrFH+tTnRW56JpogYezgV
         K+yhNqnleU+VmWApCEBU7lxmjkyw32MhWz/vZA/+M5m+mT9nLMLCCB1vwPL+FpnzAROH
         SyVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=bCUeL2LwzWzPc/sCnPq3vQKRa497LtaFfo73shmlIWw=;
        b=KPBI2gNjYysoY73aa+/hyorqnSevmc3k2kDQWRjw3QOoAGFo3mabzluc8UKBar4q8E
         TN+E1EyLw8sWa6ZvoVK4zncoML3+TgizksOptkYqc4GM+P62i9wy+oqFWLQebevyAgQd
         TOPajrMdthriDA3VsRYZvYqM2W+i3PAs4NtQgbhFnZ4d9gqoOuBSaoKhb+4EgSNYenXl
         GjzJRkLZjXfu+l+HptIdgINjFrVSHs2jzqZQ6BUdWnheBHXy+Ff2/uHoe9oEpxzFAwb5
         trx4QromelNOfqGlC2yNdB1DjqJdDxc3VkvGpjcRjmUXh6mvHydh5yHS6QGZfl3vUE9D
         kbEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=wTfdD2QO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bCUeL2LwzWzPc/sCnPq3vQKRa497LtaFfo73shmlIWw=;
        b=SlHkXrf3y5NLXznfsKHfAGS1P7zWE6E33bNYFgYlZg3hcL/jd3KOzat2SmBzRT4zbv
         xNVFIIcgdnPAPq+m8EcuwUFfCX4mOl834vkPNU2WpQnoMflBB3j+l0fCgMNeVH6rFm53
         60scSOfRUXyTRT61PKw291PPuzrt733nyxIsHS08VuYN1GfeKx6Pgc7GYOAGlJCnBXoj
         SldpHINRn4yOB84IE/0KMNL5U4zNnBjVTWCDs+to/lH7PVzUBjyScDS3wnEvxWzrrrcF
         M8pCRLXpTc/oi7vMTt6hQuqhBH01I48o2sM/wYdDJI9ebmmlsKGb7RBLBn5hOcXqsEuB
         9KJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bCUeL2LwzWzPc/sCnPq3vQKRa497LtaFfo73shmlIWw=;
        b=YEKz4DzAMG0NJS+vtGvy3GlnjnuVdjUroHRMgczvrXYVkWxlssJWNEcdqb3zyGluzy
         hFxW/fdTjT6INdwOVpeeg/geYlSRJDtXkU2Alx3tyrgX/ix3KWWsrl4JXuRCpWoYci+q
         /6hnhcdl+klfa4LO2fXQNhrMtgdhwAB2S9c3/kKtw3KO5ZJWe87YqqOGrjKrpc7Y2FBt
         WlEVsDReZEoBpBz4hL31y13Lkk3aPstlfp9MNqe0YTblKpFoYAZ/d7AS/q4oDIdcwHm3
         OKDW6wZDTnmOXSEygVNyfm1PJx/NpsYYWDAN526FzqNlTFSUWvmF5hbU056M+TzNqXi7
         GZJw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533KYKE6HSWYn74GHEzEWTP+6GZnJ2kzZtreLT5ua0QPKpdyTcMo
	IkCjuz6vbXZao40ToJyHlmM=
X-Google-Smtp-Source: ABdhPJw0Xx12wdbydQuP9g3glTHFrV0b+GlfNcedxJDLm7dS1jt8QCdK+OC659jlSubr2n6sketWBw==
X-Received: by 2002:a5d:58ef:: with SMTP id f15mr128322wrd.108.1640037746798;
        Mon, 20 Dec 2021 14:02:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a4cc:: with SMTP id h12ls1075122wrb.2.gmail; Mon, 20 Dec
 2021 14:02:26 -0800 (PST)
X-Received: by 2002:adf:f245:: with SMTP id b5mr111627wrp.506.1640037746188;
        Mon, 20 Dec 2021 14:02:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037746; cv=none;
        d=google.com; s=arc-20160816;
        b=U+GigM2TVXXWHg3VO+By7uPCyGYJ9KzrMAGgCFuw6QpdBzcKiwUqDzuMGV2DpKID+T
         tPgVWKZn9hCUT9KmghW1/0FjkIbz5VkN0gu1kaZYoVL95qYpXAHvDs0fZLKs01OkYHKS
         RyIjrBs4pgitHkoZEBqowEVP2dOn1aXG8H86719byQ0Vw827v1Z6TI1uO0DkP4JCxyXU
         VDZKiyHgzb1eHCWwu9V2uiVrGTWs6hrRnko7hmeBhM3f8kPC8fBt0MKDMh9w8P33bHnc
         5R7Fgelh6vofekvtppnKyxW6BvZ6h5cWZvGOsslkm6zTXEZD7gNf/E/grbcygpRGThuB
         CXyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=woHyASpRd1dsSk1k8aXjCDxvW5sGTzgveGosFVStA8I=;
        b=zNu7ne7TZQEhy2Rx+hJ2kslAB/nbwvUgw/5VUxeNnQVWlbb6p3DEG6IeN6b6DXIvmM
         5QNv88J9ndofuI7SiaC3QVVOwPCn1XSFq1HIGpCq5E4DHX1XBn2IwdeRB9oYvbr+Taxf
         bQQ45N7gsCJyGsOxDkFDblgAEOrF1PHnrTYZAiBJ1RD2JNpIDC8LwX5h6Z93UKOrCWMU
         5aCMmwwMmbsczRcok3hnciAN6xLslfEFoGYQZ45HWf0jmMAhs2IZNWN/Pfr6KGby4ICV
         fYE8aNakKmL78uzfy9YzDNDVhBN2jjHv+mUa+7jor8nvOluccGjbZXAXqq4panXL01zM
         AtCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=wTfdD2QO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id o29si32307wms.1.2021.12.20.14.02.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:02:26 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
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
Subject: [PATCH mm v4 33/39] kasan: mark kasan_arg_stacktrace as __initdata
Date: Mon, 20 Dec 2021 23:02:05 +0100
Message-Id: <b6bb02445ebf2f6dc33e85a76c4091040b0afbd4.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=wTfdD2QO;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

As kasan_arg_stacktrace is only used in __init functions, mark it as
__initdata instead of __ro_after_init to allow it be freed after boot.

The other enums for KASAN args are used in kasan_init_hw_tags_cpu(),
which is not marked as __init as a CPU can be hot-plugged after boot.
Clarify this in a comment.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Suggested-by: Marco Elver <elver@google.com>

---

Changes v1->v2:
- Add this patch.
---
 mm/kasan/hw_tags.c | 7 +++++--
 1 file changed, 5 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 2e9378a4f07f..6509809dd5d8 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -40,7 +40,7 @@ enum kasan_arg_stacktrace {
 
 static enum kasan_arg kasan_arg __ro_after_init;
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
-static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
+static enum kasan_arg_stacktrace kasan_arg_stacktrace __initdata;
 
 /* Whether KASAN is enabled at all. */
 DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
@@ -116,7 +116,10 @@ static inline const char *kasan_mode_info(void)
 		return "sync";
 }
 
-/* kasan_init_hw_tags_cpu() is called for each CPU. */
+/*
+ * kasan_init_hw_tags_cpu() is called for each CPU.
+ * Not marked as __init as a CPU can be hot-plugged after boot.
+ */
 void kasan_init_hw_tags_cpu(void)
 {
 	/*
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b6bb02445ebf2f6dc33e85a76c4091040b0afbd4.1640036051.git.andreyknvl%40google.com.
