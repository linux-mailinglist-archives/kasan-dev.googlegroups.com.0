Return-Path: <kasan-dev+bncBCCMH5WKTMGRBNWV26MAMGQEU63ALPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id BAAB95AD257
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:25:26 +0200 (CEST)
Received: by mail-ej1-x640.google.com with SMTP id nb19-20020a1709071c9300b0074151953770sf2296993ejc.21
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:25:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380726; cv=pass;
        d=google.com; s=arc-20160816;
        b=zmkBLoIBbwzyRVhavEzfTcS0DBti0GtyOAq841z3kPwB3wCC2TcqxNEVFGXu5wYFPd
         VxyEbzDS3DzRpDkP+M7Okxk5dDfQFfn7yyxZ2xkyLMQ23dQvg6PWBMTe/DbEsJL+I8LG
         z01UpwASsKUuMwwm+7vaVOfsR0DS9Q/hmcTBUa8ViWkzH+MG5rmMRk1d6mWuoXAG/G3l
         7ZupCEBnOsqgVmhaHS9rh8v0VXo5foqBGaUWFzSQGm3EXHtyUorjrYqR6tCHB8SDV7n2
         7A3YiSkmVOu66oaIgqcisF+XNGewaqh88wWzpgdDup+iMZtSeFKyHkwx/MZisUTewTrK
         2LhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=HETPvLeGs8YvH/UdT/wnW33R/wNt1rV+fkmX+0rP5nk=;
        b=Elw58s5fw6em+Q8OSiheS2rjhlsxHAIegGorzxB7SAOW6ousSMaIy/XvDoZMywUM0N
         NbCqRbnQLYhSIPJmO8IBXRYGR99M4PkQsfxge5k7Yd45oMnhFeUO1b61GaWZwwwvoVMF
         /Q5MJ0hRoG9maobvYq+wkOWSR9b6S0wSgPg5DxakRIsqKJ53XgFnJx/gLXIjfs48zPXl
         YUfAYAVv4yeIov8LBTT7U98hGMM0RdMcEgz/8zIbuomyDJ0m2+CP3Ct0iMnIqE+V6D8a
         y+lV3BDLH5g48GIXTxlbZDWXnYKPJoGYUBcNF/3XXBKFoRc2imaQlmdEQRcwBcLazUiM
         9liw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="O96bjuI/";
       spf=pass (google.com: domain of 3teovywykcqiinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3teoVYwYKCQIinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=HETPvLeGs8YvH/UdT/wnW33R/wNt1rV+fkmX+0rP5nk=;
        b=bdzxWylLuydC6i7KG655xJTOkrCn3hIjbgSwv5WMBeiUjuiIAGyCpReyIxyQ9cv52d
         o+MMDdHyP0tQCPA3PZ16ckr/22O/K+GTSqF0kQ7gPW/0GRMAsHbseVQru5IuqiXlhmnT
         mgurar6E1Cgnole/I24iA6mw4ikNMdABku0rrXooVonSAzFcqk1LB1DLuEycZ1jQpool
         KA3I4/tHBx1sCvkGq/OlUZVHMGAWUNVM8dQ2oYfhmr/i0D0uVOltFLkI6XZPtuOS8KJR
         2H3wMluappBv9zTSk/BZL3irWa795nkmgas/BXvpJSuLpPMd0qofikC6G4c6Nxj6uCQ2
         H+2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=HETPvLeGs8YvH/UdT/wnW33R/wNt1rV+fkmX+0rP5nk=;
        b=UpbMb5ieGPHIbm/inX+x1iiZg3zXoGo9+wBD9J36nAonv7D2jOFpd067XbcYcG8ZWt
         1Rq+NR+dXdInQ2cDYOC03+QgEt4pqQdaVNtAbBy8FvPmoljH41AO2kSgpZT1YYXbauKn
         6UGEnr+OZ1XppgtfDjRiReUWodYEQueyg/hRl1e59oiTnZrv9LGyLhe8YcK0PAso57td
         uatbZcSqkwXUb17ovVfOXBc68rhliDqjVbeXDhc0+kNbnBe7ocdBpNFZ1Yqv3UCpPn6e
         KJzk6OcZNsDTZKXbtub61YrVxj2wJrv/oRO+km7cC7bDPfwi9v4SuFj5UCZg37dB3cF7
         oVRg==
X-Gm-Message-State: ACgBeo0H7HnYzfcyOZMlI/3uZ0KqPdb8D7bOjLif5GLV5MbFsealo06T
	l8CZZ/j/yIvYYUzBRKYqSLM=
X-Google-Smtp-Source: AA6agR6KPblCrEUSQVViFl+7gZKsZMt5jhy9sXw98fwjmd5kCODOIK0xTJPQUl/mIU0iTihGAr0POQ==
X-Received: by 2002:a17:907:1c01:b0:6f4:2692:e23 with SMTP id nc1-20020a1709071c0100b006f426920e23mr35369864ejc.243.1662380726442;
        Mon, 05 Sep 2022 05:25:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:14db:b0:730:6969:95e6 with SMTP id
 y27-20020a17090614db00b00730696995e6ls3415614ejc.7.-pod-prod-gmail; Mon, 05
 Sep 2022 05:25:25 -0700 (PDT)
X-Received: by 2002:a17:907:1690:b0:731:56b6:fded with SMTP id hc16-20020a170907169000b0073156b6fdedmr36104036ejc.119.1662380725407;
        Mon, 05 Sep 2022 05:25:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380725; cv=none;
        d=google.com; s=arc-20160816;
        b=fXoCzRiqgpGloqMrIPCp+79Wr/5EqV9dxgcCGk3TGN3S2is+smkgHGA8CeBHpS5zGE
         Ect95msapcI7GCbepO3qhdMEGvWu2eDwYeUVgZKDVceFJ7rt7nuFkgUnwdrDGH77cfrE
         z6HsE63KeX6LtuC2HIQSj2L8V5jqJvZnOueXT5NW7CAEUCWBxmbGYN431Arc74kAImdC
         1N4n2pmrEJDPBaKq/Vc50ERHYY0phishdM4aIMIFY8GiCpaQP8N+G6tcLWqaHFqRNCb3
         sdYjYRt+NgU8jkmNtebV+dCj4+T0T/wKGv+bfznzFdGskJkObM5zS8UPu2r+vRKGBVR6
         3Irw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=vmKBMF2McNFVJqtG6TmpI3MAJxV0RMGeKyj0ZsE0Fyg=;
        b=OBZxE74ginaipQU4Y+w/ZFvUvnfttMZpKW65qSMqzjMyWTkq2CdUrD/snvloi8mlMF
         9OTSUDogzaDQv5xvXcz9BG2JgZyW1uumf/0XQUss4SMPp5bIe/WQpoBMrDi/iSk7c0C5
         By0zo/j+pzk/v05onJNJgLopm1p9tWeGXdWdF7AIky7CDibKAH7ZcY0TsJYYiuS81uMj
         EHjAzBbQlUIFfFmq/XpzLjOrD5VKHkiEjvM3k1sb4cxBD/xljzpDLmFdVGrIDhqeQbJv
         9X0+aNXZVI2iBt9FOdXoWDtyIQ06YC/KlKLsOW33pMhh8Q5N9pS6ZGJQrVgUsCtfW14o
         3yxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="O96bjuI/";
       spf=pass (google.com: domain of 3teovywykcqiinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3teoVYwYKCQIinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id v14-20020aa7d64e000000b0044e9a9c3a73si70247edr.3.2022.09.05.05.25.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:25:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3teovywykcqiinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id v1-20020a056402348100b00448acc79177so5806468edc.23
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:25:25 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a17:907:b13:b0:73f:d86a:6e3c with SMTP id
 h19-20020a1709070b1300b0073fd86a6e3cmr31127618ejl.132.1662380725053; Mon, 05
 Sep 2022 05:25:25 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:18 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-11-glider@google.com>
Subject: [PATCH v6 10/44] libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="O96bjuI/";       spf=pass
 (google.com: domain of 3teovywykcqiinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3teoVYwYKCQIinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

KMSAN adds extra metadata fields to struct page, so it does not fit into
64 bytes anymore.

This change leads to increased memory consumption of the nvdimm driver,
regardless of whether the kernel is built with KMSAN or not.

Signed-off-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Link: https://linux-review.googlesource.com/id/I353796acc6a850bfd7bb342aa1b63e616fc614f1
---
 drivers/nvdimm/nd.h       | 2 +-
 drivers/nvdimm/pfn_devs.c | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/drivers/nvdimm/nd.h b/drivers/nvdimm/nd.h
index ec5219680092d..85ca5b4da3cf3 100644
--- a/drivers/nvdimm/nd.h
+++ b/drivers/nvdimm/nd.h
@@ -652,7 +652,7 @@ void devm_namespace_disable(struct device *dev,
 		struct nd_namespace_common *ndns);
 #if IS_ENABLED(CONFIG_ND_CLAIM)
 /* max struct page size independent of kernel config */
-#define MAX_STRUCT_PAGE_SIZE 64
+#define MAX_STRUCT_PAGE_SIZE 128
 int nvdimm_setup_pfn(struct nd_pfn *nd_pfn, struct dev_pagemap *pgmap);
 #else
 static inline int nvdimm_setup_pfn(struct nd_pfn *nd_pfn,
diff --git a/drivers/nvdimm/pfn_devs.c b/drivers/nvdimm/pfn_devs.c
index 0e92ab4b32833..61af072ac98f9 100644
--- a/drivers/nvdimm/pfn_devs.c
+++ b/drivers/nvdimm/pfn_devs.c
@@ -787,7 +787,7 @@ static int nd_pfn_init(struct nd_pfn *nd_pfn)
 		 * when populating the vmemmap. This *should* be equal to
 		 * PMD_SIZE for most architectures.
 		 *
-		 * Also make sure size of struct page is less than 64. We
+		 * Also make sure size of struct page is less than 128. We
 		 * want to make sure we use large enough size here so that
 		 * we don't have a dynamic reserve space depending on
 		 * struct page size. But we also want to make sure we notice
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-11-glider%40google.com.
