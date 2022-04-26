Return-Path: <kasan-dev+bncBCCMH5WKTMGRBAODUCJQMGQE3PYPHRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E2C65103EB
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:44:50 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id v29-20020adfa1dd000000b0020ad932b7c0sf2067704wrv.0
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:44:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991490; cv=pass;
        d=google.com; s=arc-20160816;
        b=QdIWd8fvXUU8uR1sqORP79ockiomaHvY8z53jtJ1G7GGm4u/1lb+y2L+RWJdTkUb8h
         yP8R1oMkjZFmZMoSe6KwmaJagnsXMgnQIfbb54Ibu/Q9gawJrPDvHk9ecwFaD9SgX6i2
         d6V8JkKA23eLD7BdS1N4YPhEhohvBlF+ZtopBul8D6gKf7wDGFJ9cMtCWgMrIFPfUtAR
         JAumxhzq0dqKyGVgu51PsRNl+YrWg18P9mXtbw60kpCpPysqvM6g6UOEeJd0k08oc3fL
         hZFu7JKf/jRJEA23KxwCk/0+ttEghA4OM+Go45lUJesR/SfnNNLsjBp0bGtspkV2o53w
         2qjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=cMdyGmGjgNXpbI6FOwi+NLsedgIG8KpkGgRdqkWtUYY=;
        b=axF9BUe3Y+lNhfu3XBXjQ+Qh0IGRdKYRrwbj42GF716Hdnj14z4Glx0hf/fc/VvcaP
         3xefxob1ucRW/tl8erklNf6LGe8g6pY69Dpn5DutHQy+8k4obhd3PxwGSHQOGe+Aobxl
         +ICYh9/zuMW3IbqzDtY3XBIdR3IRcSofb5+ZF1rJt1uT1rXm5KPilcj3wgPDARmNXLBF
         G8kqzY9SAqqLDrLv9CymrFViGv3k9jvLMyuPIjhEpzB7or6GucXIhUYa2mqTxrLyDJyT
         RMmJnC7yMZwKOyZY6lruyLFkfjFTb9w8jglUKjKK7+vN0vHBFBOAqoKRveglbwQBcdVh
         Bt/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=V1UPpoK1;
       spf=pass (google.com: domain of 3gcfoygykcx0hmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3gCFoYgYKCX0hmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cMdyGmGjgNXpbI6FOwi+NLsedgIG8KpkGgRdqkWtUYY=;
        b=pLTUQC3vHUh2a/ImmpKIwx0NlRqbl6GIT5iTqX1BQIGiD5tvvWHcqBPgRbcFv/Xqf1
         G0l0QrLKSVvsQQ5G5syyhOieNr1c4RwelI1u6ZTu1V6orjOnUHJD/gFV8CR0N005svI5
         1z0/b5iYxj8kssHI8BEVK1bv6Q+KwIH2+68yb2IyQhfU3iwaog+xLrgvemxkCc/qid3l
         3G+nQmyjVh29vFxP2C/vwK8LRHlXwVpN98Zs634Ay2V8d0aELGBHIMKuVs5ZRWLSHw0X
         GEhrQZoWyFSm+tgfvd6kvUFr9O0mZHdK42AXav430unQl5XEv+2IYgqXleKUYwP/3Q47
         aYwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cMdyGmGjgNXpbI6FOwi+NLsedgIG8KpkGgRdqkWtUYY=;
        b=wV1u9RBQtj55wmvsnEkfDXOLY2vgbzakmRSnQKtZmWobAKN4nYYEGulf5Zoq6ufkb+
         IxObEO4MoiPy0uKnkEkIRNx5eEoENZLT2Azqw0kYr21IfpM2DPQcCq9eSKMCr+nwmMc8
         U/9Du+CTz08lITEsbTibnqM3BdqOkPWHIgkZGKwXHpdyW9XUwZ6+VhZLDdW/3ezNFJkt
         QejWgJtthLmBdryg0CB5O6/5Zgr0ch0T/iKSifurUVUBlwonVJolgkhI4S+NbAwKjTeG
         JQrV4aGFFn9h1I4OAOQwl/Bg/hr54dbEB2nyCSWh8sGDZ6xBJege5f9S/Rczvu+kQgyc
         99+g==
X-Gm-Message-State: AOAM533Q+8/nQFtXEWP/KHf2Ny9vBGG3AQq0CoYm0Zjg1/7YU5qGTYj1
	yzjgPrKe92tVhmoz35DlLsU=
X-Google-Smtp-Source: ABdhPJz+b7JiQp3KvtpLxsnJuoVBQ8yI9fE8wYGAxm6rEHcrccoH3612iyDO/KlLaIym3yHfh0W4qg==
X-Received: by 2002:a7b:c382:0:b0:388:2e76:49ed with SMTP id s2-20020a7bc382000000b003882e7649edmr22350403wmj.195.1650991489966;
        Tue, 26 Apr 2022 09:44:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3590:b0:393:e880:6531 with SMTP id
 p16-20020a05600c359000b00393e8806531ls3797904wmq.1.canary-gmail; Tue, 26 Apr
 2022 09:44:49 -0700 (PDT)
X-Received: by 2002:a1c:a185:0:b0:392:206d:209d with SMTP id k127-20020a1ca185000000b00392206d209dmr21562780wme.168.1650991489132;
        Tue, 26 Apr 2022 09:44:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991489; cv=none;
        d=google.com; s=arc-20160816;
        b=weLfIsuPODhFR4Dy0gajNJrfcNoodKb2tnTLYdTC7Pr1NKDXxuJ0xu7FSitJyCEVr+
         ybKvxnAXfEtV0KR19djuSqVDyS+heOvdpY/EMqt6c68MD5nHvwSNxMTxQIQGzaNkahbv
         xNRWRqzlcRdvQndSq8XTj0InFK6HJiCYhu+yF2MpoSQ0R0iWY9OspkGDQQvHG3bitl5W
         g4qHigaJLrd4nr8iBqc0qaq9V3MelJz55d1QBuY9f3sRdM5qThmsltzqN03vU+CzUpT/
         rFOACSPrlqgh6Vhj9RnXTEYHcgp6Ue6rRohJ046HvXNMn0CTNe/Bp9aQzalnMN23Ext4
         h8Ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=SEm8RFoD3mzqXjcHWM9Z/XfNnVTnRxEBaTJIwFUC6FI=;
        b=TWnHGhnmVooTxnxlxx2zmDwbOMdls9gzF76O2nAIqObGYXcVUUSoejwzQXHIx5Eg+n
         PZUz3CTTaLFaeqc0HuwH/CMunw/eru5Y4f/xNUKMFv76vGMuIPvGxSt8BMJu3vJWe/LB
         pGzu83dqk0FW+mMaF+kJ50AAg94vSpF+40jyXMSAZonPSNf90ZeqvU0p/6JiKnPi8doR
         /Qq8mROKsJwDIKPGokQQycxw4tBmACSQk1Re2xobDn6l1C7ggAKMLSps2BkuR+w5rDpH
         PhX1n2ybIarTBIsqg2wJv1t6kFTXVbDCRLZnvPgsb1pr9VHSeiRtTL5sfYY7kv7u5lk7
         +EDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=V1UPpoK1;
       spf=pass (google.com: domain of 3gcfoygykcx0hmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3gCFoYgYKCX0hmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id d23-20020a1c7317000000b0038ebc691b17si214962wmb.2.2022.04.26.09.44.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:44:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3gcfoygykcx0hmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id nb10-20020a1709071c8a00b006e8f89863ceso9376441ejc.18
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:44:49 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a05:6402:35d2:b0:424:1eb0:45c2 with SMTP id
 z18-20020a05640235d200b004241eb045c2mr25704880edc.152.1650991488637; Tue, 26
 Apr 2022 09:44:48 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:40 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-12-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 11/46] libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=V1UPpoK1;       spf=pass
 (google.com: domain of 3gcfoygykcx0hmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3gCFoYgYKCX0hmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com;
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

Signed-off-by: Alexander Potapenko <glider@google.com>
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
index c31e184bfa45e..d51a3cd6581b1 100644
--- a/drivers/nvdimm/pfn_devs.c
+++ b/drivers/nvdimm/pfn_devs.c
@@ -784,7 +784,7 @@ static int nd_pfn_init(struct nd_pfn *nd_pfn)
 		 * when populating the vmemmap. This *should* be equal to
 		 * PMD_SIZE for most architectures.
 		 *
-		 * Also make sure size of struct page is less than 64. We
+		 * Also make sure size of struct page is less than 128. We
 		 * want to make sure we use large enough size here so that
 		 * we don't have a dynamic reserve space depending on
 		 * struct page size. But we also want to make sure we notice
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-12-glider%40google.com.
