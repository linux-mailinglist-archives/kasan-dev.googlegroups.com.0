Return-Path: <kasan-dev+bncBAABBC64Q6UAMGQEZAXO7PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id C2BD279F004
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 19:14:52 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-502d969ac46sf22540e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:14:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694625292; cv=pass;
        d=google.com; s=arc-20160816;
        b=X2U8lISeyeHmZdQJgvb1CuWmIHq6fV3LqTQI3vp6JZS2qcFl/3nZXKzLHVzE5wlti2
         mU4ImAK7eiAgLQKKy5F+xIgNfbhtLA3WsBQVtnwz7aIGoETQg6SUs4j/kEDrTsbSaPwf
         9fEWptxXzR7bdHy5A+gqDwn0EOzPl+zTNyIy7Wj6tIhOkxGUIPPAgqZn2n9Q7ImJV5Hs
         O8I89pK9rl0tiCwC1mbM35hzxRvVmWCW+3YAXApdNjkUCxSe/L+eJyi69PLGiOvCKj71
         CEPxKGv3WBLFIhQOnqoj4ongiicICZPwEr2o6jazvCRzJICSnCNAPvXKfld/5rM79lJ+
         Tgpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=MRMe4IjVK6egtdB/w5erea7Emu9jpVvf/GUgJZ/PKo0=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=M19TS8vd6PdccPbt36gjjtrWcakPGl+d7IohFhJQ1Rf4tbRWiq4/SMaolewTRe1b6s
         FSZwxpWbW17tbnGbyMwGmyKiVh6ete2XY3EahaNDSqAliA6QNWEiQ9fNAcr510ka1/iO
         js2b+B0BfB8HJZ2mifLY+j+1vJvGJJ7RuPexJJpvck71AYrjQ9h8Ohhp5Lw250pACxxa
         hETpfQy0WAlq51LE+jw9PEHjasWXmTasLyhQzdW5NltPEiLKmOdFO2cuzvenZ4DlvqCJ
         vWm3WkuGEn82gy4KC4823cA01pDu7wTeZBUUbWlfsIui3czsCbrkw0QSuygXMd1Sh98x
         FL3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pRcWYiA4;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.230 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694625292; x=1695230092; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MRMe4IjVK6egtdB/w5erea7Emu9jpVvf/GUgJZ/PKo0=;
        b=MAcDvSczhk5LMsdpiKZZqDw6aSABKJ7JvjMa+iUNSqZP2D3soYvEpCWME/LEIEm689
         Ln/ADFhZHPCfvzGjhKqscKfYHujeHkkO2aQE0zeZFfiCE/9QutMUqAHWv5M9xNs/cdh5
         0EJ3nmNSiP0RatFQ9hSMLDCW7Ykp9BCJoGJEoyobmExPbzpVSnK+Nd5MWzGuHulQVPoR
         FAVGYBRsdXZZOoWguUC0FLJRartmc2OFKx1+X7ttWR04IeIL1JzbyWeor2ezacNIp0X4
         15p94OGUErarvMSt4cA5Sg1u6FOxXmh91bOKpDrv5s5sVsP9KrIrOiAVySTJYqFYtzpA
         cYtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694625292; x=1695230092;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MRMe4IjVK6egtdB/w5erea7Emu9jpVvf/GUgJZ/PKo0=;
        b=FDUfEWLiGFkwwwNY3d+fFJ41vTtZnpG0BT2O3lt+REXSnsE1ebQpo8pPlFnzP6+Igq
         KdaBmMj1bju9wLNr7pD4OxEzVIM+jMUXs8AW9n7gDLXWjqm0lKorZRtwnzWw4ff5nr84
         KspZOIVuewodLbOg24pHhuSH78ePjJ8pUoT20yvLkOx1GvXlhDhtbYRdUuqRAYn3xcXG
         T33RnMvycwN1VhJK2zQoo5pmkueGylNFUQSKI9nVESqvEkqXqEPsjBxepbQDjfZnJhDi
         eNgQm60z0DyZl/vHuK2HQuZJX28RVPw/4oyVaBFXu83RjWMk7/gy4S5pXzYBonMunu8B
         6b/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzXmGKaoTF1ivVYOryYoVxIowq9U/kynKVruHwrdjcqSvk4W0xd
	IkXK/d482E3MkBO49yGHTZQ=
X-Google-Smtp-Source: AGHT+IFrYptjvz66cIgTwVTLhWbncPmuVml6HUZ1jubd7QOSo57JqT9bkhD5BtM9HZOug4iD4aFhuQ==
X-Received: by 2002:ac2:4c55:0:b0:4fe:e50:422d with SMTP id o21-20020ac24c55000000b004fe0e50422dmr3494442lfk.25.1694625291287;
        Wed, 13 Sep 2023 10:14:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:505b:0:b0:500:7f17:b77d with SMTP id a27-20020ac2505b000000b005007f17b77dls1653039lfm.2.-pod-prod-01-eu;
 Wed, 13 Sep 2023 10:14:49 -0700 (PDT)
X-Received: by 2002:a19:435d:0:b0:4fb:8948:2b28 with SMTP id m29-20020a19435d000000b004fb89482b28mr2299944lfj.63.1694625289841;
        Wed, 13 Sep 2023 10:14:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694625289; cv=none;
        d=google.com; s=arc-20160816;
        b=LEDVma5VhiAhZrLQeu9Ftc4R85mQlsIal0wyvAKwZQMzxj/o66v1p7/PIyXvo5E8o0
         v7Lrhornimguo/X3uu2XVXsriX5qlhiWfOjfLm1ZQdJC1RPc7Dkkwevl6Ydez3QEtSfE
         RjsZeNPrVnktyXzyDjrtJaDmM2Orh0HuFX0XnZ+ppa2b08Xxg1fLdQwmzkwbs5Mvy66M
         ar7D6yu42bdO+8LuA/cpP9GDKVA0KynaREr/mZ8fUhPdbd5v6GVlviITwr3o9uBmUP4U
         zIi3baCQ4sGUwcqskiBCuVH0zwUMxv4PBB1/tKb6MayolfgsnID+GZcdP9PCzYnfW7lc
         0yzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hlykGlfL2an/VgWBLR95t+wE6CpOLlFaVT0cHbSVLN0=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=m1hZwdSR0RUS/Cng7vuDPrw8GqmO2NSrqQuissr0MGreJdU56MDqJBZZxNbgQy5F97
         6BIeLkp8lwCCIo2kZdVqlLEooS52BN/cRzHjrwADpRg4G28FHqxfH4Hx0zFUxs2axB9L
         DNQQS9Yw8Fsk0/0klDWPtHYLXj5X+yDtYmIUH3vuwR5+KHqpQdPy4XmS4vmVeFLuFxgk
         PUehkpXyka/9CONgxTyLTos6zTITBstmychKfZ7G04Yt7SMVLvE8Y8nq5PEScpEaz1fh
         ntJyjtLcqeBqWI6aQ+mJlA5So8o1FmC3/e/dpw39wo9/q7LhQ1ENPG5G8TXO/Ax2e4Fa
         y5/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pRcWYiA4;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.230 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-230.mta0.migadu.com (out-230.mta0.migadu.com. [91.218.175.230])
        by gmr-mx.google.com with ESMTPS id t32-20020a056402242000b0052e7b1828cfsi960678eda.5.2023.09.13.10.14.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Sep 2023 10:14:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.230 as permitted sender) client-ip=91.218.175.230;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 02/19] lib/stackdepot: simplify __stack_depot_save
Date: Wed, 13 Sep 2023 19:14:27 +0200
Message-Id: <3336cf19b8e53ed5449550a085cff9bddec4c873.1694625260.git.andreyknvl@google.com>
In-Reply-To: <cover.1694625260.git.andreyknvl@google.com>
References: <cover.1694625260.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=pRcWYiA4;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.230
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

The retval local variable in __stack_depot_save has the union type
handle_parts, but the function never uses anything but the union's
handle field.

Define retval simply as depot_stack_handle_t to simplify the code.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 9 ++++-----
 1 file changed, 4 insertions(+), 5 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 3a945c7206f3..0772125efe8a 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -360,7 +360,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 					gfp_t alloc_flags, bool can_alloc)
 {
 	struct stack_record *found = NULL, **bucket;
-	union handle_parts retval = { .handle = 0 };
+	depot_stack_handle_t handle = 0;
 	struct page *page = NULL;
 	void *prealloc = NULL;
 	unsigned long flags;
@@ -377,7 +377,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	nr_entries = filter_irq_stacks(entries, nr_entries);
 
 	if (unlikely(nr_entries == 0) || stack_depot_disabled)
-		goto fast_exit;
+		return 0;
 
 	hash = hash_stack(entries, nr_entries);
 	bucket = &stack_table[hash & stack_hash_mask];
@@ -443,9 +443,8 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		free_pages((unsigned long)prealloc, DEPOT_POOL_ORDER);
 	}
 	if (found)
-		retval.handle = found->handle.handle;
-fast_exit:
-	return retval.handle;
+		handle = found->handle.handle;
+	return handle;
 }
 EXPORT_SYMBOL_GPL(__stack_depot_save);
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3336cf19b8e53ed5449550a085cff9bddec4c873.1694625260.git.andreyknvl%40google.com.
