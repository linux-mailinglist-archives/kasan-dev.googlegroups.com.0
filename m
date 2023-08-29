Return-Path: <kasan-dev+bncBAABBSONXCTQMGQE44DCCLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id E881678CA52
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 19:11:38 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-52bdadd5497sf213966a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 10:11:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693329098; cv=pass;
        d=google.com; s=arc-20160816;
        b=e3StGMDT1O6cRDLZH+RdO3mrJgSmSqJuLAA0mNGS4qDVLqd1ARyvAKg6hOOzUnYxrq
         UyzWYk9GcaN9MKwzjl3o5vVl9BV+tYimal2Ufn73CjIqBp6eoke+FK9b1HuTCIFFQm13
         Tkm2otNQOAPmLnInU8MZrd/Jj7zi8+6cczEfnttzgAgCWJ0h9+z8Q8/o6jEee4BrDSSZ
         M1TySinZisIk1aLDL7KUWAl5AmYWG1VcPmojMkcZiWOFwvERt68PoiLiVSXgWhAoy3rd
         Xn7JZd5THMtrg4st2cgSjD1F6G6bCYooxy0+A8ASiorxRCbIABQJtuLsBw39ZJkfI0DG
         /ISw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tJl3+0GecPT2cGwfSL7BCgukkVKDYBhVJvaMp8lBtIw=;
        fh=ZTTSst3850TI+4y2eqKpcuCmJhEtn1qZX9lpGyHR9Jg=;
        b=KXd5G2tHX9voKrAGlN8a+LHvKxwxVNQQXDx6MEplor4M1WNL37bjZyR+MhPsB8kJ++
         bZ7f/RqbMH8K3n4ILD5qEc8Plll4gflVh2rkDpkugPbzpkz02Ueu6EsNAAVs0slg6h3N
         /W1Ph7SJpl+U/SMqXr5j6rURnlROFzcfSr3tSSE6kKBmwKnTG5bJ8DY+PCjv+hw/1Zma
         OaACYTAz8pmiLReZdjxzRgf2QegcjyPRHJZfV1+pV5RHTmQ2dtbUH2IquhZi04QiPG6P
         Nw+QMq+NOk8PU7ylRuaM1jxPZrn4vL7rz22qRrI1+YWJSC9t1kCx5MGUvtuj+sOvx23f
         EexA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=FMOUlvJx;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::fd as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1693329098; x=1693933898;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tJl3+0GecPT2cGwfSL7BCgukkVKDYBhVJvaMp8lBtIw=;
        b=nblvb51xIXTGqH1IOwXlnomBmFgGou4YahYA1rNdCgMNtqRIgRTSU55+W3DVkmeLq/
         bUeghOh7FAgX1pWhj5cch6QNgOSHNhnf5EOw0301BTLHrgEaMhnQqvXIUVNSIBcUzSsY
         f8gSnE6K7W9ZzoiXttu+WYi7SO0Fpp8nKOtWBB9ULnR4+Trne8NTR5ZE3YGJyvpMDP8e
         iMeuW/8MER3ZpdUV4oTZ4fvE7RUeQz8pUuc6+x2zIKxINPBZywRHrDOpMDqz/wJ18TD7
         f8yrWngWe9gLjOtQsgJ+pJAHjodWHFoOj9Q/6vINQUrTbm2kH7qBH0zSaUOavr4ehME+
         aj8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693329098; x=1693933898;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tJl3+0GecPT2cGwfSL7BCgukkVKDYBhVJvaMp8lBtIw=;
        b=WK6wbsRcSYxwa7PP2FuaUsiPHTu+WPIJSANI9WfubKtjRIuiLkEuw+xgKnLYS+uywj
         wqsmjlkUUJ/bUjNLtWnXDLNsiv2kq0f3cIK49P435+jwVaALi5r2Pm1Esk0ydSPXNcal
         zxH/rYv0YKFnvxO58jz64xcJuTuDl5/I4J4ZqResuqFh2uOUPLnHofFF2RQMOxRDrwFp
         moKQT2OshO4a+MO/YkqB4qhqqc4JhQItHiqM+zGxzgZdMvT8LSkih7b33arPLvZk0VfW
         PHGWs0cHOUjxILDrLj1HXbofDK/3pMPpAMM9sqbn4eUJe45VQ8iPKP9YoTQvdxGzTzgw
         Xw9w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzhWiQ61VGwjaM6qGDjBqzvFdmZZpWiTwtin+qNvO9pkaKuNVqN
	HbckafFQuO24dH33hnPjjCQ=
X-Google-Smtp-Source: AGHT+IEALCBa1nskadLeaZsN6KSJ7r42xFJKFRG0shDpCzYNPda248OIjEO/qt/m71B+py6Rjpn0rg==
X-Received: by 2002:aa7:dad5:0:b0:522:564d:6de with SMTP id x21-20020aa7dad5000000b00522564d06demr25754361eds.36.1693329098073;
        Tue, 29 Aug 2023 10:11:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c509:0:b0:525:455e:f9d1 with SMTP id o9-20020aa7c509000000b00525455ef9d1ls380097edq.1.-pod-prod-01-eu;
 Tue, 29 Aug 2023 10:11:36 -0700 (PDT)
X-Received: by 2002:a05:6402:14d:b0:522:20a0:7eb8 with SMTP id s13-20020a056402014d00b0052220a07eb8mr23136708edu.33.1693329096643;
        Tue, 29 Aug 2023 10:11:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693329096; cv=none;
        d=google.com; s=arc-20160816;
        b=NgYKUHA7L74Y7l1FKQpYHtrWGesOG7pJMQKhy6X40TDAqv8MKUFJGywIZZic02IiwJ
         H7vv4DD5zp2DuuelEsUJATkn6en8t85RuYiREl8t9leoC78Cx4hkZXFHO3RseJJdgO1v
         Bl+iKKEQ0ALEEEeJOJLXJa+HfvhoIsFzIPMv5kcDS3ZhyVhq5XhYQtaJXDtp2MFu6sON
         udSiS3Ts57rbIlv9KCEVAr7xtHmwYQA2CwanUB1LjraYonqPqBeK51W2lOZpk/4Kub4J
         UhiIofRzNi/ucQasFNWUDLrts8zowYRSASZAhAuV8LkQ114/ksiksVHXyrc2TRu7lGuj
         mlNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Opt9t2Sh3BPQLxjav3raWw4j3L9ASrpPJpFprr4WIwg=;
        fh=J1Qt2dYQZwHfoASHEf8Q1j6KnDtpzzpCUlDsDM7WT0M=;
        b=Pru2GkkcHhTTQWxK5S89hfQTy/1v31dkZfOxkqQRNZEnPGMqXFp17r9pQJNJsxj3Kx
         PIqGS0kQi/qr0XEVgXDyAf5fS4oW5g9w0dl1qoSZp5pVjyzjdwHoKRjxdNGWo9Nty0bh
         8mAIRab780dPm6VG6W9/IpIqTSodPSpH2/gfQknbPUu5DuynfFM/zcDG9bgKZzSintvt
         R5cF7XRscClE2VwQYiWIrpBVdHmcHVeRG1DCPahhDRTADvtegQfBSyozM++hJjIdRyux
         oNqgIqueYkNYiJmnGEZuXOwBGztglHiM25Kfa1z9PooPsEWZjVdkNRgtnVM9yuURHjLA
         K+Xg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=FMOUlvJx;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::fd as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-253.mta1.migadu.com (out-253.mta1.migadu.com. [2001:41d0:203:375::fd])
        by gmr-mx.google.com with ESMTPS id d28-20020a056402401c00b00523bb65dd1fsi1072255eda.0.2023.08.29.10.11.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Aug 2023 10:11:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::fd as permitted sender) client-ip=2001:41d0:203:375::fd;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 02/15] stackdepot: simplify __stack_depot_save
Date: Tue, 29 Aug 2023 19:11:12 +0200
Message-Id: <20dbc3376fccf2e7824482f56a75d6670bccd8ff.1693328501.git.andreyknvl@google.com>
In-Reply-To: <cover.1693328501.git.andreyknvl@google.com>
References: <cover.1693328501.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=FMOUlvJx;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::fd as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20dbc3376fccf2e7824482f56a75d6670bccd8ff.1693328501.git.andreyknvl%40google.com.
