Return-Path: <kasan-dev+bncBAABBSWOXCTQMGQESV2D7OQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id D313678CA72
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 19:13:46 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-401be705672sf25765845e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 10:13:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693329226; cv=pass;
        d=google.com; s=arc-20160816;
        b=HSCg3+S6b6QDHj0rOG4MR5vO/TfjM9gnT9g9QZvoOLn5tt4GoeSB6sX+drOAeVoQAc
         c7qY6HoMx3SCPJEwsvXssl2chHM/cdL3grLkN9L4X1PtJTDeL2bY3NIEbOzaX/Zxv/dL
         Q5snFm8djF/3ziDihjXjbEV2FK0s3MyWLG6TgKrRkBiBoLIYaGCzXZ/jE2eNqcHRXNAu
         SxbnrTlLt+AXBEE/lNGrR86hCUFx5ipHyZXLh7wsvsGHM5Mqwck8VHn6w7mKMbKSrku/
         VmOhhmJtzqKJmwYY9FmdjKbSKW5CgPy26g3zjrwxDQ4tZLcb/9mf6NRVmaRu1OIkLSxw
         SNEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=aNUPq6kc7NnoQmot82gLlcQGm5Jzb6QXuKwXbOdQyPE=;
        fh=ZTTSst3850TI+4y2eqKpcuCmJhEtn1qZX9lpGyHR9Jg=;
        b=JoGMi8w72h7FfQ5vLGw3+E/8neePsfCkOWPVocNUuGdcz2DCVVpcJMxjcxPI0erk+d
         KrZP9IChco+spbKAPeAa08iYHjN/ia9ih8u7QPQxyMHPgXrr50P4Ur3PTa/sTIh35ySP
         vN8+e45yaR5j+tV6yf2dTZeQ+ZUVdAGlrwnsUgG2+tITbJzc1zL7coAB36eX72MKHpAZ
         JL5qP81q0KkbLffc8YrQzx5MXEkV9M4QIBb+nm+tStTiMFMy0ByxW8d9LeQekqcGSi4S
         br0qrJwhHmPoF3m1LBbr6Q1MTwOLkEi78Mz9bWS0B50sX+r82xqViPepFjVdhUynij58
         slQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=T1iG7qQW;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.249 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1693329226; x=1693934026;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=aNUPq6kc7NnoQmot82gLlcQGm5Jzb6QXuKwXbOdQyPE=;
        b=e66kXI9sOYqnkMNs0vIWqVHuyLezGNL4P58tO24I4Pxmh4oaFsp/ILYd6PtFHWxaKZ
         6boQI0cKXos3YdEVE/Bi/xww/fm5ie8htv1vu9VY8d1gr53TnU6SnvOIbODAYBgJp5jo
         OXm+bCP2eJQO1yiUI9OpD1iYVHxWCfte65e1ECV31mx81fWlI5SK85a0300783jKCjMo
         85ZmRUON+5WtdJ8dz4eAXmkDfH7hUWhyd+1zrLSbyY3wgBgnrn9dE94HXm6nHSl3cdEq
         sjpqvHicvO5Y0055kFKefE+qU/33EYRmxhgHjJ6Yd7YB9QGegadK8dvIfmkbQC8lPB6v
         v1zQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693329226; x=1693934026;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=aNUPq6kc7NnoQmot82gLlcQGm5Jzb6QXuKwXbOdQyPE=;
        b=Goe+zf3Lat+83+RR9fRDfWROtTY43JOdUSq6iYsznHyX7KylrOP1+0ltsMxM1AyaWM
         q8ir8SeEtWE9MbekiRmQP62CS09e2i12gg3JOeij5mw/TLwLExO06LxRHqBthE3ULI4m
         ZEdUd1DJlE0z/ILFP7LkzX+EM4vmyHv/VwXG6CUXcBUCw1rYhStNiFtgsSI2wpl/FzX1
         H+r5mTi9EfzbZPlMFdz4ghRhCwd2luaW4B6mi/aVvC/7gv3eEHad4cy8HE37ltII4UrT
         mLSb+ochKcNvyLpe7EykfaewAEc9W7KVsdq8hwxoNATGNsELAWAZ78RWsEgnbN43N9KX
         NpBQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzNeldX4uFh8+R43DlvfWxqvuHdZXKco3L29pEwdUVisRCM/MCy
	Ehh1AqL2bMWMYhED6oWkGMxgsg==
X-Google-Smtp-Source: AGHT+IED+HRhHPCyoOlxNkBua+BX1W1psp8qFnit4tfOHftA+RiEwdwScZHV9GSswOmWTDBZq2njEw==
X-Received: by 2002:a05:600c:2993:b0:400:57d1:4900 with SMTP id r19-20020a05600c299300b0040057d14900mr13918334wmd.38.1693329226250;
        Tue, 29 Aug 2023 10:13:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c19:b0:3fe:f6c4:6bc7 with SMTP id
 j25-20020a05600c1c1900b003fef6c46bc7ls233686wms.0.-pod-prod-01-eu; Tue, 29
 Aug 2023 10:13:45 -0700 (PDT)
X-Received: by 2002:a7b:c408:0:b0:401:aa8f:7565 with SMTP id k8-20020a7bc408000000b00401aa8f7565mr10886140wmi.34.1693329224994;
        Tue, 29 Aug 2023 10:13:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693329224; cv=none;
        d=google.com; s=arc-20160816;
        b=V565CxxoCogkF3TTa0aw4PEgG/Xl0694195r/7G05mC7TGPtEeCnYOhO+hUVtYPNIf
         nxlOpahqtQdYzEB5MsBcNZGWfaDi5Yig0BjQtz+1X6T44MA4cBglRv4DVRmpPq7xUpJP
         8TSpE0g6LxOaW/VwYaLonx/TQzUjpgHoKZ1dbFcZPdny1V3Yupkss2MuAjK3EpZlqaE/
         306qr2/dZ8G83XiC1Iqh0KVVI3bBfQARgEf3j1GTYDJTUtwzYBGi2pfdV0sW5VbnY09y
         rtHWpHcPdObHcsmLg4DmP2H7qzQolOcSmstuIGDOv4ipOFFHyMfG42xzhhHP2oL76+le
         TvoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=c+OqyPrsOPGHg5XrLPNZBNE7kZ+J8BEkGBD6zb/JuYQ=;
        fh=J1Qt2dYQZwHfoASHEf8Q1j6KnDtpzzpCUlDsDM7WT0M=;
        b=RFi1O26VB6l9OWN27r7BvTpLNU2sdZ1wJhUzY3G0u28AkoCiPgBpkKcsH5IMmadOC9
         /DrYLGm4LGT0TSk4oK0CzK59QzB1YN4Q+ThQNCS2v4jFMBmqYklruWHae9cHVFSHu2n9
         cu5x3I0KRTa2xuoDAQt6bYqBsV0sn/9yek5oZ9kuEzXeRhi8EUDIj9l6YjKbWwzeQ0bv
         jedpoIkLlpILbw8xcdyTPMYz6AghhKn++DSx1PWtfIMrBq7j9Iz+coS4OVBZzIC2Cgq8
         xDc3OPhDfbazBwUAo8ZCpakpLLq4+Bl+lfFAitM9USAskv3b/HwxwCx9u5MhmxanmFOs
         OQBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=T1iG7qQW;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.249 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-249.mta1.migadu.com (out-249.mta1.migadu.com. [95.215.58.249])
        by gmr-mx.google.com with ESMTPS id ay11-20020a05600c1e0b00b003fed6917d56si1277515wmb.0.2023.08.29.10.13.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Aug 2023 10:13:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.249 as permitted sender) client-ip=95.215.58.249;
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
Subject: [PATCH 14/15] stackdepot: allow users to evict stack traces
Date: Tue, 29 Aug 2023 19:11:24 +0200
Message-Id: <99cd7ac4a312e86c768b933332364272b9e3fb40.1693328501.git.andreyknvl@google.com>
In-Reply-To: <cover.1693328501.git.andreyknvl@google.com>
References: <cover.1693328501.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=T1iG7qQW;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.249 as
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

Add stack_depot_evict, a function that decrements a reference counter
on a stack record and removes it from the stack depot once the counter
reaches 0.

Internally, when removing a stack record, the function unlinks it from
the hash table bucket and returns to the freelist.

With this change, the users of stack depot can call stack_depot_evict
when keeping a stack trace in the stack depot is not needed anymore.
This allows avoiding polluting the stack depot with irrelevant stack
traces and thus have more space to store the relevant ones before the
stack depot reaches its capacity.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/stackdepot.h | 11 ++++++++++
 lib/stackdepot.c           | 43 ++++++++++++++++++++++++++++++++++++++
 2 files changed, 54 insertions(+)

diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index e58306783d8e..b14da6797714 100644
--- a/include/linux/stackdepot.h
+++ b/include/linux/stackdepot.h
@@ -121,6 +121,17 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
 unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 			       unsigned long **entries);
 
+/**
+ * stack_depot_evict - Drop a reference to a stack trace from stack depot
+ *
+ * @handle:	Stack depot handle returned from stack_depot_save()
+ *
+ * The stack trace gets fully removed from stack depot once all references
+ * to it has been dropped (once the number of stack_depot_evict calls matches
+ * the number of stack_depot_save calls for this stack trace).
+ */
+void stack_depot_evict(depot_stack_handle_t handle);
+
 /**
  * stack_depot_print - Print a stack trace from stack depot
  *
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 641db97d8c7c..cf28720b842d 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -384,6 +384,13 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 	return stack;
 }
 
+/* Frees stack into the freelist. */
+static void depot_free_stack(struct stack_record *stack)
+{
+	stack->next = next_stack;
+	next_stack = stack;
+}
+
 /* Calculates the hash for a stack. */
 static inline u32 hash_stack(unsigned long *entries, unsigned int size)
 {
@@ -555,6 +562,42 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 }
 EXPORT_SYMBOL_GPL(stack_depot_fetch);
 
+void stack_depot_evict(depot_stack_handle_t handle)
+{
+	struct stack_record *stack, **bucket;
+	unsigned long flags;
+
+	if (!handle || stack_depot_disabled)
+		return;
+
+	write_lock_irqsave(&pool_rwlock, flags);
+
+	stack = depot_fetch_stack(handle);
+	if (WARN_ON(!stack))
+		goto out;
+
+	if (refcount_dec_and_test(&stack->count)) {
+		/* Drop stack from the hash table. */
+		if (stack->next)
+			stack->next->prev = stack->prev;
+		if (stack->prev)
+			stack->prev->next = stack->next;
+		else {
+			bucket = &stack_table[stack->hash & stack_hash_mask];
+			*bucket = stack->next;
+		}
+		stack->next = NULL;
+		stack->prev = NULL;
+
+		/* Free stack. */
+		depot_free_stack(stack);
+	}
+
+out:
+	write_unlock_irqrestore(&pool_rwlock, flags);
+}
+EXPORT_SYMBOL_GPL(stack_depot_evict);
+
 void stack_depot_print(depot_stack_handle_t stack)
 {
 	unsigned long *entries;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/99cd7ac4a312e86c768b933332364272b9e3fb40.1693328501.git.andreyknvl%40google.com.
