Return-Path: <kasan-dev+bncBAABBEG5Q6UAMGQEDNLKMVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6CF2079F037
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 19:17:05 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2bc84f4d7a5sf8042901fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:17:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694625425; cv=pass;
        d=google.com; s=arc-20160816;
        b=OVjf2wIbhbMEz/qCXZVoYKrbP0NoywvJivOzIn81HprRx/nBsld9j+iBHk/XBsGKYB
         /q+ckghaOOhZsiKqHlk4pJr493XNkXlD2M04EXljGelyrHZaZzG2Hrg6zlelfA0QLDl3
         2sAN7tkrskWjq0OJgv1eVtJwlwKtU7TXJfmK3GCcKGkuGcmv/QbI50z3ITnd9WjdHFzW
         UeGZ+OPV4n4ilWffcfOgJWLgfCKS2PpeVYOhA11gZW5DebmbQU329YpKVPNzm3m5bP8O
         7yCZr8I3LcaABWJ2A6U4McnqKwmt/VCsOT4qAgjfAcp+Fr27HjPnal7h5t01khfEfuBJ
         cL8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+W/yK3WZipgekfXoRgbrL4jvLT8HP2KAf8jpoLWiE/M=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=iJ2322Nq6qKpeD7AGGJSyTwxGEZulOhDQ2R4irJWGIzt7ggbBGu6IIf9YP4OErb3tS
         MIs42pd64v4A7OCLJF9HHEZWu2RHpmiwspdzT3kTnKewkLmPgafK+7oaW/t1DxYWF0LR
         ZF+mGUyjC5KdxZtJ/BmxEzwanvpmQ6ddJ5f15+MdfnYH5r3i/pQdNE4rKmLGuxIWlq6h
         zLyctJ/JybmdDfCA6zzd2p13H4ZE035sbEDtR8iBckZm7oOH5uYIe+yXwM0To/roBLLn
         iXA4iFBfTb7CrxVgitMNTaDaV13NiDOU1CSpaAkUmOanqzuHz6E3G2ZRfVqh+6UiRwNk
         IDXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=F2Ii6+s+;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.227 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694625425; x=1695230225; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+W/yK3WZipgekfXoRgbrL4jvLT8HP2KAf8jpoLWiE/M=;
        b=vfqQdnMKvafZxD/eEQbfxYeTZRyBdmr3BwkizCgaG0/uMSuMWLmtgvTBKhIyIetmw+
         9BCDxTPQxu54iUGkIvX1YV9703AkyJNLBzPh+kzrcD9TKgdk3LXxh3Aco00G7yHY+kOK
         V7PRrxjWpmToGLifxrinZElDf15uMgyUwrTVIVT5BOpvu83MsoZNzfUuH+0t9lg+lKuR
         FM3WMlg91t19GOw7evvsZlvOXBCD76zQ4Cda7mRzlZomqgwM2JyplF8R9hdRBIJ5K+ta
         EtcT87i4k5UJ7LXI8bC0xqoV1QVrZl2ISoEps448i9DX4/DeIV4MVZOrzGZNLv/vg4ib
         T4qQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694625425; x=1695230225;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+W/yK3WZipgekfXoRgbrL4jvLT8HP2KAf8jpoLWiE/M=;
        b=DTgixTD4uIc4oWfDSgIIKx9IHStogBajEveLOt98CtXHTp0LnHqeYIKyPIR9Ru1pa9
         3P4aNyzHtEnYNj1mhJwMixAibxSk9AHqf2B9aGdzweX9ZMJAgQf1BBgmwrG8sGL9BWY2
         QiVq26H8FxcPSRypRfNHxYo9eOdcvgIuW2LVybj1yQ/9JPrJoEVUZ0jA7nm9H3JElinM
         Q+0wKEGhK9v/AdElkB4FhrEPT0dcbfybYAOgvBmRIePgpAiYk4Uxmhn39OjyOmc5yi4o
         yySIUVndLcQENEBoGzvmW5M6WCswv/KyCy263/lhLvSurI8RWD26S617DX1szXMhac4z
         lREw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxOGsKnnhX2bXvp4JS5IPNjkH1IC6+/xW5N3+tCJQomdOpAUEBy
	q9helimrqXcWTTm7h53RmC8=
X-Google-Smtp-Source: AGHT+IG870Fx7TIaM8KQ3BhD4W/10AjYdHzmcPUhGHbFZItMF4M4rgTIeZUj2KZg12K+EYualC4ryA==
X-Received: by 2002:a2e:8e92:0:b0:2b6:eceb:9b8 with SMTP id z18-20020a2e8e92000000b002b6eceb09b8mr1151460ljk.10.1694625424278;
        Wed, 13 Sep 2023 10:17:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:6a02:0:b0:2b9:310a:6b15 with SMTP id f2-20020a2e6a02000000b002b9310a6b15ls188028ljc.0.-pod-prod-00-eu;
 Wed, 13 Sep 2023 10:17:03 -0700 (PDT)
X-Received: by 2002:a05:651c:168a:b0:2b9:b1fb:5ff4 with SMTP id bd10-20020a05651c168a00b002b9b1fb5ff4mr2279501ljb.21.1694625422868;
        Wed, 13 Sep 2023 10:17:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694625422; cv=none;
        d=google.com; s=arc-20160816;
        b=L6D0Znb6fim4FADJIxVuoXSHgqM7PARlPcAtaPloO7RuDGw0ooolYDXmhkfDPxoOsC
         0B9SG/Wk7Nh7gjWKtVUTcV8diKGZ/TyfB7QLWrNPakqCILbVepxNUml40rHmUf+solgI
         lblhMqsK3YF4GhvGfbNjach53oyl6VTa/aGN4HCzWmuRoJ9z/MyRMGGWinwnTjN1KgSb
         pdKi2K2LIkhJICrQ4yL3SsxWlUfiOdrMFgJctP8waiqMvaofYYKZAYL7jebtPxFEiEBl
         ToGB944oxFR7ur6iyUt1D82YMt496h3kfyJIZU5Mni9h1XcYukAcsSSSKyImQPOFItzI
         YJbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=AuXPIx9M1sa3aovsp0XdlaM599Z45TGxV3EusWHlaB4=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=FAo6dvifBk980QOSmyZ8FEtMfGzeVDb9JShtlCskoH52/pSZtl3rDBSING2ffm+khG
         Ttz+XhtnG8apEUXykgnRaiXjyFpmfSPI1EQGS+G2zpAGJam8B8IpUJOKbNAG6FnaNrCU
         4tyEK2+5uNbhI29s18zqbgzfFM+QTMAbmumaYT0DmpLVpbFelxgGCXCb8q6lQAc93oE2
         uNqkCibSGiftS0Clg1fKHwKEiJPiy7KYpzt7ohp9DF99ehKUOEy4bz4D2C7fX3YROFbh
         VYACXn/ShjMm+UTmvpxwMUbo4xkOK6O5/Hl6stAaB6aEAonkEfKhVbqKwtp9hTigi9mX
         /3Iw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=F2Ii6+s+;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.227 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-227.mta1.migadu.com (out-227.mta1.migadu.com. [95.215.58.227])
        by gmr-mx.google.com with ESMTPS id r3-20020a2e80c3000000b002bb9bc937aesi837615ljg.8.2023.09.13.10.17.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Sep 2023 10:17:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.227 as permitted sender) client-ip=95.215.58.227;
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
Subject: [PATCH v2 16/19] lib/stackdepot: allow users to evict stack traces
Date: Wed, 13 Sep 2023 19:14:41 +0200
Message-Id: <1a3ea1e6b82f95eea644875756e12daba6c4cc7f.1694625260.git.andreyknvl@google.com>
In-Reply-To: <cover.1694625260.git.andreyknvl@google.com>
References: <cover.1694625260.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=F2Ii6+s+;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.227 as
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

Add stack_depot_put, a function that decrements the reference counter
on a stack record and removes it from the stack depot once the counter
reaches 0.

Internally, when removing a stack record, the function unlinks it from
the hash table bucket and returns to the freelist.

With this change, the users of stack depot can call stack_depot_put
when keeping a stack trace in the stack depot is not needed anymore.
This allows avoiding polluting the stack depot with irrelevant stack
traces and thus have more space to store the relevant ones before the
stack depot reaches its capacity.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Comments fixes as suggested by Marco.
- Add lockdep_assert annotation.
- Adapt to using list_head's.
- Rename stack_depot_evict to stack_depot_put.
---
 include/linux/stackdepot.h | 14 ++++++++++++++
 lib/stackdepot.c           | 35 +++++++++++++++++++++++++++++++++++
 2 files changed, 49 insertions(+)

diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index 611716702d73..a6796f178913 100644
--- a/include/linux/stackdepot.h
+++ b/include/linux/stackdepot.h
@@ -97,6 +97,8 @@ static inline int stack_depot_early_init(void)	{ return 0; }
  *
  * If STACK_DEPOT_FLAG_GET is set in @depot_flags, stack depot will increment
  * the refcount on the saved stack trace if it already exists in stack depot.
+ * Users of this flag must also call stack_depot_put() when keeping the stack
+ * trace is no longer required to avoid overflowing the refcount.
  *
  * If the provided stack trace comes from the interrupt context, only the part
  * up to the interrupt entry is saved.
@@ -162,6 +164,18 @@ void stack_depot_print(depot_stack_handle_t stack);
 int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
 		       int spaces);
 
+/**
+ * stack_depot_put - Drop a reference to a stack trace from stack depot
+ *
+ * @handle:	Stack depot handle returned from stack_depot_save()
+ *
+ * The stack trace is evicted from stack depot once all references to it have
+ * been dropped (once the number of stack_depot_evict() calls matches the
+ * number of stack_depot_save_flags() calls with STACK_DEPOT_FLAG_GET set for
+ * this stack trace).
+ */
+void stack_depot_put(depot_stack_handle_t handle);
+
 /**
  * stack_depot_set_extra_bits - Set extra bits in a stack depot handle
  *
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index e2c622054265..56f2abc03717 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -398,6 +398,14 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 	return stack;
 }
 
+/* Links stack into the freelist. */
+static void depot_free_stack(struct stack_record *stack)
+{
+	lockdep_assert_held_write(&pool_rwlock);
+
+	list_add(&stack->list, &free_stacks);
+}
+
 /* Calculates the hash for a stack. */
 static inline u32 hash_stack(unsigned long *entries, unsigned int size)
 {
@@ -580,6 +588,33 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 }
 EXPORT_SYMBOL_GPL(stack_depot_fetch);
 
+void stack_depot_put(depot_stack_handle_t handle)
+{
+	struct stack_record *stack;
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
+		/* Unlink stack from the hash table. */
+		list_del(&stack->list);
+
+		/* Free stack. */
+		depot_free_stack(stack);
+	}
+
+out:
+	write_unlock_irqrestore(&pool_rwlock, flags);
+}
+EXPORT_SYMBOL_GPL(stack_depot_put);
+
 void stack_depot_print(depot_stack_handle_t stack)
 {
 	unsigned long *entries;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1a3ea1e6b82f95eea644875756e12daba6c4cc7f.1694625260.git.andreyknvl%40google.com.
