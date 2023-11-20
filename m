Return-Path: <kasan-dev+bncBAABBNVY52VAMGQEU3AVTZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F07F7F1B7E
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 18:49:43 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-50aa6b1bea6sf2383894e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 09:49:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700502582; cv=pass;
        d=google.com; s=arc-20160816;
        b=SbE7vw7aWTx7NNBHA306sIx0KhPNooS0EQ2Ef9BEuYJDyLcLAFdFe4puz1AVoW5N7s
         1n4zQAB7FyF/aFONULzR0hwpX3A0PqIbn935YPL+utNf5d0eIBvJHU6pMktiQ4tSsL3E
         nKhIO8B+9/fQC9SXWp9PEjgoB3VdJTdRNuDGmy29EB35kLVPhhZhCJh+YXUMehSL26gP
         3PG05kSLU2EAvpmQXALMQNENTcTG2PEH+AVvV2DCYuCj8ltAtL8WvA9mopOfghTC8OSG
         2HzYMdahF9UCtNgQt6mg4rttm89FTuUECdVQjFpZNOzwswnjkBRVVJK0zzJA7p4gsO++
         d8mA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=1iIP3MxAHMC4giujmL1IoApBYCboJUnEoM/y06TXAbI=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=mRIv3Fel+ZdhCR62klaMd/Yanv9MafiFQYX72ODjZlUCpFDqpUlDZRE24NHXPS33xF
         wX/RxO7f/NPwjfEFRifzVJiQAjE8xCyE5VqLKQkLzF6GesrQrywX4j9kGBPQUeiyjWZy
         ybfIQAZF3YBa6+RD957hgIpwmdp0Ua26Fw8hPy0roJfuIKx1WIAZ9MSsPfylevXwgs9s
         YhgdAbFXozdgsrxcvenPgo+hzqDOLyO6xrsaaUdQYVh/PCNwBcb1tPFxScBA8HMJKTxm
         PKXnmLyJXptQRyLAGWz1rn/mmF/O1PKDbj90et5nSgdu5aRhqzfiXmM66dVJMlPEj6AO
         AmGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DLuotPQZ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.185 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700502582; x=1701107382; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1iIP3MxAHMC4giujmL1IoApBYCboJUnEoM/y06TXAbI=;
        b=JpVeXGqQRyu2ypqly97W2eV5fX7hi7Zh/xAT9qEG8s6x5JGdMUIS1UmQuzvralRyjn
         Wb1Dp4WkIPSutS4EAQpH0jJWEr8rPb9EcI0s5GVYrbkooz1x3hWutSRrAZbA923NarU7
         /BzerzxQnmxwhPCqd5sALmXl0xK/AqlWv5d0FH2P4b8JnoTY5XmBVwnxP/sfLveOYp2E
         sOUr4mqry0OgoWI4Q/A0Ly2eFizYBrE7IMm1XwKk9ToZYGjkX1WQclMGqgpBg1yhpEqX
         X4jILjtkbWftWLN1t8ymQkDC2BZ6MoORGN0oY9DNgNq+Nuf5X2Hr1bWeydhGkWsT74RI
         UPLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700502582; x=1701107382;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1iIP3MxAHMC4giujmL1IoApBYCboJUnEoM/y06TXAbI=;
        b=UTuiJ4939E8J+FgMS8lK89C4V6i18APEmYcC+hm27kPviIgpD2O7A7+9/0ZdpD1aPT
         EiSoAft9WzJVy3k16HhZZKEhD00KYfwop8UN4U5ClyJvfpYsHwhuCN/4uHGoEHhaUiXJ
         DwGtkvo/felJV7o+eJYBBhQ7hMEfZCC1IkEqRxZNyKoes+wRDcdfctLyv/zfJqgLIA+g
         S+ns+GdYjaLjgo36h2Eqs9+GAdaF5ghZ2Agu//WIkWNZF7w7OogftaT9NAtSixfuYY3d
         H3bYz4I9UQoDOpTtp/gRIibkNw5shFumLmJQ5VrcWSqbvo9mncLTTL+dxdIoNDA+Fl+1
         h5Tg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyTXR64Mv2SBT9dL/BDbsPiHeEEhkgGNrNH74wNtuynvmeXGGHd
	/1l76L9cvsrQf99/mctxnSE=
X-Google-Smtp-Source: AGHT+IEVfg881Jj6cN92ce/rSTY6mher0mGw6N9eZQkrte1/lPwHqUbTifvjQ6osWjHks2GNPeR9Aw==
X-Received: by 2002:a19:c219:0:b0:500:b42f:1830 with SMTP id l25-20020a19c219000000b00500b42f1830mr5282548lfc.63.1700502582587;
        Mon, 20 Nov 2023 09:49:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1e85:b0:32f:7df3:a10c with SMTP id
 dd5-20020a0560001e8500b0032f7df3a10cls1493970wrb.0.-pod-prod-08-eu; Mon, 20
 Nov 2023 09:49:41 -0800 (PST)
X-Received: by 2002:adf:cd86:0:b0:32f:aaff:96dd with SMTP id q6-20020adfcd86000000b0032faaff96ddmr6372839wrj.4.1700502581158;
        Mon, 20 Nov 2023 09:49:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700502581; cv=none;
        d=google.com; s=arc-20160816;
        b=U1712mltv5ODU0vRIwemYjI9MIGCUpVRkJ9WrhvzIxY6quV+PpEXOgVUf+pYykoRXS
         +2gqi8V2LO2A1ntRbh2xS+OhvM2BAUG2Lf8bAZ7mImP91fVPMyemppvYiP/zDYJKvDf5
         2jCWWPLHWX/YDaVBqnW8X0YyCQsdHSeufoiXMnM6bLJyf2qYP0miWY6PZkXELQtIzx2N
         8wRIuxpCAWiYpxhw0UeoGffbHbiT09zotxQrFQnnd51lKNm16zB4ioWQiZeSGn/FTJp0
         kUa8cqmzWZv/SaUk9mrb7QIqHZSUAj94qutLrj2J0CbMvl94XajKq4u4N/VtDuPQWHPa
         1cgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=taQhm6+sqq7C99vuNmST7zKoEFBrlbi2ArfSWbY49ok=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=k6yc3t6xCJCcciLdQFMupZmINqWwBb9iZRvLkPkNzm8x+BKNWMrJc58MfKSy61Xm7j
         SiW41pwsvws+UGPLfyFBDwgJe+cZDS5tyJHESB1tRGdwcHKA2n+ctDjBzqpPzoXo3poQ
         9YuKjy01mmX5CfvFro4YOTTr6cHTV2eHVnEZz6Nov/elREQLn480XU0EWTO2V7BpsB2G
         BIMX+Tw9KK5yem+4ItpFnzm3w4lxtT5ZmOvu97AhI18U/ifugRPMHXZRald+jI/Q2DXA
         ZwZmdahGYhiSCBbQOhq5t8WTaih6Hbsx5y9JmLWyaW2hFM6kT2Mxan8UGaWtprSVJRKp
         ldSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DLuotPQZ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.185 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-185.mta0.migadu.com (out-185.mta0.migadu.com. [91.218.175.185])
        by gmr-mx.google.com with ESMTPS id r16-20020a056000015000b003233224954esi286088wrx.6.2023.11.20.09.49.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 09:49:41 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.185 as permitted sender) client-ip=91.218.175.185;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v4 17/22] lib/stackdepot: allow users to evict stack traces
Date: Mon, 20 Nov 2023 18:47:15 +0100
Message-Id: <1d1ad5692ee43d4fc2b3fd9d221331d30b36123f.1700502145.git.andreyknvl@google.com>
In-Reply-To: <cover.1700502145.git.andreyknvl@google.com>
References: <cover.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=DLuotPQZ;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.185
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
 lib/stackdepot.c           | 37 ++++++++++++++++++++++++++++++++++++-
 2 files changed, 50 insertions(+), 1 deletion(-)

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
index 911dee11bf39..c1b31160f4b4 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -394,7 +394,7 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 	size_t offset = parts.offset << DEPOT_STACK_ALIGN;
 	struct stack_record *stack;
 
-	lockdep_assert_held_read(&pool_rwlock);
+	lockdep_assert_held(&pool_rwlock);
 
 	if (parts.pool_index > pools_num) {
 		WARN(1, "pool index %d out of bounds (%d) for stack id %08x\n",
@@ -410,6 +410,14 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
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
@@ -592,6 +600,33 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1d1ad5692ee43d4fc2b3fd9d221331d30b36123f.1700502145.git.andreyknvl%40google.com.
