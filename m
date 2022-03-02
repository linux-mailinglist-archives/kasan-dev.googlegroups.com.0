Return-Path: <kasan-dev+bncBAABBIV272IAMGQEJF5TNCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63e.google.com (mail-ej1-x63e.google.com [IPv6:2a00:1450:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id D0CF24CAA70
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 17:36:50 +0100 (CET)
Received: by mail-ej1-x63e.google.com with SMTP id sa7-20020a170906eda700b006d1b130d65bsf1250166ejb.13
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 08:36:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646239010; cv=pass;
        d=google.com; s=arc-20160816;
        b=yE5Bz+zg6nmR6HCjqHVUlW/9QnFyZKe4S71pvVu7bCYhfTDAcMzL2uD02s76mhHuyL
         MZ8Nz0Uq2oTpxhoj2gprjcJh9YnRUCmWC8BySwEVMlHM4w24Q8FcVcPfO+d8vETxvxBU
         ztjHYG5hS5U4ssX5FlytILtIb2hnI9xVK1QLFExKUvF5xS+iW97Xx+ukPkejy9Wx/787
         YGhlIT5buOK8M3KbVllBEj2lo88PN73GlFHoxw33cFQ8ITp53oaVy25wrV/hS7QyERXk
         mhjrHAzQGhbYWY6eR8K/KV1G7FGS8OwiJFtXlCKQnnuNUK9rMPqCkm55mFIWw/C40LJ6
         nALA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=dIPE0b7Mu2jxdtUNX9zzvc60PNJMCoA0FfJ4j3avQfI=;
        b=Lg5ttfQ53mAhEaOsXPkgCT25EyFkg2UnJFEz+WoKQo4wTaWEfCC1EA9GOv+hxttkbS
         P0PazID+mWAmWgobdhskNsvg6P6ALeh7RV0AZj7bwuq+8FRoE9uVFZBbtjgjVlbpqK3+
         0gdygxTssyBv3JfNlMp48vG+knNqxPENSP3PloX7zbQ/iqLnx1JhID3GfQ+TcBSsrp1u
         ctRBFnYMSzx0Vo8yJT2AvvhIyOUT4OBGO1ZikTCJ/YKXHYIf9lzwW8dcBaARK47+SORR
         OEXjxqnyKIc1q30HDHLOMEKrcEtrxfnxBUcSPadYUh/1TvwkuTLfk/8wxE+MyglKCg6k
         k9kw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Lt4GrBE4;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dIPE0b7Mu2jxdtUNX9zzvc60PNJMCoA0FfJ4j3avQfI=;
        b=fTkygq4TtAn61pE689v9YbUzOG5+yBQC5B/2ZTdFPNm4DI8405e6TFqypc12s5Pzt1
         6V8KNgeVQQTmx3TfW14z/EuxXUqkhwOy67N6KUpt686RHiA47kYiqHJGQ7bNgPzI+5t2
         +R9Tka7ytuCYT5GLuE+ugR9zHjkYuGUUdTX7apCk6GgS/akQnn580MVyhZjCNMjCv8+H
         nIpFt7OIYNOzS7xIEh7tOqFLO5/qYt8/l2LFYXuxGWMpSDdrxQdugjawnH0chpr3GTjC
         H9mJXD89TwR4k7BFoX/HT+zAqg69A3FdpTIp65fuOGwYXUpxZQdyhDqn7GnVemKn8L+D
         2+xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dIPE0b7Mu2jxdtUNX9zzvc60PNJMCoA0FfJ4j3avQfI=;
        b=dhfTfsDJckvTZyvit45/aUHvRPmrHce8p3pgrwPosSUUwivBTfGKJJAty64HZAQnVP
         fFFsR5bF5jxuCxidaPp5rfxJYZHJUNGJ87X3XgnM3VsE8us4h425RvjhgmYXkq07Ew54
         zrG6r4sVZmAOVEuuh0hgcDWVap7PZDyXQfTxzoESn2bdIgQtal2KBlxF1iiBIVqQ0w+3
         7rO0reoiCJEl9YGTrObuS7oUYyG2DrGvdRbnDcGty2cddvNoc2Xc4CYemjVrB+BPNyE+
         FP82G/jKJN/4gvMs0I521ffFRPCS2Wstr0YMj3HR9H8RvP9dgw63TGP7Dr/IH5Bup4OZ
         D/Xw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530nZR7MfsFkigQlZYGyDQcYq5yu8mfwNK0skW1n90I2smy4pnL2
	+xn1vA1OR1rJIrv3mo9QaFY=
X-Google-Smtp-Source: ABdhPJz0RETuOEmYFY19yPvL5d7IG4u2OQD/C6F5e0YknbhZcucxq7BI89bZIiqUopaWdsgSn3hiZQ==
X-Received: by 2002:a50:fc12:0:b0:415:cf24:f6c2 with SMTP id i18-20020a50fc12000000b00415cf24f6c2mr471955edr.3.1646239010616;
        Wed, 02 Mar 2022 08:36:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:a94a:b0:6d0:76e0:adbd with SMTP id
 hh10-20020a170906a94a00b006d076e0adbdls2889845ejb.9.gmail; Wed, 02 Mar 2022
 08:36:49 -0800 (PST)
X-Received: by 2002:a17:907:c28:b0:6da:6f40:eced with SMTP id ga40-20020a1709070c2800b006da6f40ecedmr1902757ejc.400.1646239009877;
        Wed, 02 Mar 2022 08:36:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646239009; cv=none;
        d=google.com; s=arc-20160816;
        b=kuNOS2EjQkjYNiBJfVKf5pXmp/Mf8QT/8Wk++DUM5TU3s0LyLbmYYqkcDlkZWq741J
         jVJ3KjvGg+feZNhotyvaWXxgwYjDu62Ph+CK2+UqvaA8+C7VltpxXPNjJSd+yNPSK3qg
         o98SRH9WqovtxEBmATrREcndQpTWDrsw1JplHFUL/L8yFzg1NM1LkzpStlBm1/DZwaat
         jTHmwRxPb128rmX3+N5NTvMcpy2bw4MQgWM/CziHHnZjr9EjEAYK/Bqe8RTSAxtlBM6r
         gITsBdKKBlAWkgVOGhcyyoiod7CqQhM/dosEocvV0B/7qEpwBgerGxLrhTKwgw7y1txA
         fNAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Y1tVVcjXP0EERa5LTGRHGhA3byiWB4oonSnJ546jpQY=;
        b=YIKW6jAy7VDOX0ERUo1bbDMmF6I3WV899Fj+nT/nFg3UZ/Bd68OQY341IQNYxute9I
         G8uo5LOE669CfaT1EbwmhW3lxWND0cUATNFhFd6WfME2guqxScITvZJVPyyf9ngEkkP0
         vgCOy6aKyiSg4+vGSKIkq8Oiyd2Pr2TTLjJnPB1BQ3HCrYMHEHciI7FFTRxpCTVbLkHX
         JiahXogpqBLINTqPkH8CMgGEQMkju4J1bL0MNkHutAEg1/aGbx4FOcI2rEQ2Jdps2BHA
         Y+do37Fk/OzkjvIxOaxWALEncZJjuzpu1Sju0Ea5rl3+U1SQeq3KOoUb3L6xRPs/F1Kv
         oqgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Lt4GrBE4;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id b88-20020a509f61000000b00413ed059da9si487371edf.4.2022.03.02.08.36.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 02 Mar 2022 08:36:49 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 05/22] kasan: print basic stack frame info for SW_TAGS
Date: Wed,  2 Mar 2022 17:36:25 +0100
Message-Id: <029aaa87ceadde0702f3312a34697c9139c9fb53.1646237226.git.andreyknvl@google.com>
In-Reply-To: <cover.1646237226.git.andreyknvl@google.com>
References: <cover.1646237226.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Lt4GrBE4;       spf=pass
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

Software Tag-Based mode tags stack allocations when CONFIG_KASAN_STACK
is enabled. Print task name and id in reports for stack-related bugs.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h          |  2 +-
 mm/kasan/report_sw_tags.c | 11 +++++++++++
 2 files changed, 12 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index d1e111b7d5d8..4447df0d7343 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -274,7 +274,7 @@ void *kasan_find_first_bad_addr(void *addr, size_t size);
 const char *kasan_get_bug_type(struct kasan_access_info *info);
 void kasan_metadata_fetch_row(char *buffer, void *row);
 
-#if defined(CONFIG_KASAN_GENERIC) && defined(CONFIG_KASAN_STACK)
+#if defined(CONFIG_KASAN_STACK)
 void kasan_print_address_stack_frame(const void *addr);
 #else
 static inline void kasan_print_address_stack_frame(const void *addr) { }
diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
index d2298c357834..44577b8d47a7 100644
--- a/mm/kasan/report_sw_tags.c
+++ b/mm/kasan/report_sw_tags.c
@@ -51,3 +51,14 @@ void kasan_print_tags(u8 addr_tag, const void *addr)
 
 	pr_err("Pointer tag: [%02x], memory tag: [%02x]\n", addr_tag, *shadow);
 }
+
+#ifdef CONFIG_KASAN_STACK
+void kasan_print_address_stack_frame(const void *addr)
+{
+	if (WARN_ON(!object_is_on_stack(addr)))
+		return;
+
+	pr_err("The buggy address belongs to stack of task %s/%d\n",
+	       current->comm, task_pid_nr(current));
+}
+#endif
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/029aaa87ceadde0702f3312a34697c9139c9fb53.1646237226.git.andreyknvl%40google.com.
