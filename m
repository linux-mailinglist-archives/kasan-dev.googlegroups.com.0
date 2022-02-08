Return-Path: <kasan-dev+bncBAABBP6ORGIAMGQEGHKSG4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 658954AD86F
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 13:51:13 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id o8-20020a056e0214c800b002bc2f9cffffsf11231907ilk.8
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Feb 2022 04:51:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644324672; cv=pass;
        d=google.com; s=arc-20160816;
        b=XX4wamkdjrjgKtFEnQMJT7WI7IsdZuTJCyZOVE0yzbZQczT5z3UHpx9AF9eAuUa5gJ
         r2+HKs8D6TTjiFsaImmkHl76tto7R+DE+7QS+UsmGpZmjTEOYDMyEw9o2hABTM5GE8so
         4C0bfKDvawl2vtWcvNG64fK+z2spe0CDyrKv8dzlTpvI1cse7+YG6LfkWOHb+ivvKAzQ
         4gmvQN+QZ9GurWIwAZhNNmrcw492gTRDD8CFud6w1SkVk36zKiUA0N1kX26ZzRf90xDb
         V0nYPRg2SdUGd6WMZpxMvmIVlxjG00UdVT8RNJG2xgxLniBNA5LIvEr1OogpPQjq3bOH
         dXLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=va9tPCBwFtm3WT45jq4RQ6ZV/Z32tRENzqQhhQsfqP0=;
        b=EU3hr1h3BptbvogUfQYe3jXS7u7gt9ZhLbYn0YjNisTdVaw9ttiG/m8EIaJozfUgCk
         FdUSz3ItOLun2VLL2r7yT0caNxW8WzZxkRaNDeJ8inXPKaHEA0Oq9NyO3K+Ap+sl9Lof
         f5Zd+oosN6y5Ft5UG/V7oegJkxvSqRsVaXK6t88kpk2o8P0PsJJqRjp2Ip40dR7QbLR0
         aijnlmIoj2j1xBqpoEWpeGhQEUifK2rmI4+7C8T7Vukql+GGH9tA/WU4wlYInCeND6iU
         iDbRXeleZgpeBSrtoTleEej+JQJHPqvCUN5sWQCZl2PI6Z/zPAKmB9CvWkb8qJShSnmS
         0ySA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=va9tPCBwFtm3WT45jq4RQ6ZV/Z32tRENzqQhhQsfqP0=;
        b=WAColF+sQxyO+qXPbrKkAor2/5DYYJuxKUp7ovA2YHtO9HxwPoA3AysyQbS6hj+HZY
         P5x7jRjFjqA5bES6WGPXLG/6BAqEKaSCou4ROv/wUuFnm5GfEcu5vvRShW0aXdMSLvii
         zyE9H683e335BTjFSRM1jlOwnqPetO9Z03ZZpJv7KNigtLgR8XuiSEcpifJMDcjzcXec
         de2sUWUyVbJNzFJ1yt3OuS5WHchpI03X9YY5savgJqXq++SGRQAbcIx/+n9Kta9y6VFC
         F66eD5yF7A/uCSkf8EfBZB9CIQZ9P+muXcxON8fcECvoKaXm1ftqYmBA+6FKL1Nusr2e
         rDHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=va9tPCBwFtm3WT45jq4RQ6ZV/Z32tRENzqQhhQsfqP0=;
        b=BrLRMtiRgxGB3bYNOEIpGfzlv4Atb3mwEjLSb31X2TPIuk9l4yUr6JWBbQUmW6XVrB
         p+EfhAl9qrxtkmmTBqRAbQSzz5eXKgtm06lpE/DciwKBKLO6RPKTFHerCQoGSmzsEf1w
         uHJxbIZW8BGaHY/98sUiV7LJkBxYQEsig8XRnetsdA2NXao3oEQ+JEBj57BA5z50vUub
         gpiLEV+2Htq8y/2sRdZBKaT5g9ui85211xUl0HNGoycsO0HPCk1hLUaj7ODLZDo882pR
         jOxgU0HZZ4aXfRF9WUA3Qua5Cfvw4rr1+rCf9AFFeL55n3NOp8Zo6TVC4ZNRn0QJTwxv
         t8EA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532/mPAeP7NYk49Gk4X527IHifGbLiZIvQcchXnhO3KIPaDCZ0B3
	Y+lGypcgXmcBGuufhwU5yAc=
X-Google-Smtp-Source: ABdhPJxOt0e5wSa4RitQ5vIEtNxaXTW5XVCPe021Arr8++SDL7Ji0XBEIek7FCIlG9JH1mKLKQYzMQ==
X-Received: by 2002:a02:3b67:: with SMTP id i39mr2144434jaf.32.1644324672173;
        Tue, 08 Feb 2022 04:51:12 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1c8d:: with SMTP id w13ls2099801ill.4.gmail; Tue,
 08 Feb 2022 04:51:11 -0800 (PST)
X-Received: by 2002:a92:5208:: with SMTP id g8mr2082172ilb.310.1644324671621;
        Tue, 08 Feb 2022 04:51:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644324671; cv=none;
        d=google.com; s=arc-20160816;
        b=MxRihXT3mSDUg5e+vpEwhV3X1ShS4oVI1DNzhW/l8z/JfIfjf9YGRO7KXIfIPCRMeB
         0nAnGerd5zDSZKNhNgZn5Y+kCkJBSGei3Ssb/P80sacJjHxIUME9YCKsOlrwvhX6VIkx
         /dB5FUhWdBk6PQA6TPThVa6h1xVxRu/NIsvBgxAHMPiP8G+wESbgTJNYrHg9TAZY6KVR
         dKRvRDWumTQy0xlkrlUVYZGJGFfjYzTIRiArlfvG2kfmPvtuOObPu1dTdGjrPvPox0l3
         qChd8SmeHqgc1j9ZGTDhi/AE08pnCMtZMiPr+jS9/btGCFYc8WXHngk5Fal7Tg+bTyx3
         sGXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from;
        bh=qGJnNbLPzK7UyDbI79WZ4oMXPkEl5Okr72aVK5OpkZU=;
        b=B0AqcOYMHEAxSIrredsQ2rBkCzlMzpuI0naVtUzUcxbKGD+30O+r6+3ryUJLI84hMZ
         i90W4OnjgmXz2QQIhrkaCdyyIsqYjSbVg7sz9agCJy7708qWP1rJugu05KwtKDkQfpCb
         cY6onk9fr9Z2KSkfthqATzhQMtN4UR2EkM3jg6mLFDgUjzs6T9Z1zVs17Pp5Ca+cxVQG
         bKojtd3SMeae3wDK1+w5RlvD+5gy0xqlsocngTYNcEC1CCcd2rCjdA6n0OjvQ+BgvEC2
         GJJUYwKBCs+9gS1oCyI+mbhHgbsaDGwydcQfshcqql1pHCvvKm7lNOs5m0Xj7Xj3TrTQ
         hdYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id f2si411517ilu.4.2022.02.08.04.51.10
        for <kasan-dev@googlegroups.com>;
        Tue, 08 Feb 2022 04:51:11 -0800 (PST)
Received-SPF: pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from linux.localdomain (unknown [113.200.148.30])
	by mail.loongson.cn (Coremail) with SMTP id AQAAf9DxL+M6ZwJik0oIAA--.26524S5;
	Tue, 08 Feb 2022 20:51:08 +0800 (CST)
From: Tiezhu Yang <yangtiezhu@loongson.cn>
To: Baoquan He <bhe@redhat.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrew Morton <akpm@linux-foundation.org>,
	Marco Elver <elver@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Xuefeng Li <lixuefeng@loongson.cn>,
	kexec@lists.infradead.org,
	linux-doc@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v2 3/5] panic: unset panic_on_warn inside panic()
Date: Tue,  8 Feb 2022 20:51:04 +0800
Message-Id: <1644324666-15947-4-git-send-email-yangtiezhu@loongson.cn>
X-Mailer: git-send-email 2.1.0
In-Reply-To: <1644324666-15947-1-git-send-email-yangtiezhu@loongson.cn>
References: <1644324666-15947-1-git-send-email-yangtiezhu@loongson.cn>
X-CM-TRANSID: AQAAf9DxL+M6ZwJik0oIAA--.26524S5
X-Coremail-Antispam: 1UD129KBjvJXoW7Cr4UuFy7ury7WrWrWFW3Jrb_yoW8AryDpF
	nxKFWDKr4kKr1rXa97Jw4vyryYvws5Xa4xCas7Ar4Fyan8tFn8JrZ7CFy2q34Yg34xXayY
	vr1qqry3K3W8JaUanT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUPl14x267AKxVWrJVCq3wAFc2x0x2IEx4CE42xK8VAvwI8IcIk0
	rVWrJVCq3wAFIxvE14AKwVWUJVWUGwA2048vs2IY020E87I2jVAFwI0_JrWl82xGYIkIc2
	x26xkF7I0E14v26ryj6s0DM28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48ve4kI8wA2z4x0
	Y4vE2Ix0cI8IcVAFwI0_Xr0_Ar1l84ACjcxK6xIIjxv20xvEc7CjxVAFwI0_Cr0_Gr1UM2
	8EF7xvwVC2z280aVAFwI0_GcCE3s1l84ACjcxK6I8E87Iv6xkF7I0E14v26rxl6s0DM2AI
	xVAIcxkEcVAq07x20xvEncxIr21l5I8CrVACY4xI64kE6c02F40Ex7xfMcIj6xIIjxv20x
	vE14v26r106r15McIj6I8E87Iv67AKxVW8JVWxJwAm72CE4IkC6x0Yz7v_Jr0_Gr1lF7xv
	r2IYc2Ij64vIr41lF7I21c0EjII2zVCS5cI20VAGYxC7M4IIrI8v6xkF7I0E8cxan2IY04
	v7MxkIecxEwVAFwVW5JwCF04k20xvY0x0EwIxGrwCFx2IqxVCFs4IE7xkEbVWUJVW8JwC2
	0s026c02F40E14v26r1j6r18MI8I3I0E7480Y4vE14v26r106r1rMI8E67AF67kF1VAFwI
	0_Jw0_GFylIxkGc2Ij64vIr41lIxAIcVC0I7IYx2IY67AKxVWUJVWUCwCI42IY6xIIjxv2
	0xvEc7CjxVAFwI0_Gr0_Cr1lIxAIcVCF04k26cxKx2IYs7xG6r1j6r1xMIIF0xvEx4A2js
	IE14v26r1j6r4UMIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr0_Gr1UYxBIdaVFxhVjvjDU0xZF
	pf9x0JUhBMNUUUUU=
X-CM-SenderInfo: p1dqw3xlh2x3gn0dqz5rrqw2lrqou0/
X-Original-Sender: yangtiezhu@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
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

In the current code, the following three places need to unset
panic_on_warn before calling panic() to avoid recursive panics:

kernel/kcsan/report.c: print_report()
kernel/sched/core.c: __schedule_bug()
mm/kfence/report.c: kfence_report_error()

In order to avoid copy-pasting "panic_on_warn = 0" all over the
places, it is better to move it inside panic() and then remove
it from the other places.

Signed-off-by: Tiezhu Yang <yangtiezhu@loongson.cn>
---
 kernel/panic.c | 20 +++++++++++---------
 1 file changed, 11 insertions(+), 9 deletions(-)

diff --git a/kernel/panic.c b/kernel/panic.c
index 55b50e0..95ba825 100644
--- a/kernel/panic.c
+++ b/kernel/panic.c
@@ -185,6 +185,16 @@ void panic(const char *fmt, ...)
 	int old_cpu, this_cpu;
 	bool _crash_kexec_post_notifiers = crash_kexec_post_notifiers;
 
+	if (panic_on_warn) {
+		/*
+		 * This thread may hit another WARN() in the panic path.
+		 * Resetting this prevents additional WARN() from panicking the
+		 * system on this thread.  Other threads are blocked by the
+		 * panic_mutex in panic().
+		 */
+		panic_on_warn = 0;
+	}
+
 	/*
 	 * Disable local interrupts. This will prevent panic_smp_self_stop
 	 * from deadlocking the first cpu that invokes the panic, since
@@ -576,16 +586,8 @@ void __warn(const char *file, int line, void *caller, unsigned taint,
 	if (regs)
 		show_regs(regs);
 
-	if (panic_on_warn) {
-		/*
-		 * This thread may hit another WARN() in the panic path.
-		 * Resetting this prevents additional WARN() from panicking the
-		 * system on this thread.  Other threads are blocked by the
-		 * panic_mutex in panic().
-		 */
-		panic_on_warn = 0;
+	if (panic_on_warn)
 		panic("panic_on_warn set ...\n");
-	}
 
 	if (!regs)
 		dump_stack();
-- 
2.1.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1644324666-15947-4-git-send-email-yangtiezhu%40loongson.cn.
