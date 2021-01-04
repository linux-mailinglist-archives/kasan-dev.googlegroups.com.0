Return-Path: <kasan-dev+bncBC7OBJGL2MHBBW5GZT7QKGQERRGXTOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 88FA22E9595
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jan 2021 14:08:44 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 25sf16976957lft.1
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jan 2021 05:08:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609765724; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mjz+OyK8iCy7WY8PA/Z3LYY21kDsVAtewr/jBEyALy6hdNaoWFDpOCbhuzCLhdIi6D
         helRe3HkUddLAEkcn3BM36a/XTs+219w+AQy57iktr7EhHm7wUkwBMPgLcy2C8g4jhtB
         /pgrHJ59qD0K6mHv4jecBVimjKKHssv9yffBjQNuYNC5egQLZ/MxL2B+jRiega6Dkxib
         3G8enZUemyjvu3C1THI83OfTxQi/lr2MlgrPOn+6UxJWwJei7uaXH6XTSFqVXhIdz3Q4
         LUQ+b2Mm45Wu0izCyYeCEYmOYVWZtagQtcHwYgJlp/kQRJxsIaxwlHc5m5OCy9SxmRix
         rKsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=XtFSJQhQ1hDS5BmlEQRrmGLEFfV3sV4esCL1AzQ3TE4=;
        b=YHMDGPdPNg9hWJAWJUoCGHDZMgNSnK4LXs5lSKGQ6iYy6iwWmHHy9n9OQ5sX4PLn8m
         HI5/jKCDuE6fd6gPLWYBZ8daUFlU2LqYjRpvnKV2VcNzbxW0kHFTvp20N7W7j3coTNxa
         v/tPQtzjmotWR8Rd6gUOdCpMDrJOdeJsCjKcx8l7iUKN9eKirEUbdzeg9IMZYj94bOxs
         hemiuDEvzMrL6c/Gu0tiu7QfHownDTgSxp2qVKDocelXj0y7vO1Sv9YHO2lZ3+j2bmvA
         DnhAcN0nt/pss7faRriLWdiNO3zg/K7NkZ+qspffTsLo04Tf7Uvk4GdJNnj9oQ1zIrb5
         zO3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nH8T7gQC;
       spf=pass (google.com: domain of 3whpzxwukcvmz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3WhPzXwUKCVMz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XtFSJQhQ1hDS5BmlEQRrmGLEFfV3sV4esCL1AzQ3TE4=;
        b=EwUZoC0HjiUV+UZlzNW8WugvoDI5oybVAViWoJes4c8S+y6dKvPjFoxMh1Wrb0iTCg
         QyRkDg2ZNufdRhmUbmVjxLcNQDdvGy/00UmzjjhF38OchUXUqOOo6BjIYyJHpeVZ7FLe
         AclGYPQ76WlebwPFXwxdW/gVN1mHnKbmmj9XXrhqmzQ358z4a7/26MQu29Dbppm+tZ9s
         ekMMaCkg3fyv6uzpf0ikvuqTTEFVq89O3q5Ticbec4d5SKGFfYBEWPKk7VGF5QF+dTBK
         waqfRfYfvNrH/kGT9ufTMGe+ttcJ0Js/DXgesp848tMrL3PA0X9e2tVPaqTywF3bCung
         kZlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XtFSJQhQ1hDS5BmlEQRrmGLEFfV3sV4esCL1AzQ3TE4=;
        b=ks5jIR7F4zp7NXyHUe8XgeAs1c71CUZGn2NbpBsKEkuGA+IP2OXJEOcLqe7n9OP4mJ
         JO+jdlVibFuN75dW8UPXORtB4Ny0e44oVwRphSRAz1HXOW4G5QOXv1LoVhFLesVHCfzg
         4tgSUr8vYgfRnlN3LMs96tty5fklVpxzeM0pXH1Khp7m+ugv5X9P1lqWusq/se+Y5Noj
         OiVW4db/NK/ZgamWfwuS+HSDn6E9MwUOKI5nYXPDtg0UYUZodgwPYwSQDJkVwjkuGUw3
         r2rW1+O+0cHnbelE5jBQiMf9uiR/ipBeL25ULeTswfICc7GQ7NMROs38K3VH7yHMLz5k
         VdFg==
X-Gm-Message-State: AOAM531QWxS9Mu/fJ5nwUloBn4Ur1wa97qP8RNYB708pyzUUZyvYFQ/H
	hjezGXCYq3UG7k1IBjtn5C4=
X-Google-Smtp-Source: ABdhPJwrumBnPpLqleg0DRfF39UYXQ0ug20Ye69W//R5FctD+xqb7KJALBkxKb9h+UBDFtN0X3hOng==
X-Received: by 2002:ac2:561b:: with SMTP id v27mr30947124lfd.425.1609765724128;
        Mon, 04 Jan 2021 05:08:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:6145:: with SMTP id m5ls5118020lfk.2.gmail; Mon, 04 Jan
 2021 05:08:42 -0800 (PST)
X-Received: by 2002:a05:6512:318f:: with SMTP id i15mr34658304lfe.385.1609765722860;
        Mon, 04 Jan 2021 05:08:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609765722; cv=none;
        d=google.com; s=arc-20160816;
        b=Bv4DbGow6OmdphcICeg7nPKQLsQTs7zqU2RRdjKIYsMAd6efoJyCC/Rh5Wyd0rOMwV
         RxKGsdfhAitCjp80Q4nACURxFNbDZszTNxP5Hkh8Hd5AbnU+1LU0g1jAerNb7GyAp4BS
         36WDZAiRx8JTNzRy08CYpMlmiAIZBAjLu1BUkzr580KZW4UDXmNAZKTBG3KTRtdknHgk
         AGokgczFeNgothOsx577nyJsb63R7myzs+BSlIr0xhBRqelzMWZdoxOMXRrbZYjL+dOH
         dlo2QuWaz/oj2QLgXoMm9mFlL3mrAiDdPVBXHZEfn7usAyWMagL+zTqUNTklL7djJ30o
         i68g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=4L00xbr85BzSZDrQcVSi8abHo1VhpZjBCyy/C5zqGwE=;
        b=gGd7KCH4pg1Gsq/6g0PVHB8cSUsWssEpnz6pol3iLaZQ1RzaeLKBkMeBubnsRNO+I0
         htTjLl/shHswxp1AyKKg5RrSLu5cqFbfIc126KhX11OtLcC10ckBNn9Up7bO+C1WHzNx
         aKYryi6v7G6gm23nPdDr1pLaUTyKqTbwaHoTMKvUAA4C91qnQMIUidH5w5W759OxSr+p
         X19ATLrEbFuD43nLFaxuBMCb3ri6J8MvQBsRNvCk0H394hirETv4Mk3qiaFLtSEKUM6d
         hV42A8dKLry0Vt1/VJdKzSu174ZboIlSujOF6chsat3GhaYW1Vjg4b+gWMW3/z3d2bFZ
         QvVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nH8T7gQC;
       spf=pass (google.com: domain of 3whpzxwukcvmz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3WhPzXwUKCVMz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id d3si1841771ljj.4.2021.01.04.05.08.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jan 2021 05:08:42 -0800 (PST)
Received-SPF: pass (google.com: domain of 3whpzxwukcvmz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id h21so10538308wmq.7
        for <kasan-dev@googlegroups.com>; Mon, 04 Jan 2021 05:08:42 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a5d:69c2:: with SMTP id s2mr78387688wrw.36.1609765722195;
 Mon, 04 Jan 2021 05:08:42 -0800 (PST)
Date: Mon,  4 Jan 2021 14:07:49 +0100
Message-Id: <20210104130749.1768991-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.2.729.g45daf8777d-goog
Subject: [PATCH mm] kfence: fix potential deadlock due to wake_up()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, jannh@google.com, 
	mark.rutland@arm.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, 
	syzbot+8983d6d4f7df556be565@syzkaller.appspotmail.com, 
	Hillf Danton <hdanton@sina.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nH8T7gQC;       spf=pass
 (google.com: domain of 3whpzxwukcvmz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3WhPzXwUKCVMz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Lockdep reports that we may deadlock when calling wake_up() in
__kfence_alloc(), because we may already hold base->lock. This can
happen if debug objects are enabled:

    ...
    __kfence_alloc+0xa0/0xbc0 mm/kfence/core.c:710
    kfence_alloc include/linux/kfence.h:108 [inline]
    ...
    kmem_cache_zalloc include/linux/slab.h:672 [inline]
    fill_pool+0x264/0x5c0 lib/debugobjects.c:171
    __debug_object_init+0x7a/0xd10 lib/debugobjects.c:560
    debug_object_init lib/debugobjects.c:615 [inline]
    debug_object_activate+0x32c/0x3e0 lib/debugobjects.c:701
    debug_timer_activate kernel/time/timer.c:727 [inline]
    __mod_timer+0x77d/0xe30 kernel/time/timer.c:1048
    ...

Therefore, switch to an open-coded wait loop. The difference to before
is that the waiter wakes up and rechecks the condition after 1 jiffy;
however, given the infrequency of kfence allocations, the difference is
insignificant.

Link: https://lkml.kernel.org/r/000000000000c0645805b7f982e4@google.com
Reported-by: syzbot+8983d6d4f7df556be565@syzkaller.appspotmail.com
Suggested-by: Hillf Danton <hdanton@sina.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kfence/core.c | 15 ++++++++++-----
 1 file changed, 10 insertions(+), 5 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 933b197b8634..f0816d5f5913 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -94,9 +94,6 @@ DEFINE_STATIC_KEY_FALSE(kfence_allocation_key);
 /* Gates the allocation, ensuring only one succeeds in a given period. */
 static atomic_t allocation_gate = ATOMIC_INIT(1);
 
-/* Wait queue to wake up allocation-gate timer task. */
-static DECLARE_WAIT_QUEUE_HEAD(allocation_wait);
-
 /* Statistics counters for debugfs. */
 enum kfence_counter_id {
 	KFENCE_COUNTER_ALLOCATED,
@@ -586,6 +583,8 @@ late_initcall(kfence_debugfs_init);
 static struct delayed_work kfence_timer;
 static void toggle_allocation_gate(struct work_struct *work)
 {
+	unsigned long end_wait;
+
 	if (!READ_ONCE(kfence_enabled))
 		return;
 
@@ -596,7 +595,14 @@ static void toggle_allocation_gate(struct work_struct *work)
 	 * Await an allocation. Timeout after 1 second, in case the kernel stops
 	 * doing allocations, to avoid stalling this worker task for too long.
 	 */
-	wait_event_timeout(allocation_wait, atomic_read(&allocation_gate) != 0, HZ);
+	end_wait = jiffies + HZ;
+	do {
+		set_current_state(TASK_UNINTERRUPTIBLE);
+		if (atomic_read(&allocation_gate) != 0)
+			break;
+		schedule_timeout(1);
+	} while (time_before(jiffies, end_wait));
+	__set_current_state(TASK_RUNNING);
 
 	/* Disable static key and reset timer. */
 	static_branch_disable(&kfence_allocation_key);
@@ -707,7 +713,6 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
 	 */
 	if (atomic_read(&allocation_gate) || atomic_inc_return(&allocation_gate) > 1)
 		return NULL;
-	wake_up(&allocation_wait);
 
 	if (!READ_ONCE(kfence_enabled))
 		return NULL;
-- 
2.29.2.729.g45daf8777d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210104130749.1768991-1-elver%40google.com.
