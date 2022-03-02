Return-Path: <kasan-dev+bncBAABBY5372IAMGQEKZJ2PFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D44C4CAA97
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 17:40:04 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id x12-20020a19f60c000000b00443972023c6sf890010lfe.10
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 08:40:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646239204; cv=pass;
        d=google.com; s=arc-20160816;
        b=gZVbezP9rwy5NsuJmJjUYtZQzPscP4nhiyqMHMtKG65SJD6SHiP12uOi0s1eib4II9
         zvs4Pb6vrlY0S2dCgw8GjS/D4GMWXHozMBrObmZNiQMEq44XKV8WIfuiYC2AI/dg8X2I
         zShpwXgyzR9GGf2T+8SCilUssQU8rHLQh/5/xUpT8TAi0+j4bdSOGGl5jwr9bPwYtsj3
         bDbpXmNAS04QxFvLXR69/8P7MOBo+5t9//ZgLVJafYCXeb0cUG37+d3fcIu1XHhgpXe/
         OmKJbI1rH8vrNnr558p3nDw7oAXPZRM7F6WNsD63B/Lg5kMli9w1BioPhMw5OAerj62s
         dNmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=S5j1WmWKwsxV6wnfJCQH38ygYT6bWrnFyb2Ci21nW88=;
        b=blVbGUnaR/MfnOpvdOTCUKpX8pPwAjbjH1iosu7GopscHhJaypiZJ2VHFWuHK0KjXs
         GYhMh1jt4PgFckCcipCO381VLkFYR9YmH5/u3KBhgXNF3KTrKYu35rRSymeqPgkhbVLh
         fAiP3WmdRuQHh+WvbuZMojcnkMFhawlhst+t/xav1X4HvkXVnPmUdLnLs/eQOQYJkxtz
         T/1rJTv4Js23lC8R4gfNxwtJKcHTZXGlHfIvR+jbusQf+Sf+uFzQFKRv2WWJ6JuPv3VH
         gblFrHAo+nvNfWkhAzCDrCQzPqzUXaw0wRHlM5XJeaZE6EsUXuh4X26YqnqnrvTCa6cU
         WvMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="PnZ2t/AN";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S5j1WmWKwsxV6wnfJCQH38ygYT6bWrnFyb2Ci21nW88=;
        b=VC9W03w23VcESDd+XLBD/8YLjr/elAWFMFVRmz/IdErYtXKVSAYm3zDy5VQv1yx0sB
         /JwibYkwUITGd12I40FfF5kx54sOht6LTX8AqmFDzkptVdKdB4dORe7TJ8XrhUWqlBb9
         ieT0Bk/xprGyH/KTelKmiRwdOKpcdBCbCaDqXA3jVvY56hbaJdHcbTyt0FZc2vMJbEqr
         +SasuhjvRtzdocEZdnRCjFcV/uyRZAJ+V/i45wF+IqqvBHX5ExLqFfZwN5Ps9iLtTMz4
         eqk3bzb3yDD/vnmaCHoWG8oYFIWs0Z+efIeGCNh2PW3GxZ/U6gB2q5yZSaeRozu8Xl+5
         FcQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S5j1WmWKwsxV6wnfJCQH38ygYT6bWrnFyb2Ci21nW88=;
        b=wiKCYacnJb0Zl1pP4Y+hgKiR6gCONlVXP0bTcVhEv8eaBu2yULXANTLfrAp8qpu9LH
         ecenZ1uYa89UhTAzKADZ/CIvbXf/LehWeNAa3NwusL6NMbcyqROD153eVBkyXxWvEvnP
         aBqXh5u2in9sZP7TSX3xaEubNlmQpEqdNszyy/RD0Z6BhZLez7cHBA0Mdg8KydIskLUJ
         7/qOwgekl9O74Q7tJVflHYdTbmAqH0lsDKkWvxk0VtwQ3FWiuoWpi8a6BjCMnycTl2rF
         1fmrrTD8HG+nj4bkkTUIEn6juwxrDFhBkqNNngDeUxLi5UeEFPsArp4QTW1cAA+ONX8B
         3JGQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533TeBmU+XfEFBCFlFUNBmLFEopAsAEem0pCd5qJYxKiFBfaW2Xj
	WauPqDA3Ip4EKMayLBT23/c=
X-Google-Smtp-Source: ABdhPJz08LOxOpAbgZvkAHo641IrbCGzd/82j4tkyfdkiFLnezdY4Zmnwij0jW6kF4N7gGtOwdMCTw==
X-Received: by 2002:ac2:562b:0:b0:443:76b5:cb35 with SMTP id b11-20020ac2562b000000b0044376b5cb35mr18343556lff.208.1646239203996;
        Wed, 02 Mar 2022 08:40:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a7c4:0:b0:246:3e9a:df6e with SMTP id x4-20020a2ea7c4000000b002463e9adf6els3656771ljp.6.gmail;
 Wed, 02 Mar 2022 08:40:03 -0800 (PST)
X-Received: by 2002:a2e:a792:0:b0:246:4680:e553 with SMTP id c18-20020a2ea792000000b002464680e553mr21330968ljf.175.1646239203128;
        Wed, 02 Mar 2022 08:40:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646239203; cv=none;
        d=google.com; s=arc-20160816;
        b=sCYl0o3lDy3BQVPXrDub1zqfeAqdQJvsRFbdEPqGkMwmB170gDt3t7zuLR+lCQpNXf
         s6d1eVSnUrAeaQdFkQ6+m1DNRd1TAX3KLgsNV2zVG5uqBCoanKIRdN8vhZp9i4Lk/qSR
         rl3RqvBd+z7ka+H4B6O7w+v24OiC8KUwNxThBF33mP5gm28i6SIoZM8QJ5aTHTNv2rTY
         fN1G3tqg0AABKibKKJTah6eYVP2FkabXwfhOXJlOkD75HCPaYkGplTRV9sTVF48FneQK
         7KXDueAB6D49neFJJH/MPdkqpR8OKnuLxbUIFr12wWoRNo1Rg14594mJKivi2dOV/tMG
         vItA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=djMH4j9HV8SXlCfl9Af/XXd5VDpDAiry7CNPlQpwESU=;
        b=dWOsQ1v3nCOeI8gTgfjDsE28rmmV1nky9oLTKhuaccRLqD6W0KgxdmMkoVogOcUCWh
         wPuMbzFzffboxS2Qfg4kd6lia/mJKc4FcmH/fayRoiQDKKMsB9Xk7gU226Pmwfs0ngqP
         S0vq17SwM/xEffRiFryo4SB4l9nntEo84hiRRgP25/xx4ayuppGJVsQS154fUhXGwohh
         55bVFc8MbdDL/zF6P97oUl6vstbfw/eWG6PWzFHgV50m1yuTsFttc5wFH/mc8DX1tHI8
         aZfSDEM/IRihAZOpk+16JYuZ9jRrikJx0KeHtiwkBZD0i5Fpz22hScFJ/Igkkhy9oVHk
         us5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="PnZ2t/AN";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id s22-20020a056512315600b004433c2a6e0fsi709919lfi.10.2022.03.02.08.40.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 02 Mar 2022 08:40:03 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
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
Subject: [PATCH mm 20/22] kasan: reorder reporting functions
Date: Wed,  2 Mar 2022 17:36:40 +0100
Message-Id: <82aa926c411e00e76e97e645a551ede9ed0c5e79.1646237226.git.andreyknvl@google.com>
In-Reply-To: <cover.1646237226.git.andreyknvl@google.com>
References: <cover.1646237226.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="PnZ2t/AN";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Move print_error_description()'s, report_suppressed()'s, and
report_enabled()'s definitions to improve the logical order of
function definitions in report.c.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 82 +++++++++++++++++++++++------------------------
 1 file changed, 41 insertions(+), 41 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index ef649f5cee29..7ef3b0455603 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -84,24 +84,29 @@ static int __init kasan_set_multi_shot(char *str)
 }
 __setup("kasan_multi_shot", kasan_set_multi_shot);
 
-static void print_error_description(struct kasan_report_info *info)
+/*
+ * Used to suppress reports within kasan_disable/enable_current() critical
+ * sections, which are used for marking accesses to slab metadata.
+ */
+static bool report_suppressed(void)
 {
-	if (info->type == KASAN_REPORT_INVALID_FREE) {
-		pr_err("BUG: KASAN: double-free or invalid-free in %pS\n",
-		       (void *)info->ip);
-		return;
-	}
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
+	if (current->kasan_depth)
+		return true;
+#endif
+	return false;
+}
 
-	pr_err("BUG: KASAN: %s in %pS\n",
-		kasan_get_bug_type(info), (void *)info->ip);
-	if (info->access_size)
-		pr_err("%s of size %zu at addr %px by task %s/%d\n",
-			info->is_write ? "Write" : "Read", info->access_size,
-			info->access_addr, current->comm, task_pid_nr(current));
-	else
-		pr_err("%s at addr %px by task %s/%d\n",
-			info->is_write ? "Write" : "Read",
-			info->access_addr, current->comm, task_pid_nr(current));
+/*
+ * Used to avoid reporting more than one KASAN bug unless kasan_multi_shot
+ * is enabled. Note that KASAN tests effectively enable kasan_multi_shot
+ * for their duration.
+ */
+static bool report_enabled(void)
+{
+	if (test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
+		return true;
+	return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
 }
 
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
@@ -160,6 +165,26 @@ static void end_report(unsigned long *flags, void *addr)
 	kasan_enable_current();
 }
 
+static void print_error_description(struct kasan_report_info *info)
+{
+	if (info->type == KASAN_REPORT_INVALID_FREE) {
+		pr_err("BUG: KASAN: double-free or invalid-free in %pS\n",
+		       (void *)info->ip);
+		return;
+	}
+
+	pr_err("BUG: KASAN: %s in %pS\n",
+		kasan_get_bug_type(info), (void *)info->ip);
+	if (info->access_size)
+		pr_err("%s of size %zu at addr %px by task %s/%d\n",
+			info->is_write ? "Write" : "Read", info->access_size,
+			info->access_addr, current->comm, task_pid_nr(current));
+	else
+		pr_err("%s at addr %px by task %s/%d\n",
+			info->is_write ? "Write" : "Read",
+			info->access_addr, current->comm, task_pid_nr(current));
+}
+
 static void print_track(struct kasan_track *track, const char *prefix)
 {
 	pr_err("%s by task %u:\n", prefix, track->pid);
@@ -381,31 +406,6 @@ static void print_memory_metadata(const void *addr)
 	}
 }
 
-/*
- * Used to suppress reports within kasan_disable/enable_current() critical
- * sections, which are used for marking accesses to slab metadata.
- */
-static bool report_suppressed(void)
-{
-#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
-	if (current->kasan_depth)
-		return true;
-#endif
-	return false;
-}
-
-/*
- * Used to avoid reporting more than one KASAN bug unless kasan_multi_shot
- * is enabled. Note that KASAN tests effectively enable kasan_multi_shot
- * for their duration.
- */
-static bool report_enabled(void)
-{
-	if (test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
-		return true;
-	return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
-}
-
 static void print_report(struct kasan_report_info *info)
 {
 	void *tagged_addr = info->access_addr;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/82aa926c411e00e76e97e645a551ede9ed0c5e79.1646237226.git.andreyknvl%40google.com.
