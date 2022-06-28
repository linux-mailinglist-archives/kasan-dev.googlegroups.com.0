Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3VB5OKQMGQERH3KW7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6244955BFF6
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 11:59:11 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id e5-20020adff345000000b0021b9f00e882sf1668458wrp.6
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 02:59:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656410351; cv=pass;
        d=google.com; s=arc-20160816;
        b=wLk7wDWFC7nQ6b+nNsbJW6z/3QPTYWU4V9O/NPiE38u3hSrZncYPZ/Lw5NN/AuuExx
         xLQTyRkt8vMeqVl5VGvADvz4VUzEamr0NKyJs59MKHu1ZGO50RUkTTO7Oge41mC8QXdB
         xSXnicvYomYskIWSwSgUpVXEcyW10qRDMTjCkYoZR1NI3B5JTwCD/NVT8ZDpwYIJyS24
         6YVaoCenjR47tq1ktYvRbxKJ4YmlpKTQQ4TZPBMZIHgwpsJEsbf0BlwDdubKfUTTcYBc
         Z55WMECophZjuIkjGzr3NLTCz2WlGLQQ/V5wXpnsILHynBZG7i6dvcqCbJG9CzZLFdiJ
         dpyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=O6BA5PaByq8wcNC52nTDEqvS+P1/R4l9MvVCi0WoKMw=;
        b=tKuSM//VS4cSZbVSpdkxa7MF27FiyzgDSaEwpf8L+6etv9D9hHVj9SgHTYL0ozQtwI
         Vcz+//2UqBLJpEWcvb7urMPc49wrBm+D4TVv4BVLI0iG8b+shZZflaX9/SUBzF3imk3a
         JnFV1AB8Dsae3Yz/PTY9l/jxh6JMfrziFdx4wmS6F8oDCw8D6dNSTGmtJZsNTRNsu+4d
         qU6JJywvncJ/9S6MUCnvon7LV6yeWVv2+FL3ndqjjL7OE1Ogzba/625pQYZlZKKWgoTU
         NIz2ZxITcwqxfw/QOPpuUuELT8/ClOx+meeZRtK/dlX3Iabfy74rya9GgEthq8qI6Bx5
         gj9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hlkFl0FC;
       spf=pass (google.com: domain of 37dc6ygukczy4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=37dC6YgUKCZY4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O6BA5PaByq8wcNC52nTDEqvS+P1/R4l9MvVCi0WoKMw=;
        b=EuavPrvkyEoOQv7VZj2iAxdnCEK3DW1+KIGOudg4k7tCTqhQdafEAu4DvFyS9e0PR2
         ExH0sDIfbSRAIS5BEZaEt6b5HhoXl0pS8BfwUPcqDJeYga+uoL7e6zEze+PPhqUmKg+D
         tWLnky9tRC8ZC4P4eHgGcFmF8Nt4qPx509AJn3GrsABwC2kKbKyseRCqm1qFj/+Jxno1
         DTlvlWRkGQdhf9wIjAT3+wKfV9RuTgkATLnel+0HwUYva5DAjLjqgqvcLWAVONl0fA2A
         Uwi6CmfePduGtneLSWFbCqsgZjfXEtr6XqipnSTURe1ToMjICzU1tqezvcBdFHAf6vLj
         bHzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O6BA5PaByq8wcNC52nTDEqvS+P1/R4l9MvVCi0WoKMw=;
        b=s5re1sIvT8/6ctOwgUGefqUhThrsQmqKFXWEKDUEUXmeDT63ieJ7BQYOofc+mVF9P0
         2MwXMTowyfViTcIFTA/Xf+90+aHPfDHjpGZXIedmwVsP9lcZ8F5Cp2hGKEpzSrv4iqcg
         sh+M22GWDskyvDNi7JmVXn9HGYCM2bNDpIfxx8UcdYjdbMxabdCquZr2Qr8T2xl3DIF4
         pJe8KfUAnCMl1r8WoHlg9KZ7SwaORZ7eseh4GcRGX1aL87V2mrr9TkKsyKvzPFaskxfw
         unkKWtnzMhasTaIDBu99fpn4uoNje0HaueT8W53rjcawS3Mz4yw84RIFWMQgI12w5ySq
         zSNw==
X-Gm-Message-State: AJIora/9Soo6gWo41LcXZ6PR+fsKAgXizRdSljdyfx498om+8rwWrhwD
	62pQDAy+ijqduMGKNRU8esw=
X-Google-Smtp-Source: AGRyM1tcLiEQyClmibI3P+yu3QVhgpmyCFUqCHAOZo9kAG83dTDtGsD3ld1JMWTLpjz4luTI7B29Yg==
X-Received: by 2002:a05:6000:2c6:b0:21b:ad25:9c1b with SMTP id o6-20020a05600002c600b0021bad259c1bmr17253993wry.391.1656410350847;
        Tue, 28 Jun 2022 02:59:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:350f:b0:397:475d:b954 with SMTP id
 h15-20020a05600c350f00b00397475db954ls4688442wmq.0.canary-gmail; Tue, 28 Jun
 2022 02:59:09 -0700 (PDT)
X-Received: by 2002:a7b:cb82:0:b0:39e:f9cf:12b7 with SMTP id m2-20020a7bcb82000000b0039ef9cf12b7mr25983645wmi.135.1656410349635;
        Tue, 28 Jun 2022 02:59:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656410349; cv=none;
        d=google.com; s=arc-20160816;
        b=OT4B1TwAbqpivAbclAn6FPz/gU4+dO8inwmM9haBV1Hm8LP16LJhzkn02A4/nPdLML
         aN8i12aPIbwb/oyHLwgRIMYjk61fjS/FnVX+eHueqqj/UEKEsZlvTqV53WdDLxVvH6d+
         Kfs74PMq4+orqeVfsDA6Fyvoiqzg13R2n3hOqA0ICw7G7CTKwmrvNlbtGz4xs/L0R7PD
         ejccrL4W0za8gXFH3UdIWOFfXo6q31p7vqEiQ3DCkaryg8x75cfw8AB+ekRzdCIYGRXG
         wSjtN+MM1bqh1EGMwgFrCtimaQaB7B1ytwzaY+RyeGREekdorJPoeWij6yFVLx6Ll7a+
         97pQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=y3vu5QzrDjJQpXkXaz04N0mmbkIf31DuJdXr7A4d0cQ=;
        b=ftm0sRVozP6qHmRMykkM4YCgL8hljOOmm4X+O9KD5HPQUZm1yZAL38rljjH56xPMDk
         BaN3RiM4+grizkTz3aZT1SKQxsy/I+rlxfYMMIRmyxGM9JiVUaszaw9of5rD8CE832Fy
         ljJoHMpbG38g8lKhCbKnpFhaAp33YQhK6c1HOnUbgNiotF7VwBvsHRZxMpCmnRfqloLE
         CCwRnHTb3SdBlGgH2Cvh2ceFSHKY7YLtUDVxjL4oNmznkVRp7Wnu1nTVZ68vooYgwnBf
         zMEfKCmPtWgOxmKgBkBqJo+jQycj3jQObkLNLSGg5AA8hADw+H/J9x/SZQFQhNeC7S36
         YCcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hlkFl0FC;
       spf=pass (google.com: domain of 37dc6ygukczy4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=37dC6YgUKCZY4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id c15-20020a5d4f0f000000b0021b947060b9si572370wru.6.2022.06.28.02.59.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 02:59:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37dc6ygukczy4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id m20-20020a05600c4f5400b003a03aad6bdfso4795125wmq.6
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 02:59:09 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:3496:744e:315a:b41b])
 (user=elver job=sendgmr) by 2002:a5d:4c8a:0:b0:21b:9f3a:c002 with SMTP id
 z10-20020a5d4c8a000000b0021b9f3ac002mr16723653wrs.182.1656410349259; Tue, 28
 Jun 2022 02:59:09 -0700 (PDT)
Date: Tue, 28 Jun 2022 11:58:24 +0200
In-Reply-To: <20220628095833.2579903-1-elver@google.com>
Message-Id: <20220628095833.2579903-5-elver@google.com>
Mime-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v2 04/13] perf/hw_breakpoint: Mark data __ro_after_init
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hlkFl0FC;       spf=pass
 (google.com: domain of 37dc6ygukczy4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=37dC6YgUKCZY4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
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

Mark read-only data after initialization as __ro_after_init.

While we are here, turn 'constraints_initialized' into a bool.

Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
---
 kernel/events/hw_breakpoint.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index add1b9c59631..270be965f829 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -46,7 +46,7 @@ struct bp_cpuinfo {
 };
 
 static DEFINE_PER_CPU(struct bp_cpuinfo, bp_cpuinfo[TYPE_MAX]);
-static int nr_slots[TYPE_MAX];
+static int nr_slots[TYPE_MAX] __ro_after_init;
 
 static struct bp_cpuinfo *get_bp_info(int cpu, enum bp_type_idx type)
 {
@@ -62,7 +62,7 @@ static const struct rhashtable_params task_bps_ht_params = {
 	.automatic_shrinking = true,
 };
 
-static int constraints_initialized;
+static bool constraints_initialized __ro_after_init;
 
 /* Gather the number of total pinned and un-pinned bp in a cpuset */
 struct bp_busy_slots {
@@ -710,7 +710,7 @@ int __init init_hw_breakpoint(void)
 	if (ret)
 		goto err;
 
-	constraints_initialized = 1;
+	constraints_initialized = true;
 
 	perf_pmu_register(&perf_breakpoint, "breakpoint", PERF_TYPE_BREAKPOINT);
 
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220628095833.2579903-5-elver%40google.com.
