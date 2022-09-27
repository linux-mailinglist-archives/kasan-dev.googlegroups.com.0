Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4XBZSMQMGQEZJZHBHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id B06575ECAA9
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 19:20:51 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id b16-20020a056512061000b0049771081af2sf3757875lfe.5
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 10:20:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664299250; cv=pass;
        d=google.com; s=arc-20160816;
        b=Nd9IcREey0U/Aovoy5pVv4hT2lUhvFwshiDsKE54h0B4p2ebtVwM85iJwpSH0OnVlu
         ggBC3fI0/qvsKMME5Qn+Jd1osbWFH6SxipUAZJKz4hM+Hr3V6CmIfBCwVIiWqvIGN6Tz
         ZK1TwPaTjMsgg7f7CYwBE6/5ozYzTbAeC/PSN4WpJ4btzG6cFawoE7UN7Jd7gQ/0vSL8
         RgUNKKHgXBoWid0xElt/WLYs9Z43NOTUXH+QDnXhOesC6ll3S9eXtywFGHrqYDgWBUe9
         973dKx2ftCnJhkfc8ozwC/3Qfv97i9xMIoX4vIDMSVZ4eS666OXnVDW0d//i5Jw2+tu5
         qCIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=r380s5BEheVHsuDHR2+tYB/Grfe596q59HD+CFt/MMI=;
        b=rieQONc6Ng3Mn0Pcpq8EQV/ZqIEd7H3VPwjXw/WE0Gk5pJyLaI9lxoBwQouj0tVkKO
         zkc4AQiQM13Ti6N0DeDiKtnb8E0Uc+WnRBdJPq/kZT0iNgHPsAXlPPidW1Z+U9uNdyiO
         45d98a2GA7ChCOIxTz8S+wNSO05fgxaPEifHmb0YF3VWcqbZ9ooJ0uZIb7KfeIGUSlke
         aE8b3YD0DZD8pdxF10KJJUmPqIXF4/VoEdIolCFvtp+hPbsYPNxAQCwYRnzVu+oliA4G
         AIeNoayn2NVAr1+kndW92x4wT8ZZUOaRQdYgCShudr5nVKhVjzQnx1EpIF6su9/InH/4
         1VMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=OMULmYEI;
       spf=pass (google.com: domain of 37zazywukct4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=37zAzYwUKCT4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date;
        bh=r380s5BEheVHsuDHR2+tYB/Grfe596q59HD+CFt/MMI=;
        b=dqDGk19TIa4TYuaVQGMYNABWVYpyStnQj4CmM49UF0FprO7skhg0rIuqPykaBsH74t
         je2eJpzSZd66dUNEpmbEGWEVQnGgJ+iqUD2k78OYP5Fc2fksLD7RzBEreivp9JDS5owT
         uFQL1NoExu/X7iygb4GAL5VvlMl/UDZ51qHXDy4wkqrAHdc9LjxY6lJR2Z5TMyTThRTE
         Ngr7+Uzg/Bt9jFWGDHR3ueCMxF1meePKy0bA0WD7ZKsqHPCf/eJk8EcWmFT8QUwgGrIX
         LEDKDL8tYpnpP5W3z/T7Prj0EO7zqC0gXeouQQPKOU4nAtIgjNhT742Z+MO1u+arfFSh
         2zKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date;
        bh=r380s5BEheVHsuDHR2+tYB/Grfe596q59HD+CFt/MMI=;
        b=xB6ucSUwhhd78PYYwCKd6xexmZf3P/0jdZTYNSCR4HsDuTa8plwMpJQa2PCCvlcvcv
         ++2lEJHsx2FKzVftTDgu0IcPaG1RNvOOyNSQXFJFdz9ianuQFLlgIgHdWJMtDmqyxW65
         pV7EtSCkDVHQRBtlbuPABxC9K+9qQtgLgkNDGQbyENHcOi9TB0r3L2udf+jZ+02zqca/
         xMLSoRghXzV95eHEs4+vhvvss2PBx25hCl6mmHtriL/C1qkfzdVrihkpUUBzX0v7CWnY
         L7+gd0dikuTXKNaZc6TYGqESvbG53ga2fdTTzPOY7+0R5IkACCLKe9p2VuPqiwJkTFLT
         V+ng==
X-Gm-Message-State: ACrzQf1Xo+kLAYt+hZMr2waqhEAQnm5UelVP6czlk/6n4fKj6X0yuw0u
	636vow3BWeap0VoZ00C+UJo=
X-Google-Smtp-Source: AMsMyM7D+/YL5TKCXUvoZzF2TnkLHFaZEyMrpaoecibz1u0BJW5ms5TyXxzhwiRluHc7X8jgbgo+dg==
X-Received: by 2002:a2e:a4d3:0:b0:26a:cc7d:d50b with SMTP id p19-20020a2ea4d3000000b0026acc7dd50bmr10701655ljm.77.1664299250444;
        Tue, 27 Sep 2022 10:20:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4a74:0:b0:49b:8c05:71a5 with SMTP id q20-20020ac24a74000000b0049b8c0571a5ls1358678lfp.0.-pod-prod-gmail;
 Tue, 27 Sep 2022 10:20:48 -0700 (PDT)
X-Received: by 2002:a05:6512:2345:b0:49e:359f:5579 with SMTP id p5-20020a056512234500b0049e359f5579mr12504603lfu.478.1664299248493;
        Tue, 27 Sep 2022 10:20:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664299248; cv=none;
        d=google.com; s=arc-20160816;
        b=MIDn6tQ5VTBczADHikzQkuD+MR0w9JHODqEe8Ch13JbZfwZ9KaCHtjL73+Lte0t4N5
         DuQRaUs+Z8SBcpd9M0OPucqB/Y+WVRQemsKFHZ39MpNER9mVrn9GC1cPQvaMV9dQxfIH
         MxdvjKBQDK5y0YnK6CgAJqTOIW68/oGA1xBV6G7baVjG8w8mfSQW/AIwjMJX9k5cdroj
         NcY07/YWgdtguy6ygzgVLAw26zCH5gIFG5rkhfhzcDdc3s3DiouZxTFb6GCzM5oKFXMo
         dtW1VgYmjqJTDfJtUf6UhfOIcIgzGzSzmoOYG4Nh91JD/cPXcLAITOoSC2IoTQL5S9+8
         7aQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=xrimbA31oh12GrLjVo2B/hMpsltLczwvj4VfTLXOv0M=;
        b=QYsJkQTmOlkrwnDvC4DiCxZqkuYNNkx3J4/T/cx44Pt4Z+Ger5GsoHXKxTme5ahRb8
         G2VN4mejG++OiVjtq1DzCBWAtfJHQa1/vfps9f86JLgfsI21liY1k08URB0q+3EmMPkM
         3HZcNvd5aqauSC90N8knkLeMRsUAJ4g+QV04EZcNrYq387YKhXI3H0SVa3pTJgO2z9xN
         4inA2ZyGz5iWPgZ11/H06wqjpzTisGcgsLV1zWTcTEKPASH5iz4Yxvd2BPUk7C8DDDaO
         O1/YEX/V0MrvaXTFW2JLRgjO1GUXstVk22TD4lyr4j+9/8f1mEk4DwuaeD/s4xLSyZj4
         HWiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=OMULmYEI;
       spf=pass (google.com: domain of 37zazywukct4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=37zAzYwUKCT4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id j15-20020a056512108f00b0048b38f379d7si89285lfg.0.2022.09.27.10.20.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Sep 2022 10:20:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37zazywukct4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id z16-20020a05640235d000b0045485e4a5e0so8297201edc.1
        for <kasan-dev@googlegroups.com>; Tue, 27 Sep 2022 10:20:48 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:693c:15a1:a531:bb4e])
 (user=elver job=sendgmr) by 2002:a05:6402:d5a:b0:457:b705:3280 with SMTP id
 ec26-20020a0564020d5a00b00457b7053280mr3560695edb.201.1664299247897; Tue, 27
 Sep 2022 10:20:47 -0700 (PDT)
Date: Tue, 27 Sep 2022 19:20:25 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.37.3.998.g577e59143f-goog
Message-ID: <20220927172025.1636995-1-elver@google.com>
Subject: [PATCH -tip] perf, hw_breakpoint: Fix use-after-free if
 perf_event_open() fails
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@redhat.com>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@kernel.org>, 
	Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, 
	linux-kernel@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=OMULmYEI;       spf=pass
 (google.com: domain of 37zazywukct4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=37zAzYwUKCT4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
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

Local testing revealed that we can trigger a use-after-free during
rhashtable lookup as follows:

 | BUG: KASAN: use-after-free in memcmp lib/string.c:757
 | Read of size 8 at addr ffff888107544dc0 by task perf-rhltable-n/1293
 |
 | CPU: 0 PID: 1293 Comm: perf-rhltable-n Not tainted 6.0.0-rc3-00014-g85260862789c #46
 | Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.0-debian-1.16.0-4 04/01/2014
 | Call Trace:
 |  <TASK>
 |  memcmp			lib/string.c:757
 |  rhashtable_compare		include/linux/rhashtable.h:577 [inline]
 |  __rhashtable_lookup		include/linux/rhashtable.h:602 [inline]
 |  rhltable_lookup		include/linux/rhashtable.h:688 [inline]
 |  task_bp_pinned		kernel/events/hw_breakpoint.c:324
 |  toggle_bp_slot		kernel/events/hw_breakpoint.c:462
 |  __release_bp_slot		kernel/events/hw_breakpoint.c:631 [inline]
 |  release_bp_slot		kernel/events/hw_breakpoint.c:639
 |  register_perf_hw_breakpoint	kernel/events/hw_breakpoint.c:742
 |  hw_breakpoint_event_init	kernel/events/hw_breakpoint.c:976
 |  perf_try_init_event		kernel/events/core.c:11261
 |  perf_init_event		kernel/events/core.c:11325 [inline]
 |  perf_event_alloc		kernel/events/core.c:11619
 |  __do_sys_perf_event_open	kernel/events/core.c:12157
 |  do_syscall_x64 		arch/x86/entry/common.c:50 [inline]
 |  do_syscall_64		arch/x86/entry/common.c:80
 |  entry_SYSCALL_64_after_hwframe
 |  </TASK>
 |
 | Allocated by task 1292:
 |  perf_event_alloc		kernel/events/core.c:11505
 |  __do_sys_perf_event_open	kernel/events/core.c:12157
 |  do_syscall_x64		arch/x86/entry/common.c:50 [inline]
 |  do_syscall_64		arch/x86/entry/common.c:80
 |  entry_SYSCALL_64_after_hwframe
 |
 | Freed by task 1292:
 |  perf_event_alloc		kernel/events/core.c:11716
 |  __do_sys_perf_event_open	kernel/events/core.c:12157
 |  do_syscall_x64		arch/x86/entry/common.c:50 [inline]
 |  do_syscall_64		arch/x86/entry/common.c:80
 |  entry_SYSCALL_64_after_hwframe
 |
 | The buggy address belongs to the object at ffff888107544c00
 |  which belongs to the cache perf_event of size 1352
 | The buggy address is located 448 bytes inside of
 |  1352-byte region [ffff888107544c00, ffff888107545148)

This happens because the first perf_event_open() managed to reserve a HW
breakpoint slot, however, later fails for other reasons and returns. The
second perf_event_open() runs concurrently, and during rhltable_lookup()
looks up an entry which is being freed: since rhltable_lookup() may run
concurrently (under the RCU read lock) with rhltable_remove(), we may
end up with a stale entry, for which memory may also have already been
freed when being accessed.

To fix, only free the failed perf_event after an RCU grace period. This
allows subsystems that store references to an event to always access it
concurrently under the RCU read lock, even if initialization will fail.

Given failure is unlikely and a slow-path, turning the immediate free
into a call_rcu()-wrapped free does not affect performance elsewhere.

Fixes: 0370dc314df3 ("perf/hw_breakpoint: Optimize list of per-task breakpoints")
Reported-by: syzkaller <syzkaller@googlegroups.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/events/core.c | 4 +---
 1 file changed, 1 insertion(+), 3 deletions(-)

diff --git a/kernel/events/core.c b/kernel/events/core.c
index df90777262bf..007a87c1599c 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -11776,11 +11776,9 @@ perf_event_alloc(struct perf_event_attr *attr, int cpu,
 		event->destroy(event);
 	module_put(pmu->module);
 err_ns:
-	if (event->ns)
-		put_pid_ns(event->ns);
 	if (event->hw.target)
 		put_task_struct(event->hw.target);
-	kmem_cache_free(perf_event_cache, event);
+	call_rcu(&event->rcu_head, free_event_rcu);
 
 	return ERR_PTR(err);
 }
-- 
2.37.3.998.g577e59143f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220927172025.1636995-1-elver%40google.com.
