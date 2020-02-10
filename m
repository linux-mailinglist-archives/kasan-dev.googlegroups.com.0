Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLW6QXZAKGQE36T4TXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id A4A54157DF3
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 15:56:46 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id v17sf5080309wrm.17
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 06:56:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581346606; cv=pass;
        d=google.com; s=arc-20160816;
        b=lf1J2XCChHWn7VFJSJpilS2trrfYiqZZkN3OS4FKJTn4fq7O8kPNhba10a9xo2Hm+X
         AEGlgD21xZBRI/+If7EoHcWMjb6/jTMI6F0Xy4bkMI1j+RkN3Wpgk0yzPimQLd+vhCG4
         F/JMjAZKO6FQ3yg5h15Ey4f9cAPZVfHsLhp/pq0wZPvA1oCPQb/E2bJqjjvfwyS/FQmW
         VhqqK+x+pf/vnI98WjpvuqfgRGMshO+lHjQ/KthZHPpuNKj60l31F5Og5RVpHbyNhX9Y
         Gwc0qdzba9hCx87GqEAkTcJ5VeZcRwNP46isz4tiHdCPzr4jwIGZoQKFPLOsdwQQVyOD
         pswA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=QAWyoIz7l7cO/96Ke+xJEn+FEmrcryaPuligPOYRf8g=;
        b=SZVw9TYqBVTbx/blGaVrd8M/olyppTbB9Xr5a8hmLhYLkfVlIqkH9NvyvVnhkA9mN1
         WfVLTkTu4B8w2hIYQpKVmXtmUBc8HqxfaKCarbhp8JGyvD0afVo8mzTGQon8hQfuriJc
         I5kNTZjY03r4jW95tFbvFo0UGdrx+pPU7jUB7Dn6I5LfQD1TcRwG04vVgFTWmWwrzCX4
         hS43clZNNeopzXXNz+1/yhUIv8kH+KS//BBxX6EqJyhwRRPNhqiILu4hEXVN66N3kSBo
         /qZ7Fn54MYBy3e6St/sTrqzWWgQz6RwvpEkRnRpgMrSeQexhjopr4yRRXZ4nqIHHv9XH
         zvow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UshsyR45;
       spf=pass (google.com: domain of 3lw9bxgukcqoov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3LW9BXgUKCQoov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=QAWyoIz7l7cO/96Ke+xJEn+FEmrcryaPuligPOYRf8g=;
        b=V8HWPGwH2nIgSraaTLPCvWmy/zsxdeVtRt4dy/fnUJcG3/3klfuzqIv5g6mciWynix
         dpLXgpfsI4WmAwcrFkmBI7oP58WUsFXyBSal4KGR6GagyfN398mDbfLdoG3YlIlBc5RL
         bOabj25fg6G1hDrM7xTnGI4xcQFxE/WOEf3YttGWAf/0Ib3yjT5DTHMAUX8+D46lGYNO
         aC/pWRlrZWrNEGB9DsCswNnOFFiEX9KgHFBzvpgh/PFM39BNrwqispFrjDFnOXtQAaWE
         FfaXmKPwn7yK6HKU2PcHcCplAYfWdgAWwLKMg5vqu0B9sG/gl2+VeZWvsDwY/NZnZ4Qp
         5NGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QAWyoIz7l7cO/96Ke+xJEn+FEmrcryaPuligPOYRf8g=;
        b=Wn+xtdTZ95+SPGZn9VHoKA0GQGzQePzppg30ZJjZ6LFx1gIdlWy7UwekjbQbrUkUHD
         qdcx0ueMQ0RYy1cdaHtBPllpK44G2xaz3yWqHi2TaohemBb+VtSM4w7w/dJeXunKif0/
         6dT5QVLiGxEs3OgM8YhiTiHD3L6IUGIUh7mtva20bhxuimgwlvhJXA3K6phPaB3JHBBd
         YK3hq2DmDvXROIy3sID/L6SbQo0csOqgAofvATGQsWLi4nzeKy4W7cHAqHJyx7Bw28zj
         L0OBnNi3jXCbua2kXyrp+MtSSbiANFbceC6AZyMQ4JYG+SpeXqKe9Be61RQ9Ee3Pdspq
         pwLA==
X-Gm-Message-State: APjAAAUZcEItmYJrUrfDt1DmT3jvKymLt8aHpzn/vXbtgr25DfuwItRY
	U7UBpf8yrbt48ZMVgUru+ZY=
X-Google-Smtp-Source: APXvYqwe748XSn2HUrBhXfIqvyCL6uUpZZcsJfOxM79rK2TsR2sRxYxfmUiRGnEWb19uo1l7c7S1Ww==
X-Received: by 2002:adf:e80e:: with SMTP id o14mr2403453wrm.212.1581346606418;
        Mon, 10 Feb 2020 06:56:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4141:: with SMTP id c1ls5211476wrq.8.gmail; Mon, 10 Feb
 2020 06:56:45 -0800 (PST)
X-Received: by 2002:a5d:6b82:: with SMTP id n2mr2559248wrx.153.1581346605813;
        Mon, 10 Feb 2020 06:56:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581346605; cv=none;
        d=google.com; s=arc-20160816;
        b=jktFlDwbeDFY5LeDzJzmUtvOMXg1u86hQK+06lAHjUj8EOfWrBiSIFNzUAZ36N8L0D
         5qtS60rqTZnhAY7CjdXqcqe9KYfeqP4YH5KB5U7VzXOh1vRjKwTQ7tCsaw0zA/WkNteb
         T9I2JgQXlvorpRSSgMfMmy1Pd8vXb0mbK4KBq4MN6nol/TrzMlOaSi02+Wnh0OKv++HP
         ArRWry8+E+7M2CGsjiKcbfmA1qAH0tlZfzcv5zXcsITq6a2qgBIG3Z0seCbWxhvTHe7M
         s0Qy4r5iM5BGY1GtvxUQQxyPQGyU6OWPllCuiKHGKRYNHKWgxVF1JDmt1wndawCaoUfI
         9C6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=AzV6vPSa86ml6UzbSmsHU+/6rSkAmcJ+1ZtL4VXaug0=;
        b=nR8ap++V3gAgj1ZiHW4XiqLJYgm/tQ9qH+DCFtnHQbW9VqWjTzhi1UXF+29dGaK1G5
         wmD5BLQg1yjaLPm2l9OiAz4M7PRSeAJjHOE+cgp61Lqw1NIw0df4hGTOAuDNDnrpzB5b
         ieMVD7CSkqsJEp+hLzcrWsw3Y01MhQHdPj6XtbwptNtsYYmfX2A+/sqhSvPFfjfyNN2n
         xkMlkaDi9fSVUpM3euNTLyX/HAqIpj3lGu1aZ0zFyCGvuh63Us8l1kgY6+JMWO4D0HjU
         4Zh9csqoADorawppQ3JKbNDKTDp8RDp9dyoqoZ4q1rXHG/cGV2ASZRvp4jIo2p9xzrdy
         NvVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UshsyR45;
       spf=pass (google.com: domain of 3lw9bxgukcqoov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3LW9BXgUKCQoov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id i18si25108wrn.0.2020.02.10.06.56.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Feb 2020 06:56:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 3lw9bxgukcqoov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id r1so1080684wrc.15
        for <kasan-dev@googlegroups.com>; Mon, 10 Feb 2020 06:56:45 -0800 (PST)
X-Received: by 2002:a5d:5647:: with SMTP id j7mr2378246wrw.265.1581346605196;
 Mon, 10 Feb 2020 06:56:45 -0800 (PST)
Date: Mon, 10 Feb 2020 15:56:39 +0100
Message-Id: <20200210145639.169712-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH] kcsan: Fix misreporting if concurrent races on same address
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UshsyR45;       spf=pass
 (google.com: domain of 3lw9bxgukcqoov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3LW9BXgUKCQoov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
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

If there are more than 3 threads racing on the same address, it can
happen that 'other_info' is populated not by the thread that consumed
the calling thread's watchpoint but by one of the others.

To avoid deadlock, we have to consume 'other_info' regardless. In case
we observe that we only have information about readers, we discard the
'other_info' and skip the report.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/report.c | 20 ++++++++++++++++++++
 1 file changed, 20 insertions(+)

diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 3bc590e6be7e3..e046dd26a2459 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -422,6 +422,26 @@ static bool prepare_report(unsigned long *flags, const volatile void *ptr,
 			return false;
 		}
 
+		access_type |= other_info.access_type;
+		if ((access_type & KCSAN_ACCESS_WRITE) == 0) {
+			/*
+			 * This is not the other_info from the thread that
+			 * consumed our watchpoint.
+			 *
+			 * There are concurrent races between more than 3
+			 * threads on the same address. The thread that set up
+			 * the watchpoint here was a read, as well as the one
+			 * that is currently in other_info.
+			 *
+			 * It's fine if we simply omit this report, since the
+			 * chances of one of the other reports including the
+			 * same info is high, as well as the chances that we
+			 * simply re-report the race again.
+			 */
+			release_report(flags, KCSAN_REPORT_RACE_SIGNAL);
+			return false;
+		}
+
 		/*
 		 * Matching & usable access in other_info: keep other_info_lock
 		 * locked, as this thread consumes it to print the full report;
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200210145639.169712-1-elver%40google.com.
