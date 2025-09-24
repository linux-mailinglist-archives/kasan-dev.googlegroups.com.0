Return-Path: <kasan-dev+bncBD53XBUFWQDBB4FWZ7DAMGQEMRZKJSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 466B0B99AA9
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 13:52:18 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id ca18e2360f4ac-88760a9d5c6sf1484757839f.2
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 04:52:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758714736; cv=pass;
        d=google.com; s=arc-20240605;
        b=BQrrn0yvA5t0KSlKTcsTgf5+2cowTh8T+fhh0reS9qW5uHBR9nKKdekYUaLymJGanJ
         YxDSqIb5IQ15LUvU3JWRicKOMmt7UrrtOXFn591ByCZ5f3r07zo2JUQGSbNy6+dHveUt
         9k9blpew4Bvyy+e/xvGeOwYu/FWPRMjscLygf1rKfMsicEXZventu7crq+MA8xYbe4nu
         jO9hAqCio0kOJbdTMOTEuzHsipDelbgKbxayZ9KhGdu3FfnpJkEtFFw3CiB6/u5hJ5V2
         +bWD8Y7L7EunYwYDQ1avFNQmCf9jKDJKpKykK+iWn87P85wA7YX0ALGoZ25rRsF+DSog
         kukQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=1402O8BbwvfEabq7Fklt1qgycMP2yR76Crd3+IlnmFo=;
        fh=snmoaZ+WRKsbmUE3LDoeRqPYqLWzA0rnRrLh8N73R0U=;
        b=Tm6Vtqhf2qMw38WGfdyE2J/g2J7HB/hySOg1AdGiouAhf5xEiFzH+fLIYdQUmqKOeV
         tHWZ76u020/n68H+aLmht/6PBvNWiX8lFWKcUCtywhLAsAQK84C1sBey7np8CaMUrRjP
         LBFZzqhbXbMlgDGVZANCr9ciOC6RG/0GT4mR6eSNlqKk1YZ+H4QDbX2qycqcy8eteNd1
         tLSAOx1j+OBch+MHRVieAXRrMSlD/QvLXMdJqrZ7nsMpdyVs3xcnG3LqnU7iBI2frNUt
         LFyjr0pbwaIJITo9a2BxKBc623g9DsU6YYX04XBEoyQDRzwJS4yGao3aIZJOkIOPp56W
         cuOw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GaQigjgM;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758714736; x=1759319536; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1402O8BbwvfEabq7Fklt1qgycMP2yR76Crd3+IlnmFo=;
        b=YstxWg4G1Wzz7TbD003WFv0AuOshz6AGwjHNZLGWKMwd4cGTqxiIK6s8mgr/nuRb10
         4PxkMvJxUH5xGtk3qlDXUmNx/XECgL9elxP/GCLYBSmwEN7oc58UBglPKXFZMlkqx5tR
         Wpo9RL3YM70n/TnVJscOsAQmq6QyFB0rfNAZQwXUnbdVEsudLNPqMJPLk4STMTJnVoLJ
         hwBFcLNGY1CzxknGXozy8pPBDW66DRgs1y/upjF41fX3+QiU+IKQxtCh/KMEy9avXyLY
         IT8ued3VAdzyXzLmZreplrL4Gp3shYmrcpkQqpp2zHhvrNTUK4mCulHBaPni6ZvuirYH
         ZYrQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758714736; x=1759319536; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=1402O8BbwvfEabq7Fklt1qgycMP2yR76Crd3+IlnmFo=;
        b=U3/W8jk2XXi/1auAjacBwgRFY77AJOokWlZF1mvUCMn4RpDatXhhzyPEhhAoixYpWq
         HMahtH64fK0h6syUpX5N43C6MIJ24GFInsIoGsvJPHqsteIay3zIpT+iU894tnWfFpNd
         G6bZFk6zbFKVp4cdDbaFo/sreIQwMgzAOERJy8eXPsfbaA300KPIwNfbRetrIwy/NsZ4
         auVVtbV8c/g1KdBuEFMYLtiFOFE7yb5vS35BXjIjO8Mst5Vjhrcxese1pu7gyZSoCW+t
         0YHBK0uCdsO7ARSESxSsiu6Zxe4I3D97aey4LfoUCG7Kr0UFY+aTP/80B+evXDKQDbel
         Y3oA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758714736; x=1759319536;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1402O8BbwvfEabq7Fklt1qgycMP2yR76Crd3+IlnmFo=;
        b=WXpJmrn3B7d2UpdHcpf9d91ShcYQQTTyvIO1flXi+alWepB+dcvw5D2eAgm4mLgpp1
         xttrZ6NgnZH42zIGCmHYBo35DQ3U1AnHPiUNhkulo1447raHJ1Eh0Xmu1XNADko8oy93
         QYFYWGb/3u6az7Xju2h0N0yUA0pvFmQpXlgy+kwMgCHM/qLcbnRqWxXERaiAKHC9xT07
         cdIDeos39dQCHnCLZh1hNMWY6kcIzD+CiLKfizoW1WlELSg620yaOBf8iY0RdTGAI1qM
         6077SndliJFHwgdBJ4Gy5BbPBNRu7+cK40oPCPWcGf9oVpPX4xzuwLY0v0WMPudYdmmz
         3qPA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV1AZbJAx+lSRvJgTlCpqFxc06ufwx1lDJPC7/iB4z1zWf6uqizfkfzZxihDJd/pbuSnlID0Q==@lfdr.de
X-Gm-Message-State: AOJu0YxVz9wyBpkQndASg1BFNQmCluoddtlaKJ3v6WnHjDE3XY0X93n9
	YQt2rj0uFCNdYnxN+8+qleyVHoo2FeIH2kn+aDSCLy44DeIZqDgsGZh0
X-Google-Smtp-Source: AGHT+IHFW/hmFXhQhLRqDJf3AWdngp+ZSq6VSks3Pqa+MpNA/62UWxdXueJ7yOkuASnsKcf8UCPBjA==
X-Received: by 2002:a05:6e02:2165:b0:423:51e8:3694 with SMTP id e9e14a558f8ab-42581e1e3b5mr96523135ab.11.1758714736508;
        Wed, 24 Sep 2025 04:52:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5ag5V3vftJ1K3ylDztdKjiX0Cg3sRlUMBE34GMvJ4c/A==
Received: by 2002:a92:c5c6:0:b0:424:fc1:c420 with SMTP id e9e14a558f8ab-4244db36dc6ls59619705ab.2.-pod-prod-02-us;
 Wed, 24 Sep 2025 04:52:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXL+gwtGH8JN5bSXPtGNLYxHhvyeNCGLFRsmxqXxhP1jboNpxu/EoKjavJmVGllOsV0vHI7yZ+ggzM=@googlegroups.com
X-Received: by 2002:a05:6602:3424:b0:8e7:1242:9550 with SMTP id ca18e2360f4ac-8e712429f0bmr879195439f.15.1758714735666;
        Wed, 24 Sep 2025 04:52:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758714735; cv=none;
        d=google.com; s=arc-20240605;
        b=KHJ3+LXsBw6fP3C894Me0MzB2zvC7JWeXWKg91ZYCYXNemiNntnZsogl7DH9Kzc1bv
         sCLgNOp9NQYdTfRnh5Rlz6dk934d8EQVdlC83AcuJtw26XPzXKZtqySbTfr4RwKevmEy
         PaIEmVL+W10PvGDFphX3Spfa0UN5BpFshoS6sXtM/qJ664oWr1WIp3oW/p4NFDz2zTZU
         S5Hhh/FOCLp9cMuN3EIDzZm0WAjRO6vJpS09t+u8ZfO8XP6p904m+asOrK29HeTOeUrC
         +uct7GOOD92rIFM85+SRxYcfrOLcFzKxd/VHedPjxpgsuEhdzqXI2MQdY1N+PFr3xhHP
         GRww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=E4BKEfc9ax2ksTKKBAwbjubQHvBiDjA54WMJGQTptLg=;
        fh=KNMfIWh0jYrQbLEJBM11oAwunYkN55wHQsFTN9G3AHU=;
        b=QNwHupMpm3t3TQYCDRf2pxPVxuP4F6CR7z3KC432af+oNHhgtip1x08obRJ072/bZx
         E3+/DNBM9OsNpdjaL6NYp+qQTxhXVNdHeIx/QD2OJ1t5/Po8IVE8jQ1ro7Jj/MfPHy8X
         NSN/DeUuRee5aecB88W8gNh1Pt1qCOKf0yfMavt6rcbAb5Kt5PiCtGaPK+EdiRfv95Ik
         u1qo2BDkbpQT2QorHLy7fHPVcaA9QeX6UxxtMZZjUVu74C1bHReGcizYLSJTS/jy/dXn
         XsMRxQwDw3Nr1MsigIU44Qx/SA2WiSp4nwKVvvdK+RI1qBYF+1xY26DzOTs3hrVnCW2Z
         GORA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GaQigjgM;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x533.google.com (mail-pg1-x533.google.com. [2607:f8b0:4864:20::533])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-8a4560de689si82347439f.0.2025.09.24.04.52.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 04:52:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::533 as permitted sender) client-ip=2607:f8b0:4864:20::533;
Received: by mail-pg1-x533.google.com with SMTP id 41be03b00d2f7-b553412a19bso2685998a12.1
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 04:52:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX4sViyemy0y9VuYKbFlwBbKsQkhMz0Fk+UQr5Dxk6q1Vdrgrs4vkyLsH8amo/34fxyH3Oje4B28jc=@googlegroups.com
X-Gm-Gg: ASbGncvCgBGJv6AX2DkMjTQJXC3z4M7deiWDZ9FwcS7VAwVGGKV2vVz3n0OLcdLfLYe
	DmJzhJrmDNFyMM3sYXin92huaToA8UeSYUjnkejUmW3BoOJnFw3EqvLHq1znRxnnzZfZdn4d1Ae
	X592aNwInruUrbhq5AZYUEChppUcB9+4dzZfpTpgNpC59xqIo0tu3n18kHavF4F17/68BGq3xaG
	SNyezK7JRzBUaVxqmJb9ULkulqsMzyeqNQLSW1HKnOkFOSU2mqRO1G/ZrnUFWULezVasS+UVRbv
	95OkpwV7MdwEsaO1Ke1ZffsfHtiMDUtjg/uaHwy0nkkzLpAzR9NUEPtIUSdz0BpsrWNpYAVz1rc
	jhNV0rjMr8nq7GYLeFbr9AckiMg==
X-Received: by 2002:a17:903:8ce:b0:266:2e6b:f592 with SMTP id d9443c01a7336-27cc325ea9emr75331615ad.25.1758714734961;
        Wed, 24 Sep 2025 04:52:14 -0700 (PDT)
Received: from localhost ([23.142.224.65])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-27cc8b251f7sm49110575ad.8.2025.09.24.04.52.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 04:52:14 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Randy Dunlap <rdunlap@infradead.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>,
	Mel Gorman <mgorman@suse.de>,
	Valentin Schneider <vschneid@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Namhyung Kim <namhyung@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Ian Rogers <irogers@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	"Liang, Kan" <kan.liang@linux.intel.com>,
	David Hildenbrand <david@redhat.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Kees Cook <kees@kernel.org>,
	Alice Ryhl <aliceryhl@google.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Rong Xu <xur@google.com>,
	Naveen N Rao <naveen@kernel.org>,
	David Kaplan <david.kaplan@amd.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	Jinjie Ruan <ruanjinjie@huawei.com>,
	Nam Cao <namcao@linutronix.de>,
	workflows@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	"David S. Miller" <davem@davemloft.net>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	linux-trace-kernel@vger.kernel.org
Cc: Jinchao Wang <wangjinchao600@gmail.com>
Subject: [PATCH v5 11/23] sched: add per-task context
Date: Wed, 24 Sep 2025 19:50:54 +0800
Message-ID: <20250924115124.194940-12-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250924115124.194940-1-wangjinchao600@gmail.com>
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=GaQigjgM;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

Introduce struct ksw_ctx to enable lockless per-task state
tracking. This is required because KStackWatch operates in NMI context
(via kprobe handler) where traditional locking is unsafe.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 include/linux/kstackwatch_types.h | 14 ++++++++++++++
 include/linux/sched.h             |  5 +++++
 2 files changed, 19 insertions(+)
 create mode 100644 include/linux/kstackwatch_types.h

diff --git a/include/linux/kstackwatch_types.h b/include/linux/kstackwatch_types.h
new file mode 100644
index 000000000000..2b515c06a918
--- /dev/null
+++ b/include/linux/kstackwatch_types.h
@@ -0,0 +1,14 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef _LINUX_KSTACK_WATCH_TYPES_H
+#define _LINUX_KSTACK_WATCH_TYPES_H
+#include <linux/types.h>
+
+struct ksw_watchpoint;
+struct ksw_ctx {
+	struct ksw_watchpoint *wp;
+	ulong sp;
+	u16 depth;
+	u16 generation;
+};
+
+#endif /* _LINUX_KSTACK_WATCH_TYPES_H */
diff --git a/include/linux/sched.h b/include/linux/sched.h
index f8188b833350..6935ee51f855 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -22,6 +22,7 @@
 #include <linux/sem_types.h>
 #include <linux/shm.h>
 #include <linux/kmsan_types.h>
+#include <linux/kstackwatch_types.h>
 #include <linux/mutex_types.h>
 #include <linux/plist_types.h>
 #include <linux/hrtimer_types.h>
@@ -1481,6 +1482,10 @@ struct task_struct {
 	struct kmsan_ctx		kmsan_ctx;
 #endif
 
+#if IS_ENABLED(CONFIG_KSTACK_WATCH)
+	struct ksw_ctx		ksw_ctx;
+#endif
+
 #if IS_ENABLED(CONFIG_KUNIT)
 	struct kunit			*kunit_test;
 #endif
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924115124.194940-12-wangjinchao600%40gmail.com.
