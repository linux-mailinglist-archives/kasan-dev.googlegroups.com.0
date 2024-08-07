Return-Path: <kasan-dev+bncBC5OTC6XTQGRB4OEZO2QMGQE3XUWKTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id B62D5949DF8
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2024 04:56:50 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-39a29e7099dsf17909985ab.3
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Aug 2024 19:56:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722999409; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZZtTJqNQOD8MRRIHQbaRHzwD+Uy/uBAiZCWeF/3CHKxZWDLLSM2NPYPiNxsyYipoTg
         o/WjU0FFJnm05eyV2MNQey+JQcOWev/OlZIQIeUJYM9P4ru3wVtvnbBQQOT1awyCjyW0
         0U4ZZBm7rDo5sj2kS+8ydchC7mMHVj/rqmVyNN3KjRUUSDPUbwnqVdgAAODtOZ6a2sly
         1NR7lP3FcdDmS3nB+DGveiUifXmlbyzcSjCFGV+W1O1KfiG2mCD0T1Svfem0WOTWF+Ge
         ORlLIKQoVmZJJOfiyZrNqcfZHMXaYzYIcNJpt/wInH3K5y5qxJ6s5mkoa2ZdYF+/MITn
         fQPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=l3IQSmWHZVs3giJ7iK0BZ0LONH7OOGf/2sxKg8iLwHc=;
        fh=WBYRhmdu5325TfH7fwDhWIcM1cRRdZU27rf5TK+Oay0=;
        b=w151O1AsnoOX1W76rysDhN2c8fCcdhqRycmEl5F1DkO5ukrAw5SQX76Hbq+EKMNXJ0
         zAdDpTpPBfBN/iWPLG8PeMP/zfk8QI2sZZXkXkiuX+3lMwbL6CBlivig1Xoq5BbONvH7
         ZkeNvyEX5xjxsaUq6DwB+VBGJjQjFOdcrgVtlZvjWKBSkwAZZZHhU1hUybFi3aJC/YPu
         8A4NymAv1N4P6ULo7LRMTjymLt57isjX129ZLzOkthMBXLymePaK+g9f4oJZCkC1VcZ6
         886MpyPcq2aKo+NhGVJpvjRFgLs3VSRccQVn/ox/QKkBL+lVCGKSPSzMUaOlr1YL9rdw
         MqJA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RTkzg+9A;
       spf=pass (google.com: domain of qiwuchen55@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=qiwuchen55@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722999409; x=1723604209; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=l3IQSmWHZVs3giJ7iK0BZ0LONH7OOGf/2sxKg8iLwHc=;
        b=a7OGjfGDdUcl4R1cwlOBI3SQV7VGhEVkaI/3FS3hGVebJD6JuLkkjgawFOZ7dhicFW
         Jr5Ic2o1EtBuIP+0JK5m5ButzwNe4dEV6YvyDT8bleBukDUFI9ecEqIQ6oKLOk+2Rga5
         r2+i49KLqeCXg2jE3vZ+F4npZM2BieL33huSfxIFsAo4f9g3KGGI98T81Iye273dNNNv
         d3bwjFWqgZYiO0EdBb+weswOzshLjFCDn3J5KxvaKZ8VlpNf/JRgVxussKJMXrQLKexg
         WFbcfATIBqiDHjqmgTh0NeDs5fqXHyHK+TREB04p2OHZKTShmfwI349nlx3X4zzGcPwu
         FKDw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722999409; x=1723604209; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=l3IQSmWHZVs3giJ7iK0BZ0LONH7OOGf/2sxKg8iLwHc=;
        b=I1bw8+WuyvwczEi0opnHKOOWi7zD+xu0NW3b3Ll/FrBhTKmZ+PbIZzsg/5e3leRovH
         fIXN43WCC1DUC01hFkjv70cx0CRXCCZNtAdu1NPizK1XcIsM14MAlmcMWEvPkDqgC53F
         NuOOgsGz5LLfcpKUDsZbgs1hOpWFuwiVrASBaZJz0QNEEoqRtWdJcK9qcQxNNQgV0ksL
         24pFOqHcc2GKBxrJVzbaCEC2nXx40scJa7TucF2j90LNZi0BZxEnNt4cAXr8R/RJViJj
         +7l2NFRXQWfUkZIlJcvMz0sdbjd+JWKPfpeSrORWTfuqHtgu/pjG2qprnlRdLW2C4hVX
         Pg3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722999409; x=1723604209;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=l3IQSmWHZVs3giJ7iK0BZ0LONH7OOGf/2sxKg8iLwHc=;
        b=Ax8SV/yTf2cp/OTwXApiPfjcMz989Dwg0qY7lAqkmwgFPjQbXRRPztQmIMm6LpfhDc
         tdOMN++dr36/VIu56X+rU+fv3/FTy9o4MEWnW8Mi6rVVYWpmir6fQpA43t77FXx9Bq4S
         VhuhmEMVZfAg8g6Z6121ujpDcgSWgNmAkFIal3UsbJVeRwEivTNB7QsKoYqMRERyNaiH
         fF7goeXSLk2E/T3zPu9RNoRU3qe3bhDyO+iGH+NtmndB3WMG43rWM4EVLWl7w4iPnhFd
         DW5VzvIFlNTYHptKOmgJbjH1OOaYShW9SePsO/gmCgVYqruAHsqEURCkiuC9Dkos2cvl
         VNSA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWscBuhSKHF6OohyWLyvIl5eyfC4MsoPV5YA89vjiYvHFafS40sigQ+PjShqMs3wPVc5czplxmaaOQbq2ty2L2tSytFUt0r2g==
X-Gm-Message-State: AOJu0YxvmmHlglelw9EnMT7kHzkiGn9j3ZOWEacsacXaD30A0ggEU3uE
	SyKTf3FmEbocmZmVkrwrUBAd5COKRAncgpLREr0eHoZHmRPpxL4z
X-Google-Smtp-Source: AGHT+IFHvDQFAuyOAvCX/OBL8WpJ8flt4zE/qxEk+oB2w0p9a1yBSrWm7gg8cqKQD1KheUGvCyMrVQ==
X-Received: by 2002:a92:c683:0:b0:376:3e9c:d9a8 with SMTP id e9e14a558f8ab-39b1fb6bb1dmr177814605ab.9.1722999409299;
        Tue, 06 Aug 2024 19:56:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:8ed:b0:39a:f263:546d with SMTP id
 e9e14a558f8ab-39b29ee095els32644525ab.2.-pod-prod-01-us; Tue, 06 Aug 2024
 19:56:48 -0700 (PDT)
X-Received: by 2002:a05:6602:6019:b0:81f:a447:632d with SMTP id ca18e2360f4ac-81fd4374539mr2221298939f.9.1722999407998;
        Tue, 06 Aug 2024 19:56:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722999407; cv=none;
        d=google.com; s=arc-20160816;
        b=l2e+JPAWwHAhx5p54+jPAmZbFvdyz2RswohJz2YpHvwt+IAiVEzVlQXaV8KAIN+7c8
         t06MElpFzSDd6CdD3igyF0btfwYJyeVdtIMGPfGqyE2HG7lmAYz1t0EAHseKsTAomqgX
         N3+e66X6dbYd95h4X2zfBKqWBskJFcLZXYSgSKVHmXtPL0WfLQAIbrkV7e2kLPHItqt1
         kpC4Xc9No/mmimagscQfJAYSmy3lfhEu3uj1uzxItaLINF4fO9L7rrcNg8s651gPNzc8
         Rch8SeFRG1jkkb4E8URQW1satsM8G4GSaHK4aCrJfqDfO9KtiPkfdgab5GQ3E1hD+VJg
         7GRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=hC9LOzC4g2aywRQd/yOVSGI6hrjrTT7t8qrshL0eQlE=;
        fh=f4XqgVN2dluRiU6o+2ZPhfTZPiSz37MITivt+N9r4FY=;
        b=MQTMlgtRN69n524oVpOgOVNWcvzGv6ocAkU2SDy79PWItOr8EAJJh9unZCZhbU7ixx
         sSbtE+kcX3E/cGEb5cgib2Xey0wVRjqqVaji1yEr6f6Cc9a3TCrlnwFKoMHU7ykcURJC
         YBoZwZZoDQKXwoJcNXOqb759CTz/C8HSH0Feg+eKlS5cxsfbQg20MHSzEo41Tl7lK/i1
         vExZ3zlQMp5sB5M86ji5xgkGzVwE8dS1+ti0F5zRq5rT0pApsqeq3w9CmS3ygukkcE1j
         uBHRw3vTihOQ29UASVls+pWvjNZzmWoA4qvEVwF1/Ilu7Qyyey80gf/vTCNFHC9CVAMc
         xILA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RTkzg+9A;
       spf=pass (google.com: domain of qiwuchen55@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=qiwuchen55@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x433.google.com (mail-pf1-x433.google.com. [2607:f8b0:4864:20::433])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4c8d6a3c2d8si409555173.5.2024.08.06.19.56.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 06 Aug 2024 19:56:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of qiwuchen55@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) client-ip=2607:f8b0:4864:20::433;
Received: by mail-pf1-x433.google.com with SMTP id d2e1a72fcca58-7104f93a20eso1027965b3a.1
        for <kasan-dev@googlegroups.com>; Tue, 06 Aug 2024 19:56:47 -0700 (PDT)
X-Received: by 2002:a05:6a00:2445:b0:704:1c78:4f8a with SMTP id d2e1a72fcca58-7106d047487mr17311651b3a.21.1722999407287;
        Tue, 06 Aug 2024 19:56:47 -0700 (PDT)
Received: from localhost ([107.155.12.245])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7106ec40f5asm7575964b3a.51.2024.08.06.19.56.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 06 Aug 2024 19:56:46 -0700 (PDT)
From: "qiwu.chen" <qiwuchen55@gmail.com>
To: elver@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	"qiwu.chen" <qiwu.chen@transsion.com>
Subject: [PATCH v2] mm: kfence: print the elapsed time for allocated/freed track
Date: Wed,  7 Aug 2024 10:56:27 +0800
Message-Id: <20240807025627.37419-1-qiwu.chen@transsion.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: qiwuchen55@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=RTkzg+9A;       spf=pass
 (google.com: domain of qiwuchen55@gmail.com designates 2607:f8b0:4864:20::433
 as permitted sender) smtp.mailfrom=qiwuchen55@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Print the elapsed time for the allocated or freed track,
which can be useful in some debugging scenarios.

Signed-off-by: qiwu.chen <qiwu.chen@transsion.com>
---
 mm/kfence/report.c | 8 ++++++--
 1 file changed, 6 insertions(+), 2 deletions(-)

diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index c509aed326ce..73a6fe42845a 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -16,6 +16,7 @@
 #include <linux/sprintf.h>
 #include <linux/stacktrace.h>
 #include <linux/string.h>
+#include <linux/sched/clock.h>
 #include <trace/events/error_report.h>
 
 #include <asm/kfence.h>
@@ -108,11 +109,14 @@ static void kfence_print_stack(struct seq_file *seq, const struct kfence_metadat
 	const struct kfence_track *track = show_alloc ? &meta->alloc_track : &meta->free_track;
 	u64 ts_sec = track->ts_nsec;
 	unsigned long rem_nsec = do_div(ts_sec, NSEC_PER_SEC);
+	u64 interval_nsec = local_clock() - meta->alloc_track.ts_nsec;
+	unsigned long rem_interval_nsec = do_div(interval_nsec, NSEC_PER_SEC);
 
 	/* Timestamp matches printk timestamp format. */
-	seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus:\n",
+	seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus (%lu.%06lus ago):\n",
 		       show_alloc ? "allocated" : "freed", track->pid,
-		       track->cpu, (unsigned long)ts_sec, rem_nsec / 1000);
+		       track->cpu, (unsigned long)ts_sec, rem_nsec / 1000,
+		       (unsigned long)interval_nsec, rem_interval_nsec / 1000);
 
 	if (track->num_stack_entries) {
 		/* Skip allocation/free internals stack. */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240807025627.37419-1-qiwu.chen%40transsion.com.
