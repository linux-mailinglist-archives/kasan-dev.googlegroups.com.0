Return-Path: <kasan-dev+bncBC5OTC6XTQGRBUPEXC2QMGQELQMO6DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 875789469E0
	for <lists+kasan-dev@lfdr.de>; Sat,  3 Aug 2024 15:36:19 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-70d14709555sf8096271b3a.2
        for <lists+kasan-dev@lfdr.de>; Sat, 03 Aug 2024 06:36:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722692178; cv=pass;
        d=google.com; s=arc-20160816;
        b=pxeoC2BPKEyXaVbR3A1jf5n7gZPoBEacw6X6Z/8hkBZOdMmgibFA1p1Z75QyeWRDyg
         lUOl7pc85vNrxwQypuhl7pDAEheG2SeDHkqm75gXwTgcjQFoHAUNR+befh677QDQ50Jc
         B+tE763wEtf5CE5TV4kClAeQkpfSeambykqSruVkHN/bNExTJseGPp1Tpv+kxff+gFBd
         ipB8o9nFtj/GAkPV2Vgw7aT+D117M6Sy+PqhChKe/RbIgRtZ5cT4XGNj+FNrMI6imryg
         SSHiwuMniWA69+4yemtqSugArIO0wkDGQQ5xsYVhVesv+/2GQw/vnXk2y5c2YwNBc2nL
         E//g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=lxmM6KMTPzzMmh3VQqPcW1LFR++lPrxPXjuU2jtUdSs=;
        fh=I7DGIH7QfgOcgH1dS0UydJbiMBq/Wu6E9ojqdaE7KFU=;
        b=aNdN0meOVoVYuAMSFEfiX4f31KwPqjh5iYUxnQfJUbCCACktiyvq5+GwaavBmG0pNJ
         7ihq7IiFxU9HIKf1UTsr0GD1MadME0VwYzmjTLIcol6LzjtKGQrKqan85f+7+Yp5uowT
         u43jCkcN1Ena3trwrtFl5e0gsmaGq8GhWeHPzjfPyU+R5U5MpYgnsTDZ7NDjCmFPQpMz
         6BXwt+GfKSx1LmPkqClfX58NTEcPi4jwpROsy1saexICK81GTDsBKeHZM5+vlKYcC+0D
         apbUXZzSdbnyg90yfDYxS0kQu5Mt34osfzt29R75jc7lCAMWSLf2qX/tLThUf52WyWTe
         HO8g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lu0hv3+X;
       spf=pass (google.com: domain of qiwuchen55@gmail.com designates 2001:4860:4864:20::2a as permitted sender) smtp.mailfrom=qiwuchen55@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722692178; x=1723296978; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:date:subject:cc:to:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=lxmM6KMTPzzMmh3VQqPcW1LFR++lPrxPXjuU2jtUdSs=;
        b=CD8aGUrNXMIl8W59jrJzx3HKtajYrup+A8XjS6fz1r66/ZQn9mcCyEl2qSeSWz1v6b
         jkNVRshUajBwM306r0/LvzL8PYEmY9VQgCixgAG4rnUTX9bvhMp9q857vX88b+ss/6iI
         jOO7YwcCUt5E6mXa4LWM69VGdNyuhyfYrZKB8f+0Hn/LDsr0UT8qDtUX8aiazs0ypRTq
         x7u8dF6w4GlBcAOXp56m5YmrUY/X49jNdQPjHluDV5+05jJ1CCjfinr7zuR2NR0jvdz0
         mTKBU5U5tHZsY8Ou0YvryWcQjOlYJoQD9w1Uo/Cctr4n6nL3hAo2jlcaVTLfb5mFNIAs
         XS3w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722692178; x=1723296978; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:date:subject:cc:to:from:mime-version
         :from:to:cc:subject:date:message-id:reply-to;
        bh=lxmM6KMTPzzMmh3VQqPcW1LFR++lPrxPXjuU2jtUdSs=;
        b=AYn3sFyn4h+M5w/mUzURG08T4lPivkunyoZfAoFcphGy7nRN8wYrV0kVaUg+sDeyZH
         J2IwRUllpEe0vR+HyMYH+aEo65B1J/YGmDC269y3SnTh0ebgO6F++CYdegozsRJSrYf/
         d6le1679oXsKAH++IJtFu9C/0on0PUQqFPjNtRaqU/zthUqD6cu+6CGTGBaWzxYu83G1
         0K6ZEv4rBd/AGrim9uODsqi/1Onkvl5KX4iFLRn3IbGsHTpu8nyKeqwrd5GwICFRhV/a
         ftny7iKeBZIsra0ZFTvSQaUmV117xohnGmVRzinvEracg/WZ9VUFPnDPZHG+m08A0oEY
         4d+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722692178; x=1723296978;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id:date
         :subject:cc:to:from:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=lxmM6KMTPzzMmh3VQqPcW1LFR++lPrxPXjuU2jtUdSs=;
        b=gjkrxQbNRjq/2MXawIpgBSFgxrMZqS6IIN6YVX6JNIHpBpX/8kMoJSurBpKYprwNiy
         F+sPWUoailSq7f1+AXCPoIgUwRw9YDHef3/XCdj/6GMF6+0UdfUSTAg/a2Q70raVAL4g
         On0ya014xy+3HLBsEY+PUdWHSt0iMSIyXYH2RgkDpjAFb0n6tJtnAew+K+I/yZtR8bMU
         qY1/zjvfhNwTdgCL+3idVGNVBAm+evVHUJlqZeQTpu5lwjCSOt37eHynE5eAG1H298R3
         8v8DLxY22a9hcqvV5yua/Pfekasag+6icS8wCCNqWKIdeNeHyhVRWULTxgNEWNVtKp/e
         a3Yw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXUGbj8nWvjz10CzWTuCn4xURwghWgqXklBXqv8Ok0sfrppO2CSukWIcZv5zRqidN5CpYp4hJTdxSWV+wzRXQ91kdJppjYbog==
X-Gm-Message-State: AOJu0YxlMjWb3JKXhXpXAlkZffedx48KJh5m6qiuggW4kjYp2BsbA8Mt
	vPcka9Uy0JUAJbqchef6c6y4JYgvVKr+UF16sll65fKBw6wzCdID
X-Google-Smtp-Source: AGHT+IFpi+U79QvzkcpXSyQZFWX9U0OzAm6EcQ/Fqccn87MVQdwLhlSbcQtVqaMVBC5mvTmneJJjUw==
X-Received: by 2002:a05:6a20:6597:b0:1c2:a722:92b2 with SMTP id adf61e73a8af0-1c69968aee7mr5830670637.45.1722692177512;
        Sat, 03 Aug 2024 06:36:17 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:7349:b0:2c7:e17f:422b with SMTP id
 98e67ed59e1d1-2d00cefa0b3ls414068a91.0.-pod-prod-09-us; Sat, 03 Aug 2024
 06:36:16 -0700 (PDT)
X-Received: by 2002:a05:6a20:c90c:b0:1c4:c1cd:a29d with SMTP id adf61e73a8af0-1c6995ab267mr7362550637.28.1722692176305;
        Sat, 03 Aug 2024 06:36:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722692176; cv=none;
        d=google.com; s=arc-20160816;
        b=JBtU6CdTE8tHi+TSNIqW83tmijx90IjDcrtiFMmvNSZzEGQeGgK3yyvAlmbqZEMLgO
         cqMoJ0vMW1ZfnlHmilz8WaV+CnCra9O2iy75QD9CJeK+O08SEAR5k4z7CyMsCLGiM++z
         xMXwuTQz9+OwB3wSvJ0xb58hnD6TvJ/URB28Yup7S7IFgou/VZ9Mpn6R7TejYfwrDhoh
         TgIG8XPgIw3dSVdPxNNVIh2f83bwzmbI48BsZKC2+EIgiW5+MsCHd1O47mNzI95GKIrD
         YFNho1G5FFcP+1/dfOX6/NOugwfFjLlk4da6TuJy+s6OhY8nwD4GNnGUh4nBugTPAm+z
         w10A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from:dkim-signature;
        bh=/76okRFWOXJC7JJ9KQhVHqF3l6rzQxaPyzz3y9bru5Y=;
        fh=Irf29MxZMCG+lWeS/HhO+jbUZZu16HcSTkZ7U8LMRH0=;
        b=Ts01hyVPHk6qDS/abBxcDC3+tGvqBZGF20oUyPgF/iCztcNhrE516wcOCiw5pcplUT
         pMu+6VYwlfYrLQf90cYo8FCQW/mGmwYkReishwhgNhHD46I2PNShlnpIecqLFTotag+G
         E6lflc3P90UD4jAvuBO/RMqwcV915qwJv/dt2ujkCSTdXsNbTjkQ54YS9OIpj2hLKooV
         gJOUHC7o6WgTEqGfR5KBt0OGW8uMBK8zm+bR3TmkwtIr0A4bXD/jcn0/6Wyi6GmtNGMq
         7CDaHjShqWjqz/1jH54oVNqfCR427hqKDcqVpT92dJ4aMB/qNf5S0soP8HbXZtqH0HqB
         T+yQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lu0hv3+X;
       spf=pass (google.com: domain of qiwuchen55@gmail.com designates 2001:4860:4864:20::2a as permitted sender) smtp.mailfrom=qiwuchen55@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-oa1-x2a.google.com (mail-oa1-x2a.google.com. [2001:4860:4864:20::2a])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2cffaf7ba08si186214a91.1.2024.08.03.06.36.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 03 Aug 2024 06:36:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of qiwuchen55@gmail.com designates 2001:4860:4864:20::2a as permitted sender) client-ip=2001:4860:4864:20::2a;
Received: by mail-oa1-x2a.google.com with SMTP id 586e51a60fabf-261e543ef35so5098414fac.3
        for <kasan-dev@googlegroups.com>; Sat, 03 Aug 2024 06:36:16 -0700 (PDT)
X-Received: by 2002:a05:6871:3325:b0:261:218:dae with SMTP id 586e51a60fabf-26891ea8f86mr8392010fac.33.1722692175477;
        Sat, 03 Aug 2024 06:36:15 -0700 (PDT)
Received: from localhost ([183.226.244.186])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7106ec4169csm2775658b3a.64.2024.08.03.06.36.14
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 03 Aug 2024 06:36:15 -0700 (PDT)
From: Qiwu Chen <qiwuchen55@gmail.com>
To: glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	"qiwu.chen" <qiwu.chen@transsion.com>
Subject: [PATCH] mm: kfence: print the age time for alloacted objectes to trace memleak
Date: Sat,  3 Aug 2024 06:36:08 -0700
Message-Id: <20240803133608.2124-1-chenqiwu@xiaomi.com>
X-Mailer: git-send-email 2.17.1
X-Original-Sender: qiwuchen55@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=lu0hv3+X;       spf=pass
 (google.com: domain of qiwuchen55@gmail.com designates 2001:4860:4864:20::2a
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

From: "qiwu.chen" <qiwu.chen@transsion.com>

For a convienince of tracing slab object leak, print the age time for
alloacted objectes in kfence_print_stack().

Signed-off-by: qiwu.chen <qiwu.chen@transsion.com>
---
 mm/kfence/report.c | 14 ++++++++++++--
 1 file changed, 12 insertions(+), 2 deletions(-)

diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index c509aed326ce..44c3f82b25a8 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -16,6 +16,7 @@
 #include <linux/sprintf.h>
 #include <linux/stacktrace.h>
 #include <linux/string.h>
+#include <linux/sched/clock.h>
 #include <trace/events/error_report.h>
 
 #include <asm/kfence.h>
@@ -110,9 +111,18 @@ static void kfence_print_stack(struct seq_file *seq, const struct kfence_metadat
 	unsigned long rem_nsec = do_div(ts_sec, NSEC_PER_SEC);
 
 	/* Timestamp matches printk timestamp format. */
-	seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus:\n",
+	if (meta->state == KFENCE_OBJECT_ALLOCATED) {
+		u64 interval_nsec = local_clock() - meta->alloc_track.ts_nsec;
+		unsigned long rem_interval_nsec = do_div(interval_nsec, NSEC_PER_SEC);
+
+		seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus (age: %lu.%06lus):\n",
 		       show_alloc ? "allocated" : "freed", track->pid,
-		       track->cpu, (unsigned long)ts_sec, rem_nsec / 1000);
+		       track->cpu, (unsigned long)ts_sec, rem_nsec / 1000,
+			   (unsigned long)interval_nsec, rem_interval_nsec / 1000);
+	} else
+		seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus:\n",
+				   show_alloc ? "allocated" : "freed", track->pid,
+				   track->cpu, (unsigned long)ts_sec, rem_nsec / 1000);
 
 	if (track->num_stack_entries) {
 		/* Skip allocation/free internals stack. */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240803133608.2124-1-chenqiwu%40xiaomi.com.
