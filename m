Return-Path: <kasan-dev+bncBC7OD3FKWUERB5O5X6RAMGQEXEVHPCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 390FF6F33BD
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:55:19 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id ca18e2360f4ac-763bc8ac23asf151161939f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:55:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960118; cv=pass;
        d=google.com; s=arc-20160816;
        b=hPf5RG4RpdDIFQ3Fj6Mge+YSX1CHeZj8GDy2hHIPgSNI1Cf6hDUeGNJYIAEldb3Ucw
         UstrTo2FC7/5eTxK5ZS5zyDzSRGb3AWHQABLzT+C6gfI7Jok1OGemcdx+JK/XQnv2iIT
         tr3L+44RZTKxO79LVSkDE1d/Ef3SRNaAJt3kwfbUXDnIpwk4l+qHtkuAoGJ16IheWCzj
         HK9yIVhWdzum5nH3x2Zw5Ml4U6D5c3zMMFHpT1qq9oANIOTohR5560N6F2CwLYuOtBPM
         WmwTyX8T8bMgVpDMZzLSn2AHM6gG9/B910VL99wPmgVE9lcFVMoVfcmcxk/t1v28Y4h1
         Ar/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=nrDnDIi8TZ4cfgfEuH5agcTy0NFy0PTlj+9OgFFtqF4=;
        b=IkWRhdKoygf1Wr61GSL9jHKloK5sbyT/0StAldVlZT9DSFXZB76kIID9wTTwVcS0GX
         WUEnYw6MBDbIVN+TCcvc4hbWVGiMTEpK1MjNdV7hHBGzNYFavCk7oFkTIrI071VRDZ57
         XA0Rk3dlS4UbRQwZy5eC33n+9upmpTHFw0xy06Ai0Dk+q2yht2njbfZI6uGsIyAQlL4n
         PbjP6T1nVcIRGkGxIq7KNHbuMMM+OQ4+nDVpIdLHbcszuWlmiHWzbRruiVm4F6yf6Y3T
         P+HSdSQSjWElhyGKz+wA8IGnibiebheMYg1nkHkC+n6Fwo+8RdUP6vLlebM0dDl/p3yj
         qPHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=yKDBPh22;
       spf=pass (google.com: domain of 39o5pzaykctsprobkydlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=39O5PZAYKCTsprobkYdlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960118; x=1685552118;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=nrDnDIi8TZ4cfgfEuH5agcTy0NFy0PTlj+9OgFFtqF4=;
        b=TWfA8nKB6SSQcWN+zleM4RBKgodbUVG+VJtP4glJoi2je8k9ZI4S3dfKf7KhnmTw+U
         KXEBUk5LzH/C3PReUQntpEZ/UYcC4B1fieyFDas+Sgn+sk29Kz91a46iGtr3aKCtEhw4
         fqOKCQN0cdAkSSwznVqEmcBJC63osgPnTramP8SujG+vXOZn0j6A58xDI9pP7SiJnAC4
         X0liI+5i1nWXMz3nAA75nzZK//SGqAg2Kzk8Ad9AaF33U24k+PAJJQIM6sfMLyiZJcfO
         eivZUN7Hem/ls1j3UwSOaGSPM1n9oSPyHQqFq+2dJXdopw7ThX0Xdz+lbrwyEPZuCB8e
         mcXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960118; x=1685552118;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nrDnDIi8TZ4cfgfEuH5agcTy0NFy0PTlj+9OgFFtqF4=;
        b=lWSSlGYYUSL/jkrK3OP16Uf8QNE74sPJ8vK9BJ5wdOYWGaKCi04bf7DAKuXDmp/NLF
         ec/jfYQOt98u8BffZE5udnQcAMNBEHfdiWSmyKVcNpQHx4bB8pWll9JM2Ey04wOWUZwn
         Vs4uuYfF6KzyaWw3QpTwLwX6He7U7hBDjhOhMVHBeR2MVVHKS7aqweRaWmpKSBGYPYfH
         bGTWmkSUpEgN0qYES2aXe9r+MpWsDDHCV8de4gqgWJv7nlWU0xQkoq4ar7hWEM46qlFZ
         AeUdSykf1rvDkZW9WTXKiVwoCSg037X2gg3Wd7fuhfFK7D1SrhLNJ6c6si4zNZzxr+xn
         FMQg==
X-Gm-Message-State: AC+VfDzQIKVA6n6LIY3ElrCzsF/Uuk8AuhtfrXsuStNIGFS4JFldK25E
	7mdfy0xfoztkhuxfVoj7vBA=
X-Google-Smtp-Source: ACHHUZ6Mh7RW4bGdABvNwKnOTEFSw40Vyz1n6on/lauOBIc8aDMIbckLbtXKVSWtBKMi1cufhQUBZQ==
X-Received: by 2002:a02:3304:0:b0:40f:9ab9:c438 with SMTP id c4-20020a023304000000b0040f9ab9c438mr6161956jae.3.1682960118016;
        Mon, 01 May 2023 09:55:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d82:b0:317:97e2:9054 with SMTP id
 h2-20020a056e021d8200b0031797e29054ls3410151ila.4.-pod-prod-gmail; Mon, 01
 May 2023 09:55:17 -0700 (PDT)
X-Received: by 2002:a92:de0d:0:b0:326:3cff:dba9 with SMTP id x13-20020a92de0d000000b003263cffdba9mr10934218ilm.29.1682960117391;
        Mon, 01 May 2023 09:55:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960117; cv=none;
        d=google.com; s=arc-20160816;
        b=H1uNQqjkK3XDoDuXwSG40cZAgu9rJ4ysBlrnoUz8KJkKAVBUWO6zU9cqqg+J1q43x3
         bgBgfz2rHzI36vQRG1cJYm7iOwUyGV9mLT7Mb2xzVtoBkCK0a/eiM3HqXWcmANpI4b8/
         1G80HJnlLRsNXNZ6E+IUZy7DdWAxUVZaY8dieXp4F7FmMNGCmcVsAodNa/5HTWAnaH/q
         Ug/84/7QRBxZSNx1Bhv81Qi+M/ZO0lHJ1aSJA8p5yBLcpdiwCb02weQ/mokv9xzMvoWf
         ZgOh3LMFi7dQjTic8ZzH9FTbHb53TZ92FObrrkGtHlGMuDJV9OnVZHtM0Q1Nj7o5j0Jy
         skKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=MvglFAc23/TKNtr0bbBz1MPaCPYCHObzjBdGSdfY+dE=;
        b=pz5Oz0bhsfa+P9RIeBwHcMTFCUewAYOMrCIsBX13egVCbvzrNipAPW3sGfrRA4hEly
         iTmtlP9+MNCgEoWIklJF8BbFtmvpQU45fpDXjjSG/zpEKDmytdwEtxmGgqa14tLuBHj+
         zAEkWw079oo+KKf9qa3yhDjmldAoiTc9ZwrndNzvenO/tB1wUEVvU80STYHuYrRN+9O7
         0see2elvjNP/35yCoiMpX44u7PfwrTAmKHb3vr9LkEYhHI/ANMtBk41c/wESiNVIY9DZ
         yk4JPYoYZ0/2ksch6qskh2RaHOOJ+P1Mzn7lzMHfXXyh7g7BzL9VogztejwPh0Lylgpc
         IWMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=yKDBPh22;
       spf=pass (google.com: domain of 39o5pzaykctsprobkydlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=39O5PZAYKCTsprobkYdlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id az39-20020a05663841a700b0040f8a20c639si2028706jab.5.2023.05.01.09.55.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:55:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39o5pzaykctsprobkydlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-b9a7766d220so3264338276.2
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:55:17 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a25:c54f:0:b0:b8e:fbcb:d6ef with SMTP id
 v76-20020a25c54f000000b00b8efbcbd6efmr8806787ybe.4.1682960116894; Mon, 01 May
 2023 09:55:16 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:14 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-5-surenb@google.com>
Subject: [PATCH 04/40] nodemask: Split out include/linux/nodemask_types.h
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=yKDBPh22;       spf=pass
 (google.com: domain of 39o5pzaykctsprobkydlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=39O5PZAYKCTsprobkYdlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

From: Kent Overstreet <kent.overstreet@linux.dev>

sched.h, which defines task_struct, needs nodemask_t - but sched.h is a
frequently used header and ideally shouldn't be pulling in any more code
that it needs to.

This splits out nodemask_types.h which has the definition sched.h needs,
which will avoid a circular header dependency in the alloc tagging patch
series, and as a bonus should speed up kernel build times.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Cc: Ingo Molnar <mingo@redhat.com>
Cc: Peter Zijlstra <peterz@infradead.org>
---
 include/linux/nodemask.h       | 2 +-
 include/linux/nodemask_types.h | 9 +++++++++
 include/linux/sched.h          | 2 +-
 3 files changed, 11 insertions(+), 2 deletions(-)
 create mode 100644 include/linux/nodemask_types.h

diff --git a/include/linux/nodemask.h b/include/linux/nodemask.h
index bb0ee80526b2..fda37b6df274 100644
--- a/include/linux/nodemask.h
+++ b/include/linux/nodemask.h
@@ -93,10 +93,10 @@
 #include <linux/threads.h>
 #include <linux/bitmap.h>
 #include <linux/minmax.h>
+#include <linux/nodemask_types.h>
 #include <linux/numa.h>
 #include <linux/random.h>
 
-typedef struct { DECLARE_BITMAP(bits, MAX_NUMNODES); } nodemask_t;
 extern nodemask_t _unused_nodemask_arg_;
 
 /**
diff --git a/include/linux/nodemask_types.h b/include/linux/nodemask_types.h
new file mode 100644
index 000000000000..84c2f47c4237
--- /dev/null
+++ b/include/linux/nodemask_types.h
@@ -0,0 +1,9 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef __LINUX_NODEMASK_TYPES_H
+#define __LINUX_NODEMASK_TYPES_H
+
+#include <linux/numa.h>
+
+typedef struct { DECLARE_BITMAP(bits, MAX_NUMNODES); } nodemask_t;
+
+#endif /* __LINUX_NODEMASK_TYPES_H */
diff --git a/include/linux/sched.h b/include/linux/sched.h
index eed5d65b8d1f..35e7efdea2d9 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -20,7 +20,7 @@
 #include <linux/hrtimer.h>
 #include <linux/irqflags.h>
 #include <linux/seccomp.h>
-#include <linux/nodemask.h>
+#include <linux/nodemask_types.h>
 #include <linux/rcupdate.h>
 #include <linux/refcount.h>
 #include <linux/resource.h>
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-5-surenb%40google.com.
