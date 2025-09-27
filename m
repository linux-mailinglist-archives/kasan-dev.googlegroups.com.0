Return-Path: <kasan-dev+bncBD5MD3MG34LRBV5W33DAMGQEMBW45MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5DE1BBA5A8F
	for <lists+kasan-dev@lfdr.de>; Sat, 27 Sep 2025 10:07:53 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-42594b7f2ddsf43268885ab.2
        for <lists+kasan-dev@lfdr.de>; Sat, 27 Sep 2025 01:07:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758960472; cv=pass;
        d=google.com; s=arc-20240605;
        b=FvySH0FsQuBHpgvObgGl+ZjSQscZViCDqCYj12lptNMkjwXAhahanBw4U8RpVWzgan
         isTLJaL2B6N7PqtrfQym29mWoXBhdEXyzvgs8fSlVMsGUuu6a3Lupf+Rb8/Do78QWJHS
         hmReHzqdbYRok9s/3dBzdLRKmBhtL3GNhemAiTxQmk+GQNrpD2EghZPGagvopNxBiUPL
         cmHHA2SdoFXOe/us4qLPZq4PjVuZJPuE0Y5R+h5oYnLCFbWqP0MQH18Xt+r0BPWWQdTl
         PMHJs+XAibDPAU8Xbazxj/zRzajroHx6G7ZPBpucR1qO4OM0R6OumdPmxHSpTi+F9oT2
         ZnqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=MPU2QR5fCerc+i1tlzkEDRj7s7aJiDrgE0wno7H5384=;
        fh=BN8nQZQBTTftfOzWv/+/CPpGlD/kN091t7gTouycN5I=;
        b=exTtUIHgChE2VW6J7oKvFOjgv47za8OPIEvDvs7/NgeI+MaUt7Wewsi/RsUoao4CD5
         TGMSxpMpq+Kw5Mdz+aYZ/lkUd0jutY+PHA9BqO6wRlC/mqJGab2Jua+clD4s6DYWvuu6
         VAbogr0d9kEpUGXuqd5d8vKIoq+UYwbKBwtpzaxifKrjkAPq+hS0rtZCtPqYVHeZcl8y
         QcbUOF7FcaBZArfDIr0y4Urg3ZpALQCoM2ldPahxQUXtJUKBc79wxTjt3Ay/2Ip3MJfh
         WD0gW6vmweJ4EfnnukFN2q90cqkN5SaZfK0X8YgNcczD8dzX9m7Y+Oi7QzoObucMVF51
         J1Bg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=P9ReA4Yp;
       spf=pass (google.com: domain of jianyungao89@gmail.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=jianyungao89@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758960472; x=1759565272; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MPU2QR5fCerc+i1tlzkEDRj7s7aJiDrgE0wno7H5384=;
        b=L34Gla89zMfE7C25T8b1+63+MM7Cre+AZsIgNJTbk8saY9e0eD9NY7IuURqGEikSc3
         MkS98I4zuSreB33DW0orKDThcSN9coAXuZeGCEay5SGPqeVbV2t5DKjJ9/vFxLplyhpN
         MIqZ1IBPtunnDkbtiqT5+3NYoY3PyuGEvbLuZVUmn4EoW+w8GHULjsCMeuaJNvKc2uGT
         TZcPyMPaTrZezZBMKSmLnGDlvfLwpcDL9erKrqaypDdptd0O/B+T0lUbnHU0QbTyWGaF
         /O7O6+8yYNR+eXfCpMB7U4wHbM/D6VjMXtz/19SzEPD+N8NsfJYLC9ZMQcxapOkLd1Ma
         w3Nw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758960472; x=1759565272; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=MPU2QR5fCerc+i1tlzkEDRj7s7aJiDrgE0wno7H5384=;
        b=aEhA3JByFbXCEaJz4I2FIaIHyvydy1BYYDxFJpqGV2VRCrAA44SJhRVKJ7dLkKXDam
         nYCZwSJP3R552F0elFnuD/oBaDTjlatwUXrEwrWWHDEz2Pj//P2VbWIsrPVSXlL66+9b
         iAqjuBf/c852xbdXrUSHFqxcUBduVVC2xPcmVsPsC1hvofwpEpPeNyaXUew/6jlpsixk
         cVSi2CV/iqKK804udAO06LtAFeCnbziwWsA5bG74txODSCH7tQscGIQSZnAbcz6thp5C
         boaRBFgz7V9ckWJ8Moi5PlrW6sbfMjaLdEs7FSGkT/TfoADXViCqnLF38WPDrq6HJE+9
         2g4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758960472; x=1759565272;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MPU2QR5fCerc+i1tlzkEDRj7s7aJiDrgE0wno7H5384=;
        b=KdDb4fCCqCguBrYKY1KkZkguwgopFF4UvfAomozNuw8Dx9bd3nMbVSVM+wQS5h2t0t
         rUFxrftdNl3V2+uStzunw0fgFKzVDvarUSCFIedxw0iVVGUnjxxylvoZytqTM5IDQgPu
         mkspPLO8RU+Yrt58V5v1Ig+32aVJq65eB8nyTYX8iMiCg3kx/ew5e57fm8AKKWmhZMDY
         RHh38hXots56n1hjFPOTGaaPyRI9qHh+oPIGYyXxaqPZWBcxMYoKyi1jzaoYW77WxusU
         0cPBGhDXSve3BR9zI/CLGsEV6Juc4SNUYjJV8OZjbox7jdi2CXrfY7OBJtD67dzrcMiX
         02Lg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW7MBLC7rwscQoAi7OE1Frck0gc4ysaC682HVECxtg9wscAEN1/uTeY+ZR8NPPPzmW4QRqXUw==@lfdr.de
X-Gm-Message-State: AOJu0Yxr2VWtleEEs3zll/cnXTvalEkPNqElYKUpucuKYBtLd9x8fn9R
	k4NXbxR4jCta1z8LrK+lxIs4sgM2iYjyoItAaWwwaUKoG4dU9qcqncFV
X-Google-Smtp-Source: AGHT+IEydmql6mMVsxBiDMvUlYZ+SDVng50o+Ol2BUiK24OxAmeOT79b1BBw08IhU8NgtHfIaKJTaw==
X-Received: by 2002:a05:6e02:218f:b0:424:b862:8329 with SMTP id e9e14a558f8ab-425955cc9a8mr159650045ab.6.1758960471709;
        Sat, 27 Sep 2025 01:07:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6B5/mLeeG7DB/huwsA52c220mNcTHozIIXwHu/094lTw=="
Received: by 2002:a05:6e02:4610:b0:423:f3d2:2352 with SMTP id
 e9e14a558f8ab-425955b0cd1ls21655175ab.0.-pod-prod-04-us; Sat, 27 Sep 2025
 01:07:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUIla+mQGO306Tgms9wms2AZpk0h5BxU0KM1m1I7sD+4CyThWPWHJeQxl2LEsJWbfTYjhIoq7DpAGY=@googlegroups.com
X-Received: by 2002:a05:6602:6081:b0:90e:3639:26bd with SMTP id ca18e2360f4ac-90e36392718mr1001504839f.3.1758960470866;
        Sat, 27 Sep 2025 01:07:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758960470; cv=none;
        d=google.com; s=arc-20240605;
        b=VieSgJx+lWcLq+H1X6gbvGIBPti2pZ+37UXi4smPLc6+p+dvkc82P5Xmc2lm1G9xGS
         m8K3fywqQBfqSsYKozNwLkEiO84dB1E0eyaiMVh3hr3FvG25zwMVw7/gv+iATbGRSEKb
         GbW0J91GVVn4jwJ1h3amX1UCzPZQA5S/VD3upds9k1khG0QFiIybqGSfUMARnYj4fsL0
         do8jiEtexuDmyzOJUdnw+zeWgzdYOJxCJAi4xD7sPIN/NzJ1j5cyDZuwu8GzVWc41sEP
         fktNa1wcpgn7gHciqbsS3JWZfPZ+guAM2zEdjR4BMwI/T4gth5HJWXc1wcltH6OEVSNa
         awsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=2pnX7Z7v528RTOngSyYskOdERrXRUZlzBZkjWOik6R8=;
        fh=CDGw+FWukvrHYVbHQmkrjrfwIVpF8qh/Gi0i+KggjAg=;
        b=IMquEAij2JlRmC+5UeyPthmRFofHNh5bk/pMW9r53eGKUr7ydrP6+9lWrJB51bn0AX
         d0wzUQJhuLbkIJnCuKHTaExB0HgmnL5Up9R9ilsjwYRyH2UQFCy5GrWDW+8Clvrt5KGj
         1fuQsDeb2tp2cfScK0pPeaRBYcAZ0P8Qu3YJYlajb/jPvEDWcDzpA30sLpS3nSEYdVjC
         IsgcRN/5z9US/90GIC9OlLgiXFG9fXO9KzgM0ofsOvCPEydCTnWEp3jzYwn3bQPi6TLx
         kZl60V1+bv/VywGAidg3uPxCynA5dQUHGuPOcuV24Kact44y01JIiUw989SkcN12g++9
         EElg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=P9ReA4Yp;
       spf=pass (google.com: domain of jianyungao89@gmail.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=jianyungao89@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-9040a31f0d2si31701439f.3.2025.09.27.01.07.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 27 Sep 2025 01:07:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of jianyungao89@gmail.com designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id d2e1a72fcca58-7811a02316bso1071534b3a.3
        for <kasan-dev@googlegroups.com>; Sat, 27 Sep 2025 01:07:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXaFvflDgA3hilAxMj1fAlqd9flE17ROnq+zxynzzEQH2jEebLq2OCmuH7r2XXHChXWfz/gShza490=@googlegroups.com
X-Gm-Gg: ASbGnctAps4b/IurUsGCumNls911h7crvrZeEuV9Cw7L7QQUPnLu9HKfq9WtoqKae3B
	ohQDaQ+3CgoP4Daxi0uMmPoBqfwcnRfxw2JvSZ753flWZtrE+yUVuh5Rw841h2NLEAMQSsbxLRH
	VGnf6dXehTD/LNNcl5Ds+m7i9nIS51/VIoQ0CaNXQh6++SY4nwRL7hbIPeBZyLiwS8Ni1Ytm2wR
	GGTrZwHVHX7QWSSQ+i1aw497h8sWNMkH8dQNPMnV2JY8Woy+5A9d7YM1uS7FauqQWrpx1UOqsn+
	9pSd0b3uXGJJ16Clpr0O3zFCda7G3+lz3TmFn7Sp/m0eu6gjEKSKjvjdM+8kGj0I0vXkh3wBe/5
	O0yzOTxDPI9dDIAY/FMto00FvCGdyJkNl/VRcYxDC
X-Received: by 2002:a05:6a00:14c5:b0:781:d163:ce41 with SMTP id d2e1a72fcca58-781d163d14bmr599623b3a.11.1758960469954;
        Sat, 27 Sep 2025 01:07:49 -0700 (PDT)
Received: from E07P150077.ecarx.com.cn ([103.52.189.21])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7810cfdb99fsm4744233b3a.31.2025.09.27.01.07.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 27 Sep 2025 01:07:49 -0700 (PDT)
From: "jianyun.gao" <jianyungao89@gmail.com>
To: linux-mm@kvack.org
Cc: "jianyun.gao" <jianyungao89@gmail.com>,
	SeongJae Park <sj@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Hildenbrand <david@redhat.com>,
	Jason Gunthorpe <jgg@ziepe.ca>,
	John Hubbard <jhubbard@nvidia.com>,
	Peter Xu <peterx@redhat.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Xu Xin <xu.xin16@zte.com.cn>,
	Chengming Zhou <chengming.zhou@linux.dev>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Mike Rapoport <rppt@kernel.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Christoph Lameter <cl@gentwo.org>,
	David Rientjes <rientjes@google.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Harry Yoo <harry.yoo@oracle.com>,
	Kemeng Shi <shikemeng@huaweicloud.com>,
	Kairui Song <kasong@tencent.com>,
	Nhat Pham <nphamcs@gmail.com>,
	Baoquan He <bhe@redhat.com>,
	Barry Song <baohua@kernel.org>,
	Chris Li <chrisl@kernel.org>,
	Jann Horn <jannh@google.com>,
	Pedro Falcato <pfalcato@suse.de>,
	damon@lists.linux.dev (open list:DATA ACCESS MONITOR),
	linux-kernel@vger.kernel.org (open list),
	kasan-dev@googlegroups.com (open list:KMSAN)
Subject: [PATCH] mm: Fix some typos in mm module
Date: Sat, 27 Sep 2025 16:06:34 +0800
Message-Id: <20250927080635.1502997-1-jianyungao89@gmail.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: jianyungao89@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=P9ReA4Yp;       spf=pass
 (google.com: domain of jianyungao89@gmail.com designates 2607:f8b0:4864:20::442
 as permitted sender) smtp.mailfrom=jianyungao89@gmail.com;       dmarc=pass
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

Below are some typos in the code comments:

  intevals ==> intervals
  addesses ==> addresses
  unavaliable ==> unavailable
  facor ==> factor
  droping ==> dropping
  exlusive ==> exclusive
  decription ==> description
  confict ==> conflict
  desriptions ==> descriptions
  otherwize ==> otherwise
  vlaue ==> value
  cheching ==> checking
  exisitng ==> existing
  modifed ==> modified

Just fix it.

Signed-off-by: jianyun.gao <jianyungao89@gmail.com>
---
 mm/damon/sysfs.c  | 2 +-
 mm/gup.c          | 2 +-
 mm/kmsan/core.c   | 2 +-
 mm/ksm.c          | 2 +-
 mm/memory-tiers.c | 2 +-
 mm/memory.c       | 4 ++--
 mm/secretmem.c    | 2 +-
 mm/slab_common.c  | 2 +-
 mm/slub.c         | 2 +-
 mm/swapfile.c     | 2 +-
 mm/userfaultfd.c  | 2 +-
 mm/vma.c          | 4 ++--
 12 files changed, 14 insertions(+), 14 deletions(-)

diff --git a/mm/damon/sysfs.c b/mm/damon/sysfs.c
index c96c2154128f..25ff8bd17e9c 100644
--- a/mm/damon/sysfs.c
+++ b/mm/damon/sysfs.c
@@ -1232,7 +1232,7 @@ enum damon_sysfs_cmd {
 	DAMON_SYSFS_CMD_UPDATE_SCHEMES_EFFECTIVE_QUOTAS,
 	/*
 	 * @DAMON_SYSFS_CMD_UPDATE_TUNED_INTERVALS: Update the tuned monitoring
-	 * intevals.
+	 * intervals.
 	 */
 	DAMON_SYSFS_CMD_UPDATE_TUNED_INTERVALS,
 	/*
diff --git a/mm/gup.c b/mm/gup.c
index 0bc4d140fc07..6ed50811da8f 100644
--- a/mm/gup.c
+++ b/mm/gup.c
@@ -2730,7 +2730,7 @@ EXPORT_SYMBOL(get_user_pages_unlocked);
  *
  *  *) ptes can be read atomically by the architecture.
  *
- *  *) valid user addesses are below TASK_MAX_SIZE
+ *  *) valid user addresses are below TASK_MAX_SIZE
  *
  * The last two assumptions can be relaxed by the addition of helper functions.
  *
diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
index 1ea711786c52..1bb0e741936b 100644
--- a/mm/kmsan/core.c
+++ b/mm/kmsan/core.c
@@ -33,7 +33,7 @@ bool kmsan_enabled __read_mostly;
 
 /*
  * Per-CPU KMSAN context to be used in interrupts, where current->kmsan is
- * unavaliable.
+ * unavailable.
  */
 DEFINE_PER_CPU(struct kmsan_ctx, kmsan_percpu_ctx);
 
diff --git a/mm/ksm.c b/mm/ksm.c
index 160787bb121c..edd6484577d7 100644
--- a/mm/ksm.c
+++ b/mm/ksm.c
@@ -389,7 +389,7 @@ static unsigned long ewma(unsigned long prev, unsigned long curr)
  * exponentially weighted moving average. The new pages_to_scan value is
  * multiplied with that change factor:
  *
- *      new_pages_to_scan *= change facor
+ *      new_pages_to_scan *= change factor
  *
  * The new_pages_to_scan value is limited by the cpu min and max values. It
  * calculates the cpu percent for the last scan and calculates the new
diff --git a/mm/memory-tiers.c b/mm/memory-tiers.c
index 0382b6942b8b..f97aa5497040 100644
--- a/mm/memory-tiers.c
+++ b/mm/memory-tiers.c
@@ -519,7 +519,7 @@ static inline void __init_node_memory_type(int node, struct memory_dev_type *mem
 	 * for each device getting added in the same NUMA node
 	 * with this specific memtype, bump the map count. We
 	 * Only take memtype device reference once, so that
-	 * changing a node memtype can be done by droping the
+	 * changing a node memtype can be done by dropping the
 	 * only reference count taken here.
 	 */
 
diff --git a/mm/memory.c b/mm/memory.c
index 0ba4f6b71847..d6b0318df951 100644
--- a/mm/memory.c
+++ b/mm/memory.c
@@ -4200,7 +4200,7 @@ static inline bool should_try_to_free_swap(struct folio *folio,
 	 * If we want to map a page that's in the swapcache writable, we
 	 * have to detect via the refcount if we're really the exclusive
 	 * user. Try freeing the swapcache to get rid of the swapcache
-	 * reference only in case it's likely that we'll be the exlusive user.
+	 * reference only in case it's likely that we'll be the exclusive user.
 	 */
 	return (fault_flags & FAULT_FLAG_WRITE) && !folio_test_ksm(folio) &&
 		folio_ref_count(folio) == (1 + folio_nr_pages(folio));
@@ -5274,7 +5274,7 @@ vm_fault_t do_set_pmd(struct vm_fault *vmf, struct folio *folio, struct page *pa
 
 /**
  * set_pte_range - Set a range of PTEs to point to pages in a folio.
- * @vmf: Fault decription.
+ * @vmf: Fault description.
  * @folio: The folio that contains @page.
  * @page: The first page to create a PTE for.
  * @nr: The number of PTEs to create.
diff --git a/mm/secretmem.c b/mm/secretmem.c
index 60137305bc20..a350ca20ca56 100644
--- a/mm/secretmem.c
+++ b/mm/secretmem.c
@@ -227,7 +227,7 @@ SYSCALL_DEFINE1(memfd_secret, unsigned int, flags)
 	struct file *file;
 	int fd, err;
 
-	/* make sure local flags do not confict with global fcntl.h */
+	/* make sure local flags do not conflict with global fcntl.h */
 	BUILD_BUG_ON(SECRETMEM_FLAGS_MASK & O_CLOEXEC);
 
 	if (!secretmem_enable || !can_set_direct_map())
diff --git a/mm/slab_common.c b/mm/slab_common.c
index bfe7c40eeee1..9ab116156444 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -256,7 +256,7 @@ static struct kmem_cache *create_cache(const char *name,
  * @object_size: The size of objects to be created in this cache.
  * @args: Additional arguments for the cache creation (see
  *        &struct kmem_cache_args).
- * @flags: See the desriptions of individual flags. The common ones are listed
+ * @flags: See the descriptions of individual flags. The common ones are listed
  *         in the description below.
  *
  * Not to be called directly, use the kmem_cache_create() wrapper with the same
diff --git a/mm/slub.c b/mm/slub.c
index d257141896c9..5f2622c370cc 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2412,7 +2412,7 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init,
 		memset((char *)kasan_reset_tag(x) + inuse, 0,
 		       s->size - inuse - rsize);
 		/*
-		 * Restore orig_size, otherwize kmalloc redzone overwritten
+		 * Restore orig_size, otherwise kmalloc redzone overwritten
 		 * would be reported
 		 */
 		set_orig_size(s, x, orig_size);
diff --git a/mm/swapfile.c b/mm/swapfile.c
index b4f3cc712580..b55f10ec1f3f 100644
--- a/mm/swapfile.c
+++ b/mm/swapfile.c
@@ -1545,7 +1545,7 @@ static bool swap_entries_put_map_nr(struct swap_info_struct *si,
 
 /*
  * Check if it's the last ref of swap entry in the freeing path.
- * Qualified vlaue includes 1, SWAP_HAS_CACHE or SWAP_MAP_SHMEM.
+ * Qualified value includes 1, SWAP_HAS_CACHE or SWAP_MAP_SHMEM.
  */
 static inline bool __maybe_unused swap_is_last_ref(unsigned char count)
 {
diff --git a/mm/userfaultfd.c b/mm/userfaultfd.c
index aefdf3a812a1..333f4b8bc810 100644
--- a/mm/userfaultfd.c
+++ b/mm/userfaultfd.c
@@ -1508,7 +1508,7 @@ static int validate_move_areas(struct userfaultfd_ctx *ctx,
 
 	/*
 	 * For now, we keep it simple and only move between writable VMAs.
-	 * Access flags are equal, therefore cheching only the source is enough.
+	 * Access flags are equal, therefore checking only the source is enough.
 	 */
 	if (!(src_vma->vm_flags & VM_WRITE))
 		return -EINVAL;
diff --git a/mm/vma.c b/mm/vma.c
index 3b12c7579831..2e127fa97475 100644
--- a/mm/vma.c
+++ b/mm/vma.c
@@ -109,7 +109,7 @@ static inline bool is_mergeable_vma(struct vma_merge_struct *vmg, bool merge_nex
 static bool is_mergeable_anon_vma(struct vma_merge_struct *vmg, bool merge_next)
 {
 	struct vm_area_struct *tgt = merge_next ? vmg->next : vmg->prev;
-	struct vm_area_struct *src = vmg->middle; /* exisitng merge case. */
+	struct vm_area_struct *src = vmg->middle; /* existing merge case. */
 	struct anon_vma *tgt_anon = tgt->anon_vma;
 	struct anon_vma *src_anon = vmg->anon_vma;
 
@@ -798,7 +798,7 @@ static bool can_merge_remove_vma(struct vm_area_struct *vma)
  * Returns: The merged VMA if merge succeeds, or NULL otherwise.
  *
  * ASSUMPTIONS:
- * - The caller must assign the VMA to be modifed to @vmg->middle.
+ * - The caller must assign the VMA to be modified to @vmg->middle.
  * - The caller must have set @vmg->prev to the previous VMA, if there is one.
  * - The caller must not set @vmg->next, as we determine this.
  * - The caller must hold a WRITE lock on the mm_struct->mmap_lock.
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250927080635.1502997-1-jianyungao89%40gmail.com.
