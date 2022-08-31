Return-Path: <kasan-dev+bncBDN7L7O25EIBBDU4XSMAMGQEDTKWVKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 618A85A777D
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 09:30:23 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id u26-20020a2ea17a000000b00265f0e09c8csf2152395ljl.2
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 00:30:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661931022; cv=pass;
        d=google.com; s=arc-20160816;
        b=cw85rqhd+0k9+qZLnO1NRPZMU/sVaTvfLIVIdlrku/UZQWgPflmGh/Mha5sknChJLe
         t+9CtXq/fJPG7hv2SEDv/YXEDFuy8Hb/vCkXEsSeS95yWUl5BO3VRiCm/ZKxU25kJ8eN
         bA2fHr6NyIowpDcOv9K4BADHJLBNMVyt0L0yf6eGCczAk9WkItAvkRCoUR9YizQ0NJrg
         j/UOcUZEQtOtxm2/dXM6c8xpSVqzRqt1uXf92VoxEAC69Q9Nqk8Amg2MJiMHMYgKoCHi
         NhcNU1zGpThZdvp86OqrjMeLCC/n+fPt7uecQFkYEfqwq2PBnDnzg4EGzZCG9uP9xRfP
         CjJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=4DVpit9KEzc32+wvRWmu60REI10pgT1p7++HO9G6Xy8=;
        b=cxowHRdHxHoTcXWVmk+bhpfk4ZWQliJ+9VcUKXFxXpQUrevRq0pUQlOAYgxBe7X44f
         I33E8VtRC4YogB/Z19ktv6EqW3+lA04Kh6wAVA7X9UAO4/Qw06rIBCBh+SmkINdfCsE/
         NztybaaQelInoBmhFN4cRaS4/IguJ9ZnMYkUfcpuXsy4Jd2miQv31zKlMER0yi4MZGvr
         hlsS38s11JP4C+/tHWZh8ClkXHDiYEGyIpbxu41uIkQloD2G6C6bqO+TV8LKkNaianiF
         a3XdlVsY0Ar8Oywnr2MfBnYquDSnYtsH+irPvRB/zSS2QBEMfvq1lq2U/wYtZ9nRCXQD
         ijDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="ZjniA/zq";
       spf=pass (google.com: domain of feng.tang@intel.com designates 192.55.52.115 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc;
        bh=4DVpit9KEzc32+wvRWmu60REI10pgT1p7++HO9G6Xy8=;
        b=FDuqPQe/GqNTPSq9GkSlgqZ/HJRN79SU1tab5ygDRCKOhHbOlWjGOU88J1TEvf36Et
         A9xngclRugtKcb8KOzrRHJ1YtH/l+VAIyj+9ikQpnirWGqAA4UAXsbzKQQ42zvkF9LXB
         0vTG4vthneRuRwisbnTiHY0bMXdqPoyDeIFZn2mmq0KTup3qUAnfs7EBD7sa5lGxlPRv
         ozVUgz+z2NJralWy+ONmmIuRhRfF6Juw3KFOyDGBFkdJAqLAXjAz+VJ2mJtNa2amNm7d
         LBQrurbydAPzmZn2LGRXRSkPw3EknAk9cIWMx2tm4y6cB3vrNRCgzlDUXFhu5ixI3Kf5
         oGJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc;
        bh=4DVpit9KEzc32+wvRWmu60REI10pgT1p7++HO9G6Xy8=;
        b=fnIxqxa7d+/VcJvj/LIXi4jI9bfNbTTqPZSngTnIE0OmXljwdQdhYlSsAnsVZ9/Lf+
         PlFOeF/GG0cBLMQ7Zr0fO2DHwmu11gw9KYL3RZ5NmoROky1IKjFEsP8bbTdF36cMQDRl
         Ve0VdJ7go0A5crVsk1Nzx/3ezaobh1sMP3iEMPTFAa9OcSA8zBMBUA/k4uNG5y2bAq26
         YY/4nfkVJ/7nOb7oWfmMjMWhrQaAWBfeeCtc44ceXf/NIz0O8D9nnK1z++8FImQIC0Mp
         jeljCyGuKADiHNV5YHI9CFkfZIL98KCEWLj/GqCUSTtU554Db+05SJKQbm78I7cJL9KV
         c9mg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1LUQzdbKc+qb2fFen67nHfoqzGNYaiBhA9sz5eaqW6x2Re7xOe
	/HHkU9knEi3d9PVncIPd0xk=
X-Google-Smtp-Source: AA6agR6NxyKA7cXgAQLxX+nU/pza6QS2ELHVrTaQlrEqXT1w8AlHc+pj5YRKvr7wPc3XEMdzkDfSiw==
X-Received: by 2002:a05:6512:2614:b0:492:befa:cace with SMTP id bt20-20020a056512261400b00492befacacemr8379566lfb.444.1661931022843;
        Wed, 31 Aug 2022 00:30:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:57c9:0:b0:492:f1b2:ac20 with SMTP id k9-20020ac257c9000000b00492f1b2ac20ls2641690lfo.1.-pod-prod-gmail;
 Wed, 31 Aug 2022 00:30:21 -0700 (PDT)
X-Received: by 2002:ac2:44c1:0:b0:494:7813:27af with SMTP id d1-20020ac244c1000000b00494781327afmr2466796lfm.619.1661931021454;
        Wed, 31 Aug 2022 00:30:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661931021; cv=none;
        d=google.com; s=arc-20160816;
        b=aFMOZmWZrosS9O2Kyo9AZQMsL4NAxS2BZASHcPqaO9mupHRnO/uUeWlZkxXAz8is1A
         vxYNcwyHBcq0MBO+sMlR1tNtBS/HRZ47JGuR3TnYc7b72Ic2VRHmGj4cZbOLdtY745IL
         TF5E2bJ6t9SYbDef14u3nGO7v0EICelitGXEzdSiXUTuWASv9j71Ni5Dyanmcai+SBYZ
         bcCHyRcQe07NLf3rCIRaiOp/Xp+V9J5KMy9Stm6TAiF4yGVLlY1Vafl65qH35aZ+itA4
         CSFb0E/keILvjjfCIkhtmUcJZV6ZvnOZD8iLG7+Hd7L+uQcI5Ccv3EX/tycLpWj5PyFB
         /DDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=shEyZ4ffTq52T5de9pugtA16ZoRuWyieNc6a+jK04JQ=;
        b=LGknlM2hH4AZZfxsKVa+9XZtLjp860NBLN/T7B9Dov+AxubzFZJabEE1QIjnHCKTRx
         bIMLyKePa++uAP/MjtQ9ty4h5WkpyebOwhltUheSPflPfF03agUx2Q+GdZjLg/sO3fKS
         tQyNvjv2onCW5MEEWSPgg1Pg8sXhQlmv6/FKH8L9FPvWgKKjX/tSlVgg4SY2CEECeIwr
         Y9MXcoFgQNwQk1b07JcttvNNL0KJI8/WhfMLnIl+oupM33hO8+hVtwx6Q2PlPrOqxH/L
         KI5PORzIlzCkrOlu12FMwHdpamVUzmNfKCQl70PFnnh4c5fI95YYZnzRkNHF7JxA/g+w
         bGSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="ZjniA/zq";
       spf=pass (google.com: domain of feng.tang@intel.com designates 192.55.52.115 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga14.intel.com (mga14.intel.com. [192.55.52.115])
        by gmr-mx.google.com with ESMTPS id t12-20020a056512068c00b0048b12871da5si576587lfe.4.2022.08.31.00.30.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 31 Aug 2022 00:30:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.55.52.115 as permitted sender) client-ip=192.55.52.115;
X-IronPort-AV: E=McAfee;i="6500,9779,10455"; a="295397534"
X-IronPort-AV: E=Sophos;i="5.93,277,1654585200"; 
   d="scan'208";a="295397534"
Received: from fmsmga004.fm.intel.com ([10.253.24.48])
  by fmsmga103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 31 Aug 2022 00:30:17 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,277,1654585200"; 
   d="scan'208";a="680341142"
Received: from shbuild999.sh.intel.com ([10.239.147.181])
  by fmsmga004.fm.intel.com with ESMTP; 31 Aug 2022 00:30:15 -0700
From: Feng Tang <feng.tang@intel.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Cc: Feng Tang <feng.tang@intel.com>
Subject: [PATCH -next] mm: kence: add __kmem_cache_free to function skip list
Date: Wed, 31 Aug 2022 15:30:51 +0800
Message-Id: <20220831073051.3032-1-feng.tang@intel.com>
X-Mailer: git-send-email 2.27.0
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="ZjniA/zq";       spf=pass
 (google.com: domain of feng.tang@intel.com designates 192.55.52.115 as
 permitted sender) smtp.mailfrom=feng.tang@intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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

When testing the linux-next kernel, kfence's kunit test reported some
errors:

  [   12.812412]     not ok 7 - test_double_free
  [   13.011968]     not ok 9 - test_invalid_addr_free
  [   13.438947]     not ok 11 - test_corruption
  [   18.635647]     not ok 18 - test_kmalloc_aligned_oob_write

Further check shows there is the "common kmalloc" patchset from
Hyeonggon Yoo, which cleanup the kmalloc code and make a better
sharing of slab/slub. There is some function name change around it,
which was not recognized by current kfence function name handling
code, and interpreted as error.

Add new function name "__kmem_cache_free" to make it known to kfence.

Signed-off-by: Feng Tang <feng.tang@intel.com>
---
 mm/kfence/report.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index f5a6d8ba3e21..7e496856c2eb 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -86,6 +86,7 @@ static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries
 		/* Also the *_bulk() variants by only checking prefixes. */
 		if (str_has_prefix(buf, ARCH_FUNC_PREFIX "kfree") ||
 		    str_has_prefix(buf, ARCH_FUNC_PREFIX "kmem_cache_free") ||
+		    str_has_prefix(buf, ARCH_FUNC_PREFIX "__kmem_cache_free") ||
 		    str_has_prefix(buf, ARCH_FUNC_PREFIX "__kmalloc") ||
 		    str_has_prefix(buf, ARCH_FUNC_PREFIX "kmem_cache_alloc"))
 			goto found;
-- 
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220831073051.3032-1-feng.tang%40intel.com.
