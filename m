Return-Path: <kasan-dev+bncBC4LXIPCY4NRBOMHTCFQMGQEJM5ZTIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B1BC42AF53
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Oct 2021 23:52:58 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id p42-20020a05651213aa00b003fd8935b8d6sf476201lfa.10
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Oct 2021 14:52:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634075578; cv=pass;
        d=google.com; s=arc-20160816;
        b=nRf7+/6YZVNcNgLT+rfqMF32+zE/kfv09c/4WUD6sIyvSk6hkGPEjNpEOx9f8LG40o
         Y3IAZpdQBuVrCazEKuC96tKYstHPWYTkLocEY+8MdjJOP7F6XbdHPEOwycyB5SqsmACs
         xL2CbQrzP8SHsERuA5CJL2Niqqz2eiuROhQth4dRKUWubaO8I9jAog+FRVHMCFhpDtyA
         STUD5QPDRMrHN85jDm02HKMskNaU6t99R3Z78mFKTSd4k0d48uzefgrbvlEfTeuc/JKF
         YjiGWPmtX227WCHlgYFmO6vOXIUKXEyOtJ9A0ixv0AtGux3jrFZW7Uno3s+a7+LrUgMm
         e+SQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=c6ni5+ewTb3Umaj5oi2izFDCShePu6UWMCDrL1JFB00=;
        b=Q7U0nSwJITd2YqF5XHlPa37dJ5mGWmJbyq3gJMEb/tFAjhPvNtrHJoKV7EG6i1ssEh
         roK9OX9/DLBx8CH72d5jd2bvWybvf81E5BxkwJTI2OGpJLeJfKsXvcR39kQx7JOB0uMF
         b7wpG+0u7MWeF0z7i+aWu8GVVYmxFVGzRYF0nt8CTlWJ5ZDhtcsMtrvamzGfF2/Rw6HA
         axJi8kWq+avqlKVk4XgQPrCMuPeYBgXVQs1tKVOKNPQKe41QlMNUW76m368to0+kdW45
         AAl7ONYlS2JZnlOG8pnd7cZsTefUhj/6vj+oyhCpu5tGN1nwqzyC7W4yhXbBHz945O3T
         3jyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.100 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=c6ni5+ewTb3Umaj5oi2izFDCShePu6UWMCDrL1JFB00=;
        b=nc5BjxgoApDmwWcGqxKAPKV0xvQfCnMkP+p/1EMa+SWSQn/O3uPgM7vJBuqgNG0qcA
         PnwOAkje7W3FRKHwmyH1MopTMVtdhGAcVh2g/8pG9VULkSQ6IWyKc7j7wlNTI1hco1iS
         nKSh8tKGy5368gKvvi8hX+AW27xL2Hdg6touw42AoJG7ZA3YAsTvbh18sU6gIAWSwHf+
         4S7BLDhmifUI4//JE04J1x+xLO6fc/6ASCZcBMjpnssw/haN1+hDN1oqoYXMyrFnE0Qo
         T3CIqvse6W0oXUuA7clnpCdm1iXNDiBEfofGtIimxz1X9yXk5ukC65DrKqxRaQ5pzpTJ
         BKww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=c6ni5+ewTb3Umaj5oi2izFDCShePu6UWMCDrL1JFB00=;
        b=RTS4Byy7bpguqm20JqnVMRwxLhXb0IZ9vP+87r+gkAm5ff/OEnjAnKKOC/WauPuuEs
         vVK26lhxd5AWdt2/aB0sL2kM8JoDKNCUu/9mFy6vmPzoZGs9AlcCNJvxQ93bWo4zj0fy
         xSHGyy60zjfq20NnZCzMDmusKEBnsfpiQA54gn2ippDMF5lLxP2qcYnQjsXitu9aGL4P
         oY4JJyZMQTDUkaTe2FrpakvGWhd9Jukr47II5Dam2cNjZTuRJcOoT6mYNMQBDsUS9EOJ
         Br2hGIlBZGPuP3WUhJKp6MywyMl2q1sW0gbgqFzE57rnyrS/X9vAN9/9pPxqq7tPdzsK
         rxzg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533x7ePI2tQdrB4qZKkeZ+UHQPqTym5q/uUwl7xHHU8w5xlqHU9e
	UXpyxL2XPTugDKfYqjzhfKo=
X-Google-Smtp-Source: ABdhPJwGlhSYU82FTTuPLdRHShxan48u9zJh3SFEUGLqWdbnGOBceSp0xxfHabg5co2ThTnFXYpZzA==
X-Received: by 2002:a2e:a4b6:: with SMTP id g22mr33910864ljm.324.1634075578107;
        Tue, 12 Oct 2021 14:52:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3a83:: with SMTP id q3ls152838lfu.2.gmail; Tue, 12
 Oct 2021 14:52:57 -0700 (PDT)
X-Received: by 2002:a05:6512:6d6:: with SMTP id u22mr35981005lff.624.1634075577185;
        Tue, 12 Oct 2021 14:52:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634075577; cv=none;
        d=google.com; s=arc-20160816;
        b=id70DPmQQ2ySsAF3wRsa16eJSQz/KBnm4s12yLpo4xOHvG7UHpiNgkteNe3yhdaWZs
         GQyzgnUeRCdgl1MmifOoPuy6KU5+CzWcfAm0ivNk8E5C9F21lrDDYdRlKqwpUnO5a/tm
         X0dLyOWv6dd0veWWHg2yC+amDc1tRd3kATk6c2aj2W/6nQfd2vJT0LIlgWBV+O6D8uUU
         XqyysTEdwMHoednqgP48c7ySZYAAZptJ58kvsBL+E/cALWOnJyWvh+UxudSphkDRMm7k
         2IfZaHxUg4LjtaB0qzBWHJX4KUeuBXw7eakGHCaIiQNTGCX45QZDdGCYE5+z350M6/rb
         wMjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=W0Vg5qoI5+m6NXL9R0LDjUO56wu5XbOC7OBN9hc5/2A=;
        b=CYxwX5BWBut27iYJ5BR1U3MjkSlGPdMhtI0JB+PfdL0X4wmYKxRbehs2/Nm1s8qVBX
         HX/54flfUivfT/Ts9q2xNPYdKQRskiAeeNknVH5/aWm1vgWWtBJg1OPXZXJmMeNxFlhG
         jfCFTLKkGfISXAF2jbsyj/R1NJzKb/T+e7Zkr4T8VOVG+yGm7sDET8P1h6zFlocxuaNp
         TLFcOvcAdAzbnP1mf5C2IO0ZN9d7syTzk5KShGVg1oqnrHmRD+qfGh/z8w0qNvQdpWOM
         zK2xc82LCkYNXHKVeQzJ5CT+4CMdX3RrhVs95JWDypSBc04AmW+Onpp//3HxVQMqz3mA
         gIDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.100 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga07.intel.com (mga07.intel.com. [134.134.136.100])
        by gmr-mx.google.com with ESMTPS id i21si663729lfv.2.2021.10.12.14.52.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 Oct 2021 14:52:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 134.134.136.100 as permitted sender) client-ip=134.134.136.100;
X-IronPort-AV: E=McAfee;i="6200,9189,10135"; a="290772315"
X-IronPort-AV: E=Sophos;i="5.85,368,1624345200"; 
   d="scan'208";a="290772315"
Received: from orsmga005.jf.intel.com ([10.7.209.41])
  by orsmga105.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Oct 2021 14:52:54 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.85,368,1624345200"; 
   d="scan'208";a="659280302"
Received: from lkp-server02.sh.intel.com (HELO 08b2c502c3de) ([10.239.97.151])
  by orsmga005.jf.intel.com with ESMTP; 12 Oct 2021 14:52:51 -0700
Received: from kbuild by 08b2c502c3de with local (Exim 4.92)
	(envelope-from <lkp@intel.com>)
	id 1maPha-0003wK-Vh; Tue, 12 Oct 2021 21:52:50 +0000
Date: Wed, 13 Oct 2021 05:52:33 +0800
From: kernel test robot <lkp@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: kbuild-all@lists.01.org,
	Linux Memory Management List <linux-mm@kvack.org>,
	linux-kernel@vger.kernel.org, dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org, kasan-dev@googlegroups.com,
	Vlastimil Babka <vbabka@suse.cz>,
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>,
	Vijayanand Jitta <vjitta@codeaurora.org>
Subject: [RFC PATCH] lib/stackdepot: stack_depot_init_mutex can be static
Message-ID: <20211012215233.GA41525@800d2291961c>
References: <20211012090621.1357-1-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211012090621.1357-1-vbabka@suse.cz>
X-Patchwork-Hint: ignore
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lkp@intel.com designates 134.134.136.100 as permitted
 sender) smtp.mailfrom=lkp@intel.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=intel.com
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

lib/stackdepot.c:150:1: warning: symbol 'stack_depot_init_mutex' was not declared. Should it be static?

Reported-by: kernel test robot <lkp@intel.com>
Signed-off-by: kernel test robot <lkp@intel.com>
---
 stackdepot.c |    2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 9bb5333bf02f61..89b67aef9b320b 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -147,7 +147,7 @@ static struct stack_record *depot_alloc_stack(unsigned long *entries, int size,
 #define STACK_HASH_MASK (STACK_HASH_SIZE - 1)
 #define STACK_HASH_SEED 0x9747b28c
 
-DEFINE_MUTEX(stack_depot_init_mutex);
+static DEFINE_MUTEX(stack_depot_init_mutex);
 static bool stack_depot_disable;
 static struct stack_record **stack_table;
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211012215233.GA41525%40800d2291961c.
