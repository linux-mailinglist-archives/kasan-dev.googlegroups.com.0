Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBEPZ7S4QMGQEXTA5KSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 949D19D4E30
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2024 14:58:47 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-211e6642b31sf11090035ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2024 05:58:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732197522; cv=pass;
        d=google.com; s=arc-20240605;
        b=D+JlhUFxeo8sLi1pUCSlNqWCuxuw3TSm4TznDxXcaC+ZHs2zuc2PfLiCmLjH20YmSV
         UCsgt851XPAg7rvIBTGCXKc5/RziAPeSFTw4vS5vwtzOJzvs5PfUFGpSmYzhJQoa6aCz
         ERAK1g+7M/cWKtTzEbmgxtjB1PksZJKnEil+uV0yB4EgsqwMYcLyC31thI+hVtm4e4r1
         EYgkrxx/qT8vhTHtVr8BgQPyK8VFshFkuG7jDWwgzXajHj27JQyyoQ+ZvOCx5Z9o5esR
         sAknYeXRDLsSSkJXTc05hYCUkANyIWiuMouGvfJT5A/26/6CxCH1MVZCHiT8Tn3kJ4R9
         vXjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=llTigJAsQxCzxqIfjXPq+Nu2Z+nYNmUwZ4vZW+AJ+Og=;
        fh=FLPKAN5TaV5k86vahiUJarrO5S0mCCmw9yhdQp4I5d0=;
        b=TBlFwPKUrfYkZArM3XnO1iV9Qnb6riR/y4RJoz4gtsUUcpRgIpDcrNUTPmemjkDe75
         Tvx/PulcoIADlchGkGkuGjFY+tpzwG3ARl2jpKMX3um1kAZr2YOkBP9SKCLelRA/ZoiG
         PrrWS6+p+neXWy0it64OwCh+55Najig44bTRyBGG3mVwbz6hhe0IJjAkiZ1GFQIYCgv9
         ghAdPCNmmmrpy6gPo4Ss2KoH3h4it2BkiYRznRu9Q+a3vfNebktVuHfvdE7iOEw2shBE
         eHw68CA61kdILudnd2nJw/9Ljdn7alEp/uhRGG0NnL12erVyMXOD3dAV4nk4K9GKYeuE
         wJeQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="RG/jHfI9";
       spf=none (google.com: andriy.shevchenko@linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732197522; x=1732802322; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=llTigJAsQxCzxqIfjXPq+Nu2Z+nYNmUwZ4vZW+AJ+Og=;
        b=OramwHMHXjnEV2H3yTBOes2l4QPIcTnhQbMRSuxuoiy8dK842XB8xXutzs16S98XcJ
         ZyHrJQWSDPJLKMGKRfXUS6VePK9KF/yT7ahEWMFYF1rzf6Tkq7+kKOCMTtm8YgOuy6Th
         X0QaqdJpEAq6P+kEtVY20NM1E5CyZBpJ974SQYgtEwHlVdyZtn6lEugP3yIeGdw/Ourj
         jAh4939aXyPtKtqH+WoapH2+YE/QhcWR43XDrK+HNBpf7VbSzoXsxgyratSi/Ow03GUf
         eNRuS73sXiTJ7nBHvEB/hr3ss4cP0azoLBueuuQtB/yGxXqxP1Lp/6El0uNzdrbtobQe
         KGMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732197522; x=1732802322;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=llTigJAsQxCzxqIfjXPq+Nu2Z+nYNmUwZ4vZW+AJ+Og=;
        b=Uo2kglwHOmwSBy6lVmXVNNSi7sDWe1h+t8Il1Kti3bdBzyn0CJaJtcwV1H0j0i8Q44
         WV4kxWQye0eh27HBfqJOOvC+jr9dZzM7UX7fCETfvtWLnM/O1Tsqq7stx6F4Y/6AKV5+
         GGRXfbocCUoX8VjLRh9H1z6+cCUPxxLs+rY2q9YYKeDc7iARGb7BTn7sQoB+OOtH18OD
         9JGEhb+I621aq+n77Gu434jdBfTRbln9fqjkchxrcqvn9pbfD+2sZUQATEjQP74qYpWp
         XVJW5H2nUWE0lpftA2Qt0eqvwr3FspILh87hvT3xCDY/hKdvnceS8D8ZirfiO/DjLXxD
         kd+g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUBidbYlCA6TemzbFNZ4jA/pCvHShUrbxIzsIrEoeioXIp6Uj3fcrmsl81IOufKJZQxkqJqGA==@lfdr.de
X-Gm-Message-State: AOJu0Yxe838DEN+OlVLW9RGncrl/Qo0vWXWiDuUNuf/dvYWSna63aGgM
	1qBvdbWWsiHk09sowQUkctZOXqq29SsdEFEKyCl2/3eSlxi8eLh+
X-Google-Smtp-Source: AGHT+IFOs3C366wmMypDZmcZo9nAHOm/Sua2cFwOhIgAXnhMy8ziFs/PpWD/P5XqiPSWtfg6iLddGw==
X-Received: by 2002:a17:902:e5c7:b0:211:2b2:2086 with SMTP id d9443c01a7336-2126a49345fmr90465385ad.49.1732197522297;
        Thu, 21 Nov 2024 05:58:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4b91:b0:2cb:5bad:6b1a with SMTP id
 98e67ed59e1d1-2eaeae78f85ls817973a91.0.-pod-prod-05-us; Thu, 21 Nov 2024
 05:58:41 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUyeKAsc5znJznD1Rvd4gccnPrcZ7rJcrarYfUgNCZ1+qThpu71rbBYM/RaJXmrc3x3BoArdDk5Imo=@googlegroups.com
X-Received: by 2002:a17:90b:4c04:b0:2ea:8e42:c40 with SMTP id 98e67ed59e1d1-2eaca7dcd21mr7479031a91.31.1732197520664;
        Thu, 21 Nov 2024 05:58:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732197520; cv=none;
        d=google.com; s=arc-20240605;
        b=c3SV6s8nXUZhGqfXyWLP9ZzbBfhLH+fr7NkjfIvAlR8osAKFBTKlqlmqWh4ck2KRXa
         BHnaDY2gwogZT22ryzW3a1rfCN97b6kaETK2zSQ2FtwS6SrTIDYv+QqN77dYO9g5n1Nz
         iyOgyUwoR+cUhYkw6TZkELNpGEkyzF4XBtDZw/mNQk/SWFttz80RCaDvNT56jwRmtXn+
         EQe0erLnIKsHPhrl3Xbp/34Cao1EL84KaaikcMMJ7izxSHE+az25NqtdH69OCO2pOYkP
         OlRcagnhtkmW0XDaWkOkVXoL188IxOHsZlmNaF6wUpWLdqH1wDy8Qu/xBABzKYQ8keTx
         rbtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=AuKKU/baF5U/smUGKcuSM6V5Ro8NBcc6DjogfOy9n1Q=;
        fh=Asz3tCiqcb+lO3Qc3nLyQSgGVV4z17Eomw2ZBQ8X/2o=;
        b=aST2bz2CVLHKsspuQ/CyWNDHA2+ELbe7vLeCLNqbNNwdi4Yf/S80rDH0E5EzeTEUl+
         tfYKPmLMb7ml89Hab+o7GqTfG37Yd8AjLTmuGALlUFDm1idN5yhHv3KgdRdmOauq+x9Y
         NhVJa5Gf9KPG81BzJXtZGpl8HHCp2PiulpwH0kDJkGeVtvBr3dlci25e/LB3xeeMRG9o
         62CIjdBi+YAhAHhNKHNxddd/GWsLeSS4B6PdeYyQpXX6TAH/yCZmyy/Qhb+uOfn99Kp5
         XR1plGtFLYCA7L3T1He14vndyUnYSrnz+Zeh1bjnL3QiRwLxD3Sibrx2oqrxNywwAQnZ
         BXvA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="RG/jHfI9";
       spf=none (google.com: andriy.shevchenko@linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.10])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2eaca6fce6dsi545830a91.1.2024.11.21.05.58.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 21 Nov 2024 05:58:40 -0800 (PST)
Received-SPF: none (google.com: andriy.shevchenko@linux.intel.com does not designate permitted sender hosts) client-ip=198.175.65.10;
X-CSE-ConnectionGUID: CfE0GmhfSVOG0yr/yCRgzg==
X-CSE-MsgGUID: e+FNOK6NTZudGw3EsW87ag==
X-IronPort-AV: E=McAfee;i="6700,10204,11263"; a="49732497"
X-IronPort-AV: E=Sophos;i="6.12,172,1728975600"; 
   d="scan'208";a="49732497"
Received: from fmviesa005.fm.intel.com ([10.60.135.145])
  by orvoesa102.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Nov 2024 05:58:39 -0800
X-CSE-ConnectionGUID: wpAzhqApSWqWuZlm0e00gw==
X-CSE-MsgGUID: 8Ul0LmMCSC6tv0pPYeQs9Q==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,172,1728975600"; 
   d="scan'208";a="94706865"
Received: from black.fi.intel.com ([10.237.72.28])
  by fmviesa005.fm.intel.com with ESMTP; 21 Nov 2024 05:58:37 -0800
Received: by black.fi.intel.com (Postfix, from userid 1003)
	id 1E9ED2CA; Thu, 21 Nov 2024 15:58:36 +0200 (EET)
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Cc: Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>
Subject: [PATCH v1 1/1] kcsan: debugfs: Use krealloc_array() to replace krealloc()
Date: Thu, 21 Nov 2024 15:58:34 +0200
Message-ID: <20241121135834.103015-1-andriy.shevchenko@linux.intel.com>
X-Mailer: git-send-email 2.43.0.rc1.1336.g36b5255a03ac
MIME-Version: 1.0
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="RG/jHfI9";       spf=none
 (google.com: andriy.shevchenko@linux.intel.com does not designate permitted
 sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

Use krealloc_array() to replace krealloc() with multiplication.
krealloc_array() has multiply overflow check, which will be safer.

Signed-off-by: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
---
 kernel/kcsan/debugfs.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index 53b21ae30e00..be7051d0e7f4 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -166,10 +166,10 @@ static ssize_t insert_report_filterlist(const char *func)
 	} else if (report_filterlist.used == report_filterlist.size) {
 		/* resize filterlist */
 		size_t new_size = report_filterlist.size * 2;
-		unsigned long *new_addrs =
-			krealloc(report_filterlist.addrs,
-				 new_size * sizeof(unsigned long), GFP_ATOMIC);
+		unsigned long *new_addrs;
 
+		new_addrs = krealloc_array(report_filterlist.addrs,
+					   new_size, sizeof(*new_addrs), GFP_ATOMIC);
 		if (new_addrs == NULL) {
 			/* leave filterlist itself untouched */
 			ret = -ENOMEM;
-- 
2.43.0.rc1.1336.g36b5255a03ac

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241121135834.103015-1-andriy.shevchenko%40linux.intel.com.
