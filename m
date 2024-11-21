Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBQ4A7W4QMGQEBMN6STA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id D75249D4E69
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2024 15:14:29 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id 41be03b00d2f7-6c8f99fef10sf1051458a12.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2024 06:14:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732198468; cv=pass;
        d=google.com; s=arc-20240605;
        b=ffDMej0ms3HBM0Gc85tJsOnd/R84hT9glP1HU6gNv6sCP/6LU5wrbPay6orvQI/ZDJ
         jIynnCKTM0GKyl2yqre8G8IWet9lO+7bVqQLknS7xgIvgADLI8y+vJEFas/+PdCSA8W2
         h34IpVulTvNgtyZDKJyfM5nlEltjVxKXTQvup8MyYUNYAwuIPDLktb6JtLCR3QvXMOqi
         vFSmSQ0quCDDqeAlvBmQqKn0T83l/uwyCHoLlmxdvV5zaJPii1ilL4i7MEX99v8+F5vV
         1fvWuj6kzAl6JgO6G34Gx8S/4ZhKJh0AhRSuIy90GvLpxFOgKyxzsuUOabOdWzVUOUwt
         BSWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=hyR6v+JHRNUAo/aiNfRYOmrq6Ry6QyMx10si9n735bM=;
        fh=7W+bb3ai+SoJ/0qQm5TT3NBgzLkfpuwHUqZAXhco0xA=;
        b=URPNCoRolSlVCVbRd8em1hPgIqtQfdCcKT3NQ1BihhacC6zW0+VgiYxCm+Z3LMoZNp
         Jo6yJaNRUdGRdJLMpvmW6cLFUImXvb3XIOnvcZUWC37Fj0GOZHNiVKKqvWx6HPcdkHiS
         Q5iugrWskX7xTa4WLMnNyvHV6xy0uOCaLDvQdQFiRDOASE3x+oK1XPuP5xJD0+Q6yBIc
         uWrrsOotV6/KrP4qBBjUdPL7cpcn8dJTjd7RZVaib/agHNrg2arhe0bAcZTr0YQKH2q4
         FQqKzJgCvwEAVD5Rec/yOb9f6tfb8WMYY58SLxK8f+tKuD+JWs++W2P3IC3B6iq9vK4l
         BjpQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Ebxm42Tw;
       spf=none (google.com: andriy.shevchenko@linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732198468; x=1732803268; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hyR6v+JHRNUAo/aiNfRYOmrq6Ry6QyMx10si9n735bM=;
        b=APwirukZAhyPicq7GS7IyqdOQJBClpPA5Ql+qymgoU6CcfPtbyrmrL60J9IB+hvrmo
         LpO8JLOVnCY0xC0YgD1KTojZJDjDuXzbaFuHZUlYaLy7a2CztIpvasEvkQQRJ3uFCJkT
         StqDiQWMHBzzLwQf//Uc+J+AGjbqDqDClGVowTK88K5S2AcLnDeV+cprjf/mgsF0cjbg
         Xhuvl1YpZncxjYRt/I8My1g4DxWW/fpRFmSH7o93o4Lpd5muujps4JarAPcFugRky3yr
         SUIPk2tWwXbdJIwW21OnCV/OuVXrwjsF83kuNqY3i0l6iLEBnVhIPhjtl8GI5tGbmCEM
         Oq+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732198468; x=1732803268;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hyR6v+JHRNUAo/aiNfRYOmrq6Ry6QyMx10si9n735bM=;
        b=tfUVuLrnmsLZFMNxa7+fyQk2XaOcv/LjlRrq55b4x1BQ04h/pck1qkj1oaErk61ua1
         JfpQTvGdIAYt+ysxwXM8nQAAzGhCwh8sQ/ucumNYo1nh7HcnHbE+DGLdXwKvDSWWg0l3
         hBgRQ4eFUpkTY6O9J6Bg4MIdByR/LeMQUJaYL6DR0lDIOOGpx1O4E4/cTN6arUvXDqal
         M2dtqVG5ZCkFYELqsN5gUIyrLKSoHIxilWSi/a8dUbshk6ulsyvKc7jz5D9VYshpNQNm
         r99w/b7iL85XnmTJoCwXsOseD5qKNw2VZsHyVFUdEq0wbuKqC7Gl5JBc2jvmA/DqD1q+
         8O+A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWoL+BoRJXsjxwuQf8oUwdK/ybYLMrzP35G3+NjglDNL5VG1z4BULA33hJ6Ola6gfrwoGWyLg==@lfdr.de
X-Gm-Message-State: AOJu0YzsyKccIK9GLjrpW3f1w9sJX9wf4wynvqLnXBdUgwUel386Bken
	ano2g6UIfH/bmdqRA+wC1wtxPATx9/JpqVfyJSXMXuTqinVPyVBE
X-Google-Smtp-Source: AGHT+IGqU6iZ402LdlNk2IbQ4BEr/pXFjAAkrVRGMu7fY4Zm1srHcNvacOlwUMMuWykiafUIFTVTnA==
X-Received: by 2002:a17:902:e84c:b0:20c:6399:d637 with SMTP id d9443c01a7336-2126fd8e088mr87128675ad.40.1732198467687;
        Thu, 21 Nov 2024 06:14:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4a0c:b0:2e2:b20c:8c63 with SMTP id
 98e67ed59e1d1-2eaead79b61ls816663a91.0.-pod-prod-06-us; Thu, 21 Nov 2024
 06:14:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXH4HIfx59kpxcEZn5/8qu6pZgr5G2Nfkl5uNIpycJUztJkjs+GroacB6u6i/oqPNtMbetIHRyjR7M=@googlegroups.com
X-Received: by 2002:a05:6a20:7494:b0:1db:eb82:b22f with SMTP id adf61e73a8af0-1ddae1f88a1mr9121328637.5.1732198466035;
        Thu, 21 Nov 2024 06:14:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732198466; cv=none;
        d=google.com; s=arc-20240605;
        b=Y/BdCEuzYspbsZo0RDe/80rY6JwreB0aEtTk+jeu25bF/cvtB0n6+wjdRbqJqEL1/q
         BYLTt3cdNNg4PUK47uaYoHZyIcbsGDTQ8tN+HVEV3dhTjP4mVGZPNMyycMaFHr3Z9iON
         VHx3JO/THyKcwYJfivXmCCq1x6ZIEndPF+Fk/SD/eO0qeYaSMZDybzOLCMUHJfMWfWRy
         OGlMjhEThHVbe23AbvcsAVL8hzd5kpb9zBQiMvPgiO3a0MtgnibXJxda6gi4OPvu5Z23
         Sk3dveEEcSjFSOzfBQVc/GN3fxc0Z9tgTDyzskiLNdh2ysorCohB18O2Z9SrQIr5hBrz
         J/8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=mzeyJEKbc53oJjsK/XMYOsuQduG0QzQSySA0l73ije0=;
        fh=Asz3tCiqcb+lO3Qc3nLyQSgGVV4z17Eomw2ZBQ8X/2o=;
        b=MejLWAmxBnEvylXVc+2ll280D42we9+mb+CmJQj86SyEvEsIsYUYbSjMk7h7qGCYWt
         QvnkVBdhJ0KBcPKC16SfnxOcpKFjx8jXmQn5r8ZSgtagjZp4gqu0cojddP+p0Mtq17u/
         7Sy+FfgrPR4ZQKHl+gxJ0z+JhvhlMVnmFby7GyOHjFemfj4Twv9BSIZEk8A14Qq1Wvjv
         psPvblG9Mp8KrFrlARNTpI7m5A0f4pVAvK19N1rRd8bI9wPPO8kP+WoXFlEMtgr633uH
         JPbY9GWLET4sr+Im3d53D0WlqnQiA9G0DQSlVx3mZ+XyOHX0K+OugvysFpzgnBtcMzLa
         UN7Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Ebxm42Tw;
       spf=none (google.com: andriy.shevchenko@linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.10])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7fbb64fc0f4si87098a12.2.2024.11.21.06.14.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 21 Nov 2024 06:14:26 -0800 (PST)
Received-SPF: none (google.com: andriy.shevchenko@linux.intel.com does not designate permitted sender hosts) client-ip=192.198.163.10;
X-CSE-ConnectionGUID: ms6P+FSCQpKZEjKlnVSDmg==
X-CSE-MsgGUID: Ezd5+LH4SpugSbquF2MM7A==
X-IronPort-AV: E=McAfee;i="6700,10204,11263"; a="43707184"
X-IronPort-AV: E=Sophos;i="6.12,173,1728975600"; 
   d="scan'208";a="43707184"
Received: from fmviesa006.fm.intel.com ([10.60.135.146])
  by fmvoesa104.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Nov 2024 06:14:23 -0800
X-CSE-ConnectionGUID: aqkPYLhlRLObQJvhxtAwrA==
X-CSE-MsgGUID: Z2NK+wbrQjSOaHZdZYG+lg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,173,1728975600"; 
   d="scan'208";a="89867605"
Received: from black.fi.intel.com ([10.237.72.28])
  by fmviesa006.fm.intel.com with ESMTP; 21 Nov 2024 06:14:22 -0800
Received: by black.fi.intel.com (Postfix, from userid 1003)
	id 23EFB18E; Thu, 21 Nov 2024 16:14:21 +0200 (EET)
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Cc: Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>
Subject: [PATCH v2 2/2] kcsan: debugfs: Use krealloc_array() for initial allocation as well
Date: Thu, 21 Nov 2024 16:12:52 +0200
Message-ID: <20241121141412.107370-3-andriy.shevchenko@linux.intel.com>
X-Mailer: git-send-email 2.43.0.rc1.1336.g36b5255a03ac
In-Reply-To: <20241121141412.107370-1-andriy.shevchenko@linux.intel.com>
References: <20241121141412.107370-1-andriy.shevchenko@linux.intel.com>
MIME-Version: 1.0
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Ebxm42Tw;       spf=none
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

Use krealloc_array() for initial allocation as well.

Signed-off-by: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
---
 kernel/kcsan/debugfs.c | 16 ++++++----------
 1 file changed, 6 insertions(+), 10 deletions(-)

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index be7051d0e7f4..ac31412de646 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -145,6 +145,8 @@ static ssize_t insert_report_filterlist(const char *func)
 {
 	unsigned long flags;
 	unsigned long addr = kallsyms_lookup_name(func);
+	unsigned long *new_addrs;
+	size_t new_size = 0;
 	ssize_t ret = 0;
 
 	if (!addr) {
@@ -156,18 +158,12 @@ static ssize_t insert_report_filterlist(const char *func)
 
 	if (report_filterlist.addrs == NULL) {
 		/* initial allocation */
-		report_filterlist.addrs =
-			kmalloc_array(report_filterlist.size,
-				      sizeof(unsigned long), GFP_ATOMIC);
-		if (report_filterlist.addrs == NULL) {
-			ret = -ENOMEM;
-			goto out;
-		}
+		new_size = report_filterlist.size;
 	} else if (report_filterlist.used == report_filterlist.size) {
 		/* resize filterlist */
-		size_t new_size = report_filterlist.size * 2;
-		unsigned long *new_addrs;
-
+		new_size = report_filterlist.size * 2;
+	}
+	if (new_size) {
 		new_addrs = krealloc_array(report_filterlist.addrs,
 					   new_size, sizeof(*new_addrs), GFP_ATOMIC);
 		if (new_addrs == NULL) {
-- 
2.43.0.rc1.1336.g36b5255a03ac

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241121141412.107370-3-andriy.shevchenko%40linux.intel.com.
