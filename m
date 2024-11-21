Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBQUA7W4QMGQEHW3LISY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 790239D4E67
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2024 15:14:28 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-212099b3f01sf9310205ad.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2024 06:14:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732198467; cv=pass;
        d=google.com; s=arc-20240605;
        b=JjViz5P5SnQyUNxse5Er2re8+VdXv9EW0s9S8mUimuqNQTf0PjMAoCMuhvGC1ZBJdJ
         O4f7XhJcoFpnoEhMQM0zXEuVYU8Ikkv6iwdV4U43lj9KeY0LOsoC1KmetnI6CehWMUX4
         EJ0tGYbeaAwtLVhAKpCzkbwDF5It/XnUYFy/YQFJmovkc6CK2g7R7StlkUGI6/vSJkWg
         CMs1aiJ4FwaVcSPR0ZDKNx822WIqOxyhDnnadtGgdgKwp9xkI1G/ONmwc8TvTaWaHhtB
         j+HCxtooz4oSAzTn2EzM4mvgxy/Hbxtn1DjN06Dvsyh7/x0vG7MQ4oft6tVFcfOmP9hf
         Xw+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=R712wXVgxVZ6TBn1BAryLvl+qG2pcNnIlCz1KCrk8Kw=;
        fh=YWDr4oIrh3qwkv+Y/jcga07XCdqbReHCj7TYoF/Poqc=;
        b=STm+KsF4oM2lu/NYQh6p9Nv4l7hOmR4jUnB4Rot+rO6eaE6og2D0YKx9QC5KUoO4e2
         DfIMeP8bxEHImhjtISBqoudeECroJlXBicsPmT955rkkcThvILhqxtLMg0eiK11E2lEd
         yaWb+0h18oT0qdAn7Mn0j87/E9D05o9uMHOS1CgiXN8TGLzxL6pi0uQ+4DEMDZID4wzw
         TcXHNZBpXtWOef+3wcNBdLIOCYubR3zrCtsjndGWPif4hdF81OOHNgCqmSgcdltemPpU
         wvBm+62eK6Xha3oaoYPVI7IZ/vcbNgxXUlpe6elZm7qtWc3Us9DhOCOQIei1mtVT+7Qn
         4nwA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=JiuTgMi+;
       spf=none (google.com: andriy.shevchenko@linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732198467; x=1732803267; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=R712wXVgxVZ6TBn1BAryLvl+qG2pcNnIlCz1KCrk8Kw=;
        b=gCzZSyC1FUmdPsB0dXBhi8evawaMXipAsyJRXtK3zAQ4h8NTU2WtmCX7pD2LO4w3nS
         NhQqAyQQOfykr2TqK20OfmEV/ctNH6NAYgorP+TdYM41AAkKvOwnfCaIWGjeBVR5+Dlc
         z5mDtADGmi/KMUYT6JDmgOZzQqVRQ4L677ymJEZqO+DI+dHU/29HIXb2SDEV5yEcNzHT
         NVlVtO3xAJ7Wua2YpXb9s0UlvNye9OrUnx8B29TgheXnomoHAeLCn1dJiCKyeHEmN+4I
         LEtldFfv58aY8XD/QZS0xL/g9xfWu9xpIJonhv+YeeJhesKnQv8kh/eSj8yFQ8Z+qscs
         DhsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732198467; x=1732803267;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=R712wXVgxVZ6TBn1BAryLvl+qG2pcNnIlCz1KCrk8Kw=;
        b=mL0NjtS2lEP3Cqi7AhcWwHs+ifemRGJ0LeA1QRmC1kC3w0C0ZlFsF5ENJ/Jb0H8ug9
         JcmMAVB5uNBteT5ncJ+UvUo3bd1outylSNOMDmqyulRWLrlKwSRkmTbyeM/IcA9uzUzc
         MFi1OZCE4tzTAtU9ajTAmvXcwqDVjWu8pQe2kDPm9LsphL+t2MCCyPdcYULNBPvpgdLf
         XklAnDNeopWPidvVafDSBBRFS7axY17ete6zh7n0otjyQHIEqbXnselg0LVuNZC2gGDO
         tBSQLQUO0fmIgjM9DUDUhw2AUxGJvRJunKVVzaIsf6wpBYA9UtfXIOOUItcG1H8bETQ2
         RRzg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUUT5rZVHq1vWIHMjzzWcUDYfgPw6T8T6a3JZNPZ83YIKhpdOa0cSEm0xhqkcfNpZ6q/2rcZQ==@lfdr.de
X-Gm-Message-State: AOJu0YwF0GTry/aweCvmXBzK4XOlfCzGaKuQVOitpty0yXarmYHhs/SJ
	aa98VgCFdK7WvqAM4Lbj2CBVycjbLywik51pz4bYlNV8SAYaD9GA
X-Google-Smtp-Source: AGHT+IGEVmtGRaD6z7y6g8U4b85xMVeMHJcDpbNZfF7Z4QmTJ20ZnAL0njd90f9TSghM/BO+Wv2ddg==
X-Received: by 2002:a17:902:f682:b0:20c:6bff:fca1 with SMTP id d9443c01a7336-2126a3ad151mr88090905ad.23.1732198466757;
        Thu, 21 Nov 2024 06:14:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:845a:0:b0:724:ccde:2f5 with SMTP id d2e1a72fcca58-724ccde0334ls544727b3a.0.-pod-prod-09-us;
 Thu, 21 Nov 2024 06:14:25 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUoh2VoUfyPfpqoto8R2Lr6KtTpTxqHy5IFmKinuU8XS+FxUCNV0KXD66EWBbNfxQCIn+8R919Yomw=@googlegroups.com
X-Received: by 2002:a05:6a20:9150:b0:1db:f960:bda8 with SMTP id adf61e73a8af0-1ddb06255efmr10045053637.34.1732198465209;
        Thu, 21 Nov 2024 06:14:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732198465; cv=none;
        d=google.com; s=arc-20240605;
        b=IwFc86vYQfZx2qIgWpt40luAmuhhq5cJ2Ww6NQFppIVcBDH+SgflMJTkGhEgwsY/eb
         Y2LIAQohQXQ4C1xeTVpUxtUNKiKz9eugUf5V8XSvsF/zLFA703CBWMSUYxXAFVLEdQmM
         4ZpzqhGfWHfdQpUV53lCdSO0RIo1b4OyfUAAiN1VCZvPLnkZDTHUdA/YQwqlQCLGGimd
         x7vLnd/DWVVZe1HSIwVHLi3Ozhh47BF+8wqUNYb42neQqnT56OwEk3+di3dHpQ+ldfdd
         kiguvbRXqQfo4odlymX+0CTbupP74Mi/bY4/f2PVZgyqcXkelss9iootd8pnoHY82x4o
         SYsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=m/yBciuXMAywdCQY1Du3CHRLbn/sAZunSCRm80IC2WE=;
        fh=Asz3tCiqcb+lO3Qc3nLyQSgGVV4z17Eomw2ZBQ8X/2o=;
        b=HHg2n38LyKPDrewsSWFCX0Ij0dvDzUwbNuG+0Iio10fL1mmng4W64CG4hzBbQdNxM+
         K4ohrDfko+0Ga+x/c1noG4LyzY2PYP4OzFOssivYwadCAXuv6K3avx0AOb+n+tNoNsHK
         L8qLcbOJjCLgmSzuRecdpdhJ35geicOP+sObkeQCJPqj9fFK+7lZYp/KLWuwmBw0/ie0
         J9QuQVrgShWDW2Lotee92IJG9P4rAXtas4Q0sGtwJxoTTFvULvg67RDQFMsSmwEXh3F7
         04VrxQVnj4AlxCNYObnkdBPA/0ZmmA8eea/iBp0/kZ6ZmB1k09J7Tw14qZfEiDZTwdh3
         YLEw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=JiuTgMi+;
       spf=none (google.com: andriy.shevchenko@linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.10])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7fbb64fc0f4si87098a12.2.2024.11.21.06.14.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 21 Nov 2024 06:14:25 -0800 (PST)
Received-SPF: none (google.com: andriy.shevchenko@linux.intel.com does not designate permitted sender hosts) client-ip=192.198.163.10;
X-CSE-ConnectionGUID: H+seWVKIRT+KdPGDB4dBYA==
X-CSE-MsgGUID: +ZZFu1UZTHi5fBwYoDmfVw==
X-IronPort-AV: E=McAfee;i="6700,10204,11263"; a="43707176"
X-IronPort-AV: E=Sophos;i="6.12,173,1728975600"; 
   d="scan'208";a="43707176"
Received: from fmviesa006.fm.intel.com ([10.60.135.146])
  by fmvoesa104.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Nov 2024 06:14:21 -0800
X-CSE-ConnectionGUID: 2U49WKnvSGe6ETjvdnhKCQ==
X-CSE-MsgGUID: dpOzJJFQR4eGUOlkHuCW+g==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,173,1728975600"; 
   d="scan'208";a="89867598"
Received: from black.fi.intel.com ([10.237.72.28])
  by fmviesa006.fm.intel.com with ESMTP; 21 Nov 2024 06:14:20 -0800
Received: by black.fi.intel.com (Postfix, from userid 1003)
	id EB1DE2CA; Thu, 21 Nov 2024 16:14:18 +0200 (EET)
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Cc: Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>
Subject: [PATCH v2 1/2] kcsan: debugfs: Use krealloc_array() to replace krealloc()
Date: Thu, 21 Nov 2024 16:12:51 +0200
Message-ID: <20241121141412.107370-2-andriy.shevchenko@linux.intel.com>
X-Mailer: git-send-email 2.43.0.rc1.1336.g36b5255a03ac
In-Reply-To: <20241121141412.107370-1-andriy.shevchenko@linux.intel.com>
References: <20241121141412.107370-1-andriy.shevchenko@linux.intel.com>
MIME-Version: 1.0
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=JiuTgMi+;       spf=none
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

Reviewed-by: Marco Elver <elver@google.com>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241121141412.107370-2-andriy.shevchenko%40linux.intel.com.
