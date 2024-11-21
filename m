Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBQ4A7W4QMGQEBMN6STA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id D00069D4E68
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2024 15:14:28 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-5eee0967128sf840602eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2024 06:14:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732198467; cv=pass;
        d=google.com; s=arc-20240605;
        b=YK6Fvv8OGi4JhWVP5tIs/RHWOpU6D7Y4n9koLpIRLdcQx0IMd9gFl0fvLPD/doCe1X
         +BkrwfBY3lgRh5/L5vI08frHLUwf9ExdqpYL0hC7Iwl0GKlse04axptPrZpHQ6yjWEjX
         u7TpYMWeKX0cogGg+HJLQkZMhKNqHYwq/ounYcmQDUZ/hvVTxO76RY9N9reMIdXfGm3Y
         Hcr22Llv5eIqAAnaGYxF3X0kwUpfGd1Uh26naAVWDTOcMVeIr4/fZbflLaAAb629j+Ur
         RglAv+xTRa4DfFQUHGNKg5abwJ11iP8onc5QnQzZ/s5yQx048yqJpp6N5c7+wMYFhB6G
         ho/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=5153anLT+KKYoM9tY1Ao+ASV+qYm6WmIhuHwvT2kfj4=;
        fh=+38XweZQCG7jQHGF+U3DT90MVqFKODkVswnswxmuaeY=;
        b=iCWx0juzxJOdAs8eFfuPkZizlyIi8KPCwC8OpSl0yAQAKrmCFs7M+0khfUzRHu0Frf
         EGLQOyhBzKEE274X3esDlYYDVtHCrWWnx1PS165hSVm1tMZVCIOswNRZK6VY1wI92YlP
         uNMWorvhwMr/DV1LhvoUalJFpBtX8zLSgFdNu9VlOclAAf723oBGy8LVv1iTyECHQ/tA
         ZgmK7ejbBpqvN22Zossh2kM5wKYBeECahbqcWHCc4rP9JdwsvAY079Eu+wlEJ90V1N66
         cfPlKtj5RT5dE7hnS1B/UimGpjq9H5s6y8Td+fspCJgKuRQEuFHI5Io1lJvh9tNVDyMY
         7P5w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=P8HmNugz;
       spf=none (google.com: andriy.shevchenko@linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732198467; x=1732803267; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5153anLT+KKYoM9tY1Ao+ASV+qYm6WmIhuHwvT2kfj4=;
        b=F+jIEYJxrHo6KXgT6wkYNz9pmI0EnZHiEkUASeyuSQiXMMPSKwpda+3RKVQChufPmx
         vxeFkPmQNbkuFKoC2N83GoW/zr/PtaIYN8kuY++rhK8j+nrz9Kvm573gAFMlM7KJu+yf
         MEpr4+9N7+UOdEOj4HmZ0FGQAeVD7C2qDMr6vfyNWQBnT1Bf7XOFn006JSyTm6WlCBwz
         Vmgwh9sD1qq258fDoKcXBjDH5s2n/8Fn66aFsL5ySmeoowaW6cpjI0IQUsJoDoI3gBR9
         EYW8SdRLqyUJH62tRusOBcN7Vy7rVSI8bOBlP49x+mcRzSaTFIyfn5BkqbDj9mwKs6Lj
         xlKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732198467; x=1732803267;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5153anLT+KKYoM9tY1Ao+ASV+qYm6WmIhuHwvT2kfj4=;
        b=PDLJpNx/CeGKV8Fg9F4J5bf7nCzwUgUlGLgyT0i9iYa2LqjDR+yTpFOBwIaRz5f9D0
         XA1enif6Ek4rjuXeiwy07xj1zj/2KzGlHugqjeXBG9fUOIPfBx5bIgMkPro1i6dvS0l4
         HrXZlu8tuDlY45PxsJlPndhpVmSE3iXh6/W+SPjlongXS6hMv9NndJ9zTfFjOcgITmYb
         P0hkksdN1HeoCdVSw0VyZ5rfm0n8ydrQ53udopZBJps3IhQPUsfvLTaz4JrsQ5PM/WFm
         fW1a4VzObfWuUDTkMJJ0Nz0vGwgKXQ1qC5qfufBYws6J3aF8eKMz9MLwgHzdt3O1hiOu
         1/oQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUYQ/aBD1yMsdt54rd9eZ/lPg7BJx3f4wNB4Exm/UO1W3lfvowUkoXpz6fvWe2Uwqt9HT3TNQ==@lfdr.de
X-Gm-Message-State: AOJu0YzWGrlHmAuGhaBX07WbmJrAmnLg30bVw4cMmwXzyCmDqA/LE1Y0
	tE6UwBfggq0msWPdbA4o8ekYwtH3Zs+lsGEl36D1wQfA3y3zGyEp
X-Google-Smtp-Source: AGHT+IEdeW5jlqyBbWy3QDafrZxou7eWqrqlwa9CCQRHob4V/BUB1Z3i34ls+l4Tr7fl7NelZegSlg==
X-Received: by 2002:a05:6870:d24b:b0:270:1fc6:18 with SMTP id 586e51a60fabf-296d9a6957dmr7270960fac.3.1732198467536;
        Thu, 21 Nov 2024 06:14:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:9e91:b0:295:e98b:7a4e with SMTP id
 586e51a60fabf-296fc525dc4ls658089fac.0.-pod-prod-03-us; Thu, 21 Nov 2024
 06:14:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX7fz4sP2rcsTK2D2CTeLGScCdqqmIIee5SdJUQKUD+fVDSCt6bSkyYENNWALhB80HMHFFV1YUL7uA=@googlegroups.com
X-Received: by 2002:a05:6808:f88:b0:3e6:6145:d0eb with SMTP id 5614622812f47-3e7eb7b3994mr8414117b6e.30.1732198462621;
        Thu, 21 Nov 2024 06:14:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732198462; cv=none;
        d=google.com; s=arc-20240605;
        b=BT+2OFyNzCaaRsJCDM/pg/T3MvjsM2E0839kG1B78egc+aMQG9wtaJKKT1bY0yiey4
         ga1dw9m9iT8th15Y8a7EsmTj6mEkYX8cGbDGefQXjGLEUadZRlk6eOxREkVLqFl8fQh4
         ITLLdEbRHc2x6oWsoNQYHl4d44S7p5+PvU7qNHlIMGmlLGsXGhW+WwoFISWmCtFrDQl6
         YGP45iOSAHAVmJ2ETmCaoddlD8wNtRUPhRMeRDkReyhUUDbl/QtKlLrIKlEF5H8gTXAc
         X3f1RL2rGkdNZBVamWeIrRJhVBzvkjUs2Pidvc7NZUhAIaoU92K+92VkDA+Z2VNChcf0
         briw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=74PtPeLwDOy/XBcrcy2fY1BvYsM1z/9R85xMScpJ2zI=;
        fh=Asz3tCiqcb+lO3Qc3nLyQSgGVV4z17Eomw2ZBQ8X/2o=;
        b=eLLuIjtc4Vuh59ffry4orFpmJESDmn7JWQUiPlT22yPbrxTFhjklOtVSX6QMBo0C27
         1sgGHcge++AiS27q/pLgYu1asTMZU0z3DUip6iLkz1pFQ0PanecLHXJXELVkC/Fn6h37
         tkwi/qbQRz02yr2CoIfIWPX4PW1Jnp250xgvuloByaiVE+bRkpuApnCfBTC7sqge7J8U
         Haz2C9wOWiMiSOzBHXlOiP0i3aUhB2bFTi00Fz51EpPUEdGoPaIudUUegEe36iWL1Lja
         VqpbsNMkZT1y/bDnDRz8lcXwiP1zs90nfHkxNJxczT90xAKSFKdCTytBQP5d51Ssagx/
         Cqqg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=P8HmNugz;
       spf=none (google.com: andriy.shevchenko@linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.10])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3e7bcdc2fe0si709595b6e.5.2024.11.21.06.14.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 21 Nov 2024 06:14:22 -0800 (PST)
Received-SPF: none (google.com: andriy.shevchenko@linux.intel.com does not designate permitted sender hosts) client-ip=192.198.163.10;
X-CSE-ConnectionGUID: WAqOtNL0TNKjky8akxBKkg==
X-CSE-MsgGUID: 2IBsXpioQ6KaSz8r1grilg==
X-IronPort-AV: E=McAfee;i="6700,10204,11263"; a="43707170"
X-IronPort-AV: E=Sophos;i="6.12,173,1728975600"; 
   d="scan'208";a="43707170"
Received: from fmviesa006.fm.intel.com ([10.60.135.146])
  by fmvoesa104.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Nov 2024 06:14:20 -0800
X-CSE-ConnectionGUID: ThFwL1k/Qg+gBsWkB6sdQA==
X-CSE-MsgGUID: LKK6tNodS0KGm7gk5wEEaA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,173,1728975600"; 
   d="scan'208";a="89867595"
Received: from black.fi.intel.com ([10.237.72.28])
  by fmviesa006.fm.intel.com with ESMTP; 21 Nov 2024 06:14:19 -0800
Received: by black.fi.intel.com (Postfix, from userid 1003)
	id 4B2A918E; Thu, 21 Nov 2024 16:14:18 +0200 (EET)
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Cc: Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>
Subject: [PATCH v2 0/2] kcsan: debugs: Refactor allocation code
Date: Thu, 21 Nov 2024 16:12:50 +0200
Message-ID: <20241121141412.107370-1-andriy.shevchenko@linux.intel.com>
X-Mailer: git-send-email 2.43.0.rc1.1336.g36b5255a03ac
MIME-Version: 1.0
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=P8HmNugz;       spf=none
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

Refactor allocation code to be more robust against overflows
and shorted in terms of LoCs.

In v2:
- collected tags (Marco)
- added patch 2

Andy Shevchenko (2):
  kcsan: debugfs: Use krealloc_array() to replace krealloc()
  kcsan: debugfs: Use krealloc_array() for initial allocation as well

 kernel/kcsan/debugfs.c | 20 ++++++++------------
 1 file changed, 8 insertions(+), 12 deletions(-)

-- 
2.43.0.rc1.1336.g36b5255a03ac

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241121141412.107370-1-andriy.shevchenko%40linux.intel.com.
