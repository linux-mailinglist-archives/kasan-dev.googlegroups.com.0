Return-Path: <kasan-dev+bncBCXO3LFH74NBBTHH37ZAKGQEGUIWFJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id E4D5F1723F9
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 17:52:29 +0100 (CET)
Received: by mail-ua1-x938.google.com with SMTP id b15sf7740uas.23
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 08:52:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582822348; cv=pass;
        d=google.com; s=arc-20160816;
        b=VLx9O4/xQHQUxFelajeMyW+FWjhNg5JVhhcJLDzSZ7Wih2gddH0TMOnkDklEKBnk6S
         g3Q9xnC6wIr8xrk26AkuDQIWiavfEiN4UUvo7+jDV8340p+ePX4+TgNlMBqotdauMqeS
         T8sXxRkGXnejIpun92Fzur9YEvvIwhHOZL8BXZ0o2hnGgYvEDrHSZm1xOO7TrcqWY4dj
         hYmc7Z6mFOGqUytNqQnitofpm4XNr+CMLiEAecRMFyc4aLUzQB6OsluudFIUlo6f7ybv
         z69v9EfUkZV6pUCYp6PIm52TrC0bEOxW/iMOOmLm518xvej/xWkxizhxuOPsRmyclJLU
         DAZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=VC2mRxlsMdR0gTeArbyWpN/8Eeg8+1pqka49cI1z1j4=;
        b=DbTmke3DPCIJeweratJRYWqFXOOGqZ6dbQjnXP+6nQFC2jXYH8rTQg4uhSL4qESqdV
         36HnHdYcG6VHeohY5cK/2XDBypdo0tb2Vs1rv8k1l/wmcUWu5Er2Tzqkq5r7/b6WSBrI
         nwSKUDvUeAh7N6dXlTgWHX0a1NYXKnN91Fg7erTH+MRBLeXOBx9J5G50uv9aKWNK9BeJ
         sx0OOyBx/L8RtdOi5HwOVa9+FxiYQ5zXdeu9CgQ5wFtG5uJcLqNP356l+H0mzq8UJBGu
         52uecAU1MSihjk//rKD2xtDUsGCnMgI1ZxeNAc5MwcI2aJ4dY3IHZfG+EHJaT5VpBM7a
         j28Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Uwjv1Nwa;
       spf=pass (google.com: domain of hqjagain@gmail.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=hqjagain@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VC2mRxlsMdR0gTeArbyWpN/8Eeg8+1pqka49cI1z1j4=;
        b=fNETUbRcgM2uhFns2XRwXr6bw4H3OvUKdD2eaMH5/N3AkdEvJ1jdxihlbmTsp4zHoi
         J6GwPNuoEgUPXGEFUXUkM2mafQWMTRWk8DaHEnjeCteUOMM58/grhpwdWmqpqwVXsP/K
         du8jB+/J2rBKohTWyFZHgBAmbI4zu+Gh0wSqV3rXgqBmFU4hdaLCUK5XuVK2L0CTNWaL
         cVPbsOZ9oM6A2IIehnxy5bJpqgsSdFJXMLga1TyhGrg3wRMxQMFTvYt+CXphILfeC7Hk
         oW9IJTRmlX8F4bksBb2/XFstAucsTQRt4+RaWTzmBXDhaxXMVShPOVkknllGTFzc2rZY
         obtQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:to:cc:subject:date:message-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VC2mRxlsMdR0gTeArbyWpN/8Eeg8+1pqka49cI1z1j4=;
        b=fomdKcMK3+eTYE3DkMG3NjapdXJk04wMwpWP09UG43mPnUIevqAWQPqlYiQZeiiXNu
         Xkbrg3bnRL911TQcPd8srodaEvS1HuPwNvFKUw3aeIhLdZAjihHsJ6fmBZs+z9l1daKc
         hcGG+R98VzWrc+pwCcLWcufBySKe7nTgqLRsb/e602XYMQByNhC2GxaX4wPS9P/EWiZ9
         DzIGiVTfP3cwSPrG/QnVs5znO1tm24c5dxB43A6P7MuPOs4AdiWno9z8w/nZGGaV8Uhk
         PuzRbpZQdBV74Xjys03YpJ6NH/d5iWk5zG5qtW6wO956/F6EphVytKsD31M2zLe19nA4
         LVzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VC2mRxlsMdR0gTeArbyWpN/8Eeg8+1pqka49cI1z1j4=;
        b=GgIJ5zpT9+m0O7wpbUhD93P+f5/u/dYo7IcnStF8QftDVwCMCgUVZGngsJ1mTxf9Cr
         E5/LKZR/kN/saVrNfOsL0ZIuzV97iV+r8v7l6iDkrXS5gXyUkV2W0tAsUFAHyVv/E/PG
         xzE1agj0gf0X+N8C3+gd4W4EoUHq/rLztZ7izl/jbIWScVXHkK3zqq3pVlcu9NF6Xoi8
         L8Lzd35/yvK0MmaOf/lDnzAf41pIbzSxiB7jdf7XRSCrXHvFv935vWUsJ4x4QQGbcfMt
         hMoU1uJC3+zDQbyPlRdnt4v8RFP8lTpGN1y0ifi9nQZzlZGOPL9poGlDBCr2FQTHiZP3
         qtWg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1OEn/gsHM2DUDeWI25fLYbYMj6NQG0Q5BoQLRItwNO7TTDyHLo
	8kVep+efjmwE9FAmDW+o9WE=
X-Google-Smtp-Source: ADFU+vvFd1VyCx3KMby9tKWS5TD3DLVISH17JvB6NWWwgp6xxkHNfyiHR8gOHSCZ/7fBSO8mYScfDw==
X-Received: by 2002:a67:10c1:: with SMTP id 184mr123669vsq.76.1582822348628;
        Thu, 27 Feb 2020 08:52:28 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:2883:: with SMTP id d3ls273557uad.6.gmail; Thu, 27 Feb
 2020 08:52:28 -0800 (PST)
X-Received: by 2002:ab0:7612:: with SMTP id o18mr2971184uap.73.1582822348333;
        Thu, 27 Feb 2020 08:52:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582822348; cv=none;
        d=google.com; s=arc-20160816;
        b=kQyBWxl0UTVKSA2ZqiC3XB1qmGRJpetQQDiYgmpAuaNssUtCRW0vB3m3H9KKLvQpXV
         dzyc3ZcgNmwkhohM88lT65CXIVC/78N0GZivwGt2cW5iapIKdbTAduD7e3/TG14+RD+i
         I3YtNu6GzrbhRph7KLPHzA62A/eP1JQlEIo298xg/4DmXs8EIgbBGOhgp3mA+51T0Oz/
         YGQK7hDlIKpILZZ8hKndBC2tdvMLP56oTtB3diFwjARxOiUtYV/GLVA+Nh7HVpAM8iBb
         CeldeNc/RM9Oq/hT4xYDV4VIPP7RPISuYnydwUDBqW1QckgYtJutpcWej0XbPixObg4q
         kX9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from:dkim-signature;
        bh=jKuXW28lW9AH6MJSzQGV9UYY4yuB4lYRJ5J1zMaBeWg=;
        b=Z2zDoKtcqRukejdxPnfHjm6YIu+3FE6YSRB8ttwz24OZcBQVxb7fFJxKrOTWOqALe/
         DOiMc1JnR1u/pTQxkTLkk1GH5MDGX9vEEHrVjMFUtSqzA3BitCXhihr2FmFFTXwd8z1y
         uOH5LfcUWEcGXtvMcxwDPBqwchGiHprbOlJdTs7HKnTdrwHnMSr0i2ing7bH9Q4nT/e6
         cBR5MeLN2m+T6vumHLa+8Bjk1jFVbjdhPbnuY3BcqR022zWan6Uiq5EH7GtL8Z8NE14a
         +hp/fpxCNgzv+o9UF34uF0faaFoWPd2fE9y4mNbV7N/G5KYOQc631CTz196kXrVzRJeR
         tT1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Uwjv1Nwa;
       spf=pass (google.com: domain of hqjagain@gmail.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=hqjagain@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id i27si10279uat.1.2020.02.27.08.52.28
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Feb 2020 08:52:28 -0800 (PST)
Received-SPF: pass (google.com: domain of hqjagain@gmail.com designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id t3so2546pgn.1;
        Thu, 27 Feb 2020 08:52:28 -0800 (PST)
X-Received: by 2002:a63:4a19:: with SMTP id x25mr273591pga.167.1582822347390;
        Thu, 27 Feb 2020 08:52:27 -0800 (PST)
Received: from VM_0_35_centos.localdomain ([150.109.62.251])
        by smtp.gmail.com with ESMTPSA id 28sm7247498pgl.42.2020.02.27.08.52.25
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Feb 2020 08:52:26 -0800 (PST)
From: Qiujun Huang <hqjagain@gmail.com>
To: elver@google.com
Cc: dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	clang-built-linux@googlegroups.com,
	Qiujun Huang <hqjagain@gmail.com>
Subject: [PATCH] kcsan: Fix a typo in a comment
Date: Fri, 28 Feb 2020 00:52:22 +0800
Message-Id: <1582822342-26871-1-git-send-email-hqjagain@gmail.com>
X-Mailer: git-send-email 1.8.3.1
X-Original-Sender: hqjagain@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=Uwjv1Nwa;       spf=pass
 (google.com: domain of hqjagain@gmail.com designates 2607:f8b0:4864:20::543
 as permitted sender) smtp.mailfrom=hqjagain@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Might clean it up.

Signed-off-by: Qiujun Huang <hqjagain@gmail.com>
---
 kernel/kcsan/core.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 065615d..4b8b846 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -45,7 +45,7 @@ static DEFINE_PER_CPU(struct kcsan_ctx, kcsan_cpu_ctx) = {
 };
 
 /*
- * Helper macros to index into adjacent slots slots, starting from address slot
+ * Helper macros to index into adjacent slots, starting from address slot
  * itself, followed by the right and left slots.
  *
  * The purpose is 2-fold:
-- 
1.8.3.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1582822342-26871-1-git-send-email-hqjagain%40gmail.com.
