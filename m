Return-Path: <kasan-dev+bncBCT6XLET5MNRBTVZ4KZQMGQEGR6FZ6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id EF999913ECA
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2024 00:08:16 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-6b5176fa67esf56808146d6.2
        for <lists+kasan-dev@lfdr.de>; Sun, 23 Jun 2024 15:08:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719180494; cv=pass;
        d=google.com; s=arc-20160816;
        b=qpqjKcOax4zgB1G2IcoFMgEIpggyGBhYkPykwu5hO2ac09oD0uPQIEGjwa68R1ug7f
         fpKt8mU75TmksID19lb9srTcJQ2WPBpqt9Btsj5M3VvtLhmBcQKm3unsJC/m5QmOdMPm
         flPy6KBCIghBeEfVK6oDTbHV68KUxWeV7ki/q9J1X0UjRdOzG4qw+SpV2lLnfao9zZN9
         gpBdxuIJEGayqTaLmQ6fTSflDv1swqdmoSShz/4ebwPg840v9VgjbCoKVo1X3hamO3xZ
         KtqPsAFmkUdSK3lHQgX/dyQmpSyya3zz/+Dk4vZ6n4mV34EUW8ml+XaK8bxJyeg4mk8i
         HiTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ux0obvGX/CP6LXt14xBry7plHYvyKIClv1AVvTMhRaE=;
        fh=6s0SGhtfo3T07PCyTSgQ9Payv4uRZclovAg73GU5o9Q=;
        b=pBGze+g4ggcMXa1UBKKsDidbIw3ML+pHPbFt+PttAgvSrtV8/hzgdQGqJ8iqaG8KFT
         sFxl49mvT/P9LQrKQ3kDGfewh6ejzGK14DWOyuQeErmS7u+TDH4PV01lJEPunuD2AFC0
         WL1uGvH2Vs24v6IJST9eH7KiyGq/LLVudtwgqJjgLaHwe9C5iF76NmlLGK7hOVEFGoCJ
         TUf9u+VvhLxedkZClgROTNWEuRiOJrT+1HnArQJttshdzv/tVZZFKrI8ekFSAeaSYp+O
         13V0SbE56eWUe0uuZG/RGgKL8ascSaQn4GYVLnl5ZZ0I+v8Ax0OAbQ6/6fhJ8b8pkJYm
         mb+w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@toblux-com.20230601.gappssmtp.com header.s=20230601 header.b=VtmEZ6fR;
       spf=neutral (google.com: 2607:f8b0:4864:20::62a is neither permitted nor denied by best guess record for domain of thorsten.blum@toblux.com) smtp.mailfrom=thorsten.blum@toblux.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719180494; x=1719785294; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ux0obvGX/CP6LXt14xBry7plHYvyKIClv1AVvTMhRaE=;
        b=NudsY0cfg5T9DaWCZxm8Jox0w3cjla8wKoq+ruElO2uonej7+wqm7p/zG6s+1h3vT+
         UBpl9dC4FoFdskhXKPcmeOFT2cvvvYdXW7/wn5rsuo09XChS9fjEtQhpXHO4GBpmetNP
         y2j04lXhYKdqIewh42/9JT57Nw1NE0E+Q4BGri5PIywmq6WDhL/m8K9CdUsn1xavWnWi
         p+DymEsKDekZOPhwwSlgLqYPX3U7bq/BzgkwRXydtr8acFcI0m6SQ9Sxk0NeMK/Arm2p
         3XNoGH3lZD2YQrcIUChDRu1fo9hv99VIVxqaAQDE/8apO+zhUyLeBCldbyI2kIgDi5g+
         QcBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719180494; x=1719785294;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ux0obvGX/CP6LXt14xBry7plHYvyKIClv1AVvTMhRaE=;
        b=SUKDGYfFdtjl22aQfGPltegInmPWB2l8YTIPntZ7PCSpmQsJ+YH8PDs1R4RrgVQ4PB
         DysHjvj6lgj2Gsn3gHB/I8vB+WuKR5IcqSyx//yNJcDIWacOCISiLYY9H4E63y0P/yri
         nfnNfpLUVVVA524fIN0ExNDTvVKfq3UEO5PODCfDdo+lwVqYlKHbv/Y6fcdlAA+XssF3
         KGmD4a6vi78UHaQjqbyWWNZ6Ac08JoundWcueaoXCLXubFWWvAsquIt/XG8bO/tBYb70
         LobF9xqBT5Tl1/1trzotZG0in1w4HILUbdHNwhaEKLwj2LcyzODiMGsOX9hqhNJMRYlH
         +8ww==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUN11C0ul35fh0lICCmW7sT60btet5vjNHrii/ukv20o5llsXMyy2KBAzk2Z4K/xglccAjJAOtcW87r6C6+/7SRWsBtauiZVQ==
X-Gm-Message-State: AOJu0Yx7+MI/Hisn5dGx9ZJk9sLRCkHiu6ZVEzRj3al49woCvQBuIa+x
	QmCRohfddBeDWS7WVmzNSmb/9oMJmvJu94MCY3MqcrbPnKKOUMKk
X-Google-Smtp-Source: AGHT+IG+xkuj8Ywedj86QEXIsoI6s8Y9ssocki9kl/GHMIZg8fncBF//I326hBEJOfeJcshFKxDN/g==
X-Received: by 2002:a05:6214:acc:b0:6b0:9228:5a86 with SMTP id 6a1803df08f44-6b5409c5e47mr40742866d6.22.1719180494402;
        Sun, 23 Jun 2024 15:08:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:3b82:b0:6b0:88f4:b00e with SMTP id
 6a1803df08f44-6b510083a33ls38426036d6.1.-pod-prod-05-us; Sun, 23 Jun 2024
 15:08:13 -0700 (PDT)
X-Received: by 2002:a67:e3b8:0:b0:48f:4f10:cb0c with SMTP id ada2fe7eead31-48f52b500c5mr2456538137.22.1719180493689;
        Sun, 23 Jun 2024 15:08:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719180493; cv=none;
        d=google.com; s=arc-20160816;
        b=Xds2R5bU24aQuPMAZ4lA0UMjQ5Ly3M/PGSi+XkwudhmH+lBHVkniYpbJfAKkyUbUtq
         Ohoc5gl5HiwuYGXne4PXtOYQp8oAYWcSg8r/C6nyLwSOMU4Vk2IXkXBAkjP46HJI38OQ
         ihkSCquXhU/w2WwxEQGVWns3QPxLRdJw74ZaKLKyO5CdO+RwaAwbaG0dB8eZsN3AjHnI
         vZAnblDgMcjENgBhdKSbLbaCARWbMkH3Ic5Phj5E9GttRG7ujqsNL3HCzGT8vDYtuYue
         7DvX5vDneFbgapzKBtb/8lKd890GZKBdUNI16lzxCXDy/tELuCdA8cU371XlABj6Q7Hh
         QscQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=lQaycCZZJSmk4VvPe3LrTmMf0NGhS8rmwmIttagYe2Y=;
        fh=toGOZK0dqt0kJYuANp9HLAsRVUm98Uiv1sc2nSaC6O4=;
        b=0b1VvuZSDlGoHHEst9CVlIx0nneY53o26Y80LFu0cU8zAbwu9sJOD4ZVbEyNE2udQl
         BJpj4j+UNwADga/v/cBUlD09GMqAECLkb6oR6YFrswpfc2LhcsCSpEnLUMV/iM1hgppa
         uGiVG5A1LO5UIu0aqwpAi7PEkfOz6WwLgnOzVSSstBDAQ7Yk1YmC05DjB6Dh+cKJ8dAz
         U+B6CbOWrwmzlX8PoAyudySeWDsxjO+3ejUd7AWmMynuP3wRDfbIaEhY3RLuW2RQ4Hbj
         +IUNPn5P2xaMniy8iKoq4ApuT02FB7odxuOGJf8E04I+Vw9+RyNFBxx1B8Cz61c45SdO
         A2Rw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@toblux-com.20230601.gappssmtp.com header.s=20230601 header.b=VtmEZ6fR;
       spf=neutral (google.com: 2607:f8b0:4864:20::62a is neither permitted nor denied by best guess record for domain of thorsten.blum@toblux.com) smtp.mailfrom=thorsten.blum@toblux.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-48f60461f85si25890137.2.2024.06.23.15.08.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 23 Jun 2024 15:08:13 -0700 (PDT)
Received-SPF: neutral (google.com: 2607:f8b0:4864:20::62a is neither permitted nor denied by best guess record for domain of thorsten.blum@toblux.com) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id d9443c01a7336-1f9a78c6c5dso29176755ad.1
        for <kasan-dev@googlegroups.com>; Sun, 23 Jun 2024 15:08:13 -0700 (PDT)
X-Received: by 2002:a17:902:ced0:b0:1e0:bae4:48f9 with SMTP id d9443c01a7336-1fa23ee263dmr30122535ad.32.1719180492508;
        Sun, 23 Jun 2024 15:08:12 -0700 (PDT)
Received: from fedora.vc.shawcable.net (S0106c09435b54ab9.vc.shawcable.net. [24.85.107.15])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-1f9ebbc7edcsm49044635ad.297.2024.06.23.15.08.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 23 Jun 2024 15:08:11 -0700 (PDT)
From: Thorsten Blum <thorsten.blum@toblux.com>
To: elver@google.com,
	dvyukov@google.com
Cc: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Thorsten Blum <thorsten.blum@toblux.com>
Subject: [PATCH] kcsan: Use min() to fix Coccinelle warning
Date: Mon, 24 Jun 2024 00:06:07 +0200
Message-ID: <20240623220606.134718-2-thorsten.blum@toblux.com>
X-Mailer: git-send-email 2.45.2
MIME-Version: 1.0
X-Original-Sender: thorsten.blum@toblux.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@toblux-com.20230601.gappssmtp.com header.s=20230601
 header.b=VtmEZ6fR;       spf=neutral (google.com: 2607:f8b0:4864:20::62a is
 neither permitted nor denied by best guess record for domain of
 thorsten.blum@toblux.com) smtp.mailfrom=thorsten.blum@toblux.com
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

Fixes the following Coccinelle/coccicheck warning reported by
minmax.cocci:

	WARNING opportunity for min()

Use size_t instead of int for the result of min().

Signed-off-by: Thorsten Blum <thorsten.blum@toblux.com>
---
 kernel/kcsan/debugfs.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index 1d1d1b0e4248..11b891fe6f7a 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -225,7 +225,7 @@ debugfs_write(struct file *file, const char __user *buf, size_t count, loff_t *o
 {
 	char kbuf[KSYM_NAME_LEN];
 	char *arg;
-	int read_len = count < (sizeof(kbuf) - 1) ? count : (sizeof(kbuf) - 1);
+	size_t read_len = min(count, (sizeof(kbuf) - 1));
 
 	if (copy_from_user(kbuf, buf, read_len))
 		return -EFAULT;
-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240623220606.134718-2-thorsten.blum%40toblux.com.
