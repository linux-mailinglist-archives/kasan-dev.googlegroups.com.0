Return-Path: <kasan-dev+bncBAABBY5372IAMGQEKZJ2PFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 7DBC64CAA98
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 17:40:04 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id bd5-20020a05651c168500b002467c7cdfb2sf667995ljb.16
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 08:40:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646239204; cv=pass;
        d=google.com; s=arc-20160816;
        b=eN2PAFalFiQVwLu4AgV4cVe/zHYC8k37dFXYJozhLM2a5YNsiTNdMbMpos7GUj60zo
         dXCmW461ow5ADxQ2cKyiwy4/3cHmMfq3Y0JpYsFpUJQOi/LnvQ8xCfCeIjhsHh9X3K5m
         FDhRzINe4+OjJ5qg3IO+XbDcy6RJYBfyRzw6qMv4yueWCPoVDQxcTfP2Q73fjgc4qeux
         ALnIcj5M2fsxdo6HykR7ItEvXAcvzxtNSZSmzwbjRoFjiIV9ctkZVvIXj6J4hWU6b30f
         aNgiApwtFA/11t1snjO2AuAehA2B0imwXzfmGPeoU0UWGidd0PTVRNYyawwAnfnbIU/B
         octw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=MZDgzRY/xbYP/RUipC/i/3Pd18CUFRJ3627dWTQDcas=;
        b=FiDGYteQ5lXYeXF6MCkX3j55rz5YQdUYxCOG12Jx1S2YZ4ljd38PHDmkFkEqMZFG93
         sDAxPk9Shofofs59Kwlv/W3u15L631JJs+myV8YKYScGaTBk3sfL8ww9TCbene9kwOl/
         CRY8wBeGgIy/np+VZU6pRagSwFP5H5VkpZubhMiP7wAbGv21bSLH9+dxBIor72Ln81fm
         efTb5aKNBqpJUvj2ZHPVoR7WcUZ2IJJ29xwHgHnPwd9djSgZOPMuEen+0pmT5RQbnYG4
         2p+Mc9oRLQd9F0mMGBne6tkofFmGZwSnP+ewk6D+yEi24+SMKkeXt9rL8+lQUGJvOADw
         rUww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Vvu6o+ZY;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MZDgzRY/xbYP/RUipC/i/3Pd18CUFRJ3627dWTQDcas=;
        b=gj3vf4aDEdq22EsnSe1bRcI+Ux/AFevM9hmQAaeC5BZ6m404LRmIR19mGs5j0txid6
         35KWcJu/XGYAYMWZ33fKOU3H6LAaqUKC+pfMVDG/DHZqpUcDVPpJQhiSiytClAl2r+o9
         RznzO8KVYy7rR3rBzxJfGaomHzRkdWb5svJyS7Ax4jBFaW3o/LBrkJgwK4TmXPDQ8oy2
         LwgaeQMYW42T/YtQmu/57nYwTNyPSHeZFNPi25k3XPnkEv1zr5S6LASKXYaP4pCAvUF/
         MR1AMdc3Ezeax0ZWyOmDYS3bRRl0vjuiUGDVaRskPbRY2ZYAkqHGOT7dGnPPxr8YUKIv
         APCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MZDgzRY/xbYP/RUipC/i/3Pd18CUFRJ3627dWTQDcas=;
        b=NJixA9t/5nyP99wD94OF+jJC56welWKWBohai/qCSzQOb4aZ53o1GePUwI3vTzzrpH
         BVjf1gbppTl9FwCcFJW/mGlm+UTKYkN98DvNSHHDmTorwUAYfO1Vh+iJROXToVYm8mBn
         bbvVq/W+ewDYJtrGN742RnRtL87KK1odhC7pJ1gvRp//5dlgGCcyct2e1ogrLQPApQ4G
         xUc1WgT6W+tPUO/UpRs8Fn4LiGN4rqiLaqNa9aRO09M9EbeYm/5PiYCVgP98cEjAvU7x
         qZTP/cpxX92ElkFa7M0W1Q9PKUuALZxEz0P0USn26GJuhinqM7mcgLgAY3Fn/lAOOjYE
         dmdQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ezIiLVjhagWS8/9grIFzFxziFKFn8+wLes5w0tzQNOXafUB0V
	mL9XbZdBnNOaLnHdHotJXSI=
X-Google-Smtp-Source: ABdhPJwh2R1eNrU0AbxNaBj5j8XTNvUSKOxz/ZANsL977PdDIPjhGIwuH+3gP3vk8nmcLg7Vfj4ygQ==
X-Received: by 2002:a2e:a4b4:0:b0:246:2930:53d7 with SMTP id g20-20020a2ea4b4000000b00246293053d7mr20126292ljm.74.1646239204089;
        Wed, 02 Mar 2022 08:40:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bf20:0:b0:246:801e:c87 with SMTP id c32-20020a2ebf20000000b00246801e0c87ls2227608ljr.1.gmail;
 Wed, 02 Mar 2022 08:40:03 -0800 (PST)
X-Received: by 2002:a2e:99d6:0:b0:23a:925:6aa0 with SMTP id l22-20020a2e99d6000000b0023a09256aa0mr21397197ljj.110.1646239203213;
        Wed, 02 Mar 2022 08:40:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646239203; cv=none;
        d=google.com; s=arc-20160816;
        b=CeO0DntDOFT2zTNXGhhRNQS2mvfjx5yYWiN3D2pDeZYO8+vL0OOzGANjymY3gshAwZ
         81bQLULXp2K0eTttHErIvTWHiPWbOc7c9ZR+2j6cQZDD9zRyPzdhLyHhwCZAF3MgI3c1
         5KyVTD3iAfUgUnX5LysJsb6y4cSr180hCxmxujbmY3KP2SoX1+fxwPwIJd8nJ6/orTtq
         lrDmvfio/y3xOWoA144cs3lzR380gAUI/Ev+zeFf3tTvjgSQnlOl5IvVgnqAjbZIQrsS
         PteIh6Y/S0SmeGu+CFsrgqsS/1jdW0oM80Mkqybaq2CabbbrAaIJA3zP/M33yYuzzPvC
         A9zQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ujXTYxMun+rvpXDm65LBC0iIPgbPBoZhDfYPsPYRrpE=;
        b=abWkq9kg3QT8TFhTS8mDStRBryfM43IAb9MnhQ0Ppyk1JUi+clQ8u676vLEEUrFsjU
         1V2Dkog1YqYJc9MF28a7qCaIUxeQMF68t+GtLOEakCN18Q8kEB3CFwvAdrJhUimjaEvc
         hGC+nvIgTkC1xtLp4jPld5LPzZcCtM42NJEci1S6LNVRFIZWS8KPVqjngaC9xmuvXPE8
         m73ISOIZzJtZtMgFd/RMDJhwtn/LI7xwk3GVXNkHQYpkSIJ8cOl/lpVvwxL5+x91xSgT
         GciGji/a5qajD9fGAwgVwrNVIp/fWSAQrmXILwn6cxHoVD2tdVLkLVsEQ5jNEJ/41GU5
         AVAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Vvu6o+ZY;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id s2-20020a2e81c2000000b002462ab45e78si1030856ljg.4.2022.03.02.08.40.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 02 Mar 2022 08:40:03 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 18/22] kasan: add comment about UACCESS regions to kasan_report
Date: Wed,  2 Mar 2022 17:36:38 +0100
Message-Id: <1201ca3c2be42c7bd077c53d2e46f4a51dd1476a.1646237226.git.andreyknvl@google.com>
In-Reply-To: <cover.1646237226.git.andreyknvl@google.com>
References: <cover.1646237226.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Vvu6o+ZY;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Add a comment explaining why kasan_report() is the only reporting
function that uses user_access_save/restore().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 7915af810815..08631d873204 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -430,6 +430,11 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip)
 	end_report(&flags, ptr);
 }
 
+/*
+ * kasan_report() is the only reporting function that uses
+ * user_access_save/restore(): kasan_report_invalid_free() cannot be called
+ * from a UACCESS region, and kasan_report_async() is not used on x86.
+ */
 bool kasan_report(unsigned long addr, size_t size, bool is_write,
 			unsigned long ip)
 {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1201ca3c2be42c7bd077c53d2e46f4a51dd1476a.1646237226.git.andreyknvl%40google.com.
