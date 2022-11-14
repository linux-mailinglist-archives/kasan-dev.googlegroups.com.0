Return-Path: <kasan-dev+bncBDHMVDGV54LBB3OUZCNQMGQEY6IN3XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AE05627CB0
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 12:45:50 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id e21-20020adfa455000000b002365c221b59sf1925995wra.22
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 03:45:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668426350; cv=pass;
        d=google.com; s=arc-20160816;
        b=im3Ux6CH2+05gDZ1yhTE2MFtDpKl8OthnBNHQSgeqOFFJbpQ+/7EDPcLpgCy7R2oDZ
         Wf4cwPDbIPydrQ+chNO1hl3lgQHD0W9lQYZFGa2Nwe8RpuyOpfb0h7D1fAjWhTX9zH0E
         6rn2RecnNQR8jBDflIY0DKwEu6llLKzrnANw2gk2Uk/KWsulkUK0x+yrkTm+0gFqi580
         MlfyU4WZ1DH/glbx1Oet2xMaKX7QcEcBv5TDQ3YPOvZ25Pi3h/kdWEd8VFMl8Ki93nPy
         +WcfanMUndir66s5F8fYHBjgsG2MGGaOA1c9eORc5OuicVjkm4CiAba4fz+9DReotOyD
         BzsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=FsuF/b5ot+3PGkKpUGps/PR3nJ4zR0NXoU1K6M1BtL4=;
        b=YHZnrTVu3WXvOL/6bDCv4hkRf7WTRvS9ju+IFH3MbmqisvDt0ZnybC/TbJBpt8mYEu
         hZADuWpijFiLHEylv2bAhQ84LYtYZNnCVR3XrWghF8EE9vY9elNwEqyNsuGDIRyBlJFa
         5KUiTRkoQFm9jIKToBEaq6rNDV269ikpCTS/ddqkfDVLgnfhtLecSORr+/z8qQZZ+bA8
         zsYA8g5Pp+63Q1slGhFlVI+GUCJnebvWHkqZfn+Re0tSIltUlRMNLjgcM6QraX4uRYvm
         JXMsH81c/KBmFXL91X5K/MiupzkoSekfxwHSML0nwkGd7wyDaaPXtYraMWNtiB3bdCCH
         QJ3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=EFbgopP7;
       spf=pass (google.com: domain of jirislaby@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=jirislaby@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FsuF/b5ot+3PGkKpUGps/PR3nJ4zR0NXoU1K6M1BtL4=;
        b=WptmlTtqekVgFTvJm7XxBn3bY8BYxsqRRondea2BzJ0oNkXittyQ+q9xM0aiz0kZRP
         p9YNftTeX0nM4L/N1oIfwpNPlY6ip52MsWIL1K2sJy1ZIeR8lT5388m2fG3PKiU1C27l
         8ftTI/oxTeqmGYRETfJbZdB0Clb2ev8b5zrHFXcxWzS3FCJrJaZbR4JluqT/StcZzAbC
         RhgsdtUVABypN/tcvWciBTGoQQsFVUD0H1ePk58m7PzAa65nsBLLG7jm80pgBYpKuNmw
         23wWwgfot+f6xNnDeXhvr8/0J0O+O7yRZABa1d5Sulaao3vAeS38l3QYgEA7ZHeIHSyM
         Y1vQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FsuF/b5ot+3PGkKpUGps/PR3nJ4zR0NXoU1K6M1BtL4=;
        b=gTmZ++b/wYZmzM1EVf0WRlKvQkIa1K3f4Gevs569k/xsTdvbD2vwCb+IwqyY226KEX
         9VvPUpiZGlcfKNQayaVYZPhSwoeVWlc2VUJGGMX++yO6VAtzHybVF4MLFcHDGju4oXpi
         WYIt2LW9/eWeEvzgXXxTWhLCbgQ8El2O3MW6VcGRKf8ePU7Be6qkMHChILF8cMdlP+9o
         9dPn9A+OAFS3hT3MMjeXhB3xOl4Sdn8oXPBq9ZqWZtlIcODbaXWfAMvedY3MsRpj0Yzm
         MFG+G0hsUszZccYdis1T1fZ0rk8FlkBIo8S/SJq3I32UjEqfryT2uXRY2Bgup7poNRSx
         P/zA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pl/Smu4EJNVlSxAl3Dz0VSQLuiZgv771ZcjK0NQB76TYHX5YOFR
	zxPMbKpgFyBySRoalIXoPrs=
X-Google-Smtp-Source: AA0mqf68zyhrIVWa6u4ewcc/5I4vbsseqhi1fss/E84fZdQOpnkoqsBX67tqyf9XN61tN+7n0QAYHw==
X-Received: by 2002:adf:d212:0:b0:22a:f546:3f68 with SMTP id j18-20020adfd212000000b0022af5463f68mr7469379wrh.651.1668426349851;
        Mon, 14 Nov 2022 03:45:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cb55:0:b0:3cf:afd2:ab84 with SMTP id v21-20020a7bcb55000000b003cfafd2ab84ls5405249wmj.2.-pod-control-gmail;
 Mon, 14 Nov 2022 03:45:48 -0800 (PST)
X-Received: by 2002:a05:600c:4f16:b0:3cf:b1c2:c92c with SMTP id l22-20020a05600c4f1600b003cfb1c2c92cmr7536520wmq.193.1668426348836;
        Mon, 14 Nov 2022 03:45:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668426348; cv=none;
        d=google.com; s=arc-20160816;
        b=Sss4DNrP/2dhTpYNBBRAdpGVyiaCcDXtiu/n4Adr+VRjqGz9T4HO1JtCfh4pudaH/c
         P50qqp3PPEEPyridGFjvyFDIVaikVWncedOtMVAlTPT72rdcncW9v8vDHvTUysefhNyp
         Nf32ib9R/vk9G5T9wJn0fx4WSOVNm57rZusttBkUY1R/B/LJdZB9YO7vG6RNIHNM325M
         aUDmMwRQQqdCoGuAIn1BpzuJ3AjOXByA5K+mOvRBe192fI3wp1gCkjGGmDwiUNq4z3eW
         6NMEboZX+Dy6V3HKlFV/p/VqGJKA4hy4K4c0B/5ffAp1btrici+NyXwt3RkWws6EeAq3
         8MWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=WKn9laZEOJi3RLi6Cjh54rnSbYfEE4oIQi1+zqu/7Pw=;
        b=RwRWluKS5kDWyr1WEuIut7xF+JMOvHQ0JVHJlwVXn+w+k/o7baKS+hPA8Il2n1d2F4
         Z3vqm+2KXJc/uIyw1cqDKKyim266x30CUjmWxKbhJFBRqild8cziWw7sOC8rjBWBXKiT
         It9BY3p78MlKs5mAX+Be575H3+rQSWRzZA3BJbsR3ei0UwE+8fUBS9J66PoIuG26pVFo
         vMXpeHUM12IUJHeu2DNkZoOMVWv4TBUwkQuTsXgqjvTprmtBJNoass1w8UXZ99KXEaZL
         Tx87OgrDW3MXzA/s6MiJeKG4J9IayhagvA/a3J77qtRDIHhlJDfUBUyAr95SpEC6qyHD
         9reg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=EFbgopP7;
       spf=pass (google.com: domain of jirislaby@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=jirislaby@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id ba16-20020a0560001c1000b00236e8baff63si315922wrb.0.2022.11.14.03.45.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 14 Nov 2022 03:45:48 -0800 (PST)
Received-SPF: pass (google.com: domain of jirislaby@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 8B09BB80E78;
	Mon, 14 Nov 2022 11:45:48 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E18D3C433B5;
	Mon, 14 Nov 2022 11:45:44 +0000 (UTC)
From: "Jiri Slaby (SUSE)" <jirislaby@kernel.org>
To: linux-kernel@vger.kernel.org
Cc: Martin Liska <mliska@suse.cz>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Jiri Slaby <jslaby@suse.cz>
Subject: [PATCH 45/46] kasan, lto: remove extra BUILD_BUG() in memory_is_poisoned
Date: Mon, 14 Nov 2022 12:43:43 +0100
Message-Id: <20221114114344.18650-46-jirislaby@kernel.org>
X-Mailer: git-send-email 2.38.1
In-Reply-To: <20221114114344.18650-1-jirislaby@kernel.org>
References: <20221114114344.18650-1-jirislaby@kernel.org>
MIME-Version: 1.0
X-Original-Sender: jirislaby@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=EFbgopP7;       spf=pass
 (google.com: domain of jirislaby@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=jirislaby@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

From: Martin Liska <mliska@suse.cz>

The function memory_is_poisoned() can handle any size which can be
propagated by LTO later on. So we can end up with a constant that is not
handled in the switch. Thus just break and call memory_is_poisoned_n()
which handles arbitrary size to avoid build errors with gcc LTO.

Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com
Cc: linux-mm@kvack.org
Signed-off-by: Martin Liska <mliska@suse.cz>
Signed-off-by: Jiri Slaby <jslaby@suse.cz>
---
 mm/kasan/generic.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index d8b5590f9484..d261f83c6687 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -152,7 +152,7 @@ static __always_inline bool memory_is_poisoned(unsigned long addr, size_t size)
 		case 16:
 			return memory_is_poisoned_16(addr);
 		default:
-			BUILD_BUG();
+			break;
 		}
 	}
 
-- 
2.38.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221114114344.18650-46-jirislaby%40kernel.org.
