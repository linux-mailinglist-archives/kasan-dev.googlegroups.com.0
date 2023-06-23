Return-Path: <kasan-dev+bncBCG6DVFRXMDRBEVB2WSAMGQEUUFJ5AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A35873B22A
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jun 2023 09:58:12 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4008e5f1dfbsf603861cf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Jun 2023 00:58:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687507091; cv=pass;
        d=google.com; s=arc-20160816;
        b=vxgCZLEE+DXXW+oU9qYMOzhNAU1oqd5BC6DEcoAubcrXKNjr6dmeNKt1PxlfGKOTRx
         uggVR/S60CVexq3Ziu1XvwNWBItQzbtLBtiLpxMQwyT8Q12zWE8oU8fQO9xDtrd/N8n9
         Lnf07FQAzlLmV6vv1kLN5fN4Y6o0iIMgTVOtH+1zDZgRppaf++9tB/xSd03QD4kcOzNP
         LT8ksyUlmMx8FQtj9SxBpVkp4n7DPWD4t5s4eQtMqO8pYiSbGYERP3AFgxPd3H4TRpM2
         2WsKwL2FzJYf+ppcQA/tNY2393VOxr2HnneE0E5tHrpe/tMMZDzi3DPqo2Zk+p++oXUX
         zU0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=fW9NM6uRbHuPTEasyPMhinxBK53jBnVpxog+RToM8mM=;
        b=m24Jv1Hz/EX180hBSm/oCkYXoVOSsCCeOGSFUBPNg2KNQdeR5c53pRDCSVwyQPc3mD
         23nmM03Qnc5oqI6aLpC4He/R44ahAAPAj1q4E0D1h6QmLZNakB7WkSvaHbaO8Y8RUSGQ
         92Lh5YOsjnalCP2FZPa4DXMSxweXV2eVI8/TzbuP4W82bLQdd/DzQqSVq6jvsgrc/RFd
         iGEQQCrgm4FGr1a5qibgGROgTH4qNfdkUeAq4OgBzaIIGZm+RwBuRlThvjHoISmdeSI1
         Kavpx2AOyINAGYsowi43zpfIa7EmjOi0p0achXeH8rI+pdv3IteJ93XbnuPBafTNkahh
         uwuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of chanho.min@lge.com designates 156.147.23.51 as permitted sender) smtp.mailfrom=chanho.min@lge.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687507091; x=1690099091;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:in-reply-to:message-id:date:subject:cc
         :to:from:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fW9NM6uRbHuPTEasyPMhinxBK53jBnVpxog+RToM8mM=;
        b=LqazJB3cID3Chaa4AElTsF6A9HVyTFSHRUTGCI/1KP2arm6VlXD2rxgndP0mPJtcIz
         vkUvFc3b3O30epJIe1HWcpNBOBXETXCeMXLhVa7sMPk/jF+hwPvFQqjdUAOdBe3+rACQ
         keFx26tlllGydoGyx2pxhSqdbwGQZR9tj/dflSNxWpz6TNg3S7iaYoayDzSIRVPHelK4
         OvJYmjBpPMCsI6iOMM2JvN9ElY5UD22qVgBsuJbTLTFxRYFhZ+qMfR4sRi8pBiXdZaS4
         +LVngj99Z4Nar/K9uNIxvR+hvM7IuUak/gknslGFUTGCJMwpGaZd8BkSQKXfnVH80lc7
         grSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687507091; x=1690099091;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :in-reply-to:message-id:date:subject:cc:to:from:x-beenthere
         :mime-version:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fW9NM6uRbHuPTEasyPMhinxBK53jBnVpxog+RToM8mM=;
        b=iziTc90yqkxrp0HzdeNFnMU7oAzNh/uDdfJwVN6/TpZE7GYWLklxn0l/ydAOLDfPMs
         sAfRP3eVcAH3/M4aCet9w3BOfczWci2eKAcYJs7xd3XYjND00GPMiLgJ3SUMqs+GV1IN
         UWkDdQng2GsRNrSVtZA3WOrpc/a3aDh8ryzMDITa493WXujmbN6hXWf5YByVjOWwCe3t
         riqEy4Oq3hTTNSuruahCyzcp8Ctj2fFX2RILMrcE4PcxH0Ac803ZVfNr9SUeYNoj5ljF
         xi1vBYojDSy+jwrvKRoW5r4EAtD9foUnpqB1IhdYgp9O3p4RVYvc+3krGKpVDsHllXKA
         ECcw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDykxYJunBrfa3VuCsoq0dqfjqEF35RSPhjms5BcwpPkNYe9Kemc
	WRvbLXtYI4vqiXP1qxpM9Ug=
X-Google-Smtp-Source: ACHHUZ42KKrLGjdYkdJLgJUA+E7VaaNhl0rOjGwsYTK2aey/GoyNsPA+3v/KqHavJotS3ldal+U2tQ==
X-Received: by 2002:a05:622a:1a20:b0:400:86fc:f979 with SMTP id f32-20020a05622a1a2000b0040086fcf979mr1359965qtb.58.1687507090896;
        Fri, 23 Jun 2023 00:58:10 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:53ca:0:b0:3ff:302c:7615 with SMTP id c10-20020ac853ca000000b003ff302c7615ls230140qtq.2.-pod-prod-03-us;
 Fri, 23 Jun 2023 00:58:09 -0700 (PDT)
X-Received: by 2002:a05:620a:290a:b0:765:4b7c:809a with SMTP id m10-20020a05620a290a00b007654b7c809amr1034765qkp.31.1687507089877;
        Fri, 23 Jun 2023 00:58:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687507089; cv=none;
        d=google.com; s=arc-20160816;
        b=vztigy6VbszgQXsV4JWkJvgY2QCLXVHVLZxw1XcYwBnT+rPccv1SEX9lBpDbPzTewI
         hc/JhYf/MzK3fiPhLT3V61EmTp2o6MjWuy1SxABTgYBUamEBAAa4wdb7UZBLzbH6aU59
         O8m2pM4NGqPZoBzqgfszPYJ8EzJIekrkDhpP6umW32/liidKcAyEYabnDDypLXlWEhKg
         Dv6nuIOdwGnMSF/p7zG0y5Hvq/LK+mrb6CFqoXOJaQqUX+q9xi42mwqkkXyCmXEOmCvg
         K60OukQwSf0XSjz9kS7cRAEUVkGMvZgOr9O0OOpRZ/kj3xy9aPOKGry5JJeKdM0MAVFb
         7xqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from;
        bh=JoKGkYgZzPdv1qxY2Tw1MfAsCqyqgX341vwV35LziNw=;
        b=pNBwI/BJ2SLTq+FRmkY22xGMrYJkVNIpvkbCredX293Ta1zRFp6Xl+y9jMQzhadgDj
         DNAMGxpK02PP7BTsm4kloKxYYJLVj49sUc8pDIC6GfNGd0GEwqimRwhSefVDbOTxMz+t
         tFe/uGpxMxqowibNxOaquQ4yYsKQGTjs/ab27tljzxoUKG+nVcVVVuIfMHMbcSUX9WnO
         uXUhfiuRsXszTlqMxb3h+Or8OxMXZH4EaxoiqWbvboLFKyg43PaIbLOCcdiqIh7fvIXm
         BsgU/bSh1CbUYd7oAU/KZ9T2vLWmGYohxNsUwcnxpqPA84VBPWYzZj6DR6i6Hcwb25KV
         Yy9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of chanho.min@lge.com designates 156.147.23.51 as permitted sender) smtp.mailfrom=chanho.min@lge.com
Received: from lgeamrelo11.lge.com (lgeamrelo11.lge.com. [156.147.23.51])
        by gmr-mx.google.com with ESMTP id rr23-20020a05620a679700b00763d5f6718esi388138qkn.5.2023.06.23.00.58.08
        for <kasan-dev@googlegroups.com>;
        Fri, 23 Jun 2023 00:58:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of chanho.min@lge.com designates 156.147.23.51 as permitted sender) client-ip=156.147.23.51;
Received: from unknown (HELO lgeamrelo01.lge.com) (156.147.1.125)
	by 156.147.23.51 with ESMTP; 23 Jun 2023 16:58:05 +0900
X-Original-MAILFROM: chanho.min@lge.com
Received: from unknown (HELO localhost.localdomain) (10.178.31.96)
	by 156.147.1.125 with ESMTP; 23 Jun 2023 16:58:05 +0900
X-Original-MAILFROM: chanho.min@lge.com
From: Chanho Min <chanho.min@lge.com>
To: andreyknvl@gmail.com
Cc: chanho.min@lge.com,
	dvyukov@google.com,
	elver@google.com,
	glider@google.com,
	gunho.lee@lge.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	ryabinin.a.a@gmail.com,
	vincenzo.frascino@arm.com
Subject: [PATCH v2] kasan: fix mention for KASAN_HW_TAGS
Date: Fri, 23 Jun 2023 16:58:05 +0900
Message-Id: <20230623075805.1630-1-chanho.min@lge.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <CA+fCnZfi_o6QbfDamUjsPXjtnEwKyBn8y+T8=zxV2mEpA=DUyQ@mail.gmail.com>
References: <CA+fCnZfi_o6QbfDamUjsPXjtnEwKyBn8y+T8=zxV2mEpA=DUyQ@mail.gmail.com>
X-Original-Sender: chanho.min@lge.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of chanho.min@lge.com designates 156.147.23.51 as
 permitted sender) smtp.mailfrom=chanho.min@lge.com
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

This patch fixes description of the KASAN_HW_TAGS's memory consumption.
KASAN_HW_TAGS are dependent on the HW implementation and are not reserved
from system memory like shadow memory.

Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Chanho Min <chanho.min@lge.com>
---
 lib/Kconfig.kasan | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index fdca89c05745..f8f9e12510b7 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -124,7 +124,8 @@ config KASAN_HW_TAGS
 	  Supported only on arm64 CPUs starting from ARMv8.5 and relies on
 	  Memory Tagging Extension and Top Byte Ignore.
 
-	  Consumes about 1/32nd of available memory.
+	  Does not consume memory by itself but relies on the 1/32nd of
+	  available memory being reserved by the firmware when MTE is enabled.
 
 	  May potentially introduce problems related to pointer casting and
 	  comparison, as it embeds a tag into the top byte of each pointer.
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230623075805.1630-1-chanho.min%40lge.com.
