Return-Path: <kasan-dev+bncBAABBBULSKWAMGQE7EDWXNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id DAFCB81BE50
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 19:35:51 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-40c25f7963bsf65245e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 10:35:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703183751; cv=pass;
        d=google.com; s=arc-20160816;
        b=SVCMk3+ngCmmtLL319ZSXo8Pgu7jwXrcJi1e3FENofIJlawOx4PMJge+PvwG4odiVH
         4oSh645aP7N8CSbo13ddrYS0n5GaR5R4HrmmGFPggV0S9Xx4r5sLiz7VQjBg3pXqSDqV
         fJlcbxtueHbdKNtfNR68NDX8adlfsgF0ut2ZkpAT0r12D61knKw4fMX6aLrjyV8A5jJN
         HzN20ZUBChuWgLUhAcJ8wZ7lrgvV9HAdg3bppG+HCZmnWLo5i9G8vRBH4zD7Shk3K4Yo
         U6zdsqIga3b5EEWQJe4p07wl4HXI4j/qHtGuryKlpcyeRUsbYOTdhmENF10R4RbICAsM
         YOwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=GjJh0PU+c4t9ZhDBwHFtngKaOVmMqgaBbF1dij2ux9U=;
        fh=E9W45FwZb6Id+g4Lg+hTR4TMK1PXvrXS/qWrVP2FBRY=;
        b=xVejfW2bkRKp0KfwwFv5Sct395BRws0fCtN+6YDFqOooOlYFBgIEViovMYyQWW/sJK
         MC/YFV/2g/BP4zf5PJ7CR6uEpjJNOGRDjGfp7TEB+3Vl6Hn9jasIer/ainiQ/2RMhIoN
         UunBMj92W9C0eA0+pBtdd1iNOQSb+zJ2jaHLeisOOlgeo+J4dcab2BZ/o13X/oc/awIO
         YHilJCfVPBrNrEzHg6Q05zNvtpfw44ilRkHlvOf7Ztaio+h3QtcW71AySDvhf1X8cke3
         ejM4yrEX8W8Y7KstCDd8rFKnnRhWB/5yNbHs3UEa3ncy3P5zAxg2kd4wBIb91RJKsfIN
         VwUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iZOz0xdv;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.188 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703183751; x=1703788551; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GjJh0PU+c4t9ZhDBwHFtngKaOVmMqgaBbF1dij2ux9U=;
        b=carpfEjtAhdywPddb67/snqU54QdXnlVxxO+E3motM0iZSEdnlK29SVRhqc7HwCPrv
         oA1vZR0byoD2SeR9n1LWsHlvwyBVfEa1uxlzSCyz1SV/1L81IAu3yPS5EYoSA4Cqz+m/
         +MyduXD2f6cxxolH3bK+Ne6x1cBM5awZnPHjuLt6WsmIv0edHfHwtUmYCw4L5+rcxeGj
         JUQe+1guq2lh17DL5ioijOSCLKihMhwriEd/PiGhD4oL5NEPkDn6Dl6xWbvD7r68i0lU
         r8l9ElTPa9jfVvJlx6sJ9aV1oeinNpoJSKeobk04R711+W7aiPUdP18LoRXZ89Ax6wI/
         HJ+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703183751; x=1703788551;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GjJh0PU+c4t9ZhDBwHFtngKaOVmMqgaBbF1dij2ux9U=;
        b=pzaW6G4EeVlrZoCUciyNyDzt1tBfmW9r5vERtDvSBd1R+VRK9H/P/PESqE/tf9ilyQ
         j7lZfIcAbkCy/X6+orEXylmIc1J8P7OQhtCzFTdYZbtDVgwG3FXDtLm4ives77eJa8vZ
         SRaX2DSrZc5azRTkpit/P37yYJa8AupCe2vZDn2BW37TYkKtpXymwhujSg/bnjM0Cxa1
         hn557nLutkZlq9oCddb9diA+WkDqz9Xv4dWSUzc0AvASoDvJeFbB7aqZQL4z6HTS6DHM
         vKg6I5WxHv+GMDTddx82r6O9QmbpbOQ29UtfbyJ6v5Gw1y3RBDIhJ3GnmndBG4mVyUfB
         PLDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxTPd4WjAjSzMrg2ZO34+uH7HrzI2qOPr1mG/8BQl6N5rQMjQH5
	wM7p0LBgln+ZIa7ebpqooqw=
X-Google-Smtp-Source: AGHT+IGZSAaSWON7KYPr27zqLfRcvPqZ0TxmhUuM+Y9K84R+13Hp/o0hXMhlPVD4MhBqYVSxBm5NXw==
X-Received: by 2002:a05:600c:63c3:b0:40d:1bcf:1abf with SMTP id dx3-20020a05600c63c300b0040d1bcf1abfmr31wmb.6.1703183751065;
        Thu, 21 Dec 2023 10:35:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3507:b0:404:7eae:e6cf with SMTP id
 h7-20020a05600c350700b004047eaee6cfls753478wmq.2.-pod-prod-05-eu; Thu, 21 Dec
 2023 10:35:49 -0800 (PST)
X-Received: by 2002:a05:600c:4747:b0:40d:3541:97ae with SMTP id w7-20020a05600c474700b0040d354197aemr84892wmo.161.1703183749590;
        Thu, 21 Dec 2023 10:35:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703183749; cv=none;
        d=google.com; s=arc-20160816;
        b=iW+OkITXTbWG26j2RQUuiLnjQmbaXx/BUoQXibdxf/b3QnzTvduX7psR8DUbOXUpCG
         FHW454XwZHO+TR4n46XmFVXyE5ha3pZnOVjScfVdQHz/zHU0Vac+iANp2rQfSrBKCTw1
         ixVE3sanah7XV5jz7Y+W75MIEW8dH7NcxfHiTLp8VAwMzsjGrBew4vwRm4lWc9c0P2LA
         OroyeDaPDfm/zP+4Hgw9cZWAfkUqbe+P+LHJJeIOND8LJEDGjor0shDDkbjQc+s9CKvd
         Vhxykknd6CAVmywwxPjXZoAS1HVYNbeuSJLxp4ZwdZfizm8DwndIesP64Cogcu4Bp3KC
         5r8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FiI0FbwykV/2XbgOuJsaOX93jnuQZGsyNc8LlrDSdxY=;
        fh=E9W45FwZb6Id+g4Lg+hTR4TMK1PXvrXS/qWrVP2FBRY=;
        b=tZYe2NLaBn8EQkLvJL9nmgaukn8Io5OviVzxx9TeAdS7MYUxRib5yQp2XgRcAz3jkL
         vuXZfm17Qy3gfPzv0m1nFDdWM0gGKzOTVwRv6eRgjR/oRDfnBfN4MS7O0UV9pxRQaHgj
         Cl/ZXbEsc7wLOfqEbHJplmGKW+OLnPu8Me1AGXFZ5GRpgc9MDSGOo19DBOzL7PQPTYo6
         VX7uiR+RsxIWMmBJZlTeONvbJn6tTLdXqJ5BWM819sCr1/tjUvRgULV9yb4T4AyD6SrP
         yc0iDWaJ2qAFnlg6vCtFjS96aj5UBraxUDLWJW/GamV+qSdltmFboRaIBjHUFu9EVPMX
         36Mg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iZOz0xdv;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.188 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-188.mta0.migadu.com (out-188.mta0.migadu.com. [91.218.175.188])
        by gmr-mx.google.com with ESMTPS id az15-20020a05600c600f00b0040b47a6405bsi357898wmb.1.2023.12.21.10.35.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Dec 2023 10:35:49 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.188 as permitted sender) client-ip=91.218.175.188;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>,
	Juntong Deng <juntong.deng@outlook.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 4/4] kasan: simplify kasan_complete_mode_report_info for tag-based modes
Date: Thu, 21 Dec 2023 19:35:40 +0100
Message-Id: <20231221183540.168428-4-andrey.konovalov@linux.dev>
In-Reply-To: <20231221183540.168428-1-andrey.konovalov@linux.dev>
References: <20231221183540.168428-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=iZOz0xdv;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.188
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

memcpy the alloc/free tracks when collecting the information about a bad
access instead of copying fields one by one.

Fixes: 5d4c6ac94694 ("kasan: record and report more information")
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report_tags.c | 23 ++++-------------------
 1 file changed, 4 insertions(+), 19 deletions(-)

diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index 688b9d70b04a..d15f8f580e2c 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -27,15 +27,6 @@ static const char *get_common_bug_type(struct kasan_report_info *info)
 	return "invalid-access";
 }
 
-#ifdef CONFIG_KASAN_EXTRA_INFO
-static void kasan_complete_extra_report_info(struct kasan_track *track,
-					 struct kasan_stack_ring_entry *entry)
-{
-	track->cpu = entry->track.cpu;
-	track->timestamp = entry->track.timestamp;
-}
-#endif /* CONFIG_KASAN_EXTRA_INFO */
-
 void kasan_complete_mode_report_info(struct kasan_report_info *info)
 {
 	unsigned long flags;
@@ -80,11 +71,8 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 			if (free_found)
 				break;
 
-			info->free_track.pid = entry->track.pid;
-			info->free_track.stack = entry->track.stack;
-#ifdef CONFIG_KASAN_EXTRA_INFO
-			kasan_complete_extra_report_info(&info->free_track, entry);
-#endif /* CONFIG_KASAN_EXTRA_INFO */
+			memcpy(&info->free_track, &entry->track,
+			       sizeof(info->free_track));
 			free_found = true;
 
 			/*
@@ -98,11 +86,8 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 			if (alloc_found)
 				break;
 
-			info->alloc_track.pid = entry->track.pid;
-			info->alloc_track.stack = entry->track.stack;
-#ifdef CONFIG_KASAN_EXTRA_INFO
-			kasan_complete_extra_report_info(&info->alloc_track, entry);
-#endif /* CONFIG_KASAN_EXTRA_INFO */
+			memcpy(&info->alloc_track, &entry->track,
+			       sizeof(info->alloc_track));
 			alloc_found = true;
 
 			/*
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231221183540.168428-4-andrey.konovalov%40linux.dev.
