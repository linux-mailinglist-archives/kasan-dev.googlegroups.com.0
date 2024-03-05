Return-Path: <kasan-dev+bncBD7YZQWS6IOBBXWDTKXQMGQEVO6AARQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 29C5A8714D8
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Mar 2024 05:38:57 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-29b1fa64666sf215288a91.1
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Mar 2024 20:38:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709613535; cv=pass;
        d=google.com; s=arc-20160816;
        b=OxF6Ohou4lmMkoM3IFwumNg0UVS4U76/IWM0UP6sNvtWF6P2WzmKSrCXYYJLxXHzgW
         suS7CQc3nOaHmfowmsRKO7GQRlOIXuaQLTRERaV9N9VLrbCFfO03W4zvbkt88b0cYc++
         JNrq4JzWt4rIQA5aUC7ZF0TtOihz6aZIPp2F/wwxXcoS4cweYqgexMUSV8FgTlUNFarc
         etgEwASlUqhJzP3GS2feO68pZOmHW5vLCHRufYQhz5H7W1gQ2ImgEt5SiiG/ZL6R/94n
         Ax/5+hV+kDJtikvSJNb35pylKax+bg1FKXiFy2fCTxCbbF6Nw9cMC+iHJFyzEys1IRb3
         6+8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=YXH5tth71IzzId4cTLD4xUv8LKMuZ4XhiQ0g1dnAuoU=;
        fh=uXZo28ZPlmGkfi0CWzMLByFwzQDkzUgOhmGDxH/cT9o=;
        b=ePg1l05hOtc/b9VKyDaaI3jQhh7JjaPzgCt5IOSbchagdP+fndjeWcVDiyyTbWSHZc
         bzqVqFZe8jyTZ7jh2ApffN2wlzgOlrZ8F7NGHhZyldDcjxViiC7GkPC/MvXXKWhWIckF
         jTfqGtbij7BgkK5trfWzRDQQWLi2uZAqBASMxLRl9cC77qpV8InBfQLk7WPwaupRSTkm
         biQp68GJP9AlnO5rOmGPEIYpiz0iicTsxwER3N78lGEN2JGIYjftkp8SBiizuIb733rZ
         JIA9KZ4/TqdGNDAChqRUL0+kSGbp2Eg47HMgDxiUUT5AoF9um7kBinB+zyoLN9TrxDGg
         WlCw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=g7pbBgeM;
       spf=pass (google.com: domain of peterx@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=peterx@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709613535; x=1710218335; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YXH5tth71IzzId4cTLD4xUv8LKMuZ4XhiQ0g1dnAuoU=;
        b=NZsEtXWLhffVAxzFMBDp8pElcVJwTb0zZ6bBATbbFtSJgQBJChFWiWwET1n8xUYZNy
         MxmgLGS8qCek94fgdPJozuszlL/TwGTv8y9ewVYK5oaTYXbMCvBHWoOIMGQBl27EKQ28
         12VsQD00bZQfw0lfgAMiD63KiG43rYv/jOyVuQgW3+gSjfyzDK0tF38kIfIaRIEz1WFM
         v8OTz2b0gTarzta96z43YyuuSbEZg/QMp1WD5MBqj7SbH3vcwz1Q74L7VC5GwRlH7kdQ
         JCcL0S9xcliVbud3pZON9SOvh8C1VLSjsk5w/00VsRzxnDeF2sg6jt21ApNbjpvF3PqF
         imsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709613535; x=1710218335;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YXH5tth71IzzId4cTLD4xUv8LKMuZ4XhiQ0g1dnAuoU=;
        b=tyeMQ0CcqaY8yZQDOvYQn8TTK4KxjN7Bdq89b5ekzBxlp5VX6NsPWngZsVEd+8DLhF
         jI6t3UBdAVBgi29JTsgNxqV7qXXa17R6yX/tQY96hA/YW1Jkn/KLqoyYrHWUQnqY9Uhd
         ZYybRZ5mTUkFOGG/SjSHzEFYy4ufEgtmQI1rSZ2z8wDR2Z5vht4xnBqaQyMKXzA+jvJL
         yEBKQsW6zjSlyXUZ8GPBRvzxK9/0hdcdp/rxto4mWFPs5qj6l1OIvBZ+sj69uhD4pTyb
         Qv/hlWCDTumL+kmsO+yyNjLP9jmsjJMz8N9KyYElslOWFHTSaCWVCzlNvyzQ99vELzug
         QcIQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW0WolaQe000/B+xZVF/pWurL7OkoE5HQwaE4w2WbLuZKI7E/7Hx/rQJRRtONsCjRLH1Py7yndGcQ8KFAqc/7c0lA3Fwv4pwg==
X-Gm-Message-State: AOJu0Yyqf1mr1jeM/R+Wex3O+3zvzEpHfocd7Ui15bxgZeR9P6ZIJe/U
	t+HWNHfq20iRPspBfX3x+8h9RwaGciJL+nSwxQwLOF/QPZXQstn5
X-Google-Smtp-Source: AGHT+IGP89Ztg8jw+cCa5xHBQEQIbVIOd6Na3BJCrv8qlH/EUpZ9t9j7G2YHG9U2zg4XalePDqgefw==
X-Received: by 2002:a17:90a:a416:b0:29b:2779:6cea with SMTP id y22-20020a17090aa41600b0029b27796ceamr7486047pjp.30.1709613534968;
        Mon, 04 Mar 2024 20:38:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4c8c:b0:29b:ff6:f4fc with SMTP id
 my12-20020a17090b4c8c00b0029b0ff6f4fcls223403pjb.2.-pod-prod-09-us; Mon, 04
 Mar 2024 20:38:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVI9k498sA6sX7d0dlN5YMwJhHW0QSlrtikgDoyMQS13RyJxzaDPgWR931ShNl/o44AErVxXm4GAa/aixctEdo/26fVd42frWqQiw==
X-Received: by 2002:a17:90a:b005:b0:29a:60bc:ae07 with SMTP id x5-20020a17090ab00500b0029a60bcae07mr8149675pjq.35.1709613533828;
        Mon, 04 Mar 2024 20:38:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709613533; cv=none;
        d=google.com; s=arc-20160816;
        b=buqD31FZ2Zu/vFGyBJP3SoUKepWXZ7PtgLICZeHLkkw1a6m4J6bJ3W1wewUh/uwCOM
         ahRKQOk9uipe/3/Ax6MeQRZxLFKbYNF/sg44boIqVpaFnzliZ4SvkEHKd36+nsGGTi7E
         IIudYXCTZxbttL49xCKr1El6zKbiScecOo6/fZ8dN1vKHbwdls/ByUMoqtWrdPqZF9Ta
         XoMeW6fA1SHJaxcCMhXaaxOaPE9juGtE3OqsFqMHJwtqXwIf/CYCgCpUBh/WTfp41k/1
         gXN4omIuqtHUFf46A02roDkx3waTG95lJrNniXMLdb5J1LrVDkovYAl97vv5gdieQjEw
         5GHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+OBCTz9lvlJv+Cv6bxuJooI+JmxCAuhU7weo02f7lPE=;
        fh=SCGEM0a3u+MIkXyfovVoHc3mfh7eSVA+HwVgff131QY=;
        b=zPUobW4RF7q5B0FDf028TXBEafroUQTIwW75Otw+LLihoMNwm+N/0R912kxoUtANjm
         LPVL1E009lydO+RZILkHa95ET7YPBhiUHBSg2OIzxH1PGszFBsrFvCSGLyd7c090mftq
         9zJONofkWkg/rhDkw6hDrDhoXJudH+zBsgOeFQPmDOgbd294PqBYHciC4oa8YTKh2xBF
         zHIMiKk5qqTzLKCBOLX6aqZZlO41NuDfLfNSHjojH6njZBO+1cfrs4lzB2L65nBxMk6u
         vRfORldlSs1yaPbAjRTEiSaJ6t8CesbdCircAMLcch6aLH+9VIDO0s1r6/1J8/4J+As1
         Rl7g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=g7pbBgeM;
       spf=pass (google.com: domain of peterx@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=peterx@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id a11-20020a17090ad80b00b0029ac89a78d7si1077570pjv.1.2024.03.04.20.38.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Mar 2024 20:38:53 -0800 (PST)
Received-SPF: pass (google.com: domain of peterx@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mimecast-mx02.redhat.com (mimecast-mx02.redhat.com
 [66.187.233.88]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-688-mm-VBS-RM56uWvAAq4EvGA-1; Mon, 04 Mar 2024 23:38:48 -0500
X-MC-Unique: mm-VBS-RM56uWvAAq4EvGA-1
Received: from smtp.corp.redhat.com (int-mx08.intmail.prod.int.rdu2.redhat.com [10.11.54.8])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id 31F86101A5BB;
	Tue,  5 Mar 2024 04:38:47 +0000 (UTC)
Received: from x1n.redhat.com (unknown [10.72.116.31])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 52DABC1F086;
	Tue,  5 Mar 2024 04:38:39 +0000 (UTC)
From: peterx@redhat.com
To: linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>,
	x86@kernel.org,
	"Kirill A . Shutemov" <kirill@shutemov.name>,
	Jason Gunthorpe <jgg@nvidia.com>,
	Yang Shi <shy828301@gmail.com>,
	peterx@redhat.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linuxppc-dev@lists.ozlabs.org,
	Muchun Song <muchun.song@linux.dev>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com
Subject: [PATCH v3 06/10] mm/kasan: Use pXd_leaf() in shadow_mapped()
Date: Tue,  5 Mar 2024 12:37:46 +0800
Message-ID: <20240305043750.93762-7-peterx@redhat.com>
In-Reply-To: <20240305043750.93762-1-peterx@redhat.com>
References: <20240305043750.93762-1-peterx@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.11.54.8
X-Original-Sender: peterx@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=g7pbBgeM;
       spf=pass (google.com: domain of peterx@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=peterx@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

From: Peter Xu <peterx@redhat.com>

There is an old trick in shadow_mapped() to use pXd_bad() to detect huge
pages.  After commit 93fab1b22ef7 ("mm: add generic p?d_leaf() macros") we
have a global API for huge mappings.  Use that to replace the trick.

Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: kasan-dev@googlegroups.com
Signed-off-by: Peter Xu <peterx@redhat.com>
---
 mm/kasan/shadow.c | 11 ++---------
 1 file changed, 2 insertions(+), 9 deletions(-)

diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 9ef84f31833f..d6210ca48dda 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -199,19 +199,12 @@ static bool shadow_mapped(unsigned long addr)
 	pud = pud_offset(p4d, addr);
 	if (pud_none(*pud))
 		return false;
-
-	/*
-	 * We can't use pud_large() or pud_huge(), the first one is
-	 * arch-specific, the last one depends on HUGETLB_PAGE.  So let's abuse
-	 * pud_bad(), if pud is bad then it's bad because it's huge.
-	 */
-	if (pud_bad(*pud))
+	if (pud_leaf(*pud))
 		return true;
 	pmd = pmd_offset(pud, addr);
 	if (pmd_none(*pmd))
 		return false;
-
-	if (pmd_bad(*pmd))
+	if (pmd_leaf(*pmd))
 		return true;
 	pte = pte_offset_kernel(pmd, addr);
 	return !pte_none(ptep_get(pte));
-- 
2.44.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240305043750.93762-7-peterx%40redhat.com.
