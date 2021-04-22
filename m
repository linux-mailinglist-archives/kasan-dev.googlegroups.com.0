Return-Path: <kasan-dev+bncBDN6TT4BRQPRBM76QSCAMGQERIXCWUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E6D9367D8D
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 11:17:41 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id 9-20020a056a000729b029025d0d3c2062sf7600805pfm.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 02:17:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619083060; cv=pass;
        d=google.com; s=arc-20160816;
        b=uDGczzuNbNcffvlnPbs7uLTNBnY4xOwuifFmTrdBruaSIv42fk+Zvf0TOVQdSjD+Z5
         a1VYYDMu0o2OxxrUgJQUq8ZMsy3EmubWB3YRhMvv/kQln33YSvHmsrtSV0FreOPvZpti
         waiMlWfD7F1eozkFdpvX6GUJAaxFwV2wnQqF2z9edKo4SIpPP3SogUKFig8Ps1ubGuRu
         tTDr/n3TvJTJBAIVNBo00EMN+r4l/fJzmNXSYZuSxnxax4Dc7UorEBEsQoKN43zVqBDW
         NHAA6HHWARMpeID+IcQAdFFOmemNLv/TwoSVi2Cou0vvJJLl4FLf0y7F5rohSKGAG1w9
         UDqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:cms-type:message-id:date
         :subject:cc:to:from:dkim-filter:mime-version:sender:dkim-signature;
        bh=yvtVT02ee81kVJZ00YtZ9hD71t6qBQqTC9lTgNiiNoc=;
        b=ERePz4VizBxm2bURUB+cMvwfO3jPX8Z8Zsmh33DZpFsPBz2lu7l5I2whD63udcsNpH
         2YaZBTLWcqJG3Cc3JGluYriAg6faG5IyhWow2JBVb//R7CPsLjbvgePPBk3j2w/+NjBo
         G7gd03rLeNtWexdBOcgQ3g0Ur6HVbJYrwd8q3vuMtvENN8MVb/49WyclM0CYbe5QDObA
         C3xWd+RrqFjexTJEM4LSbfixYTG/xcyVnNHhubFBIfbUY7G/Y31KFlPI3SKU+Gzanq3B
         OAz+x8pUzQCd/Fz8X4l6CfFt0sccsiKd87X3HWZwZM5ydIptL9FEHqSbEXqAoOENvsWS
         C+Tw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=GrzuS8Ty;
       spf=pass (google.com: domain of maninder1.s@samsung.com designates 203.254.224.24 as permitted sender) smtp.mailfrom=maninder1.s@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:dkim-filter:from:to:cc:subject:date:message-id
         :cms-type:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yvtVT02ee81kVJZ00YtZ9hD71t6qBQqTC9lTgNiiNoc=;
        b=Vj9r/aRjlJW7MNw5P8Mh18T7HLodYcQxuXJzvuPpJTihS9/NuR/3eUSnIQIzmkd4hE
         nQ3U20aKJNAusjcRZT3khq0KotF2+kpU6z5Y7I/kTciBPwnnv+mRFsloZfnMUamUi16/
         xZo9i4QKOn4BZoV2L6m5Em+LsXwxzAZLevOMLypx7yLlmibSa6jfrV6UgZlUKsXl4M6c
         9PlpAneaYm4qsGGVcDxTm23ST+WFcQ11ostBpddmkppF1ZrP0vubKNMoFUSvcdz8sPxd
         zXT9+BwQ30mOeZb9bM75AUDakpoDj/nj/TWW1+ieyNyQ4Y8LVwK9n+8y09X9e6HBS/m0
         g+aQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:dkim-filter:from:to:cc
         :subject:date:message-id:cms-type:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yvtVT02ee81kVJZ00YtZ9hD71t6qBQqTC9lTgNiiNoc=;
        b=fYEjT9VgZdB6ZPAkxfzd+HpFtW4hyNAPtrzRB1FqsoRO98Wm6AozzUTQXVIZqd773J
         4Locm8Yp7STbi0clMR4PvfYLGTnd0Bfb0BU5vH2/FfuZyOW1yJMAVqzSiv5ke6kfW/Aw
         KdwoePWwDL++ZVU/dUxWk+afBXHsVwIeufMb1eu/CwRKIE8FJU4pdALHBTIWtIq38Ajv
         oqfKLtTpe+Kh1hzHrMRR8vSYk6jZsD9ot+M7i3ygdOxMiAhTvoZf29whgF9jxk1/cEPs
         fBYgU08EWkIWAuWkoSqsJlC6pqSZfXMigLLds5Kgo6RKsJmfsKP1oVnO9wTFhOtOfuvl
         wa5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5339BJEKUZQYg9tKDWt+Vf8M6UUiWPMeCNi9UbAKSYSMNiySBTp+
	nvCdbh9zSxSxdX1BhrxPPY4=
X-Google-Smtp-Source: ABdhPJzFHpPlfJhFFiuJCE7TpNUls6m72CXJRW9AcCOs7kbH4SnhgrWitDwxqaNTucYpdP67Oe7xlQ==
X-Received: by 2002:a63:ed58:: with SMTP id m24mr2680692pgk.248.1619083059850;
        Thu, 22 Apr 2021 02:17:39 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:9d88:: with SMTP id k8ls3168182pjp.1.canary-gmail;
 Thu, 22 Apr 2021 02:17:39 -0700 (PDT)
X-Received: by 2002:a17:90a:1d4b:: with SMTP id u11mr16078079pju.74.1619083059180;
        Thu, 22 Apr 2021 02:17:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619083059; cv=none;
        d=google.com; s=arc-20160816;
        b=dg0hYEj1PVyITGNWwpP6EY7bh32cjJ5lAgf7mfOrfG6iwLLtN+lMi046KxQaphd0Iv
         VBkSWvucJlSKlXyasiJu/G1pruCY6ArHGT0UopAoJ0ALgLf6ZuMm5HpY0raNJ5+gr9mT
         +AkSx2qANwx65vFc9RbOKmxwf1T1lJxsZ4RN6jUXVhiKPkuuRk8n42Wg3ItEX8pHJ1lo
         xKDxsAbol1FR4jtrKcRLOjSrEDvz4yV2V81+bzhuSvo0PGdGGiFv0EznQoRaH8TThENX
         f8qrbFLdlxN7MH3T5+yfD/BezCQHb1oM205kz8xwOdK3xkdNe5iaML6Ul3muiuTQZMji
         XdHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:cms-type:message-id:date:subject:cc:to:from
         :dkim-signature:dkim-filter;
        bh=moCMty+hy6GEde6fVkbpppPU9h4RXN6mG5YwWbMgjuc=;
        b=pN8RHi+a3tpXikmsSw4xa7CjHOvI/PCDtQR1gS3K48qbV37mZh0npMSBanipKmVLzP
         rxLLGdqfWwnzkcgH9+PBrxElCS+ylEQ7ocXGwCMXInuF/6j7UduO9EuvqzvsDLMF1D6l
         VUgOm6tWA9/tS2u5r2aV7yueBii/Qb5sjWXed8Wf1fJDWMg1H0l24hklPsLplGZdTWXi
         IBAXGiionlKCVbhny5jjr0eh5ZBhEEHypBAcUXHypKXDw9YdDyM6q6ctkOmdiPQ8siK5
         wff3apjSzIoiXnTe5PwLxZV5HYAi6k6brLRQoSkPFxVvIPGLCwtpIIq+XKSLBPg1FYdy
         cY2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=GrzuS8Ty;
       spf=pass (google.com: domain of maninder1.s@samsung.com designates 203.254.224.24 as permitted sender) smtp.mailfrom=maninder1.s@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout1.samsung.com (mailout1.samsung.com. [203.254.224.24])
        by gmr-mx.google.com with ESMTPS id p18si437549pgi.3.2021.04.22.02.17.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 22 Apr 2021 02:17:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of maninder1.s@samsung.com designates 203.254.224.24 as permitted sender) client-ip=203.254.224.24;
Received: from epcas5p3.samsung.com (unknown [182.195.41.41])
	by mailout1.samsung.com (KnoxPortal) with ESMTP id 20210422091736epoutp01c115c39f6dcf1c71e3b5fd2e258a676b~4I3ZEfsII2606726067epoutp011
	for <kasan-dev@googlegroups.com>; Thu, 22 Apr 2021 09:17:36 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout1.samsung.com 20210422091736epoutp01c115c39f6dcf1c71e3b5fd2e258a676b~4I3ZEfsII2606726067epoutp011
Received: from epsmges5p2new.samsung.com (unknown [182.195.42.74]) by
	epcas5p4.samsung.com (KnoxPortal) with ESMTP id
	20210422091736epcas5p497e47c9e7301881621d406e8845adef0~4I3YtmWeD0245902459epcas5p4P;
	Thu, 22 Apr 2021 09:17:36 +0000 (GMT)
Received: from epcas5p4.samsung.com ( [182.195.41.42]) by
	epsmges5p2new.samsung.com (Symantec Messaging Gateway) with SMTP id
	4C.23.09697.03F31806; Thu, 22 Apr 2021 18:17:36 +0900 (KST)
Received: from epsmtrp1.samsung.com (unknown [182.195.40.13]) by
	epcas5p2.samsung.com (KnoxPortal) with ESMTPA id
	20210422081531epcas5p23d6c72ebf28a23b2efc150d581319ffa~4IBLdfpKd2379523795epcas5p20;
	Thu, 22 Apr 2021 08:15:31 +0000 (GMT)
Received: from epsmgms1p1new.samsung.com (unknown [182.195.42.41]) by
	epsmtrp1.samsung.com (KnoxPortal) with ESMTP id
	20210422081531epsmtrp1110f38b91c9cb4caea94b3bc85405947~4IBLcO7hJ2412924129epsmtrp1C;
	Thu, 22 Apr 2021 08:15:31 +0000 (GMT)
X-AuditID: b6c32a4a-64fff700000025e1-6a-60813f30f140
Received: from epsmtip2.samsung.com ( [182.195.34.31]) by
	epsmgms1p1new.samsung.com (Symantec Messaging Gateway) with SMTP id
	31.24.08637.3A031806; Thu, 22 Apr 2021 17:15:31 +0900 (KST)
Received: from localhost.localdomain (unknown [107.109.224.44]) by
	epsmtip2.samsung.com (KnoxPortal) with ESMTPA id
	20210422081529epsmtip221d1e82eb9ad9648c0a66f4c2673e534~4IBJfwv2f1502415024epsmtip2P;
	Thu, 22 Apr 2021 08:15:29 +0000 (GMT)
From: Maninder Singh <maninder1.s@samsung.com>
To: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	akpm@linux-foundation.org, dvyukov@google.com
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, a.sahrawat@samsung.com, Maninder Singh
	<maninder1.s@samsung.com>, Vaneet Narang <v.narang@samsung.com>
Subject: [PATCH 1/2] mm/kasan: avoid duplicate KASAN issues from reporting
Date: Thu, 22 Apr 2021 13:45:16 +0530
Message-Id: <1619079317-1131-1-git-send-email-maninder1.s@samsung.com>
X-Mailer: git-send-email 2.7.4
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFvrOIsWRmVeSWpSXmKPExsWy7bCmlq6BfWOCwcqtohYXd6dazFm/hs3i
	+8Tp7BYTHraxW7R/3MtsseLZfSaLy7vmsFncW/Of1eLw/DYWi+NbtzBbHDo5l9GB22PnrLvs
	Hgs2lXrsmXiSzWPTp0nsHidm/Gbx6NuyitHj8ya5APYoLpuU1JzMstQifbsErow7PzrYCzrl
	Ko5fP8PUwNgg2cXIySEhYCLxafMKxi5GLg4hgd2MEo9nPmaCcD4xSqyf94UZwvnGKPHoVwMb
	TMvkLTPZIBJ7GSX2reqGcr4wSqyZ+pEdpIpNQE9i1a49LCC2iECJxIG+LSwgRcwCexglDp65
	BZYQFvCS+Ph/CROIzSKgKtH8rB+smVfATeLB3E9Q6+Qkbp7rZIawr7FLbFogDWG7SOx9tIIF
	whaWeHV8CzuELSXxsr+NHWSZhEA3o8TMOZeZIZzVjBKbXlxnhaiyl3jd3AC0mQPoJE2J9bv0
	IcKyElNPrQM7iFmAT6L39xMmiDivxI55MLaqRMvNDVBjpCU+f/wIdYSHxIrfh8EOFRKIlfjc
	3sE2gVF2FsKGBYyMqxglUwuKc9NTi00LjPJSy/WKE3OLS/PS9ZLzczcxgtOGltcOxocPPugd
	YmTiYDzEKMHBrCTCu7a4IUGINyWxsiq1KD++qDQntfgQozQHi5I4r6BzdYKQQHpiSWp2ampB
	ahFMlomDU6qBSZfr9+9NWz9dmn/DVDUwKTRn36IuP4ffJZsdTt3c2MN6+MSKqwsq6zdNmhK3
	lu9U5UmlxHNiQn8KTdXO6RUK1jIL1t3Z+PiMX7nMPane4BV7ZeQn/A1+zLW2+/rFuqCDl/h0
	mfe/m3bntKFc2K7eE9cOzZN/PulspvjRZ0Url0TYseda+SQdX/y3nfddt8221QKCugIrf3td
	OXx30p6YENP8baxuYfw3/Htn/Z/ife2E7PublxvTvVOK75e88hHUUxPol1O/y5Pi7Xi67r/u
	BLY9782mp5g8yM+Z3nxz+55s6cPK8kYtM79efHr+k5qAYwPrvhsfithXVDTkr5ofrqeheurq
	BV35JY7Vyz/8WKDEUpyRaKjFXFScCADVhQsJigMAAA==
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFprFLMWRmVeSWpSXmKPExsWy7bCSvO5ig8YEg+nLhSwu7k61mLN+DZvF
	94nT2S0mPGxjt2j/uJfZYsWz+0wWl3fNYbO4t+Y/q8Xh+W0sFse3bmG2OHRyLqMDt8fOWXfZ
	PRZsKvXYM/Ekm8emT5PYPU7M+M3i0bdlFaPH501yAexRXDYpqTmZZalF+nYJXBl3fnSwF3TK
	VRy/foapgbFBsouRk0NCwERi8paZbF2MXBxCArsZJT49m88KkZCW+PnvPQuELSyx8t9zdhBb
	SOATo8Sh6SIgNpuAnsSqXXvAakQEqiSm/9rBBmIzCxxilOjdIQxiCwt4SXz8v4QJxGYRUJVo
	ftYPNodXwE3iwdxPbBDz5SRunutknsDIs4CRYRWjZGpBcW56brFhgWFearlecWJucWleul5y
	fu4mRnDwaWnuYNy+6oPeIUYmDkagXRzMSiK8a4sbEoR4UxIrq1KL8uOLSnNSiw8xSnOwKInz
	Xug6GS8kkJ5YkpqdmlqQWgSTZeLglGpgsr1nulLOULMswFc+vWCWycHAtYeP85jnyU9Qvh9y
	fcPDGzJVN19orGXpbxSbssyo/cNHRV+OTXNW2S7ZEcDzOrzvzm7BcAGLzEli9+75zhZ2P53f
	tLC7PczOsWWlhbqwG/dfrooZ3QzivHZn14jo/vVdn+uhtfPmtS36fJ383KtqnEyN9SXMf3b7
	NTLksnEa+T+U03P/y3FWrXr71R0T5lmxNBcYxk39WlbP7TVry6wzRbeOtE1wzwldpvRAozGt
	J/b2qunOOdVTroncmxitU2Yfv/Hs7gCnRTfzDvc+N9oy2XFbcpnmqoYfixOWe3w6tik7fwr7
	siUXt9075u8xN1w1deHNqs+9KSsdJWYqsRRnJBpqMRcVJwIAc/BDTK0CAAA=
X-CMS-MailID: 20210422081531epcas5p23d6c72ebf28a23b2efc150d581319ffa
X-Msg-Generator: CA
Content-Type: text/plain; charset="UTF-8"
X-Sendblock-Type: REQ_APPROVE
CMS-TYPE: 105P
X-CMS-RootMailID: 20210422081531epcas5p23d6c72ebf28a23b2efc150d581319ffa
References: <CGME20210422081531epcas5p23d6c72ebf28a23b2efc150d581319ffa@epcas5p2.samsung.com>
X-Original-Sender: maninder1.s@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=GrzuS8Ty;       spf=pass
 (google.com: domain of maninder1.s@samsung.com designates 203.254.224.24 as
 permitted sender) smtp.mailfrom=maninder1.s@samsung.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=samsung.com
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

when KASAN multishot is ON and some buggy code hits same code path
of KASAN issue repetetively, it can flood logs on console.

Check for allocaton, free and backtrace path at time of KASAN error,
if these are same then it is duplicate error and avoid these prints
from KASAN.

Co-developed-by: Vaneet Narang <v.narang@samsung.com>
Signed-off-by: Vaneet Narang <v.narang@samsung.com>
Signed-off-by: Maninder Singh <maninder1.s@samsung.com>
---
 mm/kasan/kasan.h  |  6 +++++
 mm/kasan/report.c | 67 +++++++++++++++++++++++++++++++++++++++++++++++
 2 files changed, 73 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 78cf99247139..d14ccce246ba 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -102,6 +102,12 @@ struct kasan_access_info {
 	unsigned long ip;
 };
 
+struct kasan_record {
+	depot_stack_handle_t	bt_handle;
+	depot_stack_handle_t	alloc_handle;
+	depot_stack_handle_t	free_handle;
+};
+
 /* The layout of struct dictated by compiler */
 struct kasan_source_location {
 	const char *filename;
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 87b271206163..4576de76991b 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -39,6 +39,10 @@ static unsigned long kasan_flags;
 #define KASAN_BIT_REPORTED	0
 #define KASAN_BIT_MULTI_SHOT	1
 
+#define MAX_RECORDS		(200)
+static struct kasan_record kasan_records[MAX_RECORDS];
+static int stored_kasan_records;
+
 bool kasan_save_enable_multi_shot(void)
 {
 	return test_and_set_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags);
@@ -360,6 +364,65 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
 	end_report(&flags, (unsigned long)object);
 }
 
+/*
+ * @save_report()
+ *
+ * returns false if same record is already saved.
+ * returns true if its new record and saved in database of KASAN.
+ */
+static bool save_report(void *addr, struct kasan_access_info *info, u8 tag, unsigned long *flags)
+{
+	struct kasan_record record = {0};
+	depot_stack_handle_t bt_handle;
+	int i = 0;
+	const char *bug_type;
+	struct kasan_alloc_meta *alloc_meta;
+	struct kasan_track *free_track;
+	struct page *page;
+	bool ret = true;
+
+	kasan_disable_current();
+	spin_lock_irqsave(&report_lock, *flags);
+
+	bug_type = kasan_get_bug_type(info);
+	page = kasan_addr_to_page(addr);
+	bt_handle = kasan_save_stack(GFP_KERNEL);
+
+	if (page && PageSlab(page)) {
+		struct kmem_cache *cache = page->slab_cache;
+		void *object = nearest_obj(cache, page, addr);
+
+		alloc_meta = kasan_get_alloc_meta(cache, object);
+		free_track = kasan_get_free_track(cache, object, tag);
+		record.alloc_handle = alloc_meta->alloc_track.stack;
+		if (free_track)
+			record.free_handle = free_track->stack;
+	}
+
+	record.bt_handle = bt_handle;
+
+	for (i = 0; i < stored_kasan_records; i++) {
+		if (record.bt_handle != kasan_records[i].bt_handle)
+			continue;
+		if (record.alloc_handle != kasan_records[i].alloc_handle)
+			continue;
+		if (!strncmp("use-after-free", bug_type, 15) &&
+			(record.free_handle != kasan_records[i].free_handle))
+			continue;
+
+		ret = false;
+		goto done;
+	}
+
+	memcpy(&kasan_records[stored_kasan_records], &record, sizeof(struct kasan_record));
+	stored_kasan_records++;
+
+done:
+	spin_unlock_irqrestore(&report_lock, *flags);
+	kasan_enable_current();
+	return ret;
+}
+
 static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 				unsigned long ip)
 {
@@ -388,6 +451,10 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	info.is_write = is_write;
 	info.ip = ip;
 
+	if (addr_has_metadata(untagged_addr) &&
+		!save_report(untagged_addr, &info, get_tag(tagged_addr), &flags))
+		return;
+
 	start_report(&flags);
 
 	print_error_description(&info);
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1619079317-1131-1-git-send-email-maninder1.s%40samsung.com.
