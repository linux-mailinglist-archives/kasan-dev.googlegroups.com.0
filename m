Return-Path: <kasan-dev+bncBC63TR5BXECBBFND4KKQMGQE5YDXOCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FDBF55B305
	for <lists+kasan-dev@lfdr.de>; Sun, 26 Jun 2022 19:04:22 +0200 (CEST)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-31814f7654dsf61088017b3.15
        for <lists+kasan-dev@lfdr.de>; Sun, 26 Jun 2022 10:04:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656263061; cv=pass;
        d=google.com; s=arc-20160816;
        b=S6wMTpE7YgfTxKMld017vYtXEYA+DoH+9K44J6oqOeoZb0bayyEubay7UF3sMgj2ey
         APLngtXtXDwB8PI3GlB++T9LFJzRLxFq/6MbKrb9/csIki+/iOwXgaSIrNGM2/L8qKmw
         YsoRFpzcsKQ3lbqBYBtdVYhCDKwkVpUb2lZfOOc/VzrDlKJmhl+fjdnit1D9ySDLT4od
         cu3Mif3pNty1qkOo4YdZVzbIbi59NsBm4LppMh6PC8Ag79DfUEgaV80k407ZDUP5H6ym
         0IVRdWr6/mTCFykI9zTnS7W+y4BcOAPyHh+6eyRgFnUxrlZlwEIKXF3GOn+rNg3dogYf
         FrUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=7LtySwGGy+uFzyuls3VQIbnRyiFuoIvMMcVCvYNSNUQ=;
        b=ygkCfvWX2BSBQGytoIdIvg24WNQQCYqVveZz8q+sbxik79ROncylROCJT3+6Hpj5jn
         PS/ItqnVjZsEiY9swypqNyCiasgQlGkqLr/xWpAtBo6xRnK/+I/y7dDxkm270dD/uJSX
         5fuKQEa6ybYagbpNqww91IkC8TqmQNtFIRMydrdp+2gIwfLqBndnVInMS1uUV4HL6kAw
         qXoZwsT9dICBCTmcdniCKGZJ4k2G8b/hI4DmtNCRo7+A2cNFKQ2lU/FA4lmE5HWWto61
         CLXMkioFrGBdkCUdTwOU9fxjSqF2Ck6ZJ+pBpCrGL2pUxS3naY3xXzXHDMPQJ3u3KNZu
         ulZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=AAAVJXiW;
       spf=pass (google.com: domain of gautammenghani201@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=gautammenghani201@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7LtySwGGy+uFzyuls3VQIbnRyiFuoIvMMcVCvYNSNUQ=;
        b=OrdUoY7627XRWUeLNTR8gabpgLGF80dKaUcSBz7TbNMNp0+EDJm/JtR0cEnEO0Urd6
         XHbVR89w/jJXHipomSNEiy1BBjqp53S/qNZE7j3jh0PqA9aFtOfZtadd3TRs65kyDlgx
         zk7xsF77yPsM0YbpWXCJpKCNs1ui8NTZUW3rL45OOe3Zn/yt4zPSsVgnAiwUTmoj8fAC
         Azh6KyrGlwJfrrXsLOAUpW/a8hkIz8makjoKZqbsvlRCJ17Ire+S15+re9pxIMU3X4JZ
         gKkv1Eb1rMze7abomRZp9RKV6Wz+gAU/cevYxkVAfbJB7cf7Zl+7ZjyBDTWGIgWiKKrv
         ABXQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7LtySwGGy+uFzyuls3VQIbnRyiFuoIvMMcVCvYNSNUQ=;
        b=e+KJFex03g1e6tD4yF1o8cYtM8viz1fh1kOU+UgtV2LyowpWIQht942D52fRrFu6tN
         3v1yzS/+V5LJPwraFvA8AwUYpTVEf/xepM8LMOLXcgxETuLe4rNY/J50zUpN0amiNSkh
         rC7K8cOB/UmGxWEZ9y+mWQ180YPOcSyZgE5a9fkfYOGvzfjXBj9ioaKUeUrWa7F0K6OQ
         8E6i2PwfSQZmhOEiobHVRvXdYjqvcYzBZ21VFyYVRBIUGM81lql3lAXpE9CNWCdzrBkk
         2P7LUwHOcWP9FA9sDdAbgu9R7B+/lDUmZYDFwYtRn7rMzqqOuAV2pTPAXHHIf8pAZNAk
         RNLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7LtySwGGy+uFzyuls3VQIbnRyiFuoIvMMcVCvYNSNUQ=;
        b=SuDSESviY2h1koiazdVGGHS1CetDToQysLr4GfN1wzy95GsPOlSCvzmfow8Xn86pCD
         UFW0HwbYgJEDZn4ZG3JpFf4DL+p2Vo1fqOc9TRLpTk0aWIXFPNtoUjpDgsJioPFBatH4
         fVuH4xx9nhRJrWJJzmm7NZTx9gTr+IYFXVSGsJYgXQmlxaytEa2PATmijWOGTS5guvy/
         OMOqsII5gM3h1esYhty6C9EVVSddXesZCmJvrWXKMxygoJanCiM4uMAO3Kq0rvReAIeI
         1iTk0+oNmSYjUBDiWBXGCVT3llt4Xk0JeD8OL2rEew3jPm/9YK5v7b0Ien9JG/+G++K9
         V0Fw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9uSDscT8cVFts5EXB4F7uyDQcYAzBq0q8ShHVKzcHjTrm3UCW6
	MjVaBPbvWdkDo+0pYrr4osY=
X-Google-Smtp-Source: AGRyM1twhQEMHFwdCvnEi8MVIXxTLT90nR1ouKixzxJHYanj+Pqebqtk4EgjPjCdG0M696aQo7F4NA==
X-Received: by 2002:a05:690c:316:b0:314:2147:2b90 with SMTP id bg22-20020a05690c031600b0031421472b90mr9878523ywb.318.1656263061241;
        Sun, 26 Jun 2022 10:04:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:9b0e:0:b0:317:7fe0:b30 with SMTP id s14-20020a819b0e000000b003177fe00b30ls12627600ywg.4.gmail;
 Sun, 26 Jun 2022 10:04:20 -0700 (PDT)
X-Received: by 2002:a81:1113:0:b0:317:a2d9:3cef with SMTP id 19-20020a811113000000b00317a2d93cefmr10239302ywr.207.1656263060724;
        Sun, 26 Jun 2022 10:04:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656263060; cv=none;
        d=google.com; s=arc-20160816;
        b=eS8KJw11805SNM2yHNLcHAFoi5PJaPuHs+qzAHDB8H1afx1Y27sXwlKklXxhD3nqUO
         lhDeJCZ3cPOwvJlcC5mhIBYGgUEO/i5UGkToDFE4p6AevJf+TBnuOoBcGS7C0XGBgPdM
         6xPrXSS4+b3FTtwSHnLSjc6beQAS/b1c7gKVc+5wJWr/ItS7iAnOtIe/XsZ1zmYTzL1u
         jot2cZFtbGNYmf/2BfiTNaOFWIO7jRbEhke+rtw5+vXc6m6FMPT0UXrOU992FuT3jkyj
         qS/s+ChWFEtja+rGjqAM3cpl6OfckdsVLrBHPTrTfsJ35n3DtaG67WYZuMPk+Ws1V41I
         BWzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=oFSj1F+cvrzuMgRbVJtsNeMg49O8qOKUhwSEI2b4t3A=;
        b=D0N28XIbQaw932a9ZDQPO9/ooTAMviwKpx1gX63uu5mVhTfzqtmhduAEgb6LXs/Xuv
         YPQNpSs3KMrXWEZlfsyiREPPzX6LgvqoHuDlSTz9mfFy0rfxkykenYU7gmMfXBYyqbPt
         uwhRhH97xlICbBEY/BS7fj7p6CIFpJNfl5zA2MSU4b8Wl8TKTMRmcsQHOtbZaLvwLYJ9
         MsMWVd+qrDfHxHYu+Iurp8fsWUlJSEbCDp9RWUG13Ghzcf/PuWElv/g1E5Jx3E4kuXQ2
         fA4lp+bMylCl+zYg0jHgRICeNN4lndCMRSJkjc247uTpAFf8GabAG0Ay0Ij1eNIqEQyD
         Qteg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=AAAVJXiW;
       spf=pass (google.com: domain of gautammenghani201@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=gautammenghani201@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id f10-20020a25cf0a000000b00669b1eaf58dsi365424ybg.2.2022.06.26.10.04.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 26 Jun 2022 10:04:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of gautammenghani201@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id n10so6281448plp.0
        for <kasan-dev@googlegroups.com>; Sun, 26 Jun 2022 10:04:20 -0700 (PDT)
X-Received: by 2002:a17:90a:5b0d:b0:1ea:d1ed:186e with SMTP id o13-20020a17090a5b0d00b001ead1ed186emr10676962pji.240.1656263059833;
        Sun, 26 Jun 2022 10:04:19 -0700 (PDT)
Received: from fedora.. ([103.230.148.188])
        by smtp.gmail.com with ESMTPSA id ms3-20020a17090b234300b001ead46e77e2sm5450642pjb.13.2022.06.26.10.04.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 26 Jun 2022 10:04:18 -0700 (PDT)
From: Gautam Menghani <gautammenghani201@gmail.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org
Cc: Gautam Menghani <gautammenghani201@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	skhan@linuxfoundation.org
Subject: [PATCH] mm/kasan: Fix null pointer dereference warning in qlink_to_cache()
Date: Sun, 26 Jun 2022 22:33:55 +0530
Message-Id: <20220626170355.198913-1-gautammenghani201@gmail.com>
X-Mailer: git-send-email 2.36.1
MIME-Version: 1.0
X-Original-Sender: gautammenghani201@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=AAAVJXiW;       spf=pass
 (google.com: domain of gautammenghani201@gmail.com designates
 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=gautammenghani201@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

The function virt_to_slab() declared in slab.h can return NULL if the
address does not belong to a slab. This case is not handled in the
function qlink_to_cache() in the file quarantine.c, which can cause a
NULL pointer dereference in "virt_to_slab(qlink)->slab_cache". 
This issue was discovered by fanalyzer (my gcc version: 12.1.1 20220507)

Signed-off-by: Gautam Menghani <gautammenghani201@gmail.com>
---
 mm/kasan/quarantine.c | 8 +++++++-
 1 file changed, 7 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 75585077eb6d..c7554f5b9fb6 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -128,7 +128,13 @@ static unsigned long quarantine_batch_size;
 
 static struct kmem_cache *qlink_to_cache(struct qlist_node *qlink)
 {
-	return virt_to_slab(qlink)->slab_cache;
+	struct slab *folio_slab = virt_to_slab(qlink);
+
+	if (!folio_slab) {
+		pr_warn("The address %p does not belong to a slab", qlink);
+		return NULL;
+	}
+	return folio_slab->slab_cache;
 }
 
 static void *qlink_to_object(struct qlist_node *qlink, struct kmem_cache *cache)
-- 
2.36.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220626170355.198913-1-gautammenghani201%40gmail.com.
