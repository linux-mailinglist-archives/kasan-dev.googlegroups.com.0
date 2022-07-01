Return-Path: <kasan-dev+bncBCCMH5WKTMGRBHMH7SKQMGQEDHSHLXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id D0C1B563527
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:24:29 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id m7-20020adfa3c7000000b0021b94088ba2sf419528wrb.9
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:24:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685469; cv=pass;
        d=google.com; s=arc-20160816;
        b=G0YfAQs23bqKIUcAlZZnxyAZA6lEMwhv+kzHdsb1eHsDhItYxdRFs5SYb548uiCsyv
         dUR6j5A/iCO4gdP8Gi6LGqEgRVlkuJtFazdU2TIa2AXAsow0Fqz/JGLypSMlWzcKEuh7
         C7GRURdbJZZQcTfxfEMSrGaDfHihKdBGMh1PZAuHqR2B4ekRAHsbSd3qvV966g8cNibX
         mvT2aD5cjWRm+UcQAGNHE0ZyrF1YrI5tfZyB2PqUty+mZNUYL/kOb1l+QYifPD7NiQg1
         SDvORB0KGIpRHm024aTf99ktAQ5DDb3HMq4XBH0ljizRX9fW2d+5v7zFdilhOFRw3+a/
         sSXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=O/53iuzyIwUH22S82FdUKx4akgUvAGdf1Bs8JMl3qJk=;
        b=gvo1J2QGP9RHnzOcnBDfIYulzgh0rZltFFZlHi8KG6Ca2gVkvHLlIL0Ioac2QlCZIt
         ZAuVokSnqpesQ0D5+4PO6q3Pu06kWVRbYyPMG8vn00zAyDCzW/3ixUDcDPrwmrttL3h2
         BhtGQh386h59tuKkjsTsp4m6blnUPjo0Ef33FNTMIl+WW2SEVbP61fN8Rw2jwgUsWYKx
         ukKpyTqjDYnYM5ALPS6UKkuOVfcMbOTuQEONqSIsF2L2yl1loL7nW7XJ9wYJmeLBKnVD
         8bnL/Atgfknm+DAaJEKruU34xDhB0spfZa0UXWHczMf0P5I/+gSKdwUvmw6/PMRf5I/i
         PlJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mRTIF6L8;
       spf=pass (google.com: domain of 3nao_ygykcbshmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3nAO_YgYKCbshmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O/53iuzyIwUH22S82FdUKx4akgUvAGdf1Bs8JMl3qJk=;
        b=IQhO73qPLZrsBnPZjovigK46V1M28g/ce1+/6KxXVgGcL5TRK8qsAdTzi5e4k2X97m
         9rWMHDexzDn4pEPsXS4aOswvaiq3T9jv4t71HwNF6XO2blAXcVmyW/vln1QVI//A9xPD
         vH8IVEgc71FqX+feEOmRunlkHXIW3MSFSd6TE9Ytck+y4083ChsGNzp/4fwoqMeDKUso
         Ug3zTcDdwibSLCGfwGp/EJMUPShyZbWBA/ZrRp65q3rtVgbm1x3n7ytIvHYHRG9yukMt
         zcEYoAAyEdCpiIk58sLyKMhAM6LR9jgQQUN9Nt/VBh4tS/zi91PIvScIF8uzHQ4vckBR
         zP9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O/53iuzyIwUH22S82FdUKx4akgUvAGdf1Bs8JMl3qJk=;
        b=XSvrnJkDR9uJ7Oqx6xoe6kLxzgjofN61cr+obxtSazKo5Q/0jSkRO0s0ShqJMWdyd3
         FVpnoqrc3cPMHtMiwz1hdOSV5WiEp/FgRwVHSQ7jb5Kl4jqnCtt2blAGW38z3bivARAw
         wWCOuBVCf5VV7/XvUHlPQAmImz8dzS/B/dOwMl8OTIquKgSuLKCYU58267VF9W+RosH1
         Rrynh0Pvj2G0X9Yy1DsCsmTP0C8SrmKeZy/unVnjATvmS9Cy9JPNA4HadaZtM/r7nQNo
         aiHR+y8cUHVNhYWhAfxqPgC4GlJS08VKxy8+kEROGWLY4xivC5UPrI7kNuQC56F2diLh
         pZPQ==
X-Gm-Message-State: AJIora/MfGQrZOLXwXKRCvMhtjJRQRPS3BgTAMYr4/6xhAP9tXQ9OyUR
	GfY6tusGMLDjSCau9RiHniY=
X-Google-Smtp-Source: AGRyM1tdITaIzu1QUpgbh13N1kM2uVAeDYebqe+LOPXD7XXHd908q9jptsCpEqoDmzJ2hRKWXoB1rA==
X-Received: by 2002:adf:d1c1:0:b0:21b:a5e9:b7b2 with SMTP id b1-20020adfd1c1000000b0021ba5e9b7b2mr14784759wrd.405.1656685469399;
        Fri, 01 Jul 2022 07:24:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4103:b0:3a1:7b62:38e7 with SMTP id
 j3-20020a05600c410300b003a17b6238e7ls3182785wmi.0.canary-gmail; Fri, 01 Jul
 2022 07:24:28 -0700 (PDT)
X-Received: by 2002:a05:600c:2313:b0:3a1:8ed2:4322 with SMTP id 19-20020a05600c231300b003a18ed24322mr3029811wmo.166.1656685468436;
        Fri, 01 Jul 2022 07:24:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685468; cv=none;
        d=google.com; s=arc-20160816;
        b=J7spR/1gjA0EtMUnRKDQjxRvn5BoHhO1SZcLqwcCTsZHgAaUBiLkCjtcE2CY2/DRhq
         MyeSVf0+7I8nPg4PJClt/LHRFQyLP+JQNmfOlYVzvhxa/YUCa4BJie7lzSd1BJk3D+jU
         KHwQ6bovIH8pGatLg9jXVeERpxynuC3wvDQIDn0Sk/cdj18JvTy0ujH0TQJLenqeKIFn
         pogcD6gYmeJBhIV+l96t2U5AVJ/GxYAQ5htHrQV3qTMpTe0C1OD4GF9xdSsNGUsu9EI2
         AOw5An6Roqu9z4Rz8N/bChpp6dk4T3ciPG/S1Ln6seCRSB0CusYQ+279YnipopxrTssi
         g37Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=BanD6+8XMfAM/imhDA9kzvs2Y65ZtmV55Antiu9BWiI=;
        b=CMOwGm2A6hrj63RidgjcPWtXOC/zM0YiODMC9DwXIvTMDA+WV88xotquYmSdcIE38/
         VHqQvH/mLjaWJW6AsGC/qDVuSqSgRpr7Q25iY/LIkqlObyCUlzrNvCfEnbRBeyE3i5RJ
         QN0irbT0sHsskxXe6YVi6Ifr1WPqiPK13zKG2W9Qh+DkkAw3RnG3JPQmYblIhS1UY7dN
         NOVUS1FQh+Grt45VhjlA2VTXgfq36FFcbVxH/rzq7c0BDlPvIBHRQfel3wL81mqf4CZQ
         ErZ/I4GK2w/wtf4hVGlO35Rf3hf7d4oSLO6hbWgS002EnrCzU4NUeFOg2CJMYYz/8BEs
         pMSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mRTIF6L8;
       spf=pass (google.com: domain of 3nao_ygykcbshmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3nAO_YgYKCbshmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id 68-20020a1c1947000000b003a050f3073asi202202wmz.4.2022.07.01.07.24.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:24:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3nao_ygykcbshmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id f13-20020a0564021e8d00b00437a2acb543so1883596edf.7
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:24:28 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a50:fe0c:0:b0:435:510a:9f1f with SMTP id
 f12-20020a50fe0c000000b00435510a9f1fmr19625057edt.297.1656685468052; Fri, 01
 Jul 2022 07:24:28 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:51 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-27-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 26/45] kmsan: disable strscpy() optimization under KMSAN
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=mRTIF6L8;       spf=pass
 (google.com: domain of 3nao_ygykcbshmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3nAO_YgYKCbshmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Disable the efficient 8-byte reading under KMSAN to avoid false positives.

Signed-off-by: Alexander Potapenko <glider@google.com>

---

Link: https://linux-review.googlesource.com/id/Iffd8336965e88fce915db2e6a9d6524422975f69
---
 lib/string.c | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/lib/string.c b/lib/string.c
index 6f334420f6871..3371d26a0e390 100644
--- a/lib/string.c
+++ b/lib/string.c
@@ -197,6 +197,14 @@ ssize_t strscpy(char *dest, const char *src, size_t count)
 		max = 0;
 #endif
 
+	/*
+	 * read_word_at_a_time() below may read uninitialized bytes after the
+	 * trailing zero and use them in comparisons. Disable this optimization
+	 * under KMSAN to prevent false positive reports.
+	 */
+	if (IS_ENABLED(CONFIG_KMSAN))
+		max = 0;
+
 	while (max >= sizeof(unsigned long)) {
 		unsigned long c, data;
 
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-27-glider%40google.com.
