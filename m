Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZMNY36AKGQE5PSQ2SA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 13E51295FA8
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 15:19:34 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id h14sf706201ljj.3
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 06:19:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603372773; cv=pass;
        d=google.com; s=arc-20160816;
        b=pvMm3dwsBycP17/hnKAd/dHlejYblNr3VH+8sa9LRtMon9tufFsn4rBVHaPYV7r/wp
         VbboChchB8h9aTXKUpjiPU/6dKZlzEZXqGd0QJ1bcY4Sq/AG/flEvTFIAp7FS0lu/z2c
         JWv7MbcejXMPwmukp5XFtW25006nn+JQJpfA3bs9dZZLHANOlcTeeLaO7z61ZVZh0U/V
         xd6FhUNpRWDblLlvatiLvKwHsSZD/9pt7/ayALmd/i7syR5yNcubE1xOwjceKo4evclP
         fs2cwBtITrn/vpVxuob+GNTGJK2efRJBDjbJIkVdoIIcaEbto+ZTPfPE2i6QAQnNGdMF
         V1Fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Jbo7yWVu1Zeuu7aeX0u2+h3v24XJuxW2pZ673GlnBMk=;
        b=SvWrNMYau9s7DiDLf/1u2xmW5n26sojbE3h0v++H8OgVkY+K442TYROEEOO15EkbfH
         H6AU3tTlkCkim4Of3oO0IzYOwOx6ozwNVyZVcryzrnWTHnWfe4uwcKmcDMkMbR73B1lY
         06NKCMLYOGSjlJoqPQ1ZmQzoK6Gfzl0nSpcPmD+1ryozC8olo37ILyqlbS2aaug/8KOc
         jtpNvLAmq3dAmdm8RrfzSI9dGjJwL3dc5vxFp2zRXc70i4uAUB3+kzum1hioW1ROaXfG
         von4LPKJ2EcU35sg3sWUX1AYoDk8a+M3bud5qGERRTtlOLlybEXwf+EOH5Jv+SIaxmvQ
         D4yw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s9oM5iH8;
       spf=pass (google.com: domain of 35iarxwokctsxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=35IaRXwoKCTsXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Jbo7yWVu1Zeuu7aeX0u2+h3v24XJuxW2pZ673GlnBMk=;
        b=tUzz+6oVgmE7pYSWGFnnqYjGivYhzbCgL81BDaJmQ28z3bfbiYTorhKDpMPouYlQdk
         cranR95zcXjoUuKc1bB0YI3aQLfLcRIliblyG9S9ThJF3azHri3FDBGUHPe/DyOvyfkN
         /6YXv3rPoa+KInXOVSHCJWGyUzB75GzDuLSCNbT/Zt0R5I2XDwxZ0lhgiQlLxbYS54PE
         kPA8zBIt8gHlhoF+KbjXOenVetUjBC0XXAdfRoAZP+pSsipDSsIGMXT2Xgh1l2KJ/DnN
         YrXrv9dWoSgCQbVsfNZq6PlP60n/hqoQ53H8mKWnNpK6hPLC5AEmLHFPFfO4DGVDVoba
         SYJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Jbo7yWVu1Zeuu7aeX0u2+h3v24XJuxW2pZ673GlnBMk=;
        b=lLVRoPY/TItMRjDCcfSM64gWAH8Ye8PM7EjOz5KgKOdeybQSCYoBJtB48CnzDhDNUF
         oGhm1rbexFhmwCps2K9wvTo1GHRL4hDx0gp28MeRWzMftUOUuEipyLXEwGpRbLadtKX0
         McXym80NsM5r0pI0amzo+CAgmV5PibMgQs7HJLyFhH8lG6FT0bYeMTZwj3K0Qb+Ceykj
         3radcYnM6rFsZgVSrOldNbnfjIm07B1noKXXQTOcdxUhjSZaRQlb9fcz4ipupbJKc/8w
         z3NnkAehwbFwOdIjB+fyZTS7KX0z/QYznvIoLWpXAK+IkTr8EIXGJ+wF3Y8H637eBhbj
         QBxg==
X-Gm-Message-State: AOAM533zTIMVaEpjdXspQ2QsmyawlfvFCCQphyQM+GYs65kvo9Z9ylrv
	0X2cZ2S3jrUkQ0Kf+ndc2c0=
X-Google-Smtp-Source: ABdhPJyMNVItxhs+7Ok62IMl8ALrTjAVO0dZs7BducHa5ze78BTpVftA5qEXFmYW2MhoCa0n0EFfJg==
X-Received: by 2002:a05:6512:358b:: with SMTP id m11mr926187lfr.282.1603372773602;
        Thu, 22 Oct 2020 06:19:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9a86:: with SMTP id p6ls334288lji.0.gmail; Thu, 22 Oct
 2020 06:19:32 -0700 (PDT)
X-Received: by 2002:a2e:85cd:: with SMTP id h13mr1057125ljj.345.1603372772595;
        Thu, 22 Oct 2020 06:19:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603372772; cv=none;
        d=google.com; s=arc-20160816;
        b=DOUvpcGccGmIpmy/HjtcrADg61RW6+n/pmwdZAI48eHg6HIaszzbk5gT+zzj9znvLq
         0NhZqiUA0SzRJNek+f1Cl2IySrjah4ZPtcMMZX4PwBB5kXzvsdO+qTzVxGWVug66gAQt
         1o1bQS5kLXRyu8pyG4cBY9edIFch/3LEPH9w2jwnwzy7U9+o/ZD39iFpbPKOqRTJeigs
         be6uFF0XxYVcF07fcdvMit0Hoi1J1WpPPc4SlyZTt46u7mLthFQJPdq/bH1Ej3nTWFSn
         HiYQ3Ducc+fKo1ATiNDSG+B94Q3kLFIRxWf13mdgxdFgyzUPXLonUEX/6eIP9HvTxk0x
         CQyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=5q3U4VLFNuW4Say/+COEa9cSd+BCTb/gfYzQFqbrIt4=;
        b=dMADlI7vfJXo7tcLiK0v4YeEEigIHWo5PUNa0fOwub1VvgO0iEvBcw+CEHdPbPaZTO
         7knKK+rnnRsAzlOfN3SOIQfxzAJemFEAIefxEf6g3z0pqbsrs3C7clhzyoVf7kdhVLYV
         VOyGKt1sjP8/kCDDSHD76fVHZfHpmFM/rrYAFPGRaZ3oC1QHtpw47T91mWuW4UtUk4vq
         4O2tqvXRniC7UiIY5bNjmCLqmKkmSTuHytHpXCgKUh0VU1ZkqK0QXDbNNGomGDtpAehD
         6EDPqPpEA6Ug2vpSJa9KgqFvnojuG5wHP291HZM/u9V0OwJfiPHyjbyi+PXdJzsTQEn6
         K0WQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s9oM5iH8;
       spf=pass (google.com: domain of 35iarxwokctsxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=35IaRXwoKCTsXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id h4si59458ljl.1.2020.10.22.06.19.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 06:19:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of 35iarxwokctsxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id l22so423790wmi.4
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 06:19:32 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:4fcc:: with SMTP id
 h12mr2880700wrw.132.1603372772026; Thu, 22 Oct 2020 06:19:32 -0700 (PDT)
Date: Thu, 22 Oct 2020 15:18:55 +0200
In-Reply-To: <cover.1603372719.git.andreyknvl@google.com>
Message-Id: <595f9936a80b62ab89b884d71e904eaa884a96c2.1603372719.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH RFC v2 03/21] kasan: introduce set_alloc_info
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Kostya Serebryany <kcc@google.com>, 
	Peter Collingbourne <pcc@google.com>, Serban Constantinescu <serbanc@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=s9oM5iH8;       spf=pass
 (google.com: domain of 35iarxwokctsxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=35IaRXwoKCTsXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Add set_alloc_info() helper and move kasan_set_track() into it. This will
simplify the code for one of the upcoming changes.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/I0316193cbb4ecc9b87b7c2eee0dd79f8ec908c1a
---
 mm/kasan/common.c | 7 ++++++-
 1 file changed, 6 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 8fd04415d8f4..a880e5a547ed 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -318,6 +318,11 @@ bool kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
 	return __kasan_slab_free(cache, object, ip, true);
 }
 
+static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
+{
+	kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
+}
+
 static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 				size_t size, gfp_t flags, bool keep_tag)
 {
@@ -345,7 +350,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 		KASAN_KMALLOC_REDZONE);
 
 	if (cache->flags & SLAB_KASAN)
-		kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
+		set_alloc_info(cache, (void *)object, flags);
 
 	return set_tag(object, tag);
 }
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/595f9936a80b62ab89b884d71e904eaa884a96c2.1603372719.git.andreyknvl%40google.com.
