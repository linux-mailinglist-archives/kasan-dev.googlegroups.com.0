Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4XRZT5QKGQEYQ72QTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 5717427CF60
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 15:39:00 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id 8sf3734238pfx.6
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 06:39:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601386739; cv=pass;
        d=google.com; s=arc-20160816;
        b=hol+TNXFVrGPMJZaVeR1+XgVP1A/xLXi2npTRUMJb1N5LuwobFU7DgayzXSo2OE8PR
         2PuHnsQHYDxD5wLi3BrOA2chY2QllTmmuruJmI0HfwOLexoWhir4mGOqiuJEfMvhx7Fv
         mWuJiCu7d4yI13jtyneJH7xUFVhMxjOzpk8KcPbKrZCUEUJxWMuB550CvK6Hvr6V6STe
         jjOb61NAGj3AF/jzKdhLz8mBC1wRJv2rM7lUqH83ceQQVpbe142iFUop8Pdheu2sdB+M
         YSB2OVvfHqU9h11MIsZST2bWrY8Aedt1WxfLoTX7Nc9o7O5dfKSpo/5XYdmuMFoWl+RU
         mQlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=F0hn0Yu2du2yZNoFM+3UYP0x4JcnNYMIlUrdTt5cOM4=;
        b=t/r36W4skzBV3Rizk7878kdOG4bwyHnOl/sv60vW/0/YKNe5LFVKXN79tEfsE9D9BZ
         PDwNJIOrxCEVi0uIz3Ju/BlmX7mP+mttNnFvmbijelpH3CojwOmUz2Z6zEuqmRPHDGPT
         PtXjWM5Y1V1gct1bTFNqq08jPSGmMmnYTr/kVj3DuCQNvtGyigsSc4ek6E+XyycK5DRH
         8rj/PBOhP8X0slsaFCByauxWr0WiFKT6LI8fJwl6eYqtqgQSUgZb9Qd2JUS7mYuqGpR/
         C2ir7b4NNpJpGNP1WFDHVmagzjNCrAxf9X2ZyXqVeBUyTD8neLT1k93peIgW8oYW2kAN
         Tb1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=er322a8g;
       spf=pass (google.com: domain of 38thzxwukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=38ThzXwUKCTISZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=F0hn0Yu2du2yZNoFM+3UYP0x4JcnNYMIlUrdTt5cOM4=;
        b=Nqu5qZeV5zHsCknyGcJyEUOMTpo8Gg4uZ/IuTdUBmJ19V572ChLBaFnBYL/DBIggry
         VTIupYLQIJ3uxk6wWbvYl5WGOhNGc9PdYhkANEteuCAUWZzYnb/yrhJ/HSezlJ5u8jgO
         yamLntbRZ03hVSobmc8jO3DMQWvg0xTLbi2M5z+FHZED6oroqNKdT8R/dfxxBQ1E2ZfK
         B8WzQD8z/7BI5cE7WmDc/hzkpxy70Q7N6msT7RR74zlyc7qD1PLlaE/0OLAqe15391mp
         MbW8rnNJ8CfhczXiCLLJ1v9YQ86gtbnK9yt4V8Mh0aD4yVGZpKinybbnu73bSSU6VjYz
         1PPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F0hn0Yu2du2yZNoFM+3UYP0x4JcnNYMIlUrdTt5cOM4=;
        b=soPMQbxNTC9f9j241b3z2SzmBoNyc16mEvJax8kn+xcVU6Erzu8Gm52EzgJA5hXdz1
         lbSsBIVHQc0/OpKSai4oNdgrpXqVoySgHmEveQ1CyOBCmavb/0+csvpDRm8MJyubt3FQ
         NalAM0J+OljJvvfpu+FbZuyXBpmtWoX8BQaD4qCsfdf5t+/5v5X81icUD8EYJGFtfq2d
         onQZ0WnByksD8wWaXreHy1ulN0+OdTxtkQjA0px2UJ4u35S+3XsCTgGLmn/U/Wq16dze
         jXtmfG1PSdZXsZeYGzSCMyERi4kjc0NoiecpxTeVPC38UUXM0bkgE1W1ucIt9joPejj6
         aSWw==
X-Gm-Message-State: AOAM531D+dLTxE9gpBZXF1uK+zg0pUlHTZuwWosCD7rvG9tOZo5PgF1A
	j/lLXWMN1EpOa/CReS/OeMg=
X-Google-Smtp-Source: ABdhPJwvPuR8fnI7ZwBEkwMj6utxSgYuyN++uOiezsSmQXxz/h9ezCgL5e3ygtggyHPUoteK4gOw2A==
X-Received: by 2002:a05:6a00:1749:b029:139:858b:8033 with SMTP id j9-20020a056a001749b0290139858b8033mr3985956pfc.3.1601386738965;
        Tue, 29 Sep 2020 06:38:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:95ac:: with SMTP id a12ls1850873pfk.5.gmail; Tue, 29 Sep
 2020 06:38:58 -0700 (PDT)
X-Received: by 2002:a63:104d:: with SMTP id 13mr3294150pgq.445.1601386738258;
        Tue, 29 Sep 2020 06:38:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601386738; cv=none;
        d=google.com; s=arc-20160816;
        b=dtDMQV4LuhdKeDHyUBzmow2JKGmRH8AszF1p7njVr2uTfIs50WfBmlcc6WXV42ntDm
         ib2VtpgVDytiAt56NFRlQI2a5x7U3X4HHgan3SIHti64MrEg6yD7/ZYglcZELd5x97t4
         XHn/AqPeAEXoBpn4+ruefFP2i4lM7F2ftA59ow2MSKlfwXRqARMOPvTxypHHNP9UmFf2
         kE5yQ6glYC4B9LE5LyImHsPZs7IZC0sHGnaOkfWZuLVmsvtrOyueNrjh+Xuceja2JTqF
         lH9Culxt4zsLBukCNboTmXTlcqeHbnyTb7sr7j6+u5+fzj3mF4MjdNaPm7iKiub3Imau
         RtHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=3PLfj7Le+IfBX8a0VvW3RStHbDZmDhyxflksdHuR0eA=;
        b=IL2G5v2jc6jdGD8mNUCa1IX/TJS1BbM7RDmrT8SRCTG6sHkP3686DjyStRx4tYqJ/Z
         +1X8oNpajsXyqX8VKh9WFPmbZqQNBdNZFihQtXtaT3g6/MlD6CLhS0/CcaqSY1ugh9or
         a8253VK3pEscQAXcv98Du1S7gZsRV7Fo72BbOSfSSM055FiODOqPL7sgG4zptelK08Qv
         qpx8OMPlmZRjmy7Pq1P26Q3nMMgIFEiBKTHMVIVOC6iEtEFg68CYURwGeG5IEa0GZUhp
         pGdvfB+djq+pZwShii97qn5j7deD1v6/vs9vEymFF+Otp66jbKNfDDyEgd6TV+V7dyrm
         Y+3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=er322a8g;
       spf=pass (google.com: domain of 38thzxwukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=38ThzXwUKCTISZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id n8si357577pfd.4.2020.09.29.06.38.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 06:38:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38thzxwukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id i17so2497089qvj.22
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 06:38:58 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a05:6214:b0d:: with SMTP id
 u13mr4600352qvj.17.1601386737145; Tue, 29 Sep 2020 06:38:57 -0700 (PDT)
Date: Tue, 29 Sep 2020 15:38:09 +0200
In-Reply-To: <20200929133814.2834621-1-elver@google.com>
Message-Id: <20200929133814.2834621-7-elver@google.com>
Mime-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 06/11] kfence, kasan: make KFENCE compatible with KASAN
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, hdanton@sina.com, mingo@redhat.com, 
	jannh@google.com, Jonathan.Cameron@huawei.com, corbet@lwn.net, 
	iamjoonsoo.kim@lge.com, keescook@chromium.org, mark.rutland@arm.com, 
	penberg@kernel.org, peterz@infradead.org, sjpark@amazon.com, 
	tglx@linutronix.de, vbabka@suse.cz, will@kernel.org, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=er322a8g;       spf=pass
 (google.com: domain of 38thzxwukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=38ThzXwUKCTISZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

From: Alexander Potapenko <glider@google.com>

We make KFENCE compatible with KASAN for testing KFENCE itself. In
particular, KASAN helps to catch any potential corruptions to KFENCE
state, or other corruptions that may be a result of freepointer
corruptions in the main allocators.

To indicate that the combination of the two is generally discouraged,
CONFIG_EXPERT=y should be set. It also gives us the nice property that
KFENCE will be build-tested by allyesconfig builds.

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Co-developed-by: Marco Elver <elver@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 lib/Kconfig.kfence | 2 +-
 mm/kasan/common.c  | 7 +++++++
 2 files changed, 8 insertions(+), 1 deletion(-)

diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
index 4c2ea1c722de..6825c1c07a10 100644
--- a/lib/Kconfig.kfence
+++ b/lib/Kconfig.kfence
@@ -10,7 +10,7 @@ config HAVE_ARCH_KFENCE_STATIC_POOL
 
 menuconfig KFENCE
 	bool "KFENCE: low-overhead sampling-based memory safety error detector"
-	depends on HAVE_ARCH_KFENCE && !KASAN && (SLAB || SLUB)
+	depends on HAVE_ARCH_KFENCE && (!KASAN || EXPERT) && (SLAB || SLUB)
 	depends on JUMP_LABEL # To ensure performance, require jump labels
 	select STACKTRACE
 	help
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 950fd372a07e..f5c49f0fdeff 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -18,6 +18,7 @@
 #include <linux/init.h>
 #include <linux/kasan.h>
 #include <linux/kernel.h>
+#include <linux/kfence.h>
 #include <linux/kmemleak.h>
 #include <linux/linkage.h>
 #include <linux/memblock.h>
@@ -396,6 +397,9 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	tagged_object = object;
 	object = reset_tag(object);
 
+	if (is_kfence_address(object))
+		return false;
+
 	if (unlikely(nearest_obj(cache, virt_to_head_page(object), object) !=
 	    object)) {
 		kasan_report_invalid_free(tagged_object, ip);
@@ -444,6 +448,9 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 	if (unlikely(object == NULL))
 		return NULL;
 
+	if (is_kfence_address(object))
+		return (void *)object;
+
 	redzone_start = round_up((unsigned long)(object + size),
 				KASAN_SHADOW_SCALE_SIZE);
 	redzone_end = round_up((unsigned long)object + cache->object_size,
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200929133814.2834621-7-elver%40google.com.
