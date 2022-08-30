Return-Path: <kasan-dev+bncBC7OD3FKWUERBL4MXKMAMGQE4LJQRQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 54A045A6FBA
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:50:45 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-11f0ae0928bsf2198437fac.3
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:50:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896239; cv=pass;
        d=google.com; s=arc-20160816;
        b=TYzS0/9GT5FoDEeVmB6FuJFzANRxkX/nxCkEB/n4S9i7y7Z05jVdKUlvWDrRIliaBY
         0xrNrHv+LJWz3bSeIDPtS1oNHD0T6U0+jslBH2Yt+tvousBXShYXg1ckMK7MLg+AtpLb
         tcpI+E02GBGFhRsP/JZnjsEFBM96sm67oGT4oc9mErE8hAufBqBQQyEcX4QyggkasySq
         4lugV3c56GQ4/mzeE/MrHdtFO0MB3YUlK4LflLqCFlKuUdq2X+Fb1s9Ko/lGsoW+0Nm4
         jNSig+R0AL56UCwsRu5PiCqQlW2OOGTUN/MGZwcJn7STW8aYUyq69tEeyjgWU5zA8UOj
         TBiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=F47Pj3mZjjvJLCcRAXl07YT/Zr3PyfsF8Hb18K8XJkk=;
        b=mwH0f2exnoQ76KZzfXkrig8GcXHG6s0XhUXF1zpqGpt645odep4T5QLRqnbMym7qXx
         EsxCBbdWJOl0/LV+U4/O2EhQjA11/OD4+lo3OSMoTjK7MzTj82lwqB/DdVTowi7EMuSc
         rdQrdDE2zoP1x98j2ItgMeHpgUi2PsLvCTBRgbTku2FA1quMvhe/dXOTB8OgDOedQdqo
         kVwMY4bW9t8WRnl74LYm4X/dBpdahKT5p+nnWKO3d4Zr5Ein7N2aT7LXoG8WCzMFnFRL
         31yhPIuWKiMHKGLHnY6A945TBEBxZLl1SNH1Cxa3UiQp40d6JaA3rmcAFNPsTd97d3ak
         7ReA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VTVsraZq;
       spf=pass (google.com: domain of 3loyoywykczmfhe1ay3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3LoYOYwYKCZMFHE1Ay3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=F47Pj3mZjjvJLCcRAXl07YT/Zr3PyfsF8Hb18K8XJkk=;
        b=LVFgL0ysLX49Dxp07wgrqFd6WeDUpQKsZ/OlAtn5UdK+XvdHGqQ7eyTYAaV9RO0VAG
         hW8I0ToWFYcG8jGOvDE15aS6Fp6bOMyYqgqXSDrbn9xvJTPTbawUk+lha063ECaaJrpP
         Zab5+WweAsGiSJZBiUsEWYSdniMjBwMOHs76++NuZIW+z5IFfJUMTqqJeS9p8xGWh34y
         1vVGvKTuz93xBf2V4INarkRInn+Yz2TU5aNUCLteo6QktvksDCplvbUjfdpPQCMBb3fG
         x8pzjJAfQUrsVDgrCaNQIRCNl/FwevWPl9jLlIQZToVZulJbhl/A2dNw5ijJiCi2isrt
         0kgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=F47Pj3mZjjvJLCcRAXl07YT/Zr3PyfsF8Hb18K8XJkk=;
        b=m+keIPkXUVmlYqXGkeNxxRJUN4/UvrWXFOehqNlv2bo/9xU7wHogA/wAUHDzEsWdLl
         WKADBoUv+Wexfnuh65XS0eTIqPE6QQGB2ACDbhnQnZKOuEW528yqaUlE3+TlNVakCSM6
         mLTBK7j7ohRsXBtMvrxZPrbvsfEA90DS+ccHwqhouv12OOJJsOPV3g31ZTXIj1KYV6KS
         QYN/B2qD4YtIxMumAYBCxTM2FldFBCWdxzx1RRasjOSeDTL2o0qXqrlIAHVDirAttTPp
         eC/ZbR0zavtyPn3Jw2rSTf6/w5WzguFqZT8j+SrdXA2xFUXA/MQvgalOwrZJxyZIYl0N
         Dr+Q==
X-Gm-Message-State: ACgBeo1+PsP+5wUObjpRjBgfD04duxVDhvYd9ctHWyOXY9Y+sS4AYCrV
	kqo3tIOUwhoVYsGGd8xeEWA=
X-Google-Smtp-Source: AA6agR6+jIHRTGEo2aCsRFbEcxqffvI7yBgzwOstmEr+nxhWfqKBN83T7dV8tX409bSi88sxKMkzmA==
X-Received: by 2002:a05:6870:c1c5:b0:11c:4108:105a with SMTP id i5-20020a056870c1c500b0011c4108105amr22599oad.187.1661896239172;
        Tue, 30 Aug 2022 14:50:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:b985:0:b0:344:ef1b:a321 with SMTP id j127-20020acab985000000b00344ef1ba321ls3852299oif.9.-pod-prod-gmail;
 Tue, 30 Aug 2022 14:50:38 -0700 (PDT)
X-Received: by 2002:a05:6808:198f:b0:344:96e8:829b with SMTP id bj15-20020a056808198f00b0034496e8829bmr28290oib.222.1661896238680;
        Tue, 30 Aug 2022 14:50:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896238; cv=none;
        d=google.com; s=arc-20160816;
        b=lTUPmiMuZb1ngH/0feXsvinFWLYS7BI8ks79jvzOOQAQPY8sJTyajnUE3cl3csnUyW
         KbADvWRWcOFw+6O6nj1TbPjjr9bdL2UY8CK9o1gijfq8iPDWlIiRBZMIEHLpP6AIthg8
         W+QV+YarBCFc/drYMFMDiFoRNdDJc+TdS6tx6dnGc2Mb5lSDvBYXebSn57Szjp2yqDR9
         uBIFz5SJK/E++nJbJuzsn4ueS4CjoUXccAznvKhmbPde4w/cNBnzkzUeS9j3ugAsd4MY
         6oJCCRbKudi+nVdom9omRqxOsLZkUOQ8sSVUEtPR/tDndrjcFNMOXjBSifsArSKX4V62
         r0/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=ZStBKMvqZf5cf9FAaMePhJpKdJzTFBwr6u3tFotg8hA=;
        b=aBwxafffGzPY77OtPfkn95yoVxsXW6wjaN9I1cf8ovMH7LFzST+Y6msKg5YxD/CdUk
         ptPU+D3araeu/Isdbmn1xWBTOvQhoR9AVx/M3B/pagFb/HKEffgohrkYMU2B20RgN/dd
         aHVw67qYe1F+6NH9ZTFuwbcJmG3LAm0ZqwxN6W2JcRAKWIDuke2I9WG833448c3BUapJ
         LWkGHvFHRxPDv0xpoCaD4BwSn6LoY5DmjFVltleO81jhCh1WE/TVAAEK1P6kcO4g9lO5
         MJlDfXX6fJWWAcgr5oLuk8b8bVk9teLUgf42wmSD5KWS0MemJ9Xi/Re+RkRKjAJNkhBD
         SNKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VTVsraZq;
       spf=pass (google.com: domain of 3loyoywykczmfhe1ay3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3LoYOYwYKCZMFHE1Ay3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id o17-20020a056870969100b0010c5005e1c8si604767oaq.3.2022.08.30.14.50.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:50:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3loyoywykczmfhe1ay3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id w63-20020a25c742000000b006960ac89fedso721381ybe.18
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:50:38 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a05:6902:15cf:b0:67c:1ee7:149 with SMTP id
 l15-20020a05690215cf00b0067c1ee70149mr13333139ybu.594.1661896238275; Tue, 30
 Aug 2022 14:50:38 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:49:17 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-29-surenb@google.com>
Subject: [RFC PATCH 28/30] Improved symbolic error names
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com, axboe@kernel.dk, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	changbin.du@intel.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-mm@kvack.org, 
	iommu@lists.linux.dev, kasan-dev@googlegroups.com, io-uring@vger.kernel.org, 
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org, 
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=VTVsraZq;       spf=pass
 (google.com: domain of 3loyoywykczmfhe1ay3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3LoYOYwYKCZMFHE1Ay3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

From: Kent Overstreet <kent.overstreet@linux.dev>

This patch adds per-error-site error codes, with error strings that
include their file and line number.

To use, change code that returns an error, e.g.
    return -ENOMEM;
to
    return -ERR(ENOMEM);

Then, errname() will return a string that includes the file and line
number of the ERR() call, for example
    printk("Got error %s!\n", errname(err));
will result in
    Got error ENOMEM at foo.c:1234

To convert back to the original error code (before returning it to
outside code that does not understand dynamic error codes), use
    return error_class(err);

To test if an error is of some type, replace
    if (err == -ENOMEM)
with
    if (error_matches(err, ENOMEM))

Implementation notes:

Error codes are allocated dynamically on module load and deallocated on
module unload. On memory allocation failure (i.e. the data structures
for indexing error strings and error parents), ERR() will fall back to
returning the error code that it was passed.

MAX_ERRNO has been raised from 4096 to 1 million, which should be
sufficient given the number of lines of code and the fraction that throw
errors in the kernel codebase.

This has implications for ERR_PTR(), since the range of the address
space reserved for errors is unavailable for other purposes. Since
ERR_PTR() ptrs are at the top of the address space there should not be
any major difficulties.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 include/asm-generic/codetag.lds.h |   3 +-
 include/linux/err.h               |   2 +-
 include/linux/errname.h           |  50 +++++++++++++++
 lib/errname.c                     | 103 ++++++++++++++++++++++++++++++
 4 files changed, 156 insertions(+), 2 deletions(-)

diff --git a/include/asm-generic/codetag.lds.h b/include/asm-generic/codetag.lds.h
index d799f4aced82..b087cf1874a9 100644
--- a/include/asm-generic/codetag.lds.h
+++ b/include/asm-generic/codetag.lds.h
@@ -11,6 +11,7 @@
 #define CODETAG_SECTIONS()		\
 	SECTION_WITH_BOUNDARIES(alloc_tags)		\
 	SECTION_WITH_BOUNDARIES(dynamic_fault_tags)	\
-	SECTION_WITH_BOUNDARIES(time_stats_tags)
+	SECTION_WITH_BOUNDARIES(time_stats_tags)	\
+	SECTION_WITH_BOUNDARIES(error_code_tags)
 
 #endif /* __ASM_GENERIC_CODETAG_LDS_H */
diff --git a/include/linux/err.h b/include/linux/err.h
index a139c64aef2a..1d8d6c46ab9c 100644
--- a/include/linux/err.h
+++ b/include/linux/err.h
@@ -15,7 +15,7 @@
  * This should be a per-architecture thing, to allow different
  * error and pointer decisions.
  */
-#define MAX_ERRNO	4095
+#define MAX_ERRNO	((1 << 20) - 1)
 
 #ifndef __ASSEMBLY__
 
diff --git a/include/linux/errname.h b/include/linux/errname.h
index e8576ad90cb7..dd39fe7120bb 100644
--- a/include/linux/errname.h
+++ b/include/linux/errname.h
@@ -5,12 +5,62 @@
 #include <linux/stddef.h>
 
 #ifdef CONFIG_SYMBOLIC_ERRNAME
+
 const char *errname(int err);
+
+#include <linux/codetag.h>
+
+struct codetag_error_code {
+	const char		*str;
+	int			err;
+};
+
+/**
+ * ERR - return an error code that records the error site
+ *
+ * E.g., instead of
+ *   return -ENOMEM;
+ * Use
+ *   return -ERR(ENOMEM);
+ *
+ * Then, when a caller prints out the error with errname(), the error string
+ * will include the file and line number.
+ */
+#define ERR(_err)							\
+({									\
+	static struct codetag_error_code				\
+	__used								\
+	__section("error_code_tags")					\
+	__aligned(8) e = {						\
+		.str	= #_err " at " __FILE__ ":" __stringify(__LINE__),\
+		.err	= _err,						\
+	};								\
+									\
+	e.err;								\
+})
+
+int error_class(int err);
+bool error_matches(int err, int class);
+
 #else
+
+static inline int error_class(int err)
+{
+	return err;
+}
+
+static inline bool error_matches(int err, int class)
+{
+	return err == class;
+}
+
+#define ERR(_err)	_err
+
 static inline const char *errname(int err)
 {
 	return NULL;
 }
+
 #endif
 
 #endif /* _LINUX_ERRNAME_H */
diff --git a/lib/errname.c b/lib/errname.c
index 05cbf731545f..2db8f5301ba0 100644
--- a/lib/errname.c
+++ b/lib/errname.c
@@ -1,9 +1,20 @@
 // SPDX-License-Identifier: GPL-2.0
 #include <linux/build_bug.h>
+#include <linux/codetag.h>
 #include <linux/errno.h>
 #include <linux/errname.h>
+#include <linux/idr.h>
 #include <linux/kernel.h>
 #include <linux/math.h>
+#include <linux/module.h>
+#include <linux/xarray.h>
+
+#define DYNAMIC_ERRCODE_START	4096
+
+static DEFINE_IDR(dynamic_error_strings);
+static DEFINE_XARRAY(error_classes);
+
+static struct codetag_type *cttype;
 
 /*
  * Ensure these tables do not accidentally become gigantic if some
@@ -200,6 +211,9 @@ static const char *names_512[] = {
 
 static const char *__errname(unsigned err)
 {
+	if (err >= DYNAMIC_ERRCODE_START)
+		return idr_find(&dynamic_error_strings, err);
+
 	if (err < ARRAY_SIZE(names_0))
 		return names_0[err];
 	if (err >= 512 && err - 512 < ARRAY_SIZE(names_512))
@@ -222,3 +236,92 @@ const char *errname(int err)
 
 	return err > 0 ? name + 1 : name;
 }
+
+/**
+ * error_class - return standard/parent error (of a dynamic error code)
+ *
+ * When using dynamic error codes returned by ERR(), error_class() will return
+ * the original errorcode that was passed to ERR().
+ */
+int error_class(int err)
+{
+	int class = abs(err);
+
+	if (class > DYNAMIC_ERRCODE_START)
+		class = (unsigned long) xa_load(&error_classes,
+					      class - DYNAMIC_ERRCODE_START);
+	if (err < 0)
+		class = -class;
+	return class;
+}
+EXPORT_SYMBOL(error_class);
+
+/**
+ * error_matches - test if error is of some type
+ *
+ * When using dynamic error codes, instead of checking for errors with e.g.
+ *   if (err == -ENOMEM)
+ * Instead use
+ *   if (error_matches(err, ENOMEM))
+ */
+bool error_matches(int err, int class)
+{
+	err	= abs(err);
+	class	= abs(class);
+
+	BUG_ON(err	>= MAX_ERRNO);
+	BUG_ON(class	>= MAX_ERRNO);
+
+	if (err != class)
+		err = error_class(err);
+
+	return err == class;
+}
+EXPORT_SYMBOL(error_matches);
+
+static void errcode_module_load(struct codetag_type *cttype, struct codetag_module *mod)
+{
+	struct codetag_error_code *i, *start = (void *) mod->range.start;
+	struct codetag_error_code *end = (void *) mod->range.stop;
+
+	for (i = start; i != end; i++) {
+		int err = idr_alloc(&dynamic_error_strings,
+				    (char *) i->str,
+				    DYNAMIC_ERRCODE_START,
+				    MAX_ERRNO,
+				    GFP_KERNEL);
+		if (err < 0)
+			continue;
+
+		xa_store(&error_classes,
+			 err - DYNAMIC_ERRCODE_START,
+			 (void *)(unsigned long) abs(i->err),
+			 GFP_KERNEL);
+
+		i->err = i->err < 0 ? -err : err;
+	}
+}
+
+static void errcode_module_unload(struct codetag_type *cttype, struct codetag_module *mod)
+{
+	struct codetag_error_code *i, *start = (void *) mod->range.start;
+	struct codetag_error_code *end = (void *) mod->range.stop;
+
+	for (i = start; i != end; i++)
+		idr_remove(&dynamic_error_strings, abs(i->err));
+}
+
+static int __init errname_init(void)
+{
+	const struct codetag_type_desc desc = {
+		.section	= "error_code_tags",
+		.tag_size	= sizeof(struct codetag_error_code),
+		.module_load	= errcode_module_load,
+		.module_unload	= errcode_module_unload,
+	};
+
+	cttype = codetag_register_type(&desc);
+
+	return PTR_ERR_OR_ZERO(cttype);
+}
+module_init(errname_init);
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-29-surenb%40google.com.
