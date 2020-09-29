Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5PRZT5QKGQEQSMUE4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 7542B27CF64
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 15:39:02 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id r128sf3712477pfr.8
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 06:39:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601386741; cv=pass;
        d=google.com; s=arc-20160816;
        b=pC1RLIDx9s86UdV5+L8PBgtwy+7I4LxPtcI4KjAGv+MPBttPw1Y9XPYetfTxo7SZ/c
         iQxtboBg+YbaNCUd0TEgRnuohGV4zi7mITUKnr/Ocw0cwmeoJ4dEA4SvucgOvymVJnFO
         eA2eNe2Rc8soRTcksbXhcDGyeGzcmZHdEHgHjI1HuO0CIlwR8W+0V9sfVfTvlVnI8dK7
         +luIGmXM63jF4DZ+5eWWNFrejjoZZBmbVo6WTAjX5B+crwXew6Kdr/jnaos6wBhwMfFD
         WiW2gsgrBgokuIoH+nW1h8JStFm42QHkjvAhCK5FEJa64x9FjSsZVlMHnCyeIKdAc18A
         nnMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=b2Qrmr/QS7kXfwmvNVK1oKGC+nT2cLk92fqdaHt21aM=;
        b=Hkguz/LlywCMN8StDu2HHOydDNd3l6dqoo5y+FggTq0sC0UeSFs5/cI1YQlDa2eXgw
         qp/XWOHRvOxoK8f9tAkOzvRXbIPRVwifFtR21H1IBZpCheUA8r2NB+++fgkfU1Z2+Vct
         gOZZhijODz3CqLYTFAcglSWeSM5b9hMfBSRZPUQLH6q477BbiAAGUvt7U0z6p0CxBdLH
         hqW1t27slz2+k1z05A5J/5YpkSYM2jqSmcL/2yWgycq+k3/xxllLbRk6kewJdfNsY+x+
         YVkgrFfOHfMXM6/Pb0YtNalEW6ZEUphQctsel9pDgbvgjghQmP2ieRj+dPpw3QISxVNv
         QAqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=B8oKuahj;
       spf=pass (google.com: domain of 38zhzxwukctqubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=38zhzXwUKCTQUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=b2Qrmr/QS7kXfwmvNVK1oKGC+nT2cLk92fqdaHt21aM=;
        b=bE/4qeyAGE5tvjfwQcQxh87lpSojGkWJ+mmEuHJ86QQUrTJ3qbjCo6je4LKrxokwca
         Ymim2xUidrLE4N8ktzOzy7K/AYwxQzbjQT2DMtw6nEXyAkGc0QBn0tMdF40pyy0aJMer
         f42hVKSDl9k2VXK0pKnTCZLKNTXURBHP8B8Yi9yW2p5cSWf6mjVAEBoquBQEUtMjD2AJ
         g+Wz4EEeUn0IRPcBNKYBvq9GBIthqMJ74SkOdZKi+AbpdqcmJQqW9zDmkfeWPET1qN5a
         /JoBTR7K3XzQDGGsrcX+h64bX44wS0BZdFqT/zO0C3zPLfRKX3MgIrOxI56+zRNKgE/V
         PP4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b2Qrmr/QS7kXfwmvNVK1oKGC+nT2cLk92fqdaHt21aM=;
        b=HOGwhzn7gZd0dhSQO5rV4tiKD9KaSPr2rnSD5P8mB/oULGRODELOSv32uvI9tnyKGy
         h9nG3re8nUBITNLve50Uah/iNhGMndxSlCak2PpEqQ6DfGNcm643LGSmCQdo1Xd+HAUL
         z2jE9gsJXUcVNm5X529GIg8Gf3faVEwuYOZlVKmwl4vrYYwO/ONyq2h1OTIYK3tr2DPU
         rOX+39fDXqN/fMXDzmEmd8gM48u8myKOQXYYpcnZpxDol+mEwmmbGbWpislAK7qwd8Kb
         RztrhHMRYSBxBOVTfz/9bh/6PCe2Tm6PCAaXD/gX8M9PM6+6dRtGDmMqchk12nsQkwJj
         4hmw==
X-Gm-Message-State: AOAM533E5UuYRbJgQ8mkHPLHo9Ifto/jHPtByaX6jNx88mVC+eXZ0H+B
	ojU6QIPATyw3q6gAVHjSOLM=
X-Google-Smtp-Source: ABdhPJxw/dcsZVnrKtbW6JWDyCSurczoxBq/PekJqROIxx0ZnLxM9zI6B6xuRqAilCPE4S7YhZFPyA==
X-Received: by 2002:a17:902:ee0c:b029:d1:8c50:aa63 with SMTP id z12-20020a170902ee0cb02900d18c50aa63mr4651400plb.21.1601386741170;
        Tue, 29 Sep 2020 06:39:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:c050:: with SMTP id z16ls3175480pgi.9.gmail; Tue, 29 Sep
 2020 06:39:00 -0700 (PDT)
X-Received: by 2002:aa7:9635:0:b029:142:2501:3980 with SMTP id r21-20020aa796350000b029014225013980mr4161469pfg.69.1601386740544;
        Tue, 29 Sep 2020 06:39:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601386740; cv=none;
        d=google.com; s=arc-20160816;
        b=OfoozxfDH1OUJoPN0Uo14Y7ZKcxzVaWXLPdHK4eS10hJ2ew9eL9Az87/m3sqnIfo4Y
         JqQxbE7JPJBY98VUMgz7Vh4MLK/QM9gHx5c6UBEjh3ksvsr4LyaUfzTixKPfPpR53VNH
         0WSPd98r6/OMXqzDWcinQT3f8KH6iBxNzzFfpzs6w9xhsRxELDwVrhTXiEt+cqtxGvwd
         iDTnEPk5BCRBCHYBbQfbFnC/PcSgx6QaTVe4IIS1Pi7ANQysihTNYzWtpcfbZCl0D+mo
         OdoDGRdy0HsuvQx4GoSZUprkDvhU5WyHGgNywqnoCOATEqMdUQZi3KPqvfXIJXMnzDQn
         5/Dg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=3tnm6vmpSMHKvgeLXX0r5hzQnU0w3hMCi/2IZuY8XC4=;
        b=xdYnRpOC9vnEcJx02CSVX0Jrk3ZpECniW9rRoaLXe26KonU/Enw0RHn8BivLkQ6cRc
         UimxsBKqg5zkTXHOKdwxMVH1LExnmsfbMFqPJD/Jc8F4hwiQKS4MwWe4XKNR4l/kfLhS
         ZhvW/V05q9DbQv79uj4ZTdoIJTC6LcNeThYL4uBxbiG8NYLD705+D/KaAfA/7z1BdTFb
         OgvdkKOMr9fq5aVEzHrHJU8mESGW2s3UIeL5fzhtk+Uo4BQFFyXZfQ/gBfQcQvBjpWr1
         sHJAvxkEwNtVw+/xVEDGYKmJG/M7ucaJwAwb9XkTjr94FTY5bdY0BJAV9ng/M/aQc9/h
         /FQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=B8oKuahj;
       spf=pass (google.com: domain of 38zhzxwukctqubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=38zhzXwUKCTQUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id lj12si648531pjb.0.2020.09.29.06.39.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 06:39:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38zhzxwukctqubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id 205so2693437qkd.2
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 06:39:00 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a0c:fe8b:: with SMTP id d11mr4599326qvs.48.1601386739523;
 Tue, 29 Sep 2020 06:38:59 -0700 (PDT)
Date: Tue, 29 Sep 2020 15:38:10 +0200
In-Reply-To: <20200929133814.2834621-1-elver@google.com>
Message-Id: <20200929133814.2834621-8-elver@google.com>
Mime-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 07/11] kfence, kmemleak: make KFENCE compatible with KMEMLEAK
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
 header.i=@google.com header.s=20161025 header.b=B8oKuahj;       spf=pass
 (google.com: domain of 38zhzxwukctqubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=38zhzXwUKCTQUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
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

Add compatibility with KMEMLEAK, by making KMEMLEAK aware of the KFENCE
memory pool. This allows building debug kernels with both enabled, which
also helped in debugging KFENCE.

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Co-developed-by: Marco Elver <elver@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
v2:
* Rework using delete_object_part() [suggested by Catalin Marinas].
---
 mm/kmemleak.c | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/mm/kmemleak.c b/mm/kmemleak.c
index 5e252d91eb14..feff16068e8e 100644
--- a/mm/kmemleak.c
+++ b/mm/kmemleak.c
@@ -97,6 +97,7 @@
 #include <linux/atomic.h>
 
 #include <linux/kasan.h>
+#include <linux/kfence.h>
 #include <linux/kmemleak.h>
 #include <linux/memory_hotplug.h>
 
@@ -1948,6 +1949,11 @@ void __init kmemleak_init(void)
 		      KMEMLEAK_GREY, GFP_ATOMIC);
 	create_object((unsigned long)__bss_start, __bss_stop - __bss_start,
 		      KMEMLEAK_GREY, GFP_ATOMIC);
+#if defined(CONFIG_KFENCE) && defined(CONFIG_HAVE_ARCH_KFENCE_STATIC_POOL)
+	/* KFENCE objects are located in .bss, which may confuse kmemleak. Skip them. */
+	delete_object_part((unsigned long)__kfence_pool, KFENCE_POOL_SIZE);
+#endif
+
 	/* only register .data..ro_after_init if not within .data */
 	if (&__start_ro_after_init < &_sdata || &__end_ro_after_init > &_edata)
 		create_object((unsigned long)__start_ro_after_init,
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200929133814.2834621-8-elver%40google.com.
