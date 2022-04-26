Return-Path: <kasan-dev+bncBCCMH5WKTMGRBO6DUCJQMGQEDVXBM6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id CBBD0510403
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:45:47 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id n4-20020a2ebd04000000b0024b618dec69sf4817183ljq.18
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:45:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991547; cv=pass;
        d=google.com; s=arc-20160816;
        b=WOMLAEc23qrEwuFwmIdPmh7e3qXe+VdOUBka68VhC4kFDygvhaTLuYkKbbHFKX/9cH
         pIbhcHfrbZCZTX/rDAjhAN4UJNHFw4gxkiebuTHRFKbYTefpxsw3XWeHtEbaH5i51KEj
         jw8a0UP/iXb0t1UuNB3cBQQ1TsCXeDghJqCPjG1UQcdj6fQkgRF3FOppkhfY7tXm8l3U
         jDJ2rFJ8VE7nITjjy6b0s19aiROY0omvBsi/F854rN2YH39Ie88XMX5hSBvLsO6SG5oq
         Aybd9MfzFB8iVpHygFJXGbTXS+p3fJHyRJ/xjZoNypTrWXZMGZ+tTMUxwPRt8Vi72T0z
         Ejrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=e09wQDm6Scd5b/4myVMIB0r2aj5CDmcn/Oj81I9CB2c=;
        b=TX/vRckL8pMhRDYh1MchlnCJTDSfdAX8Wj5sl17Tj1CaczfyIfKZcV1zxfwuJu2y5h
         liqkuc2jygJpk39aqsblSKI1aYugpRK4GWE+z7UD+LYlilBgUfYhyOG5ztBum5/pu2k9
         4Tl8oVqbXuzHRvfZcQB42UvWjsTXpQJHyd9RUGNgEOeki9j65HvffCJCg2XwglXLwnD9
         k31Dw8brvh+lzDelp+aXV38nLLFzcGPHuRGz85ar8KlSY0OhExb2iVUA+jv2pM1DN2/N
         /QwUca2E6fsHFLRkLhT7SM2WVnKBuSjEuu992PzurfeijvVOo+mME+XH5HcMyU38ERK1
         GPRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UW3AswRa;
       spf=pass (google.com: domain of 3uifoygykcbcdifabodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--glider.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3uiFoYgYKCbcdifabodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e09wQDm6Scd5b/4myVMIB0r2aj5CDmcn/Oj81I9CB2c=;
        b=lHplvhUbxCit4R7yljTopD4UNdX87rqeZ4nGrEXG4bnCnx0/G/EdMZEEy8Ww8wl+fr
         PwsIBreL0Q5PnMIJrIRaLljGZzlWEJKaD8ohe+jBU96568QnPqkyr1ujRZ0peNTpURDg
         pqQClCqAG44Gy4vZ+aVHMyO6Ob0V8sox4C6ntnZnifxHa1EtUpI5Lv3l+f3MXMGvJjJM
         QcC7p0iJB7KwZ9AvCmMPfZ7wu5oNHygDcz+m0Dm07Dg2/52eRah/mN1rdhdVUobAjgit
         O9lMjHPkthyL+5KpPbZ/A4koKpzVPCj83B8F+NFr3wrGy7tikH8HYZA3rYmyA5UjZ4Ee
         pHag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e09wQDm6Scd5b/4myVMIB0r2aj5CDmcn/Oj81I9CB2c=;
        b=i2a4NZLQ/k61ykMM0M7FXtVPdNNcHSJ6TArI38MqPfAp/4Ql9lEopa0UlkQv2j/3Uw
         gFmREAPcEvXN4Wcj2h+/93uzvC9rapuHqUSn9owSAlxK8Th9zd/q/XuXAN6OGjLLrysf
         2mLBeqJExSou6E+iEEUc+sP6tlZ+pjwLGUEMBgzjdRKVymlCoEKnTDPxbSqRNy9LLKfD
         OZBZdovoTlmqgv6ILbKCWzmuf5LVZnb9G8goxRJw/OPPO94jRXAVG8J7CKptUFFgtDIa
         MiGOBvBifXExFIUIU/UV6ep2knq2UQiTKE7tFGI1sbLQ4btUeAl7pQ4YUBnplstJ+fcT
         8b5Q==
X-Gm-Message-State: AOAM533bNB0Y9XWsjgUnz2QrRiebyunPHPVwjj+u+cGwi30iNePMPvjV
	RdbOYtVq79CmqgOeEKYnzss=
X-Google-Smtp-Source: ABdhPJw/lEB7RJ0aYCnua0+FypISjltI7QycThMkDfsISeE3DS0ZUZWwEBOFE/+lmDR28kn8VU13NA==
X-Received: by 2002:a2e:a7c5:0:b0:24e:ebdf:fc7b with SMTP id x5-20020a2ea7c5000000b0024eebdffc7bmr15291580ljp.263.1650991547433;
        Tue, 26 Apr 2022 09:45:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a54f:0:b0:24f:18c1:d26c with SMTP id e15-20020a2ea54f000000b0024f18c1d26cls757257ljn.5.gmail;
 Tue, 26 Apr 2022 09:45:46 -0700 (PDT)
X-Received: by 2002:a2e:9696:0:b0:24f:22cf:e707 with SMTP id q22-20020a2e9696000000b0024f22cfe707mr1877278lji.15.1650991546273;
        Tue, 26 Apr 2022 09:45:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991546; cv=none;
        d=google.com; s=arc-20160816;
        b=cWN8kw6WkDxZE3CCNj4wDnPS9A7fDesxG9r9yRyO8J8C6BA0dKJ00m9g48Ql6bjpQU
         X29ByWcS/LwZGcHopGqjPscOQBi2goWDO+2FCUkr916YfAnorPlxX0CVKK0yxgsdX7w4
         zX5vMRFUEa1CwoK2xAzrdp5n/WnmY8qDyc3qabAsiQFR+El8a9r4RGWY0I2KLTVohR0R
         ic0TBVO1oADEiZDGd6MzDX/gZaKWCsHSnC6W7jIPEYtyi/8muPHx5iAZtwZPtgOk239Y
         lWuHrJDFB3VLEg4xjcF01MYZngda3GQyz27eBme0o9UA7uN9rATKw487YZa+KOzzjQ8n
         DltA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=GtiQESdTzDECedHCE4txXpUZH3/tDa3FQ07WXH5OYuQ=;
        b=CTSMYG5iGusEVJRn7d61ne2svDhFJ0rjF6KyGE+d9RGgQJ+JE/TYxzc+t1GR4tGx9b
         e/G+zII6WcjTcqV7X/23LvIiWyKtpkcvMEJrwuep7RqudhI6BJOpm/P5BKNT980r8Lvr
         ZOnkI1B3pzYsmmfecp+3/BXp/nhiACjVVuItqF2nccrdQyD0loQY8TArwTIKmYScSSmf
         HbzvEN2jx5P0OWX3cDlIdcjHTebpdTxTpwQyVqGUvVQcQQ2NWdWwXiVLB3wz6m0rqQBu
         NATFpi/zNqB+Qwu+N09U2PtiKIxXD2U+pWGP0cxxAzwJnxhnXrukXqe+HrSUzcJp/kx2
         fmnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UW3AswRa;
       spf=pass (google.com: domain of 3uifoygykcbcdifabodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--glider.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3uiFoYgYKCbcdifabodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x149.google.com (mail-lf1-x149.google.com. [2a00:1450:4864:20::149])
        by gmr-mx.google.com with ESMTPS id e9-20020a2e8189000000b0024eee872899si542776ljg.0.2022.04.26.09.45.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:45:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3uifoygykcbcdifabodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--glider.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) client-ip=2a00:1450:4864:20::149;
Received: by mail-lf1-x149.google.com with SMTP id f19-20020a0565123b1300b004720c485b64so2412093lfv.5
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:45:46 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a05:6512:20c6:b0:471:fdba:1480 with SMTP id
 u6-20020a05651220c600b00471fdba1480mr10896844lfr.425.1650991546042; Tue, 26
 Apr 2022 09:45:46 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:43:02 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-34-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 33/46] kmsan: block: skip bio block merging logic for KMSAN
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org, 
	Eric Biggers <ebiggers@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=UW3AswRa;       spf=pass
 (google.com: domain of 3uifoygykcbcdifabodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3uiFoYgYKCbcdifabodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--glider.bounces.google.com;
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

KMSAN doesn't allow treating adjacent memory pages as such, if they were
allocated by different alloc_pages() calls.
The block layer however does so: adjacent pages end up being used
together. To prevent this, make page_is_mergeable() return false under
KMSAN.

Suggested-by: Eric Biggers <ebiggers@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>

---

Link: https://linux-review.googlesource.com/id/Ie29cc2464c70032347c32ab2a22e1e7a0b37b905
---
 block/bio.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/block/bio.c b/block/bio.c
index 4259125e16ab2..db56090c00bae 100644
--- a/block/bio.c
+++ b/block/bio.c
@@ -836,6 +836,8 @@ static inline bool page_is_mergeable(const struct bio_vec *bv,
 		return false;
 
 	*same_page = ((vec_end_addr & PAGE_MASK) == page_addr);
+	if (!*same_page && IS_ENABLED(CONFIG_KMSAN))
+		return false;
 	if (*same_page)
 		return true;
 	return (bv->bv_page + bv_end / PAGE_SIZE) == (page + off / PAGE_SIZE);
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-34-glider%40google.com.
