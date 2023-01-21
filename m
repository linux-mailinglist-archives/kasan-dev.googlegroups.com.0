Return-Path: <kasan-dev+bncBDUNBGN3R4KRBCFAV2PAMGQEN5FYZVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 16B526764DA
	for <lists+kasan-dev@lfdr.de>; Sat, 21 Jan 2023 08:11:06 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id k2-20020a17090ac50200b0022bb229a9c7sf1878475pjt.0
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 23:11:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674285064; cv=pass;
        d=google.com; s=arc-20160816;
        b=wvfEWHG4TzOwV6flid8fA1F+NbWqcwWGjvOtiY+uQxNeyd0j2VLsJ9MUNXuvxeORry
         uF5nv/o2Qp11KGS5gOq9x0COmA/I+uF6c4iZm9O+m6bUOmsojVdlZU2pfkXYkG5KBihs
         M+WrfMtQa17l2gpii2uGLIYhVFbDYanh4U3a7a3erMl3HFeo3DN2++KN8Hz6ctufODcV
         1NVZeSi3fbkD7B9Ox5NLH7EekHfPucz5ymBSuBuRXZCUEK3pnGnxmLRpVpf0he9vTZ++
         kU7deTwCKy7F8uU5Cvj83jpjUAbO0/OKqrq0hZO3t3kBwQYOFi7ci59I/BzX7gqI0nt2
         RtEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=GaN4O/lEJXw3jlRfS+7gHEHQPZhS3B0EWc57nuTry1g=;
        b=efK6exIKrRsM3Rp9L57ygu/7DXXqS6iAn3fguPRkG9SDzviN0G8ROMU9WF6erkdiGv
         Io3XnZ4zojkuY7snTbuuzmP8Lqfz4dZB0bKUvaubA67iW5/P8XcKd4Z2rcazcubzE0ss
         qEyjJFpODz5sB46U7wFZFO67vxJXsCysmtbEa9oliQqruhVN7s3lKl33pPkBs/i/Vq0O
         MMFo/nxFLa/zEhSNEfRwuO/TT5igkK2lCRhf/ndQasxQSEdjmmgzlQa40Iqyg4CKOfCv
         YPXwVmOg+yUQvG+RHQs+QsYpPaKmAw6L3vIA2rxronBL7FlAMr4XPOlxg/aIvOVTKytW
         eCRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b="ovyG/4CM";
       spf=none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GaN4O/lEJXw3jlRfS+7gHEHQPZhS3B0EWc57nuTry1g=;
        b=f+aykON7Wwzv6mkDsOwoh1q/XOo6pxOVIkKiVKGaqvy0wxMuSFPg32QBYD8mbmy8Dd
         HKVUib6eDiC4sM2Sn/IACREKT6G5CT1CeEZ60gISYH6L0NCInea1/FdHIZxq7UrHXRHY
         TFAzO5pQsOTCIxDeES1jbZvOMFspL3Mj6bnOh/2UkfRRMqn14ZMTOr137zGTelQyzT4O
         nhIMTxwvQj1c2oXxeXhQc8u548bbj4QF6LI3Dgr+srPlIMP+qLS5ZMQuFlLTmLrFit8V
         JrLXlNh4RJQE4xJvhO57TMRy7iiJ6V7n3T7iTU/0uUV5B+snhoFC1nrXxsKdSaY4VGxm
         /2Ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GaN4O/lEJXw3jlRfS+7gHEHQPZhS3B0EWc57nuTry1g=;
        b=IVKZbscGgro+U/YH5esVsYFFEy5Sz923Pb8h5wZ7PnB6Ef8SRr/LppA/q4nbfURYt+
         NzsOh4iIY6oV882fhshH6IzAheJUAJjcwgX/tY0fQ1PXFPMdPMD+ktGrvFcrCHVwnuvd
         8sA9itFrcuyCp6DQPnontiRN/B4cibBMqnnCM3BXJgG0qjqIMuaL7gvPfk0RONJOVrge
         GeecCInROdrISFS3W3KzXEN+W2AFawdrM18q0MXYSSRAbhgFTm1FUu9skukYtfApQMUV
         kYlrk/aXO0EEFcXHYhGC61HTRzMxv20KLricncwljzyLgId0VhTyxD6zmFvcGtOdllSO
         PpPA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kr0cjmcOf4fenO9772XjtQj9nizUlF46ULWXDdZo0z7SZ53599r
	xKOssEy5/UbatVxmV+qypGM=
X-Google-Smtp-Source: AMrXdXu1tELgA94kV2n64Jvy3j6OUj4LilZP+iXmv2CILK+wNpXhC8mH9uyyvp5eF/9VA4WYC1NKrw==
X-Received: by 2002:a17:90b:4fcf:b0:219:de90:bdc4 with SMTP id qa15-20020a17090b4fcf00b00219de90bdc4mr1946817pjb.18.1674285064285;
        Fri, 20 Jan 2023 23:11:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8a81:b0:229:24a8:b4c9 with SMTP id
 x1-20020a17090a8a8100b0022924a8b4c9ls7511550pjn.1.-pod-control-gmail; Fri, 20
 Jan 2023 23:11:03 -0800 (PST)
X-Received: by 2002:a17:90a:67c2:b0:226:c364:2d1d with SMTP id g2-20020a17090a67c200b00226c3642d1dmr18565379pjm.41.1674285063391;
        Fri, 20 Jan 2023 23:11:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674285063; cv=none;
        d=google.com; s=arc-20160816;
        b=WEZA3ui+bUZ++lq7veVjwyPDaP94IQ5C6v/b+W+ypeZq96rE9HbJbA9eCw/xuTc5vw
         Zk9MNLUuMPpd+Ue45B/fwedupBlMfElMwLocKiK5b2ckkmiMf/WwkMKVRPdESX00Ll/3
         cbDM39/dlrfAVubFExf7IL5NORbn4zk5r/BgvgleK6ospANlNuXFZ6ybn4vkhTaTUEX5
         YNK68oskGHUgsqVq+X8yEu9CfxE4ZRljTNA//QMAItTYuVmu9wpxVgXezmXukYBqWW85
         gf8o0L2WYtpreievbB5Vz6WUyd2zvSep7XVS4FnjjQkcpE4W6NcnW6UN2q1qzbhpyoXx
         /Wiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5+yIJbbq41O5DQj1Bid/P+oY4/gY3/DwnrWQQ9o5sRM=;
        b=teR/hBGrt6XFDSC71+/kQCdkz8y0ih+m/ejqTA3AuIXCKx4GXVd5/zic3PUkqDVH2v
         INdIYyYeK/2RSguQ2h2TFoJBTboYi2mUJ9NzkL2ipNDsz5dtdK1wOT+XP5QilkHyMv9Z
         NWTKn4HxeXG8pXyiB2PJAhiQGMMKhi+eSL1rvJLIu5kymVdlgj/3VwXvnsiVJtJbfye2
         5pCPgZduXfDdbFlQ9bRo+Yh6xH6V9+fxq3bxRodxTTridnM5MGmydrLs5Itj0LiTs3Sq
         ZSpV/h/OSNovyVoSP7mNqnb3mmTXYuXUwTS85GG99H0Prp+3VQmKsrxSCg2Wz8Wv7y4D
         7W1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b="ovyG/4CM";
       spf=none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id g4-20020a17090a9b8400b0022bad3e05edsi419532pjp.0.2023.01.20.23.11.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Jan 2023 23:11:03 -0800 (PST)
Received-SPF: none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [2001:4bb8:19a:2039:6754:cc81:9ace:36fc] (helo=localhost)
	by bombadil.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pJ81j-00DTmf-0Z; Sat, 21 Jan 2023 07:10:59 +0000
From: Christoph Hellwig <hch@lst.de>
To: Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: [PATCH 02/10] mm: remove __vfree
Date: Sat, 21 Jan 2023 08:10:43 +0100
Message-Id: <20230121071051.1143058-3-hch@lst.de>
X-Mailer: git-send-email 2.39.0
In-Reply-To: <20230121071051.1143058-1-hch@lst.de>
References: <20230121071051.1143058-1-hch@lst.de>
MIME-Version: 1.0
X-SRS-Rewrite: SMTP reverse-path rewritten from <hch@infradead.org> by bombadil.infradead.org. See http://www.infradead.org/rpr.html
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b="ovyG/4CM";
       spf=none (google.com: bombadil.srs.infradead.org does not designate
 permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
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

__vfree is a subset of vfree that just skips a few checks, and which is
only used by vfree and an error cleanup path.  Fold __vfree into vfree
and switch the only other caller to call vfree() instead.

Signed-off-by: Christoph Hellwig <hch@lst.de>
Reviewed-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
---
 mm/vmalloc.c | 18 ++++++------------
 1 file changed, 6 insertions(+), 12 deletions(-)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 6957d15d526e46..b989828b45109a 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2801,14 +2801,6 @@ void vfree_atomic(const void *addr)
 	__vfree_deferred(addr);
 }
 
-static void __vfree(const void *addr)
-{
-	if (unlikely(in_interrupt()))
-		__vfree_deferred(addr);
-	else
-		__vunmap(addr, 1);
-}
-
 /**
  * vfree - Release memory allocated by vmalloc()
  * @addr:  Memory base address
@@ -2836,8 +2828,10 @@ void vfree(const void *addr)
 
 	if (!addr)
 		return;
-
-	__vfree(addr);
+	if (unlikely(in_interrupt()))
+		__vfree_deferred(addr);
+	else
+		__vunmap(addr, 1);
 }
 EXPORT_SYMBOL(vfree);
 
@@ -3104,7 +3098,7 @@ static void *__vmalloc_area_node(struct vm_struct *area, gfp_t gfp_mask,
 
 	/*
 	 * If not enough pages were obtained to accomplish an
-	 * allocation request, free them via __vfree() if any.
+	 * allocation request, free them via vfree() if any.
 	 */
 	if (area->nr_pages != nr_small_pages) {
 		warn_alloc(gfp_mask, NULL,
@@ -3144,7 +3138,7 @@ static void *__vmalloc_area_node(struct vm_struct *area, gfp_t gfp_mask,
 	return area->addr;
 
 fail:
-	__vfree(area->addr);
+	vfree(area->addr);
 	return NULL;
 }
 
-- 
2.39.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230121071051.1143058-3-hch%40lst.de.
