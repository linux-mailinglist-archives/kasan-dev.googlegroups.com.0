Return-Path: <kasan-dev+bncBCM2HQW3QYHRBIXL3GFAMGQEK3INUXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F61A41E60F
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Oct 2021 04:42:43 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id o4-20020a056512230400b003fc39bb96c7sf7615562lfu.8
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Sep 2021 19:42:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633056163; cv=pass;
        d=google.com; s=arc-20160816;
        b=PLCIh56ey0GU08IWe3NYFpCq7jbqARZt5dZREJgSFv06cbwuwZt933zboq3nJt7Byo
         usIfuz4/0m6y0fF/3yZ2oxhP4i1W38bbhyMpFOy0vOQWQHZcrJmH0Y18y15z5syAJ4XI
         HAFtRzGjojqNCXV+ODHS/8IA1PPsjPtQ5kMNAzLMrrYWbAD2xsvMBUh0hRREkcqED49e
         S7GaDsbiJFi0UOVW7rSK37euSMn4Fk43MEbj4ZPaiPGynIALpIzYRpzwqahd+fnQyAj7
         7x6KNUlPoXonNNYFwHyodp6f9aIsI+DSg+hMIpWGpC9pSHWofP9u2gnuU4MDUyQTkglS
         f0Kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=rbtQC/n+584so2jXp4UKuyi6ABjycgpER/m7Z+Gms8U=;
        b=sqX+zPboEU8KCMQJd2mdaTEOTLcVpH4CwTYTdu3VZa0J9hl6S2qFO0KAaVVORwnl1X
         vIuXp6vDKxIUcyGDdtp4ZN/xC1RowH2FRROPUq2LVWeegkFBmvQGQAmi1BLdPvamBT3g
         7Zyc9Ndj335sc8M2Z0mMfJN16rTzdPiyCQf5V/dCCBsu9VU/bbfj/Fw3KC+NkeOmSOrn
         RKAptMPfOKMnacPQ92oAhqIElvyZJvfnsOc+mtRNfW1+VhQ9IOT7LazrZmQnRDVa1bj4
         04FgdS6qRmFUkT0c1YRtQvyscak5JpIYx6OkH9euOh/KudkELC0gGLKzsskXx+PlMKEr
         HFgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=L8hPFr3Z;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rbtQC/n+584so2jXp4UKuyi6ABjycgpER/m7Z+Gms8U=;
        b=V1g5VG3pSc6YKCju327ssxZwjyDah54Yq0z8oFOUEm197T87SHyaf/svDBhhXI0JMP
         h4RdMFezwN8CEXxEAj/PJH+8RNwzmeEWMqDvI8HkO2X3eu6fh4snc+9+sbc6La4GvznC
         9JGRyaHRMTE0FAWKi0vXDLaJl70AP5HGGYvj4UCLRvo8Md8XpSJGMaXydL9PsIW7iX+X
         izndRy0szJIGQgiufbFStrYXiJB3Q04c1mIiWjK3pCVZzvD5OVKoH43Bn45OkUCMsmFf
         qrBRAHxMKctAovPIfdrIexhsvPecvdt2FtCPFeKYf5mS/SdGCO68k3VdHaix/oiXmf7O
         q9WQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rbtQC/n+584so2jXp4UKuyi6ABjycgpER/m7Z+Gms8U=;
        b=SOZgO9hEh21+NNorf1il4XHGqAsii5h/8erdpG9JmjwqEErl395yhigzkT341CRMX6
         u7noD+D7bS4cOZabW6PsXK2xkiIiuZKqnFljKlpK7OkNGENdB/nqAi4PkWf7iss+U0e1
         gjUJ2xNOsJRYTIIYsvDgIKBCLvIbzycUaBY+t7GQ/9QbK72MyccDS+8szHMVuWorKS3v
         3f2XyaWJfJ3T3Q7w2bJ++Y0UGmrvvY0DDn+zMfwwqAxv9tXWwztM9kHr6I6iEWeAaLpj
         hmn7ya+FTWrZNNG+F3YPHKKiw1EywMQ7/Y01Od+iD2xSJwhRP/nCJ9PuTrF7v5D9HfMp
         BlcA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5317x4AIv0Aq+aSKUHLbnuHh+q4sIzbtHhow2h8wNbLS77C3TlmE
	VvzsWZZWautT8UoXE0m+W50=
X-Google-Smtp-Source: ABdhPJwmshTP4IDzccvUD1HvFq74xl9q/tl0pHKrZ6MiI7JnB6My8IsYwgFUTSjtQc6cfjo3SqoVjg==
X-Received: by 2002:a05:6512:c0c:: with SMTP id z12mr2856392lfu.664.1633056163184;
        Thu, 30 Sep 2021 19:42:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a48d:: with SMTP id h13ls1625899lji.8.gmail; Thu, 30 Sep
 2021 19:42:42 -0700 (PDT)
X-Received: by 2002:a2e:155d:: with SMTP id 29mr9731222ljv.522.1633056162186;
        Thu, 30 Sep 2021 19:42:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633056162; cv=none;
        d=google.com; s=arc-20160816;
        b=a2eiRMBtvZlaG6UKZy5nvwHlzqYbwkHORjkhT0mC0ItXQHZbINId24oRN/q3pz6xRR
         RUdhZYS7p+tnyEpjVr5J65zVQerv+Cu/m3tptEMd0eCy3nicIUZVrVzb8QE2dEaBOAdJ
         YtT1INtTTh/6njiqGpioJdfCi3T+0meuaYvBut7LifkewNwfcJEq/zdY+Cjhm3QXoHqP
         ZjS4hA+YnVd8I7Uev9qK08aAMwydoJym/0kfdUwRt30rcr/HmSWWv4jHLr13qE2+0SaW
         6We00VzOnjpbzWSj64JPILFVeHwMnOKDojZZg7xe4g11Fm6GfE+jGvf/FVyXX7bqdMGh
         eRFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=9b7Y2D8y+bwLRWgPDl2sed9F2MPffsUsdfPD7nrHpcA=;
        b=rKS2arjD83Nrx2B6szpL+j1Wet7faBW1B0rV3zwEDyhISxfdl7N1kWlQ2j40HOG0S/
         Z44mthqjfy/exrjwE92eZYShHDiX3btltd6bR5zj1MIPPbQ+iv7Qj9zxdSW74rh3k7er
         wGT822OLtpSo9aYB42Y6VJYV34uMVloBsTXV8905RlnF+YdKN2vaKZ5os1aeY4SaePi4
         ADQzJgFqUCZBB1L7C7HiSvVFtPFEq4nBC3rUmedegthm61uwV/VRDj7gjW+m1wmGIAtU
         EVF2H3G0hG1SZnBTxE7mb0ixgr6mX7cXlZ9HujElumiOFlTyZz5P1QU3tNL/y8rW2Abo
         vkcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=L8hPFr3Z;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id d1si228338ljq.2.2021.09.30.19.42.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 30 Sep 2021 19:42:41 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.94.2 #2 (Red Hat Linux))
	id 1mW8U8-00DV2b-6j; Fri, 01 Oct 2021 02:41:37 +0000
From: "Matthew Wilcox (Oracle)" <willy@infradead.org>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Cc: "Matthew Wilcox (Oracle)" <willy@infradead.org>
Subject: [PATCH] kasan: Fix tag for large allocations when using CONFIG_SLAB
Date: Fri,  1 Oct 2021 03:41:05 +0100
Message-Id: <20211001024105.3217339-1-willy@infradead.org>
X-Mailer: git-send-email 2.31.1
MIME-Version: 1.0
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=L8hPFr3Z;
       spf=pass (google.com: best guess record for domain of
 willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
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

If an object is allocated on a tail page of a multi-page slab, kasan
will get the wrong tag because page->s_mem is NULL for tail pages.
I'm not quite sure what the user-visible effect of this might be.

Fixes: 7f94ffbc4c6a ("kasan: add hooks implementation for tag-based mode")
Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>
---
 mm/kasan/common.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 2baf121fb8c5..41779ad109cd 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -298,7 +298,7 @@ static inline u8 assign_tag(struct kmem_cache *cache,
 	/* For caches that either have a constructor or SLAB_TYPESAFE_BY_RCU: */
 #ifdef CONFIG_SLAB
 	/* For SLAB assign tags based on the object index in the freelist. */
-	return (u8)obj_to_index(cache, virt_to_page(object), (void *)object);
+	return (u8)obj_to_index(cache, virt_to_head_page(object), (void *)object);
 #else
 	/*
 	 * For SLUB assign a random tag during slab creation, otherwise reuse
-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211001024105.3217339-1-willy%40infradead.org.
