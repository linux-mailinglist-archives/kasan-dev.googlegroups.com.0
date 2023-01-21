Return-Path: <kasan-dev+bncBDUNBGN3R4KRBBNAV2PAMGQEJFUC7FA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id BF48E6764D9
	for <lists+kasan-dev@lfdr.de>; Sat, 21 Jan 2023 08:11:02 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id k204-20020a256fd5000000b007b8b040bc50sf8072420ybc.1
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 23:11:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674285061; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z+/7nUpBlQNXHdgOGi3pRfTKPYn2fPuwWfsZxZwJ6Pasyr4Wr0yjTxhNKYn1yq7r2D
         J+SumCXCK9UgGmzqr/mlaT7awp4GRphvxv/XKjpVzFc98+TXUVWW2TivmSMdBBLoR3wl
         D+X7HbgyN66/9z6fHxE/PB9UtMXJbPHUGR7OGXnK0eDN84fSSN0T0RHVo1GyyPd/L6km
         qssZblFWc80iY52tGD0sZFpQe7eEvsIh8CPwgcxaqPwoHgOxX1Vq0lajvGHA5rQ+GR4H
         mHZ0qi27Y3wFMSW0UfTML+AH/2fV63gOPztRR/lczCuohRf3hz0x9aJABD+0OHz6BKSd
         QbqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=0qsHMN+ohQ5ch4Z9YAzHQWLgBEpaosXwmFi9XyUtNJk=;
        b=UgBh+Nygv9exvuuguBkyX32QWjjkZ/S7QmrZL4E0UDxJUXZtShtSvcrte8d04b2mou
         qfGGrNZKD+lylnHS9Elxo3fbRjfoeAIpXgqBCLOLcLAj/GvYrRgcMJ5lUAHA0lzT8Wfi
         cQMFV8NdK6jUzzy3jWytEG1N+c/TZjqzYry0wtrbxksmWMYPtL/a7B0vXAGaKPtGVapI
         UWapOQBVYsMwEkvoh4cox4ZSygF1VMRXQO9T2shnvIjALor4wnoXSLOgkOgaVGGWdBDP
         IcUhNDDnp0SW+0KwXWuumcI7y07qBVCoipz8YYqY2SbXkqhXK7LVWXlt1Q+vw69Qo6Yx
         IQEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=kCJyVDge;
       spf=none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0qsHMN+ohQ5ch4Z9YAzHQWLgBEpaosXwmFi9XyUtNJk=;
        b=CLiDvAoj53EbI0HKClTh3mLmfPoHrbc1bTlbeA7eIRrhGZ3vdNI65KRu3ZXdbtgPrL
         Njzj7z1NrW0X/kOhUE70KObH+3NN7yzSm3ejcWOz22v+1HFvbmshp1g/V4OE0VkFhLLo
         gTx+TZLHxZCe86K35sGjs14R7194E2VdAgJRgdAD0M8q7cAV9b/vlRD8oNOFp3a0KmAx
         iqT3GPwg0GKqoBMfs6oz2kGTjBMW0c8ZALDRbB9zKbL1sQjqLHcTpCSDifjpdby/JMvn
         WgyB5t+3r2Th0+2ggp3yYZdgiYdOpIp6FYs6tKQkzQSFoJCuDlM/uL24sw5/Q1GIIQei
         PBgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0qsHMN+ohQ5ch4Z9YAzHQWLgBEpaosXwmFi9XyUtNJk=;
        b=pT1fqxRDfCbv8VxVD7Zx3VJxgwMhG8eiWaMIHzCvE7iJHg21l4U8qQrQa78M1p3tc3
         g6Rt1cyBqX7m5AUCDYoFbG/NldG0c4B3uFE/slbg+o+YrVUvl9UxMjfuRqAcdYEDjD9W
         55n8X+84mXCLK+6ihZRwruL4UY2PhVqYOV47wJ7hOYIb7DK8SZivN2Qux6UkIU9M/37c
         /xa2VaRhMLfOGw+8lGoQre9uaGrWq+SwiZ8Aq64UH9ixsnZ/sUQzfQhYybFGowiYuBgr
         dkVBbqIilx3+HON1OWiV1b70MJ9Q798N6HLczynLdYEURmMaceIzUdO3SIO422kXi4/j
         LIgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpxBg84LV6b0bnsmGDr8LWhamBJ4LoFJlv8IRn/KZscZ2Pkofcc
	WrhjRCrtjmm+r4PhXR2ifyw=
X-Google-Smtp-Source: AMrXdXsp6wkJpYHNyrXXHHmVuohN03AQfMMpk7vfGaOjwUdJgaTWzQNzzv7wWi56ia+AL//x+h4EsA==
X-Received: by 2002:a81:4b50:0:b0:4a2:936c:3922 with SMTP id y77-20020a814b50000000b004a2936c3922mr2133030ywa.89.1674285061399;
        Fri, 20 Jan 2023 23:11:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:cc83:0:b0:803:4046:e75f with SMTP id l125-20020a25cc83000000b008034046e75fls1505326ybf.7.-pod-prod-gmail;
 Fri, 20 Jan 2023 23:11:00 -0800 (PST)
X-Received: by 2002:a25:db49:0:b0:7ff:f6a8:6fbd with SMTP id g70-20020a25db49000000b007fff6a86fbdmr4397633ybf.23.1674285060681;
        Fri, 20 Jan 2023 23:11:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674285060; cv=none;
        d=google.com; s=arc-20160816;
        b=CY40bKk8gXhSwC43T8MMPtYvPjAl9UaYEIG5ev240c8O56d/8lLDNcDxtJmaB07gpj
         IveZWgw/pvMbUFwGOvc983puhHwwDrTdUknEX0eNZG6ZvlpYhRc269LbBzlHHOTzMDZV
         xWgHxpF6gkw0kMloDzPNBJM2AmX+9xhCteoPSl/Tpvg8Q9ZnY+aIG+cqxcZhNWcgVNhO
         yfLwVqF1DOdOMerabqyihKKTxbZbhp0MyR2QUHezZIXdyO/q93mHaxfbxXosQm5C1u+F
         +4ZjoTsXzYiWb4fsK8KDtgKgpe9lxyBprIfSKz+hyJJ5ThIDpGyPj7HSx/7GrCENcENy
         p6AQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rOVb8YD5fFvB47xecqte18KDPoif4B7pWlksRr6JsfI=;
        b=SFD9/JJzANNRjdl8W1Rh/78hbNW19urvCyxtFpEv2gzBC4oSmUkzrj4rP9imjko+hu
         Z+GLaGyzdpade4uTihlV+XC1jtg+0qzvElW+0W7ojJp0KSJl2Px/uVlRPlRrffms7J4I
         lSqIgcFVKjzkZ2LpKD1dUtUZAArhzO6MZLvRU4f9TvmFtPYTcKxPJPUEnkyCHhkKujeg
         5C2BH+b8Lm2Wvu4hp9bwQp2khBaE2vyxKGoM1fdu7O7Eg8ZZv+VL9E51/Az34+ATrUlB
         AUPSl6Mad7ECV1IOiB/dgPVK6raE0Umpw2o9/XNRIxLswynZ3IcJYHUXEQ9JjKE+4gw3
         qF3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=kCJyVDge;
       spf=none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id o134-20020a25738c000000b008032606ec55si327062ybc.0.2023.01.20.23.11.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Jan 2023 23:11:00 -0800 (PST)
Received-SPF: none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [2001:4bb8:19a:2039:6754:cc81:9ace:36fc] (helo=localhost)
	by bombadil.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pJ81g-00DTmK-Bn; Sat, 21 Jan 2023 07:10:56 +0000
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
Subject: [PATCH 01/10] mm: reject vmap with VM_FLUSH_RESET_PERMS
Date: Sat, 21 Jan 2023 08:10:42 +0100
Message-Id: <20230121071051.1143058-2-hch@lst.de>
X-Mailer: git-send-email 2.39.0
In-Reply-To: <20230121071051.1143058-1-hch@lst.de>
References: <20230121071051.1143058-1-hch@lst.de>
MIME-Version: 1.0
X-SRS-Rewrite: SMTP reverse-path rewritten from <hch@infradead.org> by bombadil.infradead.org. See http://www.infradead.org/rpr.html
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=kCJyVDge;
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

VM_FLUSH_RESET_PERMS is just for use with vmalloc as it is tied to freeing
the underlying pages.

Signed-off-by: Christoph Hellwig <hch@lst.de>
Reviewed-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
---
 mm/vmalloc.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 0781c5a8e0e73d..6957d15d526e46 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2883,6 +2883,9 @@ void *vmap(struct page **pages, unsigned int count,
 
 	might_sleep();
 
+	if (WARN_ON_ONCE(flags & VM_FLUSH_RESET_PERMS))
+		return NULL;
+
 	/*
 	 * Your top guard is someone else's bottom guard. Not having a top
 	 * guard compromises someone else's mappings too.
-- 
2.39.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230121071051.1143058-2-hch%40lst.de.
