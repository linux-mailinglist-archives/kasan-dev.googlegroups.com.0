Return-Path: <kasan-dev+bncBDUNBGN3R4KRBE5AV2PAMGQE37SSKOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FD306764DF
	for <lists+kasan-dev@lfdr.de>; Sat, 21 Jan 2023 08:11:17 +0100 (CET)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-155144f233dsf3478259fac.22
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 23:11:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674285076; cv=pass;
        d=google.com; s=arc-20160816;
        b=kJ9QCDNUon/jW/++SLK80XVOHhpQxmAbSJ+gj//FidJO1lm6k849wxJSrZpeylpFvu
         dysIVf2xXLuSsdKCLB2wHI1SpI49xoMuCEHSzTT46vOkHz9n0/y1S5yY9MUVyYIlPETz
         tsP+KqGElO43nWPJOhzCy/g/N5Di+SwoqQpvHJRl8J+lCkATHw4dLeoW+dehb7FVg+RA
         gHNMVU1ifNwxxiH/H0Jsw45YPM5eJ/h6gkseknWM3ECJJlfF8VyNPiEsHsL6aLTQwMqT
         dK8XNi+2OgtilMS+2dB+/n+vf+dsYDBptLwrP6x7mOMK8ENJaXVbCPDFi60EOUSuUKbJ
         c0uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ldigggcR4f1uOGIejDebVhLGpjqd4d2oatnCkozTnCg=;
        b=QIIQkaZtcloyA4cUKOtDdKg0hj3cKAGag8Q4MnT9qcUUm9Swc4WFEOfae6DoQEoSNZ
         16NulbIsbCdt+Xy6ORAH65/Ujn4Huyln5xlIRpH8w2hpi4LP3tIRePRPyRx6XvSnmo10
         T5qRJi8TlOTy3UlzSa8099Kf0EQ1oZLj2SMH3a12qz3/zdbeXWOeQfhA05T+ttSp3Ukk
         /eJUh4FZEj6Xazfei5Fgg92J89QjYuivxSaNH/LUrL65yQyynROQsQX68UoPuivU5b/x
         t/IrwH8tCU/8TvEH1xaME2DomHEYc546MD9FOfswRR0KX8OInPxpc1B/ltR4iv7Tld+D
         nihg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=uZDwXXMJ;
       spf=none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ldigggcR4f1uOGIejDebVhLGpjqd4d2oatnCkozTnCg=;
        b=i/amamdvYU95Plc/AFUm/WULCbEN97R3urE3+v/eOi2xA/EujFR0MNzHYcHiRiY+Dt
         ssR8ihIK/OxWHi1wsIGHKa2g5P0GyjExoRzXH/e9JPqsXKAmbHQuHIEuFnXDXNTq2IV8
         cLuMy43k1Q3uYgTv6NFrYVYZEoNX8VTYuW/v1U1q/6PDBOgZ4Lu2gbeEFZO3JHpW6Rcq
         Qgt6P2Rm4z/LOR2TqOZOOEyZQE0KoDmktR7GqU3JkgrSuG0eXAU5k00+1gYpU+NIyraB
         7Jf3B4qYQA5Crij2/MJBRoPzWihzG0aynKTxaQvhTyHgD9b/brxqx4PjZII5tCWi40ff
         oSxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ldigggcR4f1uOGIejDebVhLGpjqd4d2oatnCkozTnCg=;
        b=YjnhcXzSP1mcKggC5yWNRBEubgVojosiGkD7werVBEsfhaemP58a1J+VahpHFJCx7c
         8k3YGlpaf8em5lLLtkKKkU2vWkdX3mPQHfmsbIM4p40GaWognr5mTDldqcIa5v6GGPO8
         3PwacvwTEML70BeNknNlInViMfFky4REI522CyPozCfmCKCmySHTjHkgugodXUZ23sdE
         8hkMyaWy+Ltul0hDNrY7QQBJN00O7i/hsM4O1cLPoL4TcdQVQyyBw7WcCRKAQXarCXSW
         fRRjG2T0RBOq7scD8ZvmymVKipeupru0o/JG9fxKzDvIGhzJ87oeFWhaiRhfI+c+rvpB
         KDtg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koQ+BTkpJxw8UYdMjQqgNnmYGTse0DCb27I2PWbnO/XTbwcO5a3
	YianutIbNiPlbuCeHxbLxO8=
X-Google-Smtp-Source: AMrXdXvNCZdqVk5f9qx7V6h5dc/jdh2rHtYqC6AxgJ9oA+6N3m75eN1oB24c3lPJq53+m/Ow84Fz2w==
X-Received: by 2002:a05:6830:4427:b0:670:5e21:7397 with SMTP id q39-20020a056830442700b006705e217397mr1100991otv.382.1674285075781;
        Fri, 20 Jan 2023 23:11:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:661c:b0:66e:aed3:654a with SMTP id
 cp28-20020a056830661c00b0066eaed3654als1290145otb.4.-pod-prod-gmail; Fri, 20
 Jan 2023 23:11:15 -0800 (PST)
X-Received: by 2002:a05:6830:1b64:b0:684:d865:eb47 with SMTP id d4-20020a0568301b6400b00684d865eb47mr8294527ote.5.1674285075325;
        Fri, 20 Jan 2023 23:11:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674285075; cv=none;
        d=google.com; s=arc-20160816;
        b=UdIz6Z+Cc5eMmHbqbIbR/yy4sLxc6jVNzd7DCRihDPb2Qisz7rcKIJqsXCRlLZvXyY
         ISOVYpwS95kw55L9N8/gGjF712ELc8gB9MWbPqM3JPPzKgSHOZBLFhNR/29x17UeFt4m
         UhsB+7JAK3r0iUjDniB/b/0bXA6rbkoBlGrVT82mcNrtWPgBe1sLs0L/0dtJW6IrrrUf
         FpsLlOCVeFceOjW7TDq9HGKTq+VByNf3f+AZpBpp7CVknOzEftrnJUsHVkPVAsRiwJUg
         NhA3ihLlN0gxuFDZUg4JctAkWeAxomxZ3zvkQ8qe5Bo1SGbHiKgAciIiV4raZ2H9Qva5
         nkow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Bku1701L1RVMz0DvJO8KOhu9YUJbNSRasY8+kRaBijA=;
        b=TVyiCx+jzrq1UQWcZ24ScDkFW9numZnjfPmiXMP7kM1vcIXHmD8CO6tUgkcipFMNRz
         6BBhmzuT+COO0J+NsehSlBNWE1MBR+NIwpAQoNq9u47p/YpJjJDfeWKDazIZeIH21J7c
         edh5MCHfex5E7L+++rxj9GV0PkJgSC1qZg+Nsn1H5doPsY8wvCuF1QbeSNUuRAKRhrbx
         cbx8dyKbcsq+zg7+Z2Jfii7Thwar06qIRBzNPn0YSQzugLGmWocvAZEg4UB/mcf4/IXd
         j0bidwvZqRhJVE+SJQ77djoqWiUuSVx+2wnrW9rYUXTzh6DeIodQIgA9cVKItMGFN6kb
         jhQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=uZDwXXMJ;
       spf=none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id r23-20020a056830237700b00686566f6f48si1143514oth.0.2023.01.20.23.11.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Jan 2023 23:11:12 -0800 (PST)
Received-SPF: none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [2001:4bb8:19a:2039:6754:cc81:9ace:36fc] (helo=localhost)
	by bombadil.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pJ81q-00DToV-Lo; Sat, 21 Jan 2023 07:11:07 +0000
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
Subject: [PATCH 05/10] mm: call vfree instead of __vunmap from delayed_vfree_work
Date: Sat, 21 Jan 2023 08:10:46 +0100
Message-Id: <20230121071051.1143058-6-hch@lst.de>
X-Mailer: git-send-email 2.39.0
In-Reply-To: <20230121071051.1143058-1-hch@lst.de>
References: <20230121071051.1143058-1-hch@lst.de>
MIME-Version: 1.0
X-SRS-Rewrite: SMTP reverse-path rewritten from <hch@infradead.org> by bombadil.infradead.org. See http://www.infradead.org/rpr.html
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=uZDwXXMJ;
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

This adds an extra, never taken,  in_interrupt() branch, but will allow
to cut down the maze of vfree helpers.

Reviewed-by: Christoph Hellwig <hch@lst.de>
Reviewed-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
---
 mm/vmalloc.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index daeb28b54663d5..3c07520b8b821b 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2722,7 +2722,7 @@ static void delayed_vfree_work(struct work_struct *w)
 	struct llist_node *t, *llnode;
 
 	llist_for_each_safe(llnode, t, llist_del_all(&p->list))
-		__vunmap((void *)llnode, 1);
+		vfree(llnode);
 }
 
 /**
-- 
2.39.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230121071051.1143058-6-hch%40lst.de.
