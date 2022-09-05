Return-Path: <kasan-dev+bncBCCMH5WKTMGRB2WV26MAMGQE3TZM3NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 060F65AD26A
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:26:19 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id q18-20020a056402519200b0043dd2ff50fesf5695272edd.9
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:26:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380778; cv=pass;
        d=google.com; s=arc-20160816;
        b=WEqGUi+Q5tp8pGSBksBm/Kg4/nMJVF7Q5b6R6fPb/xip81j9yKiBh3slCQPAq9aV0W
         JVIMjMUj8xTHp1IGqDPa3f1S9s5K6bmHwsy1CK7aIyIAjBQTnmjjOeHtnrVE10YSj59v
         e1zTf6eu6zPxF2YIHpEwWD+cr1ajR3rPnoOlrFLs1uLAuxY0/KJtoMQUrKnH9y8KERvD
         NzMVUeGUGWeVtWWreIM5Nm8X4pkqHPEfPyNYid2dQAczCo0niRmwm8npioBdGpq2FPhM
         orMUx6QF+5QuCv4K/MiK6gBCboFT0ZI0ogMH5QL7NJVTcTlm+R/Zls9TKVMBS9V+6jwV
         meHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=C8shxxJt4UGn2WATc1S3GikIymdOfBQZF6Jgg+60CcM=;
        b=XNFHjP2S3kQyeFk+X46aXnhku4/q1pZLRyQ/B3dBqfIB+OLtttg62w7E1Gg5wapQSF
         43w6PXpff8V0phzg1NUhDlCZh/Ezr6iXb5mBeR+C3CC4xOSP2t6ASzXHSdHXHC5Zo36E
         CeZuoUcVBQ6QVI/8tog7e1qY33RM7tS2PE19R/QpLKrHQXh2xheZnI6dMjrSDUHM4YJ5
         7w4BKmdiHYkAoUWeUuf7dDoR5ZCBI2m2YMvvDp0YP/uGnre7a239XqIo6btZvVGfidUU
         fBsZj6QrD9tBiOPd9zgnx27FoToMQ6SLm+UdcXxz4BFzpJCuedSxfPR2BQYJBUoaR765
         S2DA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ASzeAsbM;
       spf=pass (google.com: domain of 36eovywykctyydavwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=36eoVYwYKCTYYdaVWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=C8shxxJt4UGn2WATc1S3GikIymdOfBQZF6Jgg+60CcM=;
        b=U0NaylPg62G8wswTs+kbrBb00epKUS3ktZPA5Noctn8EqGNQA01f8/tnYIqn21azlj
         fEwd5GzPodC+vUibM6izw1B3Ykyk2HjU/4iBalZgapb9gWBuoh6rXWaUYiU7A+myjjX9
         Ml8GI2Izre8v3Z1iSfqvvviswytNCSEGuotQTAu+K4aLtDRYJl34BtM7y6Qljul840iG
         WKAKUXZcv/s4wmlII4hxRcLJnlDdda9WfURyfcPmAaie7pRuffNMFT6Ty+W/BrMlKh0J
         cTeFmPzEGc1phdhJg3TVWmNpVD6ZXlRJlH3cvEB8UOnUSRdWLXcZ7noAOyB1mW5LLowP
         0hCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=C8shxxJt4UGn2WATc1S3GikIymdOfBQZF6Jgg+60CcM=;
        b=xftoLVKQXWec4zS0ki56BITaHEI5qin2MNoarkoh0lz8NftB7WwZokfoAsxST3PKmC
         krnYAzrM2BFCoULvmsJlRdkXMwDNWNsEgnBApdIoJkcK8LDzPrGspfckAADjoDUZ+tj+
         u2H3T1aT3LtuhR6nYBXswjwezYCKeB1OC0orCQwzd1yVhcK0RXJyaMQXhl+qNqVXVFRB
         8XYRqmDnAgZjby+YDZa06SUqmIJCKh6jO/Irg3K7e7nV2vinZ9cC9aBtnJsLj3NSsW8D
         1f1kfC5YgJUOQJ+w3iqw7OHrO780EyDM+dCaEWf9sU3pTZOlwjZh0d15eM1iesGbmkE9
         uahA==
X-Gm-Message-State: ACgBeo0MbpGX/jMNJFgLcUqg7boickfAyf6VMKLDDOHxk+IiypP3wgBr
	JKMWxNXYU69qQ/okpC633uM=
X-Google-Smtp-Source: AA6agR6yLnBWoQsd6xx1La0TzIxbYY0vyMFkbT4txoeFfTOyo8Eq6hHu6OLc70b/jfxej38+jv5PYA==
X-Received: by 2002:a05:6402:911:b0:44e:a5b4:74f7 with SMTP id g17-20020a056402091100b0044ea5b474f7mr1763930edz.249.1662380778736;
        Mon, 05 Sep 2022 05:26:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:34d1:b0:447:ec6e:2ee with SMTP id
 w17-20020a05640234d100b00447ec6e02eels6882132edc.0.-pod-prod-gmail; Mon, 05
 Sep 2022 05:26:17 -0700 (PDT)
X-Received: by 2002:a05:6402:26c5:b0:448:e46f:c9f1 with SMTP id x5-20020a05640226c500b00448e46fc9f1mr23553617edd.287.1662380777862;
        Mon, 05 Sep 2022 05:26:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380777; cv=none;
        d=google.com; s=arc-20160816;
        b=EC0KsWeeZkny8+whVJk0B9peDNnf4cVnd07fAH5XeSY9JwIVsZZwgFP2NfGsBdUjYt
         CAji9jWRlfAjUzdtKW2wKqJisdi2L0A+M5UUV/08XAa6zAK0Y4QeydFKdisRWtEnXjJz
         y94lMyoGw8zCkaBCknKoaKL+iGcNJSvAZZ8xFHt3gPpHUe7iXwqiy7xN7tPxgGIcS03g
         5ytm+96TlmwV724Izodq4kQZ5Qfp/AVVuibafISeG/Q+2lRsKgI4s2yecUbIMFdGWPs0
         tCiu6TR5MJpPeCuKHN+s0DvNpZRu6wllGqaSu4XnfbZZN+Veu6yNE43S2bRPAk7hCzfz
         YNVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=r3HZXk/BEn65kcaybENH+gdA6j04yycM3f96/pfDo3Y=;
        b=uPFdn3iX01lo/dfT12wfbFzaNUVRgytC4u1GEEN+qc3o1rWPjTMY8agWAoro9kuHOQ
         H+sDE+k5VdByU4AsjryUlS59wS8x+sEqgygq4XS4VSVILf79gjJByvrvsMGkubDllxT0
         VQWSeDI1N2qbynFc++JO5gD0dJqs9GXCOCTapIXYRSTzXKIEvVnV/IMgO8N71GhWUtSk
         aOKsEzmKzrDgK/xmjCFZrM7LjwkUZ8Q81GAECylAY3nh7w/1TxE4iQe67lV7PAEiIvgd
         J2G3MJ5H790Juu0i6dwC+D3DNwcdHG7Q/FgKHXRbYeyt+3JDjDhIvMz/ivJ7NtaCFemb
         RneA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ASzeAsbM;
       spf=pass (google.com: domain of 36eovywykctyydavwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=36eoVYwYKCTYYdaVWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id og36-20020a1709071de400b007415240d93dsi373769ejc.2.2022.09.05.05.26.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:26:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 36eovywykctyydavwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id jg40-20020a170907972800b0074148cdc7baso2257886ejc.12
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:26:17 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a05:6402:348f:b0:448:6005:68af with SMTP id
 v15-20020a056402348f00b00448600568afmr32104195edc.184.1662380777495; Mon, 05
 Sep 2022 05:26:17 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:37 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-30-glider@google.com>
Subject: [PATCH v6 29/44] block: kmsan: skip bio block merging logic for KMSAN
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
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org, 
	Eric Biggers <ebiggers@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ASzeAsbM;       spf=pass
 (google.com: domain of 36eovywykctyydavwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=36eoVYwYKCTYYdaVWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--glider.bounces.google.com;
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

v4:
 -- swap block: and kmsan: in the subject

v5:
 -- address Marco Elver's comments

Link: https://linux-review.googlesource.com/id/Ie29cc2464c70032347c32ab2a22e1e7a0b37b905
---
 block/bio.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/block/bio.c b/block/bio.c
index 3d3a2678fea25..106ef14f28c2a 100644
--- a/block/bio.c
+++ b/block/bio.c
@@ -869,6 +869,8 @@ static inline bool page_is_mergeable(const struct bio_vec *bv,
 	*same_page = ((vec_end_addr & PAGE_MASK) == page_addr);
 	if (*same_page)
 		return true;
+	else if (IS_ENABLED(CONFIG_KMSAN))
+		return false;
 	return (bv->bv_page + bv_end / PAGE_SIZE) == (page + off / PAGE_SIZE);
 }
 
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-30-glider%40google.com.
