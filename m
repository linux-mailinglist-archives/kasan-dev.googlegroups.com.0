Return-Path: <kasan-dev+bncBAABB4HO26LAMGQEZGDVA6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 25807578EFE
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:14:41 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id r10-20020a05600c284a00b003a2ff6c9d6asf8254172wmb.4
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:14:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189680; cv=pass;
        d=google.com; s=arc-20160816;
        b=qLf6n1y97AUqRVwZRkLkMXzkMexX7PbATYOhbrC6X+cTHz1sLo3sJ7lUhZFCpUNzKp
         ZsU2n34LMWXaJe3rFMZStOntfFzvpzE67cH0+DkxqIO04xDIat2olt5Z6fdotHKu7CX1
         QP8ZFdUpcLo3gFrT6/ompMpk4kB0GRg5oOwTFv25xoQqroL2cS8JXJSoJ5GbMn1us5xO
         wpMWHnj4OzZAUOaIFWkKofeBomOYDfkFLep3BBz2UhVVNCy9gEyLPIi9M438IgsgaPhb
         HHN8+ao8mvmFNLIJS5GlHGJOYNPbKFUKjmDsswdjjQfMbbNaVHa81vYJAcD4SVO5HNxp
         0Rig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=DvJ4v9b7EEoa57bv93iblifA/C/gB3WkLs7ToGa85Ps=;
        b=DYNqXHmOVm8LZOmVOR5DsV/AJj9l13QJkIKpZAnNv8bxNoikojFEP64e1I6kOZFwc5
         yUyUULwqgEw/hAZAj+tM+S5pYamsqSmF5ko3ajT2lD1s2FVSfYvIFhAE0ZXw+Zkxxr+3
         h/cs3z/MRA/J3Pd89a/wt10trLSKCfg3ZzGvle2V/00sZg29y5n/iLlJIYU4/4yiMgmW
         2hKa/RCIQY9c7o7n5MAyEmzkHUetQqK8PLI1uj2TYaRfYS/jcdljmbZmSphVqxKlYggS
         DL2pTGSbZcsj+oVMyR1gxvKByhnQX3Uk+Cxa1fR9IytBIME5iTWazElMnw/eE3+fnxGJ
         MhIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=rU0FTMcq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DvJ4v9b7EEoa57bv93iblifA/C/gB3WkLs7ToGa85Ps=;
        b=tVn9CmrmqZPgi955Sh0vHdrqnBTlo0LGJMtsFW08HAx+5rJeR9vWVO9b9ufYaIpkB+
         rXTXdfKx12lhOw3rted9LcTYsrYbhkxgPXx+fiyLTQOqc6pJxM5c+lXihTSsQ0Q//AYH
         sHpeLj3S6vXMn1Es3jYI7+iqurUHi1SqWl1TXy8PMUB+4lHBobnxBiP6IRt4Tt7E9Alp
         NNalfLnjd7K+OsRd7FVEA5taY9w2+Sp+pwaj4YttX6wr+3bayY0x8b4CSHl2SVYCL52K
         f7GDNrBH7EKUxuHgasBE9vYJOJFO+k3QGSALzv3GCu6316bQeBTWGqYqs/DIixeoU+Z2
         bYbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DvJ4v9b7EEoa57bv93iblifA/C/gB3WkLs7ToGa85Ps=;
        b=p81rFBZaL5mw+mEel1BTVKMJLHb50YPUl6EYpsE/JNUwjvJE/p97+oXSxMkODJrwgQ
         D3e10jQ9yPhRhhxsz4HxlEExhFHB07c4mA1/4odPAwtI7UGLIiAg/E0QsGrwahGqk7Ii
         +NiEyuWziNrbr2xXw8ox5jw1ctBTYMwVo0Lw5qtoBv1vyjYiZDH023Wsxw2RBURAxdsC
         dY8NYcb2rd0Wx6UJiL0HjQ0fOHz0t2cWDkDtNjCNBpOU+oxkUsIjjnmAmsHQWIbZ/4Sx
         ETm306k0kpvzB5OCH0JYvaJFez+D0x2JDdsFTDntksBZW1BpzwKUlQjXeRWE/G8hP3pJ
         b5sQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8gitldvORveKqnmG0YZdfuHeKDATM5jHWHumPv6rvKRycjHEj2
	ehOJEJVLSwaeXEs/hWVqkWI=
X-Google-Smtp-Source: AGRyM1sF84ViY616bvpR4BJMbuX6vxyijuLZyjkeG/grsPs/6i+1DUG2U3Mg9Lo2aWmM5oZVjQEF4A==
X-Received: by 2002:adf:d22f:0:b0:21d:6b26:8c6f with SMTP id k15-20020adfd22f000000b0021d6b268c6fmr25796287wrh.70.1658189680849;
        Mon, 18 Jul 2022 17:14:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:588d:0:b0:21d:339f:dc1 with SMTP id n13-20020a5d588d000000b0021d339f0dc1ls477693wrf.0.gmail;
 Mon, 18 Jul 2022 17:14:40 -0700 (PDT)
X-Received: by 2002:a5d:4102:0:b0:21d:fe3a:c484 with SMTP id l2-20020a5d4102000000b0021dfe3ac484mr9402401wrp.554.1658189680178;
        Mon, 18 Jul 2022 17:14:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189680; cv=none;
        d=google.com; s=arc-20160816;
        b=FBDtq841hZiIzYYybzzphcopedrlrIA+tRWDl6086GSCQb7IBkqViatqGCu4+fjhVQ
         OWK5a1X9A0321YTbOr36VVER6uXpNkDlQhN2yXeUq+yPEQsYh3stNntlcc4bDqO7oga/
         HaZmvtngY1vEJtWN+qlkgXozFcD2kKGAb98Y0ZrN7FUW44y+DneZH7BPHBxfpVe1ABOu
         JeKdWKaR428QJ9KGyubIpJrDjMe5f5ZhfHWwiRVcCcomwGcCALix4Ko/ldblY6fYQ5NO
         nlgmPq1vQxt7syLL5QBBCs+eqv0Z/5RblPI0QKDTqs0v2mAhLehY9KHn992d8OB0MBip
         rIRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jretA47WKAcb0y56HfWCPZEL31wNbTFgLZKnmROQ4mM=;
        b=hA57682ldlZGJkOReZ73xNdKkJMrS3bxTigtYDGmUTyUCohqVRLbrNU1NVtQbeia+6
         Dgqo8xAY+wYMgz9dOdWPIpmdgciUWVZeDMB1tU7bNLOcB1RDqkiBMyJoMiLkqfhTNNGc
         B3seGVGaTcAx4k2I/Sk8ZC9bSnon6XKrPttFD2pBABrJ2mz2hJhDw8NMUhYmq53N/3lh
         W8ecawrMmLgl8Rcjt0UtMYgfz3sRXQ91jSeypzcEatrSl/EwwL0wt4Hbn2l9931aYjqm
         SmGQbDOQz7YFrVEsBFwW4KtfN9IxiZzeJiVm6A0YhVKz2N37lIsCnbjBFzWt7xEfMeo4
         KhwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=rU0FTMcq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id u3-20020a056000038300b0021d9c42c7f4si300843wrf.2.2022.07.18.17.14.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:14:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v2 25/33] kasan: simplify print_report
Date: Tue, 19 Jul 2022 02:10:05 +0200
Message-Id: <ca95c73bf01ea28e3d9324b170a9a86ff2b82b81.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=rU0FTMcq;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

To simplify reading the implementation of print_report(), remove the
tagged_addr variable and rename untagged_addr to addr.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 11 +++++------
 1 file changed, 5 insertions(+), 6 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index ac526c10ebff..dc38ada86f85 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -397,17 +397,16 @@ static void print_memory_metadata(const void *addr)
 
 static void print_report(struct kasan_report_info *info)
 {
-	void *tagged_addr = info->access_addr;
-	void *untagged_addr = kasan_reset_tag(tagged_addr);
-	u8 tag = get_tag(tagged_addr);
+	void *addr = kasan_reset_tag(info->access_addr);
+	u8 tag = get_tag(info->access_addr);
 
 	print_error_description(info);
-	if (addr_has_metadata(untagged_addr))
+	if (addr_has_metadata(addr))
 		kasan_print_tags(tag, info->first_bad_addr);
 	pr_err("\n");
 
-	if (addr_has_metadata(untagged_addr)) {
-		print_address_description(untagged_addr, tag);
+	if (addr_has_metadata(addr)) {
+		print_address_description(addr, tag);
 		print_memory_metadata(info->first_bad_addr);
 	} else {
 		dump_stack_lvl(KERN_ERR);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ca95c73bf01ea28e3d9324b170a9a86ff2b82b81.1658189199.git.andreyknvl%40google.com.
