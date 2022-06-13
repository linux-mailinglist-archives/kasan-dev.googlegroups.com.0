Return-Path: <kasan-dev+bncBAABBYNXT2KQMGQENT64FRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B1EC549EE3
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:19:46 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id j3-20020a05651231c300b0047dbea7b031sf3477112lfe.19
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:19:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151586; cv=pass;
        d=google.com; s=arc-20160816;
        b=cqkd6jRgtjXdZG3KrmMmmeWSEaiZ0kEm56PtUDyE16sPQXD1FD4RWiFKH0LOUoxmOA
         Cnis+ULzem80OaP10kvKkznagTfPBt3z6h7lEFZtsN0P6i7JkNbxWo346N9KBuGISFW+
         0UaC4kKpiSkIKM8C1YQIaj+Vsb5yq19JADOS6OeGuROIx0fll+OHAx8wB+89sW8VZloz
         sId68AA5HMRjOzohUfnsb43qKsdcu4bSLY9HgMcxO7vZZeOIM0Xto3EQDNNArFh99gRc
         UzJUQSBVdglouz6OqcNEoyM/rAtbbuc9aDSTncOlI/uwAo7iGMWdAW+H48D3mBrYV/t7
         rslw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=BTVMdXMmYn1vKbOBGhASYYsDHO9+yPhQWPD914zkRNc=;
        b=HFljoJIIADqfjfGPrvoDl8vDJ5D90dfUzds2DrHWfwwZCdckazmXSobYxvAmK9xjHB
         VLaHAFEdsUl4w1/3b3w6dUpX6Bpr1G5Hel8NFt7YSm4qgHY7eAJRy3rXxfIj168LC5fU
         BNj+t3d26B3xH8ashuG1GciKuRPXoRqSOkyaEoI2TkTWUm8hFhTUap5I/eIEo1RLH4lx
         lI7W9f82zh4XvD6RU4OxGMwjA48MUG8K2WLGjiMoeMyVz1vthvBKgSDb0hacqYQzjw4Y
         BJ//hKXgQCaVQoo0qoIYB3YfS+RpXwpSi6ObchEvbLmz0Mv8xUMJfO2E4Ym69o+4mh2y
         jsOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=uV4k7v6j;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BTVMdXMmYn1vKbOBGhASYYsDHO9+yPhQWPD914zkRNc=;
        b=FL4FWxadk1MlkWf/3kcArQDKP5jPFHVnY9l41w5EwFV8jQN3ICgGcy42l7u3AGvm8h
         +oZUQAW6br7bSJt2m95R1+SgTaPj1qrb4cgbXLx3lmezE2IZsGZQaEld6Xp03Xm/KNW6
         JsHN7wrdHIYNrli0myUj0sDD65YsOPkgW3A76pwyxtHyutU3EJzPVjK9R5NijuQe4NrA
         4IN1BGCkZOWJ23CIBzVlBwz7qDnFz6nLWTgyWRBT7r08w5nrNa7bSOKcSLNxl157fCC1
         YelYTBhRn0S+H/UGkA5Fb30jgmsUh3R369D/yDxCLqLRKn72cbgiatYdu8i7HhrZcQBx
         +ypg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BTVMdXMmYn1vKbOBGhASYYsDHO9+yPhQWPD914zkRNc=;
        b=jkbju8gPhb/rjwNroX+MuWh8ETyY1RSoD+EOXZP+ErnPJmb8CeSHxBK+or4WwcG3Tz
         4IilUI+MA6KA8GQUe9aj4ZhsMuIjTBvClLaLu+chH6l8SxehfZ2CuWXmyxZ4+LtvQWIu
         plVU8QUJ9ZJpxi3NmSwLuzT5oIDor/hLgrcvTeF3Fx42kur7QC177lCEofbM1TW9P8DH
         uYHbx6sop0HL6eVS78OmzCMrcLMwK5maKjMJs/c/PE3worR+/PrrJjKrYHoGuKa2p8HH
         RZEtJwQXvo6s4LA+hQqds0qrgRWvOqEtRWN92rPj8kg5/ND7qbDHlL4jSxwY3a4CFW9K
         cCPw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8IkKLiqTORSq8TB/0++wzeyCRKpSLsYbYwBYeRU6RGJeuFaifd
	7Vs7T1HZE4Sd5UkGDuFK1wE=
X-Google-Smtp-Source: AGRyM1u7ZTo27wyKZnnqo8HJnxQ7HU1IwgPrs9g6CnEavPVZUetdNX9Ufgqn8yPOwzRQ/121NT1C8Q==
X-Received: by 2002:a2e:9cd3:0:b0:258:e71c:6430 with SMTP id g19-20020a2e9cd3000000b00258e71c6430mr666475ljj.274.1655151585895;
        Mon, 13 Jun 2022 13:19:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:81c8:0:b0:255:7bff:427d with SMTP id s8-20020a2e81c8000000b002557bff427dls457387ljg.0.gmail;
 Mon, 13 Jun 2022 13:19:45 -0700 (PDT)
X-Received: by 2002:a05:651c:101:b0:250:896d:f870 with SMTP id a1-20020a05651c010100b00250896df870mr621370ljb.235.1655151585104;
        Mon, 13 Jun 2022 13:19:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151585; cv=none;
        d=google.com; s=arc-20160816;
        b=FFpdzRxlQaOSQskQwa6OOuPBjZhKulhy2gLfOdHGbbgwudU9oc2TdpKXtoyzC6AHaI
         0dHdYaClKT+QElFeRR+H4Ms+GMYVCyYm7cWOWj9xCbPor4Fd8j3ej7Gytt+KRQ/N+Tie
         Nlz15aO50rRj9Q6u7TiNIU5O0gUL97mZogSRD0ARjLnCO/sQRL2gXI9U7DttLy2MORsK
         IVlKqPC8EeVPTZ15i81o/icivjpCh+HNUgm8E9+vsoShGfh7CwqHiFv6VdzplvWMYBKX
         GyLvZEbuk8YjZ2naDLsj54/WfJoQqZVwL2Em/BDV55chmdeXdl++sH/h6RzY8mUkT5RA
         zY7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=xD+jOMbc8v/VbHqobo7HTP4Hy7ebCjo8HGnwIkjNmQg=;
        b=rLAc6sTxAHtI+wfjy+njg1r3hf5KE12UrkltQ/Xi3DlPUkvhupR02Gd9sGKfZecskX
         WrE/ckaG/P7/kaFsbECIcUSmxc53o6MYcbKBo2Ib6sToiHHAxtwzsrLsP9pyQHc6PaZO
         xLBmG29e1woIFLKtE9ZpaM9bNJwR9KFQc5yp1kJQKkr6CO6oPrF1eDgZqf06rnLwqU26
         vntFwONYbvuV/WnHG2EDhyPZhn5XT0HHKxK21dFGfNfXEoRobNW08LYT+pgKq7N8/bdC
         uLppxSh8xpn08BZEFulYeeHEnrSiXj5x4QHVqSeDH+Kl4c0l7Lwl52xPdJB3uzHjDKvH
         RItA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=uV4k7v6j;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id e12-20020a19674c000000b0047866dddb47si298977lfj.2.2022.06.13.13.19.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:19:45 -0700 (PDT)
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
Subject: [PATCH 26/32] kasan: simplify print_report
Date: Mon, 13 Jun 2022 22:14:17 +0200
Message-Id: <6920a74ae141ec8f45f19c8ebf3622910d10a5ed.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=uV4k7v6j;       spf=pass
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
index f3ec6f86b199..cc35c8c1a367 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -391,17 +391,16 @@ static void print_memory_metadata(const void *addr)
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6920a74ae141ec8f45f19c8ebf3622910d10a5ed.1655150842.git.andreyknvl%40google.com.
