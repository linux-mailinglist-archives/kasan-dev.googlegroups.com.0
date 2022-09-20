Return-Path: <kasan-dev+bncBAABBRM2VCMQMGQEZ7ZO5IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 383695BED38
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 20:58:14 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id i29-20020adfa51d000000b00228fa8325c0sf1518780wrb.15
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 11:58:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663700293; cv=pass;
        d=google.com; s=arc-20160816;
        b=S6r5i9Glzo85qIi6DgqUlCjJ8u9NNQ9WaztMqf3bBjY2BP08lFC7CDPJJDtDS1HZEa
         joByVX/YLBT9mhCsMSfc4I9z5rITwhrQr8F86/DOCuFKV95o/l99RH8huZv1oxcqP5w/
         Uv57IXColDgnXZkBwn7rosNAwwcXduh2VSmUU3wX0wEqb0c1hz1e4VN+4CDQ2H2aJ9n6
         vnQ/dK2PPoXOMggTIWIzWaFsIVXflPTsolg8PIN9mYClZ+MCal/OuqF6UPDWCfnAMsrk
         PSdPGp2oIpZS4MIAvpWHU7He89u7TufjHgYXizQOQPtKfNSt6DEjOvLmuUmzpdbZaZ5p
         7jvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=rt4RYDzK4nOFXu3E6BBXwTPk/xNAYfF19p4vQ42AdwE=;
        b=rsssugyQszgqPPa471OPcecoJugErzTPaBQOZH7+PzZHPQ8ygXXiXomcZtwTihm3xT
         oHRu0i7KBSre6DDNkuMG3HjyscvuHQdiqjOlRsHa/z22piERSIPAEZV7olmfxA+dEEc9
         S2PpnEFR74FZZqbTEM3H/0do1552RhQ2FfnKCIeaFHJElUL8m20t8f7mfIwnRO3AGURG
         gxNQJRnB0IFaZccOOsZnVrVBxztRmCw90YYdddZFRr5nyk8nA65kQLsNuAKzcV9tt8OH
         27mmeJvFVeMxxEtPfLKpERQkrt1UkGTsrtoTHSCg/uTotUlMegy0JuVSJsJOzFGdIMt8
         DvLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=GnIONQpn;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date;
        bh=rt4RYDzK4nOFXu3E6BBXwTPk/xNAYfF19p4vQ42AdwE=;
        b=tQcvR1va9+tVUZ5ZmiV+RFgF+vWcheRRO1gzU1IYvfvSMD0iuKwb/jWvYKOBbTUKvd
         qWtzveMvx/DcbrKCTMa+WlXgctrkn7I/1SD7RfYLDKaQAQXxsIA/GfMwS8f4OOS2Pa8G
         Zh44QQxj+suoyFOEa1UaHXeh5CAIiJkfGQ4a7AUNpkNuYdYOvGZW8897+TamlYOfo1l0
         kjJANXo+xNgRk3ss1RQ/mMJtwrbierz7szkbttkHrVELbuYRYsoZVsUXLwruCqAgtIsi
         BOrzBxHQdvhsMCYQO5IKeeniilSLqw+3KAXFvL1fbY/fjVZ9shVzh1dffju4KOlScUTf
         FjZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date;
        bh=rt4RYDzK4nOFXu3E6BBXwTPk/xNAYfF19p4vQ42AdwE=;
        b=yI4S1s9nRn59E9717oFnHiFy3yf2I3+PSj7zIC0jw+b0vKrjcqWc7RqiU94lpVCoj0
         OeJLODCe2lw9mKE6U4XB259n8aKl9DaMQnOmOArThDuI7zeYeZIaLUcizovm8bi5wKJQ
         ITaz4++Ec5pxh1r465gZkD0vVYYJ3dFEQXrLP3+iC66L9fM6Q66xKhhIPBH1oMLqLuxq
         D839oSEXGHJXXTHhdzJkRIm+BN0umxONWf/nKsFhl3SIEJzX1gBI64ujXPjdCcehPBXw
         /3RCET8hJI+TK8dxC+cSkkYKJRIx1KQxSdvdnAhOeawI6I0fuFc+bkTEocOtRxZts5ut
         Ev7w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3n2smnJUlWOxIecskDOw0pg//yWcllnsW7gXTRXuUhMRFGCFLy
	LywOj5/5WwtNZgRAulyJjPo=
X-Google-Smtp-Source: AMsMyM4AxSiz9pTU5hmlKX7tM0qW/dBeHgITI4JofnhquYhTCRjzWSpUyCUrnRG9HJEvpqwN8In33w==
X-Received: by 2002:adf:fa82:0:b0:228:6122:9903 with SMTP id h2-20020adffa82000000b0022861229903mr15044448wrr.144.1663700293577;
        Tue, 20 Sep 2022 11:58:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:490a:0:b0:225:6559:3374 with SMTP id x10-20020a5d490a000000b0022565593374ls4123992wrq.2.-pod-prod-gmail;
 Tue, 20 Sep 2022 11:58:12 -0700 (PDT)
X-Received: by 2002:a05:6000:178e:b0:22b:c23:109d with SMTP id e14-20020a056000178e00b0022b0c23109dmr5095870wrg.408.1663700292847;
        Tue, 20 Sep 2022 11:58:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663700292; cv=none;
        d=google.com; s=arc-20160816;
        b=ZHQ1q/hoiQDYR1VzLWrXX+onSPwzd09luUlZguiOqYeMqvrIIaQrhcnjBvYnwzuEYl
         Q9MQGJI4FlGFQxvKdaQi27in9UA4KZSbqYgV6T9PqhXGRLU9bb7xFBc+JrCMLCW6uG1Z
         0KgJ7+cWE5kBB1hWClBj3a11Jgpmhj89yrZa2WxQlzD6srmEMhOK2quvbjenEnGEndP5
         cLAAMj0r/YP2AuxRFHf/j+R75hRSMr4pQREAiVzKMg+NwlN49lyNsEgBAyDtYr9lzG1r
         Bl4SnJ2BIUrXdwST+lhxcSF9xQTeDjkATI8ke8kuMHGkLORQvj6HWzx4Zpxo9Tbyp+uI
         Xl9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=nxHRTq1Yg5oxG8+GRDFsDxq7DRLYMtQhvc5Xaz+eRBo=;
        b=iHx2W8qaP4CbGI98C3t6Vg7gSSb4bsgWiXDl5ldRTb+sl0SfCXFjy92lYBDNLQa6qf
         EKbkNaYC9IT0TBFd0DSddi28NsjaRMEEP4Vorpp87ZVaJvtF2emSsv4h9Ci1Bdq7Zze1
         u6EgdQIifwLkw1wk1dGa496P2+5cuFKvVwui2Ra3E0B+9BK5YY7+FUupSDyyBwnzFNpM
         81DCeiipU27XaXxmg/3oyEX+MHjRqcfYppLfqK77OJ7DuMun4NRdMVKE5I83q+6gJaTF
         L8cMZX90CgebuPlde9betRZBmq8KCifD/RU0fjkmdxn/hjTU4/fC1rDjzqAmY53WeYNt
         +Mxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=GnIONQpn;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id c2-20020a05600c0a4200b003a5a534292csi86141wmq.3.2022.09.20.11.58.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Sep 2022 11:58:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Yu Zhao <yuzhao@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm] kasan: initialize read-write lock in stack ring
Date: Tue, 20 Sep 2022 20:58:07 +0200
Message-Id: <576182d194e27531e8090bad809e4136953895f4.1663700262.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=GnIONQpn;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Use __RW_LOCK_UNLOCKED to initialize stack_ring.lock.

Reported-by: Yu Zhao <yuzhao@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Andrew, could you please fold this patch into:
"kasan: implement stack ring for tag-based modes".
---
 mm/kasan/tags.c | 4 +++-
 1 file changed, 3 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 9d867cae1b7b..67a222586846 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -36,7 +36,9 @@ DEFINE_STATIC_KEY_TRUE(kasan_flag_stacktrace);
 /* Non-zero, as initial pointer values are 0. */
 #define STACK_RING_BUSY_PTR ((void *)1)
 
-struct kasan_stack_ring stack_ring;
+struct kasan_stack_ring stack_ring = {
+	.lock = __RW_LOCK_UNLOCKED(stack_ring.lock)
+};
 
 /* kasan.stacktrace=off/on */
 static int __init early_kasan_flag_stacktrace(char *arg)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/576182d194e27531e8090bad809e4136953895f4.1663700262.git.andreyknvl%40google.com.
