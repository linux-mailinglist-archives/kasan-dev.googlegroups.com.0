Return-Path: <kasan-dev+bncBAABBIN272IAMGQEUQK7NBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 444004CAA6F
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 17:36:50 +0100 (CET)
Received: by mail-ej1-x63a.google.com with SMTP id hq34-20020a1709073f2200b006d677c94909sf1270330ejc.8
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 08:36:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646239010; cv=pass;
        d=google.com; s=arc-20160816;
        b=xK9Fp/0bXvBGxcaG2GLNfezGMjhFT0k3O4ozj0WwokYOo8Xu8o63ht08YQ0a1yEEMq
         byQZyCD0DAhFnFSIaUrR5kQx8SBl7l5GqLUekixJf+f1Hxs7fNJNSGayzIV52EbWqc/W
         EFnVLZMqT8BBl9t5CL8CDs+PXu6da9tme3Ly59dYHnmgNkFgMf9LNs0TBmkpFfRDFbeq
         pbTYB9wGVyuHROiunpPoJQYmZPGUezjF0SEZPEOQ8yRSaIN0+ZwxRDITtDv0wIY7UtQp
         CsEVNuTiK6IxyaxD4TVopwsSVyJcEWehReRz6QPolxtQisnDBc/Ul+4S+I++ZgKnd7HY
         95tQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=AEVwGzwTdTz7XwNYYTDaM8Em9Oy0BeLFv35+C+KVAl8=;
        b=jutjH8AjLsi1xucusxWmEXbVz7c0dYXMnks1/UM56g1xtD4wxftAbYnWyIm7IErXB4
         URenOJ9ZUE2gJ7ZTma38yUOi6szv/BR/5I6g+eeYYI4xgV1VegRc9TZeIteDYa3hT/xm
         VwRtUMuQkO6KnGpQ1OgjpbIrRblSdKTv+mhAq2IUA1DVYs/NLNWTmNGPm2nfYIggigtb
         Xw+R54nWs70VAnFNLBAW6jjieo0pFFfUGdGpC5OLR18apa7llZplGIVGXe1m1AIRsevc
         ZsbyzEniGqdRj3Ujc4fN3rVk0jppOjyIAtngtXcQOlmp/am4scB+WzEaFxQIp+YpNqWi
         c3OQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="dqtbv/8F";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AEVwGzwTdTz7XwNYYTDaM8Em9Oy0BeLFv35+C+KVAl8=;
        b=S4fNKWdnBYQm7QHNYHUlhTaVx1wSTCeKiixXB12w0Wi0BM2COqTpDWiwl57rbZLBeg
         /Bt+6SGjmcG3ABk3FfmIwvxPQg/HWJUNvPAQRLyifF3RNMKLnokYo+c3pjGtruAGUVQp
         axfXS/pUTHb7pl88MwTo9JuU5Rw02ODv2YX4DfGUqmVq+SxO7IvIuxvN1nMUDVrIyMdF
         z1wRT/455/UIEwGnwqrERZ1Mq8ti8kxaJgBzeq2YXc3qDF0fXcLBmHzpEtQ8GQfYfeTP
         tNPQy/jnQBU+3u5EmgKA4oja1zidPh/O16BJJWGkDmtb5DNPOq8j3JBWSWzgM5oLYHLZ
         BpkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AEVwGzwTdTz7XwNYYTDaM8Em9Oy0BeLFv35+C+KVAl8=;
        b=KZcw6Us2t5X+AUGJ2RxKMvWlHFnNLBNhIfY8Mhxa3NCh08+VF47R+Ki6cMAjeTeJT0
         sd1h7oACWnzVSOs/gkg63eWBLT9iuR0ApB5Js8OiaDBDChNterK9A6hJrtcapWWmnb+U
         TZd4GP68gg6yCIUURO+Z9b4aSS2NGaxG1jb0Dfh6v2gX4vz4fiQQBQG2nriLATbE6oxM
         8V0dFQtDG8Q2HJ4b5H1WA8E7JPUmpSV9I6E6fJrHgGwoVTs9TC9spvjsDlxmWoWIqhNq
         Ta0hCrRAvzx7pnwM4Te8lzs0vm+EUW3a8XN3+Vi21XPh2MIcvm3Wl2Lo7dj+qLEeRYkt
         N8OA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530uZCh5w1JoPltkVDgViq+arizRVmvGD+UJAqdRX+jcHH+F22rC
	KzubwghESYdYfHN/opOj/Ts=
X-Google-Smtp-Source: ABdhPJywFZfeY3SJs809XjT8GXI85WglELgv3ja9io4t/cwxKIhf/hek2xlEzkSnEWcR7WaESzCbvA==
X-Received: by 2002:a17:907:9815:b0:6d7:1898:7c90 with SMTP id ji21-20020a170907981500b006d718987c90mr4965742ejc.552.1646239010000;
        Wed, 02 Mar 2022 08:36:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:c113:b0:6b5:e466:40c7 with SMTP id
 do19-20020a170906c11300b006b5e46640c7ls2888833ejc.8.gmail; Wed, 02 Mar 2022
 08:36:49 -0800 (PST)
X-Received: by 2002:a17:906:b887:b0:6ce:36cb:1e18 with SMTP id hb7-20020a170906b88700b006ce36cb1e18mr23900734ejb.95.1646239009208;
        Wed, 02 Mar 2022 08:36:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646239009; cv=none;
        d=google.com; s=arc-20160816;
        b=UrxongZWuA+8ahk/Au9+gh4lhpr5+zUaID3K5kVcqeX/p4w0FmUejoqx9IeuVso2zp
         3p4VOSzht+DhVGdoXpaheclkfjy6mqFm0djJjWnzaLLjmUd4OIbvvQgX2TgC3Tr7xZ+s
         /HTJ6R/rfFssjidMWVUQMLL+Ayf8OWh6Z7ASjzQaoq88F8BEIeKVb2Y69JcCbtTHRzbs
         MpeZ7p6c8He53QsF27Ilryke6Alp/311WMGXNLjN/IbrdPF4njixCbAyd7Glt/Xr4Nds
         5fmUo45CH3CQ8q1M364i+7cm6uwugn3O8xfC4XtUazDoV0a+CZqfvQQgQG4xmaEvznPb
         HsjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=uo3r1XZ2YxXX2Y0KQk7NP/LkQS2+d42pEDKbCuKVO2A=;
        b=vam2NBZPizLUY5eRR0ZK0LJQm5JADvzMOiF68k/p3k2w5k/c13edcy6ZPuA04Nfvnd
         5vY2jj9etXlGzNRbz/O7Vx2gnLZ0gpNK1hIIL6vY4Ii3/OHm9dX2DLxBiBfiHeE9yhuD
         TqTRC1oyFosMcKdiODskCQBldaAAUlumh/icSZ/SgppEWXpEWzXEE+stwmB+8EN37AmX
         jNm1MQDcsP7/GGPuIZxrprnfJDrGeBDiiJL34zEMMk4zBEQUu4ApeXtBxv78exho/YWL
         vihKaW8W7Ju2G5ue7a9uGo9QsihVODl/WDL9IIax75RH16Kunfh40B1ovPm5BcjnC3bp
         kKpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="dqtbv/8F";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id b88-20020a509f61000000b00413ed059da9si487367edf.4.2022.03.02.08.36.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 02 Mar 2022 08:36:49 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 04/22] kasan: improve stack frame info in reports
Date: Wed,  2 Mar 2022 17:36:24 +0100
Message-Id: <aa613f097c12f7b75efb17f2618ae00480fb4bc3.1646237226.git.andreyknvl@google.com>
In-Reply-To: <cover.1646237226.git.andreyknvl@google.com>
References: <cover.1646237226.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="dqtbv/8F";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

- Print at least task name and id for reports affecting allocas
  (get_address_stack_frame_info() does not support them).

- Capitalize first letter of each sentence.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report_generic.c | 9 +++++----
 1 file changed, 5 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index 3751391ff11a..7e03cca569a7 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -180,7 +180,7 @@ static void print_decoded_frame_descr(const char *frame_descr)
 		return;
 
 	pr_err("\n");
-	pr_err("this frame has %lu %s:\n", num_objects,
+	pr_err("This frame has %lu %s:\n", num_objects,
 	       num_objects == 1 ? "object" : "objects");
 
 	while (num_objects--) {
@@ -266,13 +266,14 @@ void kasan_print_address_stack_frame(const void *addr)
 	if (WARN_ON(!object_is_on_stack(addr)))
 		return;
 
+	pr_err("The buggy address belongs to stack of task %s/%d\n",
+	       current->comm, task_pid_nr(current));
+
 	if (!get_address_stack_frame_info(addr, &offset, &frame_descr,
 					  &frame_pc))
 		return;
 
-	pr_err("\n");
-	pr_err("addr %px is located in stack of task %s/%d at offset %lu in frame:\n",
-	       addr, current->comm, task_pid_nr(current), offset);
+	pr_err(" and is located at offset %lu in frame:\n", offset);
 	pr_err(" %pS\n", frame_pc);
 
 	if (!frame_descr)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/aa613f097c12f7b75efb17f2618ae00480fb4bc3.1646237226.git.andreyknvl%40google.com.
