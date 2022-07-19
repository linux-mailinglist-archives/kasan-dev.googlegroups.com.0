Return-Path: <kasan-dev+bncBAABBMXO26LAMGQEJA3F5NY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id C2849578EF1
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:13:38 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id z1-20020a195041000000b00489cc321e11sf4800793lfj.23
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:13:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189618; cv=pass;
        d=google.com; s=arc-20160816;
        b=zCy9Z3O/JmWP7Dl6BK1nCHKscksRs43iCVEBE/bFu8TIoPuOoM0rbazfoR3Gq/zaZG
         Z5JbMUZvJ00A13SRAxnroxNTr0vk1E14BNlPLOpeLrrlPjATHPH5O9bI7byG5kD0g2Pl
         gMHNt+ZjhtgDIf3nreHhqPLenMmFpWHeyQnPm9ZHnnfTuKW45rwG3baHtWx555pFjvgo
         C779CMvqRBCPpyHyBKLSN4qLdBoHOS1P2qRq9jbYlfH1+ZmMVMSREuaVoFzaLwp07wok
         lbXe3l70yrKKSmxLYlQ9vJqrM5wIpzh9LG8UyF3cvqx7Cb0a6hMRs0NsbvikAsO9bzZ4
         iyKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=f4cs5Sn69yJm1tzlkJtd8babVRtEn6dF0rSWDHgRlvc=;
        b=KTgwthBw98DM765e12xN06Obn51XLZPVwiX2TfcBmNyGuoeOzMWFGUbLpoNkAXTTQ1
         js4S8JUDCtqybDrPYNgc2ZlCYmPcet0ntO6v+GVnfv+OVRP8iQN+t++YoawzN2c5U4Ei
         VEvvIhzt31p9g8i4zTeoq1n3i71ud1wRXIhQY9ZgxrLX0iu7OjCMmOaBjS6nFHOcBPM2
         lkW/46Vi+jIWo5CwWwURZKRclCkwxEMi1Hcx0hwZb20AFgPrGal9Xfw+Wq3Xb+3jwBpp
         9xnwsj1aTbgWv8vWeQq0N87XgpQ+cGy/s5EErhv/M5t1c+mC3Y17PAZvpfLDBB8PyqKW
         +kGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Hz61K3OE;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f4cs5Sn69yJm1tzlkJtd8babVRtEn6dF0rSWDHgRlvc=;
        b=NwzLoZMQ/XCIJmg5hoc7g0BPRbADv+cNyoHfSUwIFWj/17IIAr6aIVfB2iD9FYvA0u
         f220slLezNHYmzYjSQPMMflUjLBsMxMtJZqiT56S1jYTOn3E5hdh6vWsm1Tgm2LgA+7Z
         TKzY/GAnyK5dr83TRtKVb2yyl4Dn7vzHGoxYegwK+9Src24lOb9RFXUiYfCmPASUzRll
         27R51H4qoI7/Vzu8RS1b5yoD7Uo9fiN7AwsBsiGzUYRPwjAjMTk2dlNXx7AvNPVnAQS9
         rPFoe+7brfUCZBUc250sDRolVei+KcCEyesNYdrxRTnMlFvY66/3BW0rVoDynqqXytJY
         JjrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f4cs5Sn69yJm1tzlkJtd8babVRtEn6dF0rSWDHgRlvc=;
        b=dYmlESjEN4uFnp0ysHOZfe6gOmAb2bYYEALonA7E6mM0fyUH8Hi1RvPkSJbyTBgH9X
         sLUJ1FJT+M28s6re8K/X4H4J2E0ctmFCZLo3STIREjgbCaWlfrPAq/2guX6qCe5/aq8S
         MRaVf+SKfaG8wvP9w91kijtMHBwIsEH4rAsY/TZ1+altWs7vcnobsquSnQm0o+I4PbHv
         IPNFolzMaipyKXjpjzjE07J/PQUL9njfyY3fO7atfzr7y5vo58G5unpjJAgMbMZ2lHW2
         35lHhGMiFMPRBaKU7JXV1J0HQoA5KbdCCYw0TMWsNrhSa9UeGe7g2dnSScMjWbXNYH6p
         +LZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9zp0090LvzKwsCECzUXWbPi5vxFjphPAxdfMu7A0b7trmoTrgV
	gw0o68/Iku/Jjxjlc1QAegI=
X-Google-Smtp-Source: AGRyM1vHtDhxrK72NgQAYAQvZKc9iLJIPMOXW2R51wfqbMs4KfWULHsWqZi7sfAj5Y35RS3RIY1E+A==
X-Received: by 2002:ac2:4ed0:0:b0:48a:219d:4e3 with SMTP id p16-20020ac24ed0000000b0048a219d04e3mr10499211lfr.137.1658189618351;
        Mon, 18 Jul 2022 17:13:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e14:b0:487:cd81:f0e6 with SMTP id
 i20-20020a0565123e1400b00487cd81f0e6ls1663406lfv.0.gmail; Mon, 18 Jul 2022
 17:13:37 -0700 (PDT)
X-Received: by 2002:a05:6512:238d:b0:489:e42f:ca04 with SMTP id c13-20020a056512238d00b00489e42fca04mr17423122lfv.475.1658189617567;
        Mon, 18 Jul 2022 17:13:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189617; cv=none;
        d=google.com; s=arc-20160816;
        b=SXLGAMMthhdCxbnJvPMoMTD6FljJkjMVMPoTTX/LHe9qZt1vXpLBNP+iFp6YYQffTo
         fe/vIvD5peW6I8pm0blGX5EiiZ6u/HM1ecl23rDo8q6Egs/S0QEofjuaTM8yBAAxT9IA
         0EGsN2SDWvQ8dK/ObYkDbTwshEK2As6TjNGwEyi0hU/kUL092mlrzCgNwUiGtbBpyWHw
         vlRdVS5wX65HIU+NDt17i0Mvd2ozYN2iyDtmSgUo9mX1AJ8pj+D/4H2gBfRzAoVsuB+R
         9jxZBZ83xY2tNbBXFDPzA0bxaTDXDO7qz+C/yirGcuK/XRbkdlzSW+g2EqMzk6KONTwf
         5Njg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1v1m9FmRS/rLhFe38ENkOT8DlGvSMLAmXg64oTGrtEU=;
        b=roSKANyCX31AbXGtjzvb8L/7z9Ushyp0kivyQmgO3WaxUF9y5ZjmmacQ5qqqLedO9G
         6YLJ9jRy3+ZlTifIa1VhEXQ9IIlAOI0bLgSZlrIXrU3rv/eYyJX3QrUQRzDRJ1L0k76M
         VBtYKSsYQIdaU4Sa25k6Gopp1WDFcs4nALp/2pne9/5GYurUlYTyG1WEf8v/PmYh+yIQ
         FSSXa+/Q0oOO84KgNnOfrgzARIF71VRLwJRNHlmVArnenB+c1MiFM6FieT3y/zBHxFKk
         h9xVr7814nEQm523n90D8ihbzpAMpWbrrStxxed9ck5wD7plzWL6eyYxL/gnrNhnek0Q
         5a+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Hz61K3OE;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id g7-20020a056512118700b00489d2421c05si402773lfr.4.2022.07.18.17.13.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:13:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
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
Subject: [PATCH mm v2 22/33] kasan: use virt_addr_valid in kasan_addr_to_page/slab
Date: Tue, 19 Jul 2022 02:10:02 +0200
Message-Id: <d26fd9de4a19b0021451fdd35897efbf5acae2e5.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Hz61K3OE;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Instead of open-coding the validity checks for addr in
kasan_addr_to_page/slab(), use the virt_addr_valid() helper.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- This is a new patch.
---
 mm/kasan/report.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 83f420a28c0b..570f9419b90c 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -208,14 +208,14 @@ static void print_track(struct kasan_track *track, const char *prefix)
 
 struct page *kasan_addr_to_page(const void *addr)
 {
-	if ((addr >= (void *)PAGE_OFFSET) && (addr < high_memory))
+	if (virt_addr_valid(addr))
 		return virt_to_head_page(addr);
 	return NULL;
 }
 
 struct slab *kasan_addr_to_slab(const void *addr)
 {
-	if ((addr >= (void *)PAGE_OFFSET) && (addr < high_memory))
+	if (virt_addr_valid(addr))
 		return virt_to_slab(addr);
 	return NULL;
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d26fd9de4a19b0021451fdd35897efbf5acae2e5.1658189199.git.andreyknvl%40google.com.
