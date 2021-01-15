Return-Path: <kasan-dev+bncBDX4HWEMTEBRBE5NQ6AAMGQEHRJFI7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 609202F82FA
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 18:53:24 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id f3sf6435031pfa.13
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 09:53:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610733203; cv=pass;
        d=google.com; s=arc-20160816;
        b=fy5XwKhaYYCHGP70sfaI2b4sl7qOr6jGr1I9X9jS9gK2piudrJT5CFDUHDhGRWBMMP
         MJaS3eMAYZCmTkTmjmnoVSKYvH+l6BqyFU93YMdXqok1kVM2eXayTNm48GaKSXf303Xj
         YFP5b7Gm3RqUrSBHBR3N3kgSAIC6SBvyJHc7Rn2BjpCS5sDpu8KrQOwlmKfB+krtXg13
         Pa0m4fdI3FuMdZeeav9r1SVMvcAZfeTq+AaXlby+J0yAe8tG0hDH/Yrp6ivxXTl0Jtlp
         1pNHtq3tebP+rV7JhI9sOxKqIPAFMTqKL9jj3Z3D9KI/n3kb2JRQ6XU8wkH94Ox+49eJ
         /FcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=rH89tDkyxMzW0mZo+olxOjZJdBa/sLnPE2aKOd9Xkkw=;
        b=L9UYw3HIuT7OtxET3FSEfp6oxmQtNDP8GZ/Igq7WGkpBH6mom+ME47UBQGDzHnh2Nj
         bTQkWff8IxHixeH0Hlw9876eU8V1j8+G3f1i+avu5Rv2lq55VvA2gfRt9VSFhEKpPLz7
         ujbQ80ZpKLdCbk6L/KPsojsh/BkTEOQ9luiYss/SE4cuwXX/Sy0W49XF85ywiL6bvBXb
         H7UCt4iTQLAaMGg9IgW0o8dHjp4QfEDFNTT5powaZsQUv7oTsnDEsexMaFx3lAoAq7a9
         vJmU7ERN46WsjwQPrSHa6Vvk3qOXzH5OWgzuutJM8nc61pqxEy0afyJP2TR8cZXPGuwW
         MVhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oOLTb6iX;
       spf=pass (google.com: domain of 3kdybyaokcuwo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3kdYBYAoKCUwo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rH89tDkyxMzW0mZo+olxOjZJdBa/sLnPE2aKOd9Xkkw=;
        b=KKXYdJORBWAFgR+xeWd2fjjzG1Yqra1HwLuM8rSuLrVjqdf5R7u+guYpMwr2ifgJzC
         XxAMLxwA8fPIU/nkZ4Gi6Huq6s8GJ1DCKXM6+doE0b4wvDI0tEUttYCsSTFX4ppQQ5fy
         zfmkN7Gb4AnKdVor7GEdwHNYlQ7WdM11dL/XRYkPhvstXBE2aqbZIM8pzHqBv9tcf34g
         jOqmGGgmuP3w72ePdYYfEFOyHlL+/Ota4B/RNrWTtRHRjqhNa/lcmrV4zgPqh3NRxKaP
         blz0ofD6ltE4merloTPNUeWg4Ie8r7V/ieaZA4fdN78+29S1Pn2BKwUFl6pwQOyzWiS7
         Cfuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rH89tDkyxMzW0mZo+olxOjZJdBa/sLnPE2aKOd9Xkkw=;
        b=AM0Vd4gTdYzy5mkSrZpAVZ+ez85LaYBxpifUK/MzMJKGX4br8b1F1/Q4ONYkY+daZE
         E5pjU38NTxtpY2M1Kc2FzkumLM9xcsNefsyujcTlpGfDSnOksXyoza6gaBZ+L4E33SDR
         UQnUKjQu+5xLdkv74SrKp+SyBqe6AOQtub8Ng5Nue5bUuhoqRlTIhfLaF52RALcd/JgD
         gowftyWdmuZTF53hfltI/SsjIrWKRbJyyjO7exaV6rA6b3x89K5rEXjqatfH7JTWpU5D
         QovepYXJAnK8T6o3C2qJPY+/IoC3dDiFljNz74P9HaYKKyb5LcULdUCsM3/hyxE2JI2t
         couA==
X-Gm-Message-State: AOAM530xh+4jvSh2mUAwGKipXNQmJ0GMZvlHeViMX/+xp6XTclfE363l
	d+YKImCkcQwSNyRgilPRIWU=
X-Google-Smtp-Source: ABdhPJwSmddWwy37glgLFc6TqWirWiV8e1M8ByD3Td6Yz9IwQLTShqV11S2CuPmTDJt1wNYfbAUBlw==
X-Received: by 2002:a62:6d82:0:b029:1a5:a6d9:c907 with SMTP id i124-20020a626d820000b02901a5a6d9c907mr13626856pfc.69.1610733203162;
        Fri, 15 Jan 2021 09:53:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ac0b:: with SMTP id o11ls5008590pjq.3.gmail; Fri, 15
 Jan 2021 09:53:22 -0800 (PST)
X-Received: by 2002:a17:902:7887:b029:de:7866:dc2 with SMTP id q7-20020a1709027887b02900de78660dc2mr2811253pll.64.1610733202641;
        Fri, 15 Jan 2021 09:53:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610733202; cv=none;
        d=google.com; s=arc-20160816;
        b=JveBuQkEzhPkqDvw14Xc2XYVfn5cSGiKX/omp7dpQpd6RHfu9z80se5QaytnMcdWVq
         NZcveIt4BG7jV6NzG1llkEGd3g2j6Dg/YHcupqC1uz4yBYLh+FvCnmpaKQyLs6w/jcG5
         1U9m6gNZBgyDpvzSjKp7BI5/75bTdbQfACTMWN/7gd4c8EupwgWb8//Ehq/79WfkByyB
         RjagJBNmpMNFzYqe0SAgbPz75v8KFqo9NqHWEWNq7q816A2BpwpwcdFrPgEoumj7L9Qs
         hjTgHbyycG0OolYB7IPwtwvBOsIgTv4z6zCftAEvF1SV4MEe6pWxTDlT+ARszVlmZsif
         PyAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=BYOOBCCudRU7Lchp5NpxZrw19s2hqbj4Q5eYKa3nns4=;
        b=sVmPO0zsVow8CoFn66+jqgB9NOft4jgoRLDTVp8qda7HO/vc+OWb4RhfcssRYSy+9s
         3BB2IVr9CkhO+GWw8pOZCWjKYgsdOuuofRLulf0z/x32PFUb5/eb4r5G5pwGSEGjaafS
         b1gbucYoPyl2IZJPjhRChkfe7jbJjxp0BDjYLd2ThQfqBUKB1r6w6ZDEMHTryzMcZhHl
         jMvxi2ID2zmGzqtheNDDt/Lor2Fl50fbj+PKVz2Rvyz0jwfMnywwfxFu/pELbMOBgAQd
         exe6ZVvzaFyMOoWaknsJxjaI2p/k/v0JyKbQXIg2+PHKPth9X9Q3R8XGkDsKNT2/Rroa
         bQ9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oOLTb6iX;
       spf=pass (google.com: domain of 3kdybyaokcuwo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3kdYBYAoKCUwo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id c2si704200pls.4.2021.01.15.09.53.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 09:53:22 -0800 (PST)
Received-SPF: pass (google.com: domain of 3kdybyaokcuwo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id t16so8386239qvk.13
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 09:53:22 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:5188:: with SMTP id
 b8mr13230051qvp.55.1610733201718; Fri, 15 Jan 2021 09:53:21 -0800 (PST)
Date: Fri, 15 Jan 2021 18:52:46 +0100
In-Reply-To: <cover.1610733117.git.andreyknvl@google.com>
Message-Id: <9cd5cf2f633dcbf55cab801cd26845d2b075cec7.1610733117.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610733117.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v4 09/15] kasan: adapt kmalloc_uaf2 test to HW_TAGS mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=oOLTb6iX;       spf=pass
 (google.com: domain of 3kdybyaokcuwo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3kdYBYAoKCUwo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

In the kmalloc_uaf2() test, the pointers to the two allocated memory
blocks might happen to be the same, and the test will fail. With the
software tag-based mode, the probability of the that is 1/254, so it's
hard to observe the failure. For the hardware tag-based mode though,
the probablity is 1/14, which is quite noticable.

Allow up to 16 attempts at generating different tags for the tag-based
modes.

Link: https://linux-review.googlesource.com/id/Ibfa458ef2804ff465d8eb07434a300bf36388d55
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 11 +++++++++++
 1 file changed, 11 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 2419e36e117b..0cda4a1ff394 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -382,7 +382,9 @@ static void kmalloc_uaf2(struct kunit *test)
 {
 	char *ptr1, *ptr2;
 	size_t size = 43;
+	int counter = 0;
 
+again:
 	ptr1 = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
 
@@ -391,6 +393,15 @@ static void kmalloc_uaf2(struct kunit *test)
 	ptr2 = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
 
+	/*
+	 * For tag-based KASAN ptr1 and ptr2 tags might happen to be the same.
+	 * Allow up to 16 attempts at generating different tags.
+	 */
+	if (!IS_ENABLED(CONFIG_KASAN_GENERIC) && ptr1 == ptr2 && counter++ < 16) {
+		kfree(ptr2);
+		goto again;
+	}
+
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr1[40] = 'x');
 	KUNIT_EXPECT_PTR_NE(test, ptr1, ptr2);
 
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9cd5cf2f633dcbf55cab801cd26845d2b075cec7.1610733117.git.andreyknvl%40google.com.
