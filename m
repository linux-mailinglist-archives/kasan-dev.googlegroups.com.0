Return-Path: <kasan-dev+bncBDX4HWEMTEBRBVN2QKAAMGQE5QS6SIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EAD02F6B1D
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 20:36:55 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id 22sf5316828qty.14
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 11:36:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610653014; cv=pass;
        d=google.com; s=arc-20160816;
        b=f+P0c8Bz9refhUGv5dgeni5g+sz6ZyVhdKoCJWpD/arA+e+i497vmcBmBeNlZXSLIn
         kmWUZM8o7PaHQCiOBAt7jcp1CzueZZGX5l5I92T+dd9gVv8Sk/QdYGXZ1kV0cOso7rI0
         ALncCSQategsnmjGiqX01hxmN6CMnJ5HTFh+qh0SvEnpxCcdHh2Oa/I+YnUCcXG3AFq7
         GBnY6FlXs9l3fFCh1EfUIfWMSyOXRlbm2ltrfi/0MmRkFsQmvj2/7uM5aZfsb49A4biy
         cu81WWJFe5Ot52j752z0Gihz7qnq6vZm8/ivh452aWXN7g8ghy6GCOO4ZYLdhUXe2Kgq
         7q7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=07sk2XzQqwLxpZOoKgKmwU7nepSkKzLrvSnRd+LrB50=;
        b=jeHIoAdIjzROanach6aMpJjvOSZ7zRu47/A08Blzh/C7TeqEg/rW0EdRSYF4Xk+Kaa
         DISAgpKq/HKN6CHgW9PGj/4TS+6X32/nrrfMGRTdEwDgrNHwS+qngRt1Vm+iogoeKdrQ
         kQz9x00grBxrYWH3pMCXmBpFNu9JP8RQIgg7DpGltnc6pJFmQ30EkLkfwYIPITpOJdtH
         VGARUzGYLLvc4zPTOtbLODBZfXOwedRLl57cMUIcq/PTTNGY2ME3XjD1/wCFnvClEmEP
         ftG/+GU7AbnLoD9xCa0BYkZ8w9w4Q57rdU0UEEHiIeBbs5bhGNsaYunafopS6kBinLjC
         yzdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eTZNHRFw;
       spf=pass (google.com: domain of 3vj0ayaokczc1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3VJ0AYAoKCZc1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=07sk2XzQqwLxpZOoKgKmwU7nepSkKzLrvSnRd+LrB50=;
        b=pzkRNb621emylMuYoALXOhnxjYZeV+Ou/qhPpufl8eC7XPvzqtj1Qz/i4dMVpvQ2kN
         HwHN2CLqn8Sf0z53L2k8UgZVog5v5G3T3wCrGbQfSOU8mFJVK3zBYd4GHEjbm/t12143
         G8kg609Yf6lq7YPdgZPmiR9FPNfF43xGJMrB2HV22jrI/xpHuOnf1BSfOwSGx6X3Njdb
         ePlGrYPVVvVXJOYIHFw+BgFQsb54KU3j4Ka0Qt5nt4BnNE1DotDFZMrcOtrArnK+el09
         gWenjrWFrqXmixCzIUsT/AO/fhzgIZKeQgManUuOeANd74PG75PWok/oA0VCqznv+11u
         m2dA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=07sk2XzQqwLxpZOoKgKmwU7nepSkKzLrvSnRd+LrB50=;
        b=MiWTmeOjOnUWTgUtrvKghpzOK6twDe/k9/NPoKLnX8TKloAoA9c+kXsioJvND3eQaW
         0X10zwQ8k6EjQkllvaez9AGc8OQus3NTFUiHfWZGeyyJtd2XyJzZSa+Its34k3ORm1BR
         zLAx7XmYH8iiaYILlVcLoPu3A94IrruICg8ELY1Vx6zJRx8sGAzJRnNj0wfbQEyW8wpR
         znfeGew3k6+zXt6pAeQomEal47N2rmqI0oDAi/3Z551975CgvJCRtIQfg02FB2oWvYWh
         WDLb27zlYXNS1cdj+CC1k8O8yN50QlEMLFpbjE67cHwhma021ZhRdW0X3bKmvPG2Fx+f
         Kbzw==
X-Gm-Message-State: AOAM532C6HqfHBFWZ0IFXPtoOxt+x7ykHQ9OZTm/DZk695r3YicmY2NR
	4dzHajCBSp+Aj1dx/k9QBuc=
X-Google-Smtp-Source: ABdhPJwmxBBN85Q11TuN5SnJub4eeRO9FodbfaM55tIJXzUcpB9i+YQ5nqFrg6Qj4uOZ3nes6W3xkA==
X-Received: by 2002:a05:622a:4c:: with SMTP id y12mr8721432qtw.190.1610653013780;
        Thu, 14 Jan 2021 11:36:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:26c6:: with SMTP id q64ls2993440qtd.6.gmail; Thu, 14 Jan
 2021 11:36:53 -0800 (PST)
X-Received: by 2002:aed:3fea:: with SMTP id w39mr8494767qth.288.1610653013284;
        Thu, 14 Jan 2021 11:36:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610653013; cv=none;
        d=google.com; s=arc-20160816;
        b=Dkvr7qFEgKFjqLC1NTVCitDy8jkgU5SiG5sWZM2c3UWWuLzVi/JxPr8Ifi+7GpWNKY
         mtiyOWDtCwL+mzt/4J1RSjPPdAUg6Yi0LBanm6g7NfqGGsmtgxqOSLxuJP4VeCBJ18PR
         8cOc2ZlcqMP7D82d6MmJ5krOpv7ECt51LxxiKkM0vt+2WPdlWt4mOH5OAGtlxyWuGXoE
         c84hGOY0i2EhgfxYF+VhAtqZseex6vhT8rWoG0KoSiRadLZRbS5wxMMiixXWheqMdytP
         ItqwvFTQdXad4DuZZPzHvit/JMkcsIPB/pSkbx+SqSzqAr1m8I/pwWmIE7EEKQltaOY2
         lQkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=IeCg6Q6ax6zf9VJ+vRzVtCBhXruC0quH/SAPFfzsvs4=;
        b=L6p8d1Hwjc88rXyg7ESEq0yjZnCgCf4o4MPOG1U/Ljn0llIhse75ggAGE+pYPJgQxW
         El67q5ysBCXzUqSrIHoLFXBXZFSYLm5LrVWAjF7DeHtlQWnsno+QuN1gFXIaO7DFFFOy
         e2Y5yz/osj6ZmsUJBwrEc8gu098d7glGoR4Y5r7Di/75w2pOYq0LBeM8WSPPSOvYdc49
         cwEjFYLlWSEmqw86ePYVbBBWAUtgT90xev3IQL+Huk9MCAYUGUOB1d62yGg9J0uXzDgy
         QySEnr8IX2ZcNsYo6ZvpwwGvAvR3LwlFWfCfdSR+9aHagkaMXE0hiX+tTT23BO7rSHHx
         E4Sw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eTZNHRFw;
       spf=pass (google.com: domain of 3vj0ayaokczc1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3VJ0AYAoKCZc1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id t2si384712qkg.0.2021.01.14.11.36.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jan 2021 11:36:53 -0800 (PST)
Received-SPF: pass (google.com: domain of 3vj0ayaokczc1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id c14so5331708qtn.5
        for <kasan-dev@googlegroups.com>; Thu, 14 Jan 2021 11:36:53 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:f08b:: with SMTP id
 g11mr8742547qvk.7.1610653012977; Thu, 14 Jan 2021 11:36:52 -0800 (PST)
Date: Thu, 14 Jan 2021 20:36:24 +0100
In-Reply-To: <cover.1610652890.git.andreyknvl@google.com>
Message-Id: <73283ddcceed173966041f9ce1734f50ea3e9a41.1610652890.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610652890.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v3 08/15] kasan: add compiler barriers to KUNIT_EXPECT_KASAN_FAIL
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
 header.i=@google.com header.s=20161025 header.b=eTZNHRFw;       spf=pass
 (google.com: domain of 3vj0ayaokczc1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3VJ0AYAoKCZc1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
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

It might not be obvious to the compiler that the expression must be
executed between writing and reading to fail_data. In this case, the
compiler might reorder or optimize away some of the accesses, and
the tests will fail.

Add compiler barriers around the expression in KUNIT_EXPECT_KASAN_FAIL
and use READ/WRITE_ONCE() for accessing fail_data fields.

Link: https://linux-review.googlesource.com/id/I046079f48641a1d36fe627fc8827a9249102fd50
Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c  | 17 ++++++++++++-----
 mm/kasan/report.c |  2 +-
 2 files changed, 13 insertions(+), 6 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index ef663bcf83e5..2419e36e117b 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -68,23 +68,30 @@ static void kasan_test_exit(struct kunit *test)
  * normally auto-disabled. When this happens, this test handler reenables
  * tag checking. As tag checking can be only disabled or enabled per CPU, this
  * handler disables migration (preemption).
+ *
+ * Since the compiler doesn't see that the expression can change the fail_data
+ * fields, it can reorder or optimize away the accesses to those fields.
+ * Use READ/WRITE_ONCE() for the accesses and compiler barriers around the
+ * expression to prevent that.
  */
 #define KUNIT_EXPECT_KASAN_FAIL(test, expression) do {		\
 	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS))			\
 		migrate_disable();				\
-	fail_data.report_expected = true;			\
-	fail_data.report_found = false;				\
+	WRITE_ONCE(fail_data.report_expected, true);		\
+	WRITE_ONCE(fail_data.report_found, false);		\
 	kunit_add_named_resource(test,				\
 				NULL,				\
 				NULL,				\
 				&resource,			\
 				"kasan_data", &fail_data);	\
+	barrier();						\
 	expression;						\
+	barrier();						\
 	KUNIT_EXPECT_EQ(test,					\
-			fail_data.report_expected,		\
-			fail_data.report_found);		\
+			READ_ONCE(fail_data.report_expected),	\
+			READ_ONCE(fail_data.report_found));	\
 	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {			\
-		if (fail_data.report_found)			\
+		if (READ_ONCE(fail_data.report_found))		\
 			hw_enable_tagging();			\
 		migrate_enable();				\
 	}							\
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index e93d7973792e..234f35a84f19 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -331,7 +331,7 @@ static void kasan_update_kunit_status(struct kunit *cur_test)
 	}
 
 	kasan_data = (struct kunit_kasan_expectation *)resource->data;
-	kasan_data->report_found = true;
+	WRITE_ONCE(kasan_data->report_found, true);
 	kunit_put_resource(resource);
 }
 #endif /* IS_ENABLED(CONFIG_KUNIT) */
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/73283ddcceed173966041f9ce1734f50ea3e9a41.1610652890.git.andreyknvl%40google.com.
