Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBBG7VOAAMGQEVSLF4JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id D1B26300741
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 16:30:13 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id p21sf4284369qke.6
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 07:30:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611329412; cv=pass;
        d=google.com; s=arc-20160816;
        b=Huw9OUWNEBpSp3Qgsq8wZvRYXy/7vS/Sf2mriAAr0l4e7L/S943gIoJJPSOSIORrT1
         7GZXCERb5RLPnosIsf9VreEJ20TZoCRVmy4M/mvF2rMwNHNgv5CJ+Gv5PP25KRYWzNP7
         1hRXn4naxGihalyexTfh+6WzjOcTabAMyCfef4CxHPjsGS22cLxhL9iOMHz2fTMSr33N
         wEv8X7r4pp1FRl//O1GzbAlmU2EEJ0VuZjPnatxBybmJ/R0nu+zcpL1SKofMyZM1/iVe
         AkuEJlNW5CmxRiqHia6clWkW0uVIzJmkBTuBcgnDPqfdVrVF1GMU2n1rXhXf+ItpPhH7
         wZdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=qsG3vj/s9lkaS5ubkdzn5H6c+UoZWu79g+Kvl1uyyL4=;
        b=rPGfvo/mF9YeQFTn5eU/W8Qw7+/iOVpVWvgyP5WMZdqqDBJKABqOgn/wpYFh88m+rh
         Va3EM2xL0+qKxv49PYIJ/62tLYyNR1SjnGGgj4QLJIAmpeWdZTNrRQ+6jx5PzgsYt/rj
         AfgbSf8M6T1I2sudq6BQnTBZtiBKTFo0lH0l9C2xAMPeSmoEz9XGKHO3oGCyxrSaJgM2
         DTT+GOcJ1sc+oLfPJeWgvvZg5lk3cHtN8y7UvTyHh/Keqb7X+wL3dALCwP/QYBJVkQWo
         ygq2NwTmiEpi5082r/JW23xuCimb1mftKOUu2vuRz27jFcyMNnSNUBYfvbqlpfU5AlZP
         Ph3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qsG3vj/s9lkaS5ubkdzn5H6c+UoZWu79g+Kvl1uyyL4=;
        b=DJflZSLVuwAJyneQ6S9dRu+o6LOzViZNmsmONWdwEsV+hs3w+kacUmu6QTOsll10cX
         Zc69/7A8vdU57cP41+UYK2/o8GVaz21LtSUG+oKmStwgGHQHZTCmNWsvM3j2OtIKQHq1
         AmuC0M6W6iLdLN0SLYXet3Awjtdf62AfeKtpqtXtVan5YgfKn9Erqor3KAdU6q0V4bvr
         utYM60Ddo9zanjXPOtZw0LQahfGOqO6f/Celd9WLoW9T+ZTO/OKnDcEpBMu/g0F1KBRK
         JwSSQCeEY5KTqj9toLVNjYVC9Mk8DCSO0Wii2Nonqcwavam2EZBubYBdnznGX6xJECZ0
         2bEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qsG3vj/s9lkaS5ubkdzn5H6c+UoZWu79g+Kvl1uyyL4=;
        b=ls43GvIROEBHHCQmVw9t7GNe1VgkYDJOpiDk8rgZHZr+EmrfNNtlcB3jM9nWCHkECC
         txt3/LFXpoliKSE/sK1RPls6oIrZB5ImNp6dfpwe94qsq0LHidYsdp0wg00YavZJyzAL
         ZghFPNKQoPCgoEslVX0AaeSp+Imzlbe6NIZb5wCCf/z1lOIt7O0znbttgIyxFzzK8gz7
         xjE4K+R4R/vawz/UgYpgppz3W/kVZmM+ZcDafbKIab85yIOpEzuNpHrN0dsu7hCi2W2Z
         unTwoj6PjdhGJH7P5igrJ4BcFlil4rZTBovVnNd6dS/QxLY4ULRcCAsWy4QXhLXB3SOG
         ZqhQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532PJBJnm6HTkRqeysNgRKvxOwGYHcvEW8HUtLDhoRrLPz9Ig0FH
	VRyUhuKeum+9IygnqkFGCYU=
X-Google-Smtp-Source: ABdhPJyiiMbAcZUFh8ZevHV3YvnYotV7X+ufNf6aQlkxgBOE/2xBTgTUyPVHdD+BL3O0Kzk1tZT+gQ==
X-Received: by 2002:a05:620a:788:: with SMTP id 8mr5270530qka.224.1611329412861;
        Fri, 22 Jan 2021 07:30:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:2c1d:: with SMTP id d29ls452727qta.10.gmail; Fri, 22 Jan
 2021 07:30:12 -0800 (PST)
X-Received: by 2002:ac8:82b:: with SMTP id u40mr4823896qth.332.1611329412432;
        Fri, 22 Jan 2021 07:30:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611329412; cv=none;
        d=google.com; s=arc-20160816;
        b=kI/bIZTde0JQfnxUKPQpnRYXewY3JzmQ4hSVudFzGOqbtaRxhgsqfKGOkPbrLGi5ET
         Xus9+G/4MjHefJusuc1Rgu6E+VB2+Xdr/iznftT8mL2mSLpWWvRs6IN6cVss9OVhZ0E2
         XCaF6lk/9uGgXzmxYzoigNxoWDbLITNZ1RCajfoz3yrTjqjXwnIBv/7trPiWRgc6F+5V
         ZvZpFtth6U/tpzSDtnWiS1IXvO9kLEUmMBupY5/QmlWYOBz2pWBkkjFZ6QtuS49fQr/U
         Pv7HMOo6pQYESRNZVW9lYrLxhdEmOkXACLn51+OntP7ev62jiANwAnLFNHBzKzs8qs5L
         Af9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=pTyS9M5awAfiHl0XJQpXytx75ta+LXCd7XTpXjlAMAU=;
        b=uFCwJWLCDr0J2/ego7sEMuEGEAJd+gS+drmLKE0r17m7/O5x5fKNRR4OPD3zOdm5+w
         yrzfu/TIzvge3eCT5WISdOJZi1gRJve7CIGdEN2jYRJJl8phGSlkktZq1SUoiDFGN5Bl
         +5qUu/idNH9MDVuc4l95D5R3e2E7rUTqUlX9cznks3yjztVOtQimwgJSXFwhT2wEo9O5
         mum19nhs58e0xzUp6IXxmss+E6T3dydFh/PAk40M2CbI0U40TO69yMX9lfDkqBL3kjgX
         2+4D3ZR5jjq960jQ+M3itC8AHBaHDgPVoTFiPCy+VIWbjQcKqLlfOZTr0vxvrzIyqRBv
         3OjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id j33si740856qtd.5.2021.01.22.07.30.12
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 07:30:12 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 8ACAD1595;
	Fri, 22 Jan 2021 07:30:11 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D9DA23F66E;
	Fri, 22 Jan 2021 07:30:09 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v8 3/4] kasan: Add report for async mode
Date: Fri, 22 Jan 2021 15:29:55 +0000
Message-Id: <20210122152956.9896-4-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210122152956.9896-1-vincenzo.frascino@arm.com>
References: <20210122152956.9896-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

KASAN provides an asynchronous mode of execution.

Add reporting functionality for this mode.

Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 include/linux/kasan.h |  6 ++++++
 mm/kasan/report.c     | 13 +++++++++++++
 2 files changed, 19 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index bb862d1f0e15..b6c502dad54d 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -360,6 +360,12 @@ static inline void *kasan_reset_tag(const void *addr)
 
 #endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS*/
 
+#ifdef CONFIG_KASAN_HW_TAGS
+
+void kasan_report_async(void);
+
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 #ifdef CONFIG_KASAN_SW_TAGS
 void __init kasan_init_sw_tags(void);
 #else
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 234f35a84f19..e408e8c08a6f 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -358,6 +358,19 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
 	end_report(&flags);
 }
 
+#ifdef CONFIG_KASAN_HW_TAGS
+void kasan_report_async(void)
+{
+	unsigned long flags;
+
+	start_report(&flags);
+	pr_err("BUG: KASAN: invalid-access\n");
+	pr_err("Asynchronous mode enabled: no access details available\n");
+	dump_stack();
+	end_report(&flags);
+}
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 				unsigned long ip)
 {
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122152956.9896-4-vincenzo.frascino%40arm.com.
