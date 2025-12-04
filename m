Return-Path: <kasan-dev+bncBDP53XW3ZQCBB4VNY3EQMGQEDOX4UNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D598CA3F45
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 15:13:08 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-477a73607b1sf933705e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 06:13:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764857587; cv=pass;
        d=google.com; s=arc-20240605;
        b=dz5qjlD7I3RMx4TVvJUb/A925fS4MYCEy4d6uIBIaMcTLQHXoW4IZeXAklUtze5PSf
         3FMn3U4u79e7USC0Zd3422BmFIwNIl3Qn+e+k+K57HRIfXrTpyB+py+p0JfZH+BHAhjl
         wJ4T1VuN9hn7kl3q8xQtZPnomw4YGofKYpbCDmivnCpWwUk0J1IVPNVxy5NHTCY5SgNE
         IWm3HAoRiLqz2fbKNFmwpNzmwqoR7tSovnDGOZR9r9KPaxyDPhIGgu0wd3HMV0eyjyfv
         pDwQ87MuZk6ag7qwpiL09KEgfOoMyM/AsQ+pri2blG8H9vmjGtHuTwPbFHJZtXGgsMin
         LrBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=Uqcbk6Htlwd62BR6uEbUZVEtmAG9AUE97y3O7NIqZZc=;
        fh=DC/7r8fT51YOSovKVgeXbBkyIlmOjXG+5xBvM7i7yG4=;
        b=GbC0jfl0EUf3qEa0N1rCWq42yMY2g7qkDafS3Zz9wlcItkM8LqmrmtOfQW3ouGfaXy
         qOhVctM0XsP1vg+GkjoKOukS8AsQfd6DsYSgX3AFr7FStNAhfhVwdV0N8UE652hdB4VJ
         RWP27AAC8LubjBsMQn0I+mcoGtUG9OZWqxFWYIMG9fEKVnvnqB8cfS+x2Kwbg1XJYkkP
         zAbYTzIIpzLs3iIQS8LWhh/kjhzQ1hHa1d18Nuo3N83PLhOOqi/brIrGyXRNefshyYvR
         zsWGrBxUHSdICxyhVf0uQJrGtjVuEjpJ4wP69aADaYR6380eNILOjC5GDi9Ur4epiJ6B
         1z5w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Gn3gxJwb;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764857587; x=1765462387; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Uqcbk6Htlwd62BR6uEbUZVEtmAG9AUE97y3O7NIqZZc=;
        b=nDWRU+9WL4aSDxFENsG7ozLCcGta73gOYq08l7ZUioH1qvyp5N3OnG+kG1i8vkO4iw
         0hnYfm17ps9RdmLdzZpLg3z5512YhA3Y4aoT3EPLUWdDoXLEhV29Uwi8OCbIAAz05/zN
         /W8bpq221dqZQSWumVagKx2Yei6cgIKht8YsjoDYvD8D2gtOooir1reK1J9LMF+IPwTA
         ahWU+/qKp9uOT93Xykcs9k1op1HKpn/qcvZEGgvFcAiuDa219o1Y1+SYuAlXRI1eR1zr
         VitDsL5iAzu6teeBxe11mDJLWOpPM1kGzyVP6ZqMN1vvJybvmsie8s4JVSy4zWyRFAHk
         OZXg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764857587; x=1765462387; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=Uqcbk6Htlwd62BR6uEbUZVEtmAG9AUE97y3O7NIqZZc=;
        b=YV5VXVnZrP/ZJeUVwjnjzYPDTha2/kJmGHFf2CBH2pMVsXzT8beH9jbEB5ntq+19BQ
         Bx0s0YWkCBMNWxrOFZpQ9W+W1XYQgViSXbkqSUbazPZJz4Do/DbSdj7L/0xKlSbTIc3H
         wb7M4rdP3y5GRSV+MTTEfyKiV65k3BwnUUX12MQ9izcYLyS+isVzaEQaeMP4yfkwWO6n
         1/37ob3Re+StNIZdcnNh5cZwHgOQlKewVQjCQF+Qnd5avQ7t63pV1vVFHk0OWmIC2k3y
         eVnlnFLwNjav+ihqkA6s6GVKhg/CE3ZL8tcjymTvWJv4/XGlLsmSy5jyR/vB2r4378po
         JbRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764857587; x=1765462387;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Uqcbk6Htlwd62BR6uEbUZVEtmAG9AUE97y3O7NIqZZc=;
        b=pqV+8DPNFLk9nyNW26ESxelLQZnRi+XOA+LheCK54Z5i2w+3QTSxLvd+R9N5kcIUBa
         jCq0MLtZhEdwXApe44+b7sbii2YDnwAUDlgAVE+4YSDXPvJAu9+DvkS4++esZGLfwCWk
         5W1wfp3QoawAgWS9agCV/8maC8OY0TG4GFJJ2lSeZ7ULNWA7501lfWuWCoPUWfXiTKPg
         0h27aULFG9qDBVExnPsEkP/DFpPrjjJVBN1OoqN6d/nr9VK60J+YEvjjGnVo6MsR8j1B
         oEU/GW2dYb32sajbWqOpJCJi+XIC2LCbiQGnWNZ8qhBsoHt0RAty/al9B+5sXdsaKK64
         5yQQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUjLvJpA8owgfEgxwPFVvBRs5kSoHLs/skTmBUf6e8z2X88qpBw5yhJIHLdWUt5gouLFLCwiw==@lfdr.de
X-Gm-Message-State: AOJu0YyAHM2F6nmpRpLBQ9LEq9YgrscnsTv//QXrQhKUKhGDo0AmtgpB
	DFt0uwrmrVsBd1j18yJYk3Bxi1IzW5x/OPG62122OTfHgzob0DgPzeb9
X-Google-Smtp-Source: AGHT+IHPTr2goZgxp0Bl7RIyEQWIfQyq3FkK0EPZlOca0csAR5lbC9Ans9iTNZmnNig53pV7xHIRpg==
X-Received: by 2002:a05:600c:b8d:b0:477:c5a9:33ce with SMTP id 5b1f17b1804b1-4792af32c26mr33480625e9.4.1764857587357;
        Thu, 04 Dec 2025 06:13:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YRHyqJrDU3Wjks5rK5M1LJv97yS4VsI0lQC1RsQW2nLQ=="
Received: by 2002:a05:600c:4e43:b0:477:a036:8e82 with SMTP id
 5b1f17b1804b1-4792fb5ad72ls4682595e9.0.-pod-prod-08-eu; Thu, 04 Dec 2025
 06:13:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVjuDDI5qKcYAho99JO4OOwgIZI/fmVf82prqHdSgIURNwX4tAfFKmkJ33/fb8iMo8q/F3P0XniSSE=@googlegroups.com
X-Received: by 2002:a05:600c:1d1d:b0:477:abea:9028 with SMTP id 5b1f17b1804b1-4792f24418bmr32129355e9.6.1764857584481;
        Thu, 04 Dec 2025 06:13:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764857584; cv=none;
        d=google.com; s=arc-20240605;
        b=LSOd90vNvADWebLoTpr7OGswYYU8wDDlHFkMqlG0VrX7TErWrFqawb7R8T5Q0etq5p
         U5LyfqKSx6kl8qM7wowbuF2NaxDpk7+ZjENnBMj3iEmQAB1FXIK5K/cm8QZua7eRCIZs
         muFit4Y7KhS5fgBTHTYMwJcDp1T/8Xvs1Eqkk2k2/JCjY2tRbTXNj3oOUyI9kCzIiwv5
         dtdY9sXJKg1zd3eyIpEkW4BAfbIVkIqVXe/PZ7eOqiNeNQwKhBoHzy2jjpChpm3yKeel
         EpA8X0Io6rQ7+a/717P57EBzkZ5BDDnj+Kx0vxgmi+UhecZPzv/T2LLPrQD5yPGo40OF
         Z3jA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vvLRPmFVeFXL/FXUoH0yHVRGEwWvQKNGaG9SkVtG73M=;
        fh=QlSDWatTI+plH/R/vDMb1tOB01zHEHDBnwkVEsjlhqA=;
        b=AsVW9AGhpQFfWRrY2NjjNJC0aZDUoLNxiSuFzRyU/BwO9d340XReaDTXuUpdTH3sKh
         ZxQufCK1f3HOwCxZDPqSD5uo3DE91i02OJjTvlt9dQgSEfyiUotZUotAb1FbCGfWDFbb
         tBuTDSYnG1btOO/dDdetdygFXz+KwzxcmuAOgPwzQsjDCb8gtM6BDC2luyzyw2/QWRdj
         HT57u4U85zwdb+a86z9Tlv10IvHMRMycwuqZsMnOv57IBblU5/f5oRn04qdzFpVSTTmN
         l2LgaOUJCARcZ4c7UayvICZKqvHN+7bkPdBGO+g1ElN0NmQNQomhTL4KYv/UqhzW2NH4
         zsow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Gn3gxJwb;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4792afd0998si597625e9.0.2025.12.04.06.13.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 06:13:04 -0800 (PST)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id 5b1f17b1804b1-477b1cc8fb4so6997575e9.1
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 06:13:04 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVI004OKXJ7s5HqNfq0//Uos5f/hKwDZa3SpEFmaYdNtsENKU9t+4A9qB2Di+MFSsxT2QO/n5Q1cyY=@googlegroups.com
X-Gm-Gg: ASbGncu9Hc5Tgqvy9j1XQG6+KixcAFyJYwBgPWHtX2WCzqZ4hHUZ9TPzLv3U3jeTHIU
	XNhB2EVsl40RzgotnATFffTsNH84UZVj5l0ELb7AecuiuySX4hJ5oxoLT5vE3cJDvp6PhbBF/0n
	nSbyhRa7p6bHvOsLUia+ixIKskUO5vGVUURwaooOK9OOZk+tDNT78caqY2cs4yfHw2UEyFgdJtA
	k2j8iSG01OJ0wgMNQA2yLTmqqEgOD/3uJnAjdZAWSH47PjWehrJ5mb6KEsVBhZQpDhXkkvJEhXI
	Po8gQyz96ovn5twYbJrbJj9qOZKdRoZbUEPh40umSGaY4AWA8qAFXcxjnjfIHzLjplL4x0P2uqq
	vygBt8YJM6shx08zfK/3Ei6evofbauWK91rvh6FGlEMCFtAIk71LNOvSU3VvO7Uy8OgpBL98Sa/
	Gpnea5GtqDFWP6/FdK1FZ2rFp+jlb39IedWBGFvpsPMobBz01L+mWnmr4XZYKqWszUvA==
X-Received: by 2002:a05:600c:3545:b0:46e:74cc:42b8 with SMTP id 5b1f17b1804b1-4792f3860e4mr28572475e9.17.1764857583596;
        Thu, 04 Dec 2025 06:13:03 -0800 (PST)
Received: from ethan-tp.d.ethz.ch (2001-67c-10ec-5744-8000--626.net6.ethz.ch. [2001:67c:10ec:5744:8000::626])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-42f7cbfeae9sm3605808f8f.13.2025.12.04.06.13.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Dec 2025 06:13:03 -0800 (PST)
From: Ethan Graham <ethan.w.s.graham@gmail.com>
To: ethan.w.s.graham@gmail.com,
	glider@google.com
Cc: andreyknvl@gmail.com,
	andy@kernel.org,
	andy.shevchenko@gmail.com,
	brauner@kernel.org,
	brendan.higgins@linux.dev,
	davem@davemloft.net,
	davidgow@google.com,
	dhowells@redhat.com,
	dvyukov@google.com,
	elver@google.com,
	herbert@gondor.apana.org.au,
	ignat@cloudflare.com,
	jack@suse.cz,
	jannh@google.com,
	johannes@sipsolutions.net,
	kasan-dev@googlegroups.com,
	kees@kernel.org,
	kunit-dev@googlegroups.com,
	linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	lukas@wunner.de,
	rmoar@google.com,
	shuah@kernel.org,
	sj@kernel.org,
	tarasmadan@google.com,
	Ethan Graham <ethangraham@google.com>
Subject: [PATCH 01/10] mm/kasan: implement kasan_poison_range
Date: Thu,  4 Dec 2025 15:12:40 +0100
Message-ID: <20251204141250.21114-2-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
References: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Gn3gxJwb;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

From: Ethan Graham <ethangraham@google.com>

Introduce a new helper function, kasan_poison_range(), to encapsulate
the logic for poisoning an arbitrary memory range of a given size, and
expose it publically in <include/linux/kasan.h>.

This is a preparatory change for the upcoming KFuzzTest patches, which
requires the ability to poison the inter-region padding in its input
buffers.

No functional change to any other subsystem is intended by this commit.

Signed-off-by: Ethan Graham <ethangraham@google.com>
Signed-off-by: Ethan Graham <ethan.w.s.graham@gmail.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

---
PR v3:
- Move kasan_poison_range into mm/kasan/common.c so that it is built
  with HW_TAGS mode enabled.
- Add a runtime check for kasan_enabled() in kasan_poison_range.
- Add two WARN_ON()s in kasan_poison_range when the input is invalid.
PR v1:
- Enforce KASAN_GRANULE_SIZE alignment for the end of the range in
  kasan_poison_range(), and return -EINVAL when this isn't respected.
---
---
 include/linux/kasan.h | 11 +++++++++++
 mm/kasan/common.c     | 37 +++++++++++++++++++++++++++++++++++++
 2 files changed, 48 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 890011071f2b..cd6cdf732378 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -102,6 +102,16 @@ static inline bool kasan_has_integrated_init(void)
 }
 
 #ifdef CONFIG_KASAN
+
+/**
+ * kasan_poison_range - poison the memory range [@addr, @addr + @size)
+ *
+ * The exact behavior is subject to alignment with KASAN_GRANULE_SIZE, defined
+ * in <mm/kasan/kasan.h>: if @start is unaligned, the initial partial granule
+ * at the beginning of the range is only poisoned if CONFIG_KASAN_GENERIC=y.
+ */
+int kasan_poison_range(const void *addr, size_t size);
+
 void __kasan_unpoison_range(const void *addr, size_t size);
 static __always_inline void kasan_unpoison_range(const void *addr, size_t size)
 {
@@ -402,6 +412,7 @@ static __always_inline bool kasan_check_byte(const void *addr)
 
 #else /* CONFIG_KASAN */
 
+static inline int kasan_poison_range(const void *start, size_t size) { return 0; }
 static inline void kasan_unpoison_range(const void *address, size_t size) {}
 static inline void kasan_poison_pages(struct page *page, unsigned int order,
 				      bool init) {}
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 9142964ab9c9..c83579ef37c6 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -570,3 +570,40 @@ bool __kasan_check_byte(const void *address, unsigned long ip)
 	}
 	return true;
 }
+
+int kasan_poison_range(const void *addr, size_t size)
+{
+	uintptr_t start_addr = (uintptr_t)addr;
+	uintptr_t head_granule_start;
+	uintptr_t poison_body_start;
+	uintptr_t poison_body_end;
+	size_t head_prefix_size;
+	uintptr_t end_addr;
+
+	if (!kasan_enabled())
+		return 0;
+
+	end_addr = start_addr + size;
+	if (WARN_ON(end_addr % KASAN_GRANULE_SIZE))
+		return -EINVAL;
+
+	if (WARN_ON(start_addr >= end_addr))
+		return -EINVAL;
+
+	head_granule_start = ALIGN_DOWN(start_addr, KASAN_GRANULE_SIZE);
+	head_prefix_size = start_addr - head_granule_start;
+
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC) && head_prefix_size > 0)
+		kasan_poison_last_granule((void *)head_granule_start,
+					  head_prefix_size);
+
+	poison_body_start = ALIGN(start_addr, KASAN_GRANULE_SIZE);
+	poison_body_end = end_addr;
+
+	if (poison_body_start < poison_body_end)
+		kasan_poison((void *)poison_body_start,
+			     poison_body_end - poison_body_start,
+			     KASAN_SLAB_REDZONE, false);
+	return 0;
+}
+EXPORT_SYMBOL(kasan_poison_range);
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251204141250.21114-2-ethan.w.s.graham%40gmail.com.
