Return-Path: <kasan-dev+bncBDX4HWEMTEBRBX5N6D6QKGQE3F6XYBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 805652C154A
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:09:03 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id y187sf154798wmy.3
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:09:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162143; cv=pass;
        d=google.com; s=arc-20160816;
        b=dpcXDfk9ZXyQlTD6XVczacJn6qM2UcUA+IPlkUW1vxBTXHzv61z52or00wydv/CtgR
         7oOsCjev9FOvMapk5i71SYEv0yZJskl4zv+SzXvBLlQvHaEZkSSsDanne82vo55ckPNo
         cn56Z6yp8+gHsIGeJKosAjvhVBpUmKCF44lerO8NM+mHZu7+9vxXmOvckH4SHIvQIygs
         ykgngG7ebtG9KnfoxGWPiuZJ1o3tP1E/M8vtZ1RyxUrUgH2/es33ZBTc1ZmRjeUVznyy
         Lu/8TMgen+lz8W+OcmCxqUkIYXXzHxKetSlVr/sULdceLoPQi3g6Zax7IdpGmklmdZcH
         xUCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=si7DH4WKxRYcdPVOG1pznHMH0SeUGdLcSKKqGIFciBk=;
        b=0jW0ReaOjebhI9HVLDqpWVGRHyY+18tbjLLLbB3SEdPfOcW+YkIbZ/nG4Hobm1rm75
         XLimqC89EmB0/5GOtQIegIMBAPLZE9I/sL7xr2r+63EbNLJ+9CrkWNu6mQByA4jBqn+3
         2m4S8ls1llnuEDtP650LoeZfxxRQEmaxObve+wEeNlOvjdW3tdrshm+hBg2rixO57agc
         kiV7vAT2M8pSXK1uDjABxG+e6IJcOoSNpkXnU79pA7z7n+qnMJMCVZFDQKm9FAPy5H3V
         7dyufPBy1ldJsdd83ypXTstwc8rTRADcXoHKsqQOJElKpNoBzwzGh0XHuSdHTuJep7RD
         qvGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rJ0wPyDS;
       spf=pass (google.com: domain of 33ra8xwokcf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=33Ra8XwoKCf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=si7DH4WKxRYcdPVOG1pznHMH0SeUGdLcSKKqGIFciBk=;
        b=YFaZTymtSePpGXk7tRufQDBlBw53lGS9nzxWR0fGH/1+MDL0H+3w+AljCQLKSKAojJ
         4VjUtUgjD0kgQK+/hP4JDGFV3aZIB4ox1aQ39um5hGpyUsfNU+GLiUrW15mIz2yT/WEm
         wQP9FxWG3q39kvrwzHFse+dU8ELC6Y0Z1NfBFVu9JW7T0wam/Y1FrcEW9HRr6uw6AH7W
         RZ1QWFWMocQLAAO9zvEk9Wx0m3S3I37ViPxSr1v9Fr7HDF71ZvQJ4Pqt0sOW8J7FXYJT
         yuSmIUgHS7xvVshIRDsk+vna5n+Iq7dxBBuFrNbkmjuCIoWbFbgT9RFOluBIkpurPHb5
         0mAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=si7DH4WKxRYcdPVOG1pznHMH0SeUGdLcSKKqGIFciBk=;
        b=pRyjGcyTPt1zLQeNNGPtIsZ6L5hGc5ZRs8R/S8u8VrjOM5i9uv3eXS8oMHkOFaD0IW
         g2RVHLSeTMUnJgF3dYaAUR21fPG1jJhSgL/6siy3n/fjNyAyIm+Pd32m28xoPH3jqcBV
         cCTeAejoPmyCcIL8XCaRRe8ByfiW/eUfWbWXwQTa6XLMDXkctTspj02smrF3/7rLgHeS
         hiNEhKzNDJ+HXu0Sg/JkpUSN92QcewogGWhWbV+uXxv6s+zsKppfoyZTjF4rBF+AehEc
         auAHFRjh0bDBJVCsqEVnWy20A8K4itUXI6/QWBGdOkzKy6a+WKw1MqWZO5vgsoOZhSdS
         h/Mg==
X-Gm-Message-State: AOAM532BxbjB6Cejk+aNa4ligbX3zuQ/RCnOB/3kSppJkBOAp9OHS7pq
	Kd7owyD+k/zVyN433IFBjN4=
X-Google-Smtp-Source: ABdhPJxv1prvE1HAiiW8yBzUnq0gkdv5MtyxcQe8s4L7D5g+gMSLb9E6xScMLND8gn8mdniQipZvHw==
X-Received: by 2002:adf:e74d:: with SMTP id c13mr1410777wrn.277.1606162143253;
        Mon, 23 Nov 2020 12:09:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e5c2:: with SMTP id a2ls8963348wrn.3.gmail; Mon, 23 Nov
 2020 12:09:02 -0800 (PST)
X-Received: by 2002:a5d:50c6:: with SMTP id f6mr1514736wrt.150.1606162142337;
        Mon, 23 Nov 2020 12:09:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162142; cv=none;
        d=google.com; s=arc-20160816;
        b=ip2DS7BHnDyG98oFAwlahNIpy4LvDDd+nq8vIDxuk2QORSMYiR280nVbFH/EeOn6HH
         aBMTt+4NyKMx/3eUfZwHtFdUdt99L4XLBJVewUK5trD0CExjBmp90Czt24VPLAQ5rjUQ
         oGx+Nbi6zYB55ELIUOOxNirw5FBFvBgkTKNEKXezvdREQuVJmNLQvYK+aZd0fb4Trxn0
         Ni+Eo13ALWpmIP+oXyYr7IMmlpqPLxT93dgnJRX7jz9GOOiouMXh9zg9g6vXoc23ktPq
         +ZIkb0cfh7zMhWLoOhYCHkb9Cmwh0CFvoo9r3YzPo03NFOI1Xh9JKCNubPCuXxSmnN+f
         s+sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=fDQy1wc4ePFUib94ltbYtVazi0RsE8I+c8xac0+Q+Wo=;
        b=Sb5zHGgjBwE49ni8oH0VlBngnu8+STIDGOFVIh+8dLUVe6XxYTHB85TGLfPxj+kdGN
         yUabIhVDZD1IS6A8MaPJpnTKisRu/5pyxMNVXto4+G86wyWAg+i5hPQ2yF2OieHMuo/m
         CRQKKUbEQnd84QzmiSGlhtRuPpykZLfGsDHlJWqhvJq9AI/MYyRQ0k614GwZ/e/bzmJL
         UsZZmf4iva0vbJAmfSBihy6S1Da4o8oXO0MIIvPT5rGsFXgs53osLW2pstYa4j3A0a85
         K7wg55ObzygKaxIqGP5qXBHD/O1Dethf713Ypyjm0wrZDlkJkJ07qrFkzaE9HlNLPcei
         Xw9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rJ0wPyDS;
       spf=pass (google.com: domain of 33ra8xwokcf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=33Ra8XwoKCf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id o187si11529wma.2.2020.11.23.12.09.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:09:02 -0800 (PST)
Received-SPF: pass (google.com: domain of 33ra8xwokcf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id r2so3098073ejx.9
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:09:02 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:aa7:d703:: with SMTP id
 t3mr791202edq.375.1606162141605; Mon, 23 Nov 2020 12:09:01 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:42 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <370466fba590a4596b55ffd38adfd990f8886db4.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 18/42] kasan: rename addr_has_shadow to addr_has_metadata
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rJ0wPyDS;       spf=pass
 (google.com: domain of 33ra8xwokcf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=33Ra8XwoKCf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

Hardware tag-based KASAN won't be using shadow memory, but will reuse
this function. Rename "shadow" to implementation-neutral "metadata".

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I03706fe34b38da7860c39aa0968e00001a7d1873
---
 mm/kasan/kasan.h          | 2 +-
 mm/kasan/report.c         | 6 +++---
 mm/kasan/report_generic.c | 2 +-
 3 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 488ca1ff5979..c79d30c6fcdb 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -147,7 +147,7 @@ static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
 		<< KASAN_SHADOW_SCALE_SHIFT);
 }
 
-static inline bool addr_has_shadow(const void *addr)
+static inline bool addr_has_metadata(const void *addr)
 {
 	return (addr >= kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
 }
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index af9138ea54ad..2990ca34abaf 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -361,7 +361,7 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	untagged_addr = reset_tag(tagged_addr);
 
 	info.access_addr = tagged_addr;
-	if (addr_has_shadow(untagged_addr))
+	if (addr_has_metadata(untagged_addr))
 		info.first_bad_addr = find_first_bad_addr(tagged_addr, size);
 	else
 		info.first_bad_addr = untagged_addr;
@@ -372,11 +372,11 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	start_report(&flags);
 
 	print_error_description(&info);
-	if (addr_has_shadow(untagged_addr))
+	if (addr_has_metadata(untagged_addr))
 		print_tags(get_tag(tagged_addr), info.first_bad_addr);
 	pr_err("\n");
 
-	if (addr_has_shadow(untagged_addr)) {
+	if (addr_has_metadata(untagged_addr)) {
 		print_address_description(untagged_addr, get_tag(tagged_addr));
 		pr_err("\n");
 		print_shadow_for_address(info.first_bad_addr);
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index b543a1ed6078..16ed550850e9 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -118,7 +118,7 @@ const char *get_bug_type(struct kasan_access_info *info)
 	if (info->access_addr + info->access_size < info->access_addr)
 		return "out-of-bounds";
 
-	if (addr_has_shadow(info->access_addr))
+	if (addr_has_metadata(info->access_addr))
 		return get_shadow_bug_type(info);
 	return get_wild_bug_type(info);
 }
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/370466fba590a4596b55ffd38adfd990f8886db4.1606161801.git.andreyknvl%40google.com.
