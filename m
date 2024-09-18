Return-Path: <kasan-dev+bncBDAOJ6534YNBBAXEVK3QMGQEBYRXPIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id EF3FB97BB27
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 12:57:07 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-42caca7215dsf43379515e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 03:57:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726657027; cv=pass;
        d=google.com; s=arc-20240605;
        b=QbYptNpA3dnhpRwW20Z9imr52FpVmyhTKH3yjhECXaFeHS1bjmMF2WQRZj0P3ENHCs
         VMQkKWLioCHDaO11K+1mteKeINam135aJn2TnPR/KpT0gPkLWizJZaTu5kzjXyPIjkMb
         Q6d0uMTdwNxCwIvI/Mcw4s9jld0QrMDYJVrU9u7/RgQJ20KcKSL6Ry4NlDAThGb6dsNE
         GJCP3aGK7FTYmeaLRAhdfhh4zWFTgDLq+luXW+wjUOCsKEHr/B+sRA1xj7yQbvBwiKtB
         5G8/laSJBCFAvYJVisCD271vsQELjzNGSH0K7pcoeQuCgsnlztAMI1NCH8/3QsRz7yGl
         FTrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature:dkim-signature;
        bh=W6fjpbpCIeUpjYewrb0vBd+G2fuOQc+uvzipib7nWwE=;
        fh=WGrfoCXchsI/Sw2LuzqSU32sQCXVJuvYzjEmsnoICPw=;
        b=isG06Hos16Hpt0EKOGFeWUhhoLGCuzZhuBYMFKtJugwyZ9oBbEqfrjCXFjRuXESpxc
         MqHCAIGdsELYGNjR3vgNfIEhYS4zGngsFkbw3riTuc5dolwSXqbl/0qahh3s0l8yNq95
         UaSIIrLQHxsYqcddUdEu0BB1wG4egEDsBjjEcIVTQOPpqDEBvjmMbi/YdODybJ4TYTLz
         t5KuRAT2+YNOFX54Rea/1MbIdATCkiJ/Jeu6Hwvla7RCFzQLUl4UraQKliQor3v20tN2
         2JRdzOUnrMwkGcMqWhG2gWtqrlTMSkvgtPPIGfuiae22z13PFuS4Xc5yvkFcyIPtXcEM
         4YMA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="cDmQ/FNH";
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726657027; x=1727261827; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=W6fjpbpCIeUpjYewrb0vBd+G2fuOQc+uvzipib7nWwE=;
        b=D4d1brtvAiDs378D0LMySltZBu10GaWIC2y0slJOpIVKIWaVjl+ERON9RDjtKF9iKW
         x88UKvqRzqHNsFk34bfOmiBxviSejrhBb1qHl6bxiHzFKJilGLLy++q1TkGEHIHGkYbi
         YE3hqnVbDEhQcHetX6Y8pvQcTcND3lKv32Slai3XVIBBmAs3YLp/ZkMWLyH/ltFe9C+t
         r3LnbG7blU59IGDgrW/QATIui0+Ryc6YGBzba280RWR+JIdGLutvcWH2PHLDXRb5pqd+
         IBb3WAxlGmdoK7FXcsu/zulgzU7QPfB+NHiCz19V/JO2uFdIq7rjbHgTGemJhO8r/vwO
         47OA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726657027; x=1727261827; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=W6fjpbpCIeUpjYewrb0vBd+G2fuOQc+uvzipib7nWwE=;
        b=M9vezLO5kg8RWkEfkzBFbXh/O6nXWIeSLYijuVWn3kQRXGtBNr1pfu2HXtqTXVo5Hf
         Cmsbv6+dZi9IV752E4n9zFz+uPOwU3hFUyX0lPGmpRrmrdachoYFKgeYamLKimLIbe4E
         7hKhFBTKeo3qdMq3uAcDd+Njzt33CvzP/100QZTttjmCXk7/41Ld2AzBGsUYcMlwZZFk
         fPxV3vYLHICHG/qfTFaBLYl5crJVmbbOwWdu5jW816A+iD2zXYPJUj4Wd9NmhFaT3nnE
         TaFh5lOCcOdX/v/nF6fDq4oREc9kbKGLiXoVbmnfxDu5VvfDH5BsrQg7NgGAhiY1zeuB
         KwAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726657027; x=1727261827;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=W6fjpbpCIeUpjYewrb0vBd+G2fuOQc+uvzipib7nWwE=;
        b=Urra8MqTHJD9p8XmTrZbRZSHGosvpbfWAk5IlOUG48cxGAakulaM8i+oR7EtBOYBNt
         CsMCwCD3nEnLU38RakB0TTLn80AaSFn9RPfPFf3UCjvzNTMV+rB24JXdF/4eltrzGToZ
         OfB818F1NF9MBwrUOW9hxGDcNfA7g439uIHb3rpFCGKpD0+Q4O88qMch0R5hDS6xW/UM
         lRD1/CSNtR1+YVASbpo3koUmzlMjZjmwlzKHEQ8FyYmvb6XgrL4NY6zkZ38CsJLZEDHH
         AJGuWWZajF4ACwz+htpY+QkPuE3g9BPeF37nOkdYVQgaHlfXONF5YN0ES7W6RANg2FHe
         YfMA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXpXPZa87Qrx7a9c6CGBWhIWBjgGIDgvCVyAy4pfcnnqlKxJMyrRG3VNkunzy/C/9QTmciT9w==@lfdr.de
X-Gm-Message-State: AOJu0YxMnEe/VxqioqdfMj39RKNuY/FB4RW5CoSD5GVQz/P4yT3gVdta
	2Sk7gwp2TCN8UmdwqsSvgsFo73sVUxp0ZQ92mfqQWZPR5pc6WI8P
X-Google-Smtp-Source: AGHT+IEfi6hK2xp/cA0Ho8VRnfBFYGxDIH2wdi2hUzHeqVrQTvRxOAuOLgezBSE1S/GXqfpliQ09Wg==
X-Received: by 2002:a05:600c:4fc2:b0:42b:af1c:66e with SMTP id 5b1f17b1804b1-42cdb5299e8mr160015605e9.9.1726657026704;
        Wed, 18 Sep 2024 03:57:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e647:0:b0:371:7960:15b8 with SMTP id ffacd0b85a97d-378c2103932ls2009546f8f.1.-pod-prod-08-eu;
 Wed, 18 Sep 2024 03:57:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVfic1Ih6iUenwj/TdG9ONIJpnb5E57LRVx+DYhvyFag983eGVQchEyC6vz8tacB4sg/awm5tmtmnE=@googlegroups.com
X-Received: by 2002:a05:600c:511b:b0:42c:a72a:e8f4 with SMTP id 5b1f17b1804b1-42cdb5317cbmr169029725e9.14.1726657024332;
        Wed, 18 Sep 2024 03:57:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726657024; cv=none;
        d=google.com; s=arc-20240605;
        b=ZTyWkNHyTiDtMr9Slmru+wcobgQ5PtYI5/lY7DEtb4+fmYjbv3L6XbL3Fyuc00o8Za
         MZ0zy2KRfhRLrdpCh9FMHAaDH4lbU0XPLVQgVCouBFFK/48YcZ0HFTP5eZ9Yuih/KXNd
         VLvWJe887E19ifBC4VBjn46kicbvbe5ExRNGuFbH5BAts5pEwlaBmT8aKzyR1jyEmCNY
         58aDoxs1OVJu4gMmFnrJo+dzP3dWjSsuLI6COdIjSMN0SzfRNgleXo8XwEGIq3TscPcw
         cwTndn39cz4RMPsrTUdGtIsACjoobQsGwxx/9MojOyOO9E2iqWDLDJwhyRlA8tVPkuxe
         /Kqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jIjQBepkmzGZvnIkQy1K5zVrOzJD//KUcFSCnlgygqs=;
        fh=GxH3UaCnD/qwRrjdogRLVa5ktpZukjVGSGyFgxk5DBc=;
        b=KcraJL3gDStLIBzg6H/cpdLO2rTfHzzcbAU/1uzj+CUs1c9IP8nKH3GoYR4reSTitF
         TsWlHXR1w2/x3Tw4wRSjx44oq6SBdmsuyF5Ip5K+6bU8IFnI2JtO7i/WLpnl4eEhy6V9
         hOD8XZc1kGAIORMUqFwJcqwosS/nGYdurkGVK1TmQXHqr1MXJcE1X9aZJ2gC2SLReZ/X
         4Yk7JRGRujHifU+NjFWYgN8VcJpkKjv2sLq50+ifbxtXv40gpZxwQGLcCGzRpjiHlR1I
         3PD7vsuuG4GKrLIZZJuPmDmla3MFVdC5aN/8In7KQ72nS+bVdw7UlCFEniEmQU3Hj6B+
         ow6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="cDmQ/FNH";
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42e6bc40cfcsi2049535e9.0.2024.09.18.03.57.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Sep 2024 03:57:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id 2adb3069b0e04-53653ee23adso5987695e87.3
        for <kasan-dev@googlegroups.com>; Wed, 18 Sep 2024 03:57:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVyRJ0uZx4cnl1L12BAHJlTa1U4j/KYZw9Xgqg4mG2qp6tqgm0CCxCr5DHqL6x5KsbpbTzGOmcbOws=@googlegroups.com
X-Received: by 2002:a05:6512:ea2:b0:535:6ba7:7725 with SMTP id 2adb3069b0e04-53678fb1cd4mr12757113e87.3.1726657023314;
        Wed, 18 Sep 2024 03:57:03 -0700 (PDT)
Received: from work.. (2.133.25.254.dynamic.telecom.kz. [2.133.25.254])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-536870b8d6fsm1472524e87.291.2024.09.18.03.57.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Sep 2024 03:57:02 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: andreyknvl@gmail.com
Cc: akpm@linux-foundation.org,
	bp@alien8.de,
	brauner@kernel.org,
	dave.hansen@linux.intel.com,
	dhowells@redhat.com,
	dvyukov@google.com,
	glider@google.com,
	hpa@zytor.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	mingo@redhat.com,
	ryabinin.a.a@gmail.com,
	snovitoll@gmail.com,
	tglx@linutronix.de,
	vincenzo.frascino@arm.com,
	x86@kernel.org
Subject: [PATCH v2] mm: x86: instrument __get/__put_kernel_nofault
Date: Wed, 18 Sep 2024 15:56:41 +0500
Message-Id: <20240918105641.704070-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <CA+fCnZeorA7ptz6YY6=KEmJ+Bvo=9MQmUeBvzYNobtNmBM4L-A@mail.gmail.com>
References: <CA+fCnZeorA7ptz6YY6=KEmJ+Bvo=9MQmUeBvzYNobtNmBM4L-A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="cDmQ/FNH";       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Instrument copy_from_kernel_nofault(), copy_to_kernel_nofault(),
strncpy_from_kernel_nofault() where __put_kernel_nofault, __get_kernel_nofa=
ult
macros are used.

__get_kernel_nofault needs instrument_memcpy_before() which handles
KASAN, KCSAN checks for src, dst address, whereas for __put_kernel_nofault
macro, instrument_write() check should be enough as it's validated via
kmsan_copy_to_user() in instrument_put_user().

__get_user_size was appended with instrument_get_user() for KMSAN check in
commit 888f84a6da4d("x86: asm: instrument usercopy in get_user() and
put_user()") but only for CONFIG_CC_HAS_ASM_GOTO_OUTPUT.

copy_from_to_kernel_nofault() kunit test triggers 4 KASAN bug reports as
expected per each copy_from/to_kernel_nofault call.

Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D210505
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
v2: added 2 tests for src, dst check and enhanced instrument check in macro=
s

On Wed, Sep 18, 2024 at 3:51=E2=80=AFAM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
>
> On Tue, Sep 17, 2024 at 10:18=E2=80=AFPM Sabyrzhan Tasbolatov
> <snovitoll@gmail.com> wrote:
> >
> I think the easiest fix would be to allocate e.g. 128 -
> KASAN_GRANULE_SIZE bytes and do an out-of-bounds up to 128 bytes via
> copy_to/from_kernel_nofault. This will only corrupt the in-object
> kmalloc redzone, which is not harmful.

Hi Andrey,

Thanks for the comments. I've changed the target UAF buffer size to
KASAN_GRANULE_SIZE and added other test cases from bugzilla.
---
 arch/x86/include/asm/uaccess.h |  4 ++++
 mm/kasan/kasan_test.c          | 21 +++++++++++++++++++++
 2 files changed, 25 insertions(+)

diff --git a/arch/x86/include/asm/uaccess.h b/arch/x86/include/asm/uaccess.=
h
index 3a7755c1a441..bd1ee79238a2 100644
--- a/arch/x86/include/asm/uaccess.h
+++ b/arch/x86/include/asm/uaccess.h
@@ -353,6 +353,7 @@ do {									\
 	default:							\
 		(x) =3D __get_user_bad();					\
 	}								\
+	instrument_get_user(x);						\
 } while (0)
=20
 #define __get_user_asm(x, addr, err, itype)				\
@@ -620,6 +621,7 @@ do {									\
=20
 #ifdef CONFIG_CC_HAS_ASM_GOTO_OUTPUT
 #define __get_kernel_nofault(dst, src, type, err_label)			\
+	instrument_memcpy_before(dst, src, sizeof(type));		\
 	__get_user_size(*((type *)(dst)), (__force type __user *)(src),	\
 			sizeof(type), err_label)
 #else // !CONFIG_CC_HAS_ASM_GOTO_OUTPUT
@@ -627,6 +629,7 @@ do {									\
 do {									\
 	int __kr_err;							\
 									\
+	instrument_memcpy_before(dst, src, sizeof(type));		\
 	__get_user_size(*((type *)(dst)), (__force type __user *)(src),	\
 			sizeof(type), __kr_err);			\
 	if (unlikely(__kr_err))						\
@@ -635,6 +638,7 @@ do {									\
 #endif // CONFIG_CC_HAS_ASM_GOTO_OUTPUT
=20
 #define __put_kernel_nofault(dst, src, type, err_label)			\
+	instrument_write(dst, sizeof(type));		\
 	__put_user_size(*((type *)(src)), (__force type __user *)(dst),	\
 			sizeof(type), err_label)
=20
diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 7b32be2a3cf0..9a3c4ad91d59 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -1899,6 +1899,26 @@ static void match_all_mem_tag(struct kunit *test)
 	kfree(ptr);
 }
=20
+static void copy_from_to_kernel_nofault(struct kunit *test)
+{
+	char *ptr;
+	char buf[KASAN_GRANULE_SIZE];
+	size_t size =3D sizeof(buf);
+
+	ptr =3D kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+	kfree(ptr);
+
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		copy_from_kernel_nofault(&buf[0], ptr, size));
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		copy_from_kernel_nofault(ptr, &buf[0], size));
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		copy_to_kernel_nofault(&buf[0], ptr, size));
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		copy_to_kernel_nofault(ptr, &buf[0], size));
+}
+
 static struct kunit_case kasan_kunit_test_cases[] =3D {
 	KUNIT_CASE(kmalloc_oob_right),
 	KUNIT_CASE(kmalloc_oob_left),
@@ -1971,6 +1991,7 @@ static struct kunit_case kasan_kunit_test_cases[] =3D=
 {
 	KUNIT_CASE(match_all_not_assigned),
 	KUNIT_CASE(match_all_ptr_tag),
 	KUNIT_CASE(match_all_mem_tag),
+	KUNIT_CASE(copy_from_to_kernel_nofault),
 	{}
 };
=20
--=20
2.34.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240918105641.704070-1-snovitoll%40gmail.com.
