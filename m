Return-Path: <kasan-dev+bncBDAOJ6534YNBBLM64DBAMGQER2LZ2GY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id C0160AE304D
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Jun 2025 16:11:58 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-32b90e26e2fsf12823351fa.3
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Jun 2025 07:11:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750601518; cv=pass;
        d=google.com; s=arc-20240605;
        b=W4HmKVGK1EjTNuU8eP6KcedcV1yfc6uZB9gisqIv2/J+qKj1+AgkBOLsOSNDkR4d10
         OhgeF5MbSB3qhc4LBIJtvDkTcQTC/3hwRXixTWgqvt4L1y5KVOQNkK6Khe31Ym+FNkln
         DQrSwcjdCnRdxjADHjnxRND6/6yu9rmMIWjiDZDacjVbhmUs5S3EIpEdvqdAS08htPhT
         HwBkt0kDpJEoy9wplKBIHwfvP2JyReW8hPnF9yK2+L1xIxwkBHItP2Qw7jhevG80ZSpN
         0luqVC+vyUifXIFGlmtYajC3k6k7yrfvnWV/lThT1lS4PEsHNo+k1ddmO5+l8KnFHHKU
         6Rbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature:dkim-signature;
        bh=8fqYuWARcg4Apkf7W4IW4fKjmTWXLit1PW3astGNk88=;
        fh=EVt5oQbUNmwfdHeg/GgyYgS0uJWCXpzzcU27B8PNlik=;
        b=JWuS1qh2JCQHtdo5EBhTul/x8yjzAIgzdSz+D+iIQDvnzhn3zysoWmHJftbNrxmPfi
         smo0tCz+rWyMm5IzpMWIzoA/eRbLZ+UdT6XZXbLodSrXnW5Xnz0IfQHQOPmDkzIfwVff
         9RxiEUp6ABsd0Xcdna4m9UpeMcWc8TgTz0/GCeBKx2mQ8o/ofQbGcV8S8RqV5ptcCrwM
         tT7WbT8jGJRjz8K8FCcCdH5oQJcC6ZNNcYi6JRnmCfWxalzGO1hfh5S1HODJ08wxA8Bb
         vZMurmPAAdg3A4WEkSLTVdm7fVXBc7SaYl9zTp55zE+1ZKsicyHyHC3jQEv3ZzX/7zxa
         HRXg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RQpr2Jdg;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750601518; x=1751206318; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8fqYuWARcg4Apkf7W4IW4fKjmTWXLit1PW3astGNk88=;
        b=fFd56Pnh4XVzqHqquoBrVOIV1FL550gxFqA2gm6h2ekSiBsdG11o+DqxsiyENXLNkK
         HlpDRv6lSodIUjXIV8ro64Hf7UfSAiy38ZdVoG3GAawkgCEp2schdszha+i6Woiwwqjc
         tYI4j9iG0gmJl1WHrq9RCzu/fq1ahdY2ImBBcNet7qOCTmIbQGedYl03weM8FKdBEDIZ
         LTSQYsXFC+IaDGJhX/WF1c9MXA8Tl2btTZlh0McZHp47i1ROnkVKPdVy/ztgWTd4h9pq
         KbU3npG7mpTNhfDTHieUbYt6j/Ku7vKTGFt3+DhPnZpzDkZAFQ3XMfWryisR+Y3ueTYW
         kV1Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750601518; x=1751206318; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=8fqYuWARcg4Apkf7W4IW4fKjmTWXLit1PW3astGNk88=;
        b=O3Fu2GQ7/32Oj2N24x79wJOnBPPTC+XmAjb9m/f3MudCus5smiErMowdwwi02TzdOY
         Ls916fr0DHRlKkRDv1C5gEesynK2RRoSudkK4WAMXogHLjOLX3wLj8o7DIgtCngaEUNl
         57o4GgPDxmmOMZJOSiiWLUJqOextywYHikBtz+EIzV04dOdqk9JsJNXsNfsVOUTER2J4
         Nh/4xBs1NkGsESoNmEiBSRCwfZoJaav6dy5tAzEnqcE29CcpTMOGYfba+lV4UFpZPBX1
         hxd22IJtlRweHZjngCDPMRdfkTygvGEft54plojBf5Hi+M4Ov+CgPdZ4tMbCZfJpvJZt
         WpKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750601518; x=1751206318;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8fqYuWARcg4Apkf7W4IW4fKjmTWXLit1PW3astGNk88=;
        b=Z7I6+Jhe7ICPTrSLRtdX8Vn9qNlZr4cHzkrSp7GH8zYw/fa/Abb9P6ilO9Ghevpwbg
         2hwXYpUb4Qc8TtnuAfGPZs+Nn4NaProwfnHZdZnuf9nLgy+dvf3z/EKio32Y7RclOE9p
         E3f1e2lSnu/qZBJaWuKb8OYjR7FGWEcT+BHFTfuXGooLAr7xNjs1hXim2rBQqbIlca4v
         9sezGC39ky/kqJ2S22UZ5+jRfynTvXpiAImZJ3puzCmkjqdeU133H02z5UlvzilAHUg+
         c6De487eWETmugNnaNxEGQ2S+mibe4Iw0u4yknO0VTwZyGhBUr+pIGqv8waQzXo34iSr
         +X7g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXE4RCN3LeZFCw+EYJtaPrZi4zqJYVtwNrVYaraxtsCHwEIzTjyZG/SyYZmplbk1lW6jzik+A==@lfdr.de
X-Gm-Message-State: AOJu0YwmFVLfhbKuGjhoA8ivmua/tb84c+uJH0Rk8LzDgnfyP2mPwzGD
	EPmQVVHfcthqSlwkbkeYqb7294/smc7Gll1nA8fvhI9RYP0sYYw4c9J1
X-Google-Smtp-Source: AGHT+IFLMiyYs5Za0cRgr2ecHfk1kTIcRQSkP4YWrdkaTZ0bIr2bsNHXP0FcFHIa0qA67AaCQyDlIg==
X-Received: by 2002:a05:651c:384:b0:32b:93fa:2c0b with SMTP id 38308e7fff4ca-32b98e437e3mr23409441fa.11.1750601517642;
        Sun, 22 Jun 2025 07:11:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcktQYlqdZE+eswnhRqWaBtywaaMHbqLGydvxOO3SwThQ==
Received: by 2002:a05:651c:1078:b0:32b:7f84:d836 with SMTP id
 38308e7fff4ca-32b895b3381ls5888831fa.1.-pod-prod-02-eu; Sun, 22 Jun 2025
 07:11:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVX093xN1ZAJ8Uj/G2UCX1bEgczBtBYT0uybxHSPDIq03K6A/DiawwPGWFoKfvMfV6SVDFU/aFIEZU=@googlegroups.com
X-Received: by 2002:a2e:a4b1:0:b0:32b:3b53:6548 with SMTP id 38308e7fff4ca-32b98f0803amr21372071fa.23.1750601515004;
        Sun, 22 Jun 2025 07:11:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750601514; cv=none;
        d=google.com; s=arc-20240605;
        b=e+fozaiSh8d/YdZ7UJXyYMNNv0cVd6fOeonjhCL6T7lf5Pu2tI8VlO3hqde4/FYga4
         MJHonoFUaZivFKi8bg8QYPikczHROrjU6CYF0K6DHw4Y0r08MBGQpUn7ugDhJs2yOmp/
         HMpTw+FK6FWfSZLG8cAnzR4VUc4iK49spCvbpwjZuok+PHUAu8KAyDvdLpENKIBxM7g3
         HPmNTFV7ZArpa3tCt+WPm0jaq8SKDiBArwfpgbqQHDDRqZP+sCL1ycm0XO6GKiKlGo7E
         Zkutru9DYsaQekME1vw159xQw/HNucULQoJYzUGsn9FR2aJpsOr4iIQVlZt/zEoPegu8
         JB2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gQvsm7fpCMuYnjdMO+OlD8VealdHt7K+J4wH5CEjQ4E=;
        fh=YLGPa3HPq1vIUZHrBiw0WivzLswV1Gl2cGfRhvZndzs=;
        b=LIMwlLqkXWrRiagACI4Loouig0wQNeGIENp1R83Adf9S1JwC8b9XfGD62ULC024z25
         u4MSG37qW3c0U65g5bqS9trPwZXOYVw609LHRTvIsqB920c0a379fic3ElBzMB//e4Hl
         PnZik+GNK0dOpipfkxEVpQtcHU03dCTs8Q2RUonFLlnPOJwpkJsyVGeVDJreDNUgsCdF
         z87Y5Glx0wSspLtTSK2VRUfmOP2/mW9IfJRwZS/zxz6C4iPrNGVuYZ9l1WXhnpNn4xXF
         Ng78FVXSuowUhX2XhcQ3ukRW8VqDMegcyM1fePER4g9RNVU/MFpubXbt8Qq1kRvgnPJu
         cNYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RQpr2Jdg;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32b980d3316si1054891fa.6.2025.06.22.07.11.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 22 Jun 2025 07:11:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id 5b1f17b1804b1-450cfb790f7so24220165e9.0
        for <kasan-dev@googlegroups.com>; Sun, 22 Jun 2025 07:11:54 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUJuLVxmblnu4AxO/eIkT+z/Nuj60Eirfgyj5HBQTmdbYljyEVhfOPBXi35avYBpvcdwJqg07xVXLU=@googlegroups.com
X-Gm-Gg: ASbGncuHeJdXDSVmIpU0ZBe1IwIBxaNMnJSQMrXLGm9NvtC8RcTQFrMd0108UWmWQ5e
	pG9d9VQCeY/nJVOm5lFEMisMo8BROzHV4GlmeFburEQ1YNGPom67fSyVd3Ljygy/uHl6nVkQUxn
	+KvFmd+uqpalf7Jf3g7Wp12owPOTvQ7qkwY2v1xLN59+ue9qycoYOWY7jbTvOSGl8v2xIc0VONz
	ddh6d4wTm2eYRg1EhVWo43e70X5FFLzXZqbwbBjs3VDnuKo1cgtfW/wpv5raqJ2DOf05iKLA3aK
	Ie5GuMVdUQaDPubkNwNojFeKsdHCggimoXBatJk28etpAjYHpb/YiBGMBWxliJu9VBwGGnkRHmm
	A33c/EmcXQNzFWKo0tlYdvbvvi3co1KrcTykNggkW6Dbs+OkWDy5BVNSvgtYv
X-Received: by 2002:a05:600c:4e8b:b0:453:608:a18b with SMTP id 5b1f17b1804b1-453654cb7dfmr103410815e9.9.1750601514096;
        Sun, 22 Jun 2025 07:11:54 -0700 (PDT)
Received: from localhost.localdomain (ec2-3-122-242-201.eu-central-1.compute.amazonaws.com. [3.122.242.201])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3a6d297ccbcsm6775771f8f.91.2025.06.22.07.11.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 22 Jun 2025 07:11:53 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: andreyknvl@gmail.com
Cc: akpm@linux-foundation.org,
	arnd@arndb.de,
	david@redhat.com,
	dvyukov@google.com,
	elver@google.com,
	glider@google.com,
	hch@infradead.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	ryabinin.a.a@gmail.com,
	snovitoll@gmail.com,
	vincenzo.frascino@arm.com
Subject: [PATCH v2] mm: unexport globally copy_to_kernel_nofault
Date: Sun, 22 Jun 2025 19:11:42 +0500
Message-Id: <20250622141142.79332-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <CA+fCnZeb4eKAf18U7YQEUvS1GVJdC1+gn3PSAS2b4_hnkf8xaw@mail.gmail.com>
References: <CA+fCnZeb4eKAf18U7YQEUvS1GVJdC1+gn3PSAS2b4_hnkf8xaw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=RQpr2Jdg;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::329
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

`copy_to_kernel_nofault()` is an internal helper which should not be
visible to loadable modules =E2=80=93 exporting it would give exploit code =
a
cheap oracle to probe kernel addresses.  Instead, keep the helper
un-exported and compile the kunit case that exercises it only when
`mm/kasan/kasan_test.o` is linked into vmlinux.

Fixes: ca79a00bb9a8 ("kasan: migrate copy_user_test to kunit")
Suggested-by: Christoph Hellwig <hch@infradead.org>
Suggested-by: Marco Elver <elver@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
Changes v2:
- add a brief comment to `#ifndef MODULE`
---
 mm/kasan/kasan_test_c.c | 8 ++++++++
 mm/maccess.c            | 1 -
 2 files changed, 8 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index 5f922dd38ffa..2aa12dfa427a 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -1977,6 +1977,11 @@ static void rust_uaf(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, kasan_test_rust_uaf());
 }
=20
+/*
+ * copy_to_kernel_nofault() is an internal helper available when
+ * kasan_test is built-in, so it must not be visible to loadable modules.
+ */
+#ifndef MODULE
 static void copy_to_kernel_nofault_oob(struct kunit *test)
 {
 	char *ptr;
@@ -2011,6 +2016,7 @@ static void copy_to_kernel_nofault_oob(struct kunit *=
test)
=20
 	kfree(ptr);
 }
+#endif /* !MODULE */
=20
 static void copy_user_test_oob(struct kunit *test)
 {
@@ -2131,7 +2137,9 @@ static struct kunit_case kasan_kunit_test_cases[] =3D=
 {
 	KUNIT_CASE(match_all_not_assigned),
 	KUNIT_CASE(match_all_ptr_tag),
 	KUNIT_CASE(match_all_mem_tag),
+#ifndef MODULE
 	KUNIT_CASE(copy_to_kernel_nofault_oob),
+#endif
 	KUNIT_CASE(rust_uaf),
 	KUNIT_CASE(copy_user_test_oob),
 	{}
diff --git a/mm/maccess.c b/mm/maccess.c
index 831b4dd7296c..486559d68858 100644
--- a/mm/maccess.c
+++ b/mm/maccess.c
@@ -82,7 +82,6 @@ long copy_to_kernel_nofault(void *dst, const void *src, s=
ize_t size)
 	pagefault_enable();
 	return -EFAULT;
 }
-EXPORT_SYMBOL_GPL(copy_to_kernel_nofault);
=20
 long strncpy_from_kernel_nofault(char *dst, const void *unsafe_addr, long =
count)
 {
--=20
2.34.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250622141142.79332-1-snovitoll%40gmail.com.
