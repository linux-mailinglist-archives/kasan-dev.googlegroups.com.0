Return-Path: <kasan-dev+bncBDAOJ6534YNBBVVE33BAMGQERIVWZHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 02FFDAE2E66
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Jun 2025 07:19:20 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-32b400abcb8sf15327961fa.3
        for <lists+kasan-dev@lfdr.de>; Sat, 21 Jun 2025 22:19:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750569559; cv=pass;
        d=google.com; s=arc-20240605;
        b=hCz+Kw72RIL9uUOoZ8jrGRwaiXTpVOCdxB8JSQ8XnnSY5U1u95LVRiUJpQOrAek2pb
         9HvjNLDGszUbBqjGKN1HlSp5X3bt0aINajGw09Oygw7fp/Ebk6Qj2LBygsPsrU5oxIlb
         vBN8X7YXrfshZmFyQiQ1tik4L1RMNbog9LLWfcpQXPMiihRVVATgzHEDyC7xYA3c/9v/
         GBC3mXPVm8RSSnSLoVCFkjtlpu1MkJGP9s08qua7fkV3shbWfM8XZ+XRHgAK3zP51OOM
         wp1XQt8ssZAZYobxZ3yxQ9I4nrVHMEHZpbsE2EL8xMYKTD6wsN11NHL6pFOMey9J8ZTF
         x8/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:subject:cc:to:from:sender
         :dkim-signature:dkim-signature;
        bh=HrqAtEQWQm668Hz6ORcMW+ITNQbx+f90IVF4wca7esg=;
        fh=qoYykQcwchkmPu7jhnQs+kE8pcxfIu9ZSkHJE81nydg=;
        b=Eac/BJ9VYSbr7HqWAnEaSOzl69NBtL1hrftK2XauoC3+ItCP8VZWcL2XR/1xDPo4Aj
         UX6i8Sui7THOge3Xm28fCY2ZT2GFzaiawLCmyua8jyBi2cIapIjNK7Qy8ig3rh4k2iuc
         +8BdhCdSNq3lJjzUHmy3M75A+VhT+dWoPqIahHXxfnb3YOd0A111L95GBLpiUekE9Uc6
         25i6b31mKp82MX/yrwmZxqryfSTh56vicrFW7CVIfgUvpqtBCu3fTn0zAhZn+jtDxEzH
         BL/opQKuW5CmiGfUTJNDJzPPcZgNLZ0uXQsHkEsaGPnNIetUw7AhqsQmZ6FDl1iK2h8C
         lBUA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FgMl8d7z;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750569559; x=1751174359; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HrqAtEQWQm668Hz6ORcMW+ITNQbx+f90IVF4wca7esg=;
        b=qK7YRISx4ptSNM4zsrWUWJPIq2VDTAC3FVWATWxsd8EoLWqKbHADHE/23AO3ZIGXnf
         tdO9rrNlL0T0/oQ1xNN2Sc9pyUEnwfRLY00blmAhJSoC3tWdzMS04jNT5FTLXFiXHNZk
         X4RsLvnXRAwY99ZF+YzPjXlqI4bBW1Z26pBJljEgao7KKQwKVem7unyJm1WbOYzklMOL
         MY4CbEL+BqplcRm5fBmZKFeifcanWOQJrgy11v5jhrjZIjTAZfrToG0tQ6ltm0G6w3v4
         RFpdODGdMLF88wFXpMg465bV1i8AQDMpDvgkB48b4s3lCpwSJ//lFeWZRE5OgHbMEVtI
         ui0w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750569559; x=1751174359; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=HrqAtEQWQm668Hz6ORcMW+ITNQbx+f90IVF4wca7esg=;
        b=hEXRiBJ+Z6E+iE00RAURQRQpUl9yEOA5hElHIjBXW2ZttRzuSBCdQJQePWrYEGZRC7
         mtJoDrZmnQbRq+zPF6pyDInaFBUlvJIeJdhVFc3/NvD7bpmH6JHLnnMWaH8C4BInA6t3
         ZJlfyM+JXXyzNyBLUcXm9ln8SdSMJy22yAGPb5fnxq8kdKr+m1hPM2q0xGjy74fT9Te1
         MnBsbStTttQm3DLjsfj01P9sR5HqmbcEWkdPaBR6Pp6Sni+LPRotvPJzCcJuMwbNLMS6
         BVZLlBfOAQcblndhVsEdTEYIt9GgnkG8gNG0sX7qTxTN8FQ7lxRWNmGPpdYMa5JdcyYU
         gOrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750569559; x=1751174359;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=HrqAtEQWQm668Hz6ORcMW+ITNQbx+f90IVF4wca7esg=;
        b=qNskvvwuUcdAUkjJJEaSAud1ue3VGP7NYEt1MTxwjWBiorW9sq5O0RGY231VMGYPhd
         f+vgkBlzk+VGcX8cP8k0DiBuyV/qDcdZ9iL3jf6LoWxuyG1nzYzKlsrgZkr8plsMmqNv
         aZ+aCvCNBxxfGZv3yK5zjZehM+XArg8zYBi4rjhs2PR5O0TvyGpvenCtWOMw8s+zwxsO
         0AgLpLzzTtx7v9CvokP1olPbbI34TZT51RlPI8eLGq1h26SGsS1aAG5pW1XyDh9UM/1z
         ChKsEOwORUpgyfOvXeEkwEqgLubwLYFt9z9SBGzd3i7Qz0gvDndJ0MjlJnTHcEYuKZ4I
         qOHw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXq6svaMq8aYMc2QimZQGwCd7TTqBmG5Fo/U/45s98tHEmWhtUo5GuO72RT9huqOGfZX5Dy0A==@lfdr.de
X-Gm-Message-State: AOJu0Yx9TLupzfg/uHgXOsDGluN0Hum99sUZVxMrxG09geVkts8roVnD
	iwt0VicpNyDahMGiLnGFmLNYZvLRJiwk3ZJyEQE+Zzm7DNXugNu046yB
X-Google-Smtp-Source: AGHT+IF2R36BJ23t02Ow3oRrEYBbR9s5NZKryitM3hbQbssloSnvuY05DJoZDUbJZxE9grU/IkTj9Q==
X-Received: by 2002:a2e:a7ca:0:b0:32b:a85f:c0b8 with SMTP id 38308e7fff4ca-32ba85ff4e8mr12538121fa.9.1750569558621;
        Sat, 21 Jun 2025 22:19:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZegxnoooRvHmhSFR/IZ+n0kqK/viAjOjzlKrxudb2TCow==
Received: by 2002:a2e:8a96:0:b0:32b:800e:a2ed with SMTP id 38308e7fff4ca-32b898dabdbls6584661fa.1.-pod-prod-09-eu;
 Sat, 21 Jun 2025 22:19:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXO/nK5BukH6PKxqu47GsOolF42kAlvhwdZ88Oc5H5Mk97ebfKi2YcsMIwjWQBzNTR5z757ZDctFnY=@googlegroups.com
X-Received: by 2002:a05:651c:4204:b0:32a:778d:be76 with SMTP id 38308e7fff4ca-32b98fa3153mr21443791fa.26.1750569555590;
        Sat, 21 Jun 2025 22:19:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750569555; cv=none;
        d=google.com; s=arc-20240605;
        b=h3+8K0FP9gohV11K8Zn7HE1Zf47LZZCp4hqGTbdIVcOt95IBwO80KIY3lzTOQzMdZm
         x8JUX1UgfqQ9r4HCACfqMGnQmO/JsnkYjczwTRiK//b7+GFuG47MVIVXMfsxfJbvirSX
         r6kjR71TK4axyUcjqWFoMSLnYfoZNgP70id3RCEHCkmokPq+QPIOaQiRsA/7hKjCyZ4W
         wv6HD+L8PClMGUywjJF3/eP0sX2KrzhngQsi+vRr7VY46B32H9XCLg5nDh8RaDxMrAeh
         2twt6rF5aCw9NwH72pmAo9hpetu00E2bi9UosDPP684EUGkSm9iAyXkJOI9H8rcqHEPE
         BeWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=xvYslitUMqBt0gBMwySKkrly+VfBVue7PGZMHtctv/o=;
        fh=cvt7fHv200EsH2dc7DtV7+StTZoc4Lmf6grTIcXUhr0=;
        b=FOhUyTlT1gHzVfAV6N9zZEdSFI+pnpTZqQAww11j/obcWDKShHU9KVz5+x3fbbtQot
         JClIxIzn18Vw1zTZFS7xpaWE9jsRwrF0DqNxpKvG6b9WIsjJiDWSLwyLLp0/uwzGc8oS
         NmuAQUUZrNPheZITebhZ+CqMVnHG+k45pZn4e5tpj95QbEgxhOsJEnr0ZD/PDyFavboW
         RnJ21hpOy2uRqo9wYHddKVAkXM6kVKLlokRJEwfBghrL3mVcTqLz6vzQDHhHoj3dzQ3A
         SB63MOFoL85ftaCZTIR67ptPjCggqz7LoFCiLJWD4cMA7Ra66PlgFOzhpN+WLrNWR7nI
         LyUw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FgMl8d7z;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32ca8510e28si40141fa.1.2025.06.21.22.19.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 21 Jun 2025 22:19:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id 5b1f17b1804b1-453636fa0ceso22885875e9.3
        for <kasan-dev@googlegroups.com>; Sat, 21 Jun 2025 22:19:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXdg/nDY87TWjIi4gKOQQMlKtovnhmALEku4fx6wHZKiaGeFs8vPux3bk9CkscPuy6vb+PPs7KPJyY=@googlegroups.com
X-Gm-Gg: ASbGncv0RILbMiya3ZcRJbkUjFKXBt/o1AnNoULDu0xux63xI74sD1dg6OtBNsz9+rJ
	ZPdmhbgtmnZCI3Ju+zQnXK0KyMvh57+Y7rVAKWybRxll7g8BCYvCJcBp3TQ7blfGYnIYoh/p4mW
	5sRswQGTX/R1YKy2TFIaRV2ezHmqqFtf6WPJtLBB3YsuocZAwxo/dan0BrekEHgUYMAAm7as8EK
	agw1vzw8GhbCVHF1FRGEWzX4DxewfvxJ8lxzXCbB8L84ewY0zL0h3IKsWNlFRuNxll3xJJ6UnnF
	en6mMoHWmqKFrb64UqbBDHCv7LwBIPRN6DwQsPvNE6iTWJscWZvbkEGnIUcmyrXjSLM9XoA33Rf
	/jrLOvMWC13b8yP5MtHh+EDnGNc93W0dG5AB3sbleQlpKzFMtWGjCA0ckNKuyNMX2vKVrAZA=
X-Received: by 2002:a05:600c:3b84:b0:441:b698:3431 with SMTP id 5b1f17b1804b1-453659ec191mr67080645e9.28.1750569554647;
        Sat, 21 Jun 2025 22:19:14 -0700 (PDT)
Received: from localhost.localdomain (ec2-3-122-242-201.eu-central-1.compute.amazonaws.com. [3.122.242.201])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45359a09ee6sm60885395e9.1.2025.06.21.22.19.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 21 Jun 2025 22:19:14 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	hch@infradead.org,
	elver@google.com,
	arnd@arndb.de,
	glider@google.com,
	andreyknvl@gmail.com
Cc: dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	david@redhat.com,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	snovitoll@gmail.com
Subject: [PATCH] mm: unexport globally copy_to_kernel_nofault
Date: Sun, 22 Jun 2025 10:19:06 +0500
Message-Id: <20250622051906.67374-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=FgMl8d7z;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::332
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
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 mm/kasan/kasan_test_c.c | 4 ++++
 mm/maccess.c            | 1 -
 2 files changed, 4 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index 5f922dd38ffa..094ecd27b707 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -1977,6 +1977,7 @@ static void rust_uaf(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, kasan_test_rust_uaf());
 }
=20
+#ifndef MODULE
 static void copy_to_kernel_nofault_oob(struct kunit *test)
 {
 	char *ptr;
@@ -2011,6 +2012,7 @@ static void copy_to_kernel_nofault_oob(struct kunit *=
test)
=20
 	kfree(ptr);
 }
+#endif /* !MODULE */
=20
 static void copy_user_test_oob(struct kunit *test)
 {
@@ -2131,7 +2133,9 @@ static struct kunit_case kasan_kunit_test_cases[] =3D=
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
0250622051906.67374-1-snovitoll%40gmail.com.
