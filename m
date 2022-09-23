Return-Path: <kasan-dev+bncBCF5XGNWYQBRBEVRXCMQMGQEGG4RPTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AD335E83EA
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Sep 2022 22:35:32 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id q188-20020a632ac5000000b004393cb3da9csf689372pgq.3
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Sep 2022 13:35:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663965330; cv=pass;
        d=google.com; s=arc-20160816;
        b=bQuvIX1muNZlDzlK7MnrCbEiMy1ZOpAlx7/AmZTpxpscfzbHC+MhTgUY0+wYhn+Pc0
         z92KC5rPVwgZ8UQb9y/Hby2LfllJ7zUJyikpq4Lw9O0fYf/+yGIfS++/puFpN/GQ3D2j
         aLeB3l14LtQ9BLX/GzLuc1sAQQbWcgqNPtmR58EKiQRVs8103XzEDYbk6QXFnZDP3ND4
         HIGi7Ef8QHug8CrqRYgdE5zBJ2hikX1K3Pzbgd8yJHLHVHkvGkk3owyhz0/GPoaObGq+
         X8712VD4ZchqrSC3G6F4bKxPkHNUu8T2wuaTlmew01JcH3GK+9SpYiajdv23TP0cB/pf
         znUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=4BUZ84mG+0oNbwqt+B0FMEkdmw6+jCueKLqvWDvr/MY=;
        b=FzVE4PiTEOR+1uOxWSxDXBueFg+jRsG2oM68D6MqZ+5AYuRpZJqYJ1DA4qxXR7QZ2z
         sg608nWbhhhxEgOWZkfPlTGgLtFEZAzfojamIjUDrNX7YpKoTid0CNve0cawzNxC+VOC
         RHZ6B4XaoqMNJYhTMhuw50hQKiJ7190F9c41fISqrk+KahvEtsEvtT0eoCr9M1LxI3NT
         DpZySxIsOUa48E17bCSVYCQfkRvkD08NGtjlKvU7UlJG/xBEPUYZOpWrAjh3hBD5uNSy
         wntCtQHSwEwU11ahGhVsXLUpQGqe9hST23tIFTi628NfEbfGshKFrlwaPvH7E5qOWsQ0
         8p0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=f94Wfd7x;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=4BUZ84mG+0oNbwqt+B0FMEkdmw6+jCueKLqvWDvr/MY=;
        b=aWeVIsiZugwidRi3htk7c8koQ7rPgDym6rNmBExe6WXYa+NHzmTNTSY4BSUV7tzyKF
         RFisRes9w9/QnkqXHiv1rO7oJWRsgxxB56a4fA3j+kiLmyntK2gzq/rwWqJrviI17KZz
         6HxlK6zgJPdSNAb0wfHn0WZqdjA9MOiyIKm4HDnMR9bRrxIufu+NQ0cBD7De74DhtZ1U
         iQrB0an0WY6LIWDUi258HVaNh5/FR8gxOMx7LfKPsoW35mCMdu3GU8zTB7xvCCTy1X4l
         R38bFRCIBYxKmu8AetqX7DMtbDup74Xb2Jqh4VXc/Glu5e9+yCGQHp3a/CMEY9A74VG5
         x+XA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=4BUZ84mG+0oNbwqt+B0FMEkdmw6+jCueKLqvWDvr/MY=;
        b=2Ka2UHLEdDkcojaxiQwA7UgjY44mWsfh2rbdg8V//S0j/F/4TAWkXv0pxVYDlbu4fe
         QOpUw7v7ssOrG0oMz7VHijz78WN0FT74YOEGQkHKcHwuw7nsOnuXtUPngaZl24XO4vyj
         xiWoASkzSl/3L+zK/pgejPR3dKg6cUL5xm5zGDd6sjSSrJgQvbbBivQ6ls+TFDFIP2id
         CV8q1paN0FIc9k1A45LzVl+DslKxAvt7Ivp4gOA+VJT0h3unGpse0baZqxswVb7dp6FJ
         JOcLmQwXWQ3jJsPi1f4rk91E6guu9jV1WWchyMvio1TDOMht4t3dEL8II98bp+zw7/Pc
         vErg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1MNk9ny6QkyYL/uYT0AGD9tQU2uGQ4P5aTyMhT1JELw3O9YGwc
	O5sKZDljRHfQOIBBjHKGZ2o=
X-Google-Smtp-Source: AMsMyM70nyrA72lok+VgHVrSJQBTFx50flceBwR3aIboUM7nkcME3DQrAOHNoKe+zKBIgazM96RPgg==
X-Received: by 2002:a17:902:c7d1:b0:178:54cf:d69e with SMTP id r17-20020a170902c7d100b0017854cfd69emr10394329pla.86.1663965330601;
        Fri, 23 Sep 2022 13:35:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e495:b0:178:35a3:84d9 with SMTP id
 i21-20020a170902e49500b0017835a384d9ls12524617ple.10.-pod-prod-gmail; Fri, 23
 Sep 2022 13:35:29 -0700 (PDT)
X-Received: by 2002:a17:90b:394d:b0:203:d5a:d9c9 with SMTP id oe13-20020a17090b394d00b002030d5ad9c9mr11745294pjb.49.1663965329850;
        Fri, 23 Sep 2022 13:35:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663965329; cv=none;
        d=google.com; s=arc-20160816;
        b=Y9iq6Aaf2RGvvKnpDLaBr8le65dmmUJxpPDWljmPSyejQB7zXIz5sduikah/VFEp5Q
         d5lDA3wGyliaWzW/f5CFOXHj5haUzCQ/z6AGsLA6ymlNim5pJpOEJ0EDO+A6R5qwc/qi
         attRgZ8SziK3uFhGtfFU+PLGDkrFVlsGNAH/jDfDCsy2Zx30SHVh6pCqnc9VPIKyc4ma
         YZtZpvV1phES648dOwajsYJFXmvQ1jZWycorbDnB7za+MCCA5/2gVoxdtf6tJkwSkvsk
         01nZmzEdzPj6M5rMXVJykQ/0OgsEToWpw0dlRel27oz+0zFq54JTnF/Uumk3RZRjmNKc
         n4pA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=KTqecIsN+rZ/r5vRTPXwhG2Fjp/tipSlLDdfMKYcgLM=;
        b=WyKkEL0GVUaliFT9ocUoiYlW9Z26Ygq0/9uEZzvFDlfNRdHHy/wf2+AU71YKewnLNo
         ZwesmtaOwJrl73Csyt64raJ3O4PKLJt4VLOwTW5nXVPGzxczCuLwjE6FwAoAkwIwy0Vp
         tYhHmM8ogs6wbmOF1zLFwwTrIKCd4ECieaF1TyJeSl25tfYDGcYzOucb4MnVlaRLkB9n
         rCTJ75iMG1guk2Zi+L8tu6drUASbrxuo1VNuIv1G8o8+XDqzXUxQKppL0kLPpapzIYDa
         csTmNrGpkQ6zvZFxOAcJeIYlV2y299N4A0cBHV43LntR3QbtPNBd1eWO1Iq+eetnMy2/
         Hl9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=f94Wfd7x;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id l15-20020a17090a408f00b002025f077b2csi238977pjg.1.2022.09.23.13.35.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Sep 2022 13:35:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id i15-20020a17090a4b8f00b0020073b4ac27so1258121pjh.3
        for <kasan-dev@googlegroups.com>; Fri, 23 Sep 2022 13:35:29 -0700 (PDT)
X-Received: by 2002:a17:903:244d:b0:178:a0eb:d4bc with SMTP id l13-20020a170903244d00b00178a0ebd4bcmr10401235pls.33.1663965329543;
        Fri, 23 Sep 2022 13:35:29 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id n2-20020a170902d2c200b001715a939ac5sm6372093plc.295.2022.09.23.13.35.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 23 Sep 2022 13:35:28 -0700 (PDT)
From: Kees Cook <keescook@chromium.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Kees Cook <keescook@chromium.org>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	"Ruhl, Michael J" <michael.j.ruhl@intel.com>,
	"David S. Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>,
	Jakub Kicinski <kuba@kernel.org>,
	Paolo Abeni <pabeni@redhat.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Alex Elder <elder@kernel.org>,
	Josef Bacik <josef@toxicpanda.com>,
	David Sterba <dsterba@suse.com>,
	Sumit Semwal <sumit.semwal@linaro.org>,
	=?UTF-8?q?Christian=20K=C3=B6nig?= <christian.koenig@amd.com>,
	Jesse Brandeburg <jesse.brandeburg@intel.com>,
	Daniel Micay <danielmicay@gmail.com>,
	Yonghong Song <yhs@fb.com>,
	Marco Elver <elver@google.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	linux-kernel@vger.kernel.org,
	netdev@vger.kernel.org,
	linux-btrfs@vger.kernel.org,
	linux-media@vger.kernel.org,
	dri-devel@lists.freedesktop.org,
	linaro-mm-sig@lists.linaro.org,
	linux-fsdevel@vger.kernel.org,
	intel-wired-lan@lists.osuosl.org,
	dev@openvswitch.org,
	x86@kernel.org,
	llvm@lists.linux.dev,
	linux-hardening@vger.kernel.org
Subject: [PATCH v2 15/16] mm: Make ksize() a reporting-only function
Date: Fri, 23 Sep 2022 13:28:21 -0700
Message-Id: <20220923202822.2667581-16-keescook@chromium.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220923202822.2667581-1-keescook@chromium.org>
References: <20220923202822.2667581-1-keescook@chromium.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=4409; h=from:subject; bh=eTOvroLnBC5lEfD5J+pHwkaq4l0Z2pdeLmvVu9h6d+U=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBjLhbmYN/aRzOKQ1vH75NEteIR/Vhz22yGW0UEIcgR Yp367AqJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCYy4W5gAKCRCJcvTf3G3AJiNkD/ 92DJis5bkVWVuBFAf6aPfGIKZn18fqqWhgDNIB1gL3+/JoYlzCund6gFEcY8zTobmS/RbZGu3aZ6aG eGxVM7yZ+jxRPM4eiG3l1HwhmL3cHQjHtqkRmDgIyPZ9xwxYKivuUOcVZws84e+7hawBwlAhMt8li+ bgO93T234fS5FLzN/RobhSkg6ISNsI03S8QmlYHytLaSLXUZwSR0/mPUZnFFUrJZk61wAHwMxs68nu PInfWb4QkBwNwAwxJn7jG6OEI5/PSX0n80TMD9CEDNK8sroaMS2C4k5gxVvI8qQZGlT6YpdDGy5BFI oEYbO9baL9bYedtNrwWblW1L3ZmdrGVL1MbXkb3ToBxpDPvQrgQHkNTDqQsY4nttLsp3PP7SZolYSA EuyQgZv8SE2uzK0Y60dBBdrNDexKK0+R5g1mk0Fk/fCLG+1/b859Ulh7OdVyoMlBRQRnPMPCaAyju1 28AEPnC9DBu3Gim8BVHKN3GTgZ0QlUPONvmBGSbAWx359vzIQcmmHIqEMaug8yVrFqRB+cIVXcvtuT EI3ZSAAQpODVZpTsW0ZJatcd0IVMg0oWKcDLxZqolmsP3Ns+cC1eix7TMk2B/1g377zgGeJaByDfib tGymOAoaYv3yr/v92FdCHUFaW37DaZ7ARFElDKWqSBGJtj//OOcTik6X79dA==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=f94Wfd7x;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1034
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

With all "silently resizing" callers of ksize() refactored, remove the
logic in ksize() that would allow it to be used to effectively change
the size of an allocation (bypassing __alloc_size hints, etc). Users
wanting this feature need to either use kmalloc_size_roundup() before an
allocation, or call krealloc() directly.

For kfree_sensitive(), move the unpoisoning logic inline. Replace the
open-coded ksize() in __do_krealloc with ksize() now that it doesn't
perform unpoisoning.

Cc: Christoph Lameter <cl@linux.com>
Cc: Pekka Enberg <penberg@kernel.org>
Cc: David Rientjes <rientjes@google.com>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Vlastimil Babka <vbabka@suse.cz>
Cc: Roman Gushchin <roman.gushchin@linux.dev>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-mm@kvack.org
Cc: kasan-dev@googlegroups.com
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 mm/slab_common.c | 38 ++++++++++++++------------------------
 1 file changed, 14 insertions(+), 24 deletions(-)

diff --git a/mm/slab_common.c b/mm/slab_common.c
index d7420cf649f8..60b77bcdc2e3 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1160,13 +1160,8 @@ __do_krealloc(const void *p, size_t new_size, gfp_t flags)
 	void *ret;
 	size_t ks;
 
-	/* Don't use instrumented ksize to allow precise KASAN poisoning. */
-	if (likely(!ZERO_OR_NULL_PTR(p))) {
-		if (!kasan_check_byte(p))
-			return NULL;
-		ks = kfence_ksize(p) ?: __ksize(p);
-	} else
-		ks = 0;
+	/* How large is the allocation actually? */
+	ks = ksize(p);
 
 	/* If the object still fits, repoison it precisely. */
 	if (ks >= new_size) {
@@ -1232,8 +1227,10 @@ void kfree_sensitive(const void *p)
 	void *mem = (void *)p;
 
 	ks = ksize(mem);
-	if (ks)
+	if (ks) {
+		kasan_unpoison_range(mem, ks);
 		memzero_explicit(mem, ks);
+	}
 	kfree(mem);
 }
 EXPORT_SYMBOL(kfree_sensitive);
@@ -1242,10 +1239,11 @@ EXPORT_SYMBOL(kfree_sensitive);
  * ksize - get the actual amount of memory allocated for a given object
  * @objp: Pointer to the object
  *
- * kmalloc may internally round up allocations and return more memory
+ * kmalloc() may internally round up allocations and return more memory
  * than requested. ksize() can be used to determine the actual amount of
- * memory allocated. The caller may use this additional memory, even though
- * a smaller amount of memory was initially specified with the kmalloc call.
+ * allocated memory. The caller may NOT use this additional memory, unless
+ * it calls krealloc(). To avoid an alloc/realloc cycle, callers can use
+ * kmalloc_size_roundup() to find the size of the associated kmalloc bucket.
  * The caller must guarantee that objp points to a valid object previously
  * allocated with either kmalloc() or kmem_cache_alloc(). The object
  * must not be freed during the duration of the call.
@@ -1254,13 +1252,11 @@ EXPORT_SYMBOL(kfree_sensitive);
  */
 size_t ksize(const void *objp)
 {
-	size_t size;
-
 	/*
-	 * We need to first check that the pointer to the object is valid, and
-	 * only then unpoison the memory. The report printed from ksize() is
-	 * more useful, then when it's printed later when the behaviour could
-	 * be undefined due to a potential use-after-free or double-free.
+	 * We need to first check that the pointer to the object is valid.
+	 * The KASAN report printed from ksize() is more useful, then when
+	 * it's printed later when the behaviour could be undefined due to
+	 * a potential use-after-free or double-free.
 	 *
 	 * We use kasan_check_byte(), which is supported for the hardware
 	 * tag-based KASAN mode, unlike kasan_check_read/write().
@@ -1274,13 +1270,7 @@ size_t ksize(const void *objp)
 	if (unlikely(ZERO_OR_NULL_PTR(objp)) || !kasan_check_byte(objp))
 		return 0;
 
-	size = kfence_ksize(objp) ?: __ksize(objp);
-	/*
-	 * We assume that ksize callers could use whole allocated area,
-	 * so we need to unpoison this area.
-	 */
-	kasan_unpoison_range(objp, size);
-	return size;
+	return kfence_ksize(objp) ?: __ksize(objp);
 }
 EXPORT_SYMBOL(ksize);
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220923202822.2667581-16-keescook%40chromium.org.
